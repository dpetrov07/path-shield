"""Retrieve incident-scoped Process and Artifact evidence from Neo4j."""

from __future__ import annotations

from pathlib import PurePosixPath
import re
from collections import defaultdict
from typing import Any, Mapping, Sequence

from pathshield.incident import normalize_pid
from pathshield.incident_retrieval import IncidentGraph

MAX_DISPLAY_PROCESSES = 12
MAX_DISPLAY_ARTIFACTS = 8
MAX_DISPLAY_RELATIONSHIPS = 12


def _graph_id(attack_index: int, original_id: str) -> str:
    return f"attack_{attack_index:03d}:{original_id}"


def _relationship_type(value: Any) -> str:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "RELATED"))
    return re.sub(r"[^A-Za-z0-9]+", "_", words).strip("_").upper() or "RELATED"


def _canonical_process_id(graph: IncidentGraph, pid: int) -> str | None:
    matches = [
        node
        for node in graph.nodes.values()
        if node.get("type") == "Process"
        and normalize_pid(str(node.get("pid", ""))) == pid
    ]
    if not matches:
        return None
    node = next((item for item in matches if item.get("command line")), matches[0])
    return str(node["id"])


def index_incident_graphs(
    driver: Any, database: str, graphs: Sequence[IncidentGraph]
) -> tuple[int, int]:
    """Replace the managed Neo4j graph layer with all extracted incidents."""
    driver.execute_query(
        "CREATE CONSTRAINT pathshield_graph_id IF NOT EXISTS "
        "FOR (node:PathShieldEntity) REQUIRE node.graph_id IS UNIQUE",
        database_=database,
    )
    driver.execute_query(
        "MATCH (node:PathShieldEntity) DETACH DELETE node",
        database_=database,
    )

    node_rows: dict[str, list[dict[str, Any]]] = {"Process": [], "Artifact": []}
    relationship_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for graph in graphs:
        common = {
            "attack_index": graph.attack_index,
            "attack_id": f"attack_{graph.attack_index:03d}",
            "attack_pid": graph.attack_pid,
            "tactic": graph.tactic,
            "technique": graph.attack_description,
        }
        for original_id, node in graph.nodes.items():
            node_type = str(node.get("type") or "")
            if node_type not in node_rows:
                continue
            path = node.get("path")
            name = node.get("name") if node_type == "Process" else (
                PurePosixPath(str(path)).name if path else node.get("subtype") or "Artifact"
            )
            row = {
                **common,
                "graph_id": _graph_id(graph.attack_index, original_id),
                "original_id": original_id,
                "node_type": node_type,
                "name": name,
                "process_name": node.get("name") if node_type == "Process" else None,
                "pid": node.get("pid"),
                "ppid": node.get("ppid"),
                "command_line": node.get("command line"),
                "path": path,
                "timestamp": node.get("entity_time"),
                "pathshield_managed": True,
            }
            node_rows[node_type].append(row)

        for relationship in graph.observed:
            relationship_type = _relationship_type(relationship.get("type"))
            relationship_rows[relationship_type].append({
                **common,
                "source_graph_id": _graph_id(graph.attack_index, str(relationship["from"])),
                "target_graph_id": _graph_id(graph.attack_index, str(relationship["to"])),
                "display_type": relationship_type,
                "provenance_type": relationship.get("type"),
                "operation": relationship.get("operation"),
                "timestamp": relationship.get("time"),
                "evidence_kind": "observed",
                "evidence": "observed provenance relationship",
            })
        for relationship in graph.inferred:
            source_id = _canonical_process_id(graph, int(relationship["parent_pid"]))
            target_id = _canonical_process_id(graph, int(relationship["child_pid"]))
            if source_id is None or target_id is None:
                continue
            relationship_rows["INFERRED_PID_LINEAGE"].append({
                **common,
                "source_graph_id": _graph_id(graph.attack_index, source_id),
                "target_graph_id": _graph_id(graph.attack_index, target_id),
                "display_type": "INFERRED_PID_LINEAGE",
                "provenance_type": "inferred_pid_lineage",
                "operation": None,
                "timestamp": None,
                "evidence_kind": "inferred",
                "evidence": relationship.get("evidence"),
            })

    for node_type, rows in node_rows.items():
        driver.execute_query(
            f"""
            UNWIND $rows AS row
            CREATE (node:PathShieldEntity:{node_type})
            SET node = row
            """,
            rows=rows,
            database_=database,
        )
    for relationship_type, rows in relationship_rows.items():
        driver.execute_query(
            f"""
            UNWIND $rows AS row
            MATCH (source:PathShieldEntity {{graph_id: row.source_graph_id}}),
                  (target:PathShieldEntity {{graph_id: row.target_graph_id}})
            CREATE (source)-[relationship:{relationship_type}]->(target)
            SET relationship = row
            """,
            rows=rows,
            database_=database,
        )
    return (
        sum(len(rows) for rows in node_rows.values()),
        sum(len(rows) for rows in relationship_rows.values()),
    )


def _record_data(record: Any) -> dict[str, Any]:
    return record.data() if hasattr(record, "data") else dict(record)


def _attack_index(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_library_noise(path: Any) -> bool:
    value = str(path or "")
    return value.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"))


def retrieve_graph_evidence(
    driver: Any, database: str, attack_indexes: Sequence[int]
) -> list[dict[str, Any]]:
    """Return nodes and direct relationships scoped to the requested incidents."""
    requested = list(dict.fromkeys(int(index) for index in attack_indexes))
    if not requested:
        return []
    requested_set = set(requested)
    parameters = {
        "attack_indexes": [str(index) for index in requested],
        "database_": database,
    }

    node_records, _, _ = driver.execute_query(
        """
        MATCH (node)
        WHERE toString(node.attack_index) IN $attack_indexes
          AND (node:Process OR node:Artifact OR node.node_type IN ['Process', 'Artifact'])
        RETURN toInteger(node.attack_index) AS attack_index,
               coalesce(node.original_id, elementId(node)) AS original_id,
               coalesce(node.node_type,
                        CASE WHEN node:Process THEN 'Process' ELSE 'Artifact' END) AS node_type,
               node.process_name AS process_name,
               node.pid AS pid,
               node.ppid AS ppid,
               node.command_line AS command_line,
               node.path AS path,
               node.timestamp AS timestamp
        ORDER BY attack_index, node_type DESC, pid, original_id
        """,
        **parameters,
    )
    evidence = {
        index: {
            "attack_index": index,
            "processes": [],
            "artifacts": [],
            "observed_relationships": [],
            "inferred_lineage": [],
        }
        for index in requested
    }
    kept_node_ids: dict[int, set[str]] = {index: set() for index in requested}
    for record in node_records:
        node = _record_data(record)
        index = _attack_index(node.get("attack_index"))
        if index not in requested_set:
            continue
        node_type = node.get("node_type")
        if node_type == "Artifact" and _is_library_noise(node.get("path")):
            continue
        if node_type not in {"Process", "Artifact"}:
            continue
        original_id = str(node.get("original_id") or "")
        kept_node_ids[index].add(original_id)
        evidence[index]["processes" if node_type == "Process" else "artifacts"].append(node)

    relationship_records, _, _ = driver.execute_query(
        """
        MATCH (source)-[relationship]->(target)
        WHERE toString(relationship.attack_index) IN $attack_indexes
          AND toString(source.attack_index) = toString(relationship.attack_index)
          AND toString(target.attack_index) = toString(relationship.attack_index)
        RETURN toInteger(relationship.attack_index) AS attack_index,
               coalesce(source.original_id, elementId(source)) AS source_id,
               coalesce(target.original_id, elementId(target)) AS target_id,
               type(relationship) AS relationship_type,
               relationship.label AS display_type,
               relationship.relationship AS provenance_type,
               relationship.operation AS operation,
               relationship.time AS timestamp,
               relationship.evidence_kind AS evidence_kind,
               relationship.evidence AS evidence
        ORDER BY attack_index, evidence_kind, relationship_type, source_id, target_id
        """,
        **parameters,
    )
    for record in relationship_records:
        relationship = _record_data(record)
        index = _attack_index(relationship.get("attack_index"))
        if index not in requested_set:
            continue
        if (
            str(relationship.get("source_id") or "") not in kept_node_ids[index]
            or str(relationship.get("target_id") or "") not in kept_node_ids[index]
        ):
            continue
        kind = str(relationship.get("evidence_kind") or "").lower()
        relationship_type = str(relationship.get("relationship_type") or "")
        display_type = str(relationship.get("display_type") or "")
        is_inferred = (
            kind == "inferred"
            or relationship_type.startswith("INFERRED_")
            or display_type.startswith("INFERRED_")
        )
        target = "inferred_lineage" if is_inferred else "observed_relationships"
        evidence[index][target].append(relationship)

    return [evidence[index] for index in requested]


def _process_label(process: Mapping[str, Any]) -> str:
    name = str(process.get("process_name") or "Process")
    pid = process.get("pid")
    return f"{name} (PID {pid})" if pid not in {None, ""} else name


def _format_relationship(
    relationship: Mapping[str, Any], node_labels: Mapping[str, str]
) -> str:
    source = node_labels.get(str(relationship.get("source_id")), str(relationship.get("source_id")))
    target = node_labels.get(str(relationship.get("target_id")), str(relationship.get("target_id")))
    relationship_type = str(relationship.get("relationship_type") or "RELATED")
    if relationship_type == "RELATED" and relationship.get("display_type"):
        relationship_type = str(relationship["display_type"])
    operation = relationship.get("operation")
    detail = f", {operation}" if operation else ""
    return f"{source} -[{relationship_type}{detail}]-> {target}"


def format_graph_evidence(graph_evidence: Sequence[Mapping[str, Any]]) -> str:
    """Format structured graph evidence for terminal display and LLM context."""
    if not graph_evidence:
        return "No incident-scoped graph evidence found for the selected incidents."
    sections = []
    for incident in graph_evidence:
        processes = list(incident.get("processes", []))
        artifacts = list(incident.get("artifacts", []))
        observed = list(incident.get("observed_relationships", []))
        inferred = list(incident.get("inferred_lineage", []))
        node_labels = {
            str(process.get("original_id")): _process_label(process)
            for process in processes
        }
        node_labels.update({
            str(artifact.get("original_id")): str(
                artifact.get("path")
                or PurePosixPath(str(artifact.get("original_id") or "Artifact")).name
            )
            for artifact in artifacts
        })

        processes_by_identity: dict[tuple[Any, Any], Mapping[str, Any]] = {}
        for process in processes:
            key = (process.get("process_name"), process.get("pid"))
            previous = processes_by_identity.get(key)
            if previous is None or (
                not previous.get("command_line") and process.get("command_line")
            ):
                processes_by_identity[key] = process

        process_lines = []
        for process in processes_by_identity.values():
            command = str(process.get("command_line") or "").strip()
            line = _process_label(process)
            if process.get("ppid") not in {None, ""}:
                line += f", PPID {process['ppid']}"
            if command:
                line += f": {command[:239].rstrip()}{'…' if len(command) > 239 else ''}"
            process_lines.append(line)

        artifact_lines = list(dict.fromkeys(
            str(artifact.get("path"))
            for artifact in artifacts
            if artifact.get("path") not in {None, "", "0"}
        ))
        observed_lines = list(dict.fromkeys(
            _format_relationship(item, node_labels) for item in observed
        ))
        inferred_lines = list(dict.fromkeys(
            _format_relationship(item, node_labels) for item in inferred
        ))

        lines = [f"Attack {incident['attack_index']} graph evidence:"]
        if process_lines:
            lines.append("  Processes: " + "; ".join(process_lines[:MAX_DISPLAY_PROCESSES]))
        if artifact_lines:
            lines.append("  Artifacts: " + "; ".join(artifact_lines[:MAX_DISPLAY_ARTIFACTS]))
        if observed_lines:
            lines.append("  Observed: " + "; ".join(observed_lines[:MAX_DISPLAY_RELATIONSHIPS]))
        if inferred_lines:
            lines.append("  Inferred lineage: " + "; ".join(inferred_lines[:MAX_DISPLAY_RELATIONSHIPS]))
        if len(lines) == 1:
            lines.append("  No Process, Artifact, or relationship evidence found.")
        sections.append("\n".join(lines))
    return "\n\n".join(sections)
