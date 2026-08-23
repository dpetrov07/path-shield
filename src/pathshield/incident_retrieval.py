"""Build, store, and search PathShield incident retrieval documents."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pathshield.incident import (
    extract_incident_from_data,
    load_attacks,
    load_provenance,
    normalize_pid,
)
from pathshield.vector import (
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
    text_snippet,
    wait_for_index,
)

DEFAULT_PROVENANCE_PATH = Path("data/raw/Phase2_Provenance.csv")
DEFAULT_ATTACK_INFO_PATH = Path("data/raw/attack_info.csv")
INCIDENT_VECTOR_INDEX_NAME = "pathshield_incident_embedding"
INCIDENT_CORPUS_NAME = "pathshield_incidents_v1"
MAX_COMMANDS = 12
MAX_PATHS = 12
MAX_COMMAND_LENGTH = 300


@dataclass(frozen=True)
class IncidentDocument:
    attack_index: int
    attack_pid: int
    tactic: str
    technique: str
    document_text: str
    node_count: int
    observed_relationship_count: int
    inferred_lineage_count: int


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _ordered_unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value and value != "0"))


def _process_sort_key(node: Mapping[str, Any]) -> tuple[float, int, str]:
    timestamp = node.get("entity_time")
    pid = normalize_pid(str(node.get("pid", "")))
    return (
        float(timestamp) if timestamp is not None else float("inf"),
        pid if pid is not None else sys.maxsize,
        str(node.get("id", "")),
    )


def _process_nodes(
    nodes: Mapping[str, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return sorted(
        (node for node in nodes.values() if node.get("type") == "Process"),
        key=_process_sort_key,
    )


def _process_names(processes: Sequence[Mapping[str, Any]]) -> list[str]:
    return _ordered_unique([_clean_text(node.get("name")) for node in processes])


def _commands(processes: Sequence[Mapping[str, Any]]) -> list[str]:
    commands = []
    for node in processes:
        raw_command = _clean_text(
            node.get("derived_decoded_command") or node.get("command line")
        )
        for command in re.split(r"\s*;\s*", raw_command):
            if command:
                commands.append(command[:MAX_COMMAND_LENGTH])
    return _ordered_unique(commands)[:MAX_COMMANDS]


def _meaningful_paths(
    nodes: Mapping[str, Mapping[str, Any]], process_names: Sequence[str]
) -> list[str]:
    paths = []
    process_name_set = set(process_names)
    for node in nodes.values():
        if node.get("type") != "Artifact":
            continue
        path = _clean_text(node.get("path"))
        if not path or path == "0":
            continue
        if path.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")):
            continue
        if Path(path).name in process_name_set and str(Path(path).parent) in {
            "/bin", "/sbin", "/usr/bin", "/usr/sbin"
        }:
            continue
        paths.append(path)
    return sorted(set(paths))[:MAX_PATHS]


def _remote_endpoints(nodes: Mapping[str, Mapping[str, Any]]) -> list[str]:
    endpoints = []
    for node in nodes.values():
        address = _clean_text(node.get("remote address"))
        if not address or address == "0":
            continue
        port = normalize_pid(str(node.get("remote port", "")))
        endpoints.append(f"{address}:{port}" if port is not None else address)
    return sorted(set(endpoints))


def _lineage_text(
    processes: Sequence[Mapping[str, Any]], inferred: Sequence[Mapping[str, Any]]
) -> list[str]:
    names_by_pid: dict[int, str] = {}
    for node in processes:
        pid = normalize_pid(str(node.get("pid", "")))
        name = _clean_text(node.get("name"))
        if pid is not None and name:
            names_by_pid.setdefault(pid, name)

    pairs = []
    for relationship in sorted(
        inferred,
        key=lambda item: (
            int(item.get("depth", 0)),
            int(item["parent_pid"]),
            int(item["child_pid"]),
        ),
    ):
        parent_pid = int(relationship["parent_pid"])
        child_pid = int(relationship["child_pid"])
        parent = names_by_pid.get(parent_pid, "process")
        child = names_by_pid.get(child_pid, "process")
        pairs.append(f"{parent} -> {child}")
    return _ordered_unique(pairs)


def _relationship_text(observed: Sequence[Mapping[str, str]]) -> list[str]:
    values = []
    for relationship in observed:
        relationship_type = _clean_text(relationship.get("type"))
        operation = _clean_text(relationship.get("operation"))
        if relationship_type:
            values.append(
                f"{relationship_type} ({operation})" if operation else relationship_type
            )
    return sorted(set(values))


def build_incident_document(
    report: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]],
    observed: Sequence[Mapping[str, str]],
    inferred: Sequence[Mapping[str, Any]],
) -> IncidentDocument:
    """Construct reproducible semantic text from one extracted incident."""
    attack = report["attack"]
    metadata = attack["metadata"]
    attack_index = int(attack["index_zero_based"])
    attack_pid = int(report["anchor_process"]["pid"])
    tactic = _clean_text(metadata.get("Tactic Name"))
    technique = _clean_text(metadata.get("Technique Name"))
    processes = _process_nodes(nodes)
    process_names = _process_names(processes)

    sections = [
        f"PathShield attack {attack_index}.",
        f"Tactic: {tactic}." if tactic else "",
        f"Observed behavior: {technique}." if technique else "",
    ]
    details = [
        ("Processes", process_names),
        ("Commands", _commands(processes)),
        ("Artifacts and paths", _meaningful_paths(nodes, process_names)),
        ("Remote endpoints", _remote_endpoints(nodes)),
        ("Process lineage", _lineage_text(processes, inferred)),
        ("Observed relationships", _relationship_text(observed)),
    ]
    sections.extend(
        f"{label}: {'; '.join(values)}."
        for label, values in details
        if values
    )
    graph = report["incident_graph"]
    return IncidentDocument(
        attack_index=attack_index,
        attack_pid=attack_pid,
        tactic=tactic,
        technique=technique,
        document_text=" ".join(section for section in sections if section),
        node_count=int(graph["node_count"]),
        observed_relationship_count=int(graph["observed_relationship_count"]),
        inferred_lineage_count=len(inferred),
    )


def build_incident_documents(
    provenance_path: Path = DEFAULT_PROVENANCE_PATH,
    attack_info_path: Path = DEFAULT_ATTACK_INFO_PATH,
) -> list[IncidentDocument]:
    """Load the dataset once, then apply the existing extractor to every attack."""
    provenance = load_provenance(provenance_path)
    attacks = load_attacks(attack_info_path)
    documents: list[IncidentDocument] = []
    for attack_index, attack in enumerate(attacks):
        report, nodes, observed, inferred = extract_incident_from_data(
            provenance, attack, attack_index
        )
        documents.append(
            build_incident_document(report, nodes, observed, inferred)
        )
    return documents


def index_incidents(
    driver: Any,
    database: str,
    incidents: Sequence[IncidentDocument],
    embeddings: Sequence[Sequence[float]],
) -> None:
    """Upsert incident retrieval nodes without modifying provenance nodes."""
    if len(incidents) != len(embeddings):
        raise ValueError("Each incident must have one embedding")

    driver.execute_query(
        "CREATE CONSTRAINT pathshield_incident_attack_index IF NOT EXISTS "
        "FOR (incident:Incident) REQUIRE incident.attack_index IS UNIQUE",
        database_=database,
    )
    rows = [
        {
            **incident.__dict__,
            "attack_id": f"attack_{incident.attack_index:03d}",
            "embedding": list(embedding),
        }
        for incident, embedding in zip(incidents, embeddings, strict=True)
    ]
    driver.execute_query(
        """
        UNWIND $rows AS row
        MERGE (incident:Incident {attack_index: row.attack_index})
        SET incident.attack_id = row.attack_id,
            incident.attack_pid = row.attack_pid,
            incident.tactic = row.tactic,
            incident.technique = row.technique,
            incident.document_text = row.document_text,
            incident.node_count = row.node_count,
            incident.observed_relationship_count = row.observed_relationship_count,
            incident.inferred_lineage_count = row.inferred_lineage_count,
            incident.embedding = row.embedding,
            incident.embedding_model = $embedding_model,
            incident.corpus = $corpus
        """,
        rows=rows,
        embedding_model=EMBEDDING_MODEL,
        corpus=INCIDENT_CORPUS_NAME,
        database_=database,
    )
    driver.execute_query(
        f"""
        CREATE VECTOR INDEX {INCIDENT_VECTOR_INDEX_NAME} IF NOT EXISTS
        FOR (incident:Incident) ON (incident.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: {EMBEDDING_DIMENSIONS},
            `vector.similarity_function`: 'cosine'
        }}}}
        """,
        database_=database,
    )
    wait_for_index(driver, database, INCIDENT_VECTOR_INDEX_NAME)


def query_incidents(
    driver: Any, database: str, embedding: Sequence[float], top_k: int
) -> list[dict[str, Any]]:
    records, _, _ = driver.execute_query(
        f"""
        CYPHER 25
        MATCH (node:Incident)
        SEARCH node IN (
            VECTOR INDEX {INCIDENT_VECTOR_INDEX_NAME}
            FOR $embedding
            LIMIT $top_k
        ) SCORE AS score
        RETURN node.attack_index AS attack_index,
               node.attack_pid AS attack_pid,
               node.tactic AS tactic,
               node.technique AS technique,
               node.document_text AS document_text,
               score
        ORDER BY score DESC
        """,
        top_k=top_k,
        embedding=list(embedding),
        database_=database,
    )
    return [record.data() for record in records]


def format_incident_results(results: Sequence[Mapping[str, Any]]) -> str:
    if not results:
        return "No matching incidents found. Has the incident corpus been indexed?"
    lines = []
    for rank, result in enumerate(results, start=1):
        lines.append(
            f"{rank}. Attack {result['attack_index']} — {result['technique']} — "
            f"{float(result['score']):.3f}\n"
            f"   Tactic: {result['tactic']} | PID: {result['attack_pid']}\n"
            f"   {text_snippet(str(result['document_text']), 180)}"
        )
    return "\n".join(lines)


def sparse_incidents(incidents: Sequence[IncidentDocument]) -> list[IncidentDocument]:
    """Flag documents with little evidence beyond attack metadata."""
    return [
        incident
        for incident in incidents
        if incident.node_count <= 2
        or incident.observed_relationship_count == 0
        or len(incident.document_text) < 180
    ]
