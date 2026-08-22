"""Extract and export one bounded incident graph from the provenance CSV."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

BASE64_COMMAND = re.compile(r"echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+--decode")


def normalize_pid(value: str | None) -> int | None:
    """Normalize integer-like PIDs such as ``152566.0``."""
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return int(number) if number.is_integer() else None


def numeric(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def entity_time(node: Mapping[str, str]) -> float | None:
    """Return the populated Process timestamp without redefining its semantics."""
    start = numeric(node.get("start time"))
    return start if start is not None else numeric(node.get("seen time"))


def classify_row(row: Mapping[str, str]) -> str:
    """Classify a mixed CSV row using its ID and endpoint fields."""
    present = tuple(bool(row.get(key, "").strip()) for key in ("id", "from", "to"))
    if present == (True, False, False):
        return "node"
    if present == (False, True, True):
        return "edge"
    return "ambiguous"


def compact(row: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in row.items() if value}


def decode_embedded_command(command_line: str | None) -> str | None:
    """Decode, but never execute, the dataset's observed base64 wrapper."""
    match = BASE64_COMMAND.search(command_line or "")
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _iso_utc(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _load_attack(path: Path, index: int) -> dict[str, str]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        attacks = list(csv.DictReader(handle))
    if not 0 <= index < len(attacks):
        raise IndexError(f"attack index {index} is outside 0..{len(attacks) - 1}")
    return attacks[index]


def _load_nodes(
    path: Path,
) -> tuple[dict[str, dict[str, str]], dict[int, list[dict[str, str]]]]:
    nodes: dict[str, dict[str, str]] = {}
    processes: dict[int, list[dict[str, str]]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            if classify_row(row) != "node":
                continue
            node = compact(row)
            node["csv_line"] = str(line_number)
            nodes[node["id"]] = node
            pid = normalize_pid(node.get("pid"))
            if node.get("type") == "Process" and pid is not None:
                processes[pid].append(node)
    return nodes, processes


def _find_lineage(
    root_pid: int,
    anchor_time: float,
    processes: Mapping[int, list[dict[str, str]]],
    horizon_seconds: float,
    max_depth: int,
) -> tuple[set[int], list[dict[str, Any]]]:
    children: dict[int, set[int]] = defaultdict(set)
    for pid, records in processes.items():
        for node in records:
            ppid = normalize_pid(node.get("ppid"))
            if ppid is not None:
                children[ppid].add(pid)

    selected = {root_pid}
    frontier = {root_pid}
    relationships: list[dict[str, Any]] = []
    for depth in range(1, max_depth + 1):
        next_frontier: set[int] = set()
        for parent_pid in sorted(frontier):
            for child_pid in sorted(children.get(parent_pid, set()) - selected):
                times = [time for node in processes[child_pid] if (time := entity_time(node)) is not None]
                if not times or not anchor_time - 1 <= min(times) <= anchor_time + horizon_seconds:
                    continue
                next_frontier.add(child_pid)
                relationships.append({
                    "parent_pid": parent_pid,
                    "child_pid": child_pid,
                    "depth": depth,
                    "kind": "inferred_pid_lineage",
                    "evidence": "child Process.ppid equals parent Process.pid",
                })
        if not next_frontier:
            break
        selected.update(next_frontier)
        frontier = next_frontier
    return selected, relationships


def _enrich_node(node: Mapping[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = dict(node)
    if node.get("type") == "Process":
        timestamp = entity_time(node)
        result["entity_time"] = timestamp
        result["entity_time_utc"] = _iso_utc(timestamp) if timestamp is not None else None
        decoded = decode_embedded_command(node.get("command line"))
        if decoded is not None:
            result["derived_decoded_command"] = decoded
    return result


def extract_incident(
    provenance_path: Path,
    attack_info_path: Path,
    attack_index: int = 44,
    *,
    lineage_horizon_seconds: float = 300.0,
    max_lineage_depth: int = 3,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, str]], list[dict[str, Any]]]:
    """Extract an attack's Process lineage and directly adjacent provenance."""
    attack = _load_attack(attack_info_path, attack_index)
    attack_pid = normalize_pid(attack.get("PID"))
    attack_time = numeric(attack.get("Time of Attack"))
    if attack_pid is None or attack_time is None:
        raise ValueError("selected attack must have an integer PID and numeric Time of Attack")

    nodes, processes = _load_nodes(provenance_path)
    root_nodes = processes.get(attack_pid, [])
    root_times = [time for node in root_nodes if (time := entity_time(node)) is not None]
    if not root_nodes or not root_times:
        raise ValueError(f"no timestamped Process nodes match PID {attack_pid}")
    anchor_time = min(root_times, key=lambda time: abs(time - attack_time))
    selected_pids, inferred = _find_lineage(
        attack_pid, anchor_time, processes, lineage_horizon_seconds, max_lineage_depth
    )
    process_ids = {node["id"] for pid in selected_pids for node in processes[pid]}

    observed: list[dict[str, str]] = []
    incident_ids = set(process_ids)
    with provenance_path.open(newline="", encoding="utf-8-sig") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            if classify_row(row) != "edge":
                continue
            if row["from"] not in process_ids and row["to"] not in process_ids:
                continue
            edge = compact(row)
            edge["csv_line"] = str(line_number)
            observed.append(edge)
            incident_ids.update((row["from"], row["to"]))

    incident_nodes = {
        node_id: _enrich_node(nodes[node_id])
        for node_id in sorted(incident_ids)
        if node_id in nodes
    }
    report: dict[str, Any] = {
        "format_version": 2,
        "attack": {"index_zero_based": attack_index, "metadata": attack},
        "anchor_process": {
            "pid": attack_pid,
            "node_ids": [node["id"] for node in root_nodes],
            "metadata_time": attack_time,
            "metadata_time_utc": _iso_utc(attack_time),
            "provenance_time": anchor_time,
            "provenance_time_utc": _iso_utc(anchor_time),
            "provenance_minus_metadata_seconds": anchor_time - attack_time,
        },
        "inferred_process_lineage": {
            "rule": f"Follow nearby Process.ppid -> Process.pid to depth {max_lineage_depth} within {lineage_horizon_seconds:g} seconds.",
            "selected_pids": sorted(selected_pids),
            "relationships": inferred,
        },
        "incident_graph": {
            "scope": "selected Process nodes and their directly adjacent observed relationships",
            "node_count": len(incident_nodes),
            "observed_relationship_count": len(observed),
            "nodes": list(incident_nodes.values()),
            "observed_relationships": observed,
        },
        "assumptions": [
            "PID links attack metadata to Process records; differing timestamps are preserved.",
            "Nearby PPID/PID matches are inferred lineage, not observed provenance edges.",
            "Stored relationship names and from/to directions are not reinterpreted.",
        ],
    }
    return report, incident_nodes, observed, inferred


def _canonical_process_id(nodes: Mapping[str, Mapping[str, str]], pid: int) -> str | None:
    matches = [node_id for node_id, node in nodes.items() if normalize_pid(node.get("pid")) == pid]
    return next((node_id for node_id in matches if nodes[node_id].get("command line")), matches[0] if matches else None)


def _graphml_display_name(node: Mapping[str, Any]) -> str:
    """Return a short Bloom caption without discarding detailed properties."""
    if node.get("type") == "Process":
        process_name = node.get("name") or Path(str(node.get("exe", ""))).name or "Process"
        pid = normalize_pid(node.get("pid"))
        return f"{process_name} (PID {pid})" if pid is not None else str(process_name)

    path = str(node.get("path", "")).strip()
    if path and path != "0":
        return Path(path).name or path
    remote_address = str(node.get("remote address", "")).strip()
    remote_port = normalize_pid(node.get("remote port"))
    if remote_address:
        return f"{remote_address}:{remote_port}" if remote_port is not None else remote_address
    local_address = str(node.get("local address", "")).strip()
    local_port = normalize_pid(node.get("local port"))
    if local_address:
        return f"{local_address}:{local_port}" if local_port is not None else local_address
    subtype = str(node.get("subtype") or "Artifact")
    node_id = str(node.get("id", ""))
    if subtype.lower() == "unknown":
        subtype = "Artifact"
    return f"{subtype} ({node_id[:8]})" if node_id else subtype


def _graphml_relationship_type(value: str | None) -> str:
    """Convert stored relationship names to Neo4j-style relationship types."""
    if not value:
        return "RELATED"
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", words).strip("_").upper() or "RELATED"


def write_graphml(
    path: Path,
    nodes: Mapping[str, Mapping[str, Any]],
    observed: Iterable[Mapping[str, str]],
    inferred: Iterable[Mapping[str, Any]],
    *,
    attack_properties: Mapping[str, Any] | None = None,
) -> None:
    """Write Neo4j-friendly GraphML with native labels and relationship types."""
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    root = ET.Element(f"{{{namespace}}}graphml")
    keys = {
        "labels": "node", "display_name": "node", "name": "node",
        "process_name": "node", "node_type": "node", "original_id": "node",
        "dataset_label": "all", "subLabel": "node", "pid": "node", "ppid": "node",
        "command_line": "node", "path": "node", "timestamp": "node",
        "attack_id": "all", "attack_index": "all", "attack_pid": "all",
        "tactic": "all", "technique": "all", "label": "edge",
        "relationship": "edge", "operation": "edge", "time": "edge",
        "evidence_kind": "edge", "evidence": "edge",
    }
    for key, scope in keys.items():
        ET.SubElement(root, f"{{{namespace}}}key", id=key, **{"for": scope, "attr.name": key, "attr.type": "string"})
    graph = ET.SubElement(root, f"{{{namespace}}}graph", edgedefault="directed")
    common = dict(attack_properties or {})
    for node_id, node in nodes.items():
        node_type = node.get("type")
        native_labels = f":{node_type}" if node_type else None
        attributes = {"id": node_id}
        if native_labels:
            attributes["labels"] = native_labels
        element = ET.SubElement(graph, f"{{{namespace}}}node", **attributes)
        display_name = _graphml_display_name(node)
        values = {
            **common,
            "labels": native_labels,
            "display_name": display_name,
            "name": display_name,
            "process_name": node.get("name") if node_type == "Process" else None,
            "node_type": node_type,
            "original_id": node_id,
            "dataset_label": node.get("label"),
            "subLabel": node.get("subLabel"),
            "pid": node.get("pid"),
            "ppid": node.get("ppid"),
            "command_line": node.get("command line"),
            "path": node.get("path"),
            "timestamp": node.get("entity_time"),
        }
        for key, value in values.items():
            if value is not None and value != "":
                ET.SubElement(element, f"{{{namespace}}}data", key=key).text = str(value)
    edge_number = 0
    for relationship in observed:
        relationship_type = _graphml_relationship_type(relationship.get("type"))
        edge = ET.SubElement(graph, f"{{{namespace}}}edge", id=f"e{edge_number}", source=relationship["from"], target=relationship["to"], label=relationship_type)
        edge_number += 1
        values = {
            **common,
            "label": relationship_type,
            "relationship": relationship.get("type"),
            "dataset_label": relationship.get("label"),
            "operation": relationship.get("operation"),
            "time": relationship.get("time"),
            "evidence_kind": "observed",
            "evidence": "observed provenance relationship",
        }
        for key, value in values.items():
            if value is not None and value != "":
                ET.SubElement(edge, f"{{{namespace}}}data", key=key).text = str(value)
    for relationship in inferred:
        source = _canonical_process_id(nodes, int(relationship["parent_pid"]))
        target = _canonical_process_id(nodes, int(relationship["child_pid"]))
        if source is None or target is None:
            continue
        relationship_type = "INFERRED_PID_LINEAGE"
        edge = ET.SubElement(graph, f"{{{namespace}}}edge", id=f"e{edge_number}", source=source, target=target, label=relationship_type)
        edge_number += 1
        values = {
            **common,
            "label": relationship_type,
            "relationship": "inferred_pid_lineage",
            "evidence_kind": "inferred",
            "evidence": relationship["evidence"],
        }
        for key, value in values.items():
            if value is not None and value != "":
                ET.SubElement(edge, f"{{{namespace}}}data", key=key).text = str(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-index", type=int, default=44)
    parser.add_argument("--provenance", type=Path, default=Path("data/raw/Phase2_Provenance.csv"))
    parser.add_argument("--attack-info", type=Path, default=Path("data/raw/attack_info.csv"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--graphml", type=Path)
    parser.add_argument("--lineage-horizon-seconds", type=float, default=300.0)
    parser.add_argument("--max-lineage-depth", type=int, default=3)
    args = parser.parse_args()
    report, nodes, observed, inferred = extract_incident(args.provenance, args.attack_info, args.attack_index, lineage_horizon_seconds=args.lineage_horizon_seconds, max_lineage_depth=args.max_lineage_depth)
    pid = report["anchor_process"]["pid"]
    stem = f"attack_{args.attack_index:03d}_pid_{pid}"
    output = args.output or Path("data/processed") / f"{stem}.json"
    graphml = args.graphml or Path("data/processed") / f"{stem}.graphml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    metadata = report["attack"]["metadata"]
    write_graphml(
        graphml,
        nodes,
        observed,
        inferred,
        attack_properties={
            "attack_id": f"attack_{args.attack_index:03d}",
            "attack_index": args.attack_index,
            "attack_pid": pid,
            "tactic": metadata.get("Tactic Name"),
            "technique": metadata.get("Technique Name"),
        },
    )
    print(f"Wrote {output}\nWrote {graphml}")
    print(f"Attack {args.attack_index}, PID {pid}: {len(nodes)} nodes, {len(observed)} observed and {len(inferred)} inferred relationships")


if __name__ == "__main__":
    main()
