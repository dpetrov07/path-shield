"""Extract bounded incident data used to build retrieval documents."""

from __future__ import annotations

import base64
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

BASE64_COMMAND = re.compile(r"echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+--decode")


@dataclass(frozen=True)
class ProvenanceData:
    """The provenance CSV parsed once for reuse across incident extractions."""

    nodes: dict[str, dict[str, str]]
    processes: dict[int, list[dict[str, str]]]
    children: dict[int, set[int]]
    edges: list[dict[str, str]]


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


def load_attacks(path: Path) -> list[dict[str, str]]:
    """Load attack metadata in its original row order."""
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def load_provenance(path: Path) -> ProvenanceData:
    """Parse nodes and relationships from the mixed provenance CSV in one pass."""
    nodes: dict[str, dict[str, str]] = {}
    processes: dict[int, list[dict[str, str]]] = defaultdict(list)
    children: dict[int, set[int]] = defaultdict(set)
    edges: list[dict[str, str]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            row_kind = classify_row(row)
            if row_kind == "ambiguous":
                continue
            item = compact(row)
            item["csv_line"] = str(line_number)
            if row_kind == "edge":
                edges.append(item)
                continue

            nodes[item["id"]] = item
            pid = normalize_pid(item.get("pid"))
            if item.get("type") == "Process" and pid is not None:
                processes[pid].append(item)
                ppid = normalize_pid(item.get("ppid"))
                if ppid is not None:
                    children[ppid].add(pid)
    return ProvenanceData(nodes, dict(processes), dict(children), edges)


def _find_lineage(
    root_pid: int,
    anchor_time: float,
    processes: Mapping[int, list[dict[str, str]]],
    children: Mapping[int, set[int]],
    horizon_seconds: float,
    max_depth: int,
) -> tuple[set[int], list[dict[str, Any]]]:
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


def extract_incident_from_data(
    provenance: ProvenanceData,
    attack: Mapping[str, str],
    attack_index: int,
    *,
    lineage_horizon_seconds: float = 300.0,
    max_lineage_depth: int = 3,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, str]], list[dict[str, Any]]]:
    """Extract one attack from already loaded provenance data."""
    attack_pid = normalize_pid(attack.get("PID"))
    attack_time = numeric(attack.get("Time of Attack"))
    if attack_pid is None or attack_time is None:
        raise ValueError("selected attack must have an integer PID and numeric Time of Attack")

    nodes = provenance.nodes
    processes = provenance.processes
    root_nodes = processes.get(attack_pid, [])
    root_times = [time for node in root_nodes if (time := entity_time(node)) is not None]
    if not root_nodes or not root_times:
        raise ValueError(f"no timestamped Process nodes match PID {attack_pid}")
    anchor_time = min(root_times, key=lambda time: abs(time - attack_time))
    selected_pids, inferred = _find_lineage(
        attack_pid,
        anchor_time,
        processes,
        provenance.children,
        lineage_horizon_seconds,
        max_lineage_depth,
    )
    process_ids = {node["id"] for pid in selected_pids for node in processes[pid]}

    observed = [
        edge
        for edge in provenance.edges
        if edge["from"] in process_ids or edge["to"] in process_ids
    ]
    incident_ids = set(process_ids)
    for edge in observed:
        incident_ids.update((edge["from"], edge["to"]))

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
