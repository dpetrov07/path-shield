"""Focused reconstruction of one known attack in the provenance data."""

from __future__ import annotations

import base64
import csv
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .inspection import classify_record

DEFAULT_RADII_SECONDS = (60.0, 300.0, 900.0, 3600.0)
BASE64_COMMAND = re.compile(r"echo\s+([A-Za-z0-9+/=]+)\s*\|\s*base64\s+--decode")


def normalize_pid(value: str | None) -> int | None:
    """Normalize integer-like PID strings such as ``152566.0``."""
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


def iso_utc(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def entity_time(node: Mapping[str, str]) -> float | None:
    """Return the populated process timestamp without equating its semantics."""
    return numeric(node.get("start time")) or numeric(node.get("seen time"))


def compact(row: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in row.items() if value}


def decode_embedded_command(command_line: str | None) -> str | None:
    """Decode the dataset's observed ``echo BASE64 | base64 --decode`` wrapper."""
    if not command_line:
        return None
    match = BASE64_COMMAND.search(command_line)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _load_attacks(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _load_entities(
    path: Path,
) -> tuple[
    dict[str, dict[str, str]],
    dict[int, list[dict[str, str]]],
    dict[int, set[int]],
]:
    nodes: dict[str, dict[str, str]] = {}
    processes_by_pid: dict[int, list[dict[str, str]]] = defaultdict(list)
    children_by_ppid: dict[int, set[int]] = defaultdict(set)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            if classify_record(row) != "node":
                continue
            item = compact(row)
            item["csv_line"] = str(line_number)
            nodes[row["id"]] = item
            if row["type"] != "Process":
                continue
            pid = normalize_pid(row.get("pid"))
            if pid is None:
                continue
            processes_by_pid[pid].append(item)
            ppid = normalize_pid(row.get("ppid"))
            if ppid is not None:
                children_by_ppid[ppid].add(pid)
    return nodes, processes_by_pid, children_by_ppid


def _process_group(pid: int, nodes: Iterable[Mapping[str, str]]) -> dict[str, Any]:
    records = list(nodes)
    return {
        "pid": pid,
        "node_count": len(records),
        "ppids": sorted(
            {value for node in records if (value := normalize_pid(node.get("ppid"))) is not None}
        ),
        "timestamps": sorted(
            {value for node in records if (value := entity_time(node)) is not None}
        ),
        "nodes": [
            {
                **dict(node),
                "entity_time": entity_time(node),
                "entity_time_utc": iso_utc(entity_time(node)),
                "derived_decoded_payload": decode_embedded_command(node.get("command line")),
            }
            for node in records
        ],
    }


def _lineage(
    root_pid: int,
    anchor_time: float,
    processes_by_pid: Mapping[int, list[dict[str, str]]],
    children_by_ppid: Mapping[int, set[int]],
    horizon_seconds: float,
    max_depth: int,
) -> tuple[list[list[int]], list[dict[str, Any]]]:
    levels: list[list[int]] = []
    relations: list[dict[str, Any]] = []
    seen = {root_pid}
    frontier = {root_pid}
    for depth in range(1, max_depth + 1):
        candidates = {
            child for parent in frontier for child in children_by_ppid.get(parent, set())
        } - seen
        accepted: set[int] = set()
        for child_pid in candidates:
            times = [
                value
                for node in processes_by_pid.get(child_pid, [])
                if (value := entity_time(node)) is not None
            ]
            if times and anchor_time - 1.0 <= min(times) <= anchor_time + horizon_seconds:
                accepted.add(child_pid)
                parent_pids = {
                    normalize_pid(node.get("ppid"))
                    for node in processes_by_pid.get(child_pid, [])
                }
                for parent_pid in sorted(pid for pid in parent_pids if pid in frontier):
                    relations.append(
                        {
                            "parent_pid": parent_pid,
                            "child_pid": child_pid,
                            "depth": depth,
                            "evidence": "Process.ppid equals another selected Process.pid",
                            "relationship_kind": "inferred_pid_lineage",
                        }
                    )
        levels.append(sorted(accepted))
        if not accepted:
            break
        seen.update(accepted)
        frontier = accepted
    return levels, relations


def _empty_window(name: str, center_kind: str, start: float, end: float) -> dict[str, Any]:
    return {
        "name": name,
        "center_kind": center_kind,
        "start": start,
        "end": end,
        "start_utc": iso_utc(start),
        "end_utc": iso_utc(end),
        "edge_count": 0,
        "node_ids": set(),
        "labeled_edge_count": 0,
        "lineage_edge_count": 0,
    }


def _add_edge_to_window(
    window: dict[str, Any], row: Mapping[str, str], lineage_ids: set[str]
) -> None:
    event_time = numeric(row.get("time"))
    if event_time is None or not window["start"] <= event_time <= window["end"]:
        return
    window["edge_count"] += 1
    window["node_ids"].update((row["from"], row["to"]))
    window["labeled_edge_count"] += int(row.get("label") == "1")
    window["lineage_edge_count"] += int(
        row["from"] in lineage_ids or row["to"] in lineage_ids
    )


def _finalize_window(
    window: dict[str, Any], nodes: Mapping[str, Mapping[str, str]], lineage_edge_total: int
) -> dict[str, Any]:
    node_ids = window.pop("node_ids")
    labeled = [node_id for node_id in node_ids if nodes[node_id].get("label") == "1"]
    network = [
        node_id for node_id in node_ids if nodes[node_id].get("subtype") == "network socket"
    ]
    window.update(
        {
            "duration_seconds": window["end"] - window["start"],
            "node_count": len(node_ids),
            "labeled_node_count": len(labeled),
            "labeled_node_sublabel_counts": dict(
                Counter(nodes[node_id].get("subLabel", "") for node_id in labeled)
            ),
            "network_artifact_count": len(network),
            "lineage_edge_total": lineage_edge_total,
            "lineage_edge_coverage": (
                window["lineage_edge_count"] / lineage_edge_total
                if lineage_edge_total
                else 0.0
            ),
        }
    )
    return window


def _pairing_summary(
    processes_by_pid: Mapping[int, list[dict[str, str]]],
    same_pid_triggered_edges: int,
    different_pid_triggered_edges: int,
) -> dict[str, Any]:
    size_counts = Counter(len(records) for records in processes_by_pid.values())
    two_record_groups = [records for records in processes_by_pid.values() if len(records) == 2]
    same_timestamp = 0
    complementary_timestamps = 0
    same_core_attributes = 0
    core = ("uid", "egid", "exe", "gid", "euid", "name", "pid", "ppid", "label", "subLabel")
    for records in two_record_groups:
        times = [entity_time(node) for node in records]
        same_timestamp += int(times[0] == times[1])
        complementary_timestamps += int(
            sum(bool(node.get("seen time")) for node in records) == 1
            and sum(bool(node.get("start time")) for node in records) == 1
        )
        same_core_attributes += int(
            all(records[0].get(key) == records[1].get(key) for key in core)
        )
    return {
        "unique_process_pids": len(processes_by_pid),
        "process_node_count": sum(len(records) for records in processes_by_pid.values()),
        "nodes_per_pid_counts": {str(key): value for key, value in sorted(size_counts.items())},
        "two_node_pid_groups": len(two_record_groups),
        "two_node_groups_with_same_timestamp": same_timestamp,
        "two_node_groups_with_one_seen_and_one_start_time": complementary_timestamps,
        "two_node_groups_with_same_core_attributes": same_core_attributes,
        "was_triggered_by_same_pid_edges": same_pid_triggered_edges,
        "was_triggered_by_different_pid_edges": different_pid_triggered_edges,
        "interpretation": (
            "The same-PID WasTriggeredBy pattern, complementary timestamps, and state-changing "
            "operations support interpreting multiple IDs as process-state/execution-version "
            "entities rather than ordinary OS parent/child processes. The exact producer semantics "
            "remain undocumented."
        ),
    }


def investigate_attack(
    provenance_path: Path,
    attack_info_path: Path,
    attack_index: int,
    *,
    lineage_horizon_seconds: float = 300.0,
    max_lineage_depth: int = 3,
) -> tuple[dict[str, Any], dict[str, dict[str, str]], list[dict[str, str]], list[dict[str, Any]]]:
    """Investigate one zero-based attack row and return report plus GraphML inputs."""
    attacks = _load_attacks(attack_info_path)
    if not 0 <= attack_index < len(attacks):
        raise IndexError(f"attack index {attack_index} is outside 0..{len(attacks) - 1}")
    attack = attacks[attack_index]
    attack_pid = normalize_pid(attack.get("PID"))
    attack_time = numeric(attack.get("Time of Attack"))
    if attack_pid is None or attack_time is None:
        raise ValueError("selected attack must contain an integer PID and numeric Time of Attack")

    nodes, processes_by_pid, children_by_ppid = _load_entities(provenance_path)
    matches = processes_by_pid.get(attack_pid, [])
    if not matches:
        raise ValueError(f"no Process nodes match PID {attack_pid}")
    match_times = [value for node in matches if (value := entity_time(node)) is not None]
    if not match_times:
        raise ValueError(f"matching Process nodes for PID {attack_pid} have no timestamp")
    anchor_time = min(match_times, key=lambda value: abs(value - attack_time))

    levels, pid_lineage = _lineage(
        attack_pid,
        anchor_time,
        processes_by_pid,
        children_by_ppid,
        lineage_horizon_seconds,
        max_lineage_depth,
    )
    lineage_pids = {attack_pid, *(pid for level in levels for pid in level)}
    lineage_ids = {
        node["id"] for pid in lineage_pids for node in processes_by_pid.get(pid, [])
    }
    anchor_ids = {node["id"] for node in matches}

    windows = []
    for center_name, center in (("metadata", attack_time), ("provenance_process", anchor_time)):
        for radius in DEFAULT_RADII_SECONDS:
            windows.append(
                _empty_window(
                    f"{center_name}_plus_minus_{int(radius)}s",
                    center_name,
                    center - radius,
                    center + radius,
                )
            )

    local_edges: list[dict[str, str]] = []
    anchor_neighbors: set[str] = set(anchor_ids)
    same_pid_triggered = 0
    different_pid_triggered = 0
    with provenance_path.open(newline="", encoding="utf-8-sig") as handle:
        for line_number, row in enumerate(csv.DictReader(handle), start=2):
            if classify_record(row) != "edge":
                continue
            for window in windows:
                _add_edge_to_window(window, row, lineage_ids)
            if row["from"] in lineage_ids or row["to"] in lineage_ids:
                edge = compact(row)
                edge["csv_line"] = str(line_number)
                local_edges.append(edge)
            if row["from"] in anchor_ids or row["to"] in anchor_ids:
                anchor_neighbors.update((row["from"], row["to"]))
            if row["type"] == "WasTriggeredBy":
                source_pid = normalize_pid(nodes[row["from"]].get("pid"))
                destination_pid = normalize_pid(nodes[row["to"]].get("pid"))
                if source_pid == destination_pid:
                    same_pid_triggered += 1
                else:
                    different_pid_triggered += 1

    local_times = [numeric(edge.get("time")) for edge in local_edges]
    valid_local_times = [value for value in local_times if value is not None]
    envelope_start = min(valid_local_times) if valid_local_times else anchor_time
    envelope_end = max(valid_local_times) if valid_local_times else anchor_time
    extra_windows = [
        _empty_window(
            "lineage_event_envelope",
            "lineage_structure",
            envelope_start,
            envelope_end,
        ),
        _empty_window(
            "metadata_to_lineage_bridge",
            "metadata_and_lineage",
            min(attack_time, envelope_start),
            max(attack_time, envelope_end),
        ),
    ]
    depth_two_nodes = set(anchor_neighbors)
    depth_two_edge_count = 0
    with provenance_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if classify_record(row) != "edge":
                continue
            for window in extra_windows:
                _add_edge_to_window(window, row, lineage_ids)
            if row["from"] in anchor_neighbors or row["to"] in anchor_neighbors:
                depth_two_edge_count += 1
                depth_two_nodes.update((row["from"], row["to"]))
    windows.extend(extra_windows)
    finalized_windows = [
        _finalize_window(window, nodes, len(local_edges)) for window in windows
    ]

    local_node_ids = set(lineage_ids)
    for edge in local_edges:
        local_node_ids.update((edge["from"], edge["to"]))
    local_nodes = {node_id: nodes[node_id] for node_id in sorted(local_node_ids)}
    used_ids = {
        edge["to"]
        for edge in local_edges
        if edge["type"] == "Used" and edge["from"] in lineage_ids
    }
    generated_ids = {
        edge["from"]
        for edge in local_edges
        if edge["type"] == "WasGeneratedBy" and edge["to"] in lineage_ids
    }
    network_ids = {
        node_id
        for node_id, node in local_nodes.items()
        if node.get("subtype") == "network socket"
    }
    labeled_node_ids = {
        node_id for node_id, node in local_nodes.items() if node.get("label") == "1"
    }
    labeled_edges = [edge for edge in local_edges if edge.get("label") == "1"]

    parent_pids = sorted(
        {
            value for node in matches if (value := normalize_pid(node.get("ppid"))) is not None
        }
    )
    parent_groups = [
        {
            **_process_group(parent_pid, processes_by_pid.get(parent_pid, [])),
            "resolution": "matched Process nodes" if parent_pid in processes_by_pid else "PID referenced by ppid but no Process node exists",
        }
        for parent_pid in parent_pids
    ]
    child_groups = [
        {
            "depth": depth,
            **_process_group(pid, processes_by_pid[pid]),
        }
        for depth, level in enumerate(levels, start=1)
        for pid in level
    ]

    try:
        readable = datetime.strptime(attack.get("readable_time", ""), "%Y-%m-%d %H:%M:%S")
        readable_offset = (readable - datetime.fromtimestamp(attack_time, tz=timezone.utc).replace(tzinfo=None)).total_seconds()
    except ValueError:
        readable_offset = None
    deltas = [value - attack_time for value in match_times]
    relationship_counts = Counter(
        f"{edge['type']}:{edge.get('operation', '<missing>')}" for edge in local_edges
    )
    stored_direction_counts = {
        "edges_outgoing_from_lineage_nodes": sum(
            edge["from"] in lineage_ids for edge in local_edges
        ),
        "edges_incoming_to_lineage_nodes": sum(
            edge["to"] in lineage_ids for edge in local_edges
        ),
        "note": (
            "An edge between two lineage nodes contributes to both counts; these are stored from/to "
            "directions, not inferred causal or OS-parent directions."
        ),
    }

    report: dict[str, Any] = {
        "report_version": 1,
        "selection": {
            "attack_index_zero_based": attack_index,
            "reason": (
                "Selected because it is the dataset's only explicit lateral-movement record and "
                "its command and PID lineage contain scp/ssh remote-access steps."
            ),
        },
        "attack_metadata": attack,
        "attack_time": {"epoch": attack_time, "utc": iso_utc(attack_time)},
        "matching_processes": _process_group(attack_pid, matches),
        "timestamp_discrepancy": {
            "closest_provenance_process_time": anchor_time,
            "closest_provenance_process_time_utc": iso_utc(anchor_time),
            "provenance_minus_attack_seconds": anchor_time - attack_time,
            "all_matching_process_deltas_seconds": deltas,
            "readable_time_minus_epoch_utc_seconds_when_both_are_treated_as_naive": readable_offset,
            "observed_conclusion": "The metadata timestamp is not the execution timestamp for this PID.",
            "unresolved": "The intended meaning/timezone of attack_info timestamps is not documented.",
        },
        "process_lineage": {
            "method": (
                "Exact integer PID match for the root, then Process.ppid -> Process.pid within "
                f"[{anchor_time - 1.0}, {anchor_time + lineage_horizon_seconds}] to depth {max_lineage_depth}."
            ),
            "parent_processes": parent_groups,
            "child_processes": child_groups,
            "pid_relations": pid_lineage,
        },
        "process_identity_investigation": _pairing_summary(
            processes_by_pid, same_pid_triggered, different_pid_triggered
        ),
        "local_neighborhood": {
            "scope": "all provenance edges incident to root or selected PID/PPID-descendant Process IDs",
            "node_count": len(local_nodes),
            "process_node_count": sum(node.get("type") == "Process" for node in local_nodes.values()),
            "artifact_node_count": sum(node.get("type") == "Artifact" for node in local_nodes.values()),
            "edge_count": len(local_edges),
            "relationship_operation_counts": dict(sorted(relationship_counts.items())),
            "stored_direction_counts": stored_direction_counts,
            "process_nodes": [local_nodes[node_id] for node_id in sorted(lineage_ids)],
            "files_or_artifacts_used": [nodes[node_id] for node_id in sorted(used_ids)],
            "artifacts_generated": [nodes[node_id] for node_id in sorted(generated_ids)],
            "network_artifacts": [nodes[node_id] for node_id in sorted(network_ids)],
            "labeled_nodes": [nodes[node_id] for node_id in sorted(labeled_node_ids)],
            "labeled_edges": labeled_edges,
            "provenance_edges": local_edges,
        },
        "unconstrained_graph_traversal": {
            "anchor_node_count": len(anchor_ids),
            "one_hop_node_count": len(anchor_neighbors),
            "two_hop_node_count": len(depth_two_nodes),
            "two_hop_incident_edge_count": depth_two_edge_count,
            "observed_conclusion": (
                "Shared executable/loader Artifact IDs act as hubs, so unconstrained hop traversal "
                "quickly mixes unrelated activity from across the capture."
            ),
        },
        "candidate_temporal_windows": finalized_windows,
        "recommended_strategy": {
            "strategy": "provenance-anchored lineage envelope with small padding",
            "details": (
                "Anchor on the same-PID Process timestamp, follow PID/PPID descendants, then use "
                "their observed incident-edge envelope (40.302 seconds here), optionally padded to "
                "about +/-60 seconds for context. Preserve the metadata timestamp as annotation only."
            ),
            "why": (
                "Metadata-centered windows under one hour miss this PID; a metadata-to-process bridge "
                "admits substantial unrelated activity; unconstrained graph hops cross shared artifacts."
            ),
        },
        "observed_evidence": [
            "The selected PID has two labeled lateralMovement Process entities at the same provenance timestamp.",
            "The encoded command decodes to scp and ssh actions targeting 172.16.64.128.",
            "PID/PPID links identify labeled scp/ssh descendants during the following 40.302 seconds.",
            "All dataset WasTriggeredBy edges connect Process nodes with the same PID, not parent and child PIDs.",
            "No network-socket Artifact is directly adjacent to the selected lineage despite the remote commands.",
        ],
        "assumptions": [
            "Integer-equal PID/PPID values within five minutes represent OS parent/child lineage.",
            "A Process node's populated start time or seen time is its relevant entity timestamp.",
            "Used Process -> Artifact denotes an artifact used by the process; WasGeneratedBy Artifact -> Process denotes output attributed to the process.",
        ],
        "unresolved_questions": [
            "The exact semantic distinction and lifecycle order of seen-time and start-time Process IDs is undocumented.",
            "PID 4127 is referenced as the attack shell's parent but has no Process entity in this capture.",
            "The provenance has no direct network Artifact for the observed scp/ssh lineage.",
            "The metadata timestamp source, timezone, and intended relationship to execution time remain unknown.",
            "Host/session scope and PID-reuse guarantees remain undocumented.",
            "Attack labels occur on Process nodes while the incident relationship rows are unlabeled; propagation rules are unknown.",
        ],
    }
    return report, local_nodes, local_edges, pid_lineage


def _canonical_process_id(nodes: Mapping[str, Mapping[str, str]], pid: int) -> str | None:
    candidates = [node_id for node_id, node in nodes.items() if normalize_pid(node.get("pid")) == pid]
    if not candidates:
        return None
    return next(
        (node_id for node_id in candidates if nodes[node_id].get("command line")),
        candidates[0],
    )


def write_graphml(
    path: Path,
    nodes: Mapping[str, Mapping[str, str]],
    provenance_edges: Iterable[Mapping[str, str]],
    pid_relations: Iterable[Mapping[str, Any]],
) -> None:
    """Write the small local graph, marking inferred PID edges separately."""
    namespace = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", namespace)
    root = ET.Element(f"{{{namespace}}}graphml")
    keys = {
        "node_type": ("node", "string"),
        "label": ("all", "string"),
        "subLabel": ("node", "string"),
        "pid": ("node", "string"),
        "ppid": ("node", "string"),
        "name": ("node", "string"),
        "path": ("node", "string"),
        "relationship": ("edge", "string"),
        "operation": ("edge", "string"),
        "time": ("edge", "string"),
        "evidence": ("edge", "string"),
    }
    for key_id, (scope, attr_type) in keys.items():
        ET.SubElement(
            root,
            f"{{{namespace}}}key",
            id=key_id,
            **{"for": scope, "attr.name": key_id, "attr.type": attr_type},
        )
    graph = ET.SubElement(root, f"{{{namespace}}}graph", edgedefault="directed")
    for node_id, node in nodes.items():
        element = ET.SubElement(graph, f"{{{namespace}}}node", id=node_id)
        values = {
            "node_type": node.get("type", ""),
            "label": node.get("label", ""),
            "subLabel": node.get("subLabel", ""),
            "pid": node.get("pid", ""),
            "ppid": node.get("ppid", ""),
            "name": node.get("name", ""),
            "path": node.get("path", ""),
        }
        for key, value in values.items():
            if value:
                ET.SubElement(element, f"{{{namespace}}}data", key=key).text = value
    edge_number = 0
    for edge in provenance_edges:
        element = ET.SubElement(
            graph,
            f"{{{namespace}}}edge",
            id=f"e{edge_number}",
            source=edge["from"],
            target=edge["to"],
        )
        edge_number += 1
        values = {
            "label": edge.get("label", ""),
            "relationship": edge.get("type", ""),
            "operation": edge.get("operation", ""),
            "time": edge.get("time", ""),
            "evidence": "observed provenance edge",
        }
        for key, value in values.items():
            if value:
                ET.SubElement(element, f"{{{namespace}}}data", key=key).text = value
    for relation in pid_relations:
        source = _canonical_process_id(nodes, int(relation["parent_pid"]))
        target = _canonical_process_id(nodes, int(relation["child_pid"]))
        if source is None or target is None:
            continue
        element = ET.SubElement(
            graph,
            f"{{{namespace}}}edge",
            id=f"e{edge_number}",
            source=source,
            target=target,
        )
        edge_number += 1
        for key, value in {
            "relationship": "inferred_pid_lineage",
            "evidence": relation["evidence"],
        }.items():
            ET.SubElement(element, f"{{{namespace}}}data", key=key).text = str(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
