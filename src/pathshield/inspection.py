"""Streaming inspection for the mixed node/edge CICAPT provenance CSV."""

from __future__ import annotations

import csv
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

TIMESTAMP_COLUMNS = ("seen time", "start time", "time")


def _nonempty(value: str | None) -> bool:
    return bool(value and value.strip())


def _numeric(value: str) -> float | None:
    try:
        number = float(value)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def _pid(value: str) -> int | None:
    number = _numeric(value)
    if number is None or not number.is_integer():
        return None
    return int(number)


def _iso_utc(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def _compact_row(row: Mapping[str, str]) -> dict[str, str]:
    return {name: value for name, value in row.items() if _nonempty(value)}


@dataclass
class ColumnProfile:
    """Constant-memory missingness and lexical type inference for one column."""

    missing: int = 0
    non_missing: int = 0
    all_integer: bool = True
    all_float: bool = True

    def add(self, raw_value: str | None) -> None:
        if not _nonempty(raw_value):
            self.missing += 1
            return
        self.non_missing += 1
        value = raw_value.strip()  # type: ignore[union-attr]
        try:
            int(value)
        except ValueError:
            self.all_integer = False
        if _numeric(value) is None:
            self.all_float = False

    def inferred_dtype(self) -> str:
        if self.non_missing == 0:
            return "empty"
        if self.all_integer:
            return "integer"
        if self.all_float:
            return "float"
        return "string"

    def as_dict(self, total_rows: int) -> dict[str, Any]:
        return {
            "inferred_dtype": self.inferred_dtype(),
            "non_missing_count": self.non_missing,
            "missing_count": self.missing,
            "missing_rate": round(self.missing / total_rows, 6) if total_rows else 0.0,
        }


@dataclass
class TimestampProfile:
    count: int = 0
    invalid_count: int = 0
    minimum: float | None = None
    maximum: float | None = None

    def add(self, raw_value: str | None) -> None:
        if not _nonempty(raw_value):
            return
        value = _numeric(raw_value.strip())  # type: ignore[union-attr]
        if value is None:
            self.invalid_count += 1
            return
        self.count += 1
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "non_missing_numeric_count": self.count,
            "invalid_count": self.invalid_count,
            "unit_interpretation": "Unix epoch seconds (inferred)",
        }
        if self.minimum is not None and self.maximum is not None:
            result.update(
                {
                    "min": self.minimum,
                    "max": self.maximum,
                    "min_utc": _iso_utc(self.minimum),
                    "max_utc": _iso_utc(self.maximum),
                }
            )
        return result


def classify_record(row: Mapping[str, str]) -> str:
    """Classify a record by identifier/endpoint shape, without using type names."""
    has_id = _nonempty(row.get("id"))
    has_from = _nonempty(row.get("from"))
    has_to = _nonempty(row.get("to"))
    if has_id and not has_from and not has_to:
        return "node"
    if not has_id and has_from and has_to:
        return "edge"
    return "ambiguous"


def _load_attack_info(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        return list(reader.fieldnames or []), rows


def _sorted_counter(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _attack_summary(
    columns: list[str],
    attacks: list[dict[str, str]],
    attack_process_matches: Mapping[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    column_profiles = {column: ColumnProfile() for column in columns}
    for row in attacks:
        for column, profile in column_profiles.items():
            profile.add(row.get(column))
    missing = {
        column: sum(not _nonempty(row.get(column)) for row in attacks) for column in columns
    }
    tactic_counts = Counter(row.get("Tactic Name", "") for row in attacks)
    technique_counts = Counter(row.get("Technique Name", "") for row in attacks)
    pids = [_pid(row.get("PID", "")) for row in attacks]
    valid_pids = [pid for pid in pids if pid is not None]
    attack_times = [
        value
        for row in attacks
        if (value := _numeric(row.get("Time of Attack", ""))) is not None
    ]

    matched_rows = 0
    timestamp_exact_matches = 0
    deltas: list[float] = []
    tactic_to_sublabel: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    for attack in attacks:
        pid = _pid(attack.get("PID", ""))
        matches = attack_process_matches.get(pid, []) if pid is not None else []
        if matches:
            matched_rows += 1
        attack_time = _numeric(attack.get("Time of Attack", ""))
        observed_times = sorted(
            {
                float(match["entity_time"])
                for match in matches
                if match.get("entity_time") is not None
            }
        )
        if attack_time is not None and observed_times:
            closest = min(observed_times, key=lambda value: abs(value - attack_time))
            delta = closest - attack_time
            deltas.append(delta)
            timestamp_exact_matches += int(delta == 0)
        else:
            closest = None
            delta = None
        for match in matches:
            sublabel = str(match.get("subLabel", ""))
            tactic_to_sublabel[f"{attack.get('Tactic Name', '')} -> {sublabel}"] += 1
        if len(examples) < 5:
            examples.append(
                {
                    "attack": attack,
                    "matched_process_entity_ids": [match["id"] for match in matches],
                    "closest_process_time": closest,
                    "closest_process_time_delta_seconds": delta,
                }
            )

    time_range: dict[str, Any] = {}
    if attack_times:
        time_range = {
            "min": min(attack_times),
            "max": max(attack_times),
            "min_utc": _iso_utc(min(attack_times)),
            "max_utc": _iso_utc(max(attack_times)),
        }
    delta_stats: dict[str, Any] = {}
    if deltas:
        delta_stats = {
            "count": len(deltas),
            "min": min(deltas),
            "max": max(deltas),
            "median": statistics.median(deltas),
        }
    return {
        "columns": columns,
        "column_profiles": {
            column: profile.as_dict(len(attacks))
            for column, profile in column_profiles.items()
        },
        "row_count": len(attacks),
        "missing_counts": missing,
        "tactic_counts": _sorted_counter(tactic_counts),
        "technique_counts": _sorted_counter(technique_counts),
        "pid": {
            "valid_count": len(valid_pids),
            "unique_count": len(set(valid_pids)),
            "min": min(valid_pids) if valid_pids else None,
            "max": max(valid_pids) if valid_pids else None,
        },
        "timestamp_range": time_range,
        "provenance_linkage": {
            "candidate_key": "attack_info.PID == integer-normalized Process.pid",
            "matched_attack_rows": matched_rows,
            "unmatched_attack_rows": len(attacks) - matched_rows,
            "exact_attack_to_process_timestamp_matches": timestamp_exact_matches,
            "closest_process_time_delta_seconds": delta_stats,
            "tactic_to_process_sublabel_counts": _sorted_counter(tactic_to_sublabel),
            "examples": examples,
            "warning": (
                "PID matches are observed, but Time of Attack does not exactly match the "
                "matched Process seen/start time; do not use an exact composite PID/time join."
            ),
        },
    }


def inspect_dataset(provenance_path: Path, attack_info_path: Path) -> dict[str, Any]:
    """Inspect both source CSVs while streaming the large provenance file once."""
    attack_columns, attacks = _load_attack_info(attack_info_path)
    attack_pids = {
        pid for row in attacks if (pid := _pid(row.get("PID", ""))) is not None
    }

    total_rows = 0
    record_counts: Counter[str] = Counter()
    node_types: Counter[str] = Counter()
    edge_types: Counter[str] = Counter()
    operations: Counter[str] = Counter()
    subtypes: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    sublabels: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    event_ids: Counter[str] = Counter()
    examples: dict[str, list[dict[str, str]]] = defaultdict(list)
    node_ids: set[str] = set()
    node_type_by_id: dict[str, str] = {}
    referenced_ids: set[str] = set()
    pid_values: list[int] = []
    pid_by_record: Counter[str] = Counter()
    attack_process_matches: dict[int, list[dict[str, Any]]] = defaultdict(list)
    timestamp_profiles = {name: TimestampProfile() for name in TIMESTAMP_COLUMNS}

    with provenance_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        profiles = {name: ColumnProfile() for name in columns}
        required = {"id", "type", "from", "to", "pid", *TIMESTAMP_COLUMNS}
        missing_required = sorted(required - set(columns))
        if missing_required:
            raise ValueError(f"Missing required provenance columns: {missing_required}")

        for row in reader:
            total_rows += 1
            for name in columns:
                profiles[name].add(row.get(name))
            for name, profile in timestamp_profiles.items():
                profile.add(row.get(name))

            record_class = classify_record(row)
            record_counts[record_class] += 1
            record_type = row.get("type", "").strip() or "<missing>"
            if record_class == "node":
                node_types[record_type] += 1
                node_id = row["id"].strip()
                node_ids.add(node_id)
                node_type_by_id[node_id] = record_type
            elif record_class == "edge":
                edge_types[record_type] += 1
                referenced_ids.update((row["from"].strip(), row["to"].strip()))

            if len(examples[record_type]) < 2:
                examples[record_type].append(_compact_row(row))
            if _nonempty(row.get("operation")):
                operations[row["operation"].strip()] += 1
            if _nonempty(row.get("subtype")):
                subtypes[row["subtype"].strip()] += 1
            labels[row.get("label", "").strip() or "<missing>"] += 1
            sublabels[row.get("subLabel", "").strip() or "<missing>"] += 1
            sources[row.get("source", "").strip() or "<missing>"] += 1
            if _nonempty(row.get("event id")):
                event_ids[row["event id"].strip()] += 1

            pid = _pid(row.get("pid", ""))
            if pid is not None:
                pid_values.append(pid)
                pid_by_record[record_class] += 1
                if record_class == "node" and record_type == "Process" and pid in attack_pids:
                    entity_time = _numeric(row.get("start time", ""))
                    if entity_time is None:
                        entity_time = _numeric(row.get("seen time", ""))
                    attack_process_matches[pid].append(
                        {
                            "id": row["id"].strip(),
                            "entity_time": entity_time,
                            "subLabel": row.get("subLabel", ""),
                            "name": row.get("name", ""),
                        }
                    )

    missing_references = referenced_ids - node_ids
    unreferenced_nodes = node_ids - referenced_ids
    endpoint_signatures: Counter[str] = Counter()
    relationship_operations: Counter[str] = Counter()
    # A second streaming pass avoids retaining all 143k edges while resolving
    # endpoint entity types regardless of row order.
    with provenance_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            if classify_record(row) != "edge":
                continue
            relationship = row["type"].strip()
            source_type = node_type_by_id.get(row["from"].strip(), "<missing>")
            destination_type = node_type_by_id.get(row["to"].strip(), "<missing>")
            endpoint_signatures[
                f"{relationship}: {source_type} -> {destination_type}"
            ] += 1
            relationship_operations[
                f"{relationship}: {row.get('operation', '').strip() or '<missing>'}"
            ] += 1
    return {
        "format_version": 1,
        "provenance_file": {
            "path": str(provenance_path),
            "size_bytes": provenance_path.stat().st_size,
            "columns": columns,
            "column_profiles": {
                name: profile.as_dict(total_rows) for name, profile in profiles.items()
            },
            "total_rows": total_rows,
            "record_counts": dict(record_counts),
            "node_type_counts": _sorted_counter(node_types),
            "relationship_type_counts": _sorted_counter(edge_types),
            "operation_counts": _sorted_counter(operations),
            "relationship_operation_counts": _sorted_counter(relationship_operations),
            "relationship_endpoint_type_counts": _sorted_counter(endpoint_signatures),
            "artifact_subtype_counts": _sorted_counter(subtypes),
            "label_counts": _sorted_counter(labels),
            "subLabel_counts": _sorted_counter(sublabels),
            "source_counts": _sorted_counter(sources),
            "event_id_statistics": {
                "non_missing_count": sum(event_ids.values()),
                "unique_count": len(event_ids),
                "min_relationships_per_event_id": min(event_ids.values()) if event_ids else None,
                "max_relationships_per_event_id": max(event_ids.values()) if event_ids else None,
            },
            "timestamps": {name: profile.as_dict() for name, profile in timestamp_profiles.items()},
            "pid_statistics": {
                "non_missing_valid_count": len(pid_values),
                "unique_count": len(set(pid_values)),
                "min": min(pid_values) if pid_values else None,
                "max": max(pid_values) if pid_values else None,
                "record_class_counts": dict(pid_by_record),
            },
            "endpoint_integrity": {
                "unique_node_ids": len(node_ids),
                "unique_referenced_ids": len(referenced_ids),
                "missing_referenced_node_count": len(missing_references),
                "unreferenced_node_count": len(unreferenced_nodes),
                "missing_referenced_node_examples": sorted(missing_references)[:10],
                "unreferenced_node_examples": sorted(unreferenced_nodes)[:10],
            },
            "representative_examples": dict(examples),
            "classification_rule": {
                "node": "id present; from and to empty",
                "edge": "id empty; from and to present",
                "ambiguous": "any other id/from/to population pattern",
            },
        },
        "attack_info_file": {
            "path": str(attack_info_path),
            "size_bytes": attack_info_path.stat().st_size,
            **_attack_summary(attack_columns, attacks, attack_process_matches),
        },
        "ambiguities": [
            "The files contain no data dictionary, so field semantics are inferred from names and usage.",
            "The precise distinction between paired Process entities carrying seen time versus start time is undocumented.",
            "Time of Attack is not an exact match for the same-PID Process timestamp.",
            "attack_info.readable_time is four hours behind the UTC rendering of Time of Attack, but its intended timezone is undocumented.",
            "PID reuse scope and host identity are not documented; no host column is present.",
            "event id uniqueness/scope and the semantics of epoch, version, tgid, fd, and mode are undocumented.",
            "label/subLabel propagation rules across nodes and edges are not documented.",
            "Relationship direction is stored as from -> to, but the causal interpretation of each named relation should be validated before graph construction.",
        ],
    }
