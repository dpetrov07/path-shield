#!/usr/bin/env python3
"""Command-line entry point for PathShield's streaming dataset inspector."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pathshield import inspect_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provenance",
        type=Path,
        default=Path("data/raw/Phase2_Provenance.csv"),
        help="Path to the read-only provenance CSV",
    )
    parser.add_argument(
        "--attack-info",
        type=Path,
        default=Path("data/raw/attack_info.csv"),
        help="Path to the read-only attack metadata CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/schema_summary.json"),
        help="Destination for the machine-readable report",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = inspect_dataset(args.provenance, args.attack_info)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    provenance = summary["provenance_file"]
    linkage = summary["attack_info_file"]["provenance_linkage"]
    print(f"Wrote {args.output}")
    print(
        f"Rows: {provenance['total_rows']:,} "
        f"(nodes={provenance['record_counts'].get('node', 0):,}, "
        f"edges={provenance['record_counts'].get('edge', 0):,}, "
        f"ambiguous={provenance['record_counts'].get('ambiguous', 0):,})"
    )
    print(f"Node types: {provenance['node_type_counts']}")
    print(f"Relationship types: {provenance['relationship_type_counts']}")
    print(
        "Attack PID linkage: "
        f"{linkage['matched_attack_rows']}/{summary['attack_info_file']['row_count']} rows; "
        f"exact timestamp matches={linkage['exact_attack_to_process_timestamp_matches']}"
    )


if __name__ == "__main__":
    main()

