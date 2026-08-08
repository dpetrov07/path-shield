#!/usr/bin/env python3
"""Investigate one attack_info row against the local provenance graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pathshield.attack_investigation import investigate_attack, write_graphml


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attack-index",
        type=int,
        default=44,
        help="Zero-based attack_info.csv row index (default: 44, start sandcat)",
    )
    parser.add_argument("--provenance", type=Path, default=Path("data/raw/Phase2_Provenance.csv"))
    parser.add_argument("--attack-info", type=Path, default=Path("data/raw/attack_info.csv"))
    parser.add_argument("--output", type=Path, help="JSON path; default is derived from index and PID")
    parser.add_argument("--graphml", type=Path, help="GraphML path; default is derived from index and PID")
    parser.add_argument("--lineage-horizon-seconds", type=float, default=300.0)
    parser.add_argument("--max-lineage-depth", type=int, default=3)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report, nodes, edges, pid_relations = investigate_attack(
        args.provenance,
        args.attack_info,
        args.attack_index,
        lineage_horizon_seconds=args.lineage_horizon_seconds,
        max_lineage_depth=args.max_lineage_depth,
    )
    pid = report["matching_processes"]["pid"]
    stem = f"attack_{args.attack_index:03d}_pid_{pid}"
    output = args.output or Path("data/processed") / f"{stem}.json"
    graphml = args.graphml or Path("data/processed") / f"{stem}.graphml"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_graphml(graphml, nodes, edges, pid_relations)
    print(f"Wrote {output}")
    print(f"Wrote {graphml}")
    print(
        f"Attack {args.attack_index}: PID {pid}; "
        f"matching Process nodes={report['matching_processes']['node_count']}; "
        f"local nodes={report['local_neighborhood']['node_count']}; "
        f"local edges={report['local_neighborhood']['edge_count']}"
    )
    print(
        "Timestamp delta (provenance - metadata): "
        f"{report['timestamp_discrepancy']['provenance_minus_attack_seconds']:.3f}s"
    )


if __name__ == "__main__":
    main()

