from __future__ import annotations

import csv
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from pathshield.attack_investigation import (
    decode_embedded_command,
    investigate_attack,
    write_graphml,
)


COLUMNS = [
    "id", "type", "from", "to", "uid", "egid", "exe", "gid", "euid",
    "name", "pid", "seen time", "source", "ppid", "command line", "start time",
    "event id", "time", "operation", "path", "subtype", "permissions", "epoch",
    "version", "flags", "local address", "remote port", "protocol", "remote address",
    "local port", "tgid", "fd", "mode", "label", "subLabel",
]


class AttackInvestigationTests(unittest.TestCase):
    def test_decodes_observed_command_wrapper(self) -> None:
        self.assertEqual(
            decode_embedded_command('sh -c eval "$(echo ZWNobyBoaQ== | base64 --decode)"'),
            "echo hi",
        )
        self.assertIsNone(decode_embedded_command("echo ordinary text"))

    def test_investigates_pid_lineage_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = root / "provenance.csv"
            attacks = root / "attacks.csv"
            rows = [
                {"id": "root_seen", "type": "Process", "pid": "10.0", "ppid": "1.0", "seen time": "100.0", "name": "sh", "label": "1", "subLabel": "lateralMovement"},
                {"id": "root_exec", "type": "Process", "pid": "10.0", "ppid": "1.0", "start time": "100.0", "name": "sh", "command line": "sh -c test", "label": "1", "subLabel": "lateralMovement"},
                {"id": "child_seen", "type": "Process", "pid": "11.0", "ppid": "10.0", "seen time": "105.0", "name": "ssh", "label": "1", "subLabel": "lateralMovement"},
                {"id": "child_exec", "type": "Process", "pid": "11.0", "ppid": "10.0", "start time": "105.0", "name": "ssh", "command line": "ssh host", "label": "1", "subLabel": "lateralMovement"},
                {"id": "binary", "type": "Artifact", "path": "/usr/bin/sh", "subtype": "file", "label": "0", "subLabel": "0"},
                {"id": "socket", "type": "Artifact", "subtype": "network socket", "remote address": "10.0.0.2", "remote port": "22.0", "label": "0", "subLabel": "0"},
                {"type": "WasTriggeredBy", "from": "root_exec", "to": "root_seen", "event id": "1.0", "time": "100.0", "operation": "execve", "label": "0", "subLabel": "0"},
                {"type": "Used", "from": "root_exec", "to": "binary", "event id": "1.0", "time": "100.0", "operation": "load", "label": "0", "subLabel": "0"},
                {"type": "WasTriggeredBy", "from": "child_exec", "to": "child_seen", "event id": "2.0", "time": "105.0", "operation": "execve", "label": "0", "subLabel": "0"},
                {"type": "WasGeneratedBy", "from": "socket", "to": "child_exec", "event id": "3.0", "time": "106.0", "operation": "connect", "label": "0", "subLabel": "0"},
            ]
            with provenance.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            with attacks.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Time of Attack", "Tactic Name", "Technique Name", "PID", "readable_time"])
                writer.writeheader()
                writer.writerow({"Time of Attack": "90", "Tactic Name": "lateral movement", "Technique Name": "ssh", "PID": "10", "readable_time": "1970-01-01 00:01:30"})

            report, nodes, edges, relations = investigate_attack(provenance, attacks, 0)
            graphml = root / "result.graphml"
            write_graphml(graphml, nodes, edges, relations)
            ET.parse(graphml)

        self.assertEqual(report["matching_processes"]["node_count"], 2)
        self.assertEqual(report["timestamp_discrepancy"]["provenance_minus_attack_seconds"], 10.0)
        self.assertEqual([item["pid"] for item in report["process_lineage"]["child_processes"]], [11])
        self.assertEqual(report["local_neighborhood"]["node_count"], 6)
        self.assertEqual(report["local_neighborhood"]["edge_count"], 4)
        self.assertEqual(len(report["local_neighborhood"]["network_artifacts"]), 1)
        self.assertEqual(len(report["local_neighborhood"]["artifacts_generated"]), 1)
        self.assertEqual(report["process_identity_investigation"]["was_triggered_by_different_pid_edges"], 0)


if __name__ == "__main__":
    unittest.main()

