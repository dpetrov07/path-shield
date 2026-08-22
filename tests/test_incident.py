from __future__ import annotations

import csv
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from pathshield.incident import decode_embedded_command, extract_incident, write_graphml

COLUMNS = [
    "id", "type", "from", "to", "uid", "egid", "exe", "gid", "euid",
    "name", "pid", "seen time", "source", "ppid", "command line", "start time",
    "event id", "time", "operation", "path", "subtype", "permissions", "epoch",
    "version", "flags", "local address", "remote port", "protocol", "remote address",
    "local port", "tgid", "fd", "mode", "label", "subLabel",
]


class IncidentTests(unittest.TestCase):
    def test_decodes_observed_command_wrapper(self) -> None:
        command = 'sh -c eval "$(echo ZWNobyBoaQ== | base64 --decode)"'
        self.assertEqual(decode_embedded_command(command), "echo hi")
        self.assertIsNone(decode_embedded_command("echo ordinary text"))

    def test_extracts_bounded_lineage_and_writes_graphml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = root / "provenance.csv"
            attacks = root / "attacks.csv"
            rows = [
                {"id": "root_seen", "type": "Process", "pid": "10.0", "ppid": "1.0", "seen time": "100.0", "name": "sh"},
                {"id": "root_exec", "type": "Process", "pid": "10.0", "ppid": "1.0", "start time": "100.0", "name": "sh", "command line": "sh -c test"},
                {"id": "child_seen", "type": "Process", "pid": "11.0", "ppid": "10.0", "seen time": "105.0", "name": "ssh"},
                {"id": "child_exec", "type": "Process", "pid": "11.0", "ppid": "10.0", "start time": "105.0", "name": "ssh", "command line": "ssh host"},
                {"id": "binary", "type": "Artifact", "path": "/usr/bin/sh", "subtype": "file"},
                {"id": "socket", "type": "Artifact", "subtype": "network socket", "remote address": "10.0.0.2"},
                {"type": "WasTriggeredBy", "from": "root_exec", "to": "root_seen", "time": "100.0", "operation": "execve"},
                {"type": "Used", "from": "root_exec", "to": "binary", "time": "100.0", "operation": "load"},
                {"type": "WasTriggeredBy", "from": "child_exec", "to": "child_seen", "time": "105.0", "operation": "execve"},
                {"type": "WasGeneratedBy", "from": "socket", "to": "child_exec", "time": "106.0", "operation": "connect"},
            ]
            with provenance.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            with attacks.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Time of Attack", "Tactic Name", "Technique Name", "PID"])
                writer.writeheader()
                writer.writerow({"Time of Attack": "90", "Tactic Name": "lateral movement", "Technique Name": "ssh", "PID": "10"})

            report, nodes, observed, inferred = extract_incident(provenance, attacks, 0)
            graphml = root / "result.graphml"
            write_graphml(graphml, nodes, observed, inferred)
            ET.parse(graphml)

        self.assertEqual(report["anchor_process"]["provenance_minus_metadata_seconds"], 10.0)
        self.assertEqual([item["child_pid"] for item in inferred], [11])
        self.assertEqual(report["incident_graph"]["node_count"], 6)
        self.assertEqual(report["incident_graph"]["observed_relationship_count"], 4)


if __name__ == "__main__":
    unittest.main()
