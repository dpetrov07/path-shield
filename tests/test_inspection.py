from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from pathshield.inspection import ColumnProfile, classify_record, inspect_dataset


PROVENANCE_COLUMNS = [
    "id", "type", "from", "to", "pid", "seen time", "start time", "time",
    "operation", "subtype", "label", "subLabel", "source",
]


class InspectionTests(unittest.TestCase):
    def test_record_classification(self) -> None:
        self.assertEqual(classify_record({"id": "n1", "from": "", "to": ""}), "node")
        self.assertEqual(classify_record({"id": "", "from": "n1", "to": "n2"}), "edge")
        self.assertEqual(classify_record({"id": "n1", "from": "n2", "to": ""}), "ambiguous")

    def test_dtype_inference_and_missing_values(self) -> None:
        profile = ColumnProfile()
        for value in ("1.0", "2.5", ""):
            profile.add(value)
        self.assertEqual(profile.inferred_dtype(), "float")
        self.assertAlmostEqual(profile.as_dict(3)["missing_rate"], 1 / 3, places=6)

    def test_streamed_summary_and_pid_linkage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = root / "provenance.csv"
            attack_info = root / "attack.csv"
            rows = [
                {"id": "p1", "type": "Process", "pid": "42.0", "start time": "101.5", "label": "1", "subLabel": "collection", "source": "syscall"},
                {"id": "a1", "type": "Artifact", "subtype": "file", "label": "0", "subLabel": "0", "source": "syscall"},
                {"type": "Used", "from": "p1", "to": "a1", "time": "101.5", "operation": "load", "label": "1", "subLabel": "collection", "source": "syscall"},
            ]
            with provenance.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=PROVENANCE_COLUMNS)
                writer.writeheader()
                writer.writerows(rows)
            with attack_info.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Time of Attack", "Tactic Name", "Technique Name", "PID", "readable_time"])
                writer.writeheader()
                writer.writerow({"Time of Attack": "100", "Tactic Name": "collection", "Technique Name": "stage", "PID": "42", "readable_time": "x"})

            summary = inspect_dataset(provenance, attack_info)

        provenance_summary = summary["provenance_file"]
        self.assertEqual(provenance_summary["record_counts"], {"node": 2, "edge": 1})
        self.assertEqual(provenance_summary["endpoint_integrity"]["missing_referenced_node_count"], 0)
        self.assertEqual(provenance_summary["timestamps"]["time"]["min"], 101.5)
        linkage = summary["attack_info_file"]["provenance_linkage"]
        self.assertEqual(linkage["matched_attack_rows"], 1)
        self.assertEqual(linkage["closest_process_time_delta_seconds"]["median"], 1.5)


if __name__ == "__main__":
    unittest.main()
