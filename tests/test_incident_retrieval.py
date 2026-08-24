from __future__ import annotations

import unittest

from pathshield.incident_retrieval import (
    INCIDENT_VECTOR_INDEX_NAME,
    build_incident_document,
)
from pathshield.retrieval import dual_retrieval
from pathshield.technique_retrieval import TECHNIQUE_VECTOR_INDEX_NAME


class _Record:
    def __init__(self, data):
        self._data = data

    def data(self):
        return self._data


class _Driver:
    def __init__(self):
        self.calls = []

    def execute_query(self, query, **parameters):
        self.calls.append((query, parameters))
        if INCIDENT_VECTOR_INDEX_NAME in query:
            return [_Record({"attack_index": 44})], None, None
        return [_Record({"attack_id": "T1570"})], None, None


class IncidentRetrievalTests(unittest.TestCase):
    def test_document_is_deterministic_and_removes_common_noise(self) -> None:
        report = {
            "attack": {
                "index_zero_based": 44,
                "metadata": {
                    "Tactic Name": "lateral movement",
                    "Technique Name": "start sandcat",
                },
            },
            "anchor_process": {"pid": 100},
            "incident_graph": {"node_count": 6, "observed_relationship_count": 2},
        }
        nodes = {
            "process-seen": {
                "id": "process-seen", "type": "Process", "name": "scp",
                "pid": "100.0", "entity_time": 1.0,
            },
            "process-exec": {
                "id": "process-exec", "type": "Process", "name": "scp",
                "pid": "100.0", "entity_time": 1.0,
                "command line": "scp payload host:/tmp/payload",
            },
            "child": {
                "id": "child", "type": "Process", "name": "ssh",
                "pid": "101.0", "entity_time": 2.0,
                "command line": "ssh host chmod +x /tmp/payload",
            },
            "loader": {"id": "loader", "type": "Artifact", "path": "/lib64/ld-linux-x86-64.so.2"},
            "executable": {"id": "executable", "type": "Artifact", "path": "/usr/bin/scp"},
            "payload": {"id": "payload", "type": "Artifact", "path": "/tmp/payload"},
        }
        observed = [
            {"type": "Used", "operation": "load"},
            {"type": "Used", "operation": "load"},
        ]
        inferred = [{"parent_pid": 100, "child_pid": 101, "depth": 1}]

        first = build_incident_document(report, nodes, observed, inferred)
        second = build_incident_document(report, nodes, observed, inferred)

        self.assertEqual(first, second)
        self.assertIn("Processes: scp; ssh", first.document_text)
        self.assertIn("scp payload host:/tmp/payload", first.document_text)
        self.assertIn("Artifacts and paths: /tmp/payload", first.document_text)
        self.assertIn("Process lineage: scp -> ssh", first.document_text)
        self.assertEqual(first.document_text.count("Used (load)"), 1)
        self.assertNotIn("ld-linux", first.document_text)
        self.assertNotIn("/usr/bin/scp", first.document_text)
        self.assertNotIn("process-seen", first.document_text)

    def test_dual_query_reuses_embedding_for_both_vector_indexes(self) -> None:
        driver = _Driver()
        embedding = [0.1, 0.2]

        incidents, techniques = dual_retrieval(driver, "neo4j", embedding, 3)

        self.assertEqual(incidents, [{"attack_index": 44}])
        self.assertEqual(techniques, [{"attack_id": "T1570"}])
        self.assertEqual(len(driver.calls), 2)
        self.assertEqual(
            {name for query, _ in driver.calls for name in (INCIDENT_VECTOR_INDEX_NAME, TECHNIQUE_VECTOR_INDEX_NAME) if name in query},
            {INCIDENT_VECTOR_INDEX_NAME, TECHNIQUE_VECTOR_INDEX_NAME},
        )
        self.assertTrue(all(call[1]["embedding"] == embedding for call in driver.calls))
        self.assertTrue(all(call[1]["top_k"] == 3 for call in driver.calls))


if __name__ == "__main__":
    unittest.main()
