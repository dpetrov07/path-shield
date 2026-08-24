from __future__ import annotations

import unittest

from pathshield.graph_retrieval import (
    format_graph_evidence,
    index_incident_graphs,
    retrieve_graph_evidence,
)
from pathshield.incident_retrieval import IncidentGraph


class _Record:
    def __init__(self, values):
        self.values = values

    def data(self):
        return self.values


class _Driver:
    def __init__(self):
        self.calls = []

    def execute_query(self, query, **parameters):
        self.calls.append((query, parameters))
        if "MATCH (node)" in query:
            return [
                _Record({
                    "attack_index": 44,
                    "original_id": "sh",
                    "node_type": "Process",
                    "process_name": "sh",
                    "pid": "152566",
                    "ppid": "4127",
                    "command_line": "sh -c scp payload host:/tmp",
                    "path": None,
                    "timestamp": "100",
                }),
                _Record({
                    "attack_index": 44,
                    "original_id": "scp",
                    "node_type": "Process",
                    "process_name": "scp",
                    "pid": "152570",
                    "ppid": "152566",
                    "command_line": "scp payload host:/tmp",
                    "path": None,
                    "timestamp": "101",
                }),
                _Record({
                    "attack_index": 99,
                    "original_id": "unrelated",
                    "node_type": "Process",
                    "process_name": "curl",
                }),
            ], None, None
        return [
            _Record({
                "attack_index": 44,
                "source_id": "sh",
                "target_id": "scp",
                "relationship_type": "USED",
                "display_type": "USED",
                "provenance_type": "Used",
                "operation": "execute",
                "timestamp": "101",
                "evidence_kind": "observed",
                "evidence": "observed provenance relationship",
            }),
            _Record({
                "attack_index": 44,
                "source_id": "sh",
                "target_id": "scp",
                "relationship_type": "INFERRED_PID_LINEAGE",
                "display_type": "INFERRED_PID_LINEAGE",
                "provenance_type": "inferred_pid_lineage",
                "operation": None,
                "timestamp": None,
                "evidence_kind": "inferred",
                "evidence": "PPID matches PID",
            }),
            _Record({
                "attack_index": 99,
                "source_id": "unrelated",
                "target_id": "scp",
                "relationship_type": "USED",
                "evidence_kind": "observed",
            }),
        ], None, None


class _IndexDriver:
    def __init__(self):
        self.calls = []

    def execute_query(self, query, **parameters):
        self.calls.append((query, parameters))
        return [], None, None


class GraphRetrievalTests(unittest.TestCase):
    def test_indexes_scoped_observed_and_inferred_graph_data(self) -> None:
        driver = _IndexDriver()
        graph = IncidentGraph(
            attack_index=44,
            attack_pid=10,
            tactic="lateral movement",
            attack_description="start payload",
            nodes={
                "parent": {
                    "id": "parent", "type": "Process", "name": "sh",
                    "pid": "10.0", "ppid": "1.0", "command line": "sh run",
                    "entity_time": 100.0,
                },
                "child": {
                    "id": "child", "type": "Process", "name": "ssh",
                    "pid": "11.0", "ppid": "10.0", "command line": "ssh host",
                    "entity_time": 101.0,
                },
                "binary": {"id": "binary", "type": "Artifact", "path": "/usr/bin/ssh"},
            },
            observed=[{
                "from": "child", "to": "binary", "type": "Used",
                "operation": "load", "time": "101.0",
            }],
            inferred=[{
                "parent_pid": 10, "child_pid": 11,
                "evidence": "child PPID equals parent PID",
            }],
        )

        counts = index_incident_graphs(driver, "neo4j", [graph])

        self.assertEqual(counts, (3, 2))
        self.assertTrue(any("DETACH DELETE" in query for query, _ in driver.calls))
        rows = [
            row
            for _, parameters in driver.calls
            for row in parameters.get("rows", [])
        ]
        self.assertTrue(all(
            value.startswith("attack_044:")
            for row in rows
            for key, value in row.items()
            if key in {"graph_id", "source_graph_id", "target_graph_id"}
        ))
        queries = "\n".join(query for query, _ in driver.calls)
        self.assertIn("relationship:USED", queries)
        self.assertIn("relationship:INFERRED_PID_LINEAGE", queries)

    def test_retrieval_stays_scoped_and_excludes_unrelated_relationships(self) -> None:
        driver = _Driver()

        evidence = retrieve_graph_evidence(driver, "neo4j", [44])

        self.assertEqual([item["attack_index"] for item in evidence], [44])
        self.assertEqual(
            [item["process_name"] for item in evidence[0]["processes"]],
            ["sh", "scp"],
        )
        self.assertEqual(len(evidence[0]["observed_relationships"]), 1)
        self.assertEqual(len(evidence[0]["inferred_lineage"]), 1)
        self.assertEqual(len(driver.calls), 2)
        self.assertTrue(all(call[1]["attack_indexes"] == ["44"] for call in driver.calls))
        self.assertIn("toString(node.attack_index) IN $attack_indexes", driver.calls[0][0])
        self.assertIn(
            "toString(source.attack_index) = toString(relationship.attack_index)",
            driver.calls[1][0],
        )
        self.assertIn(
            "toString(target.attack_index) = toString(relationship.attack_index)",
            driver.calls[1][0],
        )

    def test_graph_evidence_formatting(self) -> None:
        evidence = retrieve_graph_evidence(_Driver(), "neo4j", [44])

        formatted = format_graph_evidence(evidence)

        self.assertIn("Attack 44 graph evidence", formatted)
        self.assertIn("sh (PID 152566)", formatted)
        self.assertIn("scp payload host:/tmp", formatted)
        self.assertIn("Observed", formatted)
        self.assertIn("USED", formatted)
        self.assertIn("Inferred lineage", formatted)
        self.assertIn("INFERRED_PID_LINEAGE", formatted)


if __name__ == "__main__":
    unittest.main()
