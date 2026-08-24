from __future__ import annotations

import unittest
from unittest.mock import patch

from pathshield.evaluate_retrieval import (
    EVALUATION_CASES,
    EvaluationCase,
    EvaluationResult,
    evaluate_retrieval,
    format_evaluation,
)


class RetrievalEvaluationTests(unittest.TestCase):
    def test_hand_written_cases_are_small_and_complete(self) -> None:
        self.assertGreaterEqual(len(EVALUATION_CASES), 10)
        self.assertLessEqual(len(EVALUATION_CASES), 15)
        self.assertEqual(len({case.query for case in EVALUATION_CASES}), len(EVALUATION_CASES))
        self.assertTrue(all(case.expected_incidents for case in EVALUATION_CASES))
        self.assertTrue(all(case.expected_techniques for case in EVALUATION_CASES))

    def test_evaluation_batches_embeddings_and_scores_expected_results(self) -> None:
        cases = (
            EvaluationCase("remote transfer", frozenset({44}), frozenset({"T1570"})),
            EvaluationCase("local account", frozenset({35}), frozenset({"T1136.001"})),
        )
        retrieved = [
            ([{"attack_index": 44}], [{"attack_id": "T1570"}]),
            ([{"attack_index": 49}, {"attack_index": 35}], [{"attack_id": "T1136.001"}]),
        ]
        with (
            patch("pathshield.evaluate_retrieval.create_embeddings", return_value=[[0.1], [0.2]]) as embeddings,
            patch("pathshield.evaluate_retrieval.dual_retrieval", side_effect=retrieved) as retrieval,
        ):
            results = evaluate_retrieval(object(), object(), "neo4j", cases)

        embeddings.assert_called_once_with(unittest.mock.ANY, [case.query for case in cases])
        self.assertEqual(retrieval.call_count, 2)
        self.assertTrue(results[0].incident_top_1)
        self.assertFalse(results[1].incident_top_1)
        self.assertTrue(results[1].incident_top_2)
        self.assertTrue(results[1].technique_top_2)

        report = format_evaluation(results)
        self.assertIn("Expected incident in top 1: 1/2 (50%)", report)
        self.assertIn("Expected incident in top 2: 2/2 (100%)", report)
        self.assertIn("Expected MITRE technique in top 2: 2/2 (100%)", report)

    def test_empty_evaluation_report(self) -> None:
        self.assertEqual(format_evaluation([]), "No evaluation cases were run.")


if __name__ == "__main__":
    unittest.main()
