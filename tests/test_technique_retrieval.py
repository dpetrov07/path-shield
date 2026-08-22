from __future__ import annotations

import unittest
from types import SimpleNamespace

from pathshield.vector import (
    EMBEDDING_DIMENSIONS,
    create_embeddings,
    text_snippet,
)
from pathshield.technique_retrieval import (
    format_technique_results,
    load_corpus,
)


class TechniqueRetrievalTests(unittest.TestCase):
    def test_curated_corpus_is_small_complete_and_unique(self) -> None:
        techniques = load_corpus()

        self.assertEqual(len(techniques), 17)
        self.assertEqual(len({item.attack_id for item in techniques}), len(techniques))
        self.assertIn("T1021.004", {item.attack_id for item in techniques})
        self.assertIn("T1570", {item.attack_id for item in techniques})
        self.assertTrue(all(item.source_url.startswith("https://attack.mitre.org/") for item in techniques))

    def test_embedding_response_is_reordered_by_input_index(self) -> None:
        first = [0.1] * EMBEDDING_DIMENSIONS
        second = [0.2] * EMBEDDING_DIMENSIONS
        response = SimpleNamespace(
            data=[
                SimpleNamespace(index=1, embedding=second),
                SimpleNamespace(index=0, embedding=first),
            ]
        )
        client = SimpleNamespace(
            embeddings=SimpleNamespace(create=lambda **_: response)
        )

        self.assertEqual(create_embeddings(client, ["first", "second"]), [first, second])

    def test_results_include_requested_fields_and_short_snippet(self) -> None:
        results = [
            {
                "attack_id": "T1570",
                "name": "Lateral Tool Transfer",
                "tactic": "Lateral Movement",
                "description": "x" * 150,
                "source_url": "https://attack.mitre.org/techniques/T1570/",
                "score": 0.8542,
            }
        ]

        output = format_technique_results(results)

        self.assertIn("1. T1570 Lateral Tool Transfer — 0.854", output)
        self.assertIn("Tactic: Lateral Movement", output)
        self.assertIn(text_snippet("x" * 150), output)
        self.assertLess(len(text_snippet("x" * 150)), 150)


if __name__ == "__main__":
    unittest.main()
