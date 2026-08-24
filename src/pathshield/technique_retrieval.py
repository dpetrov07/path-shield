"""Load, store, and search the curated MITRE ATT&CK corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from pathshield.vector import (
    EMBEDDING_MODEL,
    PROJECT_ROOT,
    ensure_vector_index,
    text_snippet,
)

DEFAULT_CORPUS_PATH = PROJECT_ROOT / "data" / "mitre" / "techniques.json"
TECHNIQUE_VECTOR_INDEX_NAME = "mitre_technique_embedding"
TECHNIQUE_CORPUS_NAME = "pathshield_mitre_v1"


@dataclass(frozen=True)
class Technique:
    attack_id: str
    name: str
    tactic: str
    description: str
    source_url: str

    @property
    def document_text(self) -> str:
        return f"{self.name}. Tactic: {self.tactic}. {self.description}"


def load_corpus(path: Path = DEFAULT_CORPUS_PATH) -> list[Technique]:
    """Load and validate the deliberately small retrieval corpus."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not 10 <= len(raw) <= 20:
        raise ValueError("The curated corpus must contain 10 to 20 techniques")

    required = {"attack_id", "name", "tactic", "description", "source_url"}
    techniques: list[Technique] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError(f"Corpus item {index} must contain exactly {sorted(required)}")
        if not all(isinstance(item[field], str) and item[field].strip() for field in required):
            raise ValueError(f"Corpus item {index} contains an empty or non-string field")
        if not item["source_url"].startswith("https://attack.mitre.org/techniques/"):
            raise ValueError(f"Corpus item {index} does not use an official ATT&CK technique URL")
        techniques.append(Technique(**item))

    attack_ids = [technique.attack_id for technique in techniques]
    if len(attack_ids) != len(set(attack_ids)):
        raise ValueError("ATT&CK IDs must be unique")
    return techniques


def index_techniques(
    driver: Any,
    database: str,
    techniques: Sequence[Technique],
    embeddings: Sequence[Sequence[float]],
) -> None:
    """Upsert the curated technique nodes and create their vector index."""
    if len(techniques) != len(embeddings):
        raise ValueError("Each technique must have one embedding")

    driver.execute_query(
        "CREATE CONSTRAINT mitre_technique_id IF NOT EXISTS "
        "FOR (technique:MitreTechnique) REQUIRE technique.attack_id IS UNIQUE",
        database_=database,
    )
    rows = [
        {
            "attack_id": technique.attack_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "description": technique.description,
            "source_url": technique.source_url,
            "document_text": technique.document_text,
            "embedding": list(embedding),
        }
        for technique, embedding in zip(techniques, embeddings, strict=True)
    ]
    driver.execute_query(
        """
        UNWIND $rows AS row
        MERGE (technique:MitreTechnique {attack_id: row.attack_id})
        SET technique.name = row.name,
            technique.tactic = row.tactic,
            technique.description = row.description,
            technique.source_url = row.source_url,
            technique.document_text = row.document_text,
            technique.embedding = row.embedding,
            technique.embedding_model = $embedding_model,
            technique.corpus = $corpus
        """,
        rows=rows,
        embedding_model=EMBEDDING_MODEL,
        corpus=TECHNIQUE_CORPUS_NAME,
        database_=database,
    )
    ensure_vector_index(
        driver, database, TECHNIQUE_VECTOR_INDEX_NAME, "MitreTechnique"
    )


def query_techniques(driver: Any, database: str, embedding: Sequence[float], top_k: int) -> list[dict[str, Any]]:
    """Return the closest technique nodes from the Neo4j vector index."""
    records, _, _ = driver.execute_query(
        f"""
        CYPHER 25
        MATCH (node:MitreTechnique)
        SEARCH node IN (
            VECTOR INDEX {TECHNIQUE_VECTOR_INDEX_NAME}
            FOR $embedding
            LIMIT $top_k
        ) SCORE AS score
        RETURN node.attack_id AS attack_id,
               node.name AS name,
               node.tactic AS tactic,
               node.description AS description,
               node.source_url AS source_url,
               score
        ORDER BY score DESC
        """,
        top_k=top_k,
        embedding=list(embedding),
        database_=database,
    )
    return [record.data() for record in records]


def format_technique_results(results: Sequence[dict[str, Any]]) -> str:
    if not results:
        return "No matching techniques found. Has the corpus been indexed?"
    lines = []
    for rank, result in enumerate(results, start=1):
        lines.append(
            f"{rank}. {result['attack_id']} {result['name']} — {float(result['score']):.3f}\n"
            f"   Tactic: {result['tactic']}\n"
            f"   {text_snippet(result['description'])}"
        )
    return "\n".join(lines)
