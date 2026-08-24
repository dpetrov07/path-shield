"""Index and query PathShield incidents and MITRE ATT&CK together."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pathshield.incident_retrieval import (
    DEFAULT_ATTACK_INFO_PATH,
    DEFAULT_PROVENANCE_PATH,
    build_incident_documents,
    format_incident_results,
    index_incidents,
    query_incidents,
    sparse_incidents,
)
from pathshield.technique_retrieval import (
    DEFAULT_CORPUS_PATH,
    format_technique_results,
    index_techniques,
    load_corpus,
    query_techniques,
)
from pathshield.vector import create_embeddings, neo4j_driver, openai_client


def dual_retrieval(
    driver: Any, database: str, query_embedding: Sequence[float], top_k: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Search both corpora with the same query embedding."""
    return (
        query_incidents(driver, database, query_embedding, top_k),
        query_techniques(driver, database, query_embedding, top_k),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--index", action="store_true", help="index both retrieval corpora")
    action.add_argument("--query", help="plain-English suspicious behavior to search for")
    parser.add_argument("--top-k", type=int, default=5, help="results per corpus (default: 5)")
    parser.add_argument("--provenance", type=Path, default=DEFAULT_PROVENANCE_PATH, help=argparse.SUPPRESS)
    parser.add_argument("--attack-info", type=Path, default=DEFAULT_ATTACK_INFO_PATH, help=argparse.SUPPRESS)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.top_k <= 10:
        raise SystemExit("--top-k must be between 1 and 10")
    if args.query is not None and not args.query.strip():
        raise SystemExit("--query must not be empty")

    try:
        client = openai_client()
        driver, database = neo4j_driver()
        with driver:
            if args.index:
                incidents = build_incident_documents(args.provenance, args.attack_info)
                techniques = load_corpus(args.corpus)
                texts = [item.document_text for item in incidents] + [
                    item.document_text for item in techniques
                ]
                embeddings = create_embeddings(client, texts)
                split = len(incidents)
                index_incidents(driver, database, incidents, embeddings[:split])
                index_techniques(driver, database, techniques, embeddings[split:])
                print(
                    f"Indexed {len(incidents)} PathShield incidents and "
                    f"{len(techniques)} MITRE ATT&CK techniques in Neo4j."
                )
                sparse = sparse_incidents(incidents)
                if sparse:
                    print(
                        "Sparse incident documents: "
                        + ", ".join(str(item.attack_index) for item in sparse)
                    )
                return 0

            query_embedding = create_embeddings(client, [args.query])[0]
            incidents, techniques = dual_retrieval(
                driver, database, query_embedding, args.top_k
            )
            print("Closest PathShield incidents:")
            print(format_incident_results(incidents))
            print("\nRelevant MITRE ATT&CK techniques:")
            print(format_technique_results(techniques))
            return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
