"""Shared OpenAI embedding and Neo4j connection helpers."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).parents[2]
EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536


def create_embeddings(client: Any, texts: Sequence[str]) -> list[list[float]]:
    """Create one embedding per text in one API request."""
    response = client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=list(texts),
        dimensions=EMBEDDING_DIMENSIONS,
    )
    embeddings = [item.embedding for item in sorted(response.data, key=lambda item: item.index)]
    if len(embeddings) != len(texts):
        raise RuntimeError("The embeddings response did not contain one vector per input")
    if any(len(embedding) != EMBEDDING_DIMENSIONS for embedding in embeddings):
        raise RuntimeError(f"Expected {EMBEDDING_DIMENSIONS}-dimension vectors")
    return embeddings


def _load_environment() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError as error:
        raise RuntimeError("Install dependencies with: python3 -m pip install -e .") from error
    load_dotenv(PROJECT_ROOT / ".env")


def openai_client() -> Any:
    """Create an OpenAI client using the project .env file."""
    _load_environment()
    try:
        from openai import OpenAI
    except ImportError as error:
        raise RuntimeError("Install dependencies with: python3 -m pip install -e .") from error
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required in .env")
    return OpenAI(api_key=api_key)


def neo4j_driver() -> tuple[Any, str]:
    """Connect to Neo4j using the project .env file."""
    _load_environment()
    try:
        from neo4j import GraphDatabase
    except ImportError as error:
        raise RuntimeError("Install dependencies with: python3 -m pip install -e .") from error
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        raise RuntimeError("NEO4J_PASSWORD is required in .env")
    driver = GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "neo4j://localhost:7687"),
        auth=(os.environ.get("NEO4J_USERNAME", "neo4j"), password),
    )
    try:
        driver.verify_connectivity()
    except Exception as error:
        driver.close()
        raise RuntimeError(
            "Could not connect to Neo4j. Make sure the database is running and .env is correct."
        ) from error
    return driver, os.environ.get("NEO4J_DATABASE", "neo4j")


def wait_for_index(driver: Any, database: str, index_name: str) -> None:
    """Wait up to 30 seconds for a vector index to become queryable."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        records, _, _ = driver.execute_query(
            "SHOW VECTOR INDEXES YIELD name, state WHERE name = $name RETURN state",
            name=index_name,
            database_=database,
        )
        if records and records[0]["state"] == "ONLINE":
            return
        time.sleep(0.25)
    raise TimeoutError(f"Vector index {index_name!r} did not become ONLINE")


def ensure_vector_index(
    driver: Any, database: str, index_name: str, node_label: str
) -> None:
    """Create a cosine embedding index if needed and wait until it is ready."""
    driver.execute_query(
        f"""
        CREATE VECTOR INDEX {index_name} IF NOT EXISTS
        FOR (node:{node_label}) ON (node.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: {EMBEDDING_DIMENSIONS},
            `vector.similarity_function`: 'cosine'
        }}}}
        """,
        database_=database,
    )
    wait_for_index(driver, database, index_name)


def text_snippet(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
