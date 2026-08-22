# PathShield

PathShield is a small cybersecurity GraphRAG learning project using the CICAPT-IIoT2024 provenance dataset. The current milestone extracts understandable incident graphs; Neo4j and retrieval come next.

## Current workflow

The extractor links an `attack_info.csv` row to Process records by PID, follows nearby PID/PPID descendants, and collects their directly adjacent provenance relationships. Observed dataset relationships remain separate from inferred process lineage.

The default example is zero-based attack row 44 (`start sandcat`, PID `152566`). It produces a 14-node graph with 15 observed relationships and 4 inferred lineage relationships, exported as JSON and GraphML under `data/processed/`.

```bash
python3 src/pathshield/incident.py
python3 src/pathshield/incident.py --attack-index N
```

Run the tests with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Python 3.11+ is required; there are no third-party runtime dependencies.

## Local dataset files

Place these read-only files in `data/raw/`:

- `Phase2_Provenance.csv` — mixed Process/Artifact entity rows and provenance relationship rows.
- `attack_info.csv` — attack timestamps, tactics, techniques, and PIDs.
- `Node2Vec final.ipynb` — reference notebook supplied alongside the dataset; PathShield does not run or depend on it.

The Node2Vec notebook is earlier experimental research, not part of the current pipeline. It loads the full provenance CSV, builds a NetworkX graph, creates 64-dimensional Node2Vec embeddings from random walks, and feeds those embeddings into a PyCaret attack-label classifier. It contains an author-specific path (`/home/erfan/...`) and saved execution output, so it will not run locally without modification and several large dependencies.

`data/raw/` is ignored by Git. The repository therefore cannot establish whether that notebook was downloaded, copied from a dataset bundle, or added manually; it has never been committed here.

## Graph interpretation

- Entity rows have `id`; relationship rows have `from` and `to`.
- Observed entity types are `Process` and `Artifact`.
- Observed relationships include `Used`, `WasGeneratedBy`, `WasTriggeredBy`, and `WasDerivedFrom`.
- Stored relationship names and directions are preserved exactly.
- `inferred_pid_lineage` is derived from bounded PID/PPID matching and is never presented as an observed edge.
- Timestamp meaning, paired Process identities, host scope, PID reuse, and label propagation remain partly undocumented.

The completed schema inspection is preserved in `data/processed/schema_summary.json`.

## Next milestone

Import several bounded incident graphs into Neo4j, preserve raw fields and evidence type, and add simple Cypher examples for lineage, bounded traversal, shortest paths, temporal filters, shared entities, and high-degree-hub exclusion. Vector retrieval and grounded LLM answers come afterward.
