# PathShield

PathShield provides semantic retrieval over CICAPT-IIoT2024 incidents and MITRE ATT&CK techniques.

## Current Workflow
- extracts bounded incident evidence for all 58 attack rows
- builds deterministic incident documents from processes, commands, paths, and relationships
- turns PathShield incidents and MITRE ATT&CK information into searchable vectors
- stores them in separate Neo4j vector indexes
- searches both indexes with one plain-English query
- formats the retrieved results as labeled context for a future generated answer.

## Data

Place the read-only source files in `data/raw/`:

- `Phase2_Provenance.csv`
- `attack_info.csv`

## How it works

During indexing, PathShield reads the provenance data, constructs a retrieval document per attack, embeds those documents and the MITRE corpus, and stores both collections in Neo4j.

During a query, the input text is embedded. Neo4j uses that vector to independently find the nearest PathShield incidents and MITRE techniques. The results retain their identifiers, metadata, similarity scores, and evidence text so they can be converted into clearly sourced prompt context.

## Retrieval

Install the client libraries and add the credentials to a `.env` file in the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

```dotenv
OPENAI_API_KEY=your_openai_key
NEO4J_PASSWORD=your_neo4j_password
```

`NEO4J_URI`, `NEO4J_USERNAME`, and `NEO4J_DATABASE` optionally override the defaults `neo4j://localhost:7687`, `neo4j`, and `neo4j`.

Build the 58 PathShield incident documents, then embed and index both those documents and the curated ATT&CK corpus:

```bash
python3 src/pathshield/retrieval.py --index
```

Search both indexes with one plain-English query:

```bash
python3 src/pathshield/retrieval.py --query "copies a payload over scp and executes it with ssh" --top-k 5
```

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
