# PathShield

PathShield provides semantic retrieval over CICAPT-IIoT2024 incidents and MITRE ATT&CK techniques.

## Current Workflow
- extracts bounded incident evidence for all 58 attack rows
- builds deterministic incident documents from processes, commands, paths, and relationships
- turns PathShield incidents and MITRE ATT&CK information into searchable vectors
- stores them in separate Neo4j vector indexes
- searches both indexes with one plain-English query
- retrieves scoped Process, Artifact, and relationship evidence for the top incidents
- uses the retrieved evidence to generate a grounded answer with OpenAI

## Dataset

Download the Phase 2 provenance CSV and `Attack_info.csv` from the [official CICAPT-IIoT2024 dataset page](https://www.unb.ca/cic/datasets/iiot-dataset-2024.html). The raw files are not committed; place them in `data/raw/` as:

- `Phase2_Provenance.csv`
- `attack_info.csv`

Created by the Canadian Institute for Cybersecurity (CIC), University of New Brunswick. Citation: Erfan Ghiasvand, Suprio Ray, Shahrear Iqbal, Sajjad Dadkhah, and Ali A. Ghorbani, “CICAPT-IIOT: A provenance-based APT attack dataset for IIoT environment,” 2024.

## How it works

During indexing, PathShield reads the provenance data once, constructs a retrieval document and scoped graph for each attack, embeds the documents and MITRE corpus, and stores everything in Neo4j.

During a query, the input text is embedded. Neo4j finds the nearest PathShield incidents and MITRE techniques, then loads graph evidence for the two closest incidents. The results are formatted as sourced context that can be sent to an OpenAI model for a grounded answer.

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
python3 src/pathshield/retrieval.py --query "copies a payload over scp and executes it with ssh"
```

Add `--answer` to generate an answer from the retrieved evidence:

```bash
python3 src/pathshield/retrieval.py --query "copies a payload over scp and executes it with ssh" --answer
```

## Evaluation

Retrieval quality is checked with 13 manually curated, reworded behavior descriptions mapped to expected PathShield attack indexes and MITRE technique IDs. Top 1 and top 2 use only Neo4j embedding cosine similarity; the LLM is not involved. Some cases allow multiple incident IDs for repeated behavior. This is a retrieval sanity check, not formal ground truth or unknown-attack detection.

Current results: incident top 1 `12/13` (92%), incident top 2 `13/13` (100%), and MITRE top 2 `12/13` (92%).

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
