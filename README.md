# PathShield

PathShield extracts focused incident graphs from the CICAPT-IIoT2024 provenance dataset.

## Data

Place the read-only source files in `data/raw/`:

- `Phase2_Provenance.csv`
- `attack_info.csv`

## Run

The default is attack row 44:

```bash
python3 src/pathshield/incident.py
```

Select another zero-based attack row with:

```bash
python3 src/pathshield/incident.py --attack-index N
```

Each run writes one JSON report and one GraphML file to `data/processed/`. Observed provenance relationships remain separate from inferred PID/PPID lineage.

## Neo4j

GraphML exports include `Process` and `Artifact` labels and named relationship types. Import with APOC using:

```cypher
CALL apoc.import.graphml("file.graphml", {readLabels: true});
```

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
