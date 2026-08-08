# PathShield

PathShield is an incremental cybersecurity research project for temporal provenance analysis of multi-stage attacks. This first milestone only inspects the CICAPT-IIoT2024 schema; it does not build a graph or train a model.

## Dataset layout

Place the authors' files in `data/raw/`:

- `Phase2_Provenance.csv`
- `attack_info.csv`
- `Node2Vec final.ipynb` (reference only)

Raw inputs are read-only and ignored by Git. The generated, versionable report is `data/processed/schema_summary.json`.

## Run the inspector

Python 3.11 or newer is required. The inspector uses only the standard library and streams the provenance CSV row by row.

```bash
python src/inspect_data.py
```

Optional paths are available through `--provenance`, `--attack-info`, and `--output`.

Run tests with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Observed schema

`Phase2_Provenance.csv` is a heterogeneous table containing both graph entities and relationships:

- Node rows have an `id` and empty `from`/`to`. Observed node types are `Process` and `Artifact`.
- Edge rows have empty `id` and populated `from`/`to`. Observed relationship types are `WasGeneratedBy`, `Used`, `WasTriggeredBy`, and `WasDerivedFrom`.
- Every observed edge endpoint resolves to an observed node ID. The authors' notebook independently uses `from` as source and `to` as target in a directed multigraph.

All observed endpoint signatures are consistent: `Used` is Process → Artifact, `WasGeneratedBy` is Artifact → Process, `WasTriggeredBy` is Process → Process, and `WasDerivedFrom` is Artifact → Artifact. These are stored directions; their causal interpretation still needs validation.

Important fields, based on values and record placement:

| Field(s) | Evidence-backed interpretation |
|---|---|
| `id` | Opaque 32-character entity identifier on node rows. |
| `from`, `to` | Opaque source and destination entity references on edge rows. |
| `type` | Overloaded discriminator: entity type on node rows and relationship type on edge rows. |
| `time` | Relationship event time, represented as fractional Unix epoch seconds. |
| `seen time`, `start time` | Process-entity timestamps in Unix epoch seconds. Their precise semantic distinction is not documented. |
| `pid`, `ppid`, `tgid` | Process-style identifiers. `pid` is mainly on Process rows but also appears on `WasDerivedFrom`; `tgid` is rare. |
| `operation` | Edge action such as `load`, `execve`, `unlink`, `connect`, or rename variants. |
| `event id` | Numeric identifier shared by one or more relationship rows; uniqueness and scope remain undocumented. |
| `subtype` | Artifact category (`file`, `network socket`, `link`, `directory`, `unknown`). |
| `path`, network fields, permissions | Artifact-specific attributes; network sockets use address/port/protocol fields. |
| `uid`, `euid`, `gid`, `egid`, `exe`, `name`, `command line` | Process-specific attributes, following familiar operating-system naming conventions. Exact collection semantics are not documented. |
| `label`, `subLabel` | Dataset annotations (`0`/`1` and attack-stage-like values). These are observed labels, not predictions. |
| `source` | `syscall` on every row in this file. |

Process executions commonly appear as two distinct `Process` entities with the same PID and attributes: one has `seen time`, while the other has `start time` plus `command line`; a `WasTriggeredBy` edge connects them. This pattern is observed, but the authors do not document the identities represented by the pair.

## Connecting attack metadata

`attack_info.csv` contains attack time, tactic, technique, and PID. All metadata PIDs can be matched after normalizing provenance PIDs such as `4437.0` to integers. That makes PID the strongest observed candidate linkage to `Process` entities.

It is not safe to join on exact `(PID, timestamp)`: the metadata attack time does not exactly equal the matched Process `seen time`/`start time`, and the offsets vary. Tactic names also use different vocabularies in places (for example metadata `cleanup` versus provenance `defenceEvasion`, and `command and control` versus `CandC`). A future join policy must therefore preserve both sources and explicitly model time tolerance and tactic normalization.

The metadata `readable_time` is consistently four hours behind the UTC rendering of `Time of Attack` in the observed file. Its intended timezone is not declared, so the numeric epoch should remain canonical until that is confirmed.

## Known ambiguities before graph construction

- Confirm relationship direction and causal meaning for each relationship type, especially `WasGeneratedBy` and `WasDerivedFrom`.
- Determine why each process execution is represented by paired IDs and which identity should anchor a subgraph.
- Establish the provenance host/session scope and whether PID reuse is possible; there is no host column.
- Reconcile attack metadata times with provenance process/event times and choose a justified temporal window.
- Document `event id`, `epoch`, `version`, `tgid`, `fd`, and `mode` semantics and scope.
- Determine how `label` and `subLabel` were assigned or propagated to entities and relationships.
- Decide whether the four relationship names follow a standard provenance ontology or dataset-specific direction conventions.

The generated JSON records these ambiguities alongside full counts, missing rates, inferred lexical dtypes, examples, timestamp ranges, endpoint integrity, PID statistics, and attack-PID linkage evidence.

## Focused attack investigation

The second milestone investigates one known attack without creating a generic extraction pipeline. The default selection is zero-based attack row `44`: lateral movement / `start sandcat` / PID `152566`.

```bash
python src/investigate_attack.py
```

Use `--attack-index N` to investigate another metadata row. The command writes a detailed JSON report and a small GraphML file under `data/processed/`. GraphML contains observed provenance edges plus separately marked `inferred_pid_lineage` edges derived from PID/PPID equality.

For the selected record, the metadata time precedes the matching provenance Process time by `2900.151` seconds. The two same-PID Process IDs share that provenance timestamp and attack label; one carries `seen time`, while the other carries `start time` and a base64-wrapped command. Decoding—not executing—that payload reveals `scp` and `ssh` steps targeting `172.16.64.128`.

PID/PPID reconstruction finds three direct children and one grandchild: one `scp` and three `ssh` Process executions. Their provenance activity spans about 40.3 seconds, and all ten Process-state nodes are labeled `lateralMovement`. No directly adjacent network-socket Artifact was recorded, despite the explicit remote commands.

The most defensible investigative window is anchored on the matching provenance Process time, follows temporally nearby PID/PPID descendants, and uses their incident-edge time envelope with small padding (about ±60 seconds here). Exact metadata-centered windows under one hour miss the attack Process; bridging the full metadata-to-process gap admits substantial unrelated activity. Unconstrained graph traversal is also unsafe because shared executable and loader Artifact IDs become high-degree hubs.

See [`docs/attack_044_analysis.md`](docs/attack_044_analysis.md) for the evidence table, temporal-window comparison, assumptions, and unresolved questions.
