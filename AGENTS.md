# PathShield

PathShield is a cybersecurity research/project exploring temporal graph-based detection, forecasting, and containment of multi-stage APT attacks.

## Current Dataset

CICAPT-IIoT2024.

Files currently available include:
- `Phase2_Provenance.csv`
- `attack_info.csv`
- `Node2Vec final.ipynb`

Treat the dataset as read-only. Never modify raw files.

## Long-Term Goal

Build a system that can:

1. Represent system activity as a temporal provenance graph.
2. Detect suspicious attack-chain activity.
3. Compare conventional ML with graph-based ML.
4. Predict likely next steps in an unfolding attack.
5. Estimate the blast radius of suspected compromises.
6. Recommend containment actions that reduce predicted attack propagation while minimizing legitimate disruption.

These are long-term goals. Do NOT implement them all at once.

## Development Philosophy

Work incrementally and keep each milestone independently understandable and testable.

Do not introduce:
- Neo4j
- PyTorch
- GNNs
- React
- FastAPI
- cloud infrastructure

until the current task explicitly requires them.

Start with Python, pandas, NetworkX, scikit-learn, and simple visualizations.

## Dataset Rules

- Never commit raw dataset files.
- Add raw data directories and large generated artifacts to `.gitignore`.
- Do not assume column meanings.
- Infer schema from the actual files.
- Document ambiguities and assumptions.
- Avoid loading the entire dataset into memory when sampling/chunking is practical.

## Code Quality

- Python 3.11+
- Use type hints for reusable functions.
- Prefer small functions/modules over large scripts.
- Add docstrings where behavior is not obvious.
- Keep dependencies minimal.
- Add tests for parsing and transformation logic.
- Run relevant tests before finishing a task.

## Research Rules

Always distinguish between:
- observed facts from the dataset,
- assumptions,
- engineered features,
- model predictions.

Avoid data leakage, especially using future events to predict earlier events.

For ML evaluation, prefer temporal train/test splits rather than random splits when appropriate.

Always keep a simple baseline before introducing a more complex model.

## Working Style

Before implementing a substantial task:

1. Inspect the relevant existing files.
2. Briefly state your understanding.
3. Make a concise implementation plan.
4. Implement only the requested milestone.
5. Run it/tests.
6. Summarize findings, assumptions, and recommended next step.

Do not silently guess when the dataset schema is ambiguous.