"""Evaluate PathShield retrieval with a small hand-written query set."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pathshield.retrieval import SEMANTIC_MATCH_COUNT, dual_retrieval
from pathshield.vector import create_embeddings, neo4j_driver, openai_client


@dataclass(frozen=True)
class EvaluationCase:
    query: str
    expected_incidents: frozenset[int]
    expected_techniques: frozenset[str]


@dataclass(frozen=True)
class EvaluationResult:
    case: EvaluationCase
    incident_ids: tuple[int, ...]
    technique_ids: tuple[str, ...]

    @property
    def incident_top_1(self) -> bool:
        return bool(self.incident_ids and self.incident_ids[0] in self.case.expected_incidents)

    @property
    def incident_top_2(self) -> bool:
        return bool(set(self.incident_ids[:2]) & self.case.expected_incidents)

    @property
    def technique_top_2(self) -> bool:
        return bool(set(self.technique_ids[:2]) & self.case.expected_techniques)


EVALUATION_CASES = (
    EvaluationCase(
        "A shell transfers a payload to another host with scp, then launches it through ssh.",
        frozenset({44}), frozenset({"T1570", "T1021.004"}),
    ),
    EvaluationCase(
        "A privileged local Linux user is added and assigned a password to preserve access.",
        frozenset({35}), frozenset({"T1136.001"}),
    ),
    EvaluationCase(
        "A script searches configuration files with grep for plaintext passwords.",
        frozenset({36}), frozenset({"T1552.001"}),
    ),
    EvaluationCase(
        "A Python credential utility reads usernames and passwords saved by Firefox.",
        frozenset({38, 39}), frozenset({"T1555.003"}),
    ),
    EvaluationCase(
        "The Linux desktop is captured and written to an image file.",
        frozenset({40}), frozenset({"T1113"}),
    ),
    EvaluationCase(
        "Several sensitive files are copied into a temporary staging location.",
        frozenset({14, 15, 16, 19, 20, 21}), frozenset({"T1074.001"}),
    ),
    EvaluationCase(
        "A staged folder is packed into a compressed tar archive.",
        frozenset({22, 23}), frozenset({"T1560.001"}),
    ),
    EvaluationCase(
        "An archive of collected files is sent from the host to a remote destination.",
        frozenset({24}), frozenset({"T1041"}),
    ),
    EvaluationCase(
        "A shell downloads an executable tool and runs it on the compromised host.",
        frozenset({25, 37}), frozenset({"T1105"}),
    ),
    EvaluationCase(
        "Commands inspect the machine's network interfaces and IP configuration.",
        frozenset({28}), frozenset({"T1016"}),
    ),
    EvaluationCase(
        "The host operating-system release and kernel details are queried.",
        frozenset({33}), frozenset({"T1082"}),
    ),
    EvaluationCase(
        "The filesystem is recursively searched for documents and configuration files.",
        frozenset(range(1, 14)) | frozenset({17, 18}), frozenset({"T1083"}),
    ),
    EvaluationCase(
        "Local usernames and currently logged-in users are enumerated.",
        frozenset({27, 30}), frozenset({"T1087.001"}),
    ),
)


def evaluate_retrieval(
    client: Any,
    driver: Any,
    database: str,
    cases: Sequence[EvaluationCase] = EVALUATION_CASES,
) -> list[EvaluationResult]:
    """Embed all queries once and evaluate the existing dual retrieval path."""
    embeddings = create_embeddings(client, [case.query for case in cases])
    results = []
    for case, embedding in zip(cases, embeddings, strict=True):
        incidents, techniques = dual_retrieval(
            driver, database, embedding, SEMANTIC_MATCH_COUNT
        )
        results.append(EvaluationResult(
            case=case,
            incident_ids=tuple(int(item["attack_index"]) for item in incidents),
            technique_ids=tuple(str(item["attack_id"]) for item in techniques),
        ))
    return results


def format_evaluation(results: Sequence[EvaluationResult]) -> str:
    """Return per-query outcomes and aggregate retrieval metrics."""
    if not results:
        return "No evaluation cases were run."
    lines = []
    for number, result in enumerate(results, start=1):
        status = (
            "PASS" if result.incident_top_1 else "MISS",
            "PASS" if result.incident_top_2 else "MISS",
            "PASS" if result.technique_top_2 else "MISS",
        )
        lines.append(
            f"{number:02d}. {result.case.query}\n"
            f"    incident@1 {status[0]} | incident@2 {status[1]} | MITRE@2 {status[2]}\n"
            f"    incidents {list(result.incident_ids)} | MITRE {list(result.technique_ids)}"
        )

    total = len(results)
    metrics = (
        ("Expected incident in top 1", sum(item.incident_top_1 for item in results)),
        ("Expected incident in top 2", sum(item.incident_top_2 for item in results)),
        ("Expected MITRE technique in top 2", sum(item.technique_top_2 for item in results)),
    )
    lines.append("\nSummary:")
    lines.extend(
        f"{label}: {count}/{total} ({count / total:.0%})"
        for label, count in metrics
    )
    return "\n".join(lines)


def main() -> int:
    try:
        client = openai_client()
        driver, database = neo4j_driver()
        with driver:
            print(format_evaluation(evaluate_retrieval(client, driver, database)))
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
