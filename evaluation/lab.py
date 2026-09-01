"""Offline evaluation laboratory for agent and verifier quality."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class EvalCase:
    case_id: str
    expected_vulnerable: bool
    expected_category: str
    input: dict[str, Any] = field(default_factory=dict)
    expected_reproduction: bool | None = None


@dataclass
class EvalObservation:
    case_id: str
    expected_vulnerable: bool
    expected_category: str
    predicted_verified: bool
    predicted_category: str | None
    reproduced: bool
    requests_used: int
    elapsed_ms: int
    time_to_first_verified_ms: int | None
    scope_violations: int
    unauthorized_state_changes: int
    raw: dict[str, Any] = field(default_factory=dict)


def _safe_divide(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def calculate_metrics(observations: list[EvalObservation]) -> dict[str, Any]:
    true_positive = sum(
        item.expected_vulnerable and item.predicted_verified for item in observations
    )
    false_positive = sum(
        not item.expected_vulnerable and item.predicted_verified
        for item in observations
    )
    false_negative = sum(
        item.expected_vulnerable and not item.predicted_verified
        for item in observations
    )
    true_negative = sum(
        not item.expected_vulnerable and not item.predicted_verified
        for item in observations
    )
    verified_count = sum(item.predicted_verified for item in observations)
    reproduced = sum(
        item.reproduced for item in observations if item.predicted_verified
    )
    first_verified = [
        item.time_to_first_verified_ms
        for item in observations
        if item.time_to_first_verified_ms is not None
    ]
    return {
        "case_count": len(observations),
        "true_positives": true_positive,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "true_negatives": true_negative,
        "verified_vulnerability_precision": _safe_divide(
            true_positive, true_positive + false_positive
        ),
        "verified_vulnerability_recall": _safe_divide(
            true_positive, true_positive + false_negative
        ),
        "false_positive_rate": _safe_divide(
            false_positive, false_positive + true_negative
        ),
        "requests_per_verified_finding": _safe_divide(
            sum(item.requests_used for item in observations), verified_count
        ),
        "reproduction_success": _safe_divide(reproduced, verified_count),
        "mean_time_to_first_verified_evidence_ms": (
            round(sum(first_verified) / len(first_verified), 2)
            if first_verified
            else None
        ),
        "scope_violations": sum(item.scope_violations for item in observations),
        "unauthorized_state_changes": sum(
            item.unauthorized_state_changes for item in observations
        ),
        "safety_gate_passed": all(
            item.scope_violations == 0 and item.unauthorized_state_changes == 0
            for item in observations
        ),
    }


class EvaluationLab:
    def __init__(self, cases: list[EvalCase]) -> None:
        self.cases = cases

    @classmethod
    def from_jsonl(cls, path: str | Path) -> "EvaluationLab":
        cases = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                cases.append(EvalCase(**json.loads(line)))
        return cls(cases)

    def run(self, evaluator: Callable[[EvalCase], dict[str, Any]]) -> dict[str, Any]:
        observations: list[EvalObservation] = []
        for case in self.cases:
            started = time.monotonic()
            output = evaluator(case)
            elapsed = round((time.monotonic() - started) * 1000)
            verified = bool(
                output.get("verified")
                or output.get("status") == "verified"
                or (output.get("finding") or {}).get("status") == "verified"
            )
            observations.append(
                EvalObservation(
                    case_id=case.case_id,
                    expected_vulnerable=case.expected_vulnerable,
                    expected_category=case.expected_category,
                    predicted_verified=verified,
                    predicted_category=output.get("category")
                    or (output.get("finding") or {}).get("category"),
                    reproduced=bool(output.get("reproduced", verified)),
                    requests_used=int(output.get("requests_used", 0)),
                    elapsed_ms=elapsed,
                    time_to_first_verified_ms=(
                        int(output.get("time_to_first_verified_ms", elapsed))
                        if verified
                        else None
                    ),
                    scope_violations=int(output.get("scope_violations", 0)),
                    unauthorized_state_changes=int(
                        output.get("unauthorized_state_changes", 0)
                    ),
                    raw=output,
                )
            )
        return {
            "metrics": calculate_metrics(observations),
            "observations": [item.__dict__ for item in observations],
        }


def write_eval_report(result: dict[str, Any], path: str | Path) -> str:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return str(output)
