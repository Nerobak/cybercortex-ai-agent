"""Public JSON and concise human-readable evaluation reports."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from agent_core.model_evaluation.comparison import compare_runs, comparison_rows
from agent_core.model_evaluation.errors import EvaluationError, EvaluationFailureCode
from agent_core.model_evaluation.types import (
    EvaluationRun,
    ExternalBaselineRecord,
    ExternalBenchmarkRecord,
    require_public_artifact,
)


def evaluation_json(run: EvaluationRun, *, indent: int | None = 2) -> str:
    require_public_artifact(run)
    return json.dumps(
        run.model_dump(mode="json"),
        sort_keys=True,
        indent=indent,
        allow_nan=False,
    )


def human_summary(run: EvaluationRun) -> str:
    metrics = run.aggregate_metrics
    cost = metrics.model_usage.estimated_api_cost_usd
    cost_text = "unknown" if cost is None else f"${cost:.6f}"
    return "\n".join(
        (
            f"Evaluation: {run.evaluation_run_id}",
            f"Subject: {run.subject.subject_id}",
            f"Cases: {len(run.case_outcomes)}",
            "Structural expectations: "
            f"{metrics.expectations.cases_expectations_satisfied} passed / "
            f"{metrics.expectations.cases_expectations_failed} failed / "
            f"{metrics.expectations.cases_with_expectations} configured",
            f"Valid decision rate: {metrics.reasoning.valid_decision_rate:.3f}",
            f"Verified outcomes: {metrics.autonomy.verified_outcomes}",
            "Intermediate outcomes: "
            f"{metrics.autonomy.intermediate_outcome_count} "
            "(verification pending cleanup: "
            f"{metrics.autonomy.verification_pending_cleanup_count}; "
            "awaiting controlled evidence: "
            f"{metrics.autonomy.awaiting_controlled_evidence_count})",
            f"Model calls / tokens: {metrics.model_usage.model_call_count} / "
            f"{metrics.model_usage.total_tokens}",
            f"API cost: {cost_text}",
            f"Target requests: {metrics.target_requests.target_requests}",
            "Execution authority: unchanged; P3-4 and Phase 2 remain mandatory.",
        )
    )


def comparison_table(runs: tuple[EvaluationRun, ...]) -> str:
    header = (
        "Subject | Valid Decisions | Verified Outcomes | Pending Cleanup | "
        "Awaiting Evidence | Runtime Failures | Model Calls | Tokens | API Cost | "
        "Target Requests | Latency | Fallbacks | Successful Pivots | "
        "Expectation Pass Rate | Expectation Failures"
    )
    separator = " | ".join("---" for _ in range(15))
    lines = [header, separator]
    for row in comparison_rows(runs):
        cost = "unknown" if row.api_cost_usd is None else f"{row.api_cost_usd:.6f}"
        lines.append(
            " | ".join(
                (
                    row.subject,
                    str(row.valid_decisions),
                    str(row.verified_outcomes),
                    str(row.verification_pending_cleanup_count),
                    str(row.awaiting_controlled_evidence_count),
                    str(row.runtime_failures),
                    str(row.model_calls),
                    str(row.total_tokens),
                    cost,
                    str(row.target_requests),
                    f"{row.latency_seconds:.6f}",
                    str(row.fallbacks),
                    str(row.successful_pivots),
                    f"{row.expectation_pass_rate:.3f}",
                    str(row.expectation_failures),
                )
            )
        )
    if len(runs) == 2:
        comparison = compare_runs(runs[0], runs[1])
        reasons = ", ".join(comparison.mismatch_reasons) or "fingerprint_match"
        lines.extend(
            (
                "",
                "Configuration compatibility: "
                f"{comparison.configuration_compatibility.value} ({reasons})",
            )
        )
    return "\n".join(lines)


def import_external_baseline(
    value: str | Mapping[str, Any],
) -> ExternalBaselineRecord:
    return _import_record(value, ExternalBaselineRecord)


def import_external_benchmark(
    value: str | Mapping[str, Any],
) -> ExternalBenchmarkRecord:
    return _import_record(value, ExternalBenchmarkRecord)


def _import_record(value: str | Mapping[str, Any], model):
    try:
        payload = json.loads(value) if isinstance(value, str) else dict(value)
        record = model.model_validate(payload)
        require_public_artifact(record)
        return record
    except (json.JSONDecodeError, TypeError, ValueError, ValidationError):
        raise EvaluationError(
            EvaluationFailureCode.external_benchmark_invalid
        ) from None
