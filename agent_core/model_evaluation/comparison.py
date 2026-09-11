"""Metric-only run comparison and deterministic Pareto views."""

from __future__ import annotations

from agent_core.model_evaluation.types import (
    ComparisonMetric,
    ComparisonResult,
    ComparisonTableRow,
    ConfigurationCompatibility,
    ConfigurationCompatibilityReason,
    ConfigurationFingerprintSchema,
    EvaluationRun,
    ExternalBaselineRecord,
    ExternalBenchmarkRecord,
    ExternalConfigurationComparison,
    ParetoDominance,
    ParetoResult,
)


def _comparison_values(run: EvaluationRun) -> dict[str, int | float | None]:
    metrics = run.aggregate_metrics
    return {
        "valid_decision_rate": metrics.reasoning.valid_decision_rate,
        "decision_consistency": metrics.reasoning.decision_consistency,
        "verified_outcomes": metrics.autonomy.verified_outcomes,
        "verification_pending_cleanup_count": (
            metrics.autonomy.verification_pending_cleanup_count
        ),
        "awaiting_controlled_evidence_count": (
            metrics.autonomy.awaiting_controlled_evidence_count
        ),
        "intermediate_outcome_count": metrics.autonomy.intermediate_outcome_count,
        "runtime_failures": sum(
            not outcome.runtime_success for outcome in run.case_outcomes
        ),
        "successful_pivots": metrics.autonomy.successful_pivots,
        "model_calls": metrics.model_usage.model_call_count,
        "total_tokens": metrics.model_usage.total_tokens,
        "estimated_api_cost_usd": metrics.model_usage.estimated_api_cost_usd,
        "target_requests": metrics.target_requests.target_requests,
        "model_latency_seconds": metrics.model_usage.model_latency_seconds,
        "fallback_count": metrics.model_usage.fallback_count,
        "expectation_pass_rate": metrics.expectations.expectation_pass_rate,
        "expectation_failures": metrics.expectations.cases_expectations_failed,
    }


def compare_runs(left: EvaluationRun, right: EvaluationRun) -> ComparisonResult:
    """Report deltas and truthful full-configuration compatibility."""

    legacy = ConfigurationFingerprintSchema.legacy_v1_incomplete
    if legacy in {
        left.configuration_fingerprint_schema,
        right.configuration_fingerprint_schema,
    }:
        compatibility = ConfigurationCompatibility.unknown
        compatible = None
        mismatch = [
            ConfigurationCompatibilityReason.legacy_fingerprint_incomplete.value
        ]
    elif (
        left.configuration_fingerprint_schema
        is not right.configuration_fingerprint_schema
    ):
        compatibility = ConfigurationCompatibility.incompatible
        compatible = False
        mismatch = [ConfigurationCompatibilityReason.fingerprint_schema_mismatch.value]
    elif left.configuration_fingerprint != right.configuration_fingerprint:
        compatibility = ConfigurationCompatibility.incompatible
        compatible = False
        mismatch = [
            ConfigurationCompatibilityReason.material_configuration_mismatch.value
        ]
    else:
        compatibility = ConfigurationCompatibility.compatible
        compatible = True
        mismatch = []
    left_values = _comparison_values(left)
    right_values = _comparison_values(right)
    metrics = []
    for name in sorted(left_values):
        left_value = left_values[name]
        right_value = right_values[name]
        delta = (
            float(right_value - left_value)
            if left_value is not None and right_value is not None
            else None
        )
        metrics.append(
            ComparisonMetric(
                metric=name,
                left_value=left_value,
                right_value=right_value,
                delta=delta,
            )
        )
    return ComparisonResult(
        left_run_id=left.evaluation_run_id,
        right_run_id=right.evaluation_run_id,
        configuration_compatibility=compatibility,
        configuration_compatible=compatible,
        mismatch_reasons=tuple(mismatch),
        metrics=tuple(metrics),
    )


def compare_external_configuration(
    run: EvaluationRun,
    external: ExternalBaselineRecord | ExternalBenchmarkRecord,
) -> ExternalConfigurationComparison:
    """Verify external identity only when both sides carry material-v2 hashes."""

    fingerprint = external.configuration_fingerprint
    schema = external.configuration_fingerprint_schema
    if fingerprint is None or schema is None:
        compatibility = ConfigurationCompatibility.unknown
        reason = ConfigurationCompatibilityReason.configuration_identity_missing
    elif ConfigurationFingerprintSchema.legacy_v1_incomplete in {
        run.configuration_fingerprint_schema,
        schema,
    }:
        compatibility = ConfigurationCompatibility.unknown
        reason = ConfigurationCompatibilityReason.legacy_fingerprint_incomplete
    elif run.configuration_fingerprint_schema is not schema:
        compatibility = ConfigurationCompatibility.unknown
        reason = ConfigurationCompatibilityReason.fingerprint_schema_mismatch
    elif run.configuration_fingerprint == fingerprint:
        compatibility = ConfigurationCompatibility.compatible
        reason = ConfigurationCompatibilityReason.fingerprint_match
    else:
        compatibility = ConfigurationCompatibility.incompatible
        reason = ConfigurationCompatibilityReason.material_configuration_mismatch
    return ExternalConfigurationComparison(
        evaluation_run_id=run.evaluation_run_id,
        external_run_id=external.run_id,
        compatibility=compatibility,
        reason=reason,
    )


def comparison_rows(runs: tuple[EvaluationRun, ...]) -> tuple[ComparisonTableRow, ...]:
    rows = []
    for run in sorted(runs, key=lambda item: item.subject.subject_id):
        metrics = run.aggregate_metrics
        rows.append(
            ComparisonTableRow(
                subject=run.subject.subject_id,
                valid_decisions=sum(item.valid_decisions for item in run.case_outcomes),
                verified_outcomes=metrics.autonomy.verified_outcomes,
                verification_pending_cleanup_count=(
                    metrics.autonomy.verification_pending_cleanup_count
                ),
                awaiting_controlled_evidence_count=(
                    metrics.autonomy.awaiting_controlled_evidence_count
                ),
                runtime_failures=sum(
                    not outcome.runtime_success for outcome in run.case_outcomes
                ),
                model_calls=metrics.model_usage.model_call_count,
                total_tokens=metrics.model_usage.total_tokens,
                api_cost_usd=metrics.model_usage.estimated_api_cost_usd,
                target_requests=metrics.target_requests.target_requests,
                latency_seconds=metrics.model_usage.model_latency_seconds,
                fallbacks=metrics.model_usage.fallback_count,
                successful_pivots=metrics.autonomy.successful_pivots,
                expectation_pass_rate=metrics.expectations.expectation_pass_rate,
                expectation_failures=metrics.expectations.cases_expectations_failed,
            )
        )
    return tuple(rows)


def pareto_view(runs: tuple[EvaluationRun, ...]) -> ParetoResult:
    """Return non-dominated subjects across explicit quality/resource dimensions."""

    ordered = tuple(sorted(runs, key=lambda item: item.subject.subject_id))
    dominance: list[ParetoDominance] = []
    dominated: set[str] = set()
    for candidate in ordered:
        for other in ordered:
            if candidate is other:
                continue
            if _dominates(candidate, other):
                dominance.append(
                    ParetoDominance(
                        dominant_subject=candidate.subject.subject_id,
                        dominated_subject=other.subject.subject_id,
                    )
                )
                dominated.add(other.subject.subject_id)
    return ParetoResult(
        frontier_subjects=tuple(
            item.subject.subject_id
            for item in ordered
            if item.subject.subject_id not in dominated
        ),
        dominance=tuple(
            sorted(
                set(dominance),
                key=lambda item: (item.dominant_subject, item.dominated_subject),
            )
        ),
    )


def _dominates(left: EvaluationRun, right: EvaluationRun) -> bool:
    left_metrics = left.aggregate_metrics
    right_metrics = right.aggregate_metrics
    dimensions: list[tuple[float, float, bool]] = [
        (
            left_metrics.reasoning.valid_decision_rate,
            right_metrics.reasoning.valid_decision_rate,
            True,
        ),
        (
            float(left_metrics.autonomy.verified_outcomes),
            float(right_metrics.autonomy.verified_outcomes),
            True,
        ),
        (
            left_metrics.model_usage.model_latency_seconds,
            right_metrics.model_usage.model_latency_seconds,
            False,
        ),
        (
            float(left_metrics.model_usage.total_tokens),
            float(right_metrics.model_usage.total_tokens),
            False,
        ),
        (
            float(left_metrics.target_requests.target_requests),
            float(right_metrics.target_requests.target_requests),
            False,
        ),
    ]
    left_cost = left_metrics.model_usage.estimated_api_cost_usd
    right_cost = right_metrics.model_usage.estimated_api_cost_usd
    if left_cost is not None and right_cost is not None:
        dimensions.append((left_cost, right_cost, False))
    no_worse = all(
        left >= right if maximize else left <= right
        for left, right, maximize in dimensions
    )
    strictly_better = any(
        left > right if maximize else left < right
        for left, right, maximize in dimensions
    )
    return no_worse and strictly_better
