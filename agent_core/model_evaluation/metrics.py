"""Deterministic metric aggregation without benchmark truth assumptions."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from statistics import pvariance

from agent_core.models import ModelUsageDelta, add_model_usage_deltas
from agent_core.model_evaluation.types import (
    AggregateMetrics,
    AutonomyMetrics,
    ConsensusMetrics,
    EfficiencyMetrics,
    EvaluationCaseOutcome,
    ExpectationMetrics,
    ModelUsageMetrics,
    ReasoningMetrics,
    RepeatabilityMetrics,
    TargetRequestMetrics,
    TimingMetrics,
)


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _sum(outcomes: tuple[EvaluationCaseOutcome, ...], field: str) -> int:
    return sum(int(getattr(item, field)) for item in outcomes)


def _first(values: tuple[float | None, ...]) -> float | None:
    available = tuple(value for value in values if value is not None)
    return float(min(available)) if available else None


def decision_consistency(
    outcomes: tuple[EvaluationCaseOutcome, ...],
) -> float | None:
    """Mean modal-signature share for cases having at least two repetitions."""

    groups: dict[str, list[str]] = defaultdict(list)
    for outcome in outcomes:
        signature = outcome.decision_signature or (
            f"failure:{outcome.failure_code.value}"
            if outcome.failure_code is not None
            else "no_valid_decision"
        )
        groups[outcome.case_id].append(signature)
    repeated = tuple(values for values in groups.values() if len(values) >= 2)
    if not repeated:
        return None
    shares = [max(Counter(values).values()) / len(values) for values in repeated]
    return float(sum(shares) / len(shares))


def calculate_aggregate_metrics(
    outcomes: tuple[EvaluationCaseOutcome, ...],
    *,
    started_at: str,
    ended_at: str,
) -> AggregateMetrics:
    attempted = _sum(outcomes, "attempted_decisions")
    valid = _sum(outcomes, "valid_decisions")
    invalid = _sum(outcomes, "invalid_decisions")
    schema_failures = _sum(outcomes, "schema_failures")
    unsupported = _sum(outcomes, "unsupported_recommendations")
    plan_only = _sum(outcomes, "plan_only_execution_recommendations")
    manual = _sum(outcomes, "manual_review_decisions")
    stopped = _sum(outcomes, "stop_decisions")
    grounded = _sum(outcomes, "capability_grounded_decisions")
    referenced = _sum(outcomes, "decisions_with_evidence_references")

    reasoning = ReasoningMetrics(
        attempted_decisions=attempted,
        valid_decision_rate=_ratio(valid, attempted),
        invalid_decision_rate=_ratio(invalid, attempted),
        schema_failure_rate=_ratio(schema_failures, attempted),
        unsupported_recommendation_rate=_ratio(unsupported, attempted),
        plan_only_execution_recommendation_rate=_ratio(plan_only, attempted),
        manual_review_rate=_ratio(manual, valid),
        stop_rate=_ratio(stopped, valid),
        decision_consistency=decision_consistency(outcomes),
        capability_grounding_rate=_ratio(grounded, valid),
        evidence_reference_rate=_ratio(referenced, valid),
    )

    stop_reasons = Counter(
        item.stop_reason.value for item in outcomes if item.stop_reason is not None
    )
    autonomy = AutonomyMetrics(
        iterations=_sum(outcomes, "autonomy_iterations"),
        verifications_attempted=_sum(outcomes, "verifications_attempted"),
        verifications_completed=_sum(outcomes, "verifications_completed"),
        verified_outcomes=_sum(outcomes, "verified_outcomes"),
        rejected_outcomes=_sum(outcomes, "rejected_outcomes"),
        inconclusive_outcomes=_sum(outcomes, "inconclusive_outcomes"),
        policy_blocked_outcomes=_sum(outcomes, "policy_blocked_outcomes"),
        verification_pending_cleanup_count=_sum(
            outcomes, "verification_pending_cleanup_outcomes"
        ),
        awaiting_controlled_evidence_count=_sum(
            outcomes, "awaiting_controlled_evidence_outcomes"
        ),
        intermediate_outcome_count=_sum(outcomes, "intermediate_outcomes"),
        duplicate_recommendations_prevented=_sum(
            outcomes, "duplicate_recommendations_prevented"
        ),
        successful_pivots=_sum(outcomes, "successful_pivots"),
        blocked_recommendations=_sum(outcomes, "blocked_recommendations"),
        cleanup_barriers=_sum(outcomes, "cleanup_barriers"),
        manual_review_outcomes=_sum(outcomes, "manual_review_outcomes"),
        stop_reasons=dict(sorted(stop_reasons.items())),
    )

    consensus_outcomes = tuple(
        item for item in outcomes if item.agreement_type is not None
    )
    consensus_count = len(consensus_outcomes)
    participant_count = _sum(consensus_outcomes, "consensus_participants")
    valid_participants = (
        participant_count
        - _sum(consensus_outcomes, "invalid_participants")
        - _sum(consensus_outcomes, "failed_participants")
    )
    confidence = tuple(
        item.aggregate_confidence
        for item in consensus_outcomes
        if item.aggregate_confidence is not None
    )
    consensus = ConsensusMetrics(
        consensus_evaluations=consensus_count,
        unanimous_rate=_ratio(
            sum(
                item.agreement_type.value == "unanimous" for item in consensus_outcomes
            ),
            consensus_count,
        ),
        majority_rate=_ratio(
            sum(item.agreement_type.value == "majority" for item in consensus_outcomes),
            consensus_count,
        ),
        split_rate=_ratio(
            sum(item.agreement_type.value == "split" for item in consensus_outcomes),
            consensus_count,
        ),
        invalid_participant_rate=_ratio(
            _sum(consensus_outcomes, "invalid_participants"), participant_count
        ),
        provider_failure_rate=_ratio(
            _sum(consensus_outcomes, "failed_participants"), participant_count
        ),
        quorum_success_rate=_ratio(
            sum(item.quorum_succeeded for item in consensus_outcomes), consensus_count
        ),
        mean_aggregate_confidence=(
            float(sum(confidence) / len(confidence)) if confidence else None
        ),
        dissent_rate=_ratio(
            _sum(consensus_outcomes, "dissenting_participants"), valid_participants
        ),
    )

    aggregate_usage = ModelUsageDelta()
    for item in outcomes:
        aggregate_usage = add_model_usage_deltas(aggregate_usage, item.model_usage)
    estimated_cost = aggregate_usage.estimated_cost_usd
    model_calls = aggregate_usage.attempted_calls
    successful_calls = aggregate_usage.successful_calls
    failed_calls = aggregate_usage.failed_calls
    input_tokens = aggregate_usage.input_tokens
    output_tokens = aggregate_usage.output_tokens
    total_tokens = aggregate_usage.total_tokens
    model_latency = aggregate_usage.latency_seconds
    fallbacks = _sum(outcomes, "fallback_count")
    model_usage = ModelUsageMetrics(
        model_call_count=model_calls,
        successful_model_calls=successful_calls,
        failed_model_calls=failed_calls,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        unknown_usage_calls=aggregate_usage.unknown_usage_calls,
        budget_input_tokens=aggregate_usage.budget_input_tokens,
        budget_output_tokens=aggregate_usage.budget_output_tokens,
        budget_total_tokens=aggregate_usage.budget_total_tokens,
        estimated_api_cost_usd=estimated_cost,
        budget_estimated_api_cost_usd=(aggregate_usage.budget_estimated_cost_usd),
        model_latency_seconds=model_latency,
        fallback_count=fallbacks,
        fallback_rate=_ratio(fallbacks, successful_calls),
    )

    discovery = sum(item.request_delta.discovery for item in outcomes)
    auth = sum(item.request_delta.auth for item in outcomes)
    verification = sum(item.request_delta.verification for item in outcomes)
    cleanup = sum(item.request_delta.cleanup for item in outcomes)
    target_total = discovery + auth + verification + cleanup
    target_requests = TargetRequestMetrics(
        target_requests=target_total,
        auth_requests=auth,
        verification_requests=verification,
        cleanup_requests=cleanup,
        discovery_requests=discovery,
    )

    verified = autonomy.verified_outcomes
    efficiency = EfficiencyMetrics(
        verified_per_model_call=_ratio(verified, model_calls),
        verified_per_1k_tokens=_ratio(verified * 1000, total_tokens),
        verified_per_target_request=_ratio(verified, target_total),
        verified_per_estimated_dollar=(
            None if estimated_cost is None else _ratio(verified, estimated_cost)
        ),
        successful_pivots_per_model_call=_ratio(
            autonomy.successful_pivots, model_calls
        ),
        average_reasoning_latency_seconds=_ratio(model_latency, model_calls),
        average_verification_request_cost=_ratio(
            verification, autonomy.verifications_completed
        ),
    )

    start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    end = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    phase2_latencies = tuple(
        item.phase2_execution_latency_seconds
        for item in outcomes
        if item.phase2_execution_latency_seconds is not None
    )
    timing = TimingMetrics(
        total_evaluation_seconds=max(0.0, (end - start).total_seconds()),
        time_to_first_valid_reasoning_decision=_first(
            tuple(item.time_to_first_valid_decision for item in outcomes)
        ),
        time_to_first_verification=_first(
            tuple(item.time_to_first_verification for item in outcomes)
        ),
        time_to_first_verified_outcome=_first(
            tuple(item.time_to_first_verified_outcome for item in outcomes)
        ),
        model_latency_seconds=model_latency,
        phase2_execution_latency_seconds=(
            float(sum(phase2_latencies)) if phase2_latencies else None
        ),
    )
    repetition_groups: dict[str, list[EvaluationCaseOutcome]] = defaultdict(list)
    for outcome in outcomes:
        repetition_groups[outcome.case_id].append(outcome)
    repeated = tuple(
        values for values in repetition_groups.values() if len(values) >= 2
    )
    repeatability = RepeatabilityMetrics(
        repeated_case_count=len(repeated),
        decision_agreement=decision_consistency(outcomes),
        mean_model_latency_variance=(
            float(
                sum(
                    pvariance(item.model_usage.latency_seconds for item in values)
                    for values in repeated
                )
                / len(repeated)
            )
            if repeated
            else None
        ),
        mean_total_token_variance=(
            float(
                sum(
                    pvariance(item.model_usage.total_tokens for item in values)
                    for values in repeated
                )
                / len(repeated)
            )
            if repeated
            else None
        ),
    )
    cases_with_expectations = sum(item.expectations_present for item in outcomes)
    cases_expectations_satisfied = sum(
        item.expectations_present and item.expectations_satisfied is True
        for item in outcomes
    )
    cases_expectations_failed = sum(
        item.expectations_present and item.expectations_satisfied is False
        for item in outcomes
    )
    expectations = ExpectationMetrics(
        cases_with_expectations=cases_with_expectations,
        cases_expectations_satisfied=cases_expectations_satisfied,
        cases_expectations_failed=cases_expectations_failed,
        expectation_pass_rate=_ratio(
            cases_expectations_satisfied, cases_with_expectations
        ),
    )
    return AggregateMetrics(
        reasoning=reasoning,
        autonomy=autonomy,
        consensus=consensus,
        model_usage=model_usage,
        target_requests=target_requests,
        efficiency=efficiency,
        timing=timing,
        repeatability=repeatability,
        expectations=expectations,
    )
