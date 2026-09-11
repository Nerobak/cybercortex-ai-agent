"""Synthetic, benchmark-independent fixtures for offline evaluator testing."""

from __future__ import annotations

from enum import Enum

from agent_core.autonomy import AutonomyLimits, AutonomyState, StopReason
from agent_core.consensus import AgreementType, ConsensusBudget, ConsensusPolicy
from agent_core.model_evaluation.errors import EvaluationFailureCode
from agent_core.model_evaluation.expectations import apply_structural_expectations
from agent_core.model_evaluation.types import (
    CaseModelProvenance,
    CanonicalPhase2ExpectationStatus,
    EvaluationCase,
    EvaluationCaseOutcome,
    EvaluationExecutionMode,
    EvaluationSubject,
    EvaluationSubjectType,
    ExpectedStructuralProperties,
)
from agent_core.models import (
    ModelBudgetLimits,
    ModelRoute,
    ModelRoutingPolicy,
    ModelUsageDelta,
    RoutingMode,
)
from agent_core.reasoning import (
    PolicyReasoningConstraints,
    ReasoningAction,
    ReasoningTaskType,
    build_reasoning_request,
)
from agent_core.request_budget import RequestDelta


class SyntheticScenario(str, Enum):
    grounded_recommendation = "grounded_recommendation"
    invalid_capability = "invalid_capability"
    plan_only_recommendation = "plan_only_recommendation"
    model_disagreement = "model_disagreement"
    verified_result = "verified_result"
    rejected_result = "rejected_result"
    inconclusive_result = "inconclusive_result"
    policy_block = "policy_block"
    provider_timeout = "provider_timeout"
    fallback = "fallback"
    budget_exhaustion = "budget_exhaustion"


def synthetic_route(
    provider: str,
    model: str,
    *,
    fallback_provider: str | None = None,
    fallback_model: str | None = None,
) -> ModelRoutingPolicy:
    if (fallback_provider is None) != (fallback_model is None):
        raise ValueError("synthetic fallback provider and model are required together")
    fallbacks = (
        (ModelRoute(provider=fallback_provider, model=fallback_model),)
        if fallback_provider is not None and fallback_model is not None
        else ()
    )
    cloud_providers = tuple(
        dict.fromkeys(
            item
            for item in (provider, fallback_provider)
            if item is not None and item != "ollama"
        )
    )
    return ModelRoutingPolicy(
        mode=(
            RoutingMode.local_only
            if provider == "ollama"
            else RoutingMode.fallback_chain if fallbacks else RoutingMode.preferred
        ),
        preferred=ModelRoute(provider=provider, model=model),
        fallbacks=fallbacks,
        fallback_allowed=bool(fallbacks),
        max_provider_attempts=1 + len(fallbacks),
        allowed_cloud_providers=cloud_providers,
        budget=ModelBudgetLimits(max_model_calls=20),
    )


def synthetic_subject(
    subject_id: str = "synthetic-gpt",
    *,
    provider: str = "openai",
    model: str = "gpt-synthetic",
    subject_type: EvaluationSubjectType = EvaluationSubjectType.single_model_reasoning,
    fallback_provider: str | None = None,
    fallback_model: str | None = None,
) -> EvaluationSubject:
    route = synthetic_route(
        provider,
        model,
        fallback_provider=fallback_provider,
        fallback_model=fallback_model,
    )
    consensus = subject_type is EvaluationSubjectType.consensus_reasoning
    autonomy = subject_type in {
        EvaluationSubjectType.dry_run_autonomy,
        EvaluationSubjectType.controlled_autonomy,
    }
    return EvaluationSubject(
        subject_id=subject_id,
        subject_type=subject_type,
        routing_policies=(route,),
        consensus_policy=(
            ConsensusPolicy(
                minimum_participants=1,
                minimum_valid_participants=1,
                allow_single_model_advisory=True,
            )
            if consensus
            else None
        ),
        consensus_budget=ConsensusBudget() if consensus else None,
        autonomy_limits=AutonomyLimits() if autonomy else None,
        local_only=provider == "ollama",
    )


def synthetic_case(
    scenario: SyntheticScenario = SyntheticScenario.grounded_recommendation,
    *,
    execution_mode: EvaluationExecutionMode = EvaluationExecutionMode.reasoning_only,
    repetitions: int = 1,
) -> EvaluationCase:
    plan_only = scenario is SyntheticScenario.plan_only_recommendation
    category = "ssrf" if plan_only else "bola"
    hypothesis_id = f"synthetic-{scenario.value}"
    request = build_reasoning_request(
        task_type=ReasoningTaskType.hypothesis_analysis,
        run_id=f"run-{scenario.value}",
        target_reference="synthetic-target",
        hypotheses=(
            {
                "hypothesis_id": hypothesis_id,
                "category": category,
                "title": "Synthetic public evidence review",
                "rationale": "A fabricated public observation supports schema testing.",
                "confidence": "medium",
                "priority": 50,
                "target_surface": {"route": "/synthetic/{id}"},
                "evidence_basis": [{"observation": "synthetic public identifier"}],
                "evidence_refs": [f"evidence-{scenario.value}"],
                "required_context": ["controlled test context"],
                "limitations": ["This fixture performs no target operation."],
            },
        ),
        policy_constraints=PolicyReasoningConstraints(
            policy_reference="synthetic-policy",
            allowed_recommendation_categories=(category,),
            remaining_target_request_budget=10,
            controlled_context_available=True,
        ),
    )
    return EvaluationCase(
        case_id=f"case-{scenario.value}",
        task_type=request.task_type,
        reasoning_request=request,
        expected_structure=ExpectedStructuralProperties(
            minimum_valid_decisions=0,
            allowed_actions=tuple(ReasoningAction),
            allowed_capabilities=(category,),
            evidence_references_required=True,
        ),
        execution_mode=execution_mode,
        model_budget=ModelBudgetLimits(max_model_calls=10),
        autonomy_budget=(
            AutonomyLimits()
            if execution_mode is not EvaluationExecutionMode.reasoning_only
            else None
        ),
        repetitions=repetitions,
    )


def synthetic_outcome(
    subject: EvaluationSubject,
    case: EvaluationCase,
    repetition: int,
    scenario: SyntheticScenario,
) -> EvaluationCaseOutcome:
    routing_policy = subject.routing_policies[0]
    route = routing_policy.preferred
    packet = case.reasoning_request.evidence_packets[0]
    category = packet.category
    hypothesis_id = packet.hypothesis_id
    valid = scenario not in {
        SyntheticScenario.invalid_capability,
        SyntheticScenario.plan_only_recommendation,
        SyntheticScenario.provider_timeout,
        SyntheticScenario.budget_exhaustion,
    }
    timeout = scenario is SyntheticScenario.provider_timeout
    budget = scenario is SyntheticScenario.budget_exhaustion
    invalid = int(not valid and not timeout and not budget)
    fallback = scenario is SyntheticScenario.fallback
    if fallback and len(routing_policy.ordered_routes()) < 2:
        raise ValueError("synthetic fallback requires a declared fallback route")
    actual_route = (
        routing_policy.ordered_routes()[1] if fallback else routing_policy.preferred
    )
    model_usage = ModelUsageDelta(
        attempted_calls=2 if fallback else int(not budget),
        successful_calls=int(valid),
        failed_calls=(1 if fallback else int(timeout or invalid)),
        input_tokens=20 if not budget else 0,
        output_tokens=10 if not budget else 0,
        total_tokens=30 if not budget else 0,
        estimated_cost_usd=(0.0 if route.provider == "ollama" else 0.002),
        latency_seconds=0.1 if not budget else 0.0,
    )
    controlled = case.execution_mode is EvaluationExecutionMode.controlled
    verified = int(controlled and scenario is SyntheticScenario.verified_result)
    rejected = int(controlled and scenario is SyntheticScenario.rejected_result)
    inconclusive = int(controlled and scenario is SyntheticScenario.inconclusive_result)
    policy_blocked = int(controlled and scenario is SyntheticScenario.policy_block)
    completed = verified + rejected + inconclusive + policy_blocked
    request_delta = (
        RequestDelta(verification=completed, attempted=completed, total=completed)
        if controlled
        else RequestDelta()
    )
    failure = (
        EvaluationFailureCode.reasoning_failed
        if timeout
        else EvaluationFailureCode.budget_exhausted if budget else None
    )
    action = (
        ReasoningAction.manual_review
        if scenario
        in {
            SyntheticScenario.model_disagreement,
            SyntheticScenario.plan_only_recommendation,
        }
        else ReasoningAction.recommend_verification
    )
    provenance = (
        CaseModelProvenance(
            requested_provider=route.provider,
            requested_model=route.model,
            actual_provider=None if budget else actual_route.provider,
            actual_model=None if budget else actual_route.model,
            fallback_used=fallback,
            reasoning_schema_version=1,
            autonomy_schema_version=(
                1
                if case.execution_mode is not EvaluationExecutionMode.reasoning_only
                else None
            ),
            phase2_result_references=(
                (f"result-{scenario.value}",) if completed else ()
            ),
        ),
    )
    return apply_structural_expectations(
        case,
        EvaluationCaseOutcome(
            subject_id=subject.subject_id,
            case_id=case.case_id,
            repetition=repetition,
            execution_mode=case.execution_mode,
            success=failure is None,
            failure_code=failure,
            attempted_decisions=int(valid) + invalid,
            valid_decisions=int(valid),
            invalid_decisions=invalid,
            unsupported_recommendations=invalid,
            plan_only_execution_recommendations=int(
                scenario is SyntheticScenario.plan_only_recommendation
            ),
            manual_review_decisions=int(
                valid and action is ReasoningAction.manual_review
            ),
            capability_grounded_decisions=int(valid),
            decisions_with_evidence_references=int(valid),
            decision_signature=(
                f"{case.reasoning_request.evidence_packets[0].hypothesis_id}:{action.value}:bola"
                if valid
                else None
            ),
            selected_action=action if valid else None,
            selected_capability=category if valid else None,
            selected_hypothesis_id=hypothesis_id if valid else None,
            selected_category=category if valid else None,
            decision_valid=valid if not timeout and not budget else None,
            agreement_type=(
                AgreementType.split
                if scenario is SyntheticScenario.model_disagreement
                else None
            ),
            consensus_participants=(
                3 if scenario is SyntheticScenario.model_disagreement else 0
            ),
            dissenting_participants=(
                3 if scenario is SyntheticScenario.model_disagreement else 0
            ),
            aggregate_confidence=(
                0.5 if scenario is SyntheticScenario.model_disagreement else None
            ),
            autonomy_iterations=int(
                case.execution_mode is not EvaluationExecutionMode.reasoning_only
            ),
            verifications_attempted=completed,
            verifications_completed=completed,
            verified_outcomes=verified,
            rejected_outcomes=rejected,
            inconclusive_outcomes=inconclusive,
            policy_blocked_outcomes=policy_blocked,
            successful_pivots=verified + rejected + inconclusive,
            blocked_recommendations=policy_blocked,
            autonomy_terminal_state=(
                AutonomyState.stopped
                if case.execution_mode is not EvaluationExecutionMode.reasoning_only
                else None
            ),
            stop_reason=(StopReason.phase2_policy_blocked if policy_blocked else None),
            phase2_statuses=(
                (CanonicalPhase2ExpectationStatus.verified,)
                if verified
                else (
                    (CanonicalPhase2ExpectationStatus.rejected,)
                    if rejected
                    else (
                        (CanonicalPhase2ExpectationStatus.inconclusive,)
                        if inconclusive
                        else (
                            (CanonicalPhase2ExpectationStatus.policy_blocked,)
                            if policy_blocked
                            else ()
                        )
                    )
                )
            ),
            model_usage=model_usage,
            request_delta=request_delta,
            fallback_count=int(fallback),
            elapsed_seconds=0.2,
            time_to_first_valid_decision=0.1 if valid else None,
            time_to_first_verification=0.15 if completed else None,
            time_to_first_verified_outcome=0.2 if verified else None,
            phase2_execution_latency_seconds=0.05 if completed else None,
            provenance=provenance,
            phase2_result_references=(
                (f"result-{scenario.value}",) if completed else ()
            ),
        ),
    )


def synthetic_scenarios() -> tuple[SyntheticScenario, ...]:
    return tuple(SyntheticScenario)
