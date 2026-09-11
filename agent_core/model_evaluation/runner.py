"""Bounded observation runner for normalized Phase 3 evaluation artifacts."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Iterator

from agent_core.autonomy import (
    AutonomyHistory,
    AutonomyIterationRecord,
    AutonomyRun,
    AutonomyState,
    PivotReason,
    StopReason,
    add_model_usage,
    add_request_delta,
)
from agent_core.consensus import AgreementType, ConsensusResult, ParticipantStatus
from agent_core.model_evaluation.budget import EvaluationBudgetPreflight
from agent_core.model_evaluation.errors import EvaluationError, EvaluationFailureCode
from agent_core.model_evaluation.expectations import apply_structural_expectations
from agent_core.model_evaluation.fingerprint import configuration_fingerprint
from agent_core.model_evaluation.metrics import calculate_aggregate_metrics
from agent_core.model_evaluation.types import (
    CaseModelProvenance,
    ConfigurationFingerprintSchema,
    EvaluationCase,
    EvaluationCaseOutcome,
    EvaluationExecutionMode,
    EvaluationFailure,
    EvaluationRun,
    EvaluationSubject,
    EvaluationSubjectType,
    require_public_artifact,
)
from agent_core.models import (
    ModelCallCapture,
    ModelCallRecord,
    ModelPricingCatalog,
    ModelReservationCommit,
    ModelRoutingPolicy,
    ModelUsageDelta,
    capture_model_calls,
)
from agent_core.phase2_result_status import (
    INTERMEDIATE_RESULT_STATUSES,
    TERMINAL_RESULT_STATUSES,
    Phase2ResultStatus,
)
from agent_core.reasoning import (
    REASONING_SCHEMA_VERSION,
    ReasoningAction,
    ReasoningDecision,
)
from agent_core.request_budget import RequestDelta

CaseEvaluator = Callable[
    [EvaluationSubject, EvaluationCase, int], EvaluationCaseOutcome
]


class _EvaluationCallbackFrame:
    """Latest public outcome observed before an outer callback failure."""

    def __init__(self) -> None:
        self.checkpoint: EvaluationCaseOutcome | None = None
        self.model_usage: ModelUsageDelta | None = None
        self.request_delta: RequestDelta | None = None
        self.provenance: tuple[CaseModelProvenance, ...] = ()


_ACTIVE_EVALUATION_CALLBACKS: ContextVar[tuple[_EvaluationCallbackFrame, ...]] = (
    ContextVar("active_evaluation_callbacks", default=())
)


@contextmanager
def _evaluation_callback_boundary() -> (
    Iterator[tuple[_EvaluationCallbackFrame, ModelCallCapture]]
):
    frame = _EvaluationCallbackFrame()
    active = _ACTIVE_EVALUATION_CALLBACKS.get()
    token = _ACTIVE_EVALUATION_CALLBACKS.set((*active, frame))
    try:
        with capture_model_calls() as model_capture:
            yield frame, model_capture
    finally:
        _ACTIVE_EVALUATION_CALLBACKS.reset(token)


def _record_evaluation_checkpoint(outcome: EvaluationCaseOutcome) -> None:
    active = _ACTIVE_EVALUATION_CALLBACKS.get()
    if active:
        frame = active[-1]
        frame.checkpoint = outcome
        frame.model_usage = outcome.model_usage
        frame.request_delta = outcome.request_delta
        frame.provenance = outcome.provenance


def _record_evaluation_accounting_checkpoint(
    *,
    model_usage: ModelUsageDelta,
    request_delta: RequestDelta,
    provenance: tuple[CaseModelProvenance, ...],
) -> None:
    """Retain public accounting before later outcome construction can fail."""

    active = _ACTIVE_EVALUATION_CALLBACKS.get()
    if active:
        frame = active[-1]
        frame.model_usage = model_usage
        frame.request_delta = request_delta
        frame.provenance = provenance


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvaluationRunner:
    """Measure supplied normalized outcomes; never route or execute security work."""

    def __init__(
        self,
        *,
        pricing: ModelPricingCatalog | None = None,
        max_output_tokens: int = 4096,
    ) -> None:
        if max_output_tokens < 1:
            raise ValueError("Evaluation output reservation must be positive")
        self.pricing = pricing or ModelPricingCatalog()
        self.max_output_tokens = max_output_tokens

    def run(
        self,
        *,
        evaluation_run_id: str,
        subject: EvaluationSubject,
        cases: tuple[EvaluationCase, ...],
        evaluator: CaseEvaluator,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> EvaluationRun:
        if not cases:
            raise EvaluationError(EvaluationFailureCode.case_invalid)
        started = started_at or utc_now()
        outcomes: list[EvaluationCaseOutcome] = []
        failures: list[EvaluationFailure] = []
        budget = EvaluationBudgetPreflight(
            cases,
            pricing=self.pricing,
            max_output_tokens=self.max_output_tokens,
        )

        for case in sorted(cases, key=lambda item: item.case_id):
            if not self._mode_matches(subject, case):
                failures.append(
                    EvaluationFailure(
                        subject_id=subject.subject_id,
                        case_id=case.case_id,
                        failure_code=EvaluationFailureCode.case_invalid,
                    )
                )
                continue
            repetitions = case.repetitions * subject.repetitions
            for repetition in range(repetitions):
                try:
                    grant = budget.preflight(subject, case)
                except EvaluationError:
                    outcome = EvaluationCaseOutcome(
                        subject_id=subject.subject_id,
                        case_id=case.case_id,
                        repetition=repetition,
                        execution_mode=case.execution_mode,
                        success=False,
                        failure_code=EvaluationFailureCode.budget_exhausted,
                    )
                else:
                    with _evaluation_callback_boundary() as (
                        callback_frame,
                        model_capture,
                    ):
                        try:
                            outcome = evaluator(
                                grant.subject,
                                grant.case,
                                repetition,
                            )
                            outcome = self._preserve_authoritative_model_usage(
                                outcome,
                                model_capture,
                            )
                            _record_evaluation_checkpoint(outcome)
                            self._validate_outcome(subject, case, repetition, outcome)
                        except EvaluationError as exc:
                            outcome = self._failed_outcome(
                                subject,
                                case,
                                repetition,
                                exc.code,
                                callback_frame=callback_frame,
                                model_capture=model_capture,
                            )
                        except Exception:
                            outcome = self._failed_outcome(
                                subject,
                                case,
                                repetition,
                                self._subject_failure(subject),
                                callback_frame=callback_frame,
                                model_capture=model_capture,
                            )
                    if not budget.reconcile(grant, outcome.model_usage):
                        outcome = self._budget_failed_outcome(outcome)
                outcome = apply_structural_expectations(case, outcome)
                outcomes.append(outcome)
                if outcome.failure_code is not None:
                    failures.append(
                        EvaluationFailure(
                            subject_id=subject.subject_id,
                            case_id=case.case_id,
                            repetition=repetition,
                            failure_code=outcome.failure_code,
                        )
                    )

        ended = ended_at or utc_now()
        materialized = tuple(outcomes)
        result = EvaluationRun(
            evaluation_run_id=evaluation_run_id,
            subject=subject,
            cases=tuple(sorted(cases, key=lambda item: item.case_id)),
            started_at=started,
            ended_at=ended,
            configuration_fingerprint=configuration_fingerprint(
                subject,
                cases,
                evaluation_max_output_tokens=self.max_output_tokens,
                pricing=self.pricing,
            ),
            configuration_fingerprint_schema=(
                ConfigurationFingerprintSchema.material_v2
            ),
            case_outcomes=materialized,
            aggregate_metrics=calculate_aggregate_metrics(
                materialized, started_at=started, ended_at=ended
            ),
            failures=tuple(failures),
        )
        require_public_artifact(result)
        return result

    @staticmethod
    def _mode_matches(subject: EvaluationSubject, case: EvaluationCase) -> bool:
        expected = {
            EvaluationSubjectType.single_model_reasoning: (
                EvaluationExecutionMode.reasoning_only
            ),
            EvaluationSubjectType.consensus_reasoning: (
                EvaluationExecutionMode.reasoning_only
            ),
            EvaluationSubjectType.dry_run_autonomy: EvaluationExecutionMode.dry_run,
            EvaluationSubjectType.controlled_autonomy: (
                EvaluationExecutionMode.controlled
            ),
        }[subject.subject_type]
        return case.execution_mode is expected

    @staticmethod
    def _validate_outcome(
        subject: EvaluationSubject,
        case: EvaluationCase,
        repetition: int,
        outcome: EvaluationCaseOutcome,
    ) -> None:
        if (
            not isinstance(outcome, EvaluationCaseOutcome)
            or outcome.subject_id != subject.subject_id
            or outcome.case_id != case.case_id
            or outcome.repetition != repetition
            or outcome.execution_mode is not case.execution_mode
        ):
            raise EvaluationError(EvaluationFailureCode.case_invalid)
        if subject.local_only and any(
            item.actual_provider in {"openai", "anthropic"}
            or item.requested_provider in {"openai", "anthropic"}
            for item in outcome.provenance
        ):
            raise EvaluationError(EvaluationFailureCode.case_invalid)
        require_public_artifact(outcome)

    @staticmethod
    def _failed_outcome(
        subject: EvaluationSubject,
        case: EvaluationCase,
        repetition: int,
        code: EvaluationFailureCode,
        *,
        callback_frame: _EvaluationCallbackFrame | None = None,
        model_capture: ModelCallCapture | None = None,
    ) -> EvaluationCaseOutcome:
        checkpoint = callback_frame.checkpoint if callback_frame is not None else None
        preserved = (
            checkpoint
            if checkpoint is not None
            and checkpoint.subject_id == subject.subject_id
            and checkpoint.case_id == case.case_id
            and checkpoint.repetition == repetition
            and checkpoint.execution_mode is case.execution_mode
            else None
        )
        captured_usage = (
            model_capture.usage if model_capture is not None else ModelUsageDelta()
        )
        empty_failure_usage = (
            ModelUsageDelta()
            if code is EvaluationFailureCode.budget_exhausted
            else ModelUsageDelta(
                estimated_cost_usd=None,
                budget_estimated_cost_usd=0.0,
            )
        )
        reported_usage = (
            preserved.model_usage
            if preserved is not None
            else (
                callback_frame.model_usage
                if callback_frame is not None and callback_frame.model_usage is not None
                else empty_failure_usage
            )
        )
        usage = _authoritative_callback_usage(
            reported_usage,
            captured_usage,
        )
        if preserved is not None:
            return EvaluationCaseOutcome.model_validate(
                {
                    **preserved.model_dump(mode="python"),
                    "success": False,
                    "runtime_success": False,
                    "failure_code": code,
                    "model_usage": usage,
                }
            )
        captured_provenance = _captured_model_provenance(model_capture)
        checkpoint_provenance = (
            callback_frame.provenance if callback_frame is not None else ()
        )
        provenance = (
            checkpoint_provenance
            or captured_provenance
            or tuple(
                CaseModelProvenance(
                    requested_provider=policy.preferred.provider,
                    requested_model=policy.preferred.model,
                    actual_provider=None,
                    actual_model=None,
                    reasoning_schema_version=REASONING_SCHEMA_VERSION,
                )
                for policy in subject.routing_policies
            )
        )
        return EvaluationCaseOutcome(
            subject_id=subject.subject_id,
            case_id=case.case_id,
            repetition=repetition,
            execution_mode=case.execution_mode,
            success=False,
            failure_code=code,
            model_usage=usage,
            request_delta=(
                callback_frame.request_delta
                if callback_frame is not None
                and callback_frame.request_delta is not None
                else RequestDelta()
            ),
            fallback_count=min(
                usage.successful_calls,
                sum(item.fallback_used for item in provenance),
            ),
            provenance=provenance,
        )

    @staticmethod
    def _preserve_authoritative_model_usage(
        outcome: EvaluationCaseOutcome,
        model_capture: ModelCallCapture,
    ) -> EvaluationCaseOutcome:
        if not isinstance(outcome, EvaluationCaseOutcome):
            return outcome
        usage = _authoritative_callback_usage(
            outcome.model_usage,
            model_capture.usage,
        )
        provenance = outcome.provenance or _captured_model_provenance(model_capture)
        if usage == outcome.model_usage and provenance == outcome.provenance:
            return outcome
        return EvaluationCaseOutcome.model_validate(
            {
                **outcome.model_dump(mode="python"),
                "model_usage": usage,
                "provenance": provenance,
            }
        )

    @staticmethod
    def _budget_failed_outcome(
        outcome: EvaluationCaseOutcome,
    ) -> EvaluationCaseOutcome:
        """Preserve observed accounting while normalizing a budget violation."""

        return EvaluationCaseOutcome.model_validate(
            {
                **outcome.model_dump(mode="python"),
                "success": False,
                "runtime_success": False,
                "failure_code": EvaluationFailureCode.budget_exhausted,
            }
        )

    @staticmethod
    def _subject_failure(subject: EvaluationSubject) -> EvaluationFailureCode:
        if subject.subject_type is EvaluationSubjectType.consensus_reasoning:
            return EvaluationFailureCode.consensus_failed
        if subject.subject_type in {
            EvaluationSubjectType.dry_run_autonomy,
            EvaluationSubjectType.controlled_autonomy,
        }:
            return EvaluationFailureCode.autonomy_failed
        return EvaluationFailureCode.reasoning_failed


def observe_reasoning_decision(
    *,
    subject: EvaluationSubject,
    case: EvaluationCase,
    repetition: int,
    decision: ReasoningDecision,
    routing_policy: ModelRoutingPolicy,
) -> EvaluationCaseOutcome:
    """Convert one already-validated P3-3 decision into measurement data."""

    provenance = decision.model_provenance
    outcome = apply_structural_expectations(
        case,
        EvaluationCaseOutcome(
            subject_id=subject.subject_id,
            case_id=case.case_id,
            repetition=repetition,
            execution_mode=case.execution_mode,
            success=True,
            attempted_decisions=1,
            valid_decisions=1,
            manual_review_decisions=int(
                decision.action is ReasoningAction.manual_review
            ),
            stop_decisions=int(decision.action is ReasoningAction.stop),
            capability_grounded_decisions=1,
            decisions_with_evidence_references=int(bool(decision.evidence_references)),
            decision_signature=_decision_signature(
                decision.hypothesis_id,
                decision.action,
                decision.recommended_capability,
            ),
            selected_action=decision.action,
            selected_capability=decision.recommended_capability,
            selected_hypothesis_id=decision.hypothesis_id,
            selected_category=_category_for_hypothesis(case, decision.hypothesis_id),
            decision_valid=True,
            model_usage=provenance.usage,
            fallback_count=int(provenance.fallback_used),
            time_to_first_valid_decision=provenance.usage.latency_seconds,
            provenance=(
                CaseModelProvenance(
                    requested_provider=routing_policy.preferred.provider,
                    requested_model=routing_policy.preferred.model,
                    actual_provider=provenance.provider_used,
                    actual_model=provenance.model_used,
                    fallback_used=provenance.fallback_used,
                    reasoning_schema_version=provenance.reasoning_schema_version,
                ),
            ),
        ),
    )
    _record_evaluation_checkpoint(outcome)
    return outcome


def observe_consensus_result(
    *,
    subject: EvaluationSubject,
    case: EvaluationCase,
    repetition: int,
    result: ConsensusResult,
) -> EvaluationCaseOutcome:
    """Measure a completed P3-5 result without reinterpreting it as truth."""

    valid = tuple(
        item
        for item in result.participants
        if item.status is ParticipantStatus.valid and item.decision is not None
    )
    invalid = sum(
        item.status is ParticipantStatus.invalid for item in result.participants
    )
    failed = sum(
        item.status in {ParticipantStatus.failed, ParticipantStatus.budget_blocked}
        for item in result.participants
    )
    provenance = tuple(
        CaseModelProvenance(
            requested_provider=item.configured_provider,
            requested_model=item.configured_model,
            actual_provider=item.actual_provider or item.configured_provider,
            actual_model=item.actual_model or item.configured_model,
            fallback_used=bool(item.decision.model_provenance.fallback_used),
            reasoning_schema_version=item.decision.model_provenance.reasoning_schema_version,
            consensus_schema_version=result.decision.consensus_schema_version,
        )
        for item in valid
        if item.decision is not None
    )
    selected = result.decision.selected_action
    outcome = apply_structural_expectations(
        case,
        EvaluationCaseOutcome(
            subject_id=subject.subject_id,
            case_id=case.case_id,
            repetition=repetition,
            execution_mode=case.execution_mode,
            success=True,
            attempted_decisions=len(valid) + invalid,
            valid_decisions=len(valid),
            invalid_decisions=invalid,
            schema_failures=invalid,
            manual_review_decisions=int(selected is ReasoningAction.manual_review),
            stop_decisions=int(selected is ReasoningAction.stop),
            capability_grounded_decisions=len(valid),
            decisions_with_evidence_references=sum(
                bool(item.decision.evidence_references)
                for item in valid
                if item.decision
            ),
            decision_signature=_decision_signature(
                result.decision.hypothesis_id,
                selected,
                result.decision.selected_capability,
            ),
            selected_action=selected,
            selected_capability=result.decision.selected_capability,
            selected_hypothesis_id=result.decision.hypothesis_id,
            selected_category=_category_for_hypothesis(
                case, result.decision.hypothesis_id
            ),
            decision_valid=True,
            agreement_type=result.decision.agreement_type,
            consensus_participants=result.decision.participant_count,
            invalid_participants=invalid,
            failed_participants=failed,
            dissenting_participants=len(result.decision.dissenting_decision_ids),
            quorum_succeeded=result.decision.agreement_type
            in {
                AgreementType.unanimous,
                AgreementType.majority,
                AgreementType.single_model_advisory,
            },
            aggregate_confidence=result.decision.aggregate_confidence,
            model_usage=result.decision.model_usage,
            fallback_count=sum(item.fallback_used for item in provenance),
            provenance=provenance,
        ),
    )
    _record_evaluation_checkpoint(outcome)
    return outcome


def observe_autonomy_run(
    *,
    subject: EvaluationSubject,
    case: EvaluationCase,
    repetition: int,
    run: AutonomyRun,
    history: AutonomyHistory,
    routing_policy: ModelRoutingPolicy,
    phase2_execution_latency_seconds: float | None = None,
) -> EvaluationCaseOutcome:
    """Observe an already completed P3-4 run; never call its Phase 2 runtime."""

    records = run.iteration_history or history.records
    pivots = [item.pivot_reason for item in records if item.pivot_reason is not None]
    statuses = tuple(_iteration_result_status(item) for item in records)
    verified = statuses.count("verified")
    rejected = statuses.count("rejected")
    inconclusive = statuses.count("inconclusive")
    policy_blocked = statuses.count("policy_blocked")
    verification_pending_cleanup = statuses.count("verification_pending_cleanup")
    awaiting_controlled_evidence = statuses.count("awaiting_controlled_evidence")
    intermediate = sum(status in INTERMEDIATE_RESULT_STATUSES for status in statuses)
    completed = sum(status in TERMINAL_RESULT_STATUSES for status in statuses)
    blocked = sum(
        item.gate_outcome is not None and not item.gate_outcome.approved
        for item in records
    )
    cleanup = sum(item.stop_reason is StopReason.cleanup_barrier for item in records)
    valid_decisions = sum(
        item.reasoning_decision_reference is not None for item in records
    )
    reasoning_attempts = sum(
        _entered_state(item, AutonomyState.reasoning) for item in records
    )
    invalid_decisions = max(0, reasoning_attempts - valid_decisions)
    reasoning_records = tuple(item for item in records if item.reasoning is not None)
    manual_review_decisions = sum(
        item.selected_action is ReasoningAction.manual_review for item in records
    )
    stop_decisions = sum(
        item.selected_action is ReasoningAction.stop for item in records
    )
    evidence_linked_decisions = sum(
        item.reasoning is not None and item.reasoning.evidence_reference_count > 0
        for item in records
    )
    final_reasoning = reasoning_records[-1].reasoning if reasoning_records else None
    provenance = _autonomy_model_provenance(records, routing_policy)
    fallback_count = sum(item.fallback_used for item in provenance)
    model_usage = ModelUsageDelta()
    request_delta = RequestDelta()
    for item in records:
        model_usage = add_model_usage(model_usage, item.model_usage)
        request_delta = add_request_delta(request_delta, item.phase2_request_delta)
    if not records:
        model_usage = run.model_usage
        request_delta = run.phase2_request_usage
        valid_decisions = len(run.reasoning_history_references)
        invalid_decisions = run.reasoning_failures
    result_references = tuple(
        item.phase2_result_reference
        for item in records
        if item.phase2_result_reference is not None
    )
    terminal_stop_reason = records[-1].stop_reason if records else run.stop_reason
    elapsed = _elapsed(run.started_at, run.stopped_at or run.updated_at)
    first_verification = _first_transition_elapsed(run.started_at, records, "executing")
    first_verified = _first_result_elapsed(run.started_at, records, "verified")
    _record_evaluation_accounting_checkpoint(
        model_usage=model_usage,
        request_delta=request_delta,
        provenance=provenance,
    )
    outcome = apply_structural_expectations(
        case,
        EvaluationCaseOutcome(
            subject_id=subject.subject_id,
            case_id=case.case_id,
            repetition=repetition,
            execution_mode=case.execution_mode,
            success=(
                run.current_state is not AutonomyState.failed
                and run.failure_reason is None
            ),
            failure_code=(
                None
                if run.current_state is not AutonomyState.failed
                and run.failure_reason is None
                else EvaluationFailureCode.autonomy_failed
            ),
            attempted_decisions=valid_decisions + invalid_decisions,
            valid_decisions=valid_decisions,
            invalid_decisions=invalid_decisions,
            unsupported_recommendations=invalid_decisions,
            manual_review_decisions=manual_review_decisions,
            stop_decisions=stop_decisions,
            capability_grounded_decisions=valid_decisions,
            decisions_with_evidence_references=evidence_linked_decisions,
            decision_signature=(
                _decision_signature(
                    final_reasoning.hypothesis_id,
                    final_reasoning.action,
                    final_reasoning.selected_capability,
                )
                if final_reasoning is not None
                else None
            ),
            selected_action=(
                final_reasoning.action if final_reasoning is not None else None
            ),
            selected_capability=(
                getattr(final_reasoning, "selected_capability", None)
                or getattr(final_reasoning, "recommended_capability", None)
                if final_reasoning is not None
                else None
            ),
            selected_hypothesis_id=(
                final_reasoning.hypothesis_id if final_reasoning is not None else None
            ),
            selected_category=(
                _category_for_hypothesis(case, final_reasoning.hypothesis_id)
                if final_reasoning is not None
                else None
            ),
            decision_valid=True if final_reasoning is not None else None,
            autonomy_iterations=records[-1].iteration if records else run.iteration,
            verifications_attempted=(
                sum(_entered_state(item, AutonomyState.executing) for item in records)
                if records
                else run.verifications_attempted
            ),
            verifications_completed=completed,
            verified_outcomes=verified,
            rejected_outcomes=rejected,
            inconclusive_outcomes=inconclusive,
            policy_blocked_outcomes=policy_blocked,
            verification_pending_cleanup_outcomes=verification_pending_cleanup,
            awaiting_controlled_evidence_outcomes=awaiting_controlled_evidence,
            intermediate_outcomes=intermediate,
            duplicate_recommendations_prevented=sum(
                item.gate_outcome is not None
                and item.gate_outcome.reason.value == "duplicate_recommendation"
                for item in records
            ),
            successful_pivots=sum(
                item
                in {
                    PivotReason.verified,
                    PivotReason.rejected,
                    PivotReason.inconclusive,
                }
                for item in pivots
            ),
            blocked_recommendations=blocked,
            cleanup_barriers=cleanup + int(run.cleanup_barrier_active and cleanup == 0),
            manual_review_outcomes=int(
                terminal_stop_reason is StopReason.manual_review_required
            ),
            autonomy_terminal_state=run.current_state,
            stop_reason=terminal_stop_reason,
            phase2_statuses=tuple(
                Phase2ResultStatus(item.phase2_result.canonical_status)
                for item in records
                if item.phase2_result is not None
            ),
            model_usage=model_usage,
            request_delta=request_delta,
            fallback_count=fallback_count,
            elapsed_seconds=elapsed,
            time_to_first_valid_decision=_first_transition_elapsed(
                run.started_at, records, "decision_validation"
            ),
            time_to_first_verification=first_verification,
            time_to_first_verified_outcome=first_verified,
            phase2_execution_latency_seconds=phase2_execution_latency_seconds,
            provenance=provenance,
            phase2_result_references=(
                result_references if records else run.verification_result_references
            ),
            iteration_provenance=records,
        ),
    )
    _record_evaluation_checkpoint(outcome)
    return outcome


def _authoritative_callback_usage(
    reported: ModelUsageDelta,
    captured: ModelUsageDelta,
) -> ModelUsageDelta:
    """Use observed P3-2 usage whenever the callback touched an authoritative ledger."""

    return captured if captured.attempted_calls else reported


def _captured_model_provenance(
    model_capture: ModelCallCapture | None,
) -> tuple[CaseModelProvenance, ...]:
    if model_capture is None:
        return ()
    provenance: list[CaseModelProvenance] = []
    for event in model_capture.events:
        provider_started = isinstance(event, ModelReservationCommit) or (
            isinstance(event, ModelCallRecord)
            and event.attempt_state != "blocked_before_provider_call"
        )
        provenance.append(
            CaseModelProvenance(
                requested_provider=event.provider,
                requested_model=event.model,
                actual_provider=event.provider if provider_started else None,
                actual_model=event.model if provider_started else None,
                fallback_used=provider_started and event.fallback_depth > 0,
                reasoning_schema_version=REASONING_SCHEMA_VERSION,
            )
        )
    return tuple(provenance)


def _entered_state(record: AutonomyIterationRecord, state: AutonomyState) -> bool:
    return any(transition.next_state is state for transition in record.transitions)


def _category_for_hypothesis(case: EvaluationCase, hypothesis_id: str) -> str | None:
    return next(
        (
            packet.category
            for packet in case.reasoning_request.evidence_packets
            if packet.hypothesis_id == hypothesis_id
        ),
        None,
    )


def _iteration_result_status(record: AutonomyIterationRecord) -> str | None:
    if record.phase2_result is not None:
        return record.phase2_result.canonical_status
    return {
        PivotReason.verified: "verified",
        PivotReason.rejected: "rejected",
        PivotReason.inconclusive: "inconclusive",
        PivotReason.policy_blocked: "policy_blocked",
    }.get(record.pivot_reason)


def _autonomy_model_provenance(
    records: tuple[AutonomyIterationRecord, ...],
    routing_policy: ModelRoutingPolicy,
) -> tuple[CaseModelProvenance, ...]:
    """Flatten only sanitized per-iteration route identities for evaluation."""

    provenance: list[CaseModelProvenance] = []
    for record in records:
        reasoning = record.reasoning
        result_references = (
            (record.phase2_result_reference,)
            if record.phase2_result_reference is not None
            else ()
        )
        if reasoning is None:
            if _entered_state(record, AutonomyState.reasoning):
                provenance.append(
                    CaseModelProvenance(
                        iteration_reference=record.iteration,
                        requested_provider=(
                            record.requested_provider
                            or routing_policy.preferred.provider
                        ),
                        requested_model=(
                            record.requested_model or routing_policy.preferred.model
                        ),
                        actual_provider=None,
                        actual_model=None,
                        reasoning_schema_version=REASONING_SCHEMA_VERSION,
                        autonomy_schema_version=1,
                        phase2_result_references=result_references,
                    )
                )
            continue
        consensus = reasoning.consensus
        if consensus is not None and consensus.participants:
            provenance.extend(
                CaseModelProvenance(
                    iteration_reference=record.iteration,
                    decision_id=participant.decision_id,
                    consensus_id=consensus.consensus_id,
                    participant_id=participant.participant_id,
                    requested_provider=participant.requested_provider,
                    requested_model=participant.requested_model,
                    actual_provider=participant.actual_provider,
                    actual_model=participant.actual_model,
                    fallback_used=participant.fallback_used,
                    reasoning_schema_version=reasoning.reasoning_schema_version,
                    consensus_schema_version=consensus.consensus_schema_version,
                    autonomy_schema_version=1,
                    phase2_result_references=result_references,
                )
                for participant in consensus.participants
            )
            continue
        provenance.append(
            CaseModelProvenance(
                iteration_reference=record.iteration,
                decision_id=reasoning.decision_id,
                consensus_id=(
                    consensus.consensus_id if consensus is not None else None
                ),
                requested_provider=reasoning.requested_provider,
                requested_model=reasoning.requested_model,
                actual_provider=reasoning.actual_provider,
                actual_model=reasoning.actual_model,
                fallback_used=reasoning.fallback_used,
                reasoning_schema_version=reasoning.reasoning_schema_version,
                consensus_schema_version=(
                    consensus.consensus_schema_version
                    if consensus is not None
                    else None
                ),
                autonomy_schema_version=1,
                phase2_result_references=result_references,
            )
        )
    return tuple(provenance)


def _decision_signature(
    hypothesis_id: str, action: ReasoningAction, capability: str | None
) -> str:
    return f"{hypothesis_id}:{action.value}:{capability or 'none'}"


def _elapsed(start: str, end: str) -> float:
    left = datetime.fromisoformat(start.replace("Z", "+00:00"))
    right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return max(0.0, (right - left).total_seconds())


def _first_transition_elapsed(start: str, records, state: str) -> float | None:
    values = [
        transition.occurred_at
        for record in records
        for transition in record.transitions
        if transition.next_state.value == state
    ]
    return min((_elapsed(start, value) for value in values), default=None)


def _first_result_elapsed(start: str, records, status: str) -> float | None:
    values = [
        transition.occurred_at
        for record in records
        if _iteration_result_status(record) == status
        for transition in record.transitions[-1:]
    ]
    return min((_elapsed(start, value) for value in values), default=None)
