"""P2-F1 regressions for canonical intermediate Phase 2 evaluation states."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import agent_core.model_evaluation.types as evaluation_types
from agent_core.autonomy import AutonomyHistory, AutonomyState, StopReason
from agent_core.model_evaluation import (
    CanonicalPhase2ExpectationStatus,
    EvaluationCaseOutcome,
    EvaluationExecutionMode,
    EvaluationFailureCode,
    EvaluationRunner,
    EvaluationSubjectType,
    ExpectedStructuralProperties,
    compare_runs,
    comparison_table,
    evaluation_json,
    human_summary,
    observe_autonomy_run,
    synthetic_case,
    synthetic_subject,
)
from agent_core.phase2_result_status import (
    INTERMEDIATE_RESULT_STATUSES,
    PUBLIC_RESULT_STATUSES,
    TERMINAL_RESULT_STATUSES,
    Phase2ResultStatus,
)
from agent_core.request_budget import RequestDelta
from tests.test_phase3_autonomy import (
    decision as autonomy_decision,
    routing_policy as autonomy_routing_policy,
    run_autonomy,
    versioned_phase2_result,
)

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:00:01+00:00"
CLEANUP_DELTA = RequestDelta(
    auth=1,
    verification=1,
    cleanup=1,
    attempted=3,
    total=3,
)
PARTIAL_EVIDENCE_DELTA = RequestDelta(
    auth=1,
    verification=1,
    attempted=2,
    total=2,
)


def _phase2_result(status: str, delta: RequestDelta) -> dict[str, object]:
    return versioned_phase2_result(
        status,
        request_count=0,
        extra={
            "request_delta": delta.model_dump(mode="json"),
            "requests_used": delta.total,
        },
    )


def _evaluate(
    status: str,
    delta: RequestDelta | None = None,
    *,
    expected_status: Phase2ResultStatus | None = None,
):
    actual_delta = (
        delta
        if delta is not None
        else (
            CLEANUP_DELTA
            if status == Phase2ResultStatus.verification_pending_cleanup.value
            else RequestDelta()
        )
    )
    subject = synthetic_subject(
        "intermediate-observer",
        provider="openai",
        model="reasoning-model",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    base_case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    case = (
        base_case.model_copy(
            update={
                "expected_structure": ExpectedStructuralProperties(
                    phase2_status=expected_status
                )
            }
        )
        if expected_status is not None
        else base_case
    )
    autonomy_run, orchestrator, _, runtime = run_autonomy(
        [autonomy_decision()],
        results=[_phase2_result(status, actual_delta)],
        route=subject.routing_policies[0],
    )

    def evaluator(selected, item, repetition):
        return observe_autonomy_run(
            subject=selected,
            case=item,
            repetition=repetition,
            run=autonomy_run,
            history=orchestrator.history,
            routing_policy=selected.routing_policies[0],
        )

    evaluation = EvaluationRunner().run(
        evaluation_run_id=f"evaluation-{status}",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    return evaluation, autonomy_run, orchestrator, runtime


def _outcome(status: str, delta: RequestDelta | None = None):
    evaluation, autonomy_run, orchestrator, runtime = _evaluate(status, delta)
    return (
        evaluation.case_outcomes[0],
        evaluation,
        autonomy_run,
        orchestrator,
        runtime,
    )


def test_verification_pending_cleanup_is_accepted():
    observed, _, _, _, _ = _outcome("verification_pending_cleanup")
    assert observed.phase2_statuses == (
        Phase2ResultStatus.verification_pending_cleanup,
    )


def test_awaiting_controlled_evidence_is_accepted():
    observed, _, _, _, _ = _outcome("awaiting_controlled_evidence")
    assert observed.phase2_statuses == (
        Phase2ResultStatus.awaiting_controlled_evidence,
    )


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_status_identity_is_exact(status: str):
    observed, _, _, _, _ = _outcome(status)
    assert observed.phase2_statuses[-1].value == status
    assert observed.iteration_provenance[-1].phase2_result.canonical_status == status


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_state_is_not_an_evaluation_runtime_failure(status: str):
    observed, evaluation, _, _, _ = _outcome(status)
    assert (observed.runtime_success, observed.success, observed.failure_code) == (
        True,
        True,
        None,
    )
    assert evaluation.failures == ()


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_state_is_not_a_completed_terminal_verification(status: str):
    observed, _, _, _, _ = _outcome(status)
    assert observed.verifications_attempted == 1
    assert observed.verifications_completed == 0
    assert observed.intermediate_outcomes == 1


def test_cleanup_pending_request_delta_is_preserved():
    observed, _, autonomy_run, _, _ = _outcome("verification_pending_cleanup")
    assert observed.request_delta == CLEANUP_DELTA
    assert observed.request_delta == autonomy_run.phase2_request_usage


def test_awaiting_evidence_zero_request_delta_is_preserved():
    observed, evaluation, _, _, _ = _outcome("awaiting_controlled_evidence")
    assert observed.request_delta == RequestDelta()
    assert evaluation.aggregate_metrics.target_requests.target_requests == 0


def test_awaiting_evidence_partial_request_delta_is_preserved():
    observed, evaluation, _, _, _ = _outcome(
        "awaiting_controlled_evidence", PARTIAL_EVIDENCE_DELTA
    )
    assert observed.request_delta == PARTIAL_EVIDENCE_DELTA
    assert evaluation.aggregate_metrics.target_requests.auth_requests == 1
    assert evaluation.aggregate_metrics.target_requests.verification_requests == 1


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_model_usage_delta_is_preserved(status: str):
    observed, evaluation, autonomy_run, _, _ = _outcome(status)
    assert observed.model_usage == autonomy_run.model_usage
    assert observed.model_usage.attempted_calls == 1
    assert evaluation.aggregate_metrics.model_usage.model_call_count == 1


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_iteration_history_is_preserved(status: str):
    observed, _, autonomy_run, orchestrator, _ = _outcome(status)
    assert observed.iteration_provenance == autonomy_run.iteration_history
    assert observed.iteration_provenance == orchestrator.history.records
    assert observed.iteration_provenance[0].iteration == 1


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_reasoning_decision_provenance_is_preserved(status: str):
    observed, _, _, _, _ = _outcome(status)
    record = observed.iteration_provenance[0]
    assert record.reasoning_decision_reference == record.reasoning.decision_id
    assert record.reasoning.model_call_reference == "safe-call-id"
    assert observed.provenance[0].decision_id == record.reasoning.decision_id
    assert observed.provenance[0].iteration_reference == record.iteration


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_phase2_result_provenance_is_preserved(status: str):
    observed, _, _, _, _ = _outcome(status)
    record = observed.iteration_provenance[0]
    result = record.phase2_result
    assert result.result_reference == record.phase2_result_reference
    assert result.result_id is not None
    assert result.result_hash is not None
    assert result.executor_version == "bola/v1"
    assert result.run_id == "phase2-run-1"
    assert observed.phase2_result_references == (result.result_reference,)


def test_cleanup_reason_and_pause_semantics_are_preserved():
    observed, _, _, _, _ = _outcome("verification_pending_cleanup")
    record = observed.iteration_provenance[0]
    assert observed.stop_reason is StopReason.cleanup_barrier
    assert record.stop_reason is StopReason.cleanup_barrier
    assert record.transitions[-1].reason == StopReason.cleanup_barrier.value


def test_controlled_evidence_reason_and_pause_semantics_are_preserved():
    observed, _, _, _, _ = _outcome("awaiting_controlled_evidence")
    record = observed.iteration_provenance[0]
    assert observed.stop_reason is StopReason.awaiting_controlled_evidence
    assert record.stop_reason is StopReason.awaiting_controlled_evidence
    assert (
        record.transitions[-1].reason == StopReason.awaiting_controlled_evidence.value
    )


def test_cleanup_pending_metrics_are_separate():
    observed, evaluation, _, _, _ = _outcome("verification_pending_cleanup")
    metrics = evaluation.aggregate_metrics.autonomy
    assert observed.verification_pending_cleanup_outcomes == 1
    assert metrics.verification_pending_cleanup_count == 1
    assert metrics.awaiting_controlled_evidence_count == 0
    assert metrics.intermediate_outcome_count == 1


def test_awaiting_evidence_metrics_are_separate():
    observed, evaluation, _, _, _ = _outcome("awaiting_controlled_evidence")
    metrics = evaluation.aggregate_metrics.autonomy
    assert observed.awaiting_controlled_evidence_outcomes == 1
    assert metrics.awaiting_controlled_evidence_count == 1
    assert metrics.verification_pending_cleanup_count == 0
    assert metrics.intermediate_outcome_count == 1


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_intermediate_does_not_increment_terminal_or_failure_metrics(status: str):
    observed, evaluation, _, _, _ = _outcome(status)
    assert (
        observed.verified_outcomes,
        observed.rejected_outcomes,
        observed.inconclusive_outcomes,
        observed.policy_blocked_outcomes,
    ) == (0, 0, 0, 0)
    assert evaluation.failures == ()


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_json_reporting_exposes_intermediate_status(status: str):
    _, evaluation, _, _, _ = _outcome(status)
    payload = json.loads(evaluation_json(evaluation))
    case = payload["case_outcomes"][0]
    assert case["phase2_statuses"] == [status]
    assert case["runtime_success"] is True
    assert payload["aggregate_metrics"]["autonomy"]["intermediate_outcome_count"] == 1


def test_human_reporting_exposes_both_intermediate_metric_names():
    _, evaluation, _, _, _ = _outcome("verification_pending_cleanup")
    summary = human_summary(evaluation)
    assert "Intermediate outcomes: 1" in summary
    assert "verification pending cleanup: 1" in summary
    assert "awaiting controlled evidence: 0" in summary


def test_comparison_distinguishes_awaiting_evidence_from_runtime_failure():
    _, intermediate, _, _, _ = _outcome("awaiting_controlled_evidence")
    subject = intermediate.subject
    case = intermediate.cases[0]
    failed = EvaluationRunner().run(
        evaluation_run_id="actual-runtime-failure",
        subject=subject,
        cases=(case,),
        evaluator=lambda *_: (_ for _ in ()).throw(RuntimeError("private failure")),
        started_at=START,
        ended_at=END,
    )
    metrics = {item.metric: item for item in compare_runs(intermediate, failed).metrics}
    assert metrics["awaiting_controlled_evidence_count"].left_value == 1
    assert metrics["awaiting_controlled_evidence_count"].right_value == 0
    assert metrics["runtime_failures"].left_value == 0
    assert metrics["runtime_failures"].right_value == 1


def test_comparison_table_exposes_intermediate_and_failure_columns():
    _, evaluation, _, _, _ = _outcome("verification_pending_cleanup")
    table = comparison_table((evaluation,))
    assert "Pending Cleanup" in table
    assert "Awaiting Evidence" in table
    assert "Runtime Failures" in table


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_structural_expectation_matches_intermediate_status(status: str):
    expected = Phase2ResultStatus(status)
    evaluation, _, _, _ = _evaluate(status, expected_status=expected)
    observed = evaluation.case_outcomes[0]
    assert observed.expectations_checked == 1
    assert observed.expectations_satisfied is True
    assert observed.expectation_results[0].observed_value == status


def test_intermediate_expectation_mismatch_is_not_runtime_failure():
    evaluation, _, _, _ = _evaluate(
        "awaiting_controlled_evidence",
        expected_status=Phase2ResultStatus.verification_pending_cleanup,
    )
    observed = evaluation.case_outcomes[0]
    assert observed.expectations_satisfied is False
    assert observed.success is False
    assert observed.runtime_success is True
    assert observed.failure_code is None
    assert evaluation.failures == ()


def test_intermediate_outcome_does_not_change_material_fingerprint_semantics():
    cleanup, _, _, _ = _evaluate("verification_pending_cleanup")
    awaiting, _, _, _ = _evaluate("awaiting_controlled_evidence")
    assert cleanup.configuration_fingerprint == awaiting.configuration_fingerprint
    assert (
        cleanup.configuration_fingerprint_schema
        is awaiting.configuration_fingerprint_schema
    )


def test_outer_callback_failure_preserves_intermediate_checkpoint_accounting():
    _, baseline, autonomy_run, orchestrator, _ = _outcome(
        "verification_pending_cleanup"
    )
    subject = baseline.subject
    case = baseline.cases[0]

    def evaluator(selected, item, repetition):
        observe_autonomy_run(
            subject=selected,
            case=item,
            repetition=repetition,
            run=autonomy_run,
            history=orchestrator.history,
            routing_policy=selected.routing_policies[0],
        )
        raise RuntimeError("private post-observation failure")

    failed = (
        EvaluationRunner()
        .run(
            evaluation_run_id="post-intermediate-failure",
            subject=subject,
            cases=(case,),
            evaluator=evaluator,
            started_at=START,
            ended_at=END,
        )
        .case_outcomes[0]
    )
    assert failed.failure_code is EvaluationFailureCode.autonomy_failed
    assert failed.phase2_statuses == (Phase2ResultStatus.verification_pending_cleanup,)
    assert failed.model_usage == autonomy_run.model_usage
    assert failed.request_delta == CLEANUP_DELTA
    assert failed.iteration_provenance == autonomy_run.iteration_history


def test_intermediate_target_attribution_remains_category_exact():
    observed, _, _, _, _ = _outcome("verification_pending_cleanup")
    assert observed.request_delta.auth == 1
    assert observed.request_delta.verification == 1
    assert observed.request_delta.cleanup == 1
    assert observed.request_delta.discovery == 0


@pytest.mark.parametrize("status", sorted(INTERMEDIATE_RESULT_STATUSES))
def test_observer_does_not_mutate_intermediate_barriers(status: str):
    _, evaluation, autonomy_run, orchestrator, _ = _outcome(status)
    before_run = autonomy_run.model_dump_json()
    before_history = tuple(
        item.model_dump_json() for item in orchestrator.history.records
    )
    observe_autonomy_run(
        subject=evaluation.subject,
        case=evaluation.cases[0],
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=evaluation.subject.routing_policies[0],
    )
    assert autonomy_run.model_dump_json() == before_run
    assert (
        tuple(item.model_dump_json() for item in orchestrator.history.records)
        == before_history
    )
    assert autonomy_run.current_state is AutonomyState.stopped


def test_cleanup_barrier_remains_active_after_evaluation():
    _, _, autonomy_run, _, _ = _outcome("verification_pending_cleanup")
    assert autonomy_run.cleanup_barrier_active is True
    assert autonomy_run.stop_reason is StopReason.cleanup_barrier


def test_controlled_evidence_barrier_remains_deferred_after_evaluation():
    _, _, autonomy_run, _, runtime = _outcome("awaiting_controlled_evidence")
    assert autonomy_run.cleanup_barrier_active is False
    assert autonomy_run.stop_reason is StopReason.awaiting_controlled_evidence
    assert len(runtime.calls) == 1


def test_unknown_status_is_rejected_by_evaluation_outcome_contract():
    with pytest.raises(ValidationError):
        EvaluationCaseOutcome(
            subject_id="subject",
            case_id="case",
            repetition=0,
            execution_mode=EvaluationExecutionMode.controlled,
            success=True,
            phase2_statuses=("fabricated_pending_state",),
        )


def test_unknown_iteration_status_still_fails_closed_in_observer():
    _, evaluation, autonomy_run, _, _ = _outcome("awaiting_controlled_evidence")
    record = autonomy_run.iteration_history[0]
    fake_result = record.phase2_result.model_copy(
        update={"canonical_status": "fabricated_pending_state"}
    )
    fake_record = record.model_copy(update={"phase2_result": fake_result})
    fake_run = autonomy_run.model_copy(update={"iteration_history": (fake_record,)})
    with pytest.raises(ValueError):
        observe_autonomy_run(
            subject=evaluation.subject,
            case=evaluation.cases[0],
            repetition=0,
            run=fake_run,
            history=AutonomyHistory(),
            routing_policy=evaluation.subject.routing_policies[0],
        )


def test_model_generated_arbitrary_phase2_status_is_not_accepted():
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [autonomy_decision()],
        results=[_phase2_result("model_invented_status", RequestDelta())],
        route=autonomy_routing_policy(),
    )
    assert autonomy_run.current_state is AutonomyState.failed
    assert autonomy_run.iteration_history[0].phase2_result is None
    subject = synthetic_subject(
        "arbitrary-status",
        provider="openai",
        model="reasoning-model",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    observed = observe_autonomy_run(
        subject=subject,
        case=synthetic_case(execution_mode=EvaluationExecutionMode.controlled),
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=subject.routing_policies[0],
    )
    assert observed.failure_code is EvaluationFailureCode.autonomy_failed
    assert observed.phase2_statuses == ()


def test_evaluation_status_contract_is_bound_to_canonical_phase2_enum():
    assert CanonicalPhase2ExpectationStatus is Phase2ResultStatus
    outcome_annotation = EvaluationCaseOutcome.model_fields[
        "phase2_statuses"
    ].annotation
    expectation_annotation = ExpectedStructuralProperties.model_fields[
        "phase2_status"
    ].annotation
    assert "Phase2ResultStatus" in str(outcome_annotation)
    assert "Phase2ResultStatus" in str(expectation_annotation)
    assert "class CanonicalPhase2ExpectationStatus" not in inspect.getsource(
        evaluation_types
    )


def test_canonical_terminal_and_intermediate_sets_remain_disjoint_and_complete():
    assert TERMINAL_RESULT_STATUSES.isdisjoint(INTERMEDIATE_RESULT_STATUSES)
    assert TERMINAL_RESULT_STATUSES | INTERMEDIATE_RESULT_STATUSES == (
        PUBLIC_RESULT_STATUSES
    )
    assert {item.value for item in Phase2ResultStatus} == PUBLIC_RESULT_STATUSES


def test_evaluation_has_no_independent_phase2_status_vocabulary():
    source = Path(evaluation_types.__file__).read_text(encoding="utf-8")
    assert source.count("CanonicalPhase2ExpectationStatus = Phase2ResultStatus") == 1
    for status in PUBLIC_RESULT_STATUSES:
        assert f'{status} = "{status}"' not in source


def test_intermediate_accounting_types_remain_independent():
    observed, _, _, _, _ = _outcome("verification_pending_cleanup")
    assert isinstance(observed.request_delta, RequestDelta)
    assert type(observed.request_delta) is not type(observed.model_usage)
    assert "request_delta=model_usage" not in inspect.getsource(
        evaluation_types
    ).replace(" ", "")


@pytest.mark.parametrize(
    "sentinel",
    (
        "sk-live-CCX-P2F1-API-KEY",
        "Authorization: Bearer CCX-P2F1-AUTH",
        "Cookie: session=CCX-P2F1-COOKIE",
        "password=CCX-P2F1-PASSWORD",
        "recovery_secret=CCX-P2F1-RECOVERY",
        "private_recovery_state=CCX-P2F1-STATE",
        "chain_of_thought=CCX-P2F1-THOUGHT",
        "raw_provider_response=CCX-P2F1-RESPONSE",
    ),
)
def test_private_failure_sentinels_do_not_enter_intermediate_json(sentinel: str):
    _, baseline, autonomy_run, orchestrator, _ = _outcome(
        "awaiting_controlled_evidence"
    )

    def evaluator(selected, item, repetition):
        observe_autonomy_run(
            subject=selected,
            case=item,
            repetition=repetition,
            run=autonomy_run,
            history=orchestrator.history,
            routing_policy=selected.routing_policies[0],
        )
        raise RuntimeError(sentinel)

    evaluation = EvaluationRunner().run(
        evaluation_run_id="private-sentinel",
        subject=baseline.subject,
        cases=baseline.cases,
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    report = evaluation_json(evaluation)
    assert sentinel not in report
    assert Phase2ResultStatus.awaiting_controlled_evidence.value in report
