"""P2-1 authoritative structural expectation regression coverage."""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from agent_core.autonomy import AutonomyState, StopReason
from agent_core.consensus import AgreementType
from agent_core.model_evaluation import (
    CanonicalPhase2ExpectationStatus,
    EvaluationCaseOutcome,
    EvaluationExecutionMode,
    EvaluationRun,
    EvaluationRunner,
    EvaluationSubjectType,
    ExpectedStructuralProperties,
    SyntheticScenario,
    compare_runs,
    comparison_table,
    evaluation_json,
    human_summary,
    synthetic_case,
    synthetic_outcome,
    synthetic_subject,
)
from agent_core.model_evaluation import expectations as expectation_module
from agent_core.models import ModelUsageDelta
from agent_core.reasoning import ReasoningAction
from agent_core.request_budget import RequestDelta

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:00:01+00:00"


def checked_run(
    expected: ExpectedStructuralProperties,
    *,
    scenario: SyntheticScenario = SyntheticScenario.grounded_recommendation,
    execution_mode: EvaluationExecutionMode = EvaluationExecutionMode.reasoning_only,
    subject_type: EvaluationSubjectType = EvaluationSubjectType.single_model_reasoning,
    outcome_updates: dict | None = None,
    run_id: str = "expectation-run",
):
    subject = synthetic_subject("expectation-subject", subject_type=subject_type)
    case = synthetic_case(scenario, execution_mode=execution_mode).model_copy(
        update={"expected_structure": expected}
    )
    observed = synthetic_outcome(subject, case, 0, scenario)
    if outcome_updates:
        observed = observed.model_copy(update=outcome_updates)
    run = EvaluationRunner().run(
        evaluation_run_id=run_id,
        subject=subject,
        cases=(case,),
        evaluator=lambda *_: observed,
        started_at=START,
        ended_at=END,
    )
    return run, case, observed


def test_no_expectations_preserve_neutral_success_semantics():
    run, _, observed = checked_run(ExpectedStructuralProperties())
    outcome = run.case_outcomes[0]
    assert outcome.success is observed.success is True
    assert outcome.runtime_success is True
    assert outcome.expectations_present is False
    assert outcome.expectations_checked == 0
    assert outcome.expectations_satisfied is None
    assert outcome.failed_expectations == ()


def test_one_satisfied_and_one_failed_expectation_are_explicit():
    passed, _, _ = checked_run(
        ExpectedStructuralProperties(
            decision_action=ReasoningAction.recommend_verification
        )
    )
    failed, _, _ = checked_run(
        ExpectedStructuralProperties(decision_action=ReasoningAction.stop),
        run_id="failed-expectation-run",
    )
    assert passed.case_outcomes[0].success is True
    assert passed.case_outcomes[0].expectations_satisfied is True
    mismatch = failed.case_outcomes[0]
    assert mismatch.runtime_success is True
    assert mismatch.success is False
    assert mismatch.failure_code is None
    assert mismatch.expectations_satisfied is False
    assert len(mismatch.failed_expectations) == 1


def test_multiple_expectations_all_satisfied_and_one_failed():
    expected = ExpectedStructuralProperties(
        decision_action=ReasoningAction.recommend_verification,
        recommended_capability="bola",
        decision_valid=True,
        hypothesis_id="synthetic-grounded_recommendation",
        category="bola",
        maximum_target_requests=0,
        maximum_model_calls=1,
        fallback_used=False,
    )
    passed, _, _ = checked_run(expected)
    assert passed.case_outcomes[0].expectations_checked == 8
    assert passed.case_outcomes[0].expectations_satisfied is True

    failed, _, _ = checked_run(
        expected.model_copy(update={"recommended_capability": "ssrf"}),
        run_id="one-of-many-failed",
    )
    assert failed.case_outcomes[0].expectations_checked == 8
    assert len(failed.case_outcomes[0].failed_expectations) == 1


@pytest.mark.parametrize(
    ("field", "expected", "satisfied"),
    (
        ("decision_action", ReasoningAction.recommend_verification, True),
        ("decision_action", ReasoningAction.stop, False),
        ("recommended_capability", "bola", True),
        ("recommended_capability", "ssrf", False),
        ("decision_valid", True, True),
        ("decision_valid", False, False),
    ),
)
def test_reasoning_expectations(field, expected, satisfied):
    run, _, _ = checked_run(ExpectedStructuralProperties(**{field: expected}))
    assert run.case_outcomes[0].expectations_satisfied is satisfied


def test_expected_invalid_decision_can_be_satisfied_without_inflating_valid_rate():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(decision_valid=False),
        scenario=SyntheticScenario.invalid_capability,
    )
    outcome = run.case_outcomes[0]
    assert outcome.expectations_satisfied is True
    assert outcome.success is True
    assert run.aggregate_metrics.reasoning.valid_decision_rate == 0.0


def test_original_structural_expectation_fields_are_authoritatively_checked():
    passed, _, _ = checked_run(
        ExpectedStructuralProperties(
            minimum_valid_decisions=1,
            maximum_valid_decisions=1,
            allowed_actions=(ReasoningAction.recommend_verification,),
            allowed_capabilities=("bola",),
            evidence_references_required=True,
        )
    )
    assert passed.case_outcomes[0].expectations_checked == 5
    assert passed.case_outcomes[0].expectations_satisfied is True

    failed, _, _ = checked_run(
        ExpectedStructuralProperties(
            minimum_valid_decisions=2,
            allowed_actions=(ReasoningAction.stop,),
            allowed_capabilities=("ssrf",),
            evidence_references_required=True,
        ),
        outcome_updates={"decisions_with_evidence_references": 0},
        run_id="original-fields-failed",
    )
    assert failed.case_outcomes[0].expectations_checked == 4
    assert len(failed.case_outcomes[0].failed_expectations) == 4


@pytest.mark.parametrize(
    "agreement",
    (
        AgreementType.unanimous,
        AgreementType.majority,
        AgreementType.split,
        AgreementType.insufficient_participants,
    ),
)
def test_consensus_agreement_expectations(agreement):
    run, _, _ = checked_run(
        ExpectedStructuralProperties(consensus_agreement=agreement),
        subject_type=EvaluationSubjectType.consensus_reasoning,
        outcome_updates={"agreement_type": agreement},
    )
    assert run.case_outcomes[0].expectations_satisfied is True


def test_consensus_expectation_mismatch_is_not_truth_reinterpretation():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(consensus_agreement=AgreementType.unanimous),
        subject_type=EvaluationSubjectType.consensus_reasoning,
        outcome_updates={"agreement_type": AgreementType.majority},
    )
    outcome = run.case_outcomes[0]
    assert outcome.agreement_type is AgreementType.majority
    assert outcome.expectations_satisfied is False


def test_autonomy_terminal_state_and_stop_reason_expectations():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(
            autonomy_terminal_state=AutonomyState.stopped,
            stop_reason=StopReason.phase2_policy_blocked,
        ),
        scenario=SyntheticScenario.policy_block,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    assert run.case_outcomes[0].expectations_satisfied is True


def test_autonomy_terminal_state_mismatch():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(autonomy_terminal_state=AutonomyState.failed),
        execution_mode=EvaluationExecutionMode.dry_run,
        subject_type=EvaluationSubjectType.dry_run_autonomy,
    )
    assert run.case_outcomes[0].autonomy_terminal_state is AutonomyState.stopped
    assert run.case_outcomes[0].expectations_satisfied is False


@pytest.mark.parametrize(
    ("execution_mode", "subject_type", "scenario", "expected", "satisfied"),
    (
        (
            EvaluationExecutionMode.dry_run,
            EvaluationSubjectType.dry_run_autonomy,
            SyntheticScenario.grounded_recommendation,
            False,
            True,
        ),
        (
            EvaluationExecutionMode.controlled,
            EvaluationSubjectType.controlled_autonomy,
            SyntheticScenario.verified_result,
            False,
            False,
        ),
        (
            EvaluationExecutionMode.controlled,
            EvaluationSubjectType.controlled_autonomy,
            SyntheticScenario.verified_result,
            True,
            True,
        ),
    ),
)
def test_execution_expectations(
    execution_mode, subject_type, scenario, expected, satisfied
):
    run, _, _ = checked_run(
        ExpectedStructuralProperties(execution_occurred=expected),
        scenario=scenario,
        execution_mode=execution_mode,
        subject_type=subject_type,
    )
    assert run.case_outcomes[0].expectations_satisfied is satisfied


@pytest.mark.parametrize(
    ("scenario", "status"),
    (
        (SyntheticScenario.verified_result, CanonicalPhase2ExpectationStatus.verified),
        (SyntheticScenario.rejected_result, CanonicalPhase2ExpectationStatus.rejected),
        (
            SyntheticScenario.inconclusive_result,
            CanonicalPhase2ExpectationStatus.inconclusive,
        ),
        (
            SyntheticScenario.policy_block,
            CanonicalPhase2ExpectationStatus.policy_blocked,
        ),
    ),
)
def test_canonical_phase2_status_expectations(scenario, status):
    run, _, _ = checked_run(
        ExpectedStructuralProperties(phase2_status=status),
        scenario=scenario,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    outcome = run.case_outcomes[0]
    assert outcome.phase2_statuses == (status,)
    assert outcome.expectations_satisfied is True


def test_phase2_status_mismatch_preserves_canonical_status():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(
            phase2_status=CanonicalPhase2ExpectationStatus.rejected
        ),
        scenario=SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    outcome = run.case_outcomes[0]
    assert outcome.phase2_statuses == (CanonicalPhase2ExpectationStatus.verified,)
    assert outcome.verified_outcomes == 1
    assert outcome.expectations_satisfied is False


def test_target_request_expectations_use_request_delta_only():
    usage = ModelUsageDelta(
        attempted_calls=5,
        successful_calls=5,
        input_tokens=5,
        output_tokens=5,
        total_tokens=10,
    )
    run, _, _ = checked_run(
        ExpectedStructuralProperties(maximum_target_requests=1),
        scenario=SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
        outcome_updates={"model_usage": usage},
    )
    result = run.case_outcomes[0].expectation_results[0]
    assert result.observed_value == 1
    assert result.satisfied is True


def test_target_request_limit_exceeded_uses_authoritative_delta():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(maximum_target_requests=0),
        scenario=SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    outcome = run.case_outcomes[0]
    assert outcome.request_delta == RequestDelta(verification=1, attempted=1, total=1)
    assert outcome.expectations_satisfied is False


def test_model_call_and_fallback_expectations_remain_separate():
    subject = synthetic_subject(
        "fallback-subject",
        fallback_provider="anthropic",
        fallback_model="fallback-model",
    )
    expected = ExpectedStructuralProperties(
        maximum_model_calls=2,
        maximum_target_requests=0,
        fallback_used=True,
    )
    case = synthetic_case(SyntheticScenario.fallback).model_copy(
        update={"expected_structure": expected}
    )
    observed = synthetic_outcome(subject, case, 0, SyntheticScenario.fallback)
    run = EvaluationRunner().run(
        evaluation_run_id="fallback-expectation-run",
        subject=subject,
        cases=(case,),
        evaluator=lambda *_: observed,
        started_at=START,
        ended_at=END,
    )
    outcome = run.case_outcomes[0]
    assert outcome.model_usage.attempted_calls == 2
    assert outcome.request_delta.total == 0
    assert outcome.expectations_satisfied is True


def test_iteration_and_verification_bounds_are_checked():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(
            minimum_iterations=1,
            maximum_iterations=1,
            minimum_verifications=1,
            maximum_verifications=1,
        ),
        scenario=SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    assert run.case_outcomes[0].expectations_satisfied is True


def test_runtime_success_and_expectation_failure_remain_distinct():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(decision_action=ReasoningAction.stop)
    )
    outcome = run.case_outcomes[0]
    assert (outcome.runtime_success, outcome.success, outcome.failure_code) == (
        True,
        False,
        None,
    )
    assert run.failures == ()


def test_runtime_failure_has_deterministic_expectation_state():
    run, _, _ = checked_run(
        ExpectedStructuralProperties(maximum_target_requests=0),
        scenario=SyntheticScenario.provider_timeout,
    )
    outcome = run.case_outcomes[0]
    assert outcome.runtime_success is False
    assert outcome.success is False
    assert outcome.failure_code is not None
    assert outcome.expectations_satisfied is True


def test_expectation_metrics_are_truthful_and_do_not_change_reasoning_rates():
    passed, _, _ = checked_run(
        ExpectedStructuralProperties(
            decision_action=ReasoningAction.recommend_verification
        )
    )
    subject = passed.subject
    base_case = passed.cases[0]
    failed_case = base_case.model_copy(
        update={
            "case_id": "failed-case",
            "expected_structure": ExpectedStructuralProperties(
                decision_action=ReasoningAction.stop
            ),
        }
    )
    passed_outcome = passed.case_outcomes[0].model_copy(
        update={
            "expectations_present": False,
            "expectations_checked": 0,
            "expectations_satisfied": None,
            "expectation_results": (),
            "failed_expectations": (),
        }
    )
    failed_outcome = synthetic_outcome(
        subject, failed_case, 0, SyntheticScenario.grounded_recommendation
    )
    run = EvaluationRunner().run(
        evaluation_run_id="mixed-expectation-run",
        subject=subject,
        cases=(base_case, failed_case),
        evaluator=lambda _subject, case, _repetition: (
            passed_outcome if case.case_id == base_case.case_id else failed_outcome
        ),
        started_at=START,
        ended_at=END,
    )
    metrics = run.aggregate_metrics
    assert metrics.expectations.cases_with_expectations == 2
    assert metrics.expectations.cases_expectations_satisfied == 1
    assert metrics.expectations.cases_expectations_failed == 1
    assert metrics.expectations.expectation_pass_rate == 0.5
    assert metrics.reasoning.valid_decision_rate == 1.0


def test_json_human_and_comparison_reports_expose_expectations():
    passed, _, _ = checked_run(
        ExpectedStructuralProperties(
            decision_action=ReasoningAction.recommend_verification
        ),
        run_id="report-left",
    )
    failed, _, _ = checked_run(
        ExpectedStructuralProperties(decision_action=ReasoningAction.stop),
        run_id="report-right",
    )
    payload = evaluation_json(failed)
    assert '"expectation_results"' in payload
    assert '"expectations_satisfied": false' in payload
    assert (
        "Structural expectations: 0 passed / 1 failed / 1 configured"
        in human_summary(failed)
    )
    comparison = compare_runs(passed, failed)
    metric_names = {item.metric for item in comparison.metrics}
    assert {"expectation_pass_rate", "expectation_failures"} <= metric_names
    table = comparison_table((passed, failed))
    assert "Expectation Pass Rate | Expectation Failures" in table


def test_legacy_no_expectation_outcome_payload_remains_compatible():
    run, _, observed = checked_run(ExpectedStructuralProperties())
    payload = observed.model_dump(mode="python")
    for field in (
        "runtime_success",
        "expectations_present",
        "expectations_checked",
        "expectations_satisfied",
        "expectation_results",
        "failed_expectations",
    ):
        payload.pop(field)
    restored = EvaluationCaseOutcome.model_validate(payload)
    assert restored.runtime_success is restored.success
    assert restored.expectations_satisfied is None
    assert run.case_outcomes[0].success is True
    run_payload = run.model_dump(mode="python")
    run_payload["aggregate_metrics"].pop("expectations")
    restored_run = EvaluationRun.model_validate(run_payload)
    assert restored_run.aggregate_metrics.expectations.cases_with_expectations == 0


@pytest.mark.parametrize(
    "secret_text",
    (
        "api_key=CCX_SECRET_API",
        "Authorization: Bearer CCX_SECRET_AUTH",
        "cookie=CCX_SECRET_SESSION",
        "password=CCX_SECRET_PASSWORD",
        "recovery_code=CCX_SECRET_RECOVERY",
        "private_recovery_state=CCX_PRIVATE_STATE",
        "chain_of_thought=CCX_PRIVATE_THOUGHT",
        "raw_provider_response=CCX_RAW_RESPONSE",
    ),
)
def test_expectation_values_cannot_carry_private_or_raw_text(secret_text):
    with pytest.raises(ValidationError):
        ExpectedStructuralProperties(recommended_capability=secret_text)
    run, _, _ = checked_run(ExpectedStructuralProperties())
    assert secret_text not in evaluation_json(run)


def test_expectation_failure_does_not_rerun_or_tune_the_evaluator():
    calls = []
    subject = synthetic_subject("single-call-subject")
    case = synthetic_case().model_copy(
        update={
            "expected_structure": ExpectedStructuralProperties(
                decision_action=ReasoningAction.stop
            )
        }
    )
    observed = synthetic_outcome(
        subject, case, 0, SyntheticScenario.grounded_recommendation
    )

    def evaluator(*_):
        calls.append("called")
        return observed

    run = EvaluationRunner().run(
        evaluation_run_id="no-feedback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert calls == ["called"]
    assert run.case_outcomes[0].expectations_satisfied is False
    source = inspect.getsource(expectation_module)
    assert "rerun" not in source.casefold()
    assert "prompt" not in source.casefold()
    assert "routing_policy" not in source
