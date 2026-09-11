"""P3-6 model benchmarking, evaluation, and comparative telemetry tests."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import agent_core.model_evaluation as evaluation_package
import agent_core.model_evaluation.runner as runner_module
from agent_core.autonomy import AutonomyHistory, AutonomyLimits, StopReason
from agent_core.consensus import (
    AgreementType,
    ConsensusEngine,
    ConsensusParticipant,
    ConsensusRequest,
    ParticipantStatus,
    consensus_to_reasoning_decision,
)
from agent_core.model_evaluation import (
    AggregateMetrics,
    CaseModelProvenance,
    EvaluationCase,
    EvaluationCaseOutcome,
    EvaluationBudgetPreflight,
    EvaluationError,
    EvaluationExecutionMode,
    EvaluationFailureCode,
    EvaluationRun,
    EvaluationRunner,
    EvaluationSubject,
    EvaluationSubjectType,
    SyntheticScenario,
    calculate_aggregate_metrics,
    compare_runs,
    comparison_table,
    configuration_fingerprint,
    evaluation_json,
    human_summary,
    import_external_baseline,
    import_external_benchmark,
    observe_autonomy_run,
    observe_consensus_result,
    pareto_view,
    require_public_artifact,
    synthetic_case,
    synthetic_outcome,
    synthetic_route,
    synthetic_scenarios,
    synthetic_subject,
)
from agent_core.models import (
    ModelBudgetLimits,
    ModelErrorCode,
    ModelPrice,
    ModelPricingCatalog,
    ModelProviderError,
    ModelResponse,
    ModelRouter,
    ModelUsageDelta,
)
from agent_core.reasoning import ReasoningAction, build_reasoning_model_request
from agent_core.request_budget import RequestDelta
from tests.test_phase3_autonomy import (
    PostTrafficRuntime,
    decision as autonomy_decision,
    hypothesis,
    phase2_result,
    routing_policy as autonomy_routing_policy,
    run_autonomy,
    run_config,
    run_with_components,
    verification_plan,
    versioned_phase2_result,
)
from tests.test_phase3_consensus import (
    ScriptedReasoningEngine,
    canonical_reasoning_request,
    consensus_request,
    evaluate as evaluate_consensus,
    model_decision,
    unanimous_outcomes,
)

API_KEY_SENTINEL = "CCX_EVAL_API_KEY_18aa"
AUTH_SENTINEL = "CCX_EVAL_AUTH_29bb"
COOKIE_SENTINEL = "CCX_EVAL_COOKIE_30cc"
PASSWORD_SENTINEL = "CCX_EVAL_PASSWORD_41dd"
RECOVERY_SENTINEL = "CCX_EVAL_RECOVERY_52ee"
RAW_RESPONSE_SENTINEL = "CCX_EVAL_RAW_RESPONSE_63ff"
THOUGHT_SENTINEL = "CCX_EVAL_PRIVATE_REASONING_74aa"

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:00:05+00:00"


def outcome(
    subject: EvaluationSubject | None = None,
    case: EvaluationCase | None = None,
    *,
    scenario: SyntheticScenario = SyntheticScenario.grounded_recommendation,
    repetition: int = 0,
) -> EvaluationCaseOutcome:
    subject = subject or (
        synthetic_subject(
            fallback_provider="anthropic",
            fallback_model="claude-fallback",
        )
        if scenario is SyntheticScenario.fallback
        else synthetic_subject()
    )
    case = case or synthetic_case(scenario)
    return synthetic_outcome(subject, case, repetition, scenario)


def run_for(
    subject: EvaluationSubject | None = None,
    case: EvaluationCase | None = None,
    *,
    outcomes: tuple[EvaluationCaseOutcome, ...] | None = None,
    run_id: str = "evaluation-run",
) -> EvaluationRun:
    subject = subject or synthetic_subject()
    case = case or synthetic_case()
    scripted = outcomes or (outcome(subject, case),)
    return EvaluationRunner().run(
        evaluation_run_id=run_id,
        subject=subject,
        cases=(case,),
        evaluator=lambda _subject, _case, repetition: scripted[repetition],
        started_at=START,
        ended_at=END,
    )


def replace_usage(
    value: EvaluationCaseOutcome,
    *,
    calls: int = 1,
    successful: int = 1,
    input_tokens: int = 100,
    output_tokens: int = 50,
    cost: float | None = 1.0,
    latency: float = 2.0,
) -> EvaluationCaseOutcome:
    return value.model_copy(
        update={
            "model_usage": ModelUsageDelta(
                attempted_calls=calls,
                successful_calls=successful,
                failed_calls=calls - successful,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                estimated_cost_usd=cost,
                latency_seconds=latency,
            )
        }
    )


def metrics(*values: EvaluationCaseOutcome) -> AggregateMetrics:
    return calculate_aggregate_metrics(tuple(values), started_at=START, ended_at=END)


def test_strict_evaluation_subject():
    subject = synthetic_subject()
    assert subject.subject_type is EvaluationSubjectType.single_model_reasoning
    with pytest.raises(ValidationError):
        EvaluationSubject(**subject.model_dump(), unexpected=True)


def test_strict_evaluation_case():
    case = synthetic_case()
    assert case.reasoning_request.evidence_packets[0].category == "bola"
    with pytest.raises(ValidationError):
        EvaluationCase(**case.model_dump(), callback=lambda: None)


def test_strict_evaluation_run():
    run = run_for()
    assert run.evaluation_schema_version == 1
    with pytest.raises(ValidationError):
        EvaluationRun(**run.model_dump(), raw_provider_response={})


def test_reasoning_metrics():
    base = outcome()
    mixed = base.model_copy(
        update={
            "attempted_decisions": 2,
            "valid_decisions": 1,
            "invalid_decisions": 1,
            "schema_failures": 1,
            "capability_grounded_decisions": 1,
            "decisions_with_evidence_references": 1,
        }
    )
    result = metrics(mixed).reasoning
    assert result.valid_decision_rate == 0.5
    assert result.invalid_decision_rate == 0.5
    assert result.schema_failure_rate == 0.5


def test_autonomy_metrics():
    base = outcome()
    observed = base.model_copy(
        update={
            "autonomy_iterations": 3,
            "verifications_attempted": 2,
            "verifications_completed": 2,
            "verified_outcomes": 1,
            "rejected_outcomes": 1,
            "duplicate_recommendations_prevented": 1,
            "successful_pivots": 2,
        }
    )
    result = metrics(observed).autonomy
    assert (result.iterations, result.verifications_completed) == (3, 2)
    assert result.successful_pivots == 2


def test_consensus_metrics():
    base = outcome()
    observed = base.model_copy(
        update={
            "agreement_type": AgreementType.majority,
            "consensus_participants": 3,
            "invalid_participants": 1,
            "dissenting_participants": 1,
            "quorum_succeeded": True,
            "aggregate_confidence": 0.75,
        }
    )
    result = metrics(observed).consensus
    assert result.majority_rate == 1.0
    assert result.invalid_participant_rate == pytest.approx(1 / 3)
    assert result.quorum_success_rate == 1.0


def test_model_usage_metrics():
    observed = replace_usage(outcome(), calls=2, successful=1)
    result = metrics(observed).model_usage
    assert (result.model_call_count, result.failed_model_calls) == (2, 1)
    assert result.total_tokens == 150


def test_request_delta_metrics():
    observed = outcome().model_copy(
        update={
            "request_delta": RequestDelta(
                discovery=1,
                auth=2,
                verification=3,
                cleanup=1,
                attempted=7,
                total=7,
            )
        }
    )
    result = metrics(observed).target_requests
    assert result.target_requests == 7
    assert result.verification_requests == 3


def test_model_usage_delta_remains_separate_from_request_delta():
    original = RequestDelta()
    observed = replace_usage(outcome(), calls=3, successful=3)
    assert metrics(observed).model_usage.model_call_count == 3
    assert original == RequestDelta()
    assert metrics(observed).target_requests.target_requests == 0


def test_verified_per_model_call():
    observed = replace_usage(
        outcome().model_copy(
            update={"verifications_completed": 1, "verified_outcomes": 1}
        ),
        calls=2,
        successful=2,
    )
    assert metrics(observed).efficiency.verified_per_model_call == 0.5


def test_verified_per_token():
    observed = replace_usage(
        outcome().model_copy(
            update={"verifications_completed": 1, "verified_outcomes": 1}
        ),
        input_tokens=600,
        output_tokens=400,
    )
    assert metrics(observed).efficiency.verified_per_1k_tokens == 1.0


def test_verified_per_request():
    observed = outcome().model_copy(
        update={
            "verifications_completed": 1,
            "verified_outcomes": 1,
            "request_delta": RequestDelta(verification=2, attempted=2, total=2),
        }
    )
    assert metrics(observed).efficiency.verified_per_target_request == 0.5


def test_cost_efficiency_with_known_cost():
    observed = replace_usage(
        outcome().model_copy(
            update={"verifications_completed": 1, "verified_outcomes": 1}
        ),
        cost=0.5,
    )
    assert metrics(observed).efficiency.verified_per_estimated_dollar == 2.0


def test_cost_efficiency_with_unknown_cost():
    observed = replace_usage(outcome(), cost=None)
    assert metrics(observed).efficiency.verified_per_estimated_dollar is None


def test_zero_denominators_are_deterministic():
    empty = EvaluationCaseOutcome(
        subject_id="synthetic-gpt",
        case_id="case-grounded_recommendation",
        repetition=0,
        execution_mode=EvaluationExecutionMode.reasoning_only,
        success=True,
    )
    result = metrics(empty).efficiency
    assert result.verified_per_model_call == 0.0
    assert result.verified_per_1k_tokens == 0.0
    assert result.verified_per_target_request == 0.0


def test_timing_metrics():
    observed = replace_usage(outcome(), latency=2.0).model_copy(
        update={
            "time_to_first_valid_decision": 1.0,
            "time_to_first_verification": 2.0,
            "time_to_first_verified_outcome": 3.0,
            "phase2_execution_latency_seconds": 0.5,
        }
    )
    result = metrics(observed).timing
    assert result.total_evaluation_seconds == 5.0
    assert result.time_to_first_verified_outcome == 3.0
    assert result.phase2_execution_latency_seconds == 0.5


@pytest.mark.parametrize(
    ("left_provider", "right_provider"),
    (("openai", "anthropic"), ("openai", "ollama")),
)
def test_model_route_comparisons(left_provider, right_provider):
    case = synthetic_case()
    left_subject = synthetic_subject(
        f"subject-{left_provider}",
        provider=left_provider,
        model=f"{left_provider}-model",
    )
    right_subject = synthetic_subject(
        f"subject-{right_provider}",
        provider=right_provider,
        model=f"{right_provider}-model",
    )
    comparison = compare_runs(
        run_for(left_subject, case, run_id=f"run-{left_provider}"),
        run_for(right_subject, case, run_id=f"run-{right_provider}"),
    )
    assert comparison.configuration_compatible is False
    assert comparison.configuration_compatibility.value == "incompatible"
    assert comparison.metrics
    assert comparison.left_run_id == f"run-{left_provider}"


def test_single_model_vs_consensus_comparison():
    case = synthetic_case()
    single = synthetic_subject()
    consensus = synthetic_subject(
        "synthetic-consensus",
        subject_type=EvaluationSubjectType.consensus_reasoning,
    )
    result = compare_runs(
        run_for(single, case, run_id="run-single"),
        run_for(consensus, case, run_id="run-consensus"),
    )
    assert result.configuration_compatible is False
    assert result.metrics


def test_dry_run_vs_controlled_autonomy_comparison():
    dry_subject = synthetic_subject(
        "subject-dry", subject_type=EvaluationSubjectType.dry_run_autonomy
    )
    controlled_subject = synthetic_subject(
        "subject-controlled",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    dry_case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    controlled_case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    dry = run_for(dry_subject, dry_case, run_id="run-dry")
    controlled = run_for(
        controlled_subject,
        controlled_case,
        outcomes=(
            outcome(
                controlled_subject,
                controlled_case,
                scenario=SyntheticScenario.verified_result,
            ),
        ),
        run_id="run-controlled",
    )
    comparison = compare_runs(dry, controlled)
    assert comparison.configuration_compatible is False
    assert comparison.metrics


def test_local_vs_cloud_comparison():
    case = synthetic_case()
    local = synthetic_subject("subject-local", provider="ollama", model="local-model")
    cloud = synthetic_subject(
        "subject-cloud", provider="anthropic", model="cloud-model"
    )
    assert not compare_runs(
        run_for(local, case, run_id="run-local"),
        run_for(cloud, case, run_id="run-cloud"),
    ).configuration_compatible


def test_pareto_dominance():
    case = synthetic_case()
    better_subject = synthetic_subject("better")
    worse_subject = synthetic_subject("worse", provider="anthropic", model="claude")
    better = run_for(
        better_subject,
        case,
        outcomes=(
            replace_usage(
                outcome(better_subject, case),
                input_tokens=10,
                output_tokens=5,
                cost=0.1,
                latency=0.1,
            ),
        ),
        run_id="run-better",
    )
    worse = run_for(
        worse_subject,
        case,
        outcomes=(
            replace_usage(
                outcome(worse_subject, case),
                input_tokens=20,
                output_tokens=10,
                cost=0.2,
                latency=0.2,
            ),
        ),
        run_id="run-worse",
    )
    result = pareto_view((worse, better))
    assert result.frontier_subjects == ("better",)


def test_pareto_tradeoff_preserves_both_subjects():
    case = synthetic_case()
    quality_subject = synthetic_subject("quality")
    efficient_subject = synthetic_subject(
        "efficient", provider="anthropic", model="claude"
    )
    quality_outcome = replace_usage(
        outcome(quality_subject, case), input_tokens=30, output_tokens=20
    )
    efficient_outcome = replace_usage(
        outcome(efficient_subject, case), input_tokens=5, output_tokens=5
    ).model_copy(
        update={
            "attempted_decisions": 1,
            "valid_decisions": 0,
            "invalid_decisions": 1,
            "capability_grounded_decisions": 0,
            "decisions_with_evidence_references": 0,
        }
    )
    result = pareto_view(
        (
            run_for(
                quality_subject, case, outcomes=(quality_outcome,), run_id="run-quality"
            ),
            run_for(
                efficient_subject,
                case,
                outcomes=(efficient_outcome,),
                run_id="run-efficient",
            ),
        )
    )
    assert result.frontier_subjects == ("efficient", "quality")


def test_repeated_case_consistency():
    subject = synthetic_subject().model_copy(update={"repetitions": 3})
    case = synthetic_case()
    scripted = tuple(outcome(subject, case, repetition=index) for index in range(3))
    run = run_for(subject, case, outcomes=scripted)
    assert run.aggregate_metrics.reasoning.decision_consistency == 1.0
    assert run.aggregate_metrics.repeatability.repeated_case_count == 1
    assert run.aggregate_metrics.repeatability.mean_total_token_variance == 0.0


def test_configuration_fingerprint_is_stable():
    subject = synthetic_subject()
    cases = (synthetic_case(), synthetic_case(SyntheticScenario.invalid_capability))
    assert configuration_fingerprint(subject, cases) == configuration_fingerprint(
        subject, tuple(reversed(cases))
    )


def test_configuration_fingerprint_excludes_process_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY_SENTINEL)
    fingerprint = configuration_fingerprint(synthetic_subject(), (synthetic_case(),))
    assert API_KEY_SENTINEL not in fingerprint
    assert len(fingerprint) == 64


def test_provider_and_model_provenance():
    record = outcome().provenance[0]
    assert (record.requested_provider, record.actual_provider) == ("openai", "openai")
    assert record.reasoning_schema_version == 1


def test_fallback_provenance():
    observed = outcome(scenario=SyntheticScenario.fallback)
    assert observed.fallback_count == 1
    assert observed.provenance[0].fallback_used is True


def test_phase2_result_provenance():
    subject = synthetic_subject(
        "controlled", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(
        SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
    )
    observed = outcome(subject, case, scenario=SyntheticScenario.verified_result)
    assert observed.phase2_result_references == ("result-verified_result",)


def test_external_baseline_import():
    record = import_external_baseline(
        {
            "baseline_name": "phase2-external",
            "run_id": "external-run",
            "aggregate_metrics": {"precision": 0.8, "requests": 10},
            "recorded_at": START,
            "configuration_reference": "external-config",
        }
    )
    assert record.aggregate_metrics["precision"] == 0.8


def test_malformed_external_baseline():
    with pytest.raises(EvaluationError) as error:
        import_external_baseline("{malformed")
    assert error.value.code is EvaluationFailureCode.external_benchmark_invalid
    with pytest.raises(EvaluationError):
        import_external_baseline(
            {
                "baseline_name": "invalid-external",
                "run_id": "external-run",
                "aggregate_metrics": {"vulnerability_id_count": 1},
                "recorded_at": START,
                "configuration_reference": "external-config",
            }
        )


def test_external_benchmark_aggregate_import():
    record = import_external_benchmark(
        {
            "benchmark_name": "external-suite",
            "run_id": "external-run",
            "aggregate_metrics": {"verification_rate": 0.5},
            "matched_count": 2,
            "discovered_count": 3,
            "verified_count": 1,
            "recorded_at": START,
            "configuration_reference": "external-config",
        }
    )
    assert (record.matched_count, record.verified_count) == (2, 1)


def test_external_import_does_not_access_benchmark_source_code():
    source = inspect.getsource(evaluation_package.import_external_benchmark)
    assert "Path(" not in source
    assert "open(" not in source


def test_no_automatic_tuning_route():
    source = inspect.getsource(runner_module.EvaluationRunner)
    assert ".route(" not in source
    assert "prompt" not in source.casefold()
    assert "capability_registry" not in source.casefold()


def test_json_report():
    payload = json.loads(evaluation_json(run_for()))
    assert payload["evaluation_schema_version"] == 1
    assert payload["aggregate_metrics"]["model_usage"]["model_call_count"] == 1


def test_human_summary():
    summary = human_summary(run_for())
    assert "Valid decision rate" in summary
    assert "P3-4 and Phase 2 remain mandatory" in summary


def test_comparison_table():
    table = comparison_table((run_for(),))
    assert "Subject | Valid Decisions" in table
    assert "synthetic-gpt" in table


@pytest.mark.parametrize(
    ("field", "sentinel"),
    (
        ("api_key", API_KEY_SENTINEL),
        ("Authorization", AUTH_SENTINEL),
        ("cookie", COOKIE_SENTINEL),
        ("password", PASSWORD_SENTINEL),
        ("recovery_secret", RECOVERY_SENTINEL),
    ),
)
def test_evaluation_artifact_sanitizer_rejects_private_fields(field, sentinel):
    with pytest.raises(ValueError):
        require_public_artifact({field: sentinel})


def test_chain_of_thought_is_absent():
    payload = evaluation_json(run_for())
    assert "chain_of_thought" not in payload
    assert THOUGHT_SENTINEL not in payload


def test_raw_provider_response_is_absent():
    payload = evaluation_json(run_for())
    assert "raw_provider_response" not in payload
    assert RAW_RESPONSE_SENTINEL not in payload


def test_evaluation_failure_is_normalized():
    subject = synthetic_subject()
    case = synthetic_case()

    def failing(_subject, _case, _repetition):
        raise RuntimeError(API_KEY_SENTINEL)

    run = EvaluationRunner().run(
        evaluation_run_id="failed-run",
        subject=subject,
        cases=(case,),
        evaluator=failing,
        started_at=START,
        ended_at=END,
    )
    assert run.failures[0].failure_code is EvaluationFailureCode.reasoning_failed
    assert run.aggregate_metrics.model_usage.estimated_api_cost_usd is None
    assert API_KEY_SENTINEL not in evaluation_json(run)


def test_dry_run_request_delta_is_zero():
    subject = synthetic_subject(
        "dry", subject_type=EvaluationSubjectType.dry_run_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    run = run_for(subject, case)
    assert run.aggregate_metrics.target_requests.target_requests == 0


def test_controlled_execution_observation_uses_p3_4_only():
    run, orchestrator, _, runtime = run_autonomy(
        [autonomy_decision(), autonomy_decision(action=ReasoningAction.stop)]
    )
    subject = synthetic_subject(
        "controlled", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    assert len(runtime.calls) == 1
    assert observed.request_delta == run.phase2_request_usage


def test_no_direct_phase2_executor_route():
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(evaluation_package.__file__).parent.glob("*.py")
    )
    assert "ControlledVerificationExecutor" not in source
    assert "execute_selected" not in source
    assert "controlled_executor" not in source


def test_local_only_evaluation_records_zero_cloud_calls():
    subject = synthetic_subject("local", provider="ollama", model="local-model")
    case = synthetic_case()
    cloud_calls = {"openai": 0, "anthropic": 0}

    def local_evaluator(selected, item, repetition):
        assert selected.local_only is True
        return outcome(selected, item, repetition=repetition)

    run = EvaluationRunner().run(
        evaluation_run_id="local-run",
        subject=subject,
        cases=(case,),
        evaluator=local_evaluator,
        started_at=START,
        ended_at=END,
    )
    assert cloud_calls == {"openai": 0, "anthropic": 0}
    assert run.case_outcomes[0].provenance[0].actual_provider == "ollama"


@pytest.mark.parametrize(
    ("budget_update", "usage_update"),
    (
        ({"max_model_calls": 1}, {}),
        ({"max_total_tokens": 30}, {"input_tokens": 20, "output_tokens": 10}),
        ({"max_estimated_cost_usd": 0.002}, {"cost": 0.002}),
    ),
)
def test_evaluation_budgets_stop_before_next_repetition(budget_update, usage_update):
    subject = synthetic_subject().model_copy(update={"repetitions": 2})
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(**budget_update)}
    )
    calls = []

    def evaluator(selected, item, repetition):
        calls.append(repetition)
        value = outcome(selected, item, repetition=repetition)
        return replace_usage(value, **usage_update) if usage_update else value

    pricing = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="gpt-synthetic",
                input_per_million_usd=0.01,
                output_per_million_usd=0.01,
            ),
        )
    )
    if "max_total_tokens" in budget_update:
        estimate = EvaluationBudgetPreflight((case,)).input_token_reservation(case)
        case = case.model_copy(
            update={"model_budget": ModelBudgetLimits(max_total_tokens=estimate + 10)}
        )
        usage_update = {"input_tokens": estimate, "output_tokens": 10}
    run = EvaluationRunner(pricing=pricing).run(
        evaluation_run_id="budget-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert calls == [0]
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted


def test_fallback_accounting():
    result = metrics(outcome(scenario=SyntheticScenario.fallback)).model_usage
    assert result.fallback_count == 1
    assert result.fallback_rate == 1.0
    assert (result.model_call_count, result.failed_model_calls) == (2, 1)


def test_consensus_usage_aggregation():
    consensus_result, _, _ = evaluate_consensus(unanimous_outcomes())
    subject = synthetic_subject(
        "consensus", subject_type=EvaluationSubjectType.consensus_reasoning
    )
    case = synthetic_case()
    observed = observe_consensus_result(
        subject=subject,
        case=case,
        repetition=0,
        result=consensus_result,
    )
    assert observed.model_usage.attempted_calls == 3
    assert observed.consensus_participants == 3


def test_successful_pivot_accounting():
    subject = synthetic_subject(
        "controlled", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(
        SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
    )
    observed = outcome(subject, case, scenario=SyntheticScenario.verified_result)
    assert metrics(observed).autonomy.successful_pivots == 1


def test_deterministic_stop_metrics():
    observed = outcome().model_copy(
        update={
            "stop_reason": StopReason.manual_review_required,
            "manual_review_outcomes": 1,
        }
    )
    result = metrics(observed).autonomy
    assert result.stop_reasons == {"manual_review_required": 1}


def test_configuration_mismatch_comparison():
    left = run_for(run_id="left")
    other_case = synthetic_case(SyntheticScenario.invalid_capability)
    right = run_for(case=other_case, run_id="right")
    result = compare_runs(left, right)
    assert result.configuration_compatible is False
    assert result.mismatch_reasons == ("material_configuration_mismatch",)


def test_schema_version_provenance():
    record = outcome().provenance[0]
    assert record.reasoning_schema_version == 1
    consensus_record = CaseModelProvenance(
        requested_provider="openai",
        requested_model="gpt",
        actual_provider="anthropic",
        actual_model="claude",
        fallback_used=True,
        reasoning_schema_version=1,
        consensus_schema_version=1,
        autonomy_schema_version=1,
        phase2_result_references=("result-ref",),
    )
    assert consensus_record.consensus_schema_version == 1


def test_no_external_range_dependency():
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(evaluation_package.__file__).parent.glob("*.py")
    ).casefold()
    assert "cybercortex-range" not in source
    assert "range ground" not in source


def test_synthetic_fixtures_contain_no_hidden_identifiers():
    source = inspect.getsource(evaluation_package.synthetic_case).casefold()
    assert "vulnerability_id" not in source
    assert "expected_vulnerability" not in source
    assert set(synthetic_scenarios()) == set(SyntheticScenario)


def test_no_benchmark_aware_routing():
    source = inspect.getsource(runner_module)
    assert "benchmark_score" not in source
    assert "preferred_provider" not in source
    assert ".route(" not in source


def test_no_benchmark_aware_prompt_mutation():
    source = inspect.getsource(runner_module)
    assert "system_instructions" not in source
    assert "user_content" not in source
    assert "prompt_builder" not in source


def test_synthetic_end_to_end_gpt_vs_claude_dry_run_comparison():
    case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    subjects = (
        synthetic_subject(
            "dry-gpt",
            provider="openai",
            model="gpt-synthetic",
            subject_type=EvaluationSubjectType.dry_run_autonomy,
        ),
        synthetic_subject(
            "dry-claude",
            provider="anthropic",
            model="claude-synthetic",
            subject_type=EvaluationSubjectType.dry_run_autonomy,
        ),
    )
    evaluation_runs = []
    for subject in subjects:
        route = subject.routing_policies[0]
        selected_decision = autonomy_decision().model_copy(
            update={
                "model_provenance": autonomy_decision().model_provenance.model_copy(
                    update={
                        "provider_requested": route.preferred.provider,
                        "provider_used": route.preferred.provider,
                        "model_used": route.preferred.model,
                    }
                )
            }
        )
        autonomy_run, orchestrator, _, runtime = run_autonomy(
            [selected_decision],
            config=run_config(dry_run=True),
            route=route,
        )
        assert runtime.calls == []
        observed = observe_autonomy_run(
            subject=subject,
            case=case,
            repetition=0,
            run=autonomy_run,
            history=orchestrator.history,
            routing_policy=route,
        )
        evaluation_runs.append(
            run_for(
                subject,
                case,
                outcomes=(observed,),
                run_id=f"evaluation-{subject.subject_id}",
            )
        )
    comparison = compare_runs(*evaluation_runs)
    assert comparison.configuration_compatible is False
    assert comparison.metrics
    assert all(
        run.aggregate_metrics.target_requests.target_requests == 0
        for run in evaluation_runs
    )
    assert {
        run.case_outcomes[0].provenance[0].requested_provider for run in evaluation_runs
    } == {"openai", "anthropic"}


class BudgetProvider:
    def __init__(self, provider, model, responder):
        self.provider_name = provider
        self.model_name = model
        self.responder = responder
        self.requests = []

    def generate(self, request):
        self.requests.append(request)
        if isinstance(self.responder, BaseException):
            raise self.responder
        return self.responder(request)


class BudgetRegistry:
    def __init__(self, providers, *, pricing=None):
        self.providers = providers
        self.pricing = pricing or ModelPricingCatalog()

    def create(self, provider, *, model_name=None):
        return self.providers[(provider, model_name)]


def budget_response(
    provider,
    model,
    *,
    input_tokens=1,
    output_tokens=1,
    cost=0.0,
):
    def respond(request):
        return ModelResponse(
            provider=provider,
            model=model,
            content="synthetic public evaluation",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=cost,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
        )

    return respond


def routed_evaluator(router, *, max_output_tokens=10):
    def evaluate_route(selected, item, repetition):
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=max_output_tokens,
        )
        before = router.ledger.snapshot(run_id=request.run_id)
        try:
            router.route(request, selected.routing_policies[0])
        except ModelProviderError:
            usage = router.ledger.delta(
                before, router.ledger.snapshot(run_id=request.run_id)
            )
            route = selected.routing_policies[0].preferred
            return EvaluationCaseOutcome(
                subject_id=selected.subject_id,
                case_id=item.case_id,
                repetition=repetition,
                execution_mode=item.execution_mode,
                success=False,
                failure_code=EvaluationFailureCode.reasoning_failed,
                model_usage=usage,
                provenance=(
                    CaseModelProvenance(
                        requested_provider=route.provider,
                        requested_model=route.model,
                        actual_provider=None,
                        actual_model=None,
                        reasoning_schema_version=1,
                    ),
                ),
            )
        usage = router.ledger.delta(
            before, router.ledger.snapshot(run_id=request.run_id)
        )
        return outcome(selected, item, repetition=repetition).model_copy(
            update={"model_usage": usage}
        )

    return evaluate_route


def evaluation_with_router(
    *,
    subject,
    case,
    provider,
    pricing=None,
    max_output_tokens=10,
):
    registry = BudgetRegistry(
        {(provider.provider_name, provider.model_name): provider},
        pricing=pricing,
    )
    router = ModelRouter(registry)
    run = EvaluationRunner(
        pricing=pricing,
        max_output_tokens=max_output_tokens,
    ).run(
        evaluation_run_id="strict-budget-run",
        subject=subject,
        cases=(case,),
        evaluator=routed_evaluator(router, max_output_tokens=max_output_tokens),
        started_at=START,
        ended_at=END,
    )
    return run, router


def test_evaluation_budget_exact_model_call_boundary():
    subject = synthetic_subject("exact-call", provider="ollama", model="local-model")
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert run.case_outcomes[0].success is True
    assert run.case_outcomes[0].model_usage.attempted_calls == 1
    assert len(provider.requests) == 1


def test_evaluation_budget_one_over_model_call_boundary():
    subject = synthetic_subject(
        "one-over-call", provider="ollama", model="local-model"
    ).model_copy(update={"repetitions": 2})
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert len(provider.requests) == 1
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted
    assert run.case_outcomes[1].model_usage == ModelUsageDelta()


def test_evaluation_budget_exact_input_token_boundary():
    subject = synthetic_subject("exact-input", provider="ollama", model="local-model")
    base = synthetic_case()
    estimate = EvaluationBudgetPreflight(
        (base,), max_output_tokens=10
    ).input_token_reservation(base)
    case = base.model_copy(
        update={"model_budget": ModelBudgetLimits(max_input_tokens=estimate)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response(
            "ollama", "local-model", input_tokens=estimate, output_tokens=1
        ),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert run.case_outcomes[0].success is True
    assert len(provider.requests) == 1


def test_evaluation_budget_one_over_input_token_boundary():
    subject = synthetic_subject(
        "one-over-input", provider="ollama", model="local-model"
    )
    base = synthetic_case()
    estimate = EvaluationBudgetPreflight(
        (base,), max_output_tokens=10
    ).input_token_reservation(base)
    case = base.model_copy(
        update={"model_budget": ModelBudgetLimits(max_input_tokens=estimate - 1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert not provider.requests
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted


def test_evaluation_budget_reserves_output_tokens_before_provider_call():
    subject = synthetic_subject(
        "output-reservation", provider="ollama", model="local-model"
    )
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_output_tokens=3)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model", output_tokens=3),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert run.case_outcomes[0].success is True
    assert provider.requests[0].max_output_tokens == 3


def test_evaluation_budget_exact_total_token_boundary():
    subject = synthetic_subject("exact-total", provider="ollama", model="local-model")
    base = synthetic_case()
    estimate = EvaluationBudgetPreflight(
        (base,), max_output_tokens=10
    ).input_token_reservation(base)
    case = base.model_copy(
        update={"model_budget": ModelBudgetLimits(max_total_tokens=estimate + 1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response(
            "ollama", "local-model", input_tokens=estimate, output_tokens=1
        ),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert run.case_outcomes[0].success is True
    assert provider.requests[0].max_output_tokens == 1


def cost_fixture():
    subject = synthetic_subject("known-cost", provider="openai", model="priced-model")
    case = synthetic_case()
    pricing = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="priced-model",
                input_per_million_usd=1.0,
                output_per_million_usd=2.0,
            ),
        )
    )
    estimate = EvaluationBudgetPreflight(
        (case,), pricing=pricing, max_output_tokens=10
    ).input_token_reservation(case)
    predicted = pricing.estimate_cost(
        "openai",
        "priced-model",
        input_tokens=estimate,
        output_tokens=10,
    )
    assert predicted is not None
    return subject, case, pricing, estimate, predicted


def test_evaluation_budget_known_cost_exact_boundary():
    subject, base, pricing, estimate, predicted = cost_fixture()
    case = base.model_copy(
        update={"model_budget": ModelBudgetLimits(max_estimated_cost_usd=predicted)}
    )
    provider = BudgetProvider(
        "openai",
        "priced-model",
        budget_response(
            "openai",
            "priced-model",
            input_tokens=estimate,
            output_tokens=10,
            cost=predicted,
        ),
    )
    run, _ = evaluation_with_router(
        subject=subject,
        case=case,
        provider=provider,
        pricing=pricing,
    )
    assert run.case_outcomes[0].success is True
    assert len(provider.requests) == 1


def test_evaluation_budget_known_cost_one_over_boundary():
    subject, base, pricing, _, predicted = cost_fixture()
    case = base.model_copy(
        update={
            "model_budget": ModelBudgetLimits(
                max_estimated_cost_usd=predicted - 0.000000001
            )
        }
    )
    provider = BudgetProvider(
        "openai",
        "priced-model",
        budget_response("openai", "priced-model", cost=predicted),
    )
    run, _ = evaluation_with_router(
        subject=subject,
        case=case,
        provider=provider,
        pricing=pricing,
    )
    assert not provider.requests
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted


def test_evaluation_budget_unknown_price_strict_ceiling_fails_closed():
    subject = synthetic_subject("unknown-cost", provider="openai", model="unknown")
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_estimated_cost_usd=100.0)}
    )
    provider = BudgetProvider(
        "openai",
        "unknown",
        budget_response("openai", "unknown", cost=None),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert not provider.requests
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted


def test_evaluation_fallback_attempts_share_authoritative_budget():
    subject = synthetic_subject(
        "fallback-budget",
        provider="openai",
        model="primary",
        fallback_provider="ollama",
        fallback_model="fallback",
    )
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=1)}
    )
    primary = BudgetProvider(
        "openai",
        "primary",
        ModelProviderError(ModelErrorCode.timeout, provider="openai", model="primary"),
    )
    fallback = BudgetProvider(
        "ollama",
        "fallback",
        budget_response("ollama", "fallback"),
    )
    router = ModelRouter(
        BudgetRegistry(
            {
                ("openai", "primary"): primary,
                ("ollama", "fallback"): fallback,
            }
        )
    )
    run = EvaluationRunner(max_output_tokens=10).run(
        evaluation_run_id="fallback-budget-run",
        subject=subject,
        cases=(case,),
        evaluator=routed_evaluator(router),
        started_at=START,
        ended_at=END,
    )
    assert len(primary.requests) == 1
    assert not fallback.requests
    assert run.case_outcomes[0].model_usage.failed_calls == 1


def test_evaluation_consensus_participants_share_authoritative_budget():
    first_policy = synthetic_route("openai", "gpt-consensus")
    second_policy = synthetic_route("anthropic", "claude-consensus")
    subject = synthetic_subject(
        "consensus-budget",
        subject_type=EvaluationSubjectType.consensus_reasoning,
    ).model_copy(update={"routing_policies": (first_policy, second_policy)})
    request = canonical_reasoning_request()
    case = synthetic_case().model_copy(
        update={
            "reasoning_request": request,
            "model_budget": ModelBudgetLimits(max_model_calls=1),
        }
    )
    captured = {}

    def evaluator(selected, item, repetition):
        participants = tuple(
            ConsensusParticipant(
                participant_id=f"participant-{index}", routing_policy=policy
            )
            for index, policy in enumerate(selected.routing_policies)
        )
        scripted = ScriptedReasoningEngine(
            {
                (
                    participant.routing_policy.preferred.provider,
                    participant.routing_policy.preferred.model,
                ): model_decision(participant)
                for participant in participants
            }
        )
        result = ConsensusEngine(scripted).evaluate(
            ConsensusRequest(
                reasoning_request=item.reasoning_request,
                participants=participants,
                policy=selected.consensus_policy,
                model_budget=selected.consensus_budget,
                task_type=item.task_type.value,
                run_id=item.reasoning_request.run_id,
                iteration_reference="evaluation-consensus",
            )
        )
        captured["calls"] = len(scripted.requests)
        captured["statuses"] = tuple(entry.status for entry in result.participants)
        return observe_consensus_result(
            subject=selected,
            case=item,
            repetition=repetition,
            result=result,
        )

    run = EvaluationRunner().run(
        evaluation_run_id="consensus-budget-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert captured["calls"] == 1
    assert captured["statuses"].count(ParticipantStatus.budget_blocked) == 1
    assert run.case_outcomes[0].model_usage.attempted_calls == 1


def test_repeated_evaluation_cases_share_configured_run_budget():
    subject = synthetic_subject("shared-run", provider="ollama", model="local-model")
    first = synthetic_case().model_copy(
        update={
            "case_id": "case-a",
            "model_budget": ModelBudgetLimits(max_model_calls=1),
        }
    )
    second = synthetic_case().model_copy(
        update={
            "case_id": "case-b",
            "model_budget": ModelBudgetLimits(max_model_calls=1),
        }
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
    run = EvaluationRunner(max_output_tokens=10).run(
        evaluation_run_id="shared-case-run",
        subject=subject,
        cases=(first, second),
        evaluator=routed_evaluator(router),
        started_at=START,
        ended_at=END,
    )
    assert len(provider.requests) == 1
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted


def test_dry_run_evaluation_enforces_model_budget():
    subject = synthetic_subject(
        "dry-budget",
        provider="ollama",
        model="local-model",
        subject_type=EvaluationSubjectType.dry_run_autonomy,
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run).model_copy(
        update={"model_budget": ModelBudgetLimits(max_input_tokens=1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert not provider.requests
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted
    assert run.case_outcomes[0].request_delta == RequestDelta()


def test_rejected_evaluation_call_has_zero_provider_invocations():
    subject = synthetic_subject("zero-provider", provider="ollama", model="local-model")
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_total_tokens=1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        budget_response("ollama", "local-model"),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    assert not provider.requests
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted


def test_model_budget_rejection_does_not_alter_request_delta():
    subject = synthetic_subject(
        "controlled-budget",
        provider="ollama",
        model="local-model",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    case = synthetic_case(
        SyntheticScenario.verified_result,
        execution_mode=EvaluationExecutionMode.controlled,
    ).model_copy(update={"model_budget": ModelBudgetLimits(max_input_tokens=1)})
    calls = []

    def prohibited_evaluator(selected, item, repetition):
        calls.append(repetition)
        return outcome(
            selected,
            item,
            scenario=SyntheticScenario.verified_result,
            repetition=repetition,
        )

    run = EvaluationRunner().run(
        evaluation_run_id="request-delta-budget-run",
        subject=subject,
        cases=(case,),
        evaluator=prohibited_evaluator,
        started_at=START,
        ended_at=END,
    )
    assert not calls
    assert run.case_outcomes[0].request_delta == RequestDelta()
    assert run.aggregate_metrics.target_requests.target_requests == 0


def test_budget_blocked_and_failed_usage_accounting_is_truthful():
    subject = synthetic_subject(
        "failed-accounting", provider="ollama", model="local-model"
    ).model_copy(update={"repetitions": 2})
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=1)}
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        ModelProviderError(
            ModelErrorCode.timeout, provider="ollama", model="local-model"
        ),
    )
    run, _ = evaluation_with_router(subject=subject, case=case, provider=provider)
    failed, blocked = run.case_outcomes
    assert (failed.model_usage.attempted_calls, failed.model_usage.failed_calls) == (
        1,
        1,
    )
    assert blocked.failure_code is EvaluationFailureCode.budget_exhausted
    assert blocked.model_usage == ModelUsageDelta()
    assert run.aggregate_metrics.model_usage.model_call_count == 1


def test_failed_attempt_token_reservation_blocks_repeated_evaluation_case():
    subject = synthetic_subject(
        "failed-token-reservation",
        provider="ollama",
        model="local-model",
    ).model_copy(update={"repetitions": 2})
    case = synthetic_case().model_copy(
        update={
            "model_budget": ModelBudgetLimits(
                max_model_calls=2,
                max_output_tokens=1,
            )
        }
    )
    provider = BudgetProvider(
        "ollama",
        "local-model",
        ModelProviderError(
            ModelErrorCode.timeout,
            provider="ollama",
            model="local-model",
        ),
    )

    run, _ = evaluation_with_router(
        subject=subject,
        case=case,
        provider=provider,
        max_output_tokens=1,
    )

    failed, blocked = run.case_outcomes
    assert len(provider.requests) == 1
    assert failed.model_usage.output_tokens == 0
    assert failed.model_usage.budget_output_tokens == 1
    assert failed.model_usage.unknown_usage_calls == 1
    assert blocked.failure_code is EvaluationFailureCode.budget_exhausted
    assert blocked.model_usage == ModelUsageDelta()


def test_evaluation_fallback_cannot_reuse_one_call_total_token_reservation():
    subject = synthetic_subject(
        "failed-fallback-reservation",
        provider="openai",
        model="primary",
        fallback_provider="anthropic",
        fallback_model="fallback",
    )
    base = synthetic_case()
    input_tokens = EvaluationBudgetPreflight(
        (base,),
        max_output_tokens=1,
    ).input_token_reservation(base)
    case = base.model_copy(
        update={
            "model_budget": ModelBudgetLimits(
                max_model_calls=2,
                max_total_tokens=input_tokens + 1,
            )
        }
    )
    first = BudgetProvider(
        "openai",
        "primary",
        ModelProviderError(
            ModelErrorCode.timeout,
            provider="openai",
            model="primary",
        ),
    )
    second = BudgetProvider(
        "anthropic",
        "fallback",
        budget_response("anthropic", "fallback"),
    )
    router = ModelRouter(
        BudgetRegistry(
            {
                ("openai", "primary"): first,
                ("anthropic", "fallback"): second,
            }
        )
    )

    run = EvaluationRunner(max_output_tokens=1).run(
        evaluation_run_id="failed-fallback-reservation-run",
        subject=subject,
        cases=(case,),
        evaluator=routed_evaluator(router, max_output_tokens=1),
        started_at=START,
        ended_at=END,
    )

    observed = run.case_outcomes[0]
    assert len(first.requests) == 1
    assert second.requests == []
    assert observed.success is False
    assert observed.model_usage.budget_total_tokens == input_tokens + 1
    assert observed.model_usage.total_tokens == 0


def test_audit_off_by_one_fallback_outcome_cannot_complete_successfully():
    original_subject = synthetic_subject(
        "audit-regression",
        provider="openai",
        model="primary",
        fallback_provider="anthropic",
        fallback_model="fallback",
    )
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=1)}
    )
    scripted = synthetic_outcome(
        original_subject,
        case,
        0,
        SyntheticScenario.fallback,
    )
    grants = []

    def evaluator(selected, item, repetition):
        grants.append(len(selected.routing_policies[0].ordered_routes()))
        return scripted

    run = EvaluationRunner().run(
        evaluation_run_id="audit-off-by-one",
        subject=original_subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert grants == [1]
    assert run.case_outcomes[0].success is False
    assert run.case_outcomes[0].failure_code is EvaluationFailureCode.budget_exhausted
    assert run.case_outcomes[0].model_usage.attempted_calls == 2


def test_p1_2_evaluation_includes_failed_autonomy_target_requests():
    autonomy_run, orchestrator, _, _ = run_with_components(
        PostTrafficRuntime(
            ("verification",),
            error=RuntimeError("private post-traffic failure"),
        )
    )
    subject = synthetic_subject(
        "failed-autonomy-evaluation",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    assert observed.success is False
    assert observed.failure_code is EvaluationFailureCode.autonomy_failed
    assert observed.request_delta.verification == 1


def test_p1_2_evaluation_aggregates_partial_failed_execution():
    autonomy_run, orchestrator, _, _ = run_with_components(
        PostTrafficRuntime(
            ("auth", "verification"),
            error=RuntimeError("private partial failure"),
        )
    )
    subject = synthetic_subject(
        "partial-autonomy-evaluation",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    evaluation = run_for(subject, case, outcomes=(observed,))
    target = evaluation.aggregate_metrics.target_requests
    assert target.target_requests == 2
    assert target.auth_requests == 1
    assert target.verification_requests == 1


def test_p1_3_evaluation_and_aggregate_metrics_consume_complete_history():
    first = autonomy_decision("hyp-1", fallback=True).model_copy(
        update={
            "model_provenance": autonomy_decision(
                "hyp-1", fallback=True
            ).model_provenance.model_copy(
                update={
                    "usage": ModelUsageDelta(
                        attempted_calls=2,
                        successful_calls=1,
                        failed_calls=1,
                        input_tokens=20,
                        output_tokens=5,
                        total_tokens=25,
                        estimated_cost_usd=0.002,
                        latency_seconds=0.02,
                    )
                }
            )
        }
    )
    autonomy_run, _, _, _ = run_autonomy(
        [
            first,
            autonomy_decision("hyp-2"),
            autonomy_decision("hyp-3", action=ReasoningAction.stop),
        ],
        results=[
            versioned_phase2_result("verified", hypothesis_id="hyp-1"),
            versioned_phase2_result("rejected", hypothesis_id="hyp-2"),
        ],
        hypotheses=[hypothesis(f"hyp-{index}") for index in range(1, 4)],
        plans=[verification_plan(f"hyp-{index}") for index in range(1, 4)],
        config=run_config(limits=AutonomyLimits(max_iterations=3)),
    )
    autonomy_run.reasoning_decision = autonomy_decision(
        "hyp-99", action=ReasoningAction.stop
    )
    autonomy_run.verification_result_references = ("latest-only-result",)
    subject = synthetic_subject(
        "complete-history", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)

    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=AutonomyHistory(),
        routing_policy=autonomy_routing_policy(),
    )
    records = observed.iteration_provenance
    assert [item.reasoning.decision_id for item in records] == [
        "decision-hyp-1-recommend_verification",
        "decision-hyp-2-recommend_verification",
        "decision-hyp-3-stop",
    ]
    assert observed.decision_signature == "hyp-3:stop:none"
    assert observed.autonomy_iterations == 3
    assert observed.verified_outcomes == 1
    assert observed.rejected_outcomes == 1
    assert observed.successful_pivots == 2
    assert observed.stop_reason is StopReason.model_recommended_stop
    assert observed.fallback_count == 1
    assert observed.model_usage.attempted_calls == 4
    assert observed.request_delta.total == 4
    assert observed.request_delta == RequestDelta(verification=4, attempted=4, total=4)
    assert observed.phase2_result_references == tuple(
        item.phase2_result_reference for item in records[:2]
    )
    assert [item.iteration_reference for item in observed.provenance] == [1, 2, 3]

    evaluation = run_for(subject, case, outcomes=(observed,))
    assert evaluation.aggregate_metrics.model_usage.model_call_count == 4
    assert evaluation.aggregate_metrics.target_requests.target_requests == 4
    assert evaluation.aggregate_metrics.autonomy.successful_pivots == 2
    assert evaluation.aggregate_metrics.autonomy.stop_reasons == {
        "model_recommended_stop": 1
    }


def test_p1_3_consensus_and_participant_decision_ids_are_iteration_exact():
    request = consensus_request()
    result, _, _ = evaluate_consensus(unanimous_outcomes(), request=request)
    selected = consensus_to_reasoning_decision(
        result.decision, result.participants, request
    )
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [selected],
        results=[versioned_phase2_result("verified", hypothesis_id="hyp-1")],
        config=run_config(limits=AutonomyLimits(max_iterations=1)),
    )
    subject = synthetic_subject(
        "consensus-history", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )

    consensus = observed.iteration_provenance[0].reasoning.consensus
    assert consensus.consensus_id == result.decision.consensus_id
    assert consensus.consensus_schema_version == 1
    assert set(consensus.participant_decision_ids) == set(
        result.decision.supporting_decision_ids
    )
    assert {item.consensus_id for item in observed.provenance} == {
        result.decision.consensus_id
    }
    assert {item.decision_id for item in observed.provenance} == set(
        result.decision.supporting_decision_ids
    )
    assert {item.iteration_reference for item in observed.provenance} == {1}
    assert observed.model_usage == selected.model_provenance.usage
    assert observed.verified_outcomes == 1
    assert observed.time_to_first_verified_outcome is not None


def test_p1_3_dry_run_evaluation_has_zero_requests_and_no_fabricated_result():
    autonomy_run, orchestrator, _, runtime = run_autonomy(
        [autonomy_decision()], config=run_config(dry_run=True)
    )
    subject = synthetic_subject(
        "dry-history", subject_type=EvaluationSubjectType.dry_run_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    record = observed.iteration_provenance[0]
    assert record.reasoning.decision_id == autonomy_decision().decision_id
    assert record.gate_outcome.approved is True
    assert record.model_usage.attempted_calls == 1
    assert record.phase2_request_delta == RequestDelta()
    assert record.phase2_result is None
    assert observed.request_delta == RequestDelta()
    assert observed.phase2_result_references == ()
    assert runtime.calls == []


def test_p1_3_single_iteration_and_external_history_compatibility():
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [autonomy_decision(action=ReasoningAction.stop)]
    )
    legacy_run = autonomy_run.model_copy(update={"iteration_history": ()})
    subject = synthetic_subject(
        "legacy-history", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=legacy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    assert len(observed.iteration_provenance) == 1
    assert observed.valid_decisions == 1
    assert observed.stop_decisions == 1
    assert observed.stop_reason is StopReason.model_recommended_stop


def test_p1_3_json_report_contains_only_sanitized_iteration_provenance(monkeypatch):
    sentinels = (
        "OPENAI_API_KEY_P1_3_SENTINEL",
        "ANTHROPIC_API_KEY_P1_3_SENTINEL",
        "AUTHORIZATION_P1_3_SENTINEL",
        "BEARER_P1_3_SENTINEL",
        "COOKIE_P1_3_SENTINEL",
        "SESSION_TOKEN_P1_3_SENTINEL",
        "PASSWORD_P1_3_SENTINEL",
        "RECOVERY_SECRET_P1_3_SENTINEL",
        "PRIVATE_RECOVERY_STATE_P1_3_SENTINEL",
        "RAW_PROVIDER_RESPONSE_P1_3_SENTINEL",
        "CHAIN_OF_THOUGHT_P1_3_SENTINEL",
    )
    monkeypatch.setenv("OPENAI_API_KEY", sentinels[0])
    monkeypatch.setenv("ANTHROPIC_API_KEY", sentinels[1])
    result = phase2_result(
        "verified",
        extra={
            "api_key": sentinels[0],
            "anthropic_api_key": sentinels[1],
            "Authorization": f"Bearer {sentinels[2]} {sentinels[3]}",
            "cookie": sentinels[4],
            "session_token": sentinels[5],
            "password": sentinels[6],
            "recovery_secret": sentinels[7],
            "private_recovery_state": sentinels[8],
            "raw_provider_response": sentinels[9],
            "chain_of_thought": sentinels[10],
        },
    )
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [
            autonomy_decision(),
            autonomy_decision(action=ReasoningAction.stop),
        ],
        results=[result],
        config=run_config(limits=AutonomyLimits(max_iterations=2)),
    )
    subject = synthetic_subject(
        "sanitized-history", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    payload = evaluation_json(run_for(subject, case, outcomes=(observed,)))
    assert '"iteration_provenance"' in payload
    assert '"reasoning_decision_reference"' in payload
    assert '"request_delta"' in payload
    for sentinel in sentinels:
        assert sentinel not in payload
    assert "raw_provider_response" not in payload
    assert "chain_of_thought" not in payload


def test_p1_3_historical_resolution_has_no_latest_lookup_or_duplicate_aggregation():
    source = inspect.getsource(runner_module.observe_autonomy_run)
    helpers = inspect.getsource(runner_module._autonomy_model_provenance)
    assert "latest" not in source.casefold()
    assert "run.reasoning_decision" not in source
    assert "records = run.iteration_history or history.records" in source
    assert "phase2_result_reference" in source
    assert "latest_result" not in source + helpers
    assert source.count("add_request_delta(") == 1
    assert source.count("add_model_usage(") == 1


def test_p1_3_evaluation_contract_rejects_latest_only_accounting():
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [
            autonomy_decision(),
            autonomy_decision(action=ReasoningAction.stop),
        ],
        config=run_config(limits=AutonomyLimits(max_iterations=2)),
    )
    subject = synthetic_subject(
        "contract-history", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    latest_only = observed.model_dump(mode="python")
    latest_only["model_usage"] = observed.iteration_provenance[-1].model_usage
    with pytest.raises(ValidationError, match="iteration provenance sum"):
        EvaluationCaseOutcome.model_validate(latest_only)


def test_p1_4_evaluation_uses_p3_4_binding_without_serializing_authority():
    autonomy_run, orchestrator, _, scripted = run_autonomy(
        [
            autonomy_decision(),
            autonomy_decision(action=ReasoningAction.stop),
        ],
        config=run_config(limits=AutonomyLimits(max_iterations=2)),
    )
    subject = synthetic_subject(
        "bound-evaluation", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    observed = observe_autonomy_run(
        subject=subject,
        case=case,
        repetition=0,
        run=autonomy_run,
        history=orchestrator.history,
        routing_policy=autonomy_routing_policy(),
    )
    payload = evaluation_json(run_for(subject, case, outcomes=(observed,)))

    assert len(scripted.calls) == 1
    assert len(observed.iteration_provenance) == 2
    for forbidden in (
        "AuthoritativePhase2RuntimeBinding",
        "runtime_binding",
        "BINDING_ISSUER",
        "defers_runtime_policy_authorization",
    ):
        assert forbidden not in payload
    evaluation_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(evaluation_package.__file__).parent.glob("*.py")
    )
    assert "bind_authoritative_phase2_runtime" not in evaluation_source
    assert "execute_selected" not in evaluation_source
