"""P1-F1 regressions for authoritative evaluation callback accounting."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from agent_core.consensus import ConsensusEngine
from agent_core.model_evaluation import (
    EvaluationCase,
    EvaluationBudgetPreflight,
    EvaluationExecutionMode,
    EvaluationFailureCode,
    EvaluationRunner,
    EvaluationSubject,
    EvaluationSubjectType,
    ExpectedStructuralProperties,
    SyntheticScenario,
    evaluation_json,
    observe_autonomy_run,
    observe_consensus_result,
    synthetic_case,
    synthetic_outcome,
    synthetic_subject,
)
from agent_core.models import (
    ModelBudgetLimits,
    ModelBudgetReservation,
    ModelCallLedger,
    ModelErrorCode,
    ModelPrice,
    ModelPricingCatalog,
    ModelProviderError,
    ModelResponse,
    ModelRouter,
)
from agent_core.reasoning import ReasoningEngine, build_reasoning_model_request
from agent_core.request_budget import RequestDelta
from tests.test_phase3_autonomy import (
    decision as autonomy_decision,
    run_autonomy,
    versioned_phase2_result,
)
from tests.test_phase3_consensus import (
    CLAUDE,
    GPT,
    ScriptedReasoningEngine,
    consensus_request,
    model_decision,
)
from tests.test_phase3_model_evaluation import BudgetProvider, BudgetRegistry
from tests.test_phase3_reasoning import candidate as reasoning_candidate

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:00:01+00:00"


def _response(
    *,
    provider: str = "ollama",
    model: str = "local-model",
    content: str = "public normalized response",
    input_tokens: int = 3,
    output_tokens: int = 2,
) -> Callable[[Any], ModelResponse]:
    def respond(request) -> ModelResponse:
        return ModelResponse(
            provider=provider,
            model=model,
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=0.0,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
        )

    return respond


def _provider_callback_run(
    responder_factory: Callable[[], Any],
    *,
    repetitions: int = 1,
    model_budget: ModelBudgetLimits | None = None,
    max_output_tokens: int = 10,
    return_success: bool = False,
):
    subject = synthetic_subject(
        "callback-accounting",
        provider="ollama",
        model="local-model",
    ).model_copy(update={"repetitions": repetitions})
    case = synthetic_case().model_copy(
        update={"model_budget": model_budget or ModelBudgetLimits(max_model_calls=10)}
    )
    providers: list[BudgetProvider] = []

    def evaluator(selected, item, repetition):
        provider = BudgetProvider("ollama", "local-model", responder_factory())
        providers.append(provider)
        router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=max_output_tokens,
        )
        router.route(request, selected.routing_policies[0])
        if return_success:
            return synthetic_outcome(
                selected,
                item,
                repetition,
                SyntheticScenario.grounded_recommendation,
            )
        raise RuntimeError("sanitized outer callback failure")

    run = EvaluationRunner(max_output_tokens=max_output_tokens).run(
        evaluation_run_id="callback-accounting-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    return run, providers


def _failure(error_code: ModelErrorCode) -> ModelProviderError:
    return ModelProviderError(
        error_code,
        provider="ollama",
        model="local-model",
    )


def _single_failure(error_code: ModelErrorCode = ModelErrorCode.timeout):
    return _provider_callback_run(lambda: _failure(error_code))


def _reasoning_failure_run(content: str):
    subject = synthetic_subject(
        "reasoning-callback",
        provider="ollama",
        model="local-model",
    )
    case = synthetic_case()
    providers: list[BudgetProvider] = []

    def evaluator(selected, item, _repetition):
        provider = BudgetProvider(
            "ollama",
            "local-model",
            _response(content=content),
        )
        providers.append(provider)
        router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
        ReasoningEngine(router, max_output_tokens=20).reason(
            item.reasoning_request,
            selected.routing_policies[0],
        )
        raise AssertionError("reasoning failure was expected")

    run = EvaluationRunner(max_output_tokens=20).run(
        evaluation_run_id="reasoning-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    return run, providers


def _exhausted_repetition_run(*, output_budget: int = 1):
    return _provider_callback_run(
        lambda: _failure(ModelErrorCode.timeout),
        repetitions=2,
        model_budget=ModelBudgetLimits(
            max_model_calls=2,
            max_output_tokens=output_budget,
        ),
        max_output_tokens=1,
    )


def _autonomy_callback_run():
    subject = synthetic_subject(
        "autonomy-callback",
        provider="openai",
        model="reasoning-model",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    route = subject.routing_policies[0]
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [autonomy_decision()],
        results=[versioned_phase2_result("verified")],
        route=route,
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
        raise RuntimeError("outer autonomy evaluation failure")

    evaluation = EvaluationRunner().run(
        evaluation_run_id="autonomy-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    return evaluation, autonomy_run


def test_callback_failure_before_provider_start_has_zero_reservation():
    subject = synthetic_subject()
    case = synthetic_case()

    def evaluator(_subject, _case, _repetition):
        raise RuntimeError("callback failed before model routing")

    run = EvaluationRunner().run(
        evaluation_run_id="pre-provider-failure",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    usage = run.case_outcomes[0].model_usage
    assert usage.attempted_calls == 0
    assert usage.budget_total_tokens == 0
    assert run.case_outcomes[0].request_delta == RequestDelta()


def test_callback_failure_after_provider_start_retains_reservation():
    run, providers = _provider_callback_run(
        lambda: RuntimeError("private provider exception")
    )
    usage = run.case_outcomes[0].model_usage
    assert len(providers[0].requests) == 1
    assert usage.attempted_calls == usage.failed_calls == 1
    assert usage.budget_total_tokens > 0


def test_callback_failure_after_success_retains_actual_usage():
    run, providers = _provider_callback_run(lambda: _response())
    usage = run.case_outcomes[0].model_usage
    assert len(providers[0].requests) == 1
    assert (usage.successful_calls, usage.failed_calls) == (1, 0)
    assert (usage.input_tokens, usage.output_tokens, usage.total_tokens) == (3, 2, 5)
    assert usage.budget_total_tokens == 5


@pytest.mark.parametrize(
    ("responder_factory", "usage_known"),
    (
        (lambda: _failure(ModelErrorCode.timeout), False),
        (lambda: _failure(ModelErrorCode.rate_limited), False),
        (lambda: _failure(ModelErrorCode.connection_failed), False),
        (lambda: (lambda _request: {"malformed": True}), False),
        (lambda: _response(model="wrong-model"), True),
    ),
    ids=(
        "timeout",
        "rate-limit",
        "connection-failure",
        "malformed-response",
        "response-normalization-failure",
    ),
)
def test_started_failure_classes_retain_reservation(responder_factory, usage_known):
    run, providers = _provider_callback_run(responder_factory)
    usage = run.case_outcomes[0].model_usage
    assert len(providers[0].requests) == 1
    assert usage.failed_calls == 1
    assert usage.budget_total_tokens > 0
    assert (usage.unknown_usage_calls == 0) is usage_known
    if not usage_known:
        assert usage.total_tokens == 0


def test_reasoning_parser_failure_retains_successful_provider_usage():
    run, providers = _reasoning_failure_run("not valid JSON")
    usage = run.case_outcomes[0].model_usage
    assert len(providers[0].requests) == 1
    assert usage.successful_calls == 1
    assert usage.total_tokens == 5


def test_reasoning_semantic_validation_failure_retains_provider_usage():
    payload = reasoning_candidate(hypothesis_id="missing-hypothesis")
    run, providers = _reasoning_failure_run(json.dumps(payload))
    usage = run.case_outcomes[0].model_usage
    assert len(providers[0].requests) == 1
    assert usage.successful_calls == 1
    assert usage.total_tokens == 5


def test_consensus_checkpoint_survives_outer_callback_exception():
    participants = (GPT, CLAUDE)
    request = consensus_request(participants)
    scripted = ScriptedReasoningEngine(
        {
            (
                participant.routing_policy.preferred.provider,
                participant.routing_policy.preferred.model,
            ): model_decision(participant)
            for participant in participants
        }
    )
    result = ConsensusEngine(scripted).evaluate(request)
    base_subject = synthetic_subject(
        "consensus-callback",
        subject_type=EvaluationSubjectType.consensus_reasoning,
    )
    subject = EvaluationSubject.model_validate(
        {
            **base_subject.model_dump(mode="python"),
            "routing_policies": tuple(
                participant.routing_policy for participant in participants
            ),
            "consensus_policy": request.policy,
            "consensus_budget": request.model_budget,
        }
    )
    base_case = synthetic_case()
    case = EvaluationCase.model_validate(
        {
            **base_case.model_dump(mode="python"),
            "reasoning_request": request.reasoning_request,
            "task_type": request.reasoning_request.task_type,
        }
    )

    def evaluator(selected, item, repetition):
        observe_consensus_result(
            subject=selected,
            case=item,
            repetition=repetition,
            result=result,
        )
        raise RuntimeError("outer consensus evaluation failure")

    run = EvaluationRunner().run(
        evaluation_run_id="consensus-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    failed = run.case_outcomes[0]
    assert failed.failure_code is EvaluationFailureCode.consensus_failed
    assert failed.model_usage == result.decision.model_usage
    assert len(failed.provenance) == 2


def test_autonomy_checkpoint_survives_outer_callback_exception():
    evaluation, autonomy_run = _autonomy_callback_run()
    failed = evaluation.case_outcomes[0]
    assert failed.failure_code is EvaluationFailureCode.autonomy_failed
    assert failed.model_usage == autonomy_run.model_usage
    assert failed.model_usage.attempted_calls > 0


def test_failed_case_exposes_truthful_usage():
    run, _ = _single_failure()
    failed = run.case_outcomes[0]
    assert failed.runtime_success is False
    assert failed.model_usage.failed_calls == 1
    assert failed.model_usage.budget_total_tokens > 0
    assert failed.provenance[0].actual_provider == "ollama"


def test_failed_case_usage_is_included_in_run_aggregation():
    run, _ = _single_failure()
    case_usage = run.case_outcomes[0].model_usage
    aggregate = run.aggregate_metrics.model_usage
    assert aggregate.model_call_count == case_usage.attempted_calls == 1
    assert aggregate.failed_model_calls == 1
    assert aggregate.budget_total_tokens == case_usage.budget_total_tokens
    assert aggregate.unknown_usage_calls == 1


def test_successful_and_failed_case_usage_aggregate_together():
    subject = synthetic_subject(
        "mixed-cases",
        provider="ollama",
        model="local-model",
    )
    base = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=2)}
    )
    cases = (
        base.model_copy(update={"case_id": "case-a-success"}),
        base.model_copy(update={"case_id": "case-b-failure"}),
    )

    def evaluator(selected, item, repetition):
        responder = (
            _response()
            if item.case_id == "case-a-success"
            else _failure(ModelErrorCode.timeout)
        )
        provider = BudgetProvider("ollama", "local-model", responder)
        router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=10,
        )
        router.route(request, selected.routing_policies[0])
        return synthetic_outcome(
            selected,
            item,
            repetition,
            SyntheticScenario.grounded_recommendation,
        )

    run = EvaluationRunner(max_output_tokens=10).run(
        evaluation_run_id="mixed-case-run",
        subject=subject,
        cases=cases,
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    aggregate = run.aggregate_metrics.model_usage
    assert (aggregate.model_call_count, aggregate.successful_model_calls) == (2, 1)
    assert aggregate.failed_model_calls == aggregate.unknown_usage_calls == 1
    assert aggregate.total_tokens == 5
    assert aggregate.budget_total_tokens == sum(
        item.model_usage.budget_total_tokens for item in run.case_outcomes
    )


def test_first_repetition_failure_consumes_reservation():
    run, _ = _exhausted_repetition_run()
    first = run.case_outcomes[0]
    assert first.failure_code is EvaluationFailureCode.reasoning_failed
    assert first.model_usage.failed_calls == 1
    assert first.model_usage.budget_output_tokens == 1


def test_second_repetition_is_blocked_after_exhausted_reservation():
    run, providers = _exhausted_repetition_run()
    assert len(providers) == 1
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted
    assert run.case_outcomes[1].model_usage.attempted_calls == 0


def test_second_repetition_runs_when_budget_really_remains():
    run, providers = _exhausted_repetition_run(output_budget=2)
    assert len(providers) == 2
    assert all(len(provider.requests) == 1 for provider in providers)
    assert [item.model_usage.failed_calls for item in run.case_outcomes] == [1, 1]
    assert run.aggregate_metrics.model_usage.budget_output_tokens == 2


def test_evaluation_level_retry_does_not_reset_shared_run_budget():
    subject = synthetic_subject(
        "shared-run-callback",
        provider="ollama",
        model="local-model",
    )
    base = synthetic_case().model_copy(
        update={
            "model_budget": ModelBudgetLimits(
                max_model_calls=2,
                max_output_tokens=1,
            )
        }
    )
    cases = (
        base.model_copy(update={"case_id": "case-a"}),
        base.model_copy(update={"case_id": "case-b"}),
    )
    providers: list[BudgetProvider] = []

    def evaluator(selected, item, _repetition):
        provider = BudgetProvider(
            "ollama",
            "local-model",
            _failure(ModelErrorCode.timeout),
        )
        providers.append(provider)
        router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=1,
        )
        router.route(request, selected.routing_policies[0])

    run = EvaluationRunner(max_output_tokens=1).run(
        evaluation_run_id="shared-run-callback",
        subject=subject,
        cases=cases,
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert len(providers) == 1
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted


def test_fallback_reservations_are_not_reset_by_outer_callback_failure():
    subject = synthetic_subject(
        "fallback-callback",
        provider="openai",
        model="primary",
        fallback_provider="anthropic",
        fallback_model="fallback",
    ).model_copy(update={"repetitions": 2})
    case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(max_model_calls=2)}
    )
    callback_count = 0

    def evaluator(selected, item, _repetition):
        nonlocal callback_count
        callback_count += 1
        primary = BudgetProvider(
            "openai",
            "primary",
            ModelProviderError(
                ModelErrorCode.timeout,
                provider="openai",
                model="primary",
            ),
        )
        fallback = BudgetProvider(
            "anthropic",
            "fallback",
            _response(provider="anthropic", model="fallback"),
        )
        router = ModelRouter(
            BudgetRegistry(
                {
                    ("openai", "primary"): primary,
                    ("anthropic", "fallback"): fallback,
                }
            )
        )
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=10,
        )
        router.route(request, selected.routing_policies[0])
        raise RuntimeError("failure after fallback completed")

    run = EvaluationRunner(max_output_tokens=10).run(
        evaluation_run_id="fallback-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    assert callback_count == 1
    assert run.case_outcomes[0].model_usage.attempted_calls == 2
    assert run.case_outcomes[1].failure_code is EvaluationFailureCode.budget_exhausted


def test_failed_callback_cost_reservation_blocks_next_repetition():
    subject = synthetic_subject(
        "cost-callback",
        provider="openai",
        model="priced-model",
    ).model_copy(update={"repetitions": 2})
    base_case = synthetic_case()
    pricing = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="priced-model",
                input_per_million_usd=2.0,
                output_per_million_usd=4.0,
            ),
        )
    )
    input_tokens = EvaluationBudgetPreflight(
        (base_case,),
        pricing=pricing,
        max_output_tokens=1,
    ).input_token_reservation(base_case)
    reservation_cost = pricing.estimate_cost(
        "openai",
        "priced-model",
        input_tokens=input_tokens,
        output_tokens=1,
    )
    assert reservation_cost is not None
    case = base_case.model_copy(
        update={
            "model_budget": ModelBudgetLimits(
                max_model_calls=2,
                max_estimated_cost_usd=reservation_cost,
            )
        }
    )
    providers: list[BudgetProvider] = []

    def evaluator(selected, item, _repetition):
        provider = BudgetProvider(
            "openai",
            "priced-model",
            ModelProviderError(
                ModelErrorCode.timeout,
                provider="openai",
                model="priced-model",
            ),
        )
        providers.append(provider)
        router = ModelRouter(
            BudgetRegistry({("openai", "priced-model"): provider}, pricing=pricing)
        )
        request = build_reasoning_model_request(
            item.reasoning_request,
            max_output_tokens=1,
        )
        router.route(request, selected.routing_policies[0])

    run = EvaluationRunner(pricing=pricing, max_output_tokens=1).run(
        evaluation_run_id="cost-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    first, second = run.case_outcomes
    assert len(providers) == 1
    assert first.model_usage.estimated_cost_usd is None
    assert first.model_usage.budget_estimated_cost_usd == pytest.approx(
        reservation_cost
    )
    assert second.failure_code is EvaluationFailureCode.budget_exhausted
    assert run.aggregate_metrics.model_usage.budget_estimated_api_cost_usd == (
        pytest.approx(reservation_cost)
    )


def test_failed_unknown_usage_does_not_fabricate_actual_tokens():
    run, _ = _single_failure()
    usage = run.case_outcomes[0].model_usage
    assert usage.unknown_usage_calls == 1
    assert (usage.input_tokens, usage.output_tokens, usage.total_tokens) == (0, 0, 0)


def test_reserved_usage_is_not_reported_as_observed_actual_usage():
    run, _ = _single_failure()
    usage = run.case_outcomes[0].model_usage
    assert usage.total_tokens == 0
    assert usage.budget_total_tokens > usage.total_tokens


def test_provider_start_commit_is_preserved_if_finalization_never_returns():
    subject = synthetic_subject()
    case = synthetic_case()

    def evaluator(_subject, item, _repetition):
        ledger = ModelCallLedger()
        ledger.commit_reservation(
            provider="ollama",
            model="local-model",
            task_type=item.reasoning_request.task_type.value,
            run_id=item.reasoning_request.run_id,
            hypothesis_id=None,
            fallback_depth=0,
            reservation=ModelBudgetReservation(
                input_tokens=3,
                output_tokens=4,
                total_tokens=7,
                estimated_cost_usd=0.0,
            ),
        )
        raise RuntimeError("failure after provider-start commit")

    run = EvaluationRunner().run(
        evaluation_run_id="pending-commit-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    usage = run.case_outcomes[0].model_usage
    assert usage.unknown_usage_calls == usage.failed_calls == 1
    assert usage.total_tokens == 0
    assert usage.budget_total_tokens == 7
    assert usage.estimated_cost_usd is None


def test_generic_failure_constructor_cannot_erase_captured_usage():
    run, _ = _provider_callback_run(
        lambda: RuntimeError("failure requiring generic conversion")
    )
    failed = run.case_outcomes[0]
    assert failed.failure_code is EvaluationFailureCode.reasoning_failed
    assert failed.model_usage != failed.model_usage.__class__(
        estimated_cost_usd=None,
        budget_estimated_cost_usd=0.0,
    )
    assert failed.model_usage.budget_total_tokens > 0


def test_model_only_callback_failure_leaves_request_delta_zero():
    run, _ = _single_failure()
    assert run.case_outcomes[0].request_delta == RequestDelta()
    assert run.aggregate_metrics.target_requests.target_requests == 0


def test_post_target_callback_failure_preserves_request_delta():
    evaluation, autonomy_run = _autonomy_callback_run()
    failed = evaluation.case_outcomes[0]
    assert failed.request_delta == autonomy_run.phase2_request_usage
    assert failed.request_delta.total == 2
    assert evaluation.aggregate_metrics.target_requests.target_requests == 2


def test_nonterminal_phase2_observer_preserves_accounting_without_runtime_failure():
    subject = synthetic_subject(
        "pending-cleanup-callback",
        provider="openai",
        model="reasoning-model",
        subject_type=EvaluationSubjectType.controlled_autonomy,
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    autonomy_run, orchestrator, _, _ = run_autonomy(
        [autonomy_decision()],
        results=[versioned_phase2_result("verification_pending_cleanup")],
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
        evaluation_run_id="pending-cleanup-callback-run",
        subject=subject,
        cases=(case,),
        evaluator=evaluator,
        started_at=START,
        ended_at=END,
    )
    observed = evaluation.case_outcomes[0]
    assert observed.runtime_success is True
    assert observed.failure_code is None
    assert observed.phase2_statuses == ("verification_pending_cleanup",)
    assert observed.model_usage == autonomy_run.model_usage
    assert observed.request_delta == autonomy_run.phase2_request_usage
    assert observed.iteration_provenance == autonomy_run.iteration_history


def test_outer_failure_preserves_iteration_usage_and_provenance():
    evaluation, autonomy_run = _autonomy_callback_run()
    failed = evaluation.case_outcomes[0]
    assert failed.iteration_provenance == autonomy_run.iteration_history
    assert failed.model_usage == autonomy_run.model_usage
    assert failed.phase2_result_references == (
        autonomy_run.iteration_history[0].phase2_result_reference,
    )


def test_structural_expectations_remain_distinct_and_keep_usage():
    for maximum, expected in ((1, True), (0, False)):
        case = synthetic_case().model_copy(
            update={
                "expected_structure": ExpectedStructuralProperties(
                    maximum_model_calls=maximum
                )
            }
        )
        subject = synthetic_subject(
            f"expectation-{maximum}",
            provider="ollama",
            model="local-model",
        )

        def evaluator(selected, item, _repetition):
            provider = BudgetProvider(
                "ollama",
                "local-model",
                _failure(ModelErrorCode.timeout),
            )
            router = ModelRouter(BudgetRegistry({("ollama", "local-model"): provider}))
            request = build_reasoning_model_request(
                item.reasoning_request,
                max_output_tokens=10,
            )
            router.route(request, selected.routing_policies[0])

        run = EvaluationRunner(max_output_tokens=10).run(
            evaluation_run_id=f"expectation-{maximum}",
            subject=subject,
            cases=(case,),
            evaluator=evaluator,
            started_at=START,
            ended_at=END,
        )
        failed = run.case_outcomes[0]
        assert failed.runtime_success is False
        assert failed.expectations_satisfied is expected
        assert failed.success is False
        assert failed.model_usage.failed_calls == 1


def test_configuration_fingerprint_is_independent_of_execution_usage():
    successful, _ = _provider_callback_run(lambda: _response(), return_success=True)
    failed, _ = _single_failure()
    assert successful.configuration_fingerprint == failed.configuration_fingerprint
    assert successful.configuration_fingerprint_schema == (
        failed.configuration_fingerprint_schema
    )


@pytest.mark.parametrize(
    "sentinel",
    (
        "P1_F1_API_KEY_SECRET",
        "Authorization: Bearer P1_F1_AUTH_SECRET",
        "cookie=session=P1_F1_COOKIE_SECRET",
        "session_token=P1_F1_SESSION_SECRET",
        "password=P1_F1_PASSWORD_SECRET",
        "recovery_secret=P1_F1_RECOVERY_SECRET",
        "raw_provider_response=P1_F1_RAW_RESPONSE",
        "chain_of_thought=P1_F1_PRIVATE_THOUGHT",
    ),
    ids=(
        "api-key",
        "authorization",
        "cookie",
        "session-token",
        "password",
        "recovery-secret",
        "raw-provider-response",
        "chain-of-thought",
    ),
)
def test_callback_failure_accounting_does_not_persist_private_values(sentinel):
    run, _ = _provider_callback_run(lambda: RuntimeError(sentinel))
    assert sentinel not in evaluation_json(run)


def test_exact_final_freeze_audit_reproduction_is_blocked():
    run, providers = _exhausted_repetition_run()
    first, second = run.case_outcomes
    assert len(providers) == 1
    assert first.model_usage.failed_calls == 1
    assert first.model_usage.unknown_usage_calls == 1
    assert first.model_usage.budget_output_tokens == 1
    assert second.failure_code is EvaluationFailureCode.budget_exhausted
    assert second.model_usage.attempted_calls == 0
    assert run.aggregate_metrics.model_usage.model_call_count == 1
    assert run.aggregate_metrics.model_usage.budget_output_tokens == 1
