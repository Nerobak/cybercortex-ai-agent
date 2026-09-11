"""P3-2 deterministic model routing, fallback, ledger, and budget tests."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from agent_core.models import (
    ModelBudgetLimits,
    ModelCallLedger,
    ModelConfiguration,
    ModelErrorCode,
    ModelPrice,
    ModelPricingCatalog,
    ModelProviderError,
    ModelRequest,
    ModelResponse,
    ModelRoute,
    ModelRouter,
    ModelRoutingError,
    ModelRoutingPolicy,
    ModelUsageDelta,
    ProviderAvailability,
    ProviderConfiguration,
    RoutingMode,
)
from agent_core.request_budget import RequestBudget

API_KEY_SENTINEL = "CCX_ROUTER_API_KEY_4ef0"
AUTH_SENTINEL = "CCX_ROUTER_AUTH_9b10"
COOKIE_SENTINEL = "CCX_ROUTER_COOKIE_7a21"
RECOVERY_SENTINEL = "CCX_ROUTER_RECOVERY_3cd8"


def model_request(**overrides: Any) -> ModelRequest:
    values: dict[str, Any] = {
        "system_instructions": "Reason about public evidence only.",
        "user_content": "Assess this evidence.",
        "evidence": {"status": "inconclusive"},
        "temperature": 0.0,
        "max_output_tokens": 10,
        "task_type": "evidence_review",
        "run_id": "run-router-1",
        "hypothesis_id": "hyp-router-1",
        "metadata": {},
    }
    values.update(overrides)
    return ModelRequest(**values)


def provider_error(code: ModelErrorCode, provider: str, model: str):
    return ModelProviderError(code, provider=provider, model=model)


def success(
    provider: str,
    model: str,
    *,
    input_tokens: int = 4,
    output_tokens: int = 2,
    cost: float | None = None,
    content: str = "normalized analysis",
):
    def build(request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider=provider,
            model=model,
            content=content,
            finish_reason="stop",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=cost,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
        )

    return build


class MockProvider:
    def __init__(self, provider: str, model: str, outcome: Any) -> None:
        self.provider_name = provider
        self.model_name = model
        self.outcome = outcome
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest):
        self.requests.append(request)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            return self.outcome(request)
        return self.outcome


class MockRegistry:
    def __init__(
        self,
        providers: dict[tuple[str, str], MockProvider],
        *,
        pricing: ModelPricingCatalog | None = None,
    ) -> None:
        self.providers = providers
        self.pricing = pricing or ModelPricingCatalog()
        self.create_calls: list[tuple[str, str | None]] = []

    def create(self, provider: str, *, model_name: str | None = None):
        self.create_calls.append((provider, model_name))
        return self.providers[(provider, str(model_name))]


def preferred_policy(
    provider: str = "openai",
    model: str = "openai-model",
    *,
    budget: ModelBudgetLimits | None = None,
) -> ModelRoutingPolicy:
    allowlist = (provider,) if provider in {"openai", "anthropic"} else ()
    mode = RoutingMode.local_only if provider == "ollama" else RoutingMode.preferred
    return ModelRoutingPolicy(
        mode=mode,
        preferred=ModelRoute(provider=provider, model=model),
        allowed_cloud_providers=allowlist,
        budget=budget or ModelBudgetLimits(),
    )


def fallback_policy(
    *routes: tuple[str, str],
    max_attempts: int | None = None,
    fallback_allowed: bool = True,
    budget: ModelBudgetLimits | None = None,
) -> ModelRoutingPolicy:
    cloud = tuple(
        dict.fromkeys(
            provider for provider, _ in routes if provider in {"openai", "anthropic"}
        )
    )
    return ModelRoutingPolicy(
        mode=RoutingMode.fallback_chain,
        preferred=ModelRoute(provider=routes[0][0], model=routes[0][1]),
        fallbacks=tuple(
            ModelRoute(provider=provider, model=model) for provider, model in routes[1:]
        ),
        fallback_allowed=fallback_allowed,
        max_provider_attempts=max_attempts or len(routes),
        allowed_cloud_providers=cloud,
        budget=budget or ModelBudgetLimits(),
    )


def test_preferred_provider_success():
    provider = MockProvider("openai", "openai-model", success("openai", "openai-model"))
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    response = router.route(model_request(), preferred_policy())
    assert response.provider == "openai"
    assert response.fallback_used is False
    assert response.model_calls_attempted == 1


def test_openai_snapshot_model_preserves_routing_accounting_and_provenance():
    snapshot = "openai-model-2026-04-23"
    provider = MockProvider("openai", "openai-model", success("openai", snapshot))
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))

    response = router.route(model_request(), preferred_policy())

    assert response.model == snapshot
    assert response.requested_model == "openai-model"
    assert response.fallback_used is False
    assert response.model_calls_attempted == 1
    assert len(router.ledger.records) == 1
    assert router.ledger.records[0].model == snapshot
    assert router.ledger.usage_for_run("run-router-1").successful_calls == 1


def test_fallback_uses_exact_declared_order():
    openai = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    anthropic = MockProvider(
        "anthropic",
        "anthropic-model",
        provider_error(ModelErrorCode.rate_limited, "anthropic", "anthropic-model"),
    )
    ollama = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    registry = MockRegistry(
        {
            ("openai", "openai-model"): openai,
            ("anthropic", "anthropic-model"): anthropic,
            ("ollama", "local-model"): ollama,
        }
    )
    router = ModelRouter(registry)
    router.route(
        model_request(),
        fallback_policy(
            ("openai", "openai-model"),
            ("anthropic", "anthropic-model"),
            ("ollama", "local-model"),
        ),
    )
    assert registry.create_calls == [
        ("openai", "openai-model"),
        ("anthropic", "anthropic-model"),
        ("ollama", "local-model"),
    ]


@pytest.mark.parametrize(
    "code",
    [
        ModelErrorCode.provider_unavailable,
        ModelErrorCode.timeout,
        ModelErrorCode.rate_limited,
        ModelErrorCode.connection_failed,
    ],
)
def test_reliability_failure_permits_configured_fallback(code):
    first = MockProvider(
        "openai", "openai-model", provider_error(code, "openai", "openai-model")
    )
    second = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("ollama", "local-model"): second,
            }
        )
    )
    response = router.route(
        model_request(),
        fallback_policy(("openai", "openai-model"), ("ollama", "local-model")),
    )
    assert response.provider == "ollama"
    assert len(first.requests) == len(second.requests) == 1


def test_unsupported_structured_output_falls_back_without_starting_provider_call():
    first = MockProvider("openai", "openai-model", success("openai", "openai-model"))
    first.supports_structured_output = False
    second = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    second.supports_structured_output = True
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("ollama", "local-model"): second,
            }
        )
    )

    response = router.route(
        model_request(structured_output=True),
        fallback_policy(("openai", "openai-model"), ("ollama", "local-model")),
    )

    assert response.provider == "ollama"
    assert first.requests == []
    assert len(second.requests) == 1
    assert [record.attempt_state for record in router.ledger.records] == [
        "blocked_before_provider_call",
        "provider_call_succeeded",
    ]
    assert router.ledger.active_reservations == ()


def test_no_fallback_when_disabled():
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider("ollama", "local-model", success("ollama", "local-model"))
    registry = MockRegistry(
        {
            ("openai", "openai-model"): first,
            ("ollama", "local-model"): second,
        }
    )
    router = ModelRouter(registry)
    with pytest.raises(ModelProviderError) as captured:
        router.route(
            model_request(),
            fallback_policy(
                ("openai", "openai-model"),
                ("ollama", "local-model"),
                fallback_allowed=False,
            ),
        )
    assert captured.value.code == ModelErrorCode.timeout
    assert not second.requests


def test_maximum_provider_attempts_truncates_chain():
    providers = {
        (provider, model): MockProvider(
            provider,
            model,
            provider_error(ModelErrorCode.connection_failed, provider, model),
        )
        for provider, model in (
            ("openai", "one"),
            ("anthropic", "two"),
            ("ollama", "three"),
        )
    }
    registry = MockRegistry(providers)
    with pytest.raises(ModelRoutingError) as captured:
        ModelRouter(registry).route(
            model_request(),
            fallback_policy(
                ("openai", "one"),
                ("anthropic", "two"),
                ("ollama", "three"),
                max_attempts=2,
            ),
        )
    assert captured.value.code == ModelErrorCode.routing_exhausted
    assert registry.create_calls == [("openai", "one"), ("anthropic", "two")]


def test_local_only_invokes_only_ollama():
    ollama = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    registry = MockRegistry({("ollama", "local-model"): ollama})
    response = ModelRouter(registry).route(
        model_request(), preferred_policy("ollama", "local-model")
    )
    assert response.provider == "ollama"
    assert registry.create_calls == [("ollama", "local-model")]


def test_local_only_policy_rejects_openai_route():
    with pytest.raises(ValidationError):
        ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="openai", model="cloud-model"),
            allowed_cloud_providers=("openai",),
        )


def test_local_only_policy_rejects_anthropic_route():
    with pytest.raises(ValidationError):
        ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="anthropic", model="cloud-model"),
            allowed_cloud_providers=("anthropic",),
        )


def test_local_only_accepts_configured_non_loopback_ollama_endpoint():
    configuration = ModelConfiguration(
        ollama=ProviderConfiguration(
            model_name="deepseek-test:latest",
            base_url="https://ollama.example.test:11434",
        )
    )
    policy = preferred_policy("ollama", "deepseek-test:latest")

    assert configuration.ollama.base_url == "https://ollama.example.test:11434"
    assert policy.mode is RoutingMode.local_only
    assert tuple(route.provider for route in policy.ordered_routes()) == ("ollama",)


def test_cloud_allowlist_permits_explicit_provider():
    provider = MockProvider(
        "anthropic", "cloud-model", success("anthropic", "cloud-model")
    )
    registry = MockRegistry({("anthropic", "cloud-model"): provider})
    policy = ModelRoutingPolicy(
        mode=RoutingMode.cloud_only,
        preferred=ModelRoute(provider="anthropic", model="cloud-model"),
        allowed_cloud_providers=("anthropic",),
    )
    assert ModelRouter(registry).route(model_request(), policy).provider == "anthropic"


def test_unlisted_cloud_provider_is_blocked_before_invocation():
    with pytest.raises(ValidationError):
        ModelRoutingPolicy(
            mode=RoutingMode.cloud_only,
            preferred=ModelRoute(provider="openai", model="cloud-model"),
            allowed_cloud_providers=("anthropic",),
        )


def test_model_call_budget_preflight_blocks_next_provider_call():
    provider = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    registry = MockRegistry({("ollama", "local-model"): provider})
    router = ModelRouter(registry)
    policy = preferred_policy(
        "ollama", "local-model", budget=ModelBudgetLimits(max_model_calls=1)
    )
    router.route(model_request(), policy)
    with pytest.raises(ModelRoutingError) as captured:
        router.route(model_request(), policy)
    assert captured.value.code == ModelErrorCode.model_budget_exceeded
    assert len(provider.requests) == 1


def test_token_budget_blocks_attempt_before_provider_call():
    provider = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    registry = MockRegistry({("ollama", "local-model"): provider})
    policy = preferred_policy(
        "ollama", "local-model", budget=ModelBudgetLimits(max_total_tokens=2)
    )
    with pytest.raises(ModelRoutingError) as captured:
        ModelRouter(registry).route(model_request(), policy)
    assert captured.value.code == ModelErrorCode.model_budget_exceeded
    assert not provider.requests


def test_known_estimated_cost_ceiling_blocks_attempt():
    pricing = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="openai-model",
                input_per_million_usd=1_000_000.0,
                output_per_million_usd=1_000_000.0,
            ),
        )
    )
    provider = MockProvider(
        "openai", "openai-model", success("openai", "openai-model", cost=1.0)
    )
    registry = MockRegistry({("openai", "openai-model"): provider}, pricing=pricing)
    policy = preferred_policy(budget=ModelBudgetLimits(max_per_call_cost_usd=1.0))
    with pytest.raises(ModelRoutingError) as captured:
        ModelRouter(registry).route(model_request(), policy)
    assert captured.value.code == ModelErrorCode.model_budget_exceeded
    assert not provider.requests

    request = model_request()
    predicted = float(ModelRouter._conservative_input_token_estimate(request) + 10)
    run_provider = MockProvider(
        "openai",
        "openai-model",
        success("openai", "openai-model", cost=predicted),
    )
    run_registry = MockRegistry(
        {("openai", "openai-model"): run_provider}, pricing=pricing
    )
    run_router = ModelRouter(run_registry)
    run_policy = preferred_policy(
        budget=ModelBudgetLimits(max_estimated_cost_usd=predicted * 1.5)
    )
    run_router.route(request, run_policy)
    with pytest.raises(ModelRoutingError) as run_captured:
        run_router.route(request, run_policy)
    assert run_captured.value.code == ModelErrorCode.model_budget_exceeded
    assert len(run_provider.requests) == 1


def test_unknown_price_under_strict_cost_budget_fails_closed():
    provider = MockProvider("openai", "openai-model", success("openai", "openai-model"))
    registry = MockRegistry({("openai", "openai-model"): provider})
    policy = preferred_policy(budget=ModelBudgetLimits(max_estimated_cost_usd=10.0))
    with pytest.raises(ModelRoutingError) as captured:
        ModelRouter(registry).route(model_request(), policy)
    assert captured.value.code == ModelErrorCode.unknown_cost
    assert not provider.requests


def test_unknown_price_allow_policy_preserves_unknown_cost():
    provider = MockProvider("openai", "openai-model", success("openai", "openai-model"))
    registry = MockRegistry({("openai", "openai-model"): provider})
    policy = preferred_policy(
        budget=ModelBudgetLimits(
            max_estimated_cost_usd=10.0,
            unknown_cost_policy="allow",
        )
    )

    response = ModelRouter(registry).route(model_request(), policy)

    assert response.estimated_cost_usd is None
    assert len(provider.requests) == 1


def test_usage_ledger_records_successful_call():
    provider = MockProvider(
        "ollama",
        "local-model",
        success("ollama", "local-model", input_tokens=8, output_tokens=3, cost=0.0),
    )
    ledger = ModelCallLedger()
    router = ModelRouter(
        MockRegistry({("ollama", "local-model"): provider}), ledger=ledger
    )
    before = ledger.snapshot(run_id="run-router-1")
    router.route(model_request(), preferred_policy("ollama", "local-model"))
    after = ledger.snapshot(run_id="run-router-1")
    delta = ledger.delta(before, after)
    assert delta.attempted_calls == delta.successful_calls == 1
    assert delta.failed_calls == 0
    assert delta.total_tokens == 11


def test_usage_ledger_records_failed_call():
    provider = MockProvider(
        "ollama",
        "local-model",
        provider_error(ModelErrorCode.connection_failed, "ollama", "local-model"),
    )
    ledger = ModelCallLedger()
    router = ModelRouter(
        MockRegistry({("ollama", "local-model"): provider}), ledger=ledger
    )
    with pytest.raises(ModelProviderError):
        router.route(model_request(), preferred_policy("ollama", "local-model"))
    usage = ledger.usage_for_run("run-router-1")
    assert usage.attempted_calls == usage.failed_calls == 1
    assert usage.successful_calls == 0


def test_usage_ledger_records_fallback_sequence_and_depth():
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    ledger = ModelCallLedger()
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("ollama", "local-model"): second,
            }
        ),
        ledger=ledger,
    )
    router.route(
        model_request(),
        fallback_policy(("openai", "openai-model"), ("ollama", "local-model")),
    )
    assert [record.fallback_depth for record in ledger.records] == [0, 1]
    assert [record.success for record in ledger.records] == [False, True]


def test_model_usage_delta_call_invariant():
    with pytest.raises(ValidationError):
        ModelUsageDelta(attempted_calls=2, successful_calls=1, failed_calls=0)


def test_model_usage_delta_token_invariant():
    with pytest.raises(ValidationError):
        ModelUsageDelta(input_tokens=2, output_tokens=3, total_tokens=6)


def test_fallback_provenance_is_complete():
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider(
        "anthropic", "anthropic-model", success("anthropic", "anthropic-model")
    )
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("anthropic", "anthropic-model"): second,
            }
        )
    )
    response = router.route(
        model_request(),
        fallback_policy(("openai", "openai-model"), ("anthropic", "anthropic-model")),
    )
    assert response.requested_provider == "openai"
    assert response.provider == "anthropic"
    assert response.fallback_used is True
    assert response.fallback_depth == 1
    assert response.model_calls_attempted == 2
    assert response.prior_attempt_outcomes[0].outcome == ModelErrorCode.timeout


def test_prior_attempt_outcomes_never_copy_raw_exception_text():
    provider = MockProvider(
        "openai", "openai-model", RuntimeError(f"secret={API_KEY_SENTINEL}")
    )
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    with pytest.raises(ModelProviderError) as captured:
        router.route(model_request(), preferred_policy())
    rendered = json.dumps(captured.value.public_dict()) + json.dumps(
        [record.model_dump(mode="json") for record in router.ledger.records]
    )
    assert API_KEY_SENTINEL not in rendered
    assert "RuntimeError" not in rendered


def test_api_key_sentinel_absent_from_router_error_and_ledger():
    provider = MockProvider("openai", "openai-model", RuntimeError(API_KEY_SENTINEL))
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    with pytest.raises(ModelProviderError) as captured:
        router.route(model_request(), preferred_policy())
    assert API_KEY_SENTINEL not in json.dumps(captured.value.public_dict())
    assert API_KEY_SENTINEL not in repr(router.ledger.records)


def sanitized_fallback_request(raw_evidence: dict[str, Any]):
    return ModelRequest.from_phase2(
        system_instructions="Reason only.",
        user_content="Review the public evidence.",
        evidence=raw_evidence,
        task_type="evidence_review",
        run_id="run-router-1",
        hypothesis_id="hyp-router-1",
        max_output_tokens=10,
        temperature=0.0,
    )


def fallback_capture(raw_evidence: dict[str, Any]):
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("ollama", "local-model"): second,
            }
        )
    )
    router.route(
        sanitized_fallback_request(raw_evidence),
        fallback_policy(("openai", "openai-model"), ("ollama", "local-model")),
    )
    return first.requests[0], second.requests[0]


def test_authorization_sentinel_absent_across_fallback():
    requests = fallback_capture(
        {"headers": {"Authorization": f"Bearer {AUTH_SENTINEL}"}}
    )
    assert all(AUTH_SENTINEL not in item.model_dump_json() for item in requests)


def test_cookie_and_session_sentinel_absent_across_fallback():
    requests = fallback_capture({"headers": {"Cookie": f"session={COOKIE_SENTINEL}"}})
    assert all(COOKIE_SENTINEL not in item.model_dump_json() for item in requests)


def test_recovery_secret_sentinel_absent_across_fallback():
    requests = fallback_capture(
        {"private_recovery_state": {"challenge": RECOVERY_SENTINEL}}
    )
    assert all(RECOVERY_SENTINEL not in item.model_dump_json() for item in requests)


def test_fallback_preserves_identical_sanitized_evidence():
    first, second = fallback_capture(
        {
            "status": "inconclusive",
            "private_recovery_state": {"challenge": RECOVERY_SENTINEL},
        }
    )
    assert first.evidence == second.evidence == {"status": "inconclusive"}


def test_model_usage_delta_does_not_alter_phase2_request_delta():
    budget = RequestBudget(limit=3)
    before = budget.snapshot()
    provider = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    router = ModelRouter(MockRegistry({("ollama", "local-model"): provider}))
    router.route(model_request(), preferred_policy("ollama", "local-model"))
    assert budget.snapshot() == before


def test_identical_policy_produces_deterministic_route_order():
    policy = fallback_policy(
        ("openai", "one"), ("anthropic", "two"), ("ollama", "three")
    )
    assert policy.ordered_routes() == policy.model_copy().ordered_routes()
    assert [route.model for route in policy.ordered_routes()] == ["one", "two", "three"]


def test_unknown_provider_is_rejected():
    with pytest.raises(ValidationError):
        ModelRoutingPolicy(
            mode=RoutingMode.fallback_chain,
            preferred=ModelRoute(provider="unknown", model="model"),
        )


def test_unavailable_preferred_provider_returns_deterministic_failure():
    provider = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.provider_unavailable, "openai", "openai-model"),
    )
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    with pytest.raises(ModelProviderError) as captured:
        router.route(model_request(), preferred_policy())
    assert captured.value.code == ModelErrorCode.provider_unavailable
    assert str(captured.value) == "The selected model provider is unavailable."


def test_fallback_exhaustion_returns_only_sanitized_outcomes():
    first = MockProvider(
        "openai",
        "one",
        provider_error(ModelErrorCode.timeout, "openai", "one"),
    )
    second = MockProvider(
        "anthropic",
        "two",
        provider_error(ModelErrorCode.connection_failed, "anthropic", "two"),
    )
    router = ModelRouter(
        MockRegistry({("openai", "one"): first, ("anthropic", "two"): second})
    )
    with pytest.raises(ModelRoutingError) as captured:
        router.route(
            model_request(),
            fallback_policy(("openai", "one"), ("anthropic", "two")),
        )
    assert captured.value.code == ModelErrorCode.routing_exhausted
    assert [item["outcome"] for item in captured.value.prior_outcomes] == [
        "timeout",
        "connection_failed",
    ]


def test_timeout_fallback_is_bounded_and_has_zero_retries():
    first = MockProvider(
        "openai",
        "one",
        provider_error(ModelErrorCode.timeout, "openai", "one"),
    )
    second = MockProvider(
        "ollama",
        "two",
        provider_error(ModelErrorCode.timeout, "ollama", "two"),
    )
    registry = MockRegistry({("openai", "one"): first, ("ollama", "two"): second})
    policy = fallback_policy(("openai", "one"), ("ollama", "two"))
    with pytest.raises(ModelRoutingError):
        ModelRouter(registry).route(model_request(), policy)
    assert policy.max_retries == 0
    assert len(first.requests) == len(second.requests) == 1


def test_model_request_cannot_supply_routing_configuration():
    with pytest.raises(ValidationError):
        ModelRequest(
            **model_request().model_dump(),
            routing_policy={"provider": "model-chosen-provider"},
        )


def test_provider_specific_raw_object_does_not_escape_router():
    raw = object()
    provider = MockProvider("openai", "openai-model", raw)
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    with pytest.raises(ModelProviderError) as captured:
        router.route(model_request(), preferred_policy())
    assert captured.value.code == ModelErrorCode.invalid_response
    assert raw not in router.ledger.records


def test_ollama_zero_api_cost_is_preserved_in_response_and_ledger():
    provider = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    router = ModelRouter(MockRegistry({("ollama", "local-model"): provider}))
    response = router.route(model_request(), preferred_policy("ollama", "local-model"))
    assert response.estimated_cost_usd == 0.0
    assert router.ledger.records[0].estimated_cost_usd == 0.0


def test_gpt_5_5_pro_snapshot_cost_is_accounted_exactly_once():
    expected_cost = 0.48669
    provider = MockProvider(
        "openai",
        "gpt-5.5-pro",
        success(
            "openai",
            "gpt-5.5-pro-2026-04-23",
            input_tokens=3887,
            output_tokens=2056,
            cost=expected_cost,
        ),
    )
    router = ModelRouter(MockRegistry({("openai", "gpt-5.5-pro"): provider}))

    response = router.route(
        model_request(max_output_tokens=2056),
        preferred_policy("openai", "gpt-5.5-pro"),
    )
    usage = router.ledger.usage_for_run("run-router-1")

    assert response.model == "gpt-5.5-pro-2026-04-23"
    assert len(router.ledger.records) == 1
    assert usage.attempted_calls == 1
    assert usage.estimated_cost_usd == pytest.approx(expected_cost)
    assert usage.budget_estimated_cost_usd == pytest.approx(expected_cost)


def test_local_only_never_contacts_any_cloud_provider():
    ollama = MockProvider(
        "ollama", "local-model", success("ollama", "local-model", cost=0.0)
    )
    registry = MockRegistry({("ollama", "local-model"): ollama})
    ModelRouter(registry).route(
        model_request(), preferred_policy("ollama", "local-model")
    )
    contacted = {provider for provider, _ in registry.create_calls}
    assert contacted.isdisjoint({"openai", "anthropic"})


class DefinitelyUnavailableProvider:
    availability = ProviderAvailability(
        provider="openai",
        model="openai-model",
        available=False,
        reason_code=ModelErrorCode.configuration_error,
        message="Provider configuration is unavailable.",
    )

    def __init__(self) -> None:
        self.called = False

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.called = True
        raise AssertionError("unavailable provider must not be invoked")


def reservation_size(request: ModelRequest) -> int:
    return ModelRouter._conservative_input_token_estimate(request) + 1


def test_definite_pre_call_failure_does_not_commit_reservation():
    provider = DefinitelyUnavailableProvider()
    router = ModelRouter(
        MockRegistry({("openai", "openai-model"): provider})  # type: ignore[arg-type]
    )

    with pytest.raises(ModelProviderError) as captured:
        router.route(model_request(), preferred_policy())

    assert captured.value.code == ModelErrorCode.configuration_error
    assert provider.called is False
    record = router.ledger.records[0]
    assert record.attempt_state == "blocked_before_provider_call"
    assert record.budget_total_tokens == 0
    assert router.ledger.active_reservations == ()


def test_success_reconciles_reservation_to_actual_without_double_counting():
    provider = MockProvider(
        "ollama",
        "local-model",
        success(
            "ollama",
            "local-model",
            input_tokens=7,
            output_tokens=3,
            cost=0.0,
        ),
    )
    router = ModelRouter(MockRegistry({("ollama", "local-model"): provider}))

    router.route(model_request(), preferred_policy("ollama", "local-model"))

    record = router.ledger.records[0]
    usage = router.ledger.usage_for_run("run-router-1")
    assert record.attempt_state == "provider_call_succeeded"
    assert record.usage_known is True
    assert record.total_tokens == record.budget_total_tokens == 10
    assert usage.total_tokens == usage.budget_total_tokens == 10
    assert usage.unknown_usage_calls == 0


@pytest.mark.parametrize(
    "code",
    [
        ModelErrorCode.timeout,
        ModelErrorCode.rate_limited,
        ModelErrorCode.connection_failed,
        ModelErrorCode.provider_unavailable,
    ],
)
def test_started_provider_failures_retain_unknown_usage_reservation(code):
    provider = MockProvider(
        "openai",
        "openai-model",
        provider_error(code, "openai", "openai-model"),
    )
    request = model_request(max_output_tokens=1)
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))

    with pytest.raises(ModelProviderError):
        router.route(request, preferred_policy())

    record = router.ledger.records[0]
    usage = router.ledger.usage_for_run(request.run_id)
    assert record.attempt_state == "provider_call_failed_after_start"
    assert record.usage_known is False
    assert (record.input_tokens, record.output_tokens, record.total_tokens) == (
        None,
        None,
        None,
    )
    assert record.budget_total_tokens == reservation_size(request)
    assert usage.total_tokens == 0
    assert usage.budget_total_tokens == reservation_size(request)
    assert usage.unknown_usage_calls == 1


def test_malformed_response_after_call_retains_reservation():
    provider = MockProvider("openai", "openai-model", {"malformed": True})
    request = model_request(max_output_tokens=1)
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))

    with pytest.raises(ModelProviderError) as captured:
        router.route(request, preferred_policy())

    assert captured.value.code == ModelErrorCode.invalid_response
    assert router.ledger.records[0].budget_total_tokens == reservation_size(request)
    assert router.ledger.records[0].usage_known is False


def test_failed_full_reservation_blocks_fallback_audit_reproduction():
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider(
        "anthropic",
        "anthropic-model",
        success("anthropic", "anthropic-model"),
    )
    request = model_request(max_output_tokens=1)
    budget = ModelBudgetLimits(max_total_tokens=reservation_size(request))
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("anthropic", "anthropic-model"): second,
            }
        )
    )

    with pytest.raises(ModelRoutingError) as captured:
        router.route(
            request,
            fallback_policy(
                ("openai", "openai-model"),
                ("anthropic", "anthropic-model"),
                budget=budget,
            ),
        )

    assert captured.value.code == ModelErrorCode.model_budget_exceeded
    assert len(first.requests) == 1
    assert second.requests == []
    assert router.ledger.usage_for_run(request.run_id).budget_total_tokens == (
        budget.max_total_tokens
    )


def test_fallback_starts_when_budget_supports_second_reservation():
    first = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    second = MockProvider(
        "anthropic",
        "anthropic-model",
        success("anthropic", "anthropic-model", input_tokens=4, output_tokens=1),
    )
    request = model_request(max_output_tokens=1)
    budget = ModelBudgetLimits(max_total_tokens=reservation_size(request) * 2)
    router = ModelRouter(
        MockRegistry(
            {
                ("openai", "openai-model"): first,
                ("anthropic", "anthropic-model"): second,
            }
        )
    )

    response = router.route(
        request,
        fallback_policy(
            ("openai", "openai-model"),
            ("anthropic", "anthropic-model"),
            budget=budget,
        ),
    )

    assert response.provider == "anthropic"
    assert len(first.requests) == len(second.requests) == 1
    usage = router.ledger.usage_for_run(request.run_id)
    assert usage.attempted_calls == 2
    assert usage.budget_total_tokens == reservation_size(request) + 5


def test_later_same_provider_attempt_cannot_reuse_failed_reservation():
    provider = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    request = model_request(max_output_tokens=1)
    budget = ModelBudgetLimits(
        max_model_calls=2,
        max_total_tokens=reservation_size(request),
    )
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    policy = preferred_policy(budget=budget)

    with pytest.raises(ModelProviderError):
        router.route(request, policy)
    with pytest.raises(ModelRoutingError) as captured:
        router.route(request, policy)

    assert captured.value.code == ModelErrorCode.model_budget_exceeded
    assert len(provider.requests) == 1


def test_later_same_provider_attempt_is_allowed_with_remaining_reservation():
    provider = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    request = model_request(max_output_tokens=1)
    budget = ModelBudgetLimits(
        max_model_calls=2,
        max_total_tokens=reservation_size(request) * 2,
    )
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    policy = preferred_policy(budget=budget)

    for _ in range(2):
        with pytest.raises(ModelProviderError):
            router.route(request, policy)

    assert len(provider.requests) == 2
    assert router.ledger.usage_for_run(request.run_id).budget_total_tokens == (
        reservation_size(request) * 2
    )


def test_partial_failure_usage_is_observed_but_reservation_stays_conservative():
    error = ModelProviderError(
        ModelErrorCode.timeout,
        provider="openai",
        model="openai-model",
        partial_input_tokens=2,
        partial_output_tokens=1,
        partial_estimated_cost_usd=0.25,
    )
    provider = MockProvider("openai", "openai-model", error)
    request = model_request(max_output_tokens=1)
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))

    with pytest.raises(ModelProviderError):
        router.route(request, preferred_policy())

    record = router.ledger.records[0]
    assert record.usage_known is True
    assert record.total_tokens == 3
    assert record.budget_total_tokens == reservation_size(request)
    assert record.estimated_cost_usd == 0.25


def test_failed_known_price_call_retains_distinct_cost_reservation():
    pricing = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="openai-model",
                input_per_million_usd=1.0,
                output_per_million_usd=2.0,
            ),
        )
    )
    provider = MockProvider(
        "openai",
        "openai-model",
        provider_error(ModelErrorCode.timeout, "openai", "openai-model"),
    )
    router = ModelRouter(
        MockRegistry({("openai", "openai-model"): provider}, pricing=pricing)
    )

    with pytest.raises(ModelProviderError):
        router.route(model_request(max_output_tokens=1), preferred_policy())

    record = router.ledger.records[0]
    assert record.estimated_cost_usd is None
    assert record.budget_estimated_cost_usd is not None
    assert record.budget_estimated_cost_usd > 0.0


@pytest.mark.parametrize(
    ("provider_name", "model_name"),
    [
        ("openai", "openai-model"),
        ("anthropic", "anthropic-model"),
        ("ollama", "local-model"),
    ],
)
def test_failed_attempt_reservation_has_provider_parity(provider_name, model_name):
    provider = MockProvider(
        provider_name,
        model_name,
        provider_error(ModelErrorCode.connection_failed, provider_name, model_name),
    )
    request = model_request(max_output_tokens=1)
    router = ModelRouter(MockRegistry({(provider_name, model_name): provider}))

    with pytest.raises(ModelProviderError):
        router.route(request, preferred_policy(provider_name, model_name))

    assert router.ledger.records[0].budget_total_tokens == reservation_size(request)
    assert router.ledger.records[0].attempt_state == (
        "provider_call_failed_after_start"
    )


def test_reservation_fields_do_not_affect_target_request_accounting_or_leak_secrets():
    raw = RuntimeError(
        f"Authorization: Bearer {AUTH_SENTINEL}; cookie={COOKIE_SENTINEL}; "
        f"password={API_KEY_SENTINEL}; recovery={RECOVERY_SENTINEL}"
    )
    provider = MockProvider("openai", "openai-model", raw)
    router = ModelRouter(MockRegistry({("openai", "openai-model"): provider}))
    target_budget = RequestBudget(limit=2)
    target_before = target_budget.snapshot()

    with pytest.raises(ModelProviderError):
        router.route(model_request(), preferred_policy())

    rendered = json.dumps(
        [record.model_dump(mode="json") for record in router.ledger.records]
    )
    assert target_budget.snapshot() == target_before
    assert all(
        sentinel not in rendered
        for sentinel in (
            AUTH_SENTINEL,
            COOKIE_SENTINEL,
            API_KEY_SENTINEL,
            RECOVERY_SENTINEL,
        )
    )
