"""Deterministic model selection, bounded fallback, and model-only budgets."""

from __future__ import annotations

import json
import re
import time
from enum import Enum
from collections.abc import Callable
from typing import Any, Literal

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.models.accounting import ModelBudgetReservation, ModelCallLedger
from agent_core.models.base import ProviderAvailability
from agent_core.models.errors import (
    ModelErrorCode,
    ModelProviderError,
    ModelRoutingError,
)
from agent_core.models.pricing import normalize_provider_alias
from agent_core.models.registry import ProviderRegistry
from agent_core.models.types import (
    ModelAttemptOutcome,
    ModelContract,
    ModelRequest,
    ModelResponse,
)

LOCAL_PROVIDERS = frozenset({"ollama"})
CLOUD_PROVIDERS = frozenset({"openai", "anthropic"})
KNOWN_PROVIDERS = LOCAL_PROVIDERS | CLOUD_PROVIDERS
RELIABILITY_FALLBACK_ERRORS = frozenset(
    {
        ModelErrorCode.provider_unavailable,
        ModelErrorCode.timeout,
        ModelErrorCode.rate_limited,
        ModelErrorCode.connection_failed,
    }
)
DEFAULT_FALLBACK_ERRORS = (
    ModelErrorCode.provider_unavailable,
    ModelErrorCode.timeout,
    ModelErrorCode.rate_limited,
    ModelErrorCode.connection_failed,
)
_MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")


class RoutingMode(str, Enum):
    preferred = "preferred"
    local_only = "local_only"
    cloud_only = "cloud_only"
    fallback_chain = "fallback_chain"


class ModelRoute(ModelContract):
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)

    @field_validator("provider")
    @classmethod
    def normalize_provider(cls, value: str) -> str:
        return normalize_provider_alias(value)

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        if not _MODEL_NAME.fullmatch(value):
            raise ValueError("model must be a configured model identifier")
        return value


class ModelBudgetLimits(ModelContract):
    max_model_calls: StrictInt = Field(default=10, ge=1, le=10_000)
    max_input_tokens: StrictInt | None = Field(default=None, ge=1)
    max_output_tokens: StrictInt | None = Field(default=None, ge=1)
    max_total_tokens: StrictInt | None = Field(default=None, ge=1)
    max_estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    max_per_call_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    unknown_cost_policy: Literal["deny", "allow"] = "deny"

    @property
    def has_monetary_ceiling(self) -> bool:
        return (
            self.max_estimated_cost_usd is not None
            or self.max_per_call_cost_usd is not None
        )


class ModelRoutingPolicy(ModelContract):
    """Strict operator configuration; model output cannot mutate this policy."""

    mode: RoutingMode
    preferred: ModelRoute
    fallbacks: tuple[ModelRoute, ...] = Field(default=(), max_length=20)
    fallback_allowed: StrictBool = False
    max_provider_attempts: StrictInt = Field(default=1, ge=1, le=20)
    allowed_cloud_providers: tuple[StrictStr, ...] = Field(default=(), max_length=2)
    fallback_on: tuple[ModelErrorCode, ...] = DEFAULT_FALLBACK_ERRORS
    max_retries: Literal[0] = 0
    budget: ModelBudgetLimits = Field(default_factory=ModelBudgetLimits)

    @field_validator("mode", mode="before")
    @classmethod
    def parse_mode(cls, value: Any) -> Any:
        if isinstance(value, str):
            return RoutingMode(value)
        return value

    @field_validator("allowed_cloud_providers")
    @classmethod
    def normalize_cloud_allowlist(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(normalize_provider_alias(value) for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_cloud_providers must not contain duplicates")
        if any(value not in CLOUD_PROVIDERS for value in normalized):
            raise ValueError("allowed_cloud_providers supports only cloud adapters")
        return normalized

    @field_validator("fallback_on", mode="before")
    @classmethod
    def restrict_fallback_errors(cls, values: Any) -> tuple[ModelErrorCode, ...]:
        values = tuple(
            item if isinstance(item, ModelErrorCode) else ModelErrorCode(item)
            for item in values
        )
        if not set(values).issubset(RELIABILITY_FALLBACK_ERRORS):
            raise ValueError("fallback_on may contain only reliability failures")
        if len(set(values)) != len(values):
            raise ValueError("fallback_on must not contain duplicates")
        return values

    @model_validator(mode="after")
    def validate_routes(self) -> "ModelRoutingPolicy":
        routes = (self.preferred, *self.fallbacks)
        unknown = [
            route.provider for route in routes if route.provider not in KNOWN_PROVIDERS
        ]
        if unknown:
            raise ValueError("routing policy contains an unknown provider")
        identities = [(route.provider, route.model) for route in routes]
        if len(set(identities)) != len(identities):
            raise ValueError("routing policy cannot retry the same provider/model")
        if self.mode == RoutingMode.preferred and self.fallback_allowed:
            raise ValueError("preferred mode does not permit fallback")
        if self.mode == RoutingMode.local_only and any(
            route.provider not in LOCAL_PROVIDERS for route in routes
        ):
            raise ValueError(
                "local_only mode permits only Ollama-family providers; "
                "endpoint locality depends on configuration"
            )
        if self.mode == RoutingMode.cloud_only and any(
            route.provider not in CLOUD_PROVIDERS for route in routes
        ):
            raise ValueError("cloud_only mode permits only cloud providers")
        unlisted_cloud = [
            route.provider
            for route in routes
            if route.provider in CLOUD_PROVIDERS
            and route.provider not in self.allowed_cloud_providers
        ]
        if unlisted_cloud:
            raise ValueError("cloud route is not in allowed_cloud_providers")
        return self

    def ordered_routes(self) -> tuple[ModelRoute, ...]:
        if self.mode == RoutingMode.preferred or not self.fallback_allowed:
            routes = (self.preferred,)
        else:
            routes = (self.preferred, *self.fallbacks)
        return routes[: self.max_provider_attempts]

    def safe_summary(self) -> dict[str, Any]:
        """Return diagnostics containing no credentials or private config values."""

        return {
            "mode": self.mode.value,
            "preferred": self.preferred.model_dump(mode="json"),
            "fallbacks": [route.model_dump(mode="json") for route in self.fallbacks],
            "fallback_allowed": self.fallback_allowed,
            "max_provider_attempts": self.max_provider_attempts,
            "max_retries": self.max_retries,
            "allowed_cloud_providers": list(self.allowed_cloud_providers),
            "budget": self.budget.model_dump(mode="json"),
        }


class ModelRouter:
    """Choose a configured model only; never choose or execute security actions."""

    def __init__(
        self,
        registry: ProviderRegistry,
        *,
        ledger: ModelCallLedger | None = None,
    ) -> None:
        self.registry = registry
        self.ledger = ledger or ModelCallLedger()

    def route(self, request: ModelRequest, policy: ModelRoutingPolicy) -> ModelResponse:
        if not isinstance(request, ModelRequest) or not isinstance(
            policy, ModelRoutingPolicy
        ):
            raise TypeError("ModelRouter requires strict request and policy models")
        routes = policy.ordered_routes()
        outcomes: list[ModelAttemptOutcome] = []
        with self.ledger.routing_transaction():
            for fallback_depth, selected in enumerate(routes):
                attempt_request, reservation = self._preflight(
                    request, selected, policy.budget
                )
                pre_call_started = time.monotonic()
                try:
                    provider = self.registry.create(
                        selected.provider,
                        model_name=selected.model,
                    )
                    generate, pre_call_failure = self._provider_call(
                        provider, selected, attempt_request
                    )
                except ModelProviderError as exc:
                    generate = None
                    pre_call_failure = exc
                except Exception:
                    generate = None
                    pre_call_failure = ModelProviderError(
                        ModelErrorCode.configuration_error,
                        provider=selected.provider,
                        model=selected.model,
                    )
                if pre_call_failure is not None or generate is None:
                    failure = pre_call_failure or ModelProviderError(
                        ModelErrorCode.invalid_response,
                        provider=selected.provider,
                        model=selected.model,
                    )
                    self.ledger.record_pre_call_failure(
                        provider=selected.provider,
                        model=selected.model,
                        latency_seconds=float(time.monotonic() - pre_call_started),
                        task_type=request.task_type,
                        run_id=request.run_id,
                        hypothesis_id=request.hypothesis_id,
                        fallback_depth=fallback_depth,
                        outcome=failure.code,
                    )
                    self._continue_after_failure(
                        policy=policy,
                        routes=routes,
                        fallback_depth=fallback_depth,
                        selected=selected,
                        failure=failure,
                        outcomes=outcomes,
                    )
                    continue

                committed = self.ledger.commit_reservation(
                    provider=selected.provider,
                    model=selected.model,
                    task_type=request.task_type,
                    run_id=request.run_id,
                    hypothesis_id=request.hypothesis_id,
                    fallback_depth=fallback_depth,
                    reservation=reservation,
                )
                started = time.monotonic()
                failure: ModelProviderError | None = None
                response: ModelResponse | None = None
                partial_response: ModelResponse | None = None
                try:
                    candidate = generate(attempt_request)
                    if not isinstance(candidate, ModelResponse):
                        failure = ModelProviderError(
                            ModelErrorCode.invalid_response,
                            provider=selected.provider,
                            model=selected.model,
                        )
                    elif (
                        candidate.provider != selected.provider
                        or candidate.model != selected.model
                        or candidate.task_type != request.task_type
                        or candidate.run_id != request.run_id
                        or candidate.hypothesis_id != request.hypothesis_id
                    ):
                        partial_response = candidate
                        failure = ModelProviderError(
                            ModelErrorCode.invalid_response,
                            provider=selected.provider,
                            model=selected.model,
                        )
                    else:
                        response = candidate
                except ModelProviderError as exc:
                    failure = exc
                except Exception:
                    failure = ModelProviderError(
                        ModelErrorCode.invalid_response,
                        provider=selected.provider,
                        model=selected.model,
                    )

                if failure is not None:
                    elapsed = float(time.monotonic() - started)
                    partial_input = (
                        partial_response.input_tokens
                        if partial_response is not None
                        else failure.partial_input_tokens
                    )
                    partial_output = (
                        partial_response.output_tokens
                        if partial_response is not None
                        else failure.partial_output_tokens
                    )
                    partial_cost = (
                        partial_response.estimated_cost_usd
                        if partial_response is not None
                        else failure.partial_estimated_cost_usd
                    )
                    if partial_cost is None and selected.provider in LOCAL_PROVIDERS:
                        partial_cost = 0.0
                    self.ledger.record_failure(
                        provider=selected.provider,
                        model=selected.model,
                        latency_seconds=elapsed,
                        task_type=request.task_type,
                        run_id=request.run_id,
                        hypothesis_id=request.hypothesis_id,
                        fallback_depth=fallback_depth,
                        outcome=failure.code,
                        estimated_cost_usd=partial_cost,
                        reservation=committed,
                        input_tokens=partial_input,
                        output_tokens=partial_output,
                    )
                    self._continue_after_failure(
                        policy=policy,
                        routes=routes,
                        fallback_depth=fallback_depth,
                        selected=selected,
                        failure=failure,
                        outcomes=outcomes,
                    )
                    continue

                if response is None:
                    raise AssertionError(
                        "model provider produced no normalized outcome"
                    )
                self.ledger.record_success(
                    response,
                    fallback_depth=fallback_depth,
                    reservation=committed,
                )
                self._reconcile_budget(request.run_id, response, policy.budget)
                return self._with_provenance(
                    response,
                    policy=policy,
                    fallback_depth=fallback_depth,
                    outcomes=tuple(outcomes),
                )

        raise self._routing_exhausted(policy, outcomes) from None

    def _preflight(
        self,
        request: ModelRequest,
        selected: ModelRoute,
        limits: ModelBudgetLimits,
    ) -> tuple[ModelRequest, ModelBudgetReservation]:
        usage = self.ledger.usage_for_run(request.run_id)
        if usage.attempted_calls >= limits.max_model_calls:
            raise self._budget_error(selected, ModelErrorCode.model_budget_exceeded)

        input_estimate = self._conservative_input_token_estimate(request)
        if (
            limits.max_input_tokens is not None
            and usage.budget_input_tokens + input_estimate > limits.max_input_tokens
        ):
            raise self._budget_error(selected, ModelErrorCode.model_budget_exceeded)

        output_limit = request.max_output_tokens
        if limits.max_output_tokens is not None:
            output_limit = min(
                output_limit,
                limits.max_output_tokens - usage.budget_output_tokens,
            )
        if limits.max_total_tokens is not None:
            total_remaining = limits.max_total_tokens - usage.budget_total_tokens
            output_limit = min(output_limit, total_remaining - input_estimate)
        if output_limit < 1:
            raise self._budget_error(selected, ModelErrorCode.model_budget_exceeded)

        predicted_cost = self.registry.pricing.estimate_cost(
            selected.provider,
            selected.model,
            input_tokens=input_estimate,
            output_tokens=output_limit,
        )
        if limits.has_monetary_ceiling:
            if predicted_cost is None and limits.unknown_cost_policy == "deny":
                raise self._budget_error(selected, ModelErrorCode.unknown_cost)
            if (
                predicted_cost is not None
                and limits.max_per_call_cost_usd is not None
                and predicted_cost > limits.max_per_call_cost_usd
            ):
                raise self._budget_error(selected, ModelErrorCode.model_budget_exceeded)
            if limits.max_estimated_cost_usd is not None:
                if (
                    usage.attempted_calls
                    and usage.budget_estimated_cost_usd is None
                    and limits.unknown_cost_policy == "deny"
                ):
                    raise self._budget_error(selected, ModelErrorCode.unknown_cost)
                if (
                    predicted_cost is not None
                    and usage.budget_estimated_cost_usd is not None
                    and usage.budget_estimated_cost_usd + predicted_cost
                    > limits.max_estimated_cost_usd
                ):
                    raise self._budget_error(
                        selected, ModelErrorCode.model_budget_exceeded
                    )

        attempt_request = (
            request
            if output_limit == request.max_output_tokens
            else ModelRequest.model_validate(
                {
                    **request.model_dump(mode="python"),
                    "max_output_tokens": output_limit,
                }
            )
        )
        return attempt_request, ModelBudgetReservation(
            input_tokens=input_estimate,
            output_tokens=output_limit,
            total_tokens=input_estimate + output_limit,
            estimated_cost_usd=predicted_cost,
        )

    def _reconcile_budget(
        self,
        run_id: str | None,
        response: ModelResponse,
        limits: ModelBudgetLimits,
    ) -> None:
        usage = self.ledger.usage_for_run(run_id)
        over_tokens = any(
            (
                ceiling is not None and actual > ceiling
                for actual, ceiling in (
                    (usage.budget_input_tokens, limits.max_input_tokens),
                    (usage.budget_output_tokens, limits.max_output_tokens),
                    (usage.budget_total_tokens, limits.max_total_tokens),
                )
            )
        )
        if over_tokens:
            raise self._budget_error(
                ModelRoute(provider=response.provider, model=response.model),
                ModelErrorCode.model_budget_exceeded,
            )
        if limits.has_monetary_ceiling:
            if (
                response.estimated_cost_usd is None
                and limits.unknown_cost_policy == "deny"
            ):
                raise self._budget_error(
                    ModelRoute(provider=response.provider, model=response.model),
                    ModelErrorCode.unknown_cost,
                )
            if (
                limits.max_per_call_cost_usd is not None
                and response.estimated_cost_usd is not None
                and response.estimated_cost_usd > limits.max_per_call_cost_usd
            ):
                raise self._budget_error(
                    ModelRoute(provider=response.provider, model=response.model),
                    ModelErrorCode.model_budget_exceeded,
                )
            if (
                limits.max_estimated_cost_usd is not None
                and usage.budget_estimated_cost_usd is not None
                and usage.budget_estimated_cost_usd > limits.max_estimated_cost_usd
            ):
                raise self._budget_error(
                    ModelRoute(provider=response.provider, model=response.model),
                    ModelErrorCode.model_budget_exceeded,
                )

    @staticmethod
    def _provider_call(
        provider: Any,
        selected: ModelRoute,
        request: ModelRequest,
    ) -> tuple[Callable[[ModelRequest], Any] | None, ModelProviderError | None]:
        """Resolve the one provider-start boundary after definite pre-call checks."""

        availability = getattr(provider, "availability", None)
        if availability is not None:
            if not isinstance(availability, ProviderAvailability):
                return None, ModelProviderError(
                    ModelErrorCode.configuration_error,
                    provider=selected.provider,
                    model=selected.model,
                )
            if not availability.available:
                return None, ModelProviderError(
                    availability.reason_code or ModelErrorCode.provider_unavailable,
                    provider=selected.provider,
                    model=selected.model,
                )
        if (
            request.structured_output
            and getattr(provider, "supports_structured_output", None) is False
        ):
            return None, ModelProviderError(
                ModelErrorCode.provider_unavailable,
                provider=selected.provider,
                model=selected.model,
            )
        generate = getattr(provider, "generate", None)
        if not callable(generate):
            return None, ModelProviderError(
                ModelErrorCode.invalid_response,
                provider=selected.provider,
                model=selected.model,
            )
        return generate, None

    @staticmethod
    def _continue_after_failure(
        *,
        policy: ModelRoutingPolicy,
        routes: tuple[ModelRoute, ...],
        fallback_depth: int,
        selected: ModelRoute,
        failure: ModelProviderError,
        outcomes: list[ModelAttemptOutcome],
    ) -> None:
        outcomes.append(
            ModelAttemptOutcome(
                attempt_index=fallback_depth,
                provider=selected.provider,
                model=selected.model,
                outcome=failure.code,
            )
        )
        has_next = fallback_depth + 1 < len(routes)
        if failure.code not in policy.fallback_on:
            failure.__traceback__ = None
            failure.__cause__ = None
            failure.__context__ = None
            raise failure from None
        if not has_next:
            if len(outcomes) == 1:
                failure.__traceback__ = None
                failure.__cause__ = None
                failure.__context__ = None
                raise failure from None
            raise ModelRouter._routing_exhausted(policy, outcomes) from None

    @staticmethod
    def _conservative_input_token_estimate(request: ModelRequest) -> int:
        """Use one token per UTF-8 byte as a deterministic preflight upper estimate."""

        evidence = json.dumps(
            request.evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        material = "\n".join(
            (request.system_instructions, request.user_content, evidence)
        )
        return max(1, len(material.encode("utf-8")))

    @staticmethod
    def _with_provenance(
        response: ModelResponse,
        *,
        policy: ModelRoutingPolicy,
        fallback_depth: int,
        outcomes: tuple[ModelAttemptOutcome, ...],
    ) -> ModelResponse:
        fallback_used = fallback_depth > 0
        return ModelResponse.model_validate(
            {
                **response.model_dump(mode="python"),
                "fallback_used": fallback_used,
                "fallback_provider": response.provider if fallback_used else None,
                "fallback_model": response.model if fallback_used else None,
                "fallback_reason": outcomes[0].outcome.value if outcomes else None,
                "requested_provider": policy.preferred.provider,
                "requested_model": policy.preferred.model,
                "fallback_depth": fallback_depth,
                "model_calls_attempted": len(outcomes) + 1,
                "prior_attempt_outcomes": outcomes,
                "metadata": {
                    **response.metadata,
                    "routing_mode": policy.mode.value,
                },
            }
        )

    @staticmethod
    def _budget_error(selected: ModelRoute, code: ModelErrorCode) -> ModelRoutingError:
        return ModelRoutingError(
            code,
            provider=selected.provider,
            model=selected.model,
        )

    @staticmethod
    def _routing_exhausted(
        policy: ModelRoutingPolicy,
        outcomes: list[ModelAttemptOutcome],
    ) -> ModelRoutingError:
        return ModelRoutingError(
            ModelErrorCode.routing_exhausted,
            provider=policy.preferred.provider,
            model=policy.preferred.model,
            prior_outcomes=tuple(
                {
                    "attempt_index": item.attempt_index,
                    "provider": item.provider,
                    "model": item.model,
                    "outcome": item.outcome.value,
                }
                for item in outcomes
            ),
        )
