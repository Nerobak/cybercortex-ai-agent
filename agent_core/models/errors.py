"""Deterministic, credential-safe provider error vocabulary."""

from __future__ import annotations

from enum import Enum

from agent_core.result_normalizer import sanitize_text


class ModelErrorCode(str, Enum):
    provider_unavailable = "provider_unavailable"
    authentication_failed = "authentication_failed"
    timeout = "timeout"
    rate_limited = "rate_limited"
    connection_failed = "connection_failed"
    invalid_response = "invalid_response"
    configuration_error = "configuration_error"
    routing_exhausted = "routing_exhausted"
    routing_policy_blocked = "routing_policy_blocked"
    model_budget_exceeded = "model_budget_exceeded"
    unknown_cost = "unknown_cost"


PUBLIC_ERROR_MESSAGES = {
    ModelErrorCode.provider_unavailable: "The selected model provider is unavailable.",
    ModelErrorCode.authentication_failed: (
        "The model provider rejected its configured credentials."
    ),
    ModelErrorCode.timeout: "The model provider request timed out.",
    ModelErrorCode.rate_limited: "The model provider rate limit was reached.",
    ModelErrorCode.connection_failed: "The model provider could not be reached.",
    ModelErrorCode.invalid_response: (
        "The model provider returned an invalid normalized response."
    ),
    ModelErrorCode.configuration_error: (
        "The model provider configuration is invalid."
    ),
    ModelErrorCode.routing_exhausted: (
        "The configured model routing attempts were exhausted."
    ),
    ModelErrorCode.routing_policy_blocked: (
        "The model routing policy blocked the requested provider."
    ),
    ModelErrorCode.model_budget_exceeded: (
        "The model usage budget does not permit another provider call."
    ),
    ModelErrorCode.unknown_cost: (
        "The model price is unknown under a strict monetary budget."
    ),
}


class ModelProviderError(RuntimeError):
    """A public-safe error that deliberately omits raw provider exceptions."""

    def __init__(
        self,
        code: ModelErrorCode,
        *,
        provider: str | None = None,
        model: str | None = None,
        partial_input_tokens: int | None = None,
        partial_output_tokens: int | None = None,
        partial_estimated_cost_usd: float | None = None,
    ) -> None:
        if (partial_input_tokens is None) != (partial_output_tokens is None):
            raise ValueError("partial provider usage requires both token counts")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (partial_input_tokens, partial_output_tokens)
            if value is not None
        ):
            raise ValueError("partial provider token usage must be nonnegative")
        if partial_estimated_cost_usd is not None and (
            not isinstance(partial_estimated_cost_usd, float)
            or partial_estimated_cost_usd < 0.0
        ):
            raise ValueError("partial provider cost must be a nonnegative float")
        self.code = code
        self.provider = sanitize_text(provider or "") or None
        self.model = sanitize_text(model or "") or None
        self.partial_input_tokens = partial_input_tokens
        self.partial_output_tokens = partial_output_tokens
        self.partial_estimated_cost_usd = partial_estimated_cost_usd
        self.public_message = PUBLIC_ERROR_MESSAGES[code]
        super().__init__(self.public_message)

    def public_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code.value,
            "message": self.public_message,
            "provider": self.provider,
            "model": self.model,
        }


class UnknownProviderError(ModelProviderError):
    def __init__(self, provider: str) -> None:
        super().__init__(ModelErrorCode.configuration_error, provider=provider)


class InvalidProviderResponseError(ModelProviderError):
    def __init__(self, *, provider: str, model: str) -> None:
        super().__init__(
            ModelErrorCode.invalid_response,
            provider=provider,
            model=model,
        )


class ModelRoutingError(ModelProviderError):
    """Deterministic router failure with only normalized attempt outcomes."""

    def __init__(
        self,
        code: ModelErrorCode,
        *,
        provider: str | None = None,
        model: str | None = None,
        prior_outcomes: tuple[dict[str, str | int], ...] = (),
    ) -> None:
        super().__init__(code, provider=provider, model=model)
        self.prior_outcomes = prior_outcomes

    def public_dict(self) -> dict[str, object]:
        return {
            **super().public_dict(),
            "prior_outcomes": list(self.prior_outcomes),
        }
