"""Anthropic adapter with lazy SDK loading and immediate normalization."""

from __future__ import annotations

import importlib
from typing import Any

from agent_core.models.base import ModelProvider, ProviderAvailability
from agent_core.models.config import ProviderConfiguration
from agent_core.models.errors import (
    InvalidProviderResponseError,
    ModelErrorCode,
    ModelProviderError,
)
from agent_core.models.pricing import ModelPricingCatalog
from agent_core.models.telemetry import ModelTelemetryRecorder
from agent_core.models.types import (
    ModelRequest,
    ModelResponse,
    sanitize_boundary_text,
)


class AnthropicProvider(ModelProvider):
    provider_name = "anthropic"

    def __init__(
        self,
        configuration: ProviderConfiguration,
        *,
        pricing: ModelPricingCatalog | None = None,
        telemetry: ModelTelemetryRecorder | None = None,
        client: Any = None,
    ) -> None:
        super().__init__(configuration, pricing=pricing, telemetry=telemetry)
        self._client = client
        self._api_key = (
            configuration.api_key.get_secret_value()
            if configuration.api_key is not None
            else ""
        )
        if not self._api_key:
            self._set_unavailable(
                ModelErrorCode.provider_unavailable,
                "Anthropic is unavailable because ANTHROPIC_API_KEY is not configured.",
            )
        elif not self.model_name:
            self._set_unavailable(
                ModelErrorCode.configuration_error,
                "Anthropic is unavailable because P3_ANTHROPIC_MODEL is not configured.",
            )
        elif self._client is None:
            try:
                sdk = importlib.import_module("anthropic")
                kwargs: dict[str, Any] = {
                    "api_key": self._api_key,
                    "timeout": configuration.timeout_seconds,
                }
                if configuration.base_url:
                    kwargs["base_url"] = configuration.base_url
                self._client = sdk.Anthropic(**kwargs)
            except (ImportError, ModuleNotFoundError):
                self._set_unavailable(
                    ModelErrorCode.provider_unavailable,
                    "Anthropic is unavailable because its optional SDK is not installed.",
                )
            except Exception:
                self._set_unavailable(
                    ModelErrorCode.provider_unavailable,
                    "Anthropic is unavailable because its SDK could not be initialized.",
                )

    def _set_unavailable(self, code: ModelErrorCode, message: str) -> None:
        self._availability = ProviderAvailability(
            provider=self.provider_name,
            model=self.model_name or None,
            available=False,
            reason_code=code,
            message=message,
        )

    def _generate(self, request: ModelRequest) -> ModelResponse:
        kwargs: dict[str, Any] = {
            "model": self.model_name,
            "system": request.system_instructions,
            "messages": [{"role": "user", "content": self.user_prompt(request)}],
            "max_tokens": min(
                request.max_output_tokens, self.configuration.max_output_tokens
            ),
            "timeout": self.configuration.timeout_seconds,
        }
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        response = self._client.messages.create(**kwargs)
        blocks = self.read_value(response, "content")
        if not isinstance(blocks, (list, tuple)):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        text_blocks: list[str] = []
        for block in blocks:
            if self.read_value(block, "type") == "text":
                block_text = self.read_value(block, "text")
                if isinstance(block_text, str) and block_text:
                    text_blocks.append(block_text)
        if not text_blocks:
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        usage = self.read_value(response, "usage", {})
        input_tokens = self.token_count(usage, "input_tokens")
        output_tokens = self.token_count(usage, "output_tokens")
        content = "\n".join(text_blocks)
        return ModelResponse(
            provider=self.provider_name,
            model=self.model_name,
            content=sanitize_boundary_text(content, secrets=(self._api_key,)),
            finish_reason=self.read_value(response, "stop_reason"),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=self.estimate_cost(input_tokens, output_tokens),
            latency_seconds=0.0,
            provider_call_id=sanitize_boundary_text(
                self.read_value(response, "id"), secrets=(self._api_key,)
            )
            or None,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
            fallback_used=False,
            metadata={},
        )

    def _normalize_exception(self, exc: BaseException) -> ModelProviderError:
        name = type(exc).__name__.casefold()
        status = getattr(exc, "status_code", None)
        if "authentication" in name or status in {401, 403}:
            code = ModelErrorCode.authentication_failed
        elif "ratelimit" in name or "rate_limit" in name or status == 429:
            code = ModelErrorCode.rate_limited
        elif "timeout" in name or isinstance(exc, TimeoutError):
            code = ModelErrorCode.timeout
        elif "connection" in name:
            code = ModelErrorCode.connection_failed
        else:
            code = ModelErrorCode.invalid_response
        return ModelProviderError(
            code,
            provider=self.provider_name,
            model=self.model_name,
        )
