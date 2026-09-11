"""Configured Ollama adapter for DeepSeek and other present or future models."""

from __future__ import annotations

from typing import Any

import httpx

from agent_core.models.base import ModelProvider, ProviderAvailability
from agent_core.models.config import ProviderConfiguration
from agent_core.models.errors import (
    InvalidProviderResponseError,
    ModelErrorCode,
    ModelProviderError,
)
from agent_core.models.pricing import ModelPricingCatalog
from agent_core.models.telemetry import ModelTelemetryRecorder
from agent_core.models.types import ModelRequest, ModelResponse, sanitize_boundary_text


class OllamaProvider(ModelProvider):
    provider_name = "ollama"
    supports_structured_output = True

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
        if not self.model_name:
            self._availability = ProviderAvailability(
                provider=self.provider_name,
                model=None,
                available=False,
                reason_code=ModelErrorCode.configuration_error,
                message="Ollama is unavailable because P3_OLLAMA_MODEL is not configured.",
            )
        elif not configuration.base_url:
            self._availability = ProviderAvailability(
                provider=self.provider_name,
                model=self.model_name,
                available=False,
                reason_code=ModelErrorCode.configuration_error,
                message="Ollama is unavailable because OLLAMA_BASE_URL is not configured.",
            )

    def _generate(self, request: ModelRequest) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": request.system_instructions},
                {"role": "user", "content": self.user_prompt(request)},
            ],
            "stream": False,
            "options": {
                "num_predict": min(
                    request.max_output_tokens, self.configuration.max_output_tokens
                )
            },
        }
        if request.temperature is not None:
            payload["options"]["temperature"] = request.temperature
        if request.structured_output:
            payload["format"] = (
                request.model_dump(mode="json", include={"structured_output_schema"})[
                    "structured_output_schema"
                ]
                if request.structured_output_schema is not None
                else "json"
            )
        url = f"{self.configuration.base_url}/api/chat"
        if self._client is None:
            response = httpx.post(
                url,
                json=payload,
                timeout=self.configuration.timeout_seconds,
            )
        else:
            response = self._client.post(
                url,
                json=payload,
                timeout=self.configuration.timeout_seconds,
            )
        raise_for_status = getattr(response, "raise_for_status", None)
        if callable(raise_for_status):
            raise_for_status()
        try:
            raw = response.json()
        except (TypeError, ValueError):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            ) from None
        if not isinstance(raw, dict):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        message = raw.get("message")
        content = self.read_value(message, "content")
        if content is None:
            content = raw.get("response")
        if not isinstance(content, str) or not content.strip():
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        input_tokens = self.token_count(raw, "prompt_eval_count")
        output_tokens = self.token_count(raw, "eval_count")
        return ModelResponse(
            provider=self.provider_name,
            model=self.model_name,
            content=sanitize_boundary_text(content),
            finish_reason=raw.get("done_reason")
            or ("stop" if raw.get("done") else None),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=0.0,
            latency_seconds=0.0,
            provider_call_id=None,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
            fallback_used=False,
            metadata={},
        )

    def _normalize_exception(self, exc: BaseException) -> ModelProviderError:
        if isinstance(exc, httpx.TimeoutException) or isinstance(exc, TimeoutError):
            code = ModelErrorCode.timeout
        elif isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            code = (
                ModelErrorCode.rate_limited
                if status == 429
                else ModelErrorCode.connection_failed
            )
        elif isinstance(exc, (httpx.ConnectError, httpx.NetworkError)):
            code = ModelErrorCode.connection_failed
        else:
            name = type(exc).__name__.casefold()
            if "timeout" in name:
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
