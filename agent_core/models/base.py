"""Provider-independent model adapter interface and call lifecycle."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any

from pydantic import Field, StrictBool, StrictStr

from agent_core.models.config import ProviderConfiguration
from agent_core.models.errors import ModelErrorCode, ModelProviderError
from agent_core.models.pricing import ModelPricingCatalog
from agent_core.models.telemetry import ModelCallTelemetry, ModelTelemetryRecorder
from agent_core.models.types import ModelContract, ModelRequest, ModelResponse


class ProviderAvailability(ModelContract):
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr | None = Field(default=None, max_length=255)
    available: StrictBool
    reason_code: ModelErrorCode | None = None
    message: StrictStr


class ModelProvider(ABC):
    """One normalized advisory model provider with no execution capability."""

    provider_name: str
    supports_structured_output = False

    def __init__(
        self,
        configuration: ProviderConfiguration,
        *,
        pricing: ModelPricingCatalog | None = None,
        telemetry: ModelTelemetryRecorder | None = None,
    ) -> None:
        self.configuration = configuration
        self.model_name = configuration.model_name or ""
        self._pricing = pricing or ModelPricingCatalog()
        self._telemetry = telemetry or ModelTelemetryRecorder()
        self._availability = ProviderAvailability(
            provider=self.provider_name,
            model=self.model_name or None,
            available=True,
            message="Provider configuration is available.",
        )

    @property
    def availability(self) -> ProviderAvailability:
        return self._availability

    @property
    def telemetry(self) -> tuple[ModelCallTelemetry, ...]:
        return self._telemetry.events

    def generate(self, request: ModelRequest) -> ModelResponse:
        """Execute one model API call and always record normalized telemetry."""

        if not self.availability.available:
            error = ModelProviderError(
                self.availability.reason_code or ModelErrorCode.provider_unavailable,
                provider=self.provider_name,
                model=self.model_name or None,
            )
            self._record_failure(
                request,
                time.monotonic(),
                error,
                provider_call_started=False,
            )
            raise error from None
        if request.structured_output and not self.supports_structured_output:
            error = ModelProviderError(
                ModelErrorCode.provider_unavailable,
                provider=self.provider_name,
                model=self.model_name or None,
            )
            self._record_failure(
                request,
                time.monotonic(),
                error,
                provider_call_started=False,
            )
            raise error from None

        started = time.monotonic()
        pending_error: ModelProviderError
        try:
            response = self._generate(request)
            if not isinstance(response, ModelResponse):
                raise ModelProviderError(
                    ModelErrorCode.invalid_response,
                    provider=self.provider_name,
                    model=self.model_name,
                )
            normalized = ModelResponse.model_validate(
                {
                    **response.model_dump(mode="python"),
                    "latency_seconds": float(time.monotonic() - started),
                }
            )
            if (
                normalized.provider != self.provider_name
                or normalized.model != self.model_name
            ):
                raise ModelProviderError(
                    ModelErrorCode.invalid_response,
                    provider=self.provider_name,
                    model=self.model_name,
                )
            self._telemetry.record(ModelCallTelemetry.from_response(normalized))
            return normalized
        except ModelProviderError as exc:
            self._record_failure(request, started, exc, provider_call_started=True)
            pending_error = exc
        except Exception as exc:
            pending_error = self._normalize_exception(exc)
            self._record_failure(
                request,
                started,
                pending_error,
                provider_call_started=True,
            )
        pending_error.__traceback__ = None
        pending_error.__cause__ = None
        pending_error.__context__ = None
        raise pending_error from None

    def _record_failure(
        self,
        request: ModelRequest,
        started: float,
        error: ModelProviderError,
        *,
        provider_call_started: bool,
    ) -> None:
        usage_known = not provider_call_started or (
            error.partial_input_tokens is not None
            and error.partial_output_tokens is not None
        )
        input_tokens = error.partial_input_tokens if provider_call_started else 0
        output_tokens = error.partial_output_tokens if provider_call_started else 0
        total_tokens = (
            input_tokens + output_tokens
            if input_tokens is not None and output_tokens is not None
            else None
        )
        self._telemetry.record(
            ModelCallTelemetry(
                provider=self.provider_name,
                model=self.model_name or "unconfigured",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                usage_known=usage_known,
                estimated_cost_usd=(
                    error.partial_estimated_cost_usd if provider_call_started else 0.0
                ),
                latency_seconds=float(time.monotonic() - started),
                task_type=request.task_type,
                run_id=request.run_id,
                hypothesis_id=request.hypothesis_id,
                success=False,
                fallback_used=False,
                error_code=error.code,
                attempt_state=(
                    "provider_call_failed_after_start"
                    if provider_call_started
                    else "blocked_before_provider_call"
                ),
            )
        )

    def _normalize_exception(self, exc: BaseException) -> ModelProviderError:
        del exc
        return ModelProviderError(
            ModelErrorCode.invalid_response,
            provider=self.provider_name,
            model=self.model_name,
        )

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float | None:
        return self._pricing.estimate_cost(
            self.provider_name,
            self.model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    @staticmethod
    def user_prompt(request: ModelRequest) -> str:
        if not request.evidence:
            return request.user_content
        evidence = json.dumps(
            request.evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return f"{request.user_content}\n\nSanitized evidence (JSON):\n{evidence}"

    @staticmethod
    def read_value(value: Any, field: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            return value.get(field, default)
        return getattr(value, field, default)

    @staticmethod
    def token_count(value: Any, field: str) -> int:
        count = ModelProvider.read_value(value, field, 0)
        if count is None:
            return 0
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("Provider token usage is malformed")
        return count

    @abstractmethod
    def _generate(self, request: ModelRequest) -> ModelResponse:
        """Convert a provider response immediately into ``ModelResponse``."""
