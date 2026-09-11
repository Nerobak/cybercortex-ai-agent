"""Model-call telemetry kept separate from target network request accounting."""

from __future__ import annotations

from threading import RLock
from typing import Literal

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from agent_core.models.errors import ModelErrorCode
from agent_core.models.types import ModelContract, ModelResponse


class ModelCallTelemetry(ModelContract):
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    input_tokens: StrictInt | None = Field(default=None, ge=0)
    output_tokens: StrictInt | None = Field(default=None, ge=0)
    total_tokens: StrictInt | None = Field(default=None, ge=0)
    usage_known: StrictBool
    estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    latency_seconds: StrictFloat = Field(ge=0.0)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr | None = Field(default=None, max_length=255)
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    success: StrictBool
    fallback_used: StrictBool = False
    error_code: ModelErrorCode | None = None
    attempt_state: Literal[
        "blocked_before_provider_call",
        "provider_call_succeeded",
        "provider_call_failed_after_start",
    ]

    @model_validator(mode="after")
    def validate_accounting(self) -> "ModelCallTelemetry":
        actual = (self.input_tokens, self.output_tokens, self.total_tokens)
        if self.usage_known:
            if any(value is None for value in actual):
                raise ValueError("known telemetry usage requires exact token counts")
            if self.total_tokens != self.input_tokens + self.output_tokens:
                raise ValueError(
                    "total_tokens must equal input_tokens plus output_tokens"
                )
        elif any(value is not None for value in actual):
            raise ValueError("unknown telemetry usage cannot contain token counts")
        if self.success and self.error_code is not None:
            raise ValueError("successful model calls cannot have an error_code")
        if not self.success and self.error_code is None:
            raise ValueError("failed model calls require an error_code")
        if self.success != (self.attempt_state == "provider_call_succeeded"):
            raise ValueError("telemetry success must match its attempt state")
        if self.attempt_state == "blocked_before_provider_call" and actual != (0, 0, 0):
            raise ValueError("pre-call telemetry must have exact zero usage")
        return self

    @classmethod
    def from_response(cls, response: ModelResponse) -> "ModelCallTelemetry":
        return cls(
            provider=response.provider,
            model=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            total_tokens=response.total_tokens,
            usage_known=True,
            estimated_cost_usd=response.estimated_cost_usd,
            latency_seconds=response.latency_seconds,
            task_type=response.task_type,
            run_id=response.run_id,
            hypothesis_id=response.hypothesis_id,
            success=True,
            fallback_used=response.fallback_used,
            attempt_state="provider_call_succeeded",
        )


class ModelTelemetryRecorder:
    """In-memory normalized event sink with no prompt, response, or secret fields."""

    def __init__(self) -> None:
        self._events: list[ModelCallTelemetry] = []
        self._lock = RLock()

    def record(self, event: ModelCallTelemetry) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> tuple[ModelCallTelemetry, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def last_event(self) -> ModelCallTelemetry | None:
        with self._lock:
            return self._events[-1] if self._events else None
