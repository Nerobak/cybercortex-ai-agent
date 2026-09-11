"""Strict provider-neutral model request and response contracts."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_serializer,
    field_validator,
    model_validator,
)

from agent_core.models.errors import ModelErrorCode
from agent_core.result_normalizer import (
    MAX_EVIDENCE_BYTES,
    public_result,
    sanitize_document_text,
    sanitize_text,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
MAX_STRUCTURED_OUTPUT_SCHEMA_BYTES = 64_000


class _FrozenJsonObject(dict[str, Any]):
    """JSON object that cannot be changed after request validation."""

    @staticmethod
    def _immutable(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError("structured output schema is immutable")

    __delitem__ = _immutable
    __ior__ = _immutable
    __setitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable


class _FrozenJsonArray(list[Any]):
    """JSON array that cannot be changed after request validation."""

    @staticmethod
    def _immutable(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise TypeError("structured output schema is immutable")

    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    __setitem__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        frozen = _FrozenJsonObject()
        dict.update(frozen, {key: _freeze_json(item) for key, item in value.items()})
        return frozen
    if isinstance(value, list):
        frozen = _FrozenJsonArray()
        list.extend(frozen, (_freeze_json(item) for item in value))
        return frozen
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_structured_output_schema(value: Any) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("structured_output_schema must be a JSON schema object")
    safe = public_result(value)
    if safe != value:
        raise ValueError("structured_output_schema must contain only public-safe data")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("structured_output_schema must be strict JSON data") from exc
    if len(encoded.encode("utf-8")) > MAX_STRUCTURED_OUTPUT_SCHEMA_BYTES:
        raise ValueError("structured_output_schema exceeds its size limit")
    canonical = json.loads(encoded)
    return _freeze_json(canonical)


class ModelContract(BaseModel):
    """Base contract that rejects coercion, mutation, and unknown fields."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
    )


def _require_safe_text(value: str, field_name: str) -> str:
    safe = sanitize_document_text(value)
    if safe != value:
        raise ValueError(f"{field_name} must contain only public-safe text")
    return value


def _require_public_result(value: Any, field_name: str) -> Any:
    safe = public_result(value)
    if safe != value:
        raise ValueError(
            f"{field_name} must already satisfy the Phase 2 public_result boundary"
        )
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON-compatible") from exc
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise ValueError(f"{field_name} exceeds the public evidence size limit")
    return value


def sanitize_boundary_text(value: Any, *, secrets: tuple[str, ...] = ()) -> str:
    """Sanitize provider output while explicitly removing configured secrets."""

    text = sanitize_document_text(str(value or ""))
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def sanitize_boundary_metadata(value: Any) -> dict[str, JsonValue]:
    """Return only canonical public-safe provider metadata."""

    safe = public_result(value if isinstance(value, dict) else {})
    return safe if isinstance(safe, dict) else {}


class ModelAttemptOutcome(ModelContract):
    """Public-safe reliability outcome for one prior routing attempt."""

    attempt_index: StrictInt = Field(ge=0)
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    outcome: ModelErrorCode


class ModelRequest(ModelContract):
    """One advisory model request with no executable callback or tool field."""

    system_instructions: StrictStr = Field(min_length=1, max_length=50_000)
    user_content: StrictStr = Field(min_length=1, max_length=200_000)
    evidence: dict[str, JsonValue] | list[JsonValue] = Field(default_factory=dict)
    structured_output: StrictBool = False
    structured_output_schema: dict[str, JsonValue] | None = None
    temperature: StrictFloat | None = Field(default=None, ge=0.0, le=2.0)
    max_output_tokens: StrictInt = Field(default=4096, ge=1, le=1_000_000)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    hypothesis_id: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("system_instructions", "user_content")
    @classmethod
    def reject_private_prompt_text(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, info.field_name)

    @field_validator("task_type", "run_id", "hypothesis_id")
    @classmethod
    def validate_identifiers(cls, value: str | None, info: Any) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"{info.field_name} has an invalid format")
        return value

    @field_validator("evidence", "metadata", mode="before")
    @classmethod
    def require_phase2_public_boundary(cls, value: Any, info: Any) -> Any:
        return _require_public_result(value, info.field_name)

    @field_validator("structured_output_schema")
    @classmethod
    def validate_structured_output_schema(
        cls, value: Any
    ) -> dict[str, JsonValue] | None:
        if value is None:
            return None
        return _canonical_structured_output_schema(value)

    @field_serializer("structured_output_schema")
    def serialize_structured_output_schema(
        self, value: dict[str, JsonValue] | None
    ) -> dict[str, JsonValue] | None:
        return _thaw_json(value)

    @model_validator(mode="after")
    def require_structured_output_for_schema(self) -> "ModelRequest":
        if self.structured_output_schema is not None and not self.structured_output:
            raise ValueError(
                "structured_output_schema requires structured_output to be enabled"
            )
        return self

    @classmethod
    def from_phase2(
        cls,
        *,
        system_instructions: str,
        user_content: str,
        evidence: Any,
        task_type: str,
        run_id: str | None = None,
        hypothesis_id: str | None = None,
        metadata: Any = None,
        structured_output: bool = False,
        structured_output_schema: dict[str, JsonValue] | None = None,
        temperature: float | None = None,
        max_output_tokens: int = 4096,
    ) -> "ModelRequest":
        """Admit evidence only after the canonical Phase 2 public serializer."""

        safe_evidence = public_result(evidence)
        if not isinstance(safe_evidence, (dict, list)):
            raise ValueError("Phase 2 evidence must normalize to an object or list")
        safe_metadata = public_result(metadata or {})
        if not isinstance(safe_metadata, dict):
            safe_metadata = {}
        return cls(
            system_instructions=system_instructions,
            user_content=user_content,
            evidence=safe_evidence,
            structured_output=structured_output,
            structured_output_schema=structured_output_schema,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            task_type=task_type,
            run_id=run_id,
            hypothesis_id=hypothesis_id,
            metadata=safe_metadata,
        )


class ModelResponse(ModelContract):
    """Normalized response; provider SDK objects never cross this contract."""

    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    content: StrictStr = Field(
        validation_alias=AliasChoices("content", "text"),
        min_length=1,
        max_length=1_000_000,
    )
    finish_reason: StrictStr | None = Field(default=None, max_length=100)
    input_tokens: StrictInt = Field(default=0, ge=0)
    output_tokens: StrictInt = Field(default=0, ge=0)
    total_tokens: StrictInt = Field(default=0, ge=0)
    estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    latency_seconds: StrictFloat = Field(ge=0.0)
    provider_call_id: StrictStr | None = Field(default=None, max_length=255)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr | None = Field(default=None, max_length=255)
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    fallback_used: StrictBool = False
    fallback_provider: StrictStr | None = Field(default=None, max_length=100)
    fallback_model: StrictStr | None = Field(default=None, max_length=255)
    fallback_reason: StrictStr | None = Field(default=None, max_length=255)
    requested_provider: StrictStr | None = Field(default=None, max_length=100)
    requested_model: StrictStr | None = Field(default=None, max_length=255)
    fallback_depth: StrictInt = Field(default=0, ge=0)
    model_calls_attempted: StrictInt = Field(default=1, ge=1)
    prior_attempt_outcomes: tuple[ModelAttemptOutcome, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, value: Any) -> str:
        return sanitize_boundary_text(value)

    @field_validator(
        "provider",
        "model",
        "finish_reason",
        "provider_call_id",
        "task_type",
        "run_id",
        "hypothesis_id",
        "fallback_provider",
        "fallback_model",
        "fallback_reason",
        "requested_provider",
        "requested_model",
        mode="before",
    )
    @classmethod
    def sanitize_string_fields(cls, value: Any) -> Any:
        return sanitize_text(value) if isinstance(value, str) else value

    @field_validator("metadata", mode="before")
    @classmethod
    def sanitize_metadata(cls, value: Any) -> dict[str, JsonValue]:
        return sanitize_boundary_metadata(value)

    @model_validator(mode="after")
    def validate_accounting(self) -> "ModelResponse":
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        if not self.fallback_used and any(
            value is not None
            for value in (
                self.fallback_provider,
                self.fallback_model,
                self.fallback_reason,
            )
        ):
            raise ValueError("fallback details require fallback_used=true")
        if self.fallback_used != (self.fallback_depth > 0):
            raise ValueError("fallback_used must match fallback_depth")
        if self.fallback_depth != len(self.prior_attempt_outcomes):
            raise ValueError("fallback_depth must match prior attempt outcomes")
        if self.model_calls_attempted != len(self.prior_attempt_outcomes) + 1:
            raise ValueError(
                "model_calls_attempted must include prior attempts and success"
            )
        if (self.requested_provider is None) != (self.requested_model is None):
            raise ValueError("requested provider and model must be recorded together")
        if self.fallback_used and self.requested_provider is None:
            raise ValueError("fallback responses require the requested route")
        return self

    @property
    def text(self) -> str:
        """Compatibility spelling for callers that prefer ``text``."""

        return self.content
