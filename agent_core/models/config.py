"""Central Phase 3 model-provider configuration."""

from __future__ import annotations

import os
from typing import Mapping
from urllib.parse import urlsplit

from pydantic import (
    Field,
    SecretStr,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
)

from agent_core.models.pricing import ModelPrice, normalize_provider_alias
from agent_core.models.types import ModelContract


class ProviderConfiguration(ModelContract):
    model_name: StrictStr | None = Field(default=None, max_length=255)
    timeout_seconds: StrictFloat = Field(default=60.0, gt=0.0, le=3600.0)
    max_output_tokens: StrictInt = Field(default=4096, ge=1, le=1_000_000)
    base_url: StrictStr | None = Field(default=None, max_length=2048)
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)

    @field_validator("model_name")
    @classmethod
    def normalize_model(cls, value: str | None) -> str | None:
        normalized = value.strip() if value else None
        return normalized or None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("base_url must be an HTTP(S) origin without credentials")
        return value.rstrip("/")


class ModelConfiguration(ModelContract):
    """Defaults and provider settings without routing intelligence."""

    default_provider: StrictStr = "ollama"
    openai: ProviderConfiguration = Field(default_factory=ProviderConfiguration)
    anthropic: ProviderConfiguration = Field(default_factory=ProviderConfiguration)
    ollama: ProviderConfiguration = Field(
        default_factory=lambda: ProviderConfiguration(
            model_name="deepseek-r1:32b",
            base_url="http://127.0.0.1:11434",
        )
    )
    pricing: tuple[ModelPrice, ...] = ()

    @field_validator("default_provider")
    @classmethod
    def normalize_default_provider(cls, value: str) -> str:
        return normalize_provider_alias(value)

    @property
    def default_models(self) -> Mapping[str, str | None]:
        return {
            "openai": self.openai.model_name,
            "anthropic": self.anthropic.model_name,
            "ollama": self.ollama.model_name,
        }

    def provider_configuration(self, provider: str) -> ProviderConfiguration:
        normalized = normalize_provider_alias(provider)
        if normalized not in {"openai", "anthropic", "ollama"}:
            raise ValueError("Unknown model provider")
        return getattr(self, normalized)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "ModelConfiguration":
        """Read standard keys without loading or persisting a dotenv file."""

        env = os.environ if environ is None else environ

        def positive_float(name: str, default: float) -> float:
            raw = env.get(name)
            if raw is None or not raw.strip():
                return default
            value = float(raw)
            if value <= 0:
                raise ValueError(f"{name} must be positive")
            return value

        def positive_int(name: str, default: int) -> int:
            raw = env.get(name)
            if raw is None or not raw.strip():
                return default
            value = int(raw)
            if value <= 0:
                raise ValueError(f"{name} must be positive")
            return value

        timeout = positive_float("MODEL_TIMEOUT_SECONDS", 60.0)
        max_tokens = positive_int("MODEL_MAX_OUTPUT_TOKENS", 4096)
        legacy_local_model = env.get("OPENAI_MODEL")
        return cls(
            default_provider=env.get("MODEL_DEFAULT_PROVIDER", "ollama"),
            openai=ProviderConfiguration(
                model_name=env.get("P3_OPENAI_MODEL") or None,
                timeout_seconds=timeout,
                max_output_tokens=max_tokens,
                base_url=env.get("P3_OPENAI_BASE_URL") or None,
                api_key=env.get("OPENAI_API_KEY") or None,
            ),
            anthropic=ProviderConfiguration(
                model_name=env.get("P3_ANTHROPIC_MODEL") or None,
                timeout_seconds=timeout,
                max_output_tokens=max_tokens,
                base_url=env.get("P3_ANTHROPIC_BASE_URL") or None,
                api_key=env.get("ANTHROPIC_API_KEY") or None,
            ),
            ollama=ProviderConfiguration(
                model_name=(
                    env.get("P3_OLLAMA_MODEL")
                    or legacy_local_model
                    or "deepseek-r1:32b"
                ),
                timeout_seconds=timeout,
                max_output_tokens=max_tokens,
                base_url=env.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434",
            ),
        )
