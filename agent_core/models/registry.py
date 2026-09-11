"""Deterministic provider construction without model-routing policy."""

from __future__ import annotations

from typing import Any

from agent_core.models.anthropic_provider import AnthropicProvider
from agent_core.models.base import ModelProvider, ProviderAvailability
from agent_core.models.config import ModelConfiguration, ProviderConfiguration
from agent_core.models.errors import UnknownProviderError
from agent_core.models.ollama_provider import OllamaProvider
from agent_core.models.openai_provider import OpenAIProvider
from agent_core.models.pricing import ModelPricingCatalog, normalize_provider_alias
from agent_core.models.telemetry import ModelTelemetryRecorder

_PROVIDER_TYPES: dict[str, type[ModelProvider]] = {
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
}


class ProviderRegistry:
    """Lookup, validate, and build only the known P3-1 adapters."""

    def __init__(
        self,
        configuration: ModelConfiguration | None = None,
        *,
        pricing: ModelPricingCatalog | None = None,
        telemetry: ModelTelemetryRecorder | None = None,
    ) -> None:
        self.configuration = configuration or ModelConfiguration.from_env()
        self.pricing = pricing or ModelPricingCatalog(self.configuration.pricing)
        self.telemetry = telemetry or ModelTelemetryRecorder()

    @property
    def supported_providers(self) -> tuple[str, ...]:
        return tuple(sorted(_PROVIDER_TYPES))

    def validate_provider(self, provider: str) -> str:
        normalized = normalize_provider_alias(provider)
        if normalized not in _PROVIDER_TYPES:
            raise UnknownProviderError(provider)
        return normalized

    def create(
        self,
        provider: str | None = None,
        *,
        model_name: str | None = None,
        client: Any = None,
    ) -> ModelProvider:
        normalized = self.validate_provider(
            provider or self.configuration.default_provider
        )
        configured = self.configuration.provider_configuration(normalized)
        requested_model = model_name or configured.model_name
        if requested_model:
            _, requested_model = self.pricing.resolve_model(normalized, requested_model)
        provider_configuration = ProviderConfiguration(
            model_name=requested_model,
            timeout_seconds=configured.timeout_seconds,
            max_output_tokens=configured.max_output_tokens,
            base_url=configured.base_url,
            api_key=configured.api_key,
        )
        return _PROVIDER_TYPES[normalized](
            provider_configuration,
            pricing=self.pricing,
            telemetry=self.telemetry,
            client=client,
        )

    def get(
        self,
        provider: str | None = None,
        *,
        model_name: str | None = None,
        client: Any = None,
    ) -> ModelProvider:
        """Provider-lookup spelling for callers that do not construct directly."""

        return self.create(provider, model_name=model_name, client=client)

    def availability(
        self,
        provider: str,
        *,
        model_name: str | None = None,
        client: Any = None,
    ) -> ProviderAvailability:
        return self.create(provider, model_name=model_name, client=client).availability
