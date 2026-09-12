"""Centralized, deterministic model alias and pricing data."""

from __future__ import annotations

import re
from decimal import Decimal
from itertools import chain
from typing import Any, Mapping

from pydantic import Field, StrictFloat, StrictStr

from agent_core.models.types import ModelContract

_TOKEN_PRICE_UNIT = Decimal("1000000")
_DATED_MODEL_SNAPSHOT = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ModelPrice(ModelContract):
    """USD prices per one million tokens for one canonical model."""

    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    input_per_million_usd: StrictFloat = Field(ge=0.0)
    output_per_million_usd: StrictFloat = Field(ge=0.0)


_STANDARD_API_PRICES = (
    ModelPrice(
        provider="anthropic",
        model="claude-sonnet-4-6",
        input_per_million_usd=3.0,
        output_per_million_usd=15.0,
    ),
    ModelPrice(
        provider="openai",
        model="gpt-5.5-pro",
        input_per_million_usd=30.0,
        output_per_million_usd=180.0,
    ),
)
_STANDARD_MODEL_ALIASES = {
    ("openai", "gpt-5.5-pro-2026-04-23"): "gpt-5.5-pro",
}


def normalize_provider_alias(provider: str) -> str:
    normalized = str(provider).strip().casefold().replace("_", "-")
    aliases = {
        "anthropic": "anthropic",
        "claude": "anthropic",
        "local": "ollama",
        "ollama": "ollama",
        "open-ai": "openai",
        "openai": "openai",
    }
    return aliases.get(normalized, normalized)


def model_response_matches_route(
    provider: str, requested_model: str, returned_model: str
) -> bool:
    """Match an exact route or OpenAI's dated realization of an alias."""

    if returned_model == requested_model:
        return True
    if normalize_provider_alias(provider) != "openai":
        return False
    prefix = f"{requested_model}-"
    if not returned_model.startswith(prefix):
        return False
    return _DATED_MODEL_SNAPSHOT.fullmatch(returned_model[len(prefix) :]) is not None


class ModelPricingCatalog:
    """Standard and configured prices; absent cloud prices remain unknown."""

    def __init__(
        self,
        prices: tuple[ModelPrice, ...] = (),
        *,
        model_aliases: Mapping[tuple[str, str], str] | None = None,
    ) -> None:
        self._prices: dict[tuple[str, str], ModelPrice] = {}
        for price in (*_STANDARD_API_PRICES, *prices):
            key = (
                normalize_provider_alias(price.provider),
                price.model.strip().casefold(),
            )
            if key in self._prices:
                raise ValueError("Duplicate provider/model pricing entry")
            self._prices[key] = price

        self._aliases: dict[tuple[str, str], str] = {}
        for (provider, alias), canonical in chain(
            _STANDARD_MODEL_ALIASES.items(), (model_aliases or {}).items()
        ):
            key = (
                normalize_provider_alias(provider),
                str(alias).strip().casefold(),
            )
            if key in self._aliases and self._aliases[key] != canonical:
                raise ValueError("Conflicting provider/model alias")
            self._aliases[key] = str(canonical).strip()

    def resolve_model(self, provider: str, model: str) -> tuple[str, str]:
        canonical_provider = normalize_provider_alias(provider)
        requested_model = str(model).strip()
        canonical_model = self._aliases.get(
            (canonical_provider, requested_model.casefold()), requested_model
        )
        return canonical_provider, canonical_model

    def estimate_cost(
        self,
        provider: str,
        model: str,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> float | None:
        canonical_provider, canonical_model = self.resolve_model(provider, model)
        if canonical_provider == "ollama":
            return 0.0
        price = self._prices.get(
            (canonical_provider, canonical_model.strip().casefold())
        )
        if price is None:
            return None
        cost = (
            Decimal(input_tokens) * Decimal(str(price.input_per_million_usd))
            + Decimal(output_tokens) * Decimal(str(price.output_per_million_usd))
        ) / _TOKEN_PRICE_UNIT
        return float(cost)

    def fingerprint_configuration(self) -> dict[str, Any]:
        """Return normalized public pricing semantics without runtime identity."""

        prices = [
            {
                "provider": provider,
                "model": model,
                "input_per_million_usd": price.input_per_million_usd,
                "output_per_million_usd": price.output_per_million_usd,
            }
            for (provider, model), price in sorted(self._prices.items())
        ]
        aliases = [
            {
                "provider": provider,
                "alias": alias,
                "canonical_model": canonical.strip().casefold(),
            }
            for (provider, alias), canonical in sorted(self._aliases.items())
        ]
        return {"prices": prices, "model_aliases": aliases}
