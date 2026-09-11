"""OpenAI Responses adapter with lazy SDK loading and normalization."""

from __future__ import annotations

import importlib
import json
from copy import deepcopy
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


class _OpenAISchemaAdaptationError(ValueError):
    """Internal signal for a schema that cannot be adapted without data loss."""


_SCHEMA_MAP_KEYWORDS = (
    "$defs",
    "definitions",
    "properties",
    "patternProperties",
    "dependentSchemas",
)
_SCHEMA_MIXED_MAP_KEYWORDS = ("dependencies",)
_SCHEMA_SINGLE_KEYWORDS = (
    "additionalItems",
    "additionalProperties",
    "contains",
    "contentSchema",
    "else",
    "if",
    "items",
    "not",
    "propertyNames",
    "then",
    "unevaluatedItems",
    "unevaluatedProperties",
)
_SCHEMA_ARRAY_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")


def _openai_strict_schema(canonical_schema: dict[str, Any]) -> dict[str, Any]:
    """Return an OpenAI-strict deep copy without changing contract semantics."""

    try:
        schema = deepcopy(canonical_schema)
    except (RecursionError, TypeError, ValueError) as exc:
        raise _OpenAISchemaAdaptationError(
            "OpenAI structured output schema cannot be copied safely"
        ) from exc

    def adapt(node: Any) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            raise _OpenAISchemaAdaptationError(
                "OpenAI structured output contains an invalid schema node"
            )

        if "properties" in node:
            properties = node["properties"]
            if not isinstance(properties, dict):
                raise _OpenAISchemaAdaptationError(
                    "OpenAI structured output properties must be an object"
                )
            required = node.get("required")
            if "required" in node and (
                not isinstance(required, list)
                or any(not isinstance(name, str) for name in required)
                or len(required) != len(set(required))
                or any(name not in properties for name in required)
            ):
                raise _OpenAISchemaAdaptationError(
                    "OpenAI structured output required fields cannot be preserved"
                )
            node["required"] = list(properties)

        for keyword in _SCHEMA_MAP_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, dict):
                raise _OpenAISchemaAdaptationError(
                    "OpenAI structured output contains an invalid schema map"
                )
            for child in children.values():
                adapt(child)

        for keyword in _SCHEMA_MIXED_MAP_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, dict):
                raise _OpenAISchemaAdaptationError(
                    "OpenAI structured output contains an invalid schema map"
                )
            for child in children.values():
                if isinstance(child, list) and all(
                    isinstance(name, str) for name in child
                ):
                    continue
                adapt(child)

        for keyword in _SCHEMA_SINGLE_KEYWORDS:
            if keyword not in node:
                continue
            child = node[keyword]
            if keyword == "items" and isinstance(child, list):
                for item in child:
                    adapt(item)
            else:
                adapt(child)

        for keyword in _SCHEMA_ARRAY_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, list):
                raise _OpenAISchemaAdaptationError(
                    "OpenAI structured output contains an invalid schema array"
                )
            for child in children:
                adapt(child)

    try:
        adapt(schema)
    except _OpenAISchemaAdaptationError:
        raise
    except (RecursionError, TypeError, ValueError) as exc:
        raise _OpenAISchemaAdaptationError(
            "OpenAI structured output schema cannot be adapted safely"
        ) from exc
    return schema


class OpenAIProvider(ModelProvider):
    provider_name = "openai"
    supports_structured_output = True

    _TERMINAL_STATUSES = frozenset({"cancelled", "completed", "failed", "incomplete"})

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
                "OpenAI is unavailable because OPENAI_API_KEY is not configured.",
            )
        elif not self.model_name:
            self._set_unavailable(
                ModelErrorCode.configuration_error,
                "OpenAI is unavailable because P3_OPENAI_MODEL is not configured.",
            )
        elif self._client is None:
            try:
                sdk = importlib.import_module("openai")
                kwargs: dict[str, Any] = {
                    "api_key": self._api_key,
                    "timeout": configuration.timeout_seconds,
                }
                if configuration.base_url:
                    kwargs["base_url"] = configuration.base_url
                self._client = sdk.OpenAI(**kwargs)
            except (ImportError, ModuleNotFoundError):
                self._set_unavailable(
                    ModelErrorCode.provider_unavailable,
                    "OpenAI is unavailable because its optional SDK is not installed.",
                )
            except Exception:
                self._set_unavailable(
                    ModelErrorCode.provider_unavailable,
                    "OpenAI is unavailable because its SDK could not be initialized.",
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
            "instructions": request.system_instructions,
            "input": self._responses_input(request),
            "max_output_tokens": min(
                request.max_output_tokens, self.configuration.max_output_tokens
            ),
            "store": False,
            "timeout": self.configuration.timeout_seconds,
        }
        if request.temperature is not None and self._supports_temperature():
            kwargs["temperature"] = request.temperature
        if request.structured_output:
            kwargs["text"] = self._structured_text_config(request)

        response = self._client.responses.create(**kwargs)
        content = self.read_value(response, "output_text")
        status = self.read_value(response, "status")
        if (
            not isinstance(content, str)
            or not content.strip()
            or status not in self._TERMINAL_STATUSES
        ):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )

        usage = self.read_value(response, "usage")
        if usage is None:
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        input_tokens = self._required_token_count(usage, "input_tokens")
        output_tokens = self._required_token_count(usage, "output_tokens")
        returned_model = sanitize_boundary_text(
            self.read_value(response, "model"), secrets=(self._api_key,)
        )
        actual_model = returned_model or self.model_name
        return ModelResponse(
            provider=self.provider_name,
            model=actual_model,
            content=sanitize_boundary_text(content, secrets=(self._api_key,)),
            finish_reason=status,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            estimated_cost_usd=self.estimate_cost(
                input_tokens, output_tokens, model=actual_model
            ),
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

    def _supports_temperature(self) -> bool:
        """Omit sampling controls unsupported by the GPT-5.5 Pro family."""

        model = self.model_name.casefold()
        return not (model == "gpt-5.5-pro" or model.startswith("gpt-5.5-pro-"))

    @staticmethod
    def _responses_input(request: ModelRequest) -> list[dict[str, Any]]:
        content = [{"type": "input_text", "text": request.user_content}]
        if request.evidence:
            evidence = json.dumps(
                request.evidence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            content.append(
                {
                    "type": "input_text",
                    "text": f"Sanitized evidence (JSON):\n{evidence}",
                }
            )
        return [{"role": "user", "content": content}]

    @staticmethod
    def _structured_text_config(request: ModelRequest) -> dict[str, Any]:
        if request.structured_output_schema is None:
            return {"format": {"type": "json_object"}}
        schema = request.model_dump(mode="json", include={"structured_output_schema"})[
            "structured_output_schema"
        ]
        return {
            "format": {
                "type": "json_schema",
                "name": "cybercortex_structured_output",
                "schema": _openai_strict_schema(schema),
                "strict": True,
            }
        }

    @staticmethod
    def _required_token_count(usage: Any, field: str) -> int:
        count = ModelProvider.read_value(usage, field)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("Provider token usage is malformed")
        return count

    def _normalize_exception(self, exc: BaseException) -> ModelProviderError:
        name = type(exc).__name__.casefold()
        status = getattr(exc, "status_code", None)
        if isinstance(exc, _OpenAISchemaAdaptationError):
            code = ModelErrorCode.configuration_error
        elif "authentication" in name or status == 401:
            code = ModelErrorCode.authentication_failed
        elif (
            "permission" in name
            or "notfound" in name
            or "not_found" in name
            or status in {403, 404}
        ):
            code = ModelErrorCode.provider_unavailable
        elif "ratelimit" in name or "rate_limit" in name or status == 429:
            code = ModelErrorCode.rate_limited
        elif "timeout" in name or isinstance(exc, TimeoutError):
            code = ModelErrorCode.timeout
        elif "connection" in name:
            code = ModelErrorCode.connection_failed
        elif "badrequest" in name or "unprocessable" in name or status in {400, 422}:
            code = ModelErrorCode.configuration_error
        else:
            code = ModelErrorCode.invalid_response
        return ModelProviderError(
            code,
            provider=self.provider_name,
            model=self.model_name,
        )
