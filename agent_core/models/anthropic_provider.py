"""Anthropic adapter with lazy SDK loading and immediate normalization."""

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


class _AnthropicSchemaAdaptationError(ValueError):
    """Internal signal for a schema that cannot be adapted without data loss."""


_GENERIC_JSON_OBJECT_SCHEMA = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}
_ANTHROPIC_TRANSPORT_ONLY_CONSTRAINTS = frozenset(
    {
        "contains",
        "dependentRequired",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maxContains",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minContains",
        "minLength",
        "minProperties",
        "multipleOf",
        "propertyNames",
        "unevaluatedItems",
        "unevaluatedProperties",
        "uniqueItems",
        "maximum",
        "minimum",
    }
)
_SCHEMA_MAP_KEYWORDS = (
    "$defs",
    "definitions",
    "dependentSchemas",
    "patternProperties",
    "properties",
)
_SCHEMA_SINGLE_KEYWORDS = (
    "additionalItems",
    "else",
    "if",
    "items",
    "not",
    "then",
)
_SCHEMA_ARRAY_KEYWORDS = ("allOf", "anyOf", "prefixItems")


def _anthropic_structured_schema(canonical_schema: dict[str, Any]) -> dict[str, Any]:
    """Return an Anthropic-compatible copy with canonical constraints retained."""

    try:
        schema = deepcopy(canonical_schema)
    except (RecursionError, TypeError, ValueError) as exc:
        raise _AnthropicSchemaAdaptationError(
            "Anthropic structured output schema cannot be copied safely"
        ) from exc

    def adapt(node: Any) -> None:
        if not isinstance(node, dict):
            raise _AnthropicSchemaAdaptationError(
                "Anthropic structured output contains an invalid schema node"
            )

        reference = node.get("$ref")
        if reference is not None and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            raise _AnthropicSchemaAdaptationError(
                "Anthropic structured output requires a local schema reference"
            )
        if "oneOf" in node:
            raise _AnthropicSchemaAdaptationError(
                "Anthropic structured output cannot preserve oneOf semantics"
            )
        if "enum" in node and (
            not isinstance(node["enum"], list)
            or any(isinstance(value, (dict, list)) for value in node["enum"])
        ):
            raise _AnthropicSchemaAdaptationError(
                "Anthropic structured output cannot preserve a complex enum"
            )

        node_type = node.get("type")
        node_types = node_type if isinstance(node_type, list) else [node_type]
        if "object" in node_types and node.get("additionalProperties") is not False:
            raise _AnthropicSchemaAdaptationError(
                "Anthropic structured output requires closed schema objects"
            )

        for keyword in _SCHEMA_MAP_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, dict):
                raise _AnthropicSchemaAdaptationError(
                    "Anthropic structured output contains an invalid schema map"
                )
            for child in children.values():
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
                raise _AnthropicSchemaAdaptationError(
                    "Anthropic structured output contains an invalid schema array"
                )
            if keyword == "allOf" and any(
                isinstance(child, dict) and "$ref" in child for child in children
            ):
                raise _AnthropicSchemaAdaptationError(
                    "Anthropic structured output cannot combine allOf with a reference"
                )
            for child in children:
                adapt(child)

        constraints = {
            keyword: node.pop(keyword)
            for keyword in sorted(_ANTHROPIC_TRANSPORT_ONLY_CONSTRAINTS)
            if keyword in node
        }
        if "minItems" in node and node["minItems"] not in {0, 1}:
            constraints["minItems"] = node.pop("minItems")
        if constraints:
            try:
                rendered = json.dumps(
                    constraints,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
            except (RecursionError, TypeError, ValueError) as exc:
                raise _AnthropicSchemaAdaptationError(
                    "Anthropic structured output constraints are malformed"
                ) from exc
            annotation = (
                "Anthropic transport-only constraints; canonical validation remains "
                f"authoritative: {rendered}"
            )
            description = node.get("description")
            node["description"] = (
                f"{description}\n\n{annotation}"
                if isinstance(description, str) and description
                else annotation
            )

    try:
        adapt(schema)
    except _AnthropicSchemaAdaptationError:
        raise
    except (RecursionError, TypeError, ValueError) as exc:
        raise _AnthropicSchemaAdaptationError(
            "Anthropic structured output schema cannot be adapted safely"
        ) from exc
    return schema


def _reject_nonstandard_json_constant(value: str) -> None:
    del value
    raise ValueError("Anthropic structured output contains non-standard JSON")


class AnthropicProvider(ModelProvider):
    provider_name = "anthropic"
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
        if request.temperature is not None and not request.structured_output:
            kwargs["temperature"] = request.temperature
        if request.structured_output:
            kwargs["output_config"] = self._structured_output_config(request)
        response = self._client.messages.create(**kwargs)
        blocks = self.read_value(response, "content")
        if not isinstance(blocks, (list, tuple)):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        content = (
            self._structured_content(response, blocks)
            if request.structured_output
            else self._plain_text_content(blocks)
        )
        usage = self.read_value(response, "usage", {})
        input_tokens = self.token_count(usage, "input_tokens")
        output_tokens = self.token_count(usage, "output_tokens")
        returned_model = sanitize_boundary_text(
            self.read_value(response, "model"), secrets=(self._api_key,)
        )
        actual_model = returned_model or self.model_name
        return ModelResponse(
            provider=self.provider_name,
            model=actual_model,
            content=content,
            finish_reason=self.read_value(response, "stop_reason"),
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

    @staticmethod
    def _structured_output_config(request: ModelRequest) -> dict[str, Any]:
        if request.structured_output_schema is None:
            schema = deepcopy(_GENERIC_JSON_OBJECT_SCHEMA)
        else:
            schema = request.model_dump(
                mode="json", include={"structured_output_schema"}
            )["structured_output_schema"]
        return {
            "format": {
                "type": "json_schema",
                "schema": _anthropic_structured_schema(schema),
            }
        }

    def _plain_text_content(self, blocks: list[Any] | tuple[Any, ...]) -> str:
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
        return sanitize_boundary_text("\n".join(text_blocks), secrets=(self._api_key,))

    def _structured_content(
        self, response: Any, blocks: list[Any] | tuple[Any, ...]
    ) -> str:
        if len(blocks) != 1 or self.read_value(blocks[0], "type") != "text":
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        block_text = self.read_value(blocks[0], "text")
        if not isinstance(block_text, str) or not block_text.strip():
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        if self.read_value(response, "stop_reason") != "end_turn":
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            )
        content = sanitize_boundary_text(block_text, secrets=(self._api_key,))
        try:
            json.loads(content, parse_constant=_reject_nonstandard_json_constant)
        except (TypeError, ValueError):
            raise InvalidProviderResponseError(
                provider=self.provider_name, model=self.model_name
            ) from None
        return content

    def _normalize_exception(self, exc: BaseException) -> ModelProviderError:
        name = type(exc).__name__.casefold()
        status = getattr(exc, "status_code", None)
        if isinstance(exc, _AnthropicSchemaAdaptationError):
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
