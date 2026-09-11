"""P3-1 provider contracts, normalization, and safety-boundary tests."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from agent_core.models import (
    AnthropicProvider,
    ModelConfiguration,
    ModelErrorCode,
    ModelPrice,
    ModelPricingCatalog,
    ModelProvider,
    ModelProviderError,
    ModelRequest,
    ModelResponse,
    OllamaProvider,
    OpenAIProvider,
    ProviderConfiguration,
    ProviderRegistry,
    UnknownProviderError,
)
from agent_core.request_budget import RequestBudget, RequestDelta
from agent_core.result_normalizer import public_result
from agent_core.models.types import MAX_STRUCTURED_OUTPUT_SCHEMA_BYTES

API_KEY_SENTINEL = "CCX_API_KEY_SENTINEL_4fb9"
AUTH_SENTINEL = "CCX_AUTHORIZATION_SENTINEL_8c2a"
COOKIE_SENTINEL = "CCX_COOKIE_SESSION_SENTINEL_6ea1"


def request(**overrides) -> ModelRequest:
    values = {
        "system_instructions": "Analyze only; do not execute anything.",
        "user_content": "Assess the supplied evidence.",
        "evidence": {"status": "inconclusive", "request_count": 2},
        "temperature": 0.0,
        "max_output_tokens": 200,
        "task_type": "evidence_review",
        "run_id": "run-1",
        "hypothesis_id": "hyp-1",
        "metadata": {"source": "phase2"},
    }
    values.update(overrides)
    return ModelRequest(**values)


class CallableResult:
    def __init__(self, result=None, error: BaseException | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


def openai_client(result=None, error: BaseException | None = None):
    responses_create = CallableResult(result=result, error=error)
    chat_create = CallableResult(error=AssertionError("Chat Completions was called"))
    return SimpleNamespace(
        responses=responses_create,
        chat=SimpleNamespace(completions=chat_create),
        create_spy=responses_create,
        chat_spy=chat_create,
    )


def anthropic_client(result=None, error: BaseException | None = None):
    create = CallableResult(result=result, error=error)
    return SimpleNamespace(messages=create, create_spy=create)


class FakeHTTPResponse:
    def __init__(self, payload) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self.payload


class FakeHTTPClient:
    def __init__(self, payload=None, error: BaseException | None = None) -> None:
        self.payload = payload
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        return FakeHTTPResponse(self.payload)


def openai_config(key: str = API_KEY_SENTINEL) -> ProviderConfiguration:
    return ProviderConfiguration(
        model_name="openai-test-model",
        api_key=key,
        timeout_seconds=2.0,
        max_output_tokens=500,
    )


def anthropic_config(key: str = API_KEY_SENTINEL) -> ProviderConfiguration:
    return ProviderConfiguration(
        model_name="anthropic-test-model",
        api_key=key,
        timeout_seconds=2.0,
        max_output_tokens=500,
    )


def ollama_config() -> ProviderConfiguration:
    return ProviderConfiguration(
        model_name="deepseek-test:latest",
        base_url="http://127.0.0.1:11434",
        timeout_seconds=2.0,
        max_output_tokens=500,
    )


def normalized_openai_response(
    content: str = "analysis",
    *,
    model: str = "openai-test-model",
    response_id: str = "resp-openai-1",
    status: str = "completed",
    input_tokens: int = 11,
    output_tokens: int = 7,
):
    return SimpleNamespace(
        id=response_id,
        model=model,
        output_text=content,
        status=status,
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        ),
    )


def normalized_anthropic_response(content: str = "analysis"):
    return SimpleNamespace(
        id="call-anthropic-1",
        content=[SimpleNamespace(type="text", text=content)],
        stop_reason="end_turn",
        usage=SimpleNamespace(input_tokens=13, output_tokens=5),
    )


def test_common_provider_interface_is_abstract_and_shared():
    assert issubclass(OpenAIProvider, ModelProvider)
    assert issubclass(AnthropicProvider, ModelProvider)
    assert issubclass(OllamaProvider, ModelProvider)
    with pytest.raises(TypeError):
        ModelProvider(ProviderConfiguration(model_name="x"))


def test_model_request_is_strict_and_has_no_tool_or_callback_field():
    with pytest.raises(ValidationError):
        request(max_output_tokens="200")
    with pytest.raises(ValidationError):
        ModelRequest(**request().model_dump(), tools=[lambda: None])


def test_model_request_structured_output_defaults_off():
    assert request().structured_output is False


def test_model_request_structured_output_can_be_explicitly_enabled():
    model_request = request(structured_output=True)
    assert model_request.structured_output is True
    assert json.loads(model_request.model_dump_json())["structured_output"] is True
    with pytest.raises(ValidationError):
        request(structured_output=1)


def test_model_request_accepts_canonical_immutable_structured_output_schema():
    supplied = {
        "type": "object",
        "required": ["answer"],
        "properties": {"answer": {"type": "string"}},
        "additionalProperties": False,
    }
    model_request = request(
        structured_output=True,
        structured_output_schema=supplied,
    )
    supplied["required"].append("late_mutation")

    serialized = json.loads(model_request.model_dump_json())
    assert serialized["structured_output_schema"] == {
        "additionalProperties": False,
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
        "type": "object",
    }
    with pytest.raises(TypeError):
        model_request.structured_output_schema["type"] = "array"
    with pytest.raises(TypeError):
        model_request.structured_output_schema["required"].append("other")


@pytest.mark.parametrize(
    "schema",
    [
        {"description": f"Authorization: Bearer {AUTH_SENTINEL}"},
        {"description": "x" * MAX_STRUCTURED_OUTPUT_SCHEMA_BYTES},
        {"type": lambda: "object"},
    ],
)
def test_model_request_structured_output_schema_is_bounded_public_safe_data(schema):
    with pytest.raises(ValidationError):
        request(structured_output=True, structured_output_schema=schema)


def test_model_request_schema_requires_structured_output_intent():
    with pytest.raises(ValidationError):
        request(structured_output_schema={"type": "object"})


def test_model_response_is_strict_and_rejects_raw_provider_fields():
    with pytest.raises(ValidationError):
        ModelResponse(
            provider="openai",
            model="model",
            content="ok",
            input_tokens=1,
            output_tokens=1,
            total_tokens=2,
            latency_seconds=0.1,
            task_type="review",
            raw_response={"private": True},
        )


def test_openai_response_normalization_and_no_tools():
    client = openai_client(normalized_openai_response())
    response = OpenAIProvider(openai_config(), client=client).generate(request())
    assert len(client.create_spy.calls) == 1
    assert client.chat_spy.calls == []
    assert response.provider == "openai"
    assert response.model == "openai-test-model"
    assert response.content == "analysis"
    assert response.finish_reason == "completed"
    assert response.provider_call_id == "resp-openai-1"
    call = client.create_spy.calls[0]
    assert call["instructions"] == request().system_instructions
    assert call["input"] == [
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": request().user_content},
                {
                    "type": "input_text",
                    "text": (
                        "Sanitized evidence (JSON):\n"
                        '{"request_count":2,"status":"inconclusive"}'
                    ),
                },
            ],
        }
    ]
    assert call["max_output_tokens"] == 200
    assert call["temperature"] == 0.0
    assert call["timeout"] == 2.0
    assert call["store"] is False
    assert "tools" not in call
    assert "text" not in call


def test_openai_response_usage_and_actual_snapshot_model_are_normalized():
    catalog = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="openai-test-model",
                input_per_million_usd=2.0,
                output_per_million_usd=8.0,
            ),
        ),
        model_aliases={("openai", "openai-test-model-2026-04-23"): "openai-test-model"},
    )
    raw = normalized_openai_response(model="openai-test-model-2026-04-23")
    provider = OpenAIProvider(
        openai_config(), pricing=catalog, client=openai_client(raw)
    )

    response = provider.generate(request())

    assert response.model == "openai-test-model-2026-04-23"
    assert (response.input_tokens, response.output_tokens, response.total_tokens) == (
        11,
        7,
        18,
    )
    assert response.estimated_cost_usd == pytest.approx(0.000078)
    assert response.provider_call_id == "resp-openai-1"
    assert provider.telemetry[-1].model == "openai-test-model-2026-04-23"


def test_gpt_5_5_pro_real_usage_is_priced_from_returned_snapshot():
    raw = normalized_openai_response(
        model="gpt-5.5-pro-2026-04-23",
        input_tokens=3887,
        output_tokens=2056,
    )
    configuration = ProviderConfiguration(
        model_name="gpt-5.5-pro",
        api_key=API_KEY_SENTINEL,
        timeout_seconds=2.0,
        max_output_tokens=4096,
    )

    response = OpenAIProvider(configuration, client=openai_client(raw)).generate(
        request(max_output_tokens=4096)
    )

    assert response.model == "gpt-5.5-pro-2026-04-23"
    assert response.input_tokens == 3887
    assert response.output_tokens == 2056
    assert response.estimated_cost_usd == pytest.approx(0.48669)


def test_openai_rejects_a_returned_model_outside_the_configured_alias():
    provider = OpenAIProvider(
        openai_config(),
        client=openai_client(normalized_openai_response(model="different-model")),
    )

    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())

    assert captured.value.code == ModelErrorCode.invalid_response


def test_openai_generic_structured_output_uses_responses_json_mode_once():
    client = openai_client(normalized_openai_response('{"result":"ok"}'))
    provider = OpenAIProvider(openai_config(), client=client)

    response = provider.generate(request(structured_output=True))

    assert response.content == '{"result":"ok"}'
    assert len(client.create_spy.calls) == 1
    assert client.chat_spy.calls == []
    assert client.create_spy.calls[0]["text"] == {"format": {"type": "json_object"}}


def test_openai_schema_structured_output_is_exact_strict_and_immutable():
    schema = {
        "type": "object",
        "properties": {"result": {"type": "string"}},
        "required": ["result"],
        "additionalProperties": False,
    }
    original = json.loads(json.dumps(schema))
    model_request = request(
        structured_output=True,
        structured_output_schema=schema,
    )
    client = openai_client(normalized_openai_response('{"result":"ok"}'))

    response = OpenAIProvider(openai_config(), client=client).generate(model_request)

    assert response.content == '{"result":"ok"}'
    assert len(client.create_spy.calls) == 1
    assert client.chat_spy.calls == []
    assert client.create_spy.calls[0]["text"] == {
        "format": {
            "type": "json_schema",
            "name": "cybercortex_structured_output",
            "schema": original,
            "strict": True,
        }
    }
    assert schema == original
    assert model_request.structured_output_schema == original


def test_openai_schema_requires_root_properties_in_canonical_order_without_mutation():
    schema = {
        "type": "object",
        "properties": {
            "z_defaulted": {"type": "string", "default": ""},
            "a_required": {"type": "integer", "minimum": 0},
        },
        "required": ["a_required"],
        "additionalProperties": False,
    }
    supplied = json.loads(json.dumps(schema))
    model_request = request(
        structured_output=True,
        structured_output_schema=schema,
    )
    canonical_before = model_request.model_dump_json()
    client = openai_client(normalized_openai_response('{"a_required":1}'))

    OpenAIProvider(openai_config(), client=client).generate(model_request)

    transport = client.create_spy.calls[0]["text"]["format"]
    transport_schema = transport["schema"]
    assert len(client.create_spy.calls) == 1
    assert transport["strict"] is True
    assert transport_schema["required"] == list(transport_schema["properties"])
    assert transport_schema["required"] == ["a_required", "z_defaulted"]
    assert transport_schema["properties"]["a_required"]["minimum"] == 0
    assert transport_schema["additionalProperties"] is False
    assert schema == supplied
    assert model_request.structured_output_schema["required"] == ["a_required"]
    assert model_request.model_dump_json() == canonical_before


def test_openai_schema_requires_properties_in_defs_nested_items_and_branches():
    schema = {
        "$defs": {
            "Definition": {
                "type": "object",
                "properties": {
                    "defaulted": {
                        "type": "integer",
                        "default": 0,
                        "minimum": 0,
                        "maximum": 10,
                    }
                },
                "additionalProperties": False,
            }
        },
        "type": "object",
        "properties": {
            "nested": {
                "type": "object",
                "properties": {"value": {"type": "string", "minLength": 1}},
                "additionalProperties": False,
            },
            "items": {
                "type": "array",
                "minItems": 0,
                "items": {
                    "type": "object",
                    "properties": {"count": {"type": "integer", "minimum": 0}},
                    "additionalProperties": False,
                },
            },
            "choice": {
                "anyOf": [
                    {
                        "type": "object",
                        "properties": {"left": {"type": "string"}},
                        "additionalProperties": False,
                    },
                    {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {"right": {"type": "boolean"}},
                                "additionalProperties": False,
                            },
                            {"type": "null"},
                        ]
                    },
                ]
            },
            "defined": {"$ref": "#/$defs/Definition"},
        },
        "additionalProperties": False,
    }
    model_request = request(
        structured_output=True,
        structured_output_schema=schema,
    )
    canonical = json.loads(model_request.model_dump_json())["structured_output_schema"]
    client = openai_client(normalized_openai_response("{}"))

    OpenAIProvider(openai_config(), client=client).generate(model_request)

    adapted = client.create_spy.calls[0]["text"]["format"]["schema"]
    properties = adapted["properties"]
    assert adapted["required"] == list(properties)
    assert adapted["$defs"]["Definition"]["required"] == ["defaulted"]
    assert properties["nested"]["required"] == ["value"]
    assert properties["items"]["items"]["required"] == ["count"]
    assert properties["choice"]["anyOf"][0]["required"] == ["left"]
    assert properties["choice"]["anyOf"][1]["oneOf"][0]["required"] == ["right"]
    assert adapted["$defs"]["Definition"]["properties"]["defaulted"] == {
        "default": 0,
        "maximum": 10,
        "minimum": 0,
        "type": "integer",
    }
    assert properties["defined"] == {"$ref": "#/$defs/Definition"}
    assert json.loads(model_request.model_dump_json())["structured_output_schema"] == (
        canonical
    )


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {"known": {"type": "string"}},
            "required": ["unconstrained_but_required"],
        },
        {"type": "object", "properties": []},
    ],
)
def test_openai_schema_adaptation_fails_closed_before_transport(schema):
    client = openai_client(normalized_openai_response("{}"))
    provider = OpenAIProvider(openai_config(), client=client)

    with pytest.raises(ModelProviderError) as captured:
        provider.generate(
            request(structured_output=True, structured_output_schema=schema)
        )

    assert captured.value.code == ModelErrorCode.configuration_error
    assert client.create_spy.calls == []


@pytest.mark.parametrize("content", [None, "", "   "])
def test_openai_empty_output_fails_closed(content):
    provider = OpenAIProvider(
        openai_config(), client=openai_client(normalized_openai_response(content))
    )

    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())

    assert captured.value.code == ModelErrorCode.invalid_response
    assert len(provider.telemetry) == 1


def test_gpt_5_5_pro_omits_unsupported_temperature_without_changing_request():
    configuration = openai_config().model_copy(update={"model_name": "gpt-5.5-pro"})
    client = openai_client(normalized_openai_response(model="gpt-5.5-pro-2026-04-23"))
    model_request = request(temperature=0.0)

    OpenAIProvider(configuration, client=client).generate(model_request)

    assert "temperature" not in client.create_spy.calls[0]
    assert model_request.temperature == 0.0


def test_openai_output_limit_uses_the_request_and_configuration_minimum():
    client = openai_client(normalized_openai_response())

    OpenAIProvider(openai_config(), client=client).generate(
        request(max_output_tokens=800)
    )

    assert client.create_spy.calls[0]["max_output_tokens"] == 500


def test_anthropic_response_normalization_and_no_tools():
    client = anthropic_client(normalized_anthropic_response())
    response = AnthropicProvider(anthropic_config(), client=client).generate(request())
    assert response.provider == "anthropic"
    assert response.content == "analysis"
    assert response.finish_reason == "end_turn"
    assert response.provider_call_id == "call-anthropic-1"
    assert "tools" not in client.create_spy.calls[0]


def test_ollama_response_normalization_and_no_tools():
    client = FakeHTTPClient(
        {
            "message": {"role": "assistant", "content": "local analysis"},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 9,
            "eval_count": 4,
        }
    )
    response = OllamaProvider(ollama_config(), client=client).generate(request())
    assert response.provider == "ollama"
    assert response.model == "deepseek-test:latest"
    assert response.content == "local analysis"
    assert len(client.calls) == 1
    payload = client.calls[0][1]["json"]
    assert "tools" not in payload
    assert "format" not in payload
    assert payload["messages"] == [
        {"role": "system", "content": request().system_instructions},
        {"role": "user", "content": OllamaProvider.user_prompt(request())},
    ]
    assert payload["options"] == {"num_predict": 200, "temperature": 0.0}


def test_ollama_generic_structured_output_uses_native_json_mode_once():
    client = FakeHTTPClient(
        {
            "message": {"role": "assistant", "content": '{"result":"ok"}'},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 9,
            "eval_count": 4,
        }
    )
    model_request = request(structured_output=True)
    provider = OllamaProvider(ollama_config(), client=client)

    response = provider.generate(model_request)

    assert len(client.calls) == 1
    payload = client.calls[0][1]["json"]
    assert payload["format"] == "json"
    assert payload["messages"] == [
        {"role": "system", "content": model_request.system_instructions},
        {"role": "user", "content": provider.user_prompt(model_request)},
    ]
    assert payload["options"] == {"num_predict": 200, "temperature": 0.0}
    assert (response.input_tokens, response.output_tokens, response.total_tokens) == (
        9,
        4,
        13,
    )
    assert provider.telemetry[-1].total_tokens == 13


def test_ollama_schema_structured_output_uses_schema_once_with_same_accounting():
    schema = {
        "type": "object",
        "properties": {"result": {"type": "string"}},
        "required": ["result"],
        "additionalProperties": False,
    }
    client = FakeHTTPClient(
        {
            "message": {"role": "assistant", "content": '{"result":"ok"}'},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 9,
            "eval_count": 4,
        }
    )
    model_request = request(
        structured_output=True,
        structured_output_schema=schema,
    )
    provider = OllamaProvider(ollama_config(), client=client)

    response = provider.generate(model_request)

    assert len(client.calls) == 1
    payload = client.calls[0][1]["json"]
    assert payload["format"] == schema
    assert "think" not in payload
    assert response.content == '{"result":"ok"}'
    assert (response.input_tokens, response.output_tokens, response.total_tokens) == (
        9,
        4,
        13,
    )
    assert provider.telemetry[-1].total_tokens == 13


def test_ollama_ignores_thinking_and_keeps_message_content_authoritative():
    client = FakeHTTPClient(
        {
            "message": {
                "role": "assistant",
                "thinking": "private provider reasoning",
                "content": '{"result":"authoritative"}',
            },
            "response": '{"result":"legacy-fallback"}',
            "done": True,
            "prompt_eval_count": 3,
            "eval_count": 2,
        }
    )

    response = OllamaProvider(ollama_config(), client=client).generate(
        request(structured_output=True)
    )

    assert response.content == '{"result":"authoritative"}'
    assert "thinking" not in response.metadata
    assert len(client.calls) == 1


def test_unsupported_anthropic_structured_output_fails_before_transport():
    client = anthropic_client(normalized_anthropic_response())
    provider = AnthropicProvider(anthropic_config(), client=client)

    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request(structured_output=True))

    assert captured.value.code == ModelErrorCode.provider_unavailable
    assert client.create_spy.calls == []
    event = provider.telemetry[-1]
    assert event.attempt_state == "blocked_before_provider_call"
    assert event.usage_known is True
    assert event.total_tokens == 0


def test_missing_openai_key_marks_only_that_provider_unavailable():
    provider = OpenAIProvider(openai_config(key=""), client=object())
    assert provider.availability.available is False
    assert provider.availability.reason_code == ModelErrorCode.provider_unavailable
    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())
    assert captured.value.code == ModelErrorCode.provider_unavailable
    event = provider.telemetry[-1]
    assert event.attempt_state == "blocked_before_provider_call"
    assert event.usage_known is True
    assert event.total_tokens == 0


def test_missing_anthropic_key_marks_only_that_provider_unavailable():
    provider = AnthropicProvider(anthropic_config(key=""), client=object())
    assert provider.availability.available is False
    assert provider.availability.reason_code == ModelErrorCode.provider_unavailable


def test_unavailable_ollama_is_a_deterministic_connection_failure():
    transport_request = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
    failure = httpx.ConnectError("private provider detail", request=transport_request)
    provider = OllamaProvider(ollama_config(), client=FakeHTTPClient(error=failure))
    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())
    assert captured.value.code == ModelErrorCode.connection_failed
    assert str(captured.value) == "The model provider could not be reached."


@pytest.mark.parametrize(
    ("provider", "error"),
    [
        (
            lambda error: OpenAIProvider(
                openai_config(), client=openai_client(error=error)
            ),
            TimeoutError("timeout with private request body"),
        ),
        (
            lambda error: AnthropicProvider(
                anthropic_config(), client=anthropic_client(error=error)
            ),
            TimeoutError("timeout with private request body"),
        ),
    ],
)
def test_cloud_timeout_normalization(provider, error):
    with pytest.raises(ModelProviderError) as captured:
        provider(error).generate(request())
    assert captured.value.code == ModelErrorCode.timeout
    assert "private request body" not in str(captured.value)


def test_provider_rate_limit_normalization():
    rate_limit_error = type("RateLimitError", (RuntimeError,), {})
    provider = OpenAIProvider(
        openai_config(),
        client=openai_client(error=rate_limit_error("Authorization: secret")),
    )
    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())
    assert captured.value.code == ModelErrorCode.rate_limited


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, ModelErrorCode.authentication_failed),
        (403, ModelErrorCode.provider_unavailable),
        (404, ModelErrorCode.provider_unavailable),
        (400, ModelErrorCode.configuration_error),
    ],
)
def test_openai_http_error_normalization_is_truthful_and_public_safe(
    status_code, expected
):
    provider_error = type(
        "ProviderHTTPError",
        (RuntimeError,),
        {"status_code": status_code},
    )
    provider = OpenAIProvider(
        openai_config(),
        client=openai_client(error=provider_error(API_KEY_SENTINEL)),
    )

    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())

    assert captured.value.code == expected
    assert API_KEY_SENTINEL not in str(captured.value)
    assert API_KEY_SENTINEL not in json.dumps(captured.value.public_dict())
    assert API_KEY_SENTINEL not in provider.telemetry[-1].model_dump_json()


@pytest.mark.parametrize(
    "provider",
    [
        OpenAIProvider(openai_config(), client=openai_client(SimpleNamespace())),
        AnthropicProvider(
            anthropic_config(), client=anthropic_client(SimpleNamespace(content=[]))
        ),
        OllamaProvider(ollama_config(), client=FakeHTTPClient({"message": {}})),
    ],
)
def test_malformed_provider_response(provider):
    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())
    assert captured.value.code == ModelErrorCode.invalid_response


@pytest.mark.parametrize(
    ("provider", "expected_input", "expected_output"),
    [
        (
            OpenAIProvider(
                openai_config(), client=openai_client(normalized_openai_response())
            ),
            11,
            7,
        ),
        (
            AnthropicProvider(
                anthropic_config(),
                client=anthropic_client(normalized_anthropic_response()),
            ),
            13,
            5,
        ),
        (
            OllamaProvider(
                ollama_config(),
                client=FakeHTTPClient(
                    {
                        "response": "local",
                        "done": True,
                        "prompt_eval_count": 17,
                        "eval_count": 3,
                    }
                ),
            ),
            17,
            3,
        ),
    ],
)
def test_token_accounting_is_normalized(provider, expected_input, expected_output):
    response = provider.generate(request())
    assert response.input_tokens == expected_input
    assert response.output_tokens == expected_output
    assert response.total_tokens == expected_input + expected_output
    assert provider.telemetry[-1].total_tokens == response.total_tokens


def test_total_token_consistency_is_enforced():
    with pytest.raises(ValidationError):
        ModelResponse(
            provider="openai",
            model="model",
            content="ok",
            input_tokens=2,
            output_tokens=3,
            total_tokens=6,
            latency_seconds=0.1,
            task_type="review",
        )


def test_known_price_cost_calculation_and_alias_resolution():
    catalog = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="canonical-model",
                input_per_million_usd=2.0,
                output_per_million_usd=8.0,
            ),
        ),
        model_aliases={("open-ai", "friendly-model"): "canonical-model"},
    )
    assert catalog.resolve_model("open-ai", "friendly-model") == (
        "openai",
        "canonical-model",
    )
    assert (
        catalog.estimate_cost(
            "open-ai", "friendly-model", input_tokens=1_000_000, output_tokens=500_000
        )
        == 6.0
    )


def test_gpt_5_5_pro_standard_api_pricing_is_exact_and_snapshot_scoped():
    catalog = ModelPricingCatalog()

    assert catalog.estimate_cost(
        "openai", "gpt-5.5-pro", input_tokens=1_000_000, output_tokens=0
    ) == pytest.approx(30.0)
    assert catalog.estimate_cost(
        "openai",
        "gpt-5.5-pro-2026-04-23",
        input_tokens=0,
        output_tokens=1_000_000,
    ) == pytest.approx(180.0)
    assert catalog.estimate_cost(
        "openai",
        "gpt-5.5-pro-2026-04-23",
        input_tokens=3887,
        output_tokens=2056,
    ) == pytest.approx(0.48669)
    assert (
        catalog.estimate_cost(
            "openai",
            "gpt-5.5-pro-experimental",
            input_tokens=3887,
            output_tokens=2056,
        )
        is None
    )


def test_anthropic_configured_pricing_is_unchanged():
    catalog = ModelPricingCatalog(
        (
            ModelPrice(
                provider="anthropic",
                model="anthropic-test-model",
                input_per_million_usd=2.0,
                output_per_million_usd=8.0,
            ),
        )
    )

    assert catalog.estimate_cost(
        "anthropic",
        "anthropic-test-model",
        input_tokens=1_000_000,
        output_tokens=500_000,
    ) == pytest.approx(6.0)


def test_unknown_price_is_none_without_losing_tokens():
    client = openai_client(normalized_openai_response())
    response = OpenAIProvider(openai_config(), client=client).generate(request())
    assert response.estimated_cost_usd is None
    assert response.total_tokens == 18


def test_ollama_cost_is_zero():
    provider = OllamaProvider(
        ollama_config(),
        client=FakeHTTPClient(
            {"response": "local", "prompt_eval_count": 2, "eval_count": 1}
        ),
    )
    assert provider.generate(request()).estimated_cost_usd == 0.0


def test_provider_registry_lookup_and_supported_enumeration():
    registry = ProviderRegistry(ModelConfiguration())
    assert registry.supported_providers == ("anthropic", "ollama", "openai")
    assert isinstance(
        registry.create(
            "local",
            model_name="qwen-test",
            client=FakeHTTPClient({"response": "ok"}),
        ),
        OllamaProvider,
    )


def test_unknown_provider_rejection():
    with pytest.raises(UnknownProviderError) as captured:
        ProviderRegistry(ModelConfiguration()).create("unknown-provider")
    assert captured.value.code == ModelErrorCode.configuration_error


@pytest.mark.parametrize(
    ("module", "provider_class", "configuration"),
    [
        ("openai", OpenAIProvider, openai_config()),
        ("anthropic", AnthropicProvider, anthropic_config()),
    ],
)
def test_optional_cloud_sdk_absence_isolated(
    monkeypatch, module, provider_class, configuration
):
    def missing(name):
        if name == module:
            raise ModuleNotFoundError(name)
        raise AssertionError(f"unexpected import: {name}")

    provider_module = __import__(provider_class.__module__, fromlist=["importlib"])
    monkeypatch.setattr(provider_module.importlib, "import_module", missing)
    provider = provider_class(configuration)
    assert provider.availability.available is False
    assert provider.availability.reason_code == ModelErrorCode.provider_unavailable


def test_api_key_sentinel_absent_from_response_and_telemetry():
    raw = normalized_openai_response(
        API_KEY_SENTINEL,
        response_id=f"resp-{API_KEY_SENTINEL}",
    )
    raw.metadata = {"private": API_KEY_SENTINEL}
    provider = OpenAIProvider(
        openai_config(),
        client=openai_client(raw),
    )
    response = provider.generate(request())
    assert API_KEY_SENTINEL not in response.model_dump_json()
    assert API_KEY_SENTINEL not in provider.telemetry[-1].model_dump_json()
    assert response.metadata == {}
    assert API_KEY_SENTINEL not in (response.provider_call_id or "")


def test_api_key_sentinel_absent_from_public_error():
    provider = OpenAIProvider(
        openai_config(),
        client=openai_client(error=RuntimeError(API_KEY_SENTINEL)),
    )
    with pytest.raises(ModelProviderError) as captured:
        provider.generate(request())
    rendered = json.dumps(captured.value.public_dict())
    assert API_KEY_SENTINEL not in rendered


@pytest.mark.parametrize(
    "unsafe",
    [
        f"Authorization: Bearer {AUTH_SENTINEL}",
        f"Cookie: session={COOKIE_SENTINEL}",
        f"session_token={COOKIE_SENTINEL}",
    ],
)
def test_authorization_cookie_and_session_sentinels_rejected_from_prompt(unsafe):
    with pytest.raises(ValidationError):
        request(user_content=unsafe)


def test_raw_phase2_private_recovery_state_cannot_enter_model_request():
    with pytest.raises(ValidationError):
        request(
            evidence={
                "status": "inconclusive",
                "private_recovery_state": {"challenge": COOKIE_SENTINEL},
            }
        )


def test_sanitized_phase2_evidence_can_enter_model_request():
    raw = {
        "status": "inconclusive",
        "private_recovery_state": {"challenge": COOKIE_SENTINEL},
        "headers": {"Authorization": AUTH_SENTINEL},
    }
    sanitized = public_result(raw)
    model_request = request(evidence=sanitized)
    assert model_request.evidence == sanitized
    rendered = model_request.model_dump_json()
    assert COOKIE_SENTINEL not in rendered
    assert AUTH_SENTINEL not in rendered


def test_from_phase2_applies_the_canonical_sanitizer():
    model_request = ModelRequest.from_phase2(
        system_instructions="Analyze only.",
        user_content="Review evidence.",
        evidence={
            "status": "inconclusive",
            "private_recovery_state": {"challenge": COOKIE_SENTINEL},
        },
        task_type="review",
    )
    assert model_request.evidence == {"status": "inconclusive"}


def test_model_telemetry_does_not_affect_request_delta_or_network_ledger():
    budget = RequestBudget(limit=5)
    before = budget.snapshot()
    provider = OpenAIProvider(
        openai_config(), client=openai_client(normalized_openai_response())
    )
    provider.generate(request())
    after = budget.snapshot()
    assert before == after
    assert RequestDelta() == RequestDelta.model_validate(
        {
            "discovery": 0,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 0,
            "total": 0,
        }
    )


def test_local_only_registry_operation_does_not_construct_cloud_providers():
    registry = ProviderRegistry(
        ModelConfiguration(
            openai=ProviderConfiguration(),
            anthropic=ProviderConfiguration(),
            ollama=ollama_config(),
        )
    )
    provider = registry.create(
        "ollama", client=FakeHTTPClient({"response": "local-only"})
    )
    assert provider.generate(request()).content == "local-only"


def test_provider_specific_raw_response_does_not_escape_normalization():
    raw = normalized_openai_response()
    raw.provider_private_object = {"Authorization": AUTH_SENTINEL}
    response = OpenAIProvider(openai_config(), client=openai_client(raw)).generate(
        request()
    )
    assert isinstance(response, ModelResponse)
    assert not hasattr(response, "provider_private_object")
    assert AUTH_SENTINEL not in response.model_dump_json()


def test_openai_does_not_strip_or_repair_markdown_wrapped_json():
    wrapped = '```json\n{"result":"ok"}\n```'
    client = openai_client(normalized_openai_response(wrapped))

    response = OpenAIProvider(openai_config(), client=client).generate(
        request(structured_output=True)
    )

    assert response.content == wrapped
    assert len(client.create_spy.calls) == 1
    assert client.chat_spy.calls == []


def test_latency_and_failure_telemetry_are_recorded_for_every_call():
    provider = OpenAIProvider(
        openai_config(), client=openai_client(error=TimeoutError("private"))
    )
    with pytest.raises(ModelProviderError):
        provider.generate(request())
    event = provider.telemetry[-1]
    assert event.success is False
    assert event.error_code == ModelErrorCode.timeout
    assert event.latency_seconds >= 0.0
    assert event.attempt_state == "provider_call_failed_after_start"
    assert event.usage_known is False
    assert event.total_tokens is None
