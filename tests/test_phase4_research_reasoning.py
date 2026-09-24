import json

import pytest
from pydantic import ValidationError

from agent_core.models import (
    ModelCallLedger,
    ModelConfiguration,
    ModelResponse,
    ModelRouter,
    ModelRoute,
    ModelRoutingPolicy,
    RoutingMode,
    ProviderConfiguration,
    ProviderRegistry,
)
from agent_core.research import (
    ExperimentRegistry,
    InformationGainEstimate,
    PublicSafeResearchPacketBuilder,
    ResearchBudgetManager,
    ResearchConfidence,
    ResearchReasoningEngine,
    ResearchStrategyAction,
    ResearchStrategyCandidate,
)
from test_phase4_research_orchestrator import research_state


class FakeRouter:
    def __init__(self, content):
        self.content = content
        self.ledger = ModelCallLedger()
        self.requests = []

    def route(self, request, policy):
        del policy
        self.requests.append(request)
        response = ModelResponse(
            provider="ollama",
            model="local-research-model",
            content=self.content,
            finish_reason="stop",
            input_tokens=10,
            output_tokens=10,
            total_tokens=20,
            estimated_cost_usd=0.0,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            hypothesis_id=request.hypothesis_id,
            requested_provider="ollama",
            requested_model="local-research-model",
        )
        self.ledger.record_success(response, fallback_depth=0)
        return response


def packet():
    return PublicSafeResearchPacketBuilder(
        ExperimentRegistry(), ResearchBudgetManager()
    ).build(research_state(), policy_limitations=("scope-is-fixed",))


def test_public_safe_packet_excludes_credentials_and_compile_only_primitives():
    value = packet().model_dump_json().lower()
    assert "vault_reference" not in value
    assert "authorization:" not in value
    assert "cookie" not in value
    names = {item["name"] for item in packet().available_execution_primitives}
    assert "header_mutation" not in names
    assert "cookie_mutation" not in names


def test_local_only_research_strategy_uses_router_ledger_and_stays_advisory():
    evidence = packet()
    candidate = ResearchStrategyCandidate(
        decision_id="decision-1",
        research_id="research-1",
        state_revision=0,
        action=ResearchStrategyAction.defer,
        selected_hypothesis_id="hypothesis-1",
        priority=90,
        confidence=ResearchConfidence.medium,
        expected_information_gain=InformationGainEstimate.high,
        reasoning_summary="The bounded differential has high information value.",
        evidence_references=("evidence-1",),
    )
    router = FakeRouter(json.dumps(candidate.model_dump(mode="json")))
    engine = ResearchReasoningEngine(router)
    decision = engine.decide(
        evidence,
        ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="local-research-model"),
        ),
    )
    assert decision.action is ResearchStrategyAction.defer
    assert decision.provenance.usage.successful_calls == 1
    assert router.requests[0].task_type == "research_strategy"
    assert router.requests[0].structured_output is True
    assert router.requests[0].structured_output_schema is not None
    schema = json.loads(router.requests[0].model_dump_json())[
        "structured_output_schema"
    ]
    assert schema["title"] == "ResearchStrategyCandidate"
    assert "proposals" in schema["properties"]
    assert not hasattr(decision, "execute")
    assert not hasattr(decision, "authorize")


def test_research_strategy_strict_parser_rejects_malformed_candidate():
    router = FakeRouter('{"research_id":"research-1"}')
    engine = ResearchReasoningEngine(router)
    with pytest.raises(Exception, match="invalid_output"):
        engine.decide(
            packet(),
            ModelRoutingPolicy(
                mode=RoutingMode.local_only,
                preferred=ModelRoute(provider="ollama", model="local-research-model"),
            ),
        )
    assert len(router.requests) == 1


def test_phase4_schema_reaches_ollama_native_format_unchanged():
    candidate = ResearchStrategyCandidate(
        decision_id="decision-schema",
        research_id="research-1",
        state_revision=0,
        action=ResearchStrategyAction.defer,
        priority=50,
        confidence=ResearchConfidence.medium,
        expected_information_gain=InformationGainEstimate.medium,
        reasoning_summary="No bounded proposal is selected in this fake response.",
    )

    class Response:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "message": {"content": json.dumps(candidate.model_dump(mode="json"))},
                "done": True,
                "prompt_eval_count": 7,
                "eval_count": 5,
            }

    reserved_output = []

    class Client:
        calls = []

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            reserved_output.append(
                router.ledger.usage_for_run("research-1").budget_output_tokens
            )
            return Response()

    client = Client()
    provider_configuration = ProviderConfiguration(
        model_name="local-research-model",
        base_url="http://127.0.0.1:11434",
        timeout_seconds=120,
        max_output_tokens=3072,
    )
    configuration = ModelConfiguration(ollama=provider_configuration)

    class ClientRegistry(ProviderRegistry):
        def create(self, provider=None, *, model_name=None, client_override=None):
            del client_override
            return super().create(provider, model_name=model_name, client=client)

    router = ModelRouter(ClientRegistry(configuration))
    decision = ResearchReasoningEngine(router, max_output_tokens=3072).decide(
        packet(),
        ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="local-research-model"),
        ),
    )
    transmitted = client.calls[0][1]["json"]
    assert isinstance(transmitted["format"], dict)
    assert transmitted["format"]["title"] == "ResearchStrategyCandidate"
    assert transmitted["format"] != "json"
    assert transmitted["options"]["num_predict"] == 3072
    assert client.calls[0][1]["timeout"] == 120
    usage = router.ledger.usage_for_run("research-1")
    assert reserved_output == [3072]
    assert usage.budget_output_tokens == 5
    assert usage.output_tokens == 5
    assert decision.provenance.usage.successful_calls == 1


@pytest.mark.parametrize(
    "forbidden",
    (
        "execute",
        "authorize",
        "confirm_vulnerability",
        "modify_policy",
        "increase_budget",
        "change_scope",
        "supply_credentials",
        "raw_request",
        "shell_command",
    ),
)
def test_strategy_contract_rejects_authority_and_credential_fields(forbidden):
    data = {
        "decision_id": "decision-1",
        "research_id": "research-1",
        "state_revision": 0,
        "action": "defer",
        "priority": 50,
        "confidence": "low",
        "expected_information_gain": "low",
        "reasoning_summary": "More bounded evidence is required.",
        forbidden: "forbidden",
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResearchStrategyCandidate.model_validate(data)
