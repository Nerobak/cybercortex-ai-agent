import json

import pytest
from pydantic import ValidationError

from agent_core.models import (
    ModelCallLedger,
    ModelResponse,
    ModelRoute,
    ModelRoutingPolicy,
    RoutingMode,
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
    assert not hasattr(decision, "execute")
    assert not hasattr(decision, "authorize")


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
