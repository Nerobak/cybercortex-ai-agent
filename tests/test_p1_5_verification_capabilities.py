from __future__ import annotations

from pathlib import Path
from types import MethodType
from typing import Any

import pytest
from pydantic import ValidationError

import agent
from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.agent_models import (
    AssessmentPlan,
    Hypothesis,
    VerificationPlan,
    VerificationStep,
)
from agent_core.controlled_context import ControlledContext
from agent_core.controlled_executor import (
    EXECUTABLE_CATEGORIES,
    ControlledVerificationExecutor,
)
from agent_core.credential_vault import CredentialVault
from agent_core.hypothesis_engine import CATEGORY_PRIORITY, build_verification_plan
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_reporter import render_phase2_report
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.priority_engine import prioritize_hypothesis
from agent_core.request_budget import RequestBudget
from agent_core.result_provenance import controlled_executor_provenance
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    CapabilityState,
    VerificationCapability,
    get_verification_capability,
    request_cost_for,
    render_capability_markdown_table,
    resolve_verification_executor,
    resolve_verification_input_schema,
)
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from agent_core.verification_registry import ACTIVE_EXECUTION_ENABLED

EXPECTED_CATEGORIES = {
    "account_lifecycle",
    "api_authorization",
    "authentication_enforcement",
    "bola",
    "business_logic",
    "business_logic_state_enforcement",
    "cache_security",
    "command_injection",
    "excessive_data_exposure",
    "file_upload_validation",
    "graphql_authorization",
    "graphql_field_authorization",
    "graphql_mutation_authorization",
    "graphql_object_authorization",
    "injection",
    "jwt_enforcement",
    "mass_assignment",
    "oauth_oidc",
    "path_traversal",
    "property_authorization",
    "rate_limit_enforcement",
    "recovery_state_enforcement",
    "session_invalidation",
    "session_security",
    "sql_injection",
    "ssrf",
    "tenant_isolation",
    "upload_ownership",
    "upload_security",
    "vertical_authorization",
}

EXPECTED_COSTS = {
    "bola": (2, 5),
    "tenant_isolation": (2, 5),
    "vertical_authorization": (2, 4),
    "mass_assignment": (5, 6),
    "authentication_enforcement": (2, 3),
    "session_invalidation": (4, 4),
    "recovery_state_enforcement": (1, 5),
    "rate_limit_enforcement": (3, 7),
    "sql_injection": (3, 4),
    "command_injection": (3, 4),
    "path_traversal": (3, 4),
}


def _hypothesis(
    category: str,
    *,
    method: str = "GET",
    parameter: str | None = None,
    parameter_location: str | None = None,
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"hyp-{category}",
        category=category,
        title="Capability registry fixture",
        rationale="The fixture exercises capability metadata without network traffic.",
        target="https://capability.example/api",
        endpoint="https://capability.example/api",
        method=method,
        parameter=parameter,
        parameter_location=parameter_location,
        proposed_tools=["request_diff_engine"],
    )


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="p1-5-capability-test",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value="https://capability.example/api",
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        request_budget=100,
        per_host_request_budget=100,
        resolve_dns_before_request=False,
    )


def test_emitted_category_inventory_equals_the_registry_exactly():
    assert set(CATEGORY_PRIORITY) == EXPECTED_CATEGORIES
    assert set(CAPABILITY_REGISTRY) == EXPECTED_CATEGORIES
    assert len(CAPABILITY_REGISTRY) == 30


def test_documented_capability_table_is_generated_from_the_registry():
    documentation = Path("docs/PHASE2.md").read_text(encoding="utf-8")
    documented = documentation.split("<!-- BEGIN GENERATED PHASE2 CAPABILITIES -->", 1)[
        1
    ].split("<!-- END GENERATED PHASE2 CAPABILITIES -->", 1)[0]
    assert documented.strip() == render_capability_markdown_table()


def test_capability_model_is_strict_and_enforces_bounds():
    payload = get_verification_capability("bola").model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        VerificationCapability.model_validate(payload)
    payload.pop("unexpected")
    payload["automatic_execution"] = "true"
    with pytest.raises(ValidationError):
        VerificationCapability.model_validate(payload)
    payload = get_verification_capability("bola").model_dump(mode="python")
    payload["min_requests"] = 6
    payload["worst_case_requests"] = 5
    with pytest.raises(ValidationError):
        VerificationCapability.model_validate(payload)


def test_typed_routes_have_real_strict_schemas_and_provenance_versions():
    typed = {
        category
        for category, capability in CAPABILITY_REGISTRY.items()
        if capability.capability_state is CapabilityState.typed_verification
    }
    assert typed == set(EXECUTABLE_CATEGORIES) == set(EXPECTED_COSTS)
    for category in typed:
        capability = get_verification_capability(category)
        schema = resolve_verification_input_schema(category)
        executor = resolve_verification_executor(category)
        assert schema is not None
        assert schema.model_config.get("extra") == "forbid"
        assert schema.model_config.get("strict") is True
        assert executor is ControlledVerificationExecutor
        assert (
            capability.executor_version
            == controlled_executor_provenance(category)["version"]
        )


def test_plan_only_entries_have_no_typed_or_automatic_route():
    plan_only = [
        capability
        for capability in CAPABILITY_REGISTRY.values()
        if capability.capability_state is CapabilityState.plan_only
    ]
    assert len(plan_only) == 19
    assert all(not item.automatic_execution for item in plan_only)
    assert all(not item.executor_available for item in plan_only)
    assert all(item.input_schema is None for item in plan_only)
    assert all(item.worst_case_requests == 0 for item in plan_only)
    assert ACTIVE_EXECUTION_ENABLED is False


def test_request_costs_match_full_workflow_bounds_and_formulas():
    for category, expected in EXPECTED_COSTS.items():
        capability = get_verification_capability(category)
        assert (capability.min_requests, capability.worst_case_requests) == expected
    assert [
        request_cost_for("rate_limit_enforcement", rate_limit_attempts=n)
        for n in range(1, 6)
    ] == [
        3,
        4,
        5,
        6,
        7,
    ]
    assert (
        request_cost_for("recovery_state_enforcement", recovery_phase="issue_challenge")
        == 1
    )
    assert (
        request_cost_for(
            "recovery_state_enforcement",
            recovery_phase="resume_with_controlled_evidence",
        )
        == 3
    )
    assert (
        request_cost_for(
            "recovery_state_enforcement", recovery_phase="confirm_external_cleanup"
        )
        == 1
    )


def test_planner_uses_registry_cost_and_quarantines_fallback_requests():
    typed = VerificationPlanner().create_plan(
        _hypothesis("bola"),
        VerificationPlanningContext(target_class="dedicated_lab"),
    )
    assert typed.estimated_requests == 5
    assert typed.minimum_requests == 2
    assert typed.executor_version == "bola/v1"

    plan_only_hypothesis = _hypothesis("session_security")
    fallback = VerificationPlanner().create_plan(
        plan_only_hypothesis,
        VerificationPlanningContext(target_class="dedicated_lab"),
    )
    assert fallback.capability_state == "plan_only"
    assert fallback.automatic_execution_allowed is False
    assert fallback.estimated_requests == 0
    assert fallback.steps[0].network is False
    assert fallback.steps[0].metadata["requests"] == []
    assert fallback.steps[0].metadata["typed_adapter_required"] is True

    capture_fallback = build_verification_plan(
        plan_only_hypothesis,
        profile="authenticated",
        authorization_confirmed=True,
        credentials_supplied=False,
    )
    assert capture_fallback.capability_state == "plan_only"
    assert capture_fallback.estimated_requests == 0
    assert all(not step.network for step in capture_fallback.steps)


def test_adaptive_orchestrator_refuses_plan_only_execution():
    hypothesis = _hypothesis("session_security")
    plan = VerificationPlanner().create_plan(
        hypothesis, VerificationPlanningContext(target_class="dedicated_lab")
    )
    assessment = AssessmentPlan(
        run_id="run-plan-only",
        goal="prove registry preflight",
        target=hypothesis.target,
        profile="authenticated",
        hypotheses=[hypothesis],
        verification_plans=[plan],
    )
    calls: list[str] = []
    result = AdaptiveAssessmentOrchestrator().execute_allowed_plans(
        assessment,
        _policy(),
        executor=lambda *_args: calls.append("called") or {},
        authorization_confirmed=True,
    )
    assert calls == []
    assert result["results"][0]["status"] == "plan_only"
    assert result["requests_used"] == 0


def test_priority_ignores_stale_hypothesis_cost_and_uses_registry_truth():
    hypothesis = _hypothesis("bola")
    hypothesis.metadata["estimated_requests"] = 99
    result = prioritize_hypothesis(
        hypothesis,
        controlled_context={"controlled_accounts": ["owner", "comparator"]},
    )
    assert "registry worst-case request cost (+3)" in result["reasons"]


def test_cli_and_report_expose_registry_capability_truth():
    typed_hypothesis = _hypothesis("bola").model_dump(mode="json")
    plan_only_hypothesis = _hypothesis("session_security").model_dump(mode="json")
    explained = agent._hypothesis_explanation(typed_hypothesis)
    assert explained["capability_state"] == "typed_verification"
    assert explained["typed_executor_available"] is True
    assert explained["executor_version"] == "bola/v1"
    assert (explained["min_requests"], explained["worst_case_requests"]) == (2, 5)

    report = render_phase2_report(
        {"hypotheses": [typed_hypothesis, plan_only_hypothesis]}
    )
    assert "Capability: TYPED VERIFICATION AVAILABLE" in report
    assert "Capability: PLAN-ONLY" in report


def test_old_plans_without_capability_metadata_remain_readable():
    plan = VerificationPlan.model_validate(
        {
            "plan_id": "legacy-plan",
            "hypothesis_id": "legacy-hypothesis",
            "target": "https://capability.example/api",
            "profile": "baseline",
            "steps": [
                {
                    "step_id": "legacy-step",
                    "name": "legacy",
                    "tool": "manual",
                }
            ],
        }
    )
    assert plan.capability_state is None
    assert plan.estimated_requests == 0


@pytest.mark.parametrize("category", sorted(EXPECTED_COSTS))
def test_executor_request_delta_never_exceeds_registry_worst_case(category: str):
    capability = get_verification_capability(category)
    budget = RequestBudget(100)
    gate = DeterministicPolicyGate(
        _policy(),
        Phase2PolicyContext(mode="verify", target_class="dedicated_lab"),
        budget,
    )
    with CredentialVault() as vault:
        executor = ControlledVerificationExecutor(
            gate, vault, ControlledContext(), lambda _request: {}
        )

        def synthetic_execution(
            self: ControlledVerificationExecutor,
            _hypothesis: Hypothesis,
            _plan: VerificationPlan,
            **_kwargs: Any,
        ) -> dict[str, Any]:
            self.gate.budget.consume(
                "verification", count=capability.worst_case_requests
            )
            return {"status": "inconclusive"}

        executor._execute_once = MethodType(synthetic_execution, executor)  # type: ignore[method-assign]
        hypothesis = _hypothesis(category)
        plan = VerificationPlan(
            plan_id=f"plan-{category}",
            hypothesis_id=hypothesis.hypothesis_id,
            target=hypothesis.target,
            profile="baseline",
            steps=[VerificationStep(step_id="step", name="step", tool="typed")],
        )
        result = executor.execute(hypothesis, plan)
        assert result["request_delta"]["total"] == capability.worst_case_requests


def test_executor_detects_request_cost_registry_drift():
    capability = get_verification_capability("bola")
    budget = RequestBudget(100)
    gate = DeterministicPolicyGate(
        _policy(),
        Phase2PolicyContext(mode="verify", target_class="dedicated_lab"),
        budget,
    )
    with CredentialVault() as vault:
        executor = ControlledVerificationExecutor(
            gate, vault, ControlledContext(), lambda _request: {}
        )

        def over_budget(
            self: ControlledVerificationExecutor,
            _hypothesis: Hypothesis,
            _plan: VerificationPlan,
            **_kwargs: Any,
        ) -> dict[str, Any]:
            self.gate.budget.consume(
                "verification", count=capability.worst_case_requests + 1
            )
            return {"status": "inconclusive"}

        executor._execute_once = MethodType(over_budget, executor)  # type: ignore[method-assign]
        hypothesis = _hypothesis("bola")
        plan = VerificationPlan(
            plan_id="plan-bola",
            hypothesis_id=hypothesis.hypothesis_id,
            target=hypothesis.target,
            profile="baseline",
            steps=[VerificationStep(step_id="step", name="step", tool="typed")],
        )
        with pytest.raises(RuntimeError, match="capability bound"):
            executor.execute(hypothesis, plan)
