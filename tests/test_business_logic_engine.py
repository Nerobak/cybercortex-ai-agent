from agent import process_user_input
from tools.business_logic_test_planner import plan_business_logic_tests
from tools.business_rule_analyzer import analyze_business_rules, compare_workflows
from tools.workflow_evidence_discovery import discover_workflow_evidence
from tools.workflow_model_builder import build_workflow_model
from tools.workflow_replay_checker import check_workflow_replay
from tools.workflow_transition_analyzer import analyze_workflow_transitions
from tool_registry import DESCRIPTIVE_FIELDS, TOOLS


def evidence():
    return {
        "workflow_name": "object creation",
        "steps": [
            {
                "sequence": 1,
                "method": "POST",
                "path": "/api/drafts",
                "actor": "controlled_account_a",
                "parameters": {"resource_id": "secret", "quantity": 1},
                "state_after": "draft",
                "body": {"password": "never-return"},
            },
            {
                "sequence": 2,
                "method": "PATCH",
                "path": "/api/drafts/123",
                "actor": "controlled_account_a",
                "parameters": {
                    "resource_id": "secret",
                    "approval": True,
                    "idempotency_key": "secret",
                },
                "state_before": "draft",
                "state_after": "ready",
            },
        ],
    }


def test_discovery_is_ordered_redacted_and_observational():
    result = discover_workflow_evidence(evidence())
    candidate = result["workflow_candidates"][0]
    assert candidate["confidence"] == "high"
    assert candidate["shared_identifiers"] == ["resource_id"]
    assert candidate["authentication_context_present"] is True
    assert candidate["network_tested"] is False
    assert candidate["vulnerability_status"] == "observation"
    assert "body" not in str(result).lower()
    assert "never-return" not in str(result)
    assert "secret" not in str(result)


def test_route_name_only_is_low_confidence_and_not_modeled():
    data = {"steps": [{"method": "GET", "path": "/checkout"}]}
    discovery = discover_workflow_evidence(data)
    assert discovery["workflow_candidates"][0]["confidence"] == "low"
    assert build_workflow_model(data)["status"] == "insufficient_evidence"


def test_model_and_transition_analysis_do_not_promote_findings():
    built = build_workflow_model(evidence())
    model = built["model"]
    assert [step["sequence"] for step in model["steps"]] == [1, 2]
    assert model["transitions"][0]["shared_identifiers"] == ["resource_id"]
    assert model["unknowns"] == ["server_side_enforcement"]
    analysis = analyze_workflow_transitions(built)
    kinds = {item["type"] for item in analysis["observations"]}
    assert "state_changing_operation_observed" in kinds
    assert "actor_boundary_observed" not in kinds
    assert "idempotency_metadata_observed" in kinds
    assert analysis["vulnerability_status"] == "observation"


def test_business_rules_are_observations_only():
    result = analyze_business_rules(build_workflow_model(evidence()))
    categories = {item["field_category"] for item in result["observations"]}
    assert {"quantity", "approval", "idempotency_key", "resource_id"} <= categories
    assert result["vulnerability_status"] == "observation"


def test_differential_analysis_redacts_values():
    other = evidence()
    other["steps"][1]["actor"] = "controlled_account_b"
    other["steps"][1]["state_after"] = "rejected"
    other["steps"][1]["response_summary"] = {"token": "private", "ok": False}
    result = compare_workflows(evidence(), other)
    assert result["actor_boundary_differences"]
    assert result["state_differences"]
    assert result["response_structure_differences"]
    assert "private" not in str(result)
    assert result["vulnerability_status"] == "observation"


def test_planner_requires_controls_and_blocks_sensitive_workflows():
    result = plan_business_logic_tests(build_workflow_model(evidence()))
    plan = result["plans"][0]
    assert plan["controlled_accounts_required"] is True
    assert plan["test_owned_resources_required"] is True
    assert plan["automatic_execution"] is False
    assert plan["stop_conditions"] and plan["prohibited_actions"]
    financial = evidence()
    financial["workflow_name"] = "checkout payment"
    assert (
        plan_business_logic_tests(build_workflow_model(financial))["status"]
        == "blocked_by_policy"
    )


def test_replay_disabled_and_policy_blocks_unsafe_requests():
    request = {
        "controlled_accounts_confirmed": True,
        "test_owned_resources_confirmed": True,
        "requests": [{"method": "POST", "url": "https://example.test/api/item"}],
    }
    assert check_workflow_replay(request, enabled=False)["status"] == "disabled"
    assert (
        check_workflow_replay(request, enabled=True, authenticated_profile=True)[
            "status"
        ]
        == "blocked_by_policy"
    )


def test_registry_metadata_and_explain_surface():
    names = {
        "workflow_evidence_discovery",
        "workflow_model_builder",
        "workflow_transition_analyzer",
        "business_rule_analyzer",
        "business_logic_test_planner",
        "workflow_replay_checker",
    }
    assert names <= TOOLS.keys()
    assert all(
        all(TOOLS[name].get(field) for field in DESCRIPTIVE_FIELDS) for name in names
    )
    assert "workflow_evidence_discovery" in process_user_input("workflow explain")
