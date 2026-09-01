from __future__ import annotations

import json

import pytest

from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.attack_surface import (
    CanonicalAttackSurface,
    build_canonical_attack_surface,
)
from agent_core.benchmark_exporter import build_benchmark_export, export_benchmark
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    SessionAcquirer,
    SessionAcquisition,
)
from agent_core.credential_vault import CredentialVault
from agent_core.differential_analyzer import (
    analyze_cross_account_access,
    analyze_role_authorization,
    analyze_state_change,
)
from agent_core.hypothesis_engine import generate_surface_hypotheses
from agent_core.phase2_policy import (
    DeterministicPolicyGate,
    Phase2PolicyContext,
    VerificationAction,
)
from agent_core.phase2_reporter import render_phase2_report
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.priority_engine import rank_hypotheses
from agent_core.request_budget import RequestBudget, RequestBudgetExceeded
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)


def _policy(**overrides) -> AssessmentPolicy:
    values = {
        "authorization_confirmed": True,
        "authorization_reference": "synthetic test authorization",
        "allowed_assets": [
            ScopeAsset(
                kind="url_prefix",
                value="https://authorized.example/api",
                schemes=["https"],
                ports=[443],
            )
        ],
        "allowed_methods": ["GET", "HEAD", "OPTIONS", "PATCH", "POST"],
        "credentials_allowed": True,
        "allow_state_changes": True,
        "request_budget": 20,
    }
    values.update(overrides)
    return AssessmentPolicy(**values)


def _surface() -> CanonicalAttackSurface:
    return CanonicalAttackSurface(
        target="https://authorized.example/api",
        routes=[
            {"method": "GET", "path": "/orders/{order_id}", "source": "openapi"},
            {
                "method": "GET",
                "path": "/tenants/{tenant_id}/projects",
                "source": "openapi",
            },
            {"method": "PATCH", "path": "/users/me", "source": "openapi"},
            {"method": "GET", "path": "/admin/audit", "source": "crawler"},
        ],
        parameters=[
            {
                "name": "order_id",
                "in": "path",
                "method": "GET",
                "path": "/orders/{order_id}",
                "source": "openapi_parameter",
                "evidence_refs": ["schema-1"],
            },
            {
                "name": "tenant_id",
                "in": "path",
                "method": "GET",
                "path": "/tenants/{tenant_id}/projects",
                "source": "openapi_parameter",
                "evidence_refs": ["schema-2"],
            },
            {
                "field_path": "role",
                "in": "request_body",
                "method": "PATCH",
                "path": "/users/me",
                "source": "openapi_request_body",
                "evidence_refs": ["schema-3"],
            },
        ],
    )


def test_surface_evidence_generates_initial_authorization_hypotheses():
    hypotheses = generate_surface_hypotheses(_surface())
    categories = {item.category for item in hypotheses}
    assert {
        "bola",
        "tenant_isolation",
        "mass_assignment",
        "vertical_authorization",
    } <= categories
    assert all(item.status.value == "proposed" for item in hypotheses)
    assert all(
        "does not establish runtime" in " ".join(item.limitations).lower()
        for item in hypotheses
    )


def test_route_and_schema_names_never_verify_findings():
    hypotheses = generate_surface_hypotheses(_surface())
    bola = next(item for item in hypotheses if item.category == "bola")
    mass = next(item for item in hypotheses if item.category == "mass_assignment")
    admin = next(
        item for item in hypotheses if item.category == "vertical_authorization"
    )
    assert bola.status.value == "proposed"
    assert mass.status.value == "proposed"
    assert admin.confidence == "low"


def test_business_logic_summary_and_root_get_do_not_create_workflow_hypothesis():
    surface = build_canonical_attack_surface(
        "https://authorized.example",
        assessment={
            "observed_surface": {
                "attack_surface": {
                    "routes": [{"method": "GET", "path": "/"}],
                },
                "business_logic": {
                    "workflow_candidates": 0,
                    "modeled_workflows": 0,
                    "steps_observed": 0,
                    "transitions_observed": 0,
                    "replay_status": "not_applicable",
                },
            }
        },
    )

    categories = {item.category for item in generate_surface_hypotheses(surface)}

    assert "business_logic_state_enforcement" not in categories


def test_ordered_state_changing_workflow_creates_workflow_hypothesis():
    surface = CanonicalAttackSurface(
        target="https://authorized.example",
        workflows=[
            {
                "name": "draft approval",
                "steps": [
                    {"sequence": 1, "method": "POST", "path": "/drafts"},
                    {
                        "sequence": 2,
                        "method": "PATCH",
                        "path": "/drafts/{id}",
                        "state_before": "draft",
                        "state_after": "ready",
                    },
                ],
                "transitions": [{"from_step": "step_1", "to_step": "step_2"}],
            }
        ],
    )

    hypothesis = next(
        item
        for item in generate_surface_hypotheses(surface)
        if item.category == "business_logic_state_enforcement"
    )

    assert hypothesis.method == "PATCH"
    assert hypothesis.target_surface["path"] == "/drafts/{id}"


def test_priority_prefers_evidence_safe_impact_over_route_speculation():
    hypotheses = generate_surface_hypotheses(_surface())
    ranked = rank_hypotheses(
        hypotheses,
        controlled_context={"controlled_accounts": ["a", "b"]},
        corroboration={hypotheses[0].hypothesis_id: 2},
    )
    assert ranked[0].metadata["priority"] == 1
    assert ranked[0].metadata["priority_score"] >= ranked[-1].metadata["priority_score"]
    bola_score = next(
        item.metadata["priority_score"] for item in ranked if item.category == "bola"
    )
    route_score = next(
        item.metadata["priority_score"]
        for item in ranked
        if item.category == "vertical_authorization"
    )
    assert bola_score > route_score


def test_policy_blocks_scope_third_party_delete_budget_and_non_verify():
    budget = RequestBudget(2)
    gate = DeterministicPolicyGate(
        _policy(),
        Phase2PolicyContext(
            mode="plan",
            target_class="local_range",
            controlled_account_ids=["a", "b"],
        ),
        budget,
    )
    action = VerificationAction(
        url="https://outside.example/api/orders/1",
        method="DELETE",
        category="bola",
        account_id="a",
        object_owner_account_id="third-party",
        test_owned_resource=True,
        credential_reference_present=True,
    )
    decision = gate.authorize_action(action)
    assert not decision.allowed
    text = " ".join(decision.reasons).lower()
    assert "authorized asset" in text
    assert "destructive" in text
    assert "third-party" in text
    assert "verify mode" in text
    budget.consume("verification", 2)
    with pytest.raises(RequestBudgetExceeded):
        budget.consume("verification")


def test_external_mutation_and_lab_only_injection_are_blocked():
    gate = DeterministicPolicyGate(
        _policy(),
        Phase2PolicyContext(
            mode="verify",
            target_class="external",
            controlled_account_ids=["a"],
        ),
        RequestBudget(10),
    )
    mutation = VerificationAction(
        url="https://authorized.example/api/users/me",
        method="PATCH",
        category="mass_assignment",
        account_id="a",
        object_owner_account_id="a",
        credential_reference_present=True,
        test_owned_resource=True,
    )
    injection = mutation.model_copy(
        update={"method": "GET", "category": "sql_injection"}
    )
    assert not gate.authorize_action(mutation).allowed
    assert not gate.authorize_action(injection).allowed


def test_session_acquisition_uses_vault_policy_and_auth_budget():
    vault = CredentialVault()
    try:
        account = ControlledAccount(
            account_id="a",
            credential_references={
                "username": vault.put("controlled-user", label="username"),
                "password": vault.put("private-password", label="password"),
            },
        )
        budget = RequestBudget(2)
        policy = _policy(controlled_account_ids=["a"])
        gate = DeterministicPolicyGate(
            policy,
            Phase2PolicyContext(
                mode="verify",
                target_class="local_range",
                controlled_account_ids=["a"],
                session_acquisition_url="https://authorized.example/api/sessions",
                session_acquisition_method="POST",
            ),
            budget,
        )
        sent = []

        def sender(request):
            sent.append(request)
            return {"body": {"token": "private-session-token"}}

        acquired = SessionAcquirer(vault, budget).acquire(
            account,
            SessionAcquisition(url="https://authorized.example/api/sessions"),
            sender,
            authorization_check=gate.authorize_session_acquisition,
        )
        assert acquired.session_reference
        assert budget.snapshot()["auth_requests"] == 1
        assert "private-session-token" not in json.dumps(
            acquired.model_dump(mode="json")
        )
        assert sent[0]["json"]["username"] == "controlled-user"
    finally:
        vault.close()


def test_200_vs_200_without_protected_data_is_inconclusive():
    response = {"status_code": 200, "body": {"id": "object-a", "name": "public"}}
    result = analyze_cross_account_access(
        response,
        response,
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=[],
    )
    assert result["status"] == "inconclusive"
    assert result["verified"] is False


def test_cross_account_protected_data_verifies_and_sanitized_denial_rejects():
    owner = {
        "status_code": 200,
        "body": {"id": "object-a", "email": "owner@example.test"},
    }
    candidate = {
        "status_code": 200,
        "body": {"id": "object-a", "email": "owner@example.test"},
    }
    result = analyze_cross_account_access(
        owner,
        candidate,
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )
    assert result["status"] == "verified"
    assert "owner@example.test" not in json.dumps(result)
    denied = analyze_cross_account_access(
        owner,
        {"status_code": 403, "body": {"error": "forbidden"}},
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )
    assert denied["status"] == "rejected"


def test_vertical_authorization_requires_confirmed_roles_and_protected_data():
    admin = {"status_code": 200, "body": {"audit": [{"email": "a@example.test"}]}}
    normal = {"status_code": 200, "body": {"audit": [{"email": "a@example.test"}]}}
    verified = analyze_role_authorization(
        admin,
        normal,
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_data_confirmed=True,
    )
    assert verified["status"] == "verified"
    public = analyze_role_authorization(
        {"status_code": 200, "body": {"message": "public"}},
        {"status_code": 200, "body": {"message": "public"}},
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_fields=[],
    )
    assert public["status"] == "inconclusive"


def test_mass_assignment_requires_persistence_and_cleanup():
    result = analyze_state_change(
        {"status_code": 200, "body": {"role": "user"}},
        {"status_code": 200, "body": {"role": "admin"}},
        field="role",
        requested_value="admin",
        field_control_authorized=False,
        cleanup_succeeded=True,
    )
    assert result["status"] == "verified"
    assert (
        analyze_state_change(
            {"status_code": 200, "body": {"role": "user"}},
            {"status_code": 200, "body": {"role": "user"}},
            field="role",
            requested_value="admin",
            field_control_authorized=False,
            cleanup_succeeded=True,
        )["status"]
        == "rejected"
    )


def test_planner_defines_minimal_requests_expectations_and_cleanup():
    mass = next(
        item
        for item in generate_surface_hypotheses(_surface())
        if item.category == "mass_assignment"
    )
    plan = VerificationPlanner().create_plan(
        mass,
        VerificationPlanningContext(
            controlled_accounts=["a"],
            credential_accounts=["a"],
            test_owned_resources=["user-a"],
        ),
    )
    assert plan.estimated_requests == 6
    assert plan.minimum_requests == 5
    assert plan.expected_secure_behavior
    assert plan.expected_vulnerable_behavior
    assert "state before/after" in plan.evidence_to_compare
    assert plan.cleanup
    assert plan.automatic_execution_allowed is False


def test_verify_mode_routes_mass_assignment_through_deferred_runtime_binding():
    surface = CanonicalAttackSurface(
        target="https://authorized.example/api",
        routes=[{"method": "PATCH", "path": "/users/me", "source": "openapi"}],
        parameters=[
            {
                "field_path": "role",
                "in": "request_body",
                "method": "PATCH",
                "path": "/users/me",
                "source": "openapi_request_body",
                "evidence_refs": ["schema-mass-runtime-binding"],
            }
        ],
    )
    context = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="alice",
                role="member",
                credential_references={"token": "runtime-token-reference"},
            )
        ],
        objects=[
            ControlledObject(
                object_id="users/me",
                owner_account_id="alice",
                object_type="user_profile",
                test_owned=True,
            )
        ],
    )
    calls = []

    def executor(hypothesis, plan, gate):
        calls.append(hypothesis.category)
        assert plan.automatic_execution_allowed is True
        return {
            "status": "inconclusive",
            "requests_used": 0,
            "runtime_binding": {
                "required_accounts": 1,
                "bound_accounts": 1,
                "owner_bound": True,
                "comparator_bound": False,
                "policy_authorized": True,
            },
        }

    executor.defers_runtime_policy_authorization = True

    result = AdaptiveAssessmentOrchestrator().run_phase2(
        surface,
        _policy(controlled_account_ids=["alice"]),
        mode="verify",
        target_class="local_range",
        controlled_context=context,
        executor=executor,
    )

    assert calls == ["mass_assignment"]
    plan = result["verification_plans"][0]
    assert plan["policy_decision"] == "allowed"
    assert plan["automatic_execution_allowed"] is True


def test_plan_mode_keeps_runtime_accounts_and_objects_out_of_templates():
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="a", credential_references={"token": "ref-a"}),
            ControlledAccount(account_id="b", credential_references={"token": "ref-b"}),
        ],
        objects=[ControlledObject(object_id="order-a", owner_account_id="a")],
    )

    result = AdaptiveAssessmentOrchestrator().run_phase2(
        _surface(),
        _policy(),
        mode="plan",
        target_class="local_range",
        controlled_context=context,
    )

    assert result["verification_plans"]
    for plan in result["verification_plans"]:
        assert plan["controlled_accounts"] == []
        assert plan["test_owned_resources"] == []
        assert plan["credentials_supplied"] is False
        assert plan["policy_decision"] == "pending"
        assert plan["automatic_execution_allowed"] is False
        for step in plan["steps"]:
            for request in step["metadata"].get("requests", []):
                assert request.get("account_id") is None
                assert request.get("object_owner_account_id") is None


def test_adaptive_loop_plans_gates_executes_and_updates_status(tmp_path):
    surface = CanonicalAttackSurface(
        target="https://authorized.example/api",
        routes=[{"method": "GET", "path": "/orders/{order_id}"}],
        parameters=[
            {
                "name": "order_id",
                "in": "path",
                "method": "GET",
                "path": "/orders/{order_id}",
                "evidence_refs": ["openapi-1"],
            }
        ],
    )
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="a", credential_references={"token": "ref-a"}),
            ControlledAccount(account_id="b", credential_references={"token": "ref-b"}),
        ],
        objects=[ControlledObject(object_id="order-a", owner_account_id="a")],
    )

    def executor(hypothesis, plan, gate):
        assert plan.automatic_execution_allowed is True
        assert gate.authorize_plan(plan).allowed
        gate.budget.consume("verification", 2)
        return {
            "status": "verified",
            "verified": True,
            "confidence": "high",
            "requests_used": 2,
            "evidence_summary": ["controlled protected object differential"],
        }

    result = AdaptiveAssessmentOrchestrator(
        graph=None,
    ).run_phase2(
        surface,
        _policy(),
        mode="verify",
        target_class="local_range",
        controlled_context=context,
        executor=executor,
    )
    assert result["hypotheses"][0]["status"] == "verified"
    assert result["verification_plans"][0]["policy_decision"] == "allowed"
    assert result["verification_results"][0]["status"] == "verified"
    assert result["metrics"]["verification_requests"] == 2
    assert result["stop_reason"] == "hypotheses exhausted"


def test_benchmark_export_schema_metrics_and_integrity(tmp_path):
    run = {
        "run_id": "run-1",
        "target": "https://authorized.example/api",
        "model": "local-model",
        "hypotheses": [
            {
                "hypothesis_id": "hyp-1",
                "category": "bola",
                "status": "verified",
                "confidence": "high",
                "target_surface": {"method": "GET", "path": "/orders/{id}"},
                "evidence_basis": [{"observation": "identifier observed"}],
            }
        ],
        "verification_results": [
            {
                "hypothesis_id": "hyp-1",
                "status": "verified",
                "confidence": "high",
                "evidence_summary": ["controlled protected data differential"],
                "requests_used": 2,
            }
        ],
        "metrics": {
            "duration_seconds": 1.25,
            "request_count": 2,
            "model_calls": 0,
            "hypotheses_generated": 1,
            "hypotheses_verified": 1,
            "hypotheses_rejected": 0,
            "pivots": 0,
        },
    }
    payload = build_benchmark_export(run)
    assert payload["assessment_mode"] == "observe"
    assert payload["findings"][0]["status"] == "verified"
    assert payload["metrics"]["request_count"] == 2
    output = tmp_path / "benchmark.json"
    export_benchmark(run, output)
    assert json.loads(output.read_text(encoding="utf-8")) == payload
    with pytest.raises(ValueError):
        build_benchmark_export({**run, "ground_truth_id": "forbidden"})


def test_phase2_report_has_required_separation():
    report = render_phase2_report(
        {
            "attack_surface": _surface().model_dump(mode="json"),
            "hypotheses": [
                item.model_dump(mode="json")
                for item in generate_surface_hypotheses(_surface())
            ],
            "verification_results": [],
        }
    )
    assert "## Attack Surface" in report
    assert "## Security Hypotheses" in report
    assert "## Planned Verification" in report
    assert "## Verification Results" in report
    assert "## Verified Findings" in report
    assert "No evidence-backed verified findings" in report
