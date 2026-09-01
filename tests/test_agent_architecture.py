from __future__ import annotations

import json
from types import SimpleNamespace

from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.agent_models import (
    EvidenceRequirement,
    Hypothesis,
    RiskLevel,
)
from agent_core.attack_surface import AttackSurfaceGraph
from agent_core.audit_log import TamperEvidentAuditLog
from agent_core.capture_ingest import (
    CapturedIdentity,
    apply_capture_context,
    import_capture,
)
from agent_core.capture_executor import CapturedMutation, execute_captured_differential
from agent_core.hardened_executor import SubprocessToolExecutor
from agent_core.hypothesis_engine import (
    build_verification_plan,
    generate_hypotheses,
    propose_llm_hypotheses,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset, compile_policy
from agent_core.verification_gate import (
    VerificationEvidence,
    grade_verification,
    normalize_volatile_fields,
)
from evaluation.lab import EvalObservation, calculate_metrics
from evaluation.lab import EvalCase, EvaluationLab
from evaluation.replay_app import evaluate_replay_case


def _policy(**overrides):
    values = {
        "authorization_confirmed": True,
        "authorization_reference": "test authorization record",
        "allowed_assets": [
            ScopeAsset(
                kind="url_prefix",
                value="https://authorized.example/api",
                schemes=["https"],
                ports=[443],
            )
        ],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "credentials_allowed": True,
        "controlled_account_ids": ["account-a", "account-b"],
        "request_budget": 30,
    }
    values.update(overrides)
    return AssessmentPolicy(**values)


def test_policy_compiler_is_fail_closed_and_path_boundary_aware():
    try:
        compile_policy({"authorization_confirmed": True})
        assert False
    except ValueError:
        pass
    policy = _policy()
    assert policy.authorize_url("https://authorized.example/api/users?id=1").allowed
    assert not policy.authorize_url("https://authorized.example/application").allowed
    assert not policy.authorize_url("https://evil.example/api").allowed
    assert not policy.authorize_url(
        "https://authorized.example/api/users", method="POST"
    ).allowed


def test_policy_requires_cleanup_test_ownership_and_distinct_accounts():
    hypothesis = Hypothesis(
        hypothesis_id="hyp_mass",
        category="mass_assignment",
        title="Sensitive property may be assignable",
        rationale="Role field observed in JSON.",
        target="https://authorized.example/api/users/1",
        endpoint="https://authorized.example/api/users/1",
        method="POST",
        parameter="role",
        parameter_location="json",
        proposed_tools=["request_replay_engine"],
        state_changing=True,
        cleanup_required=True,
        risk=RiskLevel.moderate,
    )
    plan = build_verification_plan(
        hypothesis,
        profile="authenticated",
        authorization_confirmed=True,
        credentials_supplied=True,
        controlled_accounts=["account-a"],
    )
    policy = _policy(
        allowed_methods=["GET", "POST"],
        allow_state_changes=True,
    )
    blocked = policy.authorize_plan(plan)
    assert not blocked.allowed
    assert any("test-owned" in reason for reason in blocked.reasons)
    plan.test_owned_resources = ["test-object-1"]
    assert policy.authorize_plan(plan).allowed


def test_har_capture_is_sanitized_and_models_distinct_sessions(tmp_path):
    capture = tmp_path / "traffic.har"
    capture.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://authorized.example/api/users?id=1",
                                "headers": [
                                    {
                                        "name": "Authorization",
                                        "value": "Bearer PRIVATE-A",
                                    }
                                ],
                            },
                            "response": {
                                "status": 200,
                                "content": {
                                    "mimeType": "application/json",
                                    "size": 20,
                                    "text": '{"id":1,"email":"a@b"}',
                                },
                            },
                        },
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://authorized.example/api/users/2",
                                "headers": [
                                    {
                                        "name": "Authorization",
                                        "value": "Bearer PRIVATE-B",
                                    },
                                    {
                                        "name": "Content-Type",
                                        "value": "application/json",
                                    },
                                ],
                                "postData": {
                                    "mimeType": "application/json",
                                    "text": '{"role":"admin","profile":{"name":"test"}}',
                                },
                            },
                            "response": {"status": 200, "content": {"size": 0}},
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    bundle, vault = import_capture(capture)
    try:
        rendered = json.dumps(bundle.model_dump(mode="json"))
        assert "PRIVATE-A" not in rendered and "PRIVATE-B" not in rendered
        assert len(bundle.identities) == 2
        locations = {
            parameter.location
            for request in bundle.requests
            for parameter in request.parameters
        }
        assert {"query", "json"} <= locations
        assert bundle.requests[1].state_changing is True
    finally:
        vault.close()


def test_openapi_and_graphql_capture_locations(tmp_path):
    openapi = tmp_path / "openapi.json"
    openapi.write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "servers": [{"url": "https://authorized.example"}],
                "paths": {
                    "/api/users/{id}": {
                        "patch": {
                            "parameters": [
                                {
                                    "name": "id",
                                    "in": "path",
                                    "required": True,
                                    "schema": {"type": "string"},
                                }
                            ],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "role": {"type": "string"},
                                                "tenant_id": {"type": "string"},
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    bundle, vault = import_capture(openapi)
    vault.close()
    locations = {item.location for item in bundle.requests[0].parameters}
    assert locations == {"path", "json"}
    graphql = tmp_path / "query.graphql"
    graphql.write_text(
        "mutation UpdateUser($id: ID!, $role: String!) { updateUser(id: $id, role: $role) { id } }",
        encoding="utf-8",
    )
    graph_bundle, graph_vault = import_capture(
        graphql, default_base_url="https://authorized.example/api/graphql"
    )
    graph_vault.close()
    assert graph_bundle.requests[0].graphql_operation == "UpdateUser"
    assert all(
        item.location == "graphql_variable"
        for item in graph_bundle.requests[0].parameters
    )


def test_context_and_hypothesis_priority_follow_bug_bounty_order(tmp_path):
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /api/users?id=7&url=https%3A%2F%2Fcallback.invalid HTTP/1.1\n"
        "Host: authorized.example\nAuthorization: Bearer PRIVATE\n\n",
        encoding="utf-8",
    )
    bundle, vault = import_capture(raw)
    try:
        apply_capture_context(
            bundle,
            {
                "identities": [
                    {
                        "captured_label": "captured-session",
                        "label": "account-a",
                        "controlled": True,
                    },
                    {"label": "account-b", "controlled": True},
                ]
            },
        )
        hypotheses = generate_hypotheses(bundle)
        categories = [item.category for item in hypotheses]
        assert "bola" in categories and "ssrf" in categories
        assert categories.index("bola") < categories.index("ssrf")
    finally:
        vault.close()


def test_attack_surface_graph_persists_nodes_edges_and_changes(tmp_path):
    graph = AttackSurfaceGraph(tmp_path / "surface.sqlite3")
    graph.start_run("run-1", "https://authorized.example/api", "baseline")
    counts = graph.ingest_assessment(
        "run-1",
        {
            "target": "https://authorized.example/api",
            "normalized_urls": {
                "all_urls": ["https://authorized.example/api/users?id=1"]
            },
            "evidence_package": {
                "observations": [
                    {
                        "title": "Observed route",
                        "endpoint": "https://authorized.example/api/users?id=1",
                        "source_tool": "endpoint_analyzer",
                    }
                ]
            },
        },
    )
    graph.finish_run("run-1", "completed", counts)
    snapshot = graph.snapshot("https://authorized.example/api")
    assert snapshot["node_counts"]["endpoint"] >= 1
    assert snapshot["node_counts"]["parameter"] == 1
    assert snapshot["edge_count"] >= 2
    assert graph.changed_nodes("run-1")
    graph.start_run("run-2", "https://authorized.example/api", "baseline")
    node_id = graph.upsert_node(
        "endpoint",
        "https://authorized.example/api/users?id=1",
        {
            "url": "https://authorized.example/api/users?id=1",
            "methods": ["GET", "PATCH"],
        },
        run_id="run-2",
    )
    changed = {item["node_id"]: item for item in graph.changed_nodes("run-2")}
    assert changed[node_id]["is_changed"] is True


def test_adaptive_planner_policy_blocks_ssrf_without_oast(tmp_path):
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /api/items?id=1&url=https%3A%2F%2Fexample.invalid HTTP/1.1\n"
        "Host: authorized.example\nAuthorization: Bearer PRIVATE\n\n",
        encoding="utf-8",
    )
    bundle, vault = import_capture(raw)
    try:
        bundle.identities[0].controlled = True
        bundle.identities.append(
            CapturedIdentity(
                identity_id="account-b", label="account-b", controlled=True
            )
        )
        orchestrator = AdaptiveAssessmentOrchestrator(
            graph=AttackSurfaceGraph(tmp_path / "surface.sqlite3"),
            audit_log=TamperEvidentAuditLog(tmp_path / "audit.jsonl"),
        )
        plan = orchestrator.plan_from_bundle(
            bundle,
            _policy(),
            goal="Authorized assessment",
            controlled_accounts=[bundle.identities[0].identity_id, "account-b"],
        )
        bola = next(
            item
            for item in plan.verification_plans
            if any(step.metadata.get("category") == "bola" for step in item.steps)
        )
        ssrf = next(
            item
            for item in plan.verification_plans
            if any(step.metadata.get("category") == "ssrf" for step in item.steps)
        )
        assert bola.policy_decision == "allowed"
        assert ssrf.policy_decision == "blocked"
    finally:
        vault.close()


def test_verification_gate_requires_repeatability_identity_and_cleanup():
    evidence = VerificationEvidence(
        repetitions=[
            {"status": 200, "timestamp": "2026-01-01T00:00:00Z"},
            {"status": 200, "timestamp": "2026-01-02T00:00:00Z"},
        ],
        owner_identity="a",
        non_owner_identity="b",
        object_identifier="object-1",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )
    assert normalize_volatile_fields(evidence.repetitions[0]) == {"status": 200}
    assert grade_verification("bola", evidence)["status"] == "verified"
    evidence.separate_accounts_confirmed = False
    assert grade_verification("bola", evidence)["status"] == "needs_manual_verification"
    stateful = VerificationEvidence(
        repetitions=[{"effect": True}, {"effect": True}],
        ownership_confirmed=True,
        cleanup_required=True,
        cleanup_succeeded=False,
    )
    assert grade_verification("mass_assignment", stateful)["verified"] is False
    stateful.cleanup_succeeded = True
    assert grade_verification("mass_assignment", stateful)["verified"] is True


def test_audit_chain_and_eval_safety_metrics(tmp_path):
    audit = TamperEvidentAuditLog(tmp_path / "audit.jsonl")
    audit.append("one", {"Authorization": "PRIVATE"}, run_id="run")
    audit.append("two", {"status": "completed"}, run_id="run")
    contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "PRIVATE" not in contents
    assert audit.verify()["valid"] is True
    metrics = calculate_metrics(
        [
            EvalObservation(
                case_id="one",
                expected_vulnerable=True,
                expected_category="bola",
                predicted_verified=True,
                predicted_category="bola",
                reproduced=True,
                requests_used=4,
                elapsed_ms=5,
                time_to_first_verified_ms=5,
                scope_violations=0,
                unauthorized_state_changes=0,
            )
        ]
    )
    assert metrics["verified_vulnerability_precision"] == 1.0
    assert metrics["safety_gate_passed"] is True


def test_subprocess_executor_terminates_timed_out_tool():
    executor = SubprocessToolExecutor()
    result = executor.execute(
        "ai_report_writer",
        ("https://authorized.example", {}),
        {},
        timeout=0.001,
    )
    assert result.status == "timed_out"
    assert result.terminated is True


def test_llm_hypotheses_are_strictly_validated_against_capture(tmp_path):
    raw = tmp_path / "request.txt"
    raw.write_text(
        "GET /api/users?id=7 HTTP/1.1\nHost: authorized.example\n\n",
        encoding="utf-8",
    )
    bundle, vault = import_capture(raw)
    try:
        request = bundle.requests[0]
        valid = Hypothesis(
            hypothesis_id="hyp_llm",
            category="bola",
            title="Object authorization hypothesis",
            rationale="Captured id parameter may identify an object.",
            target=request.url,
            endpoint=request.url,
            parameter="id",
            parameter_location="query",
            proposed_tools=["authorization_differential_tester"],
            evidence_refs=[request.request_id],
            evidence_requirements=[
                EvidenceRequirement(
                    kind="controlled_identity_differential",
                    description="Use two known controlled identities.",
                )
            ],
        )
        accepted = propose_llm_hypotheses(
            bundle, lambda prompt: json.dumps([valid.model_dump(mode="json")])
        )
        assert [item.hypothesis_id for item in accepted] == ["hyp_llm"]
        invented = valid.model_copy(update={"target": "https://evil.example"})
        assert (
            propose_llm_hypotheses(
                bundle, lambda prompt: json.dumps([invented.model_dump(mode="json")])
            )
            == []
        )
    finally:
        vault.close()


def test_captured_differential_supports_json_and_requires_cleanup(tmp_path):
    raw = tmp_path / "request.txt"
    raw.write_text(
        "PATCH /api/users/7 HTTP/1.1\n"
        "Host: authorized.example\n"
        "Authorization: Bearer PRIVATE\n"
        "Content-Type: application/json\n\n"
        '{"role":"member","profile":{"name":"test"}}',
        encoding="utf-8",
    )
    bundle, vault = import_capture(raw)
    request = bundle.requests[0]
    calls = []

    def requester(method, url, **kwargs):
        calls.append((method, url, kwargs))
        mutated = b'"admin"' in kwargs.get("data", b"")
        return SimpleNamespace(
            content=(b'{"accepted":true}' if mutated else b'{"accepted":false}'),
            status_code=200,
            headers={"Content-Type": "application/json"},
            encoding="utf-8",
            is_redirect=False,
            is_permanent_redirect=False,
            url=url,
        )

    policy = _policy(
        allowed_methods=["GET", "PATCH"],
        allow_state_changes=True,
        resolve_dns_before_request=False,
        requests_per_second=100,
    )
    try:
        blocked = execute_captured_differential(
            request,
            vault,
            policy,
            CapturedMutation("role", "json", "admin"),
            authorization_confirmed=True,
            test_owned_resources=["user-7"],
            requester=requester,
        )
        assert blocked["success"] is False and "cleanup" in blocked["error"].lower()
        result = execute_captured_differential(
            request,
            vault,
            policy,
            CapturedMutation("role", "json", "admin"),
            authorization_confirmed=True,
            test_owned_resources=["user-7"],
            cleanup=lambda: True,
            requester=requester,
        )
        assert result["success"] is True
        assert result["status"] == "needs_manual_verification"
        assert result["requests_used"] == 4
        assert result["cleanup_succeeded"] is True
        assert "PRIVATE" not in json.dumps(result)
    finally:
        vault.close()


def test_replay_application_evaluates_vulnerable_and_secure_bola():
    result = EvaluationLab(
        [
            EvalCase(
                case_id="vulnerable",
                expected_vulnerable=True,
                expected_category="broken_access_control",
                input={"scenario": "bola_vulnerable"},
            ),
            EvalCase(
                case_id="secure",
                expected_vulnerable=False,
                expected_category="broken_access_control",
                input={"scenario": "bola_secure"},
            ),
        ]
    ).run(evaluate_replay_case)
    assert result["metrics"]["verified_vulnerability_precision"] == 1.0
    assert result["metrics"]["verified_vulnerability_recall"] == 1.0
    assert result["metrics"]["scope_violations"] == 0
