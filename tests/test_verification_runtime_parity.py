from __future__ import annotations

import inspect
import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import requests

import agent
import phase2_cli
from agent_core import verification_runtime as runtime_module
from agent_core.agent_models import Hypothesis, VerificationPlan, VerificationStep
from agent_core.controlled_context import ControlledAccount, ControlledContext
from agent_core.controlled_executor import (
    COMMAND_EXECUTION_MARKER,
    COMMAND_PROBE_VALUE,
    SQL_PROBE_VALUE,
    TRAVERSAL_FIXTURE_MARKER,
    TRAVERSAL_PROBE_VALUE,
)
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.rate_limit_enforcement import (
    classify_rate_limit_sequence,
    safe_rate_limit_response_summary,
)
from agent_core.request_budget import RequestBudget
from agent_core.result_normalizer import public_result
from agent_core.verification_runtime import (
    VerificationHTTPTransport,
    build_verification_policy_context,
    canonical_target_class,
    comparable_verification_result,
    create_verification_runtime,
    select_verification_inputs,
    stage_verification_inputs,
)
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

TARGET = "https://parity.example"
EXECUTABLE_CATEGORIES = (
    "bola",
    "tenant_isolation",
    "vertical_authorization",
    "mass_assignment",
    "authentication_enforcement",
    "session_invalidation",
    "recovery_state_enforcement",
    "rate_limit_enforcement",
    "sql_injection",
    "command_injection",
    "path_traversal",
)


def _policy(
    *,
    authorization_confirmed: bool = True,
    request_budget: int = 30,
) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=authorization_confirmed,
        authorization_reference=("runtime-parity" if authorization_confirmed else None),
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        credentials_allowed=True,
        allow_state_changes=True,
        require_test_owned_resources=False,
        require_cleanup_for_state_changes=True,
        allow_bounded_rate_limit_verification=True,
        max_rate_limit_attempts=3,
        request_budget=request_budget,
        per_host_request_budget=request_budget,
        requests_per_second=100,
        resolve_dns_before_request=False,
    )


def _hypothesis_and_plan(category: str) -> tuple[Hypothesis, VerificationPlan]:
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-{category}",
        category=category,
        title=f"{category} runtime parity",
        rationale="The selected hypothesis must cross one shared runtime boundary.",
        target=TARGET,
        endpoint=f"{TARGET}/resource",
        method="GET",
        parameter=(
            "q"
            if category in {"sql_injection", "command_injection", "path_traversal"}
            else None
        ),
        parameter_location=(
            "query"
            if category in {"sql_injection", "command_injection", "path_traversal"}
            else None
        ),
        safe_verification_possible=True,
    )
    plan = VerificationPlan(
        plan_id=f"plan-{category}",
        hypothesis_id=hypothesis.hypothesis_id,
        target=TARGET,
        profile="baseline",
        steps=[
            VerificationStep(
                step_id=f"step-{category}",
                name="Shared typed verification",
                tool="controlled_verification_executor",
                network=False,
                request_cost=0,
                metadata={"requests": []},
            )
        ],
        request_budget=20,
        authorization_confirmed=True,
        automatic_execution_allowed=True,
    )
    return hypothesis, plan


def _response(
    *,
    status: int = 200,
    body: Any = None,
    headers: dict[str, str] | None = None,
    elapsed_ms: int = 125,
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps({"ok": True} if body is None else body).encode(
        "utf-8"
    )
    response._content_consumed = True
    response.headers.update(headers or {})
    response.elapsed = timedelta(milliseconds=elapsed_ms)
    return response


def _runtime_pair(
    tmp_path: Path,
    *,
    policy: AssessmentPolicy | None = None,
    verification_inputs: Any = None,
    requester=None,
    parent_run: dict[str, Any] | None = None,
    controlled_context: ControlledContext | None = None,
):
    selected_policy = policy or _policy()
    context = controlled_context or ControlledContext()
    inputs = {} if verification_inputs is None else verification_inputs
    vault_a = CredentialVault()
    vault_b = CredentialVault()
    budget_a = RequestBudget(
        selected_policy.request_budget,
        per_host_limit=selected_policy.per_host_request_budget,
    )
    budget_b = RequestBudget(
        selected_policy.request_budget,
        per_host_limit=selected_policy.per_host_request_budget,
    )
    client_a = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget_a,
        requester=requester or (lambda *_args, **_kwargs: _response()),
    )
    client_b = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget_b,
        requester=requester or (lambda *_args, **_kwargs: _response()),
    )
    standalone = create_verification_runtime(
        policy=selected_policy,
        controlled_context=context,
        vault=vault_a,
        verification_inputs=inputs,
        target=TARGET,
        target_class="dedicated_lab",
        store=Phase2RunStore(tmp_path / "standalone"),
        budget=budget_a,
        network_client=client_a,
        parent_run=parent_run,
    )
    scan = create_verification_runtime(
        policy=selected_policy,
        controlled_context=context,
        vault=vault_b,
        verification_inputs=inputs,
        target=TARGET,
        target_class="dedicated_lab",
        store=Phase2RunStore(tmp_path / "scan"),
        budget=budget_b,
        network_client=client_b,
        parent_run=parent_run,
    )
    gate = DeterministicPolicyGate(
        selected_policy,
        build_verification_policy_context(context, target_class="dedicated_lab"),
        budget_b,
    )
    return standalone, scan, gate, vault_a, vault_b


def test_both_public_entry_paths_visibly_reuse_one_runtime_factory():
    standalone_source = inspect.getsource(phase2_cli.run_verification_command)
    scan_source = inspect.getsource(agent.run_scan_command)

    assert "create_verification_runtime(" in standalone_source
    assert "create_verification_runtime(" in scan_source
    assert "ScopedHTTPClient" not in standalone_source
    assert "ScopedHTTPClient" not in scan_source
    assert "def transport" not in standalone_source
    assert "def transport" not in scan_source


def test_target_class_aliases_have_one_strict_internal_representation():
    assert canonical_target_class() == "external"
    assert canonical_target_class(lab=True) == "local_range"
    assert canonical_target_class(dedicated_lab=True) == "dedicated_lab"
    with pytest.raises(ValueError):
        canonical_target_class(lab=True, dedicated_lab=True)
    with pytest.raises(ValueError):
        canonical_target_class(lab=1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("account_ids", "expected"),
    (([], True), (["controlled-a"], True), (["different-account"], False)),
)
def test_both_entry_paths_share_account_eligibility_decisions(
    tmp_path: Path, account_ids: list[str], expected: bool
):
    policy = _policy().model_copy(update={"controlled_account_ids": account_ids})
    context = ControlledContext(
        accounts=[ControlledAccount(account_id="controlled-a", controlled=True)]
    )
    standalone, scan, _gate, vault_a, vault_b = _runtime_pair(
        tmp_path,
        policy=policy,
        controlled_context=context,
    )
    try:
        standalone_decision = policy.account_is_eligible(
            "controlled-a", standalone.policy_context
        )
        scan_decision = policy.account_is_eligible("controlled-a", scan.policy_context)
    finally:
        vault_a.close()
        vault_b.close()

    assert standalone.policy_context == scan.policy_context
    assert standalone_decision == scan_decision
    assert standalone_decision.eligible is expected


@pytest.mark.parametrize("category", EXECUTABLE_CATEGORIES)
def test_all_executable_categories_cross_the_same_runtime_contract(
    category: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    observed: list[dict[str, Any]] = []

    class SpyExecutor:
        def __init__(self, gate, vault, context, transport, **kwargs):
            observed.append(
                {
                    "policy": gate.policy,
                    "policy_context": gate.context.model_dump(mode="json"),
                    "transport_type": type(transport),
                    "transport_client_type": type(transport.client),
                    "context": context.model_dump(mode="json"),
                    "private_store_type": type(kwargs["private_recovery_store"]),
                    "vault": vault,
                }
            )

        def execute(self, hypothesis, plan, *, inputs, prior_result, run_id):
            return {
                "status": "inconclusive",
                "reasons": ["Equivalent deterministic fixture."],
                "request_delta": {
                    "discovery": 0,
                    "auth": 0,
                    "verification": 0,
                    "cleanup": 0,
                    "attempted": 0,
                    "total": 0,
                },
                "requests_used": 0,
                "executor": {
                    "name": "ControlledVerificationExecutor",
                    "version": f"{hypothesis.category}/v1",
                    "implementation_family": "phase2_controlled_execution",
                },
                "result_schema_version": 2,
                "selected_inputs": inputs,
                "prior_stage": (prior_result or {}).get("recovery_phase"),
                "run_binding": run_id,
            }

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        lambda _category: SpyExecutor,
    )
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path,
        verification_inputs={
            "defaults": {"safe_label": "shared"},
            "hypotheses": {f"hyp-{category}": {"category_label": category}},
        },
    )
    hypothesis, plan = _hypothesis_and_plan(category)
    try:
        standalone_result = standalone.execute_selected(
            hypothesis, plan, run_id="run-parity"
        )
        scan.phase2_run_id = "run-parity"
        scan_result = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert comparable_verification_result(
        standalone_result
    ) == comparable_verification_result(scan_result)
    assert standalone_result["selected_inputs"] == {
        "safe_label": "shared",
        "category_label": category,
    }
    assert standalone_result["request_delta"] == scan_result["request_delta"]
    assert standalone_result["requests_used"] == scan_result["requests_used"] == 0
    assert observed[0]["policy"] is observed[1]["policy"]
    assert observed[0]["policy_context"] == observed[1]["policy_context"]
    assert observed[0]["context"] == observed[1]["context"]
    assert observed[0]["transport_type"] is VerificationHTTPTransport
    assert observed[0]["transport_type"] is observed[1]["transport_type"]
    assert observed[0]["transport_client_type"] is ScopedHTTPClient
    assert observed[0]["private_store_type"] is observed[1]["private_store_type"]


def test_malformed_input_is_the_same_zero_traffic_policy_block_on_both_paths(
    tmp_path: Path,
):
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path, verification_inputs=[]
    )
    hypothesis, plan = _hypothesis_and_plan("bola")
    try:
        standalone_result = standalone.execute_selected(hypothesis, plan)
        scan_result = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert comparable_verification_result(
        standalone_result
    ) == comparable_verification_result(scan_result)
    assert standalone_result["status"] == scan_result["status"] == "policy_blocked"
    assert (
        standalone_result["reasons"]
        == scan_result["reasons"]
        == ["Verification input is invalid for the selected typed capability."]
    )
    assert standalone_result["request_delta"]["total"] == 0
    assert scan_result["request_delta"]["total"] == 0


def test_response_adapter_and_rate_limit_metadata_are_identical(tmp_path: Path):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Retry-After": "3",
        "RateLimit-Remaining": "0",
        "X-RateLimit-Limit": "5",
        "Set-Cookie": "session=CCX_COOKIE_PARITY; Secure; HttpOnly; SameSite=Lax",
        "Authorization": "Bearer CCX_AUTH_PARITY",
    }

    def requester(*_args, **_kwargs):
        return _response(
            status=429,
            body={"error": "too many requests"},
            headers=headers,
            elapsed_ms=650,
        )

    standalone, scan, _gate, vault_a, vault_b = _runtime_pair(
        tmp_path, requester=requester
    )
    request = {
        "method": "GET",
        "url": f"{TARGET}/resource",
        # The classifier-facing response shape is transport-purpose agnostic.
        # The typed rate-limit executor separately supplies the stricter POST
        # sequence context required by ScopedHTTPClient.
        "purpose": "verification",
        "credential_mode": "anonymous",
    }
    try:
        response_a = standalone.transport(request)
        response_b = scan.transport(request)
    finally:
        vault_a.close()
        vault_b.close()

    assert response_a == response_b
    assert response_a["headers"] == {
        "Content-Type": "application/json; charset=utf-8",
        "Retry-After": "3",
        "RateLimit-Remaining": "0",
        "X-RateLimit-Limit": "5",
    }
    assert response_a["elapsed_ms"] == 650
    assert response_a["content_type"] == "application/json"
    assert response_a["cookie_metadata"] == {
        "cookie_present": True,
        "cookie_count": 1,
        "cookie_names": ["session"],
        "secure": True,
        "http_only": True,
        "same_site": ["lax"],
    }
    assert "CCX_COOKIE_PARITY" not in json.dumps(public_result(response_a))
    assert "CCX_AUTH_PARITY" not in json.dumps(public_result(response_a))
    summaries = [
        safe_rate_limit_response_summary(value) for value in (response_a, response_b)
    ]
    assert summaries[0] == summaries[1]
    assert summaries[0]["retry_after_value_class"] == "delta_seconds"
    assert summaries[0]["rate_limit_header_value_classes"] == {
        "ratelimit-remaining": "zero",
        "x-ratelimit-limit": "integer",
    }
    assert summaries[0]["coarse_latency_bucket"] == "500_to_1999ms"
    assert classify_rate_limit_sequence(
        [summaries[0]], summaries[0], within_attempts=1
    ) == classify_rate_limit_sequence([summaries[1]], summaries[1], within_attempts=1)


def test_ambient_cookies_and_credential_headers_are_isolated_identically(
    tmp_path: Path,
):
    captured_a: list[dict[str, Any]] = []
    captured_b: list[dict[str, Any]] = []

    def requester_a(_method, _url, **kwargs):
        captured_a.append(kwargs)
        return _response()

    def requester_b(_method, _url, **kwargs):
        captured_b.append(kwargs)
        return _response()

    policy = _policy()
    context = ControlledContext()
    vault_a = CredentialVault()
    vault_b = CredentialVault()
    budget_a = RequestBudget(10, per_host_limit=10)
    budget_b = RequestBudget(10, per_host_limit=10)
    client_a = ScopedHTTPClient(policy=policy, budget=budget_a, requester=requester_a)
    client_b = ScopedHTTPClient(policy=policy, budget=budget_b, requester=requester_b)
    client_a.session.cookies.set("ambient", "CCX_AMBIENT_A")
    client_b.session.cookies.set("ambient", "CCX_AMBIENT_B")
    runtimes = [
        create_verification_runtime(
            policy=policy,
            controlled_context=context,
            vault=vault,
            verification_inputs={},
            target=TARGET,
            target_class="dedicated_lab",
            store=Phase2RunStore(tmp_path / name),
            budget=budget,
            network_client=client,
        )
        for name, vault, budget, client in (
            ("a", vault_a, budget_a, client_a),
            ("b", vault_b, budget_b, client_b),
        )
    ]
    anonymous = {
        "method": "GET",
        "url": f"{TARGET}/resource",
        "purpose": "verification",
        "credential_mode": "anonymous",
        "headers": {
            "Authorization": "Bearer CCX_HEADER_AUTH",
            "Cookie": "sid=CCX_HEADER_COOKIE",
            "Accept": "application/json",
        },
    }
    try:
        runtimes[0].transport(anonymous)
        runtimes[1].transport(anonymous)
    finally:
        vault_a.close()
        vault_b.close()

    for captured, client in ((captured_a, client_a), (captured_b, client_b)):
        assert captured[0]["headers"] == {"Accept": "application/json"}
        assert len(client.session.cookies) == 0


def test_input_secret_staging_and_selection_are_shared_and_non_mutating():
    raw = {
        "defaults": {"safe_label": "default"},
        "hypotheses": {
            "hyp-a": {"safe_label": "specific"},
            "hyp-secrets": {
                "rate_limit": {
                    "invalid_password": "CCX_RATE_INPUT_SECRET",
                },
                "recovery": {
                    "code": "CCX_RECOVERY_INPUT_SECRET",
                    "temporary_password": "CCX_TEMP_INPUT_SECRET",
                },
            },
        },
    }
    original = json.loads(json.dumps(raw))
    with CredentialVault() as vault_a, CredentialVault() as vault_b:
        staged_a = stage_verification_inputs(raw, vault_a)
        staged_b = stage_verification_inputs(raw, vault_b)

    assert raw == original
    assert select_verification_inputs(staged_a, "hyp-a") == select_verification_inputs(
        staged_b, "hyp-a"
    )
    rendered_a = json.dumps(public_result(staged_a))
    rendered_b = json.dumps(public_result(staged_b))
    for sentinel in (
        "CCX_RATE_INPUT_SECRET",
        "CCX_RECOVERY_INPUT_SECRET",
        "CCX_TEMP_INPUT_SECRET",
    ):
        assert sentinel not in rendered_a
        assert sentinel not in rendered_b


@pytest.mark.parametrize(
    "inputs",
    [
        {"parameter_location": "query"},
        {"safe_probe_semantics_confirmed": "false"},
    ],
)
def test_malformed_input_has_identical_zero_traffic_failure(
    inputs: dict[str, Any], tmp_path: Path
):
    calls: list[tuple[Any, ...]] = []

    def requester(*args, **_kwargs):
        calls.append(args)
        return _response()

    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path, verification_inputs=inputs, requester=requester
    )
    hypothesis, plan = _hypothesis_and_plan("sql_injection")
    try:
        result_a = standalone.execute_selected(hypothesis, plan)
        result_b = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert comparable_verification_result(result_a) == comparable_verification_result(
        result_b
    )
    assert result_a["status"] == "policy_blocked"
    assert result_a["request_delta"]["total"] == result_b["requests_used"] == 0
    assert calls == []


@pytest.mark.parametrize(
    ("category", "probe_evidence", "expected_status"),
    [
        ("sql_injection", SQL_PROBE_VALUE, "inconclusive"),
        ("command_injection", COMMAND_EXECUTION_MARKER, "verified"),
        ("path_traversal", TRAVERSAL_FIXTURE_MARKER, "verified"),
    ],
)
def test_equivalent_live_probe_evidence_has_same_classification_and_delta(
    category: str,
    probe_evidence: str,
    expected_status: str,
    tmp_path: Path,
):
    calls: list[dict[str, Any]] = []

    def requester(method, url, **kwargs):
        values = parse_qs(urlparse(url).query).get("q", [])
        supplied = values[0] if values else ""
        calls.append({"method": method, "url": url, **kwargs})
        if supplied in {
            SQL_PROBE_VALUE,
            COMMAND_PROBE_VALUE,
            TRAVERSAL_PROBE_VALUE,
        }:
            return _response(body=probe_evidence)
        return _response(body="stable-control")

    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path, requester=requester
    )
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-live-{category}",
        category=category,
        title=f"{category} bounded parity probe",
        rationale="One safe lab fixture is compared through both runtime paths.",
        target=f"{TARGET}/resource",
        endpoint=f"{TARGET}/resource",
        method="GET",
        parameter="q",
        parameter_location="query",
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(target_class="dedicated_lab"),
    )
    try:
        result_a = standalone.execute_selected(hypothesis, plan)
        result_b = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert result_a["status"] == result_b["status"] == expected_status
    assert (
        result_a["request_delta"]
        == result_b["request_delta"]
        == {
            "discovery": 0,
            "auth": 0,
            "verification": 3,
            "cleanup": 0,
            "attempted": 3,
            "total": 3,
        }
    )
    assert result_a["requests_used"] == result_b["requests_used"] == 3
    assert comparable_verification_result(result_a) == comparable_verification_result(
        result_b
    )
    assert [item["url"] for item in calls[:3]] == [item["url"] for item in calls[3:]]


def test_transport_exception_has_identical_reason_and_attempt_delta(tmp_path: Path):
    def requester(*_args, **_kwargs):
        raise requests.ConnectionError(
            "failed Authorization: Bearer CCX_TRANSPORT_SECRET"
        )

    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path, requester=requester
    )
    request = {
        "method": "GET",
        "url": f"{TARGET}/resource",
        "purpose": "verification",
        "credential_mode": "anonymous",
    }
    outcomes = []
    try:
        for transport, budget in (
            (standalone.transport, standalone.budget),
            (scan.transport, scan.budget),
        ):
            before = budget.snapshot()
            with pytest.raises(requests.ConnectionError) as raised:
                transport(request)
            after = budget.snapshot()
            outcomes.append((str(raised.value), before, after))
    finally:
        vault_a.close()
        vault_b.close()

    assert outcomes[0] == outcomes[1]
    assert outcomes[0][2]["verification_requests"] == 1
    assert "CCX_TRANSPORT_SECRET" not in json.dumps(public_result(outcomes[0][0]))
    assert gate.budget is scan.budget


def test_budget_and_policy_denials_are_zero_transport_in_both_paths(tmp_path: Path):
    calls: list[tuple[Any, ...]] = []

    def requester(*args, **_kwargs):
        calls.append(args)
        return _response()

    request = {
        "method": "GET",
        "url": f"{TARGET}/resource",
        "purpose": "verification",
        "credential_mode": "anonymous",
    }
    standalone, scan, _gate, vault_a, vault_b = _runtime_pair(
        tmp_path / "budget", policy=_policy(request_budget=1), requester=requester
    )
    try:
        standalone.budget.consume("discovery", host="parity.example")
        scan.budget.consume("discovery", host="parity.example")
        messages = []
        for transport in (standalone.transport, scan.transport):
            with pytest.raises(PolicyViolationError) as raised:
                transport(request)
            messages.append(str(raised.value))
    finally:
        vault_a.close()
        vault_b.close()
    assert messages[0] == messages[1] == "Global request budget exhausted."
    assert calls == []

    blocked, blocked_scan, _gate, vault_a, vault_b = _runtime_pair(
        tmp_path / "policy",
        policy=_policy(authorization_confirmed=False),
        requester=requester,
    )
    try:
        policy_messages = []
        for transport in (blocked.transport, blocked_scan.transport):
            with pytest.raises(PolicyViolationError) as raised:
                transport(request)
            policy_messages.append(str(raised.value))
    finally:
        vault_a.close()
        vault_b.close()
    assert policy_messages[0] == policy_messages[1]
    assert calls == []


def test_recovery_prior_stage_selection_is_identical_and_private_store_is_shared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    parent = {
        "run_id": "run-recovery",
        "target": TARGET,
        "verification_results": [
            {
                "hypothesis_id": "hyp-recovery_state_enforcement",
                "category": "recovery_state_enforcement",
                "recovery_phase": "verification_pending_cleanup",
            }
        ],
    }
    priors: list[Any] = []

    class RecoverySpy:
        def __init__(self, _gate, _vault, _context, _transport, **kwargs):
            assert kwargs["private_recovery_store"] is not None

        def execute(self, _hypothesis, _plan, *, prior_result, **_kwargs):
            priors.append(prior_result)
            return {
                "status": "verification_pending_cleanup",
                "recovery_phase": "verification_pending_cleanup",
                "request_delta": {
                    "discovery": 0,
                    "auth": 0,
                    "verification": 0,
                    "cleanup": 0,
                    "attempted": 0,
                    "total": 0,
                },
                "requests_used": 0,
            }

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        lambda _category: RecoverySpy,
    )
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path, parent_run=parent
    )
    hypothesis, plan = _hypothesis_and_plan("recovery_state_enforcement")
    try:
        result_a = standalone.execute_selected(hypothesis, plan)
        result_b = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert priors == [parent["verification_results"][0]] * 2
    assert comparable_verification_result(result_a) == comparable_verification_result(
        result_b
    )
    assert "preserved_challenge" not in json.dumps(public_result(result_a))


def test_shared_runtime_results_persist_with_equivalent_provenance_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    class ProvenanceSpy:
        def __init__(self, *_args, **_kwargs):
            pass

        def execute(self, hypothesis, _plan, **_kwargs):
            return {
                "status": "inconclusive",
                "confidence": "low",
                "reasons": ["Equivalent persisted result."],
                "request_delta": {
                    "discovery": 0,
                    "auth": 0,
                    "verification": 0,
                    "cleanup": 0,
                    "attempted": 0,
                    "total": 0,
                },
                "requests_used": 0,
                "result_schema_version": 2,
                "executor": {
                    "name": "ControlledVerificationExecutor",
                    "version": f"{hypothesis.category}/v1",
                    "implementation_family": "phase2_controlled_execution",
                },
            }

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        lambda _category: ProvenanceSpy,
    )
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(tmp_path)
    hypothesis, plan = _hypothesis_and_plan("sql_injection")
    try:
        results = [
            standalone.execute_selected(hypothesis, plan, run_id="run-parity"),
            scan(hypothesis, plan, gate),
        ]
    finally:
        vault_a.close()
        vault_b.close()

    persisted = []
    for name, result in zip(("standalone", "scan"), results, strict=True):
        store = Phase2RunStore(tmp_path / f"persisted-{name}")
        run = {
            "run_id": "run-parity",
            "target": TARGET,
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_results": [result],
        }
        store.save(run)
        persisted.append(run["verification_results"][0])

    assert persisted[0]["result_id"] != persisted[1]["result_id"]
    assert persisted[0]["result_hash"] == persisted[1]["result_hash"]
    assert persisted[0]["executor"] == persisted[1]["executor"]
    assert persisted[0]["request_delta"] == persisted[1]["request_delta"]
    assert comparable_verification_result(
        persisted[0]
    ) == comparable_verification_result(persisted[1])
