from __future__ import annotations

from types import MethodType
from typing import Any

import pytest
import requests
from pydantic import ValidationError

from agent_core.agent_models import Hypothesis, VerificationPlan, VerificationStep
from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    SessionAcquisition,
)
from agent_core.controlled_executor import (
    COMMAND_EXECUTION_MARKER,
    EXECUTABLE_CATEGORIES,
    TRAVERSAL_FIXTURE_MARKER,
    ControlledVerificationExecutor,
)
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_campaign import build_campaign_export
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import (
    RequestBudget,
    RequestDelta,
    canonical_result_request_total,
)
from agent_core.result_normalizer import public_result
from agent_core.verification_capabilities import get_verification_capability
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

TARGET = "https://delta.example/api"
EXPECTED_EXECUTORS = {
    "bola",
    "tenant_isolation",
    "vertical_authorization",
    "authentication_enforcement",
    "mass_assignment",
    "session_invalidation",
    "recovery_state_enforcement",
    "rate_limit_enforcement",
    "sql_injection",
    "command_injection",
    "path_traversal",
}


def _policy(*, request_budget: int = 20) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="request-delta-test",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST", "PATCH"],
        credentials_allowed=True,
        controlled_account_ids=["alice"],
        allow_state_changes=True,
        request_budget=request_budget,
        per_host_request_budget=request_budget,
        resolve_dns_before_request=False,
    )


def _hypothesis_and_plan(category: str) -> tuple[Hypothesis, VerificationPlan]:
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-{category}",
        category=category,
        title="Canonical request attribution",
        rationale="Every controlled result receives an authoritative request delta.",
        target=TARGET,
        endpoint=TARGET,
    )
    plan = VerificationPlan(
        plan_id=f"plan-{category}",
        hypothesis_id=hypothesis.hypothesis_id,
        target=TARGET,
        profile="baseline",
        steps=[VerificationStep(step_id="one", name="one", tool="controlled")],
    )
    return hypothesis, plan


@pytest.mark.parametrize(
    "payload",
    [
        {
            "discovery": True,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 1,
            "total": 1,
        },
        {
            "discovery": -1,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 0,
            "total": 0,
        },
        {
            "discovery": 1,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 1,
            "total": 2,
        },
        {
            "discovery": 0,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 1,
            "total": 0,
        },
        {
            "discovery": 0,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 0,
            "total": 0,
            "extra": 1,
        },
    ],
)
def test_request_delta_is_strict_and_enforces_exact_invariants(payload: dict[str, Any]):
    with pytest.raises(ValidationError):
        RequestDelta.model_validate(payload)


def test_request_delta_is_frozen():
    delta = RequestDelta(
        discovery=1,
        auth=1,
        verification=1,
        cleanup=1,
        attempted=4,
        total=4,
    )
    with pytest.raises(ValidationError):
        delta.total = 5


def test_every_active_executor_uses_one_snapshot_delta_without_prior_traffic():
    assert EXECUTABLE_CATEGORIES == EXPECTED_EXECUTORS
    policy = _policy(request_budget=100)
    budget = RequestBudget(100)
    gate = DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(mode="verify", target_class="dedicated_lab"),
        budget,
    )
    budget.consume("discovery", count=2)

    with CredentialVault() as vault:
        executor = ControlledVerificationExecutor(
            gate, vault, ControlledContext(), lambda _request: {}
        )

        def fake_execute_once(
            self: ControlledVerificationExecutor,
            _hypothesis: Hypothesis,
            _plan: VerificationPlan,
            **_kwargs: Any,
        ) -> dict[str, Any]:
            declared = get_verification_capability(_hypothesis.category)
            request_kinds = ["discovery", "auth", "verification", "cleanup"]
            for kind in request_kinds[: declared.worst_case_requests]:
                self.gate.budget.consume(kind)
            return {"status": "inconclusive", "requests_used": 999}

        executor._execute_once = MethodType(fake_execute_once, executor)  # type: ignore[method-assign]
        for category in sorted(EXPECTED_EXECUTORS):
            hypothesis, plan = _hypothesis_and_plan(category)
            result = executor.execute(hypothesis, plan)
            expected_total = min(
                4, get_verification_capability(category).worst_case_requests
            )
            assert result["request_delta"]["total"] == expected_total
            assert result["request_delta"]["attempted"] == expected_total
            assert result["requests_used"] == expected_total


def test_transport_exception_is_an_attempt_but_pretransport_blocks_are_not():
    policy = _policy(request_budget=2)
    budget = RequestBudget(2)

    def requester(*_args: Any, **_kwargs: Any):
        raise RuntimeError("synthetic transport failure")

    client = ScopedHTTPClient(policy=policy, budget=budget, requester=requester)
    before = budget.snapshot()
    with pytest.raises(RuntimeError, match="synthetic transport failure"):
        client.request("GET", TARGET, purpose="verification")
    assert RequestDelta.from_snapshots(before, budget.snapshot()) == RequestDelta(
        verification=1, attempted=1, total=1
    )

    blocked_before = budget.snapshot()
    with pytest.raises(PolicyViolationError):
        client.request("GET", "https://outside.example/api", purpose="verification")
    assert RequestDelta.from_snapshots(blocked_before, budget.snapshot()).total == 0

    budget.consume("verification")
    exhausted_before = budget.snapshot()
    with pytest.raises(PolicyViolationError, match="budget exhausted"):
        client.request("GET", TARGET, purpose="verification")
    assert RequestDelta.from_snapshots(exhausted_before, budget.snapshot()).total == 0


def test_cleanup_transport_kind_preserves_typed_session_authorization():
    policy = _policy(request_budget=2)
    budget = RequestBudget(2)

    def requester(method: str, url: str, **_kwargs: Any) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response.url = url
        response._content = b"{}"
        response._content_consumed = True
        return response

    client = ScopedHTTPClient(policy=policy, budget=budget, requester=requester)
    before = budget.snapshot()
    client.request(
        "POST",
        TARGET,
        purpose="cleanup",
        request_context={
            "purpose": "cleanup",
            "policy_authorized": True,
            "configured_url": TARGET,
            "configured_method": "POST",
            "configured_endpoint_match": True,
            "controlled_account_id": "alice",
            "account_controlled": True,
            "account_policy_authorized": True,
        },
    )
    assert RequestDelta.from_snapshots(before, budget.snapshot()) == RequestDelta(
        cleanup=1, attempted=1, total=1
    )


@pytest.mark.parametrize(
    ("category", "probe_body", "inputs"),
    [
        ("sql_injection", "sql-differential", {"safe_probe_semantics_confirmed": True}),
        ("command_injection", COMMAND_EXECUTION_MARKER, {}),
        ("path_traversal", TRAVERSAL_FIXTURE_MARKER, {}),
    ],
)
def test_bounded_probe_optional_login_is_included_in_delta(
    category: str, probe_body: str, inputs: dict[str, Any]
):
    login_url = f"{TARGET}/sessions"
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-login-{category}",
        category=category,
        title="Authenticated bounded probe",
        rationale="Optional authentication must be part of result cost.",
        target=f"{TARGET}/search",
        endpoint=f"{TARGET}/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        requires_credentials=True,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            target_class="dedicated_lab",
            controlled_accounts=["alice"],
            credential_accounts=["alice"],
        ),
    )
    calls: list[dict[str, Any]] = []
    with CredentialVault() as vault:
        context = ControlledContext(
            accounts=[
                ControlledAccount(
                    account_id="alice",
                    credential_references={
                        "username": vault.put("alice", label="username"),
                        "password": vault.put("password", label="password"),
                    },
                )
            ],
            session_acquisition=SessionAcquisition(url=login_url, method="POST"),
        )
        policy = _policy()
        gate = DeterministicPolicyGate(
            policy,
            Phase2PolicyContext(
                mode="verify",
                target_class="dedicated_lab",
                controlled_account_ids=["alice"],
                session_acquisition_url=login_url,
                session_acquisition_method="POST",
            ),
            RequestBudget(20),
        )

        def transport(request: dict[str, Any]) -> dict[str, Any]:
            calls.append(request)
            if request["url"] == login_url:
                return {"status_code": 200, "body": {"token": "session-token"}}
            probe_index = len([item for item in calls if item["url"] != login_url])
            body = probe_body if probe_index == 2 else "stable-control"
            return {"status_code": 200, "body": body}

        result = ControlledVerificationExecutor(
            gate, vault, context, transport
        ).execute(hypothesis, plan, inputs=inputs)

    assert len(calls) == 4
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 1,
        "verification": 3,
        "cleanup": 0,
        "attempted": 4,
        "total": 4,
    }
    assert result["requests_used"] == 4


def test_canonical_total_prefers_delta_and_marks_conservative_legacy_sources():
    exact = {
        "request_delta": {
            "discovery": 0,
            "auth": 2,
            "verification": 1,
            "cleanup": 0,
            "attempted": 3,
            "total": 3,
        },
        "requests_used": 99,
    }
    assert canonical_result_request_total(exact) == (3, "request_delta_v1")
    assert canonical_result_request_total({"requests_used": 4}) == (
        4,
        "legacy_requests_used",
    )
    assert canonical_result_request_total(
        {"request_counts": {"total_network_requests": 5}}
    ) == (5, "legacy_typed_request_counts")
    assert canonical_result_request_total(
        {"request_budget": {"total_requests": 8}}
    ) == (
        0,
        "legacy_unknown",
    )


def test_campaign_and_benchmark_use_selected_delta_not_cumulative_snapshot():
    delta = {
        "discovery": 0,
        "auth": 2,
        "verification": 1,
        "cleanup": 0,
        "attempted": 3,
        "total": 3,
    }
    hypothesis = {
        "hypothesis_id": "hyp-bola",
        "category": "bola",
        "status": "verified",
        "confidence": "high",
        "method": "GET",
        "parameter": "id",
        "target_surface": {"method": "GET", "path": "/api", "parameter": "id"},
    }
    result = {
        "hypothesis_id": "hyp-bola",
        "category": "bola",
        "status": "verified",
        "confidence": "high",
        "request_delta": delta,
        "requests_used": 100,
        "request_budget": {"total_requests": 100},
    }
    run = {
        "run_id": "run-delta",
        "target": TARGET,
        "assessment_mode": "verify",
        "hypotheses": [hypothesis],
        "verification_results": [result],
        "metrics": {"total_requests": 100},
    }
    campaign = {
        "campaign_id": "campaign-delta",
        "name": "campaign-delta",
        "target": TARGET,
        "created_at": "2026-08-29T00:00:00+00:00",
        "updated_at": "2026-08-29T00:00:00+00:00",
        "run_ids": ["run-delta"],
    }
    campaign_finding = build_campaign_export(campaign, [run])["findings"][0]
    benchmark_finding = build_benchmark_export(run)["findings"][0]
    assert campaign_finding["requests_used"] == 3
    assert benchmark_finding["requests_used"] == 3
    assert campaign_finding["request_accounting_source"] == "request_delta_v1"
    assert benchmark_finding["request_accounting_source"] == "request_delta_v1"


def test_request_delta_and_secret_named_numeric_metrics_survive_public_sanitizer():
    payload = public_result(
        {
            "request_delta": {
                "discovery": 1,
                "auth": 2,
                "verification": 3,
                "cleanup": 4,
                "attempted": 10,
                "total": 10,
            },
            "invalid_password_auth_requests": 3,
            "token_request_count": 2,
            "credential_attempt_count": 3,
        }
    )
    assert payload["request_delta"] == {
        "discovery": 1,
        "auth": 2,
        "verification": 3,
        "cleanup": 4,
        "attempted": 10,
        "total": 10,
    }
    assert payload["invalid_password_auth_requests"] == 3
    assert payload["token_request_count"] == 2
    assert payload["credential_attempt_count"] == 3
