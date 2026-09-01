from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import requests

from agent_core.agent_models import Hypothesis
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    SessionAcquisition,
)
from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.runtime_binding import bind_runtime_accounts
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import ScopedHTTPClient

TARGET = "https://authorized.example/api/me"
AUTH_URL = "https://authorized.example/api/sessions"
ALICE_USERNAME = "alice-controlled-username"
ALICE_PASSWORD = "alice-controlled-password"
ALICE_TOKEN = "alice-controlled-session-token"
PROTECTED_FIELDS = ["id", "email", "role", "tenant_id", "internal_note"]
PROTECTED_BODY = {
    "id": "alice",
    "email": "alice@example.test",
    "role": "member",
    "tenant_id": "tenant-a",
    "internal_note": "controlled protected evidence",
}


def _policy(account_ids: list[str] | None = None) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="authentication-enforcement-test",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value="https://authorized.example/api",
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "POST"],
        credentials_allowed=True,
        controlled_account_ids=["alice"] if account_ids is None else account_ids,
        allow_state_changes=False,
        request_budget=10,
    )


def _context(vault: CredentialVault) -> ControlledContext:
    return ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="alice",
                controlled=True,
                credential_references={
                    "username": vault.put(ALICE_USERNAME, label="alice:username"),
                    "password": vault.put(ALICE_PASSWORD, label="alice:password"),
                },
            )
        ],
        session_acquisition=SessionAcquisition(
            url=AUTH_URL,
            method="POST",
            token_field="token",
        ),
    )


def _hypothesis_and_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-authentication-enforcement",
        category="authentication_enforcement",
        title="Authentication enforcement differential",
        rationale="A controlled authenticated baseline is required.",
        target=TARGET,
        endpoint=TARGET,
        method="GET",
        requires_credentials=True,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            controlled_accounts=[],
            credential_accounts=[],
            request_budget=10,
            target_class="external",
        ),
    )
    return hypothesis, plan


def _gate(
    policy: AssessmentPolicy, context: ControlledContext
) -> DeterministicPolicyGate:
    controlled_ids = [
        account.account_id for account in context.accounts if account.controlled
    ]
    return DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="external",
            controlled_account_ids=controlled_ids,
            session_acquisition_url=AUTH_URL,
            session_acquisition_method="POST",
        ),
        RequestBudget(10),
    )


def _execute(
    vault: CredentialVault,
    *,
    authenticated_response: dict[str, Any],
    unauthenticated_response: dict[str, Any],
    login_response: dict[str, Any] | None = None,
    policy: AssessmentPolicy | None = None,
    mutate_plan: Callable[[list[dict[str, Any]]], None] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    context = _context(vault)
    hypothesis, plan = _hypothesis_and_plan()
    planned = plan.steps[0].metadata["requests"]
    if mutate_plan is not None:
        mutate_plan(planned)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        if request["url"] == AUTH_URL:
            assert request["json"] == {
                "username": ALICE_USERNAME,
                "password": ALICE_PASSWORD,
            }
            return login_response or {
                "status_code": 200,
                "body": {"token": ALICE_TOKEN},
            }
        if request["headers"].get("Authorization"):
            assert request["headers"]["Authorization"] == f"Bearer {ALICE_TOKEN}"
            return authenticated_response
        return unauthenticated_response

    result = ControlledVerificationExecutor(
        _gate(policy or _policy(), context), vault, context, transport
    ).execute(
        hypothesis,
        plan,
        inputs={"protected_fields": PROTECTED_FIELDS},
    )
    return result, calls


def test_authenticated_protected_baseline_and_anonymous_denial_is_secure():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={
                "status_code": 401,
                "body": {"error": "authentication required"},
            },
        )

        assert result["status"] == "rejected"
        assert result["analysis"]["authenticated_baseline_established"] is True
        assert result["analysis"]["verified"] is False
        assert result["runtime_binding"] == {
            "required_accounts": 1,
            "bound_accounts": 1,
            "owner_bound": True,
            "comparator_bound": False,
            "policy_authorized": True,
        }
        assert result["request_budget"] == {
            "total_requests": 3,
            "remaining_requests": 7,
            "discovery_requests": 0,
            "auth_requests": 1,
            "verification_requests": 2,
            "cleanup_requests": 0,
            "request_limit": 10,
        }
        assert result["request_delta"] == {
            "discovery": 0,
            "auth": 1,
            "verification": 2,
            "cleanup": 0,
            "attempted": 3,
            "total": 3,
        }
        assert [call["url"] for call in calls] == [AUTH_URL, TARGET, TARGET]


def test_equivalent_anonymous_protected_evidence_verifies():
    with CredentialVault() as vault:
        result, _ = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={"status_code": 200, "body": PROTECTED_BODY},
        )

        assert result["status"] == "verified"
        assert result["analysis"]["protected_evidence_matched"] is True
        assert result["analysis"]["matching_protected_field_paths"] == sorted(
            PROTECTED_FIELDS
        )


def test_session_acquisition_failure_is_inconclusive_without_comparison_traffic():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={"status_code": 401, "body": {}},
            login_response={"status_code": 401, "body": {"error": "invalid"}},
        )

        assert result["status"] == "inconclusive"
        assert [call["url"] for call in calls] == [AUTH_URL]
        assert result["request_budget"]["auth_requests"] == 1
        assert result["request_budget"]["verification_requests"] == 0


def test_denied_authenticated_request_is_inconclusive():
    with CredentialVault() as vault:
        result, _ = _execute(
            vault,
            authenticated_response={"status_code": 401, "body": {}},
            unauthenticated_response={"status_code": 200, "body": PROTECTED_BODY},
        )

        assert result["status"] == "inconclusive"
        assert result["analysis"]["authenticated_baseline_established"] is False


def test_two_denied_requests_are_never_classified_as_secure():
    with CredentialVault() as vault:
        result, _ = _execute(
            vault,
            authenticated_response={"status_code": 401, "body": {}},
            unauthenticated_response={"status_code": 401, "body": {}},
        )

        assert result["status"] == "inconclusive"
        assert result["status"] != "rejected"


def test_one_controlled_account_binds_to_only_the_authenticated_request():
    with CredentialVault() as vault:
        context = _context(vault)
        hypothesis, plan = _hypothesis_and_plan()
        stored_template = plan.model_dump(mode="json")

        binding = bind_runtime_accounts(hypothesis, plan, context, _policy())

        assert binding.succeeded is True
        assert binding.diagnostics == {
            "required_accounts": 1,
            "bound_accounts": 1,
            "owner_bound": True,
            "comparator_bound": False,
            "policy_authorized": False,
        }
        assert binding.plan is not None
        assert binding.plan.controlled_accounts == ["alice"]
        assert binding.plan.credentials_supplied is True
        requests = binding.plan.steps[0].metadata["requests"]
        assert [request["request_role"] for request in requests] == [
            "authenticated_baseline",
            "unauthenticated_comparison",
        ]
        assert [request["account_id"] for request in requests] == ["alice", None]
        assert plan.model_dump(mode="json") == stored_template


def test_policy_unauthorized_account_is_blocked_before_traffic():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={"status_code": 401, "body": {}},
            policy=_policy(["bob"]),
        )

        assert result["status"] == "policy_blocked"
        assert result["runtime_binding"]["required_accounts"] == 1
        assert result["runtime_binding"]["bound_accounts"] == 0
        assert result["runtime_binding"]["policy_authorized"] is False
        assert calls == []


def test_anonymous_comparison_strips_all_credential_material():
    def add_stale_credentials(requests: list[dict[str, Any]]) -> None:
        for request in requests:
            request["headers"] = {
                "Authorization": "Bearer stale-secret",
                "Cookie": "session=stale-cookie",
                "X-Auth-Token": "stale-auth-token",
                "X-API-Key": "stale-api-key",
                "Accept": "application/json",
            }
            request["credential_reference"] = "vault://stale-reference"
            request["session_reference"] = "vault://stale-session"

    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={"status_code": 401, "body": {}},
            mutate_plan=add_stale_credentials,
        )

        assert result["status"] == "rejected"
        authenticated, anonymous = calls[1:]
        assert authenticated["headers"] == {"Authorization": f"Bearer {ALICE_TOKEN}"}
        assert anonymous["headers"] == {}
        assert anonymous["credential_mode"] == "anonymous"
        rendered = json.dumps(anonymous).lower()
        assert "vault://" not in rendered
        assert "stale-secret" not in rendered
        assert "stale-cookie" not in rendered
        assert "stale-auth-token" not in rendered
        assert "stale-api-key" not in rendered


def test_anonymous_transport_clears_cookie_jar_and_credential_headers():
    captured: dict[str, Any] = {}
    client: ScopedHTTPClient

    def requester(method: str, url: str, **kwargs: Any) -> requests.Response:
        captured.update({"method": method, "url": url, **kwargs})
        assert not client.session.cookies
        response = requests.Response()
        response.status_code = 401
        response._content = b"{}"
        response.url = url
        return response

    client = ScopedHTTPClient(
        requester=requester,
        scope_prevalidated=True,
    )
    client.session.cookies.set("session", "persistent-session-secret")

    client.request(
        "GET",
        TARGET,
        headers={
            "Authorization": "Bearer explicit-secret",
            "Cookie": "session=explicit-secret",
            "X-Auth-Token": "explicit-secret",
            "Accept": "application/json",
        },
        purpose="verification",
        allow_session_credentials=False,
    )

    assert captured["headers"] == {"Accept": "application/json"}
    assert not client.session.cookies


def test_configured_protected_fields_absent_from_baseline_is_inconclusive():
    with CredentialVault() as vault:
        result, _ = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": {"name": "Alice"}},
            unauthenticated_response={"status_code": 401, "body": {}},
        )

        assert result["status"] == "inconclusive"
        assert result["analysis"]["authenticated_baseline_established"] is False


def test_secrets_are_absent_from_result_store_and_report(tmp_path):
    with CredentialVault() as vault:
        result, _ = _execute(
            vault,
            authenticated_response={"status_code": 200, "body": PROTECTED_BODY},
            unauthenticated_response={"status_code": 401, "body": {}},
        )

        serialized_result = json.dumps(result)
        run = {
            "run_id": "authentication-enforcement-secret-safety",
            "assessment_mode": "verify",
            "hypotheses": [],
            "verification_plans": [],
            "verification_results": [result],
        }
        store = Phase2RunStore(tmp_path / "phase2")
        stored_path = store.save(run)
        rendered = "\n".join(
            [
                serialized_result,
                Path(stored_path).read_text(encoding="utf-8"),
                render_phase2_report(run),
            ]
        )

        for secret in (ALICE_USERNAME, ALICE_PASSWORD, ALICE_TOKEN):
            assert secret not in rendered
