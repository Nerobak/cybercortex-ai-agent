from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Callable

from agent_core.agent_models import Hypothesis
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    SessionAcquisition,
)
from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_policy import SessionTerminationAction
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

TARGET = "https://service.example/api"
CREATION_URL = f"{TARGET}/sessions"
RESOURCE_URL = f"{TARGET}/account"
TERMINATION_URL = f"{TARGET}/sessions/current"
ACCOUNT_ID = "controlled-user"
USERNAME = "synthetic-controlled-username"
EMAIL = "synthetic-controlled@example.test"
PASSWORD = "synthetic-controlled-password"
SESSION_VALUE = "synthetic-private-session"
PROTECTED_FIELDS = ["id", "email", "role"]
PROTECTED_BODY = {
    "id": "controlled-user",
    "email": "controlled@example.test",
    "role": "member",
    "public": "non-protected metadata",
}


def _hypothesis_and_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-session-invalidation",
        category="session_invalidation",
        title="Session invalidation controlled replay",
        rationale="A complete semantic session lifecycle requires runtime verification.",
        target=TARGET,
        endpoint=RESOURCE_URL,
        method="GET",
        requires_credentials=True,
        state_changing=True,
        cleanup_required=True,
        safe_verification_possible=True,
        metadata={
            "related_surfaces": [
                {
                    "boundary_type": "session_creation",
                    "method": "POST",
                    "path": "/sessions",
                },
                {
                    "boundary_type": "authenticated_resource",
                    "method": "GET",
                    "path": "/account",
                },
                {
                    "boundary_type": "session_termination",
                    "method": "DELETE",
                    "path": "/sessions/current",
                },
            ]
        },
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            controlled_accounts=[],
            credential_accounts=[],
            request_budget=10,
            target_class="dedicated_lab",
        ),
    )
    return hypothesis, plan


def _policy(
    *,
    account_ids: list[str] | None = None,
    allow_state_changes: bool = True,
) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="synthetic session invalidation authorization",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=TARGET,
                schemes=["https"],
                ports=[443],
            )
        ],
        allowed_methods=["GET", "POST", "DELETE"],
        credentials_allowed=True,
        controlled_account_ids=([ACCOUNT_ID] if account_ids is None else account_ids),
        allow_state_changes=allow_state_changes,
        request_budget=10,
    )


def _context(
    vault: CredentialVault,
    *,
    identity_kind: str = "username",
    identity_field: str = "username",
) -> ControlledContext:
    identity_references: dict[str, str] = {}
    if identity_kind in {"username", "both"}:
        identity_references["username"] = vault.put(
            USERNAME, label="controlled username"
        )
    if identity_kind in {"email", "both"}:
        identity_references["email"] = vault.put(EMAIL, label="controlled email")
    return ControlledContext(
        accounts=[
            ControlledAccount(
                account_id=ACCOUNT_ID,
                credential_references={
                    **identity_references,
                    "password": vault.put(PASSWORD, label="controlled password"),
                },
            )
        ],
        session_acquisition=SessionAcquisition(
            url=CREATION_URL,
            method="POST",
            username_field=identity_field,
            token_field="session",
        ),
    )


def _execute(
    vault: CredentialVault,
    *,
    baseline: dict[str, Any] | None = None,
    termination: dict[str, Any] | None = None,
    replay: dict[str, Any] | None = None,
    login: dict[str, Any] | None = None,
    policy: AssessmentPolicy | None = None,
    mutate_plan: Callable[[list[dict[str, Any]]], None] | None = None,
    mutate_after_termination: bool = False,
    context: ControlledContext | None = None,
    expected_identity: str = USERNAME,
) -> tuple[dict[str, Any], list[dict[str, Any]], ControlledContext]:
    hypothesis, plan = _hypothesis_and_plan()
    actions = plan.steps[0].metadata["requests"]
    if mutate_plan is not None:
        mutate_plan(actions)
    context = context or _context(vault)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(deepcopy(request))
        if request["url"] == CREATION_URL:
            assert request["purpose"] == "session_acquisition"
            assert request["json"] == {
                context.session_acquisition.username_field: expected_identity,
                "password": PASSWORD,
            }
            return login or {
                "status_code": 200,
                "body": {"session": SESSION_VALUE},
            }
        assert request["headers"]["Authorization"] == f"Bearer {SESSION_VALUE}"
        assert request["isolate_session_cookies"] is True
        if request["url"] == RESOURCE_URL and len(calls) == 2:
            return baseline or {"status_code": 200, "body": PROTECTED_BODY}
        if request["url"] == TERMINATION_URL:
            assert request["purpose"] == "session_termination"
            assert request["request_context"]["workflow_category"] == (
                "session_invalidation"
            )
            if mutate_after_termination:
                context.accounts[0].session_reference = vault.put(
                    "replacement-must-not-be-used", label="unexpected replacement"
                )
            return termination or {"status_code": 204, "body": None}
        if request["url"] == RESOURCE_URL:
            return replay or {"status_code": 401, "body": {"error": "denied"}}
        raise AssertionError("The adapter dispatched an unplanned URL.")

    gate = DeterministicPolicyGate(
        policy or _policy(),
        Phase2PolicyContext(
            mode="verify",
            target_class="dedicated_lab",
            controlled_account_ids=[ACCOUNT_ID],
            session_acquisition_url=CREATION_URL,
            session_acquisition_method="POST",
            replay_enabled=True,
        ),
        RequestBudget(10),
    )
    result = ControlledVerificationExecutor(gate, vault, context, transport).execute(
        hypothesis,
        plan,
        inputs={
            "protected_fields": PROTECTED_FIELDS,
            "protected_data_confirmed": True,
        },
    )
    return result, calls, context


def test_email_only_identity_completes_session_invalidation_acquisition():
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="email", identity_field="email")
        result, calls, _ = _execute(
            vault,
            context=context,
            expected_identity=EMAIL,
        )

    assert result["status"] == "rejected"
    assert calls[0]["json"] == {"email": EMAIL, "password": PASSWORD}


def test_username_only_identity_remains_supported_for_session_invalidation():
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="username", identity_field="username")
        result, calls, _ = _execute(vault, context=context)

    assert result["status"] == "rejected"
    assert calls[0]["json"] == {"username": USERNAME, "password": PASSWORD}


def test_both_identities_prefer_the_configured_session_field():
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="both", identity_field="email")
        result, calls, _ = _execute(
            vault,
            context=context,
            expected_identity=EMAIL,
        )

    assert result["status"] == "rejected"
    assert calls[0]["json"] == {"email": EMAIL, "password": PASSWORD}


def test_missing_identity_blocks_session_invalidation_before_acquisition():
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="none", identity_field="email")
        result, calls, _ = _execute(vault, context=context)

    assert result["status"] == "policy_blocked"
    assert result["request_delta"]["total"] == 0
    assert calls == []


def test_denied_same_session_replay_is_secure_and_uses_four_requests():
    with CredentialVault() as vault:
        result, calls, context = _execute(vault)

        assert result["status"] == "rejected"
        assert result["same_session_replayed"] is True
        assert result["termination_attempted"] is True
        assert result["termination_succeeded"] is True
        assert result["cleanup_attempted"] is True
        assert result["cleanup_verified"] is True
        assert result["runtime_binding"] == {
            "required_accounts": 1,
            "bound_accounts": 1,
            "owner_bound": True,
            "comparator_bound": False,
            "policy_authorized": True,
        }
        assert result["request_budget"]["auth_requests"] == 1
        assert result["request_budget"]["verification_requests"] == 3
        assert result["request_budget"]["total_requests"] == 4
        assert result["request_delta"] == {
            "discovery": 0,
            "auth": 1,
            "verification": 3,
            "cleanup": 0,
            "attempted": 4,
            "total": 4,
        }
        assert len(calls) == 4
        assert calls[1]["headers"] == calls[2]["headers"] == calls[3]["headers"]
        assert context.accounts[0].session_reference is None


def test_matching_protected_evidence_after_logout_verifies_high_confidence():
    with CredentialVault() as vault:
        result, _, _ = _execute(
            vault, replay={"status_code": 200, "body": PROTECTED_BODY}
        )

        assert result["status"] == "verified"
        assert result["confidence"] == "high"
        assert result["protected_evidence_matched"] is True
        assert result["protected_field_paths"] == sorted(PROTECTED_FIELDS)


def test_replacement_session_is_never_replayed():
    with CredentialVault() as vault:
        result, calls, _ = _execute(vault, mutate_after_termination=True)

        assert result["status"] == "inconclusive"
        assert result["same_session_replayed"] is False
        assert result["cleanup_verified"] is False
        assert len(calls) == 3


def test_denied_baseline_is_inconclusive_and_skips_termination():
    with CredentialVault() as vault:
        result, calls, _ = _execute(
            vault, baseline={"status_code": 401, "body": {"error": "denied"}}
        )

        assert result["status"] == "inconclusive"
        assert result["termination_attempted"] is False
        assert result["cleanup_verified"] is True
        assert len(calls) == 2


def test_session_acquisition_failure_has_zero_verification_requests():
    with CredentialVault() as vault:
        result, calls, _ = _execute(
            vault, login={"status_code": 401, "body": {"error": "invalid"}}
        )

        assert result["status"] == "inconclusive"
        assert result["request_budget"]["auth_requests"] == 1
        assert result["request_budget"]["verification_requests"] == 0
        assert len(calls) == 1


def test_termination_surface_mismatch_is_policy_blocked():
    with CredentialVault() as vault:
        result, calls, _ = _execute(
            vault,
            mutate_plan=lambda actions: actions[2].update(
                {"url": f"{TARGET}/different"}
            ),
        )

        assert result["status"] == "policy_blocked"
        assert calls == []


def test_policy_unauthorized_account_is_blocked():
    with CredentialVault() as vault:
        result, calls, _ = _execute(vault, policy=_policy(account_ids=["other"]))

        assert result["status"] == "policy_blocked"
        assert calls == []


def test_empty_policy_account_allowlist_permits_the_only_controlled_account():
    with CredentialVault() as vault:
        result, calls, _ = _execute(vault, policy=_policy(account_ids=[]))

        assert result["status"] == "rejected"
        assert result["runtime_binding"]["policy_authorized"] is True
        assert len(calls) == 4


def test_more_than_one_controlled_account_is_blocked():
    with CredentialVault() as vault:
        hypothesis, plan = _hypothesis_and_plan()
        context = _context(vault)
        context.accounts.append(
            ControlledAccount(
                account_id="second-controlled-user",
                credential_references={
                    "username": vault.put("second-user", label="second username"),
                    "password": vault.put("second-pass", label="second password"),
                },
            )
        )
        gate = DeterministicPolicyGate(
            _policy(account_ids=[ACCOUNT_ID, "second-controlled-user"]),
            Phase2PolicyContext(
                mode="verify",
                target_class="dedicated_lab",
                controlled_account_ids=[ACCOUNT_ID, "second-controlled-user"],
                session_acquisition_url=CREATION_URL,
                session_acquisition_method="POST",
                replay_enabled=True,
            ),
            RequestBudget(10),
        )
        calls: list[dict[str, Any]] = []
        result = ControlledVerificationExecutor(
            gate, vault, context, lambda request: calls.append(request) or {}
        ).execute(
            hypothesis,
            plan,
            inputs={
                "protected_fields": PROTECTED_FIELDS,
                "protected_data_confirmed": True,
            },
        )

        assert result["status"] == "policy_blocked"
        assert result["runtime_binding"]["required_accounts"] == 1
        assert result["runtime_binding"]["bound_accounts"] == 0
        assert calls == []


def test_disabled_state_changes_block_before_logout_or_login():
    with CredentialVault() as vault:
        result, calls, _ = _execute(vault, policy=_policy(allow_state_changes=False))

        assert result["status"] == "policy_blocked"
        assert result["termination_attempted"] is False
        assert calls == []


def test_successful_replay_without_configured_fields_is_inconclusive():
    with CredentialVault() as vault:
        result, _, _ = _execute(
            vault,
            replay={"status_code": 200, "body": {"message": "public response"}},
        )

        assert result["status"] == "inconclusive"
        assert result["protected_evidence_matched"] is False


def test_failed_termination_is_inconclusive_and_skips_replay():
    with CredentialVault() as vault:
        result, calls, _ = _execute(
            vault,
            termination={"status_code": 500, "body": {"error": "failed"}},
        )

        assert result["status"] == "inconclusive"
        assert result["termination_attempted"] is True
        assert result["termination_succeeded"] is False
        assert result["same_session_replayed"] is False
        assert result["cleanup_verified"] is True
        assert len(calls) == 3


def test_transport_accepts_only_typed_exact_delete_termination():
    policy = _policy().model_copy(
        update={"resolve_dns_before_request": False, "requests_per_second": 100.0}
    )
    gate = DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="dedicated_lab",
            controlled_account_ids=[ACCOUNT_ID],
        ),
        RequestBudget(10),
    )
    decision = gate.authorize_session_termination(
        SessionTerminationAction(
            url=TERMINATION_URL,
            method="DELETE",
            account_id=ACCOUNT_ID,
            account_controlled=True,
            workflow_url=TERMINATION_URL,
            workflow_method="DELETE",
        )
    )
    calls: list[tuple[str, str]] = []

    class Response:
        status_code = 204
        headers: dict[str, str] = {}
        content = b""
        is_redirect = False
        is_permanent_redirect = False

    client = ScopedHTTPClient(
        policy=policy,
        requester=lambda method, url, **_kwargs: (
            calls.append((method, url)) or Response()
        ),
    )
    response, _ = client.request(
        "DELETE",
        TERMINATION_URL,
        purpose="session_termination",
        request_context=decision.request_context,
    )

    assert response.status_code == 204
    assert calls == [("DELETE", TERMINATION_URL)]
    try:
        client.request("DELETE", TERMINATION_URL, purpose="state_mutation")
    except PolicyViolationError:
        pass
    else:
        raise AssertionError("Generic DELETE must remain blocked.")


def test_result_store_and_report_are_secret_free(tmp_path):
    with CredentialVault() as vault:
        result, _, _ = _execute(
            vault, replay={"status_code": 200, "body": PROTECTED_BODY}
        )

        rendered = json.dumps(result, sort_keys=True)
        assert SESSION_VALUE not in rendered
        assert USERNAME not in rendered
        assert PASSWORD not in rendered
        assert "Authorization" not in rendered
        assert "Cookie" not in rendered
        assert "credential_reference" not in rendered
        assert "controlled@example.test" not in rendered
        assert result["baseline"]["status_code"] == 200
        assert result["replay"]["status_code"] == 200
        store = Phase2RunStore(tmp_path)
        store.save({"run_id": "session-safe-output", "verification_results": [result]})
        stored = json.dumps(store.load(), sort_keys=True)
        assert SESSION_VALUE not in stored
        assert result["same_session_replayed"] is True
        assert store.load()["verification_results"][0]["same_session_replayed"] is True
        report = render_phase2_report(
            {
                "verification_results": [result],
                "hypotheses": [],
                "verification_plans": [],
            }
        )
        assert SESSION_VALUE not in report
        assert "Same session replayed: true" in report
