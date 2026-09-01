from __future__ import annotations

import json
from typing import Any

import pytest

from agent_core.agent_models import Hypothesis
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    SessionAcquisition,
    role_privilege_rank,
)
from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.credential_vault import CredentialVault
from agent_core.differential_analyzer import (
    _extract_selector_values,
    analyze_role_authorization,
)
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

TARGET = "https://authorized.example/api/admin/audit"
AUTH_URL = "https://authorized.example/api/sessions"
ALICE_USERNAME = "vertical-alice-user-secret"
ALICE_PASSWORD = "vertical-alice-password-secret"
ALICE_TOKEN = "vertical-alice-token-secret"
ADMIN_USERNAME = "vertical-admin-user-secret"
ADMIN_PASSWORD = "vertical-admin-password-secret"
ADMIN_TOKEN = "vertical-admin-token-secret"
PROTECTED_BODY = {
    "entries": [{"event": "controlled administrative audit entry"}],
    "generated_for": "controlled-administration",
}
PROTECTED_INPUTS = {
    "protected_fields": ["entries", "generated_for"],
    "protected_data_confirmed": True,
}


def _hypothesis_and_context_free_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-runtime-bound-vertical-authorization",
        category="vertical_authorization",
        title="Runtime-bound vertical authorization differential",
        rationale="A controlled role comparison is required.",
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
            test_owned_resources=[],
            request_budget=20,
            target_class="external",
        ),
    )
    return hypothesis, plan


def _password_account(
    vault: CredentialVault,
    account_id: str,
    role: str,
    username: str,
    password: str,
) -> ControlledAccount:
    return ControlledAccount(
        account_id=account_id,
        role=role,
        credential_references={
            "username": vault.put(username, label=f"{account_id}:username"),
            "password": vault.put(password, label=f"{account_id}:password"),
        },
    )


def _context(
    vault: CredentialVault,
    *,
    alice_role: str = "member",
    admin_role: str = "administrator",
    include_admin: bool = True,
) -> ControlledContext:
    accounts = [
        _password_account(
            vault,
            "alice",
            alice_role,
            ALICE_USERNAME,
            ALICE_PASSWORD,
        )
    ]
    if include_admin:
        accounts.append(
            _password_account(
                vault,
                "admin",
                admin_role,
                ADMIN_USERNAME,
                ADMIN_PASSWORD,
            )
        )
    return ControlledContext(
        accounts=accounts,
        session_acquisition=SessionAcquisition(url=AUTH_URL, method="POST"),
    )


def _policy(account_ids: list[str] | None = None) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="vertical-runtime-binding-test",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value="https://authorized.example/api",
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "POST"],
        credentials_allowed=True,
        controlled_account_ids=account_ids or ["alice", "admin"],
        allow_state_changes=False,
        request_budget=10,
    )


def _gate(
    policy: AssessmentPolicy, context: ControlledContext
) -> DeterministicPolicyGate:
    return DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="external",
            controlled_account_ids=[item.account_id for item in context.accounts],
            session_acquisition_url=AUTH_URL,
            session_acquisition_method="POST",
        ),
        RequestBudget(10),
    )


def _execute(
    vault: CredentialVault,
    context: ControlledContext,
    response_for_account,
    *,
    policy: AssessmentPolicy | None = None,
    inputs: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hypothesis, plan = _hypothesis_and_context_free_plan()
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        if request["url"] == AUTH_URL:
            token = {
                ALICE_USERNAME: ALICE_TOKEN,
                ADMIN_USERNAME: ADMIN_TOKEN,
            }[request["json"]["username"]]
            return {"status_code": 200, "body": {"token": token}}
        bearer = request["headers"]["Authorization"]
        account_id = "admin" if bearer == f"Bearer {ADMIN_TOKEN}" else "alice"
        return response_for_account(account_id)

    result = ControlledVerificationExecutor(
        _gate(policy or _policy(), context), vault, context, transport
    ).execute(
        hypothesis,
        plan,
        inputs=PROTECTED_INPUTS if inputs is None else inputs,
    )
    return result, calls


def _nested_analysis(
    privileged_body: dict[str, Any],
    lower_body: dict[str, Any],
    protected_fields: list[str],
) -> dict[str, Any]:
    return analyze_role_authorization(
        {"status_code": 200, "body": privileged_body},
        {"status_code": 200, "body": lower_body},
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_fields=protected_fields,
        protected_data_confirmed=True,
    )


def test_context_free_vertical_plan_binds_two_runtime_accounts():
    vault = CredentialVault()
    try:
        context = _context(vault)
        hypothesis, plan = _hypothesis_and_context_free_plan()
        stored_template = plan.model_dump(mode="json")

        binding = bind_runtime_accounts(hypothesis, plan, context, _policy())

        assert binding.succeeded is True
        assert binding.diagnostics["required_accounts"] == 2
        assert binding.diagnostics["bound_accounts"] == 2
        assert binding.diagnostics["owner_bound"] is True
        assert binding.diagnostics["comparator_bound"] is True
        assert binding.plan is not None
        assert binding.plan.controlled_accounts == ["admin", "alice"]
        assert plan.model_dump(mode="json") == stored_template
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("role", "expected_rank"),
    [
        ("member", 10),
        ("normal", 10),
        ("operator", 20),
        ("administrator", 30),
        ("superadmin", 40),
    ],
)
def test_explicit_role_ordering_is_resolved(role: str, expected_rank: int):
    assert role_privilege_rank(role) == expected_rank
    assert role_privilege_rank("account-named-admin@example.test") is None


def test_same_role_vertical_accounts_are_blocked_before_network():
    vault = CredentialVault()
    try:
        result, calls = _execute(
            vault,
            _context(vault, alice_role="member", admin_role="user"),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
        assert calls == []
    finally:
        vault.close()


def test_only_one_vertical_account_is_blocked_before_network():
    vault = CredentialVault()
    try:
        result, calls = _execute(
            vault,
            _context(vault, include_admin=False),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        assert result["status"] == "policy_blocked"
        assert result["runtime_binding"]["required_accounts"] == 2
        assert calls == []
    finally:
        vault.close()


def test_missing_recognized_higher_role_is_blocked_before_network():
    vault = CredentialVault()
    try:
        result, calls = _execute(
            vault,
            _context(vault, admin_role="auditor"),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        assert result["status"] == "policy_blocked"
        assert "recognized role metadata" in " ".join(result["reasons"])
        assert calls == []
    finally:
        vault.close()


def test_policy_permitting_only_lower_account_blocks_both_requests():
    vault = CredentialVault()
    try:
        result, calls = _execute(
            vault,
            _context(vault),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
            policy=_policy(["alice"]),
        )
        assert result["status"] == "policy_blocked"
        assert result["runtime_binding"]["policy_authorized"] is False
        assert calls == []
    finally:
        vault.close()


def test_two_exact_gets_use_distinct_authenticated_role_contexts():
    vault = CredentialVault()
    try:
        result, calls = _execute(
            vault,
            _context(vault),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        auth_calls = [item for item in calls if item["url"] == AUTH_URL]
        verification_calls = [item for item in calls if item["url"] == TARGET]

        assert len(auth_calls) == 2
        assert {
            item["request_context"]["controlled_account_id"] for item in auth_calls
        } == {"alice", "admin"}
        assert [(item["method"], item["url"]) for item in verification_calls] == [
            ("GET", TARGET),
            ("GET", TARGET),
        ]
        assert [item["headers"]["Authorization"] for item in verification_calls] == [
            f"Bearer {ADMIN_TOKEN}",
            f"Bearer {ALICE_TOKEN}",
        ]
        assert result["request_budget"]["auth_requests"] == 2
        assert result["request_budget"]["verification_requests"] == 2
        assert result["request_budget"]["total_requests"] == 4
        assert result["request_delta"] == {
            "discovery": 0,
            "auth": 2,
            "verification": 2,
            "cleanup": 0,
            "attempted": 4,
            "total": 4,
        }
        assert result["runtime_binding"] == {
            "required_accounts": 2,
            "bound_accounts": 2,
            "owner_bound": True,
            "comparator_bound": True,
            "policy_authorized": True,
        }
    finally:
        vault.close()


def test_privileged_protected_response_and_lower_denial_is_secure():
    vault = CredentialVault()
    try:
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: (
                {"status_code": 200, "body": PROTECTED_BODY}
                if account_id == "admin"
                else {"status_code": 403, "body": {"error": "forbidden"}}
            ),
        )
        assert result["status"] == "rejected"
        assert result["analysis"]["privileged_baseline_established"] is True
        assert result["analysis"]["verified"] is False
    finally:
        vault.close()


def test_matching_protected_data_for_lower_role_verifies_high_confidence():
    vault = CredentialVault()
    try:
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        assert result["status"] == "verified"
        assert result["confidence"] == "high"
        assert result["analysis"]["separate_accounts_confirmed"] is True
        assert result["analysis"]["distinct_roles_confirmed"] is True
        assert result["analysis"]["protected_evidence_matched"] is True
        assert result["analysis"]["matching_protected_field_paths"] == [
            "entries",
            "generated_for",
        ]
    finally:
        vault.close()


def test_entries_event_selector_extracts_ordered_list_values():
    body = {
        "entries": [
            {"event": "controlled-event-a", "subject": "controlled-subject-a"},
            {"event": "controlled-event-b", "subject": "controlled-subject-b"},
        ]
    }

    assert _extract_selector_values(body, "entries[].event") == (
        "controlled-event-a",
        "controlled-event-b",
    )


def test_entries_subject_selector_extracts_ordered_list_values():
    body = {
        "entries": [
            {"event": "controlled-event-a", "subject": "controlled-subject-a"},
            {"event": "controlled-event-b", "subject": "controlled-subject-b"},
        ]
    }

    assert _extract_selector_values(body, "entries[].subject") == (
        "controlled-subject-a",
        "controlled-subject-b",
    )


def test_nested_protected_values_verify_when_unconfigured_metadata_differs():
    vault = CredentialVault()
    entries = [
        {"event": "controlled-event-a", "subject": "controlled-subject-a"},
        {"event": "controlled-event-b", "subject": "controlled-subject-b"},
    ]
    try:
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: {
                "status_code": 200,
                "body": {
                    "entries": entries,
                    "generated_for": account_id,
                },
            },
            inputs={
                "protected_fields": ["entries[].event", "entries[].subject"],
                "protected_data_confirmed": True,
            },
        )

        assert result["status"] == "verified"
        assert result["analysis"]["privileged_baseline_established"] is True
        assert result["analysis"]["privileged_protected_field_paths"] == [
            "entries[].event",
            "entries[].subject",
        ]
        assert result["analysis"]["protected_field_paths"] == [
            "entries[].event",
            "entries[].subject",
        ]
        assert result["analysis"]["matching_protected_field_paths"] == [
            "entries[].event",
            "entries[].subject",
        ]
        assert result["analysis"]["value_hash_match"] is True
        assert result["analysis"]["item_count_match"] is True
    finally:
        vault.close()


def test_equal_nested_schema_with_different_values_is_inconclusive():
    privileged = {"entries": [{"event": "privileged-event", "subject": "same-subject"}]}
    lower = {"entries": [{"event": "lower-event", "subject": "same-subject"}]}

    result = _nested_analysis(
        privileged,
        lower,
        ["entries[].event", "entries[].subject"],
    )

    assert result["body_structure_equal"] is True
    assert result["status"] == "inconclusive"
    assert result["verified"] is False
    assert result["matching_protected_field_paths"] == ["entries[].subject"]
    assert result["value_hash_match"] is False
    assert result["protected_evidence_matched"] is False


def test_absent_nested_protected_path_is_inconclusive():
    body = {"entries": [{"event": "controlled-event"}]}

    result = _nested_analysis(body, body, ["entries[].subject"])

    assert result["status"] == "inconclusive"
    assert result["privileged_baseline_established"] is False
    assert result["protected_field_paths"] == []
    assert result["protected_evidence_matched"] is False


def test_empty_privileged_list_does_not_establish_baseline():
    result = _nested_analysis(
        {"entries": []},
        {"entries": [{"event": "lower-event"}]},
        ["entries[].event"],
    )

    assert result["status"] == "inconclusive"
    assert result["privileged_baseline_established"] is False
    assert result["privileged_protected_field_paths"] == []


def test_different_nested_list_lengths_do_not_match():
    result = _nested_analysis(
        {"entries": [{"event": "event-a"}, {"event": "event-b"}]},
        {"entries": [{"event": "event-a"}]},
        ["entries[].event"],
    )

    assert result["status"] == "inconclusive"
    assert result["item_count_match"] is False
    assert result["value_hash_match"] is False
    assert result["matching_protected_field_paths"] == []


def test_nested_object_list_selector_and_star_alias_use_canonical_path():
    body = {
        "metadata": {
            "audit": [
                {"event": "event-a"},
                {"event": "event-b"},
            ]
        }
    }

    result = _nested_analysis(body, body, ["metadata.audit.*.event"])

    assert result["status"] == "verified"
    assert result["privileged_protected_field_paths"] == ["metadata.audit[].event"]
    assert result["matching_protected_field_paths"] == ["metadata.audit[].event"]


def test_two_successes_without_configured_protected_fields_are_inconclusive():
    vault = CredentialVault()
    try:
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: {
                "status_code": 200,
                "body": {"message": "public response"},
            },
        )
        assert result["status"] == "inconclusive"
        assert result["analysis"]["privileged_baseline_established"] is False
        assert result["analysis"]["protected_field_paths"] == []
    finally:
        vault.close()


def test_vertical_results_reports_and_store_remain_secret_free(tmp_path):
    vault = CredentialVault()
    try:
        hypothesis, plan = _hypothesis_and_context_free_plan()
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: {"status_code": 200, "body": PROTECTED_BODY},
        )
        run = {
            "run_id": "vertical-secret-free-run",
            "assessment_mode": "verify",
            "attack_surface": {},
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_plans": [plan.model_dump(mode="json")],
            "verification_results": [result],
        }
        report = render_phase2_report(run)
        store = Phase2RunStore(tmp_path / "vertical-runtime-runs")
        store.save(run)
        rendered = json.dumps(
            {"result": result, "stored": store.load(), "report": report}
        )

        for secret in (
            ALICE_USERNAME,
            ALICE_PASSWORD,
            ALICE_TOKEN,
            ADMIN_USERNAME,
            ADMIN_PASSWORD,
            ADMIN_TOKEN,
        ):
            assert secret not in rendered
        assert "Authorization" not in rendered
        assert "cred_" not in rendered
    finally:
        vault.close()


def test_nested_protected_values_do_not_enter_result_store_or_report(tmp_path):
    event_secret = "nested-protected-event-value"
    subject_secret = "nested-protected-subject-value"
    vault = CredentialVault()
    try:
        hypothesis, plan = _hypothesis_and_context_free_plan()
        result, _ = _execute(
            vault,
            _context(vault),
            lambda account_id: {
                "status_code": 200,
                "body": {
                    "entries": [{"event": event_secret, "subject": subject_secret}],
                    "generated_for": account_id,
                },
            },
            inputs={
                "protected_fields": ["entries[].event", "entries[].subject"],
                "protected_data_confirmed": True,
            },
        )
        run = {
            "run_id": "nested-protected-secret-free-run",
            "assessment_mode": "verify",
            "attack_surface": {},
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_plans": [plan.model_dump(mode="json")],
            "verification_results": [result],
        }
        report = render_phase2_report(run)
        store = Phase2RunStore(tmp_path / "nested-protected-runs")
        store.save(run)
        rendered = json.dumps(
            {"result": result, "stored": store.load(), "report": report}
        )

        assert result["status"] == "verified"
        assert event_secret not in rendered
        assert subject_secret not in rendered
    finally:
        vault.close()
