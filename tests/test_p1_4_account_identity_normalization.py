from __future__ import annotations

import json
from typing import Any

import pytest

from agent_core.agent_models import Hypothesis
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    SessionAcquirer,
    SessionAcquisition,
    SessionAcquisitionPolicyError,
    resolve_controlled_login_identity,
)
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import (
    DeterministicPolicyGate,
    Phase2PolicyContext,
    VerificationAction,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.runtime_binding import bind_runtime_accounts
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)

TARGET = "https://p1-4.example"
LOGIN_URL = f"{TARGET}/sessions"
ACCOUNT_ID = "controlled-a"
USERNAME = "p1-4-controlled-username"
EMAIL = "p1-4-controlled@example.test"
PASSWORD = "p1-4-controlled-password"

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


def _policy(account_ids: list[str]) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="p1-4-account-identity-tests",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        credentials_allowed=True,
        controlled_account_ids=account_ids,
        request_budget=20,
    )


def _account_context(
    *, controlled: bool = True, account_id: str = ACCOUNT_ID
) -> ControlledContext:
    return ControlledContext(
        accounts=[ControlledAccount(account_id=account_id, controlled=controlled)]
    )


@pytest.mark.parametrize("category", EXECUTABLE_CATEGORIES)
@pytest.mark.parametrize(
    ("policy_ids", "controlled", "expected"),
    (
        ([], True, True),
        ([], False, False),
        ([ACCOUNT_ID], True, True),
        (["different-controlled-account"], True, False),
        ([ACCOUNT_ID], False, False),
    ),
)
def test_all_executable_category_gates_share_account_eligibility_semantics(
    category: str,
    policy_ids: list[str],
    controlled: bool,
    expected: bool,
):
    context = _account_context(controlled=controlled)
    budget = RequestBudget(20)
    gate = DeterministicPolicyGate(
        _policy(policy_ids),
        Phase2PolicyContext(
            mode="verify",
            target_class="dedicated_lab",
            controlled_account_ids=[
                item.account_id for item in context.accounts if item.controlled
            ],
        ),
        budget,
    )

    decision = gate.authorize_action(
        VerificationAction(
            url=f"{TARGET}/resource",
            method="GET",
            category=category,
            account_id=ACCOUNT_ID,
            credential_reference_present=True,
        )
    )

    assert decision.allowed is expected
    assert budget.snapshot()["total_requests"] == 0
    if not expected:
        assert any("not eligible" in reason for reason in decision.reasons)


def test_account_eligibility_decision_is_typed_and_contains_no_identity_value():
    controlled = _account_context()
    eligible = _policy([]).account_is_eligible(ACCOUNT_ID, controlled)
    excluded = _policy(["other"]).account_is_eligible(ACCOUNT_ID, controlled)
    uncontrolled = _policy([ACCOUNT_ID]).account_is_eligible(
        ACCOUNT_ID, _account_context(controlled=False)
    )

    assert (eligible.eligible, eligible.reason_code, eligible.reason) == (
        True,
        "eligible",
        None,
    )
    assert (excluded.eligible, excluded.reason_code) == (False, "not_allowed")
    assert (uncontrolled.eligible, uncontrolled.reason_code) == (
        False,
        "not_controlled",
    )
    assert EMAIL not in json.dumps(excluded.model_dump(mode="json"))


def _multi_account_binding(
    category: str,
    policy_ids: list[str],
    vault: CredentialVault,
):
    accounts = [
        ControlledAccount(
            account_id="controlled-a",
            role="member",
            tenant_id="tenant-a",
            credential_references={"token": vault.put("token-a", label="token-a")},
        ),
        ControlledAccount(
            account_id="controlled-b",
            role="administrator",
            tenant_id="tenant-b",
            credential_references={"token": vault.put("token-b", label="token-b")},
        ),
    ]
    objects = [
        ControlledObject(
            object_id=("tenant-a" if category == "tenant_isolation" else "object-a"),
            owner_account_id="controlled-a",
            tenant_id="tenant-a",
            object_type=("tenant" if category == "tenant_isolation" else "record"),
        )
    ]
    context = ControlledContext(accounts=accounts, objects=objects)
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-p1-4-{category}",
        category=category,
        title=f"P1-4 {category} binding",
        rationale="Two equivalent controlled accounts exercise one policy contract.",
        target=TARGET,
        endpoint=f"{TARGET}/resource",
        method="GET",
        requires_credentials=True,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            controlled_accounts=[],
            credential_accounts=[],
            request_budget=20,
            target_class="dedicated_lab",
        ),
    )
    return bind_runtime_accounts(hypothesis, plan, context, _policy(policy_ids), vault)


@pytest.mark.parametrize(
    "category", ("bola", "tenant_isolation", "vertical_authorization")
)
@pytest.mark.parametrize(
    ("policy_ids", "expected"),
    (
        ([], True),
        (["controlled-a", "controlled-b"], True),
        (["controlled-a"], False),
    ),
)
def test_multi_account_categories_intersect_policy_with_controlled_context(
    category: str, policy_ids: list[str], expected: bool
):
    with CredentialVault() as vault:
        binding = _multi_account_binding(category, policy_ids, vault)

    assert binding.succeeded is expected
    if expected:
        assert binding.diagnostics["bound_accounts"] == 2
    else:
        assert binding.plan is None


def _identity_account(vault: CredentialVault, identity_kind: str) -> ControlledAccount:
    references = {"password": vault.put(PASSWORD, label="password")}
    if identity_kind in {"username", "both"}:
        references["username"] = vault.put(USERNAME, label="username")
    if identity_kind in {"email", "both"}:
        references["email"] = vault.put(EMAIL, label="email")
    return ControlledAccount(
        account_id=ACCOUNT_ID,
        controlled=True,
        credential_references=references,
    )


@pytest.mark.parametrize(
    ("identity_field", "identity_kind", "expected_source", "expected_value"),
    (
        ("email", "email", "email", EMAIL),
        ("email", "username", "username", USERNAME),
        ("username", "username", "username", USERNAME),
        ("username", "email", "email", EMAIL),
        ("email", "both", "email", EMAIL),
        ("username", "both", "username", USERNAME),
    ),
)
def test_controlled_identity_resolver_uses_deterministic_semantic_preference(
    identity_field: str,
    identity_kind: str,
    expected_source: str,
    expected_value: str,
):
    with CredentialVault() as vault:
        account = _identity_account(vault, identity_kind)
        resolution = resolve_controlled_login_identity(
            account,
            SessionAcquisition(url=LOGIN_URL, username_field=identity_field),
            vault,
        )
        public = resolution.public_summary()

        assert resolution.identity_bound is True
        assert resolution.identity_source == expected_source
        assert resolution.materialize(vault) == expected_value
        assert public == {
            "identity_bound": True,
            "identity_source": expected_source,
        }
        serialized = json.dumps(public)
        assert USERNAME not in serialized
        assert EMAIL not in serialized
        assert PASSWORD not in serialized
        assert "cred_" not in serialized


@pytest.mark.parametrize("discard", [False, True])
def test_missing_or_discarded_identity_fails_closed_without_materializing(
    discard: bool,
):
    calls: list[dict[str, Any]] = []
    with CredentialVault() as vault:
        account = _identity_account(vault, "username" if discard else "none")
        if discard:
            vault.discard(account.credential_references["username"])
        config = SessionAcquisition(url=LOGIN_URL)
        resolution = resolve_controlled_login_identity(account, config, vault)
        budget = RequestBudget(5)
        gate = DeterministicPolicyGate(
            _policy([]),
            Phase2PolicyContext(
                mode="verify",
                target_class="external",
                controlled_account_ids=[ACCOUNT_ID],
                session_acquisition_url=LOGIN_URL,
                session_acquisition_method="POST",
            ),
            budget,
        )
        with pytest.raises(SessionAcquisitionPolicyError):
            SessionAcquirer(vault, budget).acquire(
                account,
                config,
                calls.append,
                authorization_check=gate.authorize_session_acquisition,
            )

        assert resolution.identity_bound is False
        assert resolution.identity_source is None
        assert resolution.reason is not None
        assert calls == []
        assert budget.snapshot()["total_requests"] == 0


@pytest.mark.parametrize("password_state", ["missing", "discarded"])
def test_missing_or_discarded_password_blocks_before_transport(password_state: str):
    calls: list[dict[str, Any]] = []
    with CredentialVault() as vault:
        account = _identity_account(vault, "username")
        if password_state == "missing":
            account.credential_references.pop("password")
        else:
            vault.discard(account.credential_references["password"])
        context = ControlledContext(
            accounts=[account],
            session_acquisition=SessionAcquisition(url=LOGIN_URL),
        )
        budget = RequestBudget(5)
        gate = DeterministicPolicyGate(
            _policy([]),
            Phase2PolicyContext(
                mode="verify",
                target_class="external",
                controlled_account_ids=[ACCOUNT_ID],
                session_acquisition_url=LOGIN_URL,
                session_acquisition_method="POST",
            ),
            budget,
        )
        with pytest.raises(SessionAcquisitionPolicyError):
            SessionAcquirer(vault, budget).acquire(
                account,
                context.session_acquisition,
                calls.append,
                authorization_check=gate.authorize_session_acquisition,
            )

        assert calls == []
        assert budget.snapshot()["total_requests"] == 0


def test_unsupported_identity_field_is_blocked_before_transport():
    calls: list[dict[str, Any]] = []
    with CredentialVault() as vault:
        account = _identity_account(vault, "both")
        config = SessionAcquisition(url=LOGIN_URL, username_field="login_id")
        budget = RequestBudget(5)
        gate = DeterministicPolicyGate(
            _policy([]),
            Phase2PolicyContext(
                mode="verify",
                target_class="external",
                controlled_account_ids=[ACCOUNT_ID],
                session_acquisition_url=LOGIN_URL,
                session_acquisition_method="POST",
            ),
            budget,
        )
        with pytest.raises(SessionAcquisitionPolicyError) as exc_info:
            SessionAcquirer(vault, budget).acquire(
                account,
                config,
                calls.append,
                authorization_check=gate.authorize_session_acquisition,
            )

        assert (
            "Unsupported session-acquisition identity field." in exc_info.value.reasons
        )
        assert calls == []
        assert budget.snapshot()["total_requests"] == 0
