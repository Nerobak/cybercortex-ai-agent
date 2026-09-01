from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import agent
import phase2_cli
from agent_core import verification_runtime as verification_runtime_module
from agent_core.agent_models import Hypothesis, TransportRequestContext
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquirer,
    OwnedObjectAcquisition,
    SessionAcquirer,
    SessionAcquisition,
)
from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import (
    DeterministicPolicyGate,
    Phase2PolicyContext,
    VerificationAction,
)
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.result_normalizer import redact
from agent_core.verification_runtime import build_verification_policy_context
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

ALICE_USERNAME = "alice-session-user"
ALICE_PASSWORD = "alice-private-password"
ALICE_TOKEN = "alice-private-token"
BOB_USERNAME = "bob-session-user"
BOB_PASSWORD = "bob-private-password"
BOB_TOKEN = "bob-private-token"


def _policy(prefix: str = "https://authorized.example/api") -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="controlled-session-test",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=prefix, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        credentials_allowed=True,
        controlled_account_ids=["alice", "bob"],
        allow_state_changes=False,
        request_budget=20,
    )


def _hypothesis_and_plan(account_ids: list[str] | None = None):
    accounts = account_ids or ["alice", "bob"]
    hypothesis = Hypothesis(
        hypothesis_id="hyp-controlled-bola",
        category="bola",
        title="Controlled object authorization differential",
        rationale="A controlled two-account comparison is required.",
        target="https://authorized.example/api/orders/{order_id}",
        endpoint="https://authorized.example/api/orders/{order_id}",
        method="GET",
        requires_credentials=True,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            controlled_accounts=accounts,
            credential_accounts=accounts,
            test_owned_resources=["order-alice"],
            request_budget=20,
            target_class="local_range",
            resource_owner_account_id="alice",
        ),
    )
    return hypothesis, plan


def _password_account(
    vault: CredentialVault,
    account_id: str,
    username: str,
    password: str,
) -> ControlledAccount:
    return ControlledAccount(
        account_id=account_id,
        credential_references={
            "username": vault.put(username, label=f"{account_id}:username"),
            "password": vault.put(password, label=f"{account_id}:password"),
        },
    )


def _context(vault: CredentialVault, *, include_unused: bool = False):
    accounts = [
        _password_account(vault, "alice", ALICE_USERNAME, ALICE_PASSWORD),
        _password_account(vault, "bob", BOB_USERNAME, BOB_PASSWORD),
    ]
    if include_unused:
        accounts.append(
            _password_account(vault, "charlie", "unused-user", "unused-password")
        )
    return ControlledContext(
        accounts=accounts,
        objects=[ControlledObject(object_id="order-alice", owner_account_id="alice")],
        session_acquisition=SessionAcquisition(
            url="https://authorized.example/api/sessions",
            method="POST",
            token_field="token",
        ),
    )


def _gate(policy: AssessmentPolicy, context: ControlledContext, limit: int = 20):
    return DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="local_range",
            controlled_account_ids=[
                account.account_id for account in context.accounts if account.controlled
            ],
            controlled_object_ids=[
                item.object_id for item in context.objects if item.test_owned
            ],
            object_acquisition_owner_ids=[
                item.owner_account_id for item in context.object_acquisition
            ],
            session_acquisition_url=(
                context.session_acquisition.url
                if context.session_acquisition is not None
                else None
            ),
            session_acquisition_method=(
                context.session_acquisition.method
                if context.session_acquisition is not None
                else None
            ),
            replay_enabled=True,
        ),
        RequestBudget(limit),
    )


def _execute(
    vault: CredentialVault,
    context: ControlledContext,
    transport,
    *,
    policy: AssessmentPolicy | None = None,
):
    hypothesis, plan = _hypothesis_and_plan()
    return ControlledVerificationExecutor(
        _gate(policy or _policy(), context), vault, context, transport
    ).execute(
        hypothesis,
        plan,
        inputs={
            "request_overrides": [
                {"url": "https://authorized.example/api/orders/order-alice"},
                {"url": "https://authorized.example/api/orders/order-alice"},
            ],
            "object_identifier": "order-alice",
            "ownership_confirmed": True,
            "separate_accounts_confirmed": True,
            "protected_fields": ["private_note"],
            "protected_data_confirmed": True,
        },
    )


def test_required_password_accounts_acquire_distinct_process_local_sessions():
    vault = CredentialVault()
    context = _context(vault, include_unused=True)
    authentication_requests = []
    verification_requests = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        if request["url"].endswith("/sessions"):
            authentication_requests.append(request)
            token = {
                ALICE_USERNAME: ALICE_TOKEN,
                BOB_USERNAME: BOB_TOKEN,
            }[request["json"]["username"]]
            return {"status_code": 200, "body": {"token": token, "ignored": "x"}}
        verification_requests.append(request)
        return {
            "status_code": 200,
            "body": {"id": "order-alice", "private_note": "controlled"},
        }

    try:
        result = _execute(vault, context, transport)

        assert _policy().allow_state_changes is False
        assert len(authentication_requests) == 2
        assert [item["method"] for item in authentication_requests] == ["POST"] * 2
        assert len(verification_requests) == 2
        assert [
            request["headers"]["Authorization"] for request in verification_requests
        ] == [f"Bearer {ALICE_TOKEN}", f"Bearer {BOB_TOKEN}"]
        assert all(account.session_reference for account in context.accounts[:2])
        assert context.accounts[2].session_reference is None
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
        serialized_context = json.dumps(context.model_dump(mode="json"))
        serialized_result = json.dumps(result)
        for secret in (
            ALICE_PASSWORD,
            ALICE_TOKEN,
            BOB_PASSWORD,
            BOB_TOKEN,
            "unused-password",
        ):
            assert secret not in serialized_context
            assert secret not in serialized_result
    finally:
        vault.close()


def test_typed_session_action_is_allowed_while_unrelated_mutations_stay_blocked():
    vault = CredentialVault()
    context = _context(vault)
    policy = _policy()
    gate = _gate(policy, context)
    try:
        session_action = SessionAcquirer.authorization_action(
            context.accounts[0], context.session_acquisition
        )
        decision = gate.authorize_session_acquisition(session_action)

        assert decision.allowed
        assert decision.reasons == []
        assert policy.allow_state_changes is False
        with pytest.raises(ValueError):
            VerificationAction(
                url="https://authorized.example/api/sessions",
                method="POST",
                category="arbitrary_verification_input",
                purpose="session_acquisition",
            )
        for method, url in (
            ("POST", "https://authorized.example/api/unrelated"),
            ("PATCH", "https://authorized.example/api/users/me"),
            ("PUT", "https://authorized.example/api/resource"),
        ):
            action = VerificationAction(
                url=url,
                method=method,
                category="bounded_policy_regression",
                purpose="state_mutation",
            )
            blocked = gate.authorize_action(action)
            assert not blocked.allowed
            assert "State-changing requests are disabled by policy." in blocked.reasons
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("policy_update", "account_controlled", "reason_fragment"),
    [
        ({"credentials_allowed": False}, True, "credential use is disabled"),
        ({}, False, "non-controlled account"),
        ({"controlled_account_ids": ["bob"]}, True, "not authorized by policy"),
    ],
)
def test_session_action_fails_closed_for_credential_and_account_policy(
    policy_update: dict[str, Any], account_controlled: bool, reason_fragment: str
):
    vault = CredentialVault()
    context = _context(vault)
    context.accounts[0].controlled = account_controlled
    policy = _policy().model_copy(update=policy_update)
    gate = _gate(policy, context)
    try:
        action = SessionAcquirer.authorization_action(
            context.accounts[0], context.session_acquisition
        )
        decision = gate.authorize_session_acquisition(action)

        assert not decision.allowed
        assert reason_fragment in " ".join(decision.reasons)
        assert gate.budget.snapshot()["auth_requests"] == 0
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("action_update", "reason_fragment"),
    [
        (
            {"url": "https://authorized.example/api/other-login"},
            "does not exactly match",
        ),
        ({"method": "GET"}, "method does not exactly match"),
    ],
)
def test_session_action_must_exactly_match_configured_endpoint_and_method(
    action_update: dict[str, Any], reason_fragment: str
):
    vault = CredentialVault()
    context = _context(vault)
    gate = _gate(_policy(), context)
    try:
        action = SessionAcquirer.authorization_action(
            context.accounts[0], context.session_acquisition
        ).model_copy(update=action_update)
        decision = gate.authorize_session_acquisition(action)

        assert not decision.allowed
        assert reason_fragment in " ".join(decision.reasons)
        assert gate.budget.snapshot()["auth_requests"] == 0
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("failed_username", "expected_auth_requests"),
    ((ALICE_USERNAME, 1), (BOB_USERNAME, 2)),
)
def test_failed_login_prevents_all_bola_requests(
    failed_username: str, expected_auth_requests: int
):
    vault = CredentialVault()
    context = _context(vault)
    authentication_requests = []
    verification_requests = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        if request["url"].endswith("/sessions"):
            authentication_requests.append(request)
            username = request["json"]["username"]
            if username == failed_username:
                return {"status_code": 401, "body": {"token": "must-not-be-used"}}
            return {"status_code": 200, "body": {"token": ALICE_TOKEN}}
        verification_requests.append(request)
        return {"status_code": 200, "body": {}}

    try:
        result = _execute(vault, context, transport)

        assert result["status"] == "inconclusive"
        assert result["requests_used"] == expected_auth_requests
        assert result["request_delta"]["auth"] == expected_auth_requests
        assert result["request_budget"]["auth_requests"] == expected_auth_requests
        assert result["request_budget"]["verification_requests"] == 0
        assert len(authentication_requests) == expected_auth_requests
        assert verification_requests == []
        assert "must-not-be-used" not in json.dumps(result)
    finally:
        vault.close()


def test_out_of_scope_session_endpoint_is_blocked_before_network():
    vault = CredentialVault()
    context = _context(vault)
    context.session_acquisition = SessionAcquisition(
        url="https://authorized.example/sessions",
        method="POST",
        token_field="token",
    )
    requests = []

    try:
        result = _execute(
            vault,
            context,
            lambda request: requests.append(request) or {"status_code": 200},
        )

        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
        assert result["request_delta"]["total"] == 0
        assert result["request_budget"]["auth_requests"] == 0
        assert requests == []
    finally:
        vault.close()


def test_pre_supplied_token_skips_that_accounts_login():
    vault = CredentialVault()
    alice_token_reference = vault.put(ALICE_TOKEN, label="alice:token")
    context = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="alice",
                credential_references={"token": alice_token_reference},
            ),
            _password_account(vault, "bob", BOB_USERNAME, BOB_PASSWORD),
        ],
        objects=[ControlledObject(object_id="order-alice", owner_account_id="alice")],
        session_acquisition=SessionAcquisition(
            url="https://authorized.example/api/sessions"
        ),
    )
    authentication_requests = []
    verification_requests = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        if request["url"].endswith("/sessions"):
            authentication_requests.append(request)
            return {"status_code": 200, "body": {"token": BOB_TOKEN}}
        verification_requests.append(request)
        return {
            "status_code": 403,
            "body": {"id": "order-alice"},
        }

    try:
        result = _execute(vault, context, transport)

        assert len(authentication_requests) == 1
        assert authentication_requests[0]["json"]["username"] == BOB_USERNAME
        assert result["request_budget"]["auth_requests"] == 1
        assert [
            request["headers"]["Authorization"] for request in verification_requests
        ] == [f"Bearer {ALICE_TOKEN}", f"Bearer {BOB_TOKEN}"]
    finally:
        vault.close()


class _Response:
    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._body


def _runtime_client_type(calls: list[dict[str, Any]]):
    """Build the same scoped client used by both verification entry paths."""

    class RuntimeTestClient(ScopedHTTPClient):
        def __init__(self, *, policy, budget, **_kwargs: Any) -> None:
            policy.resolve_dns_before_request = False

            def requester(method, url, **kwargs):
                calls.append({"method": method, "url": url, **kwargs})
                if url.endswith("/sessions"):
                    token = {
                        ALICE_USERNAME: ALICE_TOKEN,
                        BOB_USERNAME: BOB_TOKEN,
                    }[kwargs["json"]["username"]]
                    return _Response(200, {"token": token})
                return _Response(
                    200,
                    {
                        "id": "order-alice",
                        "tenant_id": "tenant-alpha",
                        "private_note": "controlled",
                        "projects": [
                            {
                                "project_id": "alpha-private-project",
                                "private_note": "controlled tenant data",
                            }
                        ],
                    },
                )

            super().__init__(policy=policy, budget=budget, requester=requester)

    return RuntimeTestClient


def _bind_scan_runtime(executor, policy, context):
    budget = RequestBudget(
        policy.request_budget,
        per_host_limit=policy.per_host_request_budget,
    )
    executor.network_client = verification_runtime_module.ScopedHTTPClient(
        policy=policy,
        budget=budget,
    )
    return DeterministicPolicyGate(
        policy,
        build_verification_policy_context(context, target_class="local_range"),
        budget,
    )


def _authorized_session_transport_context(
    policy: AssessmentPolicy,
    context: ControlledContext,
) -> TransportRequestContext:
    decision = _gate(policy, context).authorize_session_acquisition(
        SessionAcquirer.authorization_action(
            context.accounts[0], context.session_acquisition
        )
    )
    assert decision.allowed
    return decision.request_context


def _scoped_test_client(
    policy: AssessmentPolicy,
    calls: list[tuple[str, str]],
) -> ScopedHTTPClient:
    policy.resolve_dns_before_request = False

    def requester(method: str, url: str, **_kwargs: Any) -> _Response:
        calls.append((method, url))
        return _Response(200, {"ok": True})

    return ScopedHTTPClient(policy=policy, requester=requester)


def test_transport_allows_only_typed_exact_session_post():
    vault = CredentialVault()
    context = _context(vault)
    policy = _policy()
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)
    request_context = _authorized_session_transport_context(policy, context)
    try:
        response, redirects = client.request(
            "POST",
            context.session_acquisition.url,
            purpose="session_acquisition",
            request_context=request_context,
        )

        assert response.status_code == 200
        assert redirects == []
        assert calls == [("POST", context.session_acquisition.url)]
        assert policy.allow_state_changes is False
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("method", "url", "purpose", "include_context"),
    [
        ("POST", "https://authorized.example/api/sessions", None, False),
        (
            "POST",
            "https://authorized.example/api/sessions",
            "verification",
            False,
        ),
        (
            "POST",
            "https://authorized.example/api/other-login",
            "session_acquisition",
            True,
        ),
        (
            "GET",
            "https://authorized.example/api/sessions",
            "session_acquisition",
            True,
        ),
    ],
)
def test_transport_session_exception_fails_closed_for_missing_or_inconsistent_purpose(
    method: str,
    url: str,
    purpose: str | None,
    include_context: bool,
):
    vault = CredentialVault()
    context = _context(vault)
    policy = _policy()
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)
    request_context = _authorized_session_transport_context(policy, context)
    try:
        kwargs: dict[str, Any] = {"purpose": purpose}
        if include_context:
            kwargs["request_context"] = request_context
        with pytest.raises(PolicyViolationError):
            client.request(method, url, **kwargs)
        assert calls == []
    finally:
        vault.close()


def test_transport_session_exception_requires_credentials_allowed():
    vault = CredentialVault()
    context = _context(vault)
    authorized_policy = _policy()
    request_context = _authorized_session_transport_context(authorized_policy, context)
    policy = _policy().model_copy(update={"credentials_allowed": False})
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)
    try:
        with pytest.raises(PolicyViolationError, match="credential use is disabled"):
            client.request(
                "POST",
                context.session_acquisition.url,
                purpose="session_acquisition",
                request_context=request_context,
            )
        assert calls == []
    finally:
        vault.close()


@pytest.mark.parametrize(
    "context_update",
    (
        {"account_controlled": False},
        {"account_policy_authorized": False},
        {"controlled_account_id": "not-policy-authorized"},
    ),
)
def test_transport_session_exception_requires_controlled_policy_account(
    context_update: dict[str, Any],
):
    vault = CredentialVault()
    context = _context(vault)
    policy = _policy()
    request_context = _authorized_session_transport_context(policy, context).model_copy(
        update=context_update
    )
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)
    try:
        with pytest.raises(PolicyViolationError):
            client.request(
                "POST",
                context.session_acquisition.url,
                purpose="session_acquisition",
                request_context=request_context,
            )
        assert calls == []
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("method", "url", "purpose"),
    (
        ("POST", "https://authorized.example/api/orders", None),
        ("POST", "https://authorized.example/api/admin/users", None),
        ("PUT", "https://authorized.example/api/orders/1", "state_mutation"),
        ("PATCH", "https://authorized.example/api/orders/1", "state_mutation"),
        ("DELETE", "https://authorized.example/api/orders/1", "state_mutation"),
    ),
)
def test_transport_does_not_create_a_generic_mutation_exception(
    method: str, url: str, purpose: str | None
):
    policy = _policy().model_copy(
        update={"allowed_methods": ["DELETE", "GET", "PATCH", "POST", "PUT"]}
    )
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)

    with pytest.raises(PolicyViolationError):
        client.request(method, url, purpose=purpose)
    assert calls == []


def test_transport_owned_object_get_uses_normal_read_only_policy():
    policy = _policy()
    calls: list[tuple[str, str]] = []
    client = _scoped_test_client(policy, calls)

    response, _ = client.request(
        "GET",
        "https://authorized.example/api/orders",
        purpose="owned_object_acquisition",
    )

    assert response.status_code == 200
    assert calls == [("GET", "https://authorized.example/api/orders")]


@pytest.mark.parametrize(
    ("transport_response", "expected_status", "reason_fragment"),
    (
        (
            PolicyViolationError("unsafe internal detail"),
            "policy_blocked",
            "transport policy",
        ),
        (
            {"status_code": 401, "body": {"token": "must-not-be-used"}},
            "inconclusive",
            "authentication was rejected",
        ),
        (
            {"status_code": 200, "body": {"message": "ok"}},
            "inconclusive",
            "configured token field",
        ),
    ),
)
def test_session_failure_diagnostics_are_distinct_and_secret_free(
    transport_response: Exception | dict[str, Any],
    expected_status: str,
    reason_fragment: str,
):
    vault = CredentialVault()
    context = _context(vault)

    def transport(_request: dict[str, Any]) -> dict[str, Any]:
        if isinstance(transport_response, Exception):
            raise transport_response
        return transport_response

    try:
        result = _execute(vault, context, transport)

        assert result["status"] == expected_status
        assert reason_fragment in " ".join(result["reasons"])
        serialized = json.dumps(result)
        for secret in (
            ALICE_USERNAME,
            ALICE_PASSWORD,
            ALICE_TOKEN,
            BOB_USERNAME,
            BOB_PASSWORD,
            BOB_TOKEN,
            "unsafe internal detail",
            "must-not-be-used",
        ):
            assert secret not in serialized
    finally:
        vault.close()


def test_full_bola_flow_succeeds_through_semantic_transport(tmp_path):
    vault = CredentialVault()
    context = _acquisition_context(vault, password_sessions=True)
    policy = _policy()
    policy.resolve_dns_before_request = False
    gate = _gate(policy, context)
    wire_calls: list[tuple[str, str]] = []
    semantic_calls: list[tuple[str, str, str | None]] = []

    def requester(method: str, url: str, **kwargs: Any) -> _Response:
        wire_calls.append((method, url))
        if url.endswith("/sessions"):
            token = {
                ALICE_USERNAME: ALICE_TOKEN,
                BOB_USERNAME: BOB_TOKEN,
            }[kwargs["json"]["username"]]
            return _Response(200, {"token": token})
        if url.endswith("/orders"):
            return _Response(200, {"orders": [{"order_id": "owned-through-http"}]})
        return _Response(
            200,
            {"order_id": "owned-through-http", "private_note": "controlled"},
        )

    client = ScopedHTTPClient(policy=policy, requester=requester)

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        semantic_calls.append(
            (request["method"], request["url"], request.get("purpose"))
        )
        response, _ = client.request(
            request["method"],
            request["url"],
            headers=request.get("headers"),
            json=request.get("json"),
            purpose=request.get("purpose"),
            request_context=request.get("request_context"),
            follow_redirects=False,
        )
        return {"status_code": response.status_code, "body": response.json()}

    hypothesis, plan = _context_independent_bola_plan()
    try:
        result = ControlledVerificationExecutor(
            gate, vault, context, transport
        ).execute(
            hypothesis,
            plan,
            inputs={
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            },
        )

        assert result["status"] == "verified"
        assert len(wire_calls) == 5
        assert [purpose for _, _, purpose in semantic_calls] == [
            "session_acquisition",
            "session_acquisition",
            "owned_object_acquisition",
            "verification",
            "verification",
        ]
        assert [method for method, _ in wire_calls] == [
            "POST",
            "POST",
            "GET",
            "GET",
            "GET",
        ]
        assert result["request_budget"]["total_requests"] == 5
        store = Phase2RunStore(tmp_path / "semantic-transport-runs")
        stored_path = store.save(
            {"run_id": "semantic-transport", "verification_results": [result]}
        )
        diagnostics = {
            "dns": client.dns_observations,
            "request_contexts": [
                item.request_context.model_dump(mode="json")
                for item in (
                    gate.authorize_session_acquisition(
                        SessionAcquirer.authorization_action(
                            account, context.session_acquisition
                        )
                    )
                    for account in context.accounts
                )
            ],
        }
        rendered = "\n".join(
            (
                json.dumps(result),
                Path(stored_path).read_text(encoding="utf-8"),
                render_phase2_report(store.load()),
                json.dumps(diagnostics),
            )
        )
        for secret in (
            ALICE_USERNAME,
            ALICE_PASSWORD,
            ALICE_TOKEN,
            BOB_USERNAME,
            BOB_PASSWORD,
            BOB_TOKEN,
        ):
            assert secret not in rendered
        assert "Authorization" not in rendered
    finally:
        vault.close()


def _write_controlled_files(tmp_path):
    context_path = tmp_path / "controlled.json"
    context_path.write_text(
        json.dumps(
            {
                "accounts": [
                    {
                        "account_id": "alice",
                        "username": ALICE_USERNAME,
                        "password": ALICE_PASSWORD,
                    },
                    {
                        "account_id": "bob",
                        "username": BOB_USERNAME,
                        "password": BOB_PASSWORD,
                    },
                ],
                "objects": [{"object_id": "order-alice", "owner_account_id": "alice"}],
                "session_acquisition": {
                    "url": "https://authorized.example/api/sessions",
                    "method": "POST",
                    "token_field": "token",
                },
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(_policy().model_dump_json(), encoding="utf-8")
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_text(
        json.dumps(
            {
                "request_overrides": [
                    {"url": "https://authorized.example/api/orders/order-alice"},
                    {"url": "https://authorized.example/api/orders/order-alice"},
                ],
                "object_identifier": "order-alice",
                "ownership_confirmed": True,
                "separate_accounts_confirmed": True,
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            }
        ),
        encoding="utf-8",
    )
    return context_path, policy_path, inputs_path


def _write_tenant_controlled_files(tmp_path):
    context_path = tmp_path / "tenant-controlled.json"
    context_path.write_text(
        json.dumps(
            {
                "accounts": [
                    {
                        "account_id": "alice",
                        "tenant_id": "tenant-alpha",
                        "username": ALICE_USERNAME,
                        "password": ALICE_PASSWORD,
                    },
                    {
                        "account_id": "bob",
                        "tenant_id": "tenant-beta",
                        "username": BOB_USERNAME,
                        "password": BOB_PASSWORD,
                    },
                ],
                "objects": [
                    {
                        "object_id": "tenant-alpha",
                        "owner_account_id": "alice",
                        "tenant_id": "tenant-alpha",
                        "object_type": "tenant",
                        "test_owned": True,
                    }
                ],
                "session_acquisition": {
                    "url": "https://authorized.example/api/sessions",
                    "method": "POST",
                    "token_field": "token",
                },
            }
        ),
        encoding="utf-8",
    )
    policy_path = tmp_path / "tenant-policy.json"
    policy_path.write_text(_policy().model_dump_json(), encoding="utf-8")
    inputs_path = tmp_path / "tenant-inputs.json"
    inputs_path.write_text(
        json.dumps(
            {
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            }
        ),
        encoding="utf-8",
    )
    return context_path, policy_path, inputs_path


def test_standalone_command_acquires_sessions_without_persisting_secrets(
    monkeypatch, tmp_path
):
    context_path, policy_path, inputs_path = _write_controlled_files(tmp_path)
    hypothesis, plan = _context_independent_bola_plan()
    stored_template = plan.model_dump(mode="json")
    store = Phase2RunStore(tmp_path / "runs")
    store.save(
        {
            "run_id": "controlled-session-run",
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_plans": [plan.model_dump(mode="json")],
            "verification_results": [],
            "metrics": {},
        }
    )
    calls = []

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def request(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            if url.endswith("/sessions"):
                token = {
                    ALICE_USERNAME: ALICE_TOKEN,
                    BOB_USERNAME: BOB_TOKEN,
                }[kwargs["json"]["username"]]
                return _Response(200, {"token": token}), {}
            return (
                _Response(
                    200,
                    {"id": "order-alice", "private_note": "controlled"},
                ),
                {},
            )

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: store)
    monkeypatch.setattr(
        verification_runtime_module, "ScopedHTTPClient", _runtime_client_type(calls)
    )

    result = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(policy_path),
            "--context",
            str(context_path),
            "--input",
            str(inputs_path),
            "--lab",
        ]
    )

    auth_calls = [call for call in calls if call["url"].endswith("/sessions")]
    bola_calls = [call for call in calls if not call["url"].endswith("/sessions")]
    stored = store.load()
    rendered = "\n".join(
        (json.dumps(result), json.dumps(stored), render_phase2_report(stored))
    )
    assert len(auth_calls) == 2
    assert _policy().allow_state_changes is False
    assert [call["headers"]["Authorization"] for call in bola_calls] == [
        f"Bearer {ALICE_TOKEN}",
        f"Bearer {BOB_TOKEN}",
    ]
    assert stored["metrics"]["auth_requests"] == 2
    assert stored["metrics"]["verification_requests"] == 2
    assert stored["metrics"]["total_requests"] == 4
    assert stored["verification_plans"][0] == stored_template
    assert result["runtime_binding"]["bound_accounts"] == 2
    assert result["runtime_binding"]["policy_authorized"] is True
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 2,
        "verification": 2,
        "cleanup": 0,
        "attempted": 4,
        "total": 4,
    }
    for secret in (
        ALICE_USERNAME,
        ALICE_PASSWORD,
        ALICE_TOKEN,
        BOB_USERNAME,
        BOB_PASSWORD,
        BOB_TOKEN,
    ):
        assert secret not in rendered
    assert "Authorization" not in rendered


def test_standalone_command_runtime_binds_tenant_isolation(monkeypatch, tmp_path):
    context_path, policy_path, inputs_path = _write_tenant_controlled_files(tmp_path)
    hypothesis, plan = _context_independent_tenant_plan()
    store = Phase2RunStore(tmp_path / "tenant-runs")
    store.save(
        {
            "run_id": "tenant-runtime-binding-run",
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_plans": [plan.model_dump(mode="json")],
            "verification_results": [],
            "metrics": {},
        }
    )
    calls: list[dict[str, Any]] = []

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def request(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            if url.endswith("/sessions"):
                token = {
                    ALICE_USERNAME: ALICE_TOKEN,
                    BOB_USERNAME: BOB_TOKEN,
                }[kwargs["json"]["username"]]
                return _Response(200, {"token": token}), {}
            return (
                _Response(
                    200,
                    {
                        "tenant_id": "tenant-alpha",
                        "projects": [
                            {
                                "project_id": "alpha-private-project",
                                "private_note": "controlled tenant data",
                            }
                        ],
                    },
                ),
                {},
            )

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: store)
    monkeypatch.setattr(
        verification_runtime_module, "ScopedHTTPClient", _runtime_client_type(calls)
    )

    result = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(policy_path),
            "--context",
            str(context_path),
            "--input",
            str(inputs_path),
            "--lab",
        ]
    )

    comparison_calls = [item for item in calls if not item["url"].endswith("/sessions")]
    assert result["status"] == "verified"
    assert result["runtime_binding"]["bound_accounts"] == 2
    assert result["runtime_binding"]["policy_authorized"] is True
    assert [item["url"] for item in comparison_calls] == [
        "https://authorized.example/api/tenants/tenant-alpha/projects",
        "https://authorized.example/api/tenants/tenant-alpha/projects",
    ]
    assert [item["headers"]["Authorization"] for item in comparison_calls] == [
        f"Bearer {ALICE_TOKEN}",
        f"Bearer {BOB_TOKEN}",
    ]


def test_run_schema_authorization_flags_preserve_only_boolean_values():
    assert redact({"authorization_confirmed": True}) == {
        "authorization_confirmed": True
    }
    assert redact({"requires_explicit_authorization": False}) == {
        "requires_explicit_authorization": False
    }
    assert redact({"authorization_confirmed": ALICE_TOKEN}) == {
        "authorization_confirmed": "[REDACTED]"
    }


def test_agent_verify_scan_uses_controlled_session_acquisition(monkeypatch, tmp_path):
    context_path, policy_path, inputs_path = _write_controlled_files(tmp_path)
    hypothesis, plan = _context_independent_bola_plan()
    calls = []

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def request(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            if url.endswith("/sessions"):
                token = {
                    ALICE_USERNAME: ALICE_TOKEN,
                    BOB_USERNAME: BOB_TOKEN,
                }[kwargs["json"]["username"]]
                return _Response(200, {"token": token}), {}
            return _Response(403, {"id": "order-alice"}), {}

    def fake_workflow(_goal, _target, _domain, **kwargs):
        assert kwargs["phase2_policy"].allow_state_changes is False
        context = kwargs["controlled_context"]
        executor = kwargs["phase2_executor"]
        gate = _bind_scan_runtime(executor, kwargs["phase2_policy"], context)
        output = executor(hypothesis, plan, gate)
        return {"success": True, "verification": output}

    monkeypatch.setattr(agent, "enforce_scope", lambda _target: {"allowed": True})
    monkeypatch.setattr(agent, "run_workflow", fake_workflow)
    monkeypatch.setattr(
        verification_runtime_module, "ScopedHTTPClient", _runtime_client_type(calls)
    )

    result = agent.run_scan_command(
        " ".join(
            (
                "https://authorized.example/api",
                "--mode verify",
                "--profile authenticated",
                f"--policy {policy_path}",
                f"--context {context_path}",
                f"--verification-input {inputs_path}",
                "--lab",
            )
        )
    )

    assert result["success"] is True
    assert result["verification"]["request_budget"]["auth_requests"] == 2
    assert result["verification"]["request_delta"] == {
        "discovery": 0,
        "auth": 2,
        "verification": 2,
        "cleanup": 0,
        "attempted": 4,
        "total": 4,
    }
    assert len([call for call in calls if call["url"].endswith("/sessions")]) == 2
    bola_calls = [call for call in calls if not call["url"].endswith("/sessions")]
    assert [call["headers"]["Authorization"] for call in bola_calls] == [
        f"Bearer {ALICE_TOKEN}",
        f"Bearer {BOB_TOKEN}",
    ]
    assert ALICE_TOKEN not in json.dumps(result)
    assert BOB_TOKEN not in json.dumps(result)


def test_agent_verify_scan_runtime_binds_tenant_isolation(monkeypatch, tmp_path):
    context_path, policy_path, inputs_path = _write_tenant_controlled_files(tmp_path)
    inputs_path.write_text(
        json.dumps(
            {
                "defaults": {
                    "protected_fields": ["private_note"],
                    "protected_data_confirmed": True,
                }
            }
        ),
        encoding="utf-8",
    )
    hypothesis, plan = _context_independent_tenant_plan()
    calls: list[dict[str, Any]] = []

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def request(self, method, url, **kwargs):
            calls.append({"method": method, "url": url, **kwargs})
            if url.endswith("/sessions"):
                token = {
                    ALICE_USERNAME: ALICE_TOKEN,
                    BOB_USERNAME: BOB_TOKEN,
                }[kwargs["json"]["username"]]
                return _Response(200, {"token": token}), {}
            return (
                _Response(
                    200,
                    {
                        "tenant_id": "tenant-alpha",
                        "projects": [
                            {
                                "project_id": "alpha-private-project",
                                "private_note": "controlled tenant data",
                            }
                        ],
                    },
                ),
                {},
            )

    def fake_workflow(_goal, _target, _domain, **kwargs):
        context = kwargs["controlled_context"]
        executor = kwargs["phase2_executor"]
        gate = _bind_scan_runtime(executor, kwargs["phase2_policy"], context)
        output = executor(hypothesis, plan, gate)
        return {"success": True, "verification": output}

    monkeypatch.setattr(agent, "enforce_scope", lambda _target: {"allowed": True})
    monkeypatch.setattr(agent, "run_workflow", fake_workflow)
    monkeypatch.setattr(
        verification_runtime_module, "ScopedHTTPClient", _runtime_client_type(calls)
    )

    result = agent.run_scan_command(
        " ".join(
            (
                "https://authorized.example/api",
                "--mode verify",
                "--profile authenticated",
                f"--policy {policy_path}",
                f"--context {context_path}",
                f"--verification-input {inputs_path}",
                "--lab",
            )
        )
    )

    comparison_calls = [item for item in calls if not item["url"].endswith("/sessions")]
    assert result["success"] is True
    assert result["verification"]["status"] == "verified"
    assert result["verification"]["runtime_binding"] == {
        "required_accounts": 2,
        "bound_accounts": 2,
        "owner_bound": True,
        "comparator_bound": True,
        "policy_authorized": True,
    }
    assert result["verification"]["request_delta"] == {
        "discovery": 0,
        "auth": 2,
        "verification": 2,
        "cleanup": 0,
        "attempted": 4,
        "total": 4,
    }
    assert [item["url"] for item in comparison_calls] == [
        "https://authorized.example/api/tenants/tenant-alpha/projects",
        "https://authorized.example/api/tenants/tenant-alpha/projects",
    ]
    assert [item["headers"]["Authorization"] for item in comparison_calls] == [
        f"Bearer {ALICE_TOKEN}",
        f"Bearer {BOB_TOKEN}",
    ]


def _acquisition_plan(
    *,
    category: str = "bola",
    target: str = "https://authorized.example/api/orders/{order_id}",
    has_existing_object: bool = False,
):
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-controlled-{category}-acquisition",
        category=category,
        title="Controlled owned-object acquisition differential",
        rationale="A controlled comparison requires owned evidence.",
        target=target,
        endpoint=target,
        method="GET",
        requires_credentials=True,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            controlled_accounts=["alice", "bob"],
            credential_accounts=["alice", "bob"],
            test_owned_resources=["existing-order"] if has_existing_object else [],
            object_acquisition_owner_ids=["alice"],
            request_budget=20,
            target_class="local_range",
            resource_owner_account_id="alice",
        ),
    )
    return hypothesis, plan


def _context_independent_bola_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-runtime-bound-bola",
        category="bola",
        title="Runtime-bound object authorization differential",
        rationale="A reusable plan defers controlled identities until verify mode.",
        target="https://authorized.example/api/orders/{order_id}",
        endpoint="https://authorized.example/api/orders/{order_id}",
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
            target_class="local_range",
        ),
    )
    return hypothesis, plan


def _context_independent_tenant_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-runtime-bound-tenant-isolation",
        category="tenant_isolation",
        title="Runtime-bound tenant authorization differential",
        rationale="A reusable plan defers controlled tenants until verify mode.",
        target=("https://authorized.example/api/tenants/{tenant_id}/projects"),
        endpoint=("https://authorized.example/api/tenants/{tenant_id}/projects"),
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
            target_class="local_range",
        ),
    )
    return hypothesis, plan


def _tenant_context(
    vault: CredentialVault,
    *,
    bob_tenant: str | None = "tenant-beta",
    object_tenant: str | None = "tenant-alpha",
    object_owner: str = "alice",
    object_test_owned: bool = True,
    include_bob: bool = True,
    include_acquisition: bool = False,
) -> ControlledContext:
    accounts = [_token_account(vault, "alice", ALICE_TOKEN, tenant_id="tenant-alpha")]
    if include_bob:
        accounts.append(_token_account(vault, "bob", BOB_TOKEN, tenant_id=bob_tenant))
    return ControlledContext(
        accounts=accounts,
        objects=[
            ControlledObject(
                object_id="tenant-alpha",
                owner_account_id=object_owner,
                tenant_id=object_tenant,
                object_type="tenant",
                test_owned=object_test_owned,
            )
        ],
        object_acquisition=(
            [
                OwnedObjectAcquisition(
                    owner_account_id="alice",
                    collection_url=("https://authorized.example/api/tenant-resources"),
                    object_type="tenant",
                    identifier_field="tenant_id",
                    tenant_field="tenant_id",
                )
            ]
            if include_acquisition
            else []
        ),
    )


def _token_account(
    vault: CredentialVault,
    account_id: str,
    token: str,
    *,
    tenant_id: str | None = None,
) -> ControlledAccount:
    return ControlledAccount(
        account_id=account_id,
        tenant_id=tenant_id,
        credential_references={
            "token": vault.put(token, label=f"{account_id}:acquisition-token")
        },
    )


def _acquisition_context(
    vault: CredentialVault,
    *,
    collection_url: str = "https://authorized.example/api/orders",
    method: str = "GET",
    existing: bool = False,
    password_sessions: bool = False,
    tenant_scoped: bool = False,
) -> ControlledContext:
    accounts = (
        [
            _password_account(vault, "alice", ALICE_USERNAME, ALICE_PASSWORD),
            _password_account(vault, "bob", BOB_USERNAME, BOB_PASSWORD),
        ]
        if password_sessions
        else [
            _token_account(
                vault,
                "alice",
                ALICE_TOKEN,
                tenant_id="tenant-a" if tenant_scoped else None,
            ),
            _token_account(
                vault,
                "bob",
                BOB_TOKEN,
                tenant_id="tenant-b" if tenant_scoped else None,
            ),
        ]
    )
    return ControlledContext(
        accounts=accounts,
        objects=(
            [
                ControlledObject(
                    object_id="existing-order",
                    owner_account_id="alice",
                    tenant_id="tenant-a" if tenant_scoped else None,
                    object_type="order",
                )
            ]
            if existing
            else []
        ),
        session_acquisition=(
            SessionAcquisition(url="https://authorized.example/api/sessions")
            if password_sessions
            else None
        ),
        object_acquisition=[
            OwnedObjectAcquisition(
                owner_account_id="alice",
                collection_url=collection_url,
                method=method,
                object_type="order",
                identifier_field="order_id",
                tenant_field="tenant_id",
                max_items=20,
            )
        ],
    )


def _execute_acquisition(
    vault: CredentialVault,
    context: ControlledContext,
    transport,
    *,
    category: str = "bola",
    target: str = "https://authorized.example/api/orders/{order_id}",
    has_existing_object: bool = False,
    limit: int = 20,
):
    hypothesis, plan = _acquisition_plan(
        category=category,
        target=target,
        has_existing_object=has_existing_object,
    )
    return ControlledVerificationExecutor(
        _gate(_policy(), context, limit=limit), vault, context, transport
    ).execute(
        hypothesis,
        plan,
        inputs={
            "protected_fields": ["private_note"],
            "protected_data_confirmed": True,
        },
    )


def test_owned_object_acquirer_builds_in_memory_test_owned_object():
    vault = CredentialVault()
    account = _token_account(vault, "alice", ALICE_TOKEN)
    config = OwnedObjectAcquisition(
        owner_account_id="alice",
        collection_url="https://authorized.example/api/orders",
        object_type="order",
        identifier_field="external_order_key",
        tenant_field="workspace",
    )
    budget = RequestBudget(1)
    try:
        acquired = OwnedObjectAcquirer(vault, budget).acquire(
            account,
            config,
            lambda request: {
                "status_code": 200,
                "body": [
                    {
                        "external_order_key": "owned-42",
                        "workspace": "tenant-a",
                    }
                ],
            },
        )

        assert acquired == ControlledObject(
            object_id="owned-42",
            owner_account_id="alice",
            tenant_id="tenant-a",
            object_type="order",
            test_owned=True,
        )
        assert budget.snapshot()["discovery_requests"] == 1
    finally:
        vault.close()


def test_bola_authenticates_owner_acquires_collection_and_uses_concrete_id(
    tmp_path, capsys
):
    vault = CredentialVault()
    context = _acquisition_context(vault, password_sessions=True)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        if request["url"].endswith("/sessions"):
            token = {
                ALICE_USERNAME: ALICE_TOKEN,
                BOB_USERNAME: BOB_TOKEN,
            }[request["json"]["username"]]
            return {"status_code": 200, "body": {"token": token}}
        if request["url"].endswith("/orders"):
            return {
                "status_code": 200,
                "body": [
                    {
                        "order_id": "alice-owned-42",
                        "tenant_id": "tenant-a",
                    }
                ],
            }
        return {
            "status_code": 200,
            "body": {
                "order_id": "alice-owned-42",
                "private_note": "controlled",
            },
        }

    try:
        result = _execute_acquisition(vault, context, transport)

        assert _policy().allow_state_changes is False
        collection_calls = [call for call in calls if call["url"].endswith("/orders")]
        bola_calls = [call for call in calls if "/orders/alice-owned-42" in call["url"]]
        assert result["status"] == "verified"
        assert len(collection_calls) == 1
        assert collection_calls[0]["method"] == "GET"
        assert collection_calls[0]["headers"]["Authorization"] == (
            f"Bearer {ALICE_TOKEN}"
        )
        assert len(bola_calls) == 2
        assert [call["headers"]["Authorization"] for call in bola_calls] == [
            f"Bearer {ALICE_TOKEN}",
            f"Bearer {BOB_TOKEN}",
        ]
        assert context.objects == []
        assert result["owned_object_acquisition"] == {
            "attempted": True,
            "succeeded": True,
            "owner": "alice",
            "object_type": "order",
            "identifier_present": True,
            "controlled_test_owned_evidence": True,
        }
        assert result["request_budget"]["auth_requests"] == 2
        assert result["request_budget"]["discovery_requests"] == 1
        assert result["request_budget"]["verification_requests"] == 2
        assert result["request_budget"]["total_requests"] == 5
        assert result["request_delta"] == {
            "discovery": 1,
            "auth": 2,
            "verification": 2,
            "cleanup": 0,
            "attempted": 5,
            "total": 5,
        }
        serialized = json.dumps(result)
        assert ALICE_TOKEN not in serialized
        assert BOB_TOKEN not in serialized
        assert "Authorization" not in serialized
        assert "cred_" not in serialized
        assert "alice-owned-42" not in serialized
        stored_run = {
            "run_id": "owned-acquisition-run",
            "verification_results": [result],
        }
        store = Phase2RunStore(tmp_path / "runs")
        stored_path = store.save(stored_run)
        rendered = Path(stored_path).read_text(encoding="utf-8") + render_phase2_report(
            stored_run
        )
        assert "Owned object acquisition:" in rendered
        assert "Attempted: true" in rendered
        assert "Succeeded: true" in rendered
        assert "Identifier present: true" in rendered
        assert "controlled test-owned evidence" in rendered
        for secret in (ALICE_PASSWORD, ALICE_TOKEN, BOB_PASSWORD, BOB_TOKEN):
            assert secret not in rendered
        assert "Authorization" not in rendered
        assert "cred_" not in rendered
        assert "alice-owned-42" not in rendered
        agent.print_result({"success": True, **result})
        console = capsys.readouterr().out
        assert "Owned object acquisition:" in console
        assert "Attempted: True" in console
        assert "Succeeded: True" in console
        assert "Identifier present: True" in console
        assert "Controlled test-owned evidence" in console
        assert ALICE_TOKEN not in console
        assert BOB_TOKEN not in console
        assert "Authorization" not in console
        assert "cred_" not in console
        assert "alice-owned-42" not in console
    finally:
        vault.close()


def test_context_independent_bola_plan_binds_runtime_accounts_and_owned_object(
    tmp_path,
):
    vault = CredentialVault()
    context = _acquisition_context(vault, password_sessions=True)
    policy = _policy().model_copy(update={"controlled_account_ids": ["alice", "bob"]})
    hypothesis, plan = _context_independent_bola_plan()
    stored_template = plan.model_dump(mode="json")
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        if request["url"].endswith("/sessions"):
            token = {
                ALICE_USERNAME: ALICE_TOKEN,
                BOB_USERNAME: BOB_TOKEN,
            }[request["json"]["username"]]
            return {"status_code": 200, "body": {"token": token}}
        if request["url"].endswith("/orders"):
            return {
                "status_code": 200,
                "body": [{"order_id": "runtime-owned-order"}],
            }
        return {
            "status_code": 200,
            "body": {
                "order_id": "runtime-owned-order",
                "private_note": "controlled",
            },
        }

    try:
        result = ControlledVerificationExecutor(
            _gate(policy, context), vault, context, transport
        ).execute(
            hypothesis,
            plan,
            inputs={
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            },
        )

        auth_calls = [call for call in calls if call["url"].endswith("/sessions")]
        acquisition_calls = [call for call in calls if call["url"].endswith("/orders")]
        comparison_calls = [
            call for call in calls if "/orders/runtime-owned-order" in call["url"]
        ]
        assert len(auth_calls) == 2
        assert len(acquisition_calls) == 1
        assert len(comparison_calls) == 2
        assert [call["headers"]["Authorization"] for call in comparison_calls] == [
            f"Bearer {ALICE_TOKEN}",
            f"Bearer {BOB_TOKEN}",
        ]
        assert result["runtime_binding"] == {
            "required_accounts": 2,
            "bound_accounts": 2,
            "owner_bound": True,
            "comparator_bound": True,
            "policy_authorized": True,
        }
        assert plan.model_dump(mode="json") == stored_template
        assert plan.controlled_accounts == []
        assert all(
            request.get("account_id") is None
            for step in plan.steps
            for request in step.metadata.get("requests", [])
        )

        store = Phase2RunStore(tmp_path / "runtime-binding-runs")
        store.save(
            {
                "run_id": "runtime-binding-run",
                "verification_plans": [stored_template],
                "verification_results": [result],
            }
        )
        serialized = json.dumps({"result": result, "stored": store.load()})
        for secret in (
            ALICE_USERNAME,
            ALICE_PASSWORD,
            ALICE_TOKEN,
            BOB_USERNAME,
            BOB_PASSWORD,
            BOB_TOKEN,
        ):
            assert secret not in serialized
        assert "Authorization" not in serialized
        assert "cred_" not in serialized
    finally:
        vault.close()


def test_context_independent_tenant_plan_binds_explicit_object_and_two_tenants():
    vault = CredentialVault()
    context = _tenant_context(vault, include_acquisition=True)
    policy = _policy().model_copy(update={"controlled_account_ids": ["alice", "bob"]})
    hypothesis, plan = _context_independent_tenant_plan()
    stored_template = plan.model_dump(mode="json")
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        return {
            "status_code": 200,
            "body": {
                "tenant_id": "tenant-alpha",
                "projects": [
                    {
                        "project_id": "alpha-private-project",
                        "private_note": "controlled tenant data",
                    }
                ],
            },
        }

    try:
        result = ControlledVerificationExecutor(
            _gate(policy, context), vault, context, transport
        ).execute(
            hypothesis,
            plan,
            inputs={
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            },
        )

        assert result["status"] == "verified"
        assert result["runtime_binding"] == {
            "required_accounts": 2,
            "bound_accounts": 2,
            "owner_bound": True,
            "comparator_bound": True,
            "policy_authorized": True,
        }
        assert len(calls) == 2
        assert [item["method"] for item in calls] == ["GET", "GET"]
        assert [item["url"] for item in calls] == [
            "https://authorized.example/api/tenants/tenant-alpha/projects",
            "https://authorized.example/api/tenants/tenant-alpha/projects",
        ]
        assert [item["headers"]["Authorization"] for item in calls] == [
            f"Bearer {ALICE_TOKEN}",
            f"Bearer {BOB_TOKEN}",
        ]
        assert result["owned_object_acquisition"]["attempted"] is False
        assert result["request_budget"]["discovery_requests"] == 0
        assert result["request_delta"] == {
            "discovery": 0,
            "auth": 0,
            "verification": 2,
            "cleanup": 0,
            "attempted": 2,
            "total": 2,
        }
        assert result["analysis"]["ownership_confirmed"] is True
        assert result["analysis"]["separate_accounts_confirmed"] is True
        assert result["analysis"]["distinct_tenants_confirmed"] is True
        assert result["analysis"]["protected_data_confirmed"] is True
        assert result["analysis"]["object_identity_matched"] is True
        assert result["analysis"]["owner_object_identity_matched"] is True
        assert result["analysis"]["protected_evidence_matched"] is True
        assert plan.model_dump(mode="json") == stored_template
    finally:
        vault.close()


@pytest.mark.parametrize(
    "case",
    (
        "same_tenant",
        "object_tenant_mismatch",
        "one_policy_account",
        "owner_missing",
        "comparator_missing",
        "tenant_metadata_missing",
        "object_not_test_owned",
    ),
)
def test_runtime_tenant_binding_fails_closed_before_network(case):
    vault = CredentialVault()
    context_options: dict[str, Any] = {}
    policy = _policy().model_copy(update={"controlled_account_ids": ["alice", "bob"]})
    if case == "same_tenant":
        context_options["bob_tenant"] = "tenant-alpha"
    elif case == "object_tenant_mismatch":
        context_options["object_tenant"] = "tenant-gamma"
    elif case == "one_policy_account":
        policy.controlled_account_ids = ["alice"]
    elif case == "owner_missing":
        context_options["object_owner"] = "carol"
    elif case == "comparator_missing":
        context_options["include_bob"] = False
    elif case == "tenant_metadata_missing":
        context_options["bob_tenant"] = None
    elif case == "object_not_test_owned":
        context_options["object_test_owned"] = False
    context = _tenant_context(vault, **context_options)
    hypothesis, plan = _context_independent_tenant_plan()
    calls: list[dict[str, Any]] = []

    try:
        result = ControlledVerificationExecutor(
            _gate(policy, context),
            vault,
            context,
            lambda request: calls.append(request) or {"status_code": 200},
        ).execute(hypothesis, plan)

        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
        assert result["runtime_binding"]["required_accounts"] == 2
        assert result["runtime_binding"]["policy_authorized"] is False
        assert calls == []
    finally:
        vault.close()


def test_tenant_equal_success_without_confirmed_protected_data_is_inconclusive():
    vault = CredentialVault()
    context = _tenant_context(vault)
    hypothesis, plan = _context_independent_tenant_plan()
    calls: list[dict[str, Any]] = []

    try:
        result = ControlledVerificationExecutor(
            _gate(_policy(), context),
            vault,
            context,
            lambda request: calls.append(request)
            or {
                "status_code": 200,
                "body": {
                    "tenant_id": "tenant-alpha",
                    "projects": [{"project_id": "public-project"}],
                },
            },
        ).execute(
            hypothesis,
            plan,
            inputs={"protected_fields": [], "protected_data_confirmed": False},
        )

        assert calls == []
        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
    finally:
        vault.close()


def test_tenant_protected_data_must_match_owner_evidence():
    vault = CredentialVault()
    context = _tenant_context(vault)
    hypothesis, plan = _context_independent_tenant_plan()

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        is_owner = request["headers"]["Authorization"] == f"Bearer {ALICE_TOKEN}"
        return {
            "status_code": 200,
            "body": {
                "tenant_id": "tenant-alpha",
                "projects": [
                    {
                        "project_id": "alpha-private-project",
                        "private_note": (
                            "owner evidence" if is_owner else "different evidence"
                        ),
                    }
                ],
            },
        }

    try:
        result = ControlledVerificationExecutor(
            _gate(_policy(), context), vault, context, transport
        ).execute(
            hypothesis,
            plan,
            inputs={
                "protected_fields": ["private_note"],
                "protected_data_confirmed": True,
            },
        )

        assert result["status"] == "inconclusive"
        assert result["analysis"]["protected_data_confirmed"] is True
        assert result["analysis"]["protected_evidence_matched"] is False
    finally:
        vault.close()


@pytest.mark.parametrize("case", ("policy", "context", "duplicate"))
def test_runtime_bola_binding_requires_two_distinct_policy_eligible_accounts(case):
    vault = CredentialVault()
    context = _acquisition_context(vault, password_sessions=True)
    policy = _policy().model_copy(update={"controlled_account_ids": ["alice", "bob"]})
    if case == "policy":
        policy.controlled_account_ids = ["alice"]
    elif case == "context":
        context.accounts = context.accounts[:1]
    else:
        context.accounts[1].account_id = "alice"
    hypothesis, plan = _context_independent_bola_plan()
    calls: list[dict[str, Any]] = []
    try:
        result = ControlledVerificationExecutor(
            _gate(policy, context),
            vault,
            context,
            lambda request: calls.append(request) or {"status_code": 200},
        ).execute(hypothesis, plan)

        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
        assert result["runtime_binding"]["policy_authorized"] is False
        assert calls == []
    finally:
        vault.close()


def test_runtime_bola_binding_missing_credentials_sends_no_network_traffic():
    vault = CredentialVault()
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="alice"),
            ControlledAccount(account_id="bob"),
        ],
        session_acquisition=SessionAcquisition(
            url="https://authorized.example/api/sessions"
        ),
        object_acquisition=[
            OwnedObjectAcquisition(
                owner_account_id="alice",
                collection_url="https://authorized.example/api/orders",
                object_type="order",
                identifier_field="order_id",
            )
        ],
    )
    policy = _policy().model_copy(update={"controlled_account_ids": ["alice", "bob"]})
    hypothesis, plan = _context_independent_bola_plan()
    calls: list[dict[str, Any]] = []
    try:
        result = ControlledVerificationExecutor(
            _gate(policy, context),
            vault,
            context,
            lambda request: calls.append(request) or {"status_code": 200},
        ).execute(hypothesis, plan)

        assert result["status"] == "policy_blocked"
        assert result["requests_used"] == 0
        assert result["runtime_binding"]["bound_accounts"] == 2
        assert result["request_budget"]["verification_requests"] == 0
        assert calls == []
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("body", "reason_fragment"),
    [
        ([], "collection was empty"),
        ([{"tenant_id": "tenant-a"}], "identifier field was absent"),
        (
            {"orders": [{"order_id": "one"}], "other": [{"order_id": "two"}]},
            "structure was ambiguous",
        ),
    ],
)
def test_invalid_owned_collection_is_inconclusive_without_bola_requests(
    body: Any, reason_fragment: str
):
    vault = CredentialVault()
    context = _acquisition_context(vault)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        return {"status_code": 200, "body": body}

    try:
        result = _execute_acquisition(vault, context, transport)

        assert result["status"] == "inconclusive"
        assert result["requests_used"] == 1
        assert result["request_delta"]["discovery"] == 1
        assert reason_fragment in " ".join(result["reasons"])
        assert len(calls) == 1
        assert calls[0]["url"].endswith("/orders")
        assert result["request_budget"]["discovery_requests"] == 1
        assert result["request_budget"]["verification_requests"] == 0
    finally:
        vault.close()


@pytest.mark.parametrize(
    ("collection_url", "method", "reason_fragment"),
    [
        ("https://outside.example/orders", "GET", "authorized asset rule"),
        (
            "https://authorized.example/api/orders",
            "POST",
            "only GET or HEAD",
        ),
    ],
)
def test_unsafe_owned_collection_rule_is_policy_blocked_before_network(
    collection_url: str, method: str, reason_fragment: str
):
    vault = CredentialVault()
    context = _acquisition_context(vault, collection_url=collection_url, method=method)
    calls: list[dict[str, Any]] = []
    try:
        result = _execute_acquisition(
            vault,
            context,
            lambda request: calls.append(request) or {"status_code": 200},
        )

        assert result["status"] == "policy_blocked"
        assert reason_fragment in " ".join(result["reasons"])
        assert calls == []
        assert result["request_budget"]["total_requests"] == 0
    finally:
        vault.close()


def test_existing_controlled_object_skips_acquisition():
    vault = CredentialVault()
    context = _acquisition_context(vault, existing=True)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        return {"status_code": 403, "body": {"order_id": "existing-order"}}

    try:
        result = _execute_acquisition(
            vault,
            context,
            transport,
            has_existing_object=True,
        )

        assert result["status"] == "inconclusive"
        assert len(calls) == 2
        assert all("/orders/existing-order" in call["url"] for call in calls)
        assert result["owned_object_acquisition"]["attempted"] is False
        assert result["request_budget"]["discovery_requests"] == 0
    finally:
        vault.close()


def test_object_acquisition_counts_against_shared_hard_budget():
    vault = CredentialVault()
    context = _acquisition_context(vault)

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        if request["url"].endswith("/orders"):
            return {"status_code": 200, "body": [{"order_id": "budget-order"}]}
        return {"status_code": 403, "body": {}}

    try:
        result = _execute_acquisition(vault, context, transport, limit=3)

        assert result["status"] == "inconclusive"
        assert result["request_budget"] == {
            "discovery_requests": 1,
            "auth_requests": 0,
            "verification_requests": 2,
            "cleanup_requests": 0,
            "total_requests": 3,
            "request_limit": 3,
            "remaining_requests": 0,
        }
    finally:
        vault.close()


def test_tenant_isolation_uses_acquired_object_and_controlled_tenant():
    vault = CredentialVault()
    context = _acquisition_context(vault, tenant_scoped=True)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        if request["url"].endswith("/orders"):
            return {
                "status_code": 200,
                "body": [{"order_id": "tenant-order", "tenant_id": "tenant-a"}],
            }
        return {"status_code": 403, "body": {"order_id": "tenant-order"}}

    try:
        result = _execute_acquisition(
            vault,
            context,
            transport,
            category="tenant_isolation",
            target=(
                "https://authorized.example/api/tenants/{tenant_id}/"
                "orders/{order_id}"
            ),
        )

        comparison_calls = [call for call in calls if "/tenants/" in call["url"]]
        assert result["status"] == "inconclusive"
        assert len(comparison_calls) == 2
        assert all(
            "/tenants/tenant-a/orders/tenant-order" in call["url"]
            for call in comparison_calls
        )
    finally:
        vault.close()
