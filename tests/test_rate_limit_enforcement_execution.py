from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Callable

import pytest

from agent_core.agent_models import Hypothesis
from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.attack_surface import CanonicalAttackSurface
from agent_core.benchmark_exporter import build_benchmark_export
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
from agent_core.rate_limit_enforcement import MAX_RATE_LIMIT_ATTEMPTS
from agent_core.request_budget import RequestBudget
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

TARGET = "https://service.example"
LOGIN_URL = f"{TARGET}/auth/login"
ACCOUNT_ID = "alice"
USERNAME = "controlled-alice"
EMAIL = "controlled-alice@example.test"
ORIGINAL_PASSWORD = "controlled-original-password"
INVALID_PASSWORD = "controlled-synthetic-wrong-password"
TOKEN = "private-session-token-must-not-survive"


def _hypothesis_and_plan() -> tuple[Hypothesis, Any]:
    hypothesis = Hypothesis(
        hypothesis_id="hyp-rate-limit-login",
        category="rate_limit_enforcement",
        title="Bounded login rate-limit enforcement",
        rationale="A classified login surface requires a controlled bounded check.",
        target=TARGET,
        endpoint=LOGIN_URL,
        method="POST",
        requires_credentials=True,
        safe_verification_possible=True,
        metadata={
            "related_surfaces": [
                {
                    "boundary_type": "session_creation",
                    "method": "POST",
                    "path": "/auth/login",
                    "semantic_classes": [
                        "login_session_creation",
                        "rate_sensitive_authentication_operation",
                    ],
                }
            ]
        },
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


def _policy(
    *,
    opt_in: bool = True,
    max_attempts: int = 3,
    account_ids: list[str] | None = None,
) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="bounded-rate-limit-test",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["POST"],
        credentials_allowed=True,
        controlled_account_ids=([ACCOUNT_ID] if account_ids is None else account_ids),
        allow_state_changes=False,
        allow_bounded_rate_limit_verification=opt_in,
        max_rate_limit_attempts=max_attempts,
        request_budget=10,
    )


def _context(
    vault: CredentialVault,
    *,
    second_account: bool = False,
    identity_kind: str = "username",
    username_field: str = "username",
):
    identity_references: dict[str, str] = {}
    if identity_kind in {"username", "both"}:
        identity_references["username"] = vault.put(USERNAME, label="alice username")
    if identity_kind in {"email", "both"}:
        identity_references["email"] = vault.put(EMAIL, label="alice email")
    accounts = [
        ControlledAccount(
            account_id=ACCOUNT_ID,
            controlled=True,
            credential_references={
                **identity_references,
                "password": vault.put(
                    ORIGINAL_PASSWORD, label="alice original password"
                ),
            },
        )
    ]
    if second_account:
        accounts.append(
            ControlledAccount(
                account_id="bob",
                controlled=True,
                credential_references={
                    "username": vault.put("controlled-bob", label="bob username"),
                    "password": vault.put(
                        "controlled-bob-password", label="bob password"
                    ),
                },
            )
        )
    return ControlledContext(
        accounts=accounts,
        session_acquisition=SessionAcquisition(
            url=LOGIN_URL,
            method="POST",
            username_field=username_field,
        ),
    )


def _input(*, attempts: int = 3, invalid_password: str = INVALID_PASSWORD):
    return {
        "rate_limit": {
            "account_id": ACCOUNT_ID,
            "mode": "authentication_login_rate_limit",
            "attempts": attempts,
            "invalid_password": invalid_password,
        },
        "expected_control": {
            "type": "throttle_or_block_within_attempts",
            "within_attempts": min(attempts, 3),
        },
    }


def _ordinary_failures() -> list[dict[str, Any]]:
    return [
        {"status_code": 200, "body": {"token": TOKEN}},
        *[
            {"status_code": 401, "body": {"error": "invalid credentials"}}
            for _ in range(3)
        ],
        {"status_code": 200, "body": {"token": TOKEN}},
    ]


def _execute(
    vault: CredentialVault,
    responses: list[dict[str, Any]],
    *,
    inputs: dict[str, Any] | None = None,
    policy: AssessmentPolicy | None = None,
    context: ControlledContext | None = None,
    mutate_hypothesis: Callable[[Hypothesis], None] | None = None,
    mutate_plan: Callable[[Any], None] | None = None,
    budget: int = 10,
    phase2_session_url: str | None = LOGIN_URL,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hypothesis, plan = _hypothesis_and_plan()
    if mutate_hypothesis is not None:
        mutate_hypothesis(hypothesis)
    if mutate_plan is not None:
        mutate_plan(plan)
    controlled = context or _context(vault)
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(deepcopy(request))
        return responses[len(calls) - 1]

    gate = DeterministicPolicyGate(
        policy or _policy(),
        Phase2PolicyContext(
            mode="verify",
            target_class="external",
            controlled_account_ids=[
                item.account_id for item in controlled.accounts if item.controlled
            ],
            session_acquisition_url=phase2_session_url,
            session_acquisition_method="POST",
        ),
        RequestBudget(budget),
    )
    result = ControlledVerificationExecutor(gate, vault, controlled, transport).execute(
        hypothesis, plan, inputs=inputs if inputs is not None else _input()
    )
    return result, calls


def _assert_zero_traffic_reason(result: dict[str, Any], calls: list[Any]) -> str:
    assert result["status"] == "policy_blocked"
    assert result["attempts_sent"] == 0
    assert result["request_counts"]["total_network_requests"] == 0
    assert calls == []
    assert result["reasons"]
    return " ".join(result["reasons"])


def test_malformed_input_preserves_reason_and_sends_no_traffic():
    supplied = {
        "rate_limit": {
            "account_id": ACCOUNT_ID,
            "mode": "unsupported-mode",
            "attempts": "three",
            "invalid_password": INVALID_PASSWORD,
        },
        "expected_control": {
            "type": "throttle_or_block_within_attempts",
            "within_attempts": 3,
        },
    }
    with CredentialVault() as vault:
        result, calls = _execute(vault, _ordinary_failures(), inputs=supplied)

    reason = _assert_zero_traffic_reason(result, calls)
    assert "Only authentication_login_rate_limit is supported." in reason
    assert "attempts must be an integer." in reason


def test_runtime_binding_failure_preserves_reason_and_sends_no_traffic():
    with CredentialVault() as vault:
        context = _context(vault, second_account=True)
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            context=context,
            policy=_policy(account_ids=[ACCOUNT_ID, "bob"]),
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "exactly one controlled account" in reason


def test_plan_validation_reason_is_preserved_and_sends_no_traffic():
    def invalidate_plan(plan: Any) -> None:
        plan.steps[0].metadata["hard_attempt_cap"] = MAX_RATE_LIMIT_ATTEMPTS - 1

    with CredentialVault() as vault:
        result, calls = _execute(
            vault, _ordinary_failures(), mutate_plan=invalidate_plan
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "not the bounded typed login template" in reason


def test_wrong_approved_account_reason_is_preserved_and_sends_no_traffic():
    supplied = _input()
    supplied["rate_limit"]["account_id"] = "bob"
    with CredentialVault() as vault:
        result, calls = _execute(vault, _ordinary_failures(), inputs=supplied)

    reason = _assert_zero_traffic_reason(result, calls)
    assert "does not match the bound controlled account" in reason


def test_missing_session_config_reason_is_preserved_and_sends_no_traffic():
    with CredentialVault() as vault:
        configured = _context(vault)
        context = ControlledContext(accounts=configured.accounts)
        result, calls = _execute(
            vault, _ordinary_failures(), context=context, phase2_session_url=None
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "session acquisition is required" in reason


@pytest.mark.parametrize(
    ("username_field", "identity_kind", "expected_identity"),
    [
        ("email", "email", EMAIL),
        ("email", "username", USERNAME),
        ("username", "username", USERNAME),
        ("username", "email", EMAIL),
    ],
)
def test_login_identity_resolution_uses_declared_field_and_supported_fallback(
    username_field: str,
    identity_kind: str,
    expected_identity: str,
):
    with CredentialVault() as vault:
        context = _context(
            vault,
            identity_kind=identity_kind,
            username_field=username_field,
        )
        result, calls = _execute(vault, _ordinary_failures(), context=context)

    assert result["status"] == "verified"
    assert len(calls) == 3 + 2
    assert [call["json"][username_field] for call in calls] == [expected_identity] * 5


def test_semantically_matching_vaulted_identity_is_preferred():
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="both", username_field="email")
        result, calls = _execute(vault, _ordinary_failures(), context=context)

    assert result["status"] == "verified"
    assert [call["json"] for call in calls] == [
        {"email": EMAIL, "password": password}
        for password in [
            ORIGINAL_PASSWORD,
            INVALID_PASSWORD,
            INVALID_PASSWORD,
            INVALID_PASSWORD,
            ORIGINAL_PASSWORD,
        ]
    ]


def test_unavailable_matching_reference_uses_live_compatible_fallback():
    unavailable_reference = "unavailable-email-reference"
    with CredentialVault() as vault:
        context = _context(vault, identity_kind="username", username_field="email")
        context.accounts[0].credential_references["email"] = unavailable_reference
        result, calls = _execute(vault, _ordinary_failures(), context=context)

    assert result["status"] == "verified"
    assert [call["json"]["email"] for call in calls] == [USERNAME] * 5
    assert unavailable_reference not in json.dumps(result)


@pytest.mark.parametrize("missing", ["username", "password"])
def test_missing_credential_reference_reason_is_preserved_and_sends_no_traffic(
    missing: str,
):
    with CredentialVault() as vault:
        context = _context(vault)
        context.accounts[0].credential_references.pop(missing)
        result, calls = _execute(vault, _ordinary_failures(), context=context)

    reason = _assert_zero_traffic_reason(result, calls)
    assert "vaulted" in reason


@pytest.mark.parametrize("invalid", ["username", "password"])
def test_vault_invalid_credential_reason_is_preserved_and_sends_no_traffic(
    invalid: str,
):
    invalid_reference = "sensitive-reference-must-not-survive"
    with CredentialVault() as vault:
        context = _context(vault)
        context.accounts[0].credential_references[invalid] = invalid_reference
        result, calls = _execute(vault, _ordinary_failures(), context=context)

    reason = _assert_zero_traffic_reason(result, calls)
    assert "unavailable in the credential vault" in reason
    assert invalid_reference not in reason


def test_policy_opt_in_absent_blocks_with_zero_requests():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault, _ordinary_failures(), policy=_policy(opt_in=False)
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "Explicit bounded rate-limit verification is disabled by policy." in reason


def test_attempts_above_policy_maximum_preserves_reason_and_sends_no_traffic():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            policy=_policy(max_attempts=2),
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "requested attempts exceed the policy maximum" in reason


def test_attempts_above_hard_cap_block_without_clamping_or_requests():
    with CredentialVault() as vault:
        supplied = _input(attempts=MAX_RATE_LIMIT_ATTEMPTS + 1)
        result, calls = _execute(vault, _ordinary_failures(), inputs=supplied)

    reason = _assert_zero_traffic_reason(result, calls)
    assert result["attempts_requested"] == MAX_RATE_LIMIT_ATTEMPTS + 1
    assert f"attempts must be between 1 and {MAX_RATE_LIMIT_ATTEMPTS}." in reason


def test_exactly_one_controlled_account_is_required_and_no_spraying_occurs():
    with CredentialVault() as vault:
        context = _context(vault, second_account=True)
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            context=context,
            policy=_policy(account_ids=[ACCOUNT_ID, "bob"]),
        )

    assert result["status"] == "policy_blocked"
    assert calls == []


def test_failed_valid_baseline_is_inconclusive_without_invalid_sequence():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            [{"status_code": 401, "body": {"error": "invalid credentials"}}],
        )

    assert result["status"] == "inconclusive"
    assert result["attempts_sent"] == 0
    assert result["final_valid_login_summary"] is None
    assert result["request_counts"]["total_network_requests"] == 1
    assert len(calls) == 1


def test_explicit_throttle_on_third_attempt_is_rejected_secure():
    responses = [
        {"status_code": 200, "body": {"token": TOKEN}},
        {"status_code": 401, "body": {"error": "invalid credentials"}},
        {"status_code": 401, "body": {"error": "invalid credentials"}},
        {
            "status_code": 429,
            "headers": {"Retry-After": "30"},
            "body": {"error": "too many requests"},
        },
        {"status_code": 200, "body": {"token": TOKEN}},
    ]
    with CredentialVault() as vault:
        result, calls = _execute(vault, responses)

    assert result["status"] == "rejected"
    assert result["expected_control_satisfied"] is True
    assert result["throttle_signal_observed"] is True
    assert result["retry_after_observed"] is True
    assert (
        result["per_attempt_sanitized_summaries"][2]["retry_after_value_class"]
        == "delta_seconds"
    )
    assert result["request_counts"]["total_network_requests"] == 5
    assert len(calls) == 5


def test_deterministic_ordinary_failures_and_final_valid_login_verify_absence():
    with CredentialVault() as vault:
        result, calls = _execute(vault, _ordinary_failures())

    assert result["status"] == "verified"
    assert result["expected_control_satisfied"] is False
    assert result["attempts_sent"] == 3
    assert result["final_valid_login_summary"]["status_class"] == "2xx"
    assert result["request_counts"] == {
        "valid_baseline_auth_requests": 1,
        "invalid_password_auth_requests": 3,
        "final_valid_auth_requests": 1,
        "auth_requests": 5,
        "total_network_requests": 5,
    }
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 5,
        "verification": 0,
        "cleanup": 0,
        "attempted": 5,
        "total": 5,
    }
    assert result["requests_used"] == 5
    assert result["reasons"] == [
        "No configured rate-limit control was observed within the approved attempt window, and the final valid login succeeded."
    ]
    assert len(calls) == 5


def test_ambiguous_401s_are_inconclusive_even_when_final_login_succeeds():
    responses = [
        {"status_code": 200, "body": {"token": TOKEN}},
        *[{"status_code": 401, "body": {}} for _ in range(3)],
        {"status_code": 200, "body": {"token": TOKEN}},
    ]
    with CredentialVault() as vault:
        result, _ = _execute(vault, responses)

    assert result["status"] == "inconclusive"
    assert result["expected_control_satisfied"] is None


def test_429_is_a_safe_throttle_signal_without_status_code_output():
    responses = [
        {"status_code": 200, "body": {"token": TOKEN}},
        {"status_code": 401, "body": {"error": "invalid credentials"}},
        {"status_code": 401, "body": {"error": "invalid credentials"}},
        {"status_code": 429, "body": {}},
        {"status_code": 200, "body": {"token": TOKEN}},
    ]
    with CredentialVault() as vault:
        result, _ = _execute(vault, responses)

    third = result["per_attempt_sanitized_summaries"][2]
    assert result["status"] == "inconclusive"
    assert third["status_class"] == "4xx"
    assert third["throttle_signal"] is True
    assert third["status_429_detected"] is True
    assert third["concrete_throttle_evidence"] is False
    assert "status_code" not in json.dumps(result)


def test_final_valid_login_blocked_after_throttle_is_secure_signal():
    responses = [
        {"status_code": 200, "body": {"token": TOKEN}},
        *[
            {"status_code": 401, "body": {"error": "invalid credentials"}}
            for _ in range(2)
        ],
        {
            "status_code": 403,
            "body": {"error": "account locked after too many failed attempts"},
        },
        {"status_code": 403, "body": {"error": "account locked"}},
    ]
    with CredentialVault() as vault:
        result, _ = _execute(vault, responses)

    assert result["status"] == "rejected"
    assert result["lockout_signal_observed"] is True
    assert result["expected_control_satisfied"] is True


def test_sequence_is_same_account_sequential_and_contains_no_hidden_retries():
    with CredentialVault() as vault:
        result, calls = _execute(vault, _ordinary_failures())

    assert result["request_counts"]["total_network_requests"] == 3 + 2
    assert [call["json"]["username"] for call in calls] == [USERNAME] * 5
    assert [
        call["request_context"]["rate_limit_sequence_position"] for call in calls
    ] == list(range(5))
    assert [call["request_context"]["rate_limit_sequence_role"] for call in calls] == [
        "valid_baseline",
        "invalid_password_attempt",
        "invalid_password_attempt",
        "invalid_password_attempt",
        "valid_final",
    ]
    assert calls[0]["json"]["password"] == ORIGINAL_PASSWORD
    assert all(call["json"]["password"] == INVALID_PASSWORD for call in calls[1:4])
    assert calls[4]["json"]["password"] == ORIGINAL_PASSWORD


def test_rate_limit_outputs_reports_runs_and_exports_never_contain_secrets(tmp_path):
    with CredentialVault() as vault:
        supplied = _input()
        context = _context(vault, identity_kind="username", username_field="email")
        result, _ = _execute(
            vault, _ordinary_failures(), inputs=supplied, context=context
        )
        hypothesis, plan = _hypothesis_and_plan()
        report = render_phase2_report(
            {
                "hypotheses": [hypothesis.model_dump(mode="json")],
                "verification_plans": [plan.model_dump(mode="json")],
                "verification_results": [
                    {
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "category": hypothesis.category,
                        **result,
                    }
                ],
            }
        )
        run = {
            "run_id": "rate-limit-safe-output",
            "target": TARGET,
            "hypotheses": [hypothesis.model_dump(mode="json")],
            "verification_plans": [plan.model_dump(mode="json")],
            "verification_results": [
                {
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "category": hypothesis.category,
                    **result,
                }
            ],
            "metrics": {"total_requests": 5},
        }
        store = Phase2RunStore(tmp_path)
        store.save(run)
        persisted_and_exported = json.dumps(
            {
                "run": store.load(),
                "export": build_benchmark_export(store.load()),
            }
        )

    serialized = json.dumps(result)
    assert "invalid_password" not in supplied["rate_limit"]
    for secret in (USERNAME, ORIGINAL_PASSWORD, INVALID_PASSWORD, TOKEN):
        assert secret not in serialized
        assert secret not in report
        assert secret not in persisted_and_exported
    assert "authorization" not in serialized.lower()
    assert "cookie" not in serialized.lower()
    assert "credential_ref" not in serialized.lower()
    assert "Hard implementation attempt cap: 5" in report
    assert "Brute force: false" in report
    assert "Spraying: false" in report
    assert "Concurrency: 1 (sequential only)" in report


def test_policy_limit_and_remaining_budget_are_reserved_before_any_request():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            policy=_policy(max_attempts=2),
        )
    reason = _assert_zero_traffic_reason(result, calls)
    assert "requested attempts exceed the policy maximum" in reason

    with CredentialVault() as vault:
        result, calls = _execute(vault, _ordinary_failures(), budget=4)
    reason = _assert_zero_traffic_reason(result, calls)
    assert (
        reason
        == "Request budget is insufficient for the required verification sequence."
    )


def test_endpoint_mismatch_reason_is_preserved_and_sends_no_traffic():
    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            phase2_session_url=f"{TARGET}/different-login",
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert "does not exactly match the configured classified login surface" in reason


def test_diagnostic_reasons_never_contain_supplied_secrets():
    diagnostic_secrets = {
        "identity": "diagnostic-identity-secret-391",
        "original": "diagnostic-original-secret-827",
        "invalid": "diagnostic-invalid-secret-614",
    }
    with CredentialVault() as vault:
        identity_reference = vault.put(
            diagnostic_secrets["identity"], label="diagnostic identity"
        )
        password_reference = vault.put(
            diagnostic_secrets["original"], label="diagnostic original"
        )
        vault.discard(password_reference)
        context = ControlledContext(
            accounts=[
                ControlledAccount(
                    account_id=ACCOUNT_ID,
                    controlled=True,
                    credential_references={
                        "username": identity_reference,
                        "password": password_reference,
                    },
                )
            ],
            session_acquisition=SessionAcquisition(url=LOGIN_URL, method="POST"),
        )
        supplied = _input(invalid_password=diagnostic_secrets["invalid"])
        result, calls = _execute(
            vault, _ordinary_failures(), inputs=supplied, context=context
        )

    _assert_zero_traffic_reason(result, calls)
    serialized_reasons = json.dumps(result["reasons"])
    for secret in [
        *diagnostic_secrets.values(),
        identity_reference,
        password_reference,
    ]:
        assert secret not in serialized_reasons


def test_recovery_rate_limit_surface_remains_non_executable():
    def make_recovery_surface(hypothesis: Hypothesis) -> None:
        hypothesis.endpoint = f"{TARGET}/recovery/complete"
        hypothesis.metadata["related_surfaces"] = [
            {
                "boundary_type": "recovery_completion",
                "method": "POST",
                "path": "/recovery/complete",
                "semantic_classes": ["account_recovery_completion"],
            }
        ]

    with CredentialVault() as vault:
        result, calls = _execute(
            vault,
            _ordinary_failures(),
            mutate_hypothesis=make_recovery_surface,
        )

    reason = _assert_zero_traffic_reason(result, calls)
    assert (
        reason
        == "The rate-limit hypothesis is not a supported classified login surface."
    )


def test_shared_transport_enforces_sequence_order_and_total_count():
    with CredentialVault() as vault:
        _, executor_calls = _execute(vault, _ordinary_failures())

    policy = _policy()
    policy.resolve_dns_before_request = False
    policy.requests_per_second = 100
    transport_calls: list[tuple[str, str]] = []

    class Response:
        status_code = 200
        headers: dict[str, str] = {}
        content = b"{}"
        is_redirect = False
        is_permanent_redirect = False

    client = ScopedHTTPClient(
        policy=policy,
        requester=lambda method, url, **_kwargs: (
            transport_calls.append((method, url)) or Response()
        ),
    )
    for call in executor_calls:
        client.request(
            call["method"],
            call["url"],
            purpose=call["purpose"],
            request_context=call["request_context"],
        )

    with pytest.raises(PolicyViolationError, match="not strictly sequential"):
        final = executor_calls[-1]
        client.request(
            final["method"],
            final["url"],
            purpose=final["purpose"],
            request_context=final["request_context"],
        )
    assert transport_calls == [("POST", LOGIN_URL)] * 5


def test_plan_reports_policy_maximum_and_never_auto_executes_without_opt_in():
    surface = CanonicalAttackSurface(
        target=TARGET,
        routes=[{"method": "POST", "path": "/auth/login", "source": "openapi"}],
        auth_boundaries=[
            {
                "method": "POST",
                "path": "/auth/login",
                "boundary_type": "session_creation",
                "semantic_classes": [
                    "login_session_creation",
                    "rate_sensitive_authentication_operation",
                ],
                "rate_sensitive_candidate": True,
                "confidence": "high",
                "source": "openapi",
            }
        ],
    )
    with CredentialVault() as vault:
        context = _context(vault)
        calls: list[str] = []

        def executor(hypothesis, _plan, _gate):
            calls.append(hypothesis.category)
            return {
                "status": "inconclusive",
                "runtime_binding": {"policy_authorized": True},
            }

        executor.defers_runtime_policy_authorization = True
        blocked = AdaptiveAssessmentOrchestrator().run_phase2(
            surface,
            _policy(opt_in=False),
            mode="verify",
            controlled_context=context,
            executor=executor,
        )
        rate_plan = next(
            item
            for item in blocked["verification_plans"]
            if item["steps"][0]["metadata"]["category"] == "rate_limit_enforcement"
        )
        assert rate_plan["automatic_execution_allowed"] is False
        assert rate_plan["steps"][0]["metadata"]["policy_opt_in"] is False
        assert rate_plan["steps"][0]["metadata"]["configured_max_attempts"] == 3
        assert rate_plan["steps"][0]["metadata"]["hard_attempt_cap"] == 5
        assert calls == []

        allowed = AdaptiveAssessmentOrchestrator().run_phase2(
            surface,
            _policy(opt_in=True),
            mode="verify",
            controlled_context=context,
            executor=executor,
        )
        rate_plan = next(
            item
            for item in allowed["verification_plans"]
            if item["steps"][0]["metadata"]["category"] == "rate_limit_enforcement"
        )
        assert rate_plan["automatic_execution_allowed"] is True
        assert rate_plan["steps"][0]["metadata"]["policy_opt_in"] is True
        assert calls == ["rate_limit_enforcement"]
