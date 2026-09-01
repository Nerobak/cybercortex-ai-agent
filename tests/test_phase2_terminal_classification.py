"""Canonical terminal classification regression tests for typed Phase 2."""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.differential_analyzer import (
    analyze_authentication_enforcement,
    analyze_cross_account_access,
    analyze_role_authorization,
    analyze_session_invalidation,
)
from agent_core.phase2_result_status import (
    BUDGET_PARTIAL_REASON,
    BUDGET_PREFLIGHT_REASON,
    CLEANUP_UNVERIFIED_REASON,
    INTERMEDIATE_RESULT_STATUSES,
    PUBLIC_RESULT_STATUSES,
    SERVICE_UNSTABLE_REASON,
    TERMINAL_RESULT_STATUSES,
    TRANSPORT_FAILURE_REASON,
    Phase2ResultStatus,
    Phase2StatusDecision,
    assess_response_instability,
    normalize_typed_result,
    transport_failure_reason,
)
from agent_core.request_budget import RequestDelta
from agent_core.result_provenance import result_content_hash
from agent_core.verification_capabilities import TYPED_VERIFICATION_CATEGORIES


def _delta(total: int) -> RequestDelta:
    return RequestDelta(
        verification=total,
        attempted=total,
        total=total,
    )


def test_canonical_status_model_is_strict_and_complete():
    assert {item.value for item in Phase2ResultStatus} == PUBLIC_RESULT_STATUSES
    assert TERMINAL_RESULT_STATUSES == {
        "verified",
        "rejected",
        "inconclusive",
        "policy_blocked",
    }
    assert INTERMEDIATE_RESULT_STATUSES == {
        "awaiting_controlled_evidence",
        "verification_pending_cleanup",
    }
    with pytest.raises(ValidationError):
        Phase2StatusDecision.model_validate(
            {"status": "error", "reasons": ["unsafe"], "extra": True}
        )


@pytest.mark.parametrize("legacy_status", ["budget_blocked", "budget_exhausted"])
def test_budget_before_traffic_has_one_policy_blocked_reason(legacy_status: str):
    result = normalize_typed_result(
        {"status": legacy_status, "reasons": ["implementation detail"]},
        _delta(0),
    )

    assert result["status"] == "policy_blocked"
    assert result["reasons"] == [BUDGET_PREFLIGHT_REASON]


def test_budget_after_partial_evidence_is_inconclusive():
    result = normalize_typed_result(
        {
            "status": "budget_exhausted",
            "reasons": ["Global request budget exhausted."],
        },
        _delta(2),
    )

    assert result["status"] == "inconclusive"
    assert result["reasons"] == [BUDGET_PARTIAL_REASON]


def test_policy_blocked_budget_reason_is_normalized_without_traffic():
    result = normalize_typed_result(
        {
            "status": "policy_blocked",
            "reasons": ["The plan exceeds a local remaining request budget."],
        },
        _delta(0),
    )

    assert result["status"] == "policy_blocked"
    assert result["reasons"] == [BUDGET_PREFLIGHT_REASON]


@pytest.mark.parametrize(
    "legacy_status",
    ["error", "failed", "unknown", "manual_required"],
)
def test_undocumented_terminal_statuses_cannot_cross_boundary(legacy_status: str):
    result = normalize_typed_result(
        {"status": legacy_status, "reasons": ["legacy detail"]}, _delta(1)
    )

    assert result["status"] == "inconclusive"
    assert result["status"] in TERMINAL_RESULT_STATUSES


def test_cleanup_failure_cannot_promote_a_terminal_conclusion():
    result = normalize_typed_result(
        {
            "status": "verified",
            "cleanup_attempted": True,
            "cleanup_verified": False,
            "reasons": ["positive evidence"],
        },
        _delta(3),
    )

    assert result["status"] == "inconclusive"
    assert result["reasons"] == [CLEANUP_UNVERIFIED_REASON]


def test_transport_reason_is_deterministic_and_does_not_persist_exception_text():
    first = transport_failure_reason(RuntimeError("password=first-secret"))
    second = transport_failure_reason(ValueError("password=second-secret"))

    assert first == second == TRANSPORT_FAILURE_REASON
    assert "secret" not in first


@pytest.mark.parametrize(
    "responses",
    [
        [{"status_code": 503, "body": {}}],
        [{"status_code": None, "body": {}}],
        [{"status_code": 200, "service_unstable": True, "body": {}}],
        [object()],
    ],
)
def test_shared_instability_predicate_is_conservative(responses: list[object]):
    decision = assess_response_instability(responses)

    assert decision.unstable is True
    assert decision.reason == SERVICE_UNSTABLE_REASON


def test_unstable_control_cannot_be_verified_or_rejected():
    result = analyze_authentication_enforcement(
        {"status_code": 503, "body": {"email": "controlled@example.test"}},
        {"status_code": 403, "body": {"error": "denied"}},
        protected_fields=["email"],
        protected_functionality_confirmed=True,
    )

    assert result["status"] == "inconclusive"
    assert result["verified"] is False
    assert result["reasons"] == [SERVICE_UNSTABLE_REASON]


def test_authorization_rejections_require_valid_secure_baselines():
    owner = {
        "status_code": 200,
        "body": {
            "id": "controlled-object",
            "email": "owner@example.test",
            "tenant_id": "tenant-a",
        },
    }
    privileged = {"status_code": 200, "body": {"email": "admin@example.test"}}
    denied = {"status_code": 403, "body": {"error": "denied"}}

    bola = analyze_cross_account_access(
        owner,
        denied,
        object_identifier="controlled-object",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["email"],
        protected_data_confirmed=True,
    )
    tenant = analyze_cross_account_access(
        owner,
        denied,
        object_identifier="controlled-object",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["email"],
        protected_data_confirmed=True,
        tenant_identifier="tenant-a",
        distinct_tenants_confirmed=True,
        tenant_isolation=True,
    )
    vertical = analyze_role_authorization(
        privileged,
        denied,
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_fields=["email"],
        protected_data_confirmed=True,
        protected_functionality_confirmed=True,
    )
    authentication = analyze_authentication_enforcement(
        privileged,
        denied,
        protected_fields=["email"],
        protected_functionality_confirmed=True,
    )
    session = analyze_session_invalidation(
        privileged,
        denied,
        protected_fields=["email"],
        protected_data_confirmed=True,
        termination_succeeded=True,
    )

    assert {
        bola["status"],
        tenant["status"],
        vertical["status"],
        authentication["status"],
        session["status"],
    } == {"rejected"}

    missing_baseline = analyze_cross_account_access(
        denied,
        denied,
        object_identifier="controlled-object",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["email"],
        protected_data_confirmed=True,
    )
    assert missing_baseline["status"] == "inconclusive"


def test_all_typed_categories_share_the_controlled_result_boundary():
    assert len(TYPED_VERIFICATION_CATEGORIES) == 11
    source = inspect.getsource(ControlledVerificationExecutor.execute)
    assert source.count("normalize_typed_result") == 1


def test_status_and_reasons_change_immutable_result_content_hash():
    base = {
        "hypothesis_id": "hyp-terminal-contract",
        "category": "bola",
        "status": "inconclusive",
        "reasons": ["Evidence was ambiguous."],
    }
    changed_status = {**base, "status": "rejected"}
    changed_reasons = {**base, "reasons": ["A secure control was demonstrated."]}

    assert result_content_hash(base) != result_content_hash(changed_status)
    assert result_content_hash(base) != result_content_hash(changed_reasons)
