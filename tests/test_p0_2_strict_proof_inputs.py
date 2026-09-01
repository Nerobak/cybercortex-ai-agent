from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agent_core.agent_models import Hypothesis
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
)
from agent_core.controlled_executor import (
    BOLAVerificationInput,
    COMMAND_EXECUTION_MARKER,
    COMMAND_PROBE_VALUE,
    CommandInjectionVerificationInput,
    ControlledVerificationExecutor,
    SQLInjectionVerificationInput,
    TRAVERSAL_FIXTURE_MARKER,
    TRAVERSAL_PROBE_VALUE,
)
from agent_core.credential_vault import CredentialVault
from agent_core.differential_analyzer import (
    analyze_authentication_enforcement,
    analyze_cross_account_access,
    analyze_role_authorization,
)
from agent_core.evidence_correlator import correlate_evidence
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from agent_core.verification_registry import (
    ACTIVE_EXECUTION_ENABLED,
    LEGACY_OFFLINE_ONLY,
    VerificationAdapterRegistry,
    execute_authorization_plan,
)

BASE = "https://lab.example/api"


def _policy(*, accounts: list[str] | None = None) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="p0-2-regression",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=BASE, schemes=["https"])],
        allowed_methods=["GET"],
        credentials_allowed=bool(accounts),
        controlled_account_ids=accounts or [],
        request_budget=20,
    )


def _gate(
    policy: AssessmentPolicy,
    context: ControlledContext,
) -> DeterministicPolicyGate:
    return DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="dedicated_lab",
            controlled_account_ids=[item.account_id for item in context.accounts],
            controlled_object_ids=[item.object_id for item in context.objects],
        ),
        RequestBudget(20),
    )


def _probe_execution(
    category: str,
    responses: list[dict[str, Any]],
    *,
    parameter_location: str = "query",
    inputs: dict[str, Any] | None = None,
    mutate_plan=None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-{category}-{parameter_location}",
        category=category,
        title="Bounded safe probe",
        rationale="An exact lab-only binding is required.",
        target=f"{BASE}/search",
        endpoint=f"{BASE}/search",
        method="GET",
        parameter="q",
        parameter_location=parameter_location,
        safe_verification_possible=True,
    )
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(target_class="dedicated_lab"),
    )
    if mutate_plan is not None:
        mutate_plan(plan.steps[0].metadata["requests"])
    calls: list[dict[str, Any]] = []

    def transport(request: dict[str, Any]) -> dict[str, Any]:
        calls.append(request)
        return responses[len(calls) - 1]

    with CredentialVault() as vault:
        context = ControlledContext()
        result = ControlledVerificationExecutor(
            _gate(_policy(), context), vault, context, transport
        ).execute(hypothesis, plan, inputs=inputs)
    return result, calls


def _authorization_execution(
    category: str,
    inputs: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    endpoint = {
        "bola": f"{BASE}/objects/object-a",
        "tenant_isolation": f"{BASE}/tenants/tenant-a",
        "vertical_authorization": f"{BASE}/admin/audit",
        "authentication_enforcement": f"{BASE}/me",
    }[category]
    object_id = "tenant-a" if category == "tenant_isolation" else "object-a"
    calls: list[dict[str, Any]] = []
    with CredentialVault() as vault:
        owner_token = vault.put("owner-token", label="owner")
        candidate_token = vault.put("candidate-token", label="candidate")
        context = ControlledContext(
            accounts=[
                ControlledAccount(
                    account_id="owner",
                    role="administrator",
                    tenant_id="tenant-a",
                    session_reference=owner_token,
                ),
                ControlledAccount(
                    account_id="candidate",
                    role="member",
                    tenant_id="tenant-b",
                    session_reference=candidate_token,
                ),
            ],
            objects=[
                ControlledObject(
                    object_id=object_id,
                    owner_account_id="owner",
                    tenant_id="tenant-a",
                    object_type=(
                        "tenant" if category == "tenant_isolation" else "object"
                    ),
                    test_owned=True,
                )
            ],
        )
        hypothesis = Hypothesis(
            hypothesis_id=f"hyp-{category}",
            category=category,
            title="Controlled authorization comparison",
            rationale="Observed protected evidence is required.",
            target=endpoint,
            endpoint=endpoint,
            method="GET",
            requires_credentials=True,
            safe_verification_possible=True,
        )
        plan = VerificationPlanner().create_plan(
            hypothesis,
            VerificationPlanningContext(target_class="dedicated_lab"),
        )
        policy = _policy(accounts=["owner", "candidate"])
        result = ControlledVerificationExecutor(
            _gate(policy, context),
            vault,
            context,
            lambda request: calls.append(request) or {"status_code": 500, "body": {}},
        ).execute(hypothesis, plan, inputs=inputs)
    return result, calls


@pytest.mark.parametrize("bad_bool", ["false", 0, 1])
def test_strict_proof_boolean_rejects_coercible_values(bad_bool: Any):
    with pytest.raises(ValidationError):
        BOLAVerificationInput.model_validate(
            {
                "protected_fields": ["private_note"],
                "protected_data_confirmed": bad_bool,
            }
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"protected_fields": "private_note"},
        {"protected_fields": ("private_note",)},
        {"protected_fields": ["private_note"], "unexpected": True},
        {"protected_fields": ["items..private_note"]},
        {"protected_fields": [1]},
    ],
)
def test_strict_proof_input_rejects_wrong_container_extra_and_bad_path(payload):
    with pytest.raises(ValidationError):
        BOLAVerificationInput.model_validate(payload)


@pytest.mark.parametrize(
    "category",
    [
        "bola",
        "tenant_isolation",
        "vertical_authorization",
        "authentication_enforcement",
    ],
)
def test_malformed_authorization_input_stops_before_transport(category: str):
    result, calls = _authorization_execution(
        category,
        {"protected_fields": ["private_note"], "protected_data_confirmed": "false"},
    )

    assert result["status"] == "policy_blocked"
    assert result["requests_used"] == 0
    assert calls == []


@pytest.mark.parametrize(
    "category,inputs",
    [
        (
            "sql_injection",
            {"safe_probe_semantics_confirmed": "false"},
        ),
        (
            "command_injection",
            {"parameter_binding": {"parameter": "q", "parameter_location": 1}},
        ),
        (
            "path_traversal",
            {"parameter_binding": ["q", "query"]},
        ),
    ],
)
def test_malformed_probe_input_stops_before_transport(category: str, inputs):
    result, calls = _probe_execution(category, [], inputs=inputs)

    assert result["status"] == "policy_blocked"
    assert result["requests_used"] == 0
    assert calls == []


def test_bola_denial_without_valid_owner_baseline_is_inconclusive():
    result = analyze_cross_account_access(
        {"status_code": 403, "body": {"error": "forbidden"}},
        {"status_code": 403, "body": {"error": "forbidden"}},
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["private_note"],
    )

    assert result["status"] == "inconclusive"
    assert result["owner_baseline_established"] is False


def test_bola_denial_after_valid_protected_owner_baseline_is_rejected():
    result = analyze_cross_account_access(
        {
            "status_code": 200,
            "body": {"id": "object-a", "private_note": "owner-safe-evidence"},
        },
        {"status_code": 403, "body": {"error": "forbidden"}},
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["private_note"],
    )

    assert result["status"] == "rejected"
    assert result["owner_baseline_established"] is True


def test_bola_success_without_matching_protected_evidence_is_inconclusive():
    result = analyze_cross_account_access(
        {"status_code": 200, "body": {"id": "object-a", "private_note": "a"}},
        {"status_code": 200, "body": {"id": "object-a", "private_note": "b"}},
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["private_note"],
    )

    assert result["status"] == "inconclusive"


def test_bola_matching_cross_account_protected_evidence_is_verified():
    body = {"id": "object-a", "private_note": "controlled-safe-evidence"}
    result = analyze_cross_account_access(
        {"status_code": 200, "body": body},
        {"status_code": 200, "body": body},
        object_identifier="object-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        protected_fields=["private_note"],
    )

    assert result["status"] == "verified"
    assert result["protected_evidence_matched"] is True


def test_tenant_requires_valid_exact_owner_baseline_and_tenant_evidence():
    invalid = analyze_cross_account_access(
        {"status_code": 200, "body": {"tenant_id": "tenant-a"}},
        {"status_code": 403, "body": {}},
        object_identifier="tenant-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        tenant_identifier="tenant-a",
        distinct_tenants_confirmed=True,
        tenant_isolation=True,
        protected_fields=["projects[].private_note"],
    )
    valid_body = {
        "tenant_id": "tenant-a",
        "projects": [{"private_note": "tenant-a-safe-evidence"}],
    }
    verified = analyze_cross_account_access(
        {"status_code": 200, "body": valid_body},
        {"status_code": 200, "body": valid_body},
        object_identifier="tenant-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        tenant_identifier="tenant-a",
        distinct_tenants_confirmed=True,
        tenant_isolation=True,
        protected_fields=["projects[].private_note"],
    )
    rejected = analyze_cross_account_access(
        {"status_code": 200, "body": valid_body},
        {"status_code": 403, "body": {"error": "forbidden"}},
        object_identifier="tenant-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
        tenant_identifier="tenant-a",
        distinct_tenants_confirmed=True,
        tenant_isolation=True,
        protected_fields=["projects[].private_note"],
    )

    assert invalid["status"] == "inconclusive"
    assert rejected["status"] == "rejected"
    assert verified["status"] == "verified"


def test_vertical_requires_observed_privileged_baseline_and_matching_evidence():
    missing = analyze_role_authorization(
        {"status_code": 200, "body": {"message": "public"}},
        {"status_code": 403, "body": {}},
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_fields=["audit"],
        protected_data_confirmed="false",  # type: ignore[arg-type]
    )
    body = {"audit": [{"event": "controlled-safe-event"}]}
    verified = analyze_role_authorization(
        {"status_code": 200, "body": body},
        {"status_code": 200, "body": body},
        separate_accounts_confirmed=True,
        distinct_roles_confirmed=True,
        protected_fields=["audit[].event"],
        protected_data_confirmed=False,
    )

    assert missing["status"] == "inconclusive"
    assert verified["status"] == "verified"


def test_authentication_requires_matching_observed_protected_evidence():
    protected = {"profile": {"private_note": "controlled-safe-evidence"}}
    no_unauth_evidence = analyze_authentication_enforcement(
        {"status_code": 200, "body": protected},
        {"status_code": 200, "body": {"message": "public"}},
        protected_fields=["profile.private_note"],
    )
    missing_baseline = analyze_authentication_enforcement(
        {"status_code": 200, "body": {"message": "public"}},
        {"status_code": 200, "body": protected},
        protected_fields=["profile.private_note"],
    )
    verified = analyze_authentication_enforcement(
        {"status_code": 200, "body": protected},
        {"status_code": 200, "body": protected},
        protected_fields=["profile.private_note"],
        protected_functionality_confirmed=False,
    )

    assert no_unauth_evidence["status"] == "inconclusive"
    assert missing_baseline["status"] == "inconclusive"
    assert verified["status"] == "verified"


def test_sql_caller_confirmation_and_reflection_cannot_verify():
    responses = [
        {"status_code": 200, "body": "stable-control"},
        {"status_code": 200, "body": "' AND '1'='1 reflected"},
        {"status_code": 200, "body": "stable-control"},
    ]
    result, calls = _probe_execution(
        "sql_injection",
        responses,
        inputs={"safe_probe_semantics_confirmed": True},
    )

    assert len(calls) == 3
    assert result["status"] == "inconclusive"
    assert result["analysis"]["verified"] is False


def test_probe_wrong_location_or_plan_binding_sends_no_traffic():
    wrong_location, location_calls = _probe_execution(
        "sql_injection", [], parameter_location="json"
    )

    def mutate(requests):
        requests[1]["parameter_location"] = "form"

    wrong_plan, plan_calls = _probe_execution("path_traversal", [], mutate_plan=mutate)

    assert wrong_location["status"] == "policy_blocked"
    assert wrong_plan["status"] == "policy_blocked"
    assert location_calls == []
    assert plan_calls == []


def test_sql_unstable_control_is_inconclusive():
    result, _ = _probe_execution(
        "sql_injection",
        [
            {"status_code": 200, "body": "control-a"},
            {"status_code": 200, "body": "probe"},
            {"status_code": 200, "body": "control-b"},
        ],
        inputs={"safe_probe_semantics_confirmed": True},
    )

    assert result["status"] == "inconclusive"
    assert result["analysis"]["control_repeatable"] is False
    assert result["request_delta"]["verification"] == 3
    assert result["requests_used"] == result["request_delta"]["total"] == 3


def test_command_reflection_is_inconclusive():
    result, _ = _probe_execution(
        "command_injection",
        [
            {"status_code": 200, "body": "stable-control"},
            {"status_code": 200, "body": f"reflected:{COMMAND_PROBE_VALUE}"},
            {"status_code": 200, "body": "stable-control"},
        ],
    )

    assert result["status"] == "inconclusive"


def test_legacy_ccx_canary_reflection_is_inconclusive():
    result, _ = _probe_execution(
        "command_injection",
        [
            {"status_code": 200, "body": "stable-control"},
            {"status_code": 200, "body": ";printf CCX_CANARY"},
            {"status_code": 200, "body": "stable-control"},
        ],
    )

    assert result["status"] == "inconclusive"


def test_command_execution_derived_marker_with_stable_controls_verifies():
    assert COMMAND_EXECUTION_MARKER not in COMMAND_PROBE_VALUE
    result, _ = _probe_execution(
        "command_injection",
        [
            {"status_code": 200, "body": "stable-control"},
            {"status_code": 200, "body": COMMAND_EXECUTION_MARKER},
            {"status_code": 200, "body": "stable-control"},
        ],
    )

    assert result["status"] == "verified"
    assert result["request_delta"]["verification"] == 3
    assert result["requests_used"] == result["request_delta"]["total"] == 3


def test_command_marker_in_control_is_inconclusive():
    result, _ = _probe_execution(
        "command_injection",
        [
            {"status_code": 200, "body": COMMAND_EXECUTION_MARKER},
            {"status_code": 200, "body": COMMAND_EXECUTION_MARKER},
            {"status_code": 200, "body": COMMAND_EXECUTION_MARKER},
        ],
    )

    assert result["status"] == "inconclusive"


def test_traversal_reflection_is_inconclusive():
    result, _ = _probe_execution(
        "path_traversal",
        [
            {"status_code": 200, "body": "stable-control"},
            {"status_code": 200, "body": f"reflected:{TRAVERSAL_PROBE_VALUE}"},
            {"status_code": 200, "body": "stable-control"},
        ],
    )

    assert result["status"] == "inconclusive"


def test_traversal_server_fixture_marker_with_stable_controls_verifies():
    assert TRAVERSAL_FIXTURE_MARKER not in TRAVERSAL_PROBE_VALUE
    result, _ = _probe_execution(
        "path_traversal",
        [
            {"status_code": 200, "body": "stable-control"},
            {"status_code": 200, "body": TRAVERSAL_FIXTURE_MARKER},
            {"status_code": 200, "body": "stable-control"},
        ],
    )

    assert result["status"] == "verified"
    assert result["request_delta"]["verification"] == 3
    assert result["requests_used"] == result["request_delta"]["total"] == 3


def test_legacy_registry_is_quarantined_and_cannot_verify():
    hypothesis = Hypothesis(
        hypothesis_id="registry-hypothesis",
        category="bola",
        title="Legacy registry quarantine",
        rationale="The active path must not use offline caller assertions.",
        target=f"{BASE}/objects/object-a",
    )
    plan = VerificationPlanner().create_plan(hypothesis, VerificationPlanningContext())
    policy = _policy()
    direct = execute_authorization_plan(
        plan,
        policy,
        {"ownership_confirmed": True, "separate_accounts_confirmed": True},
    )
    registered = VerificationAdapterRegistry().execute(plan, policy, {})

    assert LEGACY_OFFLINE_ONLY is True
    assert ACTIVE_EXECUTION_ENABLED is False
    assert direct["status"] == "manual_adapter_required"
    assert registered["status"] == "manual_adapter_required"


@pytest.mark.parametrize("metadata_proof", ["true", 1, {"proof": True}])
def test_correlation_never_promotes_inconclusive_metadata(metadata_proof):
    hypothesis = Hypothesis(
        hypothesis_id="correlation-hypothesis",
        category="command_injection",
        title="Correlation cannot promote evidence",
        rationale="Only the analyzer predicate controls verification.",
        target=f"{BASE}/search",
    )
    result = correlate_evidence(
        hypothesis,
        {
            "status": "verified",
            "verified": metadata_proof,
            "confidence": "high",
            "reasons": ["metadata only"],
        },
        requests_used=3,
        policy_approved=True,
    )

    assert result["status"] == "inconclusive"


def test_probe_envelopes_forbid_unknown_fields():
    with pytest.raises(ValidationError):
        SQLInjectionVerificationInput.model_validate({"unexpected": True})
    with pytest.raises(ValidationError):
        CommandInjectionVerificationInput.model_validate({"unexpected": True})
