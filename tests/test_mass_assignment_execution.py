from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from agent_core.agent_models import Hypothesis, RiskLevel
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
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

ACCOUNT_ID = "controlled-a"
TOKEN = "TEST-ONLY-PRIVATE-SESSION-VALUE"
ENDPOINT = "https://authorized.example/api/users/me"
LOGIN_ENDPOINT = "https://authorized.example/api/sessions"


def _policy(
    *,
    allow_state_changes: bool = True,
    controlled_account_ids: list[str] | None = None,
) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="test authorization",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value="https://authorized.example/api",
                schemes=["https"],
                ports=[443],
            )
        ],
        allowed_methods=["GET", "HEAD", "OPTIONS", "POST", "PATCH"],
        credentials_allowed=True,
        controlled_account_ids=(
            [ACCOUNT_ID] if controlled_account_ids is None else controlled_account_ids
        ),
        allow_state_changes=allow_state_changes,
        request_budget=20,
    )


def _hypothesis(field: str = "role") -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"hyp_mass_{field}",
        category="mass_assignment",
        title="Sensitive field may be client assignable",
        rationale="A documented security-sensitive request field requires verification.",
        target="https://authorized.example/api",
        endpoint=ENDPOINT,
        method="PATCH",
        parameter=field,
        confidence="medium",
        risk=RiskLevel.moderate,
        requires_credentials=True,
        state_changing=True,
        cleanup_required=True,
        metadata={"request_body_field": True},
        target_surface={"method": "PATCH", "path": "/users/me", "parameter": field},
    )


def _input(field: str, test_value: Any, expected_before: Any) -> dict[str, Any]:
    return {
        "mutation": {"field": field, "test_value": test_value},
        "expected_before": {field: expected_before},
        "cleanup_required": True,
    }


def _context_free_plan(field: str = "role"):
    hypothesis = _hypothesis(field)
    plan = VerificationPlanner().create_plan(
        hypothesis,
        VerificationPlanningContext(
            profile="authenticated",
            controlled_accounts=[],
            credential_accounts=[],
            test_owned_resources=[],
            request_budget=5,
            target_class="dedicated_lab",
        ),
    )
    return hypothesis, plan


class StatefulTransport:
    def __init__(
        self,
        *,
        field: str,
        before: Any,
        persist: bool = True,
        verification_error: bool = False,
        cleanup_status: int = 200,
        final_value: Any = ...,
    ) -> None:
        self.field = field
        self.state = before
        self.persist = persist
        self.verification_error = verification_error
        self.cleanup_status = cleanup_status
        self.final_value = final_value
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(deepcopy(request))
        if request["url"] == LOGIN_ENDPOINT:
            return {"status_code": 200, "body": {"token": TOKEN}}
        index = len([item for item in self.requests if item["url"] != LOGIN_ENDPOINT])
        if index == 1:
            return {"status_code": 200, "body": {self.field: self.state}}
        if index == 2:
            if self.persist:
                self.state = request["json"][self.field]
            return {"status_code": 200, "body": {"accepted": True}}
        if index == 3:
            if self.verification_error:
                raise RuntimeError("synthetic verification failure")
            return {"status_code": 200, "body": {self.field: self.state}}
        if index == 4:
            if 200 <= self.cleanup_status < 300:
                self.state = request["json"][self.field]
            return {
                "status_code": self.cleanup_status,
                "body": {"accepted": self.cleanup_status < 300},
            }
        if index == 5:
            value = self.state if self.final_value is ... else self.final_value
            return {"status_code": 200, "body": {self.field: value}}
        raise AssertionError("The mass-assignment adapter exceeded five requests.")


def _execute(
    transport: StatefulTransport,
    inputs: dict[str, Any],
    *,
    field: str = "role",
    allow_state_changes: bool = True,
    mutate_plan=None,
    policy_update: dict[str, Any] | None = None,
    acquire_session: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    vault = CredentialVault()
    try:
        credentials = (
            {
                "username": vault.put("controlled-a", label="controlled username"),
                "password": vault.put("controlled-password", label="password"),
            }
            if acquire_session
            else {"token": vault.put(TOKEN, label="controlled session")}
        )
        context = ControlledContext(
            accounts=[
                ControlledAccount(
                    account_id=ACCOUNT_ID,
                    credential_references=credentials,
                )
            ],
            objects=[
                ControlledObject(
                    object_id="users/me",
                    owner_account_id=ACCOUNT_ID,
                    object_type="user_profile",
                )
            ],
            session_acquisition=(
                SessionAcquisition(url=LOGIN_ENDPOINT, method="POST")
                if acquire_session
                else None
            ),
        )
        hypothesis, plan = _context_free_plan(field)
        if mutate_plan is not None:
            mutate_plan(plan)
        policy = _policy(allow_state_changes=allow_state_changes)
        if policy_update:
            policy = policy.model_copy(update=policy_update)
        gate = DeterministicPolicyGate(
            policy,
            Phase2PolicyContext(
                mode="verify",
                target_class="dedicated_lab",
                controlled_account_ids=[ACCOUNT_ID],
                controlled_object_ids=["users/me"],
                session_acquisition_url=(LOGIN_ENDPOINT if acquire_session else None),
                session_acquisition_method="POST" if acquire_session else None,
            ),
            RequestBudget(10),
        )
        result = ControlledVerificationExecutor(
            gate, vault, context, transport
        ).execute(hypothesis, plan, inputs=inputs)
        return result, transport.requests
    finally:
        vault.close()


def test_role_persists_and_restores_exact_before_state():
    transport = StatefulTransport(field="role", before="member")
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert result["status"] == "verified"
    assert result["cleanup_failed"] is False
    assert result["mutation_summary"] == {
        "field": "role",
        "before_hash": result["mutation_summary"]["before_hash"],
        "after_hash": result["mutation_summary"]["after_hash"],
        "restored_hash": result["mutation_summary"]["restored_hash"],
        "type": "string",
        "mutation_accepted": True,
        "persistence_confirmed": True,
        "cleanup_attempted": True,
        "cleanup_verified": True,
    }
    assert (
        result["mutation_summary"]["before_hash"]
        == result["mutation_summary"]["restored_hash"]
    )
    assert [item["method"] for item in requests] == [
        "GET",
        "PATCH",
        "GET",
        "PATCH",
        "GET",
    ]
    assert requests[1]["json"] == {"role": "admin"}
    assert requests[3]["json"] == {"role": "member"}
    assert [requests[3]["purpose"], requests[4]["purpose"]] == [
        "cleanup",
        "cleanup",
    ]
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 0,
        "verification": 3,
        "cleanup": 2,
        "attempted": 5,
        "total": 5,
    }
    assert result["requests_used"] == result["request_delta"]["total"]
    assert all(
        item["headers"]["Authorization"] == f"Bearer {TOKEN}" for item in requests
    )
    assert result["runtime_binding"] == {
        "required_accounts": 1,
        "bound_accounts": 1,
        "owner_bound": True,
        "comparator_bound": False,
        "policy_authorized": True,
    }


def test_session_acquisition_and_cleanup_are_both_in_result_delta():
    transport = StatefulTransport(field="role", before="member")
    result, requests = _execute(
        transport,
        _input("role", "admin", "member"),
        acquire_session=True,
    )

    assert len(requests) == 6
    assert requests[0]["url"] == LOGIN_ENDPOINT
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 1,
        "verification": 3,
        "cleanup": 2,
        "attempted": 6,
        "total": 6,
    }
    assert result["requests_used"] == 6


def test_context_free_plan_binds_one_runtime_account_and_all_five_actions():
    hypothesis, plan = _context_free_plan()
    stored_template = plan.model_dump(mode="json")
    context = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id=ACCOUNT_ID,
                role="member",
                credential_references={"token": "runtime-token-reference"},
            )
        ],
        objects=[
            ControlledObject(
                object_id="/users/me/",
                owner_account_id=ACCOUNT_ID,
                object_type="user_profile",
                test_owned=True,
            )
        ],
    )

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
    assert binding.plan.controlled_accounts == [ACCOUNT_ID]
    assert binding.plan.test_owned_resources == ["/users/me/"]
    actions = binding.plan.steps[0].metadata["requests"]
    assert len(actions) == 5
    assert {item["account_id"] for item in actions} == {ACCOUNT_ID}
    assert {item["object_owner_account_id"] for item in actions} == {ACCOUNT_ID}
    assert all(item["test_owned_resource"] for item in actions)
    assert plan.model_dump(mode="json") == stored_template


def test_runtime_binding_rejects_owner_mismatch_and_missing_test_owned_resource():
    hypothesis, plan = _context_free_plan()
    mismatched = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id=ACCOUNT_ID,
                credential_references={"token": "runtime-token-reference"},
            )
        ],
        objects=[
            ControlledObject(
                object_id="users/me",
                owner_account_id="different-account",
                object_type="user_profile",
            )
        ],
    )
    not_test_owned = mismatched.model_copy(deep=True)
    not_test_owned.objects[0].owner_account_id = ACCOUNT_ID
    not_test_owned.objects[0].test_owned = False

    owner_result = bind_runtime_accounts(hypothesis, plan, mismatched, _policy())
    ownership_result = bind_runtime_accounts(
        hypothesis, plan, not_test_owned, _policy()
    )

    assert owner_result.succeeded is False
    assert owner_result.diagnostics["bound_accounts"] == 0
    assert "not a controlled account" in " ".join(owner_result.reasons)
    assert ownership_result.succeeded is False
    assert ownership_result.diagnostics["bound_accounts"] == 0
    assert "test-owned" in " ".join(ownership_result.reasons)


def test_runtime_binding_rejects_ambiguous_owners_and_policy_denial():
    hypothesis, plan = _context_free_plan()
    accounts = [
        ControlledAccount(
            account_id=account_id,
            credential_references={"token": f"runtime-{account_id}-reference"},
        )
        for account_id in (ACCOUNT_ID, "controlled-b")
    ]
    ambiguous = ControlledContext(
        accounts=accounts,
        objects=[
            ControlledObject(
                object_id=object_id,
                owner_account_id=owner,
                object_type="user_profile",
            )
            for object_id, owner in (
                ("users/me", ACCOUNT_ID),
                ("/users/me/", "controlled-b"),
            )
        ],
    )
    unique = ambiguous.model_copy(deep=True)
    unique.objects = [unique.objects[0]]

    ambiguous_result = bind_runtime_accounts(
        hypothesis,
        plan,
        ambiguous,
        _policy(controlled_account_ids=[ACCOUNT_ID, "controlled-b"]),
    )
    unique_result = bind_runtime_accounts(
        hypothesis,
        plan,
        unique,
        _policy(controlled_account_ids=[ACCOUNT_ID, "controlled-b"]),
    )
    denied_result = bind_runtime_accounts(
        hypothesis,
        plan,
        unique,
        _policy(controlled_account_ids=["controlled-b"]),
    )

    assert ambiguous_result.succeeded is False
    assert "exactly one controlled account" in " ".join(ambiguous_result.reasons)
    assert unique_result.succeeded is True
    assert unique_result.plan is not None
    assert unique_result.plan.controlled_accounts == [ACCOUNT_ID]
    assert denied_result.succeeded is False
    assert "not authorized by policy" in " ".join(denied_result.reasons)


def test_runtime_binding_rejects_missing_credentials_and_cross_user_route():
    hypothesis, plan = _context_free_plan()
    no_credentials = ControlledContext(
        accounts=[ControlledAccount(account_id=ACCOUNT_ID)],
        objects=[
            ControlledObject(
                object_id="users/me",
                owner_account_id=ACCOUNT_ID,
                object_type="user_profile",
            )
        ],
    )
    cross_user_hypothesis = hypothesis.model_copy(
        update={"endpoint": "https://authorized.example/api/users/different-account"}
    )
    cross_user_plan = VerificationPlanner().create_plan(
        cross_user_hypothesis,
        VerificationPlanningContext(
            profile="authenticated",
            request_budget=5,
            target_class="dedicated_lab",
        ),
    )

    credential_result = bind_runtime_accounts(
        hypothesis, plan, no_credentials, _policy()
    )
    route_result = bind_runtime_accounts(
        cross_user_hypothesis,
        cross_user_plan,
        no_credentials.model_copy(
            update={
                "accounts": [
                    ControlledAccount(
                        account_id=ACCOUNT_ID,
                        credential_references={"token": "runtime-token-reference"},
                    )
                ]
            }
        ),
        _policy(),
    )

    assert credential_result.succeeded is False
    assert "no available controlled session" in " ".join(credential_result.reasons)
    assert route_result.succeeded is False
    assert "matching the planned own-resource path" in " ".join(route_result.reasons)


def test_accepted_mutation_that_does_not_persist_is_rejected():
    transport = StatefulTransport(field="role", before="member", persist=False)
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert len(requests) == 5
    assert result["status"] == "rejected"
    assert result["mutation_summary"]["mutation_accepted"] is True
    assert result["mutation_summary"]["persistence_confirmed"] is False
    assert result["mutation_summary"]["cleanup_verified"] is True


def test_unexpected_independent_state_is_inconclusive_and_restored():
    class UnexpectedStateTransport(StatefulTransport):
        def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
            response = super().__call__(request)
            if len(self.requests) == 3:
                response["body"] = {self.field: "unexpected"}
            return response

    transport = UnexpectedStateTransport(field="role", before="member")
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert len(requests) == 5
    assert result["status"] == "inconclusive"
    assert result["mutation_summary"]["persistence_confirmed"] is False
    assert result["mutation_summary"]["cleanup_verified"] is True


def test_expected_before_mismatch_stops_before_patch():
    transport = StatefulTransport(field="role", before="member")
    result, requests = _execute(transport, _input("role", "admin", "guest"))

    assert result["status"] == "inconclusive"
    assert [item["method"] for item in requests] == ["GET"]
    assert result["mutation_summary"]["cleanup_attempted"] is False


def test_field_mismatch_and_missing_test_value_are_blocked_before_patch():
    mismatch = StatefulTransport(field="role", before="member")
    mismatch_result, mismatch_requests = _execute(
        mismatch, _input("tenant_id", "tenant-b", "tenant-a")
    )
    missing = StatefulTransport(field="role", before="member")
    missing_result, missing_requests = _execute(
        missing,
        {
            "mutation": {"field": "role"},
            "expected_before": {"role": "member"},
            "cleanup_required": True,
        },
    )

    assert mismatch_result["status"] == "policy_blocked"
    assert missing_result["status"] == "policy_blocked"
    assert mismatch_requests == []
    assert missing_requests == []


def test_credit_limit_preserves_numeric_json_type():
    transport = StatefulTransport(field="credit_limit", before=100)
    result, requests = _execute(
        transport,
        _input("credit_limit", 250.5, 100),
        field="credit_limit",
    )

    assert result["status"] == "verified"
    assert result["mutation_summary"]["type"] == "number"
    assert requests[1]["json"]["credit_limit"] == 250.5
    assert type(requests[1]["json"]["credit_limit"]) is float
    assert requests[3]["json"]["credit_limit"] == 100
    assert type(requests[3]["json"]["credit_limit"]) is int


def test_verification_error_still_runs_cleanup_and_final_get():
    transport = StatefulTransport(
        field="role", before="member", verification_error=True
    )
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert len(requests) == 5
    assert [item["method"] for item in requests[-2:]] == ["PATCH", "GET"]
    assert result["status"] == "inconclusive"
    assert result["mutation_summary"]["cleanup_attempted"] is True
    assert result["mutation_summary"]["cleanup_verified"] is True


def test_cleanup_patch_failure_sets_high_visibility_failure():
    transport = StatefulTransport(field="role", before="member", cleanup_status=500)
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert len(requests) == 5
    assert result["status"] != "verified"
    assert result["cleanup_failed"] is True
    assert result["mutation_summary"]["cleanup_verified"] is False
    assert result["warning"].startswith("CLEANUP FAILED")


def test_final_get_difference_sets_cleanup_failed():
    transport = StatefulTransport(
        field="role", before="member", final_value="unexpected"
    )
    result, requests = _execute(transport, _input("role", "admin", "member"))

    assert len(requests) == 5
    assert result["status"] == "inconclusive"
    assert result["cleanup_failed"] is True
    assert result["mutation_summary"]["cleanup_verified"] is False


def test_state_changes_disabled_sends_no_requests():
    transport = StatefulTransport(field="role", before="member")
    result, requests = _execute(
        transport,
        _input("role", "admin", "member"),
        allow_state_changes=False,
    )

    assert result["status"] == "policy_blocked"
    assert requests == []


def test_policy_must_require_test_ownership_and_cleanup():
    ownership = StatefulTransport(field="role", before="member")
    ownership_result, ownership_requests = _execute(
        ownership,
        _input("role", "admin", "member"),
        policy_update={"require_test_owned_resources": False},
    )
    cleanup = StatefulTransport(field="role", before="member")
    cleanup_result, cleanup_requests = _execute(
        cleanup,
        _input("role", "admin", "member"),
        policy_update={"require_cleanup_for_state_changes": False},
    )

    assert ownership_result["status"] == "policy_blocked"
    assert cleanup_result["status"] == "policy_blocked"
    assert ownership_requests == []
    assert cleanup_requests == []


def test_arbitrary_user_resource_and_additional_input_are_blocked():
    def replace_url(plan) -> None:
        for request in plan.steps[0].metadata["requests"]:
            request["url"] = "https://authorized.example/api/users/other-user"

    arbitrary = StatefulTransport(field="role", before="member")
    arbitrary_result, arbitrary_requests = _execute(
        arbitrary,
        _input("role", "admin", "member"),
        mutate_plan=replace_url,
    )
    extra = StatefulTransport(field="role", before="member")
    extra_input = _input("role", "admin", "member")
    extra_input["request_overrides"] = [{"url": ENDPOINT}]
    extra_result, extra_requests = _execute(extra, extra_input)

    assert arbitrary_result["status"] == "policy_blocked"
    assert extra_result["status"] == "policy_blocked"
    assert arbitrary_requests == []
    assert extra_requests == []


def test_secret_values_are_absent_from_output_store_and_report(tmp_path):
    transport = StatefulTransport(field="role", before="member")
    result, _ = _execute(transport, _input("role", "admin", "member"))
    run = {
        "run_id": "safe-mass-assignment",
        "mode": "verify",
        "hypotheses": [],
        "verification_plans": [],
        "verification_results": [result],
    }
    store = Phase2RunStore(tmp_path)
    stored_path = store.save(run)
    rendered = "\n".join(
        [
            json.dumps(result, sort_keys=True),
            json.dumps(store.load(stored_path), sort_keys=True),
            render_phase2_report(run),
        ]
    )

    assert TOKEN not in rendered
    assert "Authorization" not in rendered
    assert "Bearer " not in rendered
    assert '"admin"' not in rendered
    assert '"member"' not in rendered
