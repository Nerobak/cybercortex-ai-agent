from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import agent
import phase2_cli
from agent_core import verification_runtime as verification_runtime_module
from agent_core.agent_models import Hypothesis, RiskLevel
from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    SessionAcquisition,
    load_controlled_context,
)
from agent_core.controlled_executor import ControlledVerificationExecutor
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.verification_runtime import build_verification_policy_context
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.safe_http import ScopedHTTPClient

TARGET = "https://recovery.example"
START_URL = f"{TARGET}/password-recovery"
COMPLETE_URL = f"{TARGET}/password-recovery/complete"
LOGIN_URL = f"{TARGET}/sessions"
ACCOUNT_ID = "alice"
EMAIL = "alice-controlled@example.test"
USERNAME = "alice-controlled-legacy-identity"
ORIGINAL_PASSWORD = "original-controlled-password-value"
RECOVERY_CODE = "legitimate-researcher-code-value"
TEMPORARY_PASSWORD = "approved-temporary-password-value"
COMPARISON_PASSWORD = "approved-comparison-password-value"
CHALLENGE_ID = 731


def _hypothesis_and_plan():
    hypothesis = Hypothesis(
        hypothesis_id="hyp-recovery-state",
        category="recovery_state_enforcement",
        title="Controlled recovery reuse comparison",
        rationale="A correlated recovery workflow requires controlled verification.",
        target=TARGET,
        endpoint=COMPLETE_URL,
        method="POST",
        requires_credentials=True,
        state_changing=True,
        cleanup_required=True,
        safe_verification_possible=True,
        risk=RiskLevel.moderate,
        metadata={
            "related_surfaces": [
                {
                    "boundary_type": "recovery_start",
                    "method": "POST",
                    "path": "/password-recovery",
                    "identity_field": "email",
                },
                {
                    "boundary_type": "recovery_completion",
                    "method": "POST",
                    "path": "/password-recovery/complete",
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
    allow_state_changes: bool = True,
    controlled_account_ids: list[str] | None = None,
    cleanup_policy: bool = True,
) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="controlled recovery test authorization",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=TARGET,
                schemes=["https"],
                ports=[443],
            )
        ],
        allowed_methods=["POST"],
        credentials_allowed=True,
        controlled_account_ids=(
            [ACCOUNT_ID] if controlled_account_ids is None else controlled_account_ids
        ),
        allow_state_changes=allow_state_changes,
        require_cleanup_for_state_changes=cleanup_policy,
        request_budget=10,
    )


def _context(
    vault: CredentialVault,
    *,
    accounts: int = 1,
    controlled: bool = True,
    identity_kind: str = "email",
    include_password: bool = True,
) -> ControlledContext:
    configured = []
    for index in range(accounts):
        account_id = ACCOUNT_ID if index == 0 else f"controlled-{index}"
        references: dict[str, str] = {}
        if identity_kind in {"email", "username", "both"}:
            identity = (
                EMAIL
                if identity_kind in {"email", "both"} and index == 0
                else (
                    USERNAME
                    if identity_kind == "username" and index == 0
                    else f"controlled-{index}@example.test"
                )
            )
            primary_kind = "email" if identity_kind == "both" else identity_kind
            references[primary_kind] = vault.put(
                identity, label=f"{account_id}:{primary_kind}"
            )
            if identity_kind == "both":
                references["username"] = vault.put(
                    USERNAME, label=f"{account_id}:username"
                )
        if include_password:
            references["password"] = vault.put(
                ORIGINAL_PASSWORD,
                label=f"{account_id}:original-password",
            )
        configured.append(
            ControlledAccount(
                account_id=account_id,
                controlled=controlled,
                credential_references=references,
            )
        )
    return ControlledContext(
        accounts=configured,
        session_acquisition=SessionAcquisition(
            url=LOGIN_URL,
            method="POST",
            username_field="email",
            password_field="password",
            token_field="token",
        ),
    )


def _input(**updates: Any) -> dict[str, Any]:
    recovery = {
        "account_id": ACCOUNT_ID,
        "comparison_type": "reused_same_challenge_and_code",
        "phase": "resume_with_controlled_evidence",
        "code": RECOVERY_CODE,
        "temporary_password": TEMPORARY_PASSWORD,
        "comparison_password": COMPARISON_PASSWORD,
    }
    recovery.update(updates)
    return {"recovery": recovery, "cleanup_required": True}


def _issue_input(**updates: Any) -> dict[str, Any]:
    recovery = {
        "account_id": ACCOUNT_ID,
        "comparison_type": "reused_same_challenge_and_code",
    }
    recovery.update(updates)
    return {"recovery": recovery, "cleanup_required": True}


class RecoveryTransport:
    def __init__(
        self,
        *,
        valid_status: int = 200,
        comparison_status: int = 409,
        comparison_login_succeeds: bool = True,
        original_login_succeeds: bool = True,
        challenge_id: Any = CHALLENGE_ID,
        identity: str = EMAIL,
    ) -> None:
        self.valid_status = valid_status
        self.comparison_status = comparison_status
        self.comparison_login_succeeds = comparison_login_succeeds
        self.original_login_succeeds = original_login_succeeds
        self.challenge_id = challenge_id
        self.identity = identity
        self.calls: list[dict[str, Any]] = []
        self.completions = 0

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(deepcopy(request))
        if request["url"] == START_URL:
            assert request["method"] == "POST"
            assert request["json"] == {"email": self.identity}
            return {
                "status_code": 200,
                "body": {"challenge_id": self.challenge_id, "message": "issued"},
            }
        if request["url"] == COMPLETE_URL:
            self.completions += 1
            expected_password = (
                TEMPORARY_PASSWORD if self.completions == 1 else COMPARISON_PASSWORD
            )
            assert request["json"] == {
                "challenge_id": CHALLENGE_ID,
                "code": RECOVERY_CODE,
                "new_password": expected_password,
            }
            status = (
                self.valid_status if self.completions == 1 else self.comparison_status
            )
            return {"status_code": status, "body": {"accepted": status < 300}}
        if request["url"] == LOGIN_URL:
            password = request["json"]["password"]
            succeeds = (
                self.comparison_login_succeeds
                if password == COMPARISON_PASSWORD
                else self.original_login_succeeds
            )
            return (
                {"status_code": 200, "body": {"token": "controlled-session"}}
                if succeeds
                else {"status_code": 401, "body": {"error": "denied"}}
            )
        raise AssertionError("The recovery adapter dispatched an unplanned URL.")


def _execute(
    inputs: dict[str, Any],
    transport: RecoveryTransport,
    *,
    policy: AssessmentPolicy | None = None,
    accounts: int = 1,
    controlled: bool = True,
    prior_result: dict[str, Any] | None = None,
    identity_kind: str = "email",
    include_password: bool = True,
    run_id: str = "recovery-run",
    private_store: Any | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hypothesis, plan = _hypothesis_and_plan()
    with CredentialVault() as vault:
        context = _context(
            vault,
            accounts=accounts,
            controlled=controlled,
            identity_kind=identity_kind,
            include_password=include_password,
        )
        gate = DeterministicPolicyGate(
            policy or _policy(),
            Phase2PolicyContext(
                mode="verify",
                target_class="dedicated_lab",
                controlled_account_ids=[
                    account.account_id
                    for account in context.accounts
                    if account.controlled
                ],
                session_acquisition_url=LOGIN_URL,
                session_acquisition_method="POST",
                replay_enabled=True,
            ),
            RequestBudget(10),
        )
        result = ControlledVerificationExecutor(
            gate,
            vault,
            context,
            transport,
            private_recovery_store=private_store,
        ).execute(
            hypothesis,
            plan,
            inputs=inputs,
            prior_result=prior_result,
            run_id=run_id,
        )
    return result, transport.calls


def test_private_recovery_state_supports_resume_cleanup_and_single_consumption(
    tmp_path,
):
    store = Phase2RunStore(tmp_path / "private-recovery")
    private = store.private_recovery
    transport = RecoveryTransport(comparison_status=200)

    issued, _ = _execute(
        _issue_input(), transport, private_store=private, run_id="private-run"
    )
    assert issued["status"] == "awaiting_controlled_evidence"
    assert "preserved_challenge" not in issued
    saved = private.load_for_executor(
        run_reference="private-run", hypothesis_id="hyp-recovery-state"
    )
    assert saved is not None and saved["consumed"] is False
    private_files = list((store.directory / ".private").glob("*.json"))
    assert len(private_files) == 1
    assert private_files[0].stat().st_mode & 0o777 == 0o600
    assert (store.directory / ".private").stat().st_mode & 0o777 == 0o700
    private_text = private_files[0].read_text(encoding="utf-8")
    for secret in (
        RECOVERY_CODE,
        TEMPORARY_PASSWORD,
        COMPARISON_PASSWORD,
        ORIGINAL_PASSWORD,
    ):
        assert secret not in private_text

    empty_private = Phase2RunStore(tmp_path / "empty-private").private_recovery
    missing, missing_calls = _execute(
        _input(),
        RecoveryTransport(),
        prior_result=issued,
        private_store=empty_private,
        run_id="private-run",
    )
    assert missing["status"] == "policy_blocked"
    assert missing_calls == []

    resumed, _ = _execute(
        _input(),
        transport,
        prior_result=issued,
        private_store=private,
        run_id="private-run",
    )
    assert resumed["status"] == "verification_pending_cleanup"
    assert "preserved_challenge" not in resumed
    consumed = private.load_for_executor(
        run_reference="private-run", hypothesis_id="hyp-recovery-state"
    )
    assert consumed is not None and consumed["consumed"] is True

    reused, calls_before = len(transport.calls), len(transport.calls)
    blocked, _ = _execute(
        _input(),
        transport,
        prior_result=issued,
        private_store=private,
        run_id="private-run",
    )
    assert blocked["status"] == "policy_blocked"
    assert len(transport.calls) == calls_before == reused

    final, _ = _execute(
        _cleanup_input(),
        transport,
        prior_result=resumed,
        private_store=private,
        run_id="private-run",
    )
    assert final["status"] == "verified"
    assert "preserved_challenge" not in final


def _cleanup_input() -> dict[str, Any]:
    return {
        "recovery": {
            "account_id": ACCOUNT_ID,
            "comparison_type": "reused_same_challenge_and_code",
            "phase": "confirm_external_cleanup",
        },
        "cleanup_required": True,
    }


def _issue_and_resume(
    transport: RecoveryTransport,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    issued, _ = _execute(_issue_input(), transport)
    resumed, calls = _execute(_input(), transport, prior_result=issued)
    return issued, resumed, calls


def test_challenge_issuance_requires_no_code_and_stops_before_completion():
    result, calls = _execute(_issue_input(), RecoveryTransport())

    assert result["status"] == "awaiting_controlled_evidence"
    assert result["recovery_phase"] == "challenge_issued"
    assert result["recovery_evidence_required"] is True
    assert result["external_evidence_required"] is True
    assert result["challenge_reference"].startswith("sha256:")
    assert "preserved_challenge" not in result
    assert len(calls) == 1
    assert calls[0]["url"] == START_URL
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 0,
        "verification": 1,
        "cleanup": 0,
        "attempted": 1,
        "total": 1,
    }


def test_email_and_legacy_username_identity_references_both_work():
    email_result, email_calls = _execute(_issue_input(), RecoveryTransport())
    username_result, username_calls = _execute(
        _issue_input(),
        RecoveryTransport(identity=USERNAME),
        identity_kind="username",
    )
    both_result, both_calls = _execute(
        _issue_input(), RecoveryTransport(), identity_kind="both"
    )

    assert email_result["status"] == "awaiting_controlled_evidence"
    assert username_result["status"] == "awaiting_controlled_evidence"
    assert both_result["status"] == "awaiting_controlled_evidence"
    assert email_calls[0]["json"] == {"email": EMAIL}
    assert username_calls[0]["json"] == {"email": USERNAME}
    assert both_calls[0]["json"] == {"email": EMAIL}


def test_legacy_top_level_username_password_context_loads_without_manual_refs(
    tmp_path,
):
    context_path = tmp_path / "legacy-context.json"
    context_path.write_text(
        json.dumps(
            {
                "accounts": [
                    {
                        "account_id": ACCOUNT_ID,
                        "username": USERNAME,
                        "password": ORIGINAL_PASSWORD,
                    }
                ],
                "session_acquisition": {
                    "url": LOGIN_URL,
                    "method": "POST",
                    "username_field": "email",
                    "password_field": "password",
                    "token_field": "token",
                },
            }
        ),
        encoding="utf-8",
    )
    hypothesis, plan = _hypothesis_and_plan()
    transport = RecoveryTransport(identity=USERNAME)
    with CredentialVault() as vault:
        context = load_controlled_context(context_path, vault)
        assert set(context.accounts[0].credential_references) == {
            "username",
            "password",
        }
        gate = DeterministicPolicyGate(
            _policy(),
            Phase2PolicyContext(
                mode="verify",
                target_class="dedicated_lab",
                controlled_account_ids=[ACCOUNT_ID],
                session_acquisition_url=LOGIN_URL,
                session_acquisition_method="POST",
            ),
            RequestBudget(10),
        )
        result = ControlledVerificationExecutor(
            gate, vault, context, transport
        ).execute(
            hypothesis,
            plan,
            inputs=_issue_input(),
            run_id="legacy-context-run",
        )

    assert result["status"] == "awaiting_controlled_evidence"
    assert transport.calls[0]["json"] == {"email": USERNAME}
    assert USERNAME not in json.dumps(result, sort_keys=True)


def test_missing_identity_or_original_password_blocks_before_traffic():
    no_identity, identity_calls = _execute(
        _issue_input(), RecoveryTransport(), identity_kind="neither"
    )
    no_password, password_calls = _execute(
        _issue_input(), RecoveryTransport(), include_password=False
    )

    assert no_identity["status"] == "policy_blocked"
    assert no_password["status"] == "policy_blocked"
    assert identity_calls == password_calls == []


def test_resume_uses_preserved_challenge_without_second_start_and_code_twice():
    issued, resumed, calls = _issue_and_resume(RecoveryTransport(comparison_status=200))

    assert "preserved_challenge" not in issued
    assert resumed["status"] == "verification_pending_cleanup"
    assert resumed["recovery_phase"] == "verification_pending_cleanup"
    assert "preserved_challenge" not in resumed
    assert [call["url"] for call in calls] == [
        START_URL,
        COMPLETE_URL,
        COMPLETE_URL,
        LOGIN_URL,
    ]
    assert calls[1]["json"]["challenge_id"] == CHALLENGE_ID
    assert calls[2]["json"]["challenge_id"] == CHALLENGE_ID
    assert calls[1]["json"]["code"] == RECOVERY_CODE
    assert calls[2]["json"]["code"] == RECOVERY_CODE
    assert resumed["request_budget"]["verification_requests"] == 2
    assert resumed["request_budget"]["auth_requests"] == 1
    assert resumed["request_delta"] == {
        "discovery": 0,
        "auth": 1,
        "verification": 2,
        "cleanup": 0,
        "attempted": 3,
        "total": 3,
    }


def test_user_challenge_substitution_and_wrong_comparison_fail_closed():
    issued, _ = _execute(_issue_input(), RecoveryTransport())
    substituted, substituted_calls = _execute(
        _input(challenge_id=999999), RecoveryTransport(), prior_result=issued
    )
    unsupported, unsupported_calls = _execute(
        _input(comparison_type="missing_challenge"),
        RecoveryTransport(),
        prior_result=issued,
    )

    assert substituted["status"] == "policy_blocked"
    assert unsupported["status"] == "policy_blocked"
    assert substituted_calls == unsupported_calls == []


def test_resume_missing_evidence_or_preserved_challenge_fails_closed():
    issued, _ = _execute(_issue_input(), RecoveryTransport())
    for missing in ("code", "temporary_password", "comparison_password"):
        inputs = _input()
        inputs["recovery"].pop(missing)
        result, calls = _execute(inputs, RecoveryTransport(), prior_result=issued)
        assert result["status"] == "policy_blocked"
        assert calls == []
    absent, absent_calls = _execute(_input(), RecoveryTransport())
    assert absent["status"] == "policy_blocked"
    assert absent_calls == []


def test_private_workflow_run_and_hypothesis_challenge_tampering_fails(tmp_path):
    store = Phase2RunStore(tmp_path / "tampered-private")
    private = store.private_recovery
    for field in ("account_binding", "workflow_binding", "hypothesis_binding"):
        issued, _ = _execute(_issue_input(), RecoveryTransport(), private_store=private)
        state = private.load_for_executor(
            run_reference="recovery-run", hypothesis_id="hyp-recovery-state"
        )
        assert state is not None
        state[field] = "sha256:" + "0" * 64
        private.save_for_executor(
            run_reference="recovery-run",
            hypothesis_id="hyp-recovery-state",
            challenge=state,
        )
        result, calls = _execute(
            _input(),
            RecoveryTransport(),
            prior_result=issued,
            private_store=private,
        )
        assert result["status"] == "policy_blocked"
        assert calls == []
    issued, _ = _execute(_issue_input(), RecoveryTransport(), private_store=private)
    wrong_run, wrong_run_calls = _execute(
        _input(),
        RecoveryTransport(),
        prior_result=issued,
        run_id="another-run",
        private_store=private,
    )
    assert wrong_run["status"] == "policy_blocked"
    assert wrong_run_calls == []


def test_second_resume_and_duplicate_challenge_issuance_fail_closed():
    transport = RecoveryTransport(comparison_status=200)
    issued, resumed, _ = _issue_and_resume(transport)
    second_resume, resume_calls = _execute(
        _input(), RecoveryTransport(), prior_result=resumed
    )
    duplicate_issue, issue_calls = _execute(
        _issue_input(), RecoveryTransport(), prior_result=issued
    )

    assert second_resume["status"] == "policy_blocked"
    assert duplicate_issue["status"] == "policy_blocked"
    assert resume_calls == issue_calls == []


def test_denied_reuse_is_rejected_only_after_external_cleanup_confirmation():
    _, pending, calls = _issue_and_resume(
        RecoveryTransport(
            comparison_status=409,
            comparison_login_succeeds=False,
        )
    )
    assert pending["status"] == "verification_pending_cleanup"
    assert pending["comparison_accepted"] is False
    assert pending["external_cleanup_required"] is True
    assert len(calls) == 4

    result, cleanup_calls = _execute(
        _cleanup_input(),
        RecoveryTransport(original_login_succeeds=True),
        prior_result=pending,
    )
    assert result["status"] == "rejected"
    assert result["cleanup_verified"] is True
    assert result["external_cleanup_required"] is False
    assert len(cleanup_calls) == 1
    assert cleanup_calls[0]["json"]["password"] == ORIGINAL_PASSWORD


def test_confirmed_reuse_promotes_only_after_original_credential_cleanup():
    _, pending, _ = _issue_and_resume(RecoveryTransport(comparison_status=200))
    assert pending["status"] == "verification_pending_cleanup"
    assert pending["comparison_accepted"] is True
    assert pending["independent_state_confirmed"] is True

    result, calls = _execute(
        _cleanup_input(), RecoveryTransport(), prior_result=pending
    )
    assert result["status"] == "verified"
    assert result["cleanup_verified"] is True
    assert result["request_budget"]["auth_requests"] == 0
    assert result["request_budget"]["cleanup_requests"] == 1
    assert result["request_delta"] == {
        "discovery": 0,
        "auth": 0,
        "verification": 0,
        "cleanup": 1,
        "attempted": 1,
        "total": 1,
    }
    assert calls[0]["purpose"] == "cleanup"
    assert len(calls) == 1


def test_cleanup_failure_prevents_promotion_and_sets_failure_state():
    _, pending, _ = _issue_and_resume(RecoveryTransport(comparison_status=200))
    result, calls = _execute(
        _cleanup_input(),
        RecoveryTransport(original_login_succeeds=False),
        prior_result=pending,
    )

    assert result["status"] == "inconclusive"
    assert result["cleanup_verified"] is False
    assert result["cleanup_failed"] is True
    assert result["external_cleanup_required"] is True
    assert len(calls) == 1


def test_invalid_challenge_type_and_duplicate_passwords_fail_closed():
    invalid, calls = _execute(
        _issue_input(), RecoveryTransport(challenge_id=str(CHALLENGE_ID))
    )
    issued, _ = _execute(_issue_input(), RecoveryTransport())
    duplicate, duplicate_calls = _execute(
        _input(comparison_password=TEMPORARY_PASSWORD),
        RecoveryTransport(),
        prior_result=issued,
    )

    assert invalid["status"] == "inconclusive"
    assert invalid["challenge_reference"] is None
    assert len(calls) == 1
    assert duplicate["status"] == "policy_blocked"
    assert duplicate_calls == []


def test_recovery_secrets_and_raw_identity_never_enter_result_store_report_export(
    tmp_path,
):
    transport = RecoveryTransport(identity=USERNAME, comparison_status=200)
    issued, _ = _execute(_issue_input(), transport, identity_kind="username")
    inputs = _input()
    result, _ = _execute(
        inputs,
        transport,
        prior_result=issued,
        identity_kind="username",
    )
    hypothesis, plan = _hypothesis_and_plan()
    run = {
        "run_id": "recovery-secret-regression",
        "target": TARGET,
        "assessment_mode": "verify",
        "attack_surface": {},
        "hypotheses": [hypothesis.model_dump(mode="json")],
        "verification_plans": [plan.model_dump(mode="json")],
        "verification_results": [issued, result],
        "metrics": {"request_count": 4},
    }
    store = Phase2RunStore(tmp_path / "phase2")
    stored_path = store.save(run)
    rendered = "\n".join(
        [
            json.dumps(result, sort_keys=True),
            json.dumps(inputs, sort_keys=True),
            Path(stored_path).read_text(encoding="utf-8"),
            render_phase2_report(run),
            json.dumps(build_benchmark_export(run), sort_keys=True),
        ]
    )
    for secret in (
        USERNAME,
        RECOVERY_CODE,
        TEMPORARY_PASSWORD,
        COMPARISON_PASSWORD,
        ORIGINAL_PASSWORD,
        "controlled-session",
    ):
        assert secret not in rendered


def test_policy_changes_cleanup_false_and_account_binding_block_before_traffic():
    issued, _ = _execute(_issue_input(), RecoveryTransport())
    disabled, disabled_calls = _execute(
        _input(),
        RecoveryTransport(),
        policy=_policy(allow_state_changes=False),
        prior_result=issued,
    )
    cleanup_input = _input()
    cleanup_input["cleanup_required"] = False
    no_cleanup, cleanup_calls = _execute(
        cleanup_input, RecoveryTransport(), prior_result=issued
    )
    mismatch, mismatch_calls = _execute(
        _input(),
        RecoveryTransport(),
        policy=_policy(controlled_account_ids=["different-controlled-account"]),
        prior_result=issued,
    )

    assert disabled["status"] == "policy_blocked"
    assert no_cleanup["status"] == "policy_blocked"
    assert mismatch["status"] == "policy_blocked"
    assert disabled_calls == cleanup_calls == mismatch_calls == []


def test_zero_or_multiple_controlled_accounts_block_before_traffic():
    zero, zero_calls = _execute(
        _issue_input(), RecoveryTransport(), accounts=1, controlled=False
    )
    multiple, multiple_calls = _execute(_issue_input(), RecoveryTransport(), accounts=2)
    assert zero["status"] == "policy_blocked"
    assert multiple["status"] == "policy_blocked"
    assert zero_calls == multiple_calls == []


def test_recovery_plan_separates_issue_resume_auth_and_cleanup_accounting():
    _, plan = _hypothesis_and_plan()
    assert len(plan.steps[0].metadata["requests"]) == 3
    assert plan.estimated_requests == 5
    assert plan.steps[0].metadata["request_accounting"] == {
        "challenge_issuance_recovery_requests": 1,
        "resume_recovery_completion_requests": 2,
        "resume_authentication_state_confirmation_requests": 1,
        "external_cleanup_verification_requests": 1,
        "phase_a1_challenge_issuance_requests": 1,
        "phase_a2_resume_requests": 3,
        "phase_b_cleanup_confirmation_requests": 1,
        "external_cleanup_may_be_required": True,
    }


def _write_execution_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.json"
    context_path = tmp_path / "context.json"
    input_path = tmp_path / "input.json"
    policy_path.write_text(
        json.dumps(_policy().model_dump(mode="json")), encoding="utf-8"
    )
    context_path.write_text(
        json.dumps(
            {
                "accounts": [
                    {
                        "account_id": ACCOUNT_ID,
                        "controlled": True,
                        "credentials": {
                            "email": EMAIL,
                            "password": ORIGINAL_PASSWORD,
                        },
                    }
                ],
                "session_acquisition": {
                    "url": LOGIN_URL,
                    "method": "POST",
                    "username_field": "email",
                    "password_field": "password",
                    "token_field": "token",
                },
            }
        ),
        encoding="utf-8",
    )
    input_path.write_text(json.dumps(_input()), encoding="utf-8")
    return policy_path, context_path, input_path


def test_phase2_cli_verification_run_routes_staged_recovery_input(
    tmp_path, monkeypatch
):
    hypothesis, plan = _hypothesis_and_plan()
    run = {
        "run_id": "phase2-cli-recovery",
        "target": TARGET,
        "hypotheses": [hypothesis.model_dump(mode="json")],
        "verification_plans": [plan.model_dump(mode="json")],
        "verification_results": [],
        "metrics": {},
    }
    store = Phase2RunStore(tmp_path / "phase2")
    store.save(run)
    policy_path, context_path, input_path = _write_execution_files(tmp_path)
    observed: dict[str, Any] = {}

    class SpyExecutor:
        def __init__(self, *_args, **_kwargs):
            pass

        def execute(self, hypothesis, plan, *, inputs, prior_result=None, run_id=None):
            observed["category"] = hypothesis.category
            observed["input"] = deepcopy(inputs)
            observed["prior"] = prior_result
            observed["run_id"] = run_id
            return {
                "hypothesis_id": hypothesis.hypothesis_id,
                "category": hypothesis.category,
                "status": "policy_blocked",
                "requests_used": 0,
                "diagnostic": "Authorization: Bearer CCX_SECRET_AUTH_001",
                "private_recovery_state": {"challenge": "CCX_SECRET_RECOVERY_004"},
                "request_budget": {
                    "auth_requests": 0,
                    "discovery_requests": 0,
                    "verification_requests": 0,
                    "total_requests": 0,
                },
            }

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: store)
    monkeypatch.setattr(
        verification_runtime_module,
        "resolve_verification_executor",
        lambda _category: SpyExecutor,
    )

    result = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(policy_path),
            "--context",
            str(context_path),
            "--input",
            str(input_path),
            "--dedicated-lab",
        ]
    )

    assert result["success"] is True
    assert observed["category"] == "recovery_state_enforcement"
    assert observed["prior"] is None
    assert observed["run_id"] == "phase2-cli-recovery"
    assert result["result_id"].startswith("res_")
    assert result["result_hash"].startswith("sha256:")
    assert result["result_schema_version"] == 2
    assert result["executor"]["version"] == "recovery_state_enforcement/v1"
    assert "CCX_SECRET_AUTH_001" not in json.dumps(result)
    assert "CCX_SECRET_RECOVERY_004" not in json.dumps(result)
    assert "private_recovery_state" not in result
    for field in ("code", "temporary_password", "comparison_password"):
        assert observed["input"]["recovery"][field].startswith("[CREDENTIAL_REF:")
        assert observed["input"]["recovery"][field] not in {
            RECOVERY_CODE,
            TEMPORARY_PASSWORD,
            COMPARISON_PASSWORD,
        }


def test_agent_verify_scan_routes_direct_staged_recovery_input(tmp_path, monkeypatch):
    hypothesis, plan = _hypothesis_and_plan()
    policy_path, context_path, input_path = _write_execution_files(tmp_path)
    observed: dict[str, Any] = {}

    class SpyExecutor:
        def __init__(self, *_args, **_kwargs):
            pass

        def execute(self, hypothesis, plan, *, inputs, prior_result=None, run_id=None):
            observed["category"] = hypothesis.category
            observed["input"] = deepcopy(inputs)
            observed["run_id"] = run_id
            return {
                "hypothesis_id": hypothesis.hypothesis_id,
                "category": hypothesis.category,
                "status": "policy_blocked",
                "requests_used": 0,
                "runtime_binding": {"policy_authorized": False},
                "request_budget": {
                    "auth_requests": 0,
                    "discovery_requests": 0,
                    "verification_requests": 0,
                    "total_requests": 0,
                },
            }

    def fake_workflow(_goal, target, _domain, **kwargs):
        context = kwargs["controlled_context"]
        budget = RequestBudget(10)
        policy = kwargs["phase2_policy"]
        runtime = kwargs["phase2_executor"]
        runtime.network_client = ScopedHTTPClient(policy=policy, budget=budget)
        gate = DeterministicPolicyGate(
            policy,
            build_verification_policy_context(context, target_class="local_range"),
            budget,
        )
        output = runtime(hypothesis, plan, gate)
        assert context.accounts[0].controlled is True
        return {"success": True, "target": target, "phase2_output": output}

    monkeypatch.setattr(agent, "enforce_scope", lambda _target: {"allowed": True})
    monkeypatch.setattr(agent, "run_workflow", fake_workflow)
    monkeypatch.setattr(
        verification_runtime_module,
        "resolve_verification_executor",
        lambda _category: SpyExecutor,
    )

    result = agent.run_scan_command(
        " ".join(
            [
                TARGET,
                "--mode verify",
                "--profile authenticated",
                f"--policy {policy_path}",
                f"--context {context_path}",
                f"--verification-input {input_path}",
                "--lab",
            ]
        )
    )

    assert result["success"] is True
    assert observed["category"] == "recovery_state_enforcement"
    for field in ("code", "temporary_password", "comparison_password"):
        assert observed["input"]["recovery"][field].startswith("[CREDENTIAL_REF:")
