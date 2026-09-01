"""Typed contracts for one controlled recovery-state enforcement comparison."""

from __future__ import annotations

import secrets
from typing import Any, Literal
from urllib.parse import urljoin

from pydantic import ConfigDict, Field, StrictBool, field_validator

from agent_core.agent_models import Hypothesis, StrictModel, VerificationPlan
from agent_core.credential_vault import CredentialVault

RecoveryComparisonType = Literal["reused_same_challenge_and_code"]
RecoveryExecutionPhase = Literal[
    "issue_challenge",
    "resume_with_controlled_evidence",
    "confirm_external_cleanup",
]
_CREDENTIAL_MARKER_PREFIX = "[CREDENTIAL_REF:"


class RecoverySurface(StrictModel):
    boundary_type: Literal["recovery_start", "recovery_completion"]
    method: Literal["POST"]
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: Any) -> str:
        return str(value).strip().upper()


class RecoveryWorkflow(StrictModel):
    """The exact start/completion surfaces correlated by semantic discovery."""

    recovery_start: RecoverySurface
    recovery_completion: RecoverySurface
    recovery_identity_field: str = Field(
        default="email",
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )

    @classmethod
    def from_hypothesis(cls, hypothesis: Hypothesis) -> RecoveryWorkflow:
        if hypothesis.category != "recovery_state_enforcement":
            raise ValueError("A recovery-state-enforcement hypothesis is required.")
        related = hypothesis.metadata.get("related_surfaces")
        if not isinstance(related, list) or len(related) != 2:
            raise ValueError(
                "Recovery state enforcement requires exactly two workflow surfaces."
            )
        by_type: dict[str, RecoverySurface] = {}
        recovery_identity_field = "email"
        for raw_surface in related:
            if not isinstance(raw_surface, dict):
                raise ValueError("Recovery workflow metadata is invalid.")
            boundary_type = str(raw_surface.get("boundary_type") or "")
            if boundary_type in by_type:
                raise ValueError("Recovery workflow surfaces are ambiguous.")
            path = raw_surface.get("path")
            method = raw_surface.get("method")
            if not isinstance(path, str) or not path.strip() or not method:
                raise ValueError(
                    "Recovery workflow surfaces require a path and method."
                )
            by_type[boundary_type] = RecoverySurface(
                boundary_type=boundary_type,
                method=method,
                url=urljoin(
                    hypothesis.target.rstrip("/") + "/",
                    path.strip().lstrip("/"),
                ),
            )
            if boundary_type == "recovery_start":
                declared_field = raw_surface.get("identity_field")
                declared_fields = raw_surface.get("identity_fields")
                if declared_field is None and isinstance(declared_fields, list):
                    normalized_fields = [
                        str(item).strip()
                        for item in declared_fields
                        if isinstance(item, str) and item.strip()
                    ]
                    if len(normalized_fields) > 1:
                        raise ValueError(
                            "Recovery start declares an ambiguous identity request field."
                        )
                    declared_field = normalized_fields[0] if normalized_fields else None
                if declared_field is not None:
                    recovery_identity_field = str(declared_field).strip()
        if set(by_type) != {"recovery_start", "recovery_completion"}:
            raise ValueError("Recovery workflow metadata is incomplete or ambiguous.")
        return cls(
            recovery_start=by_type["recovery_start"],
            recovery_completion=by_type["recovery_completion"],
            recovery_identity_field=recovery_identity_field,
        )

    def validate_plan(
        self, hypothesis: Hypothesis, plan: VerificationPlan
    ) -> tuple[list[dict[str, Any]] | None, list[str]]:
        """Require one start, one valid completion, and one reuse comparison."""
        actions = [
            request
            for step in plan.steps
            for request in (step.metadata.get("requests") or [])
            if isinstance(request, dict)
        ]
        expected = [
            (self.recovery_start, "controlled_recovery_start"),
            (self.recovery_completion, "valid_controlled_recovery_completion"),
            (self.recovery_completion, "reused_same_challenge_and_code"),
        ]
        if len(actions) != 3 or plan.hypothesis_id != hypothesis.hypothesis_id:
            return None, [
                "Recovery verification requires three target actions and one independently counted authentication confirmation."
            ]
        for action, (surface, mutation_type) in zip(actions, expected, strict=True):
            if (
                action.get("category") != "recovery_state_enforcement"
                or action.get("purpose") != "state_mutation"
                or str(action.get("url") or "") != surface.url
                or str(action.get("method") or "").upper() != surface.method
                or action.get("mutation_type") != mutation_type
                or bool(action.get("replay"))
            ):
                return None, [
                    "The planned request sequence does not exactly match the typed recovery workflow."
                ]
        return actions, []


class RecoveryVerificationInput(StrictModel):
    """Process-local references created while raw controlled secrets are ingested."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    account_id: str = Field(min_length=1, max_length=100)
    comparison_type: RecoveryComparisonType
    phase: RecoveryExecutionPhase = "issue_challenge"
    cleanup_required: StrictBool
    code_reference: str | None = None
    temporary_password_reference: str | None = None
    comparison_password_reference: str | None = None

    @field_validator("cleanup_required")
    @classmethod
    def require_cleanup(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("cleanup_required must be true")
        return value

    @property
    def secret_references(self) -> tuple[str, ...]:
        return tuple(
            reference
            for reference in (
                self.code_reference,
                self.temporary_password_reference,
                self.comparison_password_reference,
            )
            if reference is not None
        )


class PreservedRecoveryChallenge(StrictModel):
    """Secret-free runtime challenge state persisted only for bounded resume."""

    version: Literal[1] = 1
    issued_by: Literal["RecoveryStateEnforcementExecutor"]
    issuance_action: Literal["controlled_recovery_start"]
    challenge_id: int = Field(strict=True, ge=0)
    challenge_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}:[0-9a-f]{64}$")
    hypothesis_binding: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    account_binding: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    workflow_binding: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    run_binding: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    consumed: bool = Field(strict=True)


def ingest_recovery_verification_input(
    payload: dict[str, Any], vault: CredentialVault
) -> tuple[RecoveryVerificationInput | None, list[str]]:
    """Move supplied recovery secrets into the vault and validate an exact schema.

    Recognized secret fields are removed from the caller's nested input object even
    when another field makes the envelope invalid. Validation errors never include
    the supplied values.
    """

    reasons: list[str] = []
    if not isinstance(payload, dict):
        return None, ["Recovery verification input must be an object."]
    outer_keys = set(payload)
    if outer_keys != {"recovery", "cleanup_required"}:
        reasons.append(
            "Recovery verification input permits only recovery and cleanup_required."
        )
    if payload.get("cleanup_required") is not True:
        reasons.append("Recovery verification requires cleanup_required=true.")
    recovery = payload.get("recovery")
    if not isinstance(recovery, dict):
        return None, list(
            dict.fromkeys(
                [*reasons, "Recovery verification requires a recovery object."]
            )
        )

    phase = recovery.get("phase", "issue_challenge")
    if phase not in {
        "issue_challenge",
        "resume_with_controlled_evidence",
        "confirm_external_cleanup",
    }:
        reasons.append("The requested recovery execution phase is unsupported.")
    comparison_type = recovery.get("comparison_type")
    if comparison_type != "reused_same_challenge_and_code":
        reasons.append(
            "Only reused_same_challenge_and_code is supported as the approved comparison type."
        )
    account_id = recovery.get("account_id")
    if not isinstance(account_id, str) or not account_id.strip():
        reasons.append("A controlled recovery account_id is required.")

    references: dict[str, str] = {}
    secret_fields = ("code", "temporary_password", "comparison_password")
    for field in secret_fields:
        value = recovery.pop(field, None)
        if value is None:
            continue
        if not isinstance(value, str) or not value or len(value) > 4096:
            reasons.append(f"Recovery {field} must be a non-empty bounded string.")
            continue
        staged_reference = _staged_reference(value, vault)
        references[field] = staged_reference or vault.put(
            value, label=f"recovery:{field}"
        )

    expected_keys = {"account_id", "comparison_type"}
    if "phase" in recovery:
        expected_keys.add("phase")
    if set(recovery) != expected_keys:
        reasons.append("Recovery verification input contains unsupported fields.")

    if phase == "issue_challenge":
        if references:
            reasons.append(
                "Recovery challenge issuance does not accept recovery codes or replacement passwords."
            )
    elif phase == "resume_with_controlled_evidence":
        for field in secret_fields:
            if field not in references:
                reasons.append(f"Recovery resume requires an explicit {field}.")
        if all(field in references for field in secret_fields):
            temporary = vault.get(references["temporary_password"])
            comparison = vault.get(references["comparison_password"])
            if secrets.compare_digest(temporary, comparison):
                reasons.append(
                    "Temporary and comparison passwords must be separately approved distinct values."
                )
    elif phase == "confirm_external_cleanup" and references:
        reasons.append(
            "External cleanup confirmation does not accept recovery codes or replacement passwords."
        )

    if reasons:
        for reference in references.values():
            vault.discard(reference)
        return None, list(dict.fromkeys(reasons))

    return (
        RecoveryVerificationInput(
            account_id=str(account_id).strip(),
            comparison_type="reused_same_challenge_and_code",
            phase=phase,
            cleanup_required=True,
            code_reference=references.get("code"),
            temporary_password_reference=references.get("temporary_password"),
            comparison_password_reference=references.get("comparison_password"),
        ),
        [],
    )


def is_external_cleanup_confirmation(payload: Any) -> bool:
    return bool(
        isinstance(payload, dict)
        and isinstance(payload.get("recovery"), dict)
        and payload["recovery"].get("phase") == "confirm_external_cleanup"
    )


def is_recovery_resume(payload: Any) -> bool:
    return bool(
        isinstance(payload, dict)
        and isinstance(payload.get("recovery"), dict)
        and payload["recovery"].get("phase") == "resume_with_controlled_evidence"
    )


def stage_recovery_input_secrets(value: Any, vault: CredentialVault) -> None:
    """Replace raw recovery secrets with process-local vault markers in place."""
    if isinstance(value, dict):
        recovery = value.get("recovery")
        if isinstance(recovery, dict):
            for field in ("code", "temporary_password", "comparison_password"):
                secret = recovery.get(field)
                if (
                    isinstance(secret, str)
                    and secret
                    and not _staged_reference(secret, vault)
                ):
                    reference = vault.put(secret, label=f"recovery:{field}")
                    recovery[field] = f"{_CREDENTIAL_MARKER_PREFIX}{reference}]"
        for item in value.values():
            stage_recovery_input_secrets(item, vault)
    elif isinstance(value, list):
        for item in value:
            stage_recovery_input_secrets(item, vault)


def _staged_reference(value: str, vault: CredentialVault) -> str | None:
    if not value.startswith(_CREDENTIAL_MARKER_PREFIX) or not value.endswith("]"):
        return None
    reference = value[len(_CREDENTIAL_MARKER_PREFIX) : -1]
    try:
        vault.get(reference)
    except (KeyError, RuntimeError):
        return None
    return reference


def pending_recovery_result(run: Any, *, hypothesis_id: str) -> dict[str, Any] | None:
    """Return the latest stored state for one recovery workflow.

    Selection is deliberately not filtered to an earlier pending state.  Passing the
    latest state lets the executor reject a duplicate resume or cleanup instead of
    accidentally reviving an older unconsumed-looking record.
    """
    if not isinstance(run, dict):
        return None
    matches = [
        item
        for item in run.get("verification_results", [])
        if isinstance(item, dict)
        and item.get("hypothesis_id") == hypothesis_id
        and item.get("category") == "recovery_state_enforcement"
    ]
    return matches[-1] if matches else None
