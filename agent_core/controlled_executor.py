"""Policy-gated bounded verifier using only injected, auditable HTTP transport."""

from __future__ import annotations

import json
import math
import re
import secrets
import threading
from hashlib import sha256
from typing import Any, Callable, Literal
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.agent_models import (
    Hypothesis,
    ParameterLocation,
    StrictModel,
    VerificationPlan,
)
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquirer,
    OwnedObjectAcquisition,
    OwnedObjectAcquisitionError,
    SessionAcquirer,
    SessionAcquisition,
    SessionAcquisitionTransportPolicyError,
    SessionAuthenticationRejectedError,
    SessionAcquisitionPolicyError,
    SessionTokenFieldAbsentError,
    resolve_controlled_login_identity,
    role_privilege_rank,
)
from agent_core.credential_vault import CredentialVault
from agent_core.differential_analyzer import (
    analyze_authentication_enforcement,
    analyze_cross_account_access,
    analyze_role_authorization,
    analyze_session_invalidation,
    normalize_protected_field_path,
    response_summary,
)
from agent_core.evidence_correlator import correlate_evidence
from agent_core.phase2_policy import (
    DeterministicPolicyGate,
    RateLimitVerificationAction,
    RecoveryStateAction,
    SessionTerminationAction,
    VerificationAction,
)
from agent_core.rate_limit_enforcement import (
    AuthenticationLoginRateLimitWorkflow,
    classify_rate_limit_sequence,
    ingest_rate_limit_verification_input,
    safe_rate_limit_response_summary,
)
from agent_core.result_normalizer import public_result
from agent_core.result_provenance import (
    RESULT_SCHEMA_VERSION,
)
from agent_core.recovery_state_enforcement import (
    PreservedRecoveryChallenge,
    RecoveryVerificationInput,
    RecoveryWorkflow,
    ingest_recovery_verification_input,
)
from agent_core.request_budget import RequestBudgetExceeded, RequestDelta
from agent_core.phase2_result_status import (
    CLEANUP_UNVERIFIED_REASON,
    EXECUTION_FAILURE_REASON,
    INVALID_INPUT_REASON,
    SERVICE_UNSTABLE_REASON,
    TRANSPORT_POLICY_BLOCKED_REASON,
    assess_response_instability,
    normalize_typed_result,
    transport_failure_reason,
)
from agent_core.runtime_binding import (
    bind_runtime_accounts,
    empty_runtime_binding,
    own_resource_url_matches,
    tenant_object_binding_reasons,
)
from agent_core.session_invalidation import SessionInvalidationWorkflow
from agent_core.verification_capabilities import (
    CapabilityState,
    TYPED_VERIFICATION_CATEGORIES,
    capability_support_reasons,
    get_verification_capability,
    resolve_verification_input_schema,
    typed_producer_provenance,
)
from tools.safe_http import PolicyViolationError

EXECUTABLE_CATEGORIES = set(TYPED_VERIFICATION_CATEGORIES)

JsonScalar = StrictStr | StrictInt | StrictFloat | StrictBool | None

SQL_CONTROL_VALUE = "ccx-control"
SQL_PROBE_VALUE = "' AND '1'='1"
COMMAND_CONTROL_VALUE = "ccx-control"
COMMAND_PROBE_VALUE = ";printf CCX_%s EXECUTION"
COMMAND_EXECUTION_MARKER = "CCX_EXECUTION"
TRAVERSAL_CONTROL_VALUE = "fixtures/ccx-control.txt"
TRAVERSAL_PROBE_VALUE = "../fixtures/ccx-synthetic.txt"
TRAVERSAL_FIXTURE_MARKER = "CCX_SYNTHETIC_FIXTURE"

_PROBE_VALUES = {
    "sql_injection": (SQL_CONTROL_VALUE, SQL_PROBE_VALUE),
    "command_injection": (COMMAND_CONTROL_VALUE, COMMAND_PROBE_VALUE),
    "path_traversal": (TRAVERSAL_CONTROL_VALUE, TRAVERSAL_PROBE_VALUE),
}


def _safe_transport_failure_reason(exc: Exception) -> str:
    return transport_failure_reason(exc)


def _transport_exception_decision(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, PolicyViolationError):
        if "budget" in str(exc).casefold():
            return "budget_exhausted", str(exc)
        return "policy_blocked", TRANSPORT_POLICY_BLOCKED_REASON
    return "inconclusive", transport_failure_reason(exc)


def _is_credential_header(name: Any) -> bool:
    normalized = str(name).strip().lower().replace("_", "-")
    return bool(
        normalized in {"authorization", "proxy-authorization", "cookie", "cookie2"}
        or "authorization" in normalized
        or "credential" in normalized
        or "session" in normalized
        or "token" in normalized
        or "api-key" in normalized
        or "apikey" in normalized
        or normalized.startswith("x-auth")
    )


def _without_credential_headers(headers: Any) -> dict[str, Any]:
    if not isinstance(headers, dict):
        return {}
    return {
        str(name): value
        for name, value in headers.items()
        if not _is_credential_header(name)
    }


class ApprovedMutation(StrictModel):
    """One researcher-approved, JSON-scalar mutation and no other fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    field: str = Field(min_length=1, max_length=200)
    test_value: JsonScalar

    @model_validator(mode="after")
    def validate_scalar(self) -> ApprovedMutation:
        if isinstance(self.test_value, str) and len(self.test_value) > 500:
            raise ValueError("test_value exceeds the bounded scalar length")
        if isinstance(self.test_value, float) and not math.isfinite(self.test_value):
            raise ValueError("test_value must be a finite JSON number")
        return self


class MassAssignmentVerificationInput(StrictModel):
    """Secret-free runtime approval for one reversible mass-assignment probe."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    mutation: ApprovedMutation
    expected_before: dict[str, JsonScalar] | None = None
    cleanup_required: StrictBool

    @model_validator(mode="after")
    def bind_expected_before(self) -> MassAssignmentVerificationInput:
        if self.cleanup_required is not True:
            raise ValueError("cleanup_required must be true")
        if self.expected_before is None:
            return self
        if list(self.expected_before) != [self.mutation.field]:
            raise ValueError(
                "expected_before must contain only the approved mutation field"
            )
        value = self.expected_before[self.mutation.field]
        if isinstance(value, str) and len(value) > 500:
            raise ValueError("expected_before exceeds the bounded scalar length")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("expected_before must be a finite JSON number")
        return self


class SessionInvalidationVerificationInput(StrictModel):
    """Secret-free protected-evidence approval for one session lifecycle."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    protected_fields: list[StrictStr] = Field(min_length=1, max_length=50)
    protected_data_confirmed: StrictBool

    @model_validator(mode="after")
    def require_protected_data_approval(self) -> SessionInvalidationVerificationInput:
        if self.protected_data_confirmed is not True:
            raise ValueError("protected_data_confirmed must be true")
        return self

    @field_validator("protected_fields", mode="before")
    @classmethod
    def validate_protected_fields_container(cls, value: Any) -> list[str]:
        if type(value) is not list:
            raise ValueError("protected_fields must be a strict list")
        normalized: list[str] = []
        for item in value:
            if type(item) is not str:
                raise ValueError("protected field paths must be strings")
            normalized.append(normalize_protected_field_path(item))
        if len(set(normalized)) != len(normalized):
            raise ValueError("protected field paths must be unique")
        return normalized


class StrictProofInput(StrictModel):
    """Strict, extra-forbidden base for proof-controlling runtime input."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
        strict=True,
    )


class ProtectedEvidenceInput(StrictProofInput):
    """Configuration selects evidence paths; caller assertions are never proof."""

    protected_fields: list[StrictStr] = Field(min_length=1, max_length=50)
    protected_data_confirmed: StrictBool | None = None

    @field_validator("protected_fields", mode="before")
    @classmethod
    def validate_protected_fields_container(cls, value: Any) -> list[str]:
        if type(value) is not list:
            raise ValueError("protected_fields must be a strict list")
        normalized: list[str] = []
        for item in value:
            if type(item) is not str:
                raise ValueError("protected field paths must be strings")
            normalized.append(normalize_protected_field_path(item))
        if len(set(normalized)) != len(normalized):
            raise ValueError("protected field paths must be unique")
        return normalized


class RequestURLOverride(StrictProofInput):
    """Compatibility override limited to one concrete scoped URL."""

    url: StrictStr = Field(min_length=1, max_length=2048)


class BOLAVerificationInput(ProtectedEvidenceInput):
    request_overrides: list[RequestURLOverride] = Field(
        default_factory=list, max_length=2
    )
    object_identifier: StrictStr | None = Field(default=None, min_length=1)
    ownership_confirmed: StrictBool | None = None
    separate_accounts_confirmed: StrictBool | None = None


class TenantIsolationVerificationInput(BOLAVerificationInput):
    distinct_tenants_confirmed: StrictBool | None = None


class VerticalAuthorizationVerificationInput(ProtectedEvidenceInput):
    protected_functionality_confirmed: StrictBool | None = None


class AuthenticationEnforcementVerificationInput(ProtectedEvidenceInput):
    protected_functionality_confirmed: StrictBool | None = None


class ProbeParameterBinding(StrictProofInput):
    parameter: StrictStr = Field(min_length=1, max_length=200)
    parameter_location: ParameterLocation

    @field_validator("parameter")
    @classmethod
    def normalize_parameter(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or not re.fullmatch(r"[A-Za-z0-9_.\[\]-]+", normalized):
            raise ValueError("parameter has invalid syntax")
        return normalized


class ReadOnlyProbeVerificationInput(StrictProofInput):
    parameter_binding: ProbeParameterBinding | None = None
    parameter: StrictStr | None = Field(default=None, min_length=1, max_length=200)
    parameter_location: ParameterLocation | None = None

    @field_validator("parameter")
    @classmethod
    def normalize_direct_parameter(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return ProbeParameterBinding.normalize_parameter(value)

    @model_validator(mode="after")
    def validate_binding_shape(self) -> ReadOnlyProbeVerificationInput:
        direct_present = (
            self.parameter is not None or self.parameter_location is not None
        )
        if direct_present and (
            self.parameter is None or self.parameter_location is None
        ):
            raise ValueError(
                "parameter and parameter_location must be supplied together"
            )
        if direct_present and self.parameter_binding is not None:
            raise ValueError("only one parameter binding representation is permitted")
        return self


class SQLInjectionVerificationInput(ReadOnlyProbeVerificationInput):
    # Compatibility only. This assertion is recorded nowhere and is never proof.
    safe_probe_semantics_confirmed: StrictBool | None = None


class CommandInjectionVerificationInput(ReadOnlyProbeVerificationInput):
    pass


class PathTraversalVerificationInput(ReadOnlyProbeVerificationInput):
    pass


class _ProcessPrivateRecoveryStore:
    """Private fallback for non-persisted library use; never enters public output."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: dict[tuple[str, str], dict[str, Any]] = {}

    def save_for_executor(
        self,
        *,
        run_reference: str,
        hypothesis_id: str,
        challenge: dict[str, Any],
    ) -> None:
        validated = PreservedRecoveryChallenge.model_validate(challenge)
        key = (str(run_reference), str(hypothesis_id))
        with self._lock:
            self._states[key] = validated.model_dump(mode="json")

    def load_for_executor(
        self, *, run_reference: str, hypothesis_id: str
    ) -> dict[str, Any] | None:
        key = (str(run_reference), str(hypothesis_id))
        with self._lock:
            value = self._states.get(key)
            return dict(value) if value is not None else None


_PROCESS_PRIVATE_RECOVERY_STORE = _ProcessPrivateRecoveryStore()


class _ExecutionHalt(RuntimeError):
    """Process-local control flow carrying only safe failure metadata."""

    def __init__(self, status: str, reasons: list[str]) -> None:
        super().__init__(status)
        self.status = status
        self.reasons = reasons


class ControlledVerificationExecutor:
    """Execute exact planned requests; it has no arbitrary URL/payload generator."""

    def __init__(
        self,
        gate: DeterministicPolicyGate,
        vault: CredentialVault,
        context: ControlledContext,
        transport: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        private_recovery_store: Any | None = None,
    ) -> None:
        self.gate = gate
        self.vault = vault
        self.context = context
        self.transport = transport
        self.private_recovery_store = (
            private_recovery_store or _PROCESS_PRIVATE_RECOVERY_STORE
        )

    def _consume_legacy_transport_budget(self, kind: str) -> None:
        """Keep injected unit-test transports compatible without double counting.

        Production HTTP transport owns authorization and ledger consumption at
        the final pre-transport boundary. Legacy/local injected transports do
        not, so the executor retains the old accounting behavior for them.
        """
        if not getattr(self.transport, "manages_request_budget", False):
            self.gate.budget.consume(kind)

    def execute(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        *,
        inputs: dict[str, Any] | None = None,
        prior_result: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute one result and derive its exact authoritative ledger delta."""

        before = self.gate.budget.snapshot()
        try:
            result = self._execute_once(
                hypothesis,
                plan,
                inputs=inputs,
                prior_result=prior_result,
                run_id=run_id,
            )
        except RequestBudgetExceeded as exc:
            result = self._stopped("budget_exhausted", 0, [str(exc)])
        except (TypeError, ValueError):
            result = self._stopped(
                "invalid_verification_input", 0, [INVALID_INPUT_REASON]
            )
        except Exception:
            result = self._stopped("inconclusive", 0, [EXECUTION_FAILURE_REASON])
        after = self.gate.budget.snapshot()
        delta = RequestDelta.from_snapshots(before, after)
        try:
            declared_capability = get_verification_capability(hypothesis.category)
        except ValueError:
            declared_capability = None
        if (
            declared_capability is not None
            and delta.total > declared_capability.worst_case_requests
        ):
            raise RuntimeError(
                "Observed request usage exceeded the authoritative capability bound."
            )
        attributed = normalize_typed_result(result, delta)
        attributed["request_delta"] = delta.model_dump(mode="json")
        attributed["requests_used"] = delta.total
        attributed["request_budget"] = after
        attributed["result_schema_version"] = RESULT_SCHEMA_VERSION
        attributed["executor"] = typed_producer_provenance(hypothesis.category)
        if hypothesis.category == "rate_limit_enforcement":
            requested = attributed.get("attempts_requested", 0)
            requested = (
                requested
                if isinstance(requested, int)
                and not isinstance(requested, bool)
                and requested >= 0
                else 0
            )
            baseline_requests = int(delta.auth >= 1)
            final_requests = int(delta.auth == requested + 2)
            invalid_requests = max(0, delta.auth - baseline_requests - final_requests)
            attributed["attempts_sent"] = invalid_requests
            attributed["request_counts"] = {
                "valid_baseline_auth_requests": baseline_requests,
                "invalid_password_auth_requests": invalid_requests,
                "final_valid_auth_requests": final_requests,
                "auth_requests": delta.auth,
                "total_network_requests": delta.total,
            }
        return attributed

    def _execute_once(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        *,
        inputs: dict[str, Any] | None = None,
        prior_result: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        self._active_category = hypothesis.category
        self._acquisition_summary = self._empty_acquisition_summary()
        self._runtime_binding = empty_runtime_binding(hypothesis)
        if inputs is not None and type(inputs) is not dict:
            return self._stopped(
                "policy_blocked",
                0,
                ["Verification input must be a strict category input object."],
            )
        raw_inputs = {} if inputs is None else inputs
        inputs = dict(raw_inputs)
        try:
            capability = get_verification_capability(hypothesis.category)
        except ValueError:
            return {
                "status": "inconclusive",
                "requests_used": 0,
                "reasons": ["No declared Phase 2 capability exists for this category."],
                "runtime_binding": dict(self._runtime_binding),
            }
        if capability.capability_state is not CapabilityState.typed_verification:
            return {
                "status": "inconclusive",
                "requests_used": 0,
                "reasons": [
                    "This category is plan-only and has no active typed Phase 2 execution route."
                ],
                "runtime_binding": dict(self._runtime_binding),
            }
        support_reasons = capability_support_reasons(
            hypothesis.category,
            method=hypothesis.method,
            parameter=hypothesis.parameter,
            parameter_location=hypothesis.parameter_location,
            request_body_field=bool(hypothesis.metadata.get("request_body_field")),
            target_class=self.gate.context.target_class,
        )
        if support_reasons:
            return self._stopped("policy_blocked", 0, support_reasons)
        if hypothesis.category == "rate_limit_enforcement":
            return self._execute_rate_limit_enforcement(
                hypothesis,
                plan,
                inputs,
            )
        if hypothesis.category == "recovery_state_enforcement":
            self._recovery_run_reference = run_id or plan.plan_id
            internal_prior = self._private_recovery_prior(
                hypothesis,
                prior_result,
            )
            result = self._execute_recovery_state_enforcement(
                hypothesis,
                plan,
                inputs,
                prior_result=internal_prior,
            )
            challenge = result.get("preserved_challenge")
            if isinstance(challenge, dict):
                try:
                    self.private_recovery_store.save_for_executor(
                        run_reference=self._recovery_run_reference,
                        hypothesis_id=hypothesis.hypothesis_id,
                        challenge=challenge,
                    )
                except (OSError, TypeError, ValueError):
                    result["status"] = "inconclusive"
                    result["confidence"] = "low"
                    result.setdefault("evidence_summary", []).append(
                        "Private recovery resume state could not be persisted safely."
                    )
            return public_result(result)
        binding = bind_runtime_accounts(
            hypothesis, plan, self.context, self.gate.policy, self.vault
        )
        self._runtime_binding = dict(binding.diagnostics)
        if not binding.succeeded or binding.plan is None:
            return self._stopped("policy_blocked", 0, binding.reasons)
        runtime_plan = binding.plan
        planned = [
            item
            for step in runtime_plan.steps
            for item in (step.metadata.get("requests") or [])
        ]
        input_model = (
            None
            if hypothesis.category in {"mass_assignment", "session_invalidation"}
            else resolve_verification_input_schema(hypothesis.category)
        )
        if input_model is not None:
            try:
                approved_inputs = input_model.model_validate(inputs)
            except ValueError:
                return self._stopped(
                    "policy_blocked",
                    0,
                    [
                        f"Malformed {hypothesis.category} verification input was rejected before traffic."
                    ],
                )
            inputs = approved_inputs.model_dump(mode="python", exclude_none=True)
            if hypothesis.category in {"bola", "tenant_isolation"}:
                # Compatibility fields are accepted only to reject malformed
                # legacy input deterministically. Runtime-controlled facts
                # always replace them and caller assertions are never proof.
                for field in (
                    "object_identifier",
                    "ownership_confirmed",
                    "separate_accounts_confirmed",
                    "distinct_tenants_confirmed",
                ):
                    inputs.pop(field, None)
                override_reasons: list[str] = []
                for override in inputs.get("request_overrides", []):
                    decision = self.gate.policy.authorize_url(
                        override["url"], method="GET"
                    )
                    override_reasons.extend(decision.reasons)
                if override_reasons:
                    return self._stopped(
                        "policy_blocked",
                        0,
                        list(dict.fromkeys(override_reasons)),
                    )
        probe_urls: list[str] | None = None
        if hypothesis.category in _PROBE_VALUES:
            probe_urls, probe_binding_reasons = self._prepare_probe_urls(
                hypothesis, planned, inputs
            )
            if probe_urls is None:
                return self._stopped(
                    "policy_blocked",
                    0,
                    probe_binding_reasons,
                )
        if hypothesis.category == "session_invalidation":
            return self._execute_session_invalidation(
                hypothesis, runtime_plan, planned, inputs
            )
        mutation_input: MassAssignmentVerificationInput | None = None
        if hypothesis.category == "mass_assignment":
            mutation_input, input_reasons = self._mass_assignment_input(
                hypothesis, runtime_plan, planned, inputs
            )
            if mutation_input is None:
                return self._stopped("policy_blocked", 0, input_reasons)
        controlled_object: ControlledObject | None = None
        acquisition_rule: OwnedObjectAcquisition | None = None
        acquisition_required = self._requires_owned_object(hypothesis, runtime_plan)
        owner_account_id = self._planned_owner_account_id(planned)
        if acquisition_required:
            controlled_object = self._existing_controlled_object(
                owner_account_id,
                set(runtime_plan.test_owned_resources),
            )
            if controlled_object is None:
                acquisition_rule = self._acquisition_rule(owner_account_id)
                if acquisition_rule is None:
                    return self._stopped(
                        "inconclusive",
                        0,
                        [
                            "No explicit owned-object acquisition rule matched the planned controlled owner."
                        ],
                    )
                self._acquisition_summary.update(
                    {
                        "owner": acquisition_rule.owner_account_id,
                        "object_type": acquisition_rule.object_type,
                    }
                )
                policy_reasons = self._object_acquisition_policy_reasons(
                    acquisition_rule
                )
                if policy_reasons:
                    return self._stopped("policy_blocked", 0, policy_reasons)

        session_failure = self._prepare_required_sessions(
            runtime_plan,
            planned,
            additional_requests=int(acquisition_rule is not None),
        )
        if session_failure is not None:
            return session_failure
        if acquisition_rule is not None:
            self._acquisition_summary["attempted"] = True
            try:
                owner = self.context.account(acquisition_rule.owner_account_id)
                controlled_object = OwnedObjectAcquirer(
                    self.vault, self.gate.budget
                ).acquire(owner, acquisition_rule, self.transport)
            except RequestBudgetExceeded as exc:
                return self._stopped("budget_exhausted", 0, [str(exc)])
            except OwnedObjectAcquisitionError as exc:
                return self._stopped("inconclusive", 0, [str(exc)])
            except Exception as exc:
                return self._stopped(
                    "inconclusive",
                    0,
                    [_safe_transport_failure_reason(exc)],
                )
            if controlled_object.tenant_id is None and owner.tenant_id is not None:
                controlled_object.tenant_id = owner.tenant_id
            self._acquisition_summary.update(
                {
                    "succeeded": True,
                    "identifier_present": True,
                    "controlled_test_owned_evidence": True,
                }
            )
        if hypothesis.category == "tenant_isolation" and controlled_object is not None:
            try:
                object_owner = self.context.account(controlled_object.owner_account_id)
            except KeyError:
                return self._stopped(
                    "policy_blocked",
                    0,
                    ["The tenant object's owner is not a controlled account."],
                )
            tenant_reasons = tenant_object_binding_reasons(
                controlled_object, object_owner
            )
            if tenant_reasons:
                return self._stopped("policy_blocked", 0, tenant_reasons)

        if controlled_object is not None:
            inputs["object_identifier"] = controlled_object.object_id
            inputs["ownership_confirmed"] = True
            inputs["separate_accounts_confirmed"] = self._separate_accounts(planned)
            if hypothesis.category == "tenant_isolation":
                inputs["distinct_tenants_confirmed"] = self._distinct_tenants(planned)
                inputs["tenant_identifier"] = controlled_object.tenant_id
            if (
                controlled_object.object_id
                not in self.gate.context.controlled_object_ids
            ):
                self.gate.context.controlled_object_ids.append(
                    controlled_object.object_id
                )
            object_binding_failure = self._bind_controlled_object(
                runtime_plan,
                planned,
                controlled_object,
                acquisition_rule,
                acquisition_required=acquisition_required,
            )
            if object_binding_failure is not None:
                return object_binding_failure
        overrides = inputs.get("request_overrides") or []
        if controlled_object is None or not acquisition_required:
            for index, item in enumerate(planned):
                override = overrides[index] if index < len(overrides) else {}
                if isinstance(override, dict) and "url" in override:
                    # Only the concrete URL may be supplied at runtime. Method,
                    # identity, ownership, and policy metadata stay plan-owned.
                    item["url"] = override["url"]
        self._bind_session_references(runtime_plan, planned)
        # Authentication and object acquisition have already consumed their
        # registry-declared optional components.  This late action gate checks
        # only the still-pending typed request sequence without rewriting the
        # public plan's full-workflow worst-case cost.
        action_plan = runtime_plan.model_copy(deep=True)
        action_plan.worst_case_requests = len(planned)
        plan_decision = self.gate.authorize_plan(action_plan)
        if not plan_decision.allowed:
            return self._stopped("policy_blocked", 0, plan_decision.reasons)
        self._runtime_binding["policy_authorized"] = True
        if mutation_input is not None:
            return self._execute_mass_assignment(hypothesis, planned, mutation_input)
        responses: list[dict[str, Any]] = []
        requests_used = 0
        for index, item in enumerate(planned):
            effective = dict(item)
            account_id = effective.get("account_id")
            headers = dict(effective.get("headers") or {})
            request_role = effective.get("request_role")
            if hypothesis.category == "authentication_enforcement":
                expected_role = (
                    "authenticated_baseline"
                    if index == 0
                    else "unauthenticated_comparison"
                )
                if request_role != expected_role:
                    return self._stopped(
                        "policy_blocked",
                        requests_used,
                        [
                            "Authentication-enforcement request roles were not bound safely."
                        ],
                    )
                headers = _without_credential_headers(headers)
                if request_role == "unauthenticated_comparison":
                    account_id = None
                    effective["account_id"] = None
                    effective["credential_reference_present"] = False
            if account_id:
                try:
                    account = self.context.account(str(account_id))
                except KeyError:
                    return self._stopped(
                        "policy_blocked",
                        requests_used,
                        ["Unknown controlled account reference."],
                    )
                credential_ref = (
                    account.session_reference
                    or account.credential_references.get("token")
                )
                effective["credential_reference_present"] = bool(credential_ref)
                if credential_ref:
                    headers["Authorization"] = (
                        f"Bearer {self.vault.get(credential_ref)}"
                    )
            action = VerificationAction.model_validate(
                {
                    key: value
                    for key, value in effective.items()
                    if key in VerificationAction.model_fields
                }
            )
            action_decision = self.gate.authorize_action(action)
            if not action_decision.allowed:
                return self._stopped(
                    "policy_blocked", requests_used, action_decision.reasons
                )
            try:
                self._consume_legacy_transport_budget("verification")
            except RequestBudgetExceeded as exc:
                return self._stopped("budget_exhausted", requests_used, [str(exc)])
            request = {
                "url": effective["url"],
                "method": effective["method"],
                "headers": headers,
                "purpose": (
                    "state_mutation"
                    if action.purpose == "state_mutation"
                    else "verification"
                ),
            }
            if request_role == "unauthenticated_comparison":
                request["credential_mode"] = "anonymous"
            if probe_urls is not None:
                request["url"] = probe_urls[index]
            try:
                response = self.transport(request)
            except Exception as exc:
                status, reason = _transport_exception_decision(exc)
                if status != "inconclusive":
                    return self._stopped(status, requests_used, [reason])
                return self._stopped(
                    "inconclusive",
                    requests_used + 1,
                    [reason],
                )
            requests_used += 1
            responses.append(response)
            if response.get("service_unstable") or response.get(
                "unexpected_state_change"
            ):
                return self._stopped(
                    "inconclusive",
                    requests_used,
                    ["A configured stop condition was reached."],
                )

        if hypothesis.category in {
            "vertical_authorization",
            "graphql_field_authorization",
        }:
            inputs["separate_accounts_confirmed"] = self._separate_accounts(planned)
            inputs["distinct_roles_confirmed"] = self._distinct_privilege_levels(
                planned
            )
        analysis = self._analyze(hypothesis, responses, inputs)
        correlated = correlate_evidence(
            hypothesis,
            analysis,
            requests_used=requests_used,
            policy_approved=True,
        )
        return {
            **correlated,
            "analysis": analysis,
            "response_summaries": [response_summary(item) for item in responses],
            "owned_object_acquisition": dict(self._acquisition_summary),
            "runtime_binding": dict(self._runtime_binding),
            "request_budget": self.gate.budget.snapshot(),
        }

    def _execute_rate_limit_enforcement(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        raw_inputs: dict[str, Any],
    ) -> dict[str, Any]:
        """Run one exact valid → N invalid → valid login sequence."""
        raw_rate_limit = raw_inputs.get("rate_limit")
        requested = (
            raw_rate_limit.get("attempts")
            if isinstance(raw_rate_limit, dict)
            and isinstance(raw_rate_limit.get("attempts"), int)
            and not isinstance(raw_rate_limit.get("attempts"), bool)
            else 0
        )
        approved, input_reasons = ingest_rate_limit_verification_input(
            raw_inputs, self.vault
        )
        if approved is None:
            return self._rate_limit_result(
                status="policy_blocked",
                attempts_requested=requested,
                reasons=input_reasons,
            )
        try:
            binding = bind_runtime_accounts(
                hypothesis, plan, self.context, self.gate.policy, self.vault
            )
            self._runtime_binding = dict(binding.diagnostics)
            if not binding.succeeded or binding.plan is None:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=binding.reasons,
                )
            try:
                workflow = AuthenticationLoginRateLimitWorkflow.from_hypothesis(
                    hypothesis
                )
            except ValueError:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=[
                        "The rate-limit hypothesis is not a supported classified login surface."
                    ],
                )
            plan_reasons = workflow.validate_plan(hypothesis, binding.plan)
            if plan_reasons:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=plan_reasons,
                )
            if binding.plan.controlled_accounts != [approved.account_id]:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=[
                        "The approved rate-limit account does not match the bound controlled account."
                    ],
                )
            try:
                account = self.context.account(approved.account_id)
            except KeyError:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=[
                        "The approved controlled account is unavailable at execution time."
                    ],
                )
            config = self.context.session_acquisition
            if config is None:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=[
                        "Configured session acquisition is required for login rate-limit verification."
                    ],
                )
            identity_resolution = resolve_controlled_login_identity(
                account, config, self.vault
            )
            original_password_reference = account.credential_references.get("password")
            credential_reasons: list[str] = []
            if identity_resolution.reason:
                credential_reasons.append(identity_resolution.reason)
            if not original_password_reference:
                credential_reasons.append(
                    "The controlled account requires its vaulted original password."
                )
            elif not self._vault_contains(original_password_reference):
                credential_reasons.append(
                    "The controlled original password is unavailable in the credential vault."
                )
            credentials_present = bool(
                identity_resolution.identity_bound
                and original_password_reference
                and not credential_reasons
            )
            decision = self.gate.authorize_rate_limit_verification(
                RateLimitVerificationAction(
                    url=workflow.surface.url,
                    method=workflow.surface.method,
                    mode=approved.mode,
                    account_id=account.account_id,
                    account_controlled=account.controlled,
                    credential_references_present=credentials_present,
                    workflow_url=workflow.surface.url,
                    workflow_method=workflow.surface.method,
                    workflow_surface=workflow.surface.boundary_type,
                    attempts=approved.attempts,
                    expected_control_type=approved.expected_control.type,
                    expected_within_attempts=(
                        approved.expected_control.within_attempts
                    ),
                    request_count=approved.attempts + 2,
                )
            )
            if not decision.allowed or not credentials_present:
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=list(
                        dict.fromkeys([*credential_reasons, *decision.reasons])
                    ),
                )
            assert identity_resolution.identity_bound
            assert original_password_reference is not None
            try:
                original_password = self.vault.get(original_password_reference)
                invalid_password = self.vault.get(approved.invalid_password_reference)
                identity = identity_resolution.materialize(self.vault)
            except (KeyError, RuntimeError):
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=[
                        "A required vaulted login value is unavailable at execution time."
                    ],
                )
            if secrets.compare_digest(original_password, invalid_password):
                return self._rate_limit_result(
                    status="policy_blocked",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    reasons=["The valid and comparison login values must be distinct."],
                )
            self._runtime_binding["policy_authorized"] = True
            baseline_summary: dict[str, Any] | None = None
            attempt_summaries: list[dict[str, Any]] = []
            final_summary: dict[str, Any] | None = None
            baseline_requests = 0
            invalid_requests = 0
            final_requests = 0
            try:
                baseline_requests = 1
                baseline_response = self._dispatch_rate_limit_login(
                    config,
                    identity,
                    original_password,
                    decision.request_context,
                    role="valid_baseline",
                    position=0,
                )
                baseline_summary = safe_rate_limit_response_summary(baseline_response)
            except RequestBudgetExceeded:
                return self._rate_limit_result(
                    status="budget_exhausted",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    baseline_summary=baseline_summary,
                    baseline_requests=baseline_requests,
                    reasons=[
                        "The shared request budget was exhausted before the valid baseline request."
                    ],
                )
            except Exception as exc:
                failure_status, failure_reason = _transport_exception_decision(exc)
                return self._rate_limit_result(
                    status=failure_status,
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    baseline_summary=baseline_summary,
                    baseline_requests=baseline_requests,
                    reasons=[failure_reason],
                )
            if not self._valid_login_succeeded(baseline_summary):
                return self._rate_limit_result(
                    status="inconclusive",
                    attempts_requested=approved.attempts,
                    mode=approved.mode,
                    baseline_summary=baseline_summary,
                    baseline_requests=baseline_requests,
                    reasons=["A successful valid-login baseline was not established."],
                )

            for index in range(approved.attempts):
                try:
                    invalid_requests += 1
                    response = self._dispatch_rate_limit_login(
                        config,
                        identity,
                        invalid_password,
                        decision.request_context,
                        role="invalid_password_attempt",
                        position=index + 1,
                    )
                except RequestBudgetExceeded:
                    return self._rate_limit_result(
                        status="budget_exhausted",
                        attempts_requested=approved.attempts,
                        mode=approved.mode,
                        baseline_summary=baseline_summary,
                        attempt_summaries=attempt_summaries,
                        baseline_requests=baseline_requests,
                        invalid_requests=invalid_requests,
                        reasons=[
                            "The shared request budget was exhausted before the bounded sequence completed."
                        ],
                    )
                except Exception as exc:
                    failure_status, failure_reason = _transport_exception_decision(exc)
                    return self._rate_limit_result(
                        status=failure_status,
                        attempts_requested=approved.attempts,
                        mode=approved.mode,
                        baseline_summary=baseline_summary,
                        attempt_summaries=attempt_summaries,
                        baseline_requests=baseline_requests,
                        invalid_requests=invalid_requests,
                        reasons=[failure_reason],
                    )
                summary = safe_rate_limit_response_summary(response)
                attempt_summaries.append(summary)
                if summary["service_unstable"]:
                    return self._rate_limit_result(
                        status="inconclusive",
                        attempts_requested=approved.attempts,
                        mode=approved.mode,
                        baseline_summary=baseline_summary,
                        attempt_summaries=attempt_summaries,
                        baseline_requests=baseline_requests,
                        invalid_requests=invalid_requests,
                        reasons=[
                            "A bounded invalid-login response indicated service instability."
                        ],
                    )

            classification_reasons: list[str] = []
            final_failure_status: str | None = None
            try:
                final_requests = 1
                final_response = self._dispatch_rate_limit_login(
                    config,
                    identity,
                    original_password,
                    decision.request_context,
                    role="valid_final",
                    position=approved.attempts + 1,
                )
                final_summary = safe_rate_limit_response_summary(final_response)
            except RequestBudgetExceeded:
                final_summary = None
                final_failure_status = "budget_exhausted"
                classification_reasons.append(
                    "The shared request budget was exhausted before the final valid-login comparison."
                )
            except Exception as exc:
                final_summary = None
                final_failure_status, failure_reason = _transport_exception_decision(
                    exc
                )
                classification_reasons.append(failure_reason)
            status, expected_satisfied = classify_rate_limit_sequence(
                attempt_summaries,
                final_summary,
                within_attempts=approved.expected_control.within_attempts,
            )
            if final_failure_status is not None:
                status = final_failure_status
            if not classification_reasons:
                if status == "verified":
                    classification_reasons.append(
                        "No configured rate-limit control was observed within the approved attempt window, and the final valid login succeeded."
                    )
                elif status == "rejected":
                    classification_reasons.append(
                        "The configured rate-limit control was observed within the approved attempt window."
                    )
                else:
                    classification_reasons.append(
                        "The bounded login sequence did not provide sufficient deterministic rate-limit evidence."
                    )
            return self._rate_limit_result(
                status=status,
                attempts_requested=approved.attempts,
                mode=approved.mode,
                baseline_summary=baseline_summary,
                attempt_summaries=attempt_summaries,
                final_summary=final_summary,
                expected_control_satisfied=expected_satisfied,
                baseline_requests=baseline_requests,
                invalid_requests=invalid_requests,
                final_requests=final_requests,
                reasons=classification_reasons,
            )
        finally:
            for reference in approved.secret_references:
                try:
                    self.vault.discard(reference)
                except RuntimeError:
                    pass

    def _dispatch_rate_limit_login(
        self,
        config: SessionAcquisition,
        identity: str,
        password: str,
        request_context: Any,
        *,
        role: Literal["valid_baseline", "invalid_password_attempt", "valid_final"],
        position: int,
    ) -> dict[str, Any]:
        """Dispatch exactly one authorized sequential login with no retry path."""
        self._consume_legacy_transport_budget("auth")
        contextual = request_context.model_copy(
            update={
                "rate_limit_sequence_role": role,
                "rate_limit_sequence_position": position,
            }
        )
        response = self.transport(
            {
                "method": config.method,
                "url": config.url,
                "purpose": "rate_limit_verification",
                "request_context": contextual.model_dump(mode="json"),
                "isolate_session_cookies": True,
                "json": {
                    config.username_field: identity,
                    config.password_field: password,
                },
            }
        )
        if not isinstance(response, dict):
            raise ValueError("The transport returned an invalid response.")
        return response

    @staticmethod
    def _valid_login_succeeded(summary: dict[str, Any] | None) -> bool:
        return bool(
            summary
            and summary["status_class"] == "2xx"
            and not summary["throttle_signal"]
            and not summary["lockout_signal"]
            and not summary["service_unstable"]
        )

    def _rate_limit_result(
        self,
        *,
        status: str,
        attempts_requested: int,
        mode: str | None = None,
        baseline_summary: dict[str, Any] | None = None,
        attempt_summaries: list[dict[str, Any]] | None = None,
        final_summary: dict[str, Any] | None = None,
        expected_control_satisfied: bool | None = None,
        baseline_requests: int = 0,
        invalid_requests: int | None = None,
        final_requests: int = 0,
        reasons: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return only sanitized response summaries and explicit request counts."""
        summaries = list(attempt_summaries or [])
        normalized_status = (
            status
            if status
            in {
                "verified",
                "rejected",
                "inconclusive",
                "policy_blocked",
                "budget_exhausted",
            }
            else "inconclusive"
        )
        unique_reasons = list(dict.fromkeys(reasons or []))
        if not unique_reasons:
            default_reasons = {
                "policy_blocked": (
                    "Rate-limit verification was blocked before network execution."
                ),
                "verified": (
                    "No configured rate-limit control was observed within the approved attempt window."
                ),
                "rejected": (
                    "The configured rate-limit control was observed within the approved attempt window."
                ),
                "inconclusive": (
                    "The bounded login sequence did not provide sufficient deterministic rate-limit evidence."
                ),
                "budget_exhausted": (
                    "The bounded login sequence could not complete within its request budget."
                ),
            }
            unique_reasons = [default_reasons[normalized_status]]
        all_summaries = [
            item
            for item in [baseline_summary, *summaries, final_summary]
            if item is not None
        ]
        sent_invalid = len(summaries) if invalid_requests is None else invalid_requests
        total = baseline_requests + sent_invalid + final_requests
        return {
            "status": normalized_status,
            "mode": mode or "authentication_login_rate_limit",
            "attempts_requested": max(0, attempts_requested),
            "attempts_sent": sent_invalid,
            "baseline_summary": baseline_summary,
            "per_attempt_sanitized_summaries": summaries,
            "final_valid_login_summary": final_summary,
            "throttle_signal_observed": any(
                item["throttle_signal"] for item in all_summaries
            ),
            "retry_after_observed": any(
                item["retry_after_present"] for item in all_summaries
            ),
            "lockout_signal_observed": any(
                item["lockout_signal"] for item in all_summaries
            ),
            "expected_control_satisfied": expected_control_satisfied,
            "reasons": unique_reasons,
            "request_counts": {
                "valid_baseline_auth_requests": baseline_requests,
                "invalid_password_auth_requests": sent_invalid,
                "final_valid_auth_requests": final_requests,
                "auth_requests": total,
                "total_network_requests": total,
            },
        }

    def _execute_recovery_state_enforcement(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        raw_inputs: dict[str, Any],
        *,
        prior_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Run one runtime-bound recovery baseline and one explicit reuse check."""
        approved, input_reasons = ingest_recovery_verification_input(
            raw_inputs, self.vault
        )
        if approved is None:
            return self._stopped("policy_blocked", 0, input_reasons)
        try:
            binding = bind_runtime_accounts(
                hypothesis, plan, self.context, self.gate.policy, self.vault
            )
            self._runtime_binding = dict(binding.diagnostics)
            if not binding.succeeded or binding.plan is None:
                return self._stopped("policy_blocked", 0, binding.reasons)
            runtime_plan = binding.plan
            try:
                workflow = RecoveryWorkflow.from_hypothesis(hypothesis)
            except ValueError:
                return self._stopped(
                    "policy_blocked",
                    0,
                    ["Recovery workflow metadata is incomplete or ambiguous."],
                )
            actions, plan_reasons = workflow.validate_plan(hypothesis, runtime_plan)
            if actions is None:
                return self._stopped("policy_blocked", 0, plan_reasons)
            account_ids = {
                str(item["account_id"])
                for item in actions
                if item.get("account_id") is not None
            }
            if account_ids != {approved.account_id}:
                return self._stopped(
                    "policy_blocked",
                    0,
                    [
                        "The verification input account does not match the single runtime-bound recovery account."
                    ],
                )
            try:
                account = self.context.account(approved.account_id)
            except KeyError:
                return self._stopped(
                    "policy_blocked",
                    0,
                    ["Unknown controlled recovery account reference."],
                )
            credential_reasons = self._recovery_credential_reasons(account, workflow)
            if credential_reasons:
                return self._stopped("policy_blocked", 0, credential_reasons)
            if approved.phase == "confirm_external_cleanup":
                return self._confirm_external_recovery_cleanup(
                    hypothesis,
                    workflow,
                    approved,
                    account,
                    prior_result,
                )
            if approved.phase == "resume_with_controlled_evidence":
                return self._resume_recovery_verification(
                    hypothesis,
                    workflow,
                    actions,
                    approved,
                    account,
                    prior_result,
                )
            return self._issue_recovery_challenge(
                hypothesis,
                workflow,
                actions,
                approved,
                account,
                prior_result,
            )
        finally:
            for reference in approved.secret_references:
                try:
                    self.vault.discard(reference)
                except RuntimeError:
                    pass

    def _issue_recovery_challenge(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        actions: list[dict[str, Any]],
        approved: RecoveryVerificationInput,
        account: ControlledAccount,
        prior_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if isinstance(prior_result, dict) and (
            prior_result.get("recovery_phase")
            in {"challenge_issued", "verification_pending_cleanup", "cleanup_failed"}
            or prior_result.get("external_cleanup_required") is True
        ):
            return self._stopped(
                "policy_blocked",
                0,
                [
                    "The stored recovery workflow must be resumed or cleaned up before another challenge is issued."
                ],
            )
        decision = self.gate.authorize_recovery_state_action(
            RecoveryStateAction(
                url=actions[0]["url"],
                method=actions[0]["method"],
                workflow_phase="recovery_start",
                account_id=account.account_id,
                account_controlled=account.controlled,
                workflow_url=workflow.recovery_start.url,
                runtime_challenge_bound=False,
                comparison_type=approved.comparison_type,
            )
        )
        if decision.reasons:
            return self._stopped("policy_blocked", 0, decision.reasons)
        if self.gate.budget.remaining < 1:
            return self._stopped(
                "budget_exhausted",
                0,
                ["The shared request budget cannot cover recovery challenge issuance."],
            )
        identity_resolution = resolve_controlled_login_identity(
            account, workflow.recovery_identity_field, self.vault
        )
        if not identity_resolution.identity_bound:
            return self._stopped(
                "policy_blocked",
                0,
                [
                    identity_resolution.reason
                    or "Controlled login identity is unavailable."
                ],
            )
        self._runtime_binding["policy_authorized"] = True
        requests_used = 0
        summaries: dict[str, Any] = {}
        reasons: list[str] = []
        challenge_state: PreservedRecoveryChallenge | None = None
        failure_status: str | None = None
        try:
            requests_used = 1
            start_response = self._dispatch_recovery_request(
                actions[0],
                {
                    workflow.recovery_identity_field: identity_resolution.materialize(
                        self.vault
                    )
                },
            )
            summaries["recovery_start"] = response_summary(start_response)
            if self._successful(start_response):
                body = start_response.get("body")
                challenge_id = (
                    body.get("challenge_id") if isinstance(body, dict) else None
                )
                if isinstance(challenge_id, int) and not isinstance(challenge_id, bool):
                    challenge_state = self._new_recovery_challenge_state(
                        hypothesis, workflow, account, challenge_id
                    )
                    reasons.append(
                        "A runtime recovery challenge was issued for the controlled account; controlled channel evidence is now required."
                    )
                else:
                    reasons.append(
                        "Recovery start did not return an integer challenge_id for runtime binding."
                    )
            else:
                reasons.append("The controlled recovery-start request did not succeed.")
        except RequestBudgetExceeded as exc:
            failure_status = "budget_exhausted"
            reasons.append(str(exc))
        except Exception as exc:
            failure_status, failure_reason = _transport_exception_decision(exc)
            reasons.append(failure_reason)

        issued = challenge_state is not None
        return self._recovery_result(
            hypothesis,
            status=(
                "awaiting_controlled_evidence"
                if issued
                else failure_status or "inconclusive"
            ),
            recovery_phase="challenge_issued" if issued else "challenge_not_issued",
            confidence="low",
            reasons=reasons,
            requests_used=requests_used,
            approved=approved,
            challenge_reference=(
                challenge_state.challenge_reference if challenge_state else None
            ),
            preserved_challenge=(
                challenge_state.model_dump(mode="json") if challenge_state else None
            ),
            summaries=summaries,
            valid_completion_succeeded=False,
            comparison_attempted=False,
            comparison_accepted=False,
            independent_state_confirmed=False,
            cleanup_verified=False,
            cleanup_failed=False,
            recovery_evidence_required=issued,
            external_evidence_required=issued,
            external_cleanup_required=False,
        )

    def _resume_recovery_verification(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        actions: list[dict[str, Any]],
        approved: RecoveryVerificationInput,
        account: ControlledAccount,
        prior_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        code_reference = approved.code_reference
        temporary_reference = approved.temporary_password_reference
        comparison_reference = approved.comparison_password_reference
        if not code_reference or not temporary_reference or not comparison_reference:
            return self._stopped(
                "policy_blocked",
                0,
                ["The required controlled recovery resume secrets are unavailable."],
            )
        challenge_state, challenge_reasons = self._validated_issued_challenge(
            hypothesis, workflow, approved, account, prior_result
        )
        if challenge_state is None:
            return self._stopped("policy_blocked", 0, challenge_reasons)

        policy_reasons: list[str] = []
        for item, phase in zip(
            actions[1:], ("valid_completion", "reuse_comparison"), strict=True
        ):
            decision = self.gate.authorize_recovery_state_action(
                RecoveryStateAction(
                    url=item["url"],
                    method=item["method"],
                    workflow_phase=phase,
                    account_id=account.account_id,
                    account_controlled=account.controlled,
                    workflow_url=workflow.recovery_completion.url,
                    runtime_challenge_bound=True,
                    comparison_type=approved.comparison_type,
                )
            )
            policy_reasons.extend(decision.reasons)
        config = self.context.session_acquisition
        if config is None:
            policy_reasons.append(
                "Controlled login is required to confirm comparison credential state."
            )
            auth_decision = None
        else:
            auth_decision = SessionAcquirer(self.vault, self.gate.budget).authorize(
                account, config, self.gate.authorize_session_acquisition
            )
            policy_reasons.extend(auth_decision.reasons)
        if self.gate.budget.remaining < 3:
            policy_reasons.append(
                "The shared request budget cannot cover two recovery completions and one credential-state confirmation."
            )
        if policy_reasons:
            return self._stopped(
                "policy_blocked", 0, list(dict.fromkeys(policy_reasons))
            )
        assert config is not None and auth_decision is not None
        self._runtime_binding["policy_authorized"] = True

        self._consume_preserved_challenge(prior_result)
        challenge_state.consumed = True
        try:
            self.private_recovery_store.save_for_executor(
                run_reference=self._recovery_run_reference,
                hypothesis_id=hypothesis.hypothesis_id,
                challenge=challenge_state.model_dump(mode="json"),
            )
        except (OSError, TypeError, ValueError):
            return self._stopped(
                "policy_blocked",
                0,
                [
                    "The private recovery challenge could not be consumed safely before traffic."
                ],
            )
        requests_used = 0
        valid_completion_succeeded = False
        comparison_attempted = False
        comparison_accepted = False
        independent_state_confirmed = False
        external_cleanup_required = False
        summaries = self._safe_recovery_summaries(
            prior_result.get("response_summaries") if prior_result else None
        )
        reasons: list[str] = []
        confidence = "low"
        failure_status: str | None = None
        try:
            code = self.vault.get(code_reference)
            external_cleanup_required = True
            requests_used = 1
            valid_response = self._dispatch_recovery_request(
                actions[1],
                {
                    "challenge_id": challenge_state.challenge_id,
                    "code": code,
                    "new_password": self.vault.get(temporary_reference),
                },
            )
            summaries["valid_completion"] = response_summary(valid_response)
            valid_completion_succeeded = self._successful(valid_response)
            if not valid_completion_succeeded:
                status_code = valid_response.get("status_code")
                external_cleanup_required = not (
                    isinstance(status_code, int) and 400 <= status_code < 500
                )
                reasons.append(
                    "The legitimate controlled recovery completion could not be established."
                )
            else:
                comparison_attempted = True
                requests_used = 2
                comparison_response = self._dispatch_recovery_request(
                    actions[2],
                    {
                        "challenge_id": challenge_state.challenge_id,
                        "code": code,
                        "new_password": self.vault.get(comparison_reference),
                    },
                )
                summaries["comparison"] = response_summary(comparison_response)
                comparison_accepted = self._successful(comparison_response)
                comparison_status = comparison_response.get("status_code")
                independent_state_confirmed, auth_summary = (
                    self._authenticate_recovery_credential(
                        account, comparison_reference, config, auth_decision
                    )
                )
                if auth_summary is not None:
                    summaries["comparison_authentication"] = auth_summary
                if comparison_accepted and independent_state_confirmed:
                    confidence = "high"
                    reasons.append(
                        "The reused runtime-bound challenge and code set the separately approved comparison credential."
                    )
                elif (
                    not comparison_accepted
                    and not independent_state_confirmed
                    and isinstance(comparison_status, int)
                    and 400 <= comparison_status < 500
                ):
                    confidence = "high"
                    reasons.append(
                        "The target denied the single reuse of the runtime-bound challenge and legitimate code."
                    )
                else:
                    reasons.append(
                        "The recovery comparison response and independent credential state did not establish a consistent result."
                    )
        except RequestBudgetExceeded as exc:
            failure_status = "budget_exhausted"
            external_cleanup_required = False
            reasons.append(str(exc))
        except Exception as exc:
            failure_status, failure_reason = _transport_exception_decision(exc)
            if failure_status in {"budget_exhausted", "policy_blocked"}:
                external_cleanup_required = False
            reasons.append(failure_reason)

        pending_cleanup = external_cleanup_required
        return self._recovery_result(
            hypothesis,
            status=(
                "verification_pending_cleanup"
                if pending_cleanup
                else failure_status or "inconclusive"
            ),
            recovery_phase=(
                "verification_pending_cleanup" if pending_cleanup else "resume_failed"
            ),
            confidence=confidence,
            reasons=reasons,
            requests_used=requests_used,
            approved=approved,
            challenge_reference=challenge_state.challenge_reference,
            preserved_challenge=challenge_state.model_dump(mode="json"),
            summaries=summaries,
            valid_completion_succeeded=valid_completion_succeeded,
            comparison_attempted=comparison_attempted,
            comparison_accepted=comparison_accepted,
            independent_state_confirmed=independent_state_confirmed,
            cleanup_verified=False,
            cleanup_failed=False,
            recovery_evidence_required=False,
            external_evidence_required=False,
            external_cleanup_required=pending_cleanup,
        )

    def _confirm_external_recovery_cleanup(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        approved: RecoveryVerificationInput,
        account: ControlledAccount,
        prior_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        prior, prior_reasons = self._validated_pending_recovery_result(
            hypothesis, workflow, approved, account, prior_result
        )
        if prior is None:
            return self._stopped("policy_blocked", 0, prior_reasons)
        policy_reasons: list[str] = []
        if not self.gate.policy.allow_state_changes:
            policy_reasons.append(
                "State-changing recovery verification is disabled by policy."
            )
        if not self.gate.policy.require_cleanup_for_state_changes:
            policy_reasons.append(
                "Recovery verification requires mandatory cleanup policy."
            )
        config = self.context.session_acquisition
        if config is None:
            policy_reasons.append(
                "Controlled login is required to confirm external cleanup."
            )
            auth_decision = None
        else:
            auth_decision = SessionAcquirer(self.vault, self.gate.budget).authorize(
                account,
                config,
                self.gate.authorize_session_acquisition,
            )
            policy_reasons.extend(auth_decision.reasons)
        if self.gate.budget.remaining < 1:
            policy_reasons.append(
                "The shared request budget cannot cover cleanup verification."
            )
        if policy_reasons:
            return self._stopped(
                "policy_blocked", 0, list(dict.fromkeys(policy_reasons))
            )
        assert config is not None and auth_decision is not None
        self._runtime_binding["policy_authorized"] = True
        original_password_reference = account.credential_references["password"]
        cleanup_verified = False
        cleanup_summary: dict[str, Any] | None = None
        reasons: list[str] = []
        failure_status: str | None = None
        try:
            cleanup_verified, cleanup_summary = self._authenticate_recovery_credential(
                account,
                original_password_reference,
                config,
                auth_decision,
                cleanup=True,
            )
        except RequestBudgetExceeded as exc:
            failure_status = "budget_exhausted"
            reasons.append(str(exc))
        except Exception as exc:
            failure_status, failure_reason = _transport_exception_decision(exc)
            reasons.append(failure_reason)

        summaries = self._safe_recovery_summaries(prior.get("response_summaries"))
        if cleanup_summary is not None:
            summaries["cleanup_authentication"] = cleanup_summary
        status = failure_status or "inconclusive"
        confidence = "low"
        if cleanup_verified:
            candidate = self._pending_recovery_classification(prior)
            if candidate == "verified":
                status = "verified"
                confidence = "high"
                reasons.append(
                    "External restoration was confirmed with the original credential; the independently confirmed reuse finding is promoted."
                )
            elif candidate == "rejected":
                status = "rejected"
                confidence = "high"
                reasons.append(
                    "External restoration was confirmed with the original credential; the denied reuse comparison is classified secure."
                )
            else:
                reasons.append(
                    "Cleanup was confirmed, but the earlier recovery comparison remains inconclusive."
                )
        else:
            reasons.append(CLEANUP_UNVERIFIED_REASON)

        return self._recovery_result(
            hypothesis,
            status=status,
            recovery_phase="completed" if cleanup_verified else "cleanup_failed",
            confidence=confidence,
            reasons=reasons,
            requests_used=0,
            approved=approved,
            challenge_reference=prior.get("challenge_reference"),
            preserved_challenge=prior.get("preserved_challenge"),
            summaries=summaries,
            valid_completion_succeeded=prior["valid_completion_succeeded"],
            comparison_attempted=prior["comparison_attempted"],
            comparison_accepted=prior["comparison_accepted"],
            independent_state_confirmed=prior["independent_state_confirmed"],
            cleanup_verified=cleanup_verified,
            cleanup_failed=not cleanup_verified,
            recovery_evidence_required=False,
            external_evidence_required=False,
            external_cleanup_required=not cleanup_verified,
        )

    def _recovery_credential_reasons(
        self, account: ControlledAccount, workflow: RecoveryWorkflow
    ) -> list[str]:
        reasons: list[str] = []
        references = account.credential_references
        config = self.context.session_acquisition
        identity_field = (
            config.username_field
            if config is not None
            else workflow.recovery_identity_field
        )
        identity_resolution = resolve_controlled_login_identity(
            account, identity_field, self.vault
        )
        if not identity_resolution.identity_bound:
            reasons.append(
                identity_resolution.reason
                or "Controlled login identity is unavailable."
            )
        password_reference = references.get("password")
        if not password_reference or not self._vault_contains(password_reference):
            reasons.append(
                "The controlled recovery account has no vaulted original password credential."
            )
        if config is None:
            reasons.append("Controlled login/session acquisition is not configured.")
        return reasons

    def _dispatch_recovery_request(
        self, item: dict[str, Any], body: dict[str, Any]
    ) -> dict[str, Any]:
        self._consume_legacy_transport_budget("verification")
        response = self.transport(
            {
                "url": item["url"],
                "method": item["method"],
                "json": body,
                "purpose": "state_mutation",
                "credential_mode": "anonymous",
                "isolate_session_cookies": True,
            }
        )
        if not isinstance(response, dict):
            raise ValueError("The transport returned an invalid response.")
        return response

    def _authenticate_recovery_credential(
        self,
        account: ControlledAccount,
        password_reference: str,
        config: SessionAcquisition,
        decision: Any,
        *,
        cleanup: bool = False,
    ) -> tuple[bool, dict[str, Any] | None]:
        identity_resolution = resolve_controlled_login_identity(
            account, config, self.vault
        )
        if not identity_resolution.identity_bound:
            raise _ExecutionHalt(
                "inconclusive",
                [
                    identity_resolution.reason
                    or "Controlled login identity is unavailable."
                ],
            )
        if not self._vault_contains(password_reference):
            raise _ExecutionHalt(
                "inconclusive",
                ["The controlled login password is unavailable."],
            )
        self._consume_legacy_transport_budget("cleanup" if cleanup else "auth")
        request_context = (
            decision.request_context.model_copy(update={"purpose": "cleanup"})
            if cleanup
            else decision.request_context
        )
        response = self.transport(
            {
                "method": config.method,
                "url": config.url,
                "purpose": "cleanup" if cleanup else "session_acquisition",
                "request_context": request_context.model_dump(mode="json"),
                "credential_mode": "controlled_password_confirmation",
                "isolate_session_cookies": True,
                "json": {
                    config.username_field: identity_resolution.materialize(self.vault),
                    config.password_field: self.vault.get(password_reference),
                },
            }
        )
        if not isinstance(response, dict):
            raise ValueError("The transport returned an invalid response.")
        summary = response_summary(response)
        body = response.get("body")
        token = body.get(config.token_field) if isinstance(body, dict) else None
        authenticated = bool(
            self._successful(response) and isinstance(token, str) and token
        )
        if authenticated:
            token_reference = self.vault.put(
                token, label=f"recovery-confirmation:{account.account_id}"
            )
            self.vault.discard(token_reference)
        return authenticated, summary

    def _validated_issued_challenge(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        approved: RecoveryVerificationInput,
        account: ControlledAccount,
        prior_result: dict[str, Any] | None,
    ) -> tuple[PreservedRecoveryChallenge | None, list[str]]:
        if not isinstance(prior_result, dict):
            return None, [
                "Recovery resume requires one preserved CyberCortex-issued challenge."
            ]
        if (
            prior_result.get("hypothesis_id") != hypothesis.hypothesis_id
            or prior_result.get("category") != "recovery_state_enforcement"
            or prior_result.get("comparison_type") != approved.comparison_type
            or prior_result.get("recovery_phase") != "challenge_issued"
            or prior_result.get("recovery_evidence_required") is not True
        ):
            return None, [
                "The stored recovery state is not the issued challenge being resumed."
            ]
        challenge, reasons = self._validated_preserved_challenge(
            hypothesis, workflow, account, prior_result, consumed=False
        )
        if challenge is None:
            return None, reasons
        start_summary = (prior_result.get("response_summaries") or {}).get(
            "recovery_start"
        )
        start_status = (
            start_summary.get("status_code")
            if isinstance(start_summary, dict)
            else None
        )
        if not isinstance(start_status, int) or not 200 <= start_status < 300:
            return None, [
                "The preserved challenge is not backed by CyberCortex's successful recovery-start request."
            ]
        return challenge, []

    def _validated_pending_recovery_result(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        approved: RecoveryVerificationInput,
        account: ControlledAccount,
        prior_result: dict[str, Any] | None,
    ) -> tuple[dict[str, Any] | None, list[str]]:
        if not isinstance(prior_result, dict):
            return None, [
                "External cleanup confirmation requires one stored pending recovery result."
            ]
        if (
            prior_result.get("hypothesis_id") != hypothesis.hypothesis_id
            or prior_result.get("category") != "recovery_state_enforcement"
            or prior_result.get("comparison_type") != approved.comparison_type
            or prior_result.get("recovery_phase") != "verification_pending_cleanup"
            or prior_result.get("external_cleanup_required") is not True
            or prior_result.get("cleanup_verified") is not False
        ):
            return None, [
                "The stored result is not the pending recovery execution being cleaned up."
            ]
        challenge, reasons = self._validated_preserved_challenge(
            hypothesis, workflow, account, prior_result, consumed=True
        )
        if challenge is None:
            return None, reasons
        boolean_fields = (
            "valid_completion_succeeded",
            "comparison_attempted",
            "comparison_accepted",
            "independent_state_confirmed",
        )
        if any(type(prior_result.get(field)) is not bool for field in boolean_fields):
            return None, ["The stored pending recovery evidence is incomplete."]
        return prior_result, []

    def _validated_preserved_challenge(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        account: ControlledAccount,
        prior_result: dict[str, Any],
        *,
        consumed: bool,
    ) -> tuple[PreservedRecoveryChallenge | None, list[str]]:
        try:
            challenge = PreservedRecoveryChallenge.model_validate(
                prior_result.get("preserved_challenge")
            )
        except ValueError:
            return None, ["The stored recovery challenge metadata is invalid."]
        if challenge.consumed is not consumed:
            return None, [
                (
                    "The stored recovery challenge was already consumed by another resume."
                    if challenge.consumed
                    else "The stored recovery challenge has not completed its approved resume."
                )
            ]
        expected = self._new_recovery_challenge_state(
            hypothesis, workflow, account, challenge.challenge_id
        )
        expected.consumed = consumed
        if challenge != expected:
            return None, [
                "The stored recovery challenge belongs to another account, hypothesis, workflow, or run."
            ]
        if prior_result.get("challenge_reference") != challenge.challenge_reference:
            return None, ["The stored recovery challenge reference is inconsistent."]
        return challenge, []

    @staticmethod
    def _consume_preserved_challenge(prior_result: dict[str, Any] | None) -> None:
        if not isinstance(prior_result, dict):
            return
        for container in (
            prior_result,
            (
                prior_result.get("analysis")
                if isinstance(prior_result.get("analysis"), dict)
                else None
            ),
        ):
            if not isinstance(container, dict):
                continue
            challenge = container.get("preserved_challenge")
            if isinstance(challenge, dict):
                challenge["consumed"] = True

    @staticmethod
    def _pending_recovery_classification(prior: dict[str, Any]) -> str:
        if (
            prior.get("valid_completion_succeeded") is not True
            or prior.get("comparison_attempted") is not True
        ):
            return "inconclusive"
        summaries = prior.get("response_summaries") or {}
        observed = [
            item
            for item in summaries.values()
            if isinstance(item, dict) and "status_code" in item
        ]
        if observed and assess_response_instability(observed).unstable:
            return "inconclusive"
        if (
            prior.get("comparison_accepted") is True
            and prior.get("independent_state_confirmed") is True
        ):
            return "verified"
        comparison = summaries.get("comparison") or {}
        status_code = comparison.get("status_code")
        if (
            prior.get("comparison_accepted") is False
            and isinstance(status_code, int)
            and 400 <= status_code < 500
        ):
            return "rejected"
        return "inconclusive"

    @staticmethod
    def _safe_recovery_summaries(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        safe: dict[str, Any] = {}
        allowed_names = {
            "recovery_start",
            "valid_completion",
            "comparison",
            "comparison_authentication",
            "cleanup_authentication",
        }
        for name, summary in value.items():
            if name not in allowed_names or not isinstance(summary, dict):
                continue
            safe[name] = {
                key: summary.get(key)
                for key in (
                    "status_code",
                    "status_class",
                    "schema_fields",
                    "structure_hash",
                    "body_hash",
                    "error_semantics",
                )
            }
        return safe

    @staticmethod
    def _recovery_binding(value: Any) -> str:
        material = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return "sha256:" + sha256(material).hexdigest()

    def _new_recovery_challenge_state(
        self,
        hypothesis: Hypothesis,
        workflow: RecoveryWorkflow,
        account: ControlledAccount,
        challenge_id: int,
    ) -> PreservedRecoveryChallenge:
        hypothesis_binding = self._recovery_binding(hypothesis.hypothesis_id)
        account_binding = self._recovery_binding(
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "account_id": account.account_id,
            }
        )
        workflow_binding = self._recovery_binding(workflow.model_dump(mode="json"))
        run_binding = self._recovery_binding(self._recovery_run_reference)
        combined_binding = self._recovery_binding(
            {
                "hypothesis_binding": hypothesis_binding,
                "account_binding": account_binding,
                "workflow_binding": workflow_binding,
                "run_binding": run_binding,
            }
        ).removeprefix("sha256:")
        challenge_binding = self._recovery_binding(
            {
                "combined_binding": combined_binding,
                "challenge_type": "integer",
                "challenge_id": challenge_id,
            }
        ).removeprefix("sha256:")
        return PreservedRecoveryChallenge(
            issued_by="RecoveryStateEnforcementExecutor",
            issuance_action="controlled_recovery_start",
            challenge_id=challenge_id,
            challenge_reference=(f"sha256:{combined_binding}:{challenge_binding}"),
            hypothesis_binding=hypothesis_binding,
            account_binding=account_binding,
            workflow_binding=workflow_binding,
            run_binding=run_binding,
            consumed=False,
        )

    def _recovery_result(
        self,
        hypothesis: Hypothesis,
        *,
        status: str,
        recovery_phase: str,
        confidence: str,
        reasons: list[str],
        requests_used: int,
        approved: RecoveryVerificationInput,
        challenge_reference: str | None,
        preserved_challenge: dict[str, Any] | None,
        summaries: dict[str, Any],
        valid_completion_succeeded: bool,
        comparison_attempted: bool,
        comparison_accepted: bool,
        independent_state_confirmed: bool,
        cleanup_verified: bool,
        cleanup_failed: bool,
        recovery_evidence_required: bool,
        external_evidence_required: bool,
        external_cleanup_required: bool,
    ) -> dict[str, Any]:
        normalized_status = (
            status
            if status
            in {
                "awaiting_controlled_evidence",
                "verification_pending_cleanup",
                "verified",
                "rejected",
                "inconclusive",
            }
            else "inconclusive"
        )
        fields = {
            "comparison_type": approved.comparison_type,
            "recovery_phase": recovery_phase,
            "challenge_reference": challenge_reference,
            "response_summaries": summaries,
            "valid_completion_succeeded": valid_completion_succeeded,
            "comparison_attempted": comparison_attempted,
            "comparison_accepted": comparison_accepted,
            "independent_state_confirmed": independent_state_confirmed,
            "cleanup_attempted": approved.phase == "confirm_external_cleanup",
            "cleanup_verified": cleanup_verified,
            "cleanup_failed": cleanup_failed,
            "recovery_evidence_required": recovery_evidence_required,
            "external_evidence_required": external_evidence_required,
            "external_cleanup_required": external_cleanup_required,
        }
        return {
            "hypothesis_id": hypothesis.hypothesis_id,
            "category": hypothesis.category,
            "status": normalized_status,
            "confidence": confidence,
            "evidence_summary": list(dict.fromkeys(reasons)),
            "requests_used": requests_used,
            "recovery_run_id": self._recovery_run_reference,
            "preserved_challenge": preserved_challenge,
            **fields,
            "analysis": {
                "status": normalized_status,
                "verified": normalized_status == "verified",
                "confidence": confidence,
                **fields,
                "reasons": list(dict.fromkeys(reasons)),
            },
            "runtime_binding": dict(self._runtime_binding),
            "request_budget": self.gate.budget.snapshot(),
        }

    def _execute_session_invalidation(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        planned: list[dict[str, Any]],
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        """Run acquisition, baseline, exact logout, and same-session replay."""
        try:
            approved = SessionInvalidationVerificationInput.model_validate(inputs)
        except ValueError:
            return self._stopped(
                "policy_blocked",
                0,
                [
                    "Session invalidation requires protected_fields and protected_data_confirmed=true as its only verification input."
                ],
            )
        try:
            workflow = SessionInvalidationWorkflow.from_hypothesis(hypothesis)
        except ValueError:
            return self._stopped(
                "policy_blocked",
                0,
                ["Session-invalidation workflow metadata is incomplete or ambiguous."],
            )
        actions, plan_reasons = workflow.validate_plan(hypothesis, plan)
        if actions is None:
            return self._stopped("policy_blocked", 0, plan_reasons)
        if actions != planned:
            return self._stopped(
                "policy_blocked",
                0,
                [
                    "The bound session-invalidation action sequence changed unexpectedly."
                ],
            )
        account_ids = {
            str(item["account_id"])
            for item in actions
            if item.get("account_id") is not None
        }
        if len(account_ids) != 1:
            return self._stopped(
                "policy_blocked",
                0,
                ["Session invalidation requires one bound controlled account."],
            )
        account_id = next(iter(account_ids))
        try:
            account = self.context.account(account_id)
        except KeyError:
            return self._stopped(
                "policy_blocked", 0, ["Unknown controlled account reference."]
            )
        config = self.context.session_acquisition
        if config is None:
            return self._stopped(
                "policy_blocked",
                0,
                ["Controlled session acquisition is not configured."],
            )

        acquirer = SessionAcquirer(self.vault, self.gate.budget)
        acquisition_decision = acquirer.authorize(
            account, config, self.gate.authorize_session_acquisition
        )
        baseline_action = self._verification_action(actions[1], credential=True)
        replay_action = self._verification_action(actions[3], credential=True)
        baseline_decision = self.gate.authorize_action(baseline_action)
        replay_decision = self.gate.authorize_action(replay_action)
        termination_action = SessionTerminationAction(
            url=actions[2]["url"],
            method=actions[2]["method"],
            account_id=account.account_id,
            account_controlled=account.controlled,
            workflow_url=workflow.session_termination.url,
            workflow_method=workflow.session_termination.method,
        )
        termination_decision = self.gate.authorize_session_termination(
            termination_action
        )
        policy_reasons = list(
            dict.fromkeys(
                [
                    *acquisition_decision.reasons,
                    *baseline_decision.reasons,
                    *termination_decision.reasons,
                    *replay_decision.reasons,
                ]
            )
        )
        if policy_reasons:
            return self._stopped("policy_blocked", 0, policy_reasons)
        if self.gate.budget.remaining < 4:
            return self._stopped(
                "budget_exhausted",
                0,
                [
                    "The shared request budget cannot cover one authentication and three workflow requests."
                ],
            )
        self._runtime_binding["policy_authorized"] = True

        previous_session_reference = account.session_reference
        s1_reference: str | None = None
        requests_used = 0
        baseline_response: dict[str, Any] | None = None
        replay_response: dict[str, Any] | None = None
        same_session_replayed = False
        termination_attempted = False
        termination_succeeded = False
        cleanup_attempted = False
        cleanup_verified = False
        substitution_detected = False
        status = "inconclusive"
        confidence = "low"
        reasons: list[str] = []
        protected_field_paths: list[str] = []
        baseline_protected_field_paths: list[str] = []
        protected_evidence_matched = False

        try:
            acquisition_failed = False
            try:
                acquirer.acquire(
                    account,
                    config,
                    self.transport,
                    authorization_check=self.gate.authorize_session_acquisition,
                )
            except RequestBudgetExceeded as exc:
                acquisition_failed = True
                status = "budget_exhausted"
                reasons.append(str(exc))
            except SessionAcquisitionPolicyError as exc:
                acquisition_failed = True
                status = "policy_blocked"
                reasons.extend(exc.reasons)
            except SessionAcquisitionTransportPolicyError as exc:
                acquisition_failed = True
                cause = exc.__cause__
                status = (
                    "budget_exhausted"
                    if cause is not None and "budget" in str(cause).casefold()
                    else "policy_blocked"
                )
                reasons.append(
                    str(cause)
                    if status == "budget_exhausted"
                    else TRANSPORT_POLICY_BLOCKED_REASON
                )
            except (
                SessionAuthenticationRejectedError,
                SessionTokenFieldAbsentError,
            ) as exc:
                acquisition_failed = True
                reasons.append(str(exc))
            except Exception:
                acquisition_failed = True
                reasons.append(transport_failure_reason())

            if not acquisition_failed:
                s1_reference = account.session_reference
                if not s1_reference or not self._vault_contains(s1_reference):
                    reasons.append("The acquired controlled session is unavailable.")
                else:
                    baseline_response = self._dispatch_session_request(
                        actions[1], s1_reference, purpose="verification"
                    )
                    requests_used += 1
                    baseline_analysis = analyze_session_invalidation(
                        baseline_response,
                        {},
                        protected_fields=approved.protected_fields,
                        protected_data_confirmed=approved.protected_data_confirmed,
                        termination_succeeded=False,
                    )
                    baseline_protected_field_paths = list(
                        baseline_analysis["baseline_protected_field_paths"]
                    )
                    if not baseline_analysis["authenticated_baseline_established"]:
                        reasons.extend(baseline_analysis["reasons"])
                    else:
                        termination_attempted = True
                        termination_response = self._dispatch_session_request(
                            actions[2],
                            s1_reference,
                            purpose="session_termination",
                            request_context=(
                                termination_decision.request_context.model_dump(
                                    mode="json"
                                )
                            ),
                        )
                        requests_used += 1
                        termination_succeeded = self._successful(termination_response)
                        if not termination_succeeded:
                            reasons.append(
                                "The configured session-termination operation failed unexpectedly."
                            )
                        elif account.session_reference != s1_reference:
                            substitution_detected = True
                            reasons.append(
                                "The bound credential changed before replay; no replacement credential was used."
                            )
                        else:
                            same_session_replayed = True
                            replay_response = self._dispatch_session_request(
                                actions[3], s1_reference, purpose="verification"
                            )
                            requests_used += 1
                            analysis = analyze_session_invalidation(
                                baseline_response,
                                replay_response,
                                protected_fields=approved.protected_fields,
                                protected_data_confirmed=(
                                    approved.protected_data_confirmed
                                ),
                                termination_succeeded=termination_succeeded,
                            )
                            status = str(analysis["status"])
                            confidence = str(analysis["confidence"])
                            reasons.extend(analysis["reasons"])
                            baseline_protected_field_paths = list(
                                analysis["baseline_protected_field_paths"]
                            )
                            protected_field_paths = list(
                                analysis["protected_field_paths"]
                            )
                            protected_evidence_matched = bool(
                                analysis["protected_evidence_matched"]
                            )
        except RequestBudgetExceeded as exc:
            status = "budget_exhausted"
            reasons.append(str(exc))
        except _ExecutionHalt as exc:
            status = exc.status
            reasons.extend(exc.reasons)
        except Exception as exc:
            status, failure_reason = _transport_exception_decision(exc)
            reasons.append(failure_reason)
        finally:
            if s1_reference is not None:
                cleanup_attempted = True
                if account.session_reference not in {
                    s1_reference,
                    previous_session_reference,
                }:
                    substitution_detected = True
                try:
                    discarded = self.vault.discard(s1_reference)
                except RuntimeError:
                    discarded = False
                account.session_reference = previous_session_reference
                cleanup_verified = bool(discarded and not substitution_detected)

        return self._session_invalidation_result(
            hypothesis,
            status=status,
            confidence=confidence,
            reasons=reasons,
            requests_used=requests_used,
            baseline_response=baseline_response,
            replay_response=replay_response,
            baseline_protected_field_paths=baseline_protected_field_paths,
            protected_field_paths=protected_field_paths,
            protected_evidence_matched=protected_evidence_matched,
            same_session_replayed=same_session_replayed,
            termination_attempted=termination_attempted,
            termination_succeeded=termination_succeeded,
            cleanup_attempted=cleanup_attempted,
            cleanup_verified=cleanup_verified,
        )

    @staticmethod
    def _verification_action(
        item: dict[str, Any], *, credential: bool
    ) -> VerificationAction:
        effective = dict(item)
        effective["credential_reference_present"] = credential
        return VerificationAction.model_validate(
            {
                key: value
                for key, value in effective.items()
                if key in VerificationAction.model_fields
            }
        )

    def _dispatch_session_request(
        self,
        item: dict[str, Any],
        session_reference: str,
        *,
        purpose: Literal["verification", "session_termination"],
        request_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Dispatch one request only while the original S1 binding is unchanged."""
        account_id = str(item.get("account_id") or "")
        account = self.context.account(account_id)
        if account.session_reference != session_reference or not self._vault_contains(
            session_reference
        ):
            raise _ExecutionHalt(
                "inconclusive",
                ["The original controlled session binding changed before dispatch."],
            )
        self._consume_legacy_transport_budget("verification")
        request: dict[str, Any] = {
            "url": item["url"],
            "method": item["method"],
            "headers": {"Authorization": f"Bearer {self.vault.get(session_reference)}"},
            "purpose": purpose,
            "credential_mode": "same_acquired_session",
            "isolate_session_cookies": True,
        }
        if request_context is not None:
            request["request_context"] = request_context
        response = self.transport(request)
        if not isinstance(response, dict):
            raise ValueError("The transport returned an invalid response.")
        return response

    def _session_invalidation_result(
        self,
        hypothesis: Hypothesis,
        *,
        status: str,
        confidence: str,
        reasons: list[str],
        requests_used: int,
        baseline_response: dict[str, Any] | None,
        replay_response: dict[str, Any] | None,
        baseline_protected_field_paths: list[str],
        protected_field_paths: list[str],
        protected_evidence_matched: bool,
        same_session_replayed: bool,
        termination_attempted: bool,
        termination_succeeded: bool,
        cleanup_attempted: bool,
        cleanup_verified: bool,
    ) -> dict[str, Any]:
        """Return schema/hash metadata and booleans; never raw values or headers."""
        normalized_status = (
            status
            if status
            in {
                "verified",
                "rejected",
                "inconclusive",
                "policy_blocked",
                "budget_exhausted",
            }
            else "inconclusive"
        )
        analysis = {
            "status": normalized_status,
            "verified": normalized_status == "verified",
            "confidence": confidence,
            "baseline": (
                response_summary(baseline_response) if baseline_response else None
            ),
            "replay": response_summary(replay_response) if replay_response else None,
            "baseline_protected_field_paths": baseline_protected_field_paths,
            "protected_field_paths": protected_field_paths,
            "protected_evidence_matched": protected_evidence_matched,
            "same_session_replayed": same_session_replayed,
            "termination_attempted": termination_attempted,
            "termination_succeeded": termination_succeeded,
            "cleanup_attempted": cleanup_attempted,
            "cleanup_verified": cleanup_verified,
            "reasons": list(dict.fromkeys(reasons)),
        }
        correlated = correlate_evidence(
            hypothesis,
            analysis,
            requests_used=requests_used,
            policy_approved=bool(self._runtime_binding.get("policy_authorized")),
        )
        if normalized_status in {"policy_blocked", "budget_exhausted"}:
            correlated["status"] = normalized_status
        return {
            **correlated,
            "analysis": analysis,
            "baseline": analysis["baseline"],
            "replay": analysis["replay"],
            "baseline_protected_field_paths": baseline_protected_field_paths,
            "protected_field_paths": protected_field_paths,
            "protected_evidence_matched": protected_evidence_matched,
            "same_session_replayed": same_session_replayed,
            "termination_attempted": termination_attempted,
            "termination_succeeded": termination_succeeded,
            "cleanup_attempted": cleanup_attempted,
            "cleanup_verified": cleanup_verified,
            "runtime_binding": dict(self._runtime_binding),
            "request_budget": self.gate.budget.snapshot(),
        }

    def _mass_assignment_input(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        planned: list[dict[str, Any]],
        inputs: dict[str, Any],
    ) -> tuple[MassAssignmentVerificationInput | None, list[str]]:
        """Validate explicit approval and the immutable own-resource state machine."""
        try:
            approved = MassAssignmentVerificationInput.model_validate(inputs)
        except ValueError:
            return None, [
                "Mass-assignment verification requires only mutation.field, mutation.test_value, optional expected_before, and cleanup_required=true."
            ]

        field = hypothesis.parameter
        reasons: list[str] = []
        if not field or approved.mutation.field != field:
            reasons.append(
                "The approved mutation field must exactly match the generated hypothesis parameter."
            )
        expected_url = hypothesis.endpoint or hypothesis.target
        parsed = urlparse(expected_url)
        matching_own_resources = [
            item
            for item in self.context.objects
            if own_resource_url_matches(expected_url, item.object_id)
        ]
        if (
            not matching_own_resources
            or bool(parsed.query or parsed.fragment)
            or "{" in expected_url
            or "}" in expected_url
        ):
            reasons.append(
                "Mass-assignment verification is restricted to an exact own-resource path explicitly present in the plan and controlled context."
            )
        expected_methods = ["GET", "PATCH", "GET", "PATCH", "GET"]
        expected_mutations = [
            None,
            "documented_field_probe",
            None,
            "restore_before_state",
            None,
        ]
        if (
            len(planned) != 5
            or hypothesis.method != "PATCH"
            or any(
                str(item.get("method") or "").upper() != method
                or item.get("mutation_type") != mutation_type
                or item.get("url") != expected_url
                or item.get("category") != "mass_assignment"
                for item, method, mutation_type in zip(
                    planned, expected_methods, expected_mutations, strict=False
                )
            )
        ):
            reasons.append(
                "Mass-assignment verification requires exactly GET, PATCH, GET, PATCH, GET against the planned own-resource URL."
            )

        account_ids = {
            str(item.get("account_id"))
            for item in planned
            if item.get("account_id") is not None
        }
        owner_ids = {
            str(item.get("object_owner_account_id"))
            for item in planned
            if item.get("object_owner_account_id") is not None
        }
        account_id = next(iter(account_ids), None) if len(account_ids) == 1 else None
        owned_resource_ids = {
            item.object_id
            for item in self.context.objects
            if item.test_owned
            and item.owner_account_id == account_id
            and own_resource_url_matches(expected_url, item.object_id)
        }
        bound_owned_resources = bool(
            set(plan.test_owned_resources)
            & set(self.gate.context.controlled_object_ids)
            & owned_resource_ids
        )
        if (
            account_id is None
            or owner_ids != {account_id}
            or account_id not in plan.controlled_accounts
            or not plan.test_owned_resources_required
            or not bound_owned_resources
            or any(not bool(item.get("test_owned_resource")) for item in planned)
        ):
            reasons.append(
                "The five actions must target one controlled account's explicitly test-owned own-resource state."
            )
        account: ControlledAccount | None = None
        if account_id is not None:
            try:
                account = self.context.account(account_id)
            except KeyError:
                pass
        account_eligibility = (
            self.gate.policy.account_is_eligible(account_id, self.context)
            if account_id is not None
            else None
        )
        if (
            account is None
            or not account_eligibility
            or not account_eligibility.eligible
        ):
            reasons.append(
                "The own-resource account must be controlled and explicitly permitted by policy."
            )
        if (
            not self.gate.policy.credentials_allowed
            or not hypothesis.requires_credentials
        ):
            reasons.append(
                "Mass-assignment verification requires policy-authorized controlled credentials."
            )
        if not self.gate.policy.allow_state_changes:
            reasons.append("State-changing requests are disabled by policy.")
        if "PATCH" not in self.gate.policy.allowed_methods:
            reasons.append("HTTP method PATCH is not explicitly allowed by policy.")
        if not self.gate.policy.require_test_owned_resources:
            reasons.append(
                "Mass-assignment policy must require test-owned resources for state changes."
            )
        if not self.gate.policy.require_cleanup_for_state_changes:
            reasons.append(
                "Mass-assignment policy must require cleanup for state changes."
            )
        cleanup_steps_present = bool(
            plan.cleanup
            and hypothesis.cleanup_required
            and all(
                step.cleanup_required and step.cleanup_steps
                for step in plan.steps
                if step.state_changing
            )
        )
        if not cleanup_steps_present:
            reasons.append(
                "Mass-assignment verification requires an exact restoration and cleanup-verification plan."
            )
        return (None, list(dict.fromkeys(reasons))) if reasons else (approved, [])

    def _execute_mass_assignment(
        self,
        hypothesis: Hypothesis,
        planned: list[dict[str, Any]],
        approved: MassAssignmentVerificationInput,
    ) -> dict[str, Any]:
        """Run one exact reversible five-request own-resource state machine."""
        field = approved.mutation.field
        test_value = approved.mutation.test_value
        requests_used = 0
        mutation_attempted = False
        mutation_accepted = False
        persistence_confirmed = False
        persistence_observed = False
        unchanged_confirmed = False
        cleanup_attempted = False
        cleanup_verified = False
        original_value: Any = None
        before_hash: str | None = None
        after_hash: str | None = None
        restored_hash: str | None = None
        reasons: list[str] = []
        execution_halt_status: str | None = None

        def dispatch(
            item: dict[str, Any],
            *,
            payload: dict[str, JsonScalar] | None = None,
            mutation: bool = False,
            cleanup: bool = False,
        ) -> dict[str, Any]:
            nonlocal cleanup_attempted, mutation_attempted, requests_used
            effective = dict(item)
            account_id = str(effective.get("account_id") or "")
            try:
                account = self.context.account(account_id)
            except KeyError as exc:
                raise _ExecutionHalt(
                    "policy_blocked", ["Unknown controlled account reference."]
                ) from exc
            credential_ref = (
                account.session_reference or account.credential_references.get("token")
            )
            if not credential_ref or not self._vault_contains(credential_ref):
                raise _ExecutionHalt(
                    "policy_blocked",
                    ["A required controlled session is not available."],
                )
            effective["credential_reference_present"] = True
            action = VerificationAction.model_validate(
                {
                    key: value
                    for key, value in effective.items()
                    if key in VerificationAction.model_fields
                }
            )
            decision = self.gate.authorize_action(action)
            if not decision.allowed:
                raise _ExecutionHalt("policy_blocked", decision.reasons)
            try:
                self._consume_legacy_transport_budget(
                    "cleanup" if cleanup else "verification"
                )
            except RequestBudgetExceeded as exc:
                raise _ExecutionHalt("budget_exhausted", [str(exc)]) from exc
            if mutation:
                mutation_attempted = True
            if cleanup:
                cleanup_attempted = True
            requests_used += 1
            request: dict[str, Any] = {
                "url": effective["url"],
                "method": effective["method"],
                "headers": {
                    "Authorization": f"Bearer {self.vault.get(credential_ref)}"
                },
                "purpose": (
                    "cleanup"
                    if cleanup
                    else (
                        "state_mutation"
                        if action.purpose == "state_mutation"
                        else "verification"
                    )
                ),
            }
            if payload is not None:
                request["json"] = payload
            try:
                response = self.transport(request)
            except Exception as exc:
                failure_status, failure_reason = _transport_exception_decision(exc)
                raise _ExecutionHalt(
                    failure_status,
                    [failure_reason],
                ) from exc
            if not isinstance(response, dict):
                raise _ExecutionHalt(
                    "inconclusive", ["The transport returned an invalid response."]
                )
            instability = assess_response_instability([response])
            if instability.unstable:
                raise _ExecutionHalt(
                    "inconclusive",
                    [instability.reason or SERVICE_UNSTABLE_REASON],
                )
            return response

        try:
            before_response = dispatch(planned[0])
        except _ExecutionHalt as exc:
            return self._mass_assignment_result(
                hypothesis,
                status=exc.status,
                reasons=exc.reasons,
                requests_used=requests_used,
                field=field,
                value_type=self._json_type(test_value),
                before_hash=None,
                after_hash=None,
                restored_hash=None,
                mutation_accepted=False,
                persistence_confirmed=False,
                cleanup_attempted=False,
                cleanup_verified=False,
            )

        before_found, actual_before = self._exact_field(
            before_response.get("body"), field
        )
        if not self._successful(before_response) or not before_found:
            return self._mass_assignment_result(
                hypothesis,
                status="inconclusive",
                reasons=[
                    "The authoritative before-state GET did not establish the approved field."
                ],
                requests_used=requests_used,
                field=field,
                value_type=self._json_type(test_value),
                before_hash=None,
                after_hash=None,
                restored_hash=None,
                mutation_accepted=False,
                persistence_confirmed=False,
                cleanup_attempted=False,
                cleanup_verified=False,
            )
        if not self._is_json_scalar(actual_before):
            return self._mass_assignment_result(
                hypothesis,
                status="inconclusive",
                reasons=["The authoritative before-state field is not a JSON scalar."],
                requests_used=requests_used,
                field=field,
                value_type=self._json_type(test_value),
                before_hash=None,
                after_hash=None,
                restored_hash=None,
                mutation_accepted=False,
                persistence_confirmed=False,
                cleanup_attempted=False,
                cleanup_verified=False,
            )
        original_value = actual_before
        before_hash = self._safe_value_hash(original_value)
        if approved.expected_before is not None and not self._exact_value_equal(
            original_value, approved.expected_before[field]
        ):
            return self._mass_assignment_result(
                hypothesis,
                status="inconclusive",
                reasons=[
                    "The supplied expected_before value did not match the authoritative GET; mutation was not sent."
                ],
                requests_used=requests_used,
                field=field,
                value_type=self._json_type(test_value),
                before_hash=before_hash,
                after_hash=None,
                restored_hash=None,
                mutation_accepted=False,
                persistence_confirmed=False,
                cleanup_attempted=False,
                cleanup_verified=False,
            )
        if self._exact_value_equal(original_value, test_value):
            return self._mass_assignment_result(
                hypothesis,
                status="inconclusive",
                reasons=[
                    "The approved test value already matches current state; no mutation was sent."
                ],
                requests_used=requests_used,
                field=field,
                value_type=self._json_type(test_value),
                before_hash=before_hash,
                after_hash=None,
                restored_hash=None,
                mutation_accepted=False,
                persistence_confirmed=False,
                cleanup_attempted=False,
                cleanup_verified=False,
            )

        try:
            mutation_response = dispatch(
                planned[1], payload={field: test_value}, mutation=True
            )
            mutation_accepted = self._successful(mutation_response)
            if mutation_response.get("service_unstable") or mutation_response.get(
                "unexpected_state_change"
            ):
                reasons.append("A configured stop condition was reached.")
            else:
                verification_response = dispatch(planned[2])
                if verification_response.get(
                    "service_unstable"
                ) or verification_response.get("unexpected_state_change"):
                    reasons.append("A configured stop condition was reached.")
                elif self._successful(verification_response):
                    after_found, actual_after = self._exact_field(
                        verification_response.get("body"), field
                    )
                    if after_found:
                        persistence_observed = True
                        after_hash = self._safe_value_hash(actual_after)
                        persistence_confirmed = self._exact_value_equal(
                            actual_after, test_value
                        )
                        unchanged_confirmed = self._exact_value_equal(
                            actual_after, original_value
                        )
                    else:
                        reasons.append(
                            "The independent verification GET did not contain the approved field."
                        )
                else:
                    reasons.append(
                        "The independent verification GET did not return a successful response."
                    )
        except _ExecutionHalt as exc:
            execution_halt_status = exc.status
            reasons.extend(exc.reasons)
        except Exception:
            reasons.append(EXECUTION_FAILURE_REASON)
        finally:
            if mutation_attempted:
                cleanup_patch_accepted = False
                try:
                    cleanup_response = dispatch(
                        planned[3], payload={field: original_value}, cleanup=True
                    )
                    cleanup_patch_accepted = self._successful(cleanup_response)
                    if cleanup_response.get("service_unstable") or cleanup_response.get(
                        "unexpected_state_change"
                    ):
                        cleanup_patch_accepted = False
                except _ExecutionHalt as exc:
                    execution_halt_status = exc.status
                    reasons.extend(exc.reasons)
                except Exception:
                    reasons.append(CLEANUP_UNVERIFIED_REASON)
                try:
                    restored_response = dispatch(planned[4], cleanup=True)
                    restored_found, actual_restored = self._exact_field(
                        restored_response.get("body"), field
                    )
                    if restored_found:
                        restored_hash = self._safe_value_hash(actual_restored)
                    cleanup_verified = bool(
                        cleanup_patch_accepted
                        and self._successful(restored_response)
                        and restored_found
                        and self._exact_value_equal(actual_restored, original_value)
                    )
                except _ExecutionHalt as exc:
                    execution_halt_status = exc.status
                    reasons.extend(exc.reasons)
                except Exception:
                    reasons.append(CLEANUP_UNVERIFIED_REASON)

        cleanup_failed = bool(mutation_attempted and not cleanup_verified)
        security_sensitive_field = bool(
            hypothesis.category == "mass_assignment" and hypothesis.parameter == field
        )
        verified = bool(
            before_hash
            and mutation_accepted
            and persistence_confirmed
            and security_sensitive_field
            and cleanup_attempted
            and cleanup_verified
        )
        if verified:
            status = "verified"
            reasons.append(
                "An independent GET confirmed the approved sensitive-field value and exact cleanup restoration."
            )
        elif cleanup_failed:
            status = "inconclusive"
            reasons.append(CLEANUP_UNVERIFIED_REASON)
        elif execution_halt_status in {"policy_blocked", "budget_exhausted"}:
            status = execution_halt_status
        elif SERVICE_UNSTABLE_REASON in reasons:
            status = "inconclusive"
        elif persistence_observed and unchanged_confirmed:
            status = "rejected"
            reasons.append(
                "The mutation was rejected or ignored; the independent GET did not show the approved value."
            )
        else:
            status = "inconclusive"
            reasons.append(
                "Approved-value persistence could not be independently established."
            )
        return self._mass_assignment_result(
            hypothesis,
            status=status,
            reasons=reasons,
            requests_used=requests_used,
            field=field,
            value_type=self._json_type(test_value),
            before_hash=before_hash,
            after_hash=after_hash,
            restored_hash=restored_hash,
            mutation_accepted=mutation_accepted,
            persistence_confirmed=persistence_confirmed,
            cleanup_attempted=cleanup_attempted,
            cleanup_verified=cleanup_verified,
            mutation_attempted=mutation_attempted,
        )

    def _mass_assignment_result(
        self,
        hypothesis: Hypothesis,
        *,
        status: str,
        reasons: list[str],
        requests_used: int,
        field: str,
        value_type: str,
        before_hash: str | None,
        after_hash: str | None,
        restored_hash: str | None,
        mutation_accepted: bool,
        persistence_confirmed: bool,
        cleanup_attempted: bool,
        cleanup_verified: bool,
        mutation_attempted: bool = False,
    ) -> dict[str, Any]:
        """Return hashes and booleans only; raw state and headers never escape."""
        cleanup_failed = bool(mutation_attempted and not cleanup_verified)
        summary = {
            "field": field,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "restored_hash": restored_hash,
            "type": value_type,
            "mutation_accepted": mutation_accepted,
            "persistence_confirmed": persistence_confirmed,
            "cleanup_attempted": cleanup_attempted,
            "cleanup_verified": cleanup_verified,
        }
        analysis = {
            "status": status,
            "verified": status == "verified",
            "confidence": (
                "high"
                if status == "verified"
                else "medium" if status == "rejected" else "low"
            ),
            **summary,
            "cleanup_failed": cleanup_failed,
            "reasons": list(dict.fromkeys(reasons)),
        }
        correlated = correlate_evidence(
            hypothesis,
            analysis,
            requests_used=requests_used,
            policy_approved=bool(self._runtime_binding.get("policy_authorized")),
        )
        output = {
            **correlated,
            "analysis": analysis,
            "mutation_summary": summary,
            "cleanup_failed": cleanup_failed,
            "owned_object_acquisition": dict(self._acquisition_summary),
            "runtime_binding": dict(self._runtime_binding),
            "request_budget": self.gate.budget.snapshot(),
        }
        if cleanup_failed:
            output["warning"] = (
                "CLEANUP FAILED: exact original state was not confirmed; no further state-changing verification was performed."
            )
        return output

    def _private_recovery_prior(
        self,
        hypothesis: Hypothesis,
        prior_result: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Attach private state only inside the controlled recovery executor."""

        if not isinstance(prior_result, dict):
            return None
        internal = dict(prior_result)
        internal.pop("preserved_challenge", None)
        analysis = internal.get("analysis")
        if isinstance(analysis, dict):
            internal["analysis"] = dict(analysis)
            internal["analysis"].pop("preserved_challenge", None)
        try:
            challenge = self.private_recovery_store.load_for_executor(
                run_reference=self._recovery_run_reference,
                hypothesis_id=hypothesis.hypothesis_id,
            )
        except (OSError, TypeError, ValueError):
            challenge = None
        if isinstance(challenge, dict):
            internal["preserved_challenge"] = challenge
        return internal

    def _prepare_required_sessions(
        self,
        plan: VerificationPlan,
        planned: list[dict[str, Any]],
        *,
        additional_requests: int = 0,
    ) -> dict[str, Any] | None:
        """Materialize every required controlled identity before verification."""
        required_ids = list(
            dict.fromkeys(
                str(item["account_id"]) for item in planned if item.get("account_id")
            )
        )
        pending: list[ControlledAccount] = []
        config = self.context.session_acquisition
        for account_id in required_ids:
            try:
                account = self.context.account(account_id)
            except KeyError:
                return self._stopped(
                    "policy_blocked",
                    0,
                    [
                        "A verification request references an unknown controlled account."
                    ],
                )
            credential_reference = (
                account.session_reference or account.credential_references.get("token")
            )
            if credential_reference:
                if not self._vault_contains(credential_reference):
                    return self._stopped(
                        "policy_blocked",
                        0,
                        ["A required controlled session is not available."],
                    )
                continue
            identity_resolution = (
                resolve_controlled_login_identity(account, config, self.vault)
                if config is not None
                else None
            )
            password_reference = account.credential_references.get("password")
            if (
                config is None
                or identity_resolution is None
                or not identity_resolution.identity_bound
                or not password_reference
                or not self._vault_contains(password_reference)
            ):
                reasons = [
                    (
                        identity_resolution.reason
                        if identity_resolution is not None
                        and identity_resolution.reason
                        else "A required controlled account has no usable session or configured login credentials."
                    )
                ]
                return self._stopped(
                    "policy_blocked",
                    0,
                    reasons,
                )
            pending.append(account)

        total_required = len(planned) + len(pending) + additional_requests
        if total_required > self.gate.budget.remaining:
            return self._stopped(
                "budget_exhausted",
                0,
                [
                    "The shared request budget cannot cover controlled authentication, acquisition, and verification."
                ],
            )
        if not pending or config is None:
            return None
        policy_reasons = self._session_policy_reasons(config, pending)
        if policy_reasons:
            return self._stopped("policy_blocked", 0, policy_reasons)

        acquirer = SessionAcquirer(self.vault, self.gate.budget)
        for account in pending:
            try:
                acquirer.acquire(
                    account,
                    config,
                    self.transport,
                    authorization_check=self.gate.authorize_session_acquisition,
                )
            except RequestBudgetExceeded as exc:
                return self._stopped("budget_exhausted", 0, [str(exc)])
            except SessionAcquisitionPolicyError as exc:
                return self._stopped("policy_blocked", 0, exc.reasons)
            except SessionAcquisitionTransportPolicyError as exc:
                cause = exc.__cause__
                if cause is not None and "budget" in str(cause).casefold():
                    return self._stopped("budget_exhausted", 0, [str(cause)])
                return self._stopped(
                    "policy_blocked", 0, [TRANSPORT_POLICY_BLOCKED_REASON]
                )
            except SessionAuthenticationRejectedError as exc:
                return self._stopped("inconclusive", 0, [str(exc)])
            except SessionTokenFieldAbsentError as exc:
                return self._stopped("inconclusive", 0, [str(exc)])
            except Exception:
                return self._stopped(
                    "inconclusive",
                    0,
                    [transport_failure_reason()],
                )
        return None

    def _bind_session_references(
        self,
        plan: VerificationPlan,
        planned: list[dict[str, Any]],
    ) -> None:
        """Mark only process-local actions backed by a live vault session."""
        supplied = True
        for item in planned:
            account_id = item.get("account_id")
            if not account_id:
                continue
            try:
                account = self.context.account(str(account_id))
            except KeyError:
                item["credential_reference_present"] = False
                supplied = False
                continue
            reference = account.session_reference or account.credential_references.get(
                "token"
            )
            available = bool(reference and self._vault_contains(reference))
            item["credential_reference_present"] = available
            supplied = supplied and available
        plan.credentials_supplied = supplied

    def _bind_controlled_object(
        self,
        plan: VerificationPlan,
        planned: list[dict[str, Any]],
        controlled_object: ControlledObject,
        acquisition_rule: OwnedObjectAcquisition | None,
        *,
        acquisition_required: bool,
    ) -> dict[str, Any] | None:
        """Bind an in-memory owned object into the concrete runtime actions."""
        plan.test_owned_resources = [controlled_object.object_id]
        if not acquisition_required:
            return None
        for item in planned:
            item["test_owned_resource"] = True
            item["object_owner_account_id"] = controlled_object.owner_account_id
            try:
                item["url"], identifier_substituted = self._concrete_owned_object_url(
                    str(item["url"]),
                    controlled_object,
                    acquisition_rule,
                )
            except ValueError as exc:
                return self._stopped("inconclusive", 0, [str(exc)])
            if acquisition_rule is not None and not identifier_substituted:
                return self._stopped(
                    "inconclusive",
                    0,
                    [
                        "The planned resource URL has no unambiguous identifier placeholder for the acquired object."
                    ],
                )
        return None

    def _session_policy_reasons(
        self,
        config: SessionAcquisition,
        accounts: list[ControlledAccount],
    ) -> list[str]:
        acquirer = SessionAcquirer(self.vault, self.gate.budget)
        reasons: list[str] = []
        for account in accounts:
            decision = acquirer.authorize(
                account,
                config,
                self.gate.authorize_session_acquisition,
            )
            reasons.extend(decision.reasons)
        return list(dict.fromkeys(reasons))

    def _vault_contains(self, reference: str) -> bool:
        try:
            return self.vault.contains(reference)
        except RuntimeError:
            return False

    @staticmethod
    def _requires_owned_object(hypothesis: Hypothesis, plan: VerificationPlan) -> bool:
        return bool(
            hypothesis.category in {"bola", "tenant_isolation"}
            and (
                plan.test_owned_resources_required
                or any(step.test_owned_resource_required for step in plan.steps)
            )
        )

    @staticmethod
    def _planned_owner_account_id(
        planned: list[dict[str, Any]],
    ) -> str | None:
        owners = list(
            dict.fromkeys(
                str(item["object_owner_account_id"])
                for item in planned
                if item.get("object_owner_account_id")
            )
        )
        return owners[0] if len(owners) == 1 else None

    def _existing_controlled_object(
        self,
        owner_account_id: str | None,
        resource_ids: set[str],
    ) -> ControlledObject | None:
        return next(
            (
                item
                for item in self.context.objects
                if item.test_owned
                and self.gate.policy.account_is_eligible(
                    item.owner_account_id, self.context
                ).eligible
                and (
                    owner_account_id is None
                    or item.owner_account_id == owner_account_id
                )
                and (not resource_ids or item.object_id in resource_ids)
            ),
            None,
        )

    def _acquisition_rule(
        self, owner_account_id: str | None
    ) -> OwnedObjectAcquisition | None:
        matches = [
            item
            for item in self.context.object_acquisition
            if owner_account_id is None or item.owner_account_id == owner_account_id
        ]
        return matches[0] if len(matches) == 1 else None

    def _object_acquisition_policy_reasons(
        self, config: OwnedObjectAcquisition
    ) -> list[str]:
        reasons: list[str] = []
        if config.method not in {"GET", "HEAD"}:
            reasons.append(
                "Automatic owned-object acquisition permits only GET or HEAD."
            )
        decision = self.gate.policy.authorize_url(
            config.collection_url, method=config.method
        )
        reasons.extend(decision.reasons)
        if self.gate.context.mode != "verify":
            reasons.append("Verify mode is required for owned-object acquisition.")
        if not self.gate.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        owner_eligibility = self.gate.policy.account_is_eligible(
            config.owner_account_id, self.context
        )
        if owner_eligibility.reason:
            reasons.append(owner_eligibility.reason)
        try:
            self.context.account(config.owner_account_id)
        except KeyError:
            reasons.append(
                "Owned-object acquisition references an unknown controlled owner account."
            )
        return list(dict.fromkeys(reasons))

    @staticmethod
    def _separate_accounts(planned: list[dict[str, Any]]) -> bool:
        accounts = {
            str(item["account_id"]) for item in planned if item.get("account_id")
        }
        return len(accounts) >= 2

    def _distinct_tenants(self, planned: list[dict[str, Any]]) -> bool:
        account_ids = list(
            dict.fromkeys(
                str(item["account_id"]) for item in planned if item.get("account_id")
            )
        )
        if len(account_ids) != 2:
            return False
        try:
            tenant_ids = [self.context.account(item).tenant_id for item in account_ids]
        except KeyError:
            return False
        return bool(all(tenant_ids) and tenant_ids[0] != tenant_ids[1])

    def _distinct_privilege_levels(self, planned: list[dict[str, Any]]) -> bool:
        account_ids = list(
            dict.fromkeys(
                str(item["account_id"]) for item in planned if item.get("account_id")
            )
        )
        if len(account_ids) != 2:
            return False
        try:
            ranks = [
                role_privilege_rank(self.context.account(item).role)
                for item in account_ids
            ]
        except KeyError:
            return False
        return bool(
            all(rank is not None for rank in ranks)
            and int(ranks[0] or 0) > int(ranks[1] or 0)
        )

    @staticmethod
    def _empty_acquisition_summary() -> dict[str, Any]:
        return {
            "attempted": False,
            "succeeded": False,
            "owner": None,
            "object_type": None,
            "identifier_present": False,
            "controlled_test_owned_evidence": False,
        }

    @staticmethod
    def _normalized_field(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

    @classmethod
    def _concrete_owned_object_url(
        cls,
        url: str,
        controlled_object: ControlledObject,
        config: OwnedObjectAcquisition | None,
    ) -> tuple[str, bool]:
        placeholders = re.findall(r"\{([^{}]+)\}", url)
        if not placeholders:
            return url, False
        identifier_aliases = {
            cls._normalized_field("id"),
            cls._normalized_field("object_id"),
            cls._normalized_field(f"{controlled_object.object_type}_id"),
        }
        tenant_aliases = {cls._normalized_field("tenant_id")}
        if config is not None:
            identifier_aliases.add(cls._normalized_field(config.identifier_field))
            if config.tenant_field:
                tenant_aliases.add(cls._normalized_field(config.tenant_field))

        normalized = {field: cls._normalized_field(field) for field in placeholders}
        unresolved = [
            field
            for field, name in normalized.items()
            if name not in identifier_aliases and name not in tenant_aliases
        ]
        fallback_identifier = unresolved[0] if len(unresolved) == 1 else None
        identifier_substituted = False

        def substitute(match: re.Match[str]) -> str:
            nonlocal identifier_substituted
            field = match.group(1)
            normalized_field = normalized[field]
            if normalized_field in tenant_aliases:
                tenant_id = controlled_object.tenant_id
                if tenant_id is None:
                    raise ValueError(
                        "The planned tenant placeholder has no controlled tenant value."
                    )
                return quote(tenant_id, safe="")
            if normalized_field in identifier_aliases or field == fallback_identifier:
                identifier_substituted = True
                return quote(controlled_object.object_id, safe="")
            raise ValueError(
                "The planned resource URL contains ambiguous non-object placeholders."
            )

        return re.sub(r"\{([^{}]+)\}", substitute, url), identifier_substituted

    def _stopped(
        self, status: str, requests_used: int, reasons: list[str]
    ) -> dict[str, Any]:
        output = {
            "status": status,
            "requests_used": requests_used,
            "reasons": reasons,
            "owned_object_acquisition": dict(
                getattr(self, "_acquisition_summary", self._empty_acquisition_summary())
            ),
            "runtime_binding": dict(getattr(self, "_runtime_binding", {})),
            "request_budget": self.gate.budget.snapshot(),
        }
        if getattr(self, "_active_category", None) == "session_invalidation":
            output.update(
                {
                    "baseline": None,
                    "replay": None,
                    "baseline_protected_field_paths": [],
                    "protected_field_paths": [],
                    "protected_evidence_matched": False,
                    "same_session_replayed": False,
                    "termination_attempted": False,
                    "termination_succeeded": False,
                    "cleanup_attempted": False,
                    "cleanup_verified": False,
                }
            )
        if getattr(self, "_active_category", None) == "recovery_state_enforcement":
            output.update(
                {
                    "comparison_type": None,
                    "recovery_phase": None,
                    "recovery_run_id": None,
                    "challenge_reference": None,
                    "preserved_challenge": None,
                    "response_summaries": {},
                    "valid_completion_succeeded": False,
                    "comparison_attempted": False,
                    "comparison_accepted": False,
                    "independent_state_confirmed": False,
                    "cleanup_attempted": False,
                    "cleanup_verified": False,
                    "cleanup_failed": False,
                    "recovery_evidence_required": False,
                    "external_evidence_required": False,
                    "external_cleanup_required": False,
                }
            )
        return output

    @staticmethod
    def _prepare_probe_urls(
        hypothesis: Hypothesis,
        planned: list[dict[str, Any]],
        inputs: dict[str, Any],
    ) -> tuple[list[str] | None, list[str]]:
        parameter = hypothesis.parameter
        location = hypothesis.parameter_location
        if type(parameter) is not str or not parameter or location is None:
            return None, [
                "A discovered parameter and exact parameter location are required for an executable probe."
            ]
        supplied_binding = inputs.get("parameter_binding")
        if supplied_binding is None and (
            inputs.get("parameter") is not None
            or inputs.get("parameter_location") is not None
        ):
            supplied_binding = {
                "parameter": inputs.get("parameter"),
                "parameter_location": inputs.get("parameter_location"),
            }
        if supplied_binding is not None and (
            type(supplied_binding) is not dict
            or supplied_binding.get("parameter") != parameter
            or supplied_binding.get("parameter_location") != location
        ):
            return None, [
                "The supplied probe binding does not match the discovered parameter and location."
            ]
        if location != "query":
            return None, [
                f"No typed safe probe adapter is available for parameter location '{location}'."
            ]
        if len(planned) != 3:
            return None, [
                "The bounded probe requires exactly control, probe, and repeated-control requests."
            ]
        values = _PROBE_VALUES[hypothesis.category]
        urls: list[str] = []
        for index, item in enumerate(planned):
            if (
                item.get("parameter") != parameter
                or item.get("parameter_location") != location
                or type(item.get("url")) is not str
            ):
                return None, [
                    "The planned request is not bound to the discovered parameter and location."
                ]
            try:
                urls.append(
                    ControlledVerificationExecutor._query_variant(
                        item["url"], parameter, values[index % 2]
                    )
                )
            except ValueError:
                return None, [
                    "The query parameter could not be mutated exactly and unambiguously."
                ]
        return urls, []

    @staticmethod
    def _query_variant(url: str, field: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if sum(1 for name, _ in pairs if name == field) > 1:
            raise ValueError("duplicate bound query parameter")
        replaced = False
        output: list[tuple[str, str]] = []
        for name, current in pairs:
            if name == field:
                output.append((name, value))
                replaced = True
            else:
                output.append((name, current))
        if not replaced:
            output.append((field, value))
        mutated = urlunparse(parsed._replace(query=urlencode(output)))
        mutated_pairs = parse_qsl(urlparse(mutated).query, keep_blank_values=True)
        if [item for item in mutated_pairs if item[0] == field] != [(field, value)]:
            raise ValueError("query parameter mutation was not exact")
        return mutated

    @staticmethod
    def _exact_field(value: Any, field: str) -> tuple[bool, Any]:
        if isinstance(value, dict) and field in value:
            return True, value[field]
        return False, None

    @staticmethod
    def _is_json_scalar(value: Any) -> bool:
        return (
            value is None
            or isinstance(value, (str, bool, int, float))
            and not (isinstance(value, float) and not math.isfinite(value))
        )

    @staticmethod
    def _exact_value_equal(left: Any, right: Any) -> bool:
        return type(left) is type(right) and left == right

    @staticmethod
    def _successful(response: dict[str, Any]) -> bool:
        status_code = response.get("status_code")
        return (
            isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and 200 <= status_code < 300
        )

    @staticmethod
    def _safe_value_hash(value: Any) -> str:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + sha256(rendered.encode("utf-8")).hexdigest()

    @staticmethod
    def _json_type(value: JsonScalar) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, str):
            return "string"
        return "number"

    @staticmethod
    def _analyze(
        hypothesis: Hypothesis,
        responses: list[dict[str, Any]],
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        if len(responses) < 2:
            return {
                "status": "inconclusive",
                "verified": False,
                "confidence": "low",
                "reasons": ["At least two controlled observations are required."],
            }
        instability = assess_response_instability(responses)
        if instability.unstable:
            return {
                "status": "inconclusive",
                "verified": False,
                "confidence": "low",
                "service_unstable": True,
                "reasons": [instability.reason or SERVICE_UNSTABLE_REASON],
            }
        if hypothesis.category in {
            "bola",
            "tenant_isolation",
            "graphql_object_authorization",
            "graphql_mutation_authorization",
            "upload_ownership",
        }:
            return analyze_cross_account_access(
                responses[0],
                responses[1],
                object_identifier=inputs.get("object_identifier"),
                ownership_confirmed=inputs.get("ownership_confirmed") is True,
                separate_accounts_confirmed=(
                    inputs.get("separate_accounts_confirmed") is True
                ),
                protected_fields=inputs.get("protected_fields"),
                protected_data_confirmed=(
                    inputs.get("protected_data_confirmed") is True
                ),
                tenant_identifier=inputs.get("tenant_identifier"),
                distinct_tenants_confirmed=(
                    inputs.get("distinct_tenants_confirmed") is True
                ),
                tenant_isolation=hypothesis.category == "tenant_isolation",
            )
        if hypothesis.category in {
            "vertical_authorization",
            "graphql_field_authorization",
        }:
            return analyze_role_authorization(
                responses[0],
                responses[1],
                separate_accounts_confirmed=(
                    inputs.get("separate_accounts_confirmed") is True
                ),
                distinct_roles_confirmed=(
                    inputs.get("distinct_roles_confirmed") is True
                ),
                protected_fields=inputs.get("protected_fields"),
                protected_data_confirmed=(
                    inputs.get("protected_data_confirmed") is True
                ),
                protected_functionality_confirmed=(
                    inputs.get("protected_functionality_confirmed") is True
                ),
            )
        if hypothesis.category == "authentication_enforcement":
            return analyze_authentication_enforcement(
                responses[0],
                responses[1],
                protected_fields=inputs.get("protected_fields"),
                protected_functionality_confirmed=(
                    inputs.get("protected_functionality_confirmed") is True
                ),
            )
        if hypothesis.category in {
            "sql_injection",
            "command_injection",
            "path_traversal",
        }:
            summaries = [response_summary(item) for item in responses]
            control_repeatable = bool(
                len(summaries) >= 3
                and summaries[0]["status_code"] == summaries[2]["status_code"]
                and summaries[0]["body_hash"] == summaries[2]["body_hash"]
            )
            probe_different = bool(
                len(summaries) >= 2
                and summaries[0]["body_hash"] != summaries[1]["body_hash"]
            )
            successful_observations = bool(
                len(responses) >= 3
                and all(
                    type(item.get("status_code")) is int
                    and 200 <= item["status_code"] < 300
                    for item in responses[:3]
                )
            )
            control_texts = (
                str(responses[0].get("body") or ""),
                str(responses[2].get("body") or ""),
            )
            probe_text = str(responses[1].get("body") or "")
            if hypothesis.category == "command_injection":
                execution_marker_derived = bool(
                    COMMAND_EXECUTION_MARKER not in COMMAND_PROBE_VALUE
                    and COMMAND_EXECUTION_MARKER in probe_text
                    and all(
                        COMMAND_EXECUTION_MARKER not in item for item in control_texts
                    )
                    and COMMAND_PROBE_VALUE not in probe_text
                )
                proof = bool(
                    successful_observations
                    and control_repeatable
                    and probe_different
                    and execution_marker_derived
                )
            elif hypothesis.category == "path_traversal":
                fixture_resolution_evidence = bool(
                    TRAVERSAL_FIXTURE_MARKER not in TRAVERSAL_PROBE_VALUE
                    and TRAVERSAL_FIXTURE_MARKER in probe_text
                    and all(
                        TRAVERSAL_FIXTURE_MARKER not in item for item in control_texts
                    )
                    and TRAVERSAL_PROBE_VALUE not in probe_text
                )
                proof = bool(
                    control_repeatable
                    and probe_different
                    and fixture_resolution_evidence
                    and successful_observations
                )
            else:
                # The existing harmless differential cannot independently prove
                # SQL evaluation. A caller assertion and a reflected/hash-only
                # difference therefore remain inconclusive.
                proof = False
            return {
                "status": "verified" if proof else "inconclusive",
                "verified": proof,
                "confidence": "high" if proof else "low",
                "control_repeatable": control_repeatable,
                "probe_different": probe_different,
                "successful_observations": successful_observations,
                "parameter_binding_confirmed": True,
                "reflection_excluded": bool(
                    hypothesis.category == "command_injection"
                    and COMMAND_PROBE_VALUE not in probe_text
                    or hypothesis.category == "path_traversal"
                    and TRAVERSAL_PROBE_VALUE not in probe_text
                    or hypothesis.category == "sql_injection"
                    and SQL_PROBE_VALUE not in probe_text
                ),
                "reasons": [
                    (
                        "Stable controls and a non-reflected server-derived safe marker were observed."
                        if proof
                        else "The bounded lab probe did not produce independent, non-reflected category-specific proof."
                    )
                ],
            }
        return {
            "status": "inconclusive",
            "verified": False,
            "confidence": "low",
            "reasons": [
                "The bounded requests completed, but this category requires category-specific controlled proof."
            ],
        }
