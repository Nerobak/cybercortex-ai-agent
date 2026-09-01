"""Deterministic Phase 2 execution gate; model output never reaches this decision."""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, StrictBool, StrictInt, field_validator

from agent_core.agent_models import (
    AuthorizationAction,
    ParameterLocation,
    PolicyDecision,
    RiskLevel,
    StrictModel,
    TransportRequestContext,
    VerificationPlan,
)
from agent_core.controlled_context import (
    SUPPORTED_LOGIN_IDENTITY_FIELDS,
    SessionAcquisitionAction,
    SessionAcquisitionDecision,
)
from agent_core.policy import AssessmentPolicy
from agent_core.rate_limit_enforcement import MAX_RATE_LIMIT_ATTEMPTS
from agent_core.request_budget import RequestBudget

ExecutionMode = Literal["observe", "plan", "verify"]
TargetClass = Literal["external", "local_range", "dedicated_lab"]

DESTRUCTIVE_METHODS = {"DELETE"}
FINANCIAL_WORDS = {
    "payment",
    "pay",
    "transfer",
    "withdraw",
    "withdrawal",
    "purchase",
    "charge",
    "refund",
}
PRIVILEGE_WORDS = {"promote", "privilege", "grant_admin", "make_admin"}
PROHIBITED_TECHNIQUES = {
    "denial_of_service",
    "race_flood",
    "brute_force",
    "uncontrolled_command_execution",
    "malware",
    "shell_upload",
}
LAB_ONLY_CATEGORIES = {
    "sql_injection",
    "command_injection",
    "path_traversal",
    "file_upload_validation",
    "upload_ownership",
}


class VerificationAction(AuthorizationAction):
    category: str
    purpose: Literal[
        "object_acquisition",
        "verification",
        "state_mutation",
        "session_termination",
    ] = "verification"
    request_count: StrictInt = Field(default=1, ge=1, le=10)
    account_id: str | None = None
    object_owner_account_id: str | None = None
    test_owned_resource: StrictBool = False
    credential_reference_present: StrictBool = False
    mutation_type: str | None = None
    side_effect_risk: RiskLevel = RiskLevel.low
    technique: str | None = None
    parameter: str | None = None
    parameter_location: ParameterLocation | None = None
    replay: StrictBool = False
    request_role: (
        Literal["authenticated_baseline", "unauthenticated_comparison"] | None
    ) = None
    workflow_surface: (
        Literal[
            "session_creation",
            "authenticated_resource",
            "session_termination",
        ]
        | None
    ) = None


class SessionTerminationAction(AuthorizationAction):
    """Narrow authorization input for one typed session-invalidation logout."""

    purpose: Literal["session_termination"] = "session_termination"
    generated_by: Literal["SessionInvalidationExecutor"] = "SessionInvalidationExecutor"
    category: Literal["session_invalidation"] = "session_invalidation"
    account_id: str
    account_controlled: StrictBool
    same_session_bound: StrictBool = True
    workflow_url: str
    workflow_method: str
    request_count: StrictInt = Field(default=1, ge=1, le=1)

    @field_validator("workflow_method")
    @classmethod
    def normalize_workflow_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("workflow_method must be a conventional HTTP method token")
        return method


class SessionTerminationDecision(PolicyDecision):
    """Secret-free transport authorization for the exact logout request."""

    request_context: TransportRequestContext


class RecoveryStateAction(AuthorizationAction):
    """One immutable action in the controlled recovery workflow."""

    purpose: Literal["state_mutation"] = "state_mutation"
    generated_by: Literal["RecoveryStateEnforcementExecutor"] = (
        "RecoveryStateEnforcementExecutor"
    )
    category: Literal["recovery_state_enforcement"] = "recovery_state_enforcement"
    workflow_phase: Literal["recovery_start", "valid_completion", "reuse_comparison"]
    account_id: str
    account_controlled: StrictBool
    account_test_owned: StrictBool = True
    workflow_url: str
    workflow_method: Literal["POST"] = "POST"
    comparison_type: Literal["reused_same_challenge_and_code"]
    researcher_supplied_artifact: StrictBool = True
    runtime_challenge_bound: StrictBool
    cleanup_required: StrictBool = True
    attempt_count: StrictInt = Field(default=1, ge=1, le=1)
    request_count: StrictInt = Field(default=1, ge=1, le=1)


class RecoveryStateDecision(PolicyDecision):
    """Secret-free authorization for one exact recovery workflow request."""


class RateLimitVerificationAction(AuthorizationAction):
    """Complete authorization intent for one bounded sequential login sequence."""

    purpose: Literal["rate_limit_verification"] = "rate_limit_verification"
    generated_by: Literal["AuthenticationLoginRateLimitExecutor"] = (
        "AuthenticationLoginRateLimitExecutor"
    )
    category: Literal["rate_limit_enforcement"] = "rate_limit_enforcement"
    mode: Literal["authentication_login_rate_limit"]
    account_id: str
    account_controlled: StrictBool
    credential_references_present: StrictBool
    workflow_url: str
    workflow_method: Literal["POST"] = "POST"
    workflow_surface: Literal["session_creation", "credential_submission"]
    attempts: StrictInt = Field(ge=1, le=MAX_RATE_LIMIT_ATTEMPTS)
    expected_control_type: Literal["throttle_or_block_within_attempts"]
    expected_within_attempts: StrictInt = Field(ge=1, le=MAX_RATE_LIMIT_ATTEMPTS)
    request_count: StrictInt = Field(ge=3, le=MAX_RATE_LIMIT_ATTEMPTS + 2)
    concurrency: StrictInt = Field(default=1, ge=1, le=1)


class RateLimitVerificationDecision(PolicyDecision):
    """Secret-free transport authorization for an exact bounded login sequence."""

    request_context: TransportRequestContext


class Phase2PolicyContext(StrictModel):
    mode: ExecutionMode = "observe"
    target_class: TargetClass = "external"
    controlled_account_ids: list[str] = Field(default_factory=list, max_length=20)
    controlled_object_ids: list[str] = Field(default_factory=list, max_length=100)
    object_acquisition_owner_ids: list[str] = Field(default_factory=list, max_length=20)
    session_acquisition_url: str | None = None
    session_acquisition_method: str | None = None
    replay_enabled: StrictBool = False

    @field_validator("session_acquisition_method")
    @classmethod
    def normalize_session_method(cls, value: str | None) -> str | None:
        return value.strip().upper() if value else None


class DeterministicPolicyGate:
    def __init__(
        self,
        policy: AssessmentPolicy,
        context: Phase2PolicyContext,
        budget: RequestBudget,
    ) -> None:
        self.policy = policy
        self.context = context
        self.budget = budget

    def authorize_session_acquisition(
        self, action: SessionAcquisitionAction
    ) -> SessionAcquisitionDecision:
        """Authorize only SessionAcquirer intent for the exact login rule."""
        reasons: list[str] = []
        method = action.method.upper()
        base = self.policy._authorize_url_base(action.url, method=method)
        reasons.extend(base.reasons)
        if self.context.mode != "verify":
            reasons.append("Verify mode is required for controlled authentication.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        account_eligibility = self.policy.account_is_eligible(
            action.account_id,
            self.context,
            account_controlled=action.account_controlled,
        )
        if account_eligibility.reason:
            reasons.append(account_eligibility.reason)
        if account_eligibility.reason_code == "not_controlled":
            reasons.append("A session was requested for a non-controlled account.")
        elif account_eligibility.reason_code == "not_allowed":
            reasons.append("The acting account is not authorized by policy.")
        if (
            action.identity_field.strip().casefold()
            not in SUPPORTED_LOGIN_IDENTITY_FIELDS
        ):
            reasons.append("Unsupported session-acquisition identity field.")
        if not action.identity_bound:
            reasons.append("Controlled login identity is unavailable.")
        if not action.credential_reference_present:
            reasons.append("Controlled login credential references are required.")
        configured_url = self.context.session_acquisition_url
        configured_method = self.context.session_acquisition_method
        if configured_url is None or configured_method is None:
            reasons.append("Controlled session acquisition is not configured.")
        else:
            if action.url != configured_url:
                reasons.append(
                    "The login URL does not exactly match the configured session acquisition endpoint."
                )
            if method != configured_method:
                reasons.append(
                    "The login method does not exactly match the configured session acquisition method."
                )
        if action.follow_redirects:
            reasons.append("Controlled session acquisition cannot follow redirects.")
        if action.request_count > self.budget.remaining:
            reasons.append("The shared request budget would be exceeded.")
        unique_reasons = list(dict.fromkeys(reasons))
        configured_endpoint_match = bool(
            configured_url is not None
            and configured_method is not None
            and action.url == configured_url
            and method == configured_method
        )
        return SessionAcquisitionDecision(
            allowed=not unique_reasons,
            reasons=unique_reasons,
            matched_rule=base.matched_rule,
            remaining_request_budget=self.budget.remaining,
            request_context=TransportRequestContext(
                purpose="session_acquisition",
                policy_authorized=not unique_reasons,
                configured_url=configured_url,
                configured_method=configured_method,
                configured_endpoint_match=configured_endpoint_match,
                controlled_account_id=action.account_id,
                account_controlled=action.account_controlled,
                account_policy_authorized=account_eligibility.eligible,
            ),
        )

    def authorize_session_termination(
        self, action: SessionTerminationAction
    ) -> SessionTerminationDecision:
        """Authorize only the exact typed logout surface for one controlled session."""
        reasons: list[str] = []
        method = action.method.upper()
        base = self.policy._authorize_url_base(action.url, method=method)
        reasons.extend(base.reasons)
        if self.context.mode != "verify":
            reasons.append("Verify mode is required for session termination.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if not self.policy.allow_state_changes:
            reasons.append("State-changing session termination is disabled by policy.")
        if method not in {"DELETE", "POST"}:
            reasons.append("Session termination permits only POST or DELETE.")
        account_eligibility = self.policy.account_is_eligible(
            action.account_id,
            self.context,
            account_controlled=action.account_controlled,
        )
        if account_eligibility.reason:
            reasons.append(account_eligibility.reason)
        if action.url != action.workflow_url or method != action.workflow_method:
            reasons.append(
                "The termination request does not exactly match the typed workflow surface."
            )
        if action.request_count > self.budget.remaining:
            reasons.append("The shared request budget would be exceeded.")
        unique_reasons = list(dict.fromkeys(reasons))
        endpoint_match = bool(
            action.url == action.workflow_url and method == action.workflow_method
        )
        return SessionTerminationDecision(
            allowed=not unique_reasons,
            reasons=unique_reasons,
            matched_rule=base.matched_rule,
            remaining_request_budget=self.budget.remaining,
            request_context=TransportRequestContext(
                purpose="session_termination",
                policy_authorized=not unique_reasons,
                configured_url=action.workflow_url,
                configured_method=action.workflow_method,
                configured_endpoint_match=endpoint_match,
                controlled_account_id=action.account_id,
                account_controlled=action.account_controlled,
                account_policy_authorized=account_eligibility.eligible,
                workflow_category="session_invalidation",
                generated_by="SessionInvalidationExecutor",
            ),
        )

    def authorize_recovery_state_action(
        self, action: RecoveryStateAction
    ) -> RecoveryStateDecision:
        """Authorize one POST in the exact bounded controlled recovery sequence."""
        reasons: list[str] = []
        method = action.method.upper()
        base = self.policy._authorize_url_base(action.url, method=method)
        reasons.extend(base.reasons)
        if self.context.mode != "verify":
            reasons.append("Verify mode is required for recovery execution.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if not self.policy.allow_state_changes:
            reasons.append("State-changing recovery requests are disabled by policy.")
        if not self.policy.require_cleanup_for_state_changes:
            reasons.append("Recovery execution requires mandatory cleanup policy.")
        if method != "POST":
            reasons.append("Recovery execution permits only POST.")
        if not action.account_test_owned:
            reasons.append(
                "Recovery execution requires one test-owned controlled account."
            )
        account_eligibility = self.policy.account_is_eligible(
            action.account_id,
            self.context,
            account_controlled=action.account_controlled,
        )
        if account_eligibility.reason:
            reasons.append(account_eligibility.reason)
        if action.url != action.workflow_url or method != action.workflow_method:
            reasons.append(
                "The recovery request does not exactly match its typed workflow surface."
            )
        if (
            action.workflow_phase != "recovery_start"
            and not action.runtime_challenge_bound
        ):
            reasons.append(
                "Recovery completion requires the challenge issued by this execution."
            )
        if action.attempt_count != 1 or not action.researcher_supplied_artifact:
            reasons.append(
                "Recovery artifacts must be explicitly supplied and used once."
            )
        if not action.cleanup_required:
            reasons.append("Recovery execution requires cleanup_required=true.")
        if action.request_count > self.budget.remaining:
            reasons.append("The shared request budget would be exceeded.")
        return RecoveryStateDecision(
            allowed=not reasons,
            reasons=list(dict.fromkeys(reasons)),
            matched_rule=base.matched_rule,
            remaining_request_budget=self.budget.remaining,
        )

    def authorize_rate_limit_verification(
        self, action: RateLimitVerificationAction
    ) -> RateLimitVerificationDecision:
        """Authorize a whole N+2 sequence without using generic POST permission."""
        reasons: list[str] = []
        method = action.method.upper()
        base = self.policy._authorize_url_base(action.url, method=method)
        reasons.extend(base.reasons)
        if self.context.mode != "verify":
            reasons.append("Verify mode is required for rate-limit verification.")
        if not self.policy.allow_bounded_rate_limit_verification:
            reasons.append(
                "Explicit bounded rate-limit verification is disabled by policy."
            )
        if self.policy.max_rate_limit_attempts < 1:
            reasons.append("Policy max_rate_limit_attempts must be positive.")
        if action.attempts > self.policy.max_rate_limit_attempts:
            reasons.append("The requested attempts exceed the policy maximum.")
        if action.attempts > MAX_RATE_LIMIT_ATTEMPTS:
            reasons.append("The requested attempts exceed the implementation cap.")
        if action.expected_within_attempts > action.attempts:
            reasons.append("The configured expectation exceeds the attempt count.")
        if action.request_count != action.attempts + 2:
            reasons.append(
                "Rate-limit request accounting must equal attempts plus two."
            )
        if method != "POST" or action.workflow_method != "POST":
            reasons.append("Login rate-limit verification permits only POST.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if self.context.controlled_account_ids != [action.account_id]:
            reasons.append(
                "Rate-limit verification requires exactly one controlled account."
            )
        account_eligibility = self.policy.account_is_eligible(
            action.account_id,
            self.context,
            account_controlled=action.account_controlled,
        )
        if account_eligibility.reason:
            reasons.append(account_eligibility.reason)
        if not action.credential_references_present:
            reasons.append("Vaulted identity and original password are required.")
        configured_url = self.context.session_acquisition_url
        configured_method = self.context.session_acquisition_method
        endpoint_match = bool(
            configured_url is not None
            and configured_method == "POST"
            and action.url == configured_url == action.workflow_url
            and method == configured_method == action.workflow_method
        )
        if not endpoint_match:
            reasons.append(
                "The request does not exactly match the configured classified login surface."
            )
        if action.concurrency != 1:
            reasons.append("Rate-limit verification must be sequential.")
        if action.request_count > self.budget.remaining:
            reasons.append("The shared request budget cannot cover the full sequence.")
        unique_reasons = list(dict.fromkeys(reasons))
        policy_authorized = not unique_reasons
        return RateLimitVerificationDecision(
            allowed=policy_authorized,
            reasons=unique_reasons,
            matched_rule=base.matched_rule,
            remaining_request_budget=self.budget.remaining,
            request_context=TransportRequestContext(
                purpose="rate_limit_verification",
                policy_authorized=policy_authorized,
                configured_url=configured_url,
                configured_method=configured_method,
                configured_endpoint_match=endpoint_match,
                controlled_account_id=action.account_id,
                account_controlled=action.account_controlled,
                account_policy_authorized=account_eligibility.eligible,
                workflow_category="rate_limit_enforcement",
                generated_by="AuthenticationLoginRateLimitExecutor",
                bounded_attempt_limit=action.attempts,
                bounded_total_requests=action.request_count,
            ),
        )

    def authorize_action(
        self,
        action: VerificationAction,
        *,
        allow_deferred_object_acquisition: bool = False,
    ) -> PolicyDecision:
        reasons: list[str] = []
        method = action.method.upper()
        parsed = urlparse(action.url)
        path_words = {
            word.lower().replace("-", "_") for word in parsed.path.split("/") if word
        }
        base = self.policy.authorize_url(action.url, method=method)
        reasons.extend(base.reasons)
        is_application_mutation = bool(
            action.purpose == "state_mutation"
            or method in {"POST", "PUT", "PATCH", "DELETE"}
        )
        if action.purpose == "session_termination":
            reasons.append(
                "Session termination requires the typed session-invalidation policy gate."
            )
        if action.purpose == "state_mutation" and not self.policy.allow_state_changes:
            reasons.append("State-changing requests are disabled by policy.")
        if action.purpose == "object_acquisition" and method not in {"GET", "HEAD"}:
            reasons.append("Object acquisition permits only GET or HEAD.")
        if self.context.mode != "verify":
            reasons.append("Verify mode is required for network execution.")
        if method in DESTRUCTIVE_METHODS:
            reasons.append("Destructive HTTP methods are blocked.")
        if action.technique in PROHIBITED_TECHNIQUES:
            reasons.append("The requested technique is prohibited.")
        if any(word.startswith(tuple(FINANCIAL_WORDS)) for word in path_words):
            reasons.append("Financial and transfer operations are blocked.")
        if path_words & PRIVILEGE_WORDS:
            reasons.append("Privilege-changing operations are blocked.")
        if action.request_count > self.budget.remaining:
            reasons.append("The shared request budget would be exceeded.")
        if action.account_id:
            account_eligibility = self.policy.account_is_eligible(
                action.account_id, self.context
            )
            if account_eligibility.reason:
                reasons.append(account_eligibility.reason)
            if not action.credential_reference_present:
                reasons.append("A vault credential reference is required.")
        if action.object_owner_account_id:
            owner_eligibility = self.policy.account_is_eligible(
                action.object_owner_account_id, self.context
            )
            if not owner_eligibility.eligible:
                reasons.append("Third-party object access is blocked.")
            deferred_ownership = bool(
                allow_deferred_object_acquisition
                and action.object_owner_account_id
                in self.context.object_acquisition_owner_ids
            )
            if not action.test_owned_resource and not deferred_ownership:
                reasons.append("The object must be researcher-controlled.")
        if action.replay and not (self.context.replay_enabled and action.replay):
            reasons.append("Replay is not explicitly enabled.")
        if (
            action.category in LAB_ONLY_CATEGORIES
            and self.context.target_class
            not in {
                "local_range",
                "dedicated_lab",
            }
        ):
            reasons.append(
                "This verification category is restricted to an explicit lab."
            )
        if is_application_mutation and method != "DELETE":
            if action.side_effect_risk in {RiskLevel.high, RiskLevel.prohibited}:
                reasons.append("High-risk mutations are blocked.")
            if self.context.target_class == "external":
                reasons.append(
                    "Automatic state changes are blocked on external targets."
                )
            if not action.test_owned_resource and action.category not in {
                "authentication_enforcement",
                "session_invalidation",
                "jwt_enforcement",
            }:
                reasons.append("Mutations require a test-owned resource.")
        return PolicyDecision(
            allowed=not reasons,
            reasons=list(dict.fromkeys(reasons)),
            matched_rule=base.matched_rule,
            remaining_request_budget=self.budget.remaining,
        )

    def authorize_plan(self, plan: VerificationPlan) -> PolicyDecision:
        reasons: list[str] = []
        base = self.policy.authorize_plan(plan)
        reasons.extend(base.reasons)
        if plan.estimated_requests > self.budget.remaining:
            reasons.append("The plan exceeds the shared remaining request budget.")
        for step in plan.steps:
            requests = step.metadata.get("requests") or []
            for item in requests:
                try:
                    action = VerificationAction.model_validate(item)
                except ValueError as exc:
                    reasons.append(f"{step.step_id}: invalid action: {exc}")
                    continue
                result = self.authorize_action(
                    action, allow_deferred_object_acquisition=True
                )
                reasons.extend(f"{step.step_id}: {reason}" for reason in result.reasons)
        return PolicyDecision(
            allowed=not reasons,
            reasons=list(dict.fromkeys(reasons)),
            remaining_request_budget=self.budget.remaining,
        )
