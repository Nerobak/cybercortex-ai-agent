"""Typed contracts shared by CyberCortex planning and verification.

The language model may propose these objects, but deterministic code validates
them before a tool is selected or any network request is sent.
"""

from __future__ import annotations

from enum import Enum
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", validate_assignment=True, populate_by_name=True
    )


class RiskLevel(str, Enum):
    passive = "passive"
    low = "low"
    moderate = "moderate"
    high = "high"
    prohibited = "prohibited"


class HypothesisStatus(str, Enum):
    proposed = "proposed"
    policy_blocked = "policy_blocked"
    ready = "ready"
    testing = "testing"
    needs_manual_verification = "needs_manual_verification"
    awaiting_controlled_evidence = "awaiting_controlled_evidence"
    verification_pending_cleanup = "verification_pending_cleanup"
    cleanup_failed = "cleanup_failed"
    verified = "verified"
    rejected = "rejected"
    inconclusive = "inconclusive"


ParameterLocation = Literal[
    "path",
    "query",
    "header",
    "cookie",
    "form",
    "json",
    "multipart",
    "graphql_variable",
    "graphql_argument",
]

ActionPurpose = Literal[
    "session_acquisition",
    "session_termination",
    "rate_limit_verification",
    "object_acquisition",
    "verification",
    "state_mutation",
]

TransportRequestPurpose = Literal[
    "discovery",
    "oast",
    "session_acquisition",
    "session_termination",
    "rate_limit_verification",
    "owned_object_acquisition",
    "verification",
    "state_mutation",
    "cleanup",
]


class TransportRequestContext(StrictModel):
    """Secret-free authorization metadata passed to the shared HTTP layer."""

    purpose: TransportRequestPurpose
    policy_authorized: bool = False
    configured_url: str | None = None
    configured_method: str | None = None
    configured_endpoint_match: bool = False
    controlled_account_id: str | None = None
    account_controlled: bool = False
    account_policy_authorized: bool = False
    workflow_category: (
        Literal["session_invalidation", "rate_limit_enforcement"] | None
    ) = None
    generated_by: (
        Literal[
            "SessionInvalidationExecutor",
            "AuthenticationLoginRateLimitExecutor",
        ]
        | None
    ) = None
    bounded_attempt_limit: int | None = Field(default=None, ge=1, le=5)
    bounded_total_requests: int | None = Field(default=None, ge=3, le=7)
    rate_limit_sequence_role: (
        Literal["valid_baseline", "invalid_password_attempt", "valid_final"] | None
    ) = None
    rate_limit_sequence_position: int | None = Field(default=None, ge=0, le=6)

    @field_validator("configured_method")
    @classmethod
    def normalize_configured_method(cls, value: str | None) -> str | None:
        if value is None:
            return None
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError(
                "configured_method must be a conventional HTTP method token"
            )
        return method


class AuthorizationAction(StrictModel):
    """Semantic request intent evaluated before any network execution."""

    purpose: ActionPurpose
    url: str
    method: str = "GET"

    @field_validator("method")
    @classmethod
    def normalize_action_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("method must be a conventional HTTP method token")
        return method


def stable_identifier(prefix: str, *parts: Any) -> str:
    material = "\x1f".join(str(part or "") for part in parts)
    return f"{prefix}_{sha256(material.encode('utf-8')).hexdigest()[:16]}"


class EvidenceRequirement(StrictModel):
    kind: Literal[
        "observation",
        "response_differential",
        "controlled_identity_differential",
        "controlled_canary",
        "oast_callback",
        "workflow_transition",
        "manual_confirmation",
    ]
    minimum_repetitions: int = Field(default=1, ge=1, le=5)
    description: str = Field(min_length=3, max_length=500)


class Hypothesis(StrictModel):
    hypothesis_id: str
    category: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=3, max_length=240)
    rationale: str = Field(min_length=3, max_length=2000)
    target: str
    endpoint: str | None = None
    method: str = "GET"
    parameter: str | None = None
    parameter_location: ParameterLocation | None = None
    confidence: Literal["low", "medium", "high"] = "low"
    priority: int = Field(default=50, ge=0, le=100)
    risk: RiskLevel = RiskLevel.low
    proposed_tools: list[str] = Field(default_factory=list, max_length=12)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    evidence_requirements: list[EvidenceRequirement] = Field(
        default_factory=list, max_length=12
    )
    requires_credentials: bool = False
    requires_explicit_authorization: bool = True
    state_changing: bool = False
    cleanup_required: bool = False
    prohibited_techniques: list[str] = Field(default_factory=list, max_length=20)
    status: HypothesisStatus = HypothesisStatus.proposed
    metadata: dict[str, Any] = Field(default_factory=dict)
    target_surface: dict[str, Any] = Field(default_factory=dict)
    evidence_basis: list[dict[str, Any] | str] = Field(
        default_factory=list, max_length=50
    )
    impact_if_confirmed: str = "Security impact requires controlled verification."
    required_context: list[str] = Field(default_factory=list, max_length=20)
    safe_verification_possible: bool = False
    limitations: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("method must be a conventional HTTP method token")
        return method


class VerificationStep(StrictModel):
    step_id: str
    name: str
    tool: str
    input_ref: str | None = None
    prerequisites: list[str] = Field(default_factory=list, max_length=20)
    risk: RiskLevel = RiskLevel.low
    network: bool = False
    method: str | None = None
    request_cost: int = Field(default=0, ge=0, le=100)
    requires_credentials: bool = False
    requires_explicit_authorization: bool = True
    state_changing: bool = False
    test_owned_resource_required: bool = False
    cleanup_required: bool = False
    cleanup_steps: list[str] = Field(default_factory=list, max_length=20)
    expected_evidence: list[EvidenceRequirement] = Field(
        default_factory=list, max_length=12
    )
    stop_conditions: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def normalize_optional_method(cls, value: str | None) -> str | None:
        return value.strip().upper() if value else None


class VerificationPlan(StrictModel):
    plan_id: str
    hypothesis_id: str
    target: str
    profile: Literal["baseline", "deep", "authenticated", "intrusive"]
    steps: list[VerificationStep] = Field(min_length=1, max_length=40)
    request_budget: int = Field(default=20, ge=0, le=500)
    authorization_confirmed: bool = False
    credentials_supplied: bool = False
    controlled_accounts: list[str] = Field(default_factory=list, max_length=10)
    test_owned_resources: list[str] = Field(default_factory=list, max_length=50)
    test_owned_resources_required: bool = False
    stop_on_scope_violation: bool = True
    stop_on_unexpected_state_change: bool = True
    policy_decision: Literal["pending", "allowed", "blocked"] = "pending"
    policy_reasons: list[str] = Field(default_factory=list)
    objective: str = "Collect the minimum evidence needed to classify the hypothesis."
    prerequisites: list[str] = Field(default_factory=list, max_length=30)
    mutations: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    expected_secure_behavior: list[str] = Field(default_factory=list, max_length=20)
    expected_vulnerable_behavior: list[str] = Field(default_factory=list, max_length=20)
    evidence_to_compare: list[str] = Field(default_factory=list, max_length=30)
    cleanup: list[str] = Field(default_factory=list, max_length=20)
    side_effect_risk: RiskLevel = RiskLevel.low
    automatic_execution_allowed: bool = False
    capability_schema_version: int | None = Field(default=None, ge=1)
    capability_state: (
        Literal["discovery_only", "plan_only", "typed_verification"] | None
    ) = None
    typed_executor_available: bool | None = None
    executor_name: str | None = None
    executor_version: str | None = None
    input_schema: str | None = None
    minimum_requests: int | None = Field(default=None, ge=0, le=100)
    worst_case_requests: int | None = Field(default=None, ge=0, le=100)
    major_preconditions: list[str] = Field(default_factory=list, max_length=30)

    @property
    def estimated_requests(self) -> int:
        if self.worst_case_requests is not None:
            return self.worst_case_requests
        return sum(step.request_cost for step in self.steps)


class PolicyRunMetadata(StrictModel):
    profile_name: str
    policy_version: int = Field(ge=1)
    policy_hash: str
    authorization_reference: str
    source: Literal["saved_profile", "policy_file"]


class ContextRunMetadata(StrictModel):
    profile_name: str | None = None
    source: Literal["saved_profile", "context_file", "none"] = "none"


class AssessmentPlan(StrictModel):
    run_id: str
    goal: str
    target: str
    profile: Literal["baseline", "deep", "authenticated", "intrusive"]
    selected_tools: list[str] = Field(default_factory=list, max_length=100)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=200)
    verification_plans: list[VerificationPlan] = Field(
        default_factory=list, max_length=200
    )
    request_budget: int = Field(default=100, ge=0, le=5000)
    max_iterations: int = Field(default=3, ge=1, le=10)
    prior_surface_version: str | None = None
    stop_conditions: list[str] = Field(default_factory=list, max_length=30)
    planner_source: Literal["deterministic", "llm", "hybrid"] = "deterministic"
    policy_metadata: PolicyRunMetadata | None = None
    context_metadata: ContextRunMetadata = Field(default_factory=ContextRunMetadata)


class PolicyDecision(StrictModel):
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    matched_rule: str | None = None
    remaining_request_budget: int | None = None
