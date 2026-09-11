"""Strict, secret-free contracts for bounded Phase 3 orchestration."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.models import ModelUsageDelta, add_model_usage_deltas
from agent_core.reasoning import (
    ReasoningAction,
    ReasoningConsensusProvenance,
    ReasoningDecision,
)
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import sanitize_document_text


class AutonomyState(str, Enum):
    initialized = "initialized"
    observing = "observing"
    reasoning = "reasoning"
    decision_validation = "decision_validation"
    awaiting_execution_approval = "awaiting_execution_approval"
    executing = "executing"
    evaluating = "evaluating"
    pivoting = "pivoting"
    stopped = "stopped"
    failed = "failed"


class GateReason(str, Enum):
    approved = "approved"
    action_not_verification = "action_not_verification"
    hypothesis_not_found = "hypothesis_not_found"
    plan_not_found = "plan_not_found"
    unknown_capability = "unknown_capability"
    plan_only_capability = "plan_only_capability"
    typed_route_unavailable = "typed_route_unavailable"
    category_mismatch = "category_mismatch"
    automatic_execution_unsupported = "automatic_execution_unsupported"
    runtime_boundary_invalid = "runtime_boundary_invalid"
    phase2_policy_denied = "phase2_policy_denied"
    authorization_missing = "authorization_missing"
    controlled_account_missing = "controlled_account_missing"
    credentials_missing = "credentials_missing"
    state_change_permission_missing = "state_change_permission_missing"
    cleanup_requirement_missing = "cleanup_requirement_missing"
    test_owned_object_missing = "test_owned_object_missing"
    request_budget_exhausted = "request_budget_exhausted"
    model_budget_exhausted = "model_budget_exhausted"
    iteration_budget_exhausted = "iteration_budget_exhausted"
    verification_budget_exhausted = "verification_budget_exhausted"
    duplicate_recommendation = "duplicate_recommendation"
    cleanup_barrier = "cleanup_barrier"


class StopReason(str, Enum):
    model_recommended_stop = "model_recommended_stop"
    manual_review_required = "manual_review_required"
    additional_evidence_required = "additional_evidence_required"
    no_verification_recommended = "no_verification_recommended"
    no_eligible_hypotheses = "no_eligible_hypotheses"
    all_relevant_hypotheses_resolved = "all_relevant_hypotheses_resolved"
    max_iterations = "max_iterations"
    max_verifications = "max_verifications"
    reasoning_failure_limit = "reasoning_failure_limit"
    duplicate_recommendation_limit = "duplicate_recommendation_limit"
    phase2_policy_blocked = "phase2_policy_blocked"
    model_budget_exhausted = "model_budget_exhausted"
    model_call_budget_exhausted = "model_call_budget_exhausted"
    model_token_budget_exhausted = "model_token_budget_exhausted"
    model_cost_budget_exhausted = "model_cost_budget_exhausted"
    request_budget_exhausted = "request_budget_exhausted"
    cleanup_barrier = "cleanup_barrier"
    awaiting_controlled_evidence = "awaiting_controlled_evidence"
    service_instability = "service_instability"
    dry_run_complete = "dry_run_complete"


class FailureReason(str, Enum):
    reasoning_failed = "reasoning_failed"
    decision_invalid = "decision_invalid"
    decision_blocked = "decision_blocked"
    phase2_runtime_failed = "phase2_runtime_failed"
    invalid_phase2_result = "invalid_phase2_result"
    fatal_deterministic_runtime_error = "fatal_deterministic_runtime_error"


class PivotReason(str, Enum):
    verified = "verified_result"
    rejected = "rejected_result"
    inconclusive = "inconclusive_result"
    policy_blocked = "policy_blocked_result"
    decision_deferred = "decision_deferred"
    recommendation_blocked = "recommendation_blocked"
    reasoning_retry = "reasoning_retry"


class ModelBudgetState(str, Enum):
    available = "available"
    call_budget_exhausted = "call_budget_exhausted"
    token_budget_exhausted = "token_budget_exhausted"
    cost_budget_exhausted = "cost_budget_exhausted"


class AutonomyContract(BaseModel):
    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        strict=True,
    )


class AutonomyLimits(AutonomyContract):
    max_iterations: StrictInt = Field(default=5, ge=1, le=100)
    max_verifications: StrictInt = Field(default=3, ge=0, le=100)
    max_reasoning_failures: StrictInt = Field(default=2, ge=1, le=20)
    max_duplicate_recommendations: StrictInt = Field(default=2, ge=1, le=20)
    max_policy_blocks: StrictInt = Field(default=2, ge=1, le=20)


class AutonomyRunConfig(AutonomyContract):
    run_id: StrictStr = Field(min_length=1, max_length=255)
    phase2_run_reference: StrictStr = Field(min_length=1, max_length=255)
    target_reference: StrictStr = Field(min_length=1, max_length=255)
    dry_run: StrictBool = False
    limits: AutonomyLimits = Field(default_factory=AutonomyLimits)

    @field_validator("run_id", "phase2_run_reference", "target_reference")
    @classmethod
    def validate_references(cls, value: str) -> str:
        if sanitize_document_text(value) != value:
            raise ValueError("autonomy references must be public-safe")
        return value


class StateTransition(AutonomyContract):
    previous_state: AutonomyState
    next_state: AutonomyState
    reason: StrictStr = Field(min_length=1, max_length=255)
    occurred_at: StrictStr = Field(min_length=1, max_length=100)


class ExecutionIdentity(AutonomyContract):
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    capability: StrictStr = Field(min_length=2, max_length=100)
    controlled_context_reference: StrictStr = Field(min_length=1, max_length=255)
    result_status: StrictStr | None = Field(default=None, max_length=100)


class ProposedVerification(AutonomyContract):
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    capability: StrictStr = Field(min_length=2, max_length=100)
    plan_id: StrictStr = Field(min_length=1, max_length=255)
    estimated_requests: StrictInt = Field(ge=0, le=500)
    dry_run: Literal[True] = True


class GateDecision(AutonomyContract):
    approved: StrictBool
    reason: GateReason
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    capability: StrictStr | None = Field(default=None, max_length=100)
    plan_id: StrictStr | None = Field(default=None, max_length=255)
    required_requests: StrictInt = Field(default=0, ge=0, le=500)

    @model_validator(mode="after")
    def validate_outcome(self) -> "GateDecision":
        if self.approved != (self.reason is GateReason.approved):
            raise ValueError("gate approval must match its deterministic reason")
        return self


class IterationReasoningProvenance(AutonomyContract):
    """Immutable public snapshot of the exact decision used by one iteration."""

    decision_id: StrictStr = Field(min_length=1, max_length=255)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    reasoning_schema_version: StrictInt = Field(ge=1)
    requested_provider: StrictStr = Field(min_length=1, max_length=100)
    requested_model: StrictStr = Field(min_length=1, max_length=255)
    actual_provider: StrictStr = Field(min_length=1, max_length=100)
    actual_model: StrictStr = Field(min_length=1, max_length=255)
    fallback_used: StrictBool = False
    model_call_reference: StrictStr | None = Field(default=None, max_length=255)
    action: ReasoningAction
    selected_capability: StrictStr | None = Field(default=None, max_length=100)
    evidence_reference_count: StrictInt = Field(default=0, ge=0)
    consensus: ReasoningConsensusProvenance | None = None

    @field_validator(
        "decision_id",
        "hypothesis_id",
        "requested_provider",
        "requested_model",
        "actual_provider",
        "actual_model",
        "model_call_reference",
        "selected_capability",
    )
    @classmethod
    def validate_public_fields(cls, value: str | None) -> str | None:
        if value is not None and sanitize_document_text(value) != value:
            raise ValueError("reasoning provenance must be public-safe")
        return value

    @model_validator(mode="after")
    def validate_consensus_reference(self) -> "IterationReasoningProvenance":
        if (
            self.consensus is not None
            and self.consensus.consensus_id != self.decision_id
        ):
            raise ValueError("consensus provenance must match the selected decision")
        return self


class Phase2ResultProvenance(AutonomyContract):
    """Exact public Phase 2 result identity, or an explicit legacy reference."""

    run_id: StrictStr = Field(min_length=1, max_length=255)
    result_reference: StrictStr = Field(min_length=1, max_length=255)
    result_id: StrictStr | None = Field(default=None, max_length=255)
    result_hash: StrictStr | None = Field(default=None, max_length=100)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    executor_version: StrictStr | None = Field(default=None, max_length=255)
    canonical_status: StrictStr = Field(min_length=1, max_length=100)

    @field_validator(
        "run_id",
        "result_reference",
        "result_id",
        "result_hash",
        "hypothesis_id",
        "executor_version",
        "canonical_status",
    )
    @classmethod
    def validate_public_fields(cls, value: str | None) -> str | None:
        if value is not None and sanitize_document_text(value) != value:
            raise ValueError("Phase 2 provenance must be public-safe")
        return value

    @model_validator(mode="after")
    def validate_exact_identity(self) -> "Phase2ResultProvenance":
        if (self.result_id is None) != (self.result_hash is None):
            raise ValueError("Phase 2 result ID and hash must be recorded together")
        return self


class AutonomyIterationRecord(AutonomyContract):
    iteration: StrictInt = Field(ge=0)
    transitions: tuple[StateTransition, ...] = ()
    previous_iteration_reference: StrictInt | None = Field(default=None, ge=0)
    previous_phase2_result_reference: StrictStr | None = Field(
        default=None, max_length=255
    )
    requested_provider: StrictStr | None = Field(default=None, max_length=100)
    requested_model: StrictStr | None = Field(default=None, max_length=255)
    reasoning: IterationReasoningProvenance | None = None
    reasoning_decision_reference: StrictStr | None = Field(default=None, max_length=255)
    selected_hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    selected_action: ReasoningAction | None = None
    selected_capability: StrictStr | None = Field(default=None, max_length=100)
    gate_outcome: GateDecision | None = None
    phase2_result: Phase2ResultProvenance | None = None
    phase2_result_reference: StrictStr | None = Field(default=None, max_length=255)
    model_usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    request_delta: RequestDelta = Field(
        default_factory=RequestDelta,
        validation_alias=AliasChoices("request_delta", "phase2_request_delta"),
    )
    pivot_reason: PivotReason | None = None
    stop_reason: StopReason | None = None
    failure_reason: FailureReason | None = None
    recorded_at: StrictStr | None = Field(default=None, max_length=100)

    @field_validator(
        "previous_phase2_result_reference",
        "requested_provider",
        "requested_model",
        "reasoning_decision_reference",
        "selected_hypothesis_id",
        "selected_capability",
        "phase2_result_reference",
        "recorded_at",
    )
    @classmethod
    def validate_public_fields(cls, value: str | None) -> str | None:
        if value is not None and sanitize_document_text(value) != value:
            raise ValueError("iteration provenance must be public-safe")
        return value

    @model_validator(mode="after")
    def validate_exact_references(self) -> "AutonomyIterationRecord":
        if (self.requested_provider is None) != (self.requested_model is None):
            raise ValueError("iteration requested model route must be complete")
        if self.previous_iteration_reference is not None and (
            self.previous_iteration_reference >= self.iteration
        ):
            raise ValueError("previous iteration must precede the current iteration")
        if self.reasoning is not None and (
            self.requested_provider != self.reasoning.requested_provider
            or self.requested_model != self.reasoning.requested_model
            or self.reasoning_decision_reference != self.reasoning.decision_id
            or self.selected_hypothesis_id != self.reasoning.hypothesis_id
            or self.selected_action is not self.reasoning.action
            or self.selected_capability != self.reasoning.selected_capability
        ):
            raise ValueError("iteration decision references must match their snapshot")
        if self.phase2_result is not None and (
            self.phase2_result_reference != self.phase2_result.result_reference
            or self.selected_hypothesis_id != self.phase2_result.hypothesis_id
        ):
            raise ValueError("iteration result references must match their snapshot")
        return self

    @property
    def phase2_request_delta(self) -> RequestDelta:
        """Compatibility spelling for histories emitted before P1-3."""

        return self.request_delta


class AutonomyRun(BaseModel):
    """Mutable in-memory run state containing only safe typed references."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        validate_assignment=True,
        strict=True,
    )

    run_id: StrictStr
    phase2_run_reference: StrictStr
    target_reference: StrictStr
    current_state: AutonomyState = AutonomyState.initialized
    iteration: StrictInt = Field(default=0, ge=0)
    selected_hypothesis_id: StrictStr | None = None
    reasoning_decision: ReasoningDecision | None = None
    selected_capability: StrictStr | None = None
    verification_result_references: tuple[StrictStr, ...] = ()
    reasoning_history_references: tuple[StrictStr, ...] = ()
    iteration_history: tuple[AutonomyIterationRecord, ...] = ()
    model_usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    phase2_request_usage: RequestDelta = Field(default_factory=RequestDelta)
    verifications_attempted: StrictInt = Field(default=0, ge=0)
    reasoning_failures: StrictInt = Field(default=0, ge=0)
    duplicate_recommendations: StrictInt = Field(default=0, ge=0)
    policy_blocks: StrictInt = Field(default=0, ge=0)
    cleanup_barrier_active: StrictBool = False
    proposed_verification: ProposedVerification | None = None
    stop_reason: StopReason | None = None
    failure_reason: FailureReason | None = None
    started_at: StrictStr
    updated_at: StrictStr
    stopped_at: StrictStr | None = None


def add_model_usage(left: ModelUsageDelta, right: ModelUsageDelta) -> ModelUsageDelta:
    return add_model_usage_deltas(left, right)


def add_request_delta(left: RequestDelta, right: RequestDelta) -> RequestDelta:
    values: dict[str, Any] = {
        field: getattr(left, field) + getattr(right, field)
        for field in ("discovery", "auth", "verification", "cleanup")
    }
    total = sum(values.values())
    return RequestDelta(**values, attempted=total, total=total)
