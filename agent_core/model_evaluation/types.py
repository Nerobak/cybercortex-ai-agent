"""Strict public contracts for model, consensus, and autonomy evaluation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.autonomy import (
    AutonomyIterationRecord,
    AutonomyLimits,
    AutonomyState,
    PivotReason,
    StopReason,
    add_model_usage,
    add_request_delta,
)
from agent_core.consensus import AgreementType, ConsensusBudget, ConsensusPolicy
from agent_core.model_evaluation.errors import EvaluationFailureCode
from agent_core.models import ModelBudgetLimits, ModelRoutingPolicy, ModelUsageDelta
from agent_core.models.types import ModelContract
from agent_core.phase2_result_status import (
    INTERMEDIATE_RESULT_STATUSES,
    TERMINAL_RESULT_STATUSES,
    Phase2ResultStatus,
)
from agent_core.reasoning import ReasoningAction, ReasoningRequest, ReasoningTaskType
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import public_result, sanitize_document_text

EVALUATION_SCHEMA_VERSION = 1
FINGERPRINT_SCHEMA_VERSION = 2
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER.fullmatch(value) or sanitize_document_text(value) != value:
        raise ValueError(f"{field_name} must be a public-safe identifier")
    return value


def _safe_text(value: str, field_name: str) -> str:
    if sanitize_document_text(value) != value:
        raise ValueError(f"{field_name} must contain only public-safe text")
    return value


class EvaluationSubjectType(str, Enum):
    single_model_reasoning = "single_model_reasoning"
    consensus_reasoning = "consensus_reasoning"
    dry_run_autonomy = "dry_run_autonomy"
    controlled_autonomy = "controlled_autonomy"


class EvaluationExecutionMode(str, Enum):
    reasoning_only = "reasoning_only"
    dry_run = "dry_run"
    controlled = "controlled"


class ConfigurationFingerprintSchema(str, Enum):
    legacy_v1_incomplete = "legacy-v1-incomplete"
    material_v2 = "material-v2"


class ConfigurationCompatibility(str, Enum):
    compatible = "compatible"
    incompatible = "incompatible"
    unknown = "unknown"


class ConfigurationCompatibilityReason(str, Enum):
    fingerprint_match = "fingerprint_match"
    material_configuration_mismatch = "material_configuration_mismatch"
    configuration_identity_missing = "configuration_identity_missing"
    legacy_fingerprint_incomplete = "legacy_fingerprint_incomplete"
    fingerprint_schema_mismatch = "fingerprint_schema_mismatch"


# Compatibility export only. Evaluation consumes the canonical Phase 2 enum so its
# accepted status vocabulary cannot drift independently again.
CanonicalPhase2ExpectationStatus = Phase2ResultStatus


class StructuralExpectationType(str, Enum):
    minimum_valid_decisions = "reasoning.minimum_valid_decisions"
    maximum_valid_decisions = "reasoning.maximum_valid_decisions"
    allowed_actions = "reasoning.allowed_actions"
    allowed_capabilities = "reasoning.allowed_capabilities"
    evidence_references_required = "reasoning.evidence_references_required"
    decision_action = "reasoning.action"
    recommended_capability = "reasoning.recommended_capability"
    decision_valid = "reasoning.valid"
    hypothesis_id = "reasoning.hypothesis_id"
    category = "reasoning.category"
    consensus_agreement = "consensus.agreement"
    autonomy_terminal_state = "autonomy.terminal_state"
    stop_reason = "autonomy.stop_reason"
    minimum_iterations = "autonomy.minimum_iterations"
    maximum_iterations = "autonomy.maximum_iterations"
    minimum_verifications = "autonomy.minimum_verifications"
    maximum_verifications = "autonomy.maximum_verifications"
    execution_occurred = "autonomy.execution_occurred"
    phase2_status = "phase2.canonical_status"
    maximum_target_requests = "requests.maximum_target_requests"
    maximum_model_calls = "models.maximum_calls"
    fallback_used = "models.fallback_used"


class ExpectationCheckReason(str, Enum):
    matched = "observed structure matched the required expectation"
    mismatched = "observed structure did not match the required expectation"
    unavailable = "required structure was not present in the canonical outcome"


class ExpectedStructuralProperties(ModelContract):
    minimum_valid_decisions: StrictInt = Field(default=0, ge=0, le=100)
    maximum_valid_decisions: StrictInt | None = Field(default=None, ge=0, le=100)
    allowed_actions: tuple[ReasoningAction, ...] = ()
    allowed_capabilities: tuple[StrictStr, ...] = ()
    evidence_references_required: StrictBool = False
    decision_action: ReasoningAction | None = None
    recommended_capability: StrictStr | None = Field(default=None, max_length=100)
    decision_valid: StrictBool | None = None
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    category: StrictStr | None = Field(default=None, max_length=100)
    consensus_agreement: AgreementType | None = None
    autonomy_terminal_state: AutonomyState | None = None
    stop_reason: StopReason | None = None
    minimum_iterations: StrictInt | None = Field(default=None, ge=0, le=100)
    maximum_iterations: StrictInt | None = Field(default=None, ge=0, le=100)
    minimum_verifications: StrictInt | None = Field(default=None, ge=0, le=100)
    maximum_verifications: StrictInt | None = Field(default=None, ge=0, le=100)
    execution_occurred: StrictBool | None = None
    phase2_status: Phase2ResultStatus | None = None
    maximum_target_requests: StrictInt | None = Field(default=None, ge=0)
    maximum_model_calls: StrictInt | None = Field(default=None, ge=0)
    fallback_used: StrictBool | None = None

    @field_validator(
        "allowed_capabilities",
        "recommended_capability",
        "hypothesis_id",
        "category",
    )
    @classmethod
    def validate_identifiers(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        if isinstance(value, tuple) and len(values) != len(set(values)):
            raise ValueError(f"{info.field_name} values must be unique")
        for item in values:
            _safe_identifier(item, info.field_name)
        return value

    @field_validator("allowed_actions")
    @classmethod
    def validate_actions(
        cls, values: tuple[ReasoningAction, ...]
    ) -> tuple[ReasoningAction, ...]:
        if len(values) != len(set(values)):
            raise ValueError("allowed actions must be unique")
        return values

    @model_validator(mode="after")
    def validate_bounds(self) -> "ExpectedStructuralProperties":
        bounds = (
            (
                self.minimum_valid_decisions,
                self.maximum_valid_decisions,
                "valid decision",
            ),
            (self.minimum_iterations, self.maximum_iterations, "iteration"),
            (self.minimum_verifications, self.maximum_verifications, "verification"),
        )
        for minimum, maximum, label in bounds:
            if minimum is not None and maximum is not None and minimum > maximum:
                raise ValueError(f"minimum {label} bound exceeds maximum")
        return self


class StructuralExpectationResult(ModelContract):
    expectation_type: StructuralExpectationType
    expected_value: StrictStr | StrictInt | StrictBool | tuple[StrictStr, ...]
    observed_value: StrictStr | StrictInt | StrictBool | tuple[StrictStr, ...] | None
    satisfied: StrictBool
    reason: ExpectationCheckReason

    @field_validator("expected_value", "observed_value")
    @classmethod
    def validate_values(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            if isinstance(item, str):
                _safe_text(item, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_result(self) -> "StructuralExpectationResult":
        expected_reason = (
            ExpectationCheckReason.matched
            if self.satisfied
            else (
                ExpectationCheckReason.unavailable
                if self.observed_value is None
                else ExpectationCheckReason.mismatched
            )
        )
        if self.reason is not expected_reason:
            raise ValueError("expectation reason must match the deterministic result")
        return self


class EvaluationSubject(ModelContract):
    subject_id: StrictStr = Field(min_length=1, max_length=255)
    subject_type: EvaluationSubjectType
    routing_policies: tuple[ModelRoutingPolicy, ...] = Field(
        min_length=1, max_length=100
    )
    consensus_policy: ConsensusPolicy | None = None
    consensus_budget: ConsensusBudget | None = None
    autonomy_limits: AutonomyLimits | None = None
    repetitions: StrictInt = Field(default=1, ge=1, le=100)
    local_only: StrictBool = False

    @field_validator("subject_id")
    @classmethod
    def validate_subject_id(cls, value: str) -> str:
        return _safe_identifier(value, "subject_id")

    @model_validator(mode="after")
    def validate_subject(self) -> "EvaluationSubject":
        consensus = self.subject_type is EvaluationSubjectType.consensus_reasoning
        if consensus != (self.consensus_policy is not None):
            raise ValueError("consensus subjects require exactly one consensus policy")
        if consensus != (self.consensus_budget is not None):
            raise ValueError("consensus subjects require exactly one consensus budget")
        autonomy = self.subject_type in {
            EvaluationSubjectType.dry_run_autonomy,
            EvaluationSubjectType.controlled_autonomy,
        }
        if autonomy != (self.autonomy_limits is not None):
            raise ValueError("autonomy subjects require exactly one autonomy policy")
        if not consensus and len(self.routing_policies) != 1:
            raise ValueError("non-consensus subjects require one model route")
        identities = [policy.model_dump_json() for policy in self.routing_policies]
        if len(identities) != len(set(identities)):
            raise ValueError("evaluation subjects cannot duplicate logical routes")
        if self.local_only and any(
            policy.mode.value != "local_only" for policy in self.routing_policies
        ):
            raise ValueError(
                "local-only evaluation requires cloud-provider-disabled "
                "Ollama-family routes"
            )
        return self


class EvaluationCase(ModelContract):
    case_id: StrictStr = Field(min_length=1, max_length=255)
    task_type: ReasoningTaskType
    reasoning_request: ReasoningRequest
    expected_structure: ExpectedStructuralProperties = Field(
        default_factory=ExpectedStructuralProperties
    )
    execution_mode: EvaluationExecutionMode
    model_budget: ModelBudgetLimits = Field(default_factory=ModelBudgetLimits)
    autonomy_budget: AutonomyLimits | None = None
    repetitions: StrictInt = Field(default=1, ge=1, le=100)

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, value: str) -> str:
        return _safe_identifier(value, "case_id")

    @model_validator(mode="after")
    def validate_case(self) -> "EvaluationCase":
        if self.task_type is not self.reasoning_request.task_type:
            raise ValueError("case and reasoning task types must match")
        autonomy = self.execution_mode is not EvaluationExecutionMode.reasoning_only
        if autonomy != (self.autonomy_budget is not None):
            raise ValueError("autonomy execution modes require an autonomy budget")
        hypothesis_categories = {
            packet.hypothesis_id: packet.category
            for packet in self.reasoning_request.evidence_packets
        }
        catalog_categories = {
            entry.category
            for entry in self.reasoning_request.capability_catalog.entries
        }
        expected = self.expected_structure
        if (
            expected.hypothesis_id is not None
            and expected.hypothesis_id not in hypothesis_categories
        ):
            raise ValueError("expected hypothesis must exist in the reasoning request")
        if (
            expected.category is not None
            and expected.category not in catalog_categories
        ):
            raise ValueError("expected category must exist in the capability catalog")
        expected_capabilities = set(expected.allowed_capabilities)
        if expected.recommended_capability is not None:
            expected_capabilities.add(expected.recommended_capability)
        if not expected_capabilities <= catalog_categories:
            raise ValueError(
                "expected capabilities must exist in the capability catalog"
            )
        if (
            expected.hypothesis_id is not None
            and expected.category is not None
            and hypothesis_categories[expected.hypothesis_id] != expected.category
        ):
            raise ValueError(
                "expected hypothesis and category must identify one packet"
            )
        return self


class CaseModelProvenance(ModelContract):
    iteration_reference: StrictInt | None = Field(default=None, ge=0)
    decision_id: StrictStr | None = Field(default=None, max_length=255)
    consensus_id: StrictStr | None = Field(default=None, max_length=255)
    participant_id: StrictStr | None = Field(default=None, max_length=255)
    requested_provider: StrictStr = Field(min_length=1, max_length=100)
    requested_model: StrictStr = Field(min_length=1, max_length=255)
    actual_provider: StrictStr | None = Field(
        default=None, min_length=1, max_length=100
    )
    actual_model: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    fallback_used: StrictBool = False
    reasoning_schema_version: StrictInt = Field(ge=1)
    consensus_schema_version: StrictInt | None = Field(default=None, ge=1)
    autonomy_schema_version: StrictInt | None = Field(default=None, ge=1)
    phase2_result_references: tuple[StrictStr, ...] = ()

    @field_validator(
        "requested_provider",
        "requested_model",
        "actual_provider",
        "actual_model",
        "decision_id",
        "consensus_id",
        "participant_id",
        "phase2_result_references",
    )
    @classmethod
    def validate_provenance(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            _safe_identifier(item, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_actual_route(self) -> "CaseModelProvenance":
        if (self.actual_provider is None) != (self.actual_model is None):
            raise ValueError("actual provider and model must be known together")
        if self.fallback_used and self.actual_provider is None:
            raise ValueError("fallback provenance requires an actual model route")
        return self


class EvaluationFailure(ModelContract):
    subject_id: StrictStr = Field(min_length=1, max_length=255)
    case_id: StrictStr | None = Field(default=None, max_length=255)
    repetition: StrictInt | None = Field(default=None, ge=0)
    failure_code: EvaluationFailureCode

    @field_validator("subject_id", "case_id")
    @classmethod
    def validate_references(cls, value: str | None, info: Any) -> str | None:
        return _safe_identifier(value, info.field_name) if value is not None else None


class EvaluationCaseOutcome(ModelContract):
    subject_id: StrictStr = Field(min_length=1, max_length=255)
    case_id: StrictStr = Field(min_length=1, max_length=255)
    repetition: StrictInt = Field(ge=0)
    execution_mode: EvaluationExecutionMode
    success: StrictBool
    runtime_success: StrictBool
    failure_code: EvaluationFailureCode | None = None
    expectations_present: StrictBool = False
    expectations_checked: StrictInt = Field(default=0, ge=0)
    expectations_satisfied: StrictBool | None = None
    expectation_results: tuple[StructuralExpectationResult, ...] = ()
    failed_expectations: tuple[StructuralExpectationResult, ...] = ()
    attempted_decisions: StrictInt = Field(default=0, ge=0)
    valid_decisions: StrictInt = Field(default=0, ge=0)
    invalid_decisions: StrictInt = Field(default=0, ge=0)
    schema_failures: StrictInt = Field(default=0, ge=0)
    unsupported_recommendations: StrictInt = Field(default=0, ge=0)
    plan_only_execution_recommendations: StrictInt = Field(default=0, ge=0)
    manual_review_decisions: StrictInt = Field(default=0, ge=0)
    stop_decisions: StrictInt = Field(default=0, ge=0)
    capability_grounded_decisions: StrictInt = Field(default=0, ge=0)
    decisions_with_evidence_references: StrictInt = Field(default=0, ge=0)
    decision_signature: StrictStr | None = Field(default=None, max_length=255)
    selected_action: ReasoningAction | None = None
    selected_capability: StrictStr | None = Field(default=None, max_length=100)
    selected_hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    selected_category: StrictStr | None = Field(default=None, max_length=100)
    decision_valid: StrictBool | None = None
    agreement_type: AgreementType | None = None
    consensus_participants: StrictInt = Field(default=0, ge=0)
    invalid_participants: StrictInt = Field(default=0, ge=0)
    failed_participants: StrictInt = Field(default=0, ge=0)
    dissenting_participants: StrictInt = Field(default=0, ge=0)
    quorum_succeeded: StrictBool = False
    aggregate_confidence: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    autonomy_iterations: StrictInt = Field(default=0, ge=0)
    verifications_attempted: StrictInt = Field(default=0, ge=0)
    verifications_completed: StrictInt = Field(default=0, ge=0)
    verified_outcomes: StrictInt = Field(default=0, ge=0)
    rejected_outcomes: StrictInt = Field(default=0, ge=0)
    inconclusive_outcomes: StrictInt = Field(default=0, ge=0)
    policy_blocked_outcomes: StrictInt = Field(default=0, ge=0)
    verification_pending_cleanup_outcomes: StrictInt = Field(default=0, ge=0)
    awaiting_controlled_evidence_outcomes: StrictInt = Field(default=0, ge=0)
    intermediate_outcomes: StrictInt = Field(default=0, ge=0)
    duplicate_recommendations_prevented: StrictInt = Field(default=0, ge=0)
    successful_pivots: StrictInt = Field(default=0, ge=0)
    blocked_recommendations: StrictInt = Field(default=0, ge=0)
    cleanup_barriers: StrictInt = Field(default=0, ge=0)
    manual_review_outcomes: StrictInt = Field(default=0, ge=0)
    autonomy_terminal_state: AutonomyState | None = None
    stop_reason: StopReason | None = None
    phase2_statuses: tuple[Phase2ResultStatus, ...] = ()
    model_usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    fallback_count: StrictInt = Field(default=0, ge=0)
    elapsed_seconds: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_valid_decision: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_verification: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_verified_outcome: StrictFloat | None = Field(default=None, ge=0.0)
    phase2_execution_latency_seconds: StrictFloat | None = Field(default=None, ge=0.0)
    provenance: tuple[CaseModelProvenance, ...] = ()
    phase2_result_references: tuple[StrictStr, ...] = ()
    iteration_provenance: tuple[AutonomyIterationRecord, ...] = ()

    @field_validator(
        "subject_id",
        "case_id",
        "decision_signature",
        "selected_capability",
        "selected_hypothesis_id",
        "selected_category",
        "phase2_result_references",
    )
    @classmethod
    def validate_public_references(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            _safe_identifier(item, info.field_name)
        return value

    @model_validator(mode="before")
    @classmethod
    def default_runtime_success(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and "runtime_success" not in value:
            return {**value, "runtime_success": value.get("success")}
        return value

    @model_validator(mode="after")
    def validate_outcome(self) -> "EvaluationCaseOutcome":
        if self.runtime_success == (self.failure_code is not None):
            raise ValueError("runtime success must be inverse of failure presence")
        expectation_success = self.expectations_satisfied is not False
        if self.success != (self.runtime_success and expectation_success):
            raise ValueError("case success must include required expectation success")
        if self.expectations_present != bool(self.expectation_results):
            raise ValueError("expectation presence must match expectation results")
        if self.expectations_checked != len(self.expectation_results):
            raise ValueError("expectation count must match expectation results")
        failed = tuple(item for item in self.expectation_results if not item.satisfied)
        if self.failed_expectations != failed:
            raise ValueError("failed expectations must match expectation results")
        if self.expectations_present:
            if self.expectations_satisfied != (not failed):
                raise ValueError("expectation status must match expectation results")
        elif self.expectations_satisfied is not None:
            raise ValueError("absent expectations require neutral satisfaction status")
        if self.attempted_decisions != self.valid_decisions + self.invalid_decisions:
            raise ValueError("attempted decisions must equal valid plus invalid")
        if (
            self.schema_failures + self.unsupported_recommendations
            > self.invalid_decisions
        ):
            raise ValueError("reasoning failure classes exceed invalid decisions")
        if self.capability_grounded_decisions > self.valid_decisions:
            raise ValueError("grounded decisions exceed valid decisions")
        if self.decisions_with_evidence_references > self.valid_decisions:
            raise ValueError("evidence-linked decisions exceed valid decisions")
        classified = (
            self.verified_outcomes
            + self.rejected_outcomes
            + self.inconclusive_outcomes
            + self.policy_blocked_outcomes
        )
        if classified > self.verifications_completed:
            raise ValueError("classified results exceed completed verifications")
        intermediate = (
            self.verification_pending_cleanup_outcomes
            + self.awaiting_controlled_evidence_outcomes
        )
        if self.intermediate_outcomes < intermediate:
            raise ValueError("intermediate result count cannot omit known statuses")
        observed_intermediate = sum(
            status.value in INTERMEDIATE_RESULT_STATUSES
            for status in self.phase2_statuses
        )
        if self.intermediate_outcomes != observed_intermediate:
            raise ValueError("intermediate result count must match canonical statuses")
        if self.verification_pending_cleanup_outcomes != self.phase2_statuses.count(
            Phase2ResultStatus.verification_pending_cleanup
        ) or self.awaiting_controlled_evidence_outcomes != self.phase2_statuses.count(
            Phase2ResultStatus.awaiting_controlled_evidence
        ):
            raise ValueError("known intermediate counts must match canonical statuses")
        if (
            self.invalid_participants + self.failed_participants
            > self.consensus_participants
        ):
            raise ValueError("invalid and failed participants exceed consensus total")
        if self.fallback_count > self.model_usage.successful_calls:
            raise ValueError("fallbacks cannot exceed successful logical model calls")
        if (
            self.execution_mode is EvaluationExecutionMode.dry_run
            and self.request_delta.total != 0
        ):
            raise ValueError("dry-run evaluation cannot contain target requests")
        if self.iteration_provenance:
            iterations = [item.iteration for item in self.iteration_provenance]
            if iterations != sorted(set(iterations)):
                raise ValueError("iteration provenance must be ordered and unique")
            if self.autonomy_iterations != iterations[-1]:
                raise ValueError("autonomy iteration count must match provenance")
            model_usage = ModelUsageDelta()
            request_delta = RequestDelta()
            for item in self.iteration_provenance:
                model_usage = add_model_usage(model_usage, item.model_usage)
                request_delta = add_request_delta(
                    request_delta, item.phase2_request_delta
                )
            if model_usage != self.model_usage:
                raise ValueError("model usage must equal the iteration provenance sum")
            if request_delta != self.request_delta:
                raise ValueError(
                    "request delta must equal the iteration provenance sum"
                )
            result_references = tuple(
                item.phase2_result_reference
                for item in self.iteration_provenance
                if item.phase2_result_reference is not None
            )
            if result_references != self.phase2_result_references:
                raise ValueError("Phase 2 references must match iteration provenance")
            canonical = all(
                not any(
                    transition.next_state is AutonomyState.reasoning
                    for transition in item.transitions
                )
                or item.requested_provider is not None
                for item in self.iteration_provenance
            ) and all(
                item.reasoning_decision_reference is None or item.reasoning is not None
                for item in self.iteration_provenance
            )
            if canonical:
                self._validate_iteration_metrics()
        return self

    def _validate_iteration_metrics(self) -> None:
        records = self.iteration_provenance
        valid = sum(item.reasoning is not None for item in records)
        attempts = sum(
            any(
                transition.next_state is AutonomyState.reasoning
                for transition in item.transitions
            )
            for item in records
        )
        invalid = attempts - valid
        if (
            self.valid_decisions != valid
            or self.invalid_decisions != invalid
            or self.attempted_decisions != attempts
        ):
            raise ValueError("decision metrics must match iteration provenance")
        if self.manual_review_decisions != sum(
            item.selected_action is ReasoningAction.manual_review for item in records
        ) or self.stop_decisions != sum(
            item.selected_action is ReasoningAction.stop for item in records
        ):
            raise ValueError("decision action metrics must match iteration provenance")
        if self.decisions_with_evidence_references != sum(
            item.reasoning is not None and item.reasoning.evidence_reference_count > 0
            for item in records
        ):
            raise ValueError("evidence metrics must match iteration provenance")
        fallback_count = 0
        for item in records:
            reasoning = item.reasoning
            if reasoning is None:
                continue
            consensus = reasoning.consensus
            fallback_count += (
                sum(participant.fallback_used for participant in consensus.participants)
                if consensus is not None and consensus.participants
                else int(reasoning.fallback_used)
            )
        if self.fallback_count != fallback_count:
            raise ValueError("fallback metrics must match iteration provenance")
        statuses = []
        for item in records:
            if item.phase2_result is not None:
                statuses.append(item.phase2_result.canonical_status)
            else:
                status = {
                    PivotReason.verified: "verified",
                    PivotReason.rejected: "rejected",
                    PivotReason.inconclusive: "inconclusive",
                    PivotReason.policy_blocked: "policy_blocked",
                }.get(item.pivot_reason)
                if status is not None:
                    statuses.append(status)
        expected_classifications = (
            statuses.count("verified"),
            statuses.count("rejected"),
            statuses.count("inconclusive"),
            statuses.count("policy_blocked"),
            statuses.count("verification_pending_cleanup"),
            statuses.count("awaiting_controlled_evidence"),
        )
        actual_classifications = (
            self.verified_outcomes,
            self.rejected_outcomes,
            self.inconclusive_outcomes,
            self.policy_blocked_outcomes,
            self.verification_pending_cleanup_outcomes,
            self.awaiting_controlled_evidence_outcomes,
        )
        if actual_classifications != expected_classifications:
            raise ValueError("result metrics must match iteration provenance")
        if self.verifications_completed != sum(
            status in TERMINAL_RESULT_STATUSES for status in statuses
        ):
            raise ValueError("completed verifications must match iteration provenance")
        if self.intermediate_outcomes != sum(
            status in INTERMEDIATE_RESULT_STATUSES for status in statuses
        ):
            raise ValueError("intermediate outcomes must match iteration provenance")
        if self.verifications_attempted != sum(
            any(
                transition.next_state is AutonomyState.executing
                for transition in item.transitions
            )
            for item in records
        ):
            raise ValueError("verification attempts must match iteration provenance")
        if self.successful_pivots != sum(
            item.pivot_reason
            in {PivotReason.verified, PivotReason.rejected, PivotReason.inconclusive}
            for item in records
        ):
            raise ValueError("pivot metrics must match iteration provenance")
        if self.stop_reason is not records[-1].stop_reason:
            raise ValueError("terminal stop reason must match the final iteration")
        final_reasoning = next(
            (
                item.reasoning
                for item in reversed(records)
                if item.reasoning is not None
            ),
            None,
        )
        if final_reasoning is not None and (
            self.selected_action is not final_reasoning.action
            or self.selected_capability != final_reasoning.selected_capability
            or self.selected_hypothesis_id != final_reasoning.hypothesis_id
            or self.decision_valid is not True
        ):
            raise ValueError("selected decision structure must match final provenance")
        if self.autonomy_terminal_state is None:
            raise ValueError("autonomy history requires a terminal state observation")
        canonical_statuses = tuple(
            Phase2ResultStatus(item.phase2_result.canonical_status)
            for item in records
            if item.phase2_result is not None
        )
        if self.phase2_statuses != canonical_statuses:
            raise ValueError("Phase 2 statuses must match canonical provenance")
        expected_routes: set[tuple[int, str | None, str | None]] = set()
        for item in records:
            reasoning = item.reasoning
            if reasoning is None:
                if any(
                    transition.next_state is AutonomyState.reasoning
                    for transition in item.transitions
                ):
                    expected_routes.add((item.iteration, None, None))
                continue
            consensus = reasoning.consensus
            if consensus is not None and consensus.participants:
                expected_routes.update(
                    (
                        item.iteration,
                        participant.decision_id,
                        consensus.consensus_id,
                    )
                    for participant in consensus.participants
                )
            else:
                expected_routes.add(
                    (
                        item.iteration,
                        reasoning.decision_id,
                        consensus.consensus_id if consensus is not None else None,
                    )
                )
        actual_routes = {
            (item.iteration_reference, item.decision_id, item.consensus_id)
            for item in self.provenance
        }
        if actual_routes != expected_routes:
            raise ValueError("model routes must match exact iteration decisions")


class ReasoningMetrics(ModelContract):
    attempted_decisions: StrictInt = Field(ge=0)
    valid_decision_rate: StrictFloat = Field(ge=0.0, le=1.0)
    invalid_decision_rate: StrictFloat = Field(ge=0.0, le=1.0)
    schema_failure_rate: StrictFloat = Field(ge=0.0, le=1.0)
    unsupported_recommendation_rate: StrictFloat = Field(ge=0.0, le=1.0)
    plan_only_execution_recommendation_rate: StrictFloat = Field(ge=0.0, le=1.0)
    manual_review_rate: StrictFloat = Field(ge=0.0, le=1.0)
    stop_rate: StrictFloat = Field(ge=0.0, le=1.0)
    decision_consistency: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    capability_grounding_rate: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_reference_rate: StrictFloat = Field(ge=0.0, le=1.0)


class AutonomyMetrics(ModelContract):
    iterations: StrictInt = Field(ge=0)
    verifications_attempted: StrictInt = Field(ge=0)
    verifications_completed: StrictInt = Field(ge=0)
    verified_outcomes: StrictInt = Field(ge=0)
    rejected_outcomes: StrictInt = Field(ge=0)
    inconclusive_outcomes: StrictInt = Field(ge=0)
    policy_blocked_outcomes: StrictInt = Field(ge=0)
    verification_pending_cleanup_count: StrictInt = Field(default=0, ge=0)
    awaiting_controlled_evidence_count: StrictInt = Field(default=0, ge=0)
    intermediate_outcome_count: StrictInt = Field(default=0, ge=0)
    duplicate_recommendations_prevented: StrictInt = Field(ge=0)
    successful_pivots: StrictInt = Field(ge=0)
    blocked_recommendations: StrictInt = Field(ge=0)
    cleanup_barriers: StrictInt = Field(ge=0)
    manual_review_outcomes: StrictInt = Field(ge=0)
    stop_reasons: dict[StrictStr, StrictInt] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_intermediate_count(self) -> "AutonomyMetrics":
        if self.intermediate_outcome_count < (
            self.verification_pending_cleanup_count
            + self.awaiting_controlled_evidence_count
        ):
            raise ValueError("intermediate count cannot omit known statuses")
        return self


class ConsensusMetrics(ModelContract):
    consensus_evaluations: StrictInt = Field(ge=0)
    unanimous_rate: StrictFloat = Field(ge=0.0, le=1.0)
    majority_rate: StrictFloat = Field(ge=0.0, le=1.0)
    split_rate: StrictFloat = Field(ge=0.0, le=1.0)
    invalid_participant_rate: StrictFloat = Field(ge=0.0, le=1.0)
    provider_failure_rate: StrictFloat = Field(ge=0.0, le=1.0)
    quorum_success_rate: StrictFloat = Field(ge=0.0, le=1.0)
    mean_aggregate_confidence: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    dissent_rate: StrictFloat = Field(ge=0.0, le=1.0)


class ModelUsageMetrics(ModelContract):
    model_call_count: StrictInt = Field(ge=0)
    successful_model_calls: StrictInt = Field(ge=0)
    failed_model_calls: StrictInt = Field(ge=0)
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)
    unknown_usage_calls: StrictInt = Field(default=0, ge=0)
    budget_input_tokens: StrictInt = Field(default=0, ge=0)
    budget_output_tokens: StrictInt = Field(default=0, ge=0)
    budget_total_tokens: StrictInt = Field(default=0, ge=0)
    estimated_api_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    budget_estimated_api_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    model_latency_seconds: StrictFloat = Field(ge=0.0)
    fallback_count: StrictInt = Field(ge=0)
    fallback_rate: StrictFloat = Field(ge=0.0, le=1.0)

    @model_validator(mode="before")
    @classmethod
    def default_budget_accounting(cls, value: Any) -> Any:
        """Keep prior actual-only evaluation artifacts readable."""

        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        payload.setdefault("unknown_usage_calls", 0)
        payload.setdefault("budget_input_tokens", payload.get("input_tokens", 0))
        payload.setdefault("budget_output_tokens", payload.get("output_tokens", 0))
        payload.setdefault("budget_total_tokens", payload.get("total_tokens", 0))
        payload.setdefault(
            "budget_estimated_api_cost_usd",
            payload.get("estimated_api_cost_usd"),
        )
        return payload

    @model_validator(mode="after")
    def validate_accounting(self) -> "ModelUsageMetrics":
        if self.model_call_count != (
            self.successful_model_calls + self.failed_model_calls
        ):
            raise ValueError("model calls must equal successful plus failed calls")
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("actual model tokens must be categorized")
        if self.budget_total_tokens != (
            self.budget_input_tokens + self.budget_output_tokens
        ):
            raise ValueError("budget model tokens must be categorized")
        if self.unknown_usage_calls > self.failed_model_calls:
            raise ValueError("unknown usage calls cannot exceed failed calls")
        if (
            self.budget_input_tokens < self.input_tokens
            or self.budget_output_tokens < self.output_tokens
            or self.budget_total_tokens < self.total_tokens
        ):
            raise ValueError("budget model tokens cannot undercount actual usage")
        if self.fallback_count > self.successful_model_calls:
            raise ValueError("fallbacks cannot exceed successful calls")
        return self


class TargetRequestMetrics(ModelContract):
    target_requests: StrictInt = Field(ge=0)
    auth_requests: StrictInt = Field(ge=0)
    verification_requests: StrictInt = Field(ge=0)
    cleanup_requests: StrictInt = Field(ge=0)
    discovery_requests: StrictInt = Field(ge=0)


class EfficiencyMetrics(ModelContract):
    verified_per_model_call: StrictFloat = Field(ge=0.0)
    verified_per_1k_tokens: StrictFloat = Field(ge=0.0)
    verified_per_target_request: StrictFloat = Field(ge=0.0)
    verified_per_estimated_dollar: StrictFloat | None = Field(default=None, ge=0.0)
    successful_pivots_per_model_call: StrictFloat = Field(ge=0.0)
    average_reasoning_latency_seconds: StrictFloat = Field(ge=0.0)
    average_verification_request_cost: StrictFloat = Field(ge=0.0)


class TimingMetrics(ModelContract):
    total_evaluation_seconds: StrictFloat = Field(ge=0.0)
    time_to_first_valid_reasoning_decision: StrictFloat | None = Field(
        default=None, ge=0.0
    )
    time_to_first_verification: StrictFloat | None = Field(default=None, ge=0.0)
    time_to_first_verified_outcome: StrictFloat | None = Field(default=None, ge=0.0)
    model_latency_seconds: StrictFloat = Field(ge=0.0)
    phase2_execution_latency_seconds: StrictFloat | None = Field(default=None, ge=0.0)


class RepeatabilityMetrics(ModelContract):
    repeated_case_count: StrictInt = Field(ge=0)
    decision_agreement: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    mean_model_latency_variance: StrictFloat | None = Field(default=None, ge=0.0)
    mean_total_token_variance: StrictFloat | None = Field(default=None, ge=0.0)


class ExpectationMetrics(ModelContract):
    cases_with_expectations: StrictInt = Field(default=0, ge=0)
    cases_expectations_satisfied: StrictInt = Field(default=0, ge=0)
    cases_expectations_failed: StrictInt = Field(default=0, ge=0)
    expectation_pass_rate: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_counts(self) -> "ExpectationMetrics":
        if (
            self.cases_expectations_satisfied + self.cases_expectations_failed
            != self.cases_with_expectations
        ):
            raise ValueError("expectation case counts must be exhaustive")
        return self


class AggregateMetrics(ModelContract):
    reasoning: ReasoningMetrics
    autonomy: AutonomyMetrics
    consensus: ConsensusMetrics
    model_usage: ModelUsageMetrics
    target_requests: TargetRequestMetrics
    efficiency: EfficiencyMetrics
    timing: TimingMetrics
    repeatability: RepeatabilityMetrics
    expectations: ExpectationMetrics = Field(default_factory=ExpectationMetrics)


class EvaluationRun(ModelContract):
    evaluation_run_id: StrictStr = Field(min_length=1, max_length=255)
    subject: EvaluationSubject
    cases: tuple[EvaluationCase, ...] = Field(min_length=1, max_length=1000)
    started_at: StrictStr = Field(min_length=1, max_length=100)
    ended_at: StrictStr = Field(min_length=1, max_length=100)
    configuration_fingerprint: StrictStr = Field(min_length=64, max_length=64)
    configuration_fingerprint_schema: ConfigurationFingerprintSchema = (
        ConfigurationFingerprintSchema.legacy_v1_incomplete
    )
    case_outcomes: tuple[EvaluationCaseOutcome, ...]
    aggregate_metrics: AggregateMetrics
    failures: tuple[EvaluationFailure, ...] = ()
    evaluation_schema_version: Literal[1] = EVALUATION_SCHEMA_VERSION

    @field_validator("evaluation_run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return _safe_identifier(value, "evaluation_run_id")

    @field_validator("configuration_fingerprint")
    @classmethod
    def validate_configuration_fingerprint(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("configuration fingerprint must be lowercase SHA-256")
        return value

    @field_validator("configuration_fingerprint_schema", mode="before")
    @classmethod
    def parse_configuration_fingerprint_schema(cls, value: Any) -> Any:
        if isinstance(value, str):
            return ConfigurationFingerprintSchema(value)
        return value

    @field_validator("started_at", "ended_at")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        _safe_text(value, "timestamp")
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @model_validator(mode="after")
    def validate_run(self) -> "EvaluationRun":
        start = datetime.fromisoformat(self.started_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.ended_at.replace("Z", "+00:00"))
        if end < start:
            raise ValueError("evaluation end time cannot precede start time")
        case_ids = {item.case_id for item in self.cases}
        if len(case_ids) != len(self.cases):
            raise ValueError("evaluation case identifiers must be unique")
        if any(item.case_id not in case_ids for item in self.case_outcomes):
            raise ValueError("outcome references an unknown evaluation case")
        if any(
            item.subject_id != self.subject.subject_id for item in self.case_outcomes
        ):
            raise ValueError("outcome subject does not match evaluation run")
        return self


class ExternalBaselineRecord(ModelContract):
    baseline_name: StrictStr = Field(min_length=1, max_length=255)
    run_id: StrictStr = Field(min_length=1, max_length=255)
    aggregate_metrics: dict[StrictStr, StrictFloat | StrictInt]
    recorded_at: StrictStr = Field(min_length=1, max_length=100)
    configuration_reference: StrictStr = Field(min_length=1, max_length=255)
    configuration_fingerprint: StrictStr | None = Field(
        default=None, min_length=64, max_length=64
    )
    configuration_fingerprint_schema: ConfigurationFingerprintSchema | None = None

    @field_validator("baseline_name", "run_id", "configuration_reference")
    @classmethod
    def validate_identifiers(cls, value: str, info: Any) -> str:
        return _safe_identifier(value, info.field_name)

    @field_validator("aggregate_metrics")
    @classmethod
    def validate_metrics(cls, values: dict[str, float | int]) -> dict[str, float | int]:
        if not values or any(value < 0 for value in values.values()):
            raise ValueError("external metrics must be nonnegative and nonempty")
        for key in values:
            _safe_identifier(key, "aggregate_metrics")
            normalized = key.casefold().replace("-", "_")
            if any(
                marker in normalized
                for marker in (
                    "ground_truth",
                    "vulnerability_id",
                    "source_path",
                    "fixture_path",
                    "expected_vulnerability",
                )
            ):
                raise ValueError("external imports accept aggregate metrics only")
        return values

    @field_validator("recorded_at")
    @classmethod
    def validate_recorded_at(cls, value: str) -> str:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("configuration_fingerprint")
    @classmethod
    def validate_external_fingerprint(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.fullmatch(value):
            raise ValueError("external fingerprint must be lowercase SHA-256")
        return value

    @field_validator("configuration_fingerprint_schema", mode="before")
    @classmethod
    def parse_external_fingerprint_schema(cls, value: Any) -> Any:
        if isinstance(value, str):
            return ConfigurationFingerprintSchema(value)
        return value

    @model_validator(mode="after")
    def validate_external_identity(self) -> "ExternalBaselineRecord":
        if (self.configuration_fingerprint is None) != (
            self.configuration_fingerprint_schema is None
        ):
            raise ValueError(
                "external fingerprint and schema must be supplied together"
            )
        return self


class ExternalBenchmarkRecord(ModelContract):
    benchmark_name: StrictStr = Field(min_length=1, max_length=255)
    run_id: StrictStr = Field(min_length=1, max_length=255)
    aggregate_metrics: dict[StrictStr, StrictFloat | StrictInt]
    matched_count: StrictInt | None = Field(default=None, ge=0)
    discovered_count: StrictInt | None = Field(default=None, ge=0)
    verified_count: StrictInt | None = Field(default=None, ge=0)
    recorded_at: StrictStr = Field(min_length=1, max_length=100)
    configuration_reference: StrictStr = Field(min_length=1, max_length=255)
    configuration_fingerprint: StrictStr | None = Field(
        default=None, min_length=64, max_length=64
    )
    configuration_fingerprint_schema: ConfigurationFingerprintSchema | None = None

    @field_validator("benchmark_name", "run_id", "configuration_reference")
    @classmethod
    def validate_benchmark_identifiers(cls, value: str, info: Any) -> str:
        return _safe_identifier(value, info.field_name)

    @field_validator("aggregate_metrics")
    @classmethod
    def validate_benchmark_metrics(
        cls, values: dict[str, float | int]
    ) -> dict[str, float | int]:
        return ExternalBaselineRecord.validate_metrics(values)

    @field_validator("recorded_at")
    @classmethod
    def validate_benchmark_recorded_at(cls, value: str) -> str:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("configuration_fingerprint")
    @classmethod
    def validate_benchmark_fingerprint(cls, value: str | None) -> str | None:
        return ExternalBaselineRecord.validate_external_fingerprint(value)

    @field_validator("configuration_fingerprint_schema", mode="before")
    @classmethod
    def parse_benchmark_fingerprint_schema(cls, value: Any) -> Any:
        if isinstance(value, str):
            return ConfigurationFingerprintSchema(value)
        return value

    @model_validator(mode="after")
    def validate_benchmark_identity(self) -> "ExternalBenchmarkRecord":
        if (self.configuration_fingerprint is None) != (
            self.configuration_fingerprint_schema is None
        ):
            raise ValueError(
                "external fingerprint and schema must be supplied together"
            )
        return self


class ComparisonMetric(ModelContract):
    metric: StrictStr = Field(min_length=1, max_length=255)
    left_value: StrictFloat | StrictInt | None
    right_value: StrictFloat | StrictInt | None
    delta: StrictFloat | None


class ComparisonResult(ModelContract):
    left_run_id: StrictStr
    right_run_id: StrictStr
    configuration_compatibility: ConfigurationCompatibility
    configuration_compatible: StrictBool | None
    mismatch_reasons: tuple[StrictStr, ...] = ()
    metrics: tuple[ComparisonMetric, ...]

    @model_validator(mode="after")
    def validate_compatibility(self) -> "ComparisonResult":
        expected = {
            ConfigurationCompatibility.compatible: True,
            ConfigurationCompatibility.incompatible: False,
            ConfigurationCompatibility.unknown: None,
        }[self.configuration_compatibility]
        if self.configuration_compatible is not expected:
            raise ValueError("compatibility boolean must match compatibility state")
        if bool(self.mismatch_reasons) == (
            self.configuration_compatibility is ConfigurationCompatibility.compatible
        ):
            raise ValueError("compatibility reasons must match compatibility state")
        return self


class ExternalConfigurationComparison(ModelContract):
    evaluation_run_id: StrictStr = Field(min_length=1, max_length=255)
    external_run_id: StrictStr = Field(min_length=1, max_length=255)
    compatibility: ConfigurationCompatibility
    reason: ConfigurationCompatibilityReason

    @model_validator(mode="after")
    def validate_reason(self) -> "ExternalConfigurationComparison":
        compatible_reason = (
            self.reason is ConfigurationCompatibilityReason.fingerprint_match
        )
        if compatible_reason != (
            self.compatibility is ConfigurationCompatibility.compatible
        ):
            raise ValueError("external compatibility reason is inconsistent")
        return self


class ComparisonTableRow(ModelContract):
    subject: StrictStr
    valid_decisions: StrictInt = Field(ge=0)
    verified_outcomes: StrictInt = Field(ge=0)
    verification_pending_cleanup_count: StrictInt = Field(ge=0)
    awaiting_controlled_evidence_count: StrictInt = Field(ge=0)
    runtime_failures: StrictInt = Field(ge=0)
    model_calls: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)
    api_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    target_requests: StrictInt = Field(ge=0)
    latency_seconds: StrictFloat = Field(ge=0.0)
    fallbacks: StrictInt = Field(ge=0)
    successful_pivots: StrictInt = Field(ge=0)
    expectation_pass_rate: StrictFloat = Field(ge=0.0, le=1.0)
    expectation_failures: StrictInt = Field(ge=0)


class ParetoDominance(ModelContract):
    dominant_subject: StrictStr
    dominated_subject: StrictStr


class ParetoResult(ModelContract):
    frontier_subjects: tuple[StrictStr, ...]
    dominance: tuple[ParetoDominance, ...]


def require_public_artifact(value: Any) -> Any:
    """Reject rather than persist anything outside the canonical public boundary."""

    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    safe = public_result(payload)
    if safe != payload:
        raise ValueError("evaluation artifact must satisfy the public-safe boundary")
    return value
