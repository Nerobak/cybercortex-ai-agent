"""Strict provider-neutral contracts for evidence-grounded advisory reasoning."""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any, Literal

from pydantic import (
    Field,
    JsonValue,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.models import ModelUsageDelta
from agent_core.models.types import ModelContract
from agent_core.result_normalizer import public_result, sanitize_document_text

REASONING_SCHEMA_VERSION = 1
PHASE2_PLAN_POLICY_AUTHORIZATION_REQUIRED = (
    "Phase 2 plan policy authorization is required."
)
AUTOMATIC_EXECUTION_ELIGIBILITY_REQUIRED = (
    "Automatic execution eligibility is required."
)
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_COMMAND_INSTRUCTION = re.compile(
    r"(?i)(?:\b(?:run|execute|invoke|launch)\s+(?:the\s+)?"
    r"(?:command|shell|python|tool|scanner|executor)\b|"
    r"\b(?:curl|wget|powershell)\s+|\b(?:bash|sh|python)\s+-[a-z]|"
    r"\brm\s+-[a-z]|\b(?:ignore|bypass|override)\s+(?:the\s+)?policy\b)"
)
_URL = re.compile(r"(?i)\bhttps?://")
_CREDENTIAL_REQUEST = re.compile(
    r"(?i)\b(?:provide|send|supply|reveal|obtain|request)\b.{0,40}"
    r"\b(?:password|api[_ -]?key|authorization|cookie|session[_ -]?token|"
    r"recovery[_ -]?(?:code|secret)|credential)\b"
)


def _require_public_safe(value: Any, field_name: str) -> Any:
    safe = public_result(value)
    try:
        normalized = json.loads(json.dumps(value, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be strict JSON data") from exc
    if safe != normalized:
        raise ValueError(
            f"{field_name} must satisfy the Phase 2 public_result boundary"
        )
    return value


def _require_safe_text(value: str, field_name: str) -> str:
    if sanitize_document_text(value) != value:
        raise ValueError(f"{field_name} must contain only public-safe text")
    return value


def _reject_instruction_text(value: str, field_name: str) -> str:
    _require_safe_text(value, field_name)
    if (
        _COMMAND_INSTRUCTION.search(value)
        or _URL.search(value)
        or _CREDENTIAL_REQUEST.search(value)
    ):
        raise ValueError(f"{field_name} cannot contain executable instructions")
    return value


class ReasoningTaskType(str, Enum):
    hypothesis_analysis = "hypothesis_analysis"
    hypothesis_ranking = "hypothesis_ranking"
    result_review = "result_review"


class ReasoningAction(str, Enum):
    prioritize = "prioritize"
    recommend_verification = "recommend_verification"
    request_additional_evidence = "request_additional_evidence"
    manual_review = "manual_review"
    defer = "defer"
    stop = "stop"


class ConfidenceLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class InformationGain(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class RequestAccountingSummary(ModelContract):
    discovery_requests: StrictInt = Field(default=0, ge=0)
    auth_requests: StrictInt = Field(default=0, ge=0)
    verification_requests: StrictInt = Field(default=0, ge=0)
    cleanup_requests: StrictInt = Field(default=0, ge=0)
    attempted_requests: StrictInt = Field(default=0, ge=0)
    total_requests: StrictInt = Field(default=0, ge=0)
    source: Literal["request_delta_v1", "legacy_total", "none"] = "none"

    @model_validator(mode="after")
    def validate_counts(self) -> "RequestAccountingSummary":
        categorized = (
            self.discovery_requests
            + self.auth_requests
            + self.verification_requests
            + self.cleanup_requests
        )
        if self.source == "request_delta_v1":
            if (
                self.total_requests != categorized
                or self.attempted_requests != self.total_requests
            ):
                raise ValueError(
                    "request accounting does not satisfy Phase 2 invariants"
                )
        elif any(
            (
                self.discovery_requests,
                self.auth_requests,
                self.verification_requests,
                self.cleanup_requests,
            )
        ):
            raise ValueError("legacy request accounting cannot claim typed categories")
        elif self.attempted_requests != self.total_requests:
            raise ValueError("attempted request count must equal total")
        return self


class PriorVerificationOutcome(ModelContract):
    status: Literal[
        "verified",
        "rejected",
        "inconclusive",
        "policy_blocked",
        "awaiting_controlled_evidence",
        "verification_pending_cleanup",
    ]
    reasons: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    request_accounting: RequestAccountingSummary = Field(
        default_factory=RequestAccountingSummary
    )

    @field_validator("reasons")
    @classmethod
    def validate_reasons(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_safe_text(value, "reasons") for value in values)


class CapabilityCatalogEntry(ModelContract):
    category: StrictStr = Field(min_length=2, max_length=100)
    capability_state: Literal["discovery_only", "plan_only", "typed_verification"]
    typed_executor_available: StrictBool
    input_schema_identifier: StrictStr | None = Field(default=None, max_length=255)
    executor_version: StrictStr | None = Field(default=None, max_length=255)
    min_requests: StrictInt = Field(ge=0, le=100)
    worst_case_requests: StrictInt = Field(ge=0, le=100)
    major_preconditions: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    automatic_execution_supported: StrictBool

    @field_validator("major_preconditions")
    @classmethod
    def validate_preconditions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _require_safe_text(value, "major_preconditions") for value in values
        )

    @model_validator(mode="after")
    def validate_capability(self) -> "CapabilityCatalogEntry":
        if self.worst_case_requests < self.min_requests:
            raise ValueError("worst_case_requests must be >= min_requests")
        typed = self.capability_state == "typed_verification"
        if self.typed_executor_available and not typed:
            raise ValueError("only typed verification may expose an executor")
        if self.automatic_execution_supported and not self.typed_executor_available:
            raise ValueError("automatic support requires a typed executor")
        return self


class CapabilityCatalog(ModelContract):
    schema_version: Literal[1] = 1
    entries: tuple[CapabilityCatalogEntry, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_catalog(self) -> "CapabilityCatalog":
        categories = [entry.category for entry in self.entries]
        if categories != sorted(categories):
            raise ValueError("capability catalog entries must be deterministic")
        if len(categories) != len(set(categories)):
            raise ValueError("capability catalog categories must be unique")
        return self

    def entry(self, category: str) -> CapabilityCatalogEntry | None:
        return next((item for item in self.entries if item.category == category), None)


class EvidencePacket(ModelContract):
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    category: StrictStr = Field(min_length=2, max_length=100)
    title: StrictStr = Field(min_length=1, max_length=1000)
    rationale: StrictStr = Field(min_length=1, max_length=1000)
    confidence: ConfidenceLevel
    priority: StrictInt = Field(ge=0, le=100)
    target_surface: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_basis: tuple[JsonValue, ...] = Field(default=(), max_length=50)
    evidence_references: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    required_context: tuple[StrictStr, ...] = Field(default=(), max_length=30)
    limitations: tuple[StrictStr, ...] = Field(default=(), max_length=30)
    capability_state: Literal["discovery_only", "plan_only", "typed_verification"]
    typed_executor_available: StrictBool
    min_requests: StrictInt = Field(ge=0, le=100)
    worst_case_requests: StrictInt = Field(ge=0, le=100)
    plan_policy_decision: Literal["pending", "allowed", "blocked"] | None = None
    plan_automatic_execution_allowed: StrictBool = False
    prior_verification: PriorVerificationOutcome | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def parse_confidence(cls, value: Any) -> Any:
        return ConfidenceLevel(value) if isinstance(value, str) else value

    @field_validator("hypothesis_id", "category", "evidence_references")
    @classmethod
    def validate_references(cls, value: Any, info: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        if any(not _REFERENCE.fullmatch(item) for item in values):
            raise ValueError(f"{info.field_name} contains an invalid reference")
        return value

    @field_validator("title", "rationale")
    @classmethod
    def validate_primary_text(cls, value: str, info: Any) -> str:
        return _require_safe_text(value, info.field_name)

    @field_validator("required_context", "limitations")
    @classmethod
    def validate_text_lists(cls, values: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return tuple(_require_safe_text(value, info.field_name) for value in values)

    @field_validator("target_surface", "evidence_basis", mode="before")
    @classmethod
    def validate_public_evidence(cls, value: Any, info: Any) -> Any:
        return _require_public_safe(value, info.field_name)

    @model_validator(mode="after")
    def validate_costs(self) -> "EvidencePacket":
        if self.worst_case_requests < self.min_requests:
            raise ValueError("worst_case_requests must be >= min_requests")
        return self


class PolicyReasoningConstraints(ModelContract):
    policy_reference: StrictStr = Field(min_length=1, max_length=255)
    allowed_recommendation_categories: tuple[StrictStr, ...] = Field(
        default=(), max_length=100
    )
    blocked_categories: tuple[StrictStr, ...] = Field(default=(), max_length=100)
    remaining_target_request_budget: StrictInt | None = Field(default=None, ge=0)
    controlled_context_available: StrictBool = False
    notes: tuple[StrictStr, ...] = Field(default=(), max_length=50)

    @field_validator(
        "policy_reference",
        "allowed_recommendation_categories",
        "blocked_categories",
    )
    @classmethod
    def validate_references(cls, value: Any, info: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        if any(not _REFERENCE.fullmatch(item) for item in values):
            raise ValueError(f"{info.field_name} contains an invalid reference")
        return value

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_safe_text(value, "notes") for value in values)

    @model_validator(mode="after")
    def validate_category_sets(self) -> "PolicyReasoningConstraints":
        if set(self.allowed_recommendation_categories) & set(self.blocked_categories):
            raise ValueError("a category cannot be both allowed and blocked")
        return self


class ModelBudgetContext(ModelContract):
    remaining_model_calls: StrictInt | None = Field(default=None, ge=0)
    remaining_input_tokens: StrictInt | None = Field(default=None, ge=0)
    remaining_output_tokens: StrictInt | None = Field(default=None, ge=0)
    remaining_total_tokens: StrictInt | None = Field(default=None, ge=0)
    remaining_estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    cost_known: StrictBool = False


class PreviousReasoningDecision(ModelContract):
    decision_id: StrictStr = Field(min_length=1, max_length=255)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    action: ReasoningAction
    recommended_capability: StrictStr | None = Field(default=None, max_length=100)
    concise_rationale: StrictStr = Field(min_length=1, max_length=1000)

    @field_validator("action", mode="before")
    @classmethod
    def parse_action(cls, value: Any) -> Any:
        return ReasoningAction(value) if isinstance(value, str) else value

    @field_validator("concise_rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return _reject_instruction_text(value, "concise_rationale")


class ReasoningRequest(ModelContract):
    task_type: ReasoningTaskType
    run_id: StrictStr = Field(min_length=1, max_length=255)
    target_reference: StrictStr = Field(min_length=1, max_length=255)
    evidence_packets: tuple[EvidencePacket, ...] = Field(min_length=1, max_length=200)
    capability_catalog: CapabilityCatalog
    policy_constraints: PolicyReasoningConstraints
    previous_decisions: tuple[PreviousReasoningDecision, ...] = Field(
        default=(), max_length=200
    )
    model_budget_context: ModelBudgetContext = Field(default_factory=ModelBudgetContext)

    @field_validator("task_type", mode="before")
    @classmethod
    def parse_task_type(cls, value: Any) -> Any:
        return ReasoningTaskType(value) if isinstance(value, str) else value

    @field_validator("run_id", "target_reference")
    @classmethod
    def validate_top_references(cls, value: str, info: Any) -> str:
        if not _REFERENCE.fullmatch(value):
            raise ValueError(f"{info.field_name} must be an opaque reference")
        return value

    @model_validator(mode="after")
    def validate_packet_identity(self) -> "ReasoningRequest":
        hypothesis_ids = [packet.hypothesis_id for packet in self.evidence_packets]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("evidence packet hypothesis IDs must be unique")
        catalog_categories = {
            entry.category for entry in self.capability_catalog.entries
        }
        if any(
            packet.category not in catalog_categories
            for packet in self.evidence_packets
        ):
            raise ValueError("evidence packet category is absent from the catalog")
        return self


class ReasoningCandidate(ModelContract):
    """Strict model-authored candidate before deterministic semantic validation."""

    decision_id: StrictStr = Field(min_length=1, max_length=255)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    action: ReasoningAction
    recommended_capability: StrictStr | None = Field(default=None, max_length=100)
    priority: StrictInt = Field(ge=0, le=100)
    confidence: ConfidenceLevel
    rationale: StrictStr = Field(min_length=1, max_length=1000)
    evidence_references: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    missing_evidence: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    expected_information_gain: InformationGain
    estimated_request_cost: StrictInt = Field(ge=0, le=100)
    stop_reason: StrictStr | None = Field(default=None, max_length=1000)

    @field_validator("action", mode="before")
    @classmethod
    def parse_action(cls, value: Any) -> Any:
        return ReasoningAction(value) if isinstance(value, str) else value

    @field_validator("confidence", mode="before")
    @classmethod
    def parse_confidence(cls, value: Any) -> Any:
        return ConfidenceLevel(value) if isinstance(value, str) else value

    @field_validator("expected_information_gain", mode="before")
    @classmethod
    def parse_information_gain(cls, value: Any) -> Any:
        return InformationGain(value) if isinstance(value, str) else value

    @field_validator(
        "decision_id",
        "hypothesis_id",
        "recommended_capability",
        "evidence_references",
    )
    @classmethod
    def validate_identifiers(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        if any(not _REFERENCE.fullmatch(item) for item in values):
            raise ValueError(f"{info.field_name} contains an invalid identifier")
        return value

    @field_validator("rationale", "missing_evidence", "stop_reason")
    @classmethod
    def reject_executable_text(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            _reject_instruction_text(item, info.field_name)
        return value


class ConsensusParticipantProvenance(ModelContract):
    """Public routing and decision identity for one consensus participant."""

    participant_id: StrictStr = Field(min_length=1, max_length=255)
    decision_id: StrictStr | None = Field(default=None, max_length=255)
    requested_provider: StrictStr = Field(min_length=1, max_length=100)
    requested_model: StrictStr = Field(min_length=1, max_length=255)
    actual_provider: StrictStr | None = Field(default=None, max_length=100)
    actual_model: StrictStr | None = Field(default=None, max_length=255)
    fallback_used: StrictBool = False
    usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)

    @field_validator(
        "participant_id",
        "decision_id",
        "requested_provider",
        "requested_model",
        "actual_provider",
        "actual_model",
    )
    @classmethod
    def validate_public_identifiers(cls, value: str | None, info: Any) -> str | None:
        if value is not None:
            _require_safe_text(value, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_route(self) -> "ConsensusParticipantProvenance":
        if (self.actual_provider is None) != (self.actual_model is None):
            raise ValueError("consensus participant actual route must be complete")
        if self.fallback_used and self.actual_provider is None:
            raise ValueError("consensus participant fallback requires an actual route")
        return self


class ReasoningConsensusProvenance(ModelContract):
    """Exact sanitized consensus reference carried into P3-4."""

    consensus_id: StrictStr = Field(min_length=1, max_length=255)
    consensus_schema_version: StrictInt = Field(ge=1)
    participant_decision_ids: tuple[StrictStr, ...] = ()
    supporting_decision_ids: tuple[StrictStr, ...] = ()
    dissenting_decision_ids: tuple[StrictStr, ...] = ()
    participants: tuple[ConsensusParticipantProvenance, ...] = ()

    @field_validator(
        "consensus_id",
        "participant_decision_ids",
        "supporting_decision_ids",
        "dissenting_decision_ids",
    )
    @classmethod
    def validate_public_references(cls, value: Any, info: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        for item in values:
            _require_safe_text(item, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_decision_references(self) -> "ReasoningConsensusProvenance":
        participant_ids = set(self.participant_decision_ids)
        support = set(self.supporting_decision_ids)
        dissent = set(self.dissenting_decision_ids)
        if any(
            len(values) != len(set(values))
            for values in (
                self.participant_decision_ids,
                self.supporting_decision_ids,
                self.dissenting_decision_ids,
            )
        ):
            raise ValueError("consensus decision references must be unique")
        if support & dissent or not (support | dissent) <= participant_ids:
            raise ValueError(
                "consensus support and dissent references are inconsistent"
            )
        return self


class ReasoningModelProvenance(ModelContract):
    provider_requested: StrictStr = Field(min_length=1, max_length=100)
    requested_model: StrictStr | None = Field(default=None, max_length=255)
    provider_used: StrictStr = Field(min_length=1, max_length=100)
    model_used: StrictStr = Field(min_length=1, max_length=255)
    fallback_used: StrictBool
    model_call_id: StrictStr | None = Field(default=None, max_length=255)
    task_type: ReasoningTaskType
    usage: ModelUsageDelta
    reasoning_schema_version: Literal[1] = REASONING_SCHEMA_VERSION
    consensus: ReasoningConsensusProvenance | None = None

    @field_validator("task_type", mode="before")
    @classmethod
    def parse_task_type(cls, value: Any) -> Any:
        return ReasoningTaskType(value) if isinstance(value, str) else value


class ReasoningDecision(ReasoningCandidate):
    """Validated advisory decision with no execution method or authority."""

    required_preconditions: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    prior_result_status: StrictStr | None = Field(default=None, max_length=100)
    model_provenance: ReasoningModelProvenance


class ReasoningHistoryEntry(ModelContract):
    decision_id: StrictStr = Field(min_length=1, max_length=255)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    action: ReasoningAction
    recommended_capability: StrictStr | None = Field(default=None, max_length=100)
    priority: StrictInt = Field(ge=0, le=100)
    confidence: ConfidenceLevel
    concise_rationale: StrictStr = Field(min_length=1, max_length=1000)
    evidence_references: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    missing_evidence: tuple[StrictStr, ...] = Field(default=(), max_length=50)
    model_provenance: ReasoningModelProvenance
    created_at: StrictStr = Field(min_length=1, max_length=100)
