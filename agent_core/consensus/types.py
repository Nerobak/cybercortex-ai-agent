"""Strict contracts for provider-neutral multi-model consensus."""

from __future__ import annotations

import json
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

from agent_core.models import ModelRoutingPolicy, ModelUsageDelta
from agent_core.models.types import ModelContract
from agent_core.reasoning import ReasoningAction, ReasoningDecision, ReasoningRequest
from agent_core.result_normalizer import public_result, sanitize_document_text

CONSENSUS_SCHEMA_VERSION = 1


class AgreementType(str, Enum):
    unanimous = "unanimous"
    majority = "majority"
    split = "split"
    single_model_advisory = "single_model_advisory"
    insufficient_participants = "insufficient_participants"
    invalid_decisions = "invalid_decisions"


class SplitBehavior(str, Enum):
    manual_review = "manual_review"
    request_additional_evidence = "request_additional_evidence"
    defer = "defer"


class ParticipantStatus(str, Enum):
    valid = "valid"
    invalid = "invalid"
    failed = "failed"
    budget_blocked = "budget_blocked"


class ParticipantFailure(str, Enum):
    invalid_decision = "invalid_decision"
    provider_failed = "provider_failed"
    timeout = "timeout"
    rate_limited = "rate_limited"
    model_budget_exhausted = "model_budget_exhausted"
    consensus_budget_exhausted = "consensus_budget_exhausted"


class ConsensusBudget(ModelContract):
    max_model_calls: StrictInt = Field(default=10, ge=1, le=10_000)
    max_input_tokens: StrictInt | None = Field(default=None, ge=1)
    max_output_tokens: StrictInt | None = Field(default=None, ge=1)
    max_total_tokens: StrictInt | None = Field(default=None, ge=1)
    max_estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    unknown_cost_policy: Literal["deny", "allow"] = "deny"


class ConsensusPolicy(ModelContract):
    minimum_participants: StrictInt = Field(default=2, ge=1, le=100)
    minimum_valid_participants: StrictInt = Field(default=2, ge=1, le=100)
    require_majority: StrictBool = True
    require_unanimity: StrictBool = False
    minimum_aggregate_confidence: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    split_behavior: SplitBehavior = SplitBehavior.manual_review
    allow_single_model_advisory: StrictBool = False
    allow_duplicate_participants: StrictBool = False
    local_only: StrictBool = False

    @field_validator("split_behavior", mode="before")
    @classmethod
    def parse_split_behavior(cls, value: Any) -> Any:
        return SplitBehavior(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_thresholds(self) -> "ConsensusPolicy":
        if self.minimum_valid_participants > self.minimum_participants:
            raise ValueError(
                "minimum_valid_participants cannot exceed minimum_participants"
            )
        return self


class ConsensusParticipant(ModelContract):
    participant_id: StrictStr = Field(min_length=1, max_length=255)
    routing_policy: ModelRoutingPolicy

    @field_validator("participant_id")
    @classmethod
    def validate_participant_id(cls, value: str) -> str:
        if sanitize_document_text(value) != value:
            raise ValueError("participant_id must be public-safe")
        return value

    @property
    def route_identity(self) -> str:
        return json.dumps(
            self.routing_policy.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )


class ConsensusRequest(ModelContract):
    reasoning_request: ReasoningRequest
    participants: tuple[ConsensusParticipant, ...] = Field(min_length=1, max_length=100)
    policy: ConsensusPolicy
    model_budget: ConsensusBudget = Field(default_factory=ConsensusBudget)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr = Field(min_length=1, max_length=255)
    iteration_reference: StrictStr = Field(min_length=1, max_length=255)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def validate_metadata(cls, value: Any) -> Any:
        safe = public_result(value)
        if safe != value:
            raise ValueError("consensus metadata must be canonical public data")
        return value

    @model_validator(mode="after")
    def validate_request(self) -> "ConsensusRequest":
        if self.run_id != self.reasoning_request.run_id:
            raise ValueError("consensus and reasoning run identifiers must match")
        if self.task_type != self.reasoning_request.task_type.value:
            raise ValueError("consensus and reasoning task types must match")
        participant_ids = [item.participant_id for item in self.participants]
        if len(participant_ids) != len(set(participant_ids)):
            raise ValueError("participant identifiers must be unique")
        identities = [item.route_identity for item in self.participants]
        if not self.policy.allow_duplicate_participants and len(identities) != len(
            set(identities)
        ):
            raise ValueError("duplicate logical consensus participants are prohibited")
        if self.policy.local_only and any(
            item.routing_policy.mode.value != "local_only"
            or any(
                route.provider != "ollama"
                for route in (
                    item.routing_policy.preferred,
                    *item.routing_policy.fallbacks,
                )
            )
            for item in self.participants
        ):
            raise ValueError(
                "local-only consensus permits only Ollama-family routes; "
                "endpoint locality depends on configuration"
            )
        return self

    def ordered_participants(self) -> tuple[ConsensusParticipant, ...]:
        return tuple(sorted(self.participants, key=lambda item: item.participant_id))


class ParticipantOutcome(ModelContract):
    participant_id: StrictStr = Field(min_length=1, max_length=255)
    configured_provider: StrictStr = Field(min_length=1, max_length=100)
    configured_model: StrictStr = Field(min_length=1, max_length=255)
    actual_provider: StrictStr | None = Field(default=None, max_length=100)
    actual_model: StrictStr | None = Field(default=None, max_length=255)
    status: ParticipantStatus
    decision: ReasoningDecision | None = None
    failure: ParticipantFailure | None = None
    usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)

    @field_validator(
        "participant_id",
        "configured_provider",
        "configured_model",
        "actual_provider",
        "actual_model",
    )
    @classmethod
    def validate_public_identifiers(cls, value: str | None) -> str | None:
        if value is not None and sanitize_document_text(value) != value:
            raise ValueError("participant provenance must be public-safe")
        return value

    @model_validator(mode="after")
    def validate_outcome(self) -> "ParticipantOutcome":
        if self.status is ParticipantStatus.valid:
            if (
                self.decision is None
                or self.failure is not None
                or self.actual_provider is None
                or self.actual_model is None
            ):
                raise ValueError("valid participant outcomes require one decision")
        elif (
            self.decision is not None
            or self.failure is None
            or self.actual_provider is not None
            or self.actual_model is not None
        ):
            raise ValueError(
                "non-valid participant outcomes require only a failure code"
            )
        return self


class ConsensusDecision(ModelContract):
    """Advisory consensus result with no execution method or authority."""

    consensus_id: StrictStr = Field(min_length=1, max_length=255)
    hypothesis_id: StrictStr = Field(min_length=1, max_length=255)
    agreement_type: AgreementType
    participant_count: StrictInt = Field(ge=1)
    valid_decision_count: StrictInt = Field(ge=0)
    selected_action: ReasoningAction
    selected_capability: StrictStr | None = Field(default=None, max_length=100)
    aggregate_confidence: StrictFloat = Field(ge=0.0, le=1.0)
    supporting_decision_ids: tuple[StrictStr, ...] = ()
    dissenting_decision_ids: tuple[StrictStr, ...] = ()
    evidence_references: tuple[StrictStr, ...] = ()
    arbitration_reason: StrictStr = Field(min_length=1, max_length=255)
    invalid_participants: tuple[StrictStr, ...] = ()
    failed_participants: tuple[StrictStr, ...] = ()
    model_usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    consensus_schema_version: Literal[1] = CONSENSUS_SCHEMA_VERSION

    @field_validator(
        "consensus_id",
        "hypothesis_id",
        "selected_capability",
        "supporting_decision_ids",
        "dissenting_decision_ids",
        "evidence_references",
        "arbitration_reason",
        "invalid_participants",
        "failed_participants",
    )
    @classmethod
    def validate_public_fields(cls, value: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        if any(
            item is not None and sanitize_document_text(item) != item for item in values
        ):
            raise ValueError("consensus decision fields must be public-safe")
        return value

    @model_validator(mode="after")
    def validate_decision(self) -> "ConsensusDecision":
        if self.valid_decision_count > self.participant_count:
            raise ValueError("valid decisions cannot exceed participant count")
        support = set(self.supporting_decision_ids)
        dissent = set(self.dissenting_decision_ids)
        if len(support) != len(self.supporting_decision_ids) or len(dissent) != len(
            self.dissenting_decision_ids
        ):
            raise ValueError("decision identifiers must be unique")
        if support & dissent:
            raise ValueError("supporting and dissenting decisions must be disjoint")
        if len(support | dissent) > self.valid_decision_count:
            raise ValueError("decision identifiers exceed valid participant count")
        selected = self.agreement_type in {
            AgreementType.unanimous,
            AgreementType.majority,
            AgreementType.single_model_advisory,
        }
        if selected != bool(self.supporting_decision_ids):
            raise ValueError("agreement selection must match supporting decisions")
        if (
            self.selected_action is ReasoningAction.recommend_verification
            and self.selected_capability is None
        ):
            raise ValueError("verification consensus requires a selected capability")
        if self.selected_capability is not None and self.selected_action not in {
            ReasoningAction.recommend_verification,
            ReasoningAction.request_additional_evidence,
            ReasoningAction.manual_review,
        }:
            raise ValueError("this advisory action cannot select a capability")
        return self


class ConsensusResult(ModelContract):
    decision: ConsensusDecision
    participants: tuple[ParticipantOutcome, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_result(self) -> "ConsensusResult":
        identifiers = [item.participant_id for item in self.participants]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("consensus result participants must be unique")
        if len(self.participants) != self.decision.participant_count:
            raise ValueError("participant count must match consensus decision")
        return self


class ConsensusHistoryEntry(ModelContract):
    consensus_id: StrictStr = Field(min_length=1, max_length=255)
    participant_decision_ids: tuple[StrictStr, ...] = ()
    agreement_type: AgreementType
    selected_action: ReasoningAction
    selected_capability: StrictStr | None = Field(default=None, max_length=100)
    aggregate_confidence: StrictFloat = Field(ge=0.0, le=1.0)
    dissenting_decision_ids: tuple[StrictStr, ...] = ()
    invalid_participants: tuple[StrictStr, ...] = ()
    failed_participants: tuple[StrictStr, ...] = ()
    arbitration_reason: StrictStr = Field(min_length=1, max_length=255)
    model_usage: ModelUsageDelta
    created_at: StrictStr = Field(min_length=1, max_length=100)
