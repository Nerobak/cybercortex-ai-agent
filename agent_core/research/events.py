"""Append-only event contracts for future Phase 4 research persistence."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, StrictInt, model_validator

from agent_core.research.types import (
    EndpointId,
    ExperimentOutcomeId,
    FactId,
    FactStatus,
    FindingId,
    FindingStatus,
    HypothesisRecordId,
    HypothesisResearchStatus,
    ObservationId,
    OpaqueIdentifier,
    ProvenanceRecordId,
    ResearchContract,
    ResearchEventId,
    ResearchId,
    ResearchRunStatus,
    ShortPublicText,
    SurfaceId,
    TargetAssetId,
    Timestamp,
)

RESEARCH_EVENT_SCHEMA_VERSION = 1


class ResearchEventType(str, Enum):
    research_started = "research_started"
    surface_observed = "surface_observed"
    endpoint_observed = "endpoint_observed"
    observation_recorded = "observation_recorded"
    fact_proposed = "fact_proposed"
    fact_confirmed = "fact_confirmed"
    hypothesis_created = "hypothesis_created"
    hypothesis_status_changed = "hypothesis_status_changed"
    experiment_outcome_recorded = "experiment_outcome_recorded"
    finding_status_changed = "finding_status_changed"
    budget_updated = "budget_updated"
    research_state_transitioned = "research_state_transitioned"
    research_stopped = "research_stopped"
    research_failed = "research_failed"


class ResearchStartedPayload(ResearchContract):
    event_type: Literal["research_started"] = "research_started"
    target_ids: tuple[TargetAssetId, ...] = Field(default=(), max_length=64)


class SurfaceObservedPayload(ResearchContract):
    event_type: Literal["surface_observed"] = "surface_observed"
    surface_id: SurfaceId


class EndpointObservedPayload(ResearchContract):
    event_type: Literal["endpoint_observed"] = "endpoint_observed"
    endpoint_id: EndpointId
    surface_id: SurfaceId


class ObservationRecordedPayload(ResearchContract):
    event_type: Literal["observation_recorded"] = "observation_recorded"
    observation_id: ObservationId


class FactProposedPayload(ResearchContract):
    event_type: Literal["fact_proposed"] = "fact_proposed"
    fact_id: FactId
    status: Literal[FactStatus.proposed] = FactStatus.proposed


class FactConfirmedPayload(ResearchContract):
    event_type: Literal["fact_confirmed"] = "fact_confirmed"
    fact_id: FactId
    previous_status: FactStatus
    next_status: Literal[FactStatus.confirmed] = FactStatus.confirmed


class HypothesisCreatedPayload(ResearchContract):
    event_type: Literal["hypothesis_created"] = "hypothesis_created"
    hypothesis_id: HypothesisRecordId


class HypothesisStatusChangedPayload(ResearchContract):
    event_type: Literal["hypothesis_status_changed"] = "hypothesis_status_changed"
    hypothesis_id: HypothesisRecordId
    previous_status: HypothesisResearchStatus
    next_status: HypothesisResearchStatus

    @model_validator(mode="after")
    def require_change(self) -> "HypothesisStatusChangedPayload":
        if self.previous_status is self.next_status:
            raise ValueError("hypothesis status event must record a change")
        return self


class ExperimentOutcomeRecordedPayload(ResearchContract):
    event_type: Literal["experiment_outcome_recorded"] = "experiment_outcome_recorded"
    outcome_id: ExperimentOutcomeId


class FindingStatusChangedPayload(ResearchContract):
    event_type: Literal["finding_status_changed"] = "finding_status_changed"
    finding_id: FindingId
    previous_status: FindingStatus
    next_status: FindingStatus

    @model_validator(mode="after")
    def require_change(self) -> "FindingStatusChangedPayload":
        if self.previous_status is self.next_status:
            raise ValueError("finding status event must record a change")
        return self


class BudgetUpdatedPayload(ResearchContract):
    event_type: Literal["budget_updated"] = "budget_updated"
    budget_reference: OpaqueIdentifier


class ResearchStateTransitionedPayload(ResearchContract):
    event_type: Literal["research_state_transitioned"] = "research_state_transitioned"
    previous_state: ResearchRunStatus
    next_state: ResearchRunStatus
    reason_code: OpaqueIdentifier

    @model_validator(mode="after")
    def require_change(self) -> "ResearchStateTransitionedPayload":
        if self.previous_state is self.next_state:
            raise ValueError("research transition event must record a state change")
        if self.next_state in {ResearchRunStatus.stopped, ResearchRunStatus.failed}:
            raise ValueError("terminal transitions require a terminal event type")
        return self


class ResearchStoppedPayload(ResearchContract):
    event_type: Literal["research_stopped"] = "research_stopped"
    previous_state: ResearchRunStatus
    next_state: Literal[ResearchRunStatus.stopped] = ResearchRunStatus.stopped
    reason_code: OpaqueIdentifier

    @model_validator(mode="after")
    def require_nonterminal_source(self) -> "ResearchStoppedPayload":
        if self.previous_state in {ResearchRunStatus.stopped, ResearchRunStatus.failed}:
            raise ValueError("terminal state cannot be the source of a stop event")
        return self


class ResearchFailedPayload(ResearchContract):
    event_type: Literal["research_failed"] = "research_failed"
    previous_state: ResearchRunStatus
    next_state: Literal[ResearchRunStatus.failed] = ResearchRunStatus.failed
    reason_code: OpaqueIdentifier

    @model_validator(mode="after")
    def require_nonterminal_source(self) -> "ResearchFailedPayload":
        if self.previous_state in {ResearchRunStatus.stopped, ResearchRunStatus.failed}:
            raise ValueError("terminal state cannot be the source of a failure event")
        return self


ResearchEventPayload: TypeAlias = Annotated[
    ResearchStartedPayload
    | SurfaceObservedPayload
    | EndpointObservedPayload
    | ObservationRecordedPayload
    | FactProposedPayload
    | FactConfirmedPayload
    | HypothesisCreatedPayload
    | HypothesisStatusChangedPayload
    | ExperimentOutcomeRecordedPayload
    | FindingStatusChangedPayload
    | BudgetUpdatedPayload
    | ResearchStateTransitionedPayload
    | ResearchStoppedPayload
    | ResearchFailedPayload,
    Field(discriminator="event_type"),
]


class ResearchEvent(ResearchContract):
    """One immutable event; payloads are typed changes rather than state patches."""

    schema_version: Literal[RESEARCH_EVENT_SCHEMA_VERSION] = (
        RESEARCH_EVENT_SCHEMA_VERSION
    )
    event_id: ResearchEventId
    research_id: ResearchId
    event_type: ResearchEventType
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    provenance_id: ProvenanceRecordId
    occurred_at: Timestamp
    summary: ShortPublicText
    payload: ResearchEventPayload

    @model_validator(mode="after")
    def validate_event_type(self) -> "ResearchEvent":
        if self.payload.event_type != self.event_type.value:
            raise ValueError("event type must match its typed payload")
        return self
