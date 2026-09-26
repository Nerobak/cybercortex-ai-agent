"""Fail-closed lifecycle transitions for provider-neutral research state."""

from __future__ import annotations

from datetime import datetime

from agent_core.research.events import (
    ResearchEvent,
    ResearchEventType,
    ResearchFailedPayload,
    ResearchStateTransitionedPayload,
    ResearchStoppedPayload,
)
from agent_core.research.state import ResearchState
from agent_core.research.types import (
    AttackChainStatus,
    FindingStatus,
    OpaqueIdentifier,
    ProvenanceRecordId,
    ResearchEventId,
    ResearchRunStatus,
    Timestamp,
)


class InvalidResearchStateTransition(ValueError):
    """Raised before state changes when a lifecycle edge is not declared."""


ALLOWED_RESEARCH_TRANSITIONS: dict[ResearchRunStatus, frozenset[ResearchRunStatus]] = {
    ResearchRunStatus.initializing: frozenset(
        {
            ResearchRunStatus.discovering,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.discovering: frozenset(
        {
            ResearchRunStatus.modeling,
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.modeling: frozenset(
        {
            ResearchRunStatus.discovering,
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.hypothesizing: frozenset(
        {
            ResearchRunStatus.modeling,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.selecting_experiment: frozenset(
        {
            ResearchRunStatus.awaiting_authorization,
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.awaiting_authorization: frozenset(
        {
            ResearchRunStatus.executing_experiment,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.pivoting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.executing_experiment: frozenset(
        {
            ResearchRunStatus.evaluating_result,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.evaluating_result: frozenset(
        {
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.pivoting,
            ResearchRunStatus.reproducing,
            ResearchRunStatus.impact_analysis,
            ResearchRunStatus.chaining,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.pivoting: frozenset(
        {
            ResearchRunStatus.modeling,
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.reproducing: frozenset(
        {
            ResearchRunStatus.evaluating_result,
            ResearchRunStatus.impact_analysis,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.impact_analysis: frozenset(
        {
            ResearchRunStatus.evaluating_result,
            ResearchRunStatus.chaining,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.chaining: frozenset(
        {
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.reproducing,
            ResearchRunStatus.reporting,
            ResearchRunStatus.stopped,
            ResearchRunStatus.failed,
        }
    ),
    ResearchRunStatus.reporting: frozenset(
        {ResearchRunStatus.stopped, ResearchRunStatus.failed}
    ),
    ResearchRunStatus.stopped: frozenset(),
    ResearchRunStatus.failed: frozenset(),
}


ALLOWED_FINDING_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.candidate: frozenset(
        {FindingStatus.reproducing, FindingStatus.needs_manual_review}
    ),
    FindingStatus.reproducing: frozenset(
        {
            FindingStatus.candidate,
            FindingStatus.confirmed,
            FindingStatus.rejected,
            FindingStatus.needs_manual_review,
        }
    ),
    # Compatibility state retained from the pre-P4-0F schema.
    FindingStatus.reproduced: frozenset(
        {FindingStatus.confirmed, FindingStatus.rejected}
    ),
    FindingStatus.confirmed: frozenset(),
    FindingStatus.rejected: frozenset(),
    FindingStatus.needs_manual_review: frozenset(),
}


ALLOWED_ATTACK_CHAIN_TRANSITIONS: dict[
    AttackChainStatus, frozenset[AttackChainStatus]
] = {
    AttackChainStatus.proposed: frozenset(
        {
            AttackChainStatus.testing,
            AttackChainStatus.inconclusive,
            AttackChainStatus.rejected,
        }
    ),
    AttackChainStatus.testing: frozenset(
        {
            AttackChainStatus.supported,
            AttackChainStatus.refuted,
            AttackChainStatus.inconclusive,
            AttackChainStatus.candidate,
            AttackChainStatus.rejected,
        }
    ),
    AttackChainStatus.supported: frozenset(
        {AttackChainStatus.candidate, AttackChainStatus.rejected}
    ),
    AttackChainStatus.inconclusive: frozenset(
        {AttackChainStatus.testing, AttackChainStatus.rejected}
    ),
    AttackChainStatus.candidate: frozenset(
        {
            AttackChainStatus.reproducing,
            AttackChainStatus.rejected,
            AttackChainStatus.manual_review,
        }
    ),
    AttackChainStatus.reproducing: frozenset(
        {
            AttackChainStatus.candidate,
            AttackChainStatus.reproduced,
            AttackChainStatus.confirmed,
            AttackChainStatus.rejected,
            AttackChainStatus.manual_review,
        }
    ),
    AttackChainStatus.reproduced: frozenset(
        {AttackChainStatus.confirmed, AttackChainStatus.rejected}
    ),
    AttackChainStatus.refuted: frozenset(),
    AttackChainStatus.confirmed: frozenset(),
    AttackChainStatus.rejected: frozenset(),
    AttackChainStatus.manual_review: frozenset(),
}


def validate_finding_transition(
    previous: FindingStatus, next_status: FindingStatus
) -> None:
    if next_status not in ALLOWED_FINDING_TRANSITIONS[previous]:
        raise InvalidResearchStateTransition(
            f"Invalid finding transition: {previous.value} -> {next_status.value}"
        )


def validate_attack_chain_transition(
    previous: AttackChainStatus, next_status: AttackChainStatus
) -> None:
    if next_status not in ALLOWED_ATTACK_CHAIN_TRANSITIONS[previous]:
        raise InvalidResearchStateTransition(
            f"Invalid attack-chain transition: {previous.value} -> {next_status.value}"
        )


class ResearchStateMachine:
    """Track lifecycle state and emit immutable events without executing work."""

    def __init__(self, state: ResearchState) -> None:
        self._initial_state = state
        self._current_state = state.status
        self._revision = state.revision
        self._updated_at = state.updated_at
        self._events: list[ResearchEvent] = []

    @property
    def current_state(self) -> ResearchRunStatus:
        return self._current_state

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def events(self) -> tuple[ResearchEvent, ...]:
        return tuple(self._events)

    def transition(
        self,
        next_state: ResearchRunStatus,
        *,
        reason_code: OpaqueIdentifier,
        event_id: ResearchEventId,
        provenance_id: ProvenanceRecordId,
        occurred_at: Timestamp,
    ) -> ResearchEvent:
        previous = self._current_state
        if not isinstance(next_state, ResearchRunStatus):
            raise InvalidResearchStateTransition(
                "next state must be a ResearchRunStatus"
            )
        if next_state not in ALLOWED_RESEARCH_TRANSITIONS[previous]:
            raise InvalidResearchStateTransition(
                f"Invalid research transition: {previous.value} -> {next_state.value}"
            )
        if provenance_id not in {
            item.provenance_id for item in self._initial_state.provenance
        }:
            raise ValueError("transition provenance is not present in research state")
        if event_id in {item.event_id for item in self._events}:
            raise ValueError("transition event ID must be unique")
        if _timestamp(occurred_at) < _timestamp(self._updated_at):
            raise ValueError("transition timestamp cannot precede current state")

        revision = self._revision + 1
        if next_state is ResearchRunStatus.stopped:
            event_type = ResearchEventType.research_stopped
            payload = ResearchStoppedPayload(
                previous_state=previous,
                reason_code=reason_code,
            )
        elif next_state is ResearchRunStatus.failed:
            event_type = ResearchEventType.research_failed
            payload = ResearchFailedPayload(
                previous_state=previous,
                reason_code=reason_code,
            )
        else:
            event_type = ResearchEventType.research_state_transitioned
            payload = ResearchStateTransitionedPayload(
                previous_state=previous,
                next_state=next_state,
                reason_code=reason_code,
            )

        event = ResearchEvent(
            event_id=event_id,
            research_id=self._initial_state.research_id,
            event_type=event_type,
            state_revision=revision,
            provenance_id=provenance_id,
            occurred_at=occurred_at,
            summary=(
                f"Research state changed from {previous.value} to "
                f"{next_state.value}: {reason_code}."
            ),
            payload=payload,
        )
        self._current_state = next_state
        self._revision = revision
        self._updated_at = occurred_at
        self._events.append(event)
        return event

    def snapshot(self) -> ResearchState:
        """Return a newly validated snapshot with the machine's current lifecycle."""

        payload = self._initial_state.model_dump(mode="python")
        payload.update(
            {
                "status": self._current_state,
                "revision": self._revision,
                "updated_at": self._updated_at,
            }
        )
        return ResearchState.model_validate(payload)


def _timestamp(value: str) -> datetime:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(candidate)
