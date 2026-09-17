from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.research import (
    ALLOWED_RESEARCH_TRANSITIONS,
    BudgetUpdatedPayload,
    EndpointObservedPayload,
    ExperimentOutcomeRecordedPayload,
    FactConfirmedPayload,
    FactProposedPayload,
    FactStatus,
    FindingStatus,
    FindingStatusChangedPayload,
    HypothesisCreatedPayload,
    HypothesisResearchStatus,
    HypothesisStatusChangedPayload,
    InvalidResearchStateTransition,
    ObservationRecordedPayload,
    ProvenanceProducerType,
    ProvenanceRecord,
    ResearchEvent,
    ResearchEventType,
    ResearchFailedPayload,
    ResearchRunStatus,
    ResearchStartedPayload,
    ResearchState,
    ResearchStateMachine,
    ResearchStateTransitionedPayload,
    ResearchStoppedPayload,
    SurfaceObservedPayload,
)

TS = "2026-09-16T12:00:00+00:00"
TS_LATER = "2026-09-16T12:00:01+00:00"


def state(status: ResearchRunStatus = ResearchRunStatus.initializing) -> ResearchState:
    prov = ProvenanceRecord(
        provenance_id="prov-1",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-state-machine-test",
        producer_version="v1",
        summary="State-machine test provenance.",
        occurred_at=TS,
    )
    return ResearchState(
        research_id="research-1",
        revision=0,
        status=status,
        created_at=TS,
        updated_at=TS,
        provenance=(prov,),
    )


def transition(
    machine: ResearchStateMachine,
    next_state: ResearchRunStatus,
    index: int,
):
    return machine.transition(
        next_state,
        reason_code=f"reason-{index}",
        event_id=f"event-{index}",
        provenance_id="prov-1",
        occurred_at=TS_LATER,
    )


def test_declared_state_machine_contains_every_status():
    assert set(ALLOWED_RESEARCH_TRANSITIONS) == set(ResearchRunStatus)


def test_valid_primary_research_lifecycle():
    machine = ResearchStateMachine(state())
    route = (
        ResearchRunStatus.discovering,
        ResearchRunStatus.modeling,
        ResearchRunStatus.hypothesizing,
        ResearchRunStatus.selecting_experiment,
        ResearchRunStatus.awaiting_authorization,
        ResearchRunStatus.executing_experiment,
        ResearchRunStatus.evaluating_result,
        ResearchRunStatus.reporting,
        ResearchRunStatus.stopped,
    )
    events = [
        transition(machine, next_state, index) for index, next_state in enumerate(route)
    ]
    assert machine.current_state is ResearchRunStatus.stopped
    assert machine.revision == len(route)
    assert len(machine.events) == len(route)
    assert events[-1].event_type is ResearchEventType.research_stopped
    assert isinstance(events[-1].payload, ResearchStoppedPayload)


@pytest.mark.parametrize(
    "destination",
    (
        ResearchRunStatus.selecting_experiment,
        ResearchRunStatus.pivoting,
        ResearchRunStatus.reproducing,
        ResearchRunStatus.impact_analysis,
        ResearchRunStatus.chaining,
        ResearchRunStatus.reporting,
        ResearchRunStatus.stopped,
        ResearchRunStatus.failed,
    ),
)
def test_evaluating_result_allows_required_conceptual_destinations(destination):
    machine = ResearchStateMachine(state(ResearchRunStatus.evaluating_result))
    event = transition(machine, destination, 1)
    assert event.payload.next_state is destination


@pytest.mark.parametrize(
    "destination",
    (
        ResearchRunStatus.modeling,
        ResearchRunStatus.hypothesizing,
        ResearchRunStatus.selecting_experiment,
        ResearchRunStatus.reporting,
        ResearchRunStatus.stopped,
        ResearchRunStatus.failed,
    ),
)
def test_pivoting_returns_only_to_declared_research_states(destination):
    machine = ResearchStateMachine(state(ResearchRunStatus.pivoting))
    transition(machine, destination, 1)
    assert machine.current_state is destination


def test_reproduction_returns_through_evaluation():
    machine = ResearchStateMachine(state(ResearchRunStatus.reproducing))
    event = transition(machine, ResearchRunStatus.evaluating_result, 1)
    assert event.payload.previous_state is ResearchRunStatus.reproducing
    assert event.payload.next_state is ResearchRunStatus.evaluating_result


@pytest.mark.parametrize(
    ("source", "destination"),
    (
        (ResearchRunStatus.initializing, ResearchRunStatus.executing_experiment),
        (ResearchRunStatus.discovering, ResearchRunStatus.reproducing),
        (ResearchRunStatus.modeling, ResearchRunStatus.awaiting_authorization),
        (ResearchRunStatus.executing_experiment, ResearchRunStatus.pivoting),
        (ResearchRunStatus.reproducing, ResearchRunStatus.reporting),
        (ResearchRunStatus.reporting, ResearchRunStatus.discovering),
    ),
)
def test_invalid_transitions_fail_closed(source, destination):
    machine = ResearchStateMachine(state(source))
    with pytest.raises(InvalidResearchStateTransition):
        transition(machine, destination, 1)
    assert machine.current_state is source
    assert machine.events == ()


@pytest.mark.parametrize(
    "terminal", (ResearchRunStatus.stopped, ResearchRunStatus.failed)
)
def test_terminal_states_reject_every_transition(terminal):
    machine = ResearchStateMachine(state(terminal))
    for destination in ResearchRunStatus:
        with pytest.raises(InvalidResearchStateTransition):
            transition(machine, destination, 1)
    assert machine.current_state is terminal


def test_failure_transition_emits_typed_terminal_event():
    machine = ResearchStateMachine(state())
    event = transition(machine, ResearchRunStatus.failed, 1)
    assert event.event_type is ResearchEventType.research_failed
    assert isinstance(event.payload, ResearchFailedPayload)
    assert event.payload.previous_state is ResearchRunStatus.initializing
    assert event.payload.next_state is ResearchRunStatus.failed


def test_transition_event_contains_required_provenance_and_revision():
    machine = ResearchStateMachine(state())
    event = transition(machine, ResearchRunStatus.discovering, 1)
    assert event.state_revision == 1
    assert event.provenance_id == "prov-1"
    assert event.occurred_at == TS_LATER
    assert event.payload.reason_code == "reason-1"
    assert event.payload.previous_state is ResearchRunStatus.initializing
    assert event.payload.next_state is ResearchRunStatus.discovering


def test_transition_requires_provenance_present_in_state():
    machine = ResearchStateMachine(state())
    with pytest.raises(ValueError, match="provenance"):
        machine.transition(
            ResearchRunStatus.discovering,
            reason_code="run-started",
            event_id="event-1",
            provenance_id="missing-prov",
            occurred_at=TS_LATER,
        )


def test_transition_event_ids_are_unique():
    machine = ResearchStateMachine(state())
    machine.transition(
        ResearchRunStatus.discovering,
        reason_code="run-started",
        event_id="event-1",
        provenance_id="prov-1",
        occurred_at=TS_LATER,
    )
    with pytest.raises(ValueError, match="unique"):
        machine.transition(
            ResearchRunStatus.modeling,
            reason_code="discovery-complete",
            event_id="event-1",
            provenance_id="prov-1",
            occurred_at=TS_LATER,
        )


def test_transition_timestamp_must_be_monotonic():
    machine = ResearchStateMachine(state())
    with pytest.raises(ValueError, match="timestamp"):
        machine.transition(
            ResearchRunStatus.discovering,
            reason_code="run-started",
            event_id="event-1",
            provenance_id="prov-1",
            occurred_at="2026-09-16T11:59:59+00:00",
        )


def test_snapshot_reflects_transitions_without_mutating_initial_state():
    initial = state()
    machine = ResearchStateMachine(initial)
    transition(machine, ResearchRunStatus.discovering, 1)
    snapshot = machine.snapshot()
    assert initial.status is ResearchRunStatus.initializing
    assert initial.revision == 0
    assert snapshot.status is ResearchRunStatus.discovering
    assert snapshot.revision == 1
    assert snapshot.updated_at == TS_LATER


def test_research_event_is_immutable_and_rejects_unknown_fields():
    machine = ResearchStateMachine(state())
    event = transition(machine, ResearchRunStatus.discovering, 1)
    with pytest.raises(ValidationError, match="frozen_instance"):
        event.state_revision = 2  # type: ignore[misc]
    payload = event.model_dump(mode="python")
    payload["state_patch"] = {"status": "failed"}
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResearchEvent.model_validate(payload)


def test_event_type_must_match_typed_payload():
    with pytest.raises(ValidationError, match="must match"):
        ResearchEvent(
            event_id="event-1",
            research_id="research-1",
            event_type=ResearchEventType.surface_observed,
            state_revision=1,
            provenance_id="prov-1",
            occurred_at=TS,
            summary="An observation was recorded.",
            payload=ObservationRecordedPayload(observation_id="observation-1"),
        )


@pytest.mark.parametrize(
    ("event_type", "payload"),
    (
        (
            ResearchEventType.research_started,
            ResearchStartedPayload(target_ids=("target-1",)),
        ),
        (
            ResearchEventType.surface_observed,
            SurfaceObservedPayload(surface_id="surface-1"),
        ),
        (
            ResearchEventType.endpoint_observed,
            EndpointObservedPayload(endpoint_id="endpoint-1", surface_id="surface-1"),
        ),
        (
            ResearchEventType.observation_recorded,
            ObservationRecordedPayload(observation_id="observation-1"),
        ),
        (
            ResearchEventType.fact_proposed,
            FactProposedPayload(fact_id="fact-1"),
        ),
        (
            ResearchEventType.fact_confirmed,
            FactConfirmedPayload(fact_id="fact-1", previous_status=FactStatus.observed),
        ),
        (
            ResearchEventType.hypothesis_created,
            HypothesisCreatedPayload(hypothesis_id="hypothesis-1"),
        ),
        (
            ResearchEventType.hypothesis_status_changed,
            HypothesisStatusChangedPayload(
                hypothesis_id="hypothesis-1",
                previous_status=HypothesisResearchStatus.proposed,
                next_status=HypothesisResearchStatus.selected,
            ),
        ),
        (
            ResearchEventType.experiment_outcome_recorded,
            ExperimentOutcomeRecordedPayload(outcome_id="outcome-1"),
        ),
        (
            ResearchEventType.finding_status_changed,
            FindingStatusChangedPayload(
                finding_id="finding-1",
                previous_status=FindingStatus.candidate,
                next_status=FindingStatus.reproduced,
            ),
        ),
        (
            ResearchEventType.budget_updated,
            BudgetUpdatedPayload(budget_reference="budget-1"),
        ),
        (
            ResearchEventType.research_state_transitioned,
            ResearchStateTransitionedPayload(
                previous_state=ResearchRunStatus.initializing,
                next_state=ResearchRunStatus.discovering,
                reason_code="run-started",
            ),
        ),
        (
            ResearchEventType.research_stopped,
            ResearchStoppedPayload(
                previous_state=ResearchRunStatus.reporting,
                reason_code="report-complete",
            ),
        ),
        (
            ResearchEventType.research_failed,
            ResearchFailedPayload(
                previous_state=ResearchRunStatus.initializing,
                reason_code="state-invalid",
            ),
        ),
    ),
)
def test_all_required_event_payloads_are_strict_and_serializable(event_type, payload):
    event = ResearchEvent(
        event_id=f"event-{event_type.value}",
        research_id="research-1",
        event_type=event_type,
        state_revision=1,
        provenance_id="prov-1",
        occurred_at=TS,
        summary="A bounded research event was recorded.",
        payload=payload,
    )
    restored = ResearchEvent.model_validate_json(event.model_dump_json())
    assert restored == event


def test_transition_event_summary_rejects_structured_secret_material():
    with pytest.raises(ValidationError, match="public-safe"):
        ResearchEvent(
            event_id="event-1",
            research_id="research-1",
            event_type=ResearchEventType.research_started,
            state_revision=0,
            provenance_id="prov-1",
            occurred_at=TS,
            summary="password=SYNTHETIC_SECRET",
            payload=ResearchStartedPayload(),
        )
