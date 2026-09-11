"""Explicit deterministic P3-4 state transitions."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_core.autonomy.types import AutonomyRun, AutonomyState, StateTransition


class InvalidStateTransition(ValueError):
    pass


ALLOWED_TRANSITIONS: dict[AutonomyState, frozenset[AutonomyState]] = {
    AutonomyState.initialized: frozenset(
        {AutonomyState.observing, AutonomyState.stopped, AutonomyState.failed}
    ),
    AutonomyState.observing: frozenset(
        {AutonomyState.reasoning, AutonomyState.stopped, AutonomyState.failed}
    ),
    AutonomyState.reasoning: frozenset(
        {
            AutonomyState.decision_validation,
            AutonomyState.pivoting,
            AutonomyState.stopped,
            AutonomyState.failed,
        }
    ),
    AutonomyState.decision_validation: frozenset(
        {
            AutonomyState.awaiting_execution_approval,
            AutonomyState.pivoting,
            AutonomyState.stopped,
            AutonomyState.failed,
        }
    ),
    AutonomyState.awaiting_execution_approval: frozenset(
        {
            AutonomyState.executing,
            AutonomyState.pivoting,
            AutonomyState.stopped,
            AutonomyState.failed,
        }
    ),
    AutonomyState.executing: frozenset(
        {AutonomyState.evaluating, AutonomyState.failed}
    ),
    AutonomyState.evaluating: frozenset(
        {AutonomyState.pivoting, AutonomyState.stopped, AutonomyState.failed}
    ),
    AutonomyState.pivoting: frozenset(
        {AutonomyState.observing, AutonomyState.stopped, AutonomyState.failed}
    ),
    AutonomyState.stopped: frozenset(),
    AutonomyState.failed: frozenset(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AutonomyStateMachine:
    def __init__(self, run: AutonomyRun) -> None:
        self.run = run
        self._transitions: list[StateTransition] = []

    @property
    def transitions(self) -> tuple[StateTransition, ...]:
        return tuple(self._transitions)

    def transition(self, next_state: AutonomyState, reason: str) -> StateTransition:
        current = self.run.current_state
        if next_state not in ALLOWED_TRANSITIONS[current]:
            raise InvalidStateTransition(
                f"Invalid autonomy transition: {current.value} -> {next_state.value}"
            )
        timestamp = utc_now()
        transition = StateTransition(
            previous_state=current,
            next_state=next_state,
            reason=reason,
            occurred_at=timestamp,
        )
        self.run.current_state = next_state
        self.run.updated_at = timestamp
        if next_state in {AutonomyState.stopped, AutonomyState.failed}:
            self.run.stopped_at = timestamp
        self._transitions.append(transition)
        return transition
