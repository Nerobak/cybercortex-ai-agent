from agent_core.request_budget import RequestBudget
from agent_core.research import (
    CleanupStatus,
    ModelSelectionAdmissionReason,
    ModelSelectionWallTimeReserve,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchBudgetStopReason,
    ResearchRunStatus,
)
from test_phase4_research_orchestrator import research_state


class FakeMonotonicClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _with_budget(state, budget):
    return state.model_copy(update={"budgets": (budget,)})


def test_default_research_budget_policy_matches_bounded_architecture():
    policy = ResearchBudgetPolicy()
    assert policy.initial_experiments_per_hypothesis == 1
    assert policy.pivots_per_hypothesis == 2
    assert policy.total_experiments_per_hypothesis == 3
    assert policy.experiments_per_surface == 8
    assert policy.equivalent_retries == 0
    assert policy.consecutive_service_instability_attempts == 2
    assert policy.global_experiment_ceiling == 50


def test_budget_consumption_persists_counts_and_never_refunds():
    state = research_state()
    manager = ResearchBudgetManager(request_budget=RequestBudget(5))
    budget = manager.consume_experiment(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        pivot=True,
        state_changing=False,
        cleanup_status=CleanupStatus.not_required,
    )
    payload = state.model_dump(mode="python")
    payload["budgets"] = (budget,)
    consumed = state.model_validate(payload)
    snapshot = manager.state(consumed)
    assert snapshot.experiments_consumed == 1
    assert snapshot.hypothesis_usage[0].attempt_count == 1
    assert snapshot.hypothesis_usage[0].pivot_count == 1
    assert snapshot.surface_usage[0].experiment_count == 1


def test_cleanup_barrier_and_request_reserve_fail_closed():
    state = research_state()
    manager = ResearchBudgetManager(
        ResearchBudgetPolicy(cleanup_request_reserve=2),
        request_budget=RequestBudget(2),
    )
    request = manager.check(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        estimated_requests=1,
    )
    assert request.reason is ResearchBudgetStopReason.request_budget_exhausted

    budget = manager.consume_experiment(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        pivot=False,
        state_changing=False,
        cleanup_status=CleanupStatus.failed,
        cleanup_barrier_reference="cleanup-1",
    )
    payload = state.model_dump(mode="python")
    payload["budgets"] = (budget,)
    blocked = state.model_validate(payload)
    assert (
        manager.check(
            blocked,
            hypothesis_id="hypothesis-1",
            surface_id="surface-1",
        ).reason
        is ResearchBudgetStopReason.cleanup_barrier
    )


def test_wall_time_snapshots_checks_and_synchronization_are_delta_based():
    state = research_state()
    clock = FakeMonotonicClock()
    manager = ResearchBudgetManager(clock=clock)

    initial = manager.state(state)
    clock.advance(60.0)
    first = manager.state(state)
    repeated_state = manager.state(state)
    first_check = manager.check(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        require_model_capacity=False,
    )
    second_check = manager.check(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        require_model_capacity=False,
    )

    assert initial.wall_time_consumed_seconds == 0.0
    assert first.wall_time_consumed_seconds == 60.0
    assert repeated_state.wall_time_consumed_seconds == 60.0
    assert first_check == second_check
    assert manager.state(state).wall_time_consumed_seconds == 60.0


def test_timeout_intervals_and_experiment_consumption_are_counted_once():
    state = research_state()
    clock = FakeMonotonicClock()
    manager = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=180.0),
        clock=clock,
    )

    manager.state(state)
    clock.advance(60.0)
    after_first_timeout = manager.state(state)
    consumed = manager.consume_experiment(
        state,
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        pivot=False,
        state_changing=False,
    )
    clock.advance(60.0)
    after_second_timeout = manager.state(_with_budget(state, consumed))

    # The legacy implementation added elapsed-since-start on each sync:
    # 60 persisted seconds + 120 elapsed seconds = the erroneous 180 seconds.
    legacy_double_count = after_first_timeout.wall_time_consumed_seconds + clock.value
    assert legacy_double_count == 180.0
    assert consumed.wall_time_consumed_seconds == 60.0
    assert after_second_timeout.wall_time_consumed_seconds == 120.0
    assert manager.remaining_wall_time_seconds(state) == 60.0


def test_wall_time_clamps_at_deadline_and_never_decreases_or_goes_negative():
    state = research_state()
    clock = FakeMonotonicClock(10.0)
    manager = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=180.0),
        clock=clock,
    )
    manager.state(state)
    clock.advance(500.0)
    exhausted = manager.state(state)
    clock.value = -100.0
    repeated = manager.state(state)

    assert exhausted.wall_time_consumed_seconds == 180.0
    assert repeated.wall_time_consumed_seconds == 180.0
    assert manager.remaining_wall_time_seconds(state) == 0.0


def test_restart_recovery_uses_persisted_floor_without_stale_clock_origin():
    state = research_state()
    first_clock = FakeMonotonicClock(1_000.0)
    first_manager = ResearchBudgetManager(clock=first_clock)
    first_manager.state(state)
    first_clock.advance(25.0)
    persisted = first_manager.state(state)
    recovered_state = _with_budget(state, persisted)

    restarted_clock = FakeMonotonicClock(2.0)
    restarted = ResearchBudgetManager(clock=restarted_clock)
    first_recovery = restarted.state(recovered_state)
    repeated_recovery = restarted.state(recovered_state)
    restarted_clock.advance(5.0)
    advanced = restarted.state(recovered_state)
    durable_advanced = _with_budget(state, advanced)
    repeated_restart = ResearchBudgetManager(clock=FakeMonotonicClock(0.0))

    assert first_recovery.wall_time_consumed_seconds == 25.0
    assert repeated_recovery.wall_time_consumed_seconds == 25.0
    assert advanced.wall_time_consumed_seconds == 30.0
    assert repeated_restart.state(durable_advanced).wall_time_consumed_seconds == 30.0
    terminal = durable_advanced.model_copy(update={"status": ResearchRunStatus.stopped})
    repeated_restart.state(terminal)
    assert terminal.status is ResearchRunStatus.stopped


def test_model_selection_admission_counts_all_reserves_without_charging_calls():
    state = research_state()
    clock = FakeMonotonicClock()
    manager = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=180.0),
        clock=clock,
    )
    reserve = ModelSelectionWallTimeReserve(
        experiment_execution_seconds=30.0,
        reproduction_seconds=20.0,
        cleanup_seconds=10.0,
    )

    admitted = manager.check_model_selection_admission(
        state,
        provider_timeout_seconds=60.0,
        reserve=reserve,
    )
    clock.advance(61.0)
    rejected = manager.check_model_selection_admission(
        state,
        provider_timeout_seconds=60.0,
        reserve=reserve,
    )

    assert admitted.allowed
    assert admitted.required_wall_time_seconds == 120.0
    assert rejected.reason is (
        ModelSelectionAdmissionReason.insufficient_wall_time_for_model_selection
    )
    assert rejected.remaining_wall_time_seconds == 119.0
    assert manager.state(state).model_budget.usage.attempted_calls == 0
