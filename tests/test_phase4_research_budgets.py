from agent_core.request_budget import RequestBudget
from agent_core.research import (
    CleanupStatus,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchBudgetStopReason,
)
from test_phase4_research_orchestrator import research_state


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
