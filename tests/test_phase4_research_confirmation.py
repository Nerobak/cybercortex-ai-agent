from __future__ import annotations

import pytest

from agent_core.research import (
    CleanupExecutionResult,
    CleanupStatus,
    ExperimentResultClassification,
    ExperimentCompiler,
    ExperimentEvaluator,
    ExperimentSelector,
    FindingConfirmationAction,
    FindingConfirmationEvaluator,
    FindingStatus,
    ResearchPredicate,
    ReproductionClassification,
    ReproductionOutcomeEvaluator,
    PivotPlanner,
    ResearchBudgetManager,
    SecurityResearchOrchestrator,
    ResearchStore,
)
from tests.test_phase4_research_reproduction import (
    _persist_and_compile,
    _reproduction_runtime_outcome,
    _source_case,
)
from tests.test_phase4_research_runtime import authentication_differential_proposal
from tests.test_phase4_research_compiler import object_proposal
from tests.test_phase4_research_runtime import build_runtime_fixture


def _commit_reproduction(case, classification):
    plan, reproduction = _persist_and_compile(case)
    outcome = _reproduction_runtime_outcome(case, reproduction, classification)
    decision = FindingConfirmationEvaluator().evaluate_and_commit(
        finding_id=case.finding.finding_id,
        plan=plan,
        experiment=reproduction.experiment,
        runtime_outcome=outcome,
        policy=case.policy,
        store=case.store,
        budget_manager=case.budget_manager,
    )
    return decision, case.store.load_research("research-1"), plan, reproduction, outcome


def test_benchmark4_structural_authorization_fixture_confirms(tmp_path):
    case = _source_case(tmp_path)

    decision, state, plan, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.vulnerable_signal
    )

    finding = state.findings[0]
    assert decision.action is FindingConfirmationAction.confirm
    assert finding.status is FindingStatus.confirmed
    assert finding.reproduction_ids == (plan.reproduction_id,)
    assert finding.total_request_count == 4
    assert finding.confirmed_evidence_references
    assert state.reproduction_outcomes[0].classification is (
        ReproductionClassification.reproduced
    )


def test_false_positive_secure_reproduction_is_rejected_by_policy(tmp_path):
    case = _source_case(tmp_path)

    decision, state, _, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.secure_signal
    )

    assert decision.action is FindingConfirmationAction.reject
    assert state.findings[0].status is FindingStatus.rejected
    assert state.findings[0].contradictory_evidence
    assert state.findings[0].status is not FindingStatus.confirmed


def test_inconclusive_reproduction_remains_unconfirmed(tmp_path):
    case = _source_case(tmp_path)

    decision, state, _, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.inconclusive
    )

    assert decision.action is FindingConfirmationAction.remain_candidate
    assert state.findings[0].status is FindingStatus.candidate
    assert state.findings[0].controlled_impact is None


def test_authentication_differential_confirms_with_exact_accounting(tmp_path):
    proposal = authentication_differential_proposal().model_copy(
        update={"state_revision": 0}
    )
    case = _source_case(
        tmp_path,
        proposal=proposal,
        category="authentication",
    )

    decision, state, _, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.vulnerable_signal
    )

    finding = state.findings[0]
    usage = case.budget_manager.state(state).reproduction_usage[0]
    assert decision.action is FindingConfirmationAction.confirm
    assert finding.category == "authentication"
    assert finding.status is FindingStatus.confirmed
    assert finding.source_request_delta.total == 2
    assert finding.total_request_count == 4
    assert usage.target_requests_consumed == 2


def test_cleanup_failure_can_never_confirm(tmp_path):
    case = _source_case(tmp_path)
    plan, reproduction = _persist_and_compile(case)
    outcome = _reproduction_runtime_outcome(
        case, reproduction, ExperimentResultClassification.cleanup_failed
    ).model_copy(
        update={
            "cleanup_status": CleanupStatus.failed,
            "cleanup_result": CleanupExecutionResult(status=CleanupStatus.failed),
        }
    )

    decision = FindingConfirmationEvaluator().evaluate_and_commit(
        finding_id=case.finding.finding_id,
        plan=plan,
        experiment=reproduction.experiment,
        runtime_outcome=outcome,
        policy=case.policy,
        store=case.store,
        budget_manager=case.budget_manager,
    )
    state = case.store.load_research("research-1")

    assert decision.action is FindingConfirmationAction.stop
    assert state.findings[0].status is FindingStatus.candidate
    assert state.findings[0].status is not FindingStatus.confirmed


def test_atomic_persistence_failure_leaves_reproducing_candidate_intact(tmp_path):
    case = _source_case(tmp_path)
    plan, reproduction = _persist_and_compile(case)
    outcome = _reproduction_runtime_outcome(
        case, reproduction, ExperimentResultClassification.vulnerable_signal
    )

    class FailingStore:
        def load_research(self, research_id):
            return case.store.load_research(research_id)

        def commit_revision(self, *args, **kwargs):
            del args, kwargs
            raise RuntimeError("synthetic persistence failure")

    with pytest.raises(RuntimeError, match="synthetic persistence failure"):
        FindingConfirmationEvaluator().evaluate_and_commit(
            finding_id=case.finding.finding_id,
            plan=plan,
            experiment=reproduction.experiment,
            runtime_outcome=outcome,
            policy=case.policy,
            store=FailingStore(),
            budget_manager=case.budget_manager,
        )

    unchanged = case.store.load_research("research-1")
    assert unchanged.findings[0].status is FindingStatus.reproducing
    assert unchanged.reproduction_outcomes == ()
    assert unchanged.confirmation_decisions == ()


def test_confirmation_graph_is_evidence_backed_and_deterministic(tmp_path):
    case = _source_case(tmp_path)
    _, state, _, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.vulnerable_signal
    )

    confirmed = case.store.query_graph_assertions(
        state.research_id,
        relation=ResearchPredicate.finding_confirmed_by,
    )
    reproduced = case.store.query_graph_assertions(
        state.research_id,
        relation=ResearchPredicate.finding_reproduced_by,
    )
    reproduction_of = case.store.query_graph_assertions(
        state.research_id,
        relation=ResearchPredicate.reproduction_of,
    )

    assert confirmed and reproduced and reproduction_of
    assert confirmed[0].evidence_references
    assert confirmed[0].derivation_type.value == "deterministic"


def test_completed_reproduction_survives_restart_without_budget_duplication(tmp_path):
    case = _source_case(tmp_path)
    _, state, plan, _, _ = _commit_reproduction(
        case, ExperimentResultClassification.vulnerable_signal
    )
    database = case.store.database
    case.store.close()

    restarted = ResearchStore(database)
    recovered = restarted.load_research(state.research_id)
    usage = case.budget_manager.state(recovered).reproduction_usage[0]

    assert recovered.findings[0].status is FindingStatus.confirmed
    assert recovered.reproduction_plans[0].reproduction_id == plan.reproduction_id
    assert recovered.reproduction_plans[0].status.value == "completed"
    assert len(recovered.reproduction_outcomes) == 1
    assert usage.attempts_consumed == 1
    assert usage.target_requests_consumed == 2


def test_reused_authorization_binding_is_blocked_not_confirmed(tmp_path):
    case = _source_case(tmp_path)
    plan, reproduction = _persist_and_compile(case)
    outcome = _reproduction_runtime_outcome(
        case, reproduction, ExperimentResultClassification.vulnerable_signal
    ).model_copy(
        update={"authorization_reference": case.finding.source_authorization_reference}
    )

    reproduction_outcome = ReproductionOutcomeEvaluator().evaluate(
        case.store.load_research("research-1").findings[0],
        plan,
        reproduction.experiment,
        outcome,
    )

    assert reproduction_outcome.classification is ReproductionClassification.blocked
    assert reproduction_outcome.independence is not None
    assert reproduction_outcome.independence.new_authorization is False


def test_orchestrator_runs_eligible_read_only_confirmation_without_model(tmp_path):
    stores = []

    def create_store(state):
        store = ResearchStore(tmp_path / "orchestrated-confirmation.sqlite3")
        initial = state.model_copy(update={"revision": 0})
        store.create_research(initial)
        current = initial
        for revision in range(1, state.revision + 1):
            current = current.model_copy(update={"revision": revision})
            store.commit_revision(
                state.research_id,
                expected_revision=revision - 1,
                state=current,
            )
        stores.append(store)
        return store

    proposal = object_proposal()
    fixture = build_runtime_fixture(
        proposal=proposal,
        statuses=(200, 200, 200, 200, 200),
        store_factory=create_store,
    )
    budgets = ResearchBudgetManager(request_budget=fixture.budget)
    compiler = ExperimentCompiler(context=fixture.gate.compiler_context)
    selector = ExperimentSelector(compiler, budgets)
    runner = SecurityResearchOrchestrator(
        store=stores[0],
        compiler=compiler,
        compiler_context=fixture.gate.compiler_context,
        gate=fixture.gate,
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        enable_finding_confirmation=True,
    )

    result = runner.run("research-1", proposals=(proposal,))

    assert result.state.findings[0].status is FindingStatus.confirmed
    assert len(result.state.reproduction_outcomes) == 1
    assert result.state.budgets[0].model_budget.usage.attempted_calls == 0
