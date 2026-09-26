from __future__ import annotations

import io
from pathlib import Path

import pytest

import research_cli
from agent_core.models import ModelUsageDelta
from agent_core.request_budget import RequestDelta
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    AttackChain,
    AttackChainCandidateBuilder,
    AttackChainConfirmationEvaluator,
    AttackChainEvaluationClassification,
    AttackChainEvaluator,
    AttackChainStatus,
    AttackChainStep,
    ChainBudgetState,
    ChainBudgetLimits,
    ChainBudgetManager,
    ChainConfirmationAction,
    ChainConfirmationPolicy,
    ChainExperimentPlanner,
    ChainLinkStatus,
    ChainReproductionPlanner,
    ChainStepOutcome,
    CleanupStatus,
    EntityKind,
    EntityReference,
    HypothesisResearchStatus,
    ResearchState,
    ResearchBudgetManager,
    ResearchStore,
    apply_chain_evaluation,
    create_chain_candidate_finding,
    materialize_attack_chain,
    materialize_chain_hypothesis,
    resolve_chain_link,
)
from tests.phase4_chain_helpers import TS, TS_1, chain_state, experiment_candidate

AUTHORIZATION = "sha256:" + "a" * 64


def built_chain():
    state = chain_state()
    experiment = experiment_candidate(state)
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment,)
    )[0]
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate,
        hypothesis,
        provenance_id="prov-chain",
        created_at=TS,
    )
    return state, experiment, candidate, hypothesis, chain


def outcome(chain: AttackChain, status: ChainLinkStatus) -> ChainStepOutcome:
    step = chain.steps[1]
    return ChainStepOutcome(
        outcome_id=f"chain-outcome-{status.value}",
        chain_id=chain.attack_chain_id,
        step_id=str(step.step_id),
        sequence=step.sequence,
        status=status,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        request_delta=RequestDelta(verification=2, attempted=2, total=2),
        cleanup_status=CleanupStatus.completed,
        authorization_reference=AUTHORIZATION,
        occurred_at=TS_1,
    )


def reproduction_step_outcome(chain: AttackChain) -> ChainStepOutcome:
    step = chain.steps[1]
    return ChainStepOutcome(
        outcome_id="chain-outcome-fresh-reproduction",
        chain_id=chain.attack_chain_id,
        step_id=str(step.step_id),
        sequence=step.sequence,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain-reproduction",),
        experiment_id="experiment-chain-link-reproduction",
        request_delta=RequestDelta(verification=2, attempted=2, total=2),
        cleanup_status=CleanupStatus.completed,
        authorization_reference="sha256:" + "b" * 64,
        occurred_at=TS_1,
    )


def test_supported_link_produces_candidate_chain_finding():
    state, _, _, _, chain = built_chain()
    evaluation = AttackChainEvaluator().evaluate(
        chain, (outcome(chain, ChainLinkStatus.supported),), state
    )

    assert (
        evaluation.classification
        is AttackChainEvaluationClassification.candidate_chain_finding
    )
    assert evaluation.combined_impact_evidence == ("evidence-chain",)
    finding = create_chain_candidate_finding(
        chain, evaluation, state, provenance_id="prov-chain"
    )
    assert finding.source_chain_id == chain.attack_chain_id
    assert finding.status.value == "candidate"


def test_refuted_link_stops_downstream_steps_with_zero_downstream_requests():
    state, _, _, _, chain = built_chain()
    payload = chain.model_dump(mode="python")
    payload.update(
        semantic_fingerprint=None,
        steps=(
            *chain.steps,
            AttackChainStep(
                step_id="chain-step-downstream",
                sequence=3,
                source_reference=EntityReference(
                    entity_kind=EntityKind.object, entity_id="object-controlled"
                ),
                required_preconditions=(str(chain.steps[1].step_id),),
                evidence_requirements=("predicate:must-not-run",),
            ),
        ),
    )
    expanded = AttackChain.model_validate(payload)
    evaluation = AttackChainEvaluator().evaluate(
        expanded, (outcome(expanded, ChainLinkStatus.refuted),), state
    )

    assert evaluation.classification is AttackChainEvaluationClassification.refuted
    assert evaluation.downstream_steps_skipped == ("chain-step-downstream",)
    assert evaluation.request_delta.total == 2


def test_independent_reproduction_and_deterministic_confirmation():
    state, experiment, candidate, hypothesis, chain = built_chain()
    step_outcome = outcome(chain, ChainLinkStatus.supported)
    evaluation = AttackChainEvaluator().evaluate(chain, (step_outcome,), state)
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        updated_at=TS_1,
    )
    candidate_chain = apply_chain_evaluation(resolved, evaluation)
    finding = create_chain_candidate_finding(
        candidate_chain, evaluation, state, provenance_id="prov-chain"
    )
    experiment_plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, state, (experiment,)
    )
    assert experiment_plan is not None
    reproduction_plan = ChainReproductionPlanner().plan(
        finding,
        candidate_chain,
        (experiment_plan,),
        state,
        provenance_id="prov-chain",
        maximum_target_requests=4,
    )
    reproduction = ChainReproductionPlanner.evaluate(
        reproduction_plan,
        (reproduction_step_outcome(candidate_chain),),
        occurred_at=TS_1,
    )
    decision = AttackChainConfirmationEvaluator().evaluate(
        finding,
        candidate_chain,
        (reproduction,),
        ChainConfirmationPolicy(policy_reference="chain-confirmation-policy-v1"),
        state,
    )

    assert decision.action is ChainConfirmationAction.confirm
    confirmed_finding, confirmed_chain = AttackChainConfirmationEvaluator.promote(
        finding, candidate_chain, decision, (reproduction,)
    )
    assert confirmed_finding.status.value == "confirmed"
    assert confirmed_finding.total_request_count == 4
    assert confirmed_chain.status is AttackChainStatus.confirmed
    assert confirmed_chain.combined_impact_evidence == (
        "evidence-chain",
        "evidence-chain-reproduction",
    )


def test_restart_preserves_completed_link_and_budget(tmp_path: Path):
    state, experiment, candidate, hypothesis, chain = built_chain()
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        updated_at=TS_1,
    )
    budget = ChainBudgetState(
        budget_reference="chain-budget-v1",
        experiments_consumed=1,
        target_requests_consumed=2,
        model_usage=ModelUsageDelta(),
        completed_step_ids=(str(chain.steps[1].step_id),),
        authoritative_request_ledger_reference="request-budget-v1",
    )
    payload = state.model_dump(mode="python")
    payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(resolved,),
        chain_step_outcomes=(outcome(chain, ChainLinkStatus.supported),),
        chain_budgets=(budget,),
        updated_at=TS_1,
    )
    persisted = ResearchState.model_validate(payload)
    store = ResearchStore(tmp_path / "chain-restart.sqlite3")
    store.create_research(persisted)
    restarted = store.load_research(state.research_id)

    assert restarted.chain_budgets[0].target_requests_consumed == 2
    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis, candidate, restarted, (experiment,)
        )
        is None
    )


def test_restart_refreshes_stale_experiment_binding_without_repeating_prior_work(
    tmp_path: Path,
):
    state, experiment, candidate, hypothesis, chain = built_chain()
    payload = state.model_dump(mode="python")
    payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(chain,),
    )
    initial = ResearchState.model_validate(payload)
    store = ResearchStore(tmp_path / "chain-continue.sqlite3")
    store.create_research(initial)
    next_payload = initial.model_dump(mode="python")
    next_payload.update(revision=1, updated_at=TS_1)
    store.commit_revision(
        state.research_id,
        expected_revision=0,
        state=ResearchState.model_validate(next_payload),
    )
    restarted = store.load_research(state.research_id)
    refreshed_experiment = experiment.model_copy(
        update={
            "candidate_id": "experiment-candidate-chain-revision-1",
            "state_revision": 1,
        }
    )

    plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, restarted, (refreshed_experiment,)
    )
    assert plan is not None
    assert plan.experiment_candidate_id == refreshed_experiment.candidate_id


def test_chain_budget_reconciles_exactly_to_authoritative_request_ledger():
    state = chain_state()
    request_budget = RequestBudget(limit=5)
    research_budgets = ResearchBudgetManager(request_budget=request_budget)
    manager = ChainBudgetManager(
        research_budgets,
        ChainBudgetLimits(maximum_chain_target_requests=2),
    )
    initial = manager.state(state)
    payload = state.model_dump(mode="python")
    payload.update(chain_budgets=(initial,))
    checkpoint = ResearchState.model_validate(payload)

    request_budget.consume("verification", 2)
    consumed = manager.consume(
        checkpoint,
        request_delta=RequestDelta(verification=2, attempted=2, total=2),
        experiment=True,
        completed_step_id="chain-step-accounted",
    )
    assert consumed.target_requests_consumed == request_budget.total == 2
    assert consumed.authoritative_request_total_observed == 2

    payload = checkpoint.model_dump(mode="python")
    payload.update(chain_budgets=(consumed,))
    exhausted = ResearchState.model_validate(payload)
    assert not manager.check(exhausted, estimated_requests=1).allowed


def test_explicit_unresolved_link_cannot_be_inferred_from_supported_entity():
    state, _, _, _, chain = built_chain()
    payload = state.model_dump(mode="python")
    payload["hypotheses"] = (
        state.hypotheses[0].model_copy(
            update={"status": HypothesisResearchStatus.supported}
        ),
    )
    supported_entity_state = ResearchState.model_validate(payload)

    evaluation = AttackChainEvaluator().evaluate(chain, (), supported_entity_state)

    assert evaluation.classification is AttackChainEvaluationClassification.inconclusive
    assert evaluation.blocking_reason == ChainLinkStatus.unresolved.value


def test_cleanup_failure_blocks_supported_chain_outcome():
    state, _, _, _, chain = built_chain()
    supported = outcome(chain, ChainLinkStatus.supported).model_copy(
        update={"cleanup_status": CleanupStatus.failed}
    )

    evaluation = AttackChainEvaluator().evaluate(chain, (supported,), state)

    assert evaluation.classification is AttackChainEvaluationClassification.blocked
    assert evaluation.blocking_reason == ChainLinkStatus.cleanup_failed.value


def test_reproduction_outcomes_must_match_plan_and_request_ceiling():
    state, experiment, candidate, hypothesis, chain = built_chain()
    evaluation = AttackChainEvaluator().evaluate(
        chain, (outcome(chain, ChainLinkStatus.supported),), state
    )
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        updated_at=TS_1,
    )
    candidate_chain = apply_chain_evaluation(resolved, evaluation)
    finding = create_chain_candidate_finding(
        candidate_chain, evaluation, state, provenance_id="prov-chain"
    )
    experiment_plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, state, (experiment,)
    )
    assert experiment_plan is not None
    reproduction_plan = ChainReproductionPlanner().plan(
        finding,
        candidate_chain,
        (experiment_plan,),
        state,
        provenance_id="prov-chain",
        maximum_target_requests=2,
    )
    wrong_step = reproduction_step_outcome(candidate_chain).model_copy(
        update={"step_id": "chain-step-unbound"}
    )
    with pytest.raises(ValueError, match="do not match the plan"):
        ChainReproductionPlanner.evaluate(
            reproduction_plan, (wrong_step,), occurred_at=TS_1
        )

    over_budget = reproduction_plan.model_copy(update={"maximum_target_requests": 1})
    with pytest.raises(ValueError, match="request ceiling"):
        ChainReproductionPlanner.evaluate(
            over_budget,
            (reproduction_step_outcome(candidate_chain),),
            occurred_at=TS_1,
        )


def test_chain_budget_checks_only_requested_operation_and_prevents_reaccounting():
    state = chain_state()
    request_budget = RequestBudget(limit=5)
    research_budgets = ResearchBudgetManager(request_budget=request_budget)
    manager = ChainBudgetManager(
        research_budgets,
        ChainBudgetLimits(maximum_chain_experiments=0),
    )
    initial = manager.state(state)
    payload = state.model_dump(mode="python")
    payload.update(chain_budgets=(initial,))
    checkpoint = ResearchState.model_validate(payload)

    assert manager.check(checkpoint).allowed
    denied = manager.check(checkpoint, experiment=True)
    assert not denied.allowed
    assert denied.reason is not None
    assert denied.reason.value == "experiment_budget_exhausted"

    request_budget.consume("verification", 1)
    accounted = manager.consume(
        checkpoint,
        request_delta=RequestDelta(verification=1, attempted=1, total=1),
        completed_step_id="chain-step-once",
    )
    payload = checkpoint.model_dump(mode="python")
    payload.update(chain_budgets=(accounted,))
    persisted = ResearchState.model_validate(payload)
    with pytest.raises(ValueError, match="already accounted"):
        manager.consume(persisted, completed_step_id="chain-step-once")


def test_persisted_chain_outcome_must_bind_an_existing_step():
    state, _, candidate, hypothesis, chain = built_chain()
    bad_outcome = outcome(chain, ChainLinkStatus.supported).model_copy(
        update={"step_id": "chain-step-missing"}
    )
    payload = state.model_dump(mode="python")
    payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(chain,),
        chain_step_outcomes=(bad_outcome,),
    )

    with pytest.raises(ValueError, match="does not match its chain step"):
        ResearchState.model_validate(payload)


def test_chain_cli_trace_and_summary_are_reference_only_and_accounted():
    state, _, candidate, hypothesis, chain = built_chain()
    step_outcome = outcome(chain, ChainLinkStatus.supported)
    evaluation = AttackChainEvaluator().evaluate(chain, (step_outcome,), state)
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        updated_at=TS_1,
    )
    candidate_chain = apply_chain_evaluation(resolved, evaluation)
    finding = create_chain_candidate_finding(
        candidate_chain, evaluation, state, provenance_id="prov-chain"
    )
    chain_budget = ChainBudgetState(
        budget_reference="chain-budget-v1",
        experiments_consumed=1,
        target_requests_consumed=2,
        completed_step_ids=(step_outcome.step_id,),
        authoritative_request_ledger_reference="request-budget-v1",
        authoritative_request_total_observed=2,
    )
    payload = state.model_dump(mode="python")
    payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(candidate_chain,),
        chain_step_outcomes=(step_outcome,),
        chain_evaluations=(evaluation,),
        findings=(finding,),
        chain_budgets=(chain_budget,),
    )
    persisted = ResearchState.model_validate(payload)
    stream = io.StringIO()

    research_cli._trace_state(
        research_cli.SafeTracer(True, stream), persisted, "fixture_complete"
    )
    trace = stream.getvalue()
    for event in (
        "CHAIN_CANDIDATE",
        "CHAIN_SELECT",
        "CHAIN_HYPOTHESIS",
        "CHAIN_STEP_PLAN",
        "CHAIN_STEP_AUTHORIZE",
        "CHAIN_STEP_EXECUTE",
        "CHAIN_STEP_EVALUATE",
        "CHAIN_SUPPORTED",
        "CHAIN_CANDIDATE_FINDING",
    ):
        assert f'"event": "{event}"' in trace
    assert AUTHORIZATION not in trace

    request_budget = RequestBudget(limit=5)
    request_budget.consume("verification", 2)
    summary = research_cli.safe_run_summary(
        state=persisted,
        budget_manager=ResearchBudgetManager(request_budget=request_budget),
        request_budget=request_budget,
        iterations=1,
        stop_reason="fixture_complete",
    )
    assert summary["chains_considered"] == 1
    assert summary["chains_supported"] == 1
    assert summary["chain_findings"] == 1
    assert summary["chain_requests"] == 2
