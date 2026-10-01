from __future__ import annotations

from pathlib import Path

from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta
from agent_core.research import (
    AttackChainCandidateBuilder,
    AttackChainConfirmationEvaluator,
    AttackChainEvaluationClassification,
    AttackChainEvaluator,
    AttackChainStatus,
    ChainBudgetLimits,
    ChainBudgetState,
    ChainConfirmationAction,
    ChainConfirmationPolicy,
    ChainExperimentPlanner,
    ChainLinkStatus,
    ChainReproductionPlanner,
    ChainStepOutcome,
    CleanupStatus,
    EvidenceArtifact,
    ExperimentOutcome,
    ExperimentResultClassification,
    ExperimentRuntimeStatus,
    FindingStatus,
    GraphQLEvaluationResult,
    GraphQLSecurityProperty,
    ResearchState,
    ResearchStore,
    apply_chain_evaluation,
    create_chain_candidate_finding,
    graphql_chain_step_outcome,
    materialize_attack_chain,
    materialize_chain_hypothesis,
    resolve_chain_link,
)

from test_phase4_graphql_chains import TS, _graphql_fixture, _state

AUTHORIZATION_A = "sha256:" + "a" * 64
AUTHORIZATION_B = "sha256:" + "b" * 64


def _built_graphql_chain():
    state, experiments = _graphql_fixture()
    candidate = next(
        item
        for item in AttackChainCandidateBuilder().build(
            state, experiment_candidates=experiments
        )
        if item.category == "rest-to-graphql"
    )
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate,
        hypothesis,
        provenance_id="prov-graphql",
        created_at=TS,
    )
    return state, experiments, candidate, hypothesis, chain


def _chain_outcome(chain, *, evidence: str, authorization: str, suffix: str):
    step = next(item for item in chain.steps if item.unresolved_link_id is not None)
    return ChainStepOutcome(
        outcome_id=f"graphql-chain-step-{suffix}",
        chain_id=chain.attack_chain_id,
        step_id=str(step.step_id),
        sequence=step.sequence,
        status=ChainLinkStatus.supported,
        evidence_references=(evidence,),
        experiment_id=f"graphql-experiment-{suffix}",
        request_delta=RequestDelta(verification=2, attempted=2, total=2),
        cleanup_status=CleanupStatus.completed,
        authorization_reference=authorization,
        provenance_id="prov-graphql",
        occurred_at=TS,
    )


def _fresh_evidence(state: ResearchState) -> EvidenceArtifact:
    return state.evidence[0].model_copy(
        update={
            "evidence_id": "evidence-graphql-chain-reproduction",
            "digest": "sha256:" + "c" * 64,
            "summary": "Fresh ordered GraphQL chain reproduction evidence.",
            "source_reference": "graphql-chain-reproduction-runtime",
        }
    )


def test_graphql_differential_result_deterministically_controls_chain_link():
    state, experiments, _, _, chain = _built_graphql_chain()
    stored = ExperimentOutcome(
        outcome_id="outcome-graphql-chain-secure",
        experiment_id="experiment-graphql-chain-secure",
        runtime_status=ExperimentRuntimeStatus.completed,
        canonical_result_classification=Phase2ResultStatus.rejected,
        evidence_references=("evidence-graphql",),
        request_delta=RequestDelta(verification=2, attempted=2, total=2),
        cleanup_status=CleanupStatus.completed,
        provenance_id="prov-graphql",
        occurred_at=TS,
    )
    evaluation = GraphQLEvaluationResult(
        evaluation_id="evaluation-graphql-chain-secure",
        experiment_id=stored.experiment_id,
        outcome_id=stored.outcome_id,
        hypothesis_id=experiments[0].hypothesis_id,
        security_property=GraphQLSecurityProperty.object_authorization,
        classification=ExperimentResultClassification.secure_signal,
        operation_reference=experiments[0].operation_id,
        evidence_references=stored.evidence_references,
        summary="The registered GraphQL object boundary was enforced.",
    )

    step = graphql_chain_step_outcome(
        chain,
        unresolved_link_id=chain.unresolved_links[0].link_id,
        graphql_evaluation=evaluation,
        experiment_outcome=stored,
        authorization_reference=AUTHORIZATION_A,
    )
    chain_evaluation = AttackChainEvaluator().evaluate(chain, (step,), state)

    assert step.status is ChainLinkStatus.refuted
    assert (
        chain_evaluation.classification is AttackChainEvaluationClassification.refuted
    )
    assert chain_evaluation.request_delta.total == 2


def test_supported_graphql_link_produces_candidate_chain_finding():
    state, _, _, _, chain = _built_graphql_chain()
    step = _chain_outcome(
        chain,
        evidence="evidence-graphql",
        authorization=AUTHORIZATION_A,
        suffix="supported",
    )

    evaluation = AttackChainEvaluator().evaluate(chain, (step,), state)

    assert (
        evaluation.classification
        is AttackChainEvaluationClassification.candidate_chain_finding
    )
    finding = create_chain_candidate_finding(
        chain, evaluation, state, provenance_id="prov-graphql"
    )
    assert finding.status is FindingStatus.candidate
    assert finding.chain_graphql_semantic_references
    assert finding.graphql_operation_id is None


def test_independent_graphql_chain_reproduction_confirms_deterministically():
    state, experiments, candidate, hypothesis, chain = _built_graphql_chain()
    fresh = _fresh_evidence(state)
    state = _state(state, evidence=(*state.evidence, fresh))
    step = _chain_outcome(
        chain,
        evidence="evidence-graphql",
        authorization=AUTHORIZATION_A,
        suffix="supported",
    )
    evaluation = AttackChainEvaluator().evaluate(chain, (step,), state)
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-graphql",),
        experiment_id=step.experiment_id,
        updated_at=TS,
    )
    candidate_chain = apply_chain_evaluation(resolved, evaluation)
    finding = create_chain_candidate_finding(
        candidate_chain, evaluation, state, provenance_id="prov-graphql"
    )
    experiment_plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, state, experiments
    )
    assert experiment_plan is not None
    reproduction_plan = ChainReproductionPlanner().plan(
        finding,
        candidate_chain,
        (experiment_plan,),
        state,
        provenance_id="prov-graphql",
        maximum_target_requests=2,
    )
    reproduction_step = _chain_outcome(
        candidate_chain,
        evidence=fresh.evidence_id,
        authorization=AUTHORIZATION_B,
        suffix="reproduction",
    ).model_copy(update={"experiment_id": "graphql-experiment-reproduction-fresh"})
    reproduction = ChainReproductionPlanner.evaluate(
        reproduction_plan, (reproduction_step,), occurred_at=TS
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
    assert confirmed_finding.status is FindingStatus.confirmed
    assert confirmed_chain.status is AttackChainStatus.confirmed
    assert fresh.evidence_id in confirmed_chain.combined_impact_evidence


def test_stale_graphql_semantics_prevent_chain_confirmation():
    state, experiments, candidate, hypothesis, chain = _built_graphql_chain()
    fresh = _fresh_evidence(state)
    state = _state(state, evidence=(*state.evidence, fresh))
    step = _chain_outcome(
        chain,
        evidence="evidence-graphql",
        authorization=AUTHORIZATION_A,
        suffix="supported",
    )
    evaluation = AttackChainEvaluator().evaluate(chain, (step,), state)
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-graphql",),
        experiment_id=step.experiment_id,
        updated_at=TS,
    )
    candidate_chain = apply_chain_evaluation(resolved, evaluation)
    finding = create_chain_candidate_finding(
        candidate_chain, evaluation, state, provenance_id="prov-graphql"
    )
    experiment_plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, state, experiments
    )
    assert experiment_plan is not None
    reproduction_plan = ChainReproductionPlanner().plan(
        finding,
        candidate_chain,
        (experiment_plan,),
        state,
        provenance_id="prov-graphql",
        maximum_target_requests=2,
    )
    reproduction = ChainReproductionPlanner.evaluate(
        reproduction_plan,
        (
            _chain_outcome(
                candidate_chain,
                evidence=fresh.evidence_id,
                authorization=AUTHORIZATION_B,
                suffix="reproduction",
            ),
        ),
        occurred_at=TS,
    )
    changed = state.graphql_operations[0].model_copy(
        update={"selection_fingerprint": "sha256:" + "d" * 64}
    )
    stale_state = _state(state, graphql_operations=(changed,))

    decision = AttackChainConfirmationEvaluator().evaluate(
        finding,
        candidate_chain,
        (reproduction,),
        ChainConfirmationPolicy(policy_reference="chain-confirmation-policy-v1"),
        stale_state,
    )
    assert decision.action is ChainConfirmationAction.manual_review
    assert decision.reason_code == "stale_graphql_semantics"


def test_graphql_chain_restart_does_not_repeat_supported_link(tmp_path: Path):
    state, experiments, candidate, hypothesis, chain = _built_graphql_chain()
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-graphql",),
        experiment_id="experiment-graphql-supported",
        updated_at=TS,
    )
    payload = state.model_dump(mode="python")
    payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(resolved,),
    )
    persisted = ResearchState.model_validate(payload)
    store = ResearchStore(tmp_path / "graphql-chain-restart.sqlite3")
    store.create_research(persisted)
    restarted = store.load_research(state.research_id)

    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis, candidate, restarted, experiments
        )
        is None
    )


def test_graphql_chain_request_budget_blocks_before_planning():
    state, experiments, candidate, hypothesis, _ = _built_graphql_chain()
    budget = ChainBudgetState(
        budget_reference="graphql-chain-budget",
        limits=ChainBudgetLimits(maximum_chain_target_requests=0),
        authoritative_request_ledger_reference="request-budget",
    )

    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis,
            candidate,
            state,
            experiments,
            budget_state=budget,
        )
        is None
    )


def test_graphql_chain_fingerprint_tracks_semantic_change_not_wording():
    state, experiments, candidate, _, _ = _built_graphql_chain()
    same = next(
        item
        for item in AttackChainCandidateBuilder().build(
            state, experiment_candidates=experiments
        )
        if item.category == "rest-to-graphql"
    )
    changed_operation = state.graphql_operations[0].model_copy(
        update={"selection_fingerprint": "sha256:" + "e" * 64}
    )
    changed_state = _state(state, graphql_operations=(changed_operation,))
    changed = next(
        item
        for item in AttackChainCandidateBuilder().build(
            changed_state, experiment_candidates=experiments
        )
        if item.category == "rest-to-graphql"
    )

    assert same.semantic_fingerprint == candidate.semantic_fingerprint
    assert changed.semantic_fingerprint != candidate.semantic_fingerprint
