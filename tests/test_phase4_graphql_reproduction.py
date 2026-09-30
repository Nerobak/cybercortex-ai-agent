from __future__ import annotations

import json

import pytest

from agent_core.controlled_context import ControlledObject
from agent_core.research import (
    ExperimentCompiler,
    ExperimentEvaluator,
    ExperimentResultClassification,
    FindingConfirmationEvaluator,
    FindingConfirmationPolicy,
    FindingStatus,
    GraphQLCandidateKind,
    GraphQLReproductionPlanner,
    GraphQLReproductionSelectionDecision,
    GraphQLReproductionSelector,
    IdentityEligibility,
    ReproductionIndependentDimension,
    ReproductionPlanner,
    ReproductionPlanningError,
    ResearchBudgetPolicy,
    ResearchBudgetManager,
    ResearchStore,
)
from test_phase4_graphql_differentials import _with_comparison_state_effect
from test_phase4_graphql_runtime import FakeResponse, SECRET, _runtime_fixture
from test_phase4_graphql_runtime import _mutation_runtime_fixture


def _source_case(
    tmp_path,
    kind: GraphQLCandidateKind,
    *,
    reproduction_responses=(),
):
    database = tmp_path / f"graphql-reproduction-{kind.value}.sqlite3"
    stores: list[ResearchStore] = []

    def create_store(state):
        store = ResearchStore(database)
        store.create_research(state)
        stores.append(store)
        return store

    fixture = _runtime_fixture(
        candidate_kind=kind,
        responses=(FakeResponse(), FakeResponse(), *reproduction_responses),
        store_factory=create_store,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    budgets = ResearchBudgetManager(request_budget=fixture.budget)
    evaluation = ExperimentEvaluator().evaluate_and_commit(
        fixture.experiment,
        authorization,
        outcome,
        stores[0],
        budget_manager=budgets,
    )
    assert evaluation.classification is ExperimentResultClassification.vulnerable_signal
    assert evaluation.candidate_finding is not None
    finding = stores[0].load_research(fixture.experiment.research_id).findings[0]
    policy = FindingConfirmationPolicy.graphql_read_only(
        finding.confirmation_policy_reference
    )
    return fixture, stores[0], budgets, outcome, finding, policy


def _plan_and_compile(case):
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    planner = ReproductionPlanner()
    plans = planner.plan(
        finding,
        state,
        fixture.experiment,
        source_outcome,
        confirmation_policy=policy,
        budget_manager=budgets,
        compiler_context=fixture.gate.compiler_context,
    )
    selected = GraphQLReproductionSelector.select(state, finding, plans).plan
    state = planner.persist_plan(
        selected,
        store,
        budget_manager=budgets,
        occurred_at="2026-09-28T12:00:01+00:00",
    )
    compiler = ExperimentCompiler(context=fixture.gate.compiler_context)
    reproduction = planner.compile(
        selected,
        fixture.experiment,
        state,
        compiler,
        fixture.gate.compiler_context,
    )
    return selected, reproduction


def test_graphql_bola_uses_fresh_runtime_and_confirms_through_p4_0f(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, _source_outcome, finding, policy = case
    plan, reproduction = _plan_and_compile(case)

    authorization, binding = fixture.gate.authorize_and_bind(reproduction.experiment)
    outcome = binding.submit(authorization)
    decision = FindingConfirmationEvaluator().evaluate_and_commit(
        finding_id=finding.finding_id,
        plan=plan,
        experiment=reproduction.experiment,
        runtime_outcome=outcome,
        policy=policy,
        store=store,
        budget_manager=budgets,
    )
    state = store.load_research(fixture.experiment.research_id)

    assert decision.action.value == "confirm"
    assert state.findings[0].status is FindingStatus.confirmed
    assert state.reproduction_outcomes[0].independence.valid
    assert state.reproduction_outcomes[0].graphql_operation_id == (
        finding.graphql_operation_id
    )
    assert outcome.authorization_reference != finding.source_authorization_reference
    assert set(outcome.evidence_references).isdisjoint(finding.evidence_references)
    assert len(fixture.calls) == 4


def test_stale_graphql_selection_blocks_before_target_request(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    operation = state.graphql_operations[0].model_copy(
        update={"selection_fingerprint": "sha256:" + "a" * 64}
    )
    stale = state.model_copy(update={"graphql_operations": (operation,)})

    with pytest.raises(ReproductionPlanningError, match="schema_changed"):
        GraphQLReproductionPlanner().plan(
            finding,
            stale,
            fixture.experiment,
            source_outcome,
            confirmation_policy=policy,
            budget_manager=budgets,
            compiler_context=fixture.gate.compiler_context,
        )
    assert len(fixture.calls) == 2


def test_one_plan_skips_model_and_packet_is_public_safe(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.authentication)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    plans = GraphQLReproductionPlanner().plan(
        finding,
        state,
        fixture.experiment,
        source_outcome,
        confirmation_policy=policy,
        budget_manager=budgets,
        compiler_context=fixture.gate.compiler_context,
    )
    result = GraphQLReproductionSelector.select(state, finding, plans)

    assert len(plans) == 1
    assert result.model_call_required is False
    assert SECRET not in json.dumps(result.model_dump(mode="json"), sort_keys=True)


def test_uncontrolled_tenant_context_blocks_planning_without_request(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.tenant_bound)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    uncontrolled = state.identities[1].model_copy(
        update={"controlled": False, "eligibility": IdentityEligibility.ineligible}
    )
    state = state.model_copy(update={"identities": (state.identities[0], uncontrolled)})

    with pytest.raises(ReproductionPlanningError, match="identity_context_stale"):
        GraphQLReproductionPlanner().plan(
            finding,
            state,
            fixture.experiment,
            source_outcome,
            confirmation_policy=policy,
            budget_manager=budgets,
            compiler_context=fixture.gate.compiler_context,
        )
    assert len(fixture.calls) == 2


def test_model_can_select_only_one_prebuilt_plan_id(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    base = GraphQLReproductionPlanner().plan(
        finding,
        state,
        fixture.experiment,
        source_outcome,
        confirmation_policy=policy,
        budget_manager=budgets,
        compiler_context=fixture.gate.compiler_context,
    )[0]
    plans = tuple(
        base.model_copy(
            update={
                "reproduction_id": f"reproduction-option-{index}",
                "independent_dimension": dimension,
            }
        )
        for index, dimension in enumerate(
            (
                base.independent_dimension,
                ReproductionIndependentDimension.equivalent_endpoint_representation,
                ReproductionIndependentDimension.alternate_safe_observation_predicate,
            ),
            start=1,
        )
    )
    packet = GraphQLReproductionSelector.packet(state, finding, plans)
    decision = GraphQLReproductionSelectionDecision(
        decision_id="model-decision-r2",
        research_id=state.research_id,
        state_revision=state.revision,
        finding_id=finding.finding_id,
        selected_reproduction_id="reproduction-option-2",
    )
    selected = GraphQLReproductionSelector.select(state, finding, plans, decision).plan
    persisted = ReproductionPlanner().persist_plan(
        selected,
        store,
        budget_manager=budgets,
        occurred_at="2026-09-28T12:00:01+00:00",
    )
    materialized = ReproductionPlanner().compile(
        selected,
        fixture.experiment,
        persisted,
        ExperimentCompiler(context=fixture.gate.compiler_context),
        fixture.gate.compiler_context,
    )

    assert selected.reproduction_id == "reproduction-option-2"
    assert selected.model_decision_id == decision.decision_id
    assert materialized.reproduction_id == "reproduction-option-2"
    assert tuple(item.reproduction_id for item in persisted.reproduction_plans) == (
        "reproduction-option-2",
    )
    assert SECRET not in json.dumps(packet.public_payload(), sort_keys=True)
    with pytest.raises(ValueError):
        GraphQLReproductionSelector.select(
            state,
            finding,
            plans,
            {
                **decision.model_dump(mode="python"),
                "controlled_object_id": "model-altered-object",
            },
        )


def test_graphql_planning_rejects_mismatched_confirmation_policy(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    mismatched = policy.model_copy(update={"policy_reference": "other-policy"})

    with pytest.raises(ReproductionPlanningError, match="policy_mismatch"):
        GraphQLReproductionPlanner().plan(
            finding,
            state,
            fixture.experiment,
            source_outcome,
            confirmation_policy=mismatched,
            budget_manager=budgets,
            compiler_context=fixture.gate.compiler_context,
        )
    assert len(fixture.calls) == 2


def test_graphql_mutation_reproduction_requires_state_change_profile(tmp_path):
    fixture = _mutation_runtime_fixture(allow_state_changes=True)
    store = ResearchStore(tmp_path / "graphql-mutation-reproduction.sqlite3")
    store.create_research(fixture.gate.state)
    fixture.gate.store = store
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    source_outcome = _with_comparison_state_effect(
        fixture.experiment, binding.submit(authorization)
    )
    budgets = ResearchBudgetManager(
        ResearchBudgetPolicy(cleanup_request_reserve=1),
        request_budget=fixture.budget,
    )
    evaluation = ExperimentEvaluator().evaluate_and_commit(
        fixture.experiment,
        authorization,
        source_outcome,
        store,
        budget_manager=budgets,
    )
    assert evaluation.candidate_finding is not None
    state = store.load_research(fixture.experiment.research_id)
    finding = state.findings[0]

    with pytest.raises(ReproductionPlanningError, match="state_change_forbidden"):
        GraphQLReproductionPlanner().plan(
            finding,
            state,
            fixture.experiment,
            source_outcome,
            confirmation_policy=FindingConfirmationPolicy.graphql_read_only(
                finding.confirmation_policy_reference
            ),
            budget_manager=budgets,
            compiler_context=fixture.gate.compiler_context,
        )

    plans = GraphQLReproductionPlanner().plan(
        finding,
        state,
        fixture.experiment,
        source_outcome,
        confirmation_policy=FindingConfirmationPolicy.graphql_state_changing(
            finding.confirmation_policy_reference
        ),
        budget_manager=budgets,
        compiler_context=fixture.gate.compiler_context,
    )
    assert len(plans) == 1
    assert plans[0].state_changing is True
    assert plans[0].cleanup_required is True
    assert plans[0].cleanup_reference == "cleanup-graphql-resource"
    assert len(fixture.calls) == 3


def test_semantically_pinned_argument_does_not_offer_alternate_object(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, source_outcome, finding, policy = case
    state = store.load_research(fixture.experiment.research_id)
    original = state.objects[0]
    alternate = original.model_copy(
        update={
            "object_id": "object-resource-2",
            "object_reference": "controlled-resource-ref-2",
        }
    )
    state = state.model_copy(
        update={
            "revision": state.revision + 1,
            "objects": (*state.objects, alternate),
        }
    )
    store.commit_revision(
        state.research_id,
        expected_revision=state.revision - 1,
        state=state,
    )
    fixture.gate.controlled_context.objects.append(
        ControlledObject(
            object_id=alternate.object_id,
            owner_account_id="controlled-account-a",
            tenant_id="tenant-a",
        )
    )
    plans = GraphQLReproductionPlanner().plan(
        finding,
        state,
        fixture.experiment,
        source_outcome,
        confirmation_policy=policy,
        budget_manager=budgets,
        compiler_context=fixture.gate.compiler_context,
    )
    assert all(
        item.independent_dimension
        is not ReproductionIndependentDimension.different_owned_object
        for item in plans
    )
