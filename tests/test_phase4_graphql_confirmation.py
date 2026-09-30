from __future__ import annotations

import pytest

from agent_core.research import (
    DuplicateExperimentError,
    ExperimentResultClassification,
    FindingConfirmationAction,
    FindingConfirmationEvaluator,
    FindingStatus,
    GraphQLCandidateKind,
    FindingConfirmationPolicy,
    ResearchPredicate,
    ReproductionKind,
    ResearchStore,
)
from test_phase4_graphql_reproduction import _plan_and_compile, _source_case
from test_phase4_graphql_runtime import FakeResponse


def _confirm(case, responses):
    fixture, store, budgets, _source_outcome, finding, policy = case
    plan, reproduction = _plan_and_compile(case)
    # The fake requester closes over this queue, so replace the remaining
    # default response behavior through its transport requester fixture input.
    del responses
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
    return decision, store.load_research(fixture.experiment.research_id), outcome


def test_graphql_authentication_reproduction_confirms(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.authentication)
    decision, state, outcome = _confirm(case, (FakeResponse(), FakeResponse()))

    assert outcome.result_classification is ExperimentResultClassification.inconclusive
    assert decision.action is FindingConfirmationAction.confirm
    assert state.findings[0].status is FindingStatus.confirmed
    assert state.confirmation_decisions[0].trace_events == ("GRAPHQL_CONFIRM",)


def test_graphql_controlled_tenant_reproduction_confirms(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.tenant_bound)
    decision, state, _outcome = _confirm(case, (FakeResponse(), FakeResponse()))

    assert decision.action is FindingConfirmationAction.confirm
    assert state.findings[0].status is FindingStatus.confirmed
    assert state.reproduction_outcomes[0].identity_relationship == (
        "different_controlled_tenant"
    )


def test_graphql_mutation_confirmation_requires_explicit_stricter_policy():
    read_only = FindingConfirmationPolicy.graphql_read_only("graphql-read-only")
    mutation = FindingConfirmationPolicy.graphql_state_changing(
        "graphql-state-changing"
    )

    assert read_only.supports(ReproductionKind.object_substitution, True) is False
    assert mutation.supports(ReproductionKind.object_substitution, True) is True
    assert mutation.state_changing_confirmation_permitted is True
    assert mutation.minimum_independent_reproductions == 2


def test_graphql_inconclusive_reproduction_never_confirms(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, _source_outcome, finding, policy = case
    plan, reproduction = _plan_and_compile(case)
    authorization, binding = fixture.gate.authorize_and_bind(reproduction.experiment)
    outcome = binding.submit(authorization).model_copy(
        update={"result_classification": ExperimentResultClassification.inconclusive}
    )
    # Remove structural responses so P4-1F deterministically remains
    # inconclusive and the generic confirmation evaluator cannot promote it.
    outcome = outcome.model_copy(
        update={
            "evidence": tuple(
                item.model_copy(update={"graphql_responses": ()})
                for item in outcome.evidence
            )
        }
    )
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

    assert decision.action is FindingConfirmationAction.remain_candidate
    assert state.findings[0].status is FindingStatus.candidate


def test_graphql_secure_reproduction_is_conflicting_and_not_confirmed(tmp_path):
    denied = FakeResponse(
        403,
        b'{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}',
    )
    case = _source_case(
        tmp_path,
        GraphQLCandidateKind.object_authorization,
        reproduction_responses=(FakeResponse(), denied),
    )
    decision, state, _outcome = _confirm(case, (FakeResponse(), denied))

    assert decision.action is FindingConfirmationAction.reject
    assert state.findings[0].status is FindingStatus.rejected
    assert state.findings[0].status is not FindingStatus.confirmed
    assert state.reproduction_outcomes[0].classification.value == "conflicting"


def test_graphql_confirmation_survives_restart_without_reexecution(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, _source_outcome, _finding, _policy = case
    _decision, state, _outcome = _confirm(case, (FakeResponse(), FakeResponse()))
    database = store.database
    calls = len(fixture.calls)
    request_total = fixture.budget.total
    store.close()

    restarted = ResearchStore(database).load_research(state.research_id)

    assert restarted.findings[0].status is FindingStatus.confirmed
    assert len(restarted.reproduction_outcomes) == 1
    assert len(restarted.confirmation_decisions) == 1
    assert len(fixture.calls) == calls
    assert fixture.budget.total == request_total
    assert budgets.state(restarted).reproduction_usage[0].target_requests_consumed == 2


def test_graphql_atomic_promotion_failure_has_no_partial_edge_or_retry(tmp_path):
    case = _source_case(tmp_path, GraphQLCandidateKind.object_authorization)
    fixture, store, budgets, _source_outcome, finding, policy = case
    plan, reproduction = _plan_and_compile(case)
    authorization, binding = fixture.gate.authorize_and_bind(reproduction.experiment)
    outcome = binding.submit(authorization)

    class FailingStore:
        def load_research(self, research_id):
            return store.load_research(research_id)

        def commit_revision(self, *args, **kwargs):
            del args, kwargs
            raise RuntimeError("synthetic GraphQL promotion failure")

    with pytest.raises(RuntimeError, match="synthetic GraphQL promotion failure"):
        FindingConfirmationEvaluator().evaluate_and_commit(
            finding_id=finding.finding_id,
            plan=plan,
            experiment=reproduction.experiment,
            runtime_outcome=outcome,
            policy=policy,
            store=FailingStore(),
            budget_manager=budgets,
        )

    unchanged = store.load_research(fixture.experiment.research_id)
    assert unchanged.findings[0].status is FindingStatus.reproducing
    assert unchanged.reproduction_outcomes == ()
    assert unchanged.confirmation_decisions == ()
    assert (
        store.query_graph_assertions(
            unchanged.research_id,
            relation=ResearchPredicate.finding_confirmed_by,
        )
        == ()
    )
    calls = len(fixture.calls)
    with pytest.raises(DuplicateExperimentError):
        fixture.gate.authorize(reproduction.experiment)
    assert len(fixture.calls) == calls
