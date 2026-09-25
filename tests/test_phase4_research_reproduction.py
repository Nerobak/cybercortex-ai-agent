from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_core.request_budget import RequestDelta
from agent_core.research import (
    ExperimentCompiler,
    ExperimentEvaluator,
    ExperimentResultClassification,
    FindingConfirmationPolicy,
    FindingStatus,
    ReproductionClassification,
    ReproductionOutcomeEvaluator,
    ReproductionPlanStatus,
    ReproductionPlanner,
    ReproductionPlanningError,
    ResearchBudgetManager,
    SafeRequestSummary,
    SafeResponseSummary,
    ResearchState,
    ResearchStore,
    SessionLifecycle,
    SessionRef,
    candidate_reproduction_eligible,
    material_experiment_fingerprint,
    reject_secret_material,
)
from tests.test_phase4_research_compiler import (
    NOW,
    compiler_context,
    object_proposal,
    research_state,
)
from tests.test_phase4_research_orchestrator import DIGEST_A, FakeResearchRuntime


@dataclass
class ReproductionCase:
    store: ResearchStore
    compiler: ExperimentCompiler
    budget_manager: ResearchBudgetManager
    source_experiment: object
    source_outcome: object
    finding: object
    policy: FindingConfirmationPolicy


def _request_delta(count: int = 2) -> RequestDelta:
    return RequestDelta(verification=count, attempted=count, total=count)


def _source_case(
    tmp_path, *, proposal=None, category: str = "authorization"
) -> ReproductionCase:
    original = research_state.__wrapped__()
    payload = original.model_dump(mode="python")
    payload["revision"] = 0
    payload["hypotheses"] = tuple(
        item.model_copy(update={"category": category}) for item in original.hypotheses
    )
    if proposal is not None and proposal.primary_session_ref_id is not None:
        payload["session_refs"] = (
            SessionRef(
                session_ref_id=proposal.primary_session_ref_id,
                identity_id=str(proposal.primary_identity_id),
                vault_reference="vault:test-session-reference",
                lifecycle=SessionLifecycle.active,
                provenance_id="provenance-1",
            ),
        )
    state = ResearchState.model_validate(payload)
    selected = proposal or object_proposal()
    selected = selected.model_copy(update={"state_revision": 0})
    context = compiler_context.__wrapped__()
    compiler = ExperimentCompiler(context=context)
    experiment = compiler.compile(selected, state, context)
    outcome = FakeResearchRuntime(
        (ExperimentResultClassification.vulnerable_signal,)
    ).submit(type("Authorization", (), {"experiment": experiment})())
    outcome = outcome.model_copy(
        update={
            "request_delta": _request_delta(),
            "authorization_reference": DIGEST_A,
            "occurred_at": NOW,
        }
    )
    store = ResearchStore(tmp_path / "reproduction.sqlite3")
    store.create_research(state)
    budgets = ResearchBudgetManager()
    ExperimentEvaluator(
        allowed_vulnerability_categories=("authorization", "authentication")
    ).evaluate_and_commit(
        experiment,
        object(),
        outcome,
        store,
        budget_manager=budgets,
    )
    committed = store.load_research(state.research_id)
    finding = committed.findings[0]
    policy = (
        FindingConfirmationPolicy.authentication_read_only(
            finding.confirmation_policy_reference
        )
        if category == "authentication"
        else FindingConfirmationPolicy.authorization_read_only(
            finding.confirmation_policy_reference
        )
    )
    return ReproductionCase(
        store=store,
        compiler=compiler,
        budget_manager=budgets,
        source_experiment=experiment,
        source_outcome=outcome,
        finding=finding,
        policy=policy,
    )


def _persist_and_compile(case: ReproductionCase):
    planner = ReproductionPlanner()
    state = case.store.load_research("research-1")
    plan = planner.plan(
        case.finding,
        state,
        case.source_experiment,
        case.source_outcome,
        confirmation_policy=case.policy,
        budget_manager=case.budget_manager,
    )[0]
    state = planner.persist_plan(
        plan,
        case.store,
        budget_manager=case.budget_manager,
        occurred_at=NOW,
    )
    reproduction = planner.compile(
        plan,
        case.source_experiment,
        state,
        case.compiler,
        compiler_context.__wrapped__(),
    )
    return plan, reproduction


def _reproduction_runtime_outcome(case, reproduction, classification):
    outcome = FakeResearchRuntime((classification,)).submit(
        type("Authorization", (), {"experiment": reproduction.experiment})()
    )
    experiment = reproduction.experiment
    request_count = 2
    request_summaries = tuple(
        SafeRequestSummary(
            request_template_reference=experiment.baseline.reference_id,
            target_reference=experiment.target.target_id,
            surface_reference=str(experiment.target.surface_id),
            endpoint_reference=str(experiment.target.endpoint_id),
            method=str(experiment.target.method),
            identity_reference=(
                experiment.identity_context.primary_identity_id
                if index == 0
                else experiment.identity_context.comparison_identity_id
            ),
            body_present=False,
        )
        for index in range(request_count)
    )
    response_summaries = tuple(
        SafeResponseSummary(
            status_code=200,
            status_class="2xx",
            content_length_class="bounded",
            content_type="application-json",
            structural_digest="sha256:" + "d" * 64,
            content_digest="sha256:" + "e" * 64,
            body_present=True,
        )
        for _ in range(request_count)
    )
    evidence = outcome.evidence[0].model_copy(
        update={
            "identity_references": tuple(
                item
                for item in (
                    experiment.identity_context.primary_identity_id,
                    experiment.identity_context.comparison_identity_id,
                )
                if item is not None
            ),
            "object_references": experiment.mutation.controlled_object_ids,
            "mutation_kind": experiment.mutation.kind,
            "request_summaries": request_summaries,
            "response_summaries": response_summaries,
        }
    )
    return outcome.model_copy(
        update={
            "request_delta": _request_delta(),
            "occurred_at": NOW,
            "evidence": (evidence,),
        }
    )


def test_planner_builds_bounded_explicit_independent_reproduction(tmp_path):
    case = _source_case(tmp_path)
    assert candidate_reproduction_eligible(case.finding)

    plan, reproduction = _persist_and_compile(case)

    assert (
        plan.maximum_requests
        == case.source_experiment.request_estimate.total_reservation
    )
    assert (
        reproduction.experiment.reproduction_of == case.source_experiment.experiment_id
    )
    assert reproduction.experiment.reproduction_finding_id == case.finding.finding_id
    assert reproduction.experiment.reproduction_id == plan.reproduction_id
    assert reproduction.experiment.experiment_id != case.source_experiment.experiment_id
    assert material_experiment_fingerprint(
        reproduction.experiment
    ) == material_experiment_fingerprint(case.source_experiment)
    reject_secret_material(plan.model_dump(mode="json"), location="test plan")


def test_independence_requires_fresh_authorization_request_evidence_and_provenance(
    tmp_path,
):
    case = _source_case(tmp_path)
    plan, reproduction = _persist_and_compile(case)
    copied = case.source_outcome.model_copy(
        update={"experiment_id": reproduction.experiment.experiment_id}
    )

    result = ReproductionOutcomeEvaluator().evaluate(
        case.store.load_research("research-1").findings[0],
        plan,
        reproduction.experiment,
        copied,
    )

    assert result.classification is ReproductionClassification.blocked
    assert result.independence is not None
    assert result.independence.valid is False


def test_fresh_runtime_result_satisfies_independence(tmp_path):
    case = _source_case(tmp_path)
    plan, reproduction = _persist_and_compile(case)
    outcome = _reproduction_runtime_outcome(
        case, reproduction, ExperimentResultClassification.vulnerable_signal
    )

    result = ReproductionOutcomeEvaluator().evaluate(
        case.store.load_research("research-1").findings[0],
        plan,
        reproduction.experiment,
        outcome,
    )

    assert result.classification is ReproductionClassification.reproduced
    assert result.independence is not None and result.independence.valid
    assert result.request_delta.total == 2


def test_reproduction_attempt_is_consumed_when_plan_is_persisted(tmp_path):
    case = _source_case(tmp_path)
    plan, _ = _persist_and_compile(case)
    state = case.store.load_research("research-1")
    usage = case.budget_manager.state(state).reproduction_usage[0]

    assert usage.finding_id == case.finding.finding_id
    assert usage.attempts_consumed == 1
    assert usage.model_calls_consumed == 0
    assert plan.status is ReproductionPlanStatus.planned
    with pytest.raises(ReproductionPlanningError, match="finding_not_candidate"):
        ReproductionPlanner().plan(
            state.findings[0],
            state,
            case.source_experiment,
            case.source_outcome,
            confirmation_policy=case.policy,
            budget_manager=case.budget_manager,
        )


def test_restart_loads_plan_and_compiles_without_model_or_source_memory(tmp_path):
    case = _source_case(tmp_path)
    planner = ReproductionPlanner()
    state = case.store.load_research("research-1")
    plan = planner.plan(
        case.finding,
        state,
        case.source_experiment,
        case.source_outcome,
        confirmation_policy=case.policy,
        budget_manager=case.budget_manager,
    )[0]
    planner.persist_plan(
        plan,
        case.store,
        budget_manager=case.budget_manager,
        occurred_at=NOW,
    )
    path = case.store.database
    case.store.close()

    restarted = ResearchStore(path)
    recovered = restarted.load_research("research-1")
    compiled = planner.compile(
        recovered.reproduction_plans[0],
        None,
        recovered,
        case.compiler,
        compiler_context.__wrapped__(),
    )

    assert compiled.experiment.reproduction_id == plan.reproduction_id
    assert (
        case.budget_manager.state(recovered).reproduction_usage[0].attempts_consumed
        == 1
    )


def test_wrong_source_finding_and_request_ceiling_are_rejected(tmp_path):
    case = _source_case(tmp_path)
    state = case.store.load_research("research-1")
    wrong = case.finding.model_copy(update={"candidate_experiment_id": "wrong-source"})
    with pytest.raises(ReproductionPlanningError, match="source_experiment_mismatch"):
        ReproductionPlanner().plan(
            wrong,
            state,
            case.source_experiment,
            case.source_outcome,
            confirmation_policy=case.policy,
        )
    restrictive = case.policy.model_copy(update={"maximum_requests": 1})
    with pytest.raises(ReproductionPlanningError, match="request_ceiling"):
        ReproductionPlanner().plan(
            case.finding,
            state,
            case.source_experiment,
            case.source_outcome,
            confirmation_policy=restrictive,
        )


def test_terminal_findings_are_not_reproduction_candidates(tmp_path):
    case = _source_case(tmp_path)
    terminal = case.finding.model_copy(update={"status": FindingStatus.rejected})
    assert terminal.status is FindingStatus.rejected
    with pytest.raises(ReproductionPlanningError, match="finding_not_candidate"):
        ReproductionPlanner().plan(
            terminal,
            case.store.load_research("research-1"),
            case.source_experiment,
            case.source_outcome,
            confirmation_policy=case.policy,
        )
