from agent_core.research import (
    DifferentialSelector,
    ExperimentCompiler,
    ExperimentSelector,
    ProposalEligibilityReason,
    ResearchBudgetManager,
    ResearchExperimentRecord,
    ResearchExperimentStatus,
    material_experiment_fingerprint,
)
from test_phase4_research_orchestrator import (
    NOW,
    compiler_context,
    proposal,
    research_state,
)


def test_selector_ranks_eligible_proposals_deterministically():
    state = research_state()
    compiler = ExperimentCompiler(context=compiler_context())
    selector = ExperimentSelector(compiler, ResearchBudgetManager())
    result = selector.select(
        (
            proposal("proposal-e2", DifferentialSelector.semantic_result_class),
            proposal("proposal-e1", DifferentialSelector.status_class),
        ),
        state,
        compiler_context=compiler_context(),
    )
    assert result.selected.proposal_id == "proposal-e1"
    assert result.selected.information_value.score > 0


def test_selector_blocks_material_duplicate_across_state_revisions():
    state = research_state()
    compiler = ExperimentCompiler(context=compiler_context())
    experiment = compiler.compile(
        proposal("proposal-e1", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    history = ResearchExperimentRecord(
        experiment_id=experiment.experiment_id,
        proposal_id="proposal-e1",
        hypothesis_id="hypothesis-1",
        surface_id="surface-1",
        fingerprint=experiment.fingerprint,
        material_fingerprint=material_experiment_fingerprint(experiment),
        status=ResearchExperimentStatus.completed,
        relevant_state_revision=0,
        occurred_at=NOW,
    )
    payload = state.model_dump(mode="python")
    payload["revision"] = 1
    payload["experiment_history"] = (history,)
    later = state.model_validate(payload)
    repeated = proposal("proposal-reworded", DifferentialSelector.status_class)
    repeated = repeated.model_copy(update={"state_revision": 1})
    selector = ExperimentSelector(compiler, ResearchBudgetManager())
    result = selector.select((repeated,), later, compiler_context=compiler_context())
    assert result.selected is None
    assert result.assessments[0].reasons == (
        ProposalEligibilityReason.fingerprint_completed,
    )
