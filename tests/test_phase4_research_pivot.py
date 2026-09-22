from agent_core.research import (
    DifferentialSelector,
    ExperimentCompiler,
    ExperimentResultClassification,
    ExperimentSelector,
    PivotDimension,
    PivotPlanner,
    ResearchBudgetManager,
)
from test_phase4_research_orchestrator import (
    FakeAuthorization,
    FakeResearchRuntime,
    compiler_context,
    proposal,
    research_state,
)


def test_pivot_requires_a_material_dimension_change():
    state = research_state()
    compiler = ExperimentCompiler(context=compiler_context())
    e1 = compiler.compile(
        proposal("proposal-e1", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    equivalent = compiler.compile(
        proposal("proposal-reworded", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    e2 = compiler.compile(
        proposal("proposal-e2", DifferentialSelector.semantic_result_class),
        state,
        compiler_context(),
    )
    assert PivotPlanner.changed_dimensions(e1, equivalent) == ()
    assert PivotPlanner.changed_dimensions(e1, e2) == (
        PivotDimension.observation_method,
    )


def test_inconclusive_result_diagnoses_and_selects_material_pivot():
    state = research_state()
    compiler = ExperimentCompiler(context=compiler_context())
    selector = ExperimentSelector(compiler, ResearchBudgetManager())
    planner = PivotPlanner(selector)
    e1 = compiler.compile(
        proposal("proposal-e1", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    outcome = FakeResearchRuntime(
        (ExperimentResultClassification.inconclusive,)
    ).submit(FakeAuthorization(e1))
    diagnosis = planner.diagnose(outcome, e1)
    plan = planner.plan(
        e1,
        (
            proposal("proposal-e1-again", DifferentialSelector.status_class),
            proposal("proposal-e2", DifferentialSelector.semantic_result_class),
        ),
        state,
        compiler_context=compiler_context(),
        diagnosis=diagnosis,
    )
    assert diagnosis.material_pivot_useful is True
    assert plan.selection.selected.proposal_id == "proposal-e2"
    assert plan.changed_dimensions == (PivotDimension.observation_method,)
