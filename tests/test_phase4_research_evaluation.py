import pytest

from agent_core.research import (
    DifferentialSelector,
    ExperimentCompiler,
    ExperimentEvaluator,
    ExperimentResultClassification,
    FindingStatus,
    ResearchConsequence,
)
from test_phase4_research_orchestrator import (
    FakeAuthorization,
    FakeResearchRuntime,
    compiler_context,
    proposal,
    research_state,
)


@pytest.mark.parametrize(
    ("classification", "consequence"),
    (
        (
            ExperimentResultClassification.secure_signal,
            ResearchConsequence.refute_hypothesis,
        ),
        (
            ExperimentResultClassification.inconclusive,
            ResearchConsequence.pivot_recommended,
        ),
        (
            ExperimentResultClassification.runtime_failed,
            ResearchConsequence.pivot_recommended,
        ),
        (
            ExperimentResultClassification.cleanup_failed,
            ResearchConsequence.stop_required,
        ),
    ),
)
def test_evaluator_uses_authoritative_runtime_classification(
    classification, consequence
):
    state = research_state()
    experiment = ExperimentCompiler(context=compiler_context()).compile(
        proposal("proposal-e1", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    outcome = FakeResearchRuntime((classification,)).submit(
        FakeAuthorization(experiment)
    )
    evaluation = ExperimentEvaluator().evaluate(
        experiment, FakeAuthorization(experiment), outcome, state
    )
    assert evaluation.classification is classification
    assert evaluation.consequence is consequence
    assert evaluation.candidate_finding is None


def test_vulnerable_signal_can_create_candidate_but_never_confirmed_finding():
    state = research_state()
    experiment = ExperimentCompiler(context=compiler_context()).compile(
        proposal("proposal-e1", DifferentialSelector.status_class),
        state,
        compiler_context(),
    )
    outcome = FakeResearchRuntime(
        (ExperimentResultClassification.vulnerable_signal,)
    ).submit(FakeAuthorization(experiment))
    evaluation = ExperimentEvaluator().evaluate(
        experiment, FakeAuthorization(experiment), outcome, state
    )
    assert evaluation.consequence is ResearchConsequence.candidate_finding_signal
    assert evaluation.candidate_finding.status is FindingStatus.candidate
    assert evaluation.candidate_finding.status is not FindingStatus.confirmed
