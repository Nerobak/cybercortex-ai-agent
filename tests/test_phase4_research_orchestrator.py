from __future__ import annotations

from dataclasses import dataclass

from agent_core.models import ModelUsageDelta
from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta
from agent_core.research import (
    BaselineIntent,
    BaselineKind,
    CleanupExecutionResult,
    CleanupStatus,
    DifferentialReference,
    DifferentialSelector,
    EvidenceArtifact,
    EvidenceIntent,
    EvidenceKind,
    EvidenceRelationshipHypothesisRule,
    ExperimentCompiler,
    ExperimentEvaluator,
    ExperimentProposal,
    ExperimentResultClassification,
    ExperimentSelector,
    HypothesisRecord,
    HypothesisResearchStatus,
    PivotPlanner,
    PrimitiveExecutionEvidence,
    PrimitiveStepProposal,
    ProvenanceProducerType,
    ProvenanceRecord,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchCleanupBarrier,
    ResearchConfidence,
    ResearchExecutionGate,
    ResearchPredicate,
    ResearchRunStatus,
    ResearchRuntime,
    ResearchState,
    ResearchStore,
    ResponseDifferentialInput,
    RuntimeProvenance,
    SecurityResearchOrchestrator,
    SelectorSpec,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
)
from agent_core.research.compiler import ExperimentCompilerContext
from agent_core.research.outcomes import ExperimentOutcome
from agent_core.research.types import ExperimentRuntimeStatus

NOW = "2026-09-18T12:00:00+00:00"
FUTURE = "2026-09-18T13:00:00+00:00"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def research_state(*, relationship: bool = False) -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="provenance-1",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="p4-0e-test",
        producer_version="v1",
        summary="Autonomous research test provenance.",
        occurred_at=NOW,
    )
    evidence = (
        EvidenceArtifact(
            evidence_id="evidence-1",
            evidence_kind=EvidenceKind.capture,
            digest=DIGEST_A,
            summary="Controlled baseline A.",
            source_reference="capture-1",
            observed_at=NOW,
            provenance_id="provenance-1",
        ),
        EvidenceArtifact(
            evidence_id="evidence-2",
            evidence_kind=EvidenceKind.capture,
            digest=DIGEST_B,
            summary="Controlled baseline B.",
            source_reference="capture-2",
            observed_at=NOW,
            provenance_id="provenance-1",
        ),
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="registered-target-1",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-1",
        evidence_references=("evidence-1",),
        provenance_id="provenance-1",
    )
    surface = Surface(
        surface_id="surface-1",
        target_id="target-1",
        surface_type=SurfaceType.rest,
        label="Controlled REST surface.",
        evidence_references=("evidence-1",),
        provenance_id="provenance-1",
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-1",
        category="authorization",
        title="Controlled authorization hypothesis.",
        claim="A controlled relationship may expose protected data.",
        target_id="target-1",
        surface_id="surface-1",
        status=HypothesisResearchStatus.proposed,
        priority=80,
        confidence=ResearchConfidence.medium,
        confirmation_policy_reference="confirmation-policy-1",
        supporting_evidence=("evidence-1",),
        provenance_id="provenance-1",
    )
    relationships = ()
    if relationship:
        from agent_core.research import (
            DerivationType,
            EntityKind,
            EntityReference,
            Relationship,
            RelationshipStatus,
        )

        relationships = (
            Relationship(
                relationship_id="relationship-r1",
                source=EntityReference(
                    entity_kind=EntityKind.target, entity_id="target-1"
                ),
                predicate=ResearchPredicate.references,
                target=EntityReference(
                    entity_kind=EntityKind.surface, entity_id="surface-1"
                ),
                status=RelationshipStatus.observed,
                evidence_references=("evidence-1",),
                derivation_type=DerivationType.deterministic,
                provenance_id="provenance-1",
            ),
        )
    return ResearchState(
        research_id="research-1",
        revision=0,
        status=ResearchRunStatus.selecting_experiment,
        created_at=NOW,
        updated_at=NOW,
        targets=(target,),
        surfaces=(surface,),
        evidence=evidence,
        relationships=relationships,
        hypotheses=(hypothesis,),
        provenance=(provenance,),
    )


def proposal(proposal_id: str, selector: DifferentialSelector) -> ExperimentProposal:
    return ExperimentProposal(
        proposal_id=proposal_id,
        research_id="research-1",
        state_revision=0,
        hypothesis_id="hypothesis-1",
        capability="response_differential",
        target_id="target-1",
        surface_id="surface-1",
        objective="Compare two bounded controlled evidence summaries.",
        baseline_strategy=BaselineIntent(
            kind=BaselineKind.prior_evidence, reference_id="evidence-1"
        ),
        mutation_intent={"kind": "none"},
        expected_secure_behavior="The controlled summaries remain equivalent.",
        expected_vulnerable_behavior="The controlled summaries differ materially.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=selector,
                predicate_reference=f"predicate-{selector.value}",
            ),
        ),
        rationale="A bounded differential can resolve the hypothesis.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id=f"step-{proposal_id}",
                input=ResponseDifferentialInput(
                    references=(
                        DifferentialReference(
                            kind="evidence", reference_id="evidence-1"
                        ),
                        DifferentialReference(
                            kind="evidence", reference_id="evidence-2"
                        ),
                    ),
                    selectors=(SelectorSpec(selector=selector),),
                ),
            ),
        ),
        provenance_id="provenance-1",
        expires_at=FUTURE,
    )


def compiler_context() -> ExperimentCompilerContext:
    return ExperimentCompilerContext(
        current_time=NOW,
        execution_ready=True,
        policy_reference="policy-1",
        context_reference="context-1",
    )


@dataclass(frozen=True)
class FakeAuthorization:
    experiment: object


class FakeGate:
    def __init__(self) -> None:
        self.current_time = NOW
        self.cleanup_barrier = ResearchCleanupBarrier()
        self.policy = None

    def authorize(self, experiment):
        return FakeAuthorization(experiment)

    def bind(self, authorization):
        return authorization


class FakeResearchRuntime:
    def __init__(self, classifications):
        self.classifications = list(classifications)
        self.calls = []

    def submit(self, authorization):
        experiment = authorization.experiment
        self.calls.append(experiment.fingerprint)
        classification = self.classifications.pop(0)
        evidence_id = f"runtime-evidence-{experiment.experiment_id}"
        evidence = PrimitiveExecutionEvidence(
            evidence_id=evidence_id,
            step_id=experiment.primitive_steps[0].step_id,
            primitive_name=experiment.primitive_steps[0].primitive_name,
            summary=f"Bounded {classification.value} evidence.",
            request_accounting_reference=f"request-accounting-{len(self.calls)}",
            runtime_provenance_reference=f"runtime-provenance-{len(self.calls)}",
        )
        return ExperimentOutcome(
            outcome_id=f"outcome-{experiment.experiment_id}",
            experiment_id=experiment.experiment_id,
            runtime_status=ExperimentRuntimeStatus.completed,
            canonical_result_classification=Phase2ResultStatus.inconclusive,
            evidence_references=(evidence_id,),
            request_delta=RequestDelta(),
            model_usage_delta=ModelUsageDelta(),
            cleanup_status=CleanupStatus.not_required,
            provenance_id=f"runtime-provenance-{experiment.experiment_id}",
            occurred_at=NOW,
            result_classification=classification,
            evidence=(evidence,),
            cleanup_result=CleanupExecutionResult(status=CleanupStatus.not_required),
            runtime_provenance=RuntimeProvenance(
                runtime_name="fake-research-runtime",
                runtime_version="v1",
                executor_registry_hash=DIGEST_A,
                primitive_registry_hash=DIGEST_B,
                policy_reference="policy-1",
                policy_hash=DIGEST_C,
                target_fingerprint=DIGEST_A,
            ),
            authorization_reference=DIGEST_B,
            runtime_binding_reference="fake-runtime-binding",
        )


def orchestrator(store, runtime, *, derivation_rules=()):
    compiler = ExperimentCompiler(context=compiler_context())
    budgets = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=3600.0)
    )
    selector = ExperimentSelector(compiler, budgets)
    evaluator = ExperimentEvaluator(
        allowed_vulnerability_categories=("authorization", "derived-category"),
        derivation_rules=derivation_rules,
    )
    pivot = PivotPlanner(selector)
    return SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        compiler_context=compiler_context(),
        gate=FakeGate(),
        runtime=runtime,
        selector=selector,
        evaluator=evaluator,
        pivot_planner=pivot,
        budget_manager=budgets,
    )


def test_inconclusive_e1_autonomously_pivots_to_vulnerable_e2(tmp_path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(research_state())
    runtime = FakeResearchRuntime(
        (
            ExperimentResultClassification.inconclusive,
            ExperimentResultClassification.vulnerable_signal,
        )
    )
    result = orchestrator(store, runtime).run(
        "research-1",
        proposals=(
            proposal("proposal-e1", DifferentialSelector.status_class),
            proposal("proposal-e2", DifferentialSelector.semantic_result_class),
        ),
    )

    final = result.state
    hypothesis = final.hypotheses[0]
    assert len(runtime.calls) == 2
    assert len(final.experiment_outcomes) == 2
    assert hypothesis.attempt_count == 2
    assert hypothesis.pivot_count == 1
    assert len(final.findings) == 1
    assert final.findings[0].status.value == "candidate"
    assert final.findings[0].status.value != "confirmed"
    assert result.evaluations[-1].classification.value == "vulnerable_signal"


def test_equivalent_retry_is_blocked_without_second_runtime_submission(tmp_path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(research_state())
    runtime = FakeResearchRuntime((ExperimentResultClassification.inconclusive,))
    first = orchestrator(store, runtime).run(
        "research-1",
        proposals=(proposal("proposal-e1", DifferentialSelector.status_class),),
        max_iterations=1,
    )
    assert first.stop_reason.value == "iteration_limit"

    equivalent = proposal("proposal-reworded", DifferentialSelector.status_class)
    payload = equivalent.model_dump(mode="python")
    payload["objective"] = "Reworded bounded comparison with identical semantics."
    payload["rationale"] = "Different wording does not change the experiment."
    equivalent = ExperimentProposal.model_validate(payload)
    second = orchestrator(store, runtime).run("research-1", proposals=(equivalent,))

    assert len(runtime.calls) == 1
    assert second.stop_reason.value == "no_eligible_experiments"
    assert second.state.hypotheses[0].pivot_count == 0


def test_restart_preserves_outcome_budget_and_selects_material_pivot(tmp_path):
    path = tmp_path / "research.sqlite3"
    store = ResearchStore(path)
    store.create_research(research_state())
    runtime1 = FakeResearchRuntime((ExperimentResultClassification.inconclusive,))
    first = orchestrator(store, runtime1).run(
        "research-1",
        proposals=(proposal("proposal-e1", DifferentialSelector.status_class),),
        max_iterations=1,
    )
    assert len(first.state.experiment_history) == 1
    store.close()

    restarted_store = ResearchStore(path)
    runtime2 = FakeResearchRuntime((ExperimentResultClassification.vulnerable_signal,))
    second = orchestrator(restarted_store, runtime2).run(
        "research-1",
        proposals=(
            proposal("proposal-e1-again", DifferentialSelector.status_class),
            proposal("proposal-e2", DifferentialSelector.semantic_result_class),
        ),
    )
    assert len(runtime2.calls) == 1
    assert second.state.hypotheses[0].attempt_count == 2
    assert second.state.hypotheses[0].pivot_count == 1
    assert len(second.state.experiment_outcomes) == 2


def test_evidence_fact_and_existing_relationship_create_h2_without_human(tmp_path):
    rule = EvidenceRelationshipHypothesisRule(
        rule_id="f1-r1-h2",
        fact_predicate=ResearchPredicate.supported_by,
        relationship_predicate=ResearchPredicate.references,
        category="derived-category",
        title="Derived relationship hypothesis.",
        claim="The observed relationship may expose another controlled boundary.",
        falsification_criterion="A controlled comparison produces no protected signal.",
        confirmation_policy_reference="confirmation-policy-2",
    )
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(research_state(relationship=True))
    runtime = FakeResearchRuntime((ExperimentResultClassification.vulnerable_signal,))
    result = orchestrator(store, runtime, derivation_rules=(rule,)).run(
        "research-1",
        proposals=(proposal("proposal-e1", DifferentialSelector.status_class),),
    )
    h2 = [
        item for item in result.state.hypotheses if item.hypothesis_id != "hypothesis-1"
    ]
    assert len(h2) == 1
    assert h2[0].status is HypothesisResearchStatus.proposed
    assert h2[0].basis_fact_ids
    assert h2[0].basis_relationship_ids == ("relationship-r1",)


def test_orchestrator_dependencies_keep_model_outside_authority_boundary():
    assert not hasattr(ExperimentProposal, "execute")
    assert not hasattr(ExperimentProposal, "authorize")
    assert ResearchExecutionGate is not ResearchRuntime


def test_critical_loop_uses_real_gate_runtime_and_fake_transport(tmp_path):
    from tests.test_phase4_research_compiler import object_proposal
    from tests.test_phase4_research_runtime import build_runtime_fixture

    stores = []

    def create_store(state):
        store = ResearchStore(tmp_path / "real-gate.sqlite3")
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

    first_payload = object_proposal().model_dump(mode="python")
    first_payload["proposal_id"] = "proposal-e1"
    first = ExperimentProposal.model_validate(first_payload)
    second_payload = first.model_dump(mode="python")
    second_payload["proposal_id"] = "proposal-e2"
    second_payload["required_evidence_intent"] = (
        EvidenceIntent(
            selector=DifferentialSelector.semantic_result_class,
            predicate_reference="predicate-material-pivot",
        ),
    )
    second = ExperimentProposal.model_validate(second_payload)
    fixture = build_runtime_fixture(
        proposal=first,
        statuses=(200, 500, 200, 200),
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
    )

    result = runner.run("research-1", proposals=(first, second))

    assert len(fixture.calls) == 4
    assert [item.classification.value for item in result.evaluations] == [
        "inconclusive",
        "vulnerable_signal",
    ]
    assert result.state.hypotheses[0].attempt_count == 2
    assert result.state.hypotheses[0].pivot_count == 1
    assert result.state.findings[0].status.value == "candidate"
