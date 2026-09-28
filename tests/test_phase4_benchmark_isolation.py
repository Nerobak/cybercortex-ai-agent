from __future__ import annotations

import pytest

from agent_core.benchmark import (
    AutonomousResearchBenchmarkRunner,
    BenchmarkBlindnessError,
    BenchmarkBlindnessGuard,
    BenchmarkGroundTruthStore,
    BenchmarkPreflightError,
    BenchmarkRunStatus,
    GroundTruthAccessError,
)
from agent_core.models import ModelCallLedger, ModelErrorCode
from tests.phase4_benchmark_helpers import empty_state, research_input, truth
from agent_core.research import ResearchNotFound, ResearchStore
from agent_core.research import (
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceKind,
    Fact,
    FactStatus,
    Observation,
    ProvenanceProducerType,
    ProvenanceRecord,
    Relationship,
    RelationshipStatus,
    ResearchPredicate,
    ScalarFactObject,
    TargetAsset,
    TargetClass,
    AttackChainCandidateBuilder,
)
from tests.phase4_chain_helpers import (
    chain_state,
    experiment_candidate,
    unrelated_findings_state,
)

DIGEST = "sha256:" + "b" * 64


def _state_with_preseeded_artifact(kind: str):
    provenance = ProvenanceRecord(
        provenance_id="provenance-1",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="blindness-regression",
        producer_version="v1",
        summary="Registered controlled setup context.",
        occurred_at="2026-09-26T12:00:00+00:00",
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="https://benchmark.invalid",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-1",
        provenance_id=provenance.provenance_id,
    )
    evidence = EvidenceArtifact(
        evidence_id="evidence-1",
        evidence_kind=EvidenceKind.capture,
        digest=DIGEST,
        summary="A prior research artifact.",
        source_reference="prior-run",
        observed_at="2026-09-26T12:00:00+00:00",
        provenance_id=provenance.provenance_id,
    )
    update = {
        "targets": (target,),
        "provenance": (provenance,),
        "evidence": (evidence,),
    }
    if kind == "observation":
        update["observations"] = (
            Observation(
                observation_id="observation-1",
                observation_type="prior-observation",
                summary="A prior observation.",
                target_id=target.target_id,
                evidence_references=(evidence.evidence_id,),
                provenance_id=provenance.provenance_id,
            ),
        )
    elif kind == "fact":
        update["facts"] = (
            Fact(
                fact_id="fact-1",
                subject=EntityReference(
                    entity_kind=EntityKind.target, entity_id=target.target_id
                ),
                predicate=ResearchPredicate.returns,
                object=ScalarFactObject(value="prior-value"),
                status=FactStatus.observed,
                evidence_references=(evidence.evidence_id,),
                derivation_type=DerivationType.deterministic,
                provenance_id=provenance.provenance_id,
            ),
        )
    elif kind == "relationship":
        update["relationships"] = (
            Relationship(
                relationship_id="relationship-1",
                source=EntityReference(
                    entity_kind=EntityKind.target, entity_id=target.target_id
                ),
                predicate=ResearchPredicate.references,
                target=EntityReference(
                    entity_kind=EntityKind.target, entity_id=target.target_id
                ),
                status=RelationshipStatus.observed,
                evidence_references=(evidence.evidence_id,),
                derivation_type=DerivationType.deterministic,
                provenance_id=provenance.provenance_id,
            ),
        )
    return empty_state().model_copy(update=update)


def test_ground_truth_access_is_status_gated(tmp_path):
    store = BenchmarkGroundTruthStore(tmp_path)
    store.put("truth-1", truth())
    with pytest.raises(GroundTruthAccessError):
        store.load_for_scoring("truth-1", run_status=BenchmarkRunStatus.running)
    assert (
        store.load_for_scoring("truth-1", run_status=BenchmarkRunStatus.scoring)
        == truth()
    )


def test_blindness_guard_accepts_clean_state_and_rejects_seed_answers():
    guard = BenchmarkBlindnessGuard()
    result = guard.validate(research_input(), initial_state=empty_state())
    assert result.valid
    with pytest.raises(BenchmarkBlindnessError):
        guard.validate(
            research_input(),
            initial_state=empty_state(),
            seed_hypotheses=("preseeded",),
        )


@pytest.mark.parametrize(
    ("kind", "violation"),
    (
        ("evidence", "initial-evidence-present"),
        ("observation", "initial-observations-present"),
        ("fact", "initial-facts-present"),
        ("relationship", "initial-relationships-present"),
    ),
)
def test_strict_blindness_rejects_preseeded_research_artifacts(kind, violation):
    with pytest.raises(BenchmarkBlindnessError, match=violation):
        BenchmarkBlindnessGuard().validate(
            research_input(), initial_state=_state_with_preseeded_artifact(kind)
        )


def test_contamination_report_contains_hashes_not_hidden_material(tmp_path):
    store = BenchmarkGroundTruthStore(tmp_path)
    store.put("truth-1", truth())
    result = store.check_contamination(
        "truth-1", {"discovered_path": " /PRIVATE/object-id "}
    )
    assert result.contaminated
    assert "private" not in result.model_dump_json().lower()
    assert "hidden-sentinel-4f9c" not in result.model_dump_json()
    sentinel = store.check_contamination(
        "truth-1", {"model_packet": {"claim": "hidden sentinel 4f9c"}}
    )
    assert sentinel.contaminated


def test_default_run_storage_does_not_share_prior_research_namespace(tmp_path):
    first = ResearchStore(tmp_path / "run-a.sqlite3")
    second = ResearchStore(tmp_path / "run-b.sqlite3")
    first.create_research(
        empty_state("research-a").model_copy(
            update={"diagnostic_codes": ("run-a-private-history",)}
        )
    )
    second.create_research(empty_state("research-b"))
    with pytest.raises(ResearchNotFound):
        second.load_research("research-a")
    assert not second.load_research("research-b").diagnostic_codes


def test_run_b_isolated_from_run_a_research_and_model_accounting(tmp_path):
    run_a = chain_state()
    chain_candidate = AttackChainCandidateBuilder().build(
        run_a, experiment_candidates=(experiment_candidate(run_a),)
    )[0]
    run_a = run_a.model_copy(
        update={
            "findings": (unrelated_findings_state().findings[0],),
            "chain_candidates": (chain_candidate,),
        }
    )
    store_a = ResearchStore(tmp_path / "run-a.sqlite3")
    store_a.create_research(run_a)

    ledger = ModelCallLedger()
    ledger.record_pre_call_failure(
        provider="fixture-provider",
        model="fixture-model",
        latency_seconds=0.0,
        task_type="run-a-task",
        run_id=run_a.research_id,
        hypothesis_id=None,
        fallback_depth=0,
        outcome=ModelErrorCode.configuration_error,
    )

    store_b = ResearchStore(tmp_path / "run-b.sqlite3")
    store_b.create_research(empty_state("research-b"))
    AutonomousResearchBenchmarkRunner._validate_research_namespace(
        store_b, "research-b"
    )
    with pytest.raises(ResearchNotFound):
        store_b.load_research(run_a.research_id)
    state_b = store_b.load_research("research-b")
    assert not any(
        (
            state_b.evidence,
            state_b.facts,
            state_b.relationships,
            state_b.hypotheses,
            state_b.findings,
            state_b.chain_candidates,
            state_b.attack_chains,
        )
    )
    baseline = ledger.snapshot(run_id="research-b")
    assert baseline.position == 1
    assert baseline.usage.attempted_calls == 0
    assert (
        ledger.delta(baseline, ledger.snapshot(run_id="research-b")).attempted_calls
        == 0
    )


def test_shared_research_database_fails_strict_namespace_preflight(tmp_path):
    store = ResearchStore(tmp_path / "shared.sqlite3")
    store.create_research(empty_state("research-a"))
    store.create_research(empty_state("research-b"))
    with pytest.raises(BenchmarkPreflightError, match="fresh isolated"):
        AutonomousResearchBenchmarkRunner._validate_research_namespace(
            store, "research-b"
        )
