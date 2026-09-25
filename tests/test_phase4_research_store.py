from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_core.phase2_store import Phase2RunStore
from agent_core.research import (
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceKind,
    Fact,
    FactStatus,
    GraphAssertion,
    HypothesisResearchStatus,
    MetadataEntry,
    MigrationRegistry,
    OversizedResearchMutation,
    ProvenanceProducerType,
    ProvenanceRecord,
    PublicMetadata,
    ReferenceFactObject,
    RelationshipStatus,
    ResearchEvent,
    ResearchEventType,
    ResearchGraphRepository,
    ResearchIntegrityError,
    ResearchPredicate,
    ResearchRunStatus,
    ResearchStartedPayload,
    ResearchState,
    ResearchStore,
    SecretMaterialRejected,
    StaleResearchRevision,
    TargetAsset,
    TargetClass,
    UnsupportedResearchSchemaVersion,
    research_state_hash,
)

TS = "2026-09-17T12:00:00+00:00"
TS_1 = "2026-09-17T12:00:01+00:00"
DIGEST = "sha256:" + "a" * 64


def provenance(
    identifier: str = "prov-1", *, summary: str = "Deterministic test provenance."
) -> ProvenanceRecord:
    return ProvenanceRecord(
        provenance_id=identifier,
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-store-test",
        producer_version="v1",
        summary=summary,
        occurred_at=TS,
    )


def state(*, research_id: str = "research-1", metadata: PublicMetadata | None = None):
    prov = provenance()
    evidence = EvidenceArtifact(
        evidence_id="evidence-1",
        evidence_kind=EvidenceKind.capture,
        digest=DIGEST,
        summary="A controlled object was observed.",
        source_reference="capture-1",
        observed_at=TS,
        provenance_id="prov-1",
        metadata=metadata or PublicMetadata(),
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="authorized-target",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    return ResearchState(
        research_id=research_id,
        revision=0,
        status=ResearchRunStatus.initializing,
        created_at=TS,
        updated_at=TS,
        targets=(target,),
        evidence=(evidence,),
        provenance=(prov,),
    )


def revision(previous: ResearchState, number: int, *, updated_at: str = TS_1):
    payload = previous.model_dump(mode="python")
    payload.update(revision=number, updated_at=updated_at)
    return ResearchState.model_validate(payload)


def event(index: int, revision_number: int) -> ResearchEvent:
    return ResearchEvent(
        event_id=f"event-{index}",
        research_id="research-1",
        event_type=ResearchEventType.research_started,
        state_revision=revision_number,
        provenance_id="prov-1",
        occurred_at=TS_1,
        summary="A bounded research event was recorded.",
        payload=ResearchStartedPayload(target_ids=("target-1",)),
    )


def test_create_load_list_and_restart_are_canonical(tmp_path: Path):
    database = tmp_path / "research.sqlite3"
    store = ResearchStore(database)
    initial = store.create_research(state())
    first = store.commit_revision(
        "research-1", expected_revision=0, state=revision(initial, 1)
    )
    second = store.commit_revision(
        "research-1", expected_revision=1, state=revision(first, 2)
    )
    expected_hash = research_state_hash(second)
    assert store.list_research_runs()[0].current_revision == 2
    store.close()

    reopened = ResearchStore(database)
    restored = reopened.load_research("research-1")
    assert restored == second
    assert research_state_hash(restored) == expected_hash
    assert reopened.verify_integrity("research-1").valid


def test_in_memory_store_keeps_schema_for_its_lifetime():
    store = ResearchStore(":memory:")
    store.create_research(state())
    assert store.load_research("research-1") == state()
    assert store.verify_integrity("research-1").valid


def test_every_commit_increments_exactly_one_revision(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    initial = store.create_research(state())
    committed = store.append_event(
        event(1, 1), expected_revision=0, state=revision(initial, 1)
    )
    assert committed.revision == 1
    assert store.current_revision("research-1") == 1
    with pytest.raises(ValueError, match="exactly"):
        store.commit_revision(
            "research-1", expected_revision=1, state=revision(committed, 3)
        )


def test_two_writers_reject_stale_revision(tmp_path: Path):
    database = tmp_path / "research.sqlite3"
    first = ResearchStore(database)
    second = ResearchStore(database)
    initial = first.create_research(state())
    candidate = revision(initial, 1)
    first.commit_revision("research-1", expected_revision=0, state=candidate)
    with pytest.raises(StaleResearchRevision):
        second.commit_revision("research-1", expected_revision=0, state=candidate)
    assert second.current_revision("research-1") == 1


def test_failed_component_insert_rolls_back_whole_revision(tmp_path: Path, monkeypatch):
    store = ResearchStore(tmp_path / "research.sqlite3")
    initial = store.create_research(state())
    assertion = GraphAssertion(
        assertion_id="assertion-1",
        research_id="research-1",
        source=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        relation=ResearchPredicate.part_of,
        target=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        status=RelationshipStatus.observed,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        asserted_at=TS_1,
    )

    def fail(*_args, **_kwargs):
        raise RuntimeError("intentional transaction failure")

    monkeypatch.setattr(ResearchStore, "_insert_graph_assertion", staticmethod(fail))
    with pytest.raises(RuntimeError, match="intentional"):
        store.commit_revision(
            "research-1",
            expected_revision=0,
            state=revision(initial, 1),
            events=(event(1, 1),),
            graph_assertions=(assertion,),
        )
    assert store.current_revision("research-1") == 0
    assert store.load_research("research-1") == initial
    assert store.verify_integrity("research-1").revision_count == 1
    store.close()
    recovered = ResearchStore(store.database)
    recovered.commit_revision(
        "research-1", expected_revision=0, state=revision(initial, 1)
    )
    assert recovered.verify_integrity("research-1").current_revision == 1


def test_canonical_state_tampering_is_detected(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(state())
    with sqlite3.connect(store.database) as connection:
        payload = json.loads(
            connection.execute("SELECT state_json FROM research_revisions").fetchone()[
                0
            ]
        )
        payload["updated_at"] = TS_1
        connection.execute(
            "UPDATE research_revisions SET state_json=?", (json.dumps(payload),)
        )
    with pytest.raises(ResearchIntegrityError):
        store.verify_integrity("research-1")


def test_event_order_and_association_tampering_is_detected(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    initial = store.create_research(state())
    store.commit_revision(
        "research-1",
        expected_revision=0,
        state=revision(initial, 1),
        events=(event(1, 1), event(2, 1)),
    )
    with sqlite3.connect(store.database) as connection:
        connection.execute(
            "UPDATE research_events SET event_order=4 WHERE event_id='event-2'"
        )
    with pytest.raises(ResearchIntegrityError, match="event ordering"):
        store.verify_integrity("research-1")


def test_research_id_mismatch_fails_without_mutation(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(state())
    with pytest.raises(ValueError, match="research_id"):
        store.commit_revision(
            "research-1",
            expected_revision=0,
            state=revision(state(research_id="other-research"), 1),
        )
    assert store.current_revision("research-1") == 0


def test_future_schema_version_fails_closed(tmp_path: Path):
    database = tmp_path / "research.sqlite3"
    ResearchStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE research_schema SET schema_version=999")
    with pytest.raises(UnsupportedResearchSchemaVersion):
        ResearchStore(database)


def test_migration_registry_has_deterministic_path_and_rejects_gaps():
    registry = MigrationRegistry()
    registry.register(
        1, 2, lambda connection: connection.execute("CREATE TABLE marker(x)")
    )
    assert [
        (step.source_version, step.target_version) for step in registry.path(1, 2)
    ] == [(1, 2)]
    with pytest.raises(UnsupportedResearchSchemaVersion):
        registry.path(1, 3)
    with pytest.raises(ValueError):
        registry.register(1, 2, lambda _connection: None)


def test_migration_registry_applies_one_transactional_step():
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE research_schema(singleton INTEGER PRIMARY KEY, schema_version INTEGER)"
    )
    connection.execute("INSERT INTO research_schema VALUES(1,1)")
    registry = MigrationRegistry()
    registry.register(1, 2, lambda db: db.execute("CREATE TABLE marker(x)"))
    registry.migrate(connection, 1, 2)
    assert (
        connection.execute("SELECT schema_version FROM research_schema").fetchone()[0]
        == 2
    )
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE name='marker'"
    ).fetchone()


@pytest.mark.parametrize(
    "secret",
    (
        "SYNTHETIC_SECRET",
        "Authorization: Bearer SYNTHETIC_TOKEN_VALUE",
        "Cookie: session=SYNTHETIC_COOKIE_VALUE",
        "api_key=SYNTHETIC_API_KEY_VALUE",
        "password=SYNTHETIC_PASSWORD",
        "token=SYNTHETIC_TOKEN_VALUE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.fake_signature",
    ),
)
def test_secret_bearing_research_state_is_rejected_before_write(
    tmp_path: Path, secret: str
):
    store = ResearchStore(tmp_path / "research.sqlite3")
    with pytest.raises((SecretMaterialRejected, ValidationError)):
        unsafe = state(
            metadata=PublicMetadata(entries=(MetadataEntry(key="note", value=secret),))
        )
        store.create_research(unsafe)
    assert secret.encode() not in store.database.read_bytes()


def test_secret_bearing_event_and_graph_metadata_are_rejected(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    initial = store.create_research(state())
    unsafe_event = event(1, 1).model_copy(update={"summary": "SYNTHETIC_SECRET"})
    with pytest.raises(SecretMaterialRejected):
        store.commit_revision(
            "research-1",
            expected_revision=0,
            state=revision(initial, 1),
            events=(unsafe_event,),
        )
    assertion = GraphAssertion(
        assertion_id="assertion-secret",
        research_id="research-1",
        source=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        relation=ResearchPredicate.part_of,
        target=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        status=RelationshipStatus.proposed,
        derivation_type=DerivationType.model_proposed,
        provenance_id="prov-1",
        asserted_at=TS_1,
        metadata=PublicMetadata(
            entries=(MetadataEntry(key="note", value="SYNTHETIC_SECRET"),)
        ),
    )
    with pytest.raises(SecretMaterialRejected):
        ResearchGraphRepository(store, "research-1").record_assertion(
            assertion, expected_revision=0
        )
    assert store.current_revision("research-1") == 0


def test_provenance_secret_and_reasoning_routes_are_rejected(tmp_path: Path):
    unsafe = state()
    payload = unsafe.model_dump(mode="python")
    payload["provenance"] = (provenance(summary="SYNTHETIC_SECRET"),)
    unsafe = ResearchState.model_validate(payload)
    with pytest.raises(SecretMaterialRejected):
        ResearchStore(tmp_path / "secret.sqlite3").create_research(unsafe)
    metadata = PublicMetadata(
        entries=(MetadataEntry(key="model_prompt", value="private reasoning"),)
    )
    payload = state().model_dump(mode="python")
    payload["evidence"][0]["metadata"] = metadata.model_dump(mode="python")
    with pytest.raises(SecretMaterialRejected):
        ResearchStore(tmp_path / "reasoning.sqlite3").create_research(
            ResearchState.model_validate(payload)
        )


def test_oversized_commit_is_rejected_deterministically(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    initial = store.create_research(state())
    with pytest.raises(OversizedResearchMutation, match="event limit"):
        store.commit_revision(
            "research-1",
            expected_revision=0,
            state=revision(initial, 1),
            events=tuple(event(1, 1) for _ in range(101)),
        )
    assert store.current_revision("research-1") == 0


def _write_phase2_run(directory: Path, *, with_secret: bool = False) -> Phase2RunStore:
    phase2 = Phase2RunStore(directory)
    phase2.directory.mkdir(parents=True)
    run = {
        "run_id": "phase2-run-1",
        "run_revision": 1,
        "created_at": TS,
        "target": "https://authorized.example.test",
        "attack_surface": {"routes": [{"method": "GET", "path": "/objects"}]},
        "hypotheses": [
            {
                "hypothesis_id": "phase2-hypothesis-1",
                "category": "bola",
                "title": "Object authorization boundary",
                "description": "A boundary requires controlled verification.",
            }
        ],
        "verification_plans": [{"hypothesis_id": "phase2-hypothesis-1"}],
        "verification_results": [
            {
                "hypothesis_id": "phase2-hypothesis-1",
                "status": "inconclusive",
                "requests_used": 2,
            }
        ],
    }
    if with_secret:
        run["verification_results"][0]["password"] = "SYNTHETIC_PASSWORD"
    phase2.run_path("phase2-run-1").write_text(json.dumps(run), encoding="utf-8")
    return phase2


def test_phase2_import_is_typed_idempotent_and_source_immutable(tmp_path: Path):
    phase2 = _write_phase2_run(tmp_path / "phase2")
    before = phase2.run_path("phase2-run-1").read_bytes()
    store = ResearchStore(tmp_path / "research.sqlite3")
    imported = store.import_phase2_run(phase2, "phase2-run-1")
    repeated = store.import_phase2_run(phase2, "phase2-run-1")
    assert repeated == imported
    assert imported.hypotheses[0].status is HypothesisResearchStatus.proposed
    assert imported.facts == ()
    assert imported.experiment_outcomes[0].request_delta.total == 2
    assert any(item.metadata.entries for item in imported.evidence)
    assert phase2.run_path("phase2-run-1").read_bytes() == before
    assert store.list_research_runs()[0].research_id == imported.research_id


def test_phase2_import_rejects_raw_credentials_without_writing_them(tmp_path: Path):
    phase2 = _write_phase2_run(tmp_path / "phase2", with_secret=True)
    store = ResearchStore(tmp_path / "research.sqlite3")
    with pytest.raises(SecretMaterialRejected):
        store.import_phase2_run(phase2, "phase2-run-1")
    assert b"SYNTHETIC_PASSWORD" not in store.database.read_bytes()


def test_fact_record_promotion_and_rejection_are_revisioned(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(state())
    fact = Fact(
        fact_id="fact-1",
        subject=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        predicate=ResearchPredicate.references,
        object=ReferenceFactObject(
            reference=EntityReference(
                entity_kind=EntityKind.evidence, entity_id="evidence-1"
            )
        ),
        status=FactStatus.proposed,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.model_proposed,
        provenance_id="prov-1",
    )
    proposed = store.record_fact(
        "research-1", fact, expected_revision=0, updated_at=TS_1
    )
    observed = store.promote_fact(
        "research-1",
        "fact-1",
        FactStatus.observed,
        expected_revision=1,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        updated_at=TS_1,
    )
    confirmed = store.promote_fact(
        "research-1",
        "fact-1",
        FactStatus.confirmed,
        expected_revision=2,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        updated_at=TS_1,
    )
    rejected = store.reject_fact(
        "research-1",
        "fact-1",
        expected_revision=3,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        updated_at=TS_1,
    )
    assert proposed.facts[0].status is FactStatus.proposed
    assert observed.facts[0].status is FactStatus.observed
    assert confirmed.facts[0].status is FactStatus.confirmed
    assert rejected.facts[0].status is FactStatus.rejected
    assert (
        store.load_research("research-1", revision=1).facts[0].status
        is FactStatus.proposed
    )


def test_model_only_fact_confirmation_is_blocked(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(state())
    fact = Fact(
        fact_id="fact-1",
        subject=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        predicate=ResearchPredicate.references,
        object=ReferenceFactObject(
            reference=EntityReference(
                entity_kind=EntityKind.evidence, entity_id="evidence-1"
            )
        ),
        status=FactStatus.proposed,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.model_proposed,
        provenance_id="prov-1",
    )
    store.record_fact("research-1", fact, expected_revision=0, updated_at=TS_1)
    store.promote_fact(
        "research-1",
        "fact-1",
        FactStatus.observed,
        expected_revision=1,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        updated_at=TS_1,
    )
    with pytest.raises(ValueError, match="model-proposed"):
        store.promote_fact(
            "research-1",
            "fact-1",
            FactStatus.confirmed,
            expected_revision=2,
            evidence_references=("evidence-1",),
            derivation_type=DerivationType.model_proposed,
            provenance_id="prov-1",
            updated_at=TS_1,
        )
    assert store.current_revision("research-1") == 2


def test_fact_supersession_is_explicit_and_preserves_prior_revision(tmp_path: Path):
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(state())
    original = Fact(
        fact_id="fact-original",
        subject=EntityReference(entity_kind=EntityKind.target, entity_id="target-1"),
        predicate=ResearchPredicate.references,
        object=ReferenceFactObject(
            reference=EntityReference(
                entity_kind=EntityKind.evidence, entity_id="evidence-1"
            )
        ),
        status=FactStatus.proposed,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.model_proposed,
        provenance_id="prov-1",
    )
    store.record_fact("research-1", original, expected_revision=0, updated_at=TS_1)
    replacement = original.model_copy(update={"fact_id": "fact-replacement"})
    current = store.supersede_fact(
        "research-1",
        "fact-original",
        replacement,
        expected_revision=1,
        provenance_id="prov-1",
        updated_at=TS_1,
    )
    facts = {item.fact_id: item for item in current.facts}
    assert facts["fact-original"].status is FactStatus.superseded
    assert facts["fact-original"].supersedes_fact_id == "fact-replacement"
    assert facts["fact-replacement"].status is FactStatus.proposed
    assert store.load_research("research-1", revision=1).facts == (original,)
