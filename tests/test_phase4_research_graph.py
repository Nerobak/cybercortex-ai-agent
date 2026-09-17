from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_core.attack_surface import AttackSurfaceGraph
from agent_core.research import (
    DerivationType,
    Endpoint,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceKind,
    GraphAssertion,
    GraphQLOperation,
    GraphQLOperationType,
    GraphRelation,
    HttpMethod,
    HypothesisRecord,
    HypothesisResearchStatus,
    Identity,
    IdentityEligibility,
    Parameter,
    ParameterLocation,
    ProvenanceProducerType,
    ProvenanceRecord,
    RelationshipStatus,
    ResearchConfidence,
    ResearchGraphRepository,
    ResearchObject,
    ResearchPredicate,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
)

TS = "2026-09-17T12:00:00+00:00"
TS_1 = "2026-09-17T12:00:01+00:00"
DIGEST = "sha256:" + "b" * 64


def graph_state() -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="prov-1",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-graph-test",
        producer_version="v1",
        summary="Deterministic graph test provenance.",
        occurred_at=TS,
    )
    evidence = EvidenceArtifact(
        evidence_id="evidence-1",
        evidence_kind=EvidenceKind.capture,
        digest=DIGEST,
        summary="The controlled cross-surface entities were observed.",
        source_reference="capture-1",
        observed_at=TS,
        provenance_id="prov-1",
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="authorized-target",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    rest = Surface(
        surface_id="surface-rest",
        target_id="target-1",
        surface_type=SurfaceType.rest,
        label="Observed REST surface.",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    graphql = Surface(
        surface_id="surface-graphql",
        target_id="target-1",
        surface_type=SurfaceType.graphql,
        label="Observed GraphQL surface.",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    rest_endpoint = Endpoint(
        endpoint_id="endpoint-rest",
        target_id="target-1",
        surface_id="surface-rest",
        method=HttpMethod.get,
        route_template="/objects/{id}",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    graphql_endpoint = Endpoint(
        endpoint_id="endpoint-graphql",
        target_id="target-1",
        surface_id="surface-graphql",
        method=HttpMethod.post,
        route_template="/graphql",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    variable = Parameter(
        parameter_id="parameter-object-id",
        endpoint_id="endpoint-graphql",
        name="objectId",
        location=ParameterLocation.graphql_variable,
        data_type="ID",
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    operation = GraphQLOperation(
        operation_id="operation-object",
        surface_id="surface-graphql",
        endpoint_id="endpoint-graphql",
        operation_name="ObjectQuery",
        operation_type=GraphQLOperationType.query,
        root_fields=("object",),
        variable_parameter_ids=("parameter-object-id",),
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    identity = Identity(
        identity_id="identity-1",
        account_reference="account-1",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-1",
    )
    obj = ResearchObject(
        object_id="object-1",
        target_id="target-1",
        surface_id="surface-rest",
        object_type="Project",
        object_reference="object-reference-1",
        owner_identity_id="identity-1",
        test_owned=True,
        evidence_references=("evidence-1",),
        provenance_id="prov-1",
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-1",
        category="cross-surface-authorization",
        title="Cross-surface authorization hypothesis.",
        claim="The GraphQL operation may reference the REST-observed object.",
        target_id="target-1",
        surface_id="surface-graphql",
        status=HypothesisResearchStatus.proposed,
        priority=50,
        confidence=ResearchConfidence.low,
        confirmation_policy_reference="deterministic-policy-1",
        provenance_id="prov-1",
    )
    return ResearchState(
        research_id="research-graph",
        revision=0,
        status=ResearchRunStatus.initializing,
        created_at=TS,
        updated_at=TS,
        targets=(target,),
        surfaces=(rest, graphql),
        endpoints=(rest_endpoint, graphql_endpoint),
        parameters=(variable,),
        identities=(identity,),
        objects=(obj,),
        graphql_operations=(operation,),
        evidence=(evidence,),
        hypotheses=(hypothesis,),
        provenance=(provenance,),
    )


def assertion(
    assertion_id: str,
    source_kind: EntityKind,
    source_id: str,
    relation: ResearchPredicate | GraphRelation,
    target_kind: EntityKind,
    target_id: str,
    *,
    status: RelationshipStatus = RelationshipStatus.observed,
    derivation_type: DerivationType = DerivationType.deterministic,
    evidence: tuple[str, ...] = ("evidence-1",),
) -> GraphAssertion:
    return GraphAssertion(
        assertion_id=assertion_id,
        research_id="research-graph",
        source=EntityReference(entity_kind=source_kind, entity_id=source_id),
        relation=relation,
        target=EntityReference(entity_kind=target_kind, entity_id=target_id),
        status=status,
        evidence_references=evidence,
        derivation_type=derivation_type,
        provenance_id="prov-1",
        asserted_at=TS_1,
    )


@pytest.fixture
def graph(tmp_path: Path) -> ResearchGraphRepository:
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(graph_state())
    return ResearchGraphRepository(store, "research-graph")


def test_model_may_create_proposed_assertion_without_evidence(graph):
    proposed = assertion(
        "assertion-proposed",
        EntityKind.hypothesis,
        "hypothesis-1",
        ResearchPredicate.derives_from,
        EntityKind.evidence,
        "evidence-1",
        status=RelationshipStatus.proposed,
        derivation_type=DerivationType.model_proposed,
        evidence=(),
    )
    committed = graph.record_assertion(proposed, expected_revision=0)
    assert committed.revision == 1
    assert graph.get_assertion("assertion-proposed") == proposed


def test_graph_relation_vocabulary_is_complete():
    assert {item.value for item in GraphRelation} == {
        "AUTHENTICATES_TO",
        "OWNS",
        "BELONGS_TO",
        "RETURNS",
        "REFERENCES",
        "ACCESSES",
        "CREATES",
        "MODIFIES",
        "DERIVES_FROM",
        "REQUIRES",
        "LEAKS",
        "CONTROLS",
        "TRANSITIONS_TO",
        "ACCEPTS",
        "EMITS",
        "SAME_OBJECT_AS",
        "PART_OF",
        "TESTED_BY",
        "SUPPORTED_BY",
        "REFUTED_BY",
        "CONFIRMS",
    }


@pytest.mark.parametrize(
    "status", (RelationshipStatus.observed, RelationshipStatus.confirmed)
)
def test_observed_and_confirmed_assertions_require_evidence(status):
    with pytest.raises(ValidationError, match="require evidence"):
        assertion(
            "assertion-no-evidence",
            EntityKind.identity,
            "identity-1",
            ResearchPredicate.owns,
            EntityKind.object,
            "object-1",
            status=status,
            evidence=(),
        )


def test_security_critical_confirmation_requires_deterministic_derivation():
    with pytest.raises(ValidationError, match="deterministic"):
        assertion(
            "assertion-owns",
            EntityKind.identity,
            "identity-1",
            ResearchPredicate.owns,
            EntityKind.object,
            "object-1",
            status=RelationshipStatus.confirmed,
            derivation_type=DerivationType.researcher_asserted,
        )


def test_model_confidence_cannot_confirm_any_graph_assertion():
    with pytest.raises(ValidationError, match="model-authored"):
        assertion(
            "assertion-model-confirmed",
            EntityKind.endpoint,
            "endpoint-rest",
            ResearchPredicate.returns,
            EntityKind.object,
            "object-1",
            status=RelationshipStatus.confirmed,
            derivation_type=DerivationType.model_proposed,
        )


def test_rejected_assertion_remains_in_history(graph):
    proposed = assertion(
        "assertion-rejected",
        EntityKind.endpoint,
        "endpoint-rest",
        ResearchPredicate.returns,
        EntityKind.object,
        "object-1",
        status=RelationshipStatus.proposed,
        derivation_type=DerivationType.model_proposed,
        evidence=(),
    )
    graph.record_assertion(proposed, expected_revision=0)
    graph.reject_assertion(
        "assertion-rejected",
        expected_revision=1,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        asserted_at=TS_1,
    )
    history = graph.assertion_history("assertion-rejected")
    assert [item.status for item in history] == [
        RelationshipStatus.proposed,
        RelationshipStatus.rejected,
    ]
    assert graph.neighbors("endpoint-rest") == ()
    assert graph.neighbors("endpoint-rest", include_rejected=True)[0].status is (
        RelationshipStatus.rejected
    )


def test_supersession_is_explicit_and_preserves_both_records(graph):
    original = assertion(
        "assertion-original",
        EntityKind.endpoint,
        "endpoint-rest",
        ResearchPredicate.returns,
        EntityKind.object,
        "object-1",
    )
    replacement = assertion(
        "assertion-replacement",
        EntityKind.endpoint,
        "endpoint-rest",
        GraphRelation.confirms,
        EntityKind.object,
        "object-1",
    )
    graph.record_assertion(original, expected_revision=0)
    graph.supersede_assertion(
        "assertion-original",
        replacement,
        expected_revision=1,
        provenance_id="prov-1",
        asserted_at=TS_1,
    )
    superseded = graph.get_assertion("assertion-original")
    assert superseded.status is RelationshipStatus.superseded
    assert superseded.superseded_by_assertion_id == "assertion-replacement"
    assert (
        graph.get_assertion("assertion-replacement").relation is GraphRelation.confirms
    )


def test_security_critical_convenience_query_returns_only_authoritative_ownership(
    graph,
):
    proposed = assertion(
        "assertion-owns",
        EntityKind.identity,
        "identity-1",
        ResearchPredicate.owns,
        EntityKind.object,
        "object-1",
        status=RelationshipStatus.proposed,
        derivation_type=DerivationType.model_proposed,
        evidence=(),
    )
    graph.record_assertion(proposed, expected_revision=0)
    assert graph.objects_owned_by("identity-1") == ()
    graph.promote_assertion(
        "assertion-owns",
        RelationshipStatus.confirmed,
        expected_revision=1,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-1",
        asserted_at=TS_1,
    )
    assert graph.objects_owned_by("identity-1") == ("object-1",)


def test_neighbors_and_relationship_queries_are_bounded(graph):
    assertions = tuple(
        assertion(
            f"assertion-{index}",
            EntityKind.endpoint,
            "endpoint-rest",
            ResearchPredicate.returns,
            EntityKind.object,
            "object-1",
        )
        for index in range(3)
    )
    graph.record_assertions(assertions, expected_revision=0, updated_at=TS_1)
    assert len(graph.neighbors("endpoint-rest", limit=2)) == 2
    assert len(graph.relationships_between("endpoint-rest", "object-1", limit=2)) == 2
    with pytest.raises(ValueError, match="bound"):
        graph.neighbors("endpoint-rest", limit=501)
    with pytest.raises(ValueError, match="bound"):
        graph.assertion_history("assertion-0", limit=501)


def test_cross_surface_representation_and_bounded_path_search(graph):
    assertions = (
        assertion(
            "assertion-rest-returns",
            EntityKind.endpoint,
            "endpoint-rest",
            ResearchPredicate.returns,
            EntityKind.object,
            "object-1",
        ),
        assertion(
            "assertion-variable-references",
            EntityKind.parameter,
            "parameter-object-id",
            ResearchPredicate.references,
            EntityKind.object,
            "object-1",
        ),
        assertion(
            "assertion-operation-part",
            EntityKind.graphql_operation,
            "operation-object",
            ResearchPredicate.part_of,
            EntityKind.surface,
            "surface-graphql",
        ),
        assertion(
            "assertion-variable-part",
            EntityKind.parameter,
            "parameter-object-id",
            ResearchPredicate.part_of,
            EntityKind.graphql_operation,
            "operation-object",
        ),
        assertion(
            "assertion-hypothesis-derived",
            EntityKind.hypothesis,
            "hypothesis-1",
            ResearchPredicate.derives_from,
            EntityKind.evidence,
            "evidence-1",
        ),
    )
    graph.record_assertions(assertions, expected_revision=0, updated_at=TS_1)
    assert graph.operations_referencing_object("object-1") == ("operation-object",)
    paths = graph.find_cross_surface_paths(
        "endpoint-rest", "surface-graphql", max_depth=4, max_paths=2
    )
    assert len(paths) == 1
    assert [item.relation.value for item in paths[0]] == [
        "RETURNS",
        "REFERENCES",
        "PART_OF",
        "PART_OF",
    ]
    assert graph.hypotheses_supported_by("evidence-1") == ("hypothesis-1",)
    with pytest.raises(ValidationError):
        graph.find_cross_surface_paths("endpoint-rest", max_depth=7)


def test_evidence_lookup_returns_typed_artifacts(graph):
    observed = assertion(
        "assertion-evidence",
        EntityKind.endpoint,
        "endpoint-rest",
        ResearchPredicate.returns,
        EntityKind.object,
        "object-1",
    )
    graph.record_assertion(observed, expected_revision=0)
    assert (
        graph.evidence_for_assertion("assertion-evidence")[0].evidence_id
        == "evidence-1"
    )


def test_attack_surface_adapter_is_read_only_and_bounded(tmp_path: Path):
    legacy = AttackSurfaceGraph(tmp_path / "surface.sqlite3")
    legacy.start_run("run-1", "https://authorized.example.test", "safe")
    target = legacy.upsert_node(
        "asset", "authorized.example.test", {"host": "authorized.example.test"}
    )
    endpoint = legacy.upsert_node("endpoint", "/objects", {"path": "/objects"})
    legacy.add_edge(target, "exposes", endpoint)
    snapshot = ResearchGraphRepository.legacy_attack_surface_snapshot(
        legacy, max_nodes=2, max_edges=1
    )
    assert snapshot["adapter_schema_version"] == 1
    assert len(snapshot["nodes"]) == 2
    assert len(snapshot["edges"]) == 1
    with pytest.raises(ValueError, match="bound"):
        ResearchGraphRepository.legacy_attack_surface_snapshot(legacy, max_nodes=5_001)
