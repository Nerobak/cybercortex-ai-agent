from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_core.research import (
    DerivationType,
    EntityKind,
    EntityReference,
    GraphAssertion,
    GraphQLOperationRecord,
    GraphQLRootRole,
    GraphQLTypeKind,
    GraphQLTypeRecord,
    RelationshipStatus,
    ResearchIntegrityError,
    ResearchPredicate,
    ResearchState,
    ResearchStore,
    build_graphql_graph_assertions,
    build_public_safe_graphql_summary,
)
from test_phase4_graphql_semantics import TS_1, semantic_state


def _cross_surface_assertion(
    assertion_id: str,
    source: EntityReference,
    relation: ResearchPredicate,
    target: EntityReference,
) -> GraphAssertion:
    return GraphAssertion(
        assertion_id=assertion_id,
        research_id="research-graphql",
        source=source,
        relation=relation,
        target=target,
        status=RelationshipStatus.observed,
        evidence_references=("evidence-graphql",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-graphql",
        asserted_at=TS_1,
    )


def test_generic_schema_graph_edges_are_deterministic_and_evidenced():
    state = semantic_state()
    first = build_graphql_graph_assertions(state, asserted_at=TS_1)
    second = build_graphql_graph_assertions(state, asserted_at=TS_1)
    assert first == second
    triples = {
        (item.source.entity_id, item.relation, item.target.entity_id) for item in first
    }
    assert (
        "graphql-surface-1",
        ResearchPredicate.graphql_has_type,
        "type-query",
    ) in triples
    assert (
        "type-query",
        ResearchPredicate.graphql_has_field,
        "field-query-resource",
    ) in triples
    assert (
        "field-query-resource",
        ResearchPredicate.graphql_has_argument,
        "argument-resource-ref",
    ) in triples
    assert (
        "field-query-resource",
        ResearchPredicate.graphql_returns_type,
        "type-resource",
    ) in triples
    assert (
        "operation-resource",
        ResearchPredicate.graphql_selects_field,
        "field-query-resource",
    ) in triples
    assert (
        "variable-resource-ref",
        ResearchPredicate.graphql_variable_binds_argument,
        "argument-resource-ref",
    ) in triples
    assert all(item.evidence_references for item in first)


def test_interface_and_union_relations_have_integrity():
    state = semantic_state()
    node = GraphQLTypeRecord(
        type_id="type-node",
        graphql_surface_id="graphql-surface-1",
        name="Node",
        kind=GraphQLTypeKind.interface,
        possible_type_ids=("type-resource", "type-user"),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    search_result = GraphQLTypeRecord(
        type_id="type-search-result",
        graphql_surface_id="graphql-surface-1",
        name="SearchResult",
        kind=GraphQLTypeKind.union,
        possible_type_ids=("type-resource", "type-user"),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    payload = state.model_dump(mode="python")
    payload["graphql_types"] = tuple(
        (
            item.model_copy(update={"interface_ids": ("type-node",)})
            if item.type_id in {"type-resource", "type-user"}
            else item
        )
        for item in state.graphql_types
    ) + (node, search_result)
    extended = ResearchState.model_validate(payload)
    edges = build_graphql_graph_assertions(extended, asserted_at=TS_1)
    triples = {
        (item.source.entity_id, item.relation, item.target.entity_id) for item in edges
    }
    assert (
        "type-resource",
        ResearchPredicate.graphql_implements_interface,
        "type-node",
    ) in triples
    assert (
        "type-search-result",
        ResearchPredicate.graphql_possible_type,
        "type-user",
    ) in triples


def test_missing_possible_type_and_interface_are_rejected():
    state = semantic_state()
    invalid_union = GraphQLTypeRecord(
        type_id="type-search-result",
        graphql_surface_id="graphql-surface-1",
        name="SearchResult",
        kind=GraphQLTypeKind.union,
        possible_type_ids=("type-missing",),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    payload = state.model_dump(mode="python")
    payload["graphql_types"] = state.graphql_types + (invalid_union,)
    with pytest.raises(ValidationError, match="possible types"):
        ResearchState.model_validate(payload)

    resource = next(
        item for item in state.graphql_types if item.type_id == "type-resource"
    )
    payload = state.model_dump(mode="python")
    payload["graphql_types"] = tuple(
        (
            resource.model_copy(update={"interface_ids": ("type-missing",)})
            if item.type_id == resource.type_id
            else item
        )
        for item in state.graphql_types
    )
    with pytest.raises(ValidationError, match="interfaces"):
        ResearchState.model_validate(payload)


def test_operation_unknown_root_field_and_variable_unknown_operation_are_rejected():
    state = semantic_state()
    operation = next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    )
    payload = state.model_dump(mode="python")
    payload["graphql_operations"] = (
        operation.model_copy(update={"root_field_ids": ("field-missing",)}),
    )
    with pytest.raises(ValidationError, match="root fields"):
        ResearchState.model_validate(payload)

    variable = state.graphql_variables[0].model_copy(
        update={"operation_id": "operation-missing"}
    )
    payload = state.model_dump(mode="python")
    payload["graphql_variables"] = (variable,)
    with pytest.raises(ValidationError, match="variable owned by another operation"):
        ResearchState.model_validate(payload)


def test_graphql_relation_entity_shapes_are_strict():
    with pytest.raises(ValidationError, match="incompatible entity kinds"):
        _cross_surface_assertion(
            "assertion-invalid-shape",
            EntityReference(entity_kind=EntityKind.graphql_field, entity_id="field-1"),
            ResearchPredicate.graphql_has_type,
            EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-1"),
        )


def test_cross_surface_same_object_requires_explicit_evidence(tmp_path: Path):
    state = semantic_state()
    generated = build_graphql_graph_assertions(state, asserted_at=TS_1)
    assert not any(
        item.relation is ResearchPredicate.references_same_object for item in generated
    )
    same_object = _cross_surface_assertion(
        "assertion-same-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-resource-1"),
    )
    crosses_surface = _cross_surface_assertion(
        "assertion-crosses-surface",
        EntityReference(
            entity_kind=EntityKind.graphql_argument,
            entity_id="argument-resource-ref",
        ),
        ResearchPredicate.crosses_surface,
        EntityReference(
            entity_kind=EntityKind.parameter,
            entity_id="parameter-resource-ref",
        ),
    )
    store = ResearchStore(tmp_path / "research.sqlite3")
    store.create_research(
        state, graph_assertions=(*generated, same_object, crosses_surface)
    )
    stored = store.query_graph_assertions("research-graphql", limit=500)
    assert same_object in stored
    assert crosses_surface in stored
    packet = build_public_safe_graphql_summary(
        state, graph_assertions=(same_object, crosses_surface)
    )
    assert {item.relation for item in packet.cross_surface_relationships} == {
        ResearchPredicate.references_same_object,
        ResearchPredicate.crosses_surface,
    }


def test_name_only_cross_surface_match_never_generates_identity_edge():
    state = semantic_state()
    assert next(item for item in state.graphql_types if item.name == "Resource")
    assert next(item for item in state.objects if item.object_type == "Resource")
    assertions = build_graphql_graph_assertions(state, asserted_at=TS_1)
    assert not any(
        item.relation is ResearchPredicate.references_same_object for item in assertions
    )


def test_store_rejects_cross_surface_assertion_to_missing_entity(tmp_path: Path):
    state = semantic_state()
    missing = _cross_surface_assertion(
        "assertion-missing-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-missing"),
    )
    with pytest.raises(ValueError, match="dangling entity"):
        ResearchStore(tmp_path / "research.sqlite3").create_research(
            state, graph_assertions=(missing,)
        )


def test_graphql_assertions_survive_restart_with_integrity(tmp_path: Path):
    database = tmp_path / "research.sqlite3"
    state = semantic_state()
    assertions = build_graphql_graph_assertions(state, asserted_at=TS_1)
    store = ResearchStore(database)
    store.create_research(state, graph_assertions=assertions)
    assert store.verify_integrity("research-graphql").valid
    store.close()
    reopened = ResearchStore(database)
    assert reopened.query_graph_assertions("research-graphql", limit=500) == assertions
    assert reopened.verify_integrity("research-graphql").valid


def test_graphql_state_tamper_detection_uses_existing_store_hashing(tmp_path: Path):
    import json
    import sqlite3

    database = tmp_path / "research.sqlite3"
    store = ResearchStore(database)
    store.create_research(semantic_state())
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT state_json FROM research_revisions WHERE research_id=?",
            ("research-graphql",),
        ).fetchone()
        payload = json.loads(row[0])
        payload["graphql_surfaces"][0]["schema_state"] = "unknown"
        connection.execute(
            "UPDATE research_revisions SET state_json=? WHERE research_id=?",
            (json.dumps(payload), "research-graphql"),
        )
    with pytest.raises(ResearchIntegrityError):
        store.verify_integrity("research-graphql")


def test_root_role_integrity_matches_operation_type():
    state = semantic_state()
    query = next(item for item in state.graphql_types if item.type_id == "type-query")
    payload = state.model_dump(mode="python")
    payload["graphql_types"] = tuple(
        (
            query.model_copy(update={"root_role": GraphQLRootRole.mutation})
            if item.type_id == query.type_id
            else item
        )
        for item in state.graphql_types
    )
    with pytest.raises(ValidationError, match="matching root type"):
        ResearchState.model_validate(payload)
