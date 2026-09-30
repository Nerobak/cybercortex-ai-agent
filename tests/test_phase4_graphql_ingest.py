from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent_core.research import ResearchPredicate, ResearchStore
from agent_core.capture_ingest import import_capture
from agent_core.research.graphql_discovery import (
    GraphQLDiscoveryConfidence,
    GraphQLSurfaceDetector,
)
from agent_core.research.graphql_ingest import (
    GraphQLControlledObjectEvidence,
    GraphQLDocumentError,
    GraphQLErrorClass,
    GraphQLResponseEnvelope,
    GraphQLSemanticIngestor,
    analyze_graphql_response,
    parse_graphql_document,
)
from agent_core.research.graphql import GraphQLLimitExceeded, GraphQLSchemaState
from test_phase4_graphql_semantics import TS_1, semantic_state


DIGEST = "sha256:" + "9" * 64


def observation(**updates):
    values = {
        "observation_id": "graphql-observation-1",
        "target_id": "target-1",
        "endpoint_url": "https://authorized.example/api/gql",
        "method": "POST",
        "source_kind": "capture",
        "source_reference": "capture:graphql-1",
        "evidence_digest": DIGEST,
        "identity_id": None,
    }
    values.update(updates)
    return SimpleNamespace(**values)


def test_bounded_parser_normalizes_operations_aliases_variables_and_fragments():
    parsed = parse_graphql_document(
        """
        query GetResource($resourceId: ID!, $secretInput: String = "discard-me") {
          responseAlias: resource(id: $resourceId) {
            ...ResourceFields
            ... on OwnedResource { owner { id } }
          }
        }
        fragment ResourceFields on Resource { id displayName }
        """
    )

    operation = parsed.operations[0]
    assert operation.operation_name == "GetResource"
    assert operation.operation_type.value == "query"
    assert operation.selections[0].response_alias == "responseAlias"
    assert operation.selections[0].field_name == "resource"
    assert operation.selections[0].arguments[0].variable_name == "resourceId"
    assert operation.variables[0].input_type.to_syntax() == "ID!"
    assert operation.variables[1].default_present
    assert parsed.fragment_count == 1
    serialized = parsed.model_dump_json()
    assert "discard-me" not in serialized


@pytest.mark.parametrize(
    "document",
    (
        "query Broken {",
        "query Q { node { ...A } } fragment A on Node { ...B } fragment B on Node { ...A }",
        "query Q { ok } fragment A on Node { ...B } fragment B on Node { ...A }",
        "query Q { ...Missing }",
        "query Q { ok } fragment Unused on Node { ...Missing }",
    ),
)
def test_bounded_parser_rejects_malformed_and_cyclic_documents(document):
    with pytest.raises(GraphQLDocumentError):
        parse_graphql_document(document)


def test_fragment_expansion_obeys_the_global_node_ceiling():
    document = "query Q { ...F ...F ...F } fragment F on Query { a b c d }"
    with pytest.raises(GraphQLLimitExceeded, match="expanded"):
        parse_graphql_document(document, max_nodes=10)


def test_fragment_expansion_obeys_final_selection_depth_and_operation_rules():
    expanded_deep = (
        "query Q { ...A } "
        "fragment A on Query { a { ...B } } "
        "fragment B on Node { b { ...C } } "
        "fragment C on Node { c }"
    )
    with pytest.raises(GraphQLLimitExceeded, match="expanded.*depth"):
        parse_graphql_document(expanded_deep, max_depth=4)
    with pytest.raises(GraphQLDocumentError, match="duplicate.*operation"):
        parse_graphql_document("query Same { a } query Same { b }")
    with pytest.raises(GraphQLDocumentError, match="anonymous.*share"):
        parse_graphql_document("{ a } query Named { b }")


def test_response_analysis_retains_structure_but_not_personal_values():
    payload = {
        "data": {
            "viewer": {
                "__typename": "User",
                "email": "private-person@example.test",
                "phone": "+1-312-555-0100",
                "address": "101 Private Street",
                "name": "Private Person",
            }
        }
    }
    result = analyze_graphql_response(payload, request_was_graphql=True)

    assert result.envelope is GraphQLResponseEnvelope.graphql_data
    assert result.typename_observations == ("User",)
    assert "data.viewer.email:scalar" in result.object_shape
    serialized = result.model_dump_json()
    for value in (
        "private-person@example.test",
        "+1-312-555-0100",
        "101 Private Street",
        "Private Person",
    ):
        assert value not in serialized


def test_response_shape_marks_depth_and_list_window_truncation():
    nested: dict[str, object] = {"leaf": "excluded-value"}
    for index in range(20):
        nested = {f"level{index}": nested}
    payload = {
        "data": {
            "deep": nested,
            "items": [{"id": index} for index in range(40)],
        }
    }

    result = analyze_graphql_response(payload, request_was_graphql=True)

    assert result.is_graphql
    assert result.truncated
    assert "excluded-value" not in result.model_dump_json()
    assert analyze_graphql_response({"ok": True}).envelope is (
        GraphQLResponseEnvelope.ordinary_json
    )


def test_error_classification_uses_status_and_structured_codes_not_prose():
    prose = analyze_graphql_response(
        {"errors": [{"message": "forbidden because the prose says so"}]},
        request_was_graphql=True,
    )
    unauthorized = analyze_graphql_response(
        {"error": "login required"},
        status_code=401,
        request_was_graphql=True,
    )

    assert prose.error_classes == (GraphQLErrorClass.unknown,)
    assert unauthorized.envelope is GraphQLResponseEnvelope.ordinary_json
    assert unauthorized.error_classes == (GraphQLErrorClass.authentication_error,)


def test_error_paths_retain_their_own_safe_structural_classification():
    result = analyze_graphql_response(
        {
            "data": {"viewer": {"email": None}, "catalog": None},
            "errors": [
                {
                    "message": "excluded",
                    "path": ["viewer", "email"],
                    "extensions": {"code": "FORBIDDEN"},
                },
                {
                    "message": "excluded too",
                    "path": ["catalog"],
                    "extensions": {"category": "GRAPHQL_VALIDATION_FAILED"},
                },
            ],
        },
        request_was_graphql=True,
    )

    assert tuple((item.path, item.error_class) for item in result.error_paths) == (
        (("viewer", "email"), GraphQLErrorClass.authorization_error),
        (("catalog",), GraphQLErrorClass.validation_error),
    )
    assert "excluded" not in result.model_dump_json()


def test_document_ingestion_is_valid_idempotent_and_links_one_variable():
    state = semantic_state()
    delta = GraphQLSemanticIngestor().from_document(
        state,
        observation(),
        "query Read($resourceId: ID!) { resource(id: $resourceId) { id } }",
        occurred_at=TS_1,
    )

    first = delta.apply(state)
    second = delta.apply(first)
    acquired = next(
        item
        for item in first.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    )
    operation = next(
        item
        for item in first.graphql_operations
        if getattr(item, "graphql_surface_id", None) == acquired.graphql_surface_id
    )
    variable = next(
        item
        for item in first.graphql_variables
        if item.operation_id == operation.operation_id
    )

    assert acquired.schema_state is GraphQLSchemaState.capture_derived
    assert variable.linked_argument_id is not None
    assert len(second.graphql_surfaces) == len(first.graphql_surfaces)
    assert len(second.graphql_operations) == len(first.graphql_operations)
    assert not second.findings


def test_root_named_fragment_ingests_its_concrete_root_field():
    delta = GraphQLSemanticIngestor().from_document(
        semantic_state(),
        observation(observation_id="graphql-root-fragment"),
        "query RootFragment { ...RootFields } fragment RootFields on Query { viewer { id } }",
        occurred_at=TS_1,
    )
    assert {item.name for item in delta.fields} == {"viewer"}
    assert len(delta.operations[0].root_field_ids) == 1


def test_variable_reused_by_multiple_arguments_is_not_ambiguously_linked():
    delta = GraphQLSemanticIngestor().from_document(
        semantic_state(),
        observation(observation_id="graphql-reused-variable"),
        "query Search($term: String!) { one(term: $term) two(term: $term) }",
        occurred_at=TS_1,
    )
    assert delta.variables[0].linked_argument_id is None


def test_introspection_mapping_is_bounded_and_models_roots_interfaces_and_unions():
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "interfaces": [],
                        "fields": [
                            {
                                "name": "node",
                                "args": [
                                    {
                                        "name": "id",
                                        "defaultValue": None,
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {"kind": "SCALAR", "name": "ID"},
                                        },
                                    }
                                ],
                                "type": {"kind": "INTERFACE", "name": "Node"},
                            }
                        ],
                    },
                    {"kind": "SCALAR", "name": "ID"},
                    {
                        "kind": "INTERFACE",
                        "name": "Node",
                        "fields": [],
                        "possibleTypes": [{"name": "Resource"}],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Resource",
                        "fields": [],
                        "interfaces": [{"name": "Node"}],
                    },
                    {
                        "kind": "UNION",
                        "name": "SearchResult",
                        "possibleTypes": [{"name": "Resource"}],
                    },
                ],
            }
        }
    }
    delta = GraphQLSemanticIngestor().from_introspection(
        semantic_state(),
        observation(observation_id="graphql-introspection"),
        payload,
        occurred_at=TS_1,
    )

    by_name = {item.name: item for item in delta.types}
    assert by_name["Query"].root_role.value == "query"
    assert by_name["Node"].possible_type_ids == (by_name["Resource"].type_id,)
    assert by_name["Resource"].interface_ids == (by_name["Node"].type_id,)
    assert by_name["SearchResult"].possible_type_ids == (by_name["Resource"].type_id,)
    assert delta.arguments[0].input_type.to_syntax() == "ID!"
    assert not delta.apply(semantic_state()).findings


def test_introspection_scans_only_configured_type_field_and_argument_windows():
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {"malformed": True},
                            {
                                "name": "mustNotBeScanned",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String"},
                            },
                        ],
                    },
                    {"kind": "SCALAR", "name": "String"},
                ],
            }
        }
    }

    delta = GraphQLSemanticIngestor().from_introspection(
        semantic_state(),
        observation(observation_id="graphql-introspection-scan-bounds"),
        payload,
        occurred_at=TS_1,
        max_types=1,
        max_fields=1,
        max_arguments=1,
    )

    assert [item.name for item in delta.types] == ["Query"]
    assert not delta.fields
    assert delta.graphql_surfaces[0].schema_state is GraphQLSchemaState.partial


def test_controlled_object_requires_owned_identity_and_builds_both_cross_surface_edges():
    state = semantic_state()
    delta = GraphQLSemanticIngestor().controlled_object(
        state,
        observation(
            observation_id="graphql-controlled-object", identity_id="identity-a"
        ),
        GraphQLControlledObjectEvidence(
            identity_id="identity-a",
            object_type="Resource",
            object_reference="controlled-resource-ref",
            ownership_basis="owner_scoped_authenticated_response",
            graphql_type_name="Resource",
            existing_object_id="object-resource-1",
            evidence_reference="controlled-fixture:resource-1",
        ),
        occurred_at=TS_1,
    )

    acquired = delta.objects[0]
    assert acquired.owner_identity_id == "identity-a"
    assert acquired.test_owned
    relations = {
        item.relation
        for item in (*delta.object_relationships, *delta.cross_surface_relationships)
    }
    assert ResearchPredicate.references_same_object in relations
    assert ResearchPredicate.crosses_surface in relations
    assert delta.evidence[0].source_reference == "controlled-fixture:resource-1"
    assert "controlled-fixture:resource-1" in delta.provenance[0].source_references
    assert not delta.apply(state).findings


def test_controlled_object_does_not_claim_cross_surface_for_same_surface_match():
    state = semantic_state()
    same_surface_object = state.objects[0].model_copy(
        update={"surface_id": "surface-graphql"}
    )
    state = state.model_copy(update={"objects": (same_surface_object,)})

    delta = GraphQLSemanticIngestor().controlled_object(
        state,
        observation(
            observation_id="graphql-controlled-object-same-surface",
            identity_id="identity-a",
        ),
        GraphQLControlledObjectEvidence(
            identity_id="identity-a",
            object_type="Resource",
            object_reference="controlled-resource-ref",
            ownership_basis="authoritative_controlled_fixture",
            existing_object_id="object-resource-1",
            evidence_reference="controlled-fixture:resource-1",
        ),
        occurred_at=TS_1,
    )

    assert not delta.cross_surface_relationships


def test_parser_and_semantic_delta_never_retain_variable_values_or_secret_sentinels():
    document = (
        "query LoginShape($password: String!, $apiKey: String) "
        "{ viewer(password: $password, apiKey: $apiKey) { id } }"
    )
    parsed = parse_graphql_document(document)
    delta = GraphQLSemanticIngestor().from_document(
        semantic_state(), observation(observation_id="graphql-secret-boundary"), parsed
    )
    serialized = json.dumps(delta.model_dump(mode="json"), sort_keys=True)
    assert "raw-password-sentinel" not in serialized
    assert "raw-api-key-sentinel" not in serialized
    assert "Authorization" not in serialized
    assert "Cookie" not in serialized


def test_passive_har_capture_populates_semantics_without_target_requests(tmp_path):
    private_values = {
        "password": "synthetic-secret-password-capture",
        "email": "private-person@example.test",
        "phone": "+1-312-555-0100",
    }
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://authorized.example/api/gql",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "operationName": "Viewer",
                                    "query": (
                                        "query Viewer($password: String!) "
                                        "{ viewer(password: $password) "
                                        "{ __typename email phone } }"
                                    ),
                                    "variables": {
                                        "password": private_values["password"]
                                    },
                                }
                            ),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "data": {
                                        "viewer": {
                                            "__typename": "User",
                                            "email": private_values["email"],
                                            "phone": private_values["phone"],
                                        }
                                    }
                                }
                            ),
                            "size": 200,
                        },
                    },
                }
            ]
        }
    }
    path = tmp_path / "graphql.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    bundle, vault = import_capture(path)

    batch = GraphQLSurfaceDetector().detect(
        bundle,
        target_id="target-1",
        target_url="https://authorized.example",
        vault=vault,
    )
    assert len(batch.observations) == len(batch.documents) == 1
    assert batch.observations[0].confidence is GraphQLDiscoveryConfidence.confirmed
    delta = GraphQLSemanticIngestor().from_document(
        semantic_state(),
        batch.observations[0],
        batch.documents[0].document,
        response=batch.documents[0].response,
        occurred_at=TS_1,
    )
    acquired = delta.apply(semantic_state())
    assert any(item.operation_name == "Viewer" for item in acquired.graphql_operations)
    assert not acquired.findings

    persistent = (
        bundle.model_dump_json() + batch.model_dump_json() + delta.model_dump_json()
    )
    for value in private_values.values():
        assert value not in persistent


def test_capture_authorization_cookie_and_api_key_values_remain_vault_only(tmp_path):
    sentinels = {
        "Authorization": "Bearer synthetic-secret-authorization-capture",
        "Cookie": "session=synthetic-secret-cookie-capture",
        "X-Api-Key": "synthetic-secret-api-key-capture",
    }
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://authorized.example/graphql",
                        "headers": [
                            {"name": name, "value": value}
                            for name, value in sentinels.items()
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"query": "query Q { __typename }"}),
                        },
                    },
                    "response": {},
                }
            ]
        }
    }
    path = tmp_path / "authenticated.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    bundle, vault = import_capture(path)
    serialized = bundle.model_dump_json()

    assert bundle.identities[0].credential_references
    assert all(
        vault.contains(ref) for ref in bundle.identities[0].credential_references
    )
    assert all(value not in serialized for value in sentinels.values())


@pytest.mark.parametrize("suffix", ("graphql", "gql"))
def test_standalone_graphql_capture_uses_vault_handle_for_bounded_parsing(
    tmp_path, suffix
):
    path = tmp_path / f"viewer.{suffix}"
    path.write_text(
        "query Viewer($id: ID!) { viewer(id: $id) { id } }", encoding="utf-8"
    )
    bundle, vault = import_capture(
        path, default_base_url="https://authorized.example/api/gql"
    )
    batch = GraphQLSurfaceDetector().detect(bundle, target_id="target-1", vault=vault)
    assert batch.documents[0].document.operations[0].operation_name == "Viewer"
    assert bundle.requests[0].execution_body_ref


def _viewer_introspection(return_type: str) -> dict:
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "viewer",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": return_type},
                            }
                        ],
                        "interfaces": [],
                    },
                    {"kind": "SCALAR", "name": return_type},
                ],
            }
        }
    }


def test_restart_reimport_and_introspection_enrichment_keep_stable_ids(tmp_path):
    database = tmp_path / "graphql-restart.sqlite3"
    store = ResearchStore(database)
    initial = semantic_state()
    store.create_research(initial)
    ingestor = GraphQLSemanticIngestor()
    captured = observation(observation_id="graphql-restart-capture")
    document = "query Viewer { viewer { id } }"

    first = ingestor.from_document(
        initial, captured, document, occurred_at=TS_1
    ).commit(store, initial, updated_at=TS_1)
    first_surface = next(
        item
        for item in first.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    )
    first_operation = next(
        item
        for item in first.graphql_operations
        if getattr(item, "graphql_surface_id", None) == first_surface.graphql_surface_id
    )
    first_counts = (
        len(first.graphql_surfaces),
        len(first.graphql_types),
        len(first.graphql_fields),
        len(first.graphql_operations),
    )
    store.close()

    reopened = ResearchStore(database)
    resumed = reopened.load_research(initial.research_id)
    repeated = ingestor.from_document(
        resumed, captured, document, occurred_at=TS_1
    ).commit(
        reopened,
        resumed,
        updated_at="2026-09-28T12:00:02+00:00",
    )
    enriched = ingestor.from_introspection(
        repeated,
        observation(observation_id="graphql-restart-introspection"),
        _viewer_introspection("String"),
        occurred_at="2026-09-28T12:00:03+00:00",
    ).commit(
        reopened,
        repeated,
        updated_at="2026-09-28T12:00:03+00:00",
    )
    enriched_surface = next(
        item
        for item in enriched.graphql_surfaces
        if item.graphql_surface_id == first_surface.graphql_surface_id
    )
    enriched_operation = next(
        item
        for item in enriched.graphql_operations
        if getattr(item, "operation_id", None) == first_operation.operation_id
    )
    viewer = next(
        item
        for item in enriched.graphql_fields
        if item.type_id
        in {
            graphql_type.type_id
            for graphql_type in enriched.graphql_types
            if graphql_type.graphql_surface_id == first_surface.graphql_surface_id
            and graphql_type.name == "Query"
        }
        and item.name == "viewer"
    )

    assert first_counts == (
        len(repeated.graphql_surfaces),
        len(repeated.graphql_types),
        len(repeated.graphql_fields),
        len(repeated.graphql_operations),
    )
    assert enriched_surface.schema_state is GraphQLSchemaState.merged
    assert enriched_operation.operation_id == first_operation.operation_id
    assert viewer.return_type.to_syntax() == "String"
    assert reopened.query_graph_assertions(initial.research_id, limit=500)
    assert reopened.verify_integrity(initial.research_id).valid


def test_conflicting_introspection_retains_both_evidence_without_overwrite():
    ingestor = GraphQLSemanticIngestor()
    state = semantic_state()
    captured = ingestor.from_document(
        state,
        observation(observation_id="graphql-conflict-capture"),
        "query Viewer { viewer { id } }",
        occurred_at=TS_1,
    ).apply(state)
    string_schema = ingestor.from_introspection(
        captured,
        observation(observation_id="graphql-conflict-string"),
        _viewer_introspection("String"),
        occurred_at=TS_1,
    ).apply(captured)
    conflicted = ingestor.from_introspection(
        string_schema,
        observation(observation_id="graphql-conflict-int"),
        _viewer_introspection("Int"),
        occurred_at=TS_1,
    ).apply(string_schema)
    acquired_surface = next(
        item
        for item in conflicted.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    )
    query_type = next(
        item
        for item in conflicted.graphql_types
        if item.graphql_surface_id == acquired_surface.graphql_surface_id
        and item.name == "Query"
    )
    viewer = next(
        item
        for item in conflicted.graphql_fields
        if item.type_id == query_type.type_id and item.name == "viewer"
    )

    assert viewer.return_type.to_syntax() == "String"
    assert len(viewer.evidence_references) >= 2
    assert any(
        item.observation_type == "graphql_semantic_conflict"
        for item in conflicted.observations
    )


def test_capture_introspection_capability_conflict_is_explicit():
    ingestor = GraphQLSemanticIngestor()
    state = semantic_state()
    captured = ingestor.from_document(
        state,
        observation(observation_id="graphql-mutation-capture"),
        "mutation Update { updateViewer { id } }",
        occurred_at=TS_1,
    ).apply(state)
    conflicted = ingestor.from_introspection(
        captured,
        observation(observation_id="graphql-query-only-schema"),
        _viewer_introspection("String"),
        occurred_at=TS_1,
    ).apply(captured)
    surface = next(
        item
        for item in conflicted.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    )

    assert {item.value for item in surface.operation_capabilities} == {"mutation"}
    assert any(
        item.observation_type == "graphql_semantic_conflict"
        for item in conflicted.observations
    )
    assert any(
        item.name == "Query" and item.graphql_surface_id == surface.graphql_surface_id
        for item in conflicted.graphql_types
    )
