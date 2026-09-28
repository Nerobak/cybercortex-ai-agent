from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_core.research import (
    Endpoint,
    EvidenceArtifact,
    EvidenceKind,
    GraphQLArgumentRecord,
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLAuthorizationSemantics,
    GraphQLFieldRecord,
    GraphQLLimitExceeded,
    GraphQLObjectReferenceKind,
    GraphQLObjectReferenceSemantics,
    GraphQLOperationRecord,
    GraphQLOperationType,
    GraphQLRelationshipHint,
    GraphQLRelationshipKind,
    GraphQLReturnShape,
    GraphQLRootRole,
    GraphQLSchemaState,
    GraphQLSemanticConflict,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    GraphQLSurface,
    GraphQLTransport,
    GraphQLTypeKind,
    GraphQLTypeRecord,
    GraphQLTypeReference,
    GraphQLVariableRecord,
    HttpMethod,
    Identity,
    IdentityEligibility,
    MAX_GRAPHQL_FIELDS_PER_TYPE,
    MAX_GRAPHQL_SELECTION_DEPTH,
    Parameter,
    ParameterLocation,
    ProvenanceProducerType,
    ProvenanceRecord,
    ResearchObject,
    ResearchConfidence,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    SecretMaterialRejected,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
    build_public_safe_graphql_summary,
    graphql_operation_fingerprint,
    graphql_selection_fingerprint,
    merge_graphql_semantics,
    normalize_graphql_name,
    normalize_graphql_selection,
)

TS = "2026-09-28T12:00:00+00:00"
TS_1 = "2026-09-28T12:00:01+00:00"
DIGEST = "sha256:" + "4" * 64


def _auth(
    *observations: GraphQLAuthorizationObservation,
) -> GraphQLAuthorizationSemantics:
    return GraphQLAuthorizationSemantics(
        observations=observations or (GraphQLAuthorizationObservation.unknown,),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )


def _field(
    field_id: str,
    type_id: str,
    name: str,
    type_syntax: str,
    shape: GraphQLReturnShape,
    *,
    argument_ids: tuple[str, ...] = (),
    hints: tuple[GraphQLRelationshipHint, ...] = (),
    auth: GraphQLAuthorizationSemantics | None = None,
    unresolved: bool = False,
) -> GraphQLFieldRecord:
    reference = GraphQLTypeReference.from_syntax(
        type_syntax, unresolved_external=unresolved
    )
    return GraphQLFieldRecord(
        field_id=field_id,
        type_id=type_id,
        name=name,
        return_type=reference,
        return_shape=shape,
        nullable=reference.nullable,
        list_depth=reference.list_depth,
        argument_ids=argument_ids,
        relationship_hints=hints,
        authorization_semantics=auth or _auth(),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )


def semantic_state() -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="prov-graphql",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-graphql-fixture",
        producer_version="v1",
        summary="Deterministic GraphQL semantic fixture.",
        occurred_at=TS,
    )
    evidence = EvidenceArtifact(
        evidence_id="evidence-graphql",
        evidence_kind=EvidenceKind.graphql_document,
        digest=DIGEST,
        summary="Synthetic GraphQL structure was deterministically observed.",
        source_reference="graphql-document-1",
        observed_at=TS,
        provenance_id="prov-graphql",
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="authorized-synthetic-target",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-1",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    rest_surface = Surface(
        surface_id="surface-rest",
        target_id="target-1",
        surface_type=SurfaceType.rest,
        label="Synthetic REST surface.",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    graphql_surface = Surface(
        surface_id="surface-graphql",
        target_id="target-1",
        surface_type=SurfaceType.graphql,
        label="Synthetic GraphQL surface.",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    rest_endpoint = Endpoint(
        endpoint_id="endpoint-rest",
        target_id="target-1",
        surface_id="surface-rest",
        method=HttpMethod.get,
        route_template="/resources/{resourceRef}",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    graphql_endpoint = Endpoint(
        endpoint_id="endpoint-graphql",
        target_id="target-1",
        surface_id="surface-graphql",
        method=HttpMethod.post,
        route_template="/graphql",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    parameter = Parameter(
        parameter_id="parameter-resource-ref",
        endpoint_id="endpoint-rest",
        name="resourceRef",
        location=ParameterLocation.path,
        data_type="opaque-reference",
        required=True,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    identity = Identity(
        identity_id="identity-a",
        account_reference="controlled-account-a",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-graphql",
    )
    research_object = ResearchObject(
        object_id="object-resource-1",
        target_id="target-1",
        surface_id="surface-rest",
        object_type="Resource",
        object_reference="controlled-resource-ref",
        owner_identity_id="identity-a",
        test_owned=True,
        parameter_references=("parameter-resource-ref",),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    semantic_surface = GraphQLSurface(
        graphql_surface_id="graphql-surface-1",
        research_id="research-graphql",
        target_id="target-1",
        surface_id="surface-graphql",
        endpoint_id="endpoint-graphql",
        transport=GraphQLTransport.https,
        schema_state=GraphQLSchemaState.merged,
        operation_capabilities=(GraphQLOperationType.query,),
        authentication_requirement=GraphQLAuthenticationRequirement.unknown,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    argument = GraphQLArgumentRecord(
        argument_id="argument-resource-ref",
        field_id="field-query-resource",
        name="resourceRef",
        input_type=GraphQLTypeReference.from_syntax("ID!"),
        nullable=False,
        list_depth=0,
        default_presence=False,
        semantic_role=GraphQLSemanticRole.object_reference,
        semantic_role_evidence_references=("evidence-graphql",),
        object_reference_semantics=GraphQLObjectReferenceSemantics(
            kind=GraphQLObjectReferenceKind.research_object,
            graphql_type_id="type-resource",
            research_object_id="object-resource-1",
            confidence=ResearchConfidence.high,
        ),
        parameter_id="parameter-resource-ref",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    resource_hint = GraphQLRelationshipHint(
        kind=GraphQLRelationshipKind.returns_object,
        graphql_type_id="type-resource",
        research_object_id="object-resource-1",
        evidence_references=("evidence-graphql",),
    )
    fields = (
        _field(
            "field-query-viewer",
            "type-query",
            "viewer",
            "User",
            GraphQLReturnShape.object,
            hints=(
                GraphQLRelationshipHint(
                    kind=GraphQLRelationshipKind.returns_object,
                    graphql_type_id="type-user",
                    evidence_references=("evidence-graphql",),
                ),
            ),
        ),
        _field(
            "field-query-resource",
            "type-query",
            "resource",
            "Resource",
            GraphQLReturnShape.object,
            argument_ids=("argument-resource-ref",),
            hints=(resource_hint,),
        ),
        _field(
            "field-resource-ref",
            "type-resource",
            "resourceRef",
            "ID!",
            GraphQLReturnShape.scalar,
        ),
        _field(
            "field-resource-owner",
            "type-resource",
            "owner",
            "User",
            GraphQLReturnShape.object,
            hints=(
                GraphQLRelationshipHint(
                    kind=GraphQLRelationshipKind.traverses_object,
                    graphql_type_id="type-user",
                    evidence_references=("evidence-graphql",),
                ),
            ),
        ),
        _field(
            "field-resource-status",
            "type-resource",
            "status",
            "String!",
            GraphQLReturnShape.scalar,
        ),
    )
    types = (
        GraphQLTypeRecord(
            type_id="type-query",
            graphql_surface_id="graphql-surface-1",
            name="Query",
            kind=GraphQLTypeKind.object,
            root_role=GraphQLRootRole.query,
            field_ids=("field-query-viewer", "field-query-resource"),
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        ),
        GraphQLTypeRecord(
            type_id="type-user",
            graphql_surface_id="graphql-surface-1",
            name="User",
            kind=GraphQLTypeKind.object,
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        ),
        GraphQLTypeRecord(
            type_id="type-resource",
            graphql_surface_id="graphql-surface-1",
            name="Resource",
            kind=GraphQLTypeKind.object,
            field_ids=(
                "field-resource-ref",
                "field-resource-owner",
                "field-resource-status",
            ),
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        ),
        GraphQLTypeRecord(
            type_id="type-id",
            graphql_surface_id="graphql-surface-1",
            name="ID",
            kind=GraphQLTypeKind.scalar,
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        ),
        GraphQLTypeRecord(
            type_id="type-string",
            graphql_surface_id="graphql-surface-1",
            name="String",
            kind=GraphQLTypeKind.scalar,
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        ),
    )
    variable = GraphQLVariableRecord(
        variable_id="variable-resource-ref",
        operation_id="operation-resource",
        name="resourceRef",
        input_type=GraphQLTypeReference.from_syntax("ID!"),
        nullable=False,
        list_depth=0,
        semantic_role=GraphQLSemanticRole.object_reference,
        semantic_role_evidence_references=("evidence-graphql",),
        linked_argument_id="argument-resource-ref",
        controlled_value_reference="fixture-resource-reference",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    operation = GraphQLOperationRecord(
        operation_id="operation-resource",
        graphql_surface_id="graphql-surface-1",
        operation_type=GraphQLOperationType.query,
        operation_name="ResourceQuery",
        root_field_ids=("field-query-resource",),
        variable_ids=("variable-resource-ref",),
        selection_fingerprint=graphql_selection_fingerprint(
            "query ResourceQuery($resourceRef: ID!) "
            "{ resource(resourceRef: $resourceRef) { resourceRef owner { __typename } status } }"
        ),
        authentication_requirement=GraphQLAuthenticationRequirement.unknown,
        state_change_class=GraphQLStateChangeClass.read_only,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    return ResearchState(
        research_id="research-graphql",
        revision=0,
        status=ResearchRunStatus.modeling,
        created_at=TS,
        updated_at=TS,
        targets=(target,),
        surfaces=(rest_surface, graphql_surface),
        endpoints=(rest_endpoint, graphql_endpoint),
        parameters=(parameter,),
        identities=(identity,),
        objects=(research_object,),
        graphql_surfaces=(semantic_surface,),
        graphql_types=types,
        graphql_fields=fields,
        graphql_arguments=(argument,),
        graphql_operations=(operation,),
        graphql_variables=(variable,),
        evidence=(evidence,),
        provenance=(provenance,),
    )


@pytest.mark.parametrize(
    ("syntax", "nullable", "list_depth"),
    (
        ("Resource", True, 0),
        ("Resource!", False, 0),
        ("[Resource]", True, 1),
        ("[Resource!]!", False, 1),
        ("[[Resource]]", True, 2),
    ),
)
def test_type_reference_preserves_nested_list_and_nullability(
    syntax: str, nullable: bool, list_depth: int
):
    reference = GraphQLTypeReference.from_syntax(syntax)
    assert reference.to_syntax() == syntax
    assert reference.nullable is nullable
    assert reference.list_depth == list_depth


def test_graphql_names_preserve_case_and_reject_non_names():
    assert normalize_graphql_name("ResourceRef") == "ResourceRef"
    assert normalize_graphql_name("resourceRef") == "resourceRef"
    assert normalize_graphql_name("ResourceRef") != normalize_graphql_name(
        "resourceRef"
    )
    with pytest.raises(ValueError, match="invalid GraphQL name"):
        normalize_graphql_name("resource-ref")


def test_generic_schema_fixture_is_strict_immutable_and_integrated():
    state = semantic_state()
    assert [item.name for item in state.graphql_types] == [
        "ID",
        "Query",
        "Resource",
        "String",
        "User",
    ]
    assert any(item.name == "resource" for item in state.graphql_fields)
    assert (
        state.graphql_arguments[0].semantic_role is GraphQLSemanticRole.object_reference
    )
    with pytest.raises(ValidationError, match="frozen"):
        state.graphql_surfaces[0].schema_state = GraphQLSchemaState.unknown


def test_argument_name_alone_cannot_establish_identifier_semantics():
    with pytest.raises(ValidationError, match="supporting evidence"):
        GraphQLArgumentRecord(
            argument_id="argument-id",
            field_id="field-query-resource",
            name="id",
            input_type=GraphQLTypeReference.from_syntax("ID"),
            nullable=True,
            list_depth=0,
            default_presence=False,
            semantic_role=GraphQLSemanticRole.identifier,
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        )


def test_authorization_observation_is_semantic_not_a_finding():
    state = semantic_state()
    differing = _field(
        "field-query-viewer",
        "type-query",
        "viewer",
        "User",
        GraphQLReturnShape.object,
        auth=_auth(GraphQLAuthorizationObservation.identity_dependent_field_visibility),
    )
    payload = differing.model_dump(mode="json")
    assert payload["authorization_semantics"]["observations"] == [
        "identity_dependent_field_visibility"
    ]
    assert "vulnerability" not in json.dumps(payload).lower()
    assert state.findings == ()


def test_operation_and_selection_fingerprints_are_semantic_and_secret_free():
    compact = (
        "query ResourceQuery($resourceRef: ID!) "
        "{ resource(resourceRef:$resourceRef) { status owner { __typename } } }"
    )
    formatted = """
        query Renamed($resourceRef: ID!) {
          responseAlias: resource(resourceRef: $resourceRef) {
            owner { __typename }
            status
          }
        }
    """
    first = graphql_operation_fingerprint(
        compact, variable_values={"resourceRef": "synthetic-token-value"}
    )
    second = graphql_operation_fingerprint(
        formatted, variable_values={"resourceRef": "different-secret-value"}
    )
    assert first == second
    assert graphql_selection_fingerprint(compact) == graphql_selection_fingerprint(
        formatted
    )
    assert "synthetic-token-value" not in first
    changed_selection = compact.replace("status", "resourceRef")
    changed_argument = compact.replace("resourceRef:$resourceRef", "other:$resourceRef")
    assert graphql_operation_fingerprint(changed_selection) != first
    assert graphql_operation_fingerprint(changed_argument) != first
    assert (
        graphql_operation_fingerprint(compact.replace("query", "mutation", 1)) != first
    )


def test_selection_normalization_is_bounded_and_never_keeps_literals():
    normalized = normalize_graphql_selection(
        '{ resource(resourceRef: "private-value") { status } }'
    )
    assert "private-value" not in normalized
    too_deep = "query { " + "node { " * (MAX_GRAPHQL_SELECTION_DEPTH + 1)
    too_deep += "name " + "}" * (MAX_GRAPHQL_SELECTION_DEPTH + 2)
    with pytest.raises(GraphQLLimitExceeded, match="depth"):
        graphql_selection_fingerprint(too_deep)


def test_partial_schema_merge_is_idempotent_and_retains_evidence():
    state = semantic_state()
    partial_surface = state.graphql_surfaces[0].model_copy(
        update={"schema_state": GraphQLSchemaState.capture_derived}
    )
    unknown_viewer = _field(
        "field-query-viewer",
        "type-query",
        "viewer",
        "_Unknown",
        GraphQLReturnShape.unknown,
        unresolved=True,
    )
    payload = state.model_dump(mode="python")
    payload["graphql_surfaces"] = (partial_surface,)
    payload["graphql_fields"] = tuple(
        unknown_viewer if item.field_id == unknown_viewer.field_id else item
        for item in state.graphql_fields
    )
    partial = ResearchState.model_validate(payload)

    introspected_surface = state.graphql_surfaces[0].model_copy(
        update={"schema_state": GraphQLSchemaState.introspection_observed}
    )
    enriched = merge_graphql_semantics(
        partial,
        graphql_surfaces=(introspected_surface,),
        graphql_fields=(
            next(
                item
                for item in state.graphql_fields
                if item.field_id == "field-query-viewer"
            ),
        ),
    )
    assert enriched.graphql_surfaces[0].schema_state is GraphQLSchemaState.merged
    viewer = next(
        item
        for item in enriched.graphql_fields
        if item.field_id == "field-query-viewer"
    )
    assert viewer.return_type.to_syntax() == "User"
    assert viewer.provenance_id == "prov-graphql"
    assert (
        merge_graphql_semantics(
            enriched,
            graphql_surfaces=(introspected_surface,),
            graphql_fields=(viewer,),
        )
        == enriched
    )
    assert len({item.field_id for item in enriched.graphql_fields}) == len(
        enriched.graphql_fields
    )


def test_conflicting_schema_observations_are_not_silently_overwritten():
    state = semantic_state()
    resource = next(
        item for item in state.graphql_fields if item.field_id == "field-query-resource"
    )
    conflict = resource.model_copy(
        update={"return_type": GraphQLTypeReference.from_syntax("User")}
    )
    with pytest.raises(GraphQLSemanticConflict, match="return type"):
        merge_graphql_semantics(state, graphql_fields=(conflict,))


def test_graphql_state_rejects_dangling_semantic_references():
    state = semantic_state()
    payload = state.model_dump(mode="python")
    payload["graphql_types"] = tuple(
        item for item in state.graphql_types if item.type_id != "type-user"
    )
    with pytest.raises(ValidationError, match="dangling GraphQL return type"):
        ResearchState.model_validate(payload)


def test_model_only_evidence_cannot_become_graphql_semantic_truth():
    state = semantic_state()
    payload = state.model_dump(mode="python")
    payload["provenance"] = (
        state.provenance[0].model_copy(
            update={"producer_type": ProvenanceProducerType.model}
        ),
    )
    with pytest.raises(ValidationError, match="model-only evidence"):
        ResearchState.model_validate(payload)


def test_explicit_graphql_bounds_fail_closed():
    with pytest.raises(ValidationError, match="too_long"):
        GraphQLTypeRecord(
            type_id="type-too-large",
            graphql_surface_id="graphql-surface-1",
            name="TooLarge",
            kind=GraphQLTypeKind.object,
            field_ids=tuple(
                f"field-{index}" for index in range(MAX_GRAPHQL_FIELDS_PER_TYPE + 1)
            ),
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        )


def test_secret_values_have_no_model_field_and_store_detector_remains_active(
    tmp_path: Path,
):
    state = semantic_state()
    with pytest.raises(ValidationError, match="extra_forbidden"):
        GraphQLVariableRecord(
            variable_id="variable-secret",
            operation_id="operation-resource",
            name="secret",
            input_type=GraphQLTypeReference.from_syntax("String"),
            nullable=True,
            list_depth=0,
            raw_value="synthetic-token-value",
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        )
    with pytest.raises(ValidationError, match="secret sentinel"):
        GraphQLVariableRecord(
            variable_id="variable-secret-reference",
            operation_id="operation-resource",
            name="secretReference",
            input_type=GraphQLTypeReference.from_syntax("String"),
            nullable=True,
            list_depth=0,
            controlled_value_reference="synthetic-token-value",
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        )
    dumped = json.dumps(state.model_dump(mode="json"), sort_keys=True)
    assert "synthetic-token-value" not in dumped
    payload = state.model_dump(mode="python")
    variable = state.graphql_variables[0].model_copy(
        update={"controlled_value_reference": "synthetic-token-value"}
    )
    payload["graphql_variables"] = (variable,)
    unsafe = ResearchState.model_validate(payload)
    with pytest.raises(SecretMaterialRejected):
        ResearchStore(tmp_path / "secret.sqlite3").create_research(unsafe)


def test_public_safe_summary_is_deterministic_and_under_eight_kibibytes():
    packet = build_public_safe_graphql_summary(semantic_state())
    assert packet == build_public_safe_graphql_summary(semantic_state())
    assert len(packet.canonical_bytes()) < 8_192
    rendered = packet.canonical_bytes().decode("ascii")
    assert "query ResourceQuery" not in rendered
    assert "controlled-resource-ref" not in rendered
    assert "raw_value" not in rendered


def test_restart_can_continue_idempotent_graphql_enrichment(tmp_path: Path):
    database = tmp_path / "research.sqlite3"
    store = ResearchStore(database)
    initial = semantic_state()
    store.create_research(initial)
    store.close()
    reopened = ResearchStore(database)
    restored = reopened.load_research("research-graphql")
    merged = merge_graphql_semantics(
        restored,
        graphql_surfaces=restored.graphql_surfaces,
        graphql_types=restored.graphql_types,
        graphql_fields=restored.graphql_fields,
        graphql_arguments=restored.graphql_arguments,
        graphql_operations=tuple(
            item
            for item in restored.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
        ),
        graphql_variables=restored.graphql_variables,
        revision=1,
        updated_at=TS_1,
    )
    reopened.commit_revision("research-graphql", expected_revision=0, state=merged)
    reopened.close()
    final = ResearchStore(database).load_research("research-graphql")
    assert final.graphql_operations[0].operation_id == "operation-resource"
    assert final.graphql_operations[0].selection_fingerprint == (
        initial.graphql_operations[0].selection_fingerprint
    )
    assert final.graphql_fields == initial.graphql_fields
    assert final.provenance == initial.provenance
