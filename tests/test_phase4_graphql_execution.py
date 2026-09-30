from __future__ import annotations

import pickle

import pytest

from agent_core.research import (
    GraphQLCandidateKind,
    GraphQLDocumentRenderer,
    GraphQLExecutionError,
    GraphQLExecutionLimits,
    GraphQLExecutionRequest,
    GraphQLVariableBinding,
    GraphQLVariableValueSource,
    materialize_graphql_variables,
)

from test_phase4_graphql_candidates import _candidate_fixture


def _object_registration():
    state, context, builder = _candidate_fixture()
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    return state, context.graphql_operation_templates[0], candidate


def test_renderer_builds_one_canonical_document_from_registered_ids_only():
    state, template, candidate = _object_registration()

    rendered = GraphQLDocumentRenderer(state).render(
        template, variable_bindings=candidate.graphql_variable_bindings
    )

    assert rendered.document == (
        "query ResourceQuery($resourceRef:ID!)"
        "{resource(resourceRef:$resourceRef){owner{__typename} status}}"
    )
    assert rendered.operation_name == "ResourceQuery"
    assert rendered.variable_names == ("resourceRef",)
    assert rendered.document_digest.startswith("sha256:")


def test_renderer_rejects_unregistered_selection_and_depth_before_request():
    state, template, candidate = _object_registration()
    renderer = GraphQLDocumentRenderer(
        state, GraphQLExecutionLimits(max_selection_depth=1)
    )

    with pytest.raises(GraphQLExecutionError, match="selection bound"):
        renderer.render(template, variable_bindings=candidate.graphql_variable_bindings)
    with pytest.raises(GraphQLExecutionError, match="selected field"):
        GraphQLDocumentRenderer(state).render(
            template,
            variable_bindings=candidate.graphql_variable_bindings,
            selected_field_ids=("model-invented-field",),
        )


def test_variable_materialization_accepts_only_the_sealed_controlled_object():
    state, template, candidate = _object_registration()
    variables = materialize_graphql_variables(
        state,
        template,
        candidate.graphql_variable_bindings,
        object_references={"object-resource-1": "controlled-resource-ref"},
        identity_bindings={},
        controlled_values={},
    )
    assert dict(variables) == {"resourceRef": "controlled-resource-ref"}

    injected = GraphQLVariableBinding(
        variable_id="variable-resource-ref",
        argument_id="argument-resource-ref",
        value_source=GraphQLVariableValueSource.opaque_controlled_value,
        value_reference="model-payload",
    )
    with pytest.raises(GraphQLExecutionError, match="unavailable"):
        materialize_graphql_variables(
            state,
            template,
            (injected,),
            object_references={"object-resource-1": "controlled-resource-ref"},
            identity_bindings={},
            controlled_values={},
        )


def test_execution_request_cannot_be_model_constructed_or_serialized():
    with pytest.raises(TypeError, match="restricted"):
        GraphQLExecutionRequest(
            issuer=object(),
            target_id="target",
            surface_id="surface",
            endpoint_id="endpoint",
            operation_template_id="template",
            operation_id="operation",
            method="POST",
            url="https://example.test/graphql",
            document="query Q{__typename}",
            document_digest="sha256:" + "0" * 64,
            variables={},
            operation_name="Q",
            identity_id=None,
            object_ids=(),
            selected_field_ids=(),
            selected_field_names=(),
            expected_state_change_class="read_only",  # type: ignore[arg-type]
            response_byte_limit=1024,
            timeout_seconds=1,
            purpose="graphql_execution",
            runtime_provenance_reference="runtime",
        )

    state, template, candidate = _object_registration()
    rendered = GraphQLDocumentRenderer(state).render(
        template, variable_bindings=candidate.graphql_variable_bindings
    )
    from agent_core.research.graphql_execution import create_graphql_execution_request

    request = create_graphql_execution_request(
        target_id="target",
        surface_id="surface",
        endpoint_id="endpoint",
        operation_template_id=template.template_id,
        operation_id=template.operation_id,
        method="POST",
        url="https://example.test/graphql",
        rendered=rendered,
        variables={"resourceRef": "controlled-resource-ref"},
        identity_id=None,
        object_ids=("object-resource-1",),
        expected_state_change_class=template.state_change_class,
        response_byte_limit=1024,
        timeout_seconds=1,
        purpose="graphql_execution",
        runtime_provenance_reference="runtime",
    )
    assert "query ResourceQuery" not in repr(request)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(request)
