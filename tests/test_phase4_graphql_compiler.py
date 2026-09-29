from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.research import (
    ExperimentCompiler,
    ExperimentCompilerError,
    GraphQLCandidateKind,
    GraphQLExperimentStateChangeClass,
    PrimitiveCapabilityState,
    materialize_candidate,
)

from test_phase4_graphql_candidates import _candidate_fixture


def test_object_candidate_materializes_and_compiles_without_transport():
    state, context, builder = _candidate_fixture()
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )

    proposal = materialize_candidate(candidate, state, model_decision_id="decision-c2")
    experiment = builder.compiler.compile(proposal, state, context)

    assert proposal.model_decision_id == "decision-c2"
    assert experiment.target.operation_id == candidate.operation_id
    assert experiment.request_estimate.total_reservation == 2
    assert experiment.state_changing is False
    assert all(
        item.capability_state is PrimitiveCapabilityState.compile_only
        for item in experiment.primitive_steps
    )
    rendered = json.dumps(experiment.model_dump(mode="json"), sort_keys=True)
    assert "query ResourceQuery" not in rendered
    assert "controlled-resource-ref" not in rendered
    assert "credential" not in rendered.casefold()


def test_graphql_compiler_rejects_unknown_operation_template():
    state, context, builder = _candidate_fixture()
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    proposal = materialize_candidate(candidate, state)
    payload = proposal.model_dump(mode="python")
    first = payload["primitive_steps"][0]
    first["input"]["operation_template_id"] = "invented-template"

    with pytest.raises(ExperimentCompilerError):
        ExperimentCompiler(builder.registry).compile(payload, state, context)


def test_graphql_candidate_binding_is_not_model_editable():
    state, _context, builder = _candidate_fixture()
    candidate = next(
        item
        for item in builder.build(state, compiler_context=_context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    payload = candidate.model_dump(mode="python")
    payload["graphql_document"] = "query Invented { secret }"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        type(candidate).model_validate(payload)


def test_compile_only_graphql_primitive_is_not_execution_available():
    state, context, builder = _candidate_fixture()
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    proposal = materialize_candidate(candidate, state)
    execution_context = context.model_copy(update={"execution_ready": True})

    with pytest.raises(
        ExperimentCompilerError, match="primitive_not_execution_available"
    ):
        builder.compiler.compile(proposal, state, execution_context)


def test_irreversible_template_is_rejected_before_candidate_construction():
    state, context, builder = _candidate_fixture()
    template = context.graphql_operation_templates[0].model_copy(
        update={
            "state_change_class": (
                GraphQLExperimentStateChangeClass.irreversible_or_disallowed
            )
        }
    )
    context = context.model_copy(update={"graphql_operation_templates": (template,)})

    assert builder.build(state, compiler_context=context) == ()
