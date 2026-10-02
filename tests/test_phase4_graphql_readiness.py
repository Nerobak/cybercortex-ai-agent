from __future__ import annotations

from agent_core.research import (
    ControlledObjectDescriptor,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentRegistry,
    GraphQLCandidateKind,
    GraphQLExperimentCandidateBuilder,
    GraphQLHypothesisGenerator,
    GraphQLObjectReferenceSemantics,
    Identity,
    IdentityEligibility,
    ResearchBudgetManager,
    ResearchState,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)

from test_phase4_graphql_semantics import TS, semantic_state


def test_controlled_schema_evidence_becomes_candidate_ready_without_query_guessing():
    base = semantic_state()
    schema_arguments = tuple(
        item.model_copy(
            update={"object_reference_semantics": GraphQLObjectReferenceSemantics()}
        )
        for item in base.graphql_arguments
    )
    comparison = Identity(
        identity_id="identity-b",
        account_reference="controlled-account-b",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-graphql",
    )
    schema_only = ResearchState.model_validate(
        {
            **base.model_dump(mode="python"),
            "identities": (*base.identities, comparison),
            "graphql_arguments": schema_arguments,
            "graphql_operations": (),
            "graphql_variables": (),
        }
    )

    ready, limitations = derive_candidate_ready_graphql_operations(
        schema_only,
        {
            base.objects[0].object_id: ControlledObjectDescriptor(
                object_type="Resource",
                identifier_field="resourceRef",
            )
        },
        occurred_at=TS,
    )
    templates = candidate_ready_graphql_operation_templates(ready)
    generation = GraphQLHypothesisGenerator().generate_result(ready)
    prepared = ResearchState.model_validate(
        {
            **ready.model_dump(mode="python"),
            "hypotheses": generation.hypotheses,
            "provenance": (*ready.provenance, *generation.provenance),
        }
    )
    context = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=templates,
        policy_reference="policy-graphql-readiness",
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    compiler = ExperimentCompiler(registry, context)
    candidates = GraphQLExperimentCandidateBuilder(registry, budgets, compiler).build(
        prepared, compiler_context=context
    )

    assert limitations == ()
    assert len(ready.graphql_operations) == 1
    assert len(ready.graphql_variables) == 1
    assert len(templates) == 1
    assert ready.graphql_operations[0].state_change_class.value == "read_only"
    assert any(
        item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
        and item.controlled_object_id == base.objects[0].object_id
        and item.ownership_evidence_references
        and item.graphql_variable_bindings
        for item in candidates
    )


def test_ambiguous_schema_argument_does_not_fabricate_an_operation():
    base = semantic_state()
    duplicated_argument = base.graphql_arguments[0].model_copy(
        update={"argument_id": "argument-resource-ref-second"}
    )
    root = next(
        item for item in base.graphql_fields if item.field_id == "field-query-resource"
    ).model_copy(
        update={
            "argument_ids": (
                base.graphql_arguments[0].argument_id,
                duplicated_argument.argument_id,
            )
        }
    )
    schema_only = ResearchState.model_validate(
        {
            **base.model_dump(mode="python"),
            "graphql_fields": tuple(
                root if item.field_id == root.field_id else item
                for item in base.graphql_fields
            ),
            "graphql_arguments": (
                base.graphql_arguments[0].model_copy(
                    update={
                        "object_reference_semantics": GraphQLObjectReferenceSemantics()
                    }
                ),
                duplicated_argument.model_copy(
                    update={
                        "object_reference_semantics": GraphQLObjectReferenceSemantics()
                    }
                ),
            ),
            "graphql_operations": (),
            "graphql_variables": (),
        }
    )

    ready, _limitations = derive_candidate_ready_graphql_operations(
        schema_only,
        {
            base.objects[0].object_id: ControlledObjectDescriptor(
                object_type="Resource",
                identifier_field="resourceRef",
            )
        },
        occurred_at=TS,
    )

    assert ready.graphql_operations == ()
    assert ready.graphql_variables == ()
