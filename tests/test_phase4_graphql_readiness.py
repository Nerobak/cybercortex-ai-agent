from __future__ import annotations

import json

from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquisition,
    owned_object_acquisition_reference,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.research import (
    ControlledContextResearchAdapter,
    ControlledObjectDescriptor,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentRegistry,
    GraphQLExperimentCandidateBuilder,
    GraphQLHypothesisGenerator,
    GraphQLObjectBindingBasis,
    GraphQLObjectReferenceSemantics,
    Identity,
    IdentityEligibility,
    PublicSafeCandidatePacketBuilder,
    ResearchPredicate,
    RegisteredGraphQLObjectBindingEvidence,
    ResearchBudgetManager,
    ResearchState,
    build_graphql_graph_assertions,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)

from test_phase4_graphql_semantics import TS, semantic_state

TARGET = "https://graphql-readiness.invalid"


def _controlled_policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="graphql-readiness-fixture",
        authorization_reference="authorization-graphql-readiness",
        authorization_confirmed=True,
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        controlled_account_ids=["account-a", "account-b"],
        credentials_allowed=True,
        request_budget=10,
        per_host_request_budget=10,
        resolve_dns_before_request=False,
    )


def _schema_without_controlled_objects() -> ResearchState:
    base = semantic_state()
    arguments = tuple(
        item.model_copy(
            update={"object_reference_semantics": GraphQLObjectReferenceSemantics()}
        )
        for item in base.graphql_arguments
    )
    fields = tuple(
        item.model_copy(
            update={
                "relationship_hints": tuple(
                    hint
                    for hint in item.relationship_hints
                    if hint.research_object_id is None
                )
            }
        )
        for item in base.graphql_fields
    )
    return ResearchState.model_validate(
        {
            **base.model_dump(mode="python"),
            "targets": (
                base.targets[0].model_copy(update={"canonical_reference": TARGET}),
            ),
            "identities": (),
            "objects": (),
            "graphql_fields": fields,
            "graphql_arguments": arguments,
            "graphql_operations": (),
            "graphql_variables": (),
        }
    )


def _with_registered_operation(state: ResearchState) -> ResearchState:
    registered = semantic_state()
    return ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "graphql_operations": tuple(
                item.model_copy(
                    update={"document_fingerprint": item.selection_fingerprint}
                )
                for item in registered.graphql_operations
            ),
            "graphql_variables": tuple(
                item.model_copy(update={"controlled_value_reference": None})
                for item in registered.graphql_variables
            ),
        }
    )


def test_schema_and_controlled_object_cannot_synthesize_registered_operation():
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
    assert limitations == ("graphql_readiness_missing_registered_operation_evidence",)
    assert ready.graphql_operations == ()
    assert ready.graphql_variables == ()
    assert candidate_ready_graphql_operation_templates(ready) == ()
    assert GraphQLHypothesisGenerator().generate_result(ready).hypotheses == ()


def test_multi_surface_controlled_acquisition_reaches_graphql_candidate_readiness():
    schema_only = _schema_without_controlled_objects()
    acquisitions = tuple(
        OwnedObjectAcquisition(
            owner_account_id=account_id,
            collection_url=f"{TARGET}/resources/{{resourceRef}}",
            method="GET",
            object_type="Resource",
            identifier_field="resourceRef",
        )
        for account_id in ("account-a", "account-b")
    )
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="account-a"),
            ControlledAccount(account_id="account-b"),
        ],
        object_acquisition=list(acquisitions),
    )
    acquired = tuple(
        ControlledObject(
            object_id=f"synthetic-owned-{index}",
            owner_account_id=acquisition.owner_account_id,
            object_type=acquisition.object_type,
            ownership_basis="owner_scoped_authenticated_collection",
            source_reference=owned_object_acquisition_reference(acquisition),
        )
        for index, acquisition in enumerate(acquisitions, start=1)
    )
    adapter = ControlledContextResearchAdapter()
    records = adapter.adapt_acquired_objects(
        acquired,
        context,
        schema_only,
        policy=_controlled_policy(),
        target_id="target-1",
        occurred_at=TS,
    )
    controlled = adapter.apply(schema_only, records)
    descriptors = {
        item.object_id: ControlledObjectDescriptor(
            object_type="Resource", identifier_field="resourceRef"
        )
        for item in controlled.objects
    }

    controlled = _with_registered_operation(controlled)
    operation = controlled.graphql_operations[0]
    variable = controlled.graphql_variables[0]
    ready, limitations = derive_candidate_ready_graphql_operations(
        controlled,
        descriptors,
        occurred_at=TS,
        binding_evidence=(
            RegisteredGraphQLObjectBindingEvidence(
                operation_id=operation.operation_id,
                variable_id=variable.variable_id,
                argument_id=str(variable.linked_argument_id),
                controlled_object_id=controlled.objects[0].object_id,
                binding_basis=(
                    GraphQLObjectBindingBasis.explicit_cross_surface_relationship
                ),
                evidence_references=controlled.objects[0].evidence_references,
            ),
        ),
    )
    templates = candidate_ready_graphql_operation_templates(ready)
    graph = build_graphql_graph_assertions(ready, asserted_at=TS)
    generation = GraphQLHypothesisGenerator().generate_result(ready, graph)
    prepared = ResearchState.model_validate(
        {
            **ready.model_dump(mode="python"),
            "hypotheses": generation.hypotheses,
            "provenance": (*ready.provenance, *generation.provenance),
        }
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    context_for_compiler = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=templates,
        policy_reference="policy-graphql-readiness",
    )
    compiler = ExperimentCompiler(registry, context_for_compiler)
    candidates = GraphQLExperimentCandidateBuilder(registry, budgets, compiler).build(
        prepared,
        compiler_context=context_for_compiler,
        graph=graph,
    )
    packet = PublicSafeCandidatePacketBuilder(budgets).build(prepared, candidates)
    serialized_packet = json.dumps(packet.public_payload(), sort_keys=True)

    assert limitations == ()
    assert len(records.objects) == 2
    assert all(item.surface_id == "surface-rest" for item in records.objects)
    assert len(records.evidence) == 2
    assert len(ready.graphql_operations) == 1
    assert len(templates) == 1
    assert generation.hypotheses
    assert candidates
    assert "graphql_readiness_operation_ready" in ready.diagnostic_codes
    assert any(
        item.relation is ResearchPredicate.graphql_references_object for item in graph
    )
    assert any(item.relation is ResearchPredicate.crosses_surface for item in graph)
    assert all(item.object_reference not in serialized_packet for item in ready.objects)
    assert "Authorization" not in serialized_packet


def test_name_only_cross_surface_match_cannot_bind_registered_operation():
    schema_only = _schema_without_controlled_objects()
    acquisition = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=f"{TARGET}/resources/{{resourceRef}}",
        object_type="Resource",
        identifier_field="resourceRef",
    )
    context = ControlledContext(
        accounts=[ControlledAccount(account_id="account-a")],
        object_acquisition=[acquisition],
    )
    acquired = ControlledObject(
        object_id="name-matches-but-is-not-evidence",
        owner_account_id="account-a",
        object_type="Resource",
        ownership_basis="owner_scoped_authenticated_collection",
        source_reference=owned_object_acquisition_reference(acquisition),
    )
    adapter = ControlledContextResearchAdapter()
    records = adapter.adapt_acquired_objects(
        (acquired,),
        context,
        schema_only,
        policy=_controlled_policy(),
        target_id="target-1",
        occurred_at=TS,
    )
    controlled = _with_registered_operation(adapter.apply(schema_only, records))
    operation = controlled.graphql_operations[0]
    variable = controlled.graphql_variables[0]

    ready, limitations = derive_candidate_ready_graphql_operations(
        controlled,
        {
            controlled.objects[0].object_id: ControlledObjectDescriptor(
                object_type="Resource", identifier_field="resourceRef"
            )
        },
        occurred_at=TS,
        binding_evidence=(
            RegisteredGraphQLObjectBindingEvidence(
                operation_id=operation.operation_id,
                variable_id=variable.variable_id,
                argument_id=str(variable.linked_argument_id),
                controlled_object_id=controlled.objects[0].object_id,
                binding_basis=GraphQLObjectBindingBasis.typed_object_relationship,
                evidence_references=controlled.objects[0].evidence_references,
            ),
        ),
    )

    assert limitations == ()
    assert ready.graphql_variables[0].controlled_value_reference is None
    assert candidate_ready_graphql_operation_templates(ready)[0].variable_bindings == ()
    assert not any(
        item.relation is ResearchPredicate.references_same_object
        and item.target.entity_id == controlled.objects[0].object_id
        for item in build_graphql_graph_assertions(ready, asserted_at=TS)
    )


def test_graphql_acquisition_provenance_registers_stable_safe_operation_template():
    schema_only = _schema_without_controlled_objects()
    acquisition = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=f"{TARGET}/graphql",
        method="POST",
        object_type="Resource",
        identifier_field="resourceRef",
        registered_graphql_document_reference="cred_synthetic_document",
        graphql_object_variable="resourceRef",
    )
    context = ControlledContext(
        accounts=[ControlledAccount(account_id="account-a")],
        object_acquisition=[acquisition],
    )
    raw_object_reference = "synthetic-graphql-owned-value"
    acquired = ControlledObject(
        object_id=raw_object_reference,
        owner_account_id="account-a",
        object_type="Resource",
        ownership_basis="owner_scoped_authenticated_collection",
        source_reference=owned_object_acquisition_reference(acquisition),
    )
    adapter = ControlledContextResearchAdapter()
    records = adapter.adapt_acquired_objects(
        (acquired,),
        context,
        schema_only,
        policy=_controlled_policy(),
        target_id="target-1",
        occurred_at=TS,
    )
    controlled = adapter.apply(schema_only, records)
    research_object = controlled.objects[0]

    controlled = _with_registered_operation(controlled)
    operation = controlled.graphql_operations[0]
    variable = controlled.graphql_variables[0]
    ready, limitations = derive_candidate_ready_graphql_operations(
        controlled,
        {
            research_object.object_id: ControlledObjectDescriptor(
                object_type="Resource", identifier_field="resourceRef"
            )
        },
        occurred_at=TS,
        binding_evidence=(
            RegisteredGraphQLObjectBindingEvidence(
                operation_id=operation.operation_id,
                variable_id=variable.variable_id,
                argument_id=str(variable.linked_argument_id),
                controlled_object_id=research_object.object_id,
                binding_basis=GraphQLObjectBindingBasis.registered_graphql_acquisition,
                evidence_references=research_object.evidence_references,
            ),
        ),
    )
    first = candidate_ready_graphql_operation_templates(ready)
    second = candidate_ready_graphql_operation_templates(ready)
    serialized_templates = json.dumps(
        [item.model_dump(mode="json") for item in first], sort_keys=True
    )

    assert limitations == ()
    assert research_object.surface_id == "surface-graphql"
    assert len(ready.graphql_operations) == len(ready.graphql_variables) == 1
    assert ready.graphql_variables[0].controlled_value_reference == (
        research_object.object_id
    )
    assert first == second
    assert len(first) == 1
    assert raw_object_reference not in serialized_templates
    assert "Authorization" not in serialized_templates


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

    assert ready.graphql_operations == ()
    assert ready.graphql_variables == ()
    assert limitations == ("graphql_readiness_missing_registered_operation_evidence",)
    assert not any(
        item.relation is ResearchPredicate.graphql_references_object
        and item.source.entity_kind.value == "graphql_operation"
        for item in build_graphql_graph_assertions(ready, asserted_at=TS)
    )


def test_graphql_readiness_reports_missing_controlled_object_precisely():
    state = _schema_without_controlled_objects()

    ready, limitations = derive_candidate_ready_graphql_operations(
        state, {}, occurred_at=TS
    )

    assert ready.graphql_operations == ()
    assert limitations == ("graphql_readiness_missing_registered_operation_evidence",)
    assert ready.diagnostic_codes == (
        "graphql_readiness_missing_registered_operation_evidence",
    )
