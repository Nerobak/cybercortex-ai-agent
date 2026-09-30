from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_core.research import (
    CleanupDefinition,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentRegistry,
    GraphQLCandidateKind,
    GraphQLCandidateLimits,
    GraphQLCandidatePolicy,
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLAuthorizationSemantics,
    GraphQLExperimentCandidateBuilder,
    GraphQLExperimentStateChangeClass,
    GraphQLHypothesisGenerator,
    GraphQLHypothesisProperty,
    GraphQLRelationshipHint,
    GraphQLRelationshipKind,
    GraphQLOperationRecord,
    GraphQLOperationType,
    GraphQLRootRole,
    GraphQLSafeMutationClass,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    GraphQLVariableBinding,
    GraphQLVariableValueSource,
    Identity,
    IdentityEligibility,
    InformationGainEstimate,
    PublicSafeCandidatePacketBuilder,
    RegisteredGraphQLSafeMutation,
    ResearchBudgetManager,
    ResearchConfidence,
    ResearchPredicate,
    ResearchSelectionAction,
    ResearchSelectionDecision,
    ResearchState,
    ResearchStore,
    Relationship,
    RelationshipStatus,
    EntityKind,
    EntityReference,
    DerivationType,
    build_registered_graphql_operation_template,
    materialize_selected_graphql_candidate,
)

from test_phase4_graphql_hypotheses import (
    _assertion,
    _mutation_state,
    _two_identity_state,
)
from test_phase4_graphql_semantics import TS, semantic_state


def _state(state: ResearchState, **updates: object) -> ResearchState:
    return ResearchState.model_validate({**state.model_dump(mode="python"), **updates})


def _identity(identity_id: str, *, role: str, tenant: str) -> Identity:
    return Identity(
        identity_id=identity_id,
        account_reference=f"account-{identity_id}",
        role_reference=role,
        tenant_reference=tenant,
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-graphql",
    )


def _candidate_fixture(
    *,
    authenticated: bool = False,
    tenant: bool = False,
) -> tuple[
    ResearchState,
    ExperimentCompilerContext,
    GraphQLExperimentCandidateBuilder,
]:
    state = semantic_state()
    first = state.identities[0].model_copy(
        update={"role_reference": "reader", "tenant_reference": "tenant-a"}
    )
    second = _identity(
        "identity-b", role="operator", tenant="tenant-b" if tenant else "tenant-a"
    )
    operation = next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    )
    if authenticated or tenant:
        operation = operation.model_copy(
            update={
                "authentication_requirement": (
                    GraphQLAuthenticationRequirement.tenant_bound
                    if tenant
                    else GraphQLAuthenticationRequirement.authentication_required
                )
            }
        )
    owned = state.objects[0].model_copy(update={"tenant_reference": "tenant-a"})
    state = _state(
        state,
        identities=(first, second),
        objects=(owned,),
        graphql_operations=(operation,),
    )
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(
        state,
        operation.operation_id,
        selection_paths=(
            ("field-query-resource",),
            ("field-query-resource", "field-resource-owner"),
            ("field-query-resource", "field-resource-status"),
        ),
    )
    context = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=(template,),
        policy_reference="policy-graphql",
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    compiler = ExperimentCompiler(registry, context)
    builder = GraphQLExperimentCandidateBuilder(registry, budgets, compiler)
    return state, context, builder


def test_object_authorization_candidate_is_typed_bounded_and_stable():
    state, context, builder = _candidate_fixture()

    first = builder.build(state, compiler_context=context)
    second = builder.build(state, compiler_context=context)
    candidate = next(
        item
        for item in first
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )

    assert first == second
    assert candidate.graphql_variable_bindings[0].value_reference == (
        "object-resource-1"
    )
    assert candidate.minimum_requests == candidate.worst_case_requests == 2
    assert candidate.cleanup_required is False


def test_authentication_candidate_costs_exactly_two_requests():
    state, context, builder = _candidate_fixture(authenticated=True)

    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.authentication
    )

    assert candidate.minimum_requests == 2
    assert candidate.worst_case_requests == 2


def test_tenant_candidate_requires_two_controlled_tenants():
    state, context, builder = _candidate_fixture(tenant=True)
    candidates = builder.build(state, compiler_context=context)
    assert any(
        item.graphql_candidate_kind is GraphQLCandidateKind.tenant_bound
        for item in candidates
    )

    uncontrolled = state.identities[1].model_copy(
        update={"controlled": False, "eligibility": IdentityEligibility.ineligible}
    )
    state = _state(state, identities=(state.identities[0], uncontrolled))
    assert not any(
        item.graphql_candidate_kind is GraphQLCandidateKind.tenant_bound
        for item in builder.build(state, compiler_context=context)
    )


def test_field_and_role_candidates_use_only_registered_field_selection():
    state, context, builder = _candidate_fixture()
    operation = next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    ).model_copy(
        update={
            "authentication_requirement": GraphQLAuthenticationRequirement.role_bound
        }
    )
    protected = next(
        item for item in state.graphql_fields if item.field_id == "field-query-resource"
    ).model_copy(
        update={
            "authorization_semantics": GraphQLAuthorizationSemantics(
                observations=(
                    GraphQLAuthorizationObservation.identity_dependent_field_visibility,
                    GraphQLAuthorizationObservation.role_dependent_operation_behavior,
                ),
                identity_references=("identity-a", "identity-b"),
                evidence_references=("evidence-graphql",),
                provenance_id="prov-graphql",
            )
        }
    )
    state = _state(
        state,
        hypotheses=(),
        graphql_operations=(operation,),
        graphql_fields=tuple(
            protected if item.field_id == protected.field_id else item
            for item in state.graphql_fields
        ),
    )
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(
        state, operation.operation_id
    )
    context = context.model_copy(update={"graphql_operation_templates": (template,)})
    kinds = {
        item.graphql_candidate_kind
        for item in builder.build(state, compiler_context=context)
    }

    assert GraphQLCandidateKind.field_authorization in kinds
    assert GraphQLCandidateKind.role_bound in kinds


def test_candidate_limits_prevent_identity_object_cartesian_growth():
    state, context, _builder = _candidate_fixture()
    identities = tuple(
        _identity(f"identity-extra-{index}", role=f"role-{index}", tenant="tenant-a")
        for index in range(12)
    )
    state = _state(state, identities=(*state.identities, *identities))
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    compiler = ExperimentCompiler(registry, context)
    builder = GraphQLExperimentCandidateBuilder(
        registry,
        budgets,
        compiler,
        limits=GraphQLCandidateLimits(
            max_candidates_per_hypothesis=1,
            max_candidates_per_operation=2,
            max_candidates_per_field=1,
            max_mutation_candidates=0,
            max_total_candidates=2,
        ),
    )

    assert len(builder.build(state, compiler_context=context)) <= 2


def test_public_packet_exposes_references_but_no_operation_document_or_values():
    state, context, builder = _candidate_fixture()
    candidates = builder.build(state, compiler_context=context)
    packet = PublicSafeCandidatePacketBuilder(builder.budget_manager).build(
        state, candidates
    )
    rendered = json.dumps(
        packet.public_payload(), sort_keys=True, separators=(",", ":")
    ).encode("ascii")

    assert len(rendered) < 8_192
    assert b"query ResourceQuery" not in rendered
    assert b"controlled-resource-ref" not in rendered
    assert b"object-resource-1" not in rendered


def test_mutation_candidate_fails_closed_without_policy_and_cleanup():
    state, context, builder = _candidate_fixture()
    operation = next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    ).model_copy(
        update={
            "operation_type": GraphQLOperationType.mutation,
            "state_change_class": GraphQLStateChangeClass.potential_state_change,
        }
    )
    root = next(item for item in state.graphql_types if item.type_id == "type-query")
    root = root.model_copy(update={"root_role": GraphQLRootRole.mutation})
    semantic_surface = state.graphql_surfaces[0].model_copy(
        update={"operation_capabilities": (GraphQLOperationType.mutation,)}
    )
    state = _state(
        state,
        graphql_operations=(operation,),
        graphql_types=tuple(
            root if item.type_id == root.type_id else item
            for item in state.graphql_types
        ),
        graphql_surfaces=(semantic_surface,),
    )
    generated = GraphQLHypothesisGenerator().generate_result(
        _state(state, hypotheses=())
    )
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(
        state,
        operation.operation_id,
        state_change_class=(GraphQLExperimentStateChangeClass.reversible_state_change),
    )
    context = context.model_copy(update={"graphql_operation_templates": (template,)})

    assert not builder.build(
        state,
        compiler_context=context,
        policy=GraphQLCandidatePolicy(allow_state_change_candidates=True),
    )


def test_reversible_mutation_candidate_carries_compiler_derived_cleanup():
    state, context, builder = _candidate_fixture()
    operation = next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    ).model_copy(
        update={
            "operation_type": GraphQLOperationType.mutation,
            "state_change_class": GraphQLStateChangeClass.potential_state_change,
        }
    )
    root = next(item for item in state.graphql_types if item.type_id == "type-query")
    root = root.model_copy(update={"root_role": GraphQLRootRole.mutation})
    semantic_surface = state.graphql_surfaces[0].model_copy(
        update={"operation_capabilities": (GraphQLOperationType.mutation,)}
    )
    state = _state(
        state,
        hypotheses=(),
        graphql_operations=(operation,),
        graphql_types=tuple(
            root if item.type_id == root.type_id else item
            for item in state.graphql_types
        ),
        graphql_surfaces=(semantic_surface,),
    )
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(
        state,
        operation.operation_id,
        state_change_class=(GraphQLExperimentStateChangeClass.reversible_state_change),
    )
    cleanup = CleanupDefinition(
        cleanup_reference="cleanup-graphql-resource",
        verification_predicate_reference="predicate-cleanup-verified",
        capability_names=("graphql_mutation_authorization",),
        minimum_requests=1,
        worst_case_requests=1,
    )
    context = context.model_copy(
        update={
            "graphql_operation_templates": (template,),
            "cleanup_definitions": (cleanup,),
        }
    )

    candidates = builder.build(
        state,
        compiler_context=context,
        policy=GraphQLCandidatePolicy(allow_state_change_candidates=True),
    )
    mutation = next(
        item
        for item in candidates
        if item.graphql_candidate_kind is GraphQLCandidateKind.mutation_authorization
    )

    assert mutation.cleanup_required
    assert mutation.cleanup_reference == cleanup.cleanup_reference
    assert mutation.graphql_state_change_class is (
        GraphQLExperimentStateChangeClass.reversible_state_change
    )


def test_input_validation_requires_a_registered_safe_mutation():
    state, context, builder = _candidate_fixture()
    argument = state.graphql_arguments[0].model_copy(
        update={
            "semantic_role": GraphQLSemanticRole.search,
            "semantic_role_evidence_references": ("evidence-graphql",),
        }
    )
    state = _state(state, hypotheses=(), graphql_arguments=(argument,))
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(state, "operation-resource")
    assert not any(
        item.graphql_candidate_kind is GraphQLCandidateKind.input_validation
        for item in builder.build(
            state,
            compiler_context=context.model_copy(
                update={"graphql_operation_templates": (template,)}
            ),
        )
    )
    binding = GraphQLVariableBinding(
        variable_id="variable-resource-ref",
        argument_id="argument-resource-ref",
        value_source=GraphQLVariableValueSource.registered_safe_constant,
        value_reference="safe-argument-alternative",
    )
    safe_mutation = RegisteredGraphQLSafeMutation(
        mutation_id="safe-mutation-search-boundary",
        operation_template_id=template.template_id,
        variable_id=binding.variable_id,
        argument_id=binding.argument_id,
        mutation_class=GraphQLSafeMutationClass.registered_alternative,
        binding=binding,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    context = context.model_copy(
        update={
            "controlled_value_references": (binding.value_reference,),
            "graphql_operation_templates": (template,),
            "graphql_safe_mutations": (safe_mutation,),
        }
    )

    candidates = builder.build(state, compiler_context=context)
    bounded = next(
        item
        for item in candidates
        if item.graphql_candidate_kind is GraphQLCandidateKind.input_validation
    )
    assert bounded.safe_mutation_id == safe_mutation.mutation_id
    assert bounded.worst_case_requests == 2


def test_workflow_mutation_requires_registered_controlled_states_and_cleanup():
    state = _mutation_state(workflow=True)
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(
        state,
        "operation-resource",
        state_change_class=(GraphQLExperimentStateChangeClass.reversible_state_change),
    )
    cleanup = CleanupDefinition(
        cleanup_reference="cleanup-workflow-resource",
        verification_predicate_reference="predicate-workflow-cleanup",
        capability_names=(
            "business_logic_state_enforcement",
            "graphql_mutation_authorization",
        ),
        minimum_requests=1,
        worst_case_requests=1,
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    context = ExperimentCompilerContext(
        current_time=TS,
        state_references=("state-before", "state-after"),
        cleanup_definitions=(cleanup,),
        graphql_operation_templates=(template,),
        policy_reference="policy-graphql-state-change",
    )
    builder = GraphQLExperimentCandidateBuilder(
        registry,
        budgets,
        ExperimentCompiler(registry, context),
        policy=GraphQLCandidatePolicy(allow_state_change_candidates=True),
    )

    candidates = builder.build(state, compiler_context=context)
    workflow = next(
        item
        for item in candidates
        if item.graphql_candidate_kind is GraphQLCandidateKind.workflow_mutation
    )
    assert workflow.workflow_id == "workflow-resource-update"
    assert workflow.cleanup_reference == cleanup.cleanup_reference

    missing_state = context.model_copy(update={"state_references": ()})
    assert not any(
        item.graphql_candidate_kind is GraphQLCandidateKind.workflow_mutation
        for item in builder.build(state, compiler_context=missing_state)
    )


def test_only_graphql_hypotheses_are_considered():
    state, context, builder = _candidate_fixture()
    object_hypothesis = next(
        item
        for item in state.hypotheses
        if item.security_property
        == GraphQLHypothesisProperty.object_authorization.value
    )
    state = _state(
        state,
        hypotheses=(object_hypothesis.model_copy(update={"security_property": None}),),
    )
    assert builder.build(state, compiler_context=context) == ()


def test_cross_surface_candidate_requires_typed_graph_evidence():
    state = _two_identity_state()
    access = Relationship(
        relationship_id="relationship-rest-access",
        source=EntityReference(entity_kind=EntityKind.identity, entity_id="identity-a"),
        predicate=ResearchPredicate.accesses,
        target=EntityReference(
            entity_kind=EntityKind.object, entity_id="object-resource-1"
        ),
        status=RelationshipStatus.observed,
        evidence_references=("evidence-graphql",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-graphql",
    )
    state = _state(state, relationships=(access,))
    same_object = _assertion(
        "assertion-same-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-resource-1"),
    )
    crosses = _assertion(
        "assertion-crosses-surface",
        EntityReference(entity_kind=EntityKind.surface, entity_id="surface-graphql"),
        ResearchPredicate.crosses_surface,
        EntityReference(entity_kind=EntityKind.surface, entity_id="surface-rest"),
    )
    generated = GraphQLHypothesisGenerator().generate_result(
        state, (same_object, crosses)
    )
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    template = build_registered_graphql_operation_template(state, "operation-resource")
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    context = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=(template,),
        policy_reference="policy-graphql",
    )
    builder = GraphQLExperimentCandidateBuilder(
        registry, budgets, ExperimentCompiler(registry, context)
    )

    candidates = builder.build(
        state, compiler_context=context, graph=(same_object, crosses)
    )
    assert any(
        item.graphql_candidate_kind is GraphQLCandidateKind.cross_surface
        for item in candidates
    )
    without_mapping = builder.build(state, compiler_context=context, graph=(crosses,))
    assert not any(
        item.graphql_candidate_kind is GraphQLCandidateKind.cross_surface
        for item in without_mapping
    )


def test_nested_resolver_candidate_requires_registered_bounded_path():
    state = _two_identity_state()
    child = state.objects[0].model_copy(
        update={
            "object_id": "object-child-1",
            "object_reference": "controlled-child-reference",
            "object_type": "RelatedResource",
            "owner_identity_id": "identity-b",
        }
    )
    nested = next(
        item for item in state.graphql_fields if item.field_id == "field-resource-owner"
    ).model_copy(
        update={
            "relationship_hints": (
                GraphQLRelationshipHint(
                    kind=GraphQLRelationshipKind.traverses_object,
                    graphql_type_id="type-user",
                    research_object_id=child.object_id,
                    evidence_references=("evidence-graphql",),
                ),
            )
        }
    )
    state = _state(
        state,
        objects=(*state.objects, child),
        graphql_fields=tuple(
            nested if item.field_id == nested.field_id else item
            for item in state.graphql_fields
        ),
    )
    mapping = _assertion(
        "assertion-parent-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-resource-1"),
    )
    generated = GraphQLHypothesisGenerator().generate_result(state, (mapping,))
    state = _state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    bounded = build_registered_graphql_operation_template(
        state,
        "operation-resource",
        selection_paths=(
            ("field-query-resource",),
            ("field-query-resource", "field-resource-owner"),
        ),
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    context = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=(bounded,),
        policy_reference="policy-graphql",
    )
    builder = GraphQLExperimentCandidateBuilder(
        registry, budgets, ExperimentCompiler(registry, context)
    )

    assert any(
        item.graphql_candidate_kind is GraphQLCandidateKind.nested_resolver
        for item in builder.build(state, compiler_context=context, graph=(mapping,))
    )
    shallow = build_registered_graphql_operation_template(state, "operation-resource")
    shallow_context = context.model_copy(
        update={"graphql_operation_templates": (shallow,)}
    )
    assert not any(
        item.graphql_candidate_kind is GraphQLCandidateKind.nested_resolver
        for item in builder.build(
            state, compiler_context=shallow_context, graph=(mapping,)
        )
    )


def test_equivalent_templates_deduplicate_and_restart_stays_stable(tmp_path: Path):
    state, context, builder = _candidate_fixture()
    duplicate = context.graphql_operation_templates[0].model_copy(
        update={"template_id": "graphql-template-equivalent"}
    )
    duplicate_context = context.model_copy(
        update={
            "graphql_operation_templates": (
                context.graphql_operation_templates[0],
                duplicate,
            )
        }
    )
    candidates = builder.build(state, compiler_context=duplicate_context)
    object_candidates = tuple(
        item
        for item in candidates
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    assert len(object_candidates) == 1

    database = tmp_path / "graphql-candidates.sqlite3"
    store = ResearchStore(database)
    store.create_research(state)
    store.close()
    restored = ResearchStore(database).load_research(state.research_id)
    restarted = builder.build(restored, compiler_context=duplicate_context)
    restored_object = next(
        item
        for item in restarted
        if item.graphql_candidate_kind is GraphQLCandidateKind.object_authorization
    )
    assert restored_object.candidate_id == object_candidates[0].candidate_id
    assert restored_object.fingerprint_seed == object_candidates[0].fingerprint_seed


def test_selection_materializes_only_chosen_graphql_candidate():
    state, context, builder = _candidate_fixture(authenticated=True)
    generated = builder.build(state, compiler_context=context)
    base = generated[0]
    candidates = tuple(
        base.model_copy(update={"candidate_id": f"candidate-c{index}"})
        for index in range(1, 4)
    )
    selected = candidates[1]
    decision = ResearchSelectionDecision(
        decision_id="decision-select-c2",
        research_id=state.research_id,
        state_revision=state.revision,
        action=ResearchSelectionAction.select_candidate,
        selected_candidate_id=selected.candidate_id,
        selected_hypothesis_id=selected.hypothesis_id,
        priority=80,
        confidence=ResearchConfidence.medium,
        expected_information_gain=InformationGainEstimate.high,
        reasoning_summary="Select the bounded second GraphQL candidate.",
        evidence_references=selected.evidence_references[:1],
        missing_evidence=(),
        pivot_dimension=None,
        stop_reason=None,
    )

    proposal = materialize_selected_graphql_candidate(decision, candidates, state)
    experiment = builder.compiler.compile(proposal, state, context)
    assert proposal.model_decision_id == decision.decision_id
    assert experiment.provenance.source_proposal_id == proposal.proposal_id
    assert (
        proposal.proposal_id
        != materialize_selected_graphql_candidate(
            decision.model_copy(
                update={"selected_candidate_id": candidates[0].candidate_id}
            ),
            candidates,
            state,
        ).proposal_id
    )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResearchSelectionDecision.model_validate(
            {**decision.model_dump(mode="python"), "variable_value": "invented"}
        )


def test_secret_in_source_evidence_never_reaches_candidate_or_compilation():
    state, context, builder = _candidate_fixture()
    unsafe_evidence = state.evidence[0].model_copy(
        update={"source_reference": "synthetic-token-value"}
    )
    unsafe_state = state.model_copy(update={"evidence": (unsafe_evidence,)})

    candidate = builder.build(unsafe_state, compiler_context=context)[0]
    proposal = __import__(
        "agent_core.research", fromlist=["materialize_candidate"]
    ).materialize_candidate(candidate, unsafe_state)
    experiment = builder.compiler.compile(proposal, unsafe_state, context)
    rendered = json.dumps(
        {
            "candidate": candidate.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
            "experiment": experiment.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert "synthetic-token-value" not in rendered
