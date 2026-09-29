from __future__ import annotations

from pathlib import Path

from agent_core.research import (
    DerivationType,
    EntityKind,
    EntityReference,
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLAuthorizationSemantics,
    GraphQLHypothesisGenerator,
    GraphQLHypothesisLimits,
    GraphQLHypothesisProperty,
    GraphQLOperationRecord,
    GraphQLOperationType,
    GraphQLRelationshipHint,
    GraphQLRelationshipKind,
    GraphQLRootRole,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    HypothesisResearchStatus,
    HttpMethod,
    Identity,
    IdentityEligibility,
    NewHypothesisProposal,
    Observation,
    ProvenanceProducerType,
    Relationship,
    RelationshipStatus,
    ResearchGraphRepository,
    ResearchConfidence,
    ResearchObject,
    ResearchPredicate,
    ResearchState,
    ResearchStore,
    Workflow,
    WorkflowStep,
    build_graphql_graph_assertions,
)
from agent_core.research.adapters import adapt_model_hypotheses
from agent_core.research.evaluation import HypothesisProposalSource
from agent_core.research.graph import GraphAssertion

from test_phase4_graphql_semantics import TS, TS_1, semantic_state


def _state(state: ResearchState, **updates: object) -> ResearchState:
    return ResearchState.model_validate({**state.model_dump(mode="python"), **updates})


def _identity(
    identity_id: str,
    *,
    role: str | None = None,
    tenant: str | None = None,
) -> Identity:
    return Identity(
        identity_id=identity_id,
        account_reference=f"account-{identity_id}",
        role_reference=role,
        tenant_reference=tenant,
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-graphql",
    )


def _two_identity_state(
    *,
    role_a: str | None = None,
    role_b: str | None = None,
    tenant_a: str | None = None,
    tenant_b: str | None = None,
) -> ResearchState:
    state = semantic_state()
    first = state.identities[0].model_copy(
        update={"role_reference": role_a, "tenant_reference": tenant_a}
    )
    return _state(
        state,
        identities=(
            first,
            _identity("identity-b", role=role_b, tenant=tenant_b),
        ),
    )


def _semantic_operation(state: ResearchState) -> GraphQLOperationRecord:
    return next(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    )


def _properties(state: ResearchState, *assertions: GraphAssertion) -> set[str]:
    return {
        item.security_property or ""
        for item in GraphQLHypothesisGenerator().generate(state, assertions)
    }


def _assertion(
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


def test_controlled_object_authorization_hypothesis_is_bounded_and_non_executing():
    state = _two_identity_state()

    generated = GraphQLHypothesisGenerator().generate(state)

    hypothesis = next(
        item
        for item in generated
        if item.security_property
        == GraphQLHypothesisProperty.object_authorization.value
    )
    assert hypothesis.category == "graphql_object_authorization"
    assert hypothesis.status is HypothesisResearchStatus.proposed
    assert hypothesis.requires_state_change is False
    assert "non-owner controlled comparison response" in hypothesis.missing_evidence
    assert {
        "controlled-identities",
        "test-owned-object",
        "ownership-evidence",
        "registered-graphql-operation",
    }.issubset(hypothesis.required_preconditions)
    assert {item.entity_kind for item in hypothesis.entity_references} >= {
        EntityKind.graphql_operation,
        EntityKind.graphql_field,
        EntityKind.graphql_argument,
        EntityKind.object,
        EntityKind.identity,
    }


def test_authenticated_observation_generates_authentication_enforcement_hypothesis():
    state = semantic_state()
    operation = _semantic_operation(state).model_copy(
        update={
            "authentication_requirement": (
                GraphQLAuthenticationRequirement.authenticated_observed
            )
        }
    )
    state = _state(state, graphql_operations=(operation,))

    hypotheses = GraphQLHypothesisGenerator().generate(state)

    authentication = next(
        item
        for item in hypotheses
        if item.security_property
        == GraphQLHypothesisProperty.authentication_enforcement.value
    )
    assert authentication.category == "authentication_enforcement"
    assert authentication.missing_evidence == ("anonymous comparison response",)


def test_exact_authentication_boundary_error_suppresses_redundant_hypothesis():
    state = semantic_state()
    operation = _semantic_operation(state).model_copy(
        update={
            "authentication_requirement": (
                GraphQLAuthenticationRequirement.authentication_required
            )
        }
    )
    boundary = Observation(
        observation_id="observation-auth-boundary",
        observation_type="graphql_authentication_boundary",
        summary="A deterministic authentication boundary was observed.",
        target_id="target-1",
        surface_id="surface-graphql",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    state = _state(state, graphql_operations=(operation,), observations=(boundary,))

    assert (
        GraphQLHypothesisProperty.authentication_enforcement.value
        not in _properties(state)
    )


def test_field_role_and_operation_authorization_remain_unconfirmed():
    state = _two_identity_state(role_a="reader", role_b="operator")
    operation = _semantic_operation(state).model_copy(
        update={
            "authentication_requirement": GraphQLAuthenticationRequirement.role_bound
        }
    )
    root = next(
        item for item in state.graphql_fields if item.field_id == "field-query-resource"
    )
    protected = root.model_copy(
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
        graphql_operations=(operation,),
        graphql_fields=tuple(
            protected if item.field_id == protected.field_id else item
            for item in state.graphql_fields
        ),
    )

    properties = _properties(state)

    assert GraphQLHypothesisProperty.field_level_authorization.value in properties
    assert GraphQLHypothesisProperty.operation_level_authorization.value in properties
    assert GraphQLHypothesisProperty.role_bound_access.value in properties
    assert not state.findings


def test_tenant_hypothesis_requires_two_controlled_tenants_and_owned_object():
    state = _two_identity_state(tenant_a="tenant-a", tenant_b="tenant-b")
    operation = _semantic_operation(state).model_copy(
        update={
            "authentication_requirement": (
                GraphQLAuthenticationRequirement.tenant_bound
            )
        }
    )
    owned = state.objects[0].model_copy(update={"tenant_reference": "tenant-a"})
    state = _state(state, graphql_operations=(operation,), objects=(owned,))

    hypotheses = GraphQLHypothesisGenerator().generate(state)

    tenant = next(
        item
        for item in hypotheses
        if item.security_property == GraphQLHypothesisProperty.tenant_bound_access.value
    )
    assert tenant.category == "tenant_isolation"
    assert tenant.missing_evidence == ("tenant-B comparison",)
    assert "controlled-tenant-metadata" in tenant.required_preconditions


def _mutation_state(*, workflow: bool = False) -> ResearchState:
    state = _two_identity_state()
    semantic_surface = state.graphql_surfaces[0].model_copy(
        update={"operation_capabilities": (GraphQLOperationType.mutation,)}
    )
    root_type = next(
        item for item in state.graphql_types if item.type_id == "type-query"
    ).model_copy(update={"root_role": GraphQLRootRole.mutation})
    operation = _semantic_operation(state).model_copy(
        update={
            "operation_type": GraphQLOperationType.mutation,
            "state_change_class": GraphQLStateChangeClass.potential_state_change,
            "workflow_id": "workflow-resource-update" if workflow else None,
        }
    )
    workflows: tuple[Workflow, ...] = ()
    if workflow:
        workflows = (
            Workflow(
                workflow_id="workflow-resource-update",
                surface_id="surface-graphql",
                name="Controlled resource update workflow.",
                steps=(
                    WorkflowStep(
                        step_id="workflow-step-update",
                        sequence=1,
                        endpoint_id="endpoint-graphql",
                        method=HttpMethod.post,
                        state_before_reference="state-before",
                        state_after_reference="state-after",
                        state_changing=True,
                    ),
                ),
                evidence_references=("evidence-graphql",),
                provenance_id="prov-graphql",
            ),
        )
    return _state(
        state,
        graphql_surfaces=(semantic_surface,),
        graphql_types=tuple(
            root_type if item.type_id == root_type.type_id else item
            for item in state.graphql_types
        ),
        graphql_operations=(operation,),
        workflows=workflows,
    )


def test_mutation_authorization_is_inert_and_carries_state_change_preconditions():
    state = _mutation_state()

    hypotheses = GraphQLHypothesisGenerator().generate(state)

    mutation = next(
        item
        for item in hypotheses
        if item.security_property
        == GraphQLHypothesisProperty.mutation_authorization.value
    )
    assert mutation.category == "graphql_mutation_authorization"
    assert mutation.requires_state_change
    assert {
        "state-change-authorization",
        "cleanup-availability",
        "request-budget",
        "test-owned-object",
    }.issubset(mutation.required_preconditions)
    assert "mutation authorization result" in mutation.missing_evidence
    assert "cleanup capability" in mutation.missing_evidence


def test_workflow_bound_mutation_requires_evidenced_transition():
    state = _mutation_state(workflow=True)

    properties = _properties(state)

    assert GraphQLHypothesisProperty.workflow_bound_mutation.value in properties


def test_cross_surface_hypothesis_requires_mapping_and_known_authorization_behavior():
    state = semantic_state()
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
    explicit = _assertion(
        "assertion-explicit-same-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-resource-1"),
    )

    hypotheses = GraphQLHypothesisGenerator().generate(state, (explicit,))

    cross = next(
        item
        for item in hypotheses
        if item.security_property
        == GraphQLHypothesisProperty.cross_surface_authorization.value
    )
    assert cross.category == "graphql_authorization"
    assert cross.basis_relationship_ids == ("relationship-rest-access",)
    assert "explicit-cross-surface-object-mapping" in cross.required_preconditions

    assert (
        GraphQLHypothesisProperty.cross_surface_authorization.value
        not in _properties(state)
    )


def test_nested_resolver_hypothesis_requires_controlled_boundary_evidence():
    state = _two_identity_state()
    child = ResearchObject(
        object_id="object-child-1",
        target_id="target-1",
        surface_id="surface-rest",
        object_type="RelatedResource",
        object_reference="controlled-child-reference",
        owner_identity_id="identity-b",
        test_owned=True,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    nested = next(
        item for item in state.graphql_fields if item.field_id == "field-resource-owner"
    )
    nested = nested.model_copy(
        update={
            "relationship_hints": (
                GraphQLRelationshipHint(
                    kind=GraphQLRelationshipKind.traverses_object,
                    graphql_type_id="type-user",
                    research_object_id="object-child-1",
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
    parent_mapping = _assertion(
        "assertion-parent-object",
        EntityReference(entity_kind=EntityKind.graphql_type, entity_id="type-resource"),
        ResearchPredicate.references_same_object,
        EntityReference(entity_kind=EntityKind.object, entity_id="object-resource-1"),
    )

    properties = _properties(state, parent_mapping)

    assert (
        GraphQLHypothesisProperty.relationship_traversal_authorization.value
        in properties
    )


def test_bounded_argument_validation_uses_semantic_role_not_every_scalar():
    state = semantic_state()
    argument = state.graphql_arguments[0].model_copy(
        update={
            "semantic_role": GraphQLSemanticRole.search,
            "semantic_role_evidence_references": ("evidence-graphql",),
        }
    )
    state = _state(state, graphql_arguments=(argument,))

    properties = _properties(state)

    assert GraphQLHypothesisProperty.argument_input_validation.value in properties


def test_secure_exact_hypothesis_is_not_recreated():
    state = _two_identity_state()
    first = GraphQLHypothesisGenerator().generate_result(state)
    object_hypothesis = next(
        item
        for item in first.hypotheses
        if item.security_property
        == GraphQLHypothesisProperty.object_authorization.value
    ).model_copy(
        update={
            "status": HypothesisResearchStatus.refuted,
            "refuting_evidence": ("evidence-graphql",),
        }
    )
    state = _state(
        state,
        hypotheses=(object_hypothesis,),
        provenance=(*state.provenance, *first.provenance),
    )

    regenerated = GraphQLHypothesisGenerator().generate(state)

    assert all(
        item.semantic_fingerprint != object_hypothesis.semantic_fingerprint
        for item in regenerated
    )


def test_introspection_and_mutation_root_alone_generate_no_hypotheses():
    state = _two_identity_state()
    no_operations = _state(
        state,
        graphql_operations=(),
        graphql_variables=(),
    )
    assert GraphQLHypothesisGenerator().generate(no_operations) == ()

    surface = no_operations.graphql_surfaces[0].model_copy(
        update={"operation_capabilities": (GraphQLOperationType.mutation,)}
    )
    root = next(
        item for item in no_operations.graphql_types if item.type_id == "type-query"
    ).model_copy(update={"root_role": GraphQLRootRole.mutation})
    mutation_root_only = _state(
        no_operations,
        graphql_surfaces=(surface,),
        graphql_types=tuple(
            root if item.type_id == root.type_id else item
            for item in no_operations.graphql_types
        ),
    )
    assert GraphQLHypothesisGenerator().generate(mutation_root_only) == ()


def test_semantic_deduplication_and_generation_limits_are_deterministic():
    state = semantic_state()
    state = _state(
        state,
        identities=(
            state.identities[0],
            *(_identity(f"identity-{index}") for index in range(2, 9)),
        ),
    )
    generator = GraphQLHypothesisGenerator(
        GraphQLHypothesisLimits(
            max_hypotheses_per_surface=2,
            max_hypotheses_per_operation=2,
            max_hypotheses_per_object_relationship=2,
            max_cross_surface_hypotheses=0,
            max_total_new_hypotheses=2,
        )
    )

    first = generator.generate_result(state)
    second = generator.generate_result(state)

    assert first.hypotheses == second.hypotheses
    assert len(first.hypotheses) == 2
    assert first.truncated
    assert first.eligible_count > first.selected_count
    assert len({item.semantic_fingerprint for item in first.hypotheses}) == 2


def test_store_restart_is_atomic_and_idempotent(tmp_path: Path):
    database = tmp_path / "graphql-hypotheses.sqlite3"
    state = _two_identity_state()
    store = ResearchStore(database)
    store.create_research(
        state,
        graph_assertions=build_graphql_graph_assertions(state, asserted_at=TS_1),
    )
    generator = GraphQLHypothesisGenerator()

    persisted = generator.persist(
        store,
        state,
        ResearchGraphRepository(store, state.research_id),
        occurred_at=TS_1,
    )
    ids = tuple(item.hypothesis_id for item in persisted.hypotheses)
    fingerprints = tuple(item.semantic_fingerprint for item in persisted.hypotheses)
    store.close()

    reopened = ResearchStore(database)
    restarted = reopened.load_research(state.research_id)
    repeated = generator.persist(
        reopened,
        restarted,
        ResearchGraphRepository(reopened, state.research_id),
        occurred_at=TS_1,
    )

    assert repeated.revision == restarted.revision
    assert tuple(item.hypothesis_id for item in repeated.hypotheses) == ids
    assert tuple(item.semantic_fingerprint for item in repeated.hypotheses) == (
        fingerprints
    )
    assert reopened.verify_integrity(state.research_id).valid


def test_hypothesis_contains_only_safe_references_not_object_or_response_values():
    state = _two_identity_state()

    rendered = GraphQLHypothesisGenerator().generate_result(state).model_dump_json()

    assert "controlled-resource-ref" not in rendered
    assert "fixture-resource-reference" not in rendered
    assert "response_body" not in rendered
    assert "authorization" in rendered


def test_generator_provenance_is_deterministic_and_uses_no_model():
    state = _two_identity_state()

    result = GraphQLHypothesisGenerator().generate_result(state, occurred_at=TS)

    assert result.provenance[0].producer_type is ProvenanceProducerType.deterministic
    assert result.provenance[0].producer_name == "graphql-hypothesis-generator"
    assert result.graph_assertions
    assert all(
        item.relation is ResearchPredicate.derives_from
        and item.source.entity_kind is EntityKind.hypothesis
        for item in result.graph_assertions
    )
    assert all(
        item.status is HypothesisResearchStatus.proposed for item in result.hypotheses
    )


def test_model_cannot_bypass_deterministic_graphql_hypothesis_validation():
    state = semantic_state()
    proposal = NewHypothesisProposal(
        proposal_id="proposal-unvalidated-graphql",
        category="graphql_object_authorization",
        title="Unvalidated GraphQL proposal",
        claim="A model-authored GraphQL claim.",
        falsification_criterion="A future comparison refutes it.",
        target_id="target-1",
        surface_id="surface-graphql",
        confirmation_policy_reference="model-policy-ignored",
        evidence_references=("evidence-graphql",),
        priority=50,
        confidence=ResearchConfidence.low,
        source=HypothesisProposalSource.model,
    )

    records, provenance = adapt_model_hypotheses(
        (proposal,),
        state,
        allowed_categories=("graphql_object_authorization",),
        confirmation_policy_reference="deterministic-policy",
        max_hypotheses=1,
        occurred_at=TS,
    )

    assert records == ()
    assert provenance == ()
