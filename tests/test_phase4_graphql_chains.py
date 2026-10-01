from __future__ import annotations

from agent_core.agent_models import RiskLevel
from agent_core.research import (
    AttackChainCandidateBuilder,
    CandidateBaselineKind,
    CandidateMutationKind,
    ChainExperimentPlanner,
    CleanupStatus,
    DerivationType,
    DifferentialSelector,
    EntityKind,
    EntityReference,
    ExperimentCandidate,
    FindingRecord,
    FindingStatus,
    GraphQLAuthenticationRequirement,
    GraphQLCandidateKind,
    GraphQLChainAdapter,
    GraphQLOperationRecord,
    GraphQLOperationType,
    GraphQLObjectReferenceSemantics,
    GraphQLStateChangeClass,
    GraphQLTypeKind,
    GraphQLTypeRecord,
    GraphQLFieldRecord,
    GraphQLReturnShape,
    GraphQLRootRole,
    GraphQLTypeReference,
    HypothesisRecord,
    HypothesisResearchStatus,
    PublicSafeChainPacketBuilder,
    Relationship,
    RelationshipStatus,
    RequestIdentityRequirement,
    ResearchConfidence,
    ResearchPredicate,
    ResearchRequestTemplate,
    ResearchState,
    Surface,
    SurfaceType,
    TokenKind,
    TokenLifecycle,
    TokenRef,
    UploadArtifact,
    UploadLifecycle,
    Workflow,
    WorkflowStep,
    graphql_chain_semantics_current,
    graphql_selection_fingerprint,
    materialize_attack_chain,
    materialize_chain_hypothesis,
    revalidate_graphql_chain,
)

from test_phase4_graphql_candidates import _candidate_fixture
from test_phase4_graphql_semantics import _auth

TS = "2026-09-28T12:00:00+00:00"


def _state(state: ResearchState, **updates: object) -> ResearchState:
    return ResearchState.model_validate({**state.model_dump(mode="python"), **updates})


def _graphql_fixture(*, protected: bool = False):
    state, context, builder = _candidate_fixture()
    experiments = builder.build(state, compiler_context=context)
    if protected:
        operation = state.graphql_operations[0].model_copy(
            update={
                "authentication_requirement": (
                    GraphQLAuthenticationRequirement.role_bound
                )
            }
        )
        state = _state(state, graphql_operations=(operation,))
    return state, experiments


def _rest_destination(state: ResearchState):
    endpoint = next(
        item for item in state.endpoints if item.endpoint_id == "endpoint-rest"
    )
    template = ResearchRequestTemplate(
        template_id="template-rest-resource",
        target_id="target-1",
        surface_id="surface-rest",
        endpoint_id="endpoint-rest",
        method=endpoint.method,
        route_reference=endpoint.route_template,
        parameter_ids=("parameter-resource-ref",),
        identity_requirement=RequestIdentityRequirement(
            required=True, mechanisms=("authorization_header",)
        ),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-rest-object-authorization",
        category="object-authorization",
        title="REST object authorization boundary.",
        claim="The REST operation may mishandle the controlled object.",
        target_id="target-1",
        surface_id="surface-rest",
        status=HypothesisResearchStatus.proposed,
        priority=80,
        confidence=ResearchConfidence.medium,
        confirmation_policy_reference="policy-rest",
        supporting_evidence=("evidence-graphql",),
        security_property="object-authorization",
        entity_references=(
            EntityReference(
                entity_kind=EntityKind.object, entity_id="object-resource-1"
            ),
            EntityReference(entity_kind=EntityKind.endpoint, entity_id="endpoint-rest"),
        ),
        provenance_id="prov-graphql",
    )
    experiment = ExperimentCandidate(
        candidate_id="candidate-rest-object-authorization",
        research_id=state.research_id,
        state_revision=state.revision,
        hypothesis_id=hypothesis.hypothesis_id,
        capability="object-authorization",
        primitive_kind="authentication_differential",
        target_id="target-1",
        surface_id="surface-rest",
        endpoint_id="endpoint-rest",
        request_template_id=template.template_id,
        primary_identity_id="identity-a",
        baseline_kind=CandidateBaselineKind.registered_request,
        mutation_kind=CandidateMutationKind.authentication_differential,
        expected_evidence_class=DifferentialSelector.status_class,
        minimum_requests=2,
        worst_case_requests=2,
        risk_class=RiskLevel.low,
        information_predicates=("predicate:graphql-rest-same-object",),
        evidence_references=("evidence-graphql",),
        provenance_references=("prov-graphql",),
        fingerprint_seed="sha256:" + "8" * 64,
    )
    return (
        _state(
            state,
            request_templates=(*state.request_templates, template),
            hypotheses=(*state.hypotheses, hypothesis),
        ),
        experiment,
    )


def _relationship(source: EntityReference, target: EntityReference, name: str):
    return Relationship(
        relationship_id=name,
        source=source,
        predicate=ResearchPredicate.produces_context_for,
        target=target,
        status=RelationshipStatus.confirmed,
        evidence_references=("evidence-graphql",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-graphql",
    )


def test_rest_to_graphql_uses_registered_graphql_experiment():
    state, experiments = _graphql_fixture()
    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=experiments
    )

    candidate = next(item for item in candidates if item.category == "rest-to-graphql")
    assert [item.entity_kind for item in candidate.ordered_references] == [
        EntityKind.object,
        EntityKind.graphql_operation,
        EntityKind.hypothesis,
    ]
    assert candidate.semantic_bindings
    assert candidate.required_unresolved_links[0].allowed_experiment_capabilities == (
        "graphql_operation",
    )


def test_graphql_to_rest_requires_exact_controlled_object_binding():
    state, graphql_experiments = _graphql_fixture()
    state, rest_experiment = _rest_destination(state)

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(*graphql_experiments, rest_experiment)
    )

    candidate = next(item for item in candidates if item.category == "graphql-to-rest")
    assert candidate.object_ids == ("object-resource-1",)
    assert [item.entity_kind for item in candidate.ordered_references] == [
        EntityKind.graphql_operation,
        EntityKind.object,
        EntityKind.hypothesis,
    ]
    assert candidate.available_experiment_candidates == (
        "candidate-rest-object-authorization",
    )


def test_graphql_candidate_finding_remains_an_explicit_unresolved_component():
    state, graphql_experiments = _graphql_fixture()
    state, rest_experiment = _rest_destination(state)
    operation = state.graphql_operations[0]
    source_finding = FindingRecord(
        finding_id="finding-graphql-candidate-component",
        status=FindingStatus.candidate,
        title="Candidate GraphQL object authorization finding.",
        category="graphql-object-authorization",
        source_hypothesis_id=graphql_experiments[0].hypothesis_id,
        candidate_experiment_id="experiment-graphql-component",
        confirmation_policy_reference="policy-graphql",
        evidence_references=("evidence-graphql",),
        cleanup_status=CleanupStatus.not_required,
        provenance_id="prov-graphql",
        research_id=state.research_id,
        target_id="target-1",
        surface_id="surface-graphql",
        endpoint_id="endpoint-graphql",
        graphql_operation_id=operation.operation_id,
        graphql_operation_template_id=(
            graphql_experiments[0].graphql_operation_template_id
        ),
        graphql_candidate_kind=GraphQLCandidateKind.object_authorization,
        graphql_selection_fingerprint=operation.selection_fingerprint,
        graphql_semantic_fingerprint="sha256:" + "7" * 64,
        graphql_field_ids=operation.root_field_ids,
        controlled_object_ids=("object-resource-1",),
    )
    state = _state(state, findings=(source_finding,))

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(*graphql_experiments, rest_experiment)
    )
    candidate = next(
        item
        for item in candidates
        if item.category == "graphql-to-rest"
        and source_finding.finding_id in item.finding_ids
    )

    assert len(candidate.required_unresolved_links) == 2
    assert {item.experiment_id for item in candidate.required_unresolved_links} == {
        None
    }


def test_name_only_graphql_and_rest_resource_produces_no_chain():
    state, graphql_experiments = _graphql_fixture()
    state, rest_experiment = _rest_destination(state)
    argument = state.graphql_arguments[0].model_copy(
        update={
            "object_reference_semantics": GraphQLObjectReferenceSemantics(),
            "parameter_id": None,
        }
    )
    fields = tuple(
        item.model_copy(update={"relationship_hints": ()})
        if item.field_id == "field-query-resource"
        else item
        for item in state.graphql_fields
    )
    state = _state(state, graphql_arguments=(argument,), graphql_fields=fields)

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(*graphql_experiments, rest_experiment)
    )

    assert not any(
        item.category in {"graphql-to-rest", "rest-to-graphql"} for item in candidates
    )


def test_graphql_to_graphql_requires_evidenced_operation_dependency():
    state, experiments = _graphql_fixture()
    first = state.graphql_operations[0]
    second_variable = state.graphql_variables[0].model_copy(
        update={
            "variable_id": "variable-resource-ref-b",
            "operation_id": "operation-resource-b",
        }
    )
    second = first.model_copy(
        update={
            "operation_id": "operation-resource-b",
            "operation_name": "ResourceQueryB",
            "variable_ids": (second_variable.variable_id,),
            "selection_fingerprint": "sha256:" + "9" * 64,
            "authentication_requirement": (GraphQLAuthenticationRequirement.role_bound),
        }
    )
    second_hypothesis = state.hypotheses[0].model_copy(
        update={
            "hypothesis_id": "hypothesis-operation-b-authorization",
            "entity_references": tuple(
                EntityReference(
                    entity_kind=reference.entity_kind,
                    entity_id=(
                        second.operation_id
                        if reference.entity_kind is EntityKind.graphql_operation
                        else (
                            second_variable.variable_id
                            if reference.entity_kind is EntityKind.graphql_variable
                            else reference.entity_id
                        )
                    ),
                )
                for reference in state.hypotheses[0].entity_references
            ),
            "semantic_fingerprint": None,
        }
    )
    relation = _relationship(
        EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=first.operation_id,
        ),
        EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=second.operation_id,
        ),
        "relationship-operation-a-context-for-b",
    )
    second_experiment = experiments[0].model_copy(
        update={
            "candidate_id": "candidate-operation-b",
            "hypothesis_id": second_hypothesis.hypothesis_id,
            "operation_id": second.operation_id,
            "selection_fingerprint": second.selection_fingerprint,
        }
    )
    state = _state(
        state,
        graphql_operations=(*state.graphql_operations, second),
        graphql_variables=(*state.graphql_variables, second_variable),
        hypotheses=(*state.hypotheses, second_hypothesis),
        relationships=(relation,),
    )

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(*experiments, second_experiment)
    )
    chain = next(item for item in candidates if item.category == "graphql-to-graphql")
    assert [item.entity_id for item in chain.ordered_references[:2]] == [
        first.operation_id,
        second.operation_id,
    ]

    unrelated = _state(state, relationships=())
    unrelated_candidates = AttackChainCandidateBuilder().build(
        unrelated, experiment_candidates=(*experiments, second_experiment)
    )
    assert not any(
        item.category == "graphql-to-graphql" for item in unrelated_candidates
    )


def test_authentication_and_jwt_require_explicit_enabling_relationship():
    state, experiments = _graphql_fixture(protected=True)
    operation = state.graphql_operations[0]
    operation_ref = EntityReference(
        entity_kind=EntityKind.graphql_operation, entity_id=operation.operation_id
    )
    identity_relation = _relationship(
        EntityReference(entity_kind=EntityKind.identity, entity_id="identity-a"),
        operation_ref,
        "relationship-auth-enables-graphql",
    )
    token = TokenRef(
        token_ref_id="token-claim-reference",
        identity_id="identity-a",
        vault_reference="credential_reference_123456",
        token_kind=TokenKind.access,
        lifecycle=TokenLifecycle.active,
        issuer_reference="issuer-reference",
        provenance_id="prov-graphql",
    )
    token_relation = _relationship(
        EntityReference(entity_kind=EntityKind.token, entity_id=token.token_ref_id),
        operation_ref,
        "relationship-claim-enables-graphql",
    )
    state = _state(
        state,
        token_refs=(token,),
        relationships=(identity_relation, token_relation),
    )

    categories = {
        item.category
        for item in AttackChainCandidateBuilder().build(
            state, experiment_candidates=experiments
        )
    }
    assert "authentication-to-graphql" in categories
    assert "token-to-graphql" in categories

    no_relation = _state(state, relationships=())
    categories = {
        item.category
        for item in AttackChainCandidateBuilder().build(
            no_relation, experiment_candidates=experiments
        )
    }
    assert "authentication-to-graphql" not in categories
    assert "token-to-graphql" not in categories


def test_workflow_to_graphql_is_evidence_backed():
    state, experiments = _graphql_fixture(protected=True)
    workflow_surface = Surface(
        surface_id="surface-workflow",
        target_id="target-1",
        surface_type=SurfaceType.workflow,
        label="Controlled workflow surface.",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    workflow = Workflow(
        workflow_id="workflow-controlled",
        surface_id=workflow_surface.surface_id,
        name="Controlled workflow",
        steps=(
            WorkflowStep(
                step_id="workflow-step-1",
                sequence=1,
                state_before_reference="workflow-before",
                state_after_reference="workflow-ready",
                state_changing=False,
            ),
        ),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    relation = _relationship(
        EntityReference(
            entity_kind=EntityKind.workflow, entity_id=workflow.workflow_id
        ),
        EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=state.graphql_operations[0].operation_id,
        ),
        "relationship-workflow-enables-graphql",
    )
    state = _state(
        state,
        surfaces=(*state.surfaces, workflow_surface),
        workflows=(workflow,),
        relationships=(relation,),
    )

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=experiments
    )
    assert any(item.category == "workflow-to-graphql" for item in candidates)


def test_graphql_to_workflow_mutation_uses_existing_chain_representation():
    state, experiments = _graphql_fixture()
    workflow_surface = Surface(
        surface_id="surface-workflow",
        target_id="target-1",
        surface_type=SurfaceType.workflow,
        label="Controlled workflow surface.",
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    workflow = Workflow(
        workflow_id="workflow-mutation",
        surface_id=workflow_surface.surface_id,
        name="Mutation workflow",
        steps=(
            WorkflowStep(
                step_id="workflow-mutation-step",
                sequence=1,
                state_before_reference="draft",
                state_after_reference="submitted",
                state_changing=True,
            ),
        ),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    mutation_field = GraphQLFieldRecord(
        field_id="field-mutation-submit",
        type_id="type-mutation",
        name="submitResource",
        return_type=GraphQLTypeReference.from_syntax("Resource"),
        return_shape=GraphQLReturnShape.object,
        nullable=True,
        list_depth=0,
        authorization_semantics=_auth(),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    mutation_type = GraphQLTypeRecord(
        type_id="type-mutation",
        graphql_surface_id="graphql-surface-1",
        name="Mutation",
        kind=GraphQLTypeKind.object,
        root_role=GraphQLRootRole.mutation,
        field_ids=(mutation_field.field_id,),
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    mutation = GraphQLOperationRecord(
        operation_id="operation-submit-resource",
        graphql_surface_id="graphql-surface-1",
        operation_type=GraphQLOperationType.mutation,
        operation_name="SubmitResource",
        root_field_ids=(mutation_field.field_id,),
        selection_fingerprint=graphql_selection_fingerprint(
            "mutation SubmitResource { submitResource { resourceRef } }"
        ),
        authentication_requirement=GraphQLAuthenticationRequirement.role_bound,
        state_change_class=GraphQLStateChangeClass.state_change_observed,
        workflow_id=workflow.workflow_id,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    hypothesis = state.hypotheses[0].model_copy(
        update={
            "hypothesis_id": "hypothesis-mutation-workflow",
            "security_property": "workflow-bound-mutation",
            "entity_references": (
                EntityReference(
                    entity_kind=EntityKind.graphql_operation,
                    entity_id=mutation.operation_id,
                ),
                EntityReference(
                    entity_kind=EntityKind.graphql_field,
                    entity_id=mutation_field.field_id,
                ),
                EntityReference(
                    entity_kind=EntityKind.workflow,
                    entity_id=workflow.workflow_id,
                ),
            ),
            "semantic_fingerprint": None,
        }
    )
    experiment = experiments[0].model_copy(
        update={
            "candidate_id": "candidate-mutation-workflow",
            "hypothesis_id": hypothesis.hypothesis_id,
            "operation_id": mutation.operation_id,
            "selection_fingerprint": mutation.selection_fingerprint,
        }
    )
    semantic_surface = state.graphql_surfaces[0].model_copy(
        update={
            "operation_capabilities": (
                GraphQLOperationType.query,
                GraphQLOperationType.mutation,
            )
        }
    )
    state = _state(
        state,
        surfaces=(*state.surfaces, workflow_surface),
        workflows=(workflow,),
        graphql_surfaces=(semantic_surface,),
        graphql_types=(*state.graphql_types, mutation_type),
        graphql_fields=(*state.graphql_fields, mutation_field),
        graphql_operations=(*state.graphql_operations, mutation),
        hypotheses=(*state.hypotheses, hypothesis),
    )

    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(*experiments, experiment)
    )
    assert any(item.category == "graphql-to-workflow" for item in candidates)


def test_graphql_upload_and_server_side_are_representation_only():
    state, experiments = _graphql_fixture()
    upload = UploadArtifact(
        upload_id="upload-controlled-reference",
        surface_id="surface-rest",
        endpoint_id="endpoint-rest",
        owner_identity_id="identity-a",
        fixture_reference="registered-upload-fixture",
        media_type="application-octet-stream",
        lifecycle=UploadLifecycle.fixture_ready,
        evidence_references=("evidence-graphql",),
        provenance_id="prov-graphql",
    )
    operation_ref = EntityReference(
        entity_kind=EntityKind.graphql_operation,
        entity_id=state.graphql_operations[0].operation_id,
    )
    upload_relation = _relationship(
        operation_ref,
        EntityReference(entity_kind=EntityKind.upload, entity_id=upload.upload_id),
        "relationship-graphql-references-upload",
    )
    server_hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-server-side-capability",
        category="server-side-request-capability",
        title="Server-side capability boundary.",
        claim="The registered operation may reach a server-side capability.",
        target_id="target-1",
        surface_id="surface-rest",
        status=HypothesisResearchStatus.proposed,
        priority=60,
        confidence=ResearchConfidence.low,
        confirmation_policy_reference="policy-server-side",
        supporting_evidence=("evidence-graphql",),
        security_property="server-side-request-boundary",
        entity_references=(
            EntityReference(entity_kind=EntityKind.endpoint, entity_id="endpoint-rest"),
        ),
        provenance_id="prov-graphql",
    )
    server_relation = _relationship(
        operation_ref,
        EntityReference(
            entity_kind=EntityKind.hypothesis,
            entity_id=server_hypothesis.hypothesis_id,
        ),
        "relationship-graphql-controls-server-capability",
    )
    state, rest_experiment = _rest_destination(state)
    server_experiment = rest_experiment.model_copy(
        update={
            "candidate_id": "candidate-server-side-representation",
            "hypothesis_id": server_hypothesis.hypothesis_id,
        }
    )
    state = _state(
        state,
        uploads=(upload,),
        hypotheses=(*state.hypotheses, server_hypothesis),
        relationships=(upload_relation, server_relation),
    )

    categories = {
        item.category
        for item in AttackChainCandidateBuilder().build(
            state,
            experiment_candidates=(
                *experiments,
                rest_experiment,
                server_experiment,
            ),
        )
    }
    assert "graphql-to-upload" in categories
    assert "graphql-to-server-side" in categories


def test_graphql_semantic_bound_and_public_packet_remain_compact():
    state, experiments = _graphql_fixture()
    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=experiments
    )
    packet = PublicSafeChainPacketBuilder().build(state, candidates)

    assert packet.serialized_size < 8_192
    assert packet.candidates[0].graphql_reference_ids
    assert GraphQLChainAdapter().propose(state, (), experiments)


def test_stale_graphql_selection_blocks_planning_and_requires_manual_review():
    state, experiments = _graphql_fixture()
    candidate = next(
        item
        for item in AttackChainCandidateBuilder().build(
            state, experiment_candidates=experiments
        )
        if item.category == "rest-to-graphql"
    )
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate,
        hypothesis,
        provenance_id="prov-graphql",
        created_at=TS,
    )
    changed_operation = state.graphql_operations[0].model_copy(
        update={"selection_fingerprint": "sha256:" + "1" * 64}
    )
    stale_state = _state(state, graphql_operations=(changed_operation,))

    assert not graphql_chain_semantics_current(stale_state, candidate.semantic_bindings)
    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis, candidate, stale_state, experiments
        )
        is None
    )
    assert revalidate_graphql_chain(chain, stale_state).status.value == "manual_review"


def test_secret_source_values_never_enter_graphql_chain_or_packet():
    state, experiments = _graphql_fixture(protected=True)
    token = TokenRef(
        token_ref_id="opaque-token-reference",
        identity_id="identity-a",
        vault_reference="credential_reference_super_secret",
        token_kind=TokenKind.access,
        lifecycle=TokenLifecycle.active,
        issuer_reference="issuer-reference",
        provenance_id="prov-graphql",
    )
    relation = _relationship(
        EntityReference(entity_kind=EntityKind.token, entity_id=token.token_ref_id),
        EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=state.graphql_operations[0].operation_id,
        ),
        "relationship-token-graphql-secret-fixture",
    )
    state = _state(state, token_refs=(token,), relationships=(relation,))
    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=experiments
    )
    packet = PublicSafeChainPacketBuilder().build(state, candidates)
    rendered = repr((candidates, packet.public_payload())).lower()

    assert "credential_reference_super_secret" not in rendered
    assert "authorization_header" not in rendered
