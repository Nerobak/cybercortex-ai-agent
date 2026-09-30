from __future__ import annotations

import pytest

from agent_core.research import (
    CleanupStatus,
    EntityKind,
    EntityReference,
    ExperimentEvaluator,
    ExperimentResultClassification,
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLAuthorizationSemantics,
    GraphQLCandidateKind,
    GraphQLDifferentialEvaluator,
    GraphQLErrorClass,
    GraphQLErrorPathEvidence,
    GraphQLResponseEnvelope,
    GraphQLStateDifferentialEvidence,
    IdentityRelationship,
    InvariantResult,
    HttpMethod,
    ResearchState,
    Workflow,
    WorkflowStep,
)
from test_phase4_graphql_runtime import (
    FakeResponse,
    _mutation_runtime_fixture,
    _runtime_fixture,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _execute(kind: GraphQLCandidateKind, responses=None):
    fixture = _runtime_fixture(candidate_kind=kind, responses=responses)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    return fixture, authorization, binding.submit(authorization)


@pytest.mark.parametrize(
    "kind",
    (
        GraphQLCandidateKind.object_authorization,
        GraphQLCandidateKind.tenant_bound,
    ),
)
def test_controlled_object_differentials_classify_strong_signals(kind):
    vulnerable, _authorization, vulnerable_outcome = _execute(
        kind, (FakeResponse(), FakeResponse())
    )
    secure, _authorization, secure_outcome = _execute(kind)

    vulnerable_result = GraphQLDifferentialEvaluator().evaluate(
        vulnerable.experiment,
        vulnerable_outcome,
        state=vulnerable.gate.state,
    )
    secure_result = GraphQLDifferentialEvaluator().evaluate(
        secure.experiment,
        secure_outcome,
        state=secure.gate.state,
    )

    assert vulnerable_result.classification is (
        ExperimentResultClassification.vulnerable_signal
    )
    assert secure_result.classification is ExperimentResultClassification.secure_signal


@pytest.mark.parametrize(
    "comparison",
    (
        FakeResponse(
            200,
            b'{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}',
        ),
        FakeResponse(
            200,
            b'{"data":{"resource":null}}',
        ),
        FakeResponse(
            200,
            b'{"errors":[{"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}',
        ),
    ),
)
def test_false_positive_regressions_create_no_candidate(comparison):
    fixture, authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), comparison),
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment, authorization, outcome, fixture.gate.state
    )

    assert evaluation.classification is not (
        ExperimentResultClassification.vulnerable_signal
    )
    assert evaluation.candidate_finding is None


def test_response_fingerprint_difference_alone_is_inconclusive():
    fixture, authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), FakeResponse()),
    )
    comparison = outcome.evidence[1]
    response = comparison.graphql_responses[0].model_copy(
        update={
            "selected_field_presence": (),
            "object_shape_fingerprint": DIGEST_B,
        }
    )
    evidence = (
        outcome.evidence[0],
        comparison.model_copy(update={"graphql_responses": (response,)}),
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment,
        authorization,
        outcome.model_copy(update={"evidence": evidence}),
        fixture.gate.state,
    )

    assert evaluation.classification is (ExperimentResultClassification.inconclusive)
    assert evaluation.candidate_finding is None


def test_conflicting_bounded_responses_are_inconclusive():
    fixture, authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), FakeResponse()),
    )
    comparison = outcome.evidence[1]
    allowed = comparison.graphql_responses[0]
    denied = type(allowed).model_validate(
        {
            **allowed.model_dump(mode="python"),
            "selected_field_presence": (),
            "error_classes": (GraphQLErrorClass.authorization_error,),
            "errors_present": True,
            "error_count": 1,
            "envelope": GraphQLResponseEnvelope.graphql_errors,
            "data_present": False,
        }
    )
    evidence = (
        outcome.evidence[0],
        comparison.model_copy(update={"graphql_responses": (allowed, denied)}),
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment,
        authorization,
        outcome.model_copy(update={"evidence": evidence}),
        fixture.gate.state,
    )

    assert evaluation.classification is (ExperimentResultClassification.inconclusive)
    assert evaluation.graphql_evaluation.conflict_codes == (
        "conflicting-graphql-access-evidence",
    )
    assert evaluation.candidate_finding is None


def _with_comparison_state_effect(
    experiment, outcome, *, effect: bool = True, workflow_state=None
):
    comparison = outcome.evidence[1]
    differential = GraphQLStateDifferentialEvidence(
        invariant_reference=experiment.required_evidence[0].predicate_reference,
        identity_reference="identity-b",
        object_references=("object-resource-1",),
        workflow_state_reference=workflow_state,
        before_fingerprint=DIGEST_A,
        after_fingerprint=DIGEST_B if effect else DIGEST_A,
        protected_effect_observed=effect,
        authoritative=True,
    )
    evidence = (
        outcome.evidence[0],
        comparison.model_copy(update={"graphql_state_differentials": (differential,)}),
        *outcome.evidence[2:],
    )
    return outcome.model_copy(update={"evidence": evidence})


def test_mutation_requires_authoritative_state_effect_for_vulnerable_signal():
    fixture = _mutation_runtime_fixture(allow_state_changes=True)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    response_only = binding.submit(authorization)

    inconclusive = GraphQLDifferentialEvaluator().evaluate(
        fixture.experiment, response_only, state=fixture.gate.state
    )
    proven = _with_comparison_state_effect(fixture.experiment, response_only)
    vulnerable = ExperimentEvaluator().evaluate(
        fixture.experiment, authorization, proven, fixture.gate.state
    )

    assert inconclusive.classification is (ExperimentResultClassification.inconclusive)
    assert vulnerable.classification is (
        ExperimentResultClassification.vulnerable_signal
    )
    assert vulnerable.candidate_finding is not None


def test_cleanup_failure_has_precedence_over_observed_mutation_effect():
    fixture = _mutation_runtime_fixture(allow_state_changes=True, cleanup_status=500)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = _with_comparison_state_effect(
        fixture.experiment, binding.submit(authorization)
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment, authorization, outcome, fixture.gate.state
    )

    assert outcome.cleanup_status is CleanupStatus.failed
    assert evaluation.classification is (ExperimentResultClassification.cleanup_failed)
    assert evaluation.candidate_finding is None
    assert evaluation.stop_required


def test_workflow_mutation_uses_registered_authoritative_transition_evidence():
    fixture = _mutation_runtime_fixture(allow_state_changes=True)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    state = fixture.gate.state
    workflow = Workflow(
        workflow_id="workflow-resource-update",
        surface_id="surface-graphql",
        name="Controlled GraphQL resource workflow.",
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
    )
    operation = state.graphql_operations[0].model_copy(
        update={"workflow_id": workflow.workflow_id}
    )
    hypothesis = next(
        item
        for item in state.hypotheses
        if item.hypothesis_id == fixture.experiment.hypothesis_id
    )
    refs = {
        (item.entity_kind, item.entity_id): item
        for item in hypothesis.entity_references
    }
    refs[(EntityKind.workflow, workflow.workflow_id)] = EntityReference(
        entity_kind=EntityKind.workflow, entity_id=workflow.workflow_id
    )
    hypothesis = hypothesis.model_copy(
        update={
            "security_property": "workflow-bound-mutation",
            "entity_references": tuple(refs.values()),
        }
    )
    state = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "workflows": (workflow,),
            "graphql_operations": (operation,),
            "hypotheses": tuple(
                hypothesis if item.hypothesis_id == hypothesis.hypothesis_id else item
                for item in state.hypotheses
            ),
        }
    )
    experiment = fixture.experiment.model_copy(
        update={
            "primitive_steps": tuple(
                step.model_copy(
                    update={
                        "input": step.input.model_copy(
                            update={
                                "candidate_kind": (
                                    GraphQLCandidateKind.workflow_mutation
                                )
                            }
                        )
                    }
                )
                for step in fixture.experiment.primitive_steps
            )
        }
    )
    outcome = _with_comparison_state_effect(
        experiment, outcome, workflow_state="state-after"
    )

    result = GraphQLDifferentialEvaluator().evaluate(experiment, outcome, state=state)

    assert result.classification is (ExperimentResultClassification.vulnerable_signal)
    assert result.security_property.value == "workflow_mutation_authorization"


@pytest.mark.parametrize(
    ("secure", "expected"),
    (
        (True, ExperimentResultClassification.secure_signal),
        (False, ExperimentResultClassification.vulnerable_signal),
    ),
)
def test_registered_input_invariant_is_evaluated_deterministically(secure, expected):
    responses = (
        FakeResponse(),
        (
            FakeResponse(
                200,
                b'{"errors":[{"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}',
            )
            if secure
            else FakeResponse()
        ),
    )
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.input_validation, responses
    )
    if not secure:
        evidence = list(outcome.evidence)
        evidence[1] = evidence[1].model_copy(
            update={
                "invariant_results": (
                    InvariantResult(
                        invariant_reference=(
                            fixture.experiment.required_evidence[0].predicate_reference
                        ),
                        satisfied=False,
                    ),
                )
            }
        )
        outcome = outcome.model_copy(update={"evidence": tuple(evidence)})

    result = GraphQLDifferentialEvaluator().evaluate(
        fixture.experiment, outcome, state=fixture.gate.state
    )

    assert result.classification is expected


def _retag_identity_boundary(property_name, kind, *, denied=False):
    comparison = (
        FakeResponse(
            200,
            b'{"errors":[{"path":["resource"],"extensions":{"code":"FORBIDDEN"}}]}',
        )
        if denied
        else FakeResponse()
    )
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), comparison),
    )
    state = fixture.gate.state
    hypothesis = next(
        item
        for item in state.hypotheses
        if item.hypothesis_id == fixture.experiment.hypothesis_id
    )
    field_id = "field-query-resource"
    protected = next(item for item in state.graphql_fields if item.field_id == field_id)
    protected = protected.model_copy(
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
    refs = {
        (item.entity_kind, item.entity_id): item
        for item in hypothesis.entity_references
    }
    refs[(EntityKind.identity, "identity-b")] = EntityReference(
        entity_kind=EntityKind.identity, entity_id="identity-b"
    )
    hypothesis = hypothesis.model_copy(
        update={
            "security_property": property_name,
            "entity_references": tuple(refs.values()),
        }
    )
    operation = state.graphql_operations[0].model_copy(
        update={
            "authentication_requirement": GraphQLAuthenticationRequirement.role_bound
        }
    )
    state = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "hypotheses": tuple(
                hypothesis if item.hypothesis_id == hypothesis.hypothesis_id else item
                for item in state.hypotheses
            ),
            "graphql_fields": tuple(
                protected if item.field_id == field_id else item
                for item in state.graphql_fields
            ),
            "graphql_operations": (operation,),
        }
    )
    steps = []
    evidence = []
    for index, (step, item) in enumerate(
        zip(fixture.experiment.primitive_steps, outcome.evidence, strict=True)
    ):
        identity = "identity-a" if index == 0 else "identity-b"
        value = step.input.model_copy(
            update={
                "candidate_kind": kind,
                "identity_id": identity,
                "identity_role": "primary" if index == 0 else "comparison",
                "anonymous": False,
            }
        )
        steps.append(step.model_copy(update={"input": value}))
        response = item.graphql_responses[0].model_copy(
            update={"identity_reference": identity}
        )
        evidence.append(
            item.model_copy(
                update={
                    "identity_references": (identity,),
                    "graphql_responses": (response,),
                }
            )
        )
    experiment = fixture.experiment.model_copy(
        update={
            "primitive_steps": tuple(steps),
            "identity_context": fixture.experiment.identity_context.model_copy(
                update={
                    "comparison_identity_id": "identity-b",
                    "relationship": IdentityRelationship.different_controlled_role,
                }
            ),
        }
    )
    return experiment, outcome.model_copy(update={"evidence": tuple(evidence)}), state


@pytest.mark.parametrize(
    ("property_name", "kind"),
    (
        ("field-level-authorization", GraphQLCandidateKind.field_authorization),
        ("operation-level-authorization", GraphQLCandidateKind.operation_authorization),
        ("role-bound-access", GraphQLCandidateKind.role_bound),
    ),
)
def test_field_operation_and_role_boundaries_use_the_tested_property(
    property_name, kind
):
    experiment, outcome, state = _retag_identity_boundary(property_name, kind)

    result = GraphQLDifferentialEvaluator().evaluate(experiment, outcome, state=state)

    assert result.classification is (ExperimentResultClassification.vulnerable_signal)


def test_unknown_role_relationship_is_inconclusive():
    experiment, outcome, state = _retag_identity_boundary(
        "role-bound-access", GraphQLCandidateKind.role_bound
    )
    experiment = experiment.model_copy(
        update={
            "identity_context": experiment.identity_context.model_copy(
                update={"relationship": IdentityRelationship.same_identity}
            )
        }
    )

    result = GraphQLDifferentialEvaluator().evaluate(experiment, outcome, state=state)

    assert result.classification is ExperimentResultClassification.inconclusive
    assert "controlled-role-relationship" in result.missing_evidence


def test_field_error_path_denial_is_secure_with_partial_data():
    experiment, outcome, state = _retag_identity_boundary(
        "field-level-authorization",
        GraphQLCandidateKind.field_authorization,
        denied=True,
    )
    response = outcome.evidence[1].graphql_responses[0]
    assert response.error_classes == (GraphQLErrorClass.authorization_error,)
    assert response.error_paths == (
        GraphQLErrorPathEvidence(
            path=("resource",),
            error_class=GraphQLErrorClass.authorization_error,
        ),
    )

    result = GraphQLDifferentialEvaluator().evaluate(experiment, outcome, state=state)

    assert result.classification is ExperimentResultClassification.secure_signal


@pytest.mark.parametrize(
    ("property_name", "kind"),
    (
        ("ownership-authorization", GraphQLCandidateKind.ownership),
        ("cross-surface-authorization", GraphQLCandidateKind.cross_surface),
    ),
)
def test_registered_object_property_variants_remain_graphql_local(property_name, kind):
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.object_authorization,
        (FakeResponse(), FakeResponse()),
    )
    state = fixture.gate.state
    hypothesis = next(
        item
        for item in state.hypotheses
        if item.hypothesis_id == fixture.experiment.hypothesis_id
    ).model_copy(update={"security_property": property_name})
    state = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "hypotheses": tuple(
                hypothesis if item.hypothesis_id == hypothesis.hypothesis_id else item
                for item in state.hypotheses
            ),
        }
    )
    experiment = fixture.experiment.model_copy(
        update={
            "primitive_steps": tuple(
                step.model_copy(
                    update={
                        "input": step.input.model_copy(update={"candidate_kind": kind})
                    }
                )
                for step in fixture.experiment.primitive_steps
            )
        }
    )

    result = GraphQLDifferentialEvaluator().evaluate(experiment, outcome, state=state)

    assert result.classification is (ExperimentResultClassification.vulnerable_signal)
    assert result.security_property.value == property_name.replace("-", "_")


def test_nested_resolver_requires_and_evaluates_the_registered_child_path():
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.object_authorization,
        (FakeResponse(), FakeResponse()),
    )
    state = fixture.gate.state
    child = state.objects[0].model_copy(
        update={
            "object_id": "object-child-1",
            "object_reference": "controlled-child-reference",
            "owner_identity_id": "identity-b",
        }
    )
    field_id = "field-resource-owner"
    nested = next(item for item in state.graphql_fields if item.field_id == field_id)
    nested = nested.model_copy(
        update={
            "authorization_semantics": GraphQLAuthorizationSemantics(
                observations=(
                    GraphQLAuthorizationObservation.ownership_sensitive_access,
                ),
                identity_references=("identity-a", "identity-b"),
                evidence_references=("evidence-graphql",),
                provenance_id="prov-graphql",
            )
        }
    )
    hypothesis = next(
        item
        for item in state.hypotheses
        if item.hypothesis_id == fixture.experiment.hypothesis_id
    )
    refs = {
        (item.entity_kind, item.entity_id): item
        for item in hypothesis.entity_references
    }
    refs[(EntityKind.graphql_field, field_id)] = EntityReference(
        entity_kind=EntityKind.graphql_field, entity_id=field_id
    )
    refs[(EntityKind.object, child.object_id)] = EntityReference(
        entity_kind=EntityKind.object, entity_id=child.object_id
    )
    hypothesis = hypothesis.model_copy(
        update={
            "security_property": "relationship-traversal-authorization",
            "entity_references": tuple(refs.values()),
        }
    )
    state = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "objects": (*state.objects, child),
            "graphql_fields": tuple(
                nested if item.field_id == field_id else item
                for item in state.graphql_fields
            ),
            "hypotheses": tuple(
                hypothesis if item.hypothesis_id == hypothesis.hypothesis_id else item
                for item in state.hypotheses
            ),
        }
    )
    experiment = fixture.experiment.model_copy(
        update={
            "primitive_steps": tuple(
                step.model_copy(
                    update={
                        "input": step.input.model_copy(
                            update={
                                "candidate_kind": GraphQLCandidateKind.nested_resolver,
                                "selected_field_ids": (field_id,),
                            }
                        )
                    }
                )
                for step in fixture.experiment.primitive_steps
            )
        }
    )
    evidence = tuple(
        item.model_copy(
            update={
                "graphql_responses": (
                    item.graphql_responses[0].model_copy(
                        update={
                            "selected_field_presence": (field_id,),
                            "selected_field_nulls": (),
                        }
                    ),
                )
            }
        )
        for item in outcome.evidence
    )

    result = GraphQLDifferentialEvaluator().evaluate(
        experiment,
        outcome.model_copy(update={"evidence": evidence}),
        state=state,
    )

    assert result.classification is (ExperimentResultClassification.vulnerable_signal)
    assert result.field_references == (field_id,)
    assert result.controlled_object_references == (
        "object-child-1",
        "object-resource-1",
    )
