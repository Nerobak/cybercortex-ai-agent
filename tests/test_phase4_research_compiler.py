from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.agent_models import RiskLevel
from agent_core.research import (
    BaselineIntent,
    BaselineKind,
    CleanupDefinition,
    CompilerContext,
    CompilerErrorCode,
    DifferentialReference,
    DifferentialSelector,
    Endpoint,
    EvidenceArtifact,
    EvidenceIntent,
    EvidenceKind,
    ExperimentCompiler,
    ExperimentCompilerError,
    ExperimentProposal,
    ExperimentRegistry,
    HeaderMutationInput,
    HeaderMutationOperation,
    HttpMethod,
    HypothesisRecord,
    HypothesisResearchStatus,
    Identity,
    IdentityEligibility,
    IdentityRelationship,
    IdentitySwitchInput,
    MutationIntent,
    MutationKind,
    ObjectSubstitutionInput,
    Parameter,
    ParameterLocation,
    ParameterMutationInput,
    PrimitiveStepProposal,
    ProvenanceProducerType,
    ProvenanceRecord,
    RegisteredRequestTemplate,
    RegisteredSafeHeader,
    ResearchConfidence,
    ResearchObject,
    ResearchRunStatus,
    ResearchState,
    ResponseDifferentialInput,
    SecurityExperiment,
    SelectorSpec,
    StateDifferentialInput,
    StopConditionCode,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
    equivalent_experiment,
    experiment_fingerprint,
    blocked_fingerprint,
    previously_attempted_fingerprint,
    reproduction_fingerprint_relationship,
    ReproductionFingerprintRelationship,
)

NOW = "2026-09-17T12:00:00+00:00"
FUTURE = "2026-09-17T13:00:00+00:00"


@pytest.fixture
def research_state() -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="provenance-1",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-compiler-test",
        producer_version="v1",
        summary="Compiler fixture provenance.",
        occurred_at=NOW,
    )
    evidence = tuple(
        EvidenceArtifact(
            evidence_id=f"evidence-{index}",
            evidence_kind=EvidenceKind.capture,
            digest="sha256:" + character * 64,
            summary="A bounded controlled observation was recorded.",
            source_reference=f"capture-{index}",
            observed_at=NOW,
            provenance_id="provenance-1",
        )
        for index, character in ((1, "a"), (2, "b"))
    )
    targets = tuple(
        TargetAsset(
            target_id=f"target-{index}",
            canonical_reference=f"registered-target-{index}",
            target_class=TargetClass.local_range,
            scope_reference=f"scope-{index}",
            evidence_references=(f"evidence-{index}",),
            provenance_id="provenance-1",
        )
        for index in (1, 2)
    )
    surface = Surface(
        surface_id="surface-1",
        target_id="target-1",
        surface_type=SurfaceType.rest,
        label="Observed REST surface.",
        evidence_references=("evidence-1",),
        provenance_id="provenance-1",
    )
    endpoints = tuple(
        Endpoint(
            endpoint_id=f"endpoint-{index}",
            target_id="target-1",
            surface_id="surface-1",
            method=HttpMethod.get,
            route_template=f"/objects-{index}/{{id}}",
            evidence_references=(f"evidence-{index}",),
            provenance_id="provenance-1",
        )
        for index in (1, 2)
    )
    parameters = tuple(
        Parameter(
            parameter_id=f"parameter-{index}",
            endpoint_id=f"endpoint-{index}",
            name=f"id{index}",
            location=ParameterLocation.path,
            evidence_references=(f"evidence-{index}",),
            provenance_id="provenance-1",
        )
        for index in (1, 2)
    )
    identities = (
        Identity(
            identity_id="identity-1",
            account_reference="account-1",
            tenant_reference="tenant-1",
            controlled=True,
            eligibility=IdentityEligibility.eligible,
            provenance_id="provenance-1",
        ),
        Identity(
            identity_id="identity-2",
            account_reference="account-2",
            tenant_reference="tenant-1",
            controlled=True,
            eligibility=IdentityEligibility.eligible,
            provenance_id="provenance-1",
        ),
        Identity(
            identity_id="identity-3",
            account_reference="third-party-account",
            tenant_reference="tenant-1",
            controlled=False,
            eligibility=IdentityEligibility.ineligible,
            provenance_id="provenance-1",
        ),
    )
    objects = (
        ResearchObject(
            object_id="object-1",
            target_id="target-1",
            surface_id="surface-1",
            object_type="project",
            object_reference="controlled-object-1",
            owner_identity_id="identity-1",
            tenant_reference="tenant-1",
            test_owned=True,
            evidence_references=("evidence-1",),
            provenance_id="provenance-1",
        ),
        ResearchObject(
            object_id="object-2",
            target_id="target-1",
            surface_id="surface-1",
            object_type="project",
            object_reference="third-party-object",
            test_owned=False,
            evidence_references=("evidence-2",),
            provenance_id="provenance-1",
        ),
    )
    hypotheses = tuple(
        HypothesisRecord(
            hypothesis_id=f"hypothesis-{index}",
            category="bola",
            title="A bounded authorization hypothesis.",
            claim="A controlled comparison may cross an object boundary.",
            target_id=f"target-{index}",
            surface_id="surface-1",
            status=HypothesisResearchStatus.proposed,
            priority=80,
            confidence=ResearchConfidence.medium,
            confirmation_policy_reference="policy-bola-v1",
            supporting_evidence=(("evidence-1",) if index == 1 else ()),
            provenance_id="provenance-1",
        )
        for index in (1, 2)
    )
    return ResearchState(
        research_id="research-1",
        revision=4,
        status=ResearchRunStatus.selecting_experiment,
        created_at=NOW,
        updated_at=NOW,
        targets=targets,
        surfaces=(surface,),
        endpoints=endpoints,
        parameters=parameters,
        identities=identities,
        objects=objects,
        evidence=evidence,
        hypotheses=hypotheses,
        provenance=(provenance,),
    )


@pytest.fixture
def compiler_context() -> CompilerContext:
    return CompilerContext(
        current_time=NOW,
        controlled_value_references=("safe-value-1", "safe-value-2"),
        state_references=("state-before", "state-after", "state-cleanup"),
        request_templates=tuple(
            RegisteredRequestTemplate(
                template_id=f"template-{index}",
                target_id="target-1",
                surface_id="surface-1",
                endpoint_id=f"endpoint-{index}",
                parameter_ids=(f"parameter-{index}",),
            )
            for index in (1, 2)
        ),
        policy_reference="policy-context-1",
        context_reference="controlled-context-1",
    )


def object_proposal(**updates: object) -> ExperimentProposal:
    payload: dict[str, object] = {
        "proposal_id": "proposal-1",
        "research_id": "research-1",
        "state_revision": 4,
        "hypothesis_id": "hypothesis-1",
        "capability": "bola",
        "target_id": "target-1",
        "surface_id": "surface-1",
        "endpoint_id": "endpoint-1",
        "objective": "Compare access to one controlled owned object.",
        "primary_identity_id": "identity-1",
        "comparison_identity_id": "identity-2",
        "identity_relationship": IdentityRelationship.owner_non_owner,
        "baseline": BaselineIntent(
            kind=BaselineKind.registered_request, reference_id="template-1"
        ),
        "mutation_intent": MutationIntent(
            kind=MutationKind.replace_with_controlled_object_reference,
            parameter_id="parameter-1",
            controlled_object_id="object-1",
        ),
        "expected_secure_behavior": "The comparison identity is denied.",
        "expected_vulnerable_behavior": "The protected object is returned.",
        "required_evidence_intent": (
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="predicate-1",
            ),
        ),
        "rationale": "A bounded owner and non-owner comparison tests the claim.",
        "primitive_steps": (
            PrimitiveStepProposal(
                step_id="step-1",
                input=ObjectSubstitutionInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    parameter_id="parameter-1",
                    primary_identity_id="identity-1",
                    comparison_identity_id="identity-2",
                    controlled_object_id="object-1",
                    relationship=IdentityRelationship.owner_non_owner,
                    ownership_evidence_ids=("evidence-1",),
                ),
            ),
        ),
        "provenance_id": "provenance-1",
        "model_decision_id": "decision-1",
        "expires_at": FUTURE,
    }
    payload.update(updates)
    return ExperimentProposal.model_validate(payload)


def replace_step(proposal: ExperimentProposal, **updates: object) -> ExperimentProposal:
    payload = proposal.model_dump(mode="python")
    payload["primitive_steps"][0]["input"].update(updates)
    return ExperimentProposal.model_validate(payload)


def compile_object(
    state: ResearchState,
    context: CompilerContext,
    proposal: ExperimentProposal | None = None,
) -> SecurityExperiment:
    return ExperimentCompiler().compile(proposal or object_proposal(), state, context)


def assert_error(
    code: CompilerErrorCode,
    proposal: ExperimentProposal,
    state: ResearchState,
    context: CompilerContext,
) -> None:
    with pytest.raises(ExperimentCompilerError) as caught:
        ExperimentCompiler().compile(proposal, state, context)
    assert caught.value.code is code
    assert str(caught.value) == code.value


def test_compiler_generates_strict_immutable_derived_contract(
    research_state: ResearchState, compiler_context: CompilerContext
):
    experiment = compile_object(research_state, compiler_context)
    assert experiment.capability.version == "bola/v1"
    assert experiment.request_estimate.minimum == 2
    assert experiment.request_estimate.total_reservation == 5
    assert experiment.risk.level is RiskLevel.low
    assert experiment.state_changing is False
    assert experiment.fingerprint == experiment_fingerprint(experiment)
    assert {item.code for item in experiment.stop_conditions.items} == set(
        StopConditionCode
    )
    assert experiment.provenance.source_model_decision_id == "decision-1"
    with pytest.raises(ValidationError, match="frozen_instance"):
        experiment.objective = "changed"  # type: ignore[misc]
    payload = experiment.model_dump(mode="python")
    payload["executor"] = "forged"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        SecurityExperiment.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("target_id", "missing-target", CompilerErrorCode.unknown_target),
        ("surface_id", "missing-surface", CompilerErrorCode.unknown_surface),
        ("endpoint_id", "missing-endpoint", CompilerErrorCode.unknown_endpoint),
        ("hypothesis_id", "missing-hypothesis", CompilerErrorCode.unknown_hypothesis),
    ),
)
def test_unknown_top_level_references_fail_closed(
    field: str,
    value: str,
    code: CompilerErrorCode,
    research_state: ResearchState,
    compiler_context: CompilerContext,
):
    assert_error(
        code,
        object_proposal(**{field: value}),
        research_state,
        compiler_context,
    )


def test_unknown_parameter_fails_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.unknown_parameter,
        object_proposal(
            mutation_intent=MutationIntent(
                kind=MutationKind.replace_with_controlled_object_reference,
                parameter_id="missing-parameter",
                controlled_object_id="object-1",
            )
        ),
        research_state,
        compiler_context,
    )


def test_unknown_operation_and_missing_primitive_fail_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.unknown_operation,
        object_proposal(operation_id="missing-operation"),
        research_state,
        compiler_context,
    )
    with pytest.raises(ExperimentCompilerError) as caught:
        ExperimentCompiler(ExperimentRegistry(include_defaults=False)).compile(
            object_proposal(), research_state, compiler_context
        )
    assert caught.value.code is CompilerErrorCode.unknown_primitive


@pytest.mark.parametrize(
    ("identity_id", "code"),
    (
        ("missing-identity", CompilerErrorCode.unknown_identity),
        ("identity-3", CompilerErrorCode.uncontrolled_identity),
    ),
)
def test_unknown_or_uncontrolled_identity_fails_closed(
    identity_id: str,
    code: CompilerErrorCode,
    research_state: ResearchState,
    compiler_context: CompilerContext,
):
    proposal = replace_step(
        object_proposal(), comparison_identity_id=identity_id
    ).model_dump(mode="python")
    proposal["comparison_identity_id"] = identity_id
    assert_error(
        code,
        ExperimentProposal.model_validate(proposal),
        research_state,
        compiler_context,
    )


@pytest.mark.parametrize(
    ("object_id", "code"),
    (
        ("missing-object", CompilerErrorCode.unknown_object),
        ("object-2", CompilerErrorCode.unowned_object),
    ),
)
def test_unknown_or_unowned_object_fails_closed(
    object_id: str,
    code: CompilerErrorCode,
    research_state: ResearchState,
    compiler_context: CompilerContext,
):
    proposal = replace_step(
        object_proposal(), controlled_object_id=object_id
    ).model_dump(mode="python")
    proposal["mutation_intent"]["controlled_object_id"] = object_id
    assert_error(
        code,
        ExperimentProposal.model_validate(proposal),
        research_state,
        compiler_context,
    )


def test_parameter_endpoint_and_target_surface_mismatches_fail_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.parameter_endpoint_mismatch,
        replace_step(object_proposal(), parameter_id="parameter-2"),
        research_state,
        compiler_context,
    )


def test_missing_ownership_evidence_and_false_relationship_fail_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.missing_required_evidence,
        replace_step(object_proposal(), ownership_evidence_ids=("evidence-2",)),
        research_state,
        compiler_context,
    )
    payload = replace_step(
        object_proposal(),
        relationship=IdentityRelationship.different_controlled_tenant,
    ).model_dump(mode="python")
    payload["identity_relationship"] = IdentityRelationship.different_controlled_tenant
    assert_error(
        CompilerErrorCode.identity_relationship_mismatch,
        ExperimentProposal.model_validate(payload),
        research_state,
        compiler_context,
    )
    assert_error(
        CompilerErrorCode.target_surface_mismatch,
        object_proposal(target_id="target-2", hypothesis_id="hypothesis-2"),
        research_state,
        compiler_context,
    )


def test_unknown_template_and_execution_unavailable_fail_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.unknown_request_template,
        object_proposal(),
        research_state,
        CompilerContext(current_time=NOW),
    )
    assert_error(
        CompilerErrorCode.primitive_not_execution_available,
        object_proposal(),
        research_state,
        compiler_context.model_copy(update={"execution_ready": True}),
    )


def test_model_cannot_override_cost_risk_or_cleanup(
    research_state: ResearchState, compiler_context: CompilerContext
):
    base = object_proposal().model_dump(mode="python")
    for field in ("request_estimate", "risk", "cleanup"):
        payload = dict(base)
        payload[field] = {"model": "override"}
        with pytest.raises(ExperimentCompilerError) as caught:
            ExperimentCompiler().compile(payload, research_state, compiler_context)
        assert caught.value.code is CompilerErrorCode.invalid_proposal


def header_proposal() -> ExperimentProposal:
    return ExperimentProposal(
        proposal_id="header-proposal",
        research_id="research-1",
        state_revision=4,
        hypothesis_id="hypothesis-1",
        capability="header_mutation",
        target_id="target-1",
        surface_id="surface-1",
        endpoint_id="endpoint-1",
        objective="Remove one registered safe header.",
        baseline=BaselineIntent(
            kind=BaselineKind.registered_request, reference_id="template-1"
        ),
        mutation_intent=MutationIntent(kind="none"),
        expected_secure_behavior="The response remains securely classified.",
        expected_vulnerable_behavior="The protected response class changes.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="predicate-1",
            ),
        ),
        rationale="A registered header mutation is bounded.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id="header-step",
                input=HeaderMutationInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    header_definition_id="credential-header",
                    operation=HeaderMutationOperation.remove,
                ),
            ),
        ),
        provenance_id="provenance-1",
        expires_at=FUTURE,
    )


def test_credential_header_mutation_is_rejected(
    research_state: ResearchState, compiler_context: CompilerContext
):
    context = compiler_context.model_copy(
        update={
            "safe_headers": (
                RegisteredSafeHeader(
                    header_definition_id="credential-header",
                    normalized_name="Authorization",
                ),
            )
        }
    )
    assert_error(
        CompilerErrorCode.credential_header_prohibited,
        header_proposal(),
        research_state,
        context,
    )


def mutation_proposal() -> ExperimentProposal:
    return ExperimentProposal(
        proposal_id="mutation-proposal",
        research_id="research-1",
        state_revision=4,
        hypothesis_id="hypothesis-1",
        capability="parameter_mutation",
        target_id="target-1",
        surface_id="surface-1",
        endpoint_id="endpoint-1",
        objective="Apply one controlled structural parameter mutation.",
        baseline=BaselineIntent(
            kind=BaselineKind.registered_request, reference_id="template-1"
        ),
        mutation_intent=MutationIntent(
            kind=MutationKind.replace_with_controlled_value,
            parameter_id="parameter-1",
            value_source_reference="safe-value-1",
        ),
        expected_secure_behavior="The mutation is handled safely.",
        expected_vulnerable_behavior="The mutation changes protected state.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=DifferentialSelector.state_marker,
                predicate_reference="state-predicate-1",
            ),
        ),
        rationale="A single registered mutation is bounded.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id="mutation-step",
                input=ParameterMutationInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    parameter_id="parameter-1",
                    mutation_kind=MutationKind.replace_with_controlled_value,
                    value_source_reference="safe-value-1",
                ),
            ),
        ),
        provenance_id="provenance-1",
        expires_at=FUTURE,
    )


def patch_state(state: ResearchState) -> ResearchState:
    payload = state.model_dump(mode="python")
    payload["endpoints"][0]["method"] = HttpMethod.patch
    return ResearchState.model_validate(payload)


def test_state_change_requires_and_derives_cleanup(
    research_state: ResearchState, compiler_context: CompilerContext
):
    state = patch_state(research_state)
    assert_error(
        CompilerErrorCode.missing_cleanup,
        mutation_proposal(),
        state,
        compiler_context,
    )
    cleanup = CleanupDefinition(
        cleanup_reference="cleanup-parameter-1",
        verification_predicate_reference="cleanup-verified-1",
        primitive_names=("parameter_mutation",),
        minimum_requests=1,
        worst_case_requests=2,
    )
    context = compiler_context.model_copy(update={"cleanup_definitions": (cleanup,)})
    experiment = ExperimentCompiler().compile(mutation_proposal(), state, context)
    assert experiment.state_changing is True
    assert experiment.cleanup.required is True
    assert experiment.request_estimate.cleanup == 2
    assert experiment.request_estimate.total_reservation == 3
    assert experiment.risk.level is RiskLevel.moderate


def offline_proposal(kind: str) -> ExperimentProposal:
    common: dict[str, object] = {
        "proposal_id": f"{kind}-proposal",
        "research_id": "research-1",
        "state_revision": 4,
        "hypothesis_id": "hypothesis-1",
        "capability": kind,
        "target_id": "target-1",
        "surface_id": "surface-1",
        "objective": "Analyze already registered controlled context.",
        "mutation_intent": MutationIntent(kind="differential"),
        "expected_secure_behavior": "The recorded result has the secure class.",
        "expected_vulnerable_behavior": "The recorded result materially differs.",
        "required_evidence_intent": (
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="predicate-1",
            ),
        ),
        "rationale": "Offline analysis needs no target requests.",
        "provenance_id": "provenance-1",
        "expires_at": FUTURE,
    }
    if kind == "response_differential":
        common.update(
            baseline=BaselineIntent(
                kind=BaselineKind.prior_evidence, reference_id="evidence-1"
            ),
            primitive_steps=(
                PrimitiveStepProposal(
                    step_id="response-step",
                    input=ResponseDifferentialInput(
                        references=(
                            DifferentialReference(
                                kind="evidence", reference_id="evidence-1"
                            ),
                            DifferentialReference(
                                kind="evidence", reference_id="evidence-2"
                            ),
                        ),
                        selectors=(
                            SelectorSpec(selector=DifferentialSelector.status_class),
                        ),
                    ),
                ),
            ),
        )
    elif kind == "state_differential":
        common.update(
            baseline=BaselineIntent(
                kind=BaselineKind.before_state, reference_id="state-before"
            ),
            primitive_steps=(
                PrimitiveStepProposal(
                    step_id="state-step",
                    input=StateDifferentialInput(
                        before_state_reference="state-before",
                        after_state_reference="state-after",
                        cleanup_state_reference="state-cleanup",
                        invariant_references=("invariant-1",),
                    ),
                ),
            ),
        )
    else:
        common.update(
            primary_identity_id="identity-1",
            comparison_identity_id="identity-2",
            identity_relationship=IdentityRelationship.owner_non_owner,
            baseline=BaselineIntent(
                kind=BaselineKind.primary_identity, reference_id="identity-1"
            ),
            mutation_intent=MutationIntent(kind="context_switch"),
            primitive_steps=(
                PrimitiveStepProposal(
                    step_id="identity-step",
                    input=IdentitySwitchInput(
                        primary_identity_id="identity-1",
                        comparison_identity_id="identity-2",
                        relationship=IdentityRelationship.owner_non_owner,
                    ),
                ),
            ),
        )
    return ExperimentProposal.model_validate(common)


@pytest.mark.parametrize(
    "kind", ("response_differential", "state_differential", "identity_switch")
)
def test_offline_and_context_primitives_have_zero_request_semantics(
    kind: str, research_state: ResearchState, compiler_context: CompilerContext
):
    experiment = ExperimentCompiler().compile(
        offline_proposal(kind), research_state, compiler_context
    )
    assert experiment.request_estimate.total_reservation == 0
    assert experiment.risk.level is RiskLevel.passive


def test_fingerprint_deduplicates_equivalent_and_separates_material_pivot(
    research_state: ResearchState, compiler_context: CompilerContext
):
    first = compile_object(research_state, compiler_context)
    equivalent = compile_object(
        research_state,
        compiler_context,
        object_proposal(
            proposal_id="proposal-2",
            rationale="Different rationale with identical semantics.",
            model_decision_id="decision-2",
        ),
    )
    pivot = compile_object(
        research_state,
        compiler_context,
        object_proposal(
            mutation_intent=MutationIntent(
                kind=MutationKind.harmless_canary,
                parameter_id="parameter-1",
                value_source_reference="safe-value-1",
            )
        ),
    )
    assert first.fingerprint == equivalent.fingerprint
    assert equivalent_experiment(first, equivalent)
    assert first.fingerprint != pivot.fingerprint
    assert previously_attempted_fingerprint(first, (first.fingerprint,))
    assert blocked_fingerprint(first, (first.fingerprint,))
    assert (
        reproduction_fingerprint_relationship(equivalent, first)
        is ReproductionFingerprintRelationship.equivalent
    )
    assert (
        reproduction_fingerprint_relationship(pivot, first)
        is ReproductionFingerprintRelationship.material_variant
    )


def test_security_experiment_rejects_a_forged_fingerprint(
    research_state: ResearchState, compiler_context: CompilerContext
):
    payload = compile_object(research_state, compiler_context).model_dump(mode="python")
    payload["fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="fingerprint does not match"):
        SecurityExperiment.model_validate(payload)


def test_fingerprint_excludes_secrets_and_includes_state_revision(
    research_state: ResearchState, compiler_context: CompilerContext
):
    first = compile_object(research_state, compiler_context)
    serialized = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert "vault" not in serialized.casefold()
    assert "credential" not in serialized.casefold()
    revised_state = research_state.model_copy(update={"revision": 5})
    revised = compile_object(
        revised_state, compiler_context, object_proposal(state_revision=5)
    )
    assert first.fingerprint != revised.fingerprint


def test_stale_and_expired_proposals_fail_closed(
    research_state: ResearchState, compiler_context: CompilerContext
):
    assert_error(
        CompilerErrorCode.stale_state_revision,
        object_proposal(state_revision=3),
        research_state,
        compiler_context,
    )
    assert_error(
        CompilerErrorCode.expired_proposal,
        object_proposal(expires_at=NOW),
        research_state,
        compiler_context,
    )


def test_compiler_has_no_provider_or_network_path(
    research_state: ResearchState,
    compiler_context: CompilerContext,
    monkeypatch: pytest.MonkeyPatch,
):
    def forbidden(*_args: object, **_kwargs: object):
        raise AssertionError("network or provider path reached")

    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    compile_object(research_state, compiler_context)
