from __future__ import annotations

import json

import pytest
from pydantic import TypeAdapter, ValidationError

from agent_core.models import ModelUsageDelta
from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta
from agent_core.research import (
    AttackChain,
    AttackChainId,
    AttackChainStatus,
    AttackChainStep,
    BudgetState,
    CleanupStatus,
    ControlledImpact,
    DerivationType,
    Endpoint,
    EndpointId,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceArtifactId,
    EvidenceKind,
    ExperimentId,
    ExperimentOutcome,
    ExperimentOutcomeId,
    ExperimentRuntimeStatus,
    Fact,
    FactId,
    FactStatus,
    FindingId,
    FindingRecord,
    FindingStatus,
    GraphQLOperation,
    GraphQLOperationId,
    GraphQLOperationType,
    HttpMethod,
    HypothesisBudgetUsage,
    HypothesisRecord,
    HypothesisRecordId,
    HypothesisResearchStatus,
    Identity,
    IdentityEligibility,
    IdentityId,
    ImpactLevel,
    MetadataEntry,
    ModelBudgetSnapshot,
    Observation,
    ObservationId,
    Parameter,
    ParameterId,
    ParameterLocation,
    ProvenanceProducerType,
    ProvenanceRecord,
    ProvenanceRecordId,
    PublicMetadata,
    ReferenceFactObject,
    Relationship,
    RelationshipId,
    RelationshipStatus,
    RequestBudgetSnapshot,
    ResearchConfidence,
    ResearchEventId,
    ResearchId,
    ResearchObject,
    ResearchObjectId,
    ResearchPredicate,
    ResearchRunStatus,
    ResearchState,
    ScalarFactObject,
    SessionLifecycle,
    SessionRef,
    SessionRefId,
    Surface,
    SurfaceBudgetUsage,
    SurfaceId,
    SurfaceType,
    TargetAsset,
    TargetAssetId,
    TargetClass,
    TokenKind,
    TokenLifecycle,
    TokenRef,
    TokenRefId,
    UploadArtifact,
    UploadArtifactId,
    UploadLifecycle,
    Workflow,
    WorkflowId,
    WorkflowStep,
    canonical_research_state_bytes,
    research_state_hash,
)

TS = "2026-09-16T12:00:00+00:00"
DIGEST = "sha256:" + "a" * 64


def provenance(identifier: str = "prov-1") -> ProvenanceRecord:
    return ProvenanceRecord(
        provenance_id=identifier,
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-contract-test",
        producer_version="v1",
        summary="Deterministic test provenance.",
        occurred_at=TS,
    )


def minimal_state(**changes: object) -> ResearchState:
    values: dict[str, object] = {
        "research_id": "research-1",
        "revision": 0,
        "status": ResearchRunStatus.initializing,
        "created_at": TS,
        "updated_at": TS,
    }
    values.update(changes)
    return ResearchState.model_validate(values)


def populated_state() -> ResearchState:
    prov = provenance()
    evidence = EvidenceArtifact(
        evidence_id="evidence-1",
        evidence_kind=EvidenceKind.capture,
        digest=DIGEST,
        summary="A controlled endpoint and object were observed.",
        source_reference="capture-1",
        observed_at=TS,
        provenance_id=prov.provenance_id,
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="authorized-target",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    surface = Surface(
        surface_id="surface-1",
        target_id=target.target_id,
        surface_type=SurfaceType.graphql,
        label="Observed GraphQL surface.",
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    endpoint = Endpoint(
        endpoint_id="endpoint-1",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        method=HttpMethod.post,
        route_template="/graphql",
        content_types=("application/json",),
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    parameter = Parameter(
        parameter_id="parameter-1",
        endpoint_id=endpoint.endpoint_id,
        name="projectId",
        location=ParameterLocation.graphql_variable,
        data_type="ID",
        required=True,
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    identity = Identity(
        identity_id="identity-1",
        account_reference="account-1",
        role_reference="member",
        tenant_reference="tenant-1",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id=prov.provenance_id,
    )
    session = SessionRef(
        session_ref_id="session-1",
        identity_id=identity.identity_id,
        vault_reference="cred_0123456789abcdef0123",
        lifecycle=SessionLifecycle.active,
        issued_at=TS,
        provenance_id=prov.provenance_id,
    )
    token = TokenRef(
        token_ref_id="token-1",
        identity_id=identity.identity_id,
        vault_reference="cred_abcdef01234567890123",
        token_kind=TokenKind.access,
        lifecycle=TokenLifecycle.active,
        audience_references=("api",),
        provenance_id=prov.provenance_id,
    )
    obj = ResearchObject(
        object_id="object-1",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        object_type="Project",
        object_reference="object-ref-1",
        owner_identity_id=identity.identity_id,
        tenant_reference="tenant-1",
        test_owned=True,
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    operation = GraphQLOperation(
        operation_id="operation-1",
        surface_id=surface.surface_id,
        endpoint_id=endpoint.endpoint_id,
        operation_name="ProjectQuery",
        operation_type=GraphQLOperationType.query,
        root_fields=("project",),
        variable_parameter_ids=(parameter.parameter_id,),
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    upload = UploadArtifact(
        upload_id="upload-1",
        surface_id=surface.surface_id,
        endpoint_id=endpoint.endpoint_id,
        owner_identity_id=identity.identity_id,
        fixture_reference="fixture-1",
        media_type="text/plain",
        lifecycle=UploadLifecycle.fixture_ready,
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    workflow = Workflow(
        workflow_id="workflow-1",
        surface_id=surface.surface_id,
        name="Controlled project workflow.",
        steps=(
            WorkflowStep(
                step_id="step-1",
                sequence=1,
                endpoint_id=endpoint.endpoint_id,
                method=HttpMethod.post,
                state_changing=True,
            ),
        ),
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    observation = Observation(
        observation_id="observation-1",
        observation_type="object-reference-observed",
        summary="A controlled project reference was returned.",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    fact = Fact(
        fact_id="fact-1",
        subject=EntityReference(
            entity_kind=EntityKind.identity, entity_id=identity.identity_id
        ),
        predicate=ResearchPredicate.owns,
        object=ReferenceFactObject(
            reference=EntityReference(
                entity_kind=EntityKind.object, entity_id=obj.object_id
            )
        ),
        status=FactStatus.observed,
        evidence_references=(evidence.evidence_id,),
        derivation_type=DerivationType.deterministic,
        provenance_id=prov.provenance_id,
    )
    relationship = Relationship(
        relationship_id="relationship-1",
        source=EntityReference(
            entity_kind=EntityKind.identity, entity_id=identity.identity_id
        ),
        predicate=ResearchPredicate.owns,
        target=EntityReference(entity_kind=EntityKind.object, entity_id=obj.object_id),
        status=RelationshipStatus.observed,
        evidence_references=(evidence.evidence_id,),
        derivation_type=DerivationType.deterministic,
        provenance_id=prov.provenance_id,
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-1",
        category="graphql_object_authorization",
        title="GraphQL object authorization may be inconsistent.",
        claim="A different controlled identity may access the owned project object.",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        status=HypothesisResearchStatus.proposed,
        priority=80,
        confidence=ResearchConfidence.medium,
        confirmation_policy_reference="policy-graphql-object-auth-v1",
        supporting_evidence=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    finding = FindingRecord(
        finding_id="finding-1",
        status=FindingStatus.candidate,
        title="Candidate GraphQL authorization issue.",
        category="graphql_object_authorization",
        source_hypothesis_id=hypothesis.hypothesis_id,
        candidate_experiment_id="experiment-1",
        confirmation_policy_reference="policy-graphql-object-auth-v1",
        evidence_references=(evidence.evidence_id,),
        cleanup_status=CleanupStatus.not_required,
        provenance_id=prov.provenance_id,
    )
    outcome = ExperimentOutcome(
        outcome_id="outcome-1",
        experiment_id="experiment-1",
        runtime_status=ExperimentRuntimeStatus.completed,
        canonical_result_classification=Phase2ResultStatus.inconclusive,
        evidence_references=(evidence.evidence_id,),
        cleanup_status=CleanupStatus.not_required,
        created_fact_ids=(fact.fact_id,),
        created_hypothesis_ids=(hypothesis.hypothesis_id,),
        candidate_finding_ids=(finding.finding_id,),
        provenance_id=prov.provenance_id,
        occurred_at=TS,
    )
    chain = AttackChain(
        attack_chain_id="chain-1",
        title="Candidate controlled cross-surface chain.",
        status=AttackChainStatus.candidate,
        steps=(
            AttackChainStep(
                sequence=2,
                reference=EntityReference(
                    entity_kind=EntityKind.hypothesis,
                    entity_id=hypothesis.hypothesis_id,
                ),
                objective="Test the derived authorization hypothesis.",
            ),
            AttackChainStep(
                sequence=1,
                reference=EntityReference(
                    entity_kind=EntityKind.fact, entity_id=fact.fact_id
                ),
                objective="Use the observed ownership relationship.",
            ),
        ),
        evidence_references=(evidence.evidence_id,),
        provenance_id=prov.provenance_id,
    )
    budget = BudgetState(
        budget_reference="budget-1",
        experiment_ceiling=10,
        experiments_consumed=1,
        hypothesis_usage=(
            HypothesisBudgetUsage(
                hypothesis_id=hypothesis.hypothesis_id,
                attempt_count=1,
                pivot_count=0,
            ),
        ),
        surface_usage=(
            SurfaceBudgetUsage(surface_id=surface.surface_id, experiment_count=1),
        ),
        request_budget=RequestBudgetSnapshot(
            ledger_reference="request-ledger-1",
            limit=10,
            consumed=RequestDelta(verification=2, attempted=2, total=2),
            remaining=8,
        ),
        model_budget=ModelBudgetSnapshot(
            ledger_reference="model-ledger-1",
            max_calls=5,
            usage=ModelUsageDelta(),
            remaining_calls=5,
        ),
        wall_time_ceiling_seconds=300.0,
        wall_time_consumed_seconds=10.0,
        state_change_ceiling=2,
        state_changes_consumed=0,
        cleanup_request_reserve=1,
        cleanup_status=CleanupStatus.not_required,
    )
    return minimal_state(
        targets=(target,),
        surfaces=(surface,),
        endpoints=(endpoint,),
        parameters=(parameter,),
        identities=(identity,),
        session_refs=(session,),
        token_refs=(token,),
        objects=(obj,),
        graphql_operations=(operation,),
        uploads=(upload,),
        workflows=(workflow,),
        observations=(observation,),
        evidence=(evidence,),
        facts=(fact,),
        relationships=(relationship,),
        hypotheses=(hypothesis,),
        experiment_outcomes=(outcome,),
        findings=(finding,),
        attack_chains=(chain,),
        budgets=(budget,),
        provenance=(prov,),
    )


ID_TYPES = (
    ResearchId,
    ResearchEventId,
    TargetAssetId,
    SurfaceId,
    EndpointId,
    ParameterId,
    IdentityId,
    SessionRefId,
    TokenRefId,
    ResearchObjectId,
    GraphQLOperationId,
    UploadArtifactId,
    WorkflowId,
    ObservationId,
    EvidenceArtifactId,
    FactId,
    HypothesisRecordId,
    ExperimentId,
    ExperimentOutcomeId,
    FindingId,
    AttackChainId,
    RelationshipId,
    ProvenanceRecordId,
)


@pytest.mark.parametrize("identifier_type", ID_TYPES)
@pytest.mark.parametrize("value", ("", " bad", "bad value", "x" * 256))
def test_all_typed_ids_reject_invalid_values(identifier_type, value):
    with pytest.raises(ValidationError):
        TypeAdapter(identifier_type).validate_python(value)


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        minimal_state(unrecognized=True)


def test_records_are_immutable():
    record = provenance()
    with pytest.raises(ValidationError, match="frozen_instance"):
        record.summary = "Changed."  # type: ignore[misc]


def test_research_state_round_trips_as_strict_json():
    state = populated_state()
    restored = ResearchState.model_validate_json(state.model_dump_json())
    assert restored == state
    assert json.loads(state.model_dump_json())["schema_version"] == 1


def test_state_collections_have_hard_bounds():
    records = tuple(
        ProvenanceRecord(
            provenance_id=f"prov-{index}",
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="test",
            producer_version="v1",
            summary="Bounded provenance.",
            occurred_at=TS,
        )
        for index in range(65)
    )
    targets = tuple(
        TargetAsset(
            target_id=f"target-{index}",
            canonical_reference=f"target-{index}",
            target_class=TargetClass.local_range,
            scope_reference="scope-1",
            provenance_id=f"prov-{index}",
        )
        for index in range(65)
    )
    with pytest.raises(ValidationError):
        minimal_state(targets=targets, provenance=records)


@pytest.mark.parametrize(
    ("model", "private_field"),
    (
        (SessionRef, "password"),
        (SessionRef, "cookie"),
        (TokenRef, "token"),
        (TokenRef, "authorization"),
        (Identity, "api_key"),
    ),
)
def test_direct_secret_fields_are_rejected(model, private_field):
    common = {"provenance_id": "prov-1", private_field: "SYNTHETIC_SECRET"}
    if model is SessionRef:
        common.update(
            session_ref_id="session-1",
            identity_id="identity-1",
            vault_reference="cred_0123456789abcdef0123",
            lifecycle=SessionLifecycle.active,
        )
    elif model is TokenRef:
        common.update(
            token_ref_id="token-1",
            identity_id="identity-1",
            vault_reference="cred_0123456789abcdef0123",
            token_kind=TokenKind.access,
            lifecycle=TokenLifecycle.active,
        )
    else:
        common.update(
            identity_id="identity-1",
            account_reference="account-1",
            controlled=True,
            eligibility=IdentityEligibility.eligible,
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model.model_validate(common)


@pytest.mark.parametrize(
    "key",
    (
        "password",
        "api_key",
        "Authorization",
        "cookie",
        "jwt",
        "session",
        "shell_command",
    ),
)
def test_secret_or_executable_metadata_keys_are_rejected(key):
    with pytest.raises(ValidationError):
        MetadataEntry(key=key, value="SYNTHETIC_SECRET")


def test_secret_bearing_public_text_is_rejected_instead_of_silently_redacted():
    with pytest.raises(ValidationError, match="public-safe"):
        ProvenanceRecord(
            provenance_id="prov-1",
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="test",
            producer_version="v1",
            summary="Authorization: Bearer SYNTHETIC_SECRET",
            occurred_at=TS,
        )


def test_opaque_vault_references_are_accepted_without_materialization():
    session = SessionRef(
        session_ref_id="session-1",
        identity_id="identity-1",
        vault_reference="cred_0123456789abcdef0123",
        lifecycle=SessionLifecycle.active,
        provenance_id="prov-1",
    )
    rendered = session.model_dump_json()
    assert "cred_0123456789abcdef0123" in rendered
    assert "SYNTHETIC_SECRET" not in rendered


def test_observation_cannot_claim_vulnerability_or_verification():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Observation(
            observation_id="observation-1",
            observation_type="response-shape",
            summary="A response shape was observed.",
            target_id="target-1",
            evidence_references=("evidence-1",),
            provenance_id="prov-1",
            vulnerable=True,
        )


def test_fact_uses_typed_predicate_object_and_lifecycle():
    fact = Fact(
        fact_id="fact-1",
        subject=EntityReference(
            entity_kind=EntityKind.endpoint, entity_id="endpoint-1"
        ),
        predicate=ResearchPredicate.returns,
        object=ScalarFactObject(value="Project"),
        status=FactStatus.proposed,
        evidence_references=("evidence-1",),
        derivation_type=DerivationType.model_proposed,
        provenance_id="prov-1",
    )
    assert fact.status is FactStatus.proposed
    assert not hasattr(fact, "model_truth")


def test_superseded_fact_requires_a_distinct_reference():
    with pytest.raises(ValidationError, match="requires"):
        Fact(
            fact_id="fact-1",
            subject=EntityReference(
                entity_kind=EntityKind.endpoint, entity_id="endpoint-1"
            ),
            predicate=ResearchPredicate.returns,
            object=ScalarFactObject(value="Project"),
            status=FactStatus.superseded,
            evidence_references=("evidence-1",),
            derivation_type=DerivationType.deterministic,
            provenance_id="prov-1",
        )


@pytest.mark.parametrize(
    ("status", "derivation"),
    (
        (FactStatus.observed, DerivationType.model_proposed),
        (FactStatus.confirmed, DerivationType.model_proposed),
        (FactStatus.confirmed, DerivationType.researcher_asserted),
    ),
)
def test_only_deterministic_stages_can_promote_or_confirm_facts(status, derivation):
    with pytest.raises(ValidationError):
        Fact(
            fact_id="fact-1",
            subject=EntityReference(
                entity_kind=EntityKind.endpoint, entity_id="endpoint-1"
            ),
            predicate=ResearchPredicate.returns,
            object=ScalarFactObject(value="Project"),
            status=status,
            evidence_references=("evidence-1",),
            derivation_type=derivation,
            provenance_id="prov-1",
        )


def test_model_proposed_relationship_cannot_claim_observed_status():
    with pytest.raises(ValidationError, match="must remain proposed"):
        Relationship(
            relationship_id="relationship-1",
            source=EntityReference(
                entity_kind=EntityKind.identity, entity_id="identity-1"
            ),
            predicate=ResearchPredicate.owns,
            target=EntityReference(entity_kind=EntityKind.object, entity_id="object-1"),
            status=RelationshipStatus.observed,
            evidence_references=("evidence-1",),
            derivation_type=DerivationType.model_proposed,
            provenance_id="prov-1",
        )


def test_hypothesis_support_and_refutation_require_corresponding_evidence():
    base = {
        "hypothesis_id": "hypothesis-1",
        "category": "authorization",
        "title": "Controlled authorization hypothesis.",
        "claim": "A controlled identity may cross the recorded boundary.",
        "target_id": "target-1",
        "priority": 80,
        "confidence": ResearchConfidence.medium,
        "confirmation_policy_reference": "policy-1",
        "provenance_id": "prov-1",
    }
    with pytest.raises(ValidationError, match="supporting evidence"):
        HypothesisRecord(**base, status=HypothesisResearchStatus.supported)
    with pytest.raises(ValidationError, match="refuting evidence"):
        HypothesisRecord(**base, status=HypothesisResearchStatus.refuted)


def test_hypothesis_pivots_cannot_exceed_attempts():
    with pytest.raises(ValidationError, match="pivot_count"):
        HypothesisRecord(
            hypothesis_id="hypothesis-1",
            category="authorization",
            title="Controlled authorization hypothesis.",
            claim="A controlled identity may cross the recorded boundary.",
            target_id="target-1",
            status=HypothesisResearchStatus.inconclusive,
            priority=80,
            confidence=ResearchConfidence.medium,
            confirmation_policy_reference="policy-1",
            attempt_count=1,
            pivot_count=2,
            provenance_id="prov-1",
        )


def test_experiment_outcome_reuses_authoritative_accounting_types():
    outcome = ExperimentOutcome(
        outcome_id="outcome-1",
        experiment_id="experiment-1",
        runtime_status=ExperimentRuntimeStatus.blocked,
        canonical_result_classification=Phase2ResultStatus.policy_blocked,
        request_delta=RequestDelta(),
        model_usage_delta=ModelUsageDelta(),
        cleanup_status=CleanupStatus.not_required,
        provenance_id="prov-1",
        occurred_at=TS,
    )
    assert type(outcome.request_delta) is RequestDelta
    assert type(outcome.model_usage_delta) is ModelUsageDelta


def finding(**changes: object) -> FindingRecord:
    values: dict[str, object] = {
        "finding_id": "finding-1",
        "status": FindingStatus.candidate,
        "title": "Controlled candidate finding.",
        "category": "authorization",
        "source_hypothesis_id": "hypothesis-1",
        "candidate_experiment_id": "experiment-1",
        "confirmation_policy_reference": "policy-1",
        "evidence_references": ("evidence-1",),
        "cleanup_status": CleanupStatus.not_required,
        "provenance_id": "prov-1",
    }
    values.update(changes)
    return FindingRecord.model_validate(values)


def test_confirmed_finding_requires_reproduction():
    with pytest.raises(ValidationError, match="reproduction"):
        finding(
            status=FindingStatus.confirmed,
            controlled_impact=ControlledImpact(
                level=ImpactLevel.limited,
                summary="Controlled impact was observed.",
                evidence_references=("evidence-1",),
            ),
        )


def test_confirmed_finding_requires_controlled_impact():
    with pytest.raises(ValidationError, match="controlled impact"):
        finding(
            status=FindingStatus.confirmed,
            reproduction_experiment_ids=("experiment-2",),
        )


def test_confirmed_finding_requires_completed_cleanup():
    with pytest.raises(ValidationError, match="completed cleanup"):
        finding(
            status=FindingStatus.confirmed,
            reproduction_experiment_ids=("experiment-2",),
            controlled_impact=ControlledImpact(
                level=ImpactLevel.limited,
                summary="Controlled impact was observed.",
                evidence_references=("evidence-1",),
            ),
            cleanup_status=CleanupStatus.pending,
        )


def test_valid_confirmed_finding_satisfies_structural_invariants():
    result = finding(
        status=FindingStatus.confirmed,
        reproduction_experiment_ids=("experiment-2",),
        controlled_impact=ControlledImpact(
            level=ImpactLevel.limited,
            summary="Controlled impact was observed.",
            evidence_references=("evidence-1",),
        ),
    )
    assert result.status is FindingStatus.confirmed


def test_rejected_finding_requires_contradictory_evidence():
    with pytest.raises(ValidationError, match="contradictory evidence"):
        finding(status=FindingStatus.rejected)


@pytest.mark.parametrize(
    "changes",
    (
        {"experiments_consumed": 11},
        {"wall_time_consumed_seconds": 301.0},
        {"state_changes_consumed": 3},
    ),
)
def test_budget_state_rejects_consumption_overrun(changes):
    values = {
        "budget_reference": "budget-1",
        "experiment_ceiling": 10,
        "experiments_consumed": 1,
        "request_budget": RequestBudgetSnapshot(
            ledger_reference="request-ledger-1", limit=10, remaining=10
        ),
        "model_budget": ModelBudgetSnapshot(
            ledger_reference="model-ledger-1",
            max_calls=5,
            remaining_calls=5,
        ),
        "wall_time_ceiling_seconds": 300.0,
        "wall_time_consumed_seconds": 1.0,
        "state_change_ceiling": 2,
        "state_changes_consumed": 0,
        "cleanup_request_reserve": 1,
        "cleanup_status": CleanupStatus.reserved,
    }
    values.update(changes)
    with pytest.raises(ValidationError):
        BudgetState.model_validate(values)


def test_research_state_revision_bounds_are_strict():
    with pytest.raises(ValidationError):
        minimal_state(revision=-1)
    with pytest.raises(ValidationError):
        minimal_state(revision=True)


def test_duplicate_entity_ids_are_rejected():
    prov = provenance()
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="authorized-target",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        provenance_id=prov.provenance_id,
    )
    with pytest.raises(ValidationError, match="targets IDs"):
        minimal_state(targets=(target, target), provenance=(prov,))


@pytest.mark.parametrize(
    "changes",
    (
        {
            "surfaces": (
                Surface(
                    surface_id="surface-1",
                    target_id="missing-target",
                    surface_type=SurfaceType.rest,
                    label="REST surface.",
                    provenance_id="prov-1",
                ),
            )
        },
        {
            "session_refs": (
                SessionRef(
                    session_ref_id="session-1",
                    identity_id="missing-identity",
                    vault_reference="cred_0123456789abcdef0123",
                    lifecycle=SessionLifecycle.active,
                    provenance_id="prov-1",
                ),
            )
        },
    ),
)
def test_dangling_critical_references_are_rejected(changes):
    with pytest.raises(ValidationError, match="dangling"):
        minimal_state(provenance=(provenance(),), **changes)


def test_state_canonicalizes_logically_unordered_entities():
    first = provenance("prov-a")
    second = provenance("prov-b")
    target_a = TargetAsset(
        target_id="target-a",
        canonical_reference="target-a",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        provenance_id=first.provenance_id,
    )
    target_b = TargetAsset(
        target_id="target-b",
        canonical_reference="target-b",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        provenance_id=second.provenance_id,
    )
    left = minimal_state(targets=(target_b, target_a), provenance=(second, first))
    right = minimal_state(targets=(target_a, target_b), provenance=(first, second))
    assert canonical_research_state_bytes(left) == canonical_research_state_bytes(right)
    assert research_state_hash(left) == research_state_hash(right)


def test_unordered_reference_sets_are_canonicalized():
    left = TargetAsset(
        target_id="target-1",
        canonical_reference="target-1",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        evidence_references=("evidence-b", "evidence-a"),
        provenance_id="prov-1",
    )
    right = TargetAsset(
        target_id="target-1",
        canonical_reference="target-1",
        target_class=TargetClass.local_range,
        scope_reference="scope-1",
        evidence_references=("evidence-a", "evidence-b"),
        provenance_id="prov-1",
    )
    assert left == right


def test_canonical_serialization_and_hash_are_repeatable():
    state = populated_state()
    assert canonical_research_state_bytes(state) == canonical_research_state_bytes(
        state
    )
    assert research_state_hash(state) == research_state_hash(state)
    assert research_state_hash(state).startswith("sha256:")


def test_no_chain_of_thought_or_scratchpad_fields_exist():
    schema = json.dumps(ResearchState.model_json_schema(), sort_keys=True).lower()
    assert "chain_of_thought" not in schema
    assert "chain-of-thought" not in schema
    assert "scratchpad" not in schema


def test_research_contracts_expose_no_execution_authority_fields():
    contract_types = (
        ResearchState,
        ExperimentOutcome,
        HypothesisRecord,
        FindingRecord,
        Fact,
        Observation,
    )
    forbidden = {
        "callback",
        "callable",
        "command",
        "execute",
        "executor",
        "headers",
        "raw_request",
        "request_body",
        "script",
        "shell",
        "tool",
    }
    fields = {
        field_name
        for contract in contract_types
        for field_name in contract.model_fields
    }
    assert not fields & forbidden


def test_metadata_is_sorted_and_duplicate_keys_are_rejected():
    metadata = PublicMetadata(
        entries=(
            MetadataEntry(key="zeta", value=2),
            MetadataEntry(key="alpha", value=True),
        )
    )
    assert [entry.key for entry in metadata.entries] == ["alpha", "zeta"]
    with pytest.raises(ValidationError, match="unique"):
        PublicMetadata(
            entries=(
                MetadataEntry(key="same", value=1),
                MetadataEntry(key="same", value=2),
            )
        )
