from __future__ import annotations

from agent_core.agent_models import RiskLevel
from agent_core.research import (
    CandidateBaselineKind,
    CandidateMutationKind,
    CleanupStatus,
    DerivationType,
    DifferentialSelector,
    Endpoint,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceKind,
    ExperimentCandidate,
    Fact,
    FactStatus,
    FindingRecord,
    FindingStatus,
    HttpMethod,
    HypothesisRecord,
    HypothesisResearchStatus,
    Identity,
    IdentityEligibility,
    ProvenanceProducerType,
    ProvenanceRecord,
    ReferenceFactObject,
    Relationship,
    RelationshipStatus,
    RequestIdentityRequirement,
    ResearchConfidence,
    ResearchObject,
    ResearchPredicate,
    ResearchRequestTemplate,
    ResearchRunStatus,
    ResearchState,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
)

TS = "2026-09-25T12:00:00+00:00"
TS_1 = "2026-09-25T12:00:01+00:00"
DIGEST = "sha256:" + "d" * 64


def chain_state(
    *,
    source_type: SurfaceType = SurfaceType.graphql,
    target_type: SurfaceType = SurfaceType.rest,
) -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="prov-chain",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="phase4-chain-test",
        producer_version="v1",
        summary="Deterministic chain fixture provenance.",
        occurred_at=TS,
    )
    evidence = EvidenceArtifact(
        evidence_id="evidence-chain",
        evidence_kind=EvidenceKind.differential,
        digest=DIGEST,
        summary="A controlled object relationship crosses two typed surfaces.",
        source_reference="capture-chain",
        observed_at=TS,
        provenance_id=provenance.provenance_id,
    )
    reproduction_evidence = EvidenceArtifact(
        evidence_id="evidence-chain-reproduction",
        evidence_kind=EvidenceKind.differential,
        digest="sha256:" + "f" * 64,
        summary="A fresh ordered chain reproduction was observed.",
        source_reference="runtime-chain-reproduction",
        observed_at=TS_1,
        provenance_id=provenance.provenance_id,
    )
    target = TargetAsset(
        target_id="target-chain",
        canonical_reference="authorized-chain-fixture",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-chain",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    source = Surface(
        surface_id="surface-source",
        target_id=target.target_id,
        surface_type=source_type,
        label="Controlled source surface.",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    destination = Surface(
        surface_id="surface-destination",
        target_id=target.target_id,
        surface_type=target_type,
        label="Controlled destination surface.",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    endpoint = Endpoint(
        endpoint_id="endpoint-protected",
        target_id=target.target_id,
        surface_id=destination.surface_id,
        method=HttpMethod.get,
        route_template="/controlled/{reference}",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    template = ResearchRequestTemplate(
        template_id="template-protected",
        target_id=target.target_id,
        surface_id=destination.surface_id,
        endpoint_id=endpoint.endpoint_id,
        method=endpoint.method,
        route_reference=endpoint.route_template,
        identity_requirement=RequestIdentityRequirement(
            required=True, mechanisms=("authorization_header",)
        ),
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    identity = Identity(
        identity_id="identity-controlled",
        account_reference="account-controlled",
        role_reference="member",
        tenant_reference="tenant-controlled",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id=provenance.provenance_id,
    )
    obj = ResearchObject(
        object_id="object-controlled",
        target_id=target.target_id,
        surface_id=source.surface_id,
        object_type="ControlledRecord",
        object_reference="object-reference",
        owner_identity_id=identity.identity_id,
        tenant_reference="tenant-controlled",
        test_owned=True,
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    fact = Fact(
        fact_id="fact-source-object",
        subject=EntityReference(entity_kind=EntityKind.object, entity_id=obj.object_id),
        predicate=ResearchPredicate.references,
        object=ReferenceFactObject(
            reference=EntityReference(
                entity_kind=EntityKind.surface, entity_id=source.surface_id
            )
        ),
        status=FactStatus.confirmed,
        evidence_references=(evidence.evidence_id,),
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance.provenance_id,
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-destination-authz",
        category="object-authorization",
        title="Destination authorization boundary hypothesis.",
        claim="The destination operation may mishandle a controlled object context.",
        target_id=target.target_id,
        surface_id=destination.surface_id,
        status=HypothesisResearchStatus.proposed,
        priority=70,
        confidence=ResearchConfidence.medium,
        confirmation_policy_reference="policy-chain",
        supporting_evidence=(evidence.evidence_id,),
        basis_fact_ids=(fact.fact_id,),
        provenance_id=provenance.provenance_id,
    )
    relationship = Relationship(
        relationship_id="relationship-context-enables-test",
        source=EntityReference(entity_kind=EntityKind.fact, entity_id=fact.fact_id),
        predicate=ResearchPredicate.produces_context_for,
        target=EntityReference(
            entity_kind=EntityKind.hypothesis,
            entity_id=hypothesis.hypothesis_id,
        ),
        status=RelationshipStatus.confirmed,
        evidence_references=(evidence.evidence_id,),
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance.provenance_id,
    )
    return ResearchState(
        research_id="research-chain",
        revision=0,
        status=ResearchRunStatus.chaining,
        created_at=TS,
        updated_at=TS,
        targets=(target,),
        surfaces=(source, destination),
        endpoints=(endpoint,),
        request_templates=(template,),
        identities=(identity,),
        objects=(obj,),
        evidence=(evidence, reproduction_evidence),
        facts=(fact,),
        relationships=(relationship,),
        hypotheses=(hypothesis,),
        provenance=(provenance,),
    )


def experiment_candidate(state: ResearchState) -> ExperimentCandidate:
    return ExperimentCandidate(
        candidate_id="experiment-candidate-chain",
        research_id=state.research_id,
        state_revision=state.revision,
        hypothesis_id="hypothesis-destination-authz",
        capability="object-authorization",
        primitive_kind="authentication_differential",
        target_id="target-chain",
        surface_id="surface-destination",
        endpoint_id="endpoint-protected",
        request_template_id="template-protected",
        primary_identity_id="identity-controlled",
        baseline_kind=CandidateBaselineKind.registered_request,
        mutation_kind=CandidateMutationKind.authentication_differential,
        expected_evidence_class=DifferentialSelector.status_class,
        minimum_requests=2,
        worst_case_requests=2,
        risk_class=RiskLevel.low,
        information_predicates=("predicate:bounded-chain-link",),
        evidence_references=("evidence-chain",),
        provenance_references=("prov-chain",),
        fingerprint_seed="sha256:" + "e" * 64,
    )


def unrelated_findings_state() -> ResearchState:
    state = chain_state()
    hypothesis = state.hypotheses[0]
    findings = tuple(
        FindingRecord(
            finding_id=f"finding-unrelated-{index}",
            status=FindingStatus.candidate,
            title=f"Unrelated confirmed finding {index}.",
            category=f"unrelated-{index}",
            source_hypothesis_id=hypothesis.hypothesis_id,
            candidate_experiment_id=f"experiment-unrelated-{index}",
            confirmation_policy_reference="policy-chain",
            evidence_references=("evidence-chain",),
            cleanup_status=CleanupStatus.not_required,
            provenance_id="prov-chain",
        )
        for index in (1, 2)
    )
    payload = state.model_dump(mode="python")
    payload.update(relationships=(), findings=findings)
    return ResearchState.model_validate(payload)
