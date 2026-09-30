"""Typed, immutable Phase 4 research-state snapshot contracts."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import (
    AliasChoices,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    model_validator,
)

from agent_core.models import ModelUsageDelta
from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta
from agent_core.research.graphql import (
    MAX_GRAPHQL_ARGUMENTS_PER_FIELD,
    MAX_GRAPHQL_ARGUMENTS,
    MAX_GRAPHQL_FIELDS,
    MAX_GRAPHQL_FIELDS_PER_TYPE,
    MAX_GRAPHQL_OPERATIONS,
    MAX_GRAPHQL_SURFACES,
    MAX_GRAPHQL_TYPES_PER_SURFACE,
    MAX_GRAPHQL_TYPES,
    MAX_GRAPHQL_VARIABLES_PER_OPERATION,
    MAX_GRAPHQL_VARIABLES,
    GraphQLArgumentRecord,
    GraphQLFieldRecord,
    GraphQLOperationRecord,
    GraphQLSurface,
    GraphQLTypeKind,
    GraphQLTypeRecord,
    GraphQLVariableRecord,
)
from agent_core.research.primitives import PrimitiveStepProposal
from agent_core.research.chains import (
    AttackChainCandidate,
    AttackChainEvaluation,
    AttackChainHypothesis,
    AttackChainStepKind,
    ChainBudgetState,
    ChainConfirmationDecision,
    ChainReproductionOutcome,
    ChainReproductionPlan,
    ChainStepOutcome,
    MAX_CHAIN_DEPTH,
    UnresolvedChainLink,
    enforce_chain_public_boundary,
    stable_chain_digest,
)
from agent_core.research.types import (
    AttackChainId,
    AttackChainStatus,
    CleanupStatus,
    DerivationType,
    EndpointId,
    EntityKind,
    EntityReference,
    EvidenceArtifactId,
    EvidenceKind,
    ExperimentId,
    ExperimentOutcomeId,
    ExperimentRuntimeStatus,
    FactId,
    FactObject,
    FactStatus,
    FindingId,
    FindingConfirmationAction,
    FindingStatus,
    GraphQLArgumentId,
    GraphQLFieldId,
    GraphQLOperationId,
    GraphQLOperationType,
    HttpMethod,
    HypothesisRecordId,
    HypothesisResearchStatus,
    IdentityEligibility,
    IdentityId,
    ImpactLevel,
    ObservationId,
    OpaqueIdentifier,
    ParameterId,
    ParameterLocation,
    ProvenanceProducerType,
    ProvenanceRecordId,
    PublicMetadata,
    PublicText,
    RelationshipId,
    RelationshipStatus,
    ResearchConfidence,
    ResearchContract,
    ResearchExperimentStatus,
    ResearchId,
    ResearchObjectId,
    ResearchPredicate,
    ReproductionClassification,
    ReproductionIndependentDimension,
    ReproductionKind,
    ReproductionPlanStatus,
    ResearchRunStatus,
    SessionLifecycle,
    SessionRefId,
    Sha256Digest,
    ShortPublicText,
    SurfaceId,
    SurfaceType,
    TargetAssetId,
    TargetClass,
    Timestamp,
    TokenKind,
    TokenLifecycle,
    TokenRefId,
    UploadArtifactId,
    UploadLifecycle,
    VaultReference,
    WorkflowId,
)

RESEARCH_STATE_SCHEMA_VERSION = 1


def _unique(values: tuple[str, ...], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")


def _canonical_references(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    _unique(values, field_name)
    return tuple(sorted(values))


class ProvenanceRecord(ResearchContract):
    provenance_id: ProvenanceRecordId
    producer_type: ProvenanceProducerType
    producer_name: OpaqueIdentifier
    producer_version: OpaqueIdentifier
    source_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    parent_provenance_id: ProvenanceRecordId | None = None
    summary: ShortPublicText
    occurred_at: Timestamp
    metadata: PublicMetadata = Field(default_factory=PublicMetadata)

    @model_validator(mode="after")
    def validate_references(self) -> "ProvenanceRecord":
        object.__setattr__(
            self,
            "source_references",
            _canonical_references(self.source_references, "source_references"),
        )
        if self.parent_provenance_id == self.provenance_id:
            raise ValueError("provenance cannot be its own parent")
        return self


class TargetAsset(ResearchContract):
    target_id: TargetAssetId
    canonical_reference: PublicText
    target_class: TargetClass
    scope_reference: OpaqueIdentifier
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    provenance_id: ProvenanceRecordId
    metadata: PublicMetadata = Field(default_factory=PublicMetadata)

    @model_validator(mode="after")
    def validate_evidence(self) -> "TargetAsset":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class Surface(ResearchContract):
    surface_id: SurfaceId
    target_id: TargetAssetId
    surface_type: SurfaceType
    label: ShortPublicText
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    provenance_id: ProvenanceRecordId
    metadata: PublicMetadata = Field(default_factory=PublicMetadata)

    @model_validator(mode="after")
    def validate_evidence(self) -> "Surface":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class Endpoint(ResearchContract):
    endpoint_id: EndpointId
    target_id: TargetAssetId
    surface_id: SurfaceId
    method: HttpMethod
    route_template: PublicText
    content_types: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=30)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_collections(self) -> "Endpoint":
        object.__setattr__(
            self,
            "content_types",
            _canonical_references(self.content_types, "content_types"),
        )
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class Parameter(ResearchContract):
    parameter_id: ParameterId
    endpoint_id: EndpointId
    name: OpaqueIdentifier
    location: ParameterLocation
    data_type: OpaqueIdentifier | None = None
    required: StrictBool | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_evidence(self) -> "Parameter":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class RequestIdentityRequirement(ResearchContract):
    """Structural authentication metadata without credential material."""

    required: StrictBool = False
    mechanisms: tuple[Literal["authorization_header", "cookie"], ...] = Field(
        default=(), max_length=2
    )
    role_reference: OpaqueIdentifier | None = None
    tenant_bound: StrictBool = False

    @model_validator(mode="after")
    def validate_mechanisms(self) -> "RequestIdentityRequirement":
        object.__setattr__(
            self,
            "mechanisms",
            _canonical_references(self.mechanisms, "identity mechanisms"),
        )
        if self.mechanisms and not self.required:
            raise ValueError("identity mechanisms require an identity")
        return self


class ResearchRequestTemplate(ResearchContract):
    """Persistent, secret-free structural request registration."""

    template_id: OpaqueIdentifier
    target_id: TargetAssetId
    surface_id: SurfaceId
    endpoint_id: EndpointId
    method: HttpMethod
    route_reference: PublicText
    parameter_ids: tuple[ParameterId, ...] = Field(default=(), max_length=100)
    body_shape_reference: OpaqueIdentifier | None = None
    content_type: OpaqueIdentifier | None = None
    identity_requirement: RequestIdentityRequirement = Field(
        default_factory=RequestIdentityRequirement
    )
    source_capture_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_collections(self) -> "ResearchRequestTemplate":
        for field_name in (
            "parameter_ids",
            "source_capture_references",
            "evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        return self


class Identity(ResearchContract):
    identity_id: IdentityId
    account_reference: OpaqueIdentifier
    role_reference: OpaqueIdentifier | None = None
    tenant_reference: OpaqueIdentifier | None = None
    controlled: StrictBool
    eligibility: IdentityEligibility
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def controlled_eligibility(self) -> "Identity":
        if not self.controlled and self.eligibility is IdentityEligibility.eligible:
            raise ValueError("an uncontrolled identity cannot be execution-eligible")
        return self


class SessionRef(ResearchContract):
    session_ref_id: SessionRefId
    identity_id: IdentityId
    vault_reference: VaultReference
    lifecycle: SessionLifecycle
    issued_at: Timestamp | None = None
    expires_at: Timestamp | None = None
    provenance_id: ProvenanceRecordId


class TokenRef(ResearchContract):
    token_ref_id: TokenRefId
    identity_id: IdentityId
    vault_reference: VaultReference
    token_kind: TokenKind
    lifecycle: TokenLifecycle
    issuer_reference: OpaqueIdentifier | None = None
    audience_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=30)
    expires_at: Timestamp | None = None
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_audiences(self) -> "TokenRef":
        object.__setattr__(
            self,
            "audience_references",
            _canonical_references(self.audience_references, "audience_references"),
        )
        return self


class ResearchObject(ResearchContract):
    object_id: ResearchObjectId
    target_id: TargetAssetId
    surface_id: SurfaceId
    object_type: OpaqueIdentifier
    object_reference: OpaqueIdentifier
    owner_identity_id: IdentityId | None = None
    tenant_reference: OpaqueIdentifier | None = None
    test_owned: StrictBool
    parameter_references: tuple[ParameterId, ...] = Field(default=(), max_length=100)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_evidence(self) -> "ResearchObject":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        if self.test_owned and self.owner_identity_id is None:
            raise ValueError("a test-owned object requires an owner identity")
        object.__setattr__(
            self,
            "parameter_references",
            _canonical_references(
                self.parameter_references, "object parameter references"
            ),
        )
        return self


class GraphQLOperation(ResearchContract):
    operation_id: GraphQLOperationId
    surface_id: SurfaceId
    endpoint_id: EndpointId
    operation_name: OpaqueIdentifier
    operation_type: GraphQLOperationType
    root_fields: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=100)
    variable_parameter_ids: tuple[ParameterId, ...] = Field(default=(), max_length=100)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_collections(self) -> "GraphQLOperation":
        object.__setattr__(
            self,
            "root_fields",
            _canonical_references(self.root_fields, "root_fields"),
        )
        object.__setattr__(
            self,
            "variable_parameter_ids",
            _canonical_references(
                self.variable_parameter_ids, "variable_parameter_ids"
            ),
        )
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class UploadArtifact(ResearchContract):
    upload_id: UploadArtifactId
    surface_id: SurfaceId
    endpoint_id: EndpointId
    owner_identity_id: IdentityId
    fixture_reference: OpaqueIdentifier
    media_type: OpaqueIdentifier
    lifecycle: UploadLifecycle
    test_owned: Literal[True] = True
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_evidence(self) -> "UploadArtifact":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class WorkflowStep(ResearchContract):
    step_id: OpaqueIdentifier
    sequence: StrictInt = Field(ge=1, le=100)
    endpoint_id: EndpointId | None = None
    method: HttpMethod | None = None
    state_before_reference: OpaqueIdentifier | None = None
    state_after_reference: OpaqueIdentifier | None = None
    state_changing: StrictBool


class Workflow(ResearchContract):
    workflow_id: WorkflowId
    surface_id: SurfaceId
    name: ShortPublicText
    steps: tuple[WorkflowStep, ...] = Field(min_length=1, max_length=100)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=200
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_steps(self) -> "Workflow":
        step_ids = tuple(step.step_id for step in self.steps)
        sequences = tuple(step.sequence for step in self.steps)
        _unique(step_ids, "workflow step IDs")
        if len(sequences) != len(set(sequences)):
            raise ValueError("workflow step sequences must be unique")
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        object.__setattr__(
            self, "steps", tuple(sorted(self.steps, key=lambda x: x.sequence))
        )
        return self


class EvidenceArtifact(ResearchContract):
    evidence_id: EvidenceArtifactId
    evidence_kind: EvidenceKind
    digest: Sha256Digest
    summary: PublicText
    source_reference: OpaqueIdentifier
    observed_at: Timestamp
    provenance_id: ProvenanceRecordId
    metadata: PublicMetadata = Field(default_factory=PublicMetadata)


class Observation(ResearchContract):
    observation_id: ObservationId
    observation_type: OpaqueIdentifier
    classification: Literal["observation"] = "observation"
    summary: PublicText
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_evidence(self) -> "Observation":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class Fact(ResearchContract):
    fact_id: FactId
    subject: EntityReference
    predicate: ResearchPredicate
    object: FactObject
    status: FactStatus
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    derivation_type: DerivationType
    supersedes_fact_id: FactId | None = None
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "Fact":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        if (
            self.derivation_type is DerivationType.model_proposed
            and self.status is not FactStatus.proposed
        ):
            raise ValueError("a model-proposed fact must remain proposed")
        if self.status is FactStatus.confirmed and self.derivation_type is not (
            DerivationType.deterministic
        ):
            raise ValueError("a confirmed fact requires deterministic derivation")
        if self.status is FactStatus.superseded and self.supersedes_fact_id is None:
            raise ValueError("a superseded fact requires the replacing fact reference")
        if self.supersedes_fact_id == self.fact_id:
            raise ValueError("a fact cannot supersede itself")
        return self


class Relationship(ResearchContract):
    relationship_id: RelationshipId
    source: EntityReference
    predicate: ResearchPredicate
    target: EntityReference
    status: RelationshipStatus
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    derivation_type: DerivationType
    supersedes_relationship_id: RelationshipId | None = None
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "Relationship":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        if (
            self.derivation_type is DerivationType.model_proposed
            and self.status is not RelationshipStatus.proposed
        ):
            raise ValueError("a model-proposed relationship must remain proposed")
        if self.status is RelationshipStatus.confirmed and self.derivation_type is not (
            DerivationType.deterministic
        ):
            raise ValueError(
                "a confirmed relationship requires deterministic derivation"
            )
        if (
            self.status is RelationshipStatus.superseded
            and self.supersedes_relationship_id is None
        ):
            raise ValueError(
                "a superseded relationship requires the replacing relationship reference"
            )
        if self.supersedes_relationship_id == self.relationship_id:
            raise ValueError("a relationship cannot supersede itself")
        return self


class HypothesisRecord(ResearchContract):
    hypothesis_id: HypothesisRecordId
    category: OpaqueIdentifier
    title: ShortPublicText
    claim: PublicText
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    status: HypothesisResearchStatus
    priority: StrictInt = Field(ge=0, le=100)
    confidence: ResearchConfidence
    confirmation_policy_reference: OpaqueIdentifier
    supporting_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    refuting_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    attempt_count: StrictInt = Field(default=0, ge=0, le=100)
    pivot_count: StrictInt = Field(default=0, ge=0, le=100)
    experiment_references: tuple[ExperimentId, ...] = Field(default=(), max_length=100)
    limitations: tuple[ShortPublicText, ...] = Field(default=(), max_length=50)
    derivation_type: DerivationType = DerivationType.deterministic
    basis_fact_ids: tuple[FactId, ...] = Field(default=(), max_length=100)
    basis_relationship_ids: tuple[RelationshipId, ...] = Field(
        default=(), max_length=100
    )
    security_property: OpaqueIdentifier | None = None
    entity_references: tuple[EntityReference, ...] = Field(default=(), max_length=50)
    missing_evidence: tuple[ShortPublicText, ...] = Field(default=(), max_length=50)
    required_preconditions: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=50
    )
    requires_state_change: StrictBool = False
    semantic_fingerprint: Sha256Digest | None = None
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "HypothesisRecord":
        object.__setattr__(
            self,
            "supporting_evidence",
            _canonical_references(self.supporting_evidence, "supporting_evidence"),
        )
        object.__setattr__(
            self,
            "refuting_evidence",
            _canonical_references(self.refuting_evidence, "refuting_evidence"),
        )
        object.__setattr__(
            self,
            "experiment_references",
            _canonical_references(self.experiment_references, "experiment_references"),
        )
        object.__setattr__(self, "limitations", tuple(sorted(self.limitations)))
        object.__setattr__(
            self,
            "basis_fact_ids",
            _canonical_references(self.basis_fact_ids, "basis_fact_ids"),
        )
        object.__setattr__(
            self,
            "basis_relationship_ids",
            _canonical_references(
                self.basis_relationship_ids, "basis_relationship_ids"
            ),
        )
        rendered_references = tuple(
            sorted(
                self.entity_references,
                key=lambda item: (item.entity_kind.value, item.entity_id),
            )
        )
        if len(rendered_references) != len(
            {(item.entity_kind, item.entity_id) for item in rendered_references}
        ):
            raise ValueError("hypothesis entity references must not contain duplicates")
        object.__setattr__(self, "entity_references", rendered_references)
        object.__setattr__(
            self, "missing_evidence", tuple(sorted(set(self.missing_evidence)))
        )
        object.__setattr__(
            self,
            "required_preconditions",
            _canonical_references(
                self.required_preconditions, "required_preconditions"
            ),
        )
        if self.derivation_type is DerivationType.model_proposed and (
            self.status is not HypothesisResearchStatus.proposed
        ):
            raise ValueError("a model-proposed hypothesis must remain proposed")
        if self.pivot_count > self.attempt_count:
            raise ValueError("pivot_count cannot exceed attempt_count")
        if self.attempt_count < len(self.experiment_references):
            raise ValueError("attempt_count cannot undercount experiment references")
        if (
            self.status is HypothesisResearchStatus.supported
            and not self.supporting_evidence
        ):
            raise ValueError("a supported hypothesis requires supporting evidence")
        if (
            self.status is HypothesisResearchStatus.refuted
            and not self.refuting_evidence
        ):
            raise ValueError("a refuted hypothesis requires refuting evidence")
        return self


class ExperimentOutcome(ResearchContract):
    outcome_id: ExperimentOutcomeId
    experiment_id: ExperimentId
    runtime_status: ExperimentRuntimeStatus
    canonical_result_classification: Phase2ResultStatus
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    model_usage_delta: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    cleanup_status: CleanupStatus
    evaluator_result_reference: OpaqueIdentifier | None = None
    created_fact_ids: tuple[FactId, ...] = Field(default=(), max_length=100)
    created_hypothesis_ids: tuple[HypothesisRecordId, ...] = Field(
        default=(), max_length=100
    )
    candidate_finding_ids: tuple[FindingId, ...] = Field(default=(), max_length=100)
    provenance_id: ProvenanceRecordId
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_references(self) -> "ExperimentOutcome":
        for field_name in (
            "evidence_references",
            "created_fact_ids",
            "created_hypothesis_ids",
            "candidate_finding_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        return self


class ReproductionEvidencePredicate(ResearchContract):
    selector: OpaqueIdentifier
    predicate_reference: OpaqueIdentifier
    minimum_artifacts: StrictInt = Field(ge=1, le=20)


class ReproductionProposalTemplate(ResearchContract):
    """Secret-free compiler input persisted for crash-safe materialization."""

    proposal_id: OpaqueIdentifier
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    hypothesis_id: HypothesisRecordId
    capability: OpaqueIdentifier
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    operation_id: GraphQLOperationId | None = None
    objective: ShortPublicText
    primary_identity_id: IdentityId | None = None
    comparison_identity_id: IdentityId | None = None
    primary_session_ref_id: SessionRefId | None = None
    comparison_session_ref_id: SessionRefId | None = None
    identity_relationship: OpaqueIdentifier | None = None
    baseline_kind: OpaqueIdentifier
    baseline_reference_id: OpaqueIdentifier
    mutation_kind: OpaqueIdentifier
    mutation_parameter_id: ParameterId | None = None
    mutation_controlled_object_id: ResearchObjectId | None = None
    mutation_value_source_reference: OpaqueIdentifier | None = None
    expected_secure_behavior: PublicText
    expected_vulnerable_behavior: PublicText
    required_evidence: tuple[ReproductionEvidencePredicate, ...] = Field(
        min_length=1, max_length=20
    )
    rationale: ShortPublicText
    primitive_steps: tuple[PrimitiveStepProposal, ...] = Field(
        min_length=1, max_length=30
    )
    provenance_id: ProvenanceRecordId
    expires_at: Timestamp


class ReproductionPlan(ResearchContract):
    """Durable, inert instructions for one bounded independent reproduction."""

    reproduction_id: OpaqueIdentifier
    finding_id: FindingId
    source_experiment_id: ExperimentId
    source_fingerprint: Sha256Digest
    source_outcome_id: ExperimentOutcomeId
    source_hypothesis_id: HypothesisRecordId
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    category: OpaqueIdentifier
    reproduction_kind: ReproductionKind
    independent_dimension: ReproductionIndependentDimension
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    primary_identity_id: IdentityId | None = None
    comparison_identity_id: IdentityId | None = None
    identity_relationship: OpaqueIdentifier | None = None
    controlled_object_ids: tuple[ResearchObjectId, ...] = Field(
        default=(), max_length=20
    )
    alternate_controlled_object_id: ResearchObjectId | None = None
    required_evidence_predicates: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=20
    )
    maximum_requests: StrictInt = Field(ge=1, le=10_000)
    maximum_attempts: StrictInt = Field(ge=1, le=100)
    state_changing: StrictBool
    cleanup_required: StrictBool
    confirmation_policy_reference: OpaqueIdentifier
    confirmation_policy_fingerprint: Sha256Digest
    provenance_id: ProvenanceRecordId
    expires_at: Timestamp
    status: ReproductionPlanStatus = ReproductionPlanStatus.planned
    compiled_experiment_id: ExperimentId | None = None
    model_decision_id: OpaqueIdentifier | None = None
    proposal_template: ReproductionProposalTemplate

    @model_validator(mode="after")
    def validate_plan(self) -> "ReproductionPlan":
        object.__setattr__(
            self,
            "controlled_object_ids",
            _canonical_references(
                self.controlled_object_ids, "reproduction controlled objects"
            ),
        )
        object.__setattr__(
            self,
            "required_evidence_predicates",
            _canonical_references(
                self.required_evidence_predicates,
                "reproduction evidence predicates",
            ),
        )
        if (
            self.alternate_controlled_object_id is not None
            and self.alternate_controlled_object_id in self.controlled_object_ids
        ):
            raise ValueError("alternate controlled object must be different")
        if self.status is ReproductionPlanStatus.completed and (
            self.compiled_experiment_id is None
        ):
            raise ValueError("completed reproduction plan requires an experiment")
        if self.state_changing != self.cleanup_required:
            raise ValueError("state-changing reproduction requires cleanup")
        if (
            self.proposal_template.research_id != self.research_id
            or self.proposal_template.hypothesis_id != self.source_hypothesis_id
            or self.proposal_template.state_revision != self.state_revision
            or self.proposal_template.provenance_id != self.provenance_id
        ):
            raise ValueError("reproduction proposal template does not match its plan")
        return self


class ReproductionIndependence(ResearchContract):
    """Deterministic proof that a result was not copied from the source."""

    independent_dimension: ReproductionIndependentDimension
    source_outcome_id: ExperimentOutcomeId
    outcome_id: ExperimentOutcomeId
    source_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=200
    )
    reproduction_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=200
    )
    source_authorization_reference: Sha256Digest
    authorization_reference: Sha256Digest
    source_provenance_id: ProvenanceRecordId
    reproduction_provenance_id: ProvenanceRecordId
    new_authorization: StrictBool
    new_target_requests: StrictBool
    new_outcome: StrictBool
    new_evidence: StrictBool
    new_provenance: StrictBool
    reproduction_marker_present: StrictBool

    @property
    def valid(self) -> bool:
        return all(
            (
                self.new_authorization,
                self.new_target_requests,
                self.new_outcome,
                self.new_evidence,
                self.new_provenance,
                self.reproduction_marker_present,
            )
        )

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "ReproductionIndependence":
        for field_name in (
            "source_evidence_references",
            "reproduction_evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        return self


class ReproductionOutcome(ResearchContract):
    reproduction_id: OpaqueIdentifier
    finding_id: FindingId
    experiment_id: ExperimentId
    experiment_outcome_id: ExperimentOutcomeId
    source_experiment_id: ExperimentId
    source_outcome_id: ExperimentOutcomeId
    classification: ReproductionClassification
    category: OpaqueIdentifier
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    security_property_reference: OpaqueIdentifier
    identity_relationship: OpaqueIdentifier | None = None
    controlled_object_ids: tuple[ResearchObjectId, ...] = Field(
        default=(), max_length=20
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    independence: ReproductionIndependence | None = None
    cleanup_status: CleanupStatus
    runtime_provenance_reference: ProvenanceRecordId
    authorization_reference: Sha256Digest
    created_at: Timestamp

    @model_validator(mode="after")
    def validate_outcome(self) -> "ReproductionOutcome":
        for field_name in ("controlled_object_ids", "evidence_references"):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        if self.classification is ReproductionClassification.reproduced:
            if not self.evidence_references:
                raise ValueError("a reproduced outcome requires evidence")
            if self.independence is None or not self.independence.valid:
                raise ValueError("a reproduced outcome requires independence evidence")
        return self


class FindingConfirmationDecision(ResearchContract):
    decision_id: OpaqueIdentifier
    finding_id: FindingId
    research_id: ResearchId
    action: FindingConfirmationAction
    reason_code: OpaqueIdentifier
    confirmation_policy_reference: OpaqueIdentifier
    confirmation_policy_fingerprint: Sha256Digest
    reproduction_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    confirmed_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    conflicting_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    total_request_count: StrictInt = Field(default=0, ge=0, le=1_000_000)
    provenance_id: ProvenanceRecordId
    created_at: Timestamp

    @model_validator(mode="after")
    def canonicalize_references(self) -> "FindingConfirmationDecision":
        for field_name in (
            "reproduction_ids",
            "confirmed_evidence_references",
            "conflicting_evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        if self.action is FindingConfirmationAction.confirm and not (
            self.confirmed_evidence_references
        ):
            raise ValueError("confirmation requires confirmed evidence")
        if self.action is FindingConfirmationAction.reject and not (
            self.conflicting_evidence_references
        ):
            raise ValueError("rejection requires conflicting evidence")
        return self


class ControlledImpact(ResearchContract):
    level: ImpactLevel
    summary: PublicText
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )

    @model_validator(mode="after")
    def validate_evidence(self) -> "ControlledImpact":
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        return self


class FindingRecord(ResearchContract):
    finding_id: FindingId
    status: FindingStatus
    title: ShortPublicText
    category: OpaqueIdentifier
    source_hypothesis_id: HypothesisRecordId
    candidate_experiment_id: ExperimentId
    reproduction_experiment_ids: tuple[ExperimentId, ...] = Field(
        default=(), max_length=20
    )
    confirmation_policy_reference: OpaqueIdentifier
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=200
    )
    controlled_impact: ControlledImpact | None = None
    cleanup_status: CleanupStatus
    contradictory_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    provenance_id: ProvenanceRecordId
    research_id: ResearchId | None = None
    source_experiment_fingerprint: Sha256Digest | None = None
    source_outcome_id: ExperimentOutcomeId | None = None
    source_authorization_reference: Sha256Digest | None = None
    target_id: TargetAssetId | None = None
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    graphql_operation_id: GraphQLOperationId | None = None
    graphql_field_ids: tuple[GraphQLFieldId, ...] = Field(default=(), max_length=64)
    graphql_argument_ids: tuple[GraphQLArgumentId, ...] = Field(
        default=(), max_length=64
    )
    primitive: OpaqueIdentifier | None = None
    capability: OpaqueIdentifier | None = None
    security_property_reference: OpaqueIdentifier | None = None
    controlled_identity_ids: tuple[IdentityId, ...] = Field(default=(), max_length=2)
    controlled_identity_relationship: OpaqueIdentifier | None = None
    controlled_object_ids: tuple[ResearchObjectId, ...] = Field(
        default=(), max_length=20
    )
    expected_secure_behavior: PublicText | None = None
    observed_vulnerable_behavior: PublicText | None = None
    source_request_delta: RequestDelta = Field(default_factory=RequestDelta)
    total_request_count: StrictInt = Field(default=0, ge=0, le=1_000_000)
    reproduction_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    confirmation_decision_id: OpaqueIdentifier | None = None
    confirmation_policy_fingerprint: Sha256Digest | None = None
    confirmed_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    conflicting_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    decision_reason_code: OpaqueIdentifier | None = None
    created_at: Timestamp | None = None
    updated_at: Timestamp | None = None
    state_revision: StrictInt | None = Field(default=None, ge=0, le=1_000_000_000)
    source_chain_id: AttackChainId | None = None
    component_finding_ids: tuple[FindingId, ...] = Field(default=(), max_length=20)
    component_hypothesis_ids: tuple[HypothesisRecordId, ...] = Field(
        default=(), max_length=20
    )
    step_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=300
    )
    combined_impact_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    chain_reproduction_ids: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "FindingRecord":
        object.__setattr__(
            self,
            "reproduction_experiment_ids",
            _canonical_references(
                self.reproduction_experiment_ids, "reproduction_experiment_ids"
            ),
        )
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "evidence_references"),
        )
        object.__setattr__(
            self,
            "contradictory_evidence",
            _canonical_references(
                self.contradictory_evidence, "contradictory_evidence"
            ),
        )
        for field_name in (
            "controlled_identity_ids",
            "controlled_object_ids",
            "graphql_field_ids",
            "graphql_argument_ids",
            "reproduction_ids",
            "confirmed_evidence_references",
            "conflicting_evidence_references",
            "component_finding_ids",
            "component_hypothesis_ids",
            "step_evidence_references",
            "combined_impact_evidence_references",
            "chain_reproduction_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        if self.status is FindingStatus.reproducing and not self.reproduction_ids:
            raise ValueError("a reproducing finding requires a reproduction plan")
        if self.status in {FindingStatus.reproduced, FindingStatus.confirmed} and not (
            self.reproduction_experiment_ids
        ):
            raise ValueError("reproduced or confirmed findings require reproduction")
        if self.status is FindingStatus.confirmed:
            if self.controlled_impact is None:
                raise ValueError(
                    "a confirmed finding requires controlled impact evidence"
                )
            if self.cleanup_status not in {
                CleanupStatus.not_required,
                CleanupStatus.completed,
            }:
                raise ValueError("a confirmed finding requires completed cleanup")
        if self.status is FindingStatus.rejected and not self.contradictory_evidence:
            raise ValueError("a rejected finding requires contradictory evidence")
        if self.total_request_count < self.source_request_delta.total:
            raise ValueError("finding request total cannot undercount source requests")
        if self.source_chain_id is not None:
            if not self.component_hypothesis_ids:
                raise ValueError("a chain finding requires component hypotheses")
            if not self.step_evidence_references:
                raise ValueError("a chain finding requires step evidence")
            if not self.combined_impact_evidence_references:
                raise ValueError("a chain finding requires combined impact evidence")
            if (
                self.status is FindingStatus.confirmed
                and not self.chain_reproduction_ids
            ):
                raise ValueError(
                    "a confirmed chain finding requires chain reproduction"
                )
            enforce_chain_public_boundary(
                self.model_dump(mode="json"), location="chain finding"
            )
        if (
            self.created_at is not None
            and self.updated_at is not None
            and (_as_datetime(self.updated_at) < _as_datetime(self.created_at))
        ):
            raise ValueError("finding update cannot precede creation")
        return self


class AttackChainStep(ResearchContract):
    step_id: OpaqueIdentifier | None = None
    sequence: StrictInt = Field(ge=1, le=MAX_CHAIN_DEPTH)
    step_kind: AttackChainStepKind | None = None
    source_reference: EntityReference | None = None
    target_reference: EntityReference | None = None
    # Pre-P4-0G compatibility. It is normalized into source_reference.
    reference: EntityReference | None = None
    objective: ShortPublicText | None = None
    required_preconditions: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    produced_fact_kind: OpaqueIdentifier | None = None
    consumed_fact_ids: tuple[FactId, ...] = Field(default=(), max_length=100)
    expected_secure_behavior: PublicText | None = None
    expected_chain_behavior: PublicText | None = None
    evidence_requirements: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    unresolved_link_id: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def restrict_reference_kind(self) -> "AttackChainStep":
        source = self.source_reference or self.reference
        if source is None:
            raise ValueError("attack-chain steps require a source reference")
        if (
            self.source_reference is not None
            and self.reference is not None
            and self.source_reference != self.reference
        ):
            raise ValueError("attack-chain source reference aliases disagree")
        allowed = {
            EntityKind.fact,
            EntityKind.relationship,
            EntityKind.hypothesis,
            EntityKind.finding,
            EntityKind.observation,
            EntityKind.experiment_outcome,
            EntityKind.identity,
            EntityKind.session,
            EntityKind.token,
            EntityKind.object,
            EntityKind.surface,
            EntityKind.endpoint,
            EntityKind.parameter,
            EntityKind.graphql_operation,
            EntityKind.upload,
            EntityKind.workflow,
        }
        if source.entity_kind not in allowed:
            raise ValueError(
                "attack-chain steps must reference typed research entities"
            )
        if (
            self.target_reference is not None
            and self.target_reference.entity_kind not in allowed
        ):
            raise ValueError("attack-chain step target is not a typed chain entity")
        kind = self.step_kind
        if kind is None:
            kind = {
                EntityKind.fact: AttackChainStepKind.fact,
                EntityKind.relationship: AttackChainStepKind.relationship,
                EntityKind.finding: AttackChainStepKind.finding,
                EntityKind.experiment_outcome: AttackChainStepKind.experiment,
                EntityKind.identity: AttackChainStepKind.identity_transition,
                EntityKind.session: AttackChainStepKind.identity_transition,
                EntityKind.token: AttackChainStepKind.identity_transition,
                EntityKind.object: AttackChainStepKind.object_transition,
                EntityKind.upload: AttackChainStepKind.object_transition,
                EntityKind.surface: AttackChainStepKind.surface_transition,
                EntityKind.endpoint: AttackChainStepKind.surface_transition,
                EntityKind.parameter: AttackChainStepKind.surface_transition,
                EntityKind.graphql_operation: AttackChainStepKind.surface_transition,
                EntityKind.workflow: AttackChainStepKind.workflow_transition,
            }.get(source.entity_kind, AttackChainStepKind.relationship)
        step_id = self.step_id or (
            "chain-step-"
            + stable_chain_digest(
                {
                    "sequence": self.sequence,
                    "source": source.model_dump(mode="json"),
                    "target": (
                        self.target_reference.model_dump(mode="json")
                        if self.target_reference is not None
                        else None
                    ),
                }
            )[7:31]
        )
        object.__setattr__(self, "step_id", step_id)
        object.__setattr__(self, "step_kind", kind)
        object.__setattr__(self, "source_reference", source)
        object.__setattr__(self, "reference", source)
        for field_name in (
            "required_preconditions",
            "consumed_fact_ids",
            "evidence_requirements",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
            object.__setattr__(self, field_name, tuple(sorted(values)))
        enforce_chain_public_boundary(
            self.model_dump(mode="json"), location="attack-chain step"
        )
        return self


class AttackChain(ResearchContract):
    attack_chain_id: AttackChainId = Field(
        validation_alias=AliasChoices("attack_chain_id", "chain_id")
    )
    research_id: ResearchId | None = None
    state_revision: StrictInt = Field(default=0, ge=0, le=1_000_000_000)
    title: ShortPublicText
    category: OpaqueIdentifier = "cross-surface-chain"
    status: AttackChainStatus
    target_ids: tuple[TargetAssetId, ...] = Field(default=(), max_length=64)
    surface_ids: tuple[SurfaceId, ...] = Field(default=(), max_length=20)
    identity_ids: tuple[IdentityId, ...] = Field(default=(), max_length=20)
    object_ids: tuple[ResearchObjectId, ...] = Field(default=(), max_length=20)
    hypothesis_ids: tuple[HypothesisRecordId, ...] = Field(default=(), max_length=20)
    finding_ids: tuple[FindingId, ...] = Field(default=(), max_length=20)
    fact_ids: tuple[FactId, ...] = Field(default=(), max_length=100)
    relationship_ids: tuple[RelationshipId, ...] = Field(default=(), max_length=100)
    steps: tuple[AttackChainStep, ...] = Field(min_length=2, max_length=MAX_CHAIN_DEPTH)
    entry_condition: PublicText = "Existing evidence establishes the first chain step."
    security_property: PublicText = "A bounded security boundary may be crossed."
    expected_secure_behavior: PublicText = "The security boundary prevents the chain."
    expected_chain_behavior: PublicText = (
        "The ordered links demonstrate combined impact."
    )
    unresolved_links: tuple[UnresolvedChainLink, ...] = Field(default=(), max_length=3)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    provenance_id: ProvenanceRecordId
    confirmation_policy_reference: OpaqueIdentifier = "chain-confirmation-policy-v1"
    semantic_fingerprint: Sha256Digest | None = None
    combined_impact_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    reproduction_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    created_at: Timestamp | None = None
    updated_at: Timestamp | None = None

    @property
    def chain_id(self) -> AttackChainId:
        return self.attack_chain_id

    @model_validator(mode="after")
    def validate_steps(self) -> "AttackChain":
        sequences = tuple(step.sequence for step in self.steps)
        step_ids = tuple(str(step.step_id) for step in self.steps)
        if len(sequences) != len(set(sequences)):
            raise ValueError("attack-chain step sequences must be unique")
        if tuple(sorted(sequences)) != tuple(range(1, len(self.steps) + 1)):
            raise ValueError("attack-chain step sequences must be contiguous")
        _unique(step_ids, "attack-chain step IDs")
        for field_name in (
            "target_ids",
            "surface_ids",
            "identity_ids",
            "object_ids",
            "hypothesis_ids",
            "finding_ids",
            "fact_ids",
            "relationship_ids",
            "evidence_references",
            "combined_impact_evidence",
            "reproduction_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        link_ids = tuple(item.link_id for item in self.unresolved_links)
        _unique(link_ids, "attack-chain unresolved-link IDs")
        object.__setattr__(
            self, "steps", tuple(sorted(self.steps, key=lambda x: x.sequence))
        )
        prior_step_ids: set[str] = set()
        unresolved_link_ids = {item.link_id for item in self.unresolved_links}
        bound_link_ids: list[str] = []
        for current, following in zip(self.steps, self.steps[1:]):
            if (
                current.target_reference is not None
                and current.target_reference != following.source_reference
            ):
                raise ValueError("attack-chain step target breaks ordered continuity")
        for step in self.steps:
            if not set(step.required_preconditions).issubset(prior_step_ids):
                raise ValueError(
                    "attack-chain preconditions must reference earlier chain steps"
                )
            if step.unresolved_link_id is not None:
                if step.unresolved_link_id not in unresolved_link_ids:
                    raise ValueError("attack-chain step references an unavailable link")
                bound_link_ids.append(step.unresolved_link_id)
            prior_step_ids.add(str(step.step_id))
        _unique(tuple(bound_link_ids), "attack-chain bound unresolved links")
        if set(bound_link_ids) != unresolved_link_ids:
            raise ValueError("every unresolved chain link must bind exactly one step")
        if self.status is AttackChainStatus.confirmed and not self.evidence_references:
            raise ValueError("a confirmed attack chain requires evidence")
        if self.status is AttackChainStatus.confirmed and not self.reproduction_ids:
            raise ValueError("a confirmed attack chain requires reproduction")
        if self.status is AttackChainStatus.confirmed and not (
            self.combined_impact_evidence
        ):
            raise ValueError("a confirmed attack chain requires combined impact")
        if (
            self.created_at
            and self.updated_at
            and (_as_datetime(self.updated_at) < _as_datetime(self.created_at))
        ):
            raise ValueError("chain update cannot precede creation")
        fingerprint = stable_chain_digest(
            {
                "category": self.category,
                "ordered_links": [
                    (
                        step.source_reference.entity_kind.value,
                        step.source_reference.entity_id,
                    )
                    for step in self.steps
                ],
                "security_property": self.security_property,
                "surfaces": sorted(self.surface_ids),
                "identities": sorted(self.identity_ids),
                "objects": sorted(self.object_ids),
                "unresolved": [
                    {
                        "from": (
                            item.from_reference.entity_kind.value,
                            item.from_reference.entity_id,
                        ),
                        "to": (
                            item.to_reference.entity_kind.value,
                            item.to_reference.entity_id,
                        ),
                        "capabilities": sorted(item.allowed_experiment_capabilities),
                    }
                    for item in self.unresolved_links
                ],
            }
        )
        if (
            self.semantic_fingerprint is not None
            and self.semantic_fingerprint != fingerprint
        ):
            raise ValueError(
                "attack-chain semantic fingerprint does not match bindings"
            )
        object.__setattr__(self, "semantic_fingerprint", fingerprint)
        enforce_chain_public_boundary(
            self.model_dump(mode="json"), location="attack chain"
        )
        return self


class HypothesisBudgetUsage(ResearchContract):
    hypothesis_id: HypothesisRecordId
    attempt_count: StrictInt = Field(ge=0, le=100)
    pivot_count: StrictInt = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_counts(self) -> "HypothesisBudgetUsage":
        if self.pivot_count > self.attempt_count:
            raise ValueError("hypothesis pivots cannot exceed attempts")
        return self


class SurfaceBudgetUsage(ResearchContract):
    surface_id: SurfaceId
    experiment_count: StrictInt = Field(ge=0, le=10_000)


class ReproductionBudgetUsage(ResearchContract):
    finding_id: FindingId
    attempts_consumed: StrictInt = Field(default=0, ge=0, le=100)
    target_requests_consumed: StrictInt = Field(default=0, ge=0, le=100_000)
    model_calls_consumed: StrictInt = Field(default=0, ge=0, le=100)
    wall_time_consumed_seconds: StrictFloat = Field(
        default=0.0, ge=0.0, le=31_536_000.0
    )
    state_changes_consumed: StrictInt = Field(default=0, ge=0, le=100)
    cleanup_requests_consumed: StrictInt = Field(default=0, ge=0, le=100_000)


class ResearchBootstrapProgress(ResearchContract):
    """Durable bootstrap checkpoint backed by authoritative ledger deltas."""

    bootstrap_id: OpaqueIdentifier
    target_id: TargetAssetId
    discovery_plan_reference: OpaqueIdentifier | None = None
    discovery_completed: StrictBool = False
    modeling_completed: StrictBool = False
    hypothesizing_completed: StrictBool = False
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    model_usage_delta: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    started_at: Timestamp
    updated_at: Timestamp
    limitations: tuple[ShortPublicText, ...] = Field(default=(), max_length=100)
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_progress(self) -> "ResearchBootstrapProgress":
        if self.hypothesizing_completed and not self.modeling_completed:
            raise ValueError("hypothesizing completion requires modeling completion")
        if self.modeling_completed and not self.discovery_completed:
            raise ValueError("modeling completion requires discovery completion")
        if _as_datetime(self.updated_at) < _as_datetime(self.started_at):
            raise ValueError("bootstrap update cannot precede its start")
        object.__setattr__(self, "limitations", tuple(sorted(set(self.limitations))))
        return self


class ResearchExperimentRecord(ResearchContract):
    """Secret-free experiment history retained across process restarts."""

    experiment_id: ExperimentId
    proposal_id: OpaqueIdentifier
    hypothesis_id: HypothesisRecordId
    surface_id: SurfaceId | None = None
    fingerprint: Sha256Digest
    material_fingerprint: Sha256Digest
    status: ResearchExperimentStatus
    result_classification: OpaqueIdentifier | None = None
    relevant_state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    policy_reference: OpaqueIdentifier | None = None
    policy_fingerprint: Sha256Digest | None = None
    request_cost: StrictInt = Field(default=0, ge=0, le=10_000)
    state_changing: StrictBool = False
    reproduction_of: ExperimentId | None = None
    reproduction_finding_id: FindingId | None = None
    reproduction_id: OpaqueIdentifier | None = None
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_reproduction_markers(self) -> "ResearchExperimentRecord":
        markers = (
            self.reproduction_finding_id is not None,
            self.reproduction_id is not None,
        )
        if any(markers) and (self.reproduction_of is None or not all(markers)):
            raise ValueError("research reproduction history markers are incomplete")
        return self


class RequestBudgetSnapshot(ResearchContract):
    ledger_reference: OpaqueIdentifier
    limit: StrictInt = Field(ge=0, le=10_000_000)
    consumed: RequestDelta = Field(default_factory=RequestDelta)
    remaining: StrictInt = Field(ge=0, le=10_000_000)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "RequestBudgetSnapshot":
        if self.consumed.total + self.remaining != self.limit:
            raise ValueError("request budget snapshot must reconcile to its limit")
        return self


class ModelBudgetSnapshot(ResearchContract):
    ledger_reference: OpaqueIdentifier
    max_calls: StrictInt = Field(ge=0, le=1_000_000)
    usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    remaining_calls: StrictInt = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "ModelBudgetSnapshot":
        if self.usage.attempted_calls + self.remaining_calls != self.max_calls:
            raise ValueError("model budget snapshot must reconcile to its call limit")
        return self


class BudgetState(ResearchContract):
    budget_reference: OpaqueIdentifier
    experiment_ceiling: StrictInt = Field(ge=0, le=100_000)
    experiments_consumed: StrictInt = Field(ge=0, le=100_000)
    hypothesis_usage: tuple[HypothesisBudgetUsage, ...] = Field(
        default=(), max_length=5_000
    )
    surface_usage: tuple[SurfaceBudgetUsage, ...] = Field(default=(), max_length=5_000)
    request_budget: RequestBudgetSnapshot
    model_budget: ModelBudgetSnapshot
    wall_time_ceiling_seconds: StrictFloat = Field(ge=0.0, le=31_536_000.0)
    wall_time_consumed_seconds: StrictFloat = Field(ge=0.0, le=31_536_000.0)
    state_change_ceiling: StrictInt = Field(ge=0, le=100_000)
    state_changes_consumed: StrictInt = Field(ge=0, le=100_000)
    cleanup_request_reserve: StrictInt = Field(ge=0, le=100_000)
    cleanup_status: CleanupStatus
    consecutive_service_instability: StrictInt = Field(default=0, ge=0, le=100)
    cleanup_barrier_reference: OpaqueIdentifier | None = None
    reproduction_usage: tuple[ReproductionBudgetUsage, ...] = Field(
        default=(), max_length=2_000
    )

    @model_validator(mode="after")
    def validate_budget(self) -> "BudgetState":
        if self.experiments_consumed > self.experiment_ceiling:
            raise ValueError("experiment consumption exceeds its ceiling")
        if self.wall_time_consumed_seconds > self.wall_time_ceiling_seconds:
            raise ValueError("wall-time consumption exceeds its ceiling")
        if self.state_changes_consumed > self.state_change_ceiling:
            raise ValueError("state-change consumption exceeds its ceiling")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypothesis_usage)
        surface_ids = tuple(item.surface_id for item in self.surface_usage)
        reproduction_finding_ids = tuple(
            item.finding_id for item in self.reproduction_usage
        )
        _unique(hypothesis_ids, "hypothesis_usage IDs")
        _unique(surface_ids, "surface_usage IDs")
        _unique(reproduction_finding_ids, "reproduction_usage finding IDs")
        object.__setattr__(
            self,
            "hypothesis_usage",
            tuple(sorted(self.hypothesis_usage, key=lambda x: x.hypothesis_id)),
        )
        object.__setattr__(
            self,
            "surface_usage",
            tuple(sorted(self.surface_usage, key=lambda x: x.surface_id)),
        )
        object.__setattr__(
            self,
            "reproduction_usage",
            tuple(sorted(self.reproduction_usage, key=lambda x: x.finding_id)),
        )
        return self


class ResearchState(ResearchContract):
    """One versioned, canonical, secret-free research-state snapshot."""

    schema_version: Literal[RESEARCH_STATE_SCHEMA_VERSION] = (
        RESEARCH_STATE_SCHEMA_VERSION
    )
    research_id: ResearchId
    revision: StrictInt = Field(ge=0, le=1_000_000_000)
    status: ResearchRunStatus
    created_at: Timestamp
    updated_at: Timestamp
    targets: tuple[TargetAsset, ...] = Field(default=(), max_length=64)
    surfaces: tuple[Surface, ...] = Field(default=(), max_length=2_000)
    endpoints: tuple[Endpoint, ...] = Field(default=(), max_length=5_000)
    parameters: tuple[Parameter, ...] = Field(default=(), max_length=10_000)
    request_templates: tuple[ResearchRequestTemplate, ...] = Field(
        default=(), max_length=5_000
    )
    identities: tuple[Identity, ...] = Field(default=(), max_length=200)
    session_refs: tuple[SessionRef, ...] = Field(default=(), max_length=1_000)
    token_refs: tuple[TokenRef, ...] = Field(default=(), max_length=1_000)
    objects: tuple[ResearchObject, ...] = Field(default=(), max_length=5_000)
    graphql_surfaces: tuple[GraphQLSurface, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_SURFACES
    )
    graphql_types: tuple[GraphQLTypeRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_TYPES
    )
    graphql_fields: tuple[GraphQLFieldRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_FIELDS
    )
    graphql_arguments: tuple[GraphQLArgumentRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_ARGUMENTS
    )
    graphql_operations: tuple[GraphQLOperation | GraphQLOperationRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_OPERATIONS
    )
    graphql_variables: tuple[GraphQLVariableRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_VARIABLES
    )
    uploads: tuple[UploadArtifact, ...] = Field(default=(), max_length=2_000)
    workflows: tuple[Workflow, ...] = Field(default=(), max_length=2_000)
    observations: tuple[Observation, ...] = Field(default=(), max_length=20_000)
    evidence: tuple[EvidenceArtifact, ...] = Field(default=(), max_length=20_000)
    facts: tuple[Fact, ...] = Field(default=(), max_length=20_000)
    relationships: tuple[Relationship, ...] = Field(default=(), max_length=20_000)
    hypotheses: tuple[HypothesisRecord, ...] = Field(default=(), max_length=5_000)
    experiment_outcomes: tuple[ExperimentOutcome, ...] = Field(
        default=(), max_length=10_000
    )
    experiment_history: tuple[ResearchExperimentRecord, ...] = Field(
        default=(), max_length=10_000
    )
    reproduction_plans: tuple[ReproductionPlan, ...] = Field(
        default=(), max_length=2_000
    )
    reproduction_outcomes: tuple[ReproductionOutcome, ...] = Field(
        default=(), max_length=5_000
    )
    confirmation_decisions: tuple[FindingConfirmationDecision, ...] = Field(
        default=(), max_length=5_000
    )
    findings: tuple[FindingRecord, ...] = Field(default=(), max_length=2_000)
    chain_candidates: tuple[AttackChainCandidate, ...] = Field(
        default=(), max_length=500
    )
    chain_hypotheses: tuple[AttackChainHypothesis, ...] = Field(
        default=(), max_length=500
    )
    attack_chains: tuple[AttackChain, ...] = Field(default=(), max_length=500)
    chain_step_outcomes: tuple[ChainStepOutcome, ...] = Field(
        default=(), max_length=5_000
    )
    chain_evaluations: tuple[AttackChainEvaluation, ...] = Field(
        default=(), max_length=2_000
    )
    chain_reproduction_plans: tuple[ChainReproductionPlan, ...] = Field(
        default=(), max_length=500
    )
    chain_reproduction_outcomes: tuple[ChainReproductionOutcome, ...] = Field(
        default=(), max_length=1_000
    )
    chain_confirmation_decisions: tuple[ChainConfirmationDecision, ...] = Field(
        default=(), max_length=1_000
    )
    chain_budgets: tuple[ChainBudgetState, ...] = Field(default=(), max_length=20)
    budgets: tuple[BudgetState, ...] = Field(default=(), max_length=20)
    bootstrap_progress: tuple[ResearchBootstrapProgress, ...] = Field(
        default=(), max_length=64
    )
    diagnostic_codes: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    provenance: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=20_000)

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ResearchState":
        collections = (
            ("targets", "target_id"),
            ("surfaces", "surface_id"),
            ("endpoints", "endpoint_id"),
            ("parameters", "parameter_id"),
            ("request_templates", "template_id"),
            ("identities", "identity_id"),
            ("session_refs", "session_ref_id"),
            ("token_refs", "token_ref_id"),
            ("objects", "object_id"),
            ("graphql_surfaces", "graphql_surface_id"),
            ("graphql_types", "type_id"),
            ("graphql_fields", "field_id"),
            ("graphql_arguments", "argument_id"),
            ("graphql_operations", "operation_id"),
            ("graphql_variables", "variable_id"),
            ("uploads", "upload_id"),
            ("workflows", "workflow_id"),
            ("observations", "observation_id"),
            ("evidence", "evidence_id"),
            ("facts", "fact_id"),
            ("relationships", "relationship_id"),
            ("hypotheses", "hypothesis_id"),
            ("experiment_outcomes", "outcome_id"),
            ("experiment_history", "experiment_id"),
            ("reproduction_plans", "reproduction_id"),
            ("reproduction_outcomes", "reproduction_id"),
            ("confirmation_decisions", "decision_id"),
            ("findings", "finding_id"),
            ("chain_candidates", "candidate_id"),
            ("chain_hypotheses", "hypothesis_id"),
            ("attack_chains", "attack_chain_id"),
            ("chain_step_outcomes", "outcome_id"),
            ("chain_evaluations", "evaluation_id"),
            ("chain_reproduction_plans", "reproduction_id"),
            ("chain_reproduction_outcomes", "reproduction_id"),
            ("chain_confirmation_decisions", "decision_id"),
            ("chain_budgets", "budget_reference"),
            ("budgets", "budget_reference"),
            ("bootstrap_progress", "bootstrap_id"),
            ("provenance", "provenance_id"),
        )
        for field_name, id_field in collections:
            values = getattr(self, field_name)
            ids = tuple(getattr(item, id_field) for item in values)
            _unique(ids, f"{field_name} IDs")
            object.__setattr__(
                self,
                field_name,
                tuple(sorted(values, key=lambda item: getattr(item, id_field))),
            )
        object.__setattr__(
            self,
            "diagnostic_codes",
            _canonical_references(self.diagnostic_codes, "diagnostic codes"),
        )

        if _as_datetime(self.updated_at) < _as_datetime(self.created_at):
            raise ValueError("updated_at cannot precede created_at")
        self._validate_critical_references()
        return self

    def _validate_critical_references(self) -> None:
        target_ids = {item.target_id for item in self.targets}
        surface_ids = {item.surface_id for item in self.surfaces}
        endpoint_ids = {item.endpoint_id for item in self.endpoints}
        parameter_ids = {item.parameter_id for item in self.parameters}
        identity_ids = {item.identity_id for item in self.identities}
        evidence_ids = {item.evidence_id for item in self.evidence}
        evidence_source_references = {item.source_reference for item in self.evidence}
        fact_ids = {item.fact_id for item in self.facts}
        relationship_ids = {item.relationship_id for item in self.relationships}
        hypothesis_ids = {item.hypothesis_id for item in self.hypotheses}
        outcome_ids = {item.outcome_id for item in self.experiment_outcomes}
        experiment_ids = {item.experiment_id for item in self.experiment_history}
        reproduction_ids = {item.reproduction_id for item in self.reproduction_plans}
        confirmation_decision_ids = {
            item.decision_id for item in self.confirmation_decisions
        }
        chain_confirmation_decision_ids = {
            item.decision_id for item in self.chain_confirmation_decisions
        }
        finding_ids = {item.finding_id for item in self.findings}
        chain_ids = {item.attack_chain_id for item in self.attack_chains}
        chain_candidate_ids = {item.candidate_id for item in self.chain_candidates}
        chain_reproduction_ids = {
            item.reproduction_id for item in self.chain_reproduction_plans
        }
        observation_ids = {item.observation_id for item in self.observations}
        provenance_ids = {item.provenance_id for item in self.provenance}
        graphql_surface_ids = {
            item.graphql_surface_id for item in self.graphql_surfaces
        }
        graphql_type_ids = {item.type_id for item in self.graphql_types}
        graphql_field_ids = {item.field_id for item in self.graphql_fields}
        graphql_argument_ids = {item.argument_id for item in self.graphql_arguments}
        graphql_semantic_operation_ids = {
            item.operation_id
            for item in self.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
        }
        graphql_variable_ids = {item.variable_id for item in self.graphql_variables}

        for item in self.provenance:
            _require_optional_reference(
                item.parent_provenance_id, provenance_ids, "parent provenance"
            )

        for item in self.targets:
            _require_reference(item.provenance_id, provenance_ids, "target provenance")
            _require_references(
                item.evidence_references, evidence_ids, "target evidence"
            )
        for item in self.surfaces:
            _require_reference(item.target_id, target_ids, "surface target")
            _require_reference(item.provenance_id, provenance_ids, "surface provenance")
            _require_references(
                item.evidence_references, evidence_ids, "surface evidence"
            )
        for item in self.endpoints:
            _require_reference(item.target_id, target_ids, "endpoint target")
            _require_reference(item.surface_id, surface_ids, "endpoint surface")
            _require_reference(
                item.provenance_id, provenance_ids, "endpoint provenance"
            )
            _require_references(
                item.evidence_references, evidence_ids, "endpoint evidence"
            )
        for item in self.parameters:
            _require_reference(item.endpoint_id, endpoint_ids, "parameter endpoint")
            _require_reference(
                item.provenance_id, provenance_ids, "parameter provenance"
            )
            _require_references(
                item.evidence_references, evidence_ids, "parameter evidence"
            )
        for item in self.request_templates:
            _require_reference(item.target_id, target_ids, "request template target")
            _require_reference(item.surface_id, surface_ids, "request template surface")
            _require_reference(
                item.endpoint_id, endpoint_ids, "request template endpoint"
            )
            endpoint = next(
                value
                for value in self.endpoints
                if value.endpoint_id == item.endpoint_id
            )
            if (
                endpoint.target_id != item.target_id
                or endpoint.surface_id != item.surface_id
                or endpoint.method is not item.method
                or endpoint.route_template != item.route_reference
            ):
                raise ValueError("request template does not match its endpoint")
            endpoint_parameter_ids = {
                value.parameter_id
                for value in self.parameters
                if value.endpoint_id == item.endpoint_id
            }
            _require_references(
                item.parameter_ids,
                endpoint_parameter_ids,
                "request template parameters",
            )
            _require_references(
                item.evidence_references, evidence_ids, "request template evidence"
            )
            _require_references(
                item.source_capture_references,
                evidence_source_references,
                "request template capture provenance",
            )
            _require_reference(
                item.provenance_id, provenance_ids, "request template provenance"
            )
        for item in self.identities:
            _require_reference(
                item.provenance_id, provenance_ids, "identity provenance"
            )
        for item in (*self.session_refs, *self.token_refs):
            _require_reference(item.identity_id, identity_ids, "credential identity")
            _require_reference(
                item.provenance_id, provenance_ids, "credential provenance"
            )
        for item in self.objects:
            _require_reference(item.target_id, target_ids, "object target")
            _require_reference(item.surface_id, surface_ids, "object surface")
            _require_optional_reference(
                item.owner_identity_id, identity_ids, "object owner"
            )
            _require_references(
                item.evidence_references, evidence_ids, "object evidence"
            )
            _require_references(
                item.parameter_references, parameter_ids, "object parameters"
            )
            _require_reference(item.provenance_id, provenance_ids, "object provenance")

        graphql_surface_by_id = {
            item.graphql_surface_id: item for item in self.graphql_surfaces
        }
        surface_by_id = {item.surface_id: item for item in self.surfaces}
        endpoint_by_id = {item.endpoint_id: item for item in self.endpoints}
        types_by_id = {item.type_id: item for item in self.graphql_types}
        fields_by_id = {item.field_id: item for item in self.graphql_fields}
        arguments_by_id = {item.argument_id: item for item in self.graphql_arguments}
        variables_by_id = {item.variable_id: item for item in self.graphql_variables}
        type_by_surface_name: dict[tuple[str, str], GraphQLTypeRecord] = {}
        root_roles: set[tuple[str, str]] = set()

        for item in self.graphql_surfaces:
            if item.research_id != self.research_id:
                raise ValueError("GraphQL surface research_id mismatch")
            _require_reference(item.target_id, target_ids, "GraphQL surface target")
            _require_reference(item.surface_id, surface_ids, "GraphQL base surface")
            _require_reference(item.endpoint_id, endpoint_ids, "GraphQL endpoint")
            surface = surface_by_id[item.surface_id]
            endpoint = endpoint_by_id[item.endpoint_id]
            if surface.target_id != item.target_id:
                raise ValueError("GraphQL surface target does not match base surface")
            if surface.surface_type is not SurfaceType.graphql:
                raise ValueError(
                    "GraphQL semantic surface requires a GraphQL base surface"
                )
            if (
                endpoint.target_id != item.target_id
                or endpoint.surface_id != item.surface_id
            ):
                raise ValueError("GraphQL endpoint does not match its semantic surface")
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL surface evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "GraphQL surface provenance"
            )

        type_counts: dict[str, int] = {}
        for item in self.graphql_types:
            _require_reference(
                item.graphql_surface_id,
                graphql_surface_ids,
                "GraphQL type surface",
            )
            type_counts[item.graphql_surface_id] = (
                type_counts.get(item.graphql_surface_id, 0) + 1
            )
            if type_counts[item.graphql_surface_id] > MAX_GRAPHQL_TYPES_PER_SURFACE:
                raise ValueError("GraphQL type-per-surface limit exceeded")
            name_key = (item.graphql_surface_id, item.name)
            if name_key in type_by_surface_name:
                raise ValueError("duplicate GraphQL type name within a surface")
            type_by_surface_name[name_key] = item
            if item.root_role is not None:
                root_key = (item.graphql_surface_id, item.root_role.value)
                if root_key in root_roles:
                    raise ValueError("duplicate GraphQL root role within a surface")
                root_roles.add(root_key)
            _require_references(
                item.field_ids, graphql_field_ids, "GraphQL type fields"
            )
            _require_references(
                item.possible_type_ids,
                graphql_type_ids,
                "GraphQL possible types",
            )
            _require_references(
                item.interface_ids, graphql_type_ids, "GraphQL interfaces"
            )
            for field_id in item.field_ids:
                if fields_by_id[field_id].type_id != item.type_id:
                    raise ValueError(
                        "GraphQL type contains a field owned by another type"
                    )
            for possible_id in item.possible_type_ids:
                possible = types_by_id[possible_id]
                if (
                    possible.graphql_surface_id != item.graphql_surface_id
                    or possible.kind is not GraphQLTypeKind.object
                ):
                    raise ValueError(
                        "GraphQL possible type must be an object on the same surface"
                    )
            for interface_id in item.interface_ids:
                interface = types_by_id[interface_id]
                if (
                    interface.graphql_surface_id != item.graphql_surface_id
                    or interface.kind is not GraphQLTypeKind.interface
                ):
                    raise ValueError("GraphQL interface must exist on the same surface")
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL type evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "GraphQL type provenance"
            )

        field_counts: dict[str, int] = {}
        for item in self.graphql_fields:
            _require_reference(item.type_id, graphql_type_ids, "GraphQL field type")
            field_counts[item.type_id] = field_counts.get(item.type_id, 0) + 1
            if field_counts[item.type_id] > MAX_GRAPHQL_FIELDS_PER_TYPE:
                raise ValueError("GraphQL field-per-type limit exceeded")
            owner = types_by_id[item.type_id]
            _require_references(
                item.argument_ids, graphql_argument_ids, "GraphQL field arguments"
            )
            for argument_id in item.argument_ids:
                if arguments_by_id[argument_id].field_id != item.field_id:
                    raise ValueError(
                        "GraphQL field contains an argument owned by another field"
                    )
            return_key = (owner.graphql_surface_id, item.return_type.named_type)
            if (
                return_key not in type_by_surface_name
                and not item.return_type.unresolved_external
            ):
                raise ValueError(
                    f"dangling GraphQL return type reference: {item.return_type.named_type}"
                )
            for hint in item.relationship_hints:
                _require_optional_reference(
                    hint.graphql_type_id,
                    graphql_type_ids,
                    "GraphQL relationship type",
                )
                if hint.graphql_type_id is not None and (
                    types_by_id[hint.graphql_type_id].graphql_surface_id
                    != owner.graphql_surface_id
                ):
                    raise ValueError(
                        "GraphQL relationship type crosses semantic surfaces"
                    )
                _require_optional_reference(
                    hint.research_object_id,
                    {value.object_id for value in self.objects},
                    "GraphQL relationship object",
                )
                if hint.research_object_id is not None:
                    related_object = next(
                        value
                        for value in self.objects
                        if value.object_id == hint.research_object_id
                    )
                    semantic_surface = graphql_surface_by_id[owner.graphql_surface_id]
                    if related_object.target_id != semantic_surface.target_id:
                        raise ValueError(
                            "GraphQL relationship object belongs to another target"
                        )
                _require_references(
                    hint.evidence_references,
                    evidence_ids,
                    "GraphQL relationship evidence",
                )
            auth = item.authorization_semantics
            _require_references(
                auth.identity_references,
                identity_ids,
                "GraphQL authorization identities",
            )
            _require_references(
                auth.evidence_references,
                evidence_ids,
                "GraphQL authorization evidence",
            )
            _require_reference(
                auth.provenance_id,
                provenance_ids,
                "GraphQL authorization provenance",
            )
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL field evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "GraphQL field provenance"
            )

        argument_counts: dict[str, int] = {}
        for item in self.graphql_arguments:
            _require_reference(
                item.field_id, graphql_field_ids, "GraphQL argument field"
            )
            argument_counts[item.field_id] = argument_counts.get(item.field_id, 0) + 1
            if argument_counts[item.field_id] > MAX_GRAPHQL_ARGUMENTS_PER_FIELD:
                raise ValueError("GraphQL argument-per-field limit exceeded")
            field = fields_by_id[item.field_id]
            owner = types_by_id[field.type_id]
            input_key = (owner.graphql_surface_id, item.input_type.named_type)
            if (
                input_key not in type_by_surface_name
                and not item.input_type.unresolved_external
            ):
                raise ValueError(
                    f"dangling GraphQL input type reference: {item.input_type.named_type}"
                )
            _require_references(
                item.semantic_role_evidence_references,
                evidence_ids,
                "GraphQL argument semantic-role evidence",
            )
            semantics = item.object_reference_semantics
            _require_optional_reference(
                semantics.graphql_type_id,
                graphql_type_ids,
                "GraphQL argument object type",
            )
            if semantics.graphql_type_id is not None and (
                types_by_id[semantics.graphql_type_id].graphql_surface_id
                != owner.graphql_surface_id
            ):
                raise ValueError(
                    "GraphQL argument object type crosses semantic surfaces"
                )
            _require_optional_reference(
                semantics.research_object_id,
                {value.object_id for value in self.objects},
                "GraphQL argument research object",
            )
            if semantics.research_object_id is not None:
                related_object = next(
                    value
                    for value in self.objects
                    if value.object_id == semantics.research_object_id
                )
                semantic_surface = graphql_surface_by_id[owner.graphql_surface_id]
                if related_object.target_id != semantic_surface.target_id:
                    raise ValueError(
                        "GraphQL argument object belongs to another target"
                    )
            _require_optional_reference(
                item.parameter_id, parameter_ids, "GraphQL argument parameter"
            )
            if item.parameter_id is not None:
                parameter = next(
                    value
                    for value in self.parameters
                    if value.parameter_id == item.parameter_id
                )
                parameter_endpoint = endpoint_by_id[parameter.endpoint_id]
                semantic_surface = graphql_surface_by_id[owner.graphql_surface_id]
                if parameter_endpoint.target_id != semantic_surface.target_id:
                    raise ValueError(
                        "GraphQL argument parameter belongs to another target"
                    )
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL argument evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "GraphQL argument provenance"
            )

        for item in self.graphql_operations:
            if isinstance(item, GraphQLOperationRecord):
                _require_reference(
                    item.graphql_surface_id,
                    graphql_surface_ids,
                    "GraphQL operation surface",
                )
                semantic_surface = graphql_surface_by_id[item.graphql_surface_id]
                _require_references(
                    item.root_field_ids,
                    graphql_field_ids,
                    "GraphQL operation root fields",
                )
                for field_id in item.root_field_ids:
                    root_field = fields_by_id[field_id]
                    root_type = types_by_id[root_field.type_id]
                    if (
                        root_type.graphql_surface_id != item.graphql_surface_id
                        or root_type.root_role is None
                        or root_type.root_role.value != item.operation_type.value
                    ):
                        raise ValueError(
                            "GraphQL operation field is not on its matching root type"
                        )
                _require_references(
                    item.variable_ids,
                    graphql_variable_ids,
                    "GraphQL operation variables",
                )
                for variable_id in item.variable_ids:
                    if variables_by_id[variable_id].operation_id != item.operation_id:
                        raise ValueError(
                            "GraphQL operation contains a variable owned by another operation"
                        )
                _require_optional_reference(
                    item.workflow_id,
                    {value.workflow_id for value in self.workflows},
                    "GraphQL operation workflow",
                )
                if item.operation_type not in semantic_surface.operation_capabilities:
                    raise ValueError(
                        "GraphQL operation type is absent from surface capabilities"
                    )
            else:
                _require_reference(item.surface_id, surface_ids, "GraphQL surface")
                _require_reference(item.endpoint_id, endpoint_ids, "GraphQL endpoint")
                _require_references(
                    item.variable_parameter_ids, parameter_ids, "GraphQL variables"
                )
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL evidence"
            )
            _require_reference(item.provenance_id, provenance_ids, "GraphQL provenance")

        variable_counts: dict[str, int] = {}
        for item in self.graphql_variables:
            _require_reference(
                item.operation_id,
                graphql_semantic_operation_ids,
                "GraphQL variable operation",
            )
            variable_counts[item.operation_id] = (
                variable_counts.get(item.operation_id, 0) + 1
            )
            if variable_counts[item.operation_id] > MAX_GRAPHQL_VARIABLES_PER_OPERATION:
                raise ValueError("GraphQL variable-per-operation limit exceeded")
            _require_optional_reference(
                item.linked_argument_id,
                graphql_argument_ids,
                "GraphQL variable argument",
            )
            if item.linked_argument_id is not None:
                argument = arguments_by_id[item.linked_argument_id]
                if item.input_type != argument.input_type:
                    raise ValueError(
                        "GraphQL variable and linked argument types differ"
                    )
            _require_references(
                item.semantic_role_evidence_references,
                evidence_ids,
                "GraphQL variable semantic-role evidence",
            )
            _require_references(
                item.evidence_references, evidence_ids, "GraphQL variable evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "GraphQL variable provenance"
            )

        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        provenance_by_id = {item.provenance_id: item for item in self.provenance}

        def require_non_model_evidence(
            references: tuple[str, ...], description: str
        ) -> None:
            producers = {
                provenance_by_id[evidence_by_id[reference].provenance_id].producer_type
                for reference in references
                if reference in evidence_by_id
                and evidence_by_id[reference].provenance_id in provenance_by_id
            }
            if producers and producers == {ProvenanceProducerType.model}:
                raise ValueError(f"{description} cannot rely on model-only evidence")

        semantic_records = (
            *self.graphql_surfaces,
            *self.graphql_types,
            *self.graphql_fields,
            *self.graphql_arguments,
            *(
                item
                for item in self.graphql_operations
                if isinstance(item, GraphQLOperationRecord)
            ),
            *self.graphql_variables,
        )
        for item in semantic_records:
            require_non_model_evidence(
                item.evidence_references, "GraphQL semantic record"
            )
        for item in self.graphql_fields:
            require_non_model_evidence(
                item.authorization_semantics.evidence_references,
                "GraphQL authorization semantics",
            )
            for hint in item.relationship_hints:
                require_non_model_evidence(
                    hint.evidence_references, "GraphQL relationship semantics"
                )
        for item in self.uploads:
            _require_reference(item.surface_id, surface_ids, "upload surface")
            _require_reference(item.endpoint_id, endpoint_ids, "upload endpoint")
            _require_reference(item.owner_identity_id, identity_ids, "upload owner")
            _require_references(
                item.evidence_references, evidence_ids, "upload evidence"
            )
            _require_reference(item.provenance_id, provenance_ids, "upload provenance")
        for item in self.workflows:
            _require_reference(item.surface_id, surface_ids, "workflow surface")
            _require_references(
                item.evidence_references, evidence_ids, "workflow evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "workflow provenance"
            )
            for step in item.steps:
                _require_optional_reference(
                    step.endpoint_id, endpoint_ids, "workflow endpoint"
                )
        for item in self.evidence:
            _require_reference(
                item.provenance_id, provenance_ids, "evidence provenance"
            )
        for item in self.observations:
            _require_reference(item.target_id, target_ids, "observation target")
            _require_optional_reference(
                item.surface_id, surface_ids, "observation surface"
            )
            _require_references(
                item.evidence_references, evidence_ids, "observation evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "observation provenance"
            )
        for item in self.facts:
            _validate_entity_reference(item.subject, self)
            if item.object.kind == "reference":
                _validate_entity_reference(item.object.reference, self)
            _require_references(item.evidence_references, evidence_ids, "fact evidence")
            _require_reference(item.provenance_id, provenance_ids, "fact provenance")
            _require_optional_reference(
                item.supersedes_fact_id, fact_ids, "superseded fact"
            )
        for item in self.relationships:
            _validate_entity_reference(item.source, self)
            _validate_entity_reference(item.target, self)
            _require_references(
                item.evidence_references, evidence_ids, "relationship evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "relationship provenance"
            )
            _require_optional_reference(
                item.supersedes_relationship_id,
                relationship_ids,
                "superseded relationship",
            )
        for item in self.hypotheses:
            _require_reference(item.target_id, target_ids, "hypothesis target")
            _require_optional_reference(
                item.surface_id, surface_ids, "hypothesis surface"
            )
            _require_references(
                (*item.supporting_evidence, *item.refuting_evidence),
                evidence_ids,
                "hypothesis evidence",
            )
            _require_reference(
                item.provenance_id, provenance_ids, "hypothesis provenance"
            )
            _require_references(item.basis_fact_ids, fact_ids, "hypothesis basis facts")
            _require_references(
                item.basis_relationship_ids,
                relationship_ids,
                "hypothesis basis relationships",
            )
            for reference in item.entity_references:
                _validate_entity_reference(reference, self)
        for item in self.experiment_outcomes:
            _require_references(
                item.evidence_references, evidence_ids, "outcome evidence"
            )
            _require_references(item.created_fact_ids, fact_ids, "outcome facts")
            _require_references(
                item.created_hypothesis_ids, hypothesis_ids, "outcome hypotheses"
            )
            _require_references(
                item.candidate_finding_ids, finding_ids, "outcome findings"
            )
            _require_reference(item.provenance_id, provenance_ids, "outcome provenance")
        for item in self.experiment_history:
            _require_reference(
                item.hypothesis_id, hypothesis_ids, "experiment history hypothesis"
            )
            _require_optional_reference(
                item.surface_id, surface_ids, "experiment history surface"
            )
        for item in self.reproduction_plans:
            _require_reference(item.finding_id, finding_ids, "reproduction finding")
            _require_reference(
                item.source_experiment_id,
                experiment_ids,
                "reproduction source experiment",
            )
            _require_reference(
                item.source_outcome_id, outcome_ids, "reproduction source outcome"
            )
            _require_reference(
                item.source_hypothesis_id,
                hypothesis_ids,
                "reproduction source hypothesis",
            )
            _require_reference(item.target_id, target_ids, "reproduction target")
            _require_optional_reference(
                item.surface_id, surface_ids, "reproduction surface"
            )
            _require_optional_reference(
                item.endpoint_id, endpoint_ids, "reproduction endpoint"
            )
            _require_optional_reference(
                item.primary_identity_id,
                identity_ids,
                "reproduction primary identity",
            )
            _require_optional_reference(
                item.comparison_identity_id,
                identity_ids,
                "reproduction comparison identity",
            )
            _require_references(
                item.controlled_object_ids,
                {value.object_id for value in self.objects},
                "reproduction objects",
            )
            _require_optional_reference(
                item.alternate_controlled_object_id,
                {value.object_id for value in self.objects},
                "reproduction alternate object",
            )
            _require_reference(
                item.provenance_id, provenance_ids, "reproduction provenance"
            )
        for item in self.reproduction_outcomes:
            _require_reference(item.finding_id, finding_ids, "reproduction finding")
            _require_reference(
                item.reproduction_id, reproduction_ids, "reproduction plan"
            )
            _require_reference(
                item.experiment_outcome_id,
                outcome_ids,
                "reproduction experiment outcome",
            )
            _require_references(
                item.evidence_references, evidence_ids, "reproduction evidence"
            )
            _require_reference(
                item.runtime_provenance_reference,
                provenance_ids,
                "reproduction runtime provenance",
            )
        for item in self.confirmation_decisions:
            _require_reference(item.finding_id, finding_ids, "decision finding")
            _require_references(
                item.reproduction_ids, reproduction_ids, "decision reproductions"
            )
            _require_references(
                (
                    *item.confirmed_evidence_references,
                    *item.conflicting_evidence_references,
                ),
                evidence_ids,
                "decision evidence",
            )
            _require_reference(
                item.provenance_id, provenance_ids, "decision provenance"
            )
        for item in self.findings:
            _require_reference(
                item.source_hypothesis_id, hypothesis_ids, "finding hypothesis"
            )
            _require_references(
                item.evidence_references, evidence_ids, "finding evidence"
            )
            _require_references(
                item.contradictory_evidence,
                evidence_ids,
                "finding contradictory evidence",
            )
            _require_references(
                (
                    *item.confirmed_evidence_references,
                    *item.conflicting_evidence_references,
                ),
                evidence_ids,
                "finding confirmation evidence",
            )
            _require_references(
                item.reproduction_ids, reproduction_ids, "finding reproductions"
            )
            _require_optional_reference(item.target_id, target_ids, "finding target")
            _require_optional_reference(item.surface_id, surface_ids, "finding surface")
            _require_optional_reference(
                item.endpoint_id, endpoint_ids, "finding endpoint"
            )
            _require_optional_reference(
                item.graphql_operation_id,
                graphql_semantic_operation_ids,
                "finding GraphQL operation",
            )
            _require_references(
                item.graphql_field_ids,
                graphql_field_ids,
                "finding GraphQL fields",
            )
            _require_references(
                item.graphql_argument_ids,
                graphql_argument_ids,
                "finding GraphQL arguments",
            )
            _require_references(
                item.controlled_identity_ids,
                identity_ids,
                "finding controlled identities",
            )
            _require_references(
                item.controlled_object_ids,
                {value.object_id for value in self.objects},
                "finding controlled objects",
            )
            _require_optional_reference(
                item.confirmation_decision_id,
                confirmation_decision_ids | chain_confirmation_decision_ids,
                "finding confirmation decision",
            )
            if item.controlled_impact is not None:
                _require_references(
                    item.controlled_impact.evidence_references,
                    evidence_ids,
                    "finding impact evidence",
                )
            _require_reference(item.provenance_id, provenance_ids, "finding provenance")
            _require_optional_reference(
                item.source_chain_id, chain_ids, "finding source chain"
            )
            _require_references(
                item.component_finding_ids, finding_ids, "chain component findings"
            )
            _require_references(
                item.component_hypothesis_ids,
                hypothesis_ids,
                "chain component hypotheses",
            )
            _require_references(
                (
                    *item.step_evidence_references,
                    *item.combined_impact_evidence_references,
                ),
                evidence_ids,
                "chain finding evidence",
            )
            _require_references(
                item.chain_reproduction_ids,
                chain_reproduction_ids,
                "chain finding reproductions",
            )
        for item in self.chain_candidates:
            if item.research_id != self.research_id:
                raise ValueError("chain candidate research reference mismatch")
            if item.state_revision > self.revision:
                raise ValueError("chain candidate references a future state revision")
            _require_references(item.target_ids, target_ids, "chain candidate targets")
            _require_references(
                item.surface_ids, surface_ids, "chain candidate surfaces"
            )
            _require_references(
                item.identity_ids, identity_ids, "chain candidate identities"
            )
            _require_references(
                item.object_ids,
                {value.object_id for value in self.objects},
                "chain candidate objects",
            )
            _require_references(
                item.hypothesis_ids,
                hypothesis_ids,
                "chain candidate hypotheses",
            )
            _require_references(
                item.finding_ids, finding_ids, "chain candidate findings"
            )
            _require_references(item.fact_ids, fact_ids, "chain candidate facts")
            _require_references(
                item.evidence_references, evidence_ids, "chain candidate evidence"
            )
            _require_references(
                item.provenance_references,
                provenance_ids,
                "chain candidate provenance",
            )
            for reference in item.ordered_references:
                _validate_entity_reference(reference, self)
            for link in item.required_unresolved_links:
                _validate_entity_reference(link.from_reference, self)
                _validate_entity_reference(link.to_reference, self)
                _require_references(
                    link.evidence_references,
                    evidence_ids,
                    "chain candidate link evidence",
                )
        for item in self.chain_hypotheses:
            if item.research_id != self.research_id:
                raise ValueError("chain hypothesis research reference mismatch")
            _require_reference(
                item.chain_candidate_id,
                chain_candidate_ids,
                "chain hypothesis candidate",
            )
            _require_references(
                item.evidence_references, evidence_ids, "chain hypothesis evidence"
            )
            _require_references(
                item.provenance_references,
                provenance_ids,
                "chain hypothesis provenance",
            )
            for reference in item.ordered_references:
                _validate_entity_reference(reference, self)
            for link in item.unresolved_links:
                _validate_entity_reference(link.from_reference, self)
                _validate_entity_reference(link.to_reference, self)
                _require_references(
                    link.evidence_references,
                    evidence_ids,
                    "chain hypothesis link evidence",
                )
        for item in self.attack_chains:
            if item.research_id is not None and item.research_id != self.research_id:
                raise ValueError("attack-chain research reference mismatch")
            _require_references(
                item.evidence_references, evidence_ids, "attack-chain evidence"
            )
            _require_reference(
                item.provenance_id, provenance_ids, "attack-chain provenance"
            )
            _require_references(item.target_ids, target_ids, "attack-chain targets")
            _require_references(item.surface_ids, surface_ids, "attack-chain surfaces")
            _require_references(
                item.identity_ids, identity_ids, "attack-chain identities"
            )
            _require_references(
                item.object_ids,
                {value.object_id for value in self.objects},
                "attack-chain objects",
            )
            _require_references(
                item.hypothesis_ids, hypothesis_ids, "attack-chain hypotheses"
            )
            _require_references(item.finding_ids, finding_ids, "attack-chain findings")
            _require_references(item.fact_ids, fact_ids, "attack-chain facts")
            # Relationship IDs may name journaled GraphAssertions, which are
            # integrity-checked by ResearchStore rather than duplicated here.
            _require_references(
                item.combined_impact_evidence,
                evidence_ids,
                "attack-chain combined impact evidence",
            )
            for step in item.steps:
                _validate_entity_reference(step.source_reference, self)
                if step.target_reference is not None:
                    _validate_entity_reference(step.target_reference, self)
                _require_references(
                    step.consumed_fact_ids, fact_ids, "attack-chain consumed facts"
                )
            for link in item.unresolved_links:
                _validate_entity_reference(link.from_reference, self)
                _validate_entity_reference(link.to_reference, self)
                _require_references(
                    link.evidence_references,
                    evidence_ids,
                    "attack-chain link evidence",
                )
        for item in self.chain_step_outcomes:
            _require_reference(item.chain_id, chain_ids, "chain-step chain")
            chain = next(
                value
                for value in self.attack_chains
                if value.attack_chain_id == item.chain_id
            )
            step = next(
                (value for value in chain.steps if value.step_id == item.step_id),
                None,
            )
            if step is None or step.sequence != item.sequence:
                raise ValueError("chain-step outcome does not match its chain step")
            _require_references(
                item.evidence_references, evidence_ids, "chain-step evidence"
            )
            _require_optional_reference(
                item.provenance_id, provenance_ids, "chain-step provenance"
            )
        for item in self.chain_evaluations:
            if item.research_id != self.research_id:
                raise ValueError("chain evaluation research reference mismatch")
            _require_reference(item.chain_id, chain_ids, "chain evaluation chain")
            _require_references(
                (*item.evidence_references, *item.combined_impact_evidence),
                evidence_ids,
                "chain evaluation evidence",
            )
            _require_optional_reference(
                item.provenance_id, provenance_ids, "chain evaluation provenance"
            )
        for item in self.chain_reproduction_plans:
            if item.research_id != self.research_id:
                raise ValueError("chain reproduction research reference mismatch")
            _require_reference(item.chain_id, chain_ids, "chain reproduction chain")
            _require_reference(
                item.finding_id, finding_ids, "chain reproduction finding"
            )
            _require_references(
                item.component_finding_ids,
                finding_ids,
                "chain reproduction component findings",
            )
            _require_reference(
                item.provenance_id, provenance_ids, "chain reproduction provenance"
            )
            chain = next(
                value
                for value in self.attack_chains
                if value.attack_chain_id == item.chain_id
            )
            _require_references(
                item.ordered_chain_step_ids,
                {str(value.step_id) for value in chain.steps},
                "chain reproduction steps",
            )
        for item in self.chain_reproduction_outcomes:
            _require_reference(item.chain_id, chain_ids, "chain reproduction chain")
            _require_reference(
                item.finding_id, finding_ids, "chain reproduction finding"
            )
            _require_reference(
                item.reproduction_id,
                chain_reproduction_ids,
                "chain reproduction plan",
            )
            _require_references(
                (*item.evidence_references, *item.combined_impact_evidence),
                evidence_ids,
                "chain reproduction evidence",
            )
            _require_optional_reference(
                item.provenance_id,
                provenance_ids,
                "chain reproduction outcome provenance",
            )
        for item in self.chain_confirmation_decisions:
            _require_reference(item.chain_id, chain_ids, "chain confirmation chain")
            _require_reference(
                item.finding_id, finding_ids, "chain confirmation finding"
            )
            _require_references(
                item.reproduction_ids,
                chain_reproduction_ids,
                "chain confirmation reproductions",
            )
            _require_references(
                (
                    *item.confirmed_evidence_references,
                    *item.conflicting_evidence_references,
                ),
                evidence_ids,
                "chain confirmation evidence",
            )
        for item in self.budgets:
            _require_references(
                tuple(usage.hypothesis_id for usage in item.hypothesis_usage),
                hypothesis_ids,
                "budget hypotheses",
            )
            _require_references(
                tuple(usage.finding_id for usage in item.reproduction_usage),
                finding_ids,
                "budget reproduction findings",
            )
            _require_references(
                tuple(usage.surface_id for usage in item.surface_usage),
                surface_ids,
                "budget surfaces",
            )
        for item in self.bootstrap_progress:
            _require_reference(item.target_id, target_ids, "bootstrap target")
            _require_reference(
                item.provenance_id, provenance_ids, "bootstrap provenance"
            )

        # These sets are also used by entity-reference validation and keeping
        # them materialized here makes accidental removal detectable.
        del outcome_ids, observation_ids


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value
    )


def _require_reference(value: str, available: set[str], description: str) -> None:
    if value not in available:
        raise ValueError(f"dangling {description} reference: {value}")


def _require_optional_reference(
    value: str | None, available: set[str], description: str
) -> None:
    if value is not None:
        _require_reference(value, available, description)


def _require_references(
    values: tuple[str, ...], available: set[str], description: str
) -> None:
    missing = sorted(set(values) - available)
    if missing:
        raise ValueError(f"dangling {description} references: {', '.join(missing)}")


def _entity_ids(state: ResearchState) -> dict[EntityKind, set[str]]:
    return {
        EntityKind.target: {item.target_id for item in state.targets},
        EntityKind.surface: {item.surface_id for item in state.surfaces},
        EntityKind.endpoint: {item.endpoint_id for item in state.endpoints},
        EntityKind.parameter: {item.parameter_id for item in state.parameters},
        EntityKind.identity: {item.identity_id for item in state.identities},
        EntityKind.session: {item.session_ref_id for item in state.session_refs},
        EntityKind.token: {item.token_ref_id for item in state.token_refs},
        EntityKind.object: {item.object_id for item in state.objects},
        EntityKind.graphql_surface: {
            item.graphql_surface_id for item in state.graphql_surfaces
        },
        EntityKind.graphql_type: {item.type_id for item in state.graphql_types},
        EntityKind.graphql_field: {item.field_id for item in state.graphql_fields},
        EntityKind.graphql_argument: {
            item.argument_id for item in state.graphql_arguments
        },
        EntityKind.graphql_operation: {
            item.operation_id for item in state.graphql_operations
        },
        EntityKind.graphql_variable: {
            item.variable_id for item in state.graphql_variables
        },
        EntityKind.upload: {item.upload_id for item in state.uploads},
        EntityKind.workflow: {item.workflow_id for item in state.workflows},
        EntityKind.observation: {item.observation_id for item in state.observations},
        EntityKind.evidence: {item.evidence_id for item in state.evidence},
        EntityKind.fact: {item.fact_id for item in state.facts},
        EntityKind.relationship: {item.relationship_id for item in state.relationships},
        EntityKind.hypothesis: {item.hypothesis_id for item in state.hypotheses},
        EntityKind.experiment_outcome: {
            item.outcome_id for item in state.experiment_outcomes
        },
        EntityKind.reproduction: {
            *(item.reproduction_id for item in state.reproduction_plans),
            *(item.reproduction_id for item in state.chain_reproduction_plans),
        },
        EntityKind.finding: {item.finding_id for item in state.findings},
        EntityKind.attack_chain: {item.attack_chain_id for item in state.attack_chains},
    }


def _validate_entity_reference(
    reference: EntityReference, state: ResearchState
) -> None:
    _require_reference(
        reference.entity_id,
        _entity_ids(state)[reference.entity_kind],
        f"{reference.entity_kind.value} entity",
    )


def canonical_research_state_bytes(state: ResearchState) -> bytes:
    """Return stable canonical JSON bytes without generating new state."""

    payload = state.model_dump(mode="json")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def research_state_hash(state: ResearchState) -> str:
    """Hash the exact canonical state bytes without signing them."""

    return "sha256:" + hashlib.sha256(canonical_research_state_bytes(state)).hexdigest()
