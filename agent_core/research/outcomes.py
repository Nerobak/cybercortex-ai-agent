"""Secret-safe authoritative outcomes for deterministic research execution."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.research.provenance import reject_secret_material
from agent_core.research.graphql import (
    GraphQLErrorClass,
    GraphQLResponseEnvelope,
)
from agent_core.research.state import ExperimentOutcome as StoredExperimentOutcome
from agent_core.research.state import ReproductionOutcome
from agent_core.research.types import (
    CleanupStatus,
    EvidenceArtifactId,
    OpaqueIdentifier,
    PublicText,
    ResearchContract,
    Sha256Digest,
)


class ExperimentResultClassification(str, Enum):
    """A signal classification.  It never confirms a finding."""

    secure_signal = "secure_signal"
    vulnerable_signal = "vulnerable_signal"
    inconclusive = "inconclusive"
    blocked = "blocked"
    runtime_failed = "runtime_failed"
    cleanup_failed = "cleanup_failed"


class SafeResponseSummary(ResearchContract):
    status_code: StrictInt = Field(ge=100, le=599)
    status_class: OpaqueIdentifier
    content_length_class: OpaqueIdentifier
    content_type: OpaqueIdentifier | None = None
    structural_digest: Sha256Digest
    content_digest: Sha256Digest
    top_level_fields: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=200)
    body_present: StrictBool


class SafeRequestSummary(ResearchContract):
    """A destination-free and credential-free description of one sent request."""

    request_template_reference: OpaqueIdentifier
    target_reference: OpaqueIdentifier
    surface_reference: OpaqueIdentifier
    endpoint_reference: OpaqueIdentifier
    method: OpaqueIdentifier
    identity_reference: OpaqueIdentifier | None = None
    parameter_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    body_present: StrictBool


class SelectorResult(ResearchContract):
    selector: OpaqueIdentifier
    equal: StrictBool
    left_reference: OpaqueIdentifier
    right_reference: OpaqueIdentifier


class InvariantResult(ResearchContract):
    invariant_reference: OpaqueIdentifier
    satisfied: StrictBool


class GraphQLErrorPathEvidence(ResearchContract):
    """A bounded GraphQL error association without message text."""

    path: tuple[OpaqueIdentifier | StrictInt, ...] = Field(min_length=1, max_length=32)
    error_class: GraphQLErrorClass


class GraphQLStateDifferentialEvidence(ResearchContract):
    """Authoritative registered effect evidence for a GraphQL mutation."""

    invariant_reference: OpaqueIdentifier
    identity_reference: OpaqueIdentifier | None = None
    object_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    workflow_state_reference: OpaqueIdentifier | None = None
    before_fingerprint: Sha256Digest
    after_fingerprint: Sha256Digest
    protected_effect_observed: StrictBool
    authoritative: StrictBool = True

    @model_validator(mode="after")
    def validate_differential(self) -> "GraphQLStateDifferentialEvidence":
        if len(self.object_references) != len(set(self.object_references)):
            raise ValueError("GraphQL state object references must be unique")
        object.__setattr__(
            self, "object_references", tuple(sorted(self.object_references))
        )
        changed = self.before_fingerprint != self.after_fingerprint
        if self.protected_effect_observed != changed:
            raise ValueError(
                "GraphQL protected-effect evidence must match its state differential"
            )
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL state evidence"
        )
        return self


class GraphQLRuntimeResponseEvidence(ResearchContract):
    """Bounded GraphQL response structure; never a response value or body."""

    authorized_experiment_reference: Sha256Digest
    operation_template_reference: OpaqueIdentifier
    operation_reference: OpaqueIdentifier
    identity_reference: OpaqueIdentifier | None = None
    object_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    request_accounting_reference: OpaqueIdentifier
    runtime_provenance_reference: OpaqueIdentifier
    status_code: StrictInt | None = Field(default=None, ge=100, le=599)
    status_class: OpaqueIdentifier
    envelope: GraphQLResponseEnvelope
    data_present: StrictBool = False
    errors_present: StrictBool = False
    error_classes: tuple[GraphQLErrorClass, ...] = Field(default=(), max_length=32)
    error_paths: tuple[GraphQLErrorPathEvidence, ...] = Field(default=(), max_length=32)
    error_count: StrictInt = Field(default=0, ge=0, le=100)
    typename_observations: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=128
    )
    selected_field_presence: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=200
    )
    selected_field_nulls: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=200
    )
    object_shape_fingerprint: Sha256Digest
    controlled_object_reference_match: StrictBool | None = None
    response_digest: Sha256Digest
    response_bytes: StrictInt = Field(ge=0, le=262_144)
    latency_ms: StrictInt = Field(ge=0, le=3_600_000)
    truncated: StrictBool = False

    @model_validator(mode="after")
    def enforce_safe_graphql_evidence(self) -> "GraphQLRuntimeResponseEvidence":
        if not self.errors_present and (
            self.error_count or self.error_classes or self.error_paths
        ):
            raise ValueError("GraphQL error evidence requires an errors envelope")
        if not set(self.selected_field_nulls).issubset(
            set(self.selected_field_presence)
        ):
            raise ValueError("GraphQL null fields must also be structurally present")
        if any(
            item.error_class is not GraphQLErrorClass.unknown
            and item.error_class not in self.error_classes
            for item in self.error_paths
        ):
            raise ValueError("GraphQL error path class is absent from response classes")
        for name in (
            "object_references",
            "error_classes",
            "typename_observations",
            "selected_field_presence",
            "selected_field_nulls",
        ):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"GraphQL {name} must not contain duplicates")
            object.__setattr__(
                self,
                name,
                tuple(
                    sorted(
                        values,
                        key=lambda item: getattr(item, "value", str(item)),
                    )
                ),
            )
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL runtime evidence"
        )
        return self


class GraphQLRuntimeTraceEvent(ResearchContract):
    """Reference-only GraphQL runtime trace event."""

    event_type: Literal[
        "GRAPHQL_AUTHORIZE",
        "GRAPHQL_EXECUTE",
        "GRAPHQL_RESPONSE",
        "GRAPHQL_CLEANUP",
    ]
    experiment_reference: OpaqueIdentifier
    operation_reference: OpaqueIdentifier
    identity_reference: OpaqueIdentifier | None = None
    request_count: StrictInt = Field(ge=0, le=100)
    status_class: OpaqueIdentifier | None = None
    error_class: GraphQLErrorClass | None = None

    @model_validator(mode="after")
    def enforce_safe_trace(self) -> "GraphQLRuntimeTraceEvent":
        reject_secret_material(self.model_dump(mode="json"), location="GraphQL trace")
        return self


class PrimitiveExecutionEvidence(ResearchContract):
    evidence_id: EvidenceArtifactId
    step_id: OpaqueIdentifier
    primitive_name: OpaqueIdentifier
    summary: PublicText
    request_template_reference: OpaqueIdentifier | None = None
    identity_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=2)
    object_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    mutation_kind: OpaqueIdentifier | None = None
    request_summaries: tuple[SafeRequestSummary, ...] = Field(default=(), max_length=10)
    response_summaries: tuple[SafeResponseSummary, ...] = Field(
        default=(), max_length=10
    )
    selector_results: tuple[SelectorResult, ...] = Field(default=(), max_length=20)
    invariant_results: tuple[InvariantResult, ...] = Field(default=(), max_length=20)
    graphql_responses: tuple[GraphQLRuntimeResponseEvidence, ...] = Field(
        default=(), max_length=10
    )
    graphql_state_differentials: tuple[GraphQLStateDifferentialEvidence, ...] = Field(
        default=(), max_length=20
    )
    graphql_trace_events: tuple[GraphQLRuntimeTraceEvent, ...] = Field(
        default=(), max_length=40
    )
    request_accounting_reference: OpaqueIdentifier
    runtime_provenance_reference: OpaqueIdentifier

    @model_validator(mode="after")
    def enforce_safe_evidence(self) -> "PrimitiveExecutionEvidence":
        reject_secret_material(
            self.model_dump(mode="json"), location="research runtime evidence"
        )
        return self


class CleanupExecutionResult(ResearchContract):
    status: CleanupStatus
    cleanup_reference: OpaqueIdentifier | None = None
    evidence_reference: EvidenceArtifactId | None = None
    requests_used: StrictInt = Field(default=0, ge=0, le=100)
    graphql_trace_event: GraphQLRuntimeTraceEvent | None = None


class RuntimeProvenance(ResearchContract):
    runtime_name: OpaqueIdentifier
    runtime_version: OpaqueIdentifier
    executor_registry_hash: Sha256Digest
    primitive_registry_hash: Sha256Digest
    policy_reference: OpaqueIdentifier
    policy_hash: Sha256Digest
    target_fingerprint: Sha256Digest


class ProposedExecutionMetadata(ResearchContract):
    dry_run: StrictBool
    primitive_routes: tuple[OpaqueIdentifier, ...] = Field(max_length=30)
    verification_reservation: StrictInt = Field(ge=0, le=10_000)
    cleanup_reservation: StrictInt = Field(ge=0, le=10_000)
    total_reservation: StrictInt = Field(ge=0, le=10_000)


class ExperimentOutcome(StoredExperimentOutcome):
    """Runtime result plus the P4-0D authority and safe-evidence references."""

    result_classification: ExperimentResultClassification
    evidence: tuple[PrimitiveExecutionEvidence, ...] = Field(default=(), max_length=200)
    cleanup_result: CleanupExecutionResult
    runtime_provenance: RuntimeProvenance
    authorization_reference: Sha256Digest
    runtime_binding_reference: OpaqueIdentifier
    proposed_execution: ProposedExecutionMetadata | None = None

    @model_validator(mode="after")
    def enforce_runtime_boundary(self) -> "ExperimentOutcome":
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(evidence_ids) != len(set(evidence_ids)) or set(evidence_ids) != set(
            self.evidence_references
        ):
            raise ValueError("outcome evidence objects must match evidence references")
        reject_secret_material(
            self.model_dump(mode="json"), location="research experiment outcome"
        )
        return self


__all__ = [
    "CleanupExecutionResult",
    "ExperimentOutcome",
    "ExperimentResultClassification",
    "GraphQLErrorPathEvidence",
    "GraphQLRuntimeResponseEvidence",
    "GraphQLStateDifferentialEvidence",
    "GraphQLRuntimeTraceEvent",
    "InvariantResult",
    "PrimitiveExecutionEvidence",
    "ProposedExecutionMetadata",
    "RuntimeProvenance",
    "ReproductionOutcome",
    "SafeRequestSummary",
    "SafeResponseSummary",
    "SelectorResult",
    "StoredExperimentOutcome",
]
