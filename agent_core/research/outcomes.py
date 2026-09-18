"""Secret-safe authoritative outcomes for deterministic research execution."""

from __future__ import annotations

from enum import Enum

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import ExperimentOutcome as StoredExperimentOutcome
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
    "InvariantResult",
    "PrimitiveExecutionEvidence",
    "ProposedExecutionMetadata",
    "RuntimeProvenance",
    "SafeRequestSummary",
    "SafeResponseSummary",
    "SelectorResult",
    "StoredExperimentOutcome",
]
