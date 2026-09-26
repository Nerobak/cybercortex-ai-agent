"""Strict, inert contracts for cross-surface attack-chain research.

The records in this module contain references and public-safe descriptions only.
They are not request plans, credentials, executable instructions, authorization,
or proof of a vulnerability.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum

from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.models import ModelUsageDelta
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import public_result
from agent_core.research.types import (
    AttackChainId,
    CleanupStatus,
    EntityReference,
    EvidenceArtifactId,
    FindingId,
    HypothesisRecordId,
    OpaqueIdentifier,
    ProvenanceRecordId,
    PublicText,
    ResearchConfidence,
    ResearchContract,
    ResearchId,
    Sha256Digest,
    ShortPublicText,
    Timestamp,
)

MAX_CHAIN_DEPTH = 4
MAX_CHAIN_CANDIDATES = 20
MAX_UNRESOLVED_LINKS = 3
MAX_ACTIVE_CHAIN_HYPOTHESES = 5
MAX_CHAIN_PACKET_BYTES = 8_192
STRICT_CHAIN_PACKET_TARGET_BYTES = 5_120


class AttackChainStepKind(str, Enum):
    finding = "finding"
    fact = "fact"
    relationship = "relationship"
    experiment = "experiment"
    identity_transition = "identity_transition"
    object_transition = "object_transition"
    surface_transition = "surface_transition"
    workflow_transition = "workflow_transition"


class ChainLinkStatus(str, Enum):
    unresolved = "unresolved"
    supported = "supported"
    refuted = "refuted"
    policy_blocked = "policy_blocked"
    cleanup_failed = "cleanup_failed"
    scope_invalid = "scope_invalid"
    identity_invalid = "identity_invalid"
    object_invalid = "object_invalid"
    budget_exhausted = "budget_exhausted"
    inconclusive = "inconclusive"

    @property
    def breaks_prerequisite(self) -> bool:
        return self in {
            ChainLinkStatus.refuted,
            ChainLinkStatus.policy_blocked,
            ChainLinkStatus.cleanup_failed,
            ChainLinkStatus.scope_invalid,
            ChainLinkStatus.identity_invalid,
            ChainLinkStatus.object_invalid,
            ChainLinkStatus.budget_exhausted,
        }


class ChainSelectionAction(str, Enum):
    select_candidate = "select_candidate"
    defer = "defer"
    stop = "stop"


class AttackChainEvaluationClassification(str, Enum):
    supported = "supported"
    refuted = "refuted"
    inconclusive = "inconclusive"
    blocked = "blocked"
    candidate_chain_finding = "candidate_chain_finding"


class ChainConfirmationAction(str, Enum):
    confirm = "confirm"
    reject = "reject"
    remain_candidate = "remain_candidate"
    manual_review = "manual_review"


class UnresolvedChainLink(ResearchContract):
    """One explicit gap. It may be tested, but must never be assumed true."""

    link_id: OpaqueIdentifier
    from_reference: EntityReference
    to_reference: EntityReference
    claim: PublicText
    required_evidence: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=20)
    allowed_experiment_capabilities: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=20
    )
    risk: RiskLevel
    request_estimate: StrictInt = Field(ge=0, le=10_000)
    status: ChainLinkStatus = ChainLinkStatus.unresolved
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    experiment_id: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> "UnresolvedChainLink":
        object.__setattr__(
            self,
            "required_evidence",
            tuple(sorted(set(self.required_evidence))),
        )
        object.__setattr__(
            self,
            "allowed_experiment_capabilities",
            tuple(sorted(set(self.allowed_experiment_capabilities))),
        )
        object.__setattr__(
            self,
            "evidence_references",
            tuple(sorted(set(self.evidence_references))),
        )
        if self.status is ChainLinkStatus.supported and not self.evidence_references:
            raise ValueError("a supported chain link requires evidence")
        if self.status is ChainLinkStatus.refuted and not self.evidence_references:
            raise ValueError("a refuted chain link requires evidence")
        _enforce_public_boundary(self, "unresolved chain link")
        return self


class AttackChainCandidate(ResearchContract):
    """A deterministically eligible chain possibility with no authority."""

    candidate_id: OpaqueIdentifier
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    category: OpaqueIdentifier
    ordered_references: tuple[EntityReference, ...] = Field(
        min_length=2, max_length=MAX_CHAIN_DEPTH
    )
    target_ids: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=16)
    surface_ids: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=16)
    identity_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    object_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    hypothesis_ids: tuple[HypothesisRecordId, ...] = Field(default=(), max_length=20)
    finding_ids: tuple[FindingId, ...] = Field(default=(), max_length=20)
    fact_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    relationship_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    entry_condition: PublicText
    security_property: PublicText
    expected_secure_behavior: PublicText
    expected_chain_behavior: PublicText
    expected_information_value: StrictFloat = Field(ge=0.0, le=1.0)
    required_unresolved_links: tuple[UnresolvedChainLink, ...] = Field(
        default=(), max_length=MAX_UNRESOLVED_LINKS
    )
    available_experiment_candidates: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    request_cost_estimate: StrictInt = Field(ge=0, le=100_000)
    risk: RiskLevel
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=300
    )
    provenance_references: tuple[ProvenanceRecordId, ...] = Field(
        min_length=1, max_length=100
    )
    semantic_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_candidate(self) -> "AttackChainCandidate":
        ordered_markers = tuple(
            (item.entity_kind, item.entity_id) for item in self.ordered_references
        )
        if len(ordered_markers) != len(set(ordered_markers)):
            raise ValueError("chain candidate references must be acyclic")
        for field_name in (
            "target_ids",
            "surface_ids",
            "identity_ids",
            "object_ids",
            "hypothesis_ids",
            "finding_ids",
            "fact_ids",
            "relationship_ids",
            "available_experiment_candidates",
            "evidence_references",
            "provenance_references",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
            object.__setattr__(self, field_name, tuple(sorted(values)))
        links = tuple(item.link_id for item in self.required_unresolved_links)
        if len(links) != len(set(links)):
            raise ValueError("candidate unresolved-link IDs must be unique")
        ordered_edges = set(zip(ordered_markers, ordered_markers[1:]))
        if any(
            (
                (item.from_reference.entity_kind, item.from_reference.entity_id),
                (item.to_reference.entity_kind, item.to_reference.entity_id),
            )
            not in ordered_edges
            for item in self.required_unresolved_links
        ):
            raise ValueError("candidate unresolved links must bind adjacent references")
        if self.request_cost_estimate != sum(
            item.request_estimate for item in self.required_unresolved_links
        ):
            raise ValueError("chain request estimate must equal unresolved-link costs")
        expected = chain_candidate_fingerprint(self)
        if self.semantic_fingerprint != expected:
            raise ValueError("chain candidate fingerprint does not match its bindings")
        _enforce_public_boundary(self, "attack-chain candidate")
        return self


class PublicSafeChainCandidateSummary(ResearchContract):
    candidate_id: OpaqueIdentifier
    category: OpaqueIdentifier
    ordered_reference_ids: tuple[OpaqueIdentifier, ...] = Field(
        min_length=2, max_length=MAX_CHAIN_DEPTH
    )
    surface_ids: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=16)
    identity_context_count: StrictInt = Field(ge=0, le=20)
    object_context_count: StrictInt = Field(ge=0, le=20)
    unresolved_link_count: StrictInt = Field(ge=0, le=MAX_UNRESOLVED_LINKS)
    available_experiment_candidate_ids: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    request_cost_estimate: StrictInt = Field(ge=0, le=100_000)
    risk: RiskLevel
    expected_information_value: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=300
    )


class ChainBudgetSummary(ResearchContract):
    candidates: StrictInt = Field(ge=0)
    active_hypotheses: StrictInt = Field(ge=0)
    experiments: StrictInt = Field(ge=0)
    target_requests: StrictInt = Field(ge=0)
    model_calls: StrictInt = Field(ge=0)
    reproductions: StrictInt = Field(ge=0)
    state_changes: StrictInt = Field(ge=0)


class PublicSafeChainPacket(ResearchContract):
    """Compact selection packet containing only candidate reference closure."""

    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    candidates: tuple[PublicSafeChainCandidateSummary, ...] = Field(
        min_length=1, max_length=MAX_CHAIN_CANDIDATES
    )
    remaining_budgets: ChainBudgetSummary
    policy_limitations: tuple[ShortPublicText, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def validate_packet(self) -> "PublicSafeChainPacket":
        ids = tuple(item.candidate_id for item in self.candidates)
        if len(ids) != len(set(ids)):
            raise ValueError("chain packet candidate IDs must be unique")
        _enforce_public_boundary(self, "public-safe chain packet")
        if self.serialized_size > MAX_CHAIN_PACKET_BYTES:
            raise ValueError("public-safe chain packet exceeds 8 KB")
        return self

    @property
    def serialized_size(self) -> int:
        return len(
            json.dumps(
                self.model_dump(mode="json", exclude_defaults=True, exclude_none=True),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        )

    def public_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_defaults=True, exclude_none=True)


class ChainSelectionDecision(ResearchContract):
    """Strategy advice. Candidate bindings and steps are intentionally absent."""

    decision_id: OpaqueIdentifier
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    action: ChainSelectionAction
    selected_chain_candidate_id: OpaqueIdentifier | None = None
    priority: StrictInt = Field(ge=0, le=100)
    confidence: ResearchConfidence
    expected_information_gain: StrictFloat = Field(ge=0.0, le=1.0)
    reasoning_summary: ShortPublicText
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    missing_evidence: tuple[ShortPublicText, ...] = Field(default=(), max_length=20)
    stop_reason: ShortPublicText | None = None

    @model_validator(mode="after")
    def validate_action(self) -> "ChainSelectionDecision":
        selected = self.action is ChainSelectionAction.select_candidate
        if selected != (self.selected_chain_candidate_id is not None):
            raise ValueError("chain selection has an invalid candidate binding")
        if (self.action is ChainSelectionAction.stop) != (self.stop_reason is not None):
            raise ValueError("only a stop decision may include a stop reason")
        _enforce_public_boundary(self, "chain selection decision")
        return self


class AttackChainHypothesis(ResearchContract):
    """Falsifiable hypothesis copied from an immutable eligible candidate."""

    hypothesis_id: OpaqueIdentifier
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    chain_candidate_id: OpaqueIdentifier
    category: OpaqueIdentifier
    claim: PublicText
    falsification_criterion: PublicText
    ordered_references: tuple[EntityReference, ...] = Field(
        min_length=2, max_length=MAX_CHAIN_DEPTH
    )
    unresolved_links: tuple[UnresolvedChainLink, ...] = Field(
        default=(), max_length=MAX_UNRESOLVED_LINKS
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=200
    )
    confidence: ResearchConfidence = ResearchConfidence.low
    confirmation_policy_reference: OpaqueIdentifier
    provenance_references: tuple[ProvenanceRecordId, ...] = Field(
        min_length=1, max_length=100
    )
    semantic_fingerprint: Sha256Digest

    @model_validator(mode="after")
    def validate_hypothesis(self) -> "AttackChainHypothesis":
        ordered_markers = tuple(
            (item.entity_kind, item.entity_id) for item in self.ordered_references
        )
        if len(ordered_markers) != len(set(ordered_markers)):
            raise ValueError("chain hypothesis references must be acyclic")
        link_ids = tuple(item.link_id for item in self.unresolved_links)
        if len(link_ids) != len(set(link_ids)):
            raise ValueError("chain unresolved-link IDs must be unique")
        ordered_edges = set(zip(ordered_markers, ordered_markers[1:]))
        if any(
            (
                (item.from_reference.entity_kind, item.from_reference.entity_id),
                (item.to_reference.entity_kind, item.to_reference.entity_id),
            )
            not in ordered_edges
            for item in self.unresolved_links
        ):
            raise ValueError("chain hypothesis links must bind adjacent references")
        for field_name in ("evidence_references", "provenance_references"):
            object.__setattr__(
                self, field_name, tuple(sorted(set(getattr(self, field_name))))
            )
        _enforce_public_boundary(self, "attack-chain hypothesis")
        return self


class ChainStepOutcome(ResearchContract):
    outcome_id: OpaqueIdentifier
    chain_id: AttackChainId
    step_id: OpaqueIdentifier
    sequence: StrictInt = Field(ge=1, le=MAX_CHAIN_DEPTH)
    status: ChainLinkStatus
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    experiment_id: OpaqueIdentifier | None = None
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    cleanup_status: CleanupStatus = CleanupStatus.not_required
    authorization_reference: Sha256Digest | None = None
    provenance_id: ProvenanceRecordId | None = None
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_outcome(self) -> "ChainStepOutcome":
        object.__setattr__(
            self,
            "evidence_references",
            tuple(sorted(set(self.evidence_references))),
        )
        if self.status in {ChainLinkStatus.supported, ChainLinkStatus.refuted} and not (
            self.evidence_references
        ):
            raise ValueError("a conclusive chain step requires evidence")
        if self.request_delta.total and self.authorization_reference is None:
            raise ValueError("an executed chain step requires fresh authorization")
        return self


class AttackChainEvaluation(ResearchContract):
    evaluation_id: OpaqueIdentifier
    research_id: ResearchId
    chain_id: AttackChainId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    classification: AttackChainEvaluationClassification
    evaluated_step_ids: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=MAX_CHAIN_DEPTH
    )
    supported_link_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    refuted_link_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    blocking_reason: OpaqueIdentifier | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=300
    )
    combined_impact_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    downstream_steps_skipped: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=MAX_CHAIN_DEPTH
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    provenance_id: ProvenanceRecordId | None = None
    summary: ShortPublicText
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_classification(self) -> "AttackChainEvaluation":
        for field_name in (
            "evaluated_step_ids",
            "supported_link_ids",
            "refuted_link_ids",
            "evidence_references",
            "combined_impact_evidence",
            "downstream_steps_skipped",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
        if (
            self.classification
            is AttackChainEvaluationClassification.candidate_chain_finding
            and not self.combined_impact_evidence
        ):
            raise ValueError("a candidate chain finding requires combined impact")
        if self.classification is AttackChainEvaluationClassification.refuted and not (
            self.refuted_link_ids
        ):
            raise ValueError("a refuted chain requires a refuted link")
        if self.classification is AttackChainEvaluationClassification.blocked and (
            self.blocking_reason is None
        ):
            raise ValueError("a blocked chain requires a reason")
        return self


class ChainReproductionPlan(ResearchContract):
    reproduction_id: OpaqueIdentifier
    chain_id: AttackChainId
    finding_id: FindingId
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    ordered_step_plan_ids: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=MAX_CHAIN_DEPTH
    )
    ordered_chain_step_ids: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=MAX_CHAIN_DEPTH
    )
    component_finding_ids: tuple[FindingId, ...] = Field(
        default=(), max_length=MAX_CHAIN_DEPTH
    )
    fresh_authorization_required: StrictBool = True
    fresh_target_requests_required: StrictBool = True
    preserve_ordering: StrictBool = True
    cleanup_required: StrictBool = True
    maximum_target_requests: StrictInt = Field(ge=1, le=10_000)
    confirmation_policy_reference: OpaqueIdentifier
    provenance_id: ProvenanceRecordId
    created_at: Timestamp

    @model_validator(mode="after")
    def enforce_independence(self) -> "ChainReproductionPlan":
        if not (
            self.fresh_authorization_required
            and self.fresh_target_requests_required
            and self.preserve_ordering
        ):
            raise ValueError("chain reproduction must be fresh and ordered")
        if len(self.ordered_step_plan_ids) != len(set(self.ordered_step_plan_ids)):
            raise ValueError("chain reproduction plan IDs must be unique")
        if len(self.ordered_chain_step_ids) != len(set(self.ordered_chain_step_ids)):
            raise ValueError("chain reproduction step IDs must be unique")
        if len(self.ordered_step_plan_ids) != len(self.ordered_chain_step_ids):
            raise ValueError("chain reproduction plans must bind every chain step")
        return self


class ChainReproductionOutcome(ResearchContract):
    reproduction_id: OpaqueIdentifier
    chain_id: AttackChainId
    finding_id: FindingId
    status: ChainLinkStatus
    step_outcome_ids: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=MAX_CHAIN_DEPTH
    )
    fresh_authorization_references: tuple[Sha256Digest, ...] = Field(
        min_length=1, max_length=MAX_CHAIN_DEPTH
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=300
    )
    combined_impact_evidence: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    cleanup_status: CleanupStatus
    ordering_valid: StrictBool = True
    dependencies_preserved: StrictBool = True
    provenance_id: ProvenanceRecordId | None = None
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_fresh_ordered_evidence(self) -> "ChainReproductionOutcome":
        if len(self.step_outcome_ids) != len(set(self.step_outcome_ids)):
            raise ValueError("chain reproduction step outcomes must be unique")
        if len(self.fresh_authorization_references) != len(self.step_outcome_ids):
            raise ValueError("every reproduced chain step requires fresh authorization")
        if len(self.fresh_authorization_references) != len(
            set(self.fresh_authorization_references)
        ):
            raise ValueError("reproduced chain steps require distinct authorizations")
        if self.request_delta.total <= 0:
            raise ValueError("chain reproduction requires fresh target requests")
        if not self.ordering_valid or not self.dependencies_preserved:
            raise ValueError(
                "chain reproduction must preserve ordering and dependencies"
            )
        if self.status is ChainLinkStatus.supported and not (
            self.combined_impact_evidence
        ):
            raise ValueError("supported reproduction requires combined impact evidence")
        if not set(self.combined_impact_evidence).issubset(self.evidence_references):
            raise ValueError("combined impact must be backed by reproduction evidence")
        return self


class ChainConfirmationPolicy(ResearchContract):
    policy_reference: OpaqueIdentifier = "chain-confirmation-policy-v1"
    minimum_independent_reproductions: StrictInt = Field(default=1, ge=1, le=10)
    require_live_reproduction: StrictBool = True
    require_component_evidence: StrictBool = True
    require_all_links_resolved: StrictBool = True
    require_ordering: StrictBool = True
    require_combined_impact: StrictBool = True
    require_cleanup: StrictBool = True
    reject_on_contradiction: StrictBool = True

    @property
    def fingerprint(self) -> Sha256Digest:
        return stable_chain_digest(self.model_dump(mode="json"))


class ChainConfirmationDecision(ResearchContract):
    decision_id: OpaqueIdentifier
    chain_id: AttackChainId
    finding_id: FindingId
    action: ChainConfirmationAction
    policy_reference: OpaqueIdentifier
    policy_fingerprint: Sha256Digest
    reproduction_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    confirmed_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=300
    )
    conflicting_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=200
    )
    reason_code: OpaqueIdentifier
    occurred_at: Timestamp

    @model_validator(mode="after")
    def validate_decision(self) -> "ChainConfirmationDecision":
        for field_name in (
            "reproduction_ids",
            "confirmed_evidence_references",
            "conflicting_evidence_references",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique")
            object.__setattr__(self, field_name, tuple(sorted(values)))
        if self.action is ChainConfirmationAction.confirm and not (
            self.reproduction_ids and self.confirmed_evidence_references
        ):
            raise ValueError("chain confirmation requires fresh reproduction evidence")
        if self.action is ChainConfirmationAction.reject and not (
            self.conflicting_evidence_references
        ):
            raise ValueError("chain rejection requires contradictory evidence")
        return self


class ChainBudgetLimits(ResearchContract):
    maximum_chain_candidates: StrictInt = Field(
        default=MAX_CHAIN_CANDIDATES, ge=1, le=MAX_CHAIN_CANDIDATES
    )
    maximum_active_chain_hypotheses: StrictInt = Field(
        default=MAX_ACTIVE_CHAIN_HYPOTHESES,
        ge=1,
        le=MAX_ACTIVE_CHAIN_HYPOTHESES,
    )
    maximum_unresolved_links_per_chain: StrictInt = Field(
        default=MAX_UNRESOLVED_LINKS, ge=0, le=MAX_UNRESOLVED_LINKS
    )
    maximum_chain_depth: StrictInt = Field(
        default=MAX_CHAIN_DEPTH, ge=2, le=MAX_CHAIN_DEPTH
    )
    maximum_chain_experiments: StrictInt = Field(default=8, ge=0, le=1_000)
    maximum_chain_target_requests: StrictInt = Field(default=20, ge=0, le=10_000)
    maximum_chain_model_calls: StrictInt = Field(default=1, ge=0, le=100)
    maximum_chain_reproductions: StrictInt = Field(default=2, ge=0, le=100)
    wall_time_ceiling_seconds: StrictFloat = Field(default=300.0, ge=1.0, le=86_400.0)
    state_changing_chain_ceiling: StrictInt = Field(default=0, ge=0, le=100)


class ChainBudgetState(ResearchContract):
    budget_reference: OpaqueIdentifier
    limits: ChainBudgetLimits = Field(default_factory=ChainBudgetLimits)
    candidates_considered: StrictInt = Field(default=0, ge=0, le=100_000)
    active_hypotheses: StrictInt = Field(default=0, ge=0, le=10_000)
    experiments_consumed: StrictInt = Field(default=0, ge=0, le=100_000)
    target_requests_consumed: StrictInt = Field(default=0, ge=0, le=1_000_000)
    model_usage: ModelUsageDelta = Field(default_factory=ModelUsageDelta)
    reproductions_consumed: StrictInt = Field(default=0, ge=0, le=10_000)
    wall_time_consumed_seconds: StrictFloat = Field(default=0.0, ge=0.0, le=86_400.0)
    state_changes_consumed: StrictInt = Field(default=0, ge=0, le=10_000)
    completed_step_ids: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=10_000
    )
    authoritative_request_ledger_reference: OpaqueIdentifier
    authoritative_request_total_observed: StrictInt = Field(
        default=0, ge=0, le=10_000_000
    )
    authoritative_model_calls_observed: StrictInt = Field(default=0, ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_usage(self) -> "ChainBudgetState":
        if "authoritative_request_total_observed" not in self.model_fields_set:
            object.__setattr__(
                self,
                "authoritative_request_total_observed",
                self.target_requests_consumed,
            )
        if "authoritative_model_calls_observed" not in self.model_fields_set:
            object.__setattr__(
                self,
                "authoritative_model_calls_observed",
                self.model_usage.attempted_calls,
            )
        if self.candidates_considered > self.limits.maximum_chain_candidates:
            raise ValueError("chain candidate budget exceeded")
        if self.active_hypotheses > self.limits.maximum_active_chain_hypotheses:
            raise ValueError("active chain-hypothesis budget exceeded")
        if self.experiments_consumed > self.limits.maximum_chain_experiments:
            raise ValueError("chain experiment budget exceeded")
        if self.target_requests_consumed > self.limits.maximum_chain_target_requests:
            raise ValueError("chain request budget exceeded")
        if self.model_usage.attempted_calls > self.limits.maximum_chain_model_calls:
            raise ValueError("chain model-call budget exceeded")
        if self.reproductions_consumed > self.limits.maximum_chain_reproductions:
            raise ValueError("chain reproduction budget exceeded")
        if self.wall_time_consumed_seconds > self.limits.wall_time_ceiling_seconds:
            raise ValueError("chain wall-time budget exceeded")
        if self.state_changes_consumed > self.limits.state_changing_chain_ceiling:
            raise ValueError("chain state-change budget exceeded")
        if self.target_requests_consumed > self.authoritative_request_total_observed:
            raise ValueError("chain requests exceed the authoritative request ledger")
        if self.model_usage.attempted_calls > self.authoritative_model_calls_observed:
            raise ValueError("chain model calls exceed the authoritative model ledger")
        object.__setattr__(
            self, "completed_step_ids", tuple(sorted(set(self.completed_step_ids)))
        )
        return self


def stable_chain_digest(value: object) -> Sha256Digest:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def stable_chain_identifier(prefix: str, value: object) -> str:
    return f"{prefix}-{stable_chain_digest(value)[7:31]}"


def chain_candidate_fingerprint(candidate: AttackChainCandidate) -> Sha256Digest:
    """Deduplicate semantic links independently of IDs, time, and wording."""

    return stable_chain_digest(
        {
            "category": candidate.category,
            "ordered_links": [
                (item.entity_kind.value, item.entity_id)
                for item in candidate.ordered_references
            ],
            "security_property": candidate.security_property,
            "surfaces": sorted(candidate.surface_ids),
            "identities": sorted(candidate.identity_ids),
            "objects": sorted(candidate.object_ids),
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
                for item in candidate.required_unresolved_links
            ],
        }
    )


def _enforce_public_boundary(record: ResearchContract, location: str) -> None:
    payload = record.model_dump(mode="json")
    if public_result(payload) != payload:
        raise ValueError(f"{location} is outside the public-safe boundary")
    enforce_chain_public_boundary(payload, location=location)


def enforce_chain_public_boundary(value: object, *, location: str) -> None:
    """Reject likely raw secrets, raw requests, executables, and hidden reasoning."""

    forbidden_keys = {
        "authorization",
        "cookie",
        "credentials",
        "jwt",
        "password",
        "raw_request",
        "request_body",
        "response_body",
        "secret",
        "shell",
        "token_value",
        "chain_of_thought",
    }
    sensitive_value = re.compile(
        r"(?:\bBearer\s+[A-Za-z0-9._~+/-]+=*|"
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
        r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{12,}\b|"
        r"(?:^|\n)\s*(?:GET|POST|PUT|PATCH|DELETE)\s+/\S+|"
        r"\b(?:curl|wget|powershell|bash|zsh)\s+|```)",
        re.IGNORECASE,
    )

    def visit(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                normalized = str(key).lower().replace("-", "_")
                if normalized in forbidden_keys:
                    raise ValueError(f"{location} contains forbidden private material")
                visit(nested)
        elif isinstance(item, (tuple, list)):
            for nested in item:
                visit(nested)
        elif isinstance(item, str) and sensitive_value.search(item):
            raise ValueError(f"{location} contains forbidden private material")

    visit(value)


__all__ = [
    "AttackChainEvaluation",
    "AttackChainEvaluationClassification",
    "AttackChainCandidate",
    "AttackChainHypothesis",
    "AttackChainStepKind",
    "ChainBudgetLimits",
    "ChainBudgetSummary",
    "ChainBudgetState",
    "ChainConfirmationAction",
    "ChainConfirmationDecision",
    "ChainConfirmationPolicy",
    "ChainLinkStatus",
    "ChainReproductionOutcome",
    "ChainReproductionPlan",
    "ChainSelectionAction",
    "ChainSelectionDecision",
    "ChainStepOutcome",
    "MAX_ACTIVE_CHAIN_HYPOTHESES",
    "MAX_CHAIN_CANDIDATES",
    "MAX_CHAIN_DEPTH",
    "MAX_CHAIN_PACKET_BYTES",
    "MAX_UNRESOLVED_LINKS",
    "PublicSafeChainCandidateSummary",
    "PublicSafeChainPacket",
    "STRICT_CHAIN_PACKET_TARGET_BYTES",
    "UnresolvedChainLink",
    "chain_candidate_fingerprint",
    "enforce_chain_public_boundary",
    "stable_chain_digest",
    "stable_chain_identifier",
]
