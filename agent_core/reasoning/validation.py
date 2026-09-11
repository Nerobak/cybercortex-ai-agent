"""Deterministic grounding and semantic validation for advisory decisions."""

from __future__ import annotations

from agent_core.reasoning.errors import ReasoningError, ReasoningErrorCode
from agent_core.reasoning.evidence import build_capability_catalog
from agent_core.reasoning.types import (
    AUTOMATIC_EXECUTION_ELIGIBILITY_REQUIRED,
    PHASE2_PLAN_POLICY_AUTHORIZATION_REQUIRED,
    CapabilityCatalogEntry,
    EvidencePacket,
    ReasoningAction,
    ReasoningCandidate,
    ReasoningDecision,
    ReasoningModelProvenance,
    ReasoningRequest,
)


def validate_reasoning_request(request: ReasoningRequest) -> None:
    """Reject forged catalog facts or policy references before a model call."""

    canonical = build_capability_catalog()
    if request.capability_catalog != canonical:
        raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)
    known = {entry.category for entry in canonical.entries}
    constrained = set(request.policy_constraints.allowed_recommendation_categories)
    blocked = set(request.policy_constraints.blocked_categories)
    if not constrained.issubset(known) or not blocked.issubset(known):
        raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)
    for packet in request.evidence_packets:
        capability = canonical.entry(packet.category)
        if capability is None or not _packet_matches_capability(packet, capability):
            raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)
    if any(
        decision.recommended_capability is not None
        and decision.recommended_capability not in known
        for decision in request.previous_decisions
    ):
        raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)


def _packet_matches_capability(
    packet: EvidencePacket, capability: CapabilityCatalogEntry
) -> bool:
    return bool(
        packet.capability_state == capability.capability_state
        and packet.typed_executor_available == capability.typed_executor_available
        and packet.min_requests == capability.min_requests
        and packet.worst_case_requests == capability.worst_case_requests
    )


def validate_reasoning_candidate(
    candidate: ReasoningCandidate,
    request: ReasoningRequest,
    provenance: ReasoningModelProvenance,
) -> ReasoningDecision:
    """Bind an untrusted candidate to Phase 2 registry and policy-safe truth."""

    packets = {packet.hypothesis_id: packet for packet in request.evidence_packets}
    packet = packets.get(candidate.hypothesis_id)
    if packet is None:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    catalog = request.capability_catalog
    capability = (
        catalog.entry(candidate.recommended_capability)
        if candidate.recommended_capability is not None
        else None
    )
    if candidate.recommended_capability is not None and capability is None:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if capability is not None and capability.category != packet.category:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if not set(candidate.evidence_references).issubset(packet.evidence_references):
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)

    required_preconditions: tuple[str, ...] = ()
    if candidate.action is ReasoningAction.recommend_verification:
        required_preconditions = _validate_verification_recommendation(
            candidate, packet, capability, request
        )
    else:
        _validate_non_verification_recommendation(candidate, capability)

    if (
        candidate.action is ReasoningAction.request_additional_evidence
        and not candidate.missing_evidence
    ):
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if candidate.action is ReasoningAction.stop:
        if candidate.stop_reason is None:
            raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    elif candidate.stop_reason is not None:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)

    prior_status = (
        packet.prior_verification.status if packet.prior_verification else None
    )
    return ReasoningDecision(
        **candidate.model_dump(mode="python"),
        required_preconditions=required_preconditions,
        prior_result_status=prior_status,
        model_provenance=provenance,
    )


def _validate_verification_recommendation(
    candidate: ReasoningCandidate,
    packet: EvidencePacket,
    capability: CapabilityCatalogEntry | None,
    request: ReasoningRequest,
) -> tuple[str, ...]:
    if capability is None:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if (
        capability.capability_state != "typed_verification"
        or not capability.typed_executor_available
        or not capability.automatic_execution_supported
    ):
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    constraints = request.policy_constraints
    if (
        capability.category not in constraints.allowed_recommendation_categories
        or capability.category in constraints.blocked_categories
        or not constraints.controlled_context_available
        or packet.plan_policy_decision == "blocked"
    ):
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if packet.prior_verification is not None and packet.prior_verification.status in {
        "verified",
        "rejected",
        "policy_blocked",
    }:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if not (
        capability.min_requests
        <= candidate.estimated_request_cost
        <= capability.worst_case_requests
    ):
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    remaining = constraints.remaining_target_request_budget
    if remaining is not None and candidate.estimated_request_cost > remaining:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    unresolved_execution_readiness: list[str] = []
    if packet.plan_policy_decision == "pending":
        unresolved_execution_readiness.append(PHASE2_PLAN_POLICY_AUTHORIZATION_REQUIRED)
    if (
        packet.plan_policy_decision is not None
        and not packet.plan_automatic_execution_allowed
    ):
        unresolved_execution_readiness.append(AUTOMATIC_EXECUTION_ELIGIBILITY_REQUIRED)
    return tuple(
        dict.fromkeys(
            (*capability.major_preconditions, *unresolved_execution_readiness)
        )
    )


def _validate_non_verification_recommendation(
    candidate: ReasoningCandidate,
    capability: CapabilityCatalogEntry | None,
) -> None:
    if candidate.estimated_request_cost != 0:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    if capability is None:
        return
    if candidate.action not in {
        ReasoningAction.manual_review,
        ReasoningAction.request_additional_evidence,
    }:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
