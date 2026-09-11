"""Conservative deterministic consensus arbitration and P3-4 mapping."""

from __future__ import annotations

import hashlib
import json

from agent_core.consensus.agreement import AgreementAssessment
from agent_core.consensus.types import (
    ConsensusDecision,
    ConsensusRequest,
    ParticipantOutcome,
    ParticipantStatus,
    SplitBehavior,
)
from agent_core.models import ModelUsageDelta, add_model_usage_deltas
from agent_core.reasoning import (
    ConfidenceLevel,
    ConsensusParticipantProvenance,
    InformationGain,
    ReasoningAction,
    ReasoningCandidate,
    ReasoningDecision,
    ReasoningError,
    ReasoningErrorCode,
    ReasoningModelProvenance,
    ReasoningConsensusProvenance,
    validate_reasoning_candidate,
)


def aggregate_model_usage(
    outcomes: tuple[ParticipantOutcome, ...],
) -> ModelUsageDelta:
    usage = ModelUsageDelta()
    for outcome in outcomes:
        usage = add_model_usage_deltas(usage, outcome.usage)
    return usage


def arbitrate_consensus(
    request: ConsensusRequest,
    outcomes: tuple[ParticipantOutcome, ...],
    assessment: AgreementAssessment,
) -> ConsensusDecision:
    valid = tuple(
        item
        for item in outcomes
        if item.status is ParticipantStatus.valid and item.decision is not None
    )
    fallback_hypothesis = sorted(
        packet.hypothesis_id for packet in request.reasoning_request.evidence_packets
    )[0]
    if assessment.selected_vote is not None:
        hypothesis_id, selected_action, selected_capability = assessment.selected_vote
        support = {
            item.decision.decision_id: item.decision
            for item in valid
            if item.decision is not None
            and item.decision.decision_id in assessment.supporting_decision_ids
        }
        evidence_references = tuple(
            sorted(
                {
                    reference
                    for decision in support.values()
                    for reference in decision.evidence_references
                }
            )
        )
    else:
        hypothesis_id = fallback_hypothesis
        selected_action = _split_action(request.policy.split_behavior)
        selected_capability = None
        evidence_references = tuple(
            sorted(
                {
                    reference
                    for item in valid
                    if item.decision is not None
                    for reference in item.decision.evidence_references
                    if item.decision.hypothesis_id == hypothesis_id
                }
            )
        )
    usage = aggregate_model_usage(outcomes)
    identity = {
        "run_id": request.run_id,
        "iteration": request.iteration_reference,
        "participants": [item.participant_id for item in outcomes],
        "support": list(assessment.supporting_decision_ids),
        "dissent": list(assessment.dissenting_decision_ids),
        "agreement": assessment.agreement_type.value,
    }
    consensus_id = (
        "consensus-"
        + hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
    )
    return ConsensusDecision(
        consensus_id=consensus_id,
        hypothesis_id=hypothesis_id,
        agreement_type=assessment.agreement_type,
        participant_count=len(outcomes),
        valid_decision_count=len(valid),
        selected_action=selected_action,
        selected_capability=selected_capability,
        aggregate_confidence=assessment.aggregate_confidence,
        supporting_decision_ids=assessment.supporting_decision_ids,
        dissenting_decision_ids=assessment.dissenting_decision_ids,
        evidence_references=evidence_references,
        arbitration_reason=assessment.arbitration_reason,
        invalid_participants=tuple(
            item.participant_id
            for item in outcomes
            if item.status is ParticipantStatus.invalid
        ),
        failed_participants=tuple(
            item.participant_id
            for item in outcomes
            if item.status
            in {ParticipantStatus.failed, ParticipantStatus.budget_blocked}
        ),
        model_usage=usage,
    )


def consensus_to_reasoning_decision(
    consensus: ConsensusDecision,
    outcomes: tuple[ParticipantOutcome, ...],
    request: ConsensusRequest,
) -> ReasoningDecision:
    """Create advisory P3-4-compatible data; this function cannot execute it."""

    supporting = tuple(
        item.decision
        for item in outcomes
        if item.decision is not None
        and item.decision.decision_id in consensus.supporting_decision_ids
    )
    packet = next(
        (
            item
            for item in request.reasoning_request.evidence_packets
            if item.hypothesis_id == consensus.hypothesis_id
        ),
        None,
    )
    if packet is None:
        raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
    priority = max((item.priority for item in supporting), default=packet.priority)
    request_cost = max((item.estimated_request_cost for item in supporting), default=0)
    missing = tuple(
        sorted({value for item in supporting for value in item.missing_evidence})
    )
    if consensus.selected_action is ReasoningAction.request_additional_evidence:
        missing = missing or ("Additional canonical evidence is required.",)
    confidence = _confidence_level(consensus.aggregate_confidence)
    information_gain = _information_gain(supporting)
    provenance = ReasoningModelProvenance(
        provider_requested="consensus",
        requested_model="deterministic-arbitration",
        provider_used="consensus",
        model_used="deterministic-arbitration",
        fallback_used=False,
        model_call_id=None,
        task_type=request.reasoning_request.task_type,
        usage=consensus.model_usage,
        consensus=ReasoningConsensusProvenance(
            consensus_id=consensus.consensus_id,
            consensus_schema_version=consensus.consensus_schema_version,
            participant_decision_ids=tuple(
                sorted(
                    {
                        *consensus.supporting_decision_ids,
                        *consensus.dissenting_decision_ids,
                    }
                )
            ),
            supporting_decision_ids=consensus.supporting_decision_ids,
            dissenting_decision_ids=consensus.dissenting_decision_ids,
            participants=tuple(
                ConsensusParticipantProvenance(
                    participant_id=item.participant_id,
                    decision_id=(
                        item.decision.decision_id if item.decision is not None else None
                    ),
                    requested_provider=item.configured_provider,
                    requested_model=item.configured_model,
                    actual_provider=item.actual_provider,
                    actual_model=item.actual_model,
                    fallback_used=bool(
                        item.decision is not None
                        and item.decision.model_provenance.fallback_used
                    ),
                    usage=item.usage,
                )
                for item in outcomes
            ),
        ),
    )
    candidate = ReasoningCandidate(
        decision_id=consensus.consensus_id,
        hypothesis_id=consensus.hypothesis_id,
        action=consensus.selected_action,
        recommended_capability=consensus.selected_capability,
        priority=priority,
        confidence=confidence,
        rationale=(
            "Deterministic consensus arbitration selected this advisory action "
            f"from {consensus.valid_decision_count} valid decision(s)."
        ),
        evidence_references=consensus.evidence_references,
        missing_evidence=missing,
        expected_information_gain=information_gain,
        estimated_request_cost=(
            request_cost
            if consensus.selected_action is ReasoningAction.recommend_verification
            else 0
        ),
        stop_reason=(
            "Deterministic consensus recommends stopping."
            if consensus.selected_action is ReasoningAction.stop
            else None
        ),
    )
    return validate_reasoning_candidate(
        candidate,
        request.reasoning_request,
        provenance,
    )


def _split_action(behavior: SplitBehavior) -> ReasoningAction:
    return {
        SplitBehavior.manual_review: ReasoningAction.manual_review,
        SplitBehavior.request_additional_evidence: (
            ReasoningAction.request_additional_evidence
        ),
        SplitBehavior.defer: ReasoningAction.defer,
    }[behavior]


def _confidence_level(value: float) -> ConfidenceLevel:
    if value < 0.4:
        return ConfidenceLevel.low
    if value < 0.65:
        return ConfidenceLevel.medium
    return ConfidenceLevel.high


def _information_gain(
    supporting: tuple[ReasoningDecision, ...],
) -> InformationGain:
    order = {
        InformationGain.low: 0,
        InformationGain.medium: 1,
        InformationGain.high: 2,
    }
    if not supporting:
        return InformationGain.low
    return min(
        (item.expected_information_gain for item in supporting),
        key=lambda item: order[item],
    )
