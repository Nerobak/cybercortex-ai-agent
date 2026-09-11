"""Deterministic structured-vote agreement classification."""

from __future__ import annotations

from dataclasses import dataclass

from agent_core.consensus.types import (
    AgreementType,
    ConsensusPolicy,
    ParticipantOutcome,
    ParticipantStatus,
)
from agent_core.reasoning import ConfidenceLevel, ReasoningAction

CONFIDENCE_SCORES = {
    ConfidenceLevel.low: 0.25,
    ConfidenceLevel.medium: 0.5,
    ConfidenceLevel.high: 0.75,
}

VoteKey = tuple[str, ReasoningAction, str | None]


@dataclass(frozen=True)
class AgreementAssessment:
    agreement_type: AgreementType
    selected_vote: VoteKey | None
    supporting_decision_ids: tuple[str, ...]
    dissenting_decision_ids: tuple[str, ...]
    aggregate_confidence: float
    arbitration_reason: str


def classify_agreement(
    outcomes: tuple[ParticipantOutcome, ...],
    policy: ConsensusPolicy,
) -> AgreementAssessment:
    """Classify only exact hypothesis/action/capability tuples; never prose."""

    valid = tuple(
        item
        for item in outcomes
        if item.status is ParticipantStatus.valid and item.decision is not None
    )
    if len(outcomes) < policy.minimum_participants:
        return _no_selection(
            AgreementType.insufficient_participants,
            valid,
            "configured_participants_below_minimum",
        )
    if len(valid) < policy.minimum_valid_participants:
        if len(valid) == 1 and policy.allow_single_model_advisory:
            decision = valid[0].decision
            assert decision is not None
            return AgreementAssessment(
                agreement_type=AgreementType.single_model_advisory,
                selected_vote=_vote_key(decision),
                supporting_decision_ids=(decision.decision_id,),
                dissenting_decision_ids=(),
                aggregate_confidence=CONFIDENCE_SCORES[decision.confidence],
                arbitration_reason="explicit_single_model_advisory",
            )
        return _no_selection(
            AgreementType.invalid_decisions,
            valid,
            "valid_participants_below_minimum",
        )
    if len(valid) == 1:
        decision = valid[0].decision
        assert decision is not None
        if policy.allow_single_model_advisory:
            return AgreementAssessment(
                agreement_type=AgreementType.single_model_advisory,
                selected_vote=_vote_key(decision),
                supporting_decision_ids=(decision.decision_id,),
                dissenting_decision_ids=(),
                aggregate_confidence=CONFIDENCE_SCORES[decision.confidence],
                arbitration_reason="explicit_single_model_advisory",
            )
        return _no_selection(
            AgreementType.insufficient_participants,
            valid,
            "single_model_advisory_disabled",
        )

    groups: dict[VoteKey, list[ParticipantOutcome]] = {}
    for item in valid:
        assert item.decision is not None
        groups.setdefault(_vote_key(item.decision), []).append(item)
    ordered = sorted(
        groups.items(),
        key=lambda item: (
            -len(item[1]),
            item[0][0],
            item[0][1].value,
            item[0][2] or "",
        ),
    )
    leading_vote, leading = ordered[0]
    tied = len(ordered) > 1 and len(ordered[1][1]) == len(leading)
    unanimous = len(leading) == len(outcomes) == len(valid)
    strict_majority = len(leading) > len(valid) / 2
    if unanimous:
        agreement = AgreementType.unanimous
        reason = "unanimous_structured_vote"
    elif (
        policy.require_unanimity
        or tied
        or (policy.require_majority and not strict_majority)
    ):
        return _split(valid, "structured_vote_split")
    elif strict_majority:
        agreement = AgreementType.majority
        reason = "strict_structured_majority"
    else:
        return _split(valid, "plurality_not_accepted_as_majority")

    decisions = tuple(item.decision for item in leading if item.decision is not None)
    aggregate = sum(CONFIDENCE_SCORES[item.confidence] for item in decisions) / len(
        decisions
    )
    if aggregate < policy.minimum_aggregate_confidence:
        return _split(valid, "aggregate_confidence_below_threshold")
    supporting = tuple(sorted(item.decision_id for item in decisions))
    dissenting = tuple(
        sorted(
            item.decision.decision_id
            for item in valid
            if item.decision is not None and item.decision.decision_id not in supporting
        )
    )
    return AgreementAssessment(
        agreement_type=agreement,
        selected_vote=leading_vote,
        supporting_decision_ids=supporting,
        dissenting_decision_ids=dissenting,
        aggregate_confidence=float(aggregate),
        arbitration_reason=reason,
    )


def _vote_key(decision) -> VoteKey:
    return (
        decision.hypothesis_id,
        decision.action,
        decision.recommended_capability,
    )


def _split(valid: tuple[ParticipantOutcome, ...], reason: str) -> AgreementAssessment:
    decisions = tuple(item.decision for item in valid if item.decision is not None)
    confidence = (
        sum(CONFIDENCE_SCORES[item.confidence] for item in decisions) / len(decisions)
        if decisions
        else 0.0
    )
    return AgreementAssessment(
        agreement_type=AgreementType.split,
        selected_vote=None,
        supporting_decision_ids=(),
        dissenting_decision_ids=tuple(sorted(item.decision_id for item in decisions)),
        aggregate_confidence=float(confidence),
        arbitration_reason=reason,
    )


def _no_selection(
    agreement: AgreementType,
    valid: tuple[ParticipantOutcome, ...],
    reason: str,
) -> AgreementAssessment:
    assessment = _split(valid, reason)
    return AgreementAssessment(
        agreement_type=agreement,
        selected_vote=None,
        supporting_decision_ids=(),
        dissenting_decision_ids=assessment.dissenting_decision_ids,
        aggregate_confidence=assessment.aggregate_confidence,
        arbitration_reason=reason,
    )
