"""Deterministic, evidence-and-safety weighted hypothesis ranking."""

from __future__ import annotations

from typing import Any

from agent_core.agent_models import Hypothesis, RiskLevel
from agent_core.verification_capabilities import (
    CapabilityState,
    capability_metadata,
    get_verification_capability,
)

IMPACT_WEIGHT = {
    "bola": 19,
    "tenant_isolation": 20,
    "vertical_authorization": 20,
    "mass_assignment": 18,
    "excessive_data_exposure": 13,
    "authentication_enforcement": 18,
    "session_invalidation": 15,
    "recovery_state_enforcement": 16,
    "rate_limit_enforcement": 14,
    "jwt_enforcement": 15,
    "graphql_object_authorization": 17,
    "graphql_field_authorization": 15,
    "graphql_mutation_authorization": 18,
    "sql_injection": 19,
    "command_injection": 20,
    "path_traversal": 15,
    "file_upload_validation": 11,
    "upload_ownership": 16,
    "business_logic_state_enforcement": 17,
}


def prioritize_hypothesis(
    hypothesis: Hypothesis,
    *,
    controlled_context: dict[str, Any] | None = None,
    corroborating_evidence: int = 0,
) -> dict[str, Any]:
    """Score a hypothesis without using severity as the sole signal."""
    context = controlled_context or {}
    capability = get_verification_capability(hypothesis.category)
    reasons: list[str] = []
    confidence_points = {"low": 4, "medium": 10, "high": 15}[hypothesis.confidence]
    score = confidence_points
    reasons.append(f"confidence:{hypothesis.confidence} (+{confidence_points})")

    evidence_count = len(hypothesis.evidence_basis) + len(hypothesis.evidence_refs)
    evidence_points = min(25, evidence_count * 5)
    if hypothesis.evidence_refs:
        evidence_points += 5
    evidence_points = min(25, evidence_points)
    score += evidence_points
    reasons.append(f"evidence quality/count (+{evidence_points})")

    workflow_completeness = hypothesis.metadata.get("workflow_completeness")
    if workflow_completeness is not None:
        completeness = max(0.0, min(1.0, float(workflow_completeness)))
        completeness_points = round(completeness * 8)
        score += completeness_points
        reasons.append(f"semantic workflow completeness (+{completeness_points})")

    impact_points = IMPACT_WEIGHT.get(hypothesis.category, 10)
    score += impact_points
    reasons.append(f"potential impact (+{impact_points})")

    if (
        capability.capability_state is CapabilityState.typed_verification
        and capability.automatic_execution
    ):
        score += 15
        reasons.append("typed bounded verification available (+15)")
    else:
        score += 4
        reasons.append("planning guidance only (+4)")

    controlled_accounts = context.get("controlled_accounts") or []
    required_accounts = capability.required_account_count
    if len(set(controlled_accounts)) >= required_accounts:
        score += 12
        reasons.append("registry-required controlled accounts available (+12)")
    elif capability.requires_credentials:
        score -= 12
        reasons.append("controlled credential context missing (-12)")

    request_count = capability.worst_case_requests
    request_points = max(0, 8 - request_count)
    score += request_points
    reasons.append(f"registry worst-case request cost (+{request_points})")

    if capability.cleanup_required:
        score -= 2
        reasons.append("mandatory cleanup burden (-2)")

    effective_risk = hypothesis.risk
    if capability.state_changing and effective_risk in {
        RiskLevel.passive,
        RiskLevel.low,
    }:
        effective_risk = RiskLevel.moderate
    risk_penalty = {
        RiskLevel.passive: 0,
        RiskLevel.low: 0,
        RiskLevel.moderate: 12,
        RiskLevel.high: 30,
        RiskLevel.prohibited: 100,
    }[effective_risk]
    score -= risk_penalty
    if risk_penalty:
        reasons.append(f"side-effect/destructive risk (-{risk_penalty})")

    corroboration_points = min(10, max(0, corroborating_evidence) * 3)
    score += corroboration_points
    if corroboration_points:
        reasons.append(f"corroborating evidence (+{corroboration_points})")

    score = max(0, min(100, score))
    return {"priority": 0, "score": score, "reasons": reasons}


def rank_hypotheses(
    hypotheses: list[Hypothesis],
    *,
    controlled_context: dict[str, Any] | None = None,
    corroboration: dict[str, int] | None = None,
) -> list[Hypothesis]:
    scored: list[tuple[Hypothesis, dict[str, Any]]] = []
    for hypothesis in hypotheses:
        hypothesis.metadata.update(
            capability_metadata(
                hypothesis.category,
                typed_route_supported=bool(
                    hypothesis.metadata.get("typed_route_supported", True)
                ),
            )
        )
        hypothesis.metadata["estimated_requests"] = get_verification_capability(
            hypothesis.category
        ).worst_case_requests
        ranking = prioritize_hypothesis(
            hypothesis,
            controlled_context=controlled_context,
            corroborating_evidence=(corroboration or {}).get(
                hypothesis.hypothesis_id, 0
            ),
        )
        hypothesis.priority = ranking["score"]
        hypothesis.metadata["priority_reasons"] = ranking["reasons"]
        scored.append((hypothesis, ranking))
    scored.sort(key=lambda item: (-item[1]["score"], item[0].hypothesis_id))
    for index, (hypothesis, ranking) in enumerate(scored, 1):
        ranking["priority"] = index
        hypothesis.metadata["priority"] = index
        hypothesis.metadata["priority_score"] = ranking["score"]
    return [item[0] for item in scored]
