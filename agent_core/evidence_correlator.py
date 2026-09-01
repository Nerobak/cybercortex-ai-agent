"""Deterministic correlation of hypotheses, plans, and verification evidence."""

from __future__ import annotations

from typing import Any

from agent_core.agent_models import Hypothesis


def correlate_evidence(
    hypothesis: Hypothesis,
    analysis: dict[str, Any],
    *,
    requests_used: int,
    policy_approved: bool,
) -> dict[str, Any]:
    raw_status = analysis.get("status")
    status = (
        raw_status
        if type(raw_status) is str
        and raw_status in {"verified", "rejected", "inconclusive"}
        else "inconclusive"
    )
    reasons: list[str] = []
    if policy_approved is not True:
        status = "inconclusive"
        reasons.append("Evidence was not collected through an approved plan.")
    elif type(requests_used) is not int or requests_used < 1:
        status = "inconclusive"
        reasons.append("No verification request was recorded.")
    elif status == "verified" and analysis.get("verified") is not True:
        status = "inconclusive"
        reasons.append(
            "The analyzer did not satisfy its deterministic proof predicate."
        )
    analyzer_reasons = analysis.get("reasons")
    if type(analyzer_reasons) is list:
        reasons.extend(item for item in analyzer_reasons if type(item) is str)
    confidence = analysis.get("confidence")
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "category": hypothesis.category,
        "status": status,
        "confidence": confidence,
        "evidence_summary": list(dict.fromkeys(reasons)),
        "requests_used": requests_used,
        "correlated_sources": sorted(
            {
                str(item.get("source"))
                for item in hypothesis.evidence_basis
                if isinstance(item, dict) and item.get("source")
            }
        ),
    }
