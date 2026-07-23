"""Offline discovery of conservative workflow candidates from sanitized evidence."""

from __future__ import annotations

import hashlib
from typing import Any

from tools.business_logic_common import STATE_FIELDS, extract_steps

CATEGORIES = (
    "authentication",
    "registration",
    "email verification",
    "password recovery",
    "mfa enrollment",
    "profile update",
    "object creation",
    "checkout",
    "order processing",
    "subscription",
    "coupon",
    "promotion",
    "approval",
    "invitation",
    "onboarding",
    "kyc",
    "identity verification",
    "file processing",
    "account closure",
    "role",
    "permission administration",
)
RESTRICTED_CATEGORIES = {
    "checkout",
    "order processing",
    "subscription",
    "kyc",
    "identity verification",
    "account closure",
    "password recovery",
    "mfa enrollment",
    "role",
    "permission administration",
}


def _category(title: str) -> tuple[str, str]:
    lowered = title.lower()
    matched = next((item for item in CATEGORIES if item in lowered), "unknown")
    return matched, "restrictive" if matched in RESTRICTED_CATEGORIES else "standard"


def discover_workflow_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, (dict, list)):
        return {
            "success": False,
            "workflow_candidates": [],
            "evidence_summary": {},
            "errors": ["Workflow evidence must be a JSON object or array."],
        }
    steps = extract_steps(evidence)
    if not steps:
        return {
            "success": True,
            "status": "not_applicable",
            "workflow_candidates": [],
            "evidence_summary": {"step_count": 0},
            "errors": ["No structured request steps were supplied."],
        }
    explicit = isinstance(evidence, dict) and bool(
        evidence.get("workflow_name") or evidence.get("explicit_sequence")
    )
    ordered = len(steps) > 1 and all(step["sequence"] for step in steps)
    identifiers = sorted(
        set().union(*(set(step["identifier_categories"]) for step in steps))
    )
    states = sorted(
        set().union(*(set(step["fields"]) & STATE_FIELDS for step in steps))
    )
    sources = ["user_supplied"] if explicit else []
    sources += (
        ["explicit_sequence" if explicit else "captured_order"] if ordered else []
    )
    sources += ["shared_identifier"] if identifiers and len(steps) > 1 else []
    if not sources:
        sources = ["route_name_only"]
    score = 2 if explicit and ordered else 1 if ordered or identifiers else 0
    signature = "|".join(f"{s['sequence']}:{s['method']}:{s['path']}" for s in steps)
    title = (
        str(evidence.get("workflow_name") if isinstance(evidence, dict) else "")
        or "Observed workflow"
    )
    category, safety_class = _category(title)
    candidate = {
        "workflow_id": "wf_" + hashlib.sha256(signature.encode()).hexdigest()[:12],
        "title": title[:120],
        "workflow_category": category,
        "category_evidence": (
            "user_supplied" if explicit else "route_name_only_observation"
        ),
        "safety_classification": safety_class,
        "confidence": ("low", "medium", "high")[score],
        "evidence_sources": sorted(set(sources)),
        "observed_steps": steps,
        "shared_identifiers": identifiers,
        "authentication_context_present": any(
            step.get("authentication_context_present")
            or step["actor"] not in {"anonymous", "unknown"}
            for step in steps
        ),
        "state_parameters": states,
        "network_tested": False,
        "vulnerability_status": "observation",
        "limitations": [
            "Observed metadata does not prove server-side workflow enforcement.",
            "Missing requests are incomplete evidence, not skipped-step vulnerabilities.",
        ],
    }
    return {
        "success": True,
        "workflow_candidates": [candidate],
        "evidence_summary": {
            "step_count": len(steps),
            "ordered_evidence": ordered,
            "sensitive_values_retained": False,
            "raw_bodies_retained": False,
        },
        "errors": [],
    }


workflow_evidence_discovery = discover_workflow_evidence
