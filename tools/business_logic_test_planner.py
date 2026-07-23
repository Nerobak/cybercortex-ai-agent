"""Non-executing, bounded manual verification planner."""

from __future__ import annotations

from typing import Any

PROHIBITED = [
    "Real payment or financial actions",
    "Third-party data access",
    "Destructive actions",
    "Production abuse",
    "Race floods",
    "Mass duplicate requests",
    "Price manipulation",
    "Inventory manipulation",
    "Coupon abuse for financial gain",
    "Bypassing KYC or regulated controls",
    "Changing account-security settings",
    "Privilege escalation attempts without explicit authorization",
]
BLOCKED_TERMS = {
    "checkout",
    "payment",
    "transfer",
    "withdraw",
    "deposit",
    "refund",
    "kyc",
    "identity",
    "account closure",
    "password",
    "mfa",
    "permission administration",
}


def plan_business_logic_tests(value: Any) -> dict[str, Any]:
    model = (
        value.get("model")
        if isinstance(value, dict) and isinstance(value.get("model"), dict)
        else value
    )
    if (
        not isinstance(model, dict)
        or len(model.get("steps") or []) < 2
        or model.get("confidence") == "low"
    ):
        return {
            "success": True,
            "status": "insufficient_evidence",
            "plans": [],
            "reason": "Ordered medium- or high-confidence workflow evidence is required.",
        }
    name = str(model.get("name", "workflow")).lower()
    if any(term in name for term in BLOCKED_TERMS) or any(
        step.get("side_effect_class") in {"financial", "destructive", "sensitive"}
        for step in model["steps"]
    ):
        return {
            "success": True,
            "status": "blocked_by_policy",
            "plans": [],
            "reason": "Financial, regulated, destructive, administrative, or account-security workflows are not planned automatically.",
        }
    relevant = [step.get("step_id") for step in model["steps"][:3]]
    plan = {
        "title": "Verify workflow step-order enforcement",
        "objective": "Confirm required prerequisites are enforced using a minimal controlled sequence.",
        "workflow": model.get("workflow_id"),
        "relevant_steps": relevant,
        "hypothesis": "Step-order enforcement requires controlled verification; no bypass is asserted.",
        "evidence_basis": list(model.get("source_evidence") or []),
        "confidence": model.get("confidence"),
        "prerequisites": [
            "Explicit authorization",
            "Sandbox or test environment where available",
            "Documented cleanup path",
        ],
        "controlled_accounts_required": True,
        "test_owned_resources_required": True,
        "safe_steps": [
            "Create or select one researcher-owned test object.",
            "Record the normal sequence using one controlled account.",
            "Perform at most one intentionally incomplete, reversible request if program rules allow.",
            "Compare only status class, response structure, and researcher-owned object state.",
        ],
        "evidence_to_collect": [
            "Redacted step order",
            "HTTP status class",
            "Response structure hash",
            "Before/after state label",
        ],
        "expected_secure_behavior": "The server rejects an out-of-order transition without changing the test-owned resource.",
        "stop_conditions": [
            "Any third-party identifier appears",
            "A financial, destructive, regulated, or account-security action is reached",
            "Unexpected side effect occurs",
            "Authorization or scope becomes unclear",
        ],
        "prohibited_actions": PROHIBITED,
        "cleanup_steps": [
            "Restore or delete only the researcher-owned test object through an approved reversible path.",
            "Revoke temporary test data where supported.",
        ],
        "automatic_execution": False,
    }
    return {
        "success": True,
        "status": "completed",
        "plans": [plan],
        "vulnerability_status": "observation",
        "network_tested": False,
    }


business_logic_test_planner = plan_business_logic_tests
