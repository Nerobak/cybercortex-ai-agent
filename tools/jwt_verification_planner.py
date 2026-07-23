"""Safe, deterministic JWT manual-verification plans."""

from __future__ import annotations

from typing import Any

PROHIBITED_ACTIONS = [
    "Third-party account access",
    "Token theft, credential stuffing, or brute force",
    "Payment or destructive operations",
    "Authentication bypass attempts outside explicit scope",
    "Replay of production tokens not owned by the researcher",
    "Use of expired or altered tokens against third-party data",
]
CATEGORIES = {
    "expiration": "Expiration enforcement",
    "audience": "Audience enforcement",
    "issuer": "Issuer enforcement",
    "role_scope": "Role or scope enforcement",
    "token_type": "Token type separation",
    "session_invalidation": "Session invalidation",
    "account_isolation": "Account isolation",
    "key_rotation": "Key rotation behavior",
    "refresh_token": "Refresh token handling",
}


def plan_jwt_verification(evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not (
        evidence.get("claims_summary")
        or evidence.get("registered_claims")
        or evidence.get("comparison_summary")
    ):
        return {
            "success": False,
            "status": "not_applicable",
            "error": "Sufficient decoded claims or comparison evidence is required.",
            "plans": [],
        }
    requested = evidence.get("plan_categories")
    categories = (
        [name for name in requested if name in CATEGORIES]
        if isinstance(requested, list)
        else list(CATEGORIES)
    )
    plans = []
    for category in categories:
        title = CATEGORIES[category]
        plans.append(
            {
                "title": title,
                "objective": f"Determine whether {title.lower()} matches the documented policy using controlled evidence.",
                "prerequisites": [
                    "Explicit written authorization and confirmed endpoint scope",
                    "Documented expected policy",
                    "Researcher-controlled tokens and test-owned resources",
                ],
                "controlled_accounts_required": (
                    2 if category in {"role_scope", "account_isolation"} else 1
                ),
                "safe_steps": [
                    "Record a redacted baseline using the controlled account.",
                    "Perform one reversible, policy-specific comparison only if explicitly permitted.",
                    "Stop after the minimum evidence needed and restore test state.",
                ],
                "evidence_to_collect": [
                    "Redacted token fingerprint and claim-name summary",
                    "HTTP status and bounded response-structure metadata",
                    "Expected versus observed secure behavior",
                ],
                "expected_secure_behavior": f"The service consistently enforces {title.lower()} and rejects invalid context.",
                "stop_conditions": [
                    "Any third-party data appears",
                    "Scope, ownership, or authorization becomes uncertain",
                    "A non-reversible action would be required",
                    "Rate limiting or service instability occurs",
                ],
                "prohibited_actions": list(PROHIBITED_ACTIONS),
                "automatic_execution": False,
            }
        )
    return {
        "success": True,
        "plans": plans,
        "plan_count": len(plans),
        "manual_verification_required": True,
        "vulnerability_status": "observation",
        "network_testing_occurred": False,
    }


jwt_verification_planner = plan_jwt_verification
