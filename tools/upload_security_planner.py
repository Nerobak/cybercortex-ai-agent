"""Generate deterministic, non-executing manual upload verification plans."""

from __future__ import annotations

from typing import Any

CATEGORIES = (
    "extension_validation",
    "mime_consistency",
    "filename_normalization",
    "overwrite_protection",
    "upload_authorization",
    "ownership",
    "download_authorization",
    "metadata_handling",
)


def plan_upload_security(evidence: Any) -> dict[str, Any]:
    has_evidence = bool(
        evidence
        and (
            not isinstance(evidence, dict)
            or evidence.get("upload_surface_observed")
            or evidence.get("observations")
        )
    )
    if not has_evidence:
        return {
            "success": True,
            "status": "insufficient_evidence",
            "plans": [],
            "automatic_execution": False,
        }
    plans = []
    for category in CATEGORIES:
        plans.append(
            {
                "category": category,
                "classification": "manual_verification_plan",
                "automatic_execution": False,
                "prerequisites": [
                    "Explicit authorization for the upload workflow.",
                    "Researcher-owned benign files and test-owned accounts/resources only.",
                    "Documented size and type boundaries.",
                ],
                "safe_steps": [
                    f"Record the observed baseline for {category.replace('_', ' ')}.",
                    "Manually compare one bounded benign test case with the baseline.",
                    "Retain only redacted response metadata and stop if ownership is uncertain.",
                ],
                "expected_secure_behavior": "The server consistently enforces the documented policy and resource boundary.",
                "stop_conditions": [
                    "A file may belong to a third party.",
                    "The action could overwrite, execute, publish, or irreversibly modify data.",
                    "The file is executable, malicious, oversized, polyglot, or an archive.",
                ],
                "prohibited_actions": [
                    "malware, exploits, shells, or executable payloads",
                    "polyglots, archive bombs, oversized files, or third-party files",
                    "automatic authorization-bypass claims without controlled proof",
                ],
            }
        )
    return {
        "success": True,
        "status": "planned",
        "plans": plans,
        "plan_count": len(plans),
        "automatic_execution": False,
        "vulnerability_status": "observation",
    }


upload_security_planner = plan_upload_security
