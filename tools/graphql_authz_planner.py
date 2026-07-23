"""Deterministic, planning-only GraphQL authorization guidance."""

from __future__ import annotations

from typing import Any


def graphql_authz_planner(
    endpoint: Any,
    operations: Any = None,
    schema_observations: Any = None,
    object_identifiers: Any = None,
    authentication_context: Any = None,
) -> dict[str, Any]:
    result = {
        "success": True,
        "plans": [],
        "manual_verification_required": True,
        "automatic_execution": False,
        "vulnerability_status": "observation",
    }
    if (
        not isinstance(endpoint, dict)
        or endpoint.get("confidence") not in {"confirmed", "likely"}
        or not endpoint.get("url")
    ):
        return {
            **result,
            "status": "not_applicable",
            "reason": "A confirmed or high-confidence endpoint is required.",
        }
    ops = operations if isinstance(operations, list) else []
    auth = authentication_context if isinstance(authentication_context, dict) else {}
    controlled = auth.get("controlled_accounts") or []
    if len(controlled) < 2 or not ops:
        return {
            **result,
            "status": "not_applicable",
            "reason": "Analyzed operations and at least two controlled accounts are required.",
        }
    identifiers = object_identifiers if isinstance(object_identifiers, list) else []
    common = {
        "endpoint": endpoint["url"],
        "prerequisites": [
            "Explicit program authorization",
            "Two researcher-controlled accounts with distinct authorization contexts",
            "Test-owned data only",
        ],
        "controlled_accounts_required": 2,
        "evidence_to_collect": [
            "Request metadata with secrets redacted",
            "Status and response-shape differences",
            "Object ownership and sensitive-field differences",
        ],
        "stop_conditions": [
            "Any response contains unrelated third-party data",
            "Scope or ownership becomes uncertain",
            "A step would create irreversible or real-world impact",
        ],
        "prohibited_actions": [
            "Accessing unrelated third-party data",
            "Payment or destructive actions",
            "Authentication bypass payloads",
            "Batching, aliases, recursive amplification, or denial-of-service queries",
        ],
        "expected_secure_behavior": "Unauthorized roles are denied, or protected objects and fields are omitted, null, or redacted.",
        "automatic_execution": False,
    }
    for op in ops[:25]:
        if not isinstance(op, dict):
            continue
        name = str(op.get("name") or op.get("operation_name") or "controlled operation")
        operation_type = str(op.get("operation_type") or "query")
        if identifiers and operation_type != "mutation":
            result["plans"].append(
                {
                    **common,
                    "title": f"Controlled object authorization comparison: {name}",
                    "operation": name,
                    "authorization_boundary": "object ownership",
                    "safe_steps": [
                        "Account A retrieves its own test-owned object and records the authorized baseline.",
                        "Account B requests the same test-owned identifier.",
                        "Compare status, response structure, ownership markers, and sensitive fields without expanding access.",
                    ],
                }
            )
        sensitive = op.get("sensitive_field_observations") or []
        if sensitive:
            result["plans"].append(
                {
                    **common,
                    "title": f"Controlled field authorization comparison: {name}",
                    "operation": name,
                    "authorization_boundary": "field or role",
                    "safe_steps": [
                        "Run the supplied operation against test-owned data under each controlled role.",
                        "Compare whether privileged fields are redacted, null, denied, or omitted.",
                    ],
                }
            )
        if operation_type == "mutation":
            result["plans"].append(
                {
                    **common,
                    "title": f"Controlled mutation authorization review: {name}",
                    "operation": name,
                    "authorization_boundary": "state change",
                    "safe_steps": [
                        "Use a reversible operation on a test-owned object only.",
                        "Record state before and after each controlled role attempt.",
                        "Do not perform payment, destructive, irreversible, or third-party actions.",
                    ],
                }
            )
    if not result["plans"]:
        return {
            **result,
            "status": "not_applicable",
            "reason": "No ownership-sensitive, privileged-field, or mutation evidence supported a plan.",
        }
    result["status"] = "completed"
    return result
