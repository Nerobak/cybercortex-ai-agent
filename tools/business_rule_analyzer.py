"""Deterministic business-rule observations and redacted trace comparison."""

from __future__ import annotations

from typing import Any

from tools.business_logic_common import BUSINESS_FIELDS, extract_steps

RULES = {
    "quantity": "quantity_consistency",
    "amount": "numeric_boundary",
    "price": "price_consistency",
    "currency": "currency_consistency",
    "coupon": "coupon_eligibility",
    "promotion": "coupon_eligibility",
    "owner": "ownership_boundary",
    "account_id": "account_isolation",
    "user_id": "account_isolation",
    "tenant_id": "tenant_isolation",
    "role": "role_boundary",
    "permission": "role_boundary",
    "approval": "approval_requirement",
    "status": "state_boundary",
    "state": "state_boundary",
    "verification_code": "one_time_use",
    "nonce": "one_time_use",
    "idempotency_key": "idempotency",
}


def analyze_business_rules(value: Any) -> dict[str, Any]:
    model = (
        value.get("model")
        if isinstance(value, dict) and isinstance(value.get("model"), dict)
        else value
    )
    if not isinstance(model, dict):
        return {
            "success": False,
            "status": "not_applicable",
            "observations": [],
            "error": "A canonical workflow model is required.",
        }
    observations = []
    for step in model.get("steps", []):
        fields = set(step.get("required_inputs") or []) & BUSINESS_FIELDS
        for field in sorted(fields):
            observations.append(
                {
                    "type": "business_rule_field_observed",
                    "field_category": field,
                    "rule_category": RULES.get(
                        field,
                        (
                            "numeric_boundary"
                            if field
                            in {"balance", "credit", "limit", "inventory", "discount"}
                            else "sequence_boundary"
                        ),
                    ),
                    "step": step.get("step_id"),
                    "vulnerability_status": "observation",
                }
            )
    return {
        "success": True,
        "observations": observations,
        "manual_review_hypotheses": [
            {
                "rule_category": item["rule_category"],
                "hypothesis": "Server-side enforcement requires controlled manual verification.",
                "evidence_basis": item["field_category"],
            }
            for item in observations
        ],
        "vulnerability_status": "observation",
        "network_tested": False,
    }


def compare_workflows(left: Any, right: Any) -> dict[str, Any]:
    a, b = extract_steps(left), extract_steps(right)

    def signature(step: dict[str, Any]) -> tuple[Any, ...]:
        return step["sequence"], step["method"], step["path"]

    sequence = [
        {"left": signature(x), "right": signature(y)}
        for x, y in zip(a, b)
        if signature(x) != signature(y)
    ]
    if len(a) != len(b):
        sequence.append({"left_step_count": len(a), "right_step_count": len(b)})
    states = [
        {"sequence": x["sequence"], "left": x["state_after"], "right": y["state_after"]}
        for x, y in zip(a, b)
        if x["state_after"] != y["state_after"]
    ]
    actors = [
        {"sequence": x["sequence"], "left": x["actor"], "right": y["actor"]}
        for x, y in zip(a, b)
        if x["actor"] != y["actor"]
    ]
    responses = [
        {
            "sequence": x["sequence"],
            "left_hash": x["response_structure_hash"],
            "right_hash": y["response_structure_hash"],
        }
        for x, y in zip(a, b)
        if x["response_structure_hash"] != y["response_structure_hash"]
    ]
    resources = [
        {
            "sequence": x["sequence"],
            "left": x["identifier_categories"],
            "right": y["identifier_categories"],
        }
        for x, y in zip(a, b)
        if x["identifier_categories"] != y["identifier_categories"]
    ]
    return {
        "comparison_summary": {
            "left_steps": len(a),
            "right_steps": len(b),
            "differences_observed": bool(
                sequence or states or actors or resources or responses
            ),
        },
        "sequence_differences": sequence,
        "state_differences": states,
        "actor_boundary_differences": actors,
        "resource_boundary_differences": resources,
        "response_structure_differences": responses,
        "manual_verification_required": True,
        "vulnerability_status": "observation",
        "sensitive_values_retained": False,
    }


business_rule_analyzer = analyze_business_rules
