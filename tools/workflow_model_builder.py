"""Build a canonical workflow model without fabricating transitions or states."""

from __future__ import annotations

from typing import Any

from tools.business_logic_common import IDENTIFIER_FIELDS, extract_steps
from tools.workflow_evidence_discovery import discover_workflow_evidence


def _operation(method: str, fields: set[str]) -> str:
    if method in {"GET", "HEAD"}:
        return "read"
    if method == "POST":
        return "authenticate" if fields & {"password", "otp"} else "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "DELETE":
        return "delete"
    return "unknown"


def build_workflow_model(evidence: Any) -> dict[str, Any]:
    discovery = discover_workflow_evidence(evidence)
    candidates = discovery.get("workflow_candidates", [])
    if not discovery.get("success") or not candidates:
        return {
            "success": False,
            "status": "insufficient_evidence",
            "error": "Sufficient structured workflow evidence was not supplied.",
            "model": None,
        }
    candidate = candidates[0]
    if candidate["evidence_sources"] == ["route_name_only"]:
        return {
            "success": False,
            "status": "insufficient_evidence",
            "error": "Route names alone cannot create a workflow model.",
            "model": None,
        }
    raw_steps = extract_steps(evidence)
    steps = []
    for index, item in enumerate(
        sorted(raw_steps, key=lambda row: (row["sequence"], row["path"])), 1
    ):
        fields = set(item["fields"])
        method = item["method"]
        side_effect = "none" if method in {"GET", "HEAD"} else "unknown"
        steps.append(
            {
                "step_id": f"step_{index}",
                "sequence": index,
                "name": f"{method} {item['path']}",
                "method": method,
                "path_template": item["path"],
                "operation_type": _operation(method, fields),
                "actor_context": item["actor"],
                "resource_type": item["path"].strip("/").split("/")[0] or "unknown",
                "resource_identifier_present": bool(
                    fields & IDENTIFIER_FIELDS or "{id}" in item["path"]
                ),
                "state_before": item["state_before"],
                "state_after": item["state_after"],
                "required_inputs": sorted(fields),
                "observed_outputs": [],
                "side_effect_class": side_effect,
                "confidence": candidate["confidence"],
                "source": item["source"],
            }
        )
    transitions = []
    ordered_raw_steps = sorted(
        raw_steps, key=lambda row: (row["sequence"], row["path"])
    )
    for index, (before, after) in enumerate(zip(steps, steps[1:])):
        raw_before, raw_after = ordered_raw_steps[index : index + 2]
        shared = sorted(
            set(raw_before["identifier_categories"])
            & set(raw_after["identifier_categories"])
        )
        # Order is observed; state linkage remains unknown unless both sides support it.
        transitions.append(
            {
                "from_step": before["step_id"],
                "to_step": after["step_id"],
                "expected_order": True,
                "shared_identifiers": shared,
                "required_state": after["state_before"],
                "observed_state": before["state_after"],
                "confidence": candidate["confidence"],
                "source": "captured_order",
            }
        )
    actors = sorted({step["actor_context"] for step in steps})
    states = sorted(
        {
            value
            for step in steps
            for value in (step["state_before"], step["state_after"])
            if value != "unknown"
        }
    )
    model = {
        "workflow_id": candidate["workflow_id"],
        "name": candidate["title"],
        "confidence": candidate["confidence"],
        "actors": actors,
        "resources": sorted({step["resource_type"] for step in steps}),
        "states": states,
        "steps": steps,
        "transitions": transitions,
        "invariants": [],
        "unknowns": ["server_side_enforcement"]
        + ([] if states else ["workflow_states"]),
        "source_evidence": candidate["evidence_sources"],
    }
    return {
        "success": True,
        "model": model,
        "vulnerability_status": "observation",
        "network_tested": False,
    }


workflow_model_builder = build_workflow_model
