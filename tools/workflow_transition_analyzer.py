"""Offline state, actor, identifier, and replay-sensitivity observations."""

from __future__ import annotations

from typing import Any


def analyze_workflow_transitions(value: Any) -> dict[str, Any]:
    model = (
        value.get("model")
        if isinstance(value, dict) and isinstance(value.get("model"), dict)
        else value
    )
    if not isinstance(model, dict) or not isinstance(model.get("steps"), list):
        return {
            "success": False,
            "status": "not_applicable",
            "observations": [],
            "error": "A canonical workflow model is required.",
        }
    observations = []
    steps = model["steps"]
    for step in steps:
        step_id = step.get("step_id", "unknown")
        method = step.get("method")
        fields = set(step.get("required_inputs") or [])
        if method not in {"GET", "HEAD"}:
            observations.append(
                {"type": "state_changing_operation_observed", "step": step_id}
            )
            observations.append(
                {"type": "replay_sensitive_step_observed", "step": step_id}
            )
        if fields & {"verification_code", "nonce"}:
            observations.append({"type": "one_time_value_observed", "step": step_id})
        if fields & {
            "quantity",
            "price",
            "discount",
            "status",
            "state",
            "role",
            "approval",
        }:
            observations.append(
                {
                    "type": "client_controlled_business_field_observed",
                    "step": step_id,
                    "fields": sorted(
                        fields
                        & {
                            "quantity",
                            "price",
                            "discount",
                            "status",
                            "state",
                            "role",
                            "approval",
                        }
                    ),
                }
            )
        observations.append(
            {
                "type": "idempotency_metadata_observed",
                "step": step_id,
                "present": "idempotency_key" in fields,
            }
        )
    for transition in model.get("transitions", []):
        observations.append(
            {
                "type": "prerequisite_step_observed",
                "from_step": transition.get("from_step"),
                "to_step": transition.get("to_step"),
            }
        )
        if transition.get("shared_identifiers"):
            observations.append(
                {
                    "type": "identifier_carried_between_steps",
                    "from_step": transition.get("from_step"),
                    "to_step": transition.get("to_step"),
                    "identifier_categories": transition["shared_identifiers"],
                }
            )
        if (
            transition.get("required_state") != "unknown"
            and transition.get("observed_state") != "unknown"
        ):
            observations.append(
                {
                    "type": "state_transition_observed",
                    "from_step": transition.get("from_step"),
                    "to_step": transition.get("to_step"),
                }
            )
    for before, after in zip(steps, steps[1:]):
        if before.get("actor_context") != after.get("actor_context"):
            observations.append(
                {
                    "type": "actor_boundary_observed",
                    "from_step": before.get("step_id"),
                    "to_step": after.get("step_id"),
                }
            )
    if model.get("unknowns"):
        observations.append(
            {"type": "incomplete_sequence", "unknowns": list(model["unknowns"])}
        )
    return {
        "success": True,
        "observations": observations,
        "vulnerability_status": "observation",
        "manual_verification_required": True,
        "network_tested": False,
    }


workflow_transition_analyzer = analyze_workflow_transitions
