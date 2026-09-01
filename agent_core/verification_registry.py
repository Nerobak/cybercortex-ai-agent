"""Legacy offline registry quarantined from active Phase 2 verification.

Active Phase 2 CLIs execute only through ``ControlledVerificationExecutor``.
This module is retained for import compatibility, but it has no active adapters
and cannot emit an active security classification.
"""

from __future__ import annotations

from typing import Any, Callable

from agent_core.agent_models import VerificationPlan
from agent_core.policy import AssessmentPolicy

LEGACY_OFFLINE_ONLY = True
ACTIVE_EXECUTION_ENABLED = False


def execute_authorization_plan(
    plan: VerificationPlan,
    policy: AssessmentPolicy,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    del plan, policy, inputs
    return {
        "status": "manual_adapter_required",
        "requests_used": 0,
        "error": (
            "The legacy offline verification registry is quarantined; use the "
            "policy-bound ControlledVerificationExecutor."
        ),
    }


class VerificationAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[
            str,
            Callable[
                [VerificationPlan, AssessmentPolicy, dict[str, Any]], dict[str, Any]
            ],
        ] = {}

    def execute(
        self,
        plan: VerificationPlan,
        policy: AssessmentPolicy,
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        tools = {step.tool for step in plan.steps}
        adapters = {
            tool: self._adapters[tool] for tool in tools if tool in self._adapters
        }
        if len(adapters) != 1:
            return {
                "status": "manual_adapter_required",
                "requests_used": 0,
                "error": "No unambiguous typed execution adapter exists for this plan.",
            }
        return next(iter(adapters.values()))(plan, policy, inputs)
