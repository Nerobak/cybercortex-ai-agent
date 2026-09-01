from tool_registry import TOOLS

from agent_core.agent_models import AssessmentPlan, VerificationPlan
from agent_core.policy import AssessmentPolicy, PolicyDecision


def parse_plan(plan_text: str):
    steps = []

    for line in plan_text.splitlines():
        line = line.strip()

        for tool_name in TOOLS.keys():
            if tool_name in line:
                steps.append(tool_name)

    return steps


def get_next_tool(plan_steps: list[str], completed_steps: list[str]):
    for step in plan_steps:
        if step not in completed_steps:
            return {"success": True, "next_tool": step, "tool_info": TOOLS.get(step)}

    return {
        "success": True,
        "next_tool": None,
        "message": "All planned steps completed",
    }


def authorize_verification_plan(
    plan: VerificationPlan, policy: AssessmentPolicy
) -> PolicyDecision:
    """The sole decision path for proposed verification execution."""
    return policy.authorize_plan(plan)


def ready_verification_plans(
    plan: AssessmentPlan, policy: AssessmentPolicy
) -> list[VerificationPlan]:
    """Return typed plans that independently pass the current policy."""
    return [
        item for item in plan.verification_plans if policy.authorize_plan(item).allowed
    ]
