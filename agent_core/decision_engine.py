from tool_registry import TOOLS


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
            return {
                "success": True,
                "next_tool": step,
                "tool_info": TOOLS.get(step)
            }

    return {
        "success": True,
        "next_tool": None,
        "message": "All planned steps completed"
    }
