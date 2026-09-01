"""Typed planning facade.

The legacy text planner is retained as ``create_text_plan`` for compatibility.
Production adaptive planning uses strict Pydantic models and deterministic
policy validation.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from pydantic import ValidationError

from agent_core.agent_models import AssessmentPlan
from agent_core.llm_client import ask_agent
from tool_registry import TOOLS


def create_text_plan(goal: str):
    tool_list = ""

    for tool_name, info in TOOLS.items():
        tool_list += f"{tool_name}: {info['description']}\n"

    prompt = f"""
You are the planning engine of a local AI security agent.

Goal:
{goal}

Available tools:
{tool_list}

Return ONLY tool names, one per line.

Rules:
- Do not explain.
- Do not use bullets.
- Do not use numbers.
- Do not use markdown.
- Do not include tools that are not listed.
- End with ai_report_writer.

Good output example:
dns_lookup
http_probe
security_headers_checker
katana_crawl
misconfiguration_detector
js_secret_scanner
nuclei_scan
ai_report_writer
"""

    return ask_agent(prompt)


def parse_typed_plan(value: str | dict[str, Any] | AssessmentPlan) -> AssessmentPlan:
    if isinstance(value, AssessmentPlan):
        return value
    if isinstance(value, str):
        value = json.loads(value)
    return AssessmentPlan.model_validate(value)


def create_plan(
    goal: str,
    *,
    planning_context: dict[str, Any] | None = None,
    llm: Callable[[str], str] | None = None,
) -> AssessmentPlan | str:
    """Create a typed plan when context is supplied, else preserve legacy output.

    Local models that cannot honor the schema fail closed; callers should use a
    deterministic plan rather than attempting to execute malformed text.
    """
    if planning_context is None:
        return create_text_plan(goal)
    available = [
        {
            "name": name,
            "purpose": info["purpose"],
            "risk": info["risk"],
            "requires_credentials": info["requires_credentials"],
            "network": info["sends_network_traffic"],
        }
        for name, info in TOOLS.items()
        if name in set(planning_context.get("allowed_tools") or TOOLS)
    ]
    prompt = json.dumps(
        {
            "instruction": (
                "Propose a strict AssessmentPlan JSON object. Do not authorize actions, "
                "invent evidence, or mark hypotheses verified. Use only available tools."
            ),
            "goal": goal,
            "context": planning_context,
            "available_tools": available,
            "schema": AssessmentPlan.model_json_schema(),
        },
        separators=(",", ":"),
    )
    raw = (llm or ask_agent)(prompt)
    try:
        return parse_typed_plan(raw)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"The model returned an invalid typed plan: {exc}") from exc
