from agent_core.llm_client import ask_agent
from tool_registry import TOOLS


def create_plan(goal: str):
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
