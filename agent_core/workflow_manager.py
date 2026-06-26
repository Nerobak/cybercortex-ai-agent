from agent_core.logger import logger
from agent_core.planner import create_plan
from agent_core.decision_engine import parse_plan, get_next_tool

from tools.dns_lookup import dns_lookup
from tools.http_probe import http_probe
from tools.security_headers_checker import security_headers_checker
from tools.katana_crawl import katana_crawl
from tools.misconfiguration_detector import misconfiguration_detector
from tools.js_secret_scanner import js_secret_scanner
from tools.nuclei_scan import nuclei_scan
from tools.ai_report_writer import ai_report_writer


def run_tool(tool_name: str, target: str, allowed_domain: str, results: dict):
    if tool_name == "dns_lookup":
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        return dns_lookup(domain)

    if tool_name == "http_probe":
        return http_probe(target)

    if tool_name == "security_headers_checker":
        return security_headers_checker(target)

    if tool_name == "katana_crawl":
        return katana_crawl(target, depth=2)

    if tool_name == "misconfiguration_detector":
        urls = results.get("katana_crawl", {}).get("urls", [])
        return misconfiguration_detector(urls, allowed_domain)

    if tool_name == "js_secret_scanner":
        urls = results.get("katana_crawl", {}).get("urls", [])
        return js_secret_scanner(urls, allowed_domain)

    if tool_name == "nuclei_scan":
        return nuclei_scan(target, severity="low")

    if tool_name == "ai_report_writer":
        return ai_report_writer(target, results)

    return {
        "success": False,
        "error": f"Unknown tool: {tool_name}"
    }


def run_workflow(goal: str, target: str, allowed_domain: str):
    print("[1] Creating plan...")
    plan_text = create_plan(goal)
    print(plan_text)

    plan_steps = parse_plan(plan_text)

    results = {}
    completed_steps = []

    while True:
        decision = get_next_tool(plan_steps, completed_steps)
        next_tool = decision.get("next_tool")

        if not next_tool:
            break

        print(f"\n[+] Running tool: {next_tool}")
        tool_result = run_tool(next_tool, target, allowed_domain, results)

        results[next_tool] = tool_result
        completed_steps.append(next_tool)

    return {
        "success": True,
        "goal": goal,
        "target": target,
        "plan": plan_text,
        "completed_steps": completed_steps,
        "results": results
    }


if __name__ == "__main__":
    target = "https://nerminzlatanovic.com"
    allowed_domain = "nerminzlatanovic.com"

    goal = f"Perform a safe security assessment of {target} and generate a report."

    workflow_result = run_workflow(goal, target, allowed_domain)

    print("\n===== COMPLETED STEPS =====")
    print(workflow_result["completed_steps"])

    print("\n===== FINAL RESULTS KEYS =====")
    print(workflow_result["results"].keys())
