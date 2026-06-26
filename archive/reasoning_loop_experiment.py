from tools.dns_lookup import dns_lookup
from tools.http_probe import http_probe
from tools.security_headers_checker import security_headers_checker
from tools.katana_crawl import katana_crawl
from tools.misconfiguration_detector import misconfiguration_detector
from tools.js_secret_scanner import js_secret_scanner
from tools.nuclei_scan import nuclei_scan
from tools.ai_report_writer import ai_report_writer
from tools.scope_guard import enforce_scope
from llm_client import ask_agent


def run_tool(tool_name, target, allowed_domain, results):
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

    return {"success": False, "error": f"Unknown tool: {tool_name}"}


def choose_next_tool(goal, target, completed, results):
    available_tools = [
        "dns_lookup",
        "http_probe",
        "security_headers_checker",
        "katana_crawl",
        "misconfiguration_detector",
        "js_secret_scanner",
        "nuclei_scan",
        "ai_report_writer",
        "finish",
    ]

    prompt = f"""
You are the reasoning loop of a local AI security agent.

Goal:
{goal}

Target:
{target}

Completed tools:
{completed}

Current result keys:
{list(results.keys())}

Available next actions:
{available_tools}

Choose exactly ONE next action.

Rules:
- If nothing has been done, choose dns_lookup.
- Use http_probe after dns_lookup.
- Use security_headers_checker after http_probe.
- Use katana_crawl before misconfiguration_detector or js_secret_scanner.
- Use nuclei_scan only after safe checks.
- Use ai_report_writer near the end.
- Use finish only after ai_report_writer has completed.
- Return only the tool name. No explanation.
"""

    decision = ask_agent(prompt).strip().lower()
    decision = decision.replace("`", "").replace(".", "").strip()

    for tool in available_tools:
        if tool in decision:
            if tool == "finish" and "ai_report_writer" not in completed:
                break
            return tool

    # Fallback rules if model gives bad/empty answer
    if not completed:
        return "dns_lookup"

    if "dns_lookup" in completed and "http_probe" not in completed:
        return "http_probe"

    if "http_probe" in completed and "security_headers_checker" not in completed:
        return "security_headers_checker"

    if "security_headers_checker" in completed and "katana_crawl" not in completed:
        return "katana_crawl"

    if "katana_crawl" in completed and "misconfiguration_detector" not in completed:
        return "misconfiguration_detector"

    if "misconfiguration_detector" in completed and "js_secret_scanner" not in completed:
        return "js_secret_scanner"

    if "js_secret_scanner" in completed and "nuclei_scan" not in completed:
        return "nuclei_scan"

    if "nuclei_scan" in completed and "ai_report_writer" not in completed:
        return "ai_report_writer"

    return "finish"


def run_reasoning_loop(goal, target, allowed_domain, max_steps=10):
    scope = enforce_scope(target)

    if not scope["allowed"]:
        return scope

    results = {}
    completed = []

    for step in range(max_steps):
        print(f"\n[Reasoning Step {step + 1}]")

        next_tool = choose_next_tool(
            goal=goal,
            target=target,
            completed=completed,
            results=results,
        )

        print(f"Decision: {next_tool}")

        if next_tool == "finish":
            break

        if next_tool in completed and next_tool != "ai_report_writer":
            print("Tool already completed. Stopping to avoid loop.")
            break

        output = run_tool(
            tool_name=next_tool,
            target=target,
            allowed_domain=allowed_domain,
            results=results,
        )

        results[next_tool] = output
        completed.append(next_tool)

    return {
        "success": True,
        "goal": goal,
        "target": target,
        "completed": completed,
        "results": results,
    }


if __name__ == "__main__":
    target = "https://nerminzlatanovic.com"
    allowed_domain = "nerminzlatanovic.com"

    goal = f"Perform a safe authorized security assessment of {target} and generate a report."

    final = run_reasoning_loop(goal, target, allowed_domain)

    print("\n===== COMPLETED =====")
    print(final["completed"])

    report = final["results"].get("ai_report_writer")
    if report:
        print("\n===== REPORT =====")
        print(report.get("report_file"))
