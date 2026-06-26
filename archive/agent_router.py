from tools.scope_guard import enforce_scope
from tools.safe_config_scan import safe_config_scan
from tools.nuclei_scan import nuclei_scan
from tools.ai_report_writer import ai_report_writer
from llm_client import ask_agent

def analyze_target(target: str, allowed_domain: str):
    scope = enforce_scope(target)

    if not scope["allowed"]:
        return scope

    print("[1] Running safe config scan...")
    safe_results = safe_config_scan(target, allowed_domain)

    print("[2] Running Nuclei header scan...")
    nuclei_results = nuclei_scan(target, severity="low")

    combined_results = {
        "safe_config_scan": safe_results,
        "nuclei_scan": nuclei_results
    }

    print("[3] Generating AI report...")
    report = ai_report_writer(
        target=target,
        results=combined_results
    )

    print("[4] Asking DeepSeek for summary...")
    summary = ask_agent(f"""
Analyze this security workflow result.

Target:
{target}

Results:
{combined_results}

Give me:
1. Top findings
2. What matters most
3. What to fix first
4. What needs manual verification
""")

    return {
        "success": True,
        "target": target,
        "summary": summary,
        "report": report,
        "results": combined_results
    }


if __name__ == "__main__":
    target = "https://example.com"
    allowed_domain = "example.com"

    result = analyze_target(target, allowed_domain)

    print("\n===== FINAL SUMMARY =====")
    print(result["summary"])

    print("\n===== REPORT FILE =====")
    print(result["report"])
