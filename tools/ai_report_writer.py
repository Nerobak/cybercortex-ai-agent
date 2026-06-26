from agent_core.result_normalizer import normalize_results
from datetime import datetime
from pathlib import Path

from agent_core.llm_client import ask_agent


def ai_report_writer(target: str, results: dict, output_dir: str = "reports"):
    """
    Generate a professional AI-powered Markdown security assessment report.
    """

    Path(output_dir).mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/ai_security_report_{timestamp}.md"

    normalized_results = normalize_results(results)

    prompt = f"""
You are an experienced cybersecurity consultant writing a professional security assessment report.

Create a clean, well-structured Markdown report.

Target:
{target}

Assessment Results:
{normalized_results}

Use EXACTLY the following structure.

========================================================

# CyberCortex AI Agent

## AI-Powered Security Assessment Report

**Target:** {target}

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

========================================================

## Executive Summary

Provide a concise summary of the overall security posture.

---

## Scope

Briefly describe what was assessed.

---

## Tools Used

List only the tools that contributed to the assessment.

---

## Key Findings

For every finding include:

### Finding Title

Severity:
Critical / High / Medium / Low / Informational

Evidence:

Risk:

Recommendation:

---

## Positive Security Controls

Highlight important security controls that were observed.

Examples:

- HSTS
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

---

## Prioritized Remediation Plan

List recommendations ordered from highest priority to lowest.

---

## Manual Verification Required

Identify findings that require manual confirmation before being considered confirmed vulnerabilities.

---

## Conclusion

Summarize the assessment in a few professional paragraphs.

Rules:

- Write like a senior penetration tester.
- Be objective and evidence-based.
- Do NOT exaggerate findings.
- Placeholder domains (example.com) are generally Low or Medium severity unless they expose sensitive information.
- Missing security headers are generally Informational or Low unless there is evidence of exploitation.
- Mark uncertain findings as **Needs Manual Verification**.
- Do NOT include raw HTML, raw JSON, or raw HTTP responses.
- Do NOT include unnecessary implementation details.
- Produce a report suitable for engineering teams, security teams, or clients.
"""

    print("\n🤖 CyberCortex AI Agent")
    print("Generating AI-powered security report with DeepSeek R1 Distill 32B...")

    report = ask_agent(prompt)

    print("✅ AI report generated successfully.")  

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)

    return {
        "success": True,
        "report_file": filename,
        "generated_at": datetime.now().isoformat(),
    }
