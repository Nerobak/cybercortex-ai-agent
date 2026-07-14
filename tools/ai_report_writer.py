import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_core.llm_client import ask_agent
from config import REPORT_DIR

MAX_FINDINGS_PER_TOOL = 25
MAX_TEXT_LENGTH = 1500


def truncate_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> Any:
    """
    Limit very long text before sending results to the local LLM.
    """

    if not isinstance(value, str):
        return value

    if len(value) <= limit:
        return value

    return value[:limit] + "... [truncated]"


def sanitize_value(value: Any) -> Any:
    """
    Recursively remove excessive or unsafe report input.

    Large raw requests, responses, HTML, and command output should not
    be sent to the report-generating LLM.
    """

    excluded_keys = {
        "request",
        "response",
        "raw_request",
        "raw_response",
        "curl-command",
        "curl_command",
        "stdout",
        "stderr",
        "raw_output",
        "html",
        "body",
    }

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            if key in excluded_keys:
                continue

            if key == "findings" and isinstance(item, list):
                cleaned[key] = [
                    sanitize_value(finding) for finding in item[:MAX_FINDINGS_PER_TOOL]
                ]
                continue

            cleaned[key] = sanitize_value(item)

        return cleaned

    if isinstance(value, list):
        return [sanitize_value(item) for item in value[:MAX_FINDINGS_PER_TOOL]]

    if isinstance(value, str):
        return truncate_text(value)

    return value


def build_compact_results(results: dict) -> dict:
    """
    Build concise evidence for the AI report.

    The AI receives useful findings and summaries, but not full raw output.
    """

    compact_results = {}

    for tool_name, tool_result in results.items():
        if tool_name == "ai_report_writer":
            continue

        compact_results[tool_name] = sanitize_value(tool_result)

    return compact_results


def ai_report_writer(
    target: str,
    results: dict,
    output_dir: str | None = None,
) -> dict:
    """
    Generate a professional Markdown security assessment report.
    """

    report_directory = Path(output_dir or REPORT_DIR)
    report_directory.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now()
    timestamp = generated_at.strftime("%Y%m%d_%H%M%S")

    filename = report_directory / f"ai_security_report_{timestamp}.md"

    evidence_filename = report_directory / f"assessment_evidence_{timestamp}.json"

    compact_results = build_compact_results(results)

    evidence_filename.write_text(
        json.dumps(
            compact_results,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    assessment_data = json.dumps(
        compact_results,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    prompt = f"""
You are an experienced cybersecurity consultant writing a professional
security assessment report.

Create a clean, evidence-based Markdown report using only the supplied
assessment data.

Target:
{target}

Generated:
{generated_at.strftime("%Y-%m-%d %H:%M:%S")}

Assessment data:
{assessment_data}

Use the following structure:

# CyberCortex AI Agent

## AI-Powered Security Assessment Report

**Target:** {target}

**Generated:** {generated_at.strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

Provide a concise description of the target's observed security posture.

State clearly whether any confirmed exploitable vulnerability was found.

Do not describe missing security headers as confirmed exploitation.

---

## Scope

Describe the target that was assessed and note that testing was restricted
to the configured authorized scope.

---

## Assessment Methodology

Briefly explain the assessment phases that actually ran.

Do not list tools that failed before producing useful evidence.

---

## Findings Summary

Create a Markdown table with these columns:

| Severity | Count |
|---|---:|

Use these severity levels:

- Critical
- High
- Medium
- Low
- Informational

Do not invent counts.

---

## Detailed Findings

For each meaningful finding use:

### Finding title

**Severity:**  
**Status:** Confirmed observation / Needs manual verification  
**Affected resource:**  
**Evidence:**  
**Risk:**  
**Recommendation:**  

Rules for findings:

- A missing HTTP security header is normally Informational or Low.
- A scanner match does not automatically prove exploitation.
- Do not claim XSS, clickjacking, data theft, account takeover, or another
  exploit unless the supplied evidence proves it.
- Consolidate duplicate Nuclei security-header results where appropriate.
- Do not include raw JSON, raw HTML, raw requests, or raw responses.
- Do not include Nuclei template filesystem paths.
- Do not treat tool errors as vulnerabilities.
- Mention tool errors in the assessment limitations section instead.

---

## Positive Security Observations

List security controls or healthy behaviors that were actually observed.

Examples may include:

- Successful HTTPS response
- Expected HTTP status
- Limited attack surface
- No exposed JavaScript secrets
- Security headers that were present

Do not claim a control was present unless the evidence confirms it.

---

## Assessment Limitations

Include relevant limitations such as:

- Automated testing cannot verify business-logic vulnerabilities.
- Authorization issues require authenticated multi-user testing.
- A crawler finding only one URL means coverage was limited.
- Failed or unavailable tools reduced coverage.
- Scanner results require manual validation.

Only mention limitations supported by the supplied results.

---

## Prioritized Remediation Plan

Order remediation steps from highest security value to lowest.

Do not recommend changes unrelated to the observed evidence.

---

## Manual Verification Required

List findings or potential issues that should be manually tested before
being treated as confirmed vulnerabilities.

---

## Conclusion

Provide a concise professional conclusion.

Important requirements:

- Be objective and conservative.
- Do not exaggerate severity.
- Do not invent findings.
- Clearly distinguish observations from vulnerabilities.
- Missing headers alone are generally hardening issues.
- Placeholder or demonstration domains should not be treated as sensitive
  production systems without supporting evidence.
- Produce valid Markdown only.
"""

    print("\n🤖 CyberCortex AI Agent")
    print("Generating AI-powered security report " "with DeepSeek R1 Distill 32B...")

    try:
        report = ask_agent(prompt)

        if not report or not report.strip():
            return {
                "success": False,
                "target": target,
                "error": "The AI model returned an empty report.",
                "evidence_file": str(evidence_filename),
            }

        filename.write_text(
            report.strip() + "\n",
            encoding="utf-8",
        )

    except Exception as exc:
        return {
            "success": False,
            "target": target,
            "error": f"AI report generation failed: {exc}",
            "evidence_file": str(evidence_filename),
        }

    print("✅ AI report generated successfully.")

    return {
        "success": True,
        "target": target,
        "report_file": str(filename),
        "evidence_file": str(evidence_filename),
        "generated_at": generated_at.isoformat(),
    }
