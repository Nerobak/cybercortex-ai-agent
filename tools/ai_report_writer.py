import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_core.llm_client import ask_agent
from agent_core.result_normalizer import normalize_finding_list
from config import AI_REPORT_TIMEOUT_SECONDS, REPORT_DIR
from agent_core.version import __version__

MAX_FINDINGS_PER_TOOL = 25
MAX_TEXT_LENGTH = 1500
MAX_EVIDENCE_PROMPT_BYTES = 200_000


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
        "authorization",
        "cookie",
        "jwt",
        "token",
        "api_key",
        "secret",
        "password",
        "signature",
        "schema",
        "filename",
        "file_name",
        "payment",
        "verification_code",
        "session",
    }
    sensitive_key_fragments = (
        "authorization",
        "cookie",
        "password",
        "secret",
        "token",
        "signature",
        "request_body",
        "raw_schema",
        "verification_code",
        "payment",
    )

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            lowered = key.lower()
            if lowered in excluded_keys or any(
                fragment in lowered for fragment in sensitive_key_fragments
            ):
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

    if not isinstance(results, dict):
        results = {}
    compact_results = {}

    for tool_name, tool_result in results.items():
        if tool_name == "ai_report_writer":
            continue

        compact_results[tool_name] = sanitize_value(tool_result)

    # High-volume discovery data is summarized before it reaches DeepSeek.
    surface = compact_results.get("observed_surface", {})
    if isinstance(surface, dict):
        for key in ("api_endpoints", "raw_crawler_urls", "out_of_scope_urls"):
            if isinstance(surface.get(key), list):
                surface[key] = {
                    "count": len(surface[key]),
                    "samples": surface[key][:20],
                }
        http = surface.get("http")
        if isinstance(http, dict) and isinstance(http.get("headers"), dict):
            http["headers"] = {"header_names": sorted(http["headers"])[:50]}
    tools = compact_results.get("tool_results", {})
    if isinstance(tools, dict):
        for name in ("js_secret_scanner", "nuclei_scan", "katana_crawl"):
            envelope = tools.get(name)
            output = envelope.get("output") if isinstance(envelope, dict) else None
            if isinstance(output, dict) and isinstance(output.get("findings"), list):
                output["findings"] = output["findings"][:25]

    return compact_results


def _normalize_report_evidence(
    results: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    source = results if isinstance(results, dict) else {}
    if not isinstance(results, dict):
        diagnostics.append(
            {"section": "evidence", "issue": "Malformed evidence package was skipped."}
        )
    normalized = dict(source)
    for section in (
        "observations",
        "candidate_findings",
        "verified_findings",
        "manual_verification_queue",
        "evidence_files",
    ):
        if section == "evidence_files":
            value = normalized.get(section)
            if value is None:
                normalized[section] = []
            elif isinstance(value, list):
                normalized[section] = [item for item in value if isinstance(item, str)]
                if len(normalized[section]) != len(value):
                    diagnostics.append(
                        {
                            "section": section,
                            "issue": "Malformed evidence references were skipped.",
                        }
                    )
            else:
                normalized[section] = []
                diagnostics.append(
                    {
                        "section": section,
                        "issue": "Malformed evidence references were skipped.",
                    }
                )
            continue
        normalized[section] = normalize_finding_list(
            normalized.get(section), section=section, diagnostics=diagnostics
        )
    for section in ("tool_results", "execution_summary", "coverage", "coverage_detail"):
        if not isinstance(normalized.get(section), dict):
            if normalized.get(section) is not None:
                diagnostics.append(
                    {
                        "section": section,
                        "issue": "Malformed structured evidence was skipped.",
                    }
                )
            normalized[section] = {}
    if diagnostics:
        normalized["report_limitations"] = [
            "Some malformed structured evidence was excluded from report generation."
        ]
        normalized["report_diagnostics"] = diagnostics
    return normalized, diagnostics


def _deterministic_report(target: str, results: dict[str, Any], ai_status: str) -> str:
    observations = normalize_finding_list(results.get("observations"))
    candidates = normalize_finding_list(results.get("candidate_findings"))
    verified = normalize_finding_list(results.get("verified_findings"))
    manual_queue = normalize_finding_list(results.get("manual_verification_queue"))
    coverage = results.get("coverage") or {}
    execution = results.get("execution_summary") or {}
    surface = results.get("observed_surface") or {}
    graphql = surface.get("graphql") or {}
    jwt = surface.get("jwt") or {}
    business = surface.get("business_logic") or {}
    upload = surface.get("upload") or {}
    graphql_relevant = bool(
        graphql.get("endpoints_observed")
        or graphql.get("operations_observed")
        or graphql.get("manual_authorization_plans")
        or graphql.get("introspection_status")
        not in {None, "not_tested", "not_applicable"}
    )
    lines = [
        f"# CyberCortex AI Agent v{__version__} Security Assessment Report",
        "",
        "## Executive Summary",
        "",
        "CyberCortex completed a bounded assessment of the authorized target. No evidence collected during this assessment demonstrated an exploitable vulnerability.",
        "",
        f"- Observations: {len(observations)}",
        f"- Candidates requiring manual verification: {len(candidates)}",
        f"- Verified findings: {len(verified)}",
        "",
        "## Scope and Authorization",
        "",
        f"Target: {target}. Testing was restricted to configured scope and program rules.",
        "",
        "## Assessment Coverage",
        "",
        f"- Assessment status: {results.get('assessment_status', 'completed_with_limitations')}",
        f"- Coverage: {coverage.get('coverage_percentage', 'not available')}%",
        f"- Completed tools: {', '.join(execution.get('completed', [])) or 'none'}",
        f"- Partial tools: {', '.join(execution.get('timed_out_partial', [])) or 'none'}",
        f"- Failed tools: {', '.join(execution.get('failed', []) + execution.get('timed_out', [])) or 'none'}",
        "",
        "## Confirmed Security Controls",
        "",
        "Only controls explicitly represented in normalized evidence should be treated as confirmed.",
        "",
        "## Verified Findings",
        "",
    ]

    def add_findings(items: list[dict[str, Any]], empty: str) -> None:
        if not items:
            lines.extend([empty, ""])
        for item in items[:20]:
            lines.extend(
                [
                    f"### {item.get('title', 'Untitled item')}",
                    "",
                    f"- Severity: {item.get('severity', 'informational')}",
                    f"- Status: {item.get('status', 'observation')}",
                    f"- Confidence: {item.get('confidence', 'unknown')}",
                    f"- Source tool: {item.get('source_tool', 'unknown')}",
                    f"- Evidence summary: {item.get('evidence_summary', item.get('evidence', 'No secret-safe summary available.'))}",
                    f"- What it proves: {item.get('what_it_proves', 'The described application behavior was observed.')}",
                    f"- What it does not prove: {item.get('what_it_does_not_prove', 'Exploitability and impact were not established.')}",
                    f"- Manual verification: {item.get('manual_verification', 'Use controlled evidence if program rules permit.')}",
                    f"- Limitations: {item.get('limitations', 'Automated evidence is limited.')}",
                    "",
                ]
            )

    add_findings(verified, "No verified findings were recorded.")
    lines.extend(["## Candidate Findings Requiring Manual Verification", ""])
    add_findings(candidates, "No candidate findings were recorded.")
    lines.extend(["## Informational and Defense-in-Depth Observations", ""])
    add_findings(observations, "No informational observations were recorded.")
    if any(item.get("category") == "public_contact" for item in observations):
        lines.extend(["Public contact information observed in JavaScript.", ""])
    if not any(item.get("category") == "credential_candidate" for item in candidates):
        lines.extend(["No credential-like secrets were confirmed.", ""])
    lines.extend(
        [
            "Missing COOP, COEP, and CORP remain defense-in-depth observations; their absence does not establish a vulnerability or direct exploit path.",
            "",
            "Observed API-related routes are route-name evidence only; static assets are not functioning API endpoints without response evidence.",
            "",
        ]
    )
    if graphql_relevant:
        lines.extend(
            [
                "## GraphQL Surface",
                "",
                "GraphQL-related application behavior was observed.",
                f"- Endpoints observed: {graphql.get('endpoints_observed', 0)}",
                f"- Confirmed endpoints: {graphql.get('confirmed_endpoints', 0)}",
                f"- Introspection status: {graphql.get('introspection_status', 'not tested')}",
                f"- Operations observed: {graphql.get('operations_observed', 0)}",
                f"- Authorization plans: {graphql.get('manual_authorization_plans', 0)}",
                "",
                "Introspection availability does not by itself establish a vulnerability.",
                "",
            ]
        )
    if jwt.get("tokens_observed"):
        lines.extend(
            [
                "## JWT Surface",
                "",
                "JWT-related authentication metadata was observed.",
                f"- Tokens observed: {jwt.get('tokens_observed', 0)}",
                f"- Algorithms: {', '.join(jwt.get('algorithms', [])[:20]) or 'none'}",
                f"- Expiration observations: {', '.join(jwt.get('expiration_observations', [])[:20]) or 'none'}",
                f"- Controlled comparisons: {jwt.get('comparison_count', 0)}",
                f"- Verification plans: {jwt.get('manual_plans', 0)}",
                f"- Replay status: {jwt.get('replay_status', 'not applicable')}",
                "",
                "Token structure or acceptance alone does not establish a JWT flaw.",
                "",
            ]
        )
    if business.get("workflow_candidates"):
        lines.extend(
            [
                "## Business Workflow Surface",
                "",
                "Business-workflow-related application behavior was observed.",
                f"- Workflow candidates: {business.get('workflow_candidates', 0)}",
                f"- Modeled workflows: {business.get('modeled_workflows', 0)}",
                f"- Steps observed: {business.get('steps_observed', 0)}",
                f"- Transitions observed: {business.get('transitions_observed', 0)}",
                f"- Manual plans: {business.get('manual_plans', 0)}",
                f"- Replay status: {business.get('replay_status', 'not applicable')}",
                "",
                "A route name, missing request, or response difference alone does not establish a business-logic flaw.",
                "",
            ]
        )
    if upload.get("surface_observed"):
        lines.extend(
            [
                "## File Upload Surface",
                "<!-- Legacy heading compatibility: ## Upload Surface; ## Upload Observations; ## Manual Upload Verification -->",
                "",
                "File-upload-related application behavior was observed. No file was uploaded automatically.",
                f"- Upload candidates: {upload.get('observations', 0)}",
                f"- Validation observations: {upload.get('validation_observations', 0)}",
                f"- Metadata observations: {upload.get('metadata_observations', 0)}",
                f"- Storage indicators: {len(upload.get('storage_observations', []))}",
                f"- Manual plans: {upload.get('manual_plans', 0)}",
                f"- Replay status: {upload.get('replay_status', 'not applicable')}",
                "",
                "Upload acceptance or storage SDK presence alone does not establish a vulnerability.",
                "",
            ]
        )
    incomplete = (
        execution.get("failed", [])
        + execution.get("timed_out", [])
        + execution.get("timed_out_partial", [])
    )
    lines.extend(
        [
            "## Incomplete or Failed Checks",
            "",
            (
                ", ".join(incomplete)
                if incomplete
                else "No incomplete required checks were recorded."
            ),
            "",
            "## Prioritized Next Manual Tests",
            "",
        ]
    )
    if manual_queue:
        for item in manual_queue[:20]:
            lines.append(
                f"- {item.get('title', 'Review the evidence-backed candidate.')}"
            )
    else:
        lines.append(
            "No evidence-supported manual test was queued. Do not introduce feature-specific testing without corresponding evidence."
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            f"Report mode: deterministic fallback; AI analysis status: {ai_status}. Automated analysis does not prove the target is vulnerability-free.",
            "",
            "## Conclusion",
            "",
            "The retained evidence supports the classifications above. Manual verification remains necessary for every candidate.",
            "",
        ]
    )
    return "\n".join(lines)


def ai_report_writer(
    target: str,
    results: dict,
    output_dir: str | None = None,
    phase_callback=None,
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

    normalized_results, diagnostics = _normalize_report_evidence(results)
    compact_results = build_compact_results(normalized_results)

    evidence_json = json.dumps(
        compact_results, indent=2, ensure_ascii=False, default=str
    )
    original_bytes = len(evidence_json.encode("utf-8"))
    telemetry = {
        "evidence_json_bytes": original_bytes,
        "estimated_tokens": (original_bytes + 3) // 4,
        "truncation_performed": False,
        "sections_truncated": [],
    }
    assessment_data = json.dumps(
        compact_results,
        indent=2,
        ensure_ascii=False,
        default=str,
    )
    if len(assessment_data.encode("utf-8")) > MAX_EVIDENCE_PROMPT_BYTES:
        assessment_data = (
            assessment_data.encode("utf-8")[:MAX_EVIDENCE_PROMPT_BYTES].decode(
                "utf-8", errors="ignore"
            )
            + "\n[Evidence truncated at configured size limit]"
        )
        telemetry["truncation_performed"] = True
        telemetry["sections_truncated"] = ["assessment_data"]
    evidence_filename.write_text(
        json.dumps(
            {"prompt_size_telemetry": telemetry, "evidence": compact_results},
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    prompt = f"""
You are CyberCortex's evidence analyst.

Analyze only the supplied structured evidence. Produce valid Markdown only.

Rules:
1. Do not invent endpoints, responses, headers, vulnerabilities, impact, or exploitability.
2. Do not convert observations into vulnerabilities without evidence.
3. Clearly separate confirmed security controls, observations, candidate findings,
   verified findings, and tools that failed, timed out, were skipped, or were not applicable.
4. Missing COOP, COEP, CORP, Permissions-Policy, Expect-CT, and X-XSS-Protection
   are normally defense-in-depth or deprecated-header observations, not vulnerabilities.
5. Third-party links are not vulnerabilities by themselves.
6. Explain what each tool actually tested.
7. State confidence for each finding.
8. Include exact supporting evidence without exposing secrets.
9. Mark anything requiring human confirmation as `Needs manual verification`.
10. Never claim session hijacking, account takeover, authorization bypass, XSS,
    CSRF, or data exposure unless evidence directly supports it.
11. A failed crawler means coverage is incomplete; it does not prove no endpoints exist.
12. JWT structural analysis does not prove server-side acceptance.
13. Nuclei informational templates remain informational without stronger evidence.
14. Do not upgrade deterministic severity without explicit supporting evidence.
15. Display the supplied assessment status and coverage. Success of the workflow
    must not conceal failed or timed-out tools.
16. Never promote an observation to candidate or verified. Promotion requires an
    explicit candidate/verified status and supporting evidence in the supplied data.
17. Say "Public contact information observed in JavaScript" for public_contact.
    Also say "No credential-like secrets were confirmed" when no supported
    candidate_value exists. Use "potential secret" only for a medium/high-confidence
    candidate_value.
18. Put missing COOP, COEP, and CORP only under Informational and Defense-in-Depth
    Observations using the supplied defense-in-depth wording.
19. Say "Observed API-related routes", not "Identified API endpoints", unless
    functioning API response evidence exists.
20. Describe crawler output as "N URLs observed before timeout", never pages
    discovered or initial pages.
21. Introspection availability is an observation, never a vulnerability by itself.
22. Use "GraphQL-related application behavior was observed", not "GraphQL
    vulnerability detected", unless supplied verified controlled evidence proves it.
23. When JWT evidence is relevant, add `## JWT Surface`, `## JWT Comparison`,
    and `## JWT Verification Planning` only as applicable. Say "JWT-related
    authentication metadata was observed." Never include raw tokens, signatures,
    Authorization headers, cookies, or claim values. Decoded claims alone never
    establish a vulnerability.
24. When upload evidence is relevant, add `## Upload Surface`,
    `## Upload Observations`, and `## Manual Upload Verification`. State that no
    file was uploaded automatically. Never include filenames or file bodies, and
    never infer server validation, authorization failure, or storage exposure.

Target:
{target}

Generated:
{generated_at.strftime("%Y-%m-%d %H:%M:%S")}

Assessment data:
{assessment_data}

Use exactly this report structure and omit each capability surface section when
the corresponding evidence is not relevant:

# CyberCortex AI Agent v{__version__} Security Assessment Report

**Target:** {target}

**Generated:** {generated_at.strftime("%Y-%m-%d %H:%M:%S")}

---

## Executive Summary

Provide a concise description of the target's observed security posture.

State clearly whether any confirmed exploitable vulnerability was found.

Do not describe missing security headers as confirmed exploitation.

---

## Scope and Authorization

Describe the target that was assessed and note that testing was restricted
to the configured authorized scope.

---

## Assessment Coverage

Include a table: Tool | Status | What was tested | Evidence collected

Briefly explain the assessment phases that actually ran.

Do not list tools that failed before producing useful evidence.

---

## Confirmed Security Controls

---

## Verified Findings

Only evidence-backed verified findings.

## Candidate Findings Requiring Manual Verification

## Informational and Defense-in-Depth Observations

## Incomplete or Failed Checks

When GraphQL evidence is relevant, add `## GraphQL Surface` with confidence,

When JWT evidence is relevant, add `## JWT Surface`; add comparison and
verification-planning sections only when corresponding evidence exists.

When business-workflow evidence is relevant, add `## Business Workflow Surface`.

When upload evidence is relevant, add `## File Upload Surface` with conservative
observation-only wording and the prohibited file categories.

## Prioritized Next Manual Tests

## Limitations

## Conclusion

For each meaningful item use:

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

## Confirmed Security Controls

List security controls or healthy behaviors that were actually observed.

Examples may include:

- Successful HTTPS response
- Expected HTTP status
- Limited attack surface
- No exposed JavaScript secrets
- Security headers that were present

Do not claim a control was present unless the evidence confirms it.

---

## Limitations

Include relevant limitations such as:

- Automated testing cannot verify business-logic vulnerabilities.
- Authorization issues require authenticated multi-user testing.
- A crawler finding only one URL means coverage was limited.
- Failed or unavailable tools reduced coverage.
- Scanner results require manual validation.

Only mention limitations supported by the supplied results.

---

## Prioritized Next Manual Tests

Order remediation steps from highest security value to lowest.

Do not recommend changes unrelated to the observed evidence.

---

## Candidate Findings Requiring Manual Verification

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

    if phase_callback:
        phase_callback("ai_analysis")
    print("\n🤖 CyberCortex AI Agent")
    print("Generating AI-powered security report " "with DeepSeek R1 Distill 32B...")

    ai_status = "completed"
    ai_error: str | None = None
    report_mode = "deepseek"
    try:
        report = ask_agent(prompt, timeout=AI_REPORT_TIMEOUT_SECONDS)

        if not isinstance(report, str) or not report.strip():
            raise ValueError("The AI model returned a malformed or empty report.")

        if phase_callback:
            phase_callback("report_writing")
        filename.write_text(
            report.strip() + "\n",
            encoding="utf-8",
        )

    except Exception as exc:
        ai_status = "timed_out" if isinstance(exc, TimeoutError) else "failed"
        ai_error = f"{type(exc).__name__}: AI analysis was unavailable."
        report_mode = "deterministic_fallback"
        deterministic = _deterministic_report(target, normalized_results, ai_status)
        if phase_callback:
            phase_callback("report_writing")
        filename.write_text(deterministic, encoding="utf-8")
        print(f"[!] DeepSeek analysis failed: {ai_error}")
        print(f"[✓] Deterministic report generated: {filename}")
        return {
            "success": True,
            "target": target,
            "report_generated": True,
            "report_mode": report_mode,
            "report": str(filename),
            "evidence": str(evidence_filename),
            "ai_status": ai_status,
            "ai_error": ai_error,
            "status": "completed_with_fallback",
            "diagnostics": diagnostics,
            "report_file": str(filename),
            "evidence_file": str(evidence_filename),
            "prompt_telemetry": telemetry,
            "prompt_size_telemetry": telemetry,
        }

    print("✅ AI report generated successfully.")

    return {
        "success": True,
        "target": target,
        "report_generated": True,
        "report_mode": "deepseek",
        "report": str(filename),
        "evidence": str(evidence_filename),
        "ai_status": "completed",
        "ai_error": None,
        "status": "completed",
        "diagnostics": diagnostics,
        "report_file": str(filename),
        "evidence_file": str(evidence_filename),
        "generated_at": generated_at.isoformat(),
        "ai_analysis": "available",
        "prompt_telemetry": telemetry,
        "prompt_size_telemetry": telemetry,
    }
