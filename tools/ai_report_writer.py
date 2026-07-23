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
    }

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            if key.lower() in excluded_keys:
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
    contacts = [
        item for item in observations if item.get("category") == "public_contact"
    ]
    secrets = [
        item for item in candidates if item.get("category") == "credential_candidate"
    ]
    coverage = results.get("coverage") or {}
    graphql = (results.get("observed_surface") or {}).get("graphql") or {}
    graphql_relevant = bool(
        graphql.get("endpoints_observed")
        or graphql.get("operations_observed")
        or graphql.get("manual_authorization_plans")
        or graphql.get("introspection_status")
        not in {None, "not_tested", "not_applicable"}
    )
    graphql_text = ""
    if graphql_relevant:
        graphql_text = (
            "## GraphQL Surface\n\n"
            f"- Endpoints observed: {graphql.get('endpoints_observed', 0)}\n"
            f"- Confirmed endpoints: {graphql.get('confirmed_endpoints', 0)}\n"
            f"- Operations observed: {graphql.get('operations_observed', 0)}\n"
            f"- Introspection status: {graphql.get('introspection_status', 'not tested')}\n\n"
            "GraphQL-related application behavior was observed. Introspection availability and schema or field names do not by themselves establish a security vulnerability.\n\n"
            "## GraphQL Authorization Planning\n\n"
            f"Controlled manual plans: {graphql.get('manual_authorization_plans', 0)}. Planning requires two controlled accounts, test-owned objects, and redacted differential evidence. Third-party access, payment, destructive actions, authentication bypass, batching, alias amplification, recursion, and denial-of-service queries are prohibited.\n\n"
        )
    jwt = (results.get("observed_surface") or {}).get("jwt") or {}
    jwt_text = ""
    if jwt.get("tokens_observed"):
        jwt_text = (
            "## JWT Surface\n\n"
            "JWT-related authentication metadata was observed.\n\n"
            f"- Tokens observed: {jwt.get('tokens_observed', 0)}\n"
            f"- Sources: {', '.join(jwt.get('sources', [])) or 'not recorded'}\n"
            f"- Algorithms: {', '.join(jwt.get('algorithms', [])) or 'not decoded'}\n"
            f"- Issuer present: {bool(jwt.get('issuer_present'))}\n"
            f"- Audience present: {bool(jwt.get('audience_present'))}\n"
            f"- Expiration observations: {', '.join(jwt.get('expiration_observations', [])) or 'none'}\n"
            f"- Signature verification: {jwt.get('signature_verification_status', 'not_verified')}\n\n"
            "All JWT items are observations unless controlled runtime evidence proves policy impact. No raw tokens, signatures, Authorization headers, cookies, or claim values are included.\n\n"
        )
        if jwt.get("comparison_count"):
            jwt_text += (
                "## JWT Comparison\n\n"
                f"Controlled tokens compared: {jwt.get('comparison_count', 0)}. Differences require manual authorization-boundary verification.\n\n"
            )
        if jwt.get("manual_plans"):
            jwt_text += (
                "## JWT Verification Planning\n\n"
                f"Safe manual plans: {jwt.get('manual_plans', 0)}. Explicit authorization, controlled accounts, test-owned resources, reversible steps, redacted evidence, and stop conditions are required.\n\n"
            )
    contact_text = (
        "Public contact information observed in JavaScript.\n\n"
        if contacts
        else "No public contact information was recorded as a report observation.\n\n"
    )
    secret_text = (
        f"{len(secrets)} potential credential-like value(s) require manual verification.\n\n"
        if secrets
        else "No credential-like secrets were confirmed.\n\n"
    )
    return (
        f"# CyberCortex AI Agent v{__version__} Security Assessment Report\n\n"
        f"**Target:** {target}\n\n"
        f"**Assessment status:** {results.get('assessment_status', 'completed_with_limitations')}\n\n"
        f"**Coverage:** {coverage.get('coverage_percentage', 'not available')}%\n\n"
        "## Executive Summary\n\n"
        "CyberCortex completed a low-impact assessment of the authorized target. No evidence collected during this assessment demonstrated an exploitable vulnerability. Informational observations were identified, primarily related to application architecture and browser defense-in-depth controls. Because the assessment did not include authenticated or business-logic testing, the result should not be interpreted as proof that the application is vulnerability-free.\n\n"
        f"- Informational observations: {len(observations)}\n"
        f"- Candidate findings: {len(candidates)}\n"
        f"- Verified findings: {len(verified)}\n\n"
        "## JavaScript Review\n\n"
        + contact_text
        + secret_text
        + graphql_text
        + jwt_text
        + "## Informational and Defense-in-Depth Observations\n\n"
        "The application does not advertise COOP, COEP, and CORP when those headers are recorded as absent. These browser isolation headers are defense-in-depth controls and their absence does not establish a vulnerability or direct exploit path.\n\n"
        "Observed API-related routes are route-name evidence only; they are not identified as functioning API endpoints without response evidence. Crawler counts represent URLs observed before timeout, not pages proven to exist.\n\n"
        "Every normalized item includes confidence, status, and source tool in the evidence package.\n\n"
        "## Prioritized Next Manual Tests\n\n"
        "Review authenticated API-related routes with controlled accounts; assess object-level authorization only where identifiers and authorization context exist; inspect parameterized requests; and review observed JavaScript API usage. Test GraphQL or file uploads only when the corresponding endpoint or workflow was observed.\n\n"
        "## Limitations\n\n"
        f"AI analysis status: {ai_status}. Malformed evidence, when present, was excluded without exposing its value.\n"
    )


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

Target:
{target}

Generated:
{generated_at.strftime("%Y-%m-%d %H:%M:%S")}

Assessment data:
{assessment_data}

Use exactly this report structure:

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

## Observed Application Surface

Include DNS, HTTP status, effective URL, redirect chain, technologies, pages
observed, observed API-related routes, JavaScript files, parameters, and object references.

When GraphQL evidence is relevant, add `## GraphQL Surface` with confidence,
status, source, limitations, and whether network testing occurred. Add
`## GraphQL Authorization Planning` only when controlled plans exist, including
prerequisites, evidence required, and prohibited actions. Never include a raw schema.

When JWT evidence is relevant, add `## JWT Surface`; add comparison and
verification-planning sections only when corresponding evidence exists.

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
