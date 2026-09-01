import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from agent_core.llm_client import ask_agent
from agent_core.result_normalizer import (
    normalize_finding_list,
    public_result,
    sanitize_document_text,
    sanitize_url,
)
from config import AI_REPORT_TIMEOUT_SECONDS, REPORT_DIR
from agent_core.version import __version__

MAX_FINDINGS_PER_TOOL = 25
MAX_TEXT_LENGTH = 1500
MAX_EVIDENCE_PROMPT_BYTES = 200_000
SUCCESSFUL_TOOL_STATUSES = {
    "completed",
    "completed_with_fallback",
    "timed_out_partial",
}
KNOWN_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
    "Expect-CT",
)


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

    value = public_result(value)
    excluded_keys = {
        "access_token",
        "request",
        "response",
        "curl-command",
        "curl_command",
        "schema",
        "filename",
        "file_name",
        "payment",
        "refresh_token",
        "verification_code",
    }
    excluded_fragments = (
        "request_body",
        "raw_schema",
        "verification_code",
    )

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            lowered = key.lower()
            if lowered in excluded_keys or any(
                fragment in lowered for fragment in excluded_fragments
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


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _package_tool_output(results: dict[str, Any], name: str) -> dict[str, Any]:
    tools = results.get("tool_results") or {}
    envelope = tools.get(name) if isinstance(tools, dict) else None
    output = envelope.get("output") if isinstance(envelope, dict) else None
    return output if isinstance(output, dict) else {}


def _canonical_tool_statuses(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    statuses: dict[str, dict[str, Any]] = {}
    tools = results.get("tool_results") or {}
    if isinstance(tools, dict):
        for name, envelope in tools.items():
            if not isinstance(envelope, dict):
                continue
            status = str(envelope.get("status") or "unknown")
            output = envelope.get("output") or {}
            output_findings = (
                output.get("findings") if isinstance(output, dict) else None
            )
            statuses[str(name)] = {
                "status": status,
                "limitation": truncate_text(envelope.get("error") or ""),
                "partial_finding_count": (
                    len(output_findings) if isinstance(output_findings, list) else 0
                ),
            }
    execution = results.get("execution_summary") or {}
    if isinstance(execution, dict):
        for status, names in execution.items():
            if not isinstance(names, list):
                continue
            for name in names:
                if not isinstance(name, str):
                    continue
                statuses.setdefault(
                    name,
                    {"status": status, "limitation": "", "partial_finding_count": 0},
                )
    return statuses


def _public_contact(item: dict[str, Any]) -> bool:
    return (
        item.get("category") == "public_contact"
        or item.get("match_kind") == "public_contact"
    )


def _js_scan_skipped_for_no_urls(facts: dict[str, Any]) -> bool:
    item = facts["tool_statuses"].get("js_secret_scanner", {})
    return item.get("status") in {"skipped", "not_applicable"} and bool(
        re.search(r"authorized javascript urls?", str(item.get("limitation", "")), re.I)
    )


def _canonical_finding(item: dict[str, Any], *, public_contact: bool = False) -> dict:
    finding = sanitize_value(dict(item))
    if public_contact:
        finding.update(
            {
                "title": "Public contact information observed in JavaScript",
                "category": "public_contact",
                "severity": "informational",
                "status": "observation",
            }
        )
    return finding


def _deduplicate_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in items:
        identity = (
            str(item.get("title", "")),
            str(item.get("source_tool", "")),
            str(item.get("endpoint", "")),
            str(item.get("category", "")),
        )
        unique.setdefault(identity, item)
    return list(unique.values())


def _manual_recommendation_supported(
    item: dict[str, Any], counts: dict[str, int], prerequisites: dict[str, Any]
) -> bool:
    text = json.dumps(item, default=str).lower()
    if "resource_slug" in text and any(
        term in text for term in ("authorization", "idor", "bola")
    ):
        return False
    if any(term in text for term in ("business logic", "business-logic", "workflow")):
        return counts["workflow_candidates"] > 0
    if "graphql" in text:
        return bool(prerequisites["graphql_surface"])
    if "jwt" in text or "token replay" in text:
        return counts["jwt_tokens"] > 0
    if any(term in text for term in ("file upload", "file-upload", "upload")):
        return counts["upload_surfaces"] > 0
    if any(term in text for term in ("header", "coop", "coep", "expect-ct")):
        return bool(prerequisites["missing_security_headers"])
    if any(term in text for term in ("authorization", "idor", "bola")):
        return bool(
            prerequisites["object_identifier_evidence"]
            or item.get("category") == "authorization_test_idea"
        )
    return True


def build_canonical_report_facts(results: dict[str, Any]) -> Mapping[str, Any]:
    """Build the immutable facts that exclusively govern report assertions."""
    surface = results.get("observed_surface") or {}
    if not isinstance(surface, dict):
        surface = {}
    graphql = surface.get("graphql") or {}
    jwt = surface.get("jwt") or {}
    business = surface.get("business_logic") or {}
    upload = surface.get("upload") or {}
    api_surface = surface.get("api_surface") or {}
    for value_name, value in (
        ("graphql", graphql),
        ("jwt", jwt),
        ("business", business),
        ("upload", upload),
        ("api_surface", api_surface),
    ):
        if not isinstance(value, dict):
            if value_name == "graphql":
                graphql = {}
            elif value_name == "jwt":
                jwt = {}
            elif value_name == "business":
                business = {}
            else:
                if value_name == "upload":
                    upload = {}
                else:
                    api_surface = {}

    tool_statuses = _canonical_tool_statuses(results)
    jwt_output = _package_tool_output(results, "jwt_discovery")
    graphql_output = _package_tool_output(results, "graphql_endpoint_discovery")
    upload_output = _package_tool_output(results, "upload_discovery")
    workflow_output = _package_tool_output(results, "workflow_evidence_discovery")
    nuclei_output = _package_tool_output(results, "nuclei_scan")

    jwt_count = (
        _nonnegative_int(jwt_output.get("token_count"))
        if "token_count" in jwt_output
        else _nonnegative_int(jwt.get("tokens_observed"))
    )
    graphql_candidates = graphql_output.get("observed_candidates")
    graphql_count = (
        len(graphql_candidates)
        if isinstance(graphql_candidates, list)
        else _nonnegative_int(graphql.get("endpoints_observed"))
    )
    upload_count = (
        _nonnegative_int(upload_output.get("observation_count"))
        if "observation_count" in upload_output
        else _nonnegative_int(upload.get("observations"))
    )
    upload_count = max(
        upload_count,
        int(
            bool(
                upload_output.get("upload_surface_observed")
                or upload.get("surface_observed")
            )
        ),
    )
    workflow_candidates = workflow_output.get("workflow_candidates")
    workflow_count = (
        len(workflow_candidates)
        if isinstance(workflow_candidates, list)
        else _nonnegative_int(business.get("workflow_candidates"))
    )
    actual_nuclei_findings = nuclei_output.get("findings")
    if not isinstance(actual_nuclei_findings, list):
        actual_nuclei_findings = []
    actual_nuclei_findings = normalize_finding_list(actual_nuclei_findings)

    observations: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    for item in normalize_finding_list(results.get("observations")):
        observations.append(
            _canonical_finding(item, public_contact=_public_contact(item))
        )
    for item in normalize_finding_list(results.get("candidate_findings")):
        if _public_contact(item):
            observations.append(_canonical_finding(item, public_contact=True))
        else:
            candidates.append(_canonical_finding(item))
    for item in normalize_finding_list(results.get("verified_findings")):
        if _public_contact(item):
            observations.append(_canonical_finding(item, public_contact=True))
        else:
            verified.append(_canonical_finding(item))

    actual_nuclei_titles = {
        str(item.get("name") or item.get("template_id") or "Nuclei observation")
        for item in actual_nuclei_findings
        if isinstance(item, dict)
    }
    for collection in (observations, candidates, verified):
        collection[:] = [
            item
            for item in collection
            if item.get("source_tool") != "nuclei_scan"
            or str(item.get("title")) in actual_nuclei_titles
        ]

    observations = _deduplicate_findings(observations)
    candidates = _deduplicate_findings(candidates)
    verified = _deduplicate_findings(verified)

    header_output = _package_tool_output(results, "security_headers_checker")
    checked_headers = header_output.get("headers_checked") or {}
    security_headers: dict[str, dict[str, Any]] = {}
    if isinstance(checked_headers, dict):
        for name, item in checked_headers.items():
            if isinstance(item, dict) and isinstance(item.get("present"), bool):
                security_headers[str(name)] = {
                    "present": item["present"],
                    "source_tool": "security_headers_checker",
                }

    def contradicts_header_authority(item: dict[str, Any]) -> bool:
        if item.get("source_tool") == "security_headers_checker":
            return False
        text = json.dumps(item, default=str).lower()
        for name, header_fact in security_headers.items():
            if name.lower() not in text:
                continue
            negative = bool(
                re.search(r"\b(?:missing|absent|not present|not set|lacks?)\b", text)
            )
            positive = bool(re.search(r"\b(?:present|enabled|set)\b", text))
            if header_fact["present"] and negative:
                return True
            if not header_fact["present"] and positive and not negative:
                return True
        return False

    observations = [
        item for item in observations if not contradicts_header_authority(item)
    ]
    candidates = [item for item in candidates if not contradicts_header_authority(item)]
    verified = [item for item in verified if not contradicts_header_authority(item)]

    allowed_additional_headers: set[str] = set()
    for item in observations + candidates + verified:
        source = str(item.get("source_tool") or "")
        source_status = tool_statuses.get(source, {}).get("status")
        if (
            source == "security_headers_checker"
            or source_status not in SUCCESSFUL_TOOL_STATUSES
        ):
            continue
        item_text = json.dumps(item, default=str).lower()
        for header in KNOWN_SECURITY_HEADERS:
            if header.lower() in item_text:
                allowed_additional_headers.add(header)

    objects = surface.get("objects") or []
    object_count = len(objects) if isinstance(objects, list) else 0
    introspection_status = str(graphql.get("introspection_status") or "not_tested")
    operations_count = _nonnegative_int(graphql.get("operations_observed"))
    counts = {
        "api_routes": _nonnegative_int(api_surface.get("routes_documented")),
        "api_operations": _nonnegative_int(api_surface.get("operations_observed")),
        "api_parameters": _nonnegative_int(api_surface.get("parameters_observed")),
        "api_objects": _nonnegative_int(api_surface.get("object_reference_candidates")),
        "api_protected_operations": _nonnegative_int(
            api_surface.get("authentication_protected_operations")
        ),
        "jwt_tokens": jwt_count,
        "graphql_endpoints": graphql_count,
        "upload_surfaces": upload_count,
        "workflow_candidates": workflow_count,
        "candidate_findings": len(candidates),
        "verified_findings": len(verified),
        "nuclei_findings": len(actual_nuclei_findings),
    }
    prerequisites = {
        "graphql_surface": bool(
            graphql_count
            or operations_count
            or introspection_status == "introspection_available"
        ),
        "object_identifier_evidence": object_count > 0,
        "missing_security_headers": sorted(
            name for name, item in security_headers.items() if not item["present"]
        ),
    }

    candidate_identities = {
        (str(item.get("title")), str(item.get("source_tool"))) for item in candidates
    }
    manual_recommendations: list[dict[str, Any]] = []
    for item in normalize_finding_list(results.get("manual_verification_queue")):
        if _public_contact(item):
            continue
        identity = (str(item.get("title")), str(item.get("source_tool")))
        if identity not in candidate_identities:
            continue
        canonical_item = _canonical_finding(item)
        if _manual_recommendation_supported(canonical_item, counts, prerequisites):
            manual_recommendations.append(
                {
                    "title": canonical_item.get(
                        "title", "Review the evidence-backed candidate."
                    ),
                    "source_tool": canonical_item.get("source_tool", "unknown"),
                    "category": canonical_item.get("category", "candidate"),
                }
            )

    assessment = results.get("assessment") or {}
    if not isinstance(assessment, dict):
        assessment = {}
    facts = {
        "counts": counts,
        "observations": observations,
        "candidates": candidates,
        "verified": verified,
        "manual_recommendations": _deduplicate_findings(manual_recommendations),
        "tool_statuses": tool_statuses,
        "security_headers": security_headers,
        "additional_deterministic_headers": sorted(allowed_additional_headers),
        "surface": {
            "graphql": sanitize_value(graphql),
            "jwt": sanitize_value(jwt),
            "business_logic": sanitize_value(business),
            "upload": sanitize_value(upload),
            "api_surface": sanitize_value(api_surface),
        },
        "prerequisites": prerequisites,
        "assessment_status": results.get(
            "assessment_status", "completed_with_limitations"
        ),
        "assessment_mode": str(assessment.get("assessment_mode") or "observe"),
        "coverage": sanitize_value(results.get("coverage") or {}),
    }
    return _freeze(facts)


def _deterministic_report(
    target: str,
    results: dict[str, Any],
    ai_status: str,
    canonical_facts: Mapping[str, Any] | None = None,
) -> str:
    facts = _thaw(canonical_facts or build_canonical_report_facts(results))
    observations = facts["observations"]
    candidates = facts["candidates"]
    verified = facts["verified"]
    recommendations = facts["manual_recommendations"]
    counts = facts["counts"]
    coverage = facts["coverage"]
    tool_statuses = facts["tool_statuses"]
    graphql = facts["surface"]["graphql"]
    jwt = facts["surface"]["jwt"]
    business = facts["surface"]["business_logic"]
    upload = facts["surface"]["upload"]
    api_surface = facts["surface"]["api_surface"]
    header_facts = facts["security_headers"]
    completed = sorted(
        name
        for name, item in tool_statuses.items()
        if item.get("status") in {"completed", "completed_with_fallback"}
    )
    partial = sorted(
        name
        for name, item in tool_statuses.items()
        if item.get("status") == "timed_out_partial"
    )
    failed = sorted(
        name
        for name, item in tool_statuses.items()
        if item.get("status") in {"failed", "timed_out"}
    )
    skipped = sorted(
        name
        for name, item in tool_statuses.items()
        if item.get("status") in {"skipped", "not_applicable"}
    )
    posture = (
        "The deterministic evidence includes verified findings listed below."
        if verified
        else "No evidence collected during this assessment demonstrated an exploitable vulnerability."
    )
    lines = [
        f"# CyberCortex AI Agent v{__version__} Security Assessment Report",
        "",
        "## Executive Summary",
        "",
        f"CyberCortex completed a bounded assessment of the authorized target. {posture}",
        "",
        f"- Observations: {len(observations)}",
        f"- Candidates requiring manual verification: {counts['candidate_findings']}",
        f"- Verified findings: {counts['verified_findings']}",
        "",
        "## Scope and Authorization",
        "",
        f"Target: {target}. Testing was restricted to configured scope and program rules.",
        "",
        "## Assessment Coverage",
        "",
        f"- Assessment status: {facts['assessment_status']}",
        f"- Assessment mode: {facts['assessment_mode']}",
        f"- Coverage: {coverage.get('coverage_percentage', 'not available')}%",
        f"- Completed tools: {', '.join(completed) or 'none'}",
        f"- Partial tools: {', '.join(partial) or 'none'}",
        f"- Failed or timed-out tools: {', '.join(failed) or 'none'}",
        f"- Skipped or not-applicable tools: {', '.join(skipped) or 'none'}",
        "",
        "## Confirmed Security Controls",
        "",
    ]

    present_headers = sorted(
        name for name, item in header_facts.items() if item.get("present") is True
    )
    if present_headers:
        lines.extend(f"- {name}: present" for name in present_headers)
    else:
        lines.append("No confirmed controls were recorded in canonical report facts.")
    lines.extend(["", "## Verified Findings", ""])

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
        lines.extend(
            [
                "Public contact information was observed in JavaScript. No credential-like secret was identified.",
                "",
            ]
        )
    js_status = tool_statuses.get("js_secret_scanner", {}).get("status")
    if _js_scan_skipped_for_no_urls(facts):
        lines.extend(
            [
                "JavaScript secret scanning was not performed because no authorized JavaScript URLs were available.",
                "",
            ]
        )
    elif js_status in SUCCESSFUL_TOOL_STATUSES and not any(
        item.get("category") == "credential_candidate" for item in candidates
    ):
        lines.extend(
            ["No credential-like secrets were identified by the completed scan.", ""]
        )

    missing_headers = sorted(
        name for name, item in header_facts.items() if item.get("present") is False
    )
    if missing_headers:
        lines.extend(
            [
                "### Deterministic security-header observations",
                "",
                *[f"- {name}: not present" for name in missing_headers],
                "",
                "A missing security header alone does not establish a vulnerability or direct exploit path.",
                "",
            ]
        )
    lines.extend(
        [
            "Observed API-related routes are route-name evidence only; static assets and resource slugs are not authorization objects without stronger identifier evidence.",
            "An observation alone does not establish a vulnerability or direct exploit path.",
            "",
        ]
    )

    if api_surface.get("relevant"):
        lines.extend(
            [
                "## API Surface",
                "",
                "API-oriented application behavior was observed.",
                f"- OpenAPI document discovered: {'yes' if api_surface.get('openapi_document_discovered') else 'no'}",
                f"- Routes documented: {counts['api_routes']}",
                f"- Operations observed: {counts['api_operations']}",
                f"- Parameters observed: {counts['api_parameters']}",
                f"- Object-reference candidates: {counts['api_objects']}",
                f"- Authentication-protected operations: {counts['api_protected_operations']}",
                "",
                "This section describes attack surface only; OpenAPI availability and identifier names do not establish a vulnerability.",
                "",
            ]
        )

    if facts["prerequisites"]["graphql_surface"]:
        lines.extend(
            [
                "## GraphQL Surface",
                "",
                "GraphQL-related application behavior was observed.",
                f"- Endpoints observed: {counts['graphql_endpoints']}",
                f"- Confirmed endpoints: {graphql.get('confirmed_endpoints', 0)}",
                f"- Introspection status: {graphql.get('introspection_status', 'not tested')}",
                f"- Operations observed: {graphql.get('operations_observed', 0)}",
                f"- Authorization plans: {graphql.get('manual_authorization_plans', 0)}",
                "",
                "Introspection availability does not by itself establish a vulnerability.",
                "",
            ]
        )
    jwt_status = tool_statuses.get("jwt_discovery", {}).get("status")
    if counts["jwt_tokens"] == 0 and jwt_status in {
        "completed",
        "completed_with_fallback",
    }:
        lines.extend(
            [
                "JWT discovery completed. No JWTs were observed in the collected evidence.",
                "",
            ]
        )
    if counts["jwt_tokens"]:
        lines.extend(
            [
                "## JWT Surface",
                "",
                "JWT-related authentication metadata was observed.",
                f"- Tokens observed: {counts['jwt_tokens']}",
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
    if counts["workflow_candidates"]:
        lines.extend(
            [
                "## Business Workflow Surface",
                "",
                "Business-workflow-related application behavior was observed.",
                f"- Workflow candidates: {counts['workflow_candidates']}",
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
    if counts["upload_surfaces"]:
        lines.extend(
            [
                "## File Upload Surface",
                "<!-- Compatibility heading: ## Upload Surface -->",
                "",
                "File-upload-related application behavior was observed. No file was uploaded automatically.",
                f"- Upload candidates: {counts['upload_surfaces']}",
                "",
                "## Upload Observations",
                "",
                f"- Validation observations: {upload.get('validation_observations', 0)}",
                f"- Metadata observations: {upload.get('metadata_observations', 0)}",
                f"- Storage indicators: {len(upload.get('storage_observations', []))}",
                "",
                "## Manual Upload Verification",
                "",
                f"- Manual plans: {upload.get('manual_plans', 0)}",
                f"- Replay status: {upload.get('replay_status', 'not applicable')}",
                "",
                "Upload acceptance or storage SDK presence alone does not establish a vulnerability.",
                "",
            ]
        )
    lines.extend(
        [
            "## Incomplete or Failed Checks",
            "",
        ]
    )
    incomplete = [
        (name, item)
        for name, item in sorted(tool_statuses.items())
        if item.get("status")
        in {"failed", "timed_out", "timed_out_partial", "skipped", "not_applicable"}
    ]
    if incomplete:
        for name, item in incomplete:
            limitation = (
                item.get("limitation") or "No additional limitation text was returned."
            )
            lines.append(f"- {name}: {item.get('status')} — {limitation}")
    else:
        lines.append("No incomplete required checks were recorded.")
    lines.extend(["", "## Prioritized Next Manual Tests", ""])
    if recommendations:
        for item in recommendations[:20]:
            lines.append(
                f"- {item.get('title', 'Review the evidence-backed candidate.')}"
            )
    else:
        lines.append("No evidence-supported manual test was queued.")
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


def _markdown_section(report: str, heading: str) -> str:
    pattern = re.compile(rf"(?ms)^## {re.escape(heading)}\s*$\n?(.*?)(?=^## |\Z)")
    match = pattern.search(report)
    return match.group(1) if match else ""


def _replace_manual_recommendations(report: str, facts: dict[str, Any]) -> str:
    heading = "Prioritized Next Manual Tests"
    pattern = re.compile(rf"(?ms)^## {re.escape(heading)}\s*$\n?.*?(?=^## |\Z)")
    recommendations = facts["manual_recommendations"]
    body = [f"## {heading}", ""]
    if recommendations:
        body.extend(f"- {item['title']}" for item in recommendations)
    else:
        body.append("No evidence-supported manual test was queued.")
    replacement = "\n".join(body) + "\n\n"
    return (
        pattern.sub(replacement, report, count=1) if pattern.search(report) else report
    )


def _append_required_grounding(report: str, facts: dict[str, Any]) -> str:
    required: list[str] = []
    statuses = facts["tool_statuses"]
    jwt_status = statuses.get("jwt_discovery", {}).get("status")
    jwt_zero = facts["counts"]["jwt_tokens"] == 0 and jwt_status in {
        "completed",
        "completed_with_fallback",
    }
    if jwt_zero:
        required.append(
            "JWT discovery completed. No JWTs were observed in the collected evidence."
        )
    if any(item.get("category") == "public_contact" for item in facts["observations"]):
        required.append(
            "Public contact information was observed in JavaScript. No credential-like secret was identified."
        )
    if _js_scan_skipped_for_no_urls(facts):
        required.append(
            "JavaScript secret scanning was not performed because no authorized JavaScript URLs were available."
        )
    blocks: list[str] = []
    api_surface = facts["surface"].get("api_surface") or {}
    if api_surface.get("relevant") and not re.search(
        r"(?m)^## API Surface\s*$", report
    ):
        counts = facts["counts"]
        blocks.append(
            "\n".join(
                [
                    "## API Surface",
                    "",
                    "API-oriented application behavior was observed.",
                    f"- OpenAPI document discovered: {'yes' if api_surface.get('openapi_document_discovered') else 'no'}",
                    f"- Routes documented: {counts['api_routes']}",
                    f"- Operations observed: {counts['api_operations']}",
                    f"- Parameters observed: {counts['api_parameters']}",
                    f"- Object-reference candidates: {counts['api_objects']}",
                    f"- Authentication-protected operations: {counts['api_protected_operations']}",
                    "",
                    "This section describes attack surface only; OpenAPI availability and identifier names do not establish a vulnerability.",
                ]
            )
        )
    missing = [statement for statement in required if statement not in report]
    blocks.extend(missing)
    if not blocks:
        return report
    block = "\n\n".join(blocks) + "\n\n"
    limitations = re.search(r"(?m)^## Limitations\s*$", report)
    if limitations:
        return report[: limitations.start()] + block + report[limitations.start() :]
    return report.rstrip() + "\n\n" + block.rstrip() + "\n"


def _numeric_claims(report: str, patterns: tuple[str, ...]) -> list[int]:
    claims: list[int] = []
    for pattern in patterns:
        claims.extend(
            int(match.group(1))
            for match in re.finditer(pattern, report, flags=re.IGNORECASE)
        )
    return claims


def _validate_count_claims(report: str, facts: dict[str, Any]) -> list[str]:
    patterns = {
        "api_routes": (r"\broutes?\s+documented\s*[:=]\s*(\d+)\b",),
        "api_operations": (r"\boperations?\s+observed\s*[:=]\s*(\d+)\b",),
        "api_parameters": (r"\bparameters?\s+observed\s*[:=]\s*(\d+)\b",),
        "api_objects": (r"\bobject-reference candidates?\s*[:=]\s*(\d+)\b",),
        "api_protected_operations": (
            r"\bauthentication-protected operations?\s*[:=]\s*(\d+)\b",
        ),
        "jwt_tokens": (
            r"\b(\d+)\s+(?:jwt\s+)?tokens?\s+(?:were\s+)?observed\b",
            r"\btokens?\s+observed\s*[:=]\s*(\d+)\b",
        ),
        "graphql_endpoints": (
            r"\b(\d+)\s+graphql\s+endpoints?\s+(?:were\s+)?observed\b",
            r"\b(?:graphql\s+)?endpoints?\s+observed\s*[:=]\s*(\d+)\b",
        ),
        "upload_surfaces": (
            r"\b(\d+)\s+(?:file[- ]?)?upload\s+(?:surfaces?|candidates?|observations?)\b",
            r"\bupload\s+(?:surfaces?|candidates?|observations?)\s*[:=]\s*(\d+)\b",
        ),
        "workflow_candidates": (
            r"\b(\d+)\s+(?:business[- ]?)?workflow\s+candidates?\b",
            r"\bworkflow\s+candidates?\s*[:=]\s*(\d+)\b",
        ),
        "candidate_findings": (
            r"\bcandidates?(?:\s+requiring\s+manual\s+verification)?\s*[:=]\s*(\d+)\b",
        ),
        "verified_findings": (r"\bverified\s+findings?\s*[:=]\s*(\d+)\b",),
        "nuclei_findings": (
            r"\b(\d+)\s+nuclei\s+findings?\b",
            r"\bnuclei\s+findings?\s*[:=]\s*(\d+)\b",
        ),
    }
    errors: list[str] = []
    for key, claim_patterns in patterns.items():
        expected = facts["counts"][key]
        for claim in _numeric_claims(report, claim_patterns):
            if claim != expected:
                errors.append(f"{key} count contradicted canonical facts")
                break
    return errors


def _validate_tool_status_claims(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name, item in facts["tool_statuses"].items():
        expected = item.get("status")
        variants = {name.lower(), name.replace("_", " ").lower()}
        for line in report.splitlines():
            lowered = line.lower()
            if not any(variant in lowered for variant in variants):
                continue
            claimed: set[str] = set()
            if re.search(r"\b(?:timed out|timeout|timed_out)\b", lowered):
                claimed.add("timed_out")
            if re.search(r"\bfailed\b", lowered):
                claimed.add("failed")
            if re.search(r"\bskipped\b", lowered):
                claimed.add("skipped")
            if re.search(r"\bnot applicable\b|\bnot_applicable\b", lowered):
                claimed.add("not_applicable")
            if re.search(r"\bcompleted\b|\bsucceeded\b|\bsuccessful\b", lowered):
                claimed.add("completed")
            compatible = {
                "completed": {"completed"},
                "completed_with_fallback": {"completed"},
                "timed_out": {"timed_out"},
                "timed_out_partial": {"timed_out"},
                "failed": {"failed"},
                "skipped": {"skipped"},
                "not_applicable": {"not_applicable"},
            }.get(expected, set())
            if claimed and not claimed.issubset(compatible):
                errors.append(f"{name} execution state contradicted canonical facts")
                break
    return errors


def _validate_header_claims(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    authoritative = facts["security_headers"]
    additional = {name.lower() for name in facts["additional_deterministic_headers"]}
    header_pattern = re.compile(
        r"\b(?:X-[A-Za-z0-9-]+|Content-Security-Policy|"
        r"Strict-Transport-Security|Referrer-Policy|Permissions-Policy|"
        r"Cross-Origin-[A-Za-z-]+|Expect-CT)\b",
        re.IGNORECASE,
    )
    header_aliases = {
        "COOP": "Cross-Origin-Opener-Policy",
        "COEP": "Cross-Origin-Embedder-Policy",
        "CORP": "Cross-Origin-Resource-Policy",
    }
    authoritative_by_lower = {
        name.lower(): item for name, item in authoritative.items()
    }
    for line in report.splitlines():
        mentions = [match.group(0) for match in header_pattern.finditer(line)]
        mentions.extend(re.findall(r"\b(?:COOP|COEP|CORP)\b", line))
        for mention in mentions:
            canonical_name = header_aliases.get(mention, mention)
            name = canonical_name.lower()
            if name not in authoritative_by_lower and name not in additional:
                errors.append(f"unsupported security-header claim: {mention}")
                continue
            item = authoritative_by_lower.get(name)
            if not item:
                continue
            lowered = line.lower()
            negative = bool(
                re.search(
                    r"\b(?:missing|absent|not present|not set|lacks?|without)\b",
                    lowered,
                )
            )
            positive = bool(re.search(r"\b(?:present|enabled|set)\b", lowered))
            if item["present"] and negative:
                errors.append(f"{mention} presence contradicted canonical facts")
            if not item["present"] and positive and not negative:
                errors.append(f"{mention} absence contradicted canonical facts")
    return errors


def _validate_classification_claims(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    candidate_section = _markdown_section(
        report, "Candidate Findings Requiring Manual Verification"
    )
    public_titles = {
        str(item.get("title", ""))
        for item in facts["observations"]
        if item.get("category") == "public_contact"
    }
    if public_titles and (
        "public contact" in candidate_section.lower()
        or any(title and title in candidate_section for title in public_titles)
    ):
        errors.append("public_contact was promoted to a candidate")
    if public_titles and re.search(
        r"(?:pii exposure|sensitive contact disclosure|contact information.{0,40}candidate vulnerability)",
        report,
        re.IGNORECASE | re.DOTALL,
    ):
        errors.append("public_contact was described as sensitive or vulnerable")

    section_facts = {
        "Verified Findings": facts["verified"],
        "Candidate Findings Requiring Manual Verification": facts["candidates"],
        "Informational and Defense-in-Depth Observations": facts["observations"],
    }
    all_titles = {
        str(item.get("title", "")): heading
        for heading, items in section_facts.items()
        for item in items
        if item.get("title")
    }
    for heading, items in section_facts.items():
        section = _markdown_section(report, heading)
        titles = {str(item.get("title", "")) for item in items}
        for markdown_title in re.findall(r"(?m)^###\s+(.+?)\s*$", section):
            expected_heading = all_titles.get(markdown_title)
            if expected_heading and expected_heading != heading:
                errors.append(f"{markdown_title} appeared in the wrong classification")
            elif markdown_title not in titles:
                errors.append(f"unsupported finding in {heading}: {markdown_title}")
    return errors


def _validate_finding_metadata(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    findings = facts["observations"] + facts["candidates"] + facts["verified"]
    for item in findings:
        title = str(item.get("title") or "")
        if not title:
            continue
        match = re.search(
            rf"(?ms)^###\s+{re.escape(title)}\s*$\n?(.*?)(?=^###\s|^##\s|\Z)",
            report,
        )
        if not match:
            continue
        block = match.group(1)
        for field in ("severity", "confidence", "source_tool"):
            claim = re.search(
                rf"(?im)^(?:[-*]\s*)?(?:\*\*)?{field.replace('_', ' ')}"
                rf"(?:\*\*)?\s*:\s*(?:\*\*)?\s*([^\n*]+)",
                block,
            )
            if not claim or item.get(field) is None:
                continue
            claimed = claim.group(1).strip().lower().replace(" ", "_")
            expected = str(item[field]).strip().lower().replace(" ", "_")
            if claimed != expected:
                errors.append(f"{title} {field} contradicted canonical facts")
        status_claim = re.search(
            r"(?im)^(?:[-*]\s*)?(?:\*\*)?status(?:\*\*)?\s*:\s*"
            r"(?:\*\*)?\s*([^\n*]+)",
            block,
        )
        if status_claim and item.get("status"):
            claimed = status_claim.group(1).strip().lower().replace(" ", "_")
            expected = str(item["status"]).strip().lower().replace(" ", "_")
            compatible = {
                "observation": {"observation", "confirmed_observation"},
                "candidate": {"candidate", "needs_manual_verification"},
                "needs_manual_verification": {
                    "candidate",
                    "needs_manual_verification",
                },
                "verified": {"verified", "verified_finding"},
            }.get(expected, {expected})
            if claimed not in compatible:
                errors.append(f"{title} status contradicted canonical facts")
    return errors


def _validate_zero_surface_claims(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    counts = facts["counts"]
    positive_patterns = {
        "jwt_tokens": r"jwt-related authentication metadata was observed|jwt (?:surface|testing)",
        "graphql_endpoints": r"graphql-related application behavior was observed|graphql surface",
        "upload_surfaces": r"file-upload-related application behavior was observed|file upload surface",
        "workflow_candidates": r"business-workflow-related application behavior was observed|business workflow surface",
    }
    for key, pattern in positive_patterns.items():
        unsupported = counts[key] == 0
        if key == "graphql_endpoints":
            unsupported = not facts["prerequisites"]["graphql_surface"]
        if unsupported and re.search(pattern, report, re.IGNORECASE):
            errors.append(f"{key} surface was claimed without deterministic evidence")

    if counts["nuclei_findings"] == 0:
        for line in report.splitlines():
            lowered = line.lower()
            if "nuclei" not in lowered:
                continue
            allowed_status_text = re.search(
                r"status|completed|timed out|timeout|failed|skipped|not applicable|"
                r"limitation|0\s+(?:partial\s+)?findings|no (?:partial )?findings",
                lowered,
            )
            if not allowed_status_text:
                errors.append(
                    "Nuclei finding was claimed when deterministic count was zero"
                )
                break
    return errors


def _validate_skipped_negative_claims(report: str, facts: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    js_status = facts["tool_statuses"].get("js_secret_scanner", {}).get("status")
    if js_status in {"skipped", "not_applicable"} and re.search(
        r"no (?:exposed )?(?:javascript )?secrets? (?:were )?(?:found|detected|identified)",
        report,
        re.IGNORECASE,
    ):
        errors.append("skipped JavaScript scan was presented as a negative result")
    for name, item in facts["tool_statuses"].items():
        if item.get("status") not in {"skipped", "not_applicable"}:
            continue
        variants = (name.lower(), name.replace("_", " ").lower())
        for line in report.splitlines():
            lowered = line.lower()
            if not any(variant in lowered for variant in variants):
                continue
            if re.search(
                r"\b(?:no|none|zero)\b.*\b(?:found|detected|observed|identified|confirmed)\b",
                lowered,
            ) and not re.search(
                r"\b(?:not performed|skipped|not applicable)\b", lowered
            ):
                errors.append(f"skipped {name} was presented as a negative result")
                break
    return errors


def _validate_recommendation_prerequisites(
    report: str, facts: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    counts = facts["counts"]
    authorization_evidence = bool(
        facts["prerequisites"]["object_identifier_evidence"]
        or any(
            item.get("category") == "authorization_test_idea"
            for item in facts["candidates"]
        )
    )
    checks = (
        (counts["jwt_tokens"] == 0, r"\b(?:jwt|token)\b"),
        (not facts["prerequisites"]["graphql_surface"], r"\bgraphql\b"),
        (counts["upload_surfaces"] == 0, r"\b(?:file[- ]?upload|upload)\b"),
        (counts["workflow_candidates"] == 0, r"\b(?:business[- ]?logic|workflow)\b"),
        (
            not authorization_evidence,
            r"\b(?:idor|bola|authorization testing)\b",
        ),
    )
    for line in report.splitlines():
        lowered = line.lower()
        if not re.search(r"\b(?:recommend|manual(?:ly)?|test(?:ing)?)\b", lowered):
            continue
        for unsupported, pattern in checks:
            if unsupported and re.search(pattern, lowered, re.IGNORECASE):
                errors.append("manual recommendation lacked prerequisite evidence")
                return errors
    return errors


def validate_generated_report(
    report: str, canonical_facts: Mapping[str, Any]
) -> tuple[str | None, list[str]]:
    """Validate and safely repair model Markdown against immutable facts."""
    facts = _thaw(canonical_facts)
    repaired = _replace_manual_recommendations(report, facts)
    errors = [
        *_validate_count_claims(repaired, facts),
        *_validate_tool_status_claims(repaired, facts),
        *_validate_header_claims(repaired, facts),
        *_validate_classification_claims(repaired, facts),
        *_validate_finding_metadata(repaired, facts),
        *_validate_zero_surface_claims(repaired, facts),
        *_validate_skipped_negative_claims(repaired, facts),
        *_validate_recommendation_prerequisites(repaired, facts),
    ]
    if errors:
        return None, sorted(set(errors))
    return _append_required_grounding(repaired, facts), []


def ai_report_writer(
    target: str,
    results: dict,
    output_dir: str | None = None,
    phase_callback=None,
    allow_network_analysis: bool = True,
) -> dict:
    """
    Generate a professional Markdown security assessment report.
    """

    target = sanitize_url(str(target))
    report_directory = Path(output_dir or REPORT_DIR)
    report_directory.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now()
    timestamp = generated_at.strftime("%Y%m%d_%H%M%S")

    filename = report_directory / f"ai_security_report_{timestamp}.md"

    evidence_filename = report_directory / f"assessment_evidence_{timestamp}.json"

    normalized_results, diagnostics = _normalize_report_evidence(public_result(results))
    normalized_results = public_result(normalized_results)
    canonical_facts = build_canonical_report_facts(normalized_results)
    canonical_data = _thaw(canonical_facts)
    compact_results = build_compact_results(normalized_results)

    evidence_json = json.dumps(
        canonical_data, indent=2, ensure_ascii=False, default=str
    )
    original_bytes = len(evidence_json.encode("utf-8"))
    telemetry = {
        "evidence_json_bytes": original_bytes,
        "estimated_tokens": (original_bytes + 3) // 4,
        "truncation_performed": False,
        "sections_truncated": [],
    }
    assessment_data = json.dumps(
        canonical_data,
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
            {
                "prompt_size_telemetry": telemetry,
                "canonical_report_facts": canonical_data,
                "evidence": compact_results,
            },
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
4. `security_headers` is authoritative for every header it contains. Do not add
   another header observation unless `additional_deterministic_headers` supplies it.
5. Third-party links are not vulnerabilities by themselves.
6. Describe a tool only from its canonical status and limitation text.
7. State confidence for each finding.
8. Include exact supporting evidence without exposing secrets.
9. Mark anything requiring human confirmation as `Needs manual verification`.
10. Never claim session hijacking, account takeover, authorization bypass, XSS,
    CSRF, or data exposure unless evidence directly supports it.
11. A failed crawler means coverage is incomplete; it does not prove no endpoints exist.
12. JWT structural analysis does not prove server-side acceptance.
13. The Nuclei finding count is immutable. A failed or timed-out Nuclei run may
    contribute only its status, limitation, and partial findings present in facts.
14. Do not upgrade deterministic severity without explicit supporting evidence.
15. Display the supplied assessment status and coverage. Success of the workflow
    must not conceal failed or timed-out tools.
16. Never promote an observation to candidate or verified. Promotion requires an
    explicit candidate/verified status and supporting evidence in the supplied data.
17. For public_contact say exactly: "Public contact information was observed in
    JavaScript. No credential-like secret was identified." Never call it PII,
    sensitive disclosure, a candidate, or a vulnerability.
18. Counts, statuses, severity, confidence, classification, and evidence existence
    are immutable. Copy them exactly from canonical report facts.
19. Say "Observed API-related routes", not "Identified API endpoints", unless
    functioning API response evidence exists.
20. Do not infer crawler coverage beyond canonical facts.
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
25. If jwt_discovery completed with jwt_tokens = 0, say exactly: "JWT discovery
    completed. No JWTs were observed in the collected evidence."
26. A skipped or not-applicable tool is not a negative result. For a skipped
    js_secret_scanner say exactly: "JavaScript secret scanning was not performed
    because no authorized JavaScript URLs were available."
27. The Prioritized Next Manual Tests section may contain only entries from
    `manual_recommendations`. Do not invent capability-specific testing.
28. When `api_surface.relevant` is true, include `## API Surface` with its exact
    canonical counts. Describe attack surface only; never call OpenAPI existence,
    documented identifiers, or authentication requirements vulnerabilities.

Target:
{target}

Generated:
{generated_at.strftime("%Y-%m-%d %H:%M:%S")}

Canonical immutable report facts:
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

List failed or timed-out tools only with their canonical status and limitation.

---

## Confirmed Security Controls

---

## Verified Findings

Only evidence-backed verified findings.

## Candidate Findings Requiring Manual Verification

## Informational and Defense-in-Depth Observations

## Incomplete or Failed Checks

When API evidence is relevant, add `## API Surface` with exact canonical counts.

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

List only security headers whose canonical `present` value is true.

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

Copy only entries from canonical `manual_recommendations`, preserving their order.

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
    validation_errors: list[str] = []
    try:
        if not allow_network_analysis:
            raise RuntimeError(
                "External AI analysis is disabled in the policy-bound scan runtime."
            )
        report = ask_agent(prompt, timeout=AI_REPORT_TIMEOUT_SECONDS)

        if not isinstance(report, str) or not report.strip():
            raise ValueError("The AI model returned a malformed or empty report.")

        validated_report, validation_errors = validate_generated_report(
            report.strip(), canonical_facts
        )
        if validated_report is None:
            report_mode = "deterministic_fallback"
            ai_error = "Model output contradicted canonical report facts."
            deterministic = _deterministic_report(
                target,
                normalized_results,
                ai_status,
                canonical_facts=canonical_facts,
            )
            if phase_callback:
                phase_callback("report_writing")
            filename.write_text(sanitize_document_text(deterministic), encoding="utf-8")
            print("[!] DeepSeek output failed deterministic grounding validation.")
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
                "report_validation_errors": validation_errors,
                "report_file": str(filename),
                "evidence_file": str(evidence_filename),
                "prompt_telemetry": telemetry,
                "prompt_size_telemetry": telemetry,
            }

        if phase_callback:
            phase_callback("report_writing")
        filename.write_text(
            sanitize_document_text(validated_report.strip()) + "\n",
            encoding="utf-8",
        )

    except Exception as exc:
        ai_status = "timed_out" if isinstance(exc, TimeoutError) else "failed"
        ai_error = f"{type(exc).__name__}: AI analysis was unavailable."
        report_mode = "deterministic_fallback"
        deterministic = _deterministic_report(
            target,
            normalized_results,
            ai_status,
            canonical_facts=canonical_facts,
        )
        if phase_callback:
            phase_callback("report_writing")
        filename.write_text(sanitize_document_text(deterministic), encoding="utf-8")
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
            "report_validation_errors": validation_errors,
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
        "report_validation_errors": validation_errors,
        "report_file": str(filename),
        "evidence_file": str(evidence_filename),
        "generated_at": generated_at.isoformat(),
        "ai_analysis": "available",
        "prompt_telemetry": telemetry,
        "prompt_size_telemetry": telemetry,
    }
