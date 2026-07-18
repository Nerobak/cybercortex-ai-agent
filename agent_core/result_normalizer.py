"""Deterministic normalization and bounded evidence packaging."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

from tools.scope_guard import enforce_scope
from agent_core.version import __version__

MAX_EVIDENCE_BYTES = 200_000
MAX_ITEMS = 100
MAX_TEXT = 1500
SECRET_KEYS = re.compile(
    r"authorization|cookie|jwt|token|api.?key|secret|password", re.I
)
EXCLUDED_KEYS = {
    "body",
    "html",
    "raw_request",
    "raw_response",
    "raw_output",
    "stdout",
    "stderr",
    "claims",
    "payload",
}


def redact(value: Any, key: str = "") -> Any:
    if SECRET_KEYS.search(key):
        if isinstance(value, list):
            return []
        if isinstance(value, dict):
            return {"redacted": True, "count": len(value)}
        return "[REDACTED]"
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for raw_key, item in value.items():
            item_key = str(raw_key)
            if item_key.lower() in EXCLUDED_KEYS:
                continue
            if SECRET_KEYS.search(item_key) and isinstance(item, list):
                cleaned[item_key] = []
                cleaned[f"{item_key.rstrip('s')}_count"] = len(item)
            else:
                cleaned[item_key] = redact(item, item_key)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value[:MAX_ITEMS]]
    if isinstance(value, str):
        # JWT-like strings must never cross the evidence boundary.
        if re.fullmatch(
            r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", value.strip()
        ):
            return "[REDACTED JWT]"
        return value[:MAX_TEXT] + ("... [truncated]" if len(value) > MAX_TEXT else "")
    return value


def normalize_finding_list(
    value: Any,
    *,
    section: str = "findings",
    diagnostics: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return only finding dictionaries without retaining malformed values."""
    if value is None:
        return []
    members = (
        value if isinstance(value, list) else [value] if isinstance(value, dict) else []
    )
    malformed = (
        0 if members else int(value is not None and not isinstance(value, (list, dict)))
    )
    normalized: list[dict[str, Any]] = []
    for item in members:
        if isinstance(item, dict):
            normalized.append(item)
        else:
            malformed += 1
    if malformed and diagnostics is not None:
        diagnostics.append(
            {
                "section": section,
                "issue": "Malformed structured evidence was skipped.",
                "skipped_count": malformed,
            }
        )
    return normalized


def normalize_url_evidence(target: str, results: dict[str, Any]) -> dict[str, Any]:
    http_envelope = results.get("http_probe", {})
    crawl_envelope = results.get("katana_crawl", {})
    http = (
        http_envelope.get("output", http_envelope)
        if isinstance(http_envelope, dict)
        else {}
    ) or {}
    crawl = (
        crawl_envelope.get("output", crawl_envelope)
        if isinstance(crawl_envelope, dict)
        else {}
    ) or {}
    if not isinstance(http, dict):
        http = {}
    if not isinstance(crawl, dict):
        crawl = {}
    crawl_urls = crawl.get("urls")
    if not isinstance(crawl_urls, list):
        crawl_urls = []
    candidates = [target, http.get("effective_url"), *crawl_urls]
    all_urls: list[str] = []
    raw_out = crawl.get("out_of_scope_urls")
    out = list(raw_out) if isinstance(raw_out, (list, tuple, set)) else []
    for item in candidates:
        if not isinstance(item, str) or not item:
            continue
        parsed = urlparse(item)
        clean = urlunparse(parsed._replace(fragment=""))
        if enforce_scope(clean).get("allowed"):
            if clean not in all_urls:
                all_urls.append(clean)
        elif clean not in out:
            out.append(clean)
    origin = urlparse(target)
    same_origin = [
        u
        for u in all_urls
        if (urlparse(u).scheme, urlparse(u).hostname, urlparse(u).port)
        == (origin.scheme, origin.hostname, origin.port)
    ]
    api_urls = [
        u
        for u in all_urls
        if any(x in urlparse(u).path.lower() for x in ("/api", "/graphql", "/rest/"))
    ]
    javascript = [
        u for u in all_urls if urlparse(u).path.lower().endswith((".js", ".mjs"))
    ]
    with_parameters = [
        u for u in all_urls if parse_qs(urlparse(u).query, keep_blank_values=True)
    ]
    return {
        "requested_target": target,
        "effective_target": http.get("effective_url") or target,
        "redirect_chain": http.get("redirect_chain", []),
        "all_urls": all_urls,
        "same_origin_urls": same_origin,
        "api_urls": api_urls,
        "javascript_urls": javascript,
        "urls_with_parameters": with_parameters,
        "out_of_scope_urls": out,
        "crawl_status": crawl.get("status", "failed"),
    }


def _finding(
    title: str,
    source: str,
    *,
    severity: str = "informational",
    status: str = "observation",
    endpoint: str | None = None,
    evidence: list[str] | None = None,
    category: str = "hardening",
) -> dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "high",
        "status": status,
        "source_tool": source,
        "endpoint": endpoint,
        "method": None,
        "evidence": evidence or [],
        "impact": "",
        "recommendation": "Review in application context.",
        "manual_verification": [],
        "metadata": {},
    }


def normalize_findings(results: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    header_envelope = results.get("security_headers_checker", {})
    header_result = (
        header_envelope.get("output", {}) if isinstance(header_envelope, dict) else {}
    ) or {}
    if not isinstance(header_result, dict):
        header_result = {}
    informational = {
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
        "Permissions-Policy",
        "X-Permitted-Cross-Domain-Policies",
        "X-XSS-Protection",
        "Expect-CT",
    }
    headers_checked = header_result.get("headers_checked")
    if not isinstance(headers_checked, dict):
        headers_checked = {}
    for name, item in headers_checked.items():
        if isinstance(item, dict) and not item.get("present"):
            severity = (
                "informational"
                if name in informational or name != "Content-Security-Policy"
                else "low"
            )
            findings.append(
                _finding(
                    f"Missing {name}",
                    "security_headers_checker",
                    severity=severity,
                    endpoint=header_result.get("effective_url")
                    or header_result.get("url"),
                    evidence=["Header was not present in the observed response."],
                )
            )
    parameter_envelope = results.get("parameter_analyzer", {})
    parameter = (
        parameter_envelope.get("output", {})
        if isinstance(parameter_envelope, dict)
        else {}
    ) or {}
    if not isinstance(parameter, dict):
        parameter = {}
    for item in normalize_finding_list(parameter.get("findings"))[:MAX_ITEMS]:
        findings.append(
            _finding(
                f"Parameter candidate: {item.get('parameter', 'unknown')}",
                "parameter_analyzer",
                status="candidate",
                severity="informational",
                endpoint=item.get("url"),
                evidence=[str(item.get("reason", "Parameter observed."))],
                category="authorization_test_idea",
            )
        )
    js = _tool_output(results, "js_secret_scanner")
    for item in normalize_finding_list(js.get("findings"))[:MAX_ITEMS]:
        candidate = item.get("match_kind") == "candidate_value" and item.get(
            "confidence"
        ) in {"medium", "high"}
        findings.append(
            _finding(
                (
                    "Potential credential-like value requires verification"
                    if candidate
                    else "Public contact information observed in JavaScript"
                ),
                "js_secret_scanner",
                status="needs_manual_verification" if candidate else "observation",
                severity="informational",
                endpoint=item.get("url"),
                evidence=[
                    f"Match kind: {item.get('match_kind', 'unknown')}; confidence: {item.get('confidence', 'unknown')}; context hash: {item.get('context_hash', 'unavailable')}"
                ],
                category="credential_candidate" if candidate else "public_contact",
            )
        )
    nuclei_envelope = results.get("nuclei_scan", {})
    nuclei = (
        nuclei_envelope.get("output", nuclei_envelope)
        if isinstance(nuclei_envelope, dict)
        else {}
    ) or {}
    if not isinstance(nuclei, dict):
        nuclei = {}
    for item in normalize_finding_list(nuclei.get("findings"))[:MAX_ITEMS]:
        findings.append(
            _finding(
                item.get("name") or item.get("template_id") or "Nuclei observation",
                "nuclei_scan",
                severity=item.get("severity", "informational"),
                endpoint=item.get("matched_at") or item.get("url"),
                evidence=[item.get("description") or "Nuclei template matched."],
                category="scanner_observation",
            )
        )
    return findings


def build_evidence_package(
    target: str,
    profile: str,
    results: dict[str, Any],
    started_at: str,
    completed_at: str,
    surface: dict[str, Any] | None = None,
) -> dict[str, Any]:
    surface = surface or normalize_url_evidence(target, results)
    findings = normalize_findings(results)
    by_status = {
        key: []
        for key in (
            "completed",
            "completed_with_fallback",
            "failed",
            "timed_out",
            "timed_out_partial",
            "skipped",
            "not_applicable",
        )
    }
    for name, envelope in results.items():
        if not isinstance(envelope, dict):
            continue
        status = envelope.get("status", "failed")
        if status in by_status:
            by_status[status].append(name)
    api_envelope = results.get("api_object_discovery", {})
    parameter_envelope = results.get("parameter_analyzer", {})
    api = (
        api_envelope.get("output", {}) if isinstance(api_envelope, dict) else {}
    ) or {}
    parameter = (
        parameter_envelope.get("output", {})
        if isinstance(parameter_envelope, dict)
        else {}
    ) or {}
    if not isinstance(api, dict):
        api = {}
    if not isinstance(parameter, dict):
        parameter = {}
    package = {
        "assessment": {
            "version": __version__,
            "requested_target": target,
            "effective_target": surface["effective_target"],
            "profile": profile,
            "scope": {"enforced": True},
            "started_at": started_at,
            "completed_at": completed_at,
        },
        "execution_summary": by_status,
        "observed_surface": {
            "dns": _tool_output(results, "dns_lookup"),
            "http": _tool_output(results, "http_probe"),
            "redirects": surface["redirect_chain"],
            "technologies": _tool_output(results, "tech_fingerprint").get(
                "technologies", []
            ),
            "urls_discovered": len(surface["all_urls"]),
            "api_related_routes": surface["api_urls"],
            "javascript_files_checked": _tool_output(results, "js_secret_scanner").get(
                "urls_checked", 0
            ),
            "parameters": normalize_finding_list(parameter.get("findings")),
            "objects": normalize_finding_list(api.get("objects"), section="objects"),
        },
        "observations": [f for f in findings if f["status"] == "observation"],
        "candidate_findings": [
            f
            for f in findings
            if f["status"] in {"candidate", "needs_manual_verification"}
        ],
        "verified_findings": [f for f in findings if f["status"] == "verified"],
        "manual_verification_queue": [
            f
            for f in findings
            if f["status"] in {"candidate", "needs_manual_verification"}
        ],
        "tool_results": {
            name: {
                "status": env.get("status"),
                "success": env.get("success"),
                "duration_ms": env.get("duration_ms"),
                "error": env.get("error"),
                "output": redact(env.get("output")),
            }
            for name, env in results.items()
            if isinstance(env, dict)
            if name != "ai_report_writer"
        },
        "evidence_files": [],
    }
    package = redact(package)
    encoded = json.dumps(package, default=str).encode()
    if len(encoded) > MAX_EVIDENCE_BYTES:
        package["tool_results"] = {
            name: {k: v for k, v in value.items() if k != "output"}
            for name, value in package["tool_results"].items()
        }
        package["evidence_truncated"] = True
    return package


def normalize_results(results: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible compact normalizer."""
    return redact(results)


def _tool_output(results: dict[str, Any], name: str) -> dict[str, Any]:
    """Return a structured tool output without trusting an external envelope."""
    envelope = results.get(name, {})
    if not isinstance(envelope, dict):
        return {}
    output = envelope.get("output") or {}
    return output if isinstance(output, dict) else {}
