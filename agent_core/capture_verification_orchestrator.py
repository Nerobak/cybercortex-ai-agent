from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from agent_core.result_normalizer import public_result, sanitize_document_text
from tools.raw_http_request_parser import parse_raw_http_request
from tools.request_mutation_engine import build_probes
from tools.scope_guard import enforce_scope

MAX_CAPTURE_FILES = 25
MAX_PARAMETERS = 20
DEFAULT_REQUEST_BUDGET = 50
SUPPORTED = {"sqli", "xss", "ssti", "command", "traversal", "ssrf"}

PARAMETER_HINTS = {
    "ssrf": {
        "url",
        "uri",
        "callback",
        "webhook",
        "redirect",
        "return",
        "next",
        "host",
        "domain",
    },
    "traversal": {
        "file",
        "filename",
        "path",
        "folder",
        "directory",
        "download",
        "document",
        "template",
    },
    "command": {
        "cmd",
        "command",
        "exec",
        "execute",
        "shell",
        "ping",
        "host",
        "hostname",
    },
    "ssti": {"template", "view", "render", "format", "layout", "name"},
    "xss": {
        "q",
        "query",
        "search",
        "name",
        "message",
        "comment",
        "title",
        "return",
        "next",
    },
    "sqli": {
        "id",
        "user",
        "account",
        "item",
        "product",
        "order",
        "page",
        "sort",
        "filter",
        "q",
        "query",
        "search",
    },
}


def _families_for_parameter(name: str, enabled: set[str]) -> list[str]:
    normalized = name.lower().replace("-", "_")
    tokens = set(normalized.split("_")) | {normalized}
    matches = [
        family
        for family in ("sqli", "xss", "ssti", "ssrf", "traversal", "command")
        if family in enabled and tokens & PARAMETER_HINTS[family]
    ]
    # Text-like parameters remain useful XSS candidates even without a known
    # name. High-impact server-side families always require a semantic hint.
    if not matches and "xss" in enabled:
        matches.append("xss")
    return matches


def build_campaign_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    request_files = manifest.get("requests") or []
    enabled = set(manifest.get("enabled_families") or ["sqli", "xss", "ssti"])
    unknown = sorted(enabled - SUPPORTED)
    if unknown:
        return {
            "success": False,
            "error": "Unsupported families: " + ", ".join(unknown),
        }
    if not isinstance(request_files, list) or not request_files:
        return {
            "success": False,
            "error": "Manifest requires a non-empty requests list.",
        }
    if len(request_files) > MAX_CAPTURE_FILES:
        return {
            "success": False,
            "error": f"Capture count exceeds {MAX_CAPTURE_FILES}.",
        }
    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for raw_path in request_files:
        path = Path(str(raw_path)).expanduser()
        try:
            raw_request = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append({"request_file": str(path), "error": str(exc)})
            continue
        parsed = parse_raw_http_request(
            raw_request, manifest.get("default_scheme", "https")
        )
        if not parsed.get("success"):
            errors.append(
                {
                    "request_file": str(path),
                    "error": parsed.get("error", "parse failed"),
                }
            )
            continue
        if parsed.get("method") != "GET":
            errors.append(
                {
                    "request_file": str(path),
                    "error": "Only GET captures are currently executable.",
                }
            )
            continue
        if not enforce_scope(parsed["url"]).get("allowed"):
            errors.append(
                {
                    "request_file": str(path),
                    "error": "Capture target is outside configured scope.",
                }
            )
            continue
        for parameter, _ in parse_qsl(
            urlsplit(parsed["url"]).query, keep_blank_values=True
        ):
            families = _families_for_parameter(parameter, enabled)
            if not families:
                continue
            mutation_families = [item for item in families if item != "sqli"]
            estimated = int("sqli" in families) * 3
            if mutation_families:
                try:
                    estimated += 1 + len(
                        build_probes(
                            mutation_families,
                            seed=f"{urlsplit(parsed['url']).path}:{parameter}",
                            callback_url=manifest.get("callback_url"),
                            traversal_canary_path=(
                                manifest.get("traversal_canary") or {}
                            ).get("path"),
                            traversal_expected_marker=(
                                manifest.get("traversal_canary") or {}
                            ).get("expected_marker"),
                        )
                    )
                except ValueError as exc:
                    errors.append(
                        {"request_file": str(path), "error": f"{parameter}: {exc}"}
                    )
                    mutation_families = [
                        item
                        for item in mutation_families
                        if item not in {"ssrf", "traversal"}
                    ]
                    estimated = int("sqli" in families) * 3 + (
                        1 + len(mutation_families) if mutation_families else 0
                    )
            candidates.append(
                {
                    "request_file": str(path),
                    "endpoint": urlsplit(parsed["url"])._replace(query="").geturl(),
                    "parameter": parameter,
                    "families": (["sqli"] if "sqli" in families else [])
                    + mutation_families,
                    "estimated_requests": estimated,
                }
            )
            if len(candidates) >= MAX_PARAMETERS:
                break
        if len(candidates) >= MAX_PARAMETERS:
            break
    return {
        "success": True,
        "candidate_count": len(candidates),
        "estimated_requests": sum(item["estimated_requests"] for item in candidates),
        "candidates": candidates,
        "diagnostics": errors,
    }


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    ranks = {"observation": 0, "needs_manual_verification": 1, "verified": 2}
    for finding in findings:
        key = (
            str(finding.get("family") or finding.get("category")),
            str(finding.get("endpoint") or finding.get("target")),
            str(finding.get("parameter")),
        )
        current = unique.get(key)
        if current is None or ranks.get(finding.get("status"), 0) > ranks.get(
            current.get("status"), 0
        ):
            unique[key] = finding
    return list(unique.values())


def run_campaign(
    manifest: dict[str, Any], *, authorization_confirmed: bool = False
) -> dict[str, Any]:
    if not authorization_confirmed:
        return {
            "success": False,
            "error": "Explicit campaign authorization confirmation is required.",
        }
    plan = build_campaign_plan(manifest)
    if not plan.get("success"):
        return plan
    return {
        "success": False,
        "status": "plan_only",
        "error": (
            "Capture campaign active network execution is disabled for Phase 2; "
            "the command is plan/offline-only."
        ),
        "plan": plan,
        "request_budget": int(manifest.get("request_budget", DEFAULT_REQUEST_BUDGET)),
        "requests_used": 0,
        "executed_candidate_count": 0,
        "findings": [],
        "results": [],
    }


def write_campaign_report(
    result: dict[str, Any], output_directory: str
) -> dict[str, str]:
    result = public_result(result)
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "campaign-results.json"
    markdown_path = directory / "campaign-report.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    findings = result.get("findings", [])
    lines = [
        "# CyberCortex Bug Bounty Verification Report",
        "",
        f"- Requests used: {result.get('requests_used', 0)} / {result.get('request_budget', 0)}",
        f"- Deduplicated findings: {len(findings)}",
        "",
    ]
    for index, finding in enumerate(findings, 1):
        lines.extend(
            [
                f"## {index}. {finding.get('title') or finding.get('family', 'Finding')}",
                "",
                f"- Status: {finding.get('status', 'unknown')}",
                f"- Confidence: {finding.get('confidence', 'unknown')}",
                f"- Endpoint: {finding.get('endpoint', 'unknown')}",
                f"- Parameter: {finding.get('parameter', 'unknown')}",
                "",
            ]
        )
    markdown_path.write_text(sanitize_document_text("\n".join(lines)), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(markdown_path)}
