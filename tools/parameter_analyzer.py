from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

PARAMETER_PATTERNS = {
    "id": "Object-reference handling review",
    "user": "User-scoped input review",
    "userid": "User-scoped input review",
    "account": "Account-scoped input review",
    "profile": "Profile-scoped input review",
    "email": "Identity-input handling review",
    "token": "Token-input handling review",
    "redirect": "Redirect-target handling review",
    "url": "URL-input handling review",
    "next": "Redirect-target handling review",
    "return": "Redirect-target handling review",
    "file": "File-input handling review",
    "path": "Path-input handling review",
    "download": "Download-input handling review",
    "search": "Input-validation review",
    "query": "Input-validation review",
}


def _review_reason(name: str) -> str | None:
    key = name.lower()
    return next(
        (reason for pattern, reason in PARAMETER_PATTERNS.items() if pattern in key),
        None,
    )


def parameter_analyzer(urls: Any) -> dict[str, Any]:
    """Normalize parameter observations from URLs and richer surface evidence."""
    normalized = getattr(urls, "normalized_parameters", [])
    try:
        url_values = list(urls or [])
    except TypeError:
        url_values = []
    parameters: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    findings: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def add(item: dict[str, Any], *, direct_url: str | None = None) -> None:
        name = str(item.get("name") or item.get("parameter") or "").strip()
        if not name:
            return
        path = str(item.get("path") or urlparse(direct_url or "").path or "/")
        method = str(item.get("method") or "GET").upper()
        location = str(item.get("in") or "query")
        key = (path, method, location, str(item.get("field_path") or name))
        observation = {
            "url": direct_url or item.get("url"),
            "path": path,
            "method": method,
            "parameter": name,
            "field_path": item.get("field_path") or name,
            "location": location,
            "required": bool(item.get("required")),
            "schema_type": item.get("schema_type") or "unknown",
            "source": item.get("source") or "url_query",
            "evidence_quality": int(item.get("evidence_quality") or 2),
            "vulnerability_status": "observation",
        }
        existing = parameters.get(key)
        if (
            existing is None
            or observation["evidence_quality"] > existing["evidence_quality"]
        ):
            parameters[key] = observation
        reason = _review_reason(name)
        from_normalized_surface = item in normalized
        if reason or from_normalized_surface:
            findings[key] = {
                **observation,
                "reason": reason
                or "Documented input field observed; no vulnerability was inferred.",
                "classification": "attack_surface_observation",
            }

    for raw_url in url_values:
        if not isinstance(raw_url, str):
            continue
        parsed = urlparse(raw_url)
        for name in sorted(parse_qs(parsed.query, keep_blank_values=True)):
            add(
                {
                    "name": name,
                    "path": parsed.path or "/",
                    "in": "query",
                    "source": "url_query",
                    "evidence_quality": 2,
                },
                direct_url=raw_url,
            )
    for item in normalized if isinstance(normalized, list) else []:
        if isinstance(item, dict):
            add(item)

    ordered_parameters = [parameters[key] for key in sorted(parameters)]
    ordered_findings = [findings[key] for key in sorted(findings)]
    return {
        "success": True,
        "parameter_count": len(ordered_parameters),
        "parameters": ordered_parameters,
        "findings_count": len(ordered_findings),
        "findings": ordered_findings,
        "vulnerability_status": "not_assessed",
    }
