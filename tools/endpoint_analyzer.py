"""Conservative, offline analysis of discovered application routes."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qs, urlparse

AREA_WORDS = {
    "user",
    "users",
    "account",
    "accounts",
    "admin",
    "profile",
    "profiles",
    "order",
    "orders",
    "project",
    "projects",
    "file",
    "files",
    "api",
    "login",
    "logout",
    "register",
    "signup",
    "reset",
    "password",
    "upload",
    "download",
    "oauth",
    "token",
    "search",
}
USER_RELATED_WORDS = {
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
}
SENSITIVE_AREA_WORDS = {"admin", "login", "password", "oauth", "token"}
RESOURCE_PARENTS = {
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "order",
    "orders",
    "project",
    "projects",
    "file",
    "files",
}
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-" r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
ID_FIELD = re.compile(r"(?:^|[_-])(?:id|uuid|guid|key)$|(?:id|uuid|guid)$", re.I)
OPAQUE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{5,}$")
HYPHENATED_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$", re.I)
STATIC_EXTENSIONS = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp)$", re.I
)


def classify_resource_kind(url: str) -> str:
    """Classify a URL without treating asset filenames as application routes."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    lowered = path.lower()
    if STATIC_EXTENSIONS.search(lowered) or (
        lowered.endswith(".json")
        and (
            "/assets/" in lowered
            or "/static/" in lowered
            or lowered.endswith(("manifest.json", "asset-manifest.json"))
        )
    ):
        return "static_asset"
    words = {word for word in re.split(r"[^a-z0-9]+", lowered) if word}
    if words & {"api", "graphql", "rest"}:
        return "api_related_route"
    if lowered in {"/", "/index", "/index.html"} or lowered.endswith((".html", ".htm")):
        return "document_route"
    if path.startswith("/") and words:
        return "application_route"
    return "unknown"


def _observed_identifiers(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    found: list[dict[str, str]] = []
    segments = [part for part in parsed.path.split("/") if part]
    for index, value in enumerate(segments):
        parent = segments[index - 1].lower() if index else ""
        mixed = bool(re.search(r"[A-Za-z]", value) and re.search(r"\d", value))
        readable_slug = bool(
            HYPHENATED_SLUG.fullmatch(value)
            and len([part for part in value.split("-") if re.search(r"[A-Za-z]", part)])
            >= 2
        )
        high_confidence_opaque = (
            parent in RESOURCE_PARENTS
            and mixed
            and not readable_slug
            and bool(OPAQUE_ID.fullmatch(value))
        )
        if UUID.fullmatch(value):
            kind = "uuid_identifier"
        elif value.isdigit():
            kind = "numeric_identifier"
        elif high_confidence_opaque:
            kind = "opaque_identifier"
        else:
            continue
        found.append(
            {
                "source": "path",
                "field": segments[index - 1] if index else "object",
                "value": value,
                "identifier_kind": kind,
            }
        )
    for field, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if ID_FIELD.search(field):
            found.extend(
                {
                    "source": "query",
                    "field": field,
                    "value": value,
                    "identifier_kind": "id_named_parameter",
                }
                for value in values
                if value
            )
    return found


def endpoint_analyzer(
    urls: Iterable[Any] | None, allowed_domain: str
) -> dict[str, Any]:
    """Classify routes without presenting route names as vulnerabilities."""
    normalized_routes = getattr(urls, "normalized_routes", [])
    route_evidence_by_url = {
        str(item.get("url")): item
        for item in normalized_routes
        if isinstance(item, dict) and item.get("url")
    }
    try:
        urls = list(urls or [])
    except TypeError:
        urls = []

    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    static_assets: list[dict[str, str]] = []
    seen: set[str] = set()
    normalized_domain = str(allowed_domain or "").strip().lower().rstrip(".")

    for index, raw_url in enumerate(urls):
        if not isinstance(raw_url, str) or not raw_url.strip():
            skipped.append(
                {"index": index, "reason": "URL must be a non-empty string."}
            )
            continue
        url = raw_url.strip()
        if url in seen:
            skipped.append({"url": url, "reason": "Duplicate URL."})
            continue
        seen.add(url)
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme not in {"http", "https"} or not hostname:
                skipped.append({"url": url, "reason": "Malformed HTTP(S) URL."})
                continue
            if normalized_domain and not (
                hostname == normalized_domain
                or hostname.endswith(f".{normalized_domain}")
            ):
                skipped.append(
                    {"url": url, "reason": "URL is outside the allowed domain."}
                )
                continue

            resource_kind = classify_resource_kind(url)
            if resource_kind == "static_asset":
                static_assets.append({"url": url, "resource_kind": resource_kind})
                continue

            words = {
                word for word in re.split(r"[^a-z0-9]+", parsed.path.lower()) if word
            }
            matched = words & AREA_WORDS
            query = parse_qs(parsed.query, keep_blank_values=True)
            identifiers = _observed_identifiers(url)
            route_evidence = route_evidence_by_url.get(url)
            documented_route = bool(
                route_evidence and route_evidence.get("source") == "openapi"
            )
            if not matched and not query and not identifiers and not documented_route:
                continue

            categories: set[str] = set()
            reasons: list[str] = []
            checks: list[str] = []
            if "api" in matched:
                categories.add("API-related route observed")
                reasons.append("API-related route observed.")
            if matched & USER_RELATED_WORDS:
                categories.add("User-related route observed")
                reasons.append(
                    "User-related route observed; the route name alone is not evidence of a vulnerability."
                )
            if query:
                categories.add("Parameterized route observed")
                reasons.append("Parameterized route observed.")
                checks.append(
                    "Review parameter handling and input validation manually."
                )
            if matched & SENSITIVE_AREA_WORDS:
                categories.add("Potentially sensitive application area")
                reasons.append("Potentially sensitive application area observed.")
            if identifiers:
                reasons.append(
                    "An object reference was observed; manual authorization review may be useful."
                )
                checks.append(
                    "If authorized test accounts are available, perform a manual object-level authorization comparison across controlled accounts."
                )
            elif matched & (
                USER_RELATED_WORDS
                | {"order", "orders", "project", "projects", "file", "files", "admin"}
            ):
                checks.append(
                    "Review the route manually; no object reference was observed."
                )
            if not categories:
                categories.add("Application route observed")
            if route_evidence and route_evidence.get("source") == "openapi":
                categories.add("OpenAPI-documented route observed")
                reasons.append(
                    "A structurally validated OpenAPI document described this operation; runtime behavior was not inferred."
                )

            findings.append(
                {
                    "url": url,
                    "path": parsed.path or "/",
                    "resource_kind": resource_kind,
                    "parameters": sorted(set(query)),
                    "methods": (
                        [str(route_evidence.get("method"))]
                        if route_evidence and route_evidence.get("method")
                        else []
                    ),
                    "source": (
                        route_evidence.get("source") if route_evidence else "crawler"
                    ),
                    "route_category": sorted(categories),
                    "observed_identifiers": identifiers,
                    "review_reasons": reasons,
                    "vulnerability_status": "observation",
                    "suggested_manual_checks": checks,
                }
            )
        except (TypeError, ValueError, UnicodeError) as exc:
            errors.append(
                {"url": url, "error": f"URL analysis failed: {type(exc).__name__}"}
            )

    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "total_urls_checked": len(urls),
        "interesting_count": len(findings),
        "interesting_endpoints": findings,
        "static_assets": static_assets,
        "skipped_urls": skipped,
        "errors": errors,
    }
