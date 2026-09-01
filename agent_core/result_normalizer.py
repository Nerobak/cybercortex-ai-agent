"""Deterministic normalization and bounded evidence packaging."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import (
    parse_qs,
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
    urlunsplit,
)

from agent_core.auth_semantics import safe_auth_semantic_summary
from agent_core.route_identity import normalize_route_path, route_identity
from tools.scope_guard import enforce_scope
from agent_core.version import __version__

MAX_EVIDENCE_BYTES = 200_000
MAX_ITEMS = 100
MAX_TEXT = 1500
SURFACE_COLLECTION_LIMITS = {
    "routes": 5000,
    "parameters": 10000,
    "objects": 5000,
    "authentication_boundaries": 5000,
    "schemas": 5000,
}
SAFE_METADATA_KEYS = {
    "authorization_scheme",
    "tokens_observed",
    "token_source",
    "token_type",
    "token_type_indicators",
}
SAFE_NUMERIC_TELEMETRY_KEYS = {
    "controlled_token_count",
    "credential_attempt_count",
    "invalid_password_auth_requests",
    "password_field_count",
    "token_count",
    "token_length",
    "token_request_count",
}
NON_SECRET_BOOLEAN_KEYS = {
    "authorization_confirmed",
    "requires_explicit_authorization",
    "same_session_replayed",
    "sets_cookie",
}
SAFE_BOOLEAN_SUFFIXES = (
    "_bound",
    "_confirmed",
    "_present",
    "_required",
)
PRIVATE_PUBLIC_KEYS = {
    "preserved_challenge",
    "private_recovery_state",
    "private_state",
    "_private_recovery_state",
    "_private_state",
}
JWT_SAFE_FIELDS = {
    "algorithm",
    "algorithms",
    "audience",
    "audience_present",
    "claim_names",
    "comparison_count",
    "confidence",
    "expiration_observations",
    "expires_at",
    "expiry_class",
    "expiry_present",
    "header_or_cookie_name",
    "header_algorithm",
    "issuer",
    "issuer_present",
    "manual_plans",
    "network_testing_occurred",
    "redacted_fingerprint",
    "signature_present",
    "signature_verification_status",
    "scope_claim_names",
    "role_claim_names",
    "segment_count",
    "source",
    "sources",
    "token_count",
    "token_length",
    "token_present",
    "token_source",
    "token_type",
    "token_type_indicators",
    "tokens_observed",
    "type",
    "subject_present",
    "vulnerability_status",
    "replay_status",
}
COOKIE_SAFE_FIELDS = {
    "cookie_count",
    "cookie_name",
    "cookie_names",
    "cookie_present",
    "expires_at",
    "expiry_class",
    "httponly",
    "http_only",
    "max_age_class",
    "same_site",
    "samesite",
    "session_cookie_name",
    "secure",
}
_SECRET_QUERY_KEY = re.compile(
    r"^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|jwt|api[_-]?key|"
    r"session(?:[_-]?token)?|auth(?:orization)?|recovery[_-]?code|code|cookie|secret|"
    r"password|csrf(?:[_-]?token)?)$",
    re.I,
)
_AUTH_HEADER_TEXT = re.compile(
    r"(?i)(\b(?:proxy[-_ ]?authorization|authorization)\s*:\s*)"
    r"(?:[A-Za-z][A-Za-z0-9+._-]{0,31}\s+)?[^\s,;]{1,1024}"
)
_AUTH_SCHEME_TEXT = re.compile(r"(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9+/=_~.-]{1,1024}")
_COOKIE_HEADER_TEXT = re.compile(
    r"(?i)(\b(?:set[-_ ]?cookie|cookie)\s*:\s*)[^\r\n]{1,2048}"
)
_ASSIGNED_SECRET_TEXT = re.compile(
    r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|session(?:[_-]?token)?|"
    r"api[_-]?key|recovery[_-]?code|csrf(?:[_-]?token)?|password|client[_-]?secret|"
    r"secret|authorization|auth|code|cookie|jwt)\b\s*[:=]\s*)"
    r"(?:[\"']?)[^\s,;&\"']{1,1024}(?:[\"']?)"
)
_DOUBLE_QUOTED_PAIR_TEXT = re.compile(
    r'(?P<prefix>"(?P<key>[A-Za-z][A-Za-z0-9_. -]{0,127})"\s*:\s*")'
    r'(?P<value>(?:\\.|[^"\\\r\n]){0,1024})(?P<suffix>")'
)
_SINGLE_QUOTED_PAIR_TEXT = re.compile(
    r"(?P<prefix>'(?P<key>[A-Za-z][A-Za-z0-9_. -]{0,127})'\s*:\s*')"
    r"(?P<value>(?:\\.|[^'\\\r\n]){0,1024})(?P<suffix>')"
)
_ESCAPED_DOUBLE_QUOTED_PAIR_TEXT = re.compile(
    r'(?P<prefix>\\"(?P<key>[A-Za-z][A-Za-z0-9_. -]{0,127})\\"\s*:\s*\\")'
    r'(?P<value>[^\r\n]{0,1024}?)(?P<suffix>\\")'
)
_QUOTED_PAIR_PATTERNS = (
    _ESCAPED_DOUBLE_QUOTED_PAIR_TEXT,
    _DOUBLE_QUOTED_PAIR_TEXT,
    _SINGLE_QUOTED_PAIR_TEXT,
)
_EMBEDDED_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']{1,2048}")
_EMBEDDED_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{2,1024}\.[A-Za-z0-9_-]{2,4096}\."
    r"[A-Za-z0-9_-]{0,4096}(?![A-Za-z0-9_-])"
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
OPENAPI_IDENTIFIER_MAPS = {
    "$defs",
    "callbacks",
    "content",
    "definitions",
    "examples",
    "headers",
    "links",
    "parameters",
    "paths",
    "properties",
    "requestBodies",
    "responses",
    "schemas",
    "securitySchemes",
}
OPENAPI_OMITTED_VALUE_KEYS = {
    "authorizationurl",
    "const",
    "contact",
    "default",
    "description",
    "enum",
    "example",
    "examples",
    "externaldocs",
    "externalvalue",
    "license",
    "openidconnecturl",
    "servers",
    "tokenurl",
    "value",
}


class SurfaceURLList(list[str]):
    """List-compatible analyzer input carrying normalized non-URL evidence."""

    def __init__(
        self,
        values: list[str],
        *,
        routes: list[dict[str, Any]],
        parameters: list[dict[str, Any]],
        objects: list[dict[str, Any]],
    ) -> None:
        super().__init__(values)
        self.normalized_routes = routes
        self.normalized_parameters = parameters
        self.normalized_objects = objects


def _decode_base64url_json_object(segment: str) -> dict[str, Any] | None:
    """Decode one JWT segment only when it is Base64URL JSON object data."""
    if not segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        return None
    try:
        padding = "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding)
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _is_credible_jwt(value: str) -> bool:
    """Require JWT structure and plausible decoded metadata before redaction."""
    segments = value.strip().split(".")
    if len(segments) != 3:
        return False
    header_segment, payload_segment, signature_segment = segments
    if signature_segment and not re.fullmatch(r"[A-Za-z0-9_-]+", signature_segment):
        return False
    header = _decode_base64url_json_object(header_segment)
    payload = _decode_base64url_json_object(payload_segment)
    if header is None or payload is None:
        return False
    alg = header.get("alg")
    typ = header.get("typ")
    return bool(
        (isinstance(alg, str) and alg.strip())
        or (isinstance(typ, str) and typ.strip().lower() in {"jwt", "at+jwt"})
    )


def _is_safe_metadata_value(key: str, value: Any) -> bool:
    normalized = key.lower()
    numeric_telemetry = bool(
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and (
            normalized in SAFE_NUMERIC_TELEMETRY_KEYS
            or normalized.endswith(
                ("_count", "_requests", "_attempts", "_fields", "_length")
            )
        )
    )
    boolean_telemetry = isinstance(value, bool)
    return normalized in SAFE_METADATA_KEYS or numeric_telemetry or boolean_telemetry


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def _secret_key(key: str, value: Any, path: tuple[str, ...]) -> bool:
    """Classify semantic secret fields without substring-redacting telemetry."""

    normalized = _normalized_key(key)
    if (
        path
        and _normalized_key(path[-1]) == "request_delta"
        and normalized
        in {"discovery", "auth", "verification", "cleanup", "attempted", "total"}
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return False
    if (
        path
        and _normalized_key(path[-1]) in {"results", "tool_results"}
        and isinstance(value, Mapping)
    ):
        return False
    if _is_safe_metadata_value(normalized, value):
        return False
    if normalized in JWT_SAFE_FIELDS or normalized in COOKIE_SAFE_FIELDS:
        return False
    if (
        normalized in SAFE_NUMERIC_TELEMETRY_KEYS
        or normalized in NON_SECRET_BOOLEAN_KEYS
    ):
        return True
    if normalized in {
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "password",
        "new_password",
        "temporary_password",
        "comparison_password",
        "invalid_password",
        "recovery_code",
        "verification_code",
        "access_token",
        "refresh_token",
        "id_token",
        "session_token",
        "csrf_token",
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "signature",
        "raw_jwt",
        "jwt_token",
        "token",
        "session",
        "session_id",
        "csrf",
        "auth",
        "credential",
        "credentials",
        "cookies",
        "credential_references",
        "vault_reference",
        "email",
        "username",
    }:
        return True
    if normalized == "code":
        return not isinstance(value, (int, float, bool)) or any(
            marker in _normalized_key(segment)
            for segment in path
            for marker in ("auth", "recovery", "challenge", "verification")
        )
    if "cookie" in normalized:
        return True
    if normalized.endswith(("_api_key", "_token")):
        return True
    if any(marker in normalized for marker in ("password", "credential", "secret")):
        return True
    if any("cookie" in _normalized_key(segment) for segment in path):
        return normalized not in COOKIE_SAFE_FIELDS
    if "authorization" in normalized and normalized != "authorization_scheme":
        return True
    if any(
        marker in normalized for marker in ("password", "token", "credential")
    ) and normalized.endswith(
        ("_count", "_requests", "_attempts", "_fields", "_length")
    ):
        return True
    if normalized.endswith("_reference") and any(
        marker in normalized
        for marker in (
            "credential",
            "password",
            "token",
            "session",
            "code",
            "secret",
            "vault",
        )
    ):
        return True
    if normalized.startswith("raw_") and any(
        marker in normalized
        for marker in (
            "auth",
            "cookie",
            "credential",
            "jwt",
            "password",
            "secret",
            "session",
            "token",
        )
    ):
        return True
    return False


def _sanitize_quoted_pair(match: re.Match[str]) -> str:
    """Redact one bounded quoted string pair using canonical key semantics."""

    key = match.group("key")
    value = match.group("value")
    normalized = _normalized_key(key)
    private = normalized in PRIVATE_PUBLIC_KEYS or normalized in {
        "jwt",
        "jwt_metadata",
    }
    if not private:
        private = _secret_key(key, value, ())
    if not private:
        return match.group(0)
    return f'{match.group("prefix")}[REDACTED]{match.group("suffix")}'


def sanitize_url(url: str) -> str:
    """Preserve route utility while removing user-info and secret query values."""

    try:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return url
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host if port is None else f"{host}:{port}"
        query = urlencode(
            [
                (name, "[REDACTED]" if _SECRET_QUERY_KEY.fullmatch(name) else item)
                for name, item in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            doseq=True,
        )
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
    except (TypeError, ValueError):
        return "[REDACTED URL]"


def sanitize_text(value: str) -> str:
    """Bound and scrub credentials embedded in arbitrary diagnostic text."""

    text = value[:MAX_TEXT]
    truncated = len(value) > MAX_TEXT
    for pattern in _QUOTED_PAIR_PATTERNS:
        text = pattern.sub(_sanitize_quoted_pair, text)
    text = _EMBEDDED_URL.sub(lambda match: sanitize_url(match.group(0)), text)
    text = _AUTH_HEADER_TEXT.sub(r"\1[REDACTED]", text)
    text = _COOKIE_HEADER_TEXT.sub(r"\1[REDACTED]", text)
    text = _AUTH_SCHEME_TEXT.sub(r"\1[REDACTED]", text)
    text = _ASSIGNED_SECRET_TEXT.sub(r"\1[REDACTED]", text)
    text = _EMBEDDED_JWT.sub(
        lambda match: (
            "[REDACTED JWT]" if _is_credible_jwt(match.group(0)) else match.group(0)
        ),
        text,
    )
    return text + ("... [truncated]" if truncated else "")


def sanitize_document_text(value: str) -> str:
    """Sanitize a rendered document without applying one global truncation."""

    return "\n".join(sanitize_text(line) for line in str(value).splitlines())


def _sanitize_jwt_metadata(
    value: Any,
    *,
    path: tuple[str, ...],
    openapi_document: bool,
) -> Any:
    if not isinstance(value, Mapping):
        return "[REDACTED]"
    safe: dict[str, Any] = {}
    for raw_key, item in value.items():
        item_key = str(raw_key)
        normalized = _normalized_key(item_key)
        if normalized not in JWT_SAFE_FIELDS:
            continue
        if normalized == "tokens_observed" and isinstance(item, list):
            safe[item_key] = [
                _sanitize_jwt_metadata(
                    candidate,
                    path=(*path, item_key),
                    openapi_document=openapi_document,
                )
                for candidate in item[:MAX_ITEMS]
                if isinstance(candidate, Mapping)
            ]
            continue
        safe[item_key] = public_result(
            item,
            key=item_key,
            _path=path,
            _openapi_document=openapi_document,
        )
    return safe


def _sanitize_cookie_metadata(
    value: Any,
    *,
    path: tuple[str, ...],
    openapi_document: bool,
) -> Any:
    if isinstance(value, (list, tuple)):
        return [
            _sanitize_cookie_metadata(
                item,
                path=path,
                openapi_document=openapi_document,
            )
            for item in value[:MAX_ITEMS]
            if isinstance(item, Mapping)
        ]
    if not isinstance(value, Mapping):
        return "[REDACTED]"
    safe: dict[str, Any] = {}
    for raw_key, item in value.items():
        item_key = str(raw_key)
        if _normalized_key(item_key) not in COOKIE_SAFE_FIELDS:
            continue
        safe[item_key] = public_result(
            item,
            key=item_key,
            _path=path,
            _openapi_document=openapi_document,
        )
    return safe


def _redacted_list_limit(path: tuple[str, ...]) -> int:
    """Preserve bounded normalized surface collections through redaction."""
    if len(path) >= 3 and path[-3:-1] == ("observed_surface", "attack_surface"):
        return SURFACE_COLLECTION_LIMITS.get(path[-1], MAX_ITEMS)
    return MAX_ITEMS


def public_result(
    value: Any,
    key: str = "",
    *,
    _path: tuple[str, ...] = (),
    _openapi_document: bool = False,
) -> Any:
    """Canonical recursive serializer for every public and persistence edge."""

    path = (*_path, key) if key else _path
    if hasattr(value, "model_dump") and callable(value.model_dump):
        value = value.model_dump(mode="python")
    is_openapi_document = _openapi_document or bool(
        isinstance(value, Mapping)
        and isinstance(value.get("paths"), dict)
        and (
            isinstance(value.get("openapi"), str)
            or isinstance(value.get("swagger"), str)
        )
    )
    structural_identifier = bool(
        is_openapi_document and _path and _path[-1] in OPENAPI_IDENTIFIER_MAPS
    )
    normalized_key = _normalized_key(key)
    if normalized_key in PRIVATE_PUBLIC_KEYS:
        return None
    if normalized_key in {"jwt", "jwt_metadata"} and not structural_identifier:
        return _sanitize_jwt_metadata(
            value,
            path=path,
            openapi_document=is_openapi_document,
        )
    if normalized_key in {
        "cookie",
        "set_cookie",
        "cookie_metadata",
        "cookie_security_attributes",
        "set_cookie_metadata",
    } and isinstance(value, (Mapping, list, tuple)):
        return _sanitize_cookie_metadata(
            value,
            path=path,
            openapi_document=is_openapi_document,
        )
    if key and not structural_identifier and _secret_key(key, value, _path):
        if isinstance(value, list):
            return []
        if isinstance(value, Mapping):
            return {"redacted": True, "count": len(value)}
        return "[REDACTED]"
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for raw_key, item in value.items():
            item_key = str(raw_key)
            normalized_item_key = _normalized_key(item_key)
            if normalized_item_key in PRIVATE_PUBLIC_KEYS:
                continue
            structural_parent = bool(
                is_openapi_document and path and path[-1] in OPENAPI_IDENTIFIER_MAPS
            )
            if item_key.lower() in EXCLUDED_KEYS:
                continue
            if is_openapi_document and not structural_parent:
                if item_key.lower().startswith("x-"):
                    continue
                if item_key.lower() in OPENAPI_OMITTED_VALUE_KEYS:
                    continue
                if item_key.lower() == "summary":
                    cleaned[item_key] = safe_auth_semantic_summary(item)
                    continue
            if normalized_item_key in {"jwt", "jwt_metadata"} and not structural_parent:
                cleaned[item_key] = _sanitize_jwt_metadata(
                    item,
                    path=(*path, item_key),
                    openapi_document=is_openapi_document,
                )
            elif normalized_item_key in {
                "cookie",
                "set_cookie",
                "cookie_metadata",
                "cookie_security_attributes",
                "set_cookie_metadata",
            } and isinstance(item, (Mapping, list, tuple)):
                cleaned[item_key] = _sanitize_cookie_metadata(
                    item,
                    path=(*path, item_key),
                    openapi_document=is_openapi_document,
                )
            elif (
                not structural_parent
                and _secret_key(item_key, item, path)
                and isinstance(item, list)
            ):
                cleaned[item_key] = []
                cleaned[f"{item_key.rstrip('s')}_count"] = len(item)
            else:
                cleaned[item_key] = public_result(
                    item,
                    item_key,
                    _path=path,
                    _openapi_document=is_openapi_document,
                )
        return cleaned
    if isinstance(value, (list, tuple, set, frozenset)):
        members = list(value)
        if isinstance(value, (set, frozenset)):
            members.sort(key=lambda item: repr(item))
        limit = _redacted_list_limit(path)
        return [
            public_result(item, _path=path, _openapi_document=is_openapi_document)
            for item in members[:limit]
        ]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def redact(
    value: Any,
    key: str = "",
    *,
    _path: tuple[str, ...] = (),
    _openapi_document: bool = False,
) -> Any:
    """Backward-compatible name for the canonical public serializer."""

    return public_result(
        value,
        key,
        _path=_path,
        _openapi_document=_openapi_document,
    )


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
    openapi_envelope = results.get("openapi_surface_analyzer", {})
    openapi = (
        openapi_envelope.get("output", openapi_envelope)
        if isinstance(openapi_envelope, dict)
        else {}
    ) or {}
    if not isinstance(openapi, dict):
        openapi = {}
    raw_routes = openapi.get("routes")
    openapi_routes = raw_routes if isinstance(raw_routes, list) else []
    raw_requests = crawl.get("requests")
    captured_requests = raw_requests if isinstance(raw_requests, list) else []
    raw_fetch_urls = crawl.get("fetch_urls")
    fetch_urls = raw_fetch_urls if isinstance(raw_fetch_urls, list) else []
    effective_target = http.get("effective_url") or target
    parsed_effective = urlparse(effective_target)
    origin_url = urlunparse(
        parsed_effective._replace(path="/", params="", query="", fragment="")
    )

    openapi_urls: list[str] = []
    for route in openapi_routes:
        path = route.get("path") if isinstance(route, dict) else None
        if isinstance(path, str) and path.startswith("/"):
            openapi_urls.append(urljoin(origin_url, path.lstrip("/")))
    request_urls: list[str] = []
    for request in captured_requests:
        if not isinstance(request, dict):
            continue
        request_url = request.get("url") or request.get("endpoint")
        if isinstance(request_url, str):
            request_urls.append(urljoin(origin_url, request_url))
    candidates = [
        target,
        http.get("effective_url"),
        *crawl_urls,
        *fetch_urls,
        *request_urls,
        *openapi_urls,
    ]
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
    route_map: dict[tuple[str, str], dict[str, Any]] = {}

    def add_route(item: dict[str, Any]) -> None:
        normalized = {
            **item,
            "path": normalize_route_path(item.get("path") or item.get("url") or "/"),
            "method": str(item.get("method") or "GET").upper(),
        }
        key = route_identity(normalized)
        existing = route_map.get(key)
        quality = int(normalized.get("evidence_quality") or 0)
        existing_quality = (
            int(existing.get("evidence_quality") or 0) if existing else -1
        )
        if existing is None or quality > existing_quality:
            route_map[key] = normalized

    if http.get("reachable") or isinstance(http.get("status_code"), int):
        parsed = urlparse(effective_target)
        add_route(
            {
                "url": effective_target,
                "path": parsed.path or "/",
                "method": "GET",
                "source": "captured_response",
                "evidence_quality": 4,
                "status_code": http.get("root_status", http.get("status_code")),
            }
        )
    for url in crawl_urls:
        if isinstance(url, str):
            parsed = urlparse(url)
            add_route(
                {
                    "url": url,
                    "path": parsed.path or "/",
                    "method": "GET",
                    "source": "crawler",
                    "evidence_quality": 2,
                }
            )
    for url in fetch_urls:
        if isinstance(url, str):
            full_url = urljoin(origin_url, url)
            parsed = urlparse(full_url)
            add_route(
                {
                    "url": full_url,
                    "path": parsed.path or "/",
                    "method": "GET",
                    "source": "javascript",
                    "evidence_quality": 2,
                }
            )
    for request in captured_requests:
        if not isinstance(request, dict):
            continue
        request_url = request.get("url") or request.get("endpoint")
        if not isinstance(request_url, str):
            continue
        full_url = urljoin(origin_url, request_url)
        parsed = urlparse(full_url)
        add_route(
            {
                "url": full_url,
                "path": parsed.path or "/",
                "method": str(request.get("method") or "GET").upper(),
                "source": "captured_request",
                "evidence_quality": 4,
            }
        )
    for route in openapi_routes:
        if not isinstance(route, dict) or not isinstance(route.get("path"), str):
            continue
        add_route(
            {
                **route,
                "url": urljoin(origin_url, route["path"].lstrip("/")),
                "source": "openapi",
                "evidence_quality": 3,
            }
        )
    routes = [route_map[key] for key in sorted(route_map)]

    parameter_map: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    def add_parameter(item: dict[str, Any]) -> None:
        name = str(item.get("name") or item.get("parameter") or "").strip()
        if not name:
            return
        key = (
            str(item.get("path") or "/"),
            str(item.get("method") or "GET").upper(),
            str(item.get("in") or "unknown"),
            str(item.get("field_path") or name),
        )
        existing = parameter_map.get(key)
        quality = int(item.get("evidence_quality") or 0)
        existing_quality = (
            int(existing.get("evidence_quality") or 0) if existing else -1
        )
        if existing is None or quality > existing_quality:
            parameter_map[key] = {**item, "name": name}

    route_quality = {
        str(route.get("url")): int(route.get("evidence_quality") or 0)
        for route in routes
    }
    for url in all_urls:
        parsed = urlparse(url)
        for name in sorted(parse_qs(parsed.query, keep_blank_values=True)):
            quality = route_quality.get(url, 2)
            add_parameter(
                {
                    "name": name,
                    "in": "query",
                    "path": parsed.path or "/",
                    "method": "GET",
                    "source": "captured_request" if quality == 4 else "url_query",
                    "evidence_quality": quality,
                }
            )
    captured_parameter_keys = {
        "parameters": "captured_parameter",
        "query_parameters": "query",
        "path_parameters": "path",
        "request_fields": "request_body",
        "body_fields": "request_body",
    }
    for request in captured_requests:
        if not isinstance(request, dict):
            continue
        request_url = request.get("url") or request.get("endpoint") or "/"
        parsed_request_url = urlparse(urljoin(origin_url, str(request_url)))
        method = str(request.get("method") or "GET").upper()
        for collection_key, default_location in captured_parameter_keys.items():
            collection = request.get(collection_key)
            members: list[Any]
            if isinstance(collection, dict):
                members = [{"name": name} for name in collection]
            elif isinstance(collection, list):
                members = collection
            else:
                members = []
            for member in members:
                item = member if isinstance(member, dict) else {"name": member}
                add_parameter(
                    {
                        "name": item.get("name") or item.get("parameter"),
                        "field_path": item.get("field_path"),
                        "in": item.get("in") or default_location,
                        "path": parsed_request_url.path or "/",
                        "method": method,
                        "required": bool(item.get("required")),
                        "schema_type": item.get("schema_type") or "unknown",
                        "source": "captured_request",
                        "evidence_quality": 4,
                    }
                )
    for item in openapi.get("parameters", []):
        if isinstance(item, dict):
            add_parameter(
                {
                    **item,
                    "source": item.get("source") or "openapi",
                    "evidence_quality": 3,
                }
            )
    forms = crawl.get("forms") if isinstance(crawl.get("forms"), list) else []
    for form in forms:
        if not isinstance(form, dict):
            continue
        action = str(form.get("action") or "/")
        fields = form.get("fields") or form.get("parameters") or []
        for field in fields if isinstance(fields, list) else []:
            name = field.get("name") if isinstance(field, dict) else field
            if isinstance(name, str):
                add_parameter(
                    {
                        "name": name,
                        "in": "form",
                        "path": urlparse(urljoin(origin_url, action)).path or "/",
                        "method": str(form.get("method") or "POST").upper(),
                        "source": "form",
                        "evidence_quality": 2,
                    }
                )
    graphql_arguments = crawl.get("graphql_arguments")
    if isinstance(graphql_arguments, list):
        for argument in graphql_arguments:
            if isinstance(argument, str):
                add_parameter(
                    {
                        "name": argument,
                        "in": "graphql_argument",
                        "path": "/graphql",
                        "method": "POST",
                        "source": "graphql",
                        "evidence_quality": 2,
                    }
                )
            elif isinstance(argument, dict):
                add_parameter(
                    {
                        **argument,
                        "in": argument.get("in") or "graphql_argument",
                        "source": "graphql",
                        "evidence_quality": int(argument.get("evidence_quality") or 2),
                    }
                )
    parameters = [parameter_map[key] for key in sorted(parameter_map)]
    objects = [item for item in openapi.get("objects", []) if isinstance(item, dict)]
    authentication_boundaries = [
        item
        for item in openapi.get("authentication_boundaries", [])
        if isinstance(item, dict)
    ]
    schemas = [item for item in openapi.get("schemas", []) if isinstance(item, dict)]
    api_target = _tool_output(results, "api_target_analyzer")
    metadata = _tool_output(results, "api_metadata_discovery")
    attack_surface = {
        "routes": routes,
        "parameters": parameters,
        "objects": objects,
        "authentication_boundaries": authentication_boundaries,
        "schemas": schemas,
        "sources": {
            "captured_requests": len(captured_requests),
            "crawler": len(crawl_urls),
            "openapi": {
                "documents": (
                    len(metadata.get("documents", []))
                    if isinstance(metadata.get("documents"), list)
                    else 0
                ),
                "routes": len(openapi_routes),
            },
            "javascript": len(fetch_urls),
            "graphql": (
                len(graphql_arguments) if isinstance(graphql_arguments, list) else 0
            ),
        },
        "api_target": api_target,
        "adaptive_decision": api_target.get("decision", {}),
    }
    analysis_urls = SurfaceURLList(
        all_urls, routes=routes, parameters=parameters, objects=objects
    )
    return {
        "requested_target": target,
        "effective_target": effective_target,
        "redirect_chain": http.get("redirect_chain", []),
        "all_urls": all_urls,
        "same_origin_urls": same_origin,
        "api_urls": api_urls,
        "javascript_urls": javascript,
        "urls_with_parameters": with_parameters,
        "out_of_scope_urls": out,
        "crawl_status": crawl.get("status", "failed"),
        "routes": routes,
        "parameters": parameters,
        "objects": objects,
        "authentication_boundaries": authentication_boundaries,
        "schemas": schemas,
        "sources": attack_surface["sources"],
        "api_target": api_target,
        "adaptive_decision": api_target.get("decision", {}),
        "attack_surface": attack_surface,
        "analysis_urls": analysis_urls,
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
        observation_only = item.get("classification") == "attack_surface_observation"
        findings.append(
            _finding(
                f"Parameter candidate: {item.get('parameter', 'unknown')}",
                "parameter_analyzer",
                status="observation" if observation_only else "candidate",
                severity="informational",
                endpoint=item.get("url"),
                evidence=[str(item.get("reason", "Parameter observed."))],
                category=(
                    "parameter_surface"
                    if observation_only
                    else "authorization_test_idea"
                ),
            )
        )
    js = _tool_output(results, "js_secret_scanner")
    for item in normalize_finding_list(js.get("findings"))[:MAX_ITEMS]:
        match_kind = item.get("match_kind")
        public_contact = match_kind == "public_contact"
        candidate = match_kind == "candidate_value" and item.get("confidence") in {
            "medium",
            "high",
        }
        findings.append(
            _finding(
                (
                    "Potential credential-like value requires verification"
                    if candidate
                    else (
                        "Public contact information observed in JavaScript"
                        if public_contact
                        else "JavaScript scanner observation"
                    )
                ),
                "js_secret_scanner",
                status="needs_manual_verification" if candidate else "observation",
                severity="informational",
                endpoint=item.get("url"),
                evidence=[
                    f"Match kind: {item.get('match_kind', 'unknown')}; confidence: {item.get('confidence', 'unknown')}; context hash: {item.get('context_hash', 'unavailable')}"
                ],
                category=(
                    "credential_candidate"
                    if candidate
                    else "public_contact" if public_contact else "scanner_observation"
                ),
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
        raw_severity = str(item.get("severity", "informational")).lower()
        severity = "informational" if raw_severity == "info" else raw_severity
        if severity not in {"informational", "low", "medium", "high", "critical"}:
            severity = "informational"
        template_id = item.get("template_id") or "unknown"
        matcher = item.get("matcher_name") or "default"
        actionable = severity != "informational"
        findings.append(
            _finding(
                item.get("name") or item.get("template_id") or "Nuclei observation",
                "nuclei_scan",
                severity=severity,
                status=("needs_manual_verification" if actionable else "observation"),
                endpoint=item.get("matched_at") or item.get("url"),
                evidence=[
                    item.get("description") or "Nuclei template matched.",
                    f"Template: {template_id}; matcher: {matcher}.",
                ],
                category=(
                    "vulnerability_candidate" if actionable else "scanner_observation"
                ),
            )
        )
    discovery = _tool_output(results, "graphql_endpoint_discovery")
    for item in normalize_finding_list(discovery.get("observed_candidates"))[
        :MAX_ITEMS
    ]:
        findings.append(
            _finding(
                "GraphQL-related application behavior was observed.",
                "graphql_endpoint_discovery",
                endpoint=item.get("url"),
                evidence=[
                    f"Endpoint confidence: {item.get('confidence', 'unknown')}; source: {item.get('source', 'unknown')}; network tested: {bool(item.get('network_checked'))}."
                ],
                category="graphql_surface",
            )
        )
    introspection = _tool_output(results, "graphql_introspection_checker")
    if introspection.get("introspection_status") == "introspection_available":
        findings.append(
            _finding(
                "GraphQL introspection was available on the tested endpoint.",
                "graphql_introspection_checker",
                evidence=[
                    "This may aid schema discovery but does not by itself establish a security vulnerability."
                ],
                category="graphql_surface",
            )
        )
    jwt_discovery = _tool_output(results, "jwt_discovery")
    for item in normalize_finding_list(jwt_discovery.get("tokens_observed"))[
        :MAX_ITEMS
    ]:
        findings.append(
            _finding(
                "JWT-related authentication metadata was observed.",
                "jwt_discovery",
                evidence=[
                    f"Source: {item.get('token_source', 'unknown')}; algorithm: {item.get('algorithm') or 'unknown'}; confidence: {item.get('confidence', 'unknown')}; network tested: false."
                ],
                category="jwt_surface",
            )
        )
    workflow_discovery = _tool_output(results, "workflow_evidence_discovery")
    for item in normalize_finding_list(
        workflow_discovery.get("workflow_candidates"),
        section="workflow_candidates",
    )[:MAX_ITEMS]:
        findings.append(
            _finding(
                "Business-workflow-related application behavior was observed.",
                "workflow_evidence_discovery",
                evidence=[
                    f"Confidence: {item.get('confidence', 'unknown')}; steps: {len(item.get('observed_steps') or [])}; network tested: false."
                ],
                category="business_workflow_surface",
            )
        )
    upload_discovery = _tool_output(results, "upload_discovery")
    for item in normalize_finding_list(upload_discovery.get("observations"))[
        :MAX_ITEMS
    ]:
        findings.append(
            _finding(
                "File-upload-related application behavior was observed.",
                "upload_discovery",
                evidence=[
                    f"Type: {item.get('type', 'unknown')}; confidence: {item.get('confidence', 'unknown')}; network tested: false."
                ],
                category="upload_surface",
            )
        )
    validation = _tool_output(results, "upload_validation_analyzer")
    for item in normalize_finding_list(validation.get("candidates"))[:MAX_ITEMS]:
        findings.append(
            _finding(
                "Upload validation consistency requires manual verification.",
                "upload_validation_analyzer",
                status="needs_manual_verification",
                evidence=item.get("evidence")
                or [
                    "Observed evidence is insufficient to establish server-side behavior."
                ],
                category="upload_validation_candidate",
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
    assessment_mode: str = "observe",
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
    api_target = _tool_output(results, "api_target_analyzer")
    metadata = _tool_output(results, "api_metadata_discovery")
    openapi = _tool_output(results, "openapi_surface_analyzer")
    metadata_documents = metadata.get("documents")
    metadata_document_count = (
        len(metadata_documents)
        if isinstance(metadata_documents, list)
        else int(metadata.get("document_count") or 0)
    )
    api_surface = {
        "relevant": bool(
            api_target.get("api_likelihood") in {"medium", "high"}
            or metadata_document_count
            or openapi.get("operation_count")
        ),
        "api_likelihood": api_target.get("api_likelihood", "low"),
        "signals": api_target.get("signals", []),
        "decision": api_target.get("decision", {}),
        "openapi_document_discovered": metadata_document_count > 0,
        "openapi_documents": metadata_document_count,
        "routes_documented": int(openapi.get("route_count") or 0),
        "operations_observed": int(openapi.get("operation_count") or 0),
        "parameters_observed": int(openapi.get("parameter_count") or 0),
        "object_reference_candidates": int(openapi.get("object_reference_count") or 0),
        "authentication_protected_operations": int(
            openapi.get("authentication_protected_operation_count") or 0
        ),
        "vulnerability_status": "not_assessed",
    }
    package = {
        "assessment": {
            "version": __version__,
            "requested_target": target,
            "effective_target": surface["effective_target"],
            "profile": profile,
            "assessment_mode": assessment_mode,
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
            "api_surface": api_surface,
            "attack_surface": {
                "routes": surface.get("routes", []),
                "parameters": surface.get("parameters", []),
                "objects": normalize_finding_list(
                    api.get("objects") or surface.get("objects"), section="objects"
                ),
                "authentication_boundaries": surface.get(
                    "authentication_boundaries", []
                ),
                "schemas": surface.get("schemas", []),
                "sources": surface.get("sources", {}),
            },
            "graphql": {
                "endpoints_observed": len(
                    _tool_output(results, "graphql_endpoint_discovery").get(
                        "observed_candidates", []
                    )
                ),
                "confirmed_endpoints": len(
                    _tool_output(results, "graphql_endpoint_discovery").get(
                        "confirmed_endpoints", []
                    )
                ),
                "introspection_status": _tool_output(
                    results, "graphql_introspection_checker"
                ).get("introspection_status", "not_tested"),
                "operations_observed": len(
                    _tool_output(results, "graphql_query_analyzer").get("fields", [])
                ),
                "manual_authorization_plans": len(
                    _tool_output(results, "graphql_authz_planner").get("plans", [])
                ),
            },
            "jwt": {
                "tokens_observed": _tool_output(results, "jwt_discovery").get(
                    "token_count", 0
                ),
                "sources": sorted(
                    {
                        item.get("token_source")
                        for item in _tool_output(results, "jwt_discovery").get(
                            "tokens_observed", []
                        )
                        if isinstance(item, dict) and item.get("token_source")
                    }
                ),
                "algorithms": sorted(
                    {
                        item.get("algorithm")
                        for item in _tool_output(results, "jwt_discovery").get(
                            "tokens_observed", []
                        )
                        if isinstance(item, dict) and item.get("algorithm")
                    }
                ),
                "issuer_present": bool(
                    _tool_output(results, "jwt_decoder")
                    .get("claims_summary", {})
                    .get("iss_present")
                ),
                "audience_present": bool(
                    _tool_output(results, "jwt_decoder")
                    .get("claims_summary", {})
                    .get("aud_present")
                ),
                "expiration_observations": _tool_output(results, "jwt_claims_analyzer")
                .get("time_analysis", {})
                .get("observations", []),
                "role_claim_names": _tool_output(results, "jwt_decoder")
                .get("claims_summary", {})
                .get("role_claim_names", []),
                "scope_claim_names": _tool_output(results, "jwt_decoder")
                .get("claims_summary", {})
                .get("scope_claim_names", []),
                "signature_verification_status": _tool_output(
                    results, "jwt_decoder"
                ).get("verification_status", "not_verified"),
                "comparison_count": _tool_output(results, "jwt_comparison_analyzer")
                .get("comparison_summary", {})
                .get("controlled_token_count", 0),
                "manual_plans": _tool_output(results, "jwt_verification_planner").get(
                    "plan_count", 0
                ),
                "replay_status": _tool_output(results, "jwt_replay_checker").get(
                    "status", "not_applicable"
                ),
            },
            "business_logic": {
                "workflow_candidates": len(
                    _tool_output(results, "workflow_evidence_discovery").get(
                        "workflow_candidates", []
                    )
                ),
                "modeled_workflows": int(
                    bool(_tool_output(results, "workflow_model_builder").get("model"))
                ),
                "steps_observed": len(
                    _tool_output(results, "workflow_model_builder")
                    .get("model", {})
                    .get("steps", [])
                ),
                "transitions_observed": len(
                    _tool_output(results, "workflow_model_builder")
                    .get("model", {})
                    .get("transitions", [])
                ),
                "business_rule_observations": len(
                    _tool_output(results, "business_rule_analyzer").get(
                        "observations", []
                    )
                ),
                "manual_plans": len(
                    _tool_output(results, "business_logic_test_planner").get(
                        "plans", []
                    )
                ),
                "replay_status": _tool_output(results, "workflow_replay_checker").get(
                    "status", "not_applicable"
                ),
            },
            "upload": {
                "surface_observed": bool(
                    _tool_output(results, "upload_discovery").get(
                        "upload_surface_observed"
                    )
                ),
                "observations": _tool_output(results, "upload_discovery").get(
                    "observation_count", 0
                ),
                "validation_observations": len(
                    _tool_output(results, "upload_validation_analyzer").get(
                        "observations", []
                    )
                ),
                "metadata_observations": len(
                    _tool_output(results, "upload_metadata_analyzer").get(
                        "observations", []
                    )
                ),
                "storage_observations": _tool_output(
                    results, "upload_storage_analyzer"
                ).get("providers_observed", []),
                "manual_plans": _tool_output(results, "upload_security_planner").get(
                    "plan_count", 0
                ),
                "replay_status": _tool_output(results, "upload_replay_checker").get(
                    "status", "not_applicable"
                ),
                "filenames_disclosed": False,
            },
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
