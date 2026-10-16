"""Canonical HTTP(S) URL contract shared by policy and transport gates.

The contract performs exactly one validation/preparation pass.  It rejects URL
representations whose path could be interpreted differently by the policy,
``requests``, an intermediary, or the origin server.  In particular, path dot
segments, encoded separators/backslashes, encoded percent signs (which enable
double encoding), malformed escapes, userinfo, and raw backslashes are denied.

Queries are preserved and percent-validated but never participate in path
scope matching.  Fragments are rejected because they are not part of an HTTP
request target.  The returned URL is the value that callers must authorize and
pass to the supported HTTP transport.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit, urlunsplit

from requests.models import PreparedRequest

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


class URLCanonicalizationError(ValueError):
    """A URL cannot be represented unambiguously at the HTTP boundary."""


@dataclass(frozen=True)
class CanonicalTransportURL:
    """One validated URL representation shared by authorization and dispatch."""

    url: str
    scheme: str
    hostname: str
    port: int
    path: str
    query: str


def normalize_transport_hostname(value: str) -> str:
    """Normalize an exact DNS name or IP address without accepting URL syntax."""

    raw = str(value).strip().lower().rstrip(".")
    if not raw or any(character.isspace() for character in raw):
        raise URLCanonicalizationError("hostname cannot be empty or contain whitespace")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if any(token in raw for token in ("://", "/", "@", "?", "#", "*", ":", "%")):
        raise URLCanonicalizationError(
            "hostname must be exact and cannot contain URL syntax"
        )
    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLCanonicalizationError("hostname is not valid IDNA") from exc
    labels = ascii_host.split(".")
    if any(
        not label or len(label) > 63 or _HOST_LABEL.fullmatch(label) is None
        for label in labels
    ):
        raise URLCanonicalizationError("hostname contains an invalid DNS label")
    if len(ascii_host) > 253:
        raise URLCanonicalizationError("hostname is too long")
    return ascii_host


def _validate_percent_encoding(value: str, *, component: str) -> None:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _HEX_DIGITS
            or value[index + 2] not in _HEX_DIGITS
        ):
            raise URLCanonicalizationError(
                f"{component} contains malformed percent encoding"
            )
        index += 3


def _validate_path(path: str) -> None:
    _validate_percent_encoding(path, component="URL path")
    if "\\" in path:
        raise URLCanonicalizationError("URL path contains a backslash")

    lowered = path.lower()
    if "%2f" in lowered:
        raise URLCanonicalizationError("URL path contains an encoded separator")
    if "%5c" in lowered:
        raise URLCanonicalizationError("URL path contains an encoded backslash")
    if "%25" in lowered:
        raise URLCanonicalizationError("URL path contains ambiguous double encoding")

    decoded_path = unquote_to_bytes(path)
    if any(byte < 0x20 or byte == 0x7F for byte in decoded_path):
        raise URLCanonicalizationError("URL path contains a control character")
    for segment in path.split("/"):
        if unquote_to_bytes(segment) in {b".", b".."}:
            raise URLCanonicalizationError("URL path contains an ambiguous dot segment")


def _validated_timeout_part(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("request timeout must be a finite positive number")
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("request timeout must be a finite positive number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("request timeout must be a finite positive number")
    return timeout


def validate_transport_timeout(
    timeout: Any,
) -> float | tuple[float, float]:
    """Validate a finite requests-compatible connect/read timeout contract.

    This bounds supported HTTP-client connect/read inactivity.  Python cannot
    forcibly terminate arbitrary caller-supplied code that ignores its timeout,
    so lease-backed callers must use a cooperative supported transport.
    """

    if isinstance(timeout, (tuple, list)):
        if len(timeout) != 2:
            raise ValueError("request timeout must contain connect and read bounds")
        return (
            _validated_timeout_part(timeout[0]),
            _validated_timeout_part(timeout[1]),
        )
    return _validated_timeout_part(timeout)


def _parse_validated(value: str) -> CanonicalTransportURL:
    if not isinstance(value, str) or not value or value != value.strip():
        raise URLCanonicalizationError("URL must be one non-empty trimmed string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise URLCanonicalizationError("URL contains a control character")
    if any(character.isspace() for character in value):
        raise URLCanonicalizationError("URL contains whitespace")
    if "\\" in value:
        raise URLCanonicalizationError("URL contains a backslash")

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise URLCanonicalizationError("URL authority is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not hostname:
        raise URLCanonicalizationError("URL must be an absolute HTTP(S) URL")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise URLCanonicalizationError("URL userinfo is not permitted")
    if parsed.fragment:
        raise URLCanonicalizationError("URL fragments are not transport targets")

    normalized_host = normalize_transport_hostname(hostname)
    port = explicit_port or (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise URLCanonicalizationError("URL port is outside the valid range")

    canonical_path = parsed.path or "/"
    _validate_path(canonical_path)
    _validate_percent_encoding(parsed.query, component="URL query")

    rendered_host = (
        f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    )
    netloc = (
        f"{rendered_host}:{explicit_port}"
        if explicit_port is not None
        else rendered_host
    )
    rendered = urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))
    return CanonicalTransportURL(
        url=rendered,
        scheme=scheme,
        hostname=normalized_host,
        port=port,
        path=canonical_path,
        query=parsed.query,
    )


def canonicalize_transport_url(
    value: str,
    *,
    params: Any = None,
) -> CanonicalTransportURL:
    """Return the sole URL representation authorized and sent by HTTP clients.

    The input is first rejected if ambiguous.  ``requests`` then prepares the
    URL once (including optional query parameters), and the prepared result is
    validated again.  No recursive or repeated percent decoding is performed.
    """

    initial = _parse_validated(value)
    prepared = PreparedRequest()
    try:
        prepared.prepare_url(initial.url, params)
    except (TypeError, ValueError) as exc:
        raise URLCanonicalizationError("URL transport preparation failed") from exc
    if not isinstance(prepared.url, str):
        raise URLCanonicalizationError("URL transport preparation failed")
    final = _parse_validated(prepared.url)
    if not urlsplit(initial.url).path and final.path == "/":
        prepared_parts = urlsplit(final.url)
        return CanonicalTransportURL(
            url=urlunsplit(
                (
                    final.scheme,
                    prepared_parts.netloc,
                    "",
                    final.query,
                    "",
                )
            ),
            scheme=final.scheme,
            hostname=final.hostname,
            port=final.port,
            path=final.path,
            query=final.query,
        )
    return final


def path_is_within_prefix(path: str, prefix: str) -> bool:
    """Compare already-canonical paths without consulting query text."""

    allowed = (prefix or "/").rstrip("/") or "/"
    target = (path or "/").rstrip("/") or "/"
    return allowed == "/" or target == allowed or target.startswith(f"{allowed}/")


__all__ = [
    "CanonicalTransportURL",
    "URLCanonicalizationError",
    "canonicalize_transport_url",
    "normalize_transport_hostname",
    "path_is_within_prefix",
    "validate_transport_timeout",
]
