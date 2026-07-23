"""Offline JWT discovery from already-authorized evidence."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterator

from tools.jwt_decoder import decode_jwt

JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
SOURCE_KEYS = {"authorization", "headers", "cookies", "cookie", "javascript", "body"}


def _walk(
    value: Any, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, (*path, str(key)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk(item, (*path, str(index)))
    elif isinstance(value, str):
        yield path, value


def _source(path: tuple[str, ...]) -> tuple[str, str | None]:
    lowered = [part.lower() for part in path]
    name = path[-1] if path else None
    if "authorization" in lowered or (name and name.lower() == "authorization"):
        return "authorization_header", "Authorization"
    if "cookies" in lowered or "cookie" in lowered:
        return "cookie", name
    if any("javascript" in part or part.endswith(".js") for part in lowered):
        return "javascript_string", None
    return "authorized_evidence", name if name and name.lower() in SOURCE_KEYS else None


def discover_jwts(evidence: Any) -> dict[str, Any]:
    """Find structurally decodable JWTs and retain metadata only."""
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[str] = []
    for path, text in _walk(evidence):
        for match in JWT_PATTERN.finditer(text):
            token = match.group(1)
            fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            if fingerprint in seen:
                continue
            decoded = decode_jwt(token)
            if not decoded.get("success"):
                continue
            seen.add(fingerprint)
            source, name = _source(path)
            summary = decoded["claims_summary"]
            observations.append(
                {
                    "token_source": source,
                    "header_or_cookie_name": name,
                    "segment_count": 3,
                    "token_length": len(token),
                    "redacted_fingerprint": fingerprint,
                    "algorithm": decoded["header"].get("alg"),
                    "issuer_present": summary["iss_present"],
                    "subject_present": summary["sub_present"],
                    "audience_present": summary["aud_present"],
                    "expiry_present": summary["exp_present"],
                    "confidence": "high",
                    "vulnerability_status": "observation",
                    "network_testing_occurred": False,
                }
            )
    return {
        "success": True,
        "tokens_observed": observations,
        "token_count": len(observations),
        "errors": errors,
        "vulnerability_status": "observation",
    }


jwt_discovery = discover_jwts
