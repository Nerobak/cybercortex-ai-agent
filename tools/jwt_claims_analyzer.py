"""Deterministic JWT header, claim-name, and time observations."""

from __future__ import annotations

import time
from typing import Any

from config import JWT_CLOCK_SKEW_SECONDS, JWT_MAX_LIFETIME_SECONDS
from tools.jwt_decoder import decode_jwt

CUSTOM_CATEGORIES = {
    "role": {"role", "roles", "admin"},
    "permission": {"permission", "permissions"},
    "scope": {"scope", "scopes"},
    "tenant": {"tenant", "organization", "org"},
    "account": {"account", "user", "identity"},
    "session": {"session", "sid"},
    "authentication_method": {"amr", "acr", "authentication_method"},
}


def analyze_jwt_header(header: dict[str, Any]) -> list[dict[str, Any]]:
    alg = str(header.get("alg") or "")
    observations = []

    def add(kind: str) -> None:
        observations.append(
            {"type": kind, "status": "observation", "confidence": "high"}
        )

    if alg.lower() == "none":
        add("unsigned_algorithm_observed")
    elif alg.upper().startswith("HS"):
        add("symmetric_algorithm_observed")
    elif alg.upper().startswith(("RS", "PS", "ES", "ED")):
        add("asymmetric_algorithm_observed")
    if header.get("kid_present") or "kid" in header:
        add("key_identifier_present")
    if any(header.get(f"{name}_present") or name in header for name in ("jku", "x5u")):
        add("remote_key_reference_present")
    if any(header.get(f"{name}_present") or name in header for name in ("jwk", "x5c")):
        add("embedded_key_present")
    if header.get("crit_present") or "crit" in header:
        add("critical_header_present")
    typ = header.get("typ")
    if typ is not None and str(typ).upper() not in {"JWT", "AT+JWT"}:
        add("unusual_type_value")
    return observations


def analyze_jwt_claims(
    controlled: str | dict[str, Any],
    *,
    current_time: int | float | None = None,
    max_lifetime_seconds: int = JWT_MAX_LIFETIME_SECONDS,
    clock_skew_seconds: int = JWT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    decoded = decode_jwt(controlled) if isinstance(controlled, str) else controlled
    if not isinstance(decoded, dict) or not decoded.get("success"):
        return {
            "success": False,
            "error": "Successful controlled JWT decoding is required.",
            "status": "not_applicable",
        }
    payload = decoded.get("_controlled_payload")
    if not isinstance(payload, dict):
        return {
            "success": False,
            "error": "Controlled decoded claim evidence is unavailable.",
            "status": "not_applicable",
        }
    now = current_time if current_time is not None else time.time()
    exp, nbf, iat = payload.get("exp"), payload.get("nbf"), payload.get("iat")
    observations: list[str] = []
    if "exp" not in payload:
        observations.append("missing_expiration")
    elif isinstance(exp, (int, float)) and not isinstance(exp, bool):
        if exp < now - clock_skew_seconds:
            observations.append("expired")
        elif exp < now:
            observations.append("clock_skew_candidate")
    if isinstance(nbf, (int, float)) and nbf > now + clock_skew_seconds:
        observations.append("not_yet_valid")
    elif isinstance(nbf, (int, float)) and nbf > now:
        observations.append("clock_skew_candidate")
    if isinstance(iat, (int, float)) and iat > now + clock_skew_seconds:
        observations.append("future_issued_at")
    elif isinstance(iat, (int, float)) and iat > now:
        observations.append("clock_skew_candidate")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = exp - iat
        observations.append(
            "long_lived" if lifetime > max_lifetime_seconds else "short_lived"
        )
    blocked = {"expired", "not_yet_valid", "future_issued_at"}
    if not blocked.intersection(observations) and "exp" in payload:
        observations.append("valid_at_analysis_time")
    names = {str(name).lower() for name in payload}
    categories = {
        category: sorted(names & candidates)
        for category, candidates in CUSTOM_CATEGORIES.items()
        if names & candidates
    }
    return {
        "success": True,
        "registered_claims": {
            f"{name}_present": name in payload
            for name in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
        },
        "custom_claim_categories": categories,
        "time_analysis": {
            "observations": sorted(set(observations)),
            "analysis_time": now,
            "max_lifetime_seconds": max_lifetime_seconds,
            "clock_skew_seconds": clock_skew_seconds,
        },
        "header_observations": analyze_jwt_header(decoded.get("header", {})),
        "signature_verified": False,
        "manual_verification_required": True,
        "vulnerability_status": "observation",
        "network_testing_occurred": False,
    }


jwt_claims_analyzer = analyze_jwt_claims
