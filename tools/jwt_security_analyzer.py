from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Any

RECOMMENDED_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}

SYMMETRIC_ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
}

WEAK_OR_UNSAFE_ALGORITHMS = {
    "none",
    "None",
    "NONE",
}

SENSITIVE_CLAIM_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "credit_card",
    "ssn",
}

PRIVILEGE_CLAIM_NAMES = {
    "admin",
    "is_admin",
    "isadmin",
    "role",
    "roles",
    "permissions",
    "scope",
    "scopes",
    "groups",
}

DEFAULT_MAX_LIFETIME_SECONDS = 24 * 60 * 60
DEFAULT_CLOCK_SKEW_SECONDS = 300


def _base64url_decode(value: str) -> bytes:
    """Decode a Base64URL JWT segment."""
    padding = "=" * (-len(value) % 4)

    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as error:
        raise ValueError("JWT segment is not valid Base64URL data.") from error


def _decode_json_segment(
    segment: str,
    segment_name: str,
) -> dict[str, Any]:
    """Decode one JWT segment as a JSON object."""
    raw = _base64url_decode(segment)

    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"The JWT {segment_name} is not valid UTF-8.") from error

    try:
        value = json.loads(decoded)
    except json.JSONDecodeError as error:
        raise ValueError(f"The JWT {segment_name} is not valid JSON.") from error

    if not isinstance(value, dict):
        raise ValueError(f"The JWT {segment_name} must decode to a JSON object.")

    return value


def _timestamp_to_iso(value: int | float) -> str:
    """Convert a Unix timestamp into an ISO-8601 UTC value."""
    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return "invalid_timestamp"


def _normalize_claim_name(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(".", "_")


def _severity_rank(severity: str) -> int:
    ranks = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    return ranks.get(severity, 0)


def _highest_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "informational"

    return max(
        (finding.get("severity", "informational") for finding in findings),
        key=_severity_rank,
    )


def _add_finding(
    findings: list[dict[str, Any]],
    *,
    title: str,
    severity: str,
    confidence: str,
    evidence: str,
    risk: str,
    recommendation: str,
    category: str = "jwt_security",
) -> None:
    findings.append(
        {
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "status": "observation",
            "evidence": [evidence],
            "risk": risk,
            "recommendation": recommendation,
        }
    )


def parse_jwt(token: str) -> dict[str, Any]:
    """
    Parse a JWT without validating its cryptographic signature.

    The signature is never decoded into reports or logs.
    """
    if not isinstance(token, str) or not token.strip():
        return {
            "success": False,
            "error": "A JWT value is required.",
        }

    normalized_token = token.strip()

    if normalized_token.lower().startswith("bearer "):
        normalized_token = normalized_token[7:].strip()

    parts = normalized_token.split(".")

    if len(parts) != 3:
        return {
            "success": False,
            "error": (
                "A standard signed JWT must contain exactly "
                "three dot-separated segments."
            ),
        }

    header_segment, payload_segment, signature_segment = parts

    if not header_segment or not payload_segment:
        return {
            "success": False,
            "error": "JWT header and payload segments cannot be empty.",
        }

    try:
        header = _decode_json_segment(
            header_segment,
            "header",
        )
        payload = _decode_json_segment(
            payload_segment,
            "payload",
        )
    except ValueError as error:
        return {
            "success": False,
            "error": str(error),
        }

    return {
        "success": True,
        "header": header,
        "payload": payload,
        "signature": {
            "present": bool(signature_segment),
            "length": len(signature_segment),
        },
        "segments": {
            "header_length": len(header_segment),
            "payload_length": len(payload_segment),
            "signature_length": len(signature_segment),
        },
    }


def analyze_jwt(
    token: str,
    *,
    current_time: int | float | None = None,
    max_lifetime_seconds: int = DEFAULT_MAX_LIFETIME_SECONDS,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """
    Perform offline JWT header and claim analysis.

    This function does not validate the cryptographic signature because no
    trusted verification key is supplied. It also does not modify or replay
    tokens.
    """
    parsed = parse_jwt(token)

    if not parsed.get("success"):
        return parsed

    now = current_time if current_time is not None else time.time()

    header = parsed["header"]
    payload = parsed["payload"]
    findings: list[dict[str, Any]] = []

    algorithm = header.get("alg")
    token_type = header.get("typ")
    key_id = header.get("kid")

    if not algorithm:
        _add_finding(
            findings,
            title="JWT algorithm is missing",
            severity="high",
            confidence="high",
            evidence="The JWT header does not contain an alg value.",
            risk=(
                "Token verification behavior may be ambiguous or "
                "incorrectly implemented."
            ),
            recommendation=(
                "Require an explicit algorithm and enforce an allowlist "
                "during signature verification."
            ),
        )

    elif str(algorithm) in WEAK_OR_UNSAFE_ALGORITHMS:
        _add_finding(
            findings,
            title="JWT uses the none algorithm",
            severity="high",
            confidence="high",
            evidence=f"The JWT header declares alg={algorithm!r}.",
            risk=("A vulnerable verifier may accept an unsigned token."),
            recommendation=(
                "Reject unsigned JWTs and enforce a server-side " "algorithm allowlist."
            ),
        )

    elif str(algorithm) in SYMMETRIC_ALGORITHMS:
        _add_finding(
            findings,
            title="JWT uses a symmetric signing algorithm",
            severity="informational",
            confidence="high",
            evidence=f"The JWT uses {algorithm}.",
            risk=(
                "Symmetric JWT verification relies on secure shared-secret "
                "management. The algorithm is not inherently vulnerable."
            ),
            recommendation=(
                "Confirm the shared secret is strong, rotated, and never "
                "exposed to untrusted services."
            ),
        )

    elif str(algorithm) not in RECOMMENDED_ALGORITHMS:
        _add_finding(
            findings,
            title="JWT uses an uncommon signing algorithm",
            severity="low",
            confidence="high",
            evidence=f"The JWT uses {algorithm!r}.",
            risk=(
                "The algorithm may not be included in the application's "
                "intended verification allowlist."
            ),
            recommendation=(
                "Verify that the algorithm is explicitly approved and "
                "supported by the token issuer and verifier."
            ),
        )

    if token_type is None:
        _add_finding(
            findings,
            title="JWT type header is missing",
            severity="informational",
            confidence="high",
            evidence="The JWT header does not include typ=JWT.",
            risk=(
                "The missing type does not normally create a vulnerability "
                "but reduces token-format clarity."
            ),
            recommendation=("Consider including typ=JWT where appropriate."),
        )

    if key_id is not None:
        _add_finding(
            findings,
            title="JWT contains a key identifier",
            severity="informational",
            confidence="high",
            evidence="The JWT header includes a kid value.",
            risk=(
                "The kid value influences key selection and should be "
                "handled as untrusted input."
            ),
            recommendation=(
                "Ensure kid values are matched against a fixed key registry "
                "and are never used directly as filesystem or URL input."
            ),
        )

    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    for claim_name, claim_value in {
        "exp": exp,
        "iat": iat,
        "nbf": nbf,
    }.items():
        if claim_value is not None and not isinstance(
            claim_value,
            (int, float),
        ):
            _add_finding(
                findings,
                title=f"JWT {claim_name} claim has an invalid type",
                severity="medium",
                confidence="high",
                evidence=(
                    f"The {claim_name} claim is "
                    f"{type(claim_value).__name__}, not a numeric timestamp."
                ),
                risk=(
                    "Incorrect claim parsing may cause expiration or "
                    "validity checks to behave unexpectedly."
                ),
                recommendation=(
                    f"Require {claim_name} to be a numeric Unix timestamp."
                ),
            )

    if exp is None:
        _add_finding(
            findings,
            title="JWT has no expiration claim",
            severity="medium",
            confidence="high",
            evidence="The JWT payload does not contain exp.",
            risk=(
                "A leaked token may remain usable indefinitely unless "
                "revoked through another mechanism."
            ),
            recommendation=(
                "Add a short, enforced expiration and use refresh-token "
                "rotation where longer sessions are required."
            ),
        )

    elif isinstance(exp, (int, float)):
        if exp < now - clock_skew_seconds:
            _add_finding(
                findings,
                title="JWT is expired",
                severity="informational",
                confidence="high",
                evidence=(f"The token expired at {_timestamp_to_iso(exp)}."),
                risk=("An expired token should be rejected by the application."),
                recommendation=("Verify that the server rejects this token."),
            )

        elif iat is not None and isinstance(iat, (int, float)):
            lifetime = exp - iat

            if lifetime < 0:
                _add_finding(
                    findings,
                    title="JWT expiration precedes issuance",
                    severity="medium",
                    confidence="high",
                    evidence=("The exp claim occurs before the iat claim."),
                    risk=("The token has inconsistent temporal claims."),
                    recommendation=(
                        "Correct token issuance logic and reject tokens "
                        "with inconsistent timestamps."
                    ),
                )

            elif lifetime > max_lifetime_seconds:
                _add_finding(
                    findings,
                    title="JWT lifetime is unusually long",
                    severity="low",
                    confidence="high",
                    evidence=(f"The token lifetime is {int(lifetime)} seconds."),
                    risk=(
                        "Long-lived access tokens increase the impact of "
                        "token theft."
                    ),
                    recommendation=(
                        "Use short-lived access tokens and rotate refresh " "tokens."
                    ),
                )

    if isinstance(iat, (int, float)) and iat > now + clock_skew_seconds:
        _add_finding(
            findings,
            title="JWT issue time is in the future",
            severity="medium",
            confidence="high",
            evidence=(f"The token iat value is {_timestamp_to_iso(iat)}."),
            risk=(
                "Future issuance times may indicate clock problems or "
                "incorrect validation."
            ),
            recommendation=(
                "Reject tokens issued too far in the future and review "
                "clock synchronization."
            ),
        )

    if isinstance(nbf, (int, float)) and nbf > now + clock_skew_seconds:
        _add_finding(
            findings,
            title="JWT is not yet valid",
            severity="informational",
            confidence="high",
            evidence=(f"The token is not valid before {_timestamp_to_iso(nbf)}."),
            risk=("The token should not be accepted before its nbf time."),
            recommendation=("Verify that the server enforces the nbf claim."),
        )

    issuer = payload.get("iss")
    audience = payload.get("aud")

    if issuer is None:
        _add_finding(
            findings,
            title="JWT issuer claim is missing",
            severity="low",
            confidence="high",
            evidence="The token does not include iss.",
            risk=(
                "The verifier may be unable to ensure that the token came "
                "from the expected issuer."
            ),
            recommendation=("Include and validate an expected issuer value."),
        )

    if audience is None:
        _add_finding(
            findings,
            title="JWT audience claim is missing",
            severity="low",
            confidence="high",
            evidence="The token does not include aud.",
            risk=(
                "A token intended for one service may be accepted by "
                "another service if audience validation is absent."
            ),
            recommendation=("Include and strictly validate the intended audience."),
        )

    sensitive_claims: list[str] = []
    privilege_claims: list[str] = []

    for claim_name in payload:
        normalized_name = _normalize_claim_name(str(claim_name))

        if normalized_name in SENSITIVE_CLAIM_NAMES:
            sensitive_claims.append(str(claim_name))

        if normalized_name in PRIVILEGE_CLAIM_NAMES:
            privilege_claims.append(str(claim_name))

    if sensitive_claims:
        _add_finding(
            findings,
            title="JWT contains potentially sensitive claims",
            severity="medium",
            confidence="high",
            evidence=(
                "Potentially sensitive claim names: "
                + ", ".join(sorted(sensitive_claims))
                + "."
            ),
            risk=(
                "JWT payloads are encoded, not encrypted, and can be read "
                "by anyone who obtains the token."
            ),
            recommendation=(
                "Remove secrets and sensitive personal data from JWT " "payloads."
            ),
        )

    if privilege_claims:
        _add_finding(
            findings,
            title="JWT contains authorization-related claims",
            severity="informational",
            confidence="high",
            evidence=(
                "Privilege-related claims: " + ", ".join(sorted(privilege_claims)) + "."
            ),
            risk=(
                "Authorization claims must only be trusted after signature, "
                "issuer, audience, and expiration validation."
            ),
            recommendation=(
                "Ensure privilege claims are enforced server-side only "
                "after complete token verification."
            ),
        )

    time_claims = {
        name: {
            "raw": payload.get(name),
            "iso": (
                _timestamp_to_iso(payload[name])
                if isinstance(payload.get(name), (int, float))
                else None
            ),
        }
        for name in ("iat", "nbf", "exp")
        if name in payload
    }

    return {
        "success": True,
        "signature_verified": False,
        "warning": (
            "This is offline structural analysis only. "
            "The JWT signature has not been verified."
        ),
        "header": header,
        "claims": payload,
        "time_claims": time_claims,
        "summary": {
            "algorithm": algorithm,
            "token_type": token_type,
            "issuer_present": issuer is not None,
            "audience_present": audience is not None,
            "expiration_present": exp is not None,
            "finding_count": len(findings),
            "highest_severity": _highest_severity(findings),
            "sensitive_claim_count": len(sensitive_claims),
            "privilege_claim_count": len(privilege_claims),
        },
        "findings": findings,
        "signature": parsed["signature"],
    }
