"""Secret-safe, offline JWT decoding primitives."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from config import JWT_MAX_TOKEN_BYTES

SENSITIVE_FRAGMENTS = {
    "email",
    "phone",
    "name",
    "address",
    "token",
    "secret",
    "session",
    "password",
    "account",
    "payment",
    "card",
    "ssn",
    "identifier",
}
ROLE_NAMES = {"role", "roles", "permission", "permissions", "admin", "groups"}
SCOPE_NAMES = {"scope", "scopes"}


def decode_segment(segment: str, label: str) -> dict[str, Any]:
    """Decode a Base64URL JSON object without accepting ambiguous encodings."""
    if not segment or any(character.isspace() for character in segment):
        raise ValueError(f"JWT {label} segment is empty or malformed.")
    try:
        raw = base64.b64decode(
            segment + ("=" * (-len(segment) % 4)), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(f"JWT {label} is not valid Base64URL data.") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JWT {label} is not a valid JSON object.") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JWT {label} must decode to a JSON object.")
    return value


def _safe_claim_value(name: str, value: Any) -> Any:
    normalized = name.lower().replace("-", "_")
    if any(fragment in normalized for fragment in SENSITIVE_FRAGMENTS):
        return "[REDACTED]"
    if normalized in {"iss", "sub", "aud", "jti"}:
        return "[PRESENT]"
    if normalized in ROLE_NAMES | SCOPE_NAMES:
        if isinstance(value, list):
            return {"present": True, "item_count": len(value)}
        return {"present": True, "value_type": type(value).__name__}
    if isinstance(value, (str, bytes)):
        return {"present": True, "value_type": "string", "length": len(value)}
    if isinstance(value, list):
        return {"present": True, "value_type": "list", "item_count": len(value)}
    if isinstance(value, dict):
        return {"present": True, "value_type": "object", "key_count": len(value)}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return {"present": True, "value_type": type(value).__name__}


def _time_claims(payload: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("exp", "nbf", "iat"):
        value = payload.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                iso = datetime.fromtimestamp(value, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                iso = "invalid_timestamp"
            result[name] = {"present": True, "unix": value, "utc": iso}
        elif name in payload:
            result[name] = {"present": True, "valid_numeric_date": False}
        else:
            result[name] = {"present": False}
    return result


def decode_jwt(
    token: str, *, max_token_bytes: int = JWT_MAX_TOKEN_BYTES
) -> dict[str, Any]:
    """Decode a controlled JWT locally; never return its token or signature."""
    if not isinstance(token, str) or not token.strip():
        return {
            "success": False,
            "valid_structure": False,
            "error": "A JWT is required.",
        }
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if len(token.encode("utf-8")) > max_token_bytes:
        return {
            "success": False,
            "valid_structure": False,
            "error": f"JWT exceeds the {max_token_bytes}-byte safety limit.",
        }
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return {
            "success": False,
            "valid_structure": False,
            "error": "JWT must contain three dot-separated segments.",
        }
    try:
        header = decode_segment(parts[0], "header")
        payload = decode_segment(parts[1], "payload")
    except ValueError as exc:
        return {"success": False, "valid_structure": False, "error": str(exc)}

    claim_names = {str(name) for name in payload}
    safe_header = {
        "alg": str(header.get("alg"))[:32] if header.get("alg") is not None else None,
        "typ": str(header.get("typ"))[:32] if header.get("typ") is not None else None,
        "kid_present": "kid" in header,
        "jku_present": "jku" in header,
        "jwk_present": "jwk" in header,
        "x5u_present": "x5u" in header,
        "x5c_present": "x5c" in header,
        "crit_present": "crit" in header,
        "b64_present": "b64" in header,
    }
    summary = {
        f"{name}_present": name in payload
        for name in ("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
    }
    summary["role_claim_names"] = sorted(claim_names & ROLE_NAMES)
    summary["scope_claim_names"] = sorted(claim_names & SCOPE_NAMES)
    return {
        "success": True,
        "valid_structure": True,
        "header": safe_header,
        "claims_summary": summary,
        "time_claims": _time_claims(payload),
        "redacted_claims": {
            str(name): _safe_claim_value(str(name), value)
            for name, value in payload.items()
        },
        "claim_names": sorted(claim_names),
        "signature_present": bool(parts[2]),
        "signature_verified": False,
        "verification_status": "not_verified",
        "vulnerability_status": "observation",
        "network_testing_occurred": False,
        "_controlled_payload": payload,
    }


def public_decoded_result(result: dict[str, Any]) -> dict[str, Any]:
    """Remove the private, in-process payload used by downstream offline tools."""
    return {key: value for key, value in result.items() if key != "_controlled_payload"}


def jwt_decoder(
    token: str, *, max_token_bytes: int = JWT_MAX_TOKEN_BYTES
) -> dict[str, Any]:
    """Registry-facing decoder that cannot return raw controlled claims."""
    return public_decoded_result(decode_jwt(token, max_token_bytes=max_token_bytes))
