from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from typing import Any

DEFAULT_SENSITIVE_FIELDS = {
    "accountid",
    "address",
    "apikey",
    "authorization",
    "balance",
    "creditcard",
    "email",
    "firstname",
    "lastname",
    "password",
    "phone",
    "role",
    "secret",
    "session",
    "ssn",
    "token",
    "userid",
}


def _normalize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Normalize HTTP header names and values for comparison."""
    if not headers:
        return {}

    return {
        str(name).strip().lower(): str(value).strip() for name, value in headers.items()
    }


def _body_to_text(body: Any) -> str:
    """Convert response content into stable text."""
    if body is None:
        return ""

    if isinstance(body, (dict, list)):
        return json.dumps(
            body,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")

    return str(body)


def _try_parse_json(body: Any) -> Any | None:
    """Return parsed JSON when possible."""
    if isinstance(body, (dict, list)):
        return body

    if not isinstance(body, (str, bytes)):
        return None

    text = _body_to_text(body).strip()

    if not text:
        return None

    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _flatten_json(
    value: Any,
    prefix: str = "",
) -> dict[str, Any]:
    """
    Flatten nested JSON into path/value pairs.

    Example:
        {"user": {"email": "a@example.com"}}

    Becomes:
        {"user.email": "a@example.com"}
    """
    flattened: dict[str, Any] = {}

    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten_json(child, path))

    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]"
            flattened.update(_flatten_json(child, path))

    else:
        flattened[prefix] = value

    return flattened


def _field_name(path: str) -> str:
    """Extract and normalize the final field name from a JSON path."""
    final_component = re.split(r"[.\[]", path)[-1]
    final_component = final_component.rstrip("]0123456789")

    return re.sub(
        r"[^a-z0-9]",
        "",
        final_component.lower(),
    )


def _sha256(value: str) -> str:
    """Create a short integrity fingerprint without exposing content."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compare_responses(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    sensitive_fields: set[str] | None = None,
) -> dict[str, Any]:
    """
    Compare two stored HTTP response representations.

    Expected response shape:

        {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {"id": 123, "email": "user@example.com"},
            "elapsed_ms": 125
        }

    This function performs comparison only. It does not send requests.
    """
    sensitive = {
        re.sub(r"[^a-z0-9]", "", field.lower())
        for field in (
            sensitive_fields
            if sensitive_fields is not None
            else DEFAULT_SENSITIVE_FIELDS
        )
    }

    baseline_status = baseline.get("status_code")
    candidate_status = candidate.get("status_code")

    baseline_headers = _normalize_headers(baseline.get("headers"))
    candidate_headers = _normalize_headers(candidate.get("headers"))

    baseline_text = _body_to_text(baseline.get("body"))
    candidate_text = _body_to_text(candidate.get("body"))

    similarity = SequenceMatcher(
        None,
        baseline_text,
        candidate_text,
    ).ratio()

    baseline_json = _try_parse_json(baseline.get("body"))
    candidate_json = _try_parse_json(candidate.get("body"))

    json_comparison: dict[str, Any] = {
        "available": False,
        "added_fields": [],
        "removed_fields": [],
        "changed_fields": [],
        "sensitive_fields_present": [],
    }

    if baseline_json is not None and candidate_json is not None:
        baseline_flat = _flatten_json(baseline_json)
        candidate_flat = _flatten_json(candidate_json)

        baseline_paths = set(baseline_flat)
        candidate_paths = set(candidate_flat)

        added_fields = sorted(candidate_paths - baseline_paths)
        removed_fields = sorted(baseline_paths - candidate_paths)

        changed_fields = sorted(
            path
            for path in baseline_paths & candidate_paths
            if baseline_flat[path] != candidate_flat[path]
        )

        sensitive_fields_present = sorted(
            path for path in candidate_paths if _field_name(path) in sensitive
        )

        json_comparison = {
            "available": True,
            "added_fields": added_fields,
            "removed_fields": removed_fields,
            "changed_fields": changed_fields,
            "sensitive_fields_present": sensitive_fields_present,
        }

    baseline_header_names = set(baseline_headers)
    candidate_header_names = set(candidate_headers)

    added_headers = sorted(candidate_header_names - baseline_header_names)
    removed_headers = sorted(baseline_header_names - candidate_header_names)

    changed_headers = sorted(
        header
        for header in baseline_header_names & candidate_header_names
        if baseline_headers[header] != candidate_headers[header]
    )

    signals: list[str] = []

    if baseline_status != candidate_status:
        signals.append(
            f"HTTP status changed from " f"{baseline_status} to {candidate_status}."
        )

    if baseline_status in {401, 403} and candidate_status == 200:
        signals.append(
            "Candidate response changed from an authorization denial "
            "to a successful response."
        )

    if (
        similarity >= 0.95
        and candidate_status == 200
        and baseline_text != candidate_text
    ):
        signals.append("Candidate body is highly similar to the baseline body.")

    if json_comparison["sensitive_fields_present"]:
        signals.append("Candidate response contains fields classified as sensitive.")

    if json_comparison["added_fields"]:
        signals.append("Candidate JSON contains fields not present in the baseline.")

    return {
        "success": True,
        "status": {
            "baseline": baseline_status,
            "candidate": candidate_status,
            "changed": baseline_status != candidate_status,
        },
        "body": {
            "baseline_length": len(baseline_text),
            "candidate_length": len(candidate_text),
            "length_difference": (len(candidate_text) - len(baseline_text)),
            "similarity_ratio": round(similarity, 4),
            "baseline_sha256": _sha256(baseline_text),
            "candidate_sha256": _sha256(candidate_text),
            "identical": baseline_text == candidate_text,
        },
        "headers": {
            "added": added_headers,
            "removed": removed_headers,
            "changed": changed_headers,
        },
        "json": json_comparison,
        "timing": {
            "baseline_ms": baseline.get("elapsed_ms"),
            "candidate_ms": candidate.get("elapsed_ms"),
        },
        "signals": signals,
    }
