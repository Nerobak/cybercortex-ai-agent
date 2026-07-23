"""Offline comparison of researcher-controlled JWTs."""

from __future__ import annotations

from typing import Any

from tools.jwt_decoder import ROLE_NAMES, SCOPE_NAMES, decode_jwt


def _present_difference(values: list[Any]) -> bool:
    return len({repr(value) for value in values}) > 1


def compare_jwts(tokens: list[str]) -> dict[str, Any]:
    if not isinstance(tokens, list) or len(tokens) < 2:
        return {
            "success": False,
            "status": "not_applicable",
            "error": "At least two controlled JWTs are required.",
        }
    decoded = [decode_jwt(token) for token in tokens]
    if not all(item.get("success") for item in decoded):
        return {
            "success": False,
            "error": "Every controlled token must decode successfully.",
        }
    payloads = [item["_controlled_payload"] for item in decoded]
    headers = [item["header"] for item in decoded]
    header_differences = [
        name
        for name in ("alg", "typ", "kid_present")
        if _present_difference([header.get(name) for header in headers])
    ]
    name_sets = [set(payload) for payload in payloads]
    all_names = set().union(*name_sets)
    claim_name_differences = sorted(
        name for name in all_names if len({name in names for names in name_sets}) > 1
    )
    role_scope = sorted(all_names & (ROLE_NAMES | SCOPE_NAMES))
    role_scope_differences = [
        name
        for name in role_scope
        if _present_difference([payload.get(name, object()) for payload in payloads])
    ]
    time_differences = []
    lifetimes = []
    for payload in payloads:
        exp, iat = payload.get("exp"), payload.get("iat")
        lifetimes.append(
            exp - iat
            if isinstance(exp, (int, float)) and isinstance(iat, (int, float))
            else None
        )
    if _present_difference(lifetimes):
        time_differences.append("lifetime_window_differs")
    boundaries = []
    for name in ("sub", "iss", "aud", "tenant", "organization", "account"):
        if _present_difference(
            [
                {"present": name in payload, "value_changed": True}
                for payload in payloads
            ]
        ):
            boundaries.append(f"{name}_presence_differs")
        elif all(name in payload for payload in payloads) and _present_difference(
            [payload[name] for payload in payloads]
        ):
            boundaries.append(f"{name}_value_differs")
    return {
        "success": True,
        "comparison_summary": {
            "controlled_token_count": len(tokens),
            "algorithms_differ": "alg" in header_differences,
            "subjects_differ": "sub_value_differs" in boundaries,
        },
        "header_differences": header_differences,
        "claim_name_differences": claim_name_differences,
        "role_scope_differences": role_scope_differences,
        "time_differences": time_differences,
        "authorization_boundary_observations": boundaries,
        "manual_verification_required": True,
        "vulnerability_status": "observation",
        "network_testing_occurred": False,
    }


jwt_comparison_analyzer = compare_jwts
