"""Policy-gated differential replay across captured parameter locations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from agent_core.capture_ingest import CapturedRequest
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy
from agent_core.verification_gate import normalize_volatile_fields
from tools.safe_http import ScopedHTTPClient


@dataclass(frozen=True)
class CapturedMutation:
    parameter: str
    location: str
    value: str


def _bounded_mutation(mutation: CapturedMutation) -> None:
    if not mutation.parameter or len(mutation.parameter) > 200:
        raise ValueError("A bounded parameter name is required.")
    if len(mutation.value.encode()) > 1024:
        raise ValueError("Mutation value exceeds the 1024-byte limit.")
    if any(character in mutation.value for character in ("\r", "\n", "\x00")):
        raise ValueError("Mutation values cannot contain CR, LF, or NUL characters.")


def _set_nested(value: dict[str, Any], path: str, replacement: str) -> None:
    parts = path.split(".")
    current: dict[str, Any] = value
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            raise ValueError(f"Nested parameter '{path}' was not present.")
        current = child
    if parts[-1] not in current:
        raise ValueError(f"Parameter '{path}' was not present.")
    current[parts[-1]] = replacement


def _materialize(
    request: CapturedRequest,
    vault: CredentialVault,
    mutation: CapturedMutation | None,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    if not request.execution_url_ref:
        raise ValueError("The capture has no executable URL reference.")
    url = vault.get(request.execution_url_ref)
    headers = vault.materialize_headers(request.headers)
    body = vault.get(request.execution_body_ref) if request.execution_body_ref else None
    kwargs: dict[str, Any] = {}
    if mutation:
        _bounded_mutation(mutation)
        if mutation.location == "query":
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            changed = False
            output = []
            for name, value in pairs:
                if not changed and name == mutation.parameter:
                    output.append((name, mutation.value))
                    changed = True
                else:
                    output.append((name, value))
            if not changed:
                raise ValueError(
                    f"Query parameter '{mutation.parameter}' was not present."
                )
            url = urlunparse(parsed._replace(query=urlencode(output)))
        elif mutation.location == "path":
            parsed = urlparse(url)
            segments = parsed.path.split("/")
            placeholder = "{" + mutation.parameter + "}"
            changed = False
            for index, segment in enumerate(segments):
                if segment == placeholder or segment == mutation.parameter:
                    segments[index] = mutation.value
                    changed = True
                    break
            if not changed:
                raise ValueError("Path mutation requires a named template segment.")
            url = urlunparse(parsed._replace(path="/".join(segments)))
        elif mutation.location == "header":
            if mutation.parameter.lower() in {
                "host",
                "content-length",
                "authorization",
                "cookie",
                "proxy-authorization",
                "x-api-key",
            }:
                raise ValueError(
                    "Credential, framing, and routing headers cannot be mutated."
                )
            headers[mutation.parameter] = mutation.value
        elif mutation.location in {"json", "graphql_variable"}:
            parsed_body = json.loads(body or "{}")
            if mutation.location == "graphql_variable":
                variables = parsed_body.get("variables")
                if not isinstance(variables, dict):
                    raise ValueError("Captured GraphQL variables were not present.")
                _set_nested(variables, mutation.parameter, mutation.value)
            else:
                _set_nested(parsed_body, mutation.parameter, mutation.value)
            body = json.dumps(parsed_body, separators=(",", ":"))
        elif mutation.location == "form":
            pairs = parse_qsl(body or "", keep_blank_values=True)
            changed = False
            output = []
            for name, value in pairs:
                if not changed and name == mutation.parameter:
                    output.append((name, mutation.value))
                    changed = True
                else:
                    output.append((name, value))
            if not changed:
                raise ValueError(
                    f"Form parameter '{mutation.parameter}' was not present."
                )
            body = urlencode(output)
        elif mutation.location == "multipart":
            raise ValueError(
                "Multipart mutation requires the dedicated benign-file upload adapter."
            )
        else:
            raise ValueError(f"Unsupported mutation location: {mutation.location}")
    if body is not None:
        if request.body_type in {"json", "graphql", "raw"}:
            kwargs["data"] = body.encode()
        elif request.body_type in {"form", "urlencoded"}:
            kwargs["data"] = body
        else:
            kwargs["data"] = body.encode()
    return url, headers, kwargs


def _fingerprint(response: Any) -> dict[str, Any]:
    content = getattr(response, "content", b"")
    if not isinstance(content, bytes):
        content = bytes(str(content), "utf-8")
    normalized: Any = content.decode(
        getattr(response, "encoding", None) or "utf-8", "replace"
    )
    content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if "json" in content_type.lower():
        try:
            normalized = normalize_volatile_fields(json.loads(normalized))
        except json.JSONDecodeError:
            pass
    serialized = json.dumps(normalized, sort_keys=True, default=str).encode()
    return {
        "status_code": int(getattr(response, "status_code", 0)),
        "body_length": len(content),
        "normalized_sha256": sha256(serialized).hexdigest(),
        "content_type": content_type[:120],
    }


def execute_captured_differential(
    request: CapturedRequest,
    vault: CredentialVault,
    policy: AssessmentPolicy,
    mutation: CapturedMutation,
    *,
    authorization_confirmed: bool = False,
    test_owned_resources: list[str] | None = None,
    cleanup: Callable[[], bool] | None = None,
    requester: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run two controls and two identical bounded mutations.

    State-changing requests require a test-owned resource and a successful
    cleanup callback. Results remain candidates; the evidence gate decides
    whether a typed verifier has enough proof to promote a finding.
    """
    if not authorization_confirmed or not policy.authorization_confirmed:
        return {
            "success": False,
            "error": "Explicit execution authorization is required.",
        }
    if not request.executable:
        return {"success": False, "error": "The imported request is metadata-only."}
    if request.state_changing:
        if not policy.allow_state_changes:
            return {
                "success": False,
                "error": "State-changing requests are disabled by policy.",
            }
        if not test_owned_resources:
            return {"success": False, "error": "A test-owned resource is required."}
        if cleanup is None:
            return {"success": False, "error": "A cleanup callback is required."}
    raw_url = vault.get(request.execution_url_ref or "")
    decision = policy.authorize_url(raw_url, method=request.method)
    if not decision.allowed:
        return {"success": False, "error": "; ".join(decision.reasons)}
    client = ScopedHTTPClient(
        policy=policy,
        requester=requester,
        requester_takes_method=True,
    )
    fingerprints: list[dict[str, Any]] = []
    cleanup_succeeded = not request.state_changing
    try:
        for selected_mutation in (None, None, mutation, mutation):
            url, headers, kwargs = _materialize(request, vault, selected_mutation)
            response, _ = client.request(
                request.method,
                url,
                headers=headers,
                follow_redirects=False,
                **kwargs,
            )
            fingerprints.append(_fingerprint(response))
        if request.state_changing and cleanup is not None:
            cleanup_succeeded = bool(cleanup())
    except Exception as exc:
        if request.state_changing and cleanup is not None:
            cleanup_succeeded = bool(cleanup())
        return {
            "success": False,
            "error": str(exc),
            "requests_used": client.requests_used,
            "cleanup_succeeded": cleanup_succeeded,
        }
    control_repeatable = fingerprints[0] == fingerprints[1]
    mutation_repeatable = fingerprints[2] == fingerprints[3]
    differential = fingerprints[0] != fingerprints[2]
    return {
        "success": True,
        "status": (
            "needs_manual_verification"
            if control_repeatable
            and mutation_repeatable
            and differential
            and cleanup_succeeded
            else "observation"
        ),
        "requests_used": client.requests_used,
        "parameter": mutation.parameter,
        "location": mutation.location,
        "controls": fingerprints[:2],
        "mutations": fingerprints[2:],
        "control_repeatable": control_repeatable,
        "mutation_repeatable": mutation_repeatable,
        "differential_observed": differential,
        "cleanup_succeeded": cleanup_succeeded,
        "scope_violations": 0,
        "unauthorized_state_changes": 0,
    }
