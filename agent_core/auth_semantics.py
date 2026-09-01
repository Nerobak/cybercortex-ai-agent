"""Deterministic authentication semantics from secret-free route metadata.

The classifier in this module records attack-surface observations only.  It
does not establish that authentication, session, recovery, or rate controls
are present, absent, or vulnerable at runtime.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

AUTH_BOUNDARY_TYPES = {
    "session_creation",
    "session_termination",
    "authenticated_resource",
    "recovery_start",
    "recovery_completion",
    "credential_submission",
}

_LOGIN_TERMS = {"login", "signin", "signon", "authenticate", "authentication"}
_SESSION_TERMS = {"session", "sessions"}
_TERMINATION_TERMS = {
    "logout",
    "signout",
    "signoff",
    "revoke",
    "terminate",
    "termination",
    "invalidate",
    "invalidation",
}
_RECOVERY_TERMS = {"recovery", "recover", "reset", "forgot", "restore"}
_RECOVERY_SUBJECTS = {"password", "passwords", "account", "accounts", "credential"}
_NON_ACCOUNT_RECOVERY_TERMS = {
    "archive",
    "backup",
    "data",
    "database",
    "disaster",
    "document",
    "file",
    "files",
    "storage",
}
_START_TERMS = {"start", "initiate", "begin", "request", "send", "forgot"}
_COMPLETE_TERMS = {
    "complete",
    "completion",
    "confirm",
    "confirmation",
    "verify",
    "verification",
    "finish",
    "redeem",
}
_IDENTITY_FIELDS = {
    "account_id",
    "email",
    "email_address",
    "username",
    "user_name",
    "user_id",
    "login",
    "identifier",
    "account_name",
}
_SECRET_FIELDS = {
    "password",
    "passwd",
    "passphrase",
    "user_password",
    "current_password",
    "new_password",
    "client_secret",
}
_VERIFICATION_FIELDS = {
    "code",
    "otp",
    "one_time_code",
    "verification_code",
    "recovery_code",
    "reset_code",
    "reset_token",
    "recovery_token",
    "authorization_code",
}
_ONE_TIME_VERIFICATION_FIELDS = {
    "otp",
    "one_time_code",
    "verification_code",
    "recovery_code",
    "reset_code",
}
_TOKEN_CREDENTIAL_FIELDS = {
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "client_secret",
    "authorization_code",
}
_AUTH_HEADER_NAMES = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "x_auth_token",
    "x_session_id",
    "x_session_token",
}
_CURRENT_USER_TERMS = {"me", "my", "self", "current", "profile", "whoami"}
_AUTH_CONTEXT_TERMS = (
    _LOGIN_TERMS
    | _SESSION_TERMS
    | {
        "auth",
        "oauth",
        "oidc",
        "token",
    }
)
_ONE_TIME_AUTH_CONTEXT_TERMS = (
    _LOGIN_TERMS
    | _SESSION_TERMS
    | {
        "account",
        "auth",
        "authentication",
        "factor",
        "mfa",
        "otp",
        "totp",
    }
)
_SAFE_SUMMARY_TERMS = (
    _AUTH_CONTEXT_TERMS
    | _TERMINATION_TERMS
    | _RECOVERY_TERMS
    | _RECOVERY_SUBJECTS
    | _START_TERMS
    | _COMPLETE_TERMS
    | _CURRENT_USER_TERMS
    | {
        "create",
        "creation",
        "credential",
        "credentials",
        "authenticated",
        "factor",
        "mfa",
        "otp",
        "sign",
        "totp",
        "in",
        "out",
        "off",
    }
)


def _normalized_word(value: object) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _tokens(value: object) -> set[str]:
    normalized = _normalized_word(value)
    return {item for item in normalized.split("_") if item}


def safe_auth_semantic_summary(value: object) -> str:
    """Retain only allowlisted auth semantics, never free-form summary text."""
    normalized = _normalized_word(value)
    return " ".join(
        item for item in normalized.split("_") if item and item in _SAFE_SUMMARY_TERMS
    )


def _path_tokens(path: object) -> set[str]:
    """Tokenize route segments without turning ``me.jpg`` into a ``me`` route."""
    output: set[str] = set()
    for raw_segment in str(path or "").split("/"):
        segment = raw_segment.strip().lower()
        if not segment or (segment.startswith("{") and segment.endswith("}")):
            continue
        if "." in segment:
            output.add(segment)
            continue
        output.update(_tokens(segment))
    return output


def _semantic_channels(route: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "path": _path_tokens(route.get("path")),
        "operation_id": _tokens(route.get("operation_id") or route.get("operationId")),
        "summary": _tokens(route.get("summary")),
    }


def _compact(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _channel_has(route: dict[str, Any], channel: str, terms: set[str]) -> bool:
    tokens = _semantic_channels(route)[channel]
    if tokens & terms:
        return True
    raw = route.get(channel)
    if channel == "operation_id":
        raw = route.get("operation_id") or route.get("operationId")
    compact = _compact(raw)
    compact_terms = terms & {"signin", "signon", "signout", "signoff"}
    return any(term in compact for term in compact_terms)


def _field_name(item: object) -> str:
    if isinstance(item, dict):
        return _normalized_word(item.get("field_path") or item.get("name"))
    return _normalized_word(item)


def _field_type(item: object) -> str:
    if not isinstance(item, dict):
        return "unknown"
    return _normalized_word(item.get("schema_type") or item.get("type") or "unknown")


def _route_parameter_items(
    route: dict[str, Any],
    parameters_by_route: dict[tuple[str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    method = str(route.get("method") or "GET").upper()
    path = str(route.get("path") or "/")
    items: list[dict[str, Any]] = []
    for key in ("parameters", "request_fields", "request_body_fields"):
        raw = route.get(key)
        if isinstance(raw, list):
            items.extend(item for item in raw if isinstance(item, dict))
    items.extend(parameters_by_route.get((method, path), []))
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        unique[
            (
                _field_name(item),
                _normalized_word(item.get("in") or item.get("location") or "unknown"),
                _field_type(item),
            )
        ] = item
    return list(unique.values())


def _request_field_names(items: Iterable[dict[str, Any]]) -> set[str]:
    request_locations = {
        "body",
        "form",
        "json",
        "multipart",
        "request_body",
        "graphql_variable",
    }
    recognized = (
        _IDENTITY_FIELDS
        | _SECRET_FIELDS
        | _VERIFICATION_FIELDS
        | _TOKEN_CREDENTIAL_FIELDS
    )
    return {
        (
            _field_name(item)
            if _field_name(item) in recognized
            else _field_name(item).split("_")[-1]
        )
        for item in items
        if _normalized_word(item.get("in") or item.get("location")) in request_locations
    }


def _request_field_details(
    items: Iterable[dict[str, Any]],
) -> dict[str, set[str]]:
    details: dict[str, set[str]] = defaultdict(set)
    request_locations = {
        "body",
        "form",
        "json",
        "multipart",
        "request_body",
        "graphql_variable",
    }
    for item in items:
        location = _normalized_word(item.get("in") or item.get("location"))
        if location not in request_locations:
            continue
        name = _field_name(item)
        details[name].add(_field_type(item))
    return details


def _header_names(items: Iterable[dict[str, Any]]) -> set[str]:
    return {
        _field_name(item)
        for item in items
        if _normalized_word(item.get("in") or item.get("location")) == "header"
    }


def _response_field_names(route: dict[str, Any]) -> set[str]:
    raw = route.get("response_fields")
    if not isinstance(raw, list):
        return set()
    return {_field_name(item) for item in raw}


def _confidence_rank(value: object) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(value), 2)


def _lower_confidence(left: object, right: object) -> str:
    rank = min(_confidence_rank(left), _confidence_rank(right))
    return {1: "low", 2: "medium", 3: "high"}[rank]


def _evidence_refs(*items: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(reference)
            for item in items
            for reference in item.get("evidence_refs", []) or []
            if reference
        }
    )


def _sources(
    route: dict[str, Any],
    parameters: Iterable[dict[str, Any]],
    existing: dict[str, Any] | None = None,
) -> list[str]:
    values = {
        str(item)
        for item in [
            route.get("source"),
            existing.get("source") if existing else None,
            *(parameter.get("source") for parameter in parameters),
        ]
        if item
    }
    return sorted(values or {"normalized_route_evidence"})


def _boundary(
    route: dict[str, Any],
    boundary_type: str,
    *,
    semantics: Iterable[str],
    evidence: Iterable[str],
    confidence: str,
    sources: Iterable[str],
    evidence_refs: Iterable[str] = (),
    rate_sensitive: bool = False,
    limitations: Iterable[str] = (),
) -> dict[str, Any]:
    return {
        "boundary_type": boundary_type,
        "semantic_classes": sorted(set(semantics)),
        "method": str(route.get("method") or "GET").upper(),
        "path": str(route.get("path") or "/"),
        "evidence": list(dict.fromkeys(str(item) for item in evidence if item)),
        "evidence_sources": sorted(set(str(item) for item in sources if item)),
        "evidence_refs": sorted(set(str(item) for item in evidence_refs if item)),
        "confidence": confidence,
        "rate_sensitive_candidate": rate_sensitive,
        "source": "auth_semantic_classifier",
        "limitations": list(
            dict.fromkeys(
                [
                    "Route metadata indicates authentication semantics but does not prove runtime enforcement.",
                    *[str(item) for item in limitations if item],
                ]
            )
        ),
    }


def _merge_boundaries(boundaries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in boundaries:
        key = (
            str(item.get("method") or "GET").upper(),
            str(item.get("path") or "/"),
            str(item.get("boundary_type") or "authenticated_resource"),
        )
        if key not in merged:
            merged[key] = item
            continue
        current = merged[key]
        for field in (
            "semantic_classes",
            "evidence",
            "evidence_sources",
            "evidence_refs",
            "limitations",
        ):
            current[field] = sorted(
                set(current.get(field, []) or []) | set(item.get(field, []) or [])
            )
        if _confidence_rank(item.get("confidence")) > _confidence_rank(
            current.get("confidence")
        ):
            current["confidence"] = item.get("confidence")
        current["rate_sensitive_candidate"] = bool(
            current.get("rate_sensitive_candidate")
            or item.get("rate_sensitive_candidate")
        )
    return [merged[key] for key in sorted(merged)]


def _shared_recovery_family(start: dict[str, Any], complete: dict[str, Any]) -> bool:
    start_tokens = _path_tokens(start.get("path"))
    complete_tokens = _path_tokens(complete.get("path"))
    shared = start_tokens & complete_tokens
    return bool(shared & (_RECOVERY_TERMS | _RECOVERY_SUBJECTS))


def _session_pair_score(creation: dict[str, Any], termination: dict[str, Any]) -> int:
    shared = _path_tokens(creation.get("path")) & _path_tokens(termination.get("path"))
    family_terms = {"account", "auth", "authentication", "session", "sessions"}
    return (10 * len(shared & family_terms)) + len(shared)


def _workflow_step(boundary: dict[str, Any], sequence: int) -> dict[str, Any]:
    step = {
        "sequence": sequence,
        "boundary_type": boundary["boundary_type"],
        "method": boundary["method"],
        "path": boundary["path"],
        "source": boundary.get("source"),
        "confidence": boundary.get("confidence", "medium"),
        "evidence": list(boundary.get("evidence", []) or []),
        "evidence_sources": list(boundary.get("evidence_sources", []) or []),
        "evidence_refs": boundary.get("evidence_refs", []),
    }
    identity_fields = boundary.get("identity_fields")
    if isinstance(identity_fields, list) and identity_fields:
        step["identity_fields"] = list(identity_fields)
    return step


def _correlate_workflows(boundaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for boundary in boundaries:
        by_type[str(boundary.get("boundary_type"))].append(boundary)
    workflows: list[dict[str, Any]] = []

    starts = sorted(
        by_type["recovery_start"], key=lambda item: (item["path"], item["method"])
    )
    completions = sorted(
        by_type["recovery_completion"],
        key=lambda item: (item["path"], item["method"]),
    )
    for completion in completions:
        candidates = [
            start for start in starts if _shared_recovery_family(start, completion)
        ]
        if not candidates:
            continue
        start = max(
            candidates,
            key=lambda item: (
                len(_path_tokens(item["path"]) & _path_tokens(completion["path"])),
                item["path"],
            ),
        )
        workflows.append(
            {
                "workflow_id": (
                    f"account_recovery:{start['method']}:{start['path']}"
                    f"->{completion['method']}:{completion['path']}"
                ),
                "name": "account_recovery",
                "workflow_type": "account_recovery",
                "semantic_domain": "authentication",
                "steps": [_workflow_step(start, 1), _workflow_step(completion, 2)],
                "evidence": [
                    "shared recovery route family",
                    "ordered recovery start and completion semantics",
                ],
                "evidence_sources": sorted(
                    set(start.get("evidence_sources", []))
                    | set(completion.get("evidence_sources", []))
                ),
                "evidence_refs": _evidence_refs(start, completion),
                "confidence": _lower_confidence(
                    start.get("confidence"), completion.get("confidence")
                ),
                "source": "auth_semantic_classifier",
                "limitations": [
                    "The ordered route relationship is a workflow candidate, not evidence of a recovery bypass."
                ],
            }
        )

    creations = sorted(
        by_type["session_creation"], key=lambda item: (item["path"], item["method"])
    )
    terminations = sorted(
        by_type["session_termination"],
        key=lambda item: (item["path"], item["method"]),
    )
    resources = sorted(
        by_type["authenticated_resource"],
        key=lambda item: (
            "current_user_resource" not in item.get("semantic_classes", []),
            item["path"],
            item["method"],
        ),
    )
    session_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for creation in creations:
        candidates = [
            termination
            for termination in terminations
            if _session_pair_score(creation, termination) > 0
        ]
        if not candidates and len(creations) == 1 and len(terminations) == 1:
            # One unambiguous pair of strongly classified lifecycle phases is
            # itself a semantic relationship; target co-location is not used.
            candidates = terminations
        if candidates:
            session_pairs.append(
                (
                    creation,
                    max(
                        candidates,
                        key=lambda item: (
                            _session_pair_score(creation, item),
                            item["path"],
                            item["method"],
                        ),
                    ),
                )
            )

    for creation, termination in session_pairs:
        if not resources:
            continue
        resource = max(
            resources,
            key=lambda item: (
                "current_user_resource" in item.get("semantic_classes", []),
                len(
                    _path_tokens(item.get("path"))
                    & (
                        _path_tokens(creation.get("path"))
                        | _path_tokens(termination.get("path"))
                    )
                ),
                item["path"],
                item["method"],
            ),
        )
        steps = [
            _workflow_step(creation, 1),
            _workflow_step(resource, 2),
            _workflow_step(termination, 3),
        ]
        participants = [creation, resource, termination]
        confidence = creation.get("confidence", "medium")
        for participant in participants[1:]:
            confidence = _lower_confidence(confidence, participant.get("confidence"))
        workflows.append(
            {
                "workflow_id": (
                    f"session_lifecycle:{creation['method']}:{creation['path']}"
                    f"->{resource['method']}:{resource['path']}"
                    f"->{termination['method']}:{termination['path']}"
                ),
                "name": "session_lifecycle",
                "workflow_type": "session_lifecycle",
                "semantic_domain": "authentication",
                "steps": steps,
                "evidence": [
                    "session creation and termination semantics",
                    "authenticated resource observed between lifecycle endpoints",
                ],
                "evidence_sources": sorted(
                    {
                        source
                        for participant in participants
                        for source in participant.get("evidence_sources", [])
                    }
                ),
                "evidence_refs": _evidence_refs(*participants),
                "confidence": confidence,
                "source": "auth_semantic_classifier",
                "limitations": [
                    "The route relationship does not prove session issuance, use, or invalidation behavior."
                ],
            }
        )
    return workflows


def discover_auth_semantics(
    routes: Iterable[dict[str, Any]],
    parameters: Iterable[dict[str, Any]],
    existing_boundaries: Iterable[dict[str, Any]] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return normalized auth boundaries and correlated workflow candidates."""
    route_list = [item for item in routes if isinstance(item, dict)][:5000]
    parameter_list = [item for item in parameters if isinstance(item, dict)][:10000]
    existing_list = [item for item in existing_boundaries if isinstance(item, dict)][
        :5000
    ]
    parameters_by_route: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for parameter in parameter_list:
        parameters_by_route[
            (
                str(parameter.get("method") or "GET").upper(),
                str(parameter.get("path") or "/"),
            )
        ].append(parameter)
    existing_by_route: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for boundary in existing_list:
        existing_by_route[
            (
                str(boundary.get("method") or "GET").upper(),
                str(boundary.get("path") or "/"),
            )
        ].append(boundary)

    discovered: list[dict[str, Any]] = []
    classified_routes: set[tuple[str, str]] = set()
    route_keys: set[tuple[str, str]] = set()
    for route in route_list:
        method = str(route.get("method") or "GET").upper()
        path = str(route.get("path") or "/")
        key = (method, path)
        route_keys.add(key)
        items = _route_parameter_items(route, parameters_by_route)
        request_fields = _request_field_names(items)
        request_details = _request_field_details(items)
        headers = _header_names(items)
        response_fields = _response_field_names(route)
        response_token_fields = response_fields & _TOKEN_CREDENTIAL_FIELDS
        response_statuses = {
            str(item) for item in route.get("response_status_codes", []) or []
        }
        response_headers = {
            _normalized_word(item) for item in route.get("response_headers", []) or []
        }
        sets_cookie = bool(route.get("sets_cookie")) or "set_cookie" in response_headers
        channels = _semantic_channels(route)
        all_tokens = set().union(*channels.values())
        existing = existing_by_route.get(key, [])
        security_declared = bool(route.get("security_required")) or bool(
            route.get("security_schemes")
        )
        explicit_auth_observation = any(
            boundary.get("authenticated_observation")
            or boundary.get("security_schemes")
            or boundary.get("boundary_type") == "authenticated_resource"
            for boundary in existing
        )
        auth_headers = headers & _AUTH_HEADER_NAMES
        current_user_context = bool(channels["path"] & _CURRENT_USER_TERMS)
        response_auth_signal = bool(response_statuses & {"401", "403"}) and bool(
            current_user_context or all_tokens & _AUTH_CONTEXT_TERMS
        )
        auth_metadata = bool(
            security_declared
            or explicit_auth_observation
            or auth_headers
            or response_auth_signal
        )
        sources = _sources(route, items, existing[0] if existing else None)
        refs = _evidence_refs(route, *existing)
        semantic_channels = {
            name
            for name, tokens in channels.items()
            if tokens & (_AUTH_CONTEXT_TERMS | _TERMINATION_TERMS | _RECOVERY_TERMS)
        }

        identity_fields = request_fields & _IDENTITY_FIELDS
        secret_fields = request_fields & _SECRET_FIELDS
        credential_pair = bool(identity_fields and secret_fields)
        credential_types_credible = all(
            request_details.get(name, {"unknown"}) & {"string", "unknown"}
            for name in identity_fields | secret_fields
        )
        login_semantics = (
            bool(all_tokens & _LOGIN_TERMS)
            or any(_channel_has(route, channel, _LOGIN_TERMS) for channel in channels)
            or (bool(all_tokens & _SESSION_TERMS) and method == "POST")
        )
        is_session_creation = bool(
            method == "POST" and credential_pair and login_semantics
        )
        if is_session_creation:
            evidence = [
                "method:POST",
                "request_shape:identity_plus_secret_fields",
                "semantic_context:login_or_session_creation",
            ]
            for name in sorted(semantic_channels):
                evidence.append(f"semantic_source:{name}")
            if sets_cookie:
                evidence.append("response_metadata:sets_session_cookie")
            if response_token_fields:
                evidence.append("response_shape:credential_or_token_field")
            if credential_types_credible:
                evidence.append("request_shape:credential_field_types_scalar")
            else:
                evidence.append("request_shape:credential_field_types_ambiguous")
            type_limitations = (
                ()
                if credential_types_credible
                else (
                    "Credential field names and route semantics are strong, but one or more schema leaf types remain ambiguous.",
                )
            )
            creation = _boundary(
                route,
                "session_creation",
                semantics=(
                    "login_session_creation",
                    "credential_token_bearing_endpoint",
                    "rate_sensitive_authentication_operation",
                ),
                evidence=evidence,
                confidence="high",
                sources=sources,
                evidence_refs=refs,
                rate_sensitive=True,
                limitations=type_limitations,
            )
            discovered.append(creation)
            classified_routes.add(key)

        termination_semantics = bool(all_tokens & _TERMINATION_TERMS) or any(
            _channel_has(route, channel, _TERMINATION_TERMS) for channel in channels
        )
        current_session_delete = bool(
            method == "DELETE"
            and channels["path"] & _SESSION_TERMS
            and channels["path"] & {"current", "self"}
        )
        explicit_logout_channel = any(
            channels[channel] & {"logout", "signout", "signoff"}
            or _channel_has(route, channel, {"logout", "signout", "signoff"})
            for channel in ("path", "operation_id")
        )
        strong_termination_channel = (
            any(
                channels[channel] & _SESSION_TERMS
                and channels[channel] & _TERMINATION_TERMS
                for channel in ("path", "operation_id")
            )
            or explicit_logout_channel
        )
        termination_support = bool(
            auth_metadata
            or len(semantic_channels) >= 2
            or strong_termination_channel
            or current_session_delete
        )
        is_session_termination = bool(
            method in {"DELETE", "POST"}
            and (termination_semantics or current_session_delete)
            and termination_support
        )
        if is_session_termination:
            evidence = [
                f"method:{method}",
                "semantic_context:session_termination",
            ]
            if auth_headers:
                evidence.append("header_parameter:authorization_or_session")
            if security_declared:
                evidence.append("openapi_security:declared")
            if len(semantic_channels) >= 2:
                evidence.append("semantic_context:corroborated_metadata_fields")
            discovered.append(
                _boundary(
                    route,
                    "session_termination",
                    semantics=("logout_session_invalidation",),
                    evidence=evidence,
                    confidence="high" if auth_metadata else "medium",
                    sources=sources,
                    evidence_refs=refs,
                )
            )
            classified_routes.add(key)

        excluded_recovery_domain = bool(
            all_tokens & _NON_ACCOUNT_RECOVERY_TERMS
        ) and not bool(
            all_tokens
            & (
                _RECOVERY_SUBJECTS
                | _LOGIN_TERMS
                | {"auth", "authentication", "mfa", "otp"}
            )
        )
        recovery_base = (
            bool(all_tokens & _RECOVERY_TERMS)
            and bool(all_tokens & _RECOVERY_SUBJECTS)
            and not excluded_recovery_domain
        )
        if (
            "recovery" in all_tokens
            and (
                secret_fields
                or identity_fields
                or request_fields & _VERIFICATION_FIELDS
            )
            and not excluded_recovery_domain
        ):
            recovery_base = True
        start_semantics = bool(all_tokens & _START_TERMS)
        complete_semantics = bool(all_tokens & _COMPLETE_TERMS)
        verification_fields = request_fields & _VERIFICATION_FIELDS
        new_secret_field = bool(
            secret_fields & {"new_password", "password", "passphrase"}
        )
        is_recovery_completion = bool(
            method == "POST"
            and recovery_base
            and complete_semantics
            and bool(verification_fields or new_secret_field)
        )
        is_recovery_start = bool(
            method == "POST"
            and recovery_base
            and start_semantics
            and bool(identity_fields)
            and not is_recovery_completion
        )
        if is_recovery_start:
            evidence = [
                "method:POST",
                "semantic_context:account_or_password_recovery",
                "workflow_phase:start_or_request",
            ]
            if identity_fields:
                evidence.append("request_shape:account_identity_field")
            recovery_start_boundary = _boundary(
                route,
                "recovery_start",
                semantics=("account_recovery_start",),
                evidence=evidence,
                confidence="high",
                sources=sources,
                evidence_refs=refs,
            )
            recovery_start_boundary["identity_fields"] = sorted(identity_fields)
            discovered.append(recovery_start_boundary)
            classified_routes.add(key)
        if is_recovery_completion:
            evidence = [
                "method:POST",
                "semantic_context:account_or_password_recovery",
                "workflow_phase:completion_or_verification",
            ]
            if verification_fields:
                evidence.append("request_shape:verification_artifact_field")
            if new_secret_field:
                evidence.append("request_shape:new_secret_field")
            discovered.append(
                _boundary(
                    route,
                    "recovery_completion",
                    semantics=(
                        "account_recovery_completion",
                        "credential_token_bearing_endpoint",
                        "rate_sensitive_authentication_operation",
                    ),
                    evidence=evidence,
                    confidence=(
                        "high" if verification_fields or new_secret_field else "medium"
                    ),
                    sources=sources,
                    evidence_refs=refs,
                    rate_sensitive=True,
                )
            )
            classified_routes.add(key)

        one_time_verification = bool(
            method == "POST"
            and complete_semantics
            and request_fields & _ONE_TIME_VERIFICATION_FIELDS
            and all_tokens & _ONE_TIME_AUTH_CONTEXT_TERMS
            and not is_recovery_completion
            and not is_session_creation
        )
        if one_time_verification:
            discovered.append(
                _boundary(
                    route,
                    "credential_submission",
                    semantics=(
                        "one_time_code_verification",
                        "rate_sensitive_authentication_operation",
                    ),
                    evidence=(
                        "method:POST",
                        "semantic_context:authentication_one_time_code_verification",
                        "request_shape:one_time_verification_artifact_field",
                    ),
                    confidence="high",
                    sources=sources,
                    evidence_refs=refs,
                    rate_sensitive=True,
                    limitations=(
                        "One-time-code semantics do not establish whether runtime throttling is configured or effective.",
                    ),
                )
            )
            classified_routes.add(key)

        auth_token_context = bool(all_tokens & _AUTH_CONTEXT_TERMS)
        token_credentials = request_fields & _TOKEN_CREDENTIAL_FIELDS
        if (
            method == "POST"
            and (token_credentials or response_token_fields or sets_cookie)
            and auth_token_context
            and not any(
                item.get("boundary_type") == "credential_submission"
                and item.get("method") == method
                and item.get("path") == path
                for item in discovered
            )
        ):
            discovered.append(
                _boundary(
                    route,
                    "credential_submission",
                    semantics=(
                        "credential_token_bearing_endpoint",
                        "rate_sensitive_authentication_operation",
                    ),
                    evidence=(
                        "method:POST",
                        "semantic_context:authentication_token_operation",
                        (
                            "request_shape:credential_or_token_field"
                            if token_credentials
                            else "response_metadata:credential_or_session_material"
                        ),
                    ),
                    confidence="medium",
                    sources=sources,
                    evidence_refs=refs,
                    rate_sensitive=True,
                )
            )
            classified_routes.add(key)

        protected_candidate = bool(
            auth_metadata
            and not (
                is_session_creation
                or is_session_termination
                or is_recovery_start
                or is_recovery_completion
                or one_time_verification
            )
        )
        if protected_candidate:
            current_user = current_user_context
            evidence = []
            if security_declared:
                evidence.append("openapi_security:declared")
            if auth_headers:
                evidence.append("header_parameter:authorization_or_session")
            if explicit_auth_observation:
                evidence.append("authenticated_request_metadata:observed")
            if response_auth_signal:
                evidence.append("response_metadata:authentication_status_documented")
            if current_user:
                evidence.append("semantic_context:current_user_or_profile")
            discovered.append(
                _boundary(
                    route,
                    "authenticated_resource",
                    semantics=(
                        "protected_authenticated_resource",
                        *(["current_user_resource"] if current_user else []),
                    ),
                    evidence=evidence,
                    confidence="high" if security_declared else "medium",
                    sources=sources,
                    evidence_refs=refs,
                    limitations=(
                        (
                            "Authorization or session header presence is evidence of intended use, not proof that the server enforces it.",
                        )
                        if auth_headers
                        else ()
                    ),
                )
            )
            classified_routes.add(key)

    for existing in existing_list:
        method = str(existing.get("method") or "GET").upper()
        path = str(existing.get("path") or "/")
        key = (method, path)
        declared_type = str(existing.get("boundary_type") or "")
        if declared_type in AUTH_BOUNDARY_TYPES:
            route = next(
                (
                    item
                    for item in route_list
                    if str(item.get("method") or "GET").upper() == method
                    and str(item.get("path") or "/") == path
                ),
                existing,
            )
            discovered.append(
                _boundary(
                    route,
                    declared_type,
                    semantics=existing.get("semantic_classes") or (declared_type,),
                    evidence=existing.get("evidence")
                    or ("normalized_auth_boundary:observed",),
                    confidence=str(existing.get("confidence") or "medium"),
                    sources=existing.get("evidence_sources")
                    or (existing.get("source") or "normalized_route_evidence",),
                    evidence_refs=existing.get("evidence_refs") or (),
                    rate_sensitive=bool(existing.get("rate_sensitive_candidate")),
                    limitations=existing.get("limitations") or (),
                )
            )
            continue
        if key in classified_routes:
            continue
        discovered.append(
            _boundary(
                existing,
                "authenticated_resource",
                semantics=("protected_authenticated_resource",),
                evidence=("normalized_auth_boundary:observed",),
                confidence=str(existing.get("confidence") or "medium"),
                sources=(existing.get("source") or "normalized_route_evidence",),
                evidence_refs=existing.get("evidence_refs") or (),
            )
        )

    # A security-derived boundary may exist without a separately normalized route.
    for key in sorted(set(existing_by_route) - route_keys):
        if key in classified_routes:
            continue
        existing = existing_by_route[key][0]
        discovered.append(
            _boundary(
                existing,
                "authenticated_resource",
                semantics=("protected_authenticated_resource",),
                evidence=("normalized_auth_boundary:observed",),
                confidence=str(existing.get("confidence") or "medium"),
                sources=(existing.get("source") or "normalized_route_evidence",),
                evidence_refs=existing.get("evidence_refs") or (),
            )
        )

    normalized = _merge_boundaries(discovered)
    return normalized, _correlate_workflows(normalized)
