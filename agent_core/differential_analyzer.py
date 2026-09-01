"""Secret-safe deterministic response and state differential analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable

from agent_core.phase2_result_status import (
    SERVICE_UNSTABLE_REASON,
    assess_response_instability,
)

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "session",
    "api_key",
}
DEFAULT_PROTECTED_FIELDS = {
    "account_id",
    "accountid",
    "balance",
    "credit_limit",
    "email",
    "owner_id",
    "role",
    "ssn",
    "tenant_id",
    "user_id",
    "userid",
}
SUCCESS = {200, 201, 202, 204}
DENIAL = {401, 403, 404}
MAX_PROTECTED_PATH_DEPTH = 20
MAX_PROTECTED_LIST_ITEMS = 20


@dataclass(frozen=True)
class _SelectorSegment:
    name: str
    iterate: bool = False


@dataclass(frozen=True)
class _ProtectedSelector:
    canonical: str
    segments: tuple[_SelectorSegment, ...]
    qualified: bool


@dataclass(frozen=True)
class _EvidenceSummary:
    value_hash: str
    item_count: int


@dataclass
class _ProtectedExtraction:
    selectors: tuple[_ProtectedSelector, ...]
    configuration_valid: bool
    values: dict[str, _EvidenceSummary]
    selector_paths: dict[str, tuple[str, ...]]
    complete_selectors: set[str]


@dataclass(frozen=True)
class _EvidenceComparison:
    matching_paths: tuple[str, ...]
    value_hash_match: bool
    item_count_match: bool
    protected_evidence_matched: bool


def _parse_body(body: Any) -> Any:
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    if isinstance(body, str):
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            return body
    return body


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in sorted(value.items()):
            path = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            output.update(_flatten(item, f"{prefix}[]" if prefix else "[]"))
            if index >= 19:
                break
    else:
        output[prefix] = value
    return output


def _normalized_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")


def _parse_protected_selector(value: Any) -> _ProtectedSelector | None:
    if type(value) is not str:
        return None
    raw = value.strip()
    if not raw:
        return None
    rendered: list[list[Any]] = []
    for part in raw.split("."):
        if part == "*":
            if not rendered or rendered[-1][1]:
                return None
            rendered[-1][1] = True
            continue
        iterate = part.endswith("[]")
        name = part[:-2] if iterate else part
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            return None
        rendered.append([_normalized_key(name), iterate])
    if not rendered or len(rendered) > MAX_PROTECTED_PATH_DEPTH:
        return None
    segments = tuple(
        _SelectorSegment(str(name), bool(iterate)) for name, iterate in rendered
    )
    canonical = ".".join(
        f"{segment.name}[]" if segment.iterate else segment.name for segment in segments
    )
    return _ProtectedSelector(
        canonical=canonical,
        segments=segments,
        qualified=len(segments) > 1 or any(segment.iterate for segment in segments),
    )


def normalize_protected_field_path(value: str) -> str:
    """Validate and canonicalize one bounded protected-evidence selector."""

    selector = _parse_protected_selector(value)
    if selector is None:
        raise ValueError("invalid protected field path")
    return selector.canonical


def _prepare_protected_selectors(
    protected_fields: Iterable[str],
) -> tuple[tuple[_ProtectedSelector, ...], bool]:
    if isinstance(protected_fields, str):
        protected_fields = [protected_fields]
    selectors: dict[str, _ProtectedSelector] = {}
    configuration_valid = True
    for item in protected_fields:
        selector = _parse_protected_selector(item)
        if selector is None:
            configuration_valid = False
            continue
        selectors.setdefault(selector.canonical, selector)
    return tuple(selectors[path] for path in sorted(selectors)), configuration_valid


def _resolve_exact_selector(
    value: Any, selector: _ProtectedSelector
) -> tuple[tuple[Any, ...], bool]:
    nodes: tuple[Any, ...] = (value,)
    for segment in selector.segments:
        selected: list[Any] = []
        for node in nodes:
            if not isinstance(node, dict):
                return (), False
            matches = [
                item
                for key, item in node.items()
                if _normalized_key(key) == segment.name
            ]
            if len(matches) != 1:
                return (), False
            child = matches[0]
            if segment.iterate:
                if not isinstance(child, list):
                    return (), False
                if len(child) > MAX_PROTECTED_LIST_ITEMS:
                    return (), False
                selected.extend(child)
            else:
                selected.append(child)
        nodes = tuple(selected)
    return nodes, True


def _extract_selector_values(value: Any, selector: str) -> tuple[Any, ...] | None:
    """Resolve one exact selector for internal use without expression evaluation."""
    parsed = _parse_protected_selector(selector)
    if parsed is None:
        return None
    values, complete = _resolve_exact_selector(value, parsed)
    return values if complete else None


def _collect_unqualified_values(
    value: Any,
    target: str,
    *,
    prefix: str = "",
    depth: int = 0,
) -> tuple[dict[str, list[Any]], bool]:
    if depth > MAX_PROTECTED_PATH_DEPTH:
        return {}, False
    output: dict[str, list[Any]] = {}
    complete = True
    if isinstance(value, dict):
        target_keys = [key for key in value if _normalized_key(key) == target]
        if len(target_keys) > 1:
            complete = False
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            rendered_key = _normalized_key(key)
            path = f"{prefix}.{rendered_key}" if prefix else rendered_key
            if rendered_key == target and len(target_keys) == 1:
                output.setdefault(path, []).append(item)
            nested, nested_complete = _collect_unqualified_values(
                item,
                target,
                prefix=path,
                depth=depth + 1,
            )
            complete = complete and nested_complete
            for nested_path, nested_values in nested.items():
                output.setdefault(nested_path, []).extend(nested_values)
    elif isinstance(value, list):
        if len(value) > MAX_PROTECTED_LIST_ITEMS:
            complete = False
        path = f"{prefix}[]" if prefix else "[]"
        for item in value[:MAX_PROTECTED_LIST_ITEMS]:
            nested, nested_complete = _collect_unqualified_values(
                item,
                target,
                prefix=path,
                depth=depth + 1,
            )
            complete = complete and nested_complete
            for nested_path, nested_values in nested.items():
                output.setdefault(nested_path, []).extend(nested_values)
    return output, complete


def _contains_evidence(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, bytes):
        return bool(value)
    if isinstance(value, dict):
        return any(_contains_evidence(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_evidence(item) for item in value)
    return True


def _extract_protected_evidence(
    value: Any,
    selectors: tuple[_ProtectedSelector, ...],
    *,
    configuration_valid: bool,
) -> _ProtectedExtraction:
    summaries: dict[str, _EvidenceSummary] = {}
    selector_paths: dict[str, tuple[str, ...]] = {}
    complete_selectors: set[str] = set()
    for selector in selectors:
        if selector.qualified:
            values, complete = _resolve_exact_selector(value, selector)
            collected = {selector.canonical: list(values)}
        else:
            collected, complete = _collect_unqualified_values(
                value, selector.segments[0].name
            )
        evidence_paths: list[str] = []
        if complete:
            for path, extracted in sorted(collected.items()):
                if not extracted or not all(
                    _contains_evidence(item) for item in extracted
                ):
                    continue
                summaries[path] = _EvidenceSummary(
                    value_hash=_hash(extracted),
                    item_count=len(extracted),
                )
                evidence_paths.append(path)
        selector_paths[selector.canonical] = tuple(evidence_paths)
        if evidence_paths:
            complete_selectors.add(selector.canonical)
    return _ProtectedExtraction(
        selectors=selectors,
        configuration_valid=configuration_valid,
        values=summaries,
        selector_paths=selector_paths,
        complete_selectors=complete_selectors,
    )


def _compare_protected_evidence(
    privileged: _ProtectedExtraction,
    lower: _ProtectedExtraction,
    *,
    require_all_selectors: bool,
) -> _EvidenceComparison:
    configured = {selector.canonical for selector in privileged.selectors}
    required = (
        configured if require_all_selectors else set(privileged.complete_selectors)
    )
    configurations_match = bool(
        required
        and privileged.configuration_valid
        and lower.configuration_valid
        and configured == {selector.canonical for selector in lower.selectors}
    )
    selectors_complete = bool(
        configurations_match
        and required <= privileged.complete_selectors
        and required <= lower.complete_selectors
    )
    paths_match = bool(
        selectors_complete
        and all(
            privileged.selector_paths.get(selector)
            == lower.selector_paths.get(selector)
            for selector in required
        )
    )
    required_paths = {
        path
        for selector in required
        for path in privileged.selector_paths.get(selector, ())
    }
    common_paths = required_paths & set(lower.values)
    matching_paths = tuple(
        sorted(
            path
            for path in common_paths
            if privileged.values[path].item_count == lower.values[path].item_count
            and privileged.values[path].value_hash == lower.values[path].value_hash
        )
    )
    item_count_match = bool(
        paths_match
        and all(
            privileged.values[path].item_count == lower.values[path].item_count
            for path in required_paths
        )
    )
    value_hash_match = bool(
        paths_match
        and all(
            privileged.values[path].value_hash == lower.values[path].value_hash
            for path in required_paths
        )
    )
    return _EvidenceComparison(
        matching_paths=matching_paths,
        value_hash_match=value_hash_match,
        item_count_match=item_count_match,
        protected_evidence_matched=value_hash_match and item_count_match,
    )


def _safe_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _safe_shape(item)
            for key, item in sorted(value.items())
            if key.lower() not in SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [_safe_shape(item) for item in value[:20]]
    return type(value).__name__


def _hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()


def response_summary(response: dict[str, Any]) -> dict[str, Any]:
    body = _parse_body(response.get("body"))
    flattened = _flatten(body)
    return {
        "status_code": response.get("status_code"),
        "status_class": (
            int(response["status_code"]) // 100
            if isinstance(response.get("status_code"), int)
            else None
        ),
        "schema_fields": sorted(flattened)[:500],
        "structure_hash": _hash(_safe_shape(body)),
        "body_hash": _hash(body),
        "error_semantics": sorted(
            path
            for path in flattened
            if path.lower().split(".")[-1] in {"error", "errors", "message", "code"}
        ),
    }


def analyze_cross_account_access(
    owner_response: dict[str, Any],
    non_owner_response: dict[str, Any],
    *,
    object_identifier: str | None,
    ownership_confirmed: bool,
    separate_accounts_confirmed: bool,
    protected_fields: Iterable[str] | None = None,
    protected_data_confirmed: bool = False,
    tenant_identifier: str | None = None,
    distinct_tenants_confirmed: bool = False,
    tenant_isolation: bool = False,
) -> dict[str, Any]:
    owner = response_summary(owner_response)
    candidate = response_summary(non_owner_response)
    instability = assess_response_instability([owner_response, non_owner_response])
    owner_body = _parse_body(owner_response.get("body"))
    candidate_body = _parse_body(non_owner_response.get("body"))
    owner_flat = _flatten(owner_body)
    candidate_flat = _flatten(candidate_body)
    tenant_identity_fields = {"tenant_id", "organization_id", "org_id"}
    configured_fields = (
        DEFAULT_PROTECTED_FIELDS if protected_fields is None else protected_fields
    )
    selectors, configuration_valid = _prepare_protected_selectors(configured_fields)
    if tenant_isolation:
        selectors = tuple(
            selector
            for selector in selectors
            if selector.segments[-1].name not in tenant_identity_fields
        )
    owner_evidence = _extract_protected_evidence(
        owner_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    candidate_evidence = _extract_protected_evidence(
        candidate_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    protected_comparison = _compare_protected_evidence(
        owner_evidence,
        candidate_evidence,
        require_all_selectors=protected_fields is not None,
    )
    configured = {selector.canonical for selector in selectors}
    required = (
        configured
        if protected_fields is not None
        else set(owner_evidence.complete_selectors)
    )
    owner_fields_complete = bool(
        required
        and configuration_valid
        and required <= owner_evidence.complete_selectors
    )
    candidate_fields_complete = bool(
        required
        and configuration_valid
        and required <= candidate_evidence.complete_selectors
    )
    owner_protected_paths = sorted(owner_evidence.values)
    protected_paths = sorted(candidate_evidence.values)
    candidate_status = candidate["status_code"]
    owner_status = owner["status_code"]
    identity_fields = {"id", "object_id", "account_id", "order_id", "project_id"}
    if tenant_isolation:
        identity_fields |= tenant_identity_fields

    def identity_matches(flattened: dict[str, Any]) -> bool:
        if type(object_identifier) is not str or not object_identifier:
            return False
        return any(
            type(value) is str and value == object_identifier
            for path, value in flattened.items()
            if path.lower().split(".")[-1].replace("-", "_") in identity_fields
        )

    owner_object_match = identity_matches(owner_flat)
    object_match = identity_matches(candidate_flat)

    def tenant_identity_matches(flattened: dict[str, Any]) -> bool:
        if type(tenant_identifier) is not str or not tenant_identifier:
            return False
        return any(
            type(value) is str and value == tenant_identifier
            for path, value in flattened.items()
            if path.lower().split(".")[-1].replace("-", "_") in tenant_identity_fields
        )

    owner_tenant_match = tenant_identity_matches(owner_flat)
    candidate_tenant_match = tenant_identity_matches(candidate_flat)
    matching_protected_paths = list(protected_comparison.matching_paths)
    owner_baseline_established = bool(
        owner_status in SUCCESS
        and ownership_confirmed is True
        and separate_accounts_confirmed is True
        and type(object_identifier) is str
        and bool(object_identifier)
        and owner_object_match
        and owner_fields_complete
        and (
            not tenant_isolation
            or (distinct_tenants_confirmed is True and owner_tenant_match)
        )
    )
    verified = bool(
        owner_baseline_established
        and candidate_status in SUCCESS
        and object_match
        and candidate_fields_complete
        and protected_comparison.protected_evidence_matched
        and (not tenant_isolation or candidate_tenant_match)
    )
    rejected = bool(owner_baseline_established and candidate_status in DENIAL)
    if instability.unstable:
        verified = False
        rejected = False
        status = "inconclusive"
        reasons = [instability.reason or SERVICE_UNSTABLE_REASON]
    elif verified:
        status = "verified"
        reasons = [
            "A distinct controlled non-owner received the confirmed owner's object identity and protected data."
        ]
    elif rejected:
        status = "rejected"
        reasons = [
            "A valid protected owner baseline was established and the controlled non-owner was denied."
        ]
    elif not owner_baseline_established:
        status = "inconclusive"
        reasons = [
            "A successful owner response with exact object identity and all configured protected evidence was not established."
        ]
    else:
        status = "inconclusive"
        reasons = [
            "Status equality or public/sanitized response similarity is insufficient without concrete protected-data and object-identity evidence."
        ]
    return {
        "status": status,
        "verified": verified,
        "confidence": ("high" if verified else "medium" if rejected else "low"),
        "owner": owner,
        "non_owner": candidate,
        "owner_protected_field_paths": owner_protected_paths,
        "protected_field_paths": protected_paths,
        "matching_protected_field_paths": matching_protected_paths,
        "value_hash_match": protected_comparison.value_hash_match,
        "item_count_match": protected_comparison.item_count_match,
        "object_identity_matched": object_match,
        "owner_object_identity_matched": owner_object_match,
        "owner_tenant_identity_matched": owner_tenant_match,
        "tenant_identity_matched": candidate_tenant_match,
        "owner_baseline_established": owner_baseline_established,
        "ownership_confirmed": ownership_confirmed,
        "separate_accounts_confirmed": separate_accounts_confirmed,
        "distinct_tenants_confirmed": distinct_tenants_confirmed,
        "protected_data_confirmed": protected_data_confirmed,
        "protected_evidence_matched": protected_comparison.protected_evidence_matched,
        "body_structure_equal": owner["structure_hash"] == candidate["structure_hash"],
        "reasons": reasons,
    }


def analyze_authentication_enforcement(
    authenticated_response: dict[str, Any],
    unauthenticated_response: dict[str, Any],
    *,
    protected_fields: Iterable[str] | None = None,
    protected_functionality_confirmed: bool = False,
) -> dict[str, Any]:
    auth = response_summary(authenticated_response)
    unauth = response_summary(unauthenticated_response)
    instability = assess_response_instability(
        [authenticated_response, unauthenticated_response]
    )
    auth_body = _parse_body(authenticated_response.get("body"))
    unauth_body = _parse_body(unauthenticated_response.get("body"))
    configured_fields = (
        DEFAULT_PROTECTED_FIELDS if protected_fields is None else protected_fields
    )
    selectors, configuration_valid = _prepare_protected_selectors(configured_fields)
    authenticated_evidence = _extract_protected_evidence(
        auth_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    unauthenticated_evidence = _extract_protected_evidence(
        unauth_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    comparison = _compare_protected_evidence(
        authenticated_evidence,
        unauthenticated_evidence,
        require_all_selectors=True,
    )
    configured = {selector.canonical for selector in selectors}
    authenticated_paths = sorted(authenticated_evidence.values)
    unauthenticated_paths = sorted(unauthenticated_evidence.values)
    authenticated_baseline_established = bool(
        auth["status_code"] in SUCCESS
        and configured
        and configuration_valid
        and configured <= authenticated_evidence.complete_selectors
    )
    verified = bool(
        authenticated_baseline_established
        and unauth["status_code"] in SUCCESS
        and comparison.protected_evidence_matched
    )
    secure_denial = bool(
        authenticated_baseline_established and unauth["status_code"] in DENIAL
    )
    secure_sanitized_response = bool(
        authenticated_baseline_established
        and unauth["status_code"] in SUCCESS
        and not unauthenticated_paths
    )
    rejected = secure_denial
    if instability.unstable:
        verified = False
        rejected = False
        reasons = [instability.reason or SERVICE_UNSTABLE_REASON]
    elif verified:
        reasons = [
            "The unauthenticated response exposed protected evidence equivalent to the authenticated baseline."
        ]
    elif not authenticated_baseline_established:
        reasons = [
            (
                "The authenticated request was denied, so no valid protected baseline was established."
                if auth["status_code"] in DENIAL
                else "Configured protected evidence was absent from the authenticated response."
            )
        ]
    elif secure_denial:
        reasons = [
            "The authenticated protected baseline succeeded and the unauthenticated comparison was denied."
        ]
    elif secure_sanitized_response:
        reasons = [
            "The unauthenticated response was successful but lacked configured protected evidence; a successful sanitized response is not a demonstrated authorization denial."
        ]
    else:
        reasons = [
            "The comparison did not provide sufficient equivalent protected evidence for a vulnerability classification."
        ]
    return {
        "status": (
            "verified" if verified else "rejected" if rejected else "inconclusive"
        ),
        "verified": verified,
        "confidence": "high" if verified else "medium" if rejected else "low",
        "authenticated": auth,
        "unauthenticated": unauth,
        "authenticated_protected_field_paths": authenticated_paths,
        "protected_field_paths": unauthenticated_paths,
        "matching_protected_field_paths": list(comparison.matching_paths),
        "value_hash_match": comparison.value_hash_match,
        "item_count_match": comparison.item_count_match,
        "protected_evidence_matched": comparison.protected_evidence_matched,
        "authenticated_baseline_established": authenticated_baseline_established,
        "protected_functionality_confirmed": protected_functionality_confirmed,
        "reasons": reasons,
    }


def analyze_session_invalidation(
    baseline_response: dict[str, Any],
    replay_response: dict[str, Any],
    *,
    protected_fields: Iterable[str],
    protected_data_confirmed: bool,
    termination_succeeded: bool,
) -> dict[str, Any]:
    """Classify only configured protected evidence across one same-session replay."""
    baseline = response_summary(baseline_response)
    replay = response_summary(replay_response)
    instability = assess_response_instability([baseline_response, replay_response])
    selectors, configuration_valid = _prepare_protected_selectors(protected_fields)
    configured = {selector.canonical for selector in selectors}
    baseline_evidence = _extract_protected_evidence(
        _parse_body(baseline_response.get("body")),
        selectors,
        configuration_valid=configuration_valid,
    )
    replay_evidence = _extract_protected_evidence(
        _parse_body(replay_response.get("body")),
        selectors,
        configuration_valid=configuration_valid,
    )
    comparison = _compare_protected_evidence(
        baseline_evidence,
        replay_evidence,
        require_all_selectors=True,
    )
    baseline_complete = bool(
        configured
        and configuration_valid
        and configured <= baseline_evidence.complete_selectors
    )
    baseline_established = bool(
        isinstance(baseline.get("status_code"), int)
        and 200 <= int(baseline["status_code"]) < 300
        and protected_data_confirmed is True
        and baseline_complete
    )
    replay_complete = bool(
        configured
        and configuration_valid
        and configured <= replay_evidence.complete_selectors
    )
    replay_status = replay.get("status_code")
    replay_success = bool(isinstance(replay_status, int) and 200 <= replay_status < 300)
    verified = bool(
        baseline_established
        and termination_succeeded is True
        and replay_success
        and replay_complete
        and comparison.protected_evidence_matched
    )
    secure_denial = bool(
        baseline_established
        and termination_succeeded is True
        and replay_status in DENIAL
        and not replay_evidence.values
    )
    if instability.unstable:
        verified = False
        secure_denial = False
        status = "inconclusive"
        reasons = [instability.reason or SERVICE_UNSTABLE_REASON]
    elif verified:
        status = "verified"
        reasons = [
            "The same previously issued session retained matching configured protected evidence after termination."
        ]
    elif secure_denial:
        status = "rejected"
        reasons = [
            "The authenticated baseline was established and the same terminated session was denied without configured protected evidence."
        ]
    elif not baseline_established:
        status = "inconclusive"
        reasons = [
            "A successful authenticated baseline with all configured protected evidence was not established."
        ]
    elif not termination_succeeded:
        status = "inconclusive"
        reasons = ["The configured session-termination operation did not succeed."]
    elif replay_success and not replay_complete:
        status = "inconclusive"
        reasons = [
            "The replay succeeded but did not contain all configured protected evidence."
        ]
    else:
        status = "inconclusive"
        reasons = [
            "The replay did not establish either a protected-data match or a protected-data-free authorization denial."
        ]
    return {
        "status": status,
        "verified": verified,
        "confidence": ("high" if verified else "medium" if secure_denial else "low"),
        "baseline": baseline,
        "replay": replay,
        "baseline_protected_field_paths": sorted(baseline_evidence.values),
        "protected_field_paths": sorted(replay_evidence.values),
        "matching_protected_field_paths": list(comparison.matching_paths),
        "protected_evidence_matched": comparison.protected_evidence_matched,
        "authenticated_baseline_established": baseline_established,
        "termination_succeeded": termination_succeeded,
        "reasons": reasons,
    }


def analyze_role_authorization(
    privileged_response: dict[str, Any],
    lower_role_response: dict[str, Any],
    *,
    separate_accounts_confirmed: bool = False,
    distinct_roles_confirmed: bool,
    protected_fields: Iterable[str] | None = None,
    protected_data_confirmed: bool = False,
    protected_functionality_confirmed: bool = False,
) -> dict[str, Any]:
    privileged = response_summary(privileged_response)
    lower = response_summary(lower_role_response)
    instability = assess_response_instability(
        [privileged_response, lower_role_response]
    )
    privileged_body = _parse_body(privileged_response.get("body"))
    lower_body = _parse_body(lower_role_response.get("body"))
    configured_fields = (
        DEFAULT_PROTECTED_FIELDS if protected_fields is None else protected_fields
    )
    selectors, configuration_valid = _prepare_protected_selectors(configured_fields)
    privileged_evidence = _extract_protected_evidence(
        privileged_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    lower_evidence = _extract_protected_evidence(
        lower_body,
        selectors,
        configuration_valid=configuration_valid,
    )
    comparison = _compare_protected_evidence(
        privileged_evidence,
        lower_evidence,
        require_all_selectors=protected_fields is not None,
    )
    configured = {selector.canonical for selector in selectors}
    required = (
        configured
        if protected_fields is not None
        else set(privileged_evidence.complete_selectors)
    )
    privileged_fields_complete = bool(
        required
        and configuration_valid
        and required <= privileged_evidence.complete_selectors
    )
    lower_fields_complete = bool(
        required
        and configuration_valid
        and required <= lower_evidence.complete_selectors
    )
    privileged_baseline_established = bool(
        privileged["status_code"] in SUCCESS
        and separate_accounts_confirmed is True
        and distinct_roles_confirmed is True
        and privileged_fields_complete
    )
    verified = bool(
        separate_accounts_confirmed is True
        and distinct_roles_confirmed is True
        and privileged_baseline_established
        and lower["status_code"] in SUCCESS
        and lower_fields_complete
        and comparison.protected_evidence_matched
    )
    secure_denial = bool(
        privileged_baseline_established and lower["status_code"] in DENIAL
    )
    rejected = secure_denial
    if instability.unstable:
        verified = False
        rejected = False
        reasons = [instability.reason or SERVICE_UNSTABLE_REASON]
    elif verified:
        reasons = [
            "A distinct lower-privileged controlled account received matching configured protected administrative data."
        ]
    elif rejected:
        reasons = [
            "A valid privileged baseline was established and the lower-privileged controlled account was denied."
        ]
    else:
        reasons = [
            "Successful responses alone are insufficient without a protected privileged baseline and matching configured protected data."
        ]
    return {
        "status": (
            "verified" if verified else "rejected" if rejected else "inconclusive"
        ),
        "verified": verified,
        "confidence": "high" if verified else "medium" if rejected else "low",
        "privileged": privileged,
        "lower_role": lower,
        "privileged_protected_field_paths": sorted(privileged_evidence.values),
        "protected_field_paths": sorted(lower_evidence.values),
        "matching_protected_field_paths": list(comparison.matching_paths),
        "value_hash_match": comparison.value_hash_match,
        "item_count_match": comparison.item_count_match,
        "protected_evidence_matched": comparison.protected_evidence_matched,
        "protected_data_confirmed": protected_data_confirmed,
        "privileged_baseline_established": privileged_baseline_established,
        "separate_accounts_confirmed": separate_accounts_confirmed,
        "distinct_roles_confirmed": distinct_roles_confirmed,
        "body_structure_equal": (
            privileged["structure_hash"] == lower["structure_hash"]
        ),
        "protected_functionality_confirmed": protected_functionality_confirmed,
        "reasons": reasons,
    }


def analyze_state_change(
    before_response: dict[str, Any],
    after_response: dict[str, Any],
    *,
    field: str,
    requested_value: Any,
    field_control_authorized: bool,
    cleanup_succeeded: bool,
) -> dict[str, Any]:
    before_body = _flatten(_parse_body(before_response.get("body")))
    after_body = _flatten(_parse_body(after_response.get("body")))
    matching_paths = [
        path for path in after_body if path.lower().split(".")[-1] == field.lower()
    ]
    persisted = any(after_body[path] == requested_value for path in matching_paths)
    changed = any(
        before_body.get(path) != after_body.get(path) for path in matching_paths
    )
    verified = bool(
        persisted and changed and not field_control_authorized and cleanup_succeeded
    )
    return {
        "status": (
            "verified" if verified else "rejected" if not persisted else "inconclusive"
        ),
        "verified": verified,
        "confidence": "high" if verified else "medium",
        "field": field,
        "field_paths": matching_paths,
        "persisted": persisted,
        "changed": changed,
        "cleanup_succeeded": cleanup_succeeded,
        "before": response_summary(before_response),
        "after": response_summary(after_response),
        "reasons": [
            (
                "An independent read confirmed unauthorized field persistence and cleanup succeeded."
                if verified
                else "Persistence, lack of authorization, independent read, and cleanup are all required."
            )
        ],
    }
