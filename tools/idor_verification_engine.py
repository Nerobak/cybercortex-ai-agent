from __future__ import annotations

import time
from copy import deepcopy
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from tools.authz_differential_tester import analyze_authorization_difference
from tools.raw_http_request_parser import parse_raw_http_request
from tools.request_replay_engine import replay_authorization_contexts
from tools.scope_guard import enforce_scope

MAX_IDENTIFIERS = 25
DEFAULT_DELAY_SECONDS = 0.25
DEFAULT_TIMEOUT_SECONDS = 15
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SUPPORTED_LOCATIONS = {"path", "query"}

AUTHORIZATION_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}


def _replace_exact_path_identifier(
    url: str,
    original_identifier: str,
    comparison_identifier: str,
) -> dict[str, Any]:
    parsed = urlparse(url)
    segments = parsed.path.split("/")
    encoded_original = quote(original_identifier, safe="")
    matches = [
        index
        for index, segment in enumerate(segments)
        if segment in {original_identifier, encoded_original}
    ]

    if not matches:
        return {
            "success": False,
            "error": (
                "The original identifier was not found as an exact URL " "path segment."
            ),
        }

    if len(matches) != 1:
        return {
            "success": False,
            "error": (
                "The original identifier appears more than once in the URL "
                "path. The object reference must be unambiguous."
            ),
        }

    segments[matches[0]] = quote(comparison_identifier, safe="")
    modified_url = urlunparse(parsed._replace(path="/".join(segments)))
    return {
        "success": True,
        "location": "path",
        "original_url": url,
        "modified_url": modified_url,
        "field": None,
    }


def _replace_exact_query_identifier(
    url: str,
    query_field: str,
    original_identifier: str,
    comparison_identifier: str,
) -> dict[str, Any]:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    matches = [
        index
        for index, (name, value) in enumerate(query_items)
        if name == query_field and value == original_identifier
    ]

    if not matches:
        return {
            "success": False,
            "error": (
                f"Query parameter {query_field!r} with the supplied "
                "original identifier was not found."
            ),
        }

    if len(matches) != 1:
        return {
            "success": False,
            "error": (
                "The selected query parameter and identifier appear more "
                "than once. The object reference must be unambiguous."
            ),
        }

    query_items[matches[0]] = (query_field, comparison_identifier)
    modified_url = urlunparse(parsed._replace(query=urlencode(query_items, doseq=True)))
    return {
        "success": True,
        "location": "query",
        "original_url": url,
        "modified_url": modified_url,
        "field": query_field,
    }


def _normalize_identifiers(
    identifiers: list[str | int],
    original_identifier: str,
) -> dict[str, Any]:
    normalized: list[str] = []

    for identifier in identifiers:
        value = str(identifier).strip()
        if value and value != original_identifier and value not in normalized:
            normalized.append(value)

    if not normalized:
        return {
            "success": False,
            "error": "At least one comparison identifier is required.",
        }

    if len(normalized) > MAX_IDENTIFIERS:
        return {
            "success": False,
            "error": (
                f"A maximum of {MAX_IDENTIFIERS} comparison identifiers "
                "may be tested in one run."
            ),
        }

    return {"success": True, "identifiers": normalized}


def build_controlled_idor_variant(
    url: str,
    original_identifier: str,
    comparison_identifier: str,
    location: str = "path",
    query_field: str | None = None,
) -> dict[str, Any]:
    """Build one exact, researcher-directed object-reference variation."""
    normalized_location = location.strip().lower()

    if normalized_location not in SUPPORTED_LOCATIONS:
        return {
            "success": False,
            "error": (
                "Unsupported identifier location. Supported locations: "
                + ", ".join(sorted(SUPPORTED_LOCATIONS))
            ),
        }

    if not original_identifier or not comparison_identifier:
        return {
            "success": False,
            "error": "Both original and comparison identifiers are required.",
        }

    if original_identifier == comparison_identifier:
        return {
            "success": False,
            "error": "The original and comparison identifiers must differ.",
        }

    original_scope = enforce_scope(url)
    if not original_scope.get("allowed"):
        return {
            "success": False,
            "error": original_scope.get(
                "error", "The target is outside the configured testing scope."
            ),
            "scope": original_scope,
        }

    if normalized_location == "path":
        result = _replace_exact_path_identifier(
            url, original_identifier, comparison_identifier
        )
    elif not query_field:
        return {
            "success": False,
            "error": "query_field is required when location is 'query'.",
        }
    else:
        result = _replace_exact_query_identifier(
            url, query_field, original_identifier, comparison_identifier
        )

    if not result.get("success"):
        return result

    modified_scope = enforce_scope(result["modified_url"])
    if not modified_scope.get("allowed"):
        return {
            "success": False,
            "error": "The modified request URL is outside the configured scope.",
            "scope": modified_scope,
        }

    return {
        **result,
        "scope": modified_scope,
        "original_identifier": original_identifier,
        "comparison_identifier": comparison_identifier,
    }


def _common_headers(parsed_request: dict[str, Any]) -> dict[str, str]:
    excluded = AUTHORIZATION_HEADERS | {"host", "content-length"}
    return {
        name: value
        for name, value in parsed_request.get("headers", {}).items()
        if name.lower() not in excluded
    }


def _orient_responses(
    replay: dict[str, Any],
    identifier: str,
    account_a_owned_ids: set[str],
    account_b_owned_ids: set[str],
) -> dict[str, Any]:
    owned_by_a = identifier in account_a_owned_ids
    owned_by_b = identifier in account_b_owned_ids

    if owned_by_a and not owned_by_b:
        return {
            "owner_account": "A",
            "candidate_account": "B",
            "baseline": replay["account_a"]["response"],
            "candidate": replay["account_b"]["response"],
            "ownership_confirmed": True,
        }

    if owned_by_b and not owned_by_a:
        return {
            "owner_account": "B",
            "candidate_account": "A",
            "baseline": replay["account_b"]["response"],
            "candidate": replay["account_a"]["response"],
            "ownership_confirmed": True,
        }

    return {
        "owner_account": None,
        "candidate_account": None,
        "baseline": replay["account_a"]["response"],
        "candidate": replay["account_b"]["response"],
        "ownership_confirmed": False,
    }


def scan_controlled_idor(
    raw_request: str,
    account_a_headers: dict[str, str],
    account_b_headers: dict[str, str],
    original_identifier: str,
    comparison_identifiers: list[str | int],
    location: str = "path",
    query_field: str | None = None,
    default_scheme: str = "https",
    account_a_owned_ids: set[str] | None = None,
    account_b_owned_ids: set[str] | None = None,
    separate_accounts_confirmed: bool = False,
    delay_seconds: float = DEFAULT_DELAY_SECONDS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Batch-check up to 25 explicitly supplied IDs using two accounts.

    IDs are never generated or discovered. Only safe, read-only methods are
    replayed, and every generated URL is checked against configured scope.
    Declared ownership determines which response is the authorized baseline.
    """
    if not isinstance(comparison_identifiers, list):
        return {"success": False, "error": "comparison_identifiers must be a list."}

    normalized_original = str(original_identifier).strip()
    if not normalized_original:
        return {"success": False, "error": "The original identifier is required."}

    identifier_result = _normalize_identifiers(
        comparison_identifiers, normalized_original
    )
    if not identifier_result["success"]:
        return identifier_result

    if not account_a_headers or not account_b_headers:
        return {
            "success": False,
            "error": "Authorization headers for both accounts are required.",
        }

    if delay_seconds < 0 or timeout_seconds <= 0:
        return {
            "success": False,
            "error": "delay_seconds cannot be negative and timeout_seconds must be positive.",
        }

    parsed_request = parse_raw_http_request(raw_request, default_scheme)
    if not parsed_request.get("success"):
        return {
            "success": False,
            "error": parsed_request.get(
                "error", "The raw request could not be parsed."
            ),
        }

    method = str(parsed_request.get("method", "")).upper()
    original_url = parsed_request.get("url")
    if method not in SAFE_METHODS:
        return {
            "success": False,
            "error": (
                f"Method {method or '<missing>'} is not supported. Allowed methods: "
                + ", ".join(sorted(SAFE_METHODS))
            ),
        }

    if not original_url:
        return {"success": False, "error": "The parsed request has no URL."}

    owned_by_a = {str(value) for value in (account_a_owned_ids or set())}
    owned_by_b = {str(value) for value in (account_b_owned_ids or set())}
    common_headers = _common_headers(parsed_request)
    results: list[dict[str, Any]] = []

    for index, identifier in enumerate(identifier_result["identifiers"]):
        variant = build_controlled_idor_variant(
            url=original_url,
            original_identifier=normalized_original,
            comparison_identifier=identifier,
            location=location,
            query_field=query_field,
        )
        if not variant.get("success"):
            results.append({"identifier": identifier, **variant})
            continue

        replay = replay_authorization_contexts(
            url=variant["modified_url"],
            method=method,
            account_a_headers=account_a_headers,
            account_b_headers=account_b_headers,
            common_headers=common_headers,
            object_identifier=identifier,
            ownership_confirmed=False,
            separate_accounts_confirmed=separate_accounts_confirmed,
            timeout_seconds=timeout_seconds,
            verify_tls=verify_tls,
        )
        if not replay.get("success"):
            results.append(
                {
                    "identifier": identifier,
                    "url": variant["modified_url"],
                    "success": False,
                    "error": replay.get("error", "Request replay failed."),
                    "replay": replay,
                }
            )
        else:
            oriented = _orient_responses(replay, identifier, owned_by_a, owned_by_b)
            analysis = analyze_authorization_difference(
                baseline_response=oriented["baseline"],
                candidate_response=oriented["candidate"],
                endpoint=urlparse(variant["modified_url"]).path or "/",
                method=method,
                object_identifier=identifier,
                ownership_confirmed=oriented["ownership_confirmed"],
                separate_accounts_confirmed=separate_accounts_confirmed,
            )
            finding = deepcopy(analysis.get("finding", {}))
            if finding:
                finding.setdefault("metadata", {}).update(
                    {
                        "idor_test": True,
                        "batch_test": True,
                        "identifier_location": location.strip().lower(),
                        "query_field": query_field,
                        "original_identifier": normalized_original,
                        "comparison_identifier": identifier,
                        "owner_account": oriented["owner_account"],
                        "candidate_account": oriented["candidate_account"],
                        "original_url": original_url,
                        "modified_url": variant["modified_url"],
                    }
                )
                if finding.get("status") == "verified":
                    finding["title"] = "Possible insecure direct object reference"

            results.append(
                {
                    "identifier": identifier,
                    "url": variant["modified_url"],
                    "success": True,
                    "owned_by_account_a": identifier in owned_by_a,
                    "owned_by_account_b": identifier in owned_by_b,
                    "owner_account": oriented["owner_account"],
                    "candidate_account": oriented["candidate_account"],
                    "account_a_status": replay["account_a"]["response"]["status_code"],
                    "account_b_status": replay["account_b"]["response"]["status_code"],
                    "finding": finding,
                    "analysis": analysis,
                    "replay": replay,
                }
            )

        if delay_seconds > 0 and index < len(identifier_result["identifiers"]) - 1:
            time.sleep(delay_seconds)

    return {
        "success": True,
        "original_request": {
            "method": method,
            "url": original_url,
            "identifier": normalized_original,
        },
        "summary": {
            "identifiers_tested": len(results),
            "verified_findings": sum(
                item.get("finding", {}).get("status") == "verified" for item in results
            ),
            "needs_manual_verification": sum(
                item.get("finding", {}).get("status") == "needs_manual_verification"
                for item in results
            ),
            "candidates": sum(
                item.get("finding", {}).get("status") == "candidate" for item in results
            ),
            "request_errors": sum(not item.get("success", False) for item in results),
        },
        "results": results,
    }


def verify_controlled_idor(
    raw_request: str,
    account_a_headers: dict[str, str],
    account_b_headers: dict[str, str],
    original_identifier: str,
    comparison_identifier: str,
    location: str = "path",
    query_field: str | None = None,
    default_scheme: str = "https",
    original_object_owned_by_account_a: bool = False,
    comparison_object_owned_by_account_b: bool = False,
    separate_accounts_confirmed: bool = False,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Backward-compatible single-identifier wrapper around the batch scan."""
    owned_by_a = {original_identifier} if original_object_owned_by_account_a else set()
    owned_by_b = (
        {comparison_identifier} if comparison_object_owned_by_account_b else set()
    )
    batch = scan_controlled_idor(
        raw_request=raw_request,
        account_a_headers=account_a_headers,
        account_b_headers=account_b_headers,
        original_identifier=original_identifier,
        comparison_identifiers=[comparison_identifier],
        location=location,
        query_field=query_field,
        default_scheme=default_scheme,
        account_a_owned_ids=owned_by_a,
        account_b_owned_ids=owned_by_b,
        separate_accounts_confirmed=separate_accounts_confirmed,
        delay_seconds=0,
        timeout_seconds=timeout_seconds,
        verify_tls=verify_tls,
    )
    if not batch.get("success") or not batch.get("results"):
        return batch

    result = batch["results"][0]
    if not result.get("success"):
        return result

    return {
        "success": True,
        "original_request": batch["original_request"],
        "comparison_request": {
            "method": batch["original_request"]["method"],
            "url": result["url"],
            "identifier": comparison_identifier,
        },
        "ownership_context": {
            "original_object_owned_by_account_a": original_object_owned_by_account_a,
            "comparison_object_owned_by_account_b": comparison_object_owned_by_account_b,
            "separate_accounts_confirmed": separate_accounts_confirmed,
        },
        "finding": result["finding"],
        "analysis": result["analysis"],
        "comparison_replay": result["replay"],
    }
