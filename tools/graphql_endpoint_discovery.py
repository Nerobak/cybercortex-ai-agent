"""Scope-safe GraphQL endpoint discovery from existing evidence."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from tools.endpoint_analyzer import classify_resource_kind
from tools.scope_guard import enforce_scope

COMMON_PATHS = (
    "/graphql",
    "/api/graphql",
    "/graphql/api",
    "/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
)
STRONG_KEYS = {"operationname", "query", "variables"}


def _items(evidence: Any) -> list[Any]:
    if isinstance(evidence, list):
        return evidence
    if isinstance(evidence, dict):
        values: list[Any] = []
        for key in (
            "all_urls",
            "urls",
            "javascript_urls",
            "form_actions",
            "fetch_urls",
            "requests",
            "captured_requests",
            "candidates",
        ):
            value = evidence.get(key, [])
            values.extend(
                value if isinstance(value, list) else [value] if value else []
            )
        return values
    return []


def graphql_endpoint_discovery(
    evidence: Any, target: str | None = None, *, check_common_routes: bool = False
) -> dict[str, Any]:
    candidates: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    entries = _items(evidence)
    if check_common_routes and target:
        entries.extend(
            {
                "url": urljoin(target.rstrip("/") + "/", path.lstrip("/")),
                "source": "common_route_check",
                "network_checked": False,
            }
            for path in COMMON_PATHS
        )
    for raw in entries:
        meta = raw if isinstance(raw, dict) else {"url": raw}
        url = meta.get("url") or meta.get("endpoint") or meta.get("action")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        if classify_resource_kind(url) == "static_asset":
            continue
        if not enforce_scope(url).get("allowed"):
            errors.append(
                {"url": url, "error": "Candidate rejected by configured scope."}
            )
            continue
        blob = " ".join(
            str(meta.get(k, ""))
            for k in (
                "content_type",
                "body",
                "response",
                "request_body",
                "client_config",
            )
        )
        keys = {k.lower() for k in meta}
        types: list[str] = []
        if (
            "application/graphql" in blob.lower()
            or "graphql-response+json" in blob.lower()
        ):
            types.append("graphql_content_type")
        if re.search(r'"errors"\s*:\s*\[', blob) and re.search(
            r'"(?:message|locations|path)"', blob
        ):
            types.append("graphql_error_object")
        if re.search(r'"data"\s*:', blob) and (
            "graphql" in blob.lower() or "__schema" in blob
        ):
            types.append("graphql_json_response")
        if "__schema" in blob or "__type" in blob:
            types.append("schema_response")
        for key in sorted(STRONG_KEYS & keys):
            types.append(f"observed_{key}")
        if re.search(r"\b(operationName|ApolloClient|GraphQLClient)\b", blob):
            types.append("graphql_client_configuration")
        path_words = {
            x for x in re.split(r"[^a-z0-9]+", urlparse(url).path.lower()) if x
        }
        route = bool(path_words & {"graphql", "gql"}) or urlparse(url).path.lower() in {
            "/query"
        }
        if route:
            types.append("graphql_route_name")
        strong = [t for t in types if t != "graphql_route_name"]
        if not types:
            continue
        confidence = (
            "confirmed"
            if any(
                t in strong
                for t in (
                    "graphql_content_type",
                    "graphql_json_response",
                    "schema_response",
                    "graphql_client_configuration",
                )
            )
            else "likely" if strong else "route_name_only"
        )
        item = {
            "url": url,
            "confidence": confidence,
            "evidence_types": sorted(set(types)),
            "source": meta.get("source", "gathered_evidence"),
            "network_checked": bool(meta.get("network_checked", False)),
            "status": "observed",
            "vulnerability_status": "observation",
            "safety_notes": "Route names and GraphQL behavior are observations, not vulnerabilities.",
        }
        old = candidates.get(url)
        rank = {"route_name_only": 0, "possible": 1, "likely": 2, "confirmed": 3}
        if not old or rank[confidence] > rank[old["confidence"]]:
            candidates[url] = item
    observed = sorted(candidates.values(), key=lambda x: x["url"])
    return {
        "success": True,
        "observed_candidates": observed,
        "confirmed_endpoints": [x for x in observed if x["confidence"] == "confirmed"],
        "likely_endpoints": [x for x in observed if x["confidence"] == "likely"],
        "evidence_summary": {
            "candidate_count": len(observed),
            "confirmed_count": sum(x["confidence"] == "confirmed" for x in observed),
            "network_checks_performed": sum(x["network_checked"] for x in observed),
        },
        "errors": errors,
    }
