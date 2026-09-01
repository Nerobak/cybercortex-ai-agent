"""Deterministic, offline API-target likelihood evaluation."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

DEFAULT_INSUFFICIENT_CRAWL_THRESHOLD = 2


def _content_type(value: Any) -> str:
    return str(value or "").split(";", 1)[0].strip().lower()


def _technology_text(technology_evidence: dict[str, Any]) -> str:
    values = technology_evidence.get("technologies") or []
    headers = technology_evidence.get("headers") or {}
    return " ".join([*(str(item) for item in values), str(headers)]).lower()


def analyze_api_target(
    target: str,
    http_evidence: dict[str, Any] | None = None,
    technology_evidence: dict[str, Any] | None = None,
    crawl_evidence: dict[str, Any] | None = None,
    *,
    insufficient_crawl_threshold: int = DEFAULT_INSUFFICIENT_CRAWL_THRESHOLD,
) -> dict[str, Any]:
    """Classify API likelihood without making a vulnerability assertion."""
    http = http_evidence if isinstance(http_evidence, dict) else {}
    technology = technology_evidence if isinstance(technology_evidence, dict) else {}
    crawl = crawl_evidence if isinstance(crawl_evidence, dict) else {}
    urls = crawl.get("urls") if isinstance(crawl.get("urls"), list) else []
    requests = crawl.get("requests") if isinstance(crawl.get("requests"), list) else []
    fetch_urls = (
        crawl.get("fetch_urls") if isinstance(crawl.get("fetch_urls"), list) else []
    )
    status = http.get("root_status", http.get("status_code"))
    reachable = bool(http.get("reachable")) or isinstance(status, int)
    content_type = _content_type(http.get("content_type"))
    server_text = " ".join(
        (str(http.get("server") or ""), _technology_text(technology))
    ).lower()
    candidate_urls = [
        item
        for item in [http.get("effective_url"), *urls, *fetch_urls]
        if isinstance(item, str)
    ]

    signals: list[str] = []
    score = 0
    if content_type in {
        "application/json",
        "application/problem+json",
        "application/graphql-response+json",
    } or content_type.endswith("+json"):
        signals.append(f"root content type is {content_type}")
        score += 2
    if any(marker in server_text for marker in ("uvicorn", "fastapi")):
        signals.append("FastAPI/Uvicorn-compatible server indicator observed")
        score += 2
    if any(marker in server_text for marker in ("swagger", "openapi")):
        signals.append("Swagger/OpenAPI technology indicator observed")
        score += 3
    if any(
        any(marker in urlparse(url).path.lower() for marker in ("/api", "/rest/"))
        for url in candidate_urls
    ):
        signals.append("API-style route evidence observed")
        score += 2
    if any("graphql" in urlparse(url).path.lower() for url in candidate_urls):
        signals.append("GraphQL route evidence observed")
        score += 2
    if fetch_urls or requests:
        signals.append("JavaScript or captured request evidence observed")
        score += 1
    effective_url = http.get("effective_url")
    if (
        isinstance(effective_url, str)
        and effective_url != target
        and any(
            marker in urlparse(effective_url).path.lower()
            for marker in ("/api", "/docs", "/swagger", "/graphql")
        )
    ):
        signals.append("API-like redirect observed")
        score += 2
    if http.get("rest_style_response") is True:
        signals.append("REST-style response structure observed")
        score += 2
    if reachable and status in {401, 403, 404}:
        signals.append(f"reachable root returned HTTP {status}")
        score += 1
    crawler_insufficient = len(urls) <= max(0, insufficient_crawl_threshold)
    if crawler_insufficient:
        signals.append(
            f"crawler surface is insufficient ({len(urls)} URL(s), threshold {insufficient_crawl_threshold})"
        )
        score += 1

    likelihood = "high" if score >= 5 else "medium" if score >= 3 else "low"
    should_discover = (
        reachable
        and crawler_insufficient
        and likelihood
        in {
            "medium",
            "high",
        }
    )
    reason = (
        "reachable API-oriented target with insufficient crawler surface"
        if should_discover
        else (
            "normal discovery produced sufficient surface"
            if reachable and not crawler_insufficient
            else "available evidence did not justify an API metadata pivot"
        )
    )
    return {
        "success": True,
        "api_likelihood": likelihood,
        "signals": signals,
        "reason": reason,
        "score": score,
        "reachable": reachable,
        "root_status": status,
        "crawler_url_count": len(urls),
        "crawler_insufficient": crawler_insufficient,
        "decision": {
            "decision": (
                "api_metadata_discovery" if should_discover else "normal_discovery"
            ),
            "reason": reason,
            "automatic": should_discover,
            "bounded": should_discover,
        },
        "network_tested": False,
        "vulnerability_status": "not_assessed",
    }
