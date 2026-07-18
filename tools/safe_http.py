"""Scope-aware HTTP redirect handling shared by network tools."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests

from tools.scope_guard import enforce_scope


class UnsafeRedirectError(requests.RequestException):
    def __init__(self, message: str, chain: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.redirect_chain = chain


def scoped_get(
    url: str,
    *,
    timeout: float = 10,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> tuple[requests.Response, list[dict[str, Any]]]:
    """GET a URL, validating the initial URL and every redirect destination."""
    if not enforce_scope(url).get("allowed"):
        raise UnsafeRedirectError("Requested URL is outside authorized scope.", [])

    session = requests.Session()
    current = url
    chain: list[dict[str, Any]] = []
    seen = {current}
    for _ in range(max_redirects + 1):
        response = session.get(
            current,
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
            **kwargs,
        )
        if not response.is_redirect and not response.is_permanent_redirect:
            response.url = current
            return response, chain

        location = response.headers.get("Location")
        if not location:
            return response, chain
        destination = urljoin(current, location)
        hop = {
            "from": current,
            "to": destination,
            "status_code": response.status_code,
            "allowed": bool(enforce_scope(destination).get("allowed")),
        }
        chain.append(hop)
        if not hop["allowed"]:
            raise UnsafeRedirectError(
                f"Redirect destination is outside authorized scope: {destination}",
                chain,
            )
        if destination in seen:
            raise UnsafeRedirectError("Redirect loop detected.", chain)
        seen.add(destination)
        current = destination
    raise UnsafeRedirectError(f"Redirect limit exceeded ({max_redirects}).", chain)
