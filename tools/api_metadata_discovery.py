"""Bounded, scope-safe discovery of common API metadata documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from agent_core.policy import AssessmentPolicy
from agent_core.url_authorization import (
    URLCanonicalizationError,
    canonicalize_transport_url,
)
from config import (
    API_METADATA_DISCOVERY_ENABLED,
    API_METADATA_MAX_REQUESTS,
    API_METADATA_MAX_RESPONSE_BYTES,
    API_METADATA_TIMEOUT_SECONDS,
)
from tools.openapi_surface_analyzer import (
    load_structured_document,
    openapi_version,
    sanitize_openapi_document,
)
from tools.safe_http import (
    PolicyViolationError,
    ResponseTooLargeError,
    ScopedHTTPClient,
    UnsafeRedirectError,
)
from tools.scope_guard import (
    ASSESSMENT_POLICY_UNSET,
    AssessmentScopeAuthorizationError,
    AssessmentScopeTransfer,
    RequestPermitDenied,
    capture_assessment_policy_scope,
    enforce_scope,
    request_dispatch_permit,
    resolve_assessment_policy_authority,
)

METADATA_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs",
    "/redoc",
)
ABSOLUTE_MAX_REQUESTS = len(METADATA_PATHS)
ABSOLUTE_MAX_REDIRECTS = 3


@dataclass(frozen=True)
class _MetadataAuthorizationContext:
    """One immutable authority for the complete metadata request sequence."""

    policy: Any
    scope_transfer: AssessmentScopeTransfer | None
    canonical_target: str

    def permit(self, target: str, *, timeout: Any):
        if self.policy is ASSESSMENT_POLICY_UNSET:
            return request_dispatch_permit(target, timeout=timeout)
        return request_dispatch_permit(
            target,
            assessment_policy=self.policy,
            timeout=timeout,
        )


@dataclass
class _MetadataAttemptBudget:
    limit: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def _metadata_authorization_context(
    *,
    target: str,
    assessment_policy: AssessmentPolicy | None | object,
) -> _MetadataAuthorizationContext:
    policy = resolve_assessment_policy_authority(assessment_policy)
    transfer = (
        None
        if policy is ASSESSMENT_POLICY_UNSET
        else capture_assessment_policy_scope(policy)
    )
    return _MetadataAuthorizationContext(
        policy=policy,
        scope_transfer=transfer,
        canonical_target=target,
    )


def _metadata_client_authority_error(
    client: Any,
    authorization: _MetadataAuthorizationContext,
) -> str | None:
    """Reject clients that could substitute authority for lease-backed scope."""

    if authorization.policy is ASSESSMENT_POLICY_UNSET:
        return None
    if bool(getattr(client, "scope_prevalidated", False)):
        return (
            "A prevalidated HTTP client cannot be used for explicit metadata "
            "authorization."
        )
    if getattr(client, "policy", ASSESSMENT_POLICY_UNSET) is not authorization.policy:
        return "The supplied HTTP client uses a different assessment policy."
    return None


def _authorize_discovery_target(
    target: str,
    assessment_policy: AssessmentPolicy | None | object,
) -> dict[str, Any]:
    if assessment_policy is ASSESSMENT_POLICY_UNSET:
        return enforce_scope(target)
    return enforce_scope(target, assessment_policy=assessment_policy)


def _safe_url(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path or "/", "", ""))


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, f"{host}{port}", "/", "", ""))


def _request_metadata_candidate(
    *,
    client: Any,
    candidate: str,
    authorization: _MetadataAuthorizationContext,
    timeout: Any,
    attempt_budget: _MetadataAttemptBudget,
    max_redirects: int,
    headers: dict[str, str],
) -> tuple[requests.Response, list[dict[str, Any]]]:
    """Dispatch one candidate with a fresh original-authority permit per hop."""

    current = canonicalize_transport_url(candidate).url
    seen = {current}
    chain: list[dict[str, Any]] = []
    pending_hop: dict[str, Any] | None = None
    redirects = 0

    while attempt_budget.remaining:
        try:
            permit = authorization.permit(current, timeout=timeout)
            with permit as admission:
                current = str(admission["target"])
                if pending_hop is not None:
                    pending_hop["to"] = current
                    pending_hop["allowed"] = True
                    chain.append(pending_hop)
                    pending_hop = None
                attempt_budget.used += 1
                response, client_chain = client.request(
                    "GET",
                    current,
                    purpose="discovery",
                    timeout=admission["dispatch_timeout"],
                    max_redirects=0,
                    follow_redirects=False,
                    headers=headers,
                )
        except RequestPermitDenied as exc:
            if pending_hop is None:
                raise
            pending_hop["to"] = current
            pending_hop["allowed"] = False
            chain.append(pending_hop)
            raise UnsafeRedirectError(
                f"Redirect destination is outside authorized scope: {current}",
                chain,
            ) from exc

        if client_chain:
            raise UnsafeRedirectError(
                "The supplied HTTP client followed redirects despite redirects being disabled.",
                [*chain, *client_chain],
            )
        try:
            response.url = current
        except AttributeError:
            pass
        if not getattr(response, "is_redirect", False) and not getattr(
            response, "is_permanent_redirect", False
        ):
            return response, chain

        location = response.headers.get("Location")
        if not location:
            return response, chain

        raw_destination = urljoin(current, location)
        try:
            destination = canonicalize_transport_url(raw_destination).url
        except URLCanonicalizationError as exc:
            chain.append(
                {
                    "from": current,
                    "to": raw_destination,
                    "status_code": response.status_code,
                    "allowed": False,
                }
            )
            raise UnsafeRedirectError(
                "Redirect destination is ambiguous or malformed.", chain
            ) from exc

        hop = {
            "from": current,
            "to": destination,
            "status_code": response.status_code,
            "allowed": False,
        }
        if destination in seen:
            hop["allowed"] = True
            chain.append(hop)
            raise UnsafeRedirectError("Redirect loop detected.", chain)
        if redirects >= max_redirects or not attempt_budget.remaining:
            chain.append(hop)
            raise UnsafeRedirectError(
                f"Redirect limit exceeded ({max_redirects}).", chain
            )

        redirects += 1
        seen.add(destination)
        pending_hop = hop
        current = destination

    raise UnsafeRedirectError(
        f"Metadata request-attempt limit exceeded ({attempt_budget.limit}).", chain
    )


def api_metadata_discovery(
    target: str,
    *,
    enabled: bool = API_METADATA_DISCOVERY_ENABLED,
    max_requests: int = API_METADATA_MAX_REQUESTS,
    timeout_seconds: int = API_METADATA_TIMEOUT_SECONDS,
    max_response_bytes: int = API_METADATA_MAX_RESPONSE_BYTES,
    http_client: ScopedHTTPClient | None = None,
    assessment_policy: AssessmentPolicy | None | object = ASSESSMENT_POLICY_UNSET,
) -> dict[str, Any]:
    """GET a fixed set of metadata paths; never enumerate arbitrary paths."""
    if not enabled:
        return {
            "success": True,
            "documents": [],
            "metadata_requests": [],
            "network_tested": False,
            "status": "disabled",
        }
    if not 1 <= max_requests <= ABSOLUTE_MAX_REQUESTS:
        return {"success": False, "error": "max_requests must be between 1 and 8."}
    if not 1 <= timeout_seconds <= 30:
        return {"success": False, "error": "timeout_seconds must be between 1 and 30."}
    if not 1 <= max_response_bytes <= 2_000_000:
        return {
            "success": False,
            "error": "max_response_bytes must be between 1 and 2000000.",
        }
    parsed_target = urlsplit(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
        return {"success": False, "error": "A valid HTTP(S) target is required."}
    target_scope = _authorize_discovery_target(target, assessment_policy)
    if not target_scope.get("allowed"):
        return {
            "success": False,
            "error": target_scope.get("error", "Target is outside scope."),
        }
    target = str(target_scope.get("target") or target)

    try:
        authorization = _metadata_authorization_context(
            target=target,
            assessment_policy=assessment_policy,
        )
    except AssessmentScopeAuthorizationError as exc:
        return {"success": False, "error": str(exc)}

    if http_client is None:
        if isinstance(authorization.policy, AssessmentPolicy):
            client = ScopedHTTPClient(
                policy=authorization.policy,
                max_response_bytes=max_response_bytes,
            )
        else:
            client = ScopedHTTPClient(
                max_response_bytes=max_response_bytes,
                scope_prevalidated=(
                    authorization.policy is not ASSESSMENT_POLICY_UNSET
                ),
            )
    else:
        client = http_client
        authority_error = _metadata_client_authority_error(client, authorization)
        if authority_error is not None:
            return {"success": False, "error": authority_error}

    origin = _origin(target)
    documents: list[dict[str, Any]] = []
    requests_made: list[dict[str, Any]] = []
    attempt_budget = _MetadataAttemptBudget(limit=max_requests)
    for path in METADATA_PATHS[:max_requests]:
        if not attempt_budget.remaining:
            break
        candidate = urljoin(origin, path.lstrip("/"))
        request_record: dict[str, Any] = {
            "url": _safe_url(candidate),
            "method": "GET",
            "status": "requested",
            "openapi_detected": False,
        }
        try:
            response, redirect_chain = _request_metadata_candidate(
                client=client,
                candidate=candidate,
                authorization=authorization,
                timeout=timeout_seconds,
                attempt_budget=attempt_budget,
                max_redirects=min(
                    ABSOLUTE_MAX_REDIRECTS,
                    max(0, attempt_budget.remaining - 1),
                ),
                headers={
                    "Accept": "application/json, application/yaml, text/yaml, */*",
                    "User-Agent": "CyberCortexAI/2.1 Authorized-Metadata-Discovery",
                },
            )
            content = response.content
            if not isinstance(content, bytes):
                content = bytes(content or b"")
            if len(content) > max_response_bytes:
                raise ResponseTooLargeError(
                    f"Response exceeded the {max_response_bytes}-byte metadata limit."
                )
            content_type = (
                str(response.headers.get("Content-Type") or "").split(";", 1)[0].lower()
            )
            request_record.update(
                {
                    "status": "completed",
                    "status_code": int(response.status_code),
                    "content_type": content_type,
                    "response_bytes": len(content),
                    "effective_url": _safe_url(getattr(response, "url", candidate)),
                    "redirect_chain": [
                        {
                            "from": _safe_url(hop.get("from")),
                            "to": _safe_url(hop.get("to")),
                            "status_code": hop.get("status_code"),
                            "allowed": bool(hop.get("allowed")),
                        }
                        for hop in redirect_chain
                        if isinstance(hop, dict)
                    ],
                }
            )
            structured = None
            if response.status_code < 400 and "html" not in content_type:
                try:
                    structured = load_structured_document(content)
                except UnicodeDecodeError:
                    structured = None
            version = openapi_version(structured)
            if version is not None and isinstance(structured, dict):
                request_record["openapi_detected"] = True
                documents.append(
                    {
                        "source_url": _safe_url(getattr(response, "url", candidate)),
                        "requested_url": _safe_url(candidate),
                        "format": (
                            "json"
                            if path.endswith(".json") or "json" in content_type
                            else "yaml"
                        ),
                        "openapi_version": version,
                        "document": sanitize_openapi_document(structured),
                    }
                )
        except RequestPermitDenied as exc:
            request_record.update(
                {
                    "status": "blocked_out_of_scope",
                    "error": str(exc),
                }
            )
        except UnsafeRedirectError as exc:
            request_record.update(
                {
                    "status": "blocked_redirect",
                    "error": "Redirect left authorized scope or exceeded the redirect bound.",
                    "redirect_chain": [
                        {
                            "from": _safe_url(hop.get("from")),
                            "to": _safe_url(hop.get("to")),
                            "status_code": hop.get("status_code"),
                            "allowed": bool(hop.get("allowed")),
                        }
                        for hop in exc.redirect_chain
                        if isinstance(hop, dict)
                    ],
                }
            )
        except ResponseTooLargeError:
            request_record.update(
                {
                    "status": "response_too_large",
                    "error": "Response exceeded the configured metadata size limit.",
                }
            )
        except PolicyViolationError as exc:
            request_record.update({"status": "policy_blocked", "error": str(exc)})
        except requests.RequestException as exc:
            request_record.update(
                {"status": "request_failed", "error": type(exc).__name__}
            )
        requests_made.append(request_record)

    return {
        "success": True,
        "documents": documents,
        "metadata_requests": requests_made,
        "document_count": len(documents),
        "request_count": len(requests_made),
        "network_request_count": attempt_budget.used,
        "network_tested": any(
            item.get("status") != "blocked_out_of_scope" for item in requests_made
        ),
        "bounds": {
            "max_requests": max_requests,
            "timeout_seconds": timeout_seconds,
            "max_response_bytes": max_response_bytes,
            "methods": ["GET"],
        },
        "vulnerability_status": "not_assessed",
    }
