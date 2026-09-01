"""Policy-aware HTTP transport shared by every network-capable tool."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from agent_core.request_budget import RequestBudget, RequestBudgetExceeded
from tools.scope_guard import enforce_scope

try:
    from agent_core.agent_models import (
        TransportRequestContext,
        TransportRequestPurpose,
    )
    from agent_core.policy import AccountEligibilityContext, AssessmentPolicy
except ImportError:  # preserve minimal standalone tool imports
    AccountEligibilityContext = Any  # type: ignore[misc,assignment]
    AssessmentPolicy = Any  # type: ignore[misc,assignment]
    TransportRequestContext = Any  # type: ignore[misc,assignment]
    TransportRequestPurpose = Any  # type: ignore[misc,assignment]


class UnsafeRedirectError(requests.RequestException):
    def __init__(self, message: str, chain: list[dict[str, Any]]) -> None:
        super().__init__(message)
        self.redirect_chain = chain


class PolicyViolationError(requests.RequestException):
    pass


class ResponseTooLargeError(requests.RequestException):
    pass


def _credential_header(name: Any) -> bool:
    normalized = str(name).strip().lower().replace("_", "-")
    return bool(
        normalized in {"authorization", "proxy-authorization", "cookie", "cookie2"}
        or "authorization" in normalized
        or "credential" in normalized
        or "session" in normalized
        or "token" in normalized
        or "api-key" in normalized
        or "apikey" in normalized
        or normalized.startswith("x-auth")
    )


def resolve_host_addresses(url: str) -> list[str]:
    """Resolve a target immediately before a request for audit/rebinding checks."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise PolicyViolationError("Requested URL has no hostname.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        return sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        )
    except socket.gaierror as exc:
        raise PolicyViolationError(f"DNS resolution failed for {host}: {exc}") from exc


class ScopedHTTPClient:
    def __init__(
        self,
        *,
        policy: AssessmentPolicy | None = None,
        requester: Callable[..., requests.Response] | None = None,
        requester_takes_method: bool = True,
        scope_prevalidated: bool = False,
        max_response_bytes: int | None = None,
        budget: RequestBudget | None = None,
    ) -> None:
        self.policy = policy
        self.session = requests.Session()
        self.session.trust_env = False
        self.requester = requester or self.session.request
        self.requester_takes_method = requester_takes_method
        self.scope_prevalidated = scope_prevalidated
        self.max_response_bytes = max_response_bytes
        self.budget = budget or (
            RequestBudget(
                policy.request_budget,
                per_host_limit=policy.per_host_request_budget,
            )
            if policy is not None
            else None
        )
        if self.policy is not None and self.budget is not None:
            if self.budget.limit > self.policy.request_budget:
                raise ValueError("The request ledger exceeds the policy budget.")
            if self.budget.per_host_limit is None:
                self.budget.per_host_limit = self.policy.per_host_request_budget
            elif self.budget.per_host_limit > self.policy.per_host_request_budget:
                raise ValueError(
                    "The request ledger exceeds the per-host policy budget."
                )
        self.manages_request_budget = (
            self.policy is not None and self.budget is not None
        )
        self._requests_used = 0
        self._host_requests: dict[str, int] = {}
        self._last_request_at = 0.0
        self._lock = threading.Lock()
        self._concurrency_slots = (
            threading.BoundedSemaphore(policy.max_concurrency)
            if policy is not None
            else None
        )
        self._rate_limit_sequence_positions: dict[tuple[str, str, int, int], int] = {}
        self.dns_observations: dict[str, list[str]] = {}

    def _transport_account_is_eligible(
        self, request_context: TransportRequestContext
    ) -> bool:
        """Revalidate the gate's controlled-account claim with the shared rule."""

        if self.policy is None or not request_context.controlled_account_id:
            return False
        controlled_ids = (
            [request_context.controlled_account_id]
            if request_context.account_controlled
            else []
        )
        return self.policy.account_is_eligible(
            request_context.controlled_account_id,
            AccountEligibilityContext(controlled_account_ids=controlled_ids),
            account_controlled=request_context.account_controlled,
        ).eligible

    @property
    def requests_used(self) -> int:
        return self._requests_used

    def resolve_dns(
        self,
        target_url: str,
        *,
        expected_host: str | None = None,
        _slot_acquired: bool = False,
    ) -> list[str]:
        """Authorize one target and resolve only its unchanged hostname.

        DNS is transport preparation, not an HTTP request, so this does not
        consume the HTTP ledger.
        """
        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if expected_host and host != expected_host.lower().rstrip("."):
            raise PolicyViolationError(
                "DNS preparation target does not match the authorized hostname."
            )
        if self.policy is None:
            if not self.scope_prevalidated and not enforce_scope(target_url).get(
                "allowed"
            ):
                raise PolicyViolationError("Requested URL is outside authorized scope.")
        else:
            decision = self.policy.authorize_url(target_url, method="GET")
            if not decision.allowed:
                raise PolicyViolationError("; ".join(decision.reasons))
        acquired = _slot_acquired or self._concurrency_slots is None
        if not acquired:
            acquired = self._concurrency_slots.acquire(blocking=False)
        if not acquired:
            raise PolicyViolationError("Concurrency limit reached.")
        try:
            addresses = resolve_host_addresses(target_url)
            self.dns_observations[target_url] = addresses
            return addresses
        finally:
            if self._concurrency_slots is not None and acquired and not _slot_acquired:
                self._concurrency_slots.release()

    @staticmethod
    def _coerce_request_context(
        request_context: TransportRequestContext | dict[str, Any] | None,
    ) -> TransportRequestContext | None:
        if request_context is None:
            return None
        if isinstance(request_context, TransportRequestContext):
            return request_context
        try:
            return TransportRequestContext.model_validate(request_context)
        except (TypeError, ValueError) as exc:
            raise PolicyViolationError("Request purpose metadata is invalid.") from exc

    def _authorize_session_acquisition(
        self,
        url: str,
        method: str,
        request_context: TransportRequestContext | None,
    ) -> Any:
        if self.policy is None:
            raise PolicyViolationError(
                "Session acquisition requires an explicit assessment policy."
            )
        reasons: list[str] = []
        if request_context is None:
            reasons.append("Typed session transport authorization metadata is missing.")
        else:
            if request_context.purpose != "session_acquisition":
                reasons.append("Request purpose metadata is inconsistent.")
            if not request_context.policy_authorized:
                reasons.append(
                    "The deterministic policy gate did not authorize session acquisition."
                )
            if not request_context.configured_endpoint_match:
                reasons.append(
                    "The session request does not match the configured endpoint and method."
                )
            if url != request_context.configured_url:
                reasons.append(
                    "The session URL does not exactly match the authorized endpoint."
                )
            if method != request_context.configured_method:
                reasons.append(
                    "The session method does not exactly match the authorized method."
                )
            if not request_context.controlled_account_id:
                reasons.append("A controlled account identifier is required.")
            if not request_context.account_controlled:
                reasons.append("Session acquisition requires a controlled account.")
            if not request_context.account_policy_authorized:
                reasons.append("The controlled account is not policy-authorized.")
            if not self._transport_account_is_eligible(request_context):
                reasons.append("The controlled account is not policy-authorized.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if method in {"PUT", "PATCH", "DELETE"}:
            reasons.append(
                "Session acquisition does not authorize PUT, PATCH, or DELETE."
            )
        base = self.policy._authorize_url_base(url, method=method)
        reasons.extend(base.reasons)
        if reasons:
            raise PolicyViolationError("; ".join(dict.fromkeys(reasons)))
        return base

    def _authorize_session_termination(
        self,
        url: str,
        method: str,
        request_context: TransportRequestContext | None,
    ) -> Any:
        """Authorize one exact typed logout without enabling generic DELETE."""
        if self.policy is None:
            raise PolicyViolationError(
                "Session termination requires an explicit assessment policy."
            )
        reasons: list[str] = []
        if request_context is None:
            reasons.append(
                "Typed session-termination transport authorization metadata is missing."
            )
        else:
            if request_context.purpose != "session_termination":
                reasons.append("Request purpose metadata is inconsistent.")
            if request_context.workflow_category != "session_invalidation":
                reasons.append(
                    "Session termination requires a typed session-invalidation workflow."
                )
            if request_context.generated_by != "SessionInvalidationExecutor":
                reasons.append(
                    "Session termination was not generated by the typed executor."
                )
            if not request_context.policy_authorized:
                reasons.append(
                    "The deterministic policy gate did not authorize session termination."
                )
            if not request_context.configured_endpoint_match:
                reasons.append(
                    "The termination request does not match the workflow surface."
                )
            if url != request_context.configured_url:
                reasons.append(
                    "The termination URL does not exactly match the workflow surface."
                )
            if method != request_context.configured_method:
                reasons.append(
                    "The termination method does not exactly match the workflow surface."
                )
            if not request_context.controlled_account_id:
                reasons.append("A controlled account identifier is required.")
            if not request_context.account_controlled:
                reasons.append("Session termination requires a controlled account.")
            if not request_context.account_policy_authorized:
                reasons.append("The controlled account is not policy-authorized.")
            if not self._transport_account_is_eligible(request_context):
                reasons.append("The controlled account is not policy-authorized.")
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if not self.policy.allow_state_changes:
            reasons.append("State-changing session termination is disabled by policy.")
        if method not in {"POST", "DELETE"}:
            reasons.append("Session termination permits only POST or DELETE.")
        base = self.policy._authorize_url_base(url, method=method)
        reasons.extend(base.reasons)
        if reasons:
            raise PolicyViolationError("; ".join(dict.fromkeys(reasons)))
        return base

    def _authorize_rate_limit_verification(
        self,
        url: str,
        method: str,
        request_context: TransportRequestContext | None,
    ) -> Any:
        """Authorize one position in a typed sequential bounded login sequence."""
        if self.policy is None:
            raise PolicyViolationError(
                "Rate-limit verification requires an explicit assessment policy."
            )
        reasons: list[str] = []
        if request_context is None:
            reasons.append(
                "Typed rate-limit transport authorization metadata is missing."
            )
        else:
            if request_context.purpose != "rate_limit_verification":
                reasons.append("Request purpose metadata is inconsistent.")
            if request_context.workflow_category != "rate_limit_enforcement":
                reasons.append("A typed rate-limit workflow is required.")
            if request_context.generated_by != "AuthenticationLoginRateLimitExecutor":
                reasons.append("The typed login rate-limit executor is required.")
            if not request_context.policy_authorized:
                reasons.append(
                    "The deterministic policy gate did not authorize rate-limit verification."
                )
            if not request_context.configured_endpoint_match:
                reasons.append(
                    "The login request does not match the configured endpoint."
                )
            if url != request_context.configured_url or method != (
                request_context.configured_method
            ):
                reasons.append(
                    "The login request does not exactly match the authorized surface."
                )
            if not request_context.controlled_account_id:
                reasons.append("A controlled account identifier is required.")
            if not request_context.account_controlled:
                reasons.append("Rate-limit verification requires a controlled account.")
            if not request_context.account_policy_authorized:
                reasons.append("The controlled account is not policy-authorized.")
            attempts = request_context.bounded_attempt_limit
            total = request_context.bounded_total_requests
            position = request_context.rate_limit_sequence_position
            role = request_context.rate_limit_sequence_role
            if attempts is None or total != attempts + 2:
                reasons.append("The bounded rate-limit request count is invalid.")
            elif position is None or position >= total:
                reasons.append("The rate-limit sequence position is invalid.")
            else:
                expected_role = (
                    "valid_baseline"
                    if position == 0
                    else (
                        "valid_final"
                        if position == total - 1
                        else "invalid_password_attempt"
                    )
                )
                if role != expected_role:
                    reasons.append("The rate-limit sequence role is out of order.")
                key = (
                    url,
                    request_context.controlled_account_id or "",
                    attempts,
                    total,
                )
                if self._rate_limit_sequence_positions.get(key, 0) != position:
                    reasons.append(
                        "The rate-limit sequence is not strictly sequential."
                    )
        if not self.policy.allow_bounded_rate_limit_verification:
            reasons.append(
                "Explicit bounded rate-limit verification is disabled by policy."
            )
        if not self.policy.credentials_allowed:
            reasons.append("Controlled credential use is disabled by policy.")
        if method != "POST":
            reasons.append("Login rate-limit verification permits only POST.")
        if request_context is not None:
            attempts = request_context.bounded_attempt_limit or 0
            if attempts > self.policy.max_rate_limit_attempts:
                reasons.append("The bounded attempt count exceeds policy.")
            if not self._transport_account_is_eligible(request_context):
                reasons.append("The controlled account is not policy-authorized.")
        base = self.policy._authorize_url_base(url, method=method)
        reasons.extend(base.reasons)
        if reasons:
            raise PolicyViolationError("; ".join(dict.fromkeys(reasons)))
        assert request_context is not None
        assert request_context.bounded_attempt_limit is not None
        assert request_context.bounded_total_requests is not None
        assert request_context.rate_limit_sequence_position is not None
        key = (
            url,
            request_context.controlled_account_id or "",
            request_context.bounded_attempt_limit,
            request_context.bounded_total_requests,
        )
        self._rate_limit_sequence_positions[key] = (
            request_context.rate_limit_sequence_position + 1
        )
        return base

    def _authorize(
        self,
        url: str,
        method: str,
        *,
        purpose: TransportRequestPurpose | None = None,
        request_context: TransportRequestContext | None = None,
        techniques: tuple[str, ...] = (),
        oast_callback_url: str | None = None,
    ) -> None:
        if request_context is not None and purpose != request_context.purpose:
            raise PolicyViolationError("Request purpose metadata is inconsistent.")
        if purpose == "session_acquisition":
            decision = self._authorize_session_acquisition(url, method, request_context)
        elif purpose == "cleanup":
            if request_context is not None:
                decision = self._authorize_session_acquisition(
                    url,
                    method,
                    request_context.model_copy(
                        update={"purpose": "session_acquisition"}
                    ),
                )
            elif self.policy is not None:
                decision = self.policy.authorize_url(url, method=method)
            else:
                decision = None
        elif purpose == "session_termination":
            decision = self._authorize_session_termination(url, method, request_context)
        elif purpose == "rate_limit_verification":
            decision = self._authorize_rate_limit_verification(
                url, method, request_context
            )
        elif purpose == "oast":
            if self.policy is None:
                raise PolicyViolationError(
                    "OAST requires an explicit assessment policy."
                )
            callback_decision = self.policy.authorize_oast(oast_callback_url or "")
            if not callback_decision.allowed:
                raise PolicyViolationError("; ".join(callback_decision.reasons))
            decision = self.policy.authorize_url(url, method=method)
        elif self.policy is not None:
            decision = self.policy.authorize_url(url, method=method)
        else:
            decision = None
        if method == "DELETE" and purpose != "session_termination":
            raise PolicyViolationError(
                "DELETE requires the typed session-termination purpose."
            )
        if self.policy is not None:
            assert decision is not None
            if not decision.allowed:
                raise PolicyViolationError("; ".join(decision.reasons))
            requested_techniques = {
                str(item).strip().lower() for item in techniques if str(item).strip()
            }
            prohibited = requested_techniques & set(self.policy.prohibited_techniques)
            if prohibited:
                raise PolicyViolationError(
                    "A requested technique is prohibited by policy."
                )
            if ({"oast", "ssrf"} & requested_techniques) and purpose != "oast":
                raise PolicyViolationError(
                    "OAST-capable requests require the explicit OAST purpose."
                )
        elif not self.scope_prevalidated and not enforce_scope(url).get("allowed"):
            raise PolicyViolationError("Requested URL is outside authorized scope.")
        if purpose in {"discovery", "owned_object_acquisition", "verification"}:
            if method not in {"GET", "HEAD", "OPTIONS"}:
                raise PolicyViolationError(
                    f"The {purpose} purpose permits only read-only requests."
                )

    @staticmethod
    def _request_kind(purpose: TransportRequestPurpose | None) -> str:
        if purpose in {"discovery", "owned_object_acquisition"}:
            return "discovery"
        if purpose in {"session_acquisition", "rate_limit_verification"}:
            return "auth"
        if purpose == "cleanup":
            return "cleanup"
        return "verification"

    def _apply_rate_limit(self) -> None:
        if self.policy is None:
            return
        delay = 1.0 / self.policy.requests_per_second
        with self._lock:
            remaining = delay - (time.monotonic() - self._last_request_at)
            if remaining > 0:
                time.sleep(remaining)
            self._last_request_at = time.monotonic()

    def _consume_attempt(
        self, url: str, purpose: TransportRequestPurpose | None
    ) -> None:
        if self.budget is None:
            return
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        try:
            self.budget.consume(self._request_kind(purpose), host=host)
        except RequestBudgetExceeded as exc:
            raise PolicyViolationError(str(exc)) from exc
        with self._lock:
            self._requests_used += 1
            self._host_requests[host] = self._host_requests.get(host, 0) + 1

    @staticmethod
    def _validate_transport_binding(url: str, kwargs: dict[str, Any]) -> None:
        if kwargs.get("proxies"):
            raise PolicyViolationError("Per-request proxy overrides are not permitted.")
        parsed = urlparse(url)
        expected_host = (parsed.hostname or "").lower().rstrip(".")
        for name, value in (kwargs.get("headers") or {}).items():
            if str(name).strip().lower() != "host":
                continue
            supplied = urlparse(f"//{str(value).strip()}")
            supplied_host = (supplied.hostname or "").lower().rstrip(".")
            if supplied_host != expected_host:
                raise PolicyViolationError(
                    "The Host header does not match the authorized target."
                )
            if supplied.port is not None and supplied.port != (
                parsed.port or (443 if parsed.scheme == "https" else 80)
            ):
                raise PolicyViolationError(
                    "The Host header port does not match the authorized target."
                )

    def _send(
        self,
        method: str,
        url: str,
        *,
        purpose: TransportRequestPurpose | None = None,
        request_context: TransportRequestContext | None = None,
        techniques: tuple[str, ...] = (),
        oast_callback_url: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        self._authorize(
            url,
            method,
            purpose=purpose,
            request_context=request_context,
            techniques=techniques,
            oast_callback_url=oast_callback_url,
        )
        self._validate_transport_binding(url, kwargs)
        acquired = self._concurrency_slots is None or self._concurrency_slots.acquire(
            blocking=False
        )
        if not acquired:
            raise PolicyViolationError("Concurrency limit reached.")
        kwargs["allow_redirects"] = False
        bounded_stream = self.policy is not None or self.max_response_bytes is not None
        if bounded_stream:
            kwargs.setdefault("stream", True)
        if self.policy is not None:
            kwargs["verify"] = self.policy.verify_tls
        try:
            if self.policy is not None and self.policy.resolve_dns_before_request:
                self.resolve_dns(url, _slot_acquired=True)
            self._apply_rate_limit()
            self._consume_attempt(url, purpose)
            if self.requester_takes_method:
                response = self.requester(method, url, **kwargs)
            else:
                response = self.requester(url, **kwargs)
            limit = (
                self.policy.max_response_bytes
                if self.policy
                else self.max_response_bytes or 1_000_000
            )
            content_length = getattr(response, "headers", {}).get("Content-Length")
            try:
                if content_length is not None and int(content_length) > limit:
                    if hasattr(response, "close"):
                        response.close()
                    raise ResponseTooLargeError(
                        f"Response Content-Length exceeded the {limit}-byte policy limit."
                    )
            except (TypeError, ValueError):
                pass
            content: bytes
            if bounded_stream and hasattr(response, "iter_content"):
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    received += len(chunk)
                    if received > limit:
                        if hasattr(response, "close"):
                            response.close()
                        raise ResponseTooLargeError(
                            f"Response exceeded the {limit}-byte policy limit."
                        )
                    chunks.append(chunk)
                content = b"".join(chunks)
                try:
                    response._content = content
                    response._content_consumed = True
                except AttributeError:
                    pass
            else:
                content = getattr(response, "content", b"")
            if isinstance(content, bytes) and len(content) > limit:
                raise ResponseTooLargeError(
                    f"Response exceeded the {limit}-byte policy limit."
                )
            return response
        finally:
            if self._concurrency_slots is not None and acquired:
                self._concurrency_slots.release()

    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: float = 10,
        max_redirects: int | None = None,
        follow_redirects: bool = False,
        headers: dict[str, str] | None = None,
        purpose: TransportRequestPurpose | None = None,
        request_context: TransportRequestContext | dict[str, Any] | None = None,
        techniques: list[str] | tuple[str, ...] | None = None,
        oast_callback_url: str | None = None,
        allow_session_credentials: bool = True,
        isolate_session_cookies: bool = False,
        **kwargs: Any,
    ) -> tuple[requests.Response, list[dict[str, Any]]]:
        method = method.strip().upper()
        if purpose is None and self.policy is not None:
            purpose = (
                "state_mutation"
                if method in {"POST", "PUT", "PATCH", "DELETE"}
                else "verification"
            )
        if purpose not in {
            None,
            "discovery",
            "oast",
            "session_acquisition",
            "session_termination",
            "rate_limit_verification",
            "owned_object_acquisition",
            "verification",
            "state_mutation",
            "cleanup",
        }:
            raise PolicyViolationError("Unsupported request purpose.")
        semantic_context = self._coerce_request_context(request_context)
        if not allow_session_credentials:
            headers = {
                name: value
                for name, value in (headers or {}).items()
                if not _credential_header(name)
            }
            kwargs.pop("auth", None)
            kwargs.pop("cookies", None)
            self.session.cookies.clear()
        elif isolate_session_cookies:
            self.session.cookies.clear()
        limit = (
            max_redirects
            if max_redirects is not None
            else self.policy.max_redirects if self.policy else 5
        )
        current = url
        current_method = method
        chain: list[dict[str, Any]] = []
        seen = {current}
        for _ in range(limit + 1):
            try:
                response = self._send(
                    current_method,
                    current,
                    timeout=timeout,
                    headers=headers,
                    purpose=purpose,
                    request_context=semantic_context,
                    techniques=tuple(techniques or ()),
                    oast_callback_url=oast_callback_url,
                    **kwargs,
                )
            finally:
                if not allow_session_credentials or isolate_session_cookies:
                    self.session.cookies.clear()
            if not getattr(response, "is_redirect", False) and not getattr(
                response, "is_permanent_redirect", False
            ):
                try:
                    response.url = current
                except AttributeError:
                    pass
                return response, chain
            location = response.headers.get("Location")
            if not location or not follow_redirects:
                response.url = current
                return response, chain
            destination = urljoin(current, location)
            try:
                self._authorize(
                    destination,
                    current_method,
                    purpose=purpose,
                    request_context=semantic_context,
                    techniques=tuple(techniques or ()),
                    oast_callback_url=oast_callback_url,
                )
                allowed = True
            except PolicyViolationError:
                allowed = False
            hop = {
                "from": current,
                "to": destination,
                "status_code": response.status_code,
                "allowed": allowed,
            }
            chain.append(hop)
            if not allowed:
                raise UnsafeRedirectError(
                    f"Redirect destination is outside authorized scope: {destination}",
                    chain,
                )
            if destination in seen:
                raise UnsafeRedirectError("Redirect loop detected.", chain)
            seen.add(destination)
            if response.status_code == 303 or (
                response.status_code in {301, 302} and current_method == "POST"
            ):
                current_method = "GET"
                kwargs.pop("data", None)
                kwargs.pop("json", None)
            current = destination
        raise UnsafeRedirectError(f"Redirect limit exceeded ({limit}).", chain)


def scoped_request(
    method: str,
    url: str,
    *,
    policy: AssessmentPolicy | None = None,
    requester: Callable[..., requests.Response] | None = None,
    requester_takes_method: bool = True,
    scope_prevalidated: bool = False,
    budget: RequestBudget | None = None,
    **kwargs: Any,
) -> tuple[requests.Response, list[dict[str, Any]]]:
    client = ScopedHTTPClient(
        policy=policy,
        requester=requester,
        requester_takes_method=requester_takes_method,
        scope_prevalidated=scope_prevalidated,
        budget=budget,
    )
    return client.request(method, url, **kwargs)


def scoped_get(
    url: str,
    *,
    timeout: float = 10,
    max_redirects: int = 5,
    headers: dict[str, str] | None = None,
    http_client: ScopedHTTPClient | None = None,
    **kwargs: Any,
) -> tuple[requests.Response, list[dict[str, Any]]]:
    """GET a URL, validating the initial URL and every redirect destination."""
    if http_client is not None:
        return http_client.request(
            "GET",
            url,
            timeout=timeout,
            max_redirects=max_redirects,
            follow_redirects=True,
            headers=headers,
            purpose="discovery",
            **kwargs,
        )
    session = requests.Session()
    try:
        return scoped_request(
            "GET",
            url,
            requester=session.get,
            requester_takes_method=False,
            timeout=timeout,
            max_redirects=max_redirects,
            follow_redirects=True,
            headers=headers,
            **kwargs,
        )
    except PolicyViolationError as exc:
        raise UnsafeRedirectError(str(exc), []) from exc
