import os
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from os import getpid
from threading import RLock
from typing import Any, Iterator

from agent_core.url_authorization import (
    URLCanonicalizationError,
    canonicalize_transport_url,
    normalize_transport_hostname,
    path_is_within_prefix,
    validate_transport_timeout,
)
from config import (
    PENTEST_ALLOWLIST,
    PENTEST_ALLOWED_URL_PREFIXES,
)

ASSESSMENT_POLICY_UNSET = object()


class AssessmentScopeAuthorizationError(RuntimeError):
    """An explicit research authorization cannot be safely propagated."""


class RequestPermitDenied(AssessmentScopeAuthorizationError):
    """A request could not acquire authorization for dispatch."""

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(str(decision.get("error") or "Request authorization denied."))


@dataclass(eq=False)
class _AssessmentScopeLease:
    policy: Any
    owner_pid: int
    _active: bool = field(default=True, init=False, repr=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    @property
    def active(self) -> bool:
        with self._lock:
            return self._active

    def revoke(self) -> bool:
        """Revoke this lease once; repeated revocation is a safe no-op."""

        with self._lock:
            was_active = self._active
            self._active = False
            return was_active


@dataclass(frozen=True)
class AssessmentScopeTransfer:
    """Opaque reference to an existing research authorization lifetime."""

    _lease: _AssessmentScopeLease


_ACTIVE_ASSESSMENT_SCOPE: ContextVar[object] = ContextVar(
    "active_assessment_scope",
    default=ASSESSMENT_POLICY_UNSET,
)
_ACTIVE_SCOPE_OWNERS: dict[int, int] = {}
_ACTIVE_SCOPE_LOCK = RLock()


def _is_assessment_policy(policy: Any) -> bool:
    return policy is not None and callable(getattr(policy, "authorize_url", None))


@contextmanager
def assessment_policy_scope(policy: Any) -> Iterator[None]:
    """Bind one explicit policy to the current context without changing the env.

    Context variables propagate to child asyncio tasks. They do not propagate
    to new threads, and a PID check prevents a forked worker from reusing the
    parent's binding. Thread and process workers must therefore receive the
    policy explicitly (or run under an explicitly copied context).
    """

    if not _is_assessment_policy(policy):
        raise AssessmentScopeAuthorizationError(
            "An explicit assessment policy is required for research scope."
        )

    owner_pid = getpid()
    lease = _AssessmentScopeLease(policy=policy, owner_pid=owner_pid)
    token = _ACTIVE_ASSESSMENT_SCOPE.set(lease)
    with _ACTIVE_SCOPE_LOCK:
        _ACTIVE_SCOPE_OWNERS[owner_pid] = _ACTIVE_SCOPE_OWNERS.get(owner_pid, 0) + 1
    try:
        yield
    finally:
        lease.revoke()
        _ACTIVE_ASSESSMENT_SCOPE.reset(token)
        with _ACTIVE_SCOPE_LOCK:
            remaining = _ACTIVE_SCOPE_OWNERS.get(owner_pid, 0) - 1
            if remaining > 0:
                _ACTIVE_SCOPE_OWNERS[owner_pid] = remaining
            else:
                _ACTIVE_SCOPE_OWNERS.pop(owner_pid, None)


def _explicit_scope_active() -> bool:
    with _ACTIVE_SCOPE_LOCK:
        return bool(_ACTIVE_SCOPE_OWNERS)


def _lease_error(lease: _AssessmentScopeLease) -> str | None:
    if lease.owner_pid != getpid():
        return "Assessment scope was not explicitly transferred to this process."
    if not lease.active:
        return "Assessment scope authorization has expired."
    return None


def capture_assessment_policy_scope(
    policy: Any,
) -> AssessmentScopeTransfer | None:
    """Validate a caller policy and capture only its active scope lease.

    A ``None`` return means there is no context-local research scope. The
    explicit policy is still required and is revalidated by the discovery tool
    at each URL boundary. An active scope must use the identical policy object.
    """

    if not _is_assessment_policy(policy):
        raise AssessmentScopeAuthorizationError(
            "An explicit assessment policy is required for worker dispatch."
        )

    active = _ACTIVE_ASSESSMENT_SCOPE.get()
    if isinstance(active, _AssessmentScopeLease):
        error = _lease_error(active)
        if error is not None:
            raise AssessmentScopeAuthorizationError(error)
        if policy is not active.policy:
            raise AssessmentScopeAuthorizationError(
                "Tool policy conflicts with the active research scope."
            )
        return AssessmentScopeTransfer(active)
    return None


def resolve_assessment_policy_authority(
    assessment_policy: Any = ASSESSMENT_POLICY_UNSET,
) -> Any:
    """Return the one policy authoritative for the current execution context.

    The unset sentinel means legacy environment authorization applies.  An active
    research lease always remains authoritative, and an explicitly supplied
    policy must be the identical object.  This lets trusted transport boundaries
    bind auxiliary clients to the same authority without exposing or copying the
    lease itself.
    """

    active = _ACTIVE_ASSESSMENT_SCOPE.get()
    if isinstance(active, _AssessmentScopeLease):
        error = _lease_error(active)
        if error is not None:
            raise AssessmentScopeAuthorizationError(error)
        if (
            assessment_policy is not ASSESSMENT_POLICY_UNSET
            and assessment_policy is not active.policy
        ):
            raise AssessmentScopeAuthorizationError(
                "Explicit assessment policy conflicts with the active research scope."
            )
        return active.policy
    if assessment_policy is ASSESSMENT_POLICY_UNSET:
        return ASSESSMENT_POLICY_UNSET
    if not _is_assessment_policy(assessment_policy):
        raise AssessmentScopeAuthorizationError(
            "An explicit assessment policy is required for request authorization."
        )
    return assessment_policy


@contextmanager
def propagated_assessment_policy_scope(
    transfer: AssessmentScopeTransfer | None,
) -> Iterator[None]:
    """Propagate one validated live lease into a worker execution context."""

    if transfer is None:
        yield
        return
    if not isinstance(transfer, AssessmentScopeTransfer):
        raise AssessmentScopeAuthorizationError(
            "Assessment scope transfer is missing or invalid."
        )

    lease = transfer._lease
    error = _lease_error(lease)
    if error is not None:
        raise AssessmentScopeAuthorizationError(error)
    active = _ACTIVE_ASSESSMENT_SCOPE.get()
    if active is not ASSESSMENT_POLICY_UNSET and active is not lease:
        raise AssessmentScopeAuthorizationError(
            "Worker context conflicts with the transferred research scope."
        )

    token = _ACTIVE_ASSESSMENT_SCOPE.set(lease)
    try:
        error = _lease_error(lease)
        if error is not None:
            raise AssessmentScopeAuthorizationError(error)
        yield
    finally:
        _ACTIVE_ASSESSMENT_SCOPE.reset(token)


def _denied(target: str, error: str, source: str) -> dict[str, Any]:
    return {
        "allowed": False,
        "target": target,
        "error": error,
        "authorization_source": source,
    }


def _policy_scope_decision(
    target: str,
    policy: Any,
    *,
    source: str,
) -> dict[str, Any]:
    if not _is_assessment_policy(policy):
        return _denied(
            target, "Explicit assessment scope is missing or invalid.", source
        )
    try:
        decision = policy.authorize_url(target, method="GET")
    except Exception:
        return _denied(target, "Explicit assessment scope validation failed.", source)
    if not bool(getattr(decision, "allowed", False)):
        return _denied(
            target, "Target is outside the explicit assessment scope.", source
        )
    return {
        "allowed": True,
        "target": target,
        "message": "Target is within the explicit assessment scope",
        "authorization_source": source,
    }


def _require_allowed(decision: dict[str, Any]) -> None:
    if not decision.get("allowed"):
        raise RequestPermitDenied(decision)


@contextmanager
def request_dispatch_permit(
    target: str,
    *,
    assessment_policy: Any = ASSESSMENT_POLICY_UNSET,
    timeout: Any = 30.0,
) -> Iterator[dict[str, Any]]:
    """Authorize and admit one synchronous request relative to scope revocation.

    Policy evaluation happens before the per-lease admission lock is acquired.
    Admission linearizes when that lock is acquired and the lease is found live.
    Revocation uses the same lock. If revocation wins, dispatch is denied. If
    admission wins, revocation waits for this context to exit, so an admitted
    synchronous request may complete. The caller must pass the returned finite
    timeout to a cooperative synchronous transport. Python cannot forcibly stop
    arbitrary client code that ignores that timeout. This permit must not span
    an async await.
    """

    active = _ACTIVE_ASSESSMENT_SCOPE.get()
    lease: _AssessmentScopeLease | None = None
    policy = assessment_policy
    source = "explicit_policy"
    explicit_authorization = (
        isinstance(active, _AssessmentScopeLease)
        or assessment_policy is not ASSESSMENT_POLICY_UNSET
    )
    try:
        canonical = canonicalize_transport_url(
            target if explicit_authorization else normalize_url(target)
        )
        dispatch_timeout = validate_transport_timeout(timeout)
    except (URLCanonicalizationError, ValueError) as exc:
        raise RequestPermitDenied(
            _denied(
                target,
                f"Request target or timeout is invalid: {exc}",
                source if explicit_authorization else "legacy_environment",
            )
        ) from exc
    target = canonical.url

    if isinstance(active, _AssessmentScopeLease):
        error = _lease_error(active)
        if error is not None:
            raise RequestPermitDenied(_denied(target, error, "context_policy"))
        if (
            assessment_policy is not ASSESSMENT_POLICY_UNSET
            and assessment_policy is not active.policy
        ):
            raise RequestPermitDenied(
                _denied(
                    target,
                    "Explicit assessment policy conflicts with the active research scope.",
                    "explicit_policy",
                )
            )
        lease = active
        policy = (
            active.policy
            if assessment_policy is ASSESSMENT_POLICY_UNSET
            else assessment_policy
        )
        source = (
            "context_policy"
            if assessment_policy is ASSESSMENT_POLICY_UNSET
            else "explicit_policy"
        )
    elif assessment_policy is ASSESSMENT_POLICY_UNSET:
        decision = enforce_scope(target)
        _require_allowed(decision)
        decision["dispatch_timeout"] = dispatch_timeout
        yield decision
        return

    decision = _policy_scope_decision(target, policy, source=source)
    _require_allowed(decision)
    decision["dispatch_timeout"] = dispatch_timeout
    if lease is None:
        yield decision
        return

    lease._lock.acquire()
    try:
        error = _lease_error(lease)
        if error is not None:
            raise RequestPermitDenied(_denied(target, error, source))
        if _ACTIVE_ASSESSMENT_SCOPE.get() is not lease:
            raise RequestPermitDenied(
                _denied(
                    target,
                    "Request scope changed before dispatch admission.",
                    source,
                )
            )
        yield decision
    finally:
        lease._lock.release()


def refresh_scope_from_environment(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Refresh the legacy guard after a trusted boundary updates its environment.

    The legacy discovery tools import this module before a benchmark factory is
    invoked, so changing ``os.environ`` alone would leave the imported values
    stale.  Keeping this refresh explicit also prevents ordinary tool callers
    from silently widening scope through later environment mutations.
    """

    source = os.environ if environment is None else environment
    allowlist = source.get("PENTEST_ALLOWLIST", "")
    prefixes = source.get("PENTEST_ALLOWED_URL_PREFIXES", "")
    if not isinstance(allowlist, str) or not isinstance(prefixes, str):
        raise ValueError("legacy scope environment values must be strings")

    global PENTEST_ALLOWLIST, PENTEST_ALLOWED_URL_PREFIXES
    PENTEST_ALLOWLIST = allowlist
    PENTEST_ALLOWED_URL_PREFIXES = prefixes
    return allowlist, prefixes


def get_allowed_domains() -> list[str]:
    return [
        item.strip().lower().rstrip(".")
        for item in PENTEST_ALLOWLIST.split(",")
        if item.strip()
    ]


def get_allowed_url_prefixes() -> list[str]:
    return [
        item.strip().rstrip("/")
        for item in PENTEST_ALLOWED_URL_PREFIXES.split(",")
        if item.strip()
    ]


def normalize_url(target: str) -> str:
    target = target.strip()

    if "://" not in target:
        target = f"https://{target}"

    return target


def normalize_path(path: str) -> str:
    if not path:
        return "/"

    if not path.startswith("/"):
        path = f"/{path}"

    # Remove trailing slash except for the root path.
    if path != "/":
        path = path.rstrip("/")

    return path


def get_effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port

    if parsed.scheme == "https":
        return 443

    if parsed.scheme == "http":
        return 80

    return None


def is_domain_allowed(target: str) -> bool:
    try:
        canonical = canonicalize_transport_url(normalize_url(target))
    except URLCanonicalizationError:
        return False
    host = canonical.hostname

    for allowed in get_allowed_domains():
        # Domain allowlist entries should not contain URLs or paths.
        try:
            allowed_host = normalize_transport_hostname(allowed)
        except URLCanonicalizationError:
            continue
        if host == allowed_host:
            return True

    return False


def is_url_prefix_allowed(target: str) -> bool:
    try:
        target_url = canonicalize_transport_url(normalize_url(target))
    except URLCanonicalizationError:
        return False

    for allowed_url in get_allowed_url_prefixes():
        try:
            allowed = canonicalize_transport_url(normalize_url(allowed_url))
        except URLCanonicalizationError:
            continue
        if allowed.query:
            continue

        same_origin = (
            target_url.scheme == allowed.scheme
            and target_url.hostname == allowed.hostname
            and target_url.port == allowed.port
        )
        if same_origin and path_is_within_prefix(target_url.path, allowed.path):
            return True

    return False


def is_target_allowed(target: str) -> bool:
    try:
        canonical = canonicalize_transport_url(normalize_url(target))
    except URLCanonicalizationError:
        return False
    host = canonical.hostname
    # A configured URL prefix for this host is the narrower authorization and
    # must not be bypassed merely because the host also appears in the domain
    # allowlist.
    host_has_prefix = False
    for prefix in get_allowed_url_prefixes():
        try:
            allowed = canonicalize_transport_url(normalize_url(prefix))
        except URLCanonicalizationError:
            continue
        if not allowed.query and allowed.hostname == host:
            host_has_prefix = True
            break
    if host_has_prefix:
        return is_url_prefix_allowed(target)
    return is_domain_allowed(target) or is_url_prefix_allowed(target)


def enforce_scope(
    target: str,
    *,
    assessment_policy: Any = ASSESSMENT_POLICY_UNSET,
) -> dict[str, Any]:
    """Authorize a target with explicit, context-local, then legacy precedence.

    An explicitly supplied policy always wins over legacy environment scope.
    When a context-local policy also exists, the explicit policy must be the
    same policy object to prevent cross-research authorization. A missing or
    invalid explicit policy never falls back to legacy scope.
    """

    active = _ACTIVE_ASSESSMENT_SCOPE.get()
    explicit_authorization = (
        assessment_policy is not ASSESSMENT_POLICY_UNSET
        or isinstance(active, _AssessmentScopeLease)
    )
    try:
        canonical = canonicalize_transport_url(
            target if explicit_authorization else normalize_url(target)
        )
    except URLCanonicalizationError as exc:
        return _denied(
            target,
            f"Target URL representation is ambiguous or malformed: {exc}",
            "explicit_policy" if explicit_authorization else "legacy_environment",
        )
    target = canonical.url
    if assessment_policy is not ASSESSMENT_POLICY_UNSET:
        if isinstance(active, _AssessmentScopeLease):
            error = _lease_error(active)
            if error is not None:
                return _denied(target, error, "explicit_policy")
            if assessment_policy is not active.policy:
                return _denied(
                    target,
                    "Explicit assessment policy conflicts with the active research scope.",
                    "explicit_policy",
                )
        return _policy_scope_decision(
            target,
            assessment_policy,
            source="explicit_policy",
        )

    if isinstance(active, _AssessmentScopeLease):
        error = _lease_error(active)
        if error is not None:
            return _denied(
                target,
                error,
                "context_policy",
            )
        return _policy_scope_decision(
            target,
            active.policy,
            source="context_policy",
        )

    if _explicit_scope_active():
        return _denied(
            target,
            "Assessment scope was not explicitly propagated to this execution context.",
            "missing_context_policy",
        )

    if not is_target_allowed(target):
        return {
            "allowed": False,
            "target": target,
            "error": (
                "Target is not covered by PENTEST_ALLOWLIST "
                "or PENTEST_ALLOWED_URL_PREFIXES"
            ),
            "authorization_source": "legacy_environment",
        }

    return {
        "allowed": True,
        "target": target,
        "message": "Target is within the configured testing scope",
        "authorization_source": "legacy_environment",
    }
