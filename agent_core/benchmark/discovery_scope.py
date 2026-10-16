"""Fail-closed handoff from benchmark authorization to legacy discovery scope."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from agent_core.benchmark.types import BenchmarkManifest
from agent_core.policy import AssessmentPolicy
from agent_core.url_authorization import (
    URLCanonicalizationError,
    canonicalize_transport_url,
)
from tools import scope_guard


class DiscoveryScopeHandoffError(ValueError):
    """The manifest and policy cannot produce one equivalent legacy scope."""


def _canonical_authorized_root(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DiscoveryScopeHandoffError(
            "the benchmark manifest must contain one non-empty target root"
        )
    if "," in value or any(character.isspace() for character in value):
        raise DiscoveryScopeHandoffError(
            "the benchmark manifest target root is ambiguous or malformed"
        )

    try:
        canonical = canonicalize_transport_url(value)
    except URLCanonicalizationError as exc:
        raise DiscoveryScopeHandoffError(
            "the benchmark manifest target root is malformed"
        ) from exc
    if canonical.query:
        raise DiscoveryScopeHandoffError(
            "the benchmark manifest target root must be an absolute HTTP(S) URL"
        )
    path = canonical.path.rstrip("/") or "/"
    rendered = urlunsplit(
        (
            canonical.scheme,
            urlsplit(canonical.url).netloc,
            path,
            "",
            "",
        )
    )
    return rendered.rstrip("/") if path == "/" else rendered


def _validated_manifest_root(manifest: BenchmarkManifest) -> str:
    try:
        validated = BenchmarkManifest.model_validate(manifest.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise DiscoveryScopeHandoffError(
            "the benchmark manifest is missing or invalid"
        ) from exc
    return _canonical_authorized_root(validated.authorized_target_reference)


def _validate_policy_equivalence(policy: AssessmentPolicy, root: str) -> None:
    if not policy.authorization_confirmed:
        raise DiscoveryScopeHandoffError(
            "the injected assessment policy has no confirmed authorization"
        )
    if len(policy.allowed_assets) != 1:
        raise DiscoveryScopeHandoffError(
            "the injected assessment policy must contain one authorized root"
        )

    asset = policy.allowed_assets[0]
    if asset.kind != "url_prefix":
        raise DiscoveryScopeHandoffError(
            "the injected assessment policy root must be a URL prefix"
        )
    try:
        policy_root = _canonical_authorized_root(asset.value)
    except DiscoveryScopeHandoffError as exc:
        raise DiscoveryScopeHandoffError(
            "the injected assessment policy target root is malformed"
        ) from exc
    if policy_root != root:
        raise DiscoveryScopeHandoffError(
            "the manifest target root is outside the injected assessment policy"
        )

    decision = policy.authorize_url(root, method="GET")
    if not decision.allowed:
        raise DiscoveryScopeHandoffError(
            "the injected assessment policy does not authorize discovery at the root"
        )


def validate_manifest_authorized_discovery_scope(
    *,
    manifest: BenchmarkManifest,
    policy: AssessmentPolicy,
) -> str:
    """Return the one root both the manifest and injected policy authorize."""

    root = _validated_manifest_root(manifest)
    _validate_policy_equivalence(policy, root)
    return root


@contextmanager
def manifest_authorized_discovery_scope(
    *,
    manifest: BenchmarkManifest,
    policy: AssessmentPolicy,
) -> Iterator[str]:
    """Bind one validated policy to the current research execution context."""

    root = validate_manifest_authorized_discovery_scope(
        manifest=manifest,
        policy=policy,
    )
    with scope_guard.assessment_policy_scope(policy):
        if not scope_guard.enforce_scope(root).get("allowed"):
            raise DiscoveryScopeHandoffError(
                "the discovery scope rejected the manifest-authorized root"
            )

        parsed = urlsplit(root)
        unrelated = "https://unrelated.scope-handoff.invalid/"
        sibling_host = "sibling.scope-handoff.invalid"
        if parsed.hostname and ":" not in parsed.hostname:
            sibling_host = f"{parsed.hostname}.scope-handoff.invalid"
        sibling = urlunsplit((parsed.scheme, sibling_host, "/", "", ""))
        probes = [unrelated, sibling]
        if parsed.path and parsed.path != "/":
            probes.append(
                urlunsplit(
                    (parsed.scheme, parsed.netloc, f"{parsed.path}-outside", "", "")
                )
            )
        if any(scope_guard.enforce_scope(probe).get("allowed") for probe in probes):
            raise DiscoveryScopeHandoffError(
                "the discovery scope accepted an unrelated target"
            )
        yield root


__all__ = [
    "DiscoveryScopeHandoffError",
    "manifest_authorized_discovery_scope",
    "validate_manifest_authorized_discovery_scope",
]
