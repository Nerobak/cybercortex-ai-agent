"""Deterministic rules-of-engagement compiler and policy profile storage.

Profiles are persistence around :class:`AssessmentPolicy`; they are not a
second authorization engine.  Every selected profile is compiled into the
same model used by the request, redirect, plan, and execution gates.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

from agent_core.agent_models import (
    PolicyDecision,
    RiskLevel,
    StrictModel,
    VerificationPlan,
    VerificationStep,
)

NON_OVERRIDABLE_TECHNIQUES = {
    "denial_of_service",
    "destructive_action",
    "credential_stuffing",
    "password_spraying",
    "phishing",
    "social_engineering",
    "malware",
    "persistence",
    "stealth_evasion",
    "data_exfiltration",
}
DEFAULT_PROHIBITED_TECHNIQUES = sorted(NON_OVERRIDABLE_TECHNIQUES)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DEFAULT_POLICY_DIRECTORY = Path("config/policies")
DEFAULT_HOST_MAPPING_PATH = Path("config/policy-host-mappings.json")
PROFILE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

ACCOUNT_NOT_ELIGIBLE_REASON = (
    "Controlled account is not eligible under the selected policy."
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_profile_name(value: str) -> str:
    """Return a safe canonical profile name or fail before path resolution."""
    name = str(value).strip().lower()
    if not PROFILE_NAME_PATTERN.fullmatch(name) or name in {".", ".."}:
        raise ValueError(
            "Profile names must use 1-64 lowercase letters, digits, dots, "
            "underscores, or hyphens and may not contain a path."
        )
    return name


def normalize_hostname(value: str) -> str:
    """Normalize an exact hostname without accepting URL or wildcard syntax."""
    raw = str(value).strip().lower().rstrip(".")
    if not raw or any(character.isspace() for character in raw):
        raise ValueError("hostname cannot be empty or contain whitespace")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if any(token in raw for token in ("://", "/", "@", "?", "#", "*", ":")):
        raise ValueError("hostname must be an exact host without scheme, port, or path")
    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("hostname is not valid IDNA") from exc
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("hostname contains an invalid DNS label")
    if len(ascii_host) > 253:
        raise ValueError("hostname is too long")
    return ascii_host


class ScopeAsset(StrictModel):
    kind: Literal["exact_host", "wildcard_host", "url_prefix", "cidr"]
    value: str
    ports: list[int] = Field(default_factory=list, max_length=100)
    schemes: list[Literal["http", "https"]] = Field(default_factory=lambda: ["https"])

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("scope asset value cannot be empty")
        return cleaned

    @field_validator("schemes")
    @classmethod
    def normalize_schemes(cls, values: list[str]) -> list[str]:
        normalized = sorted({str(value).strip().lower() for value in values})
        if not normalized:
            raise ValueError("scope assets require at least one allowed scheme")
        return normalized

    @model_validator(mode="after")
    def validate_asset_shape(self) -> "ScopeAsset":
        if self.kind == "exact_host":
            object.__setattr__(self, "value", normalize_hostname(self.value))
        elif self.kind == "wildcard_host":
            suffix = self.value.strip().lower()
            if suffix.startswith("*."):
                suffix = suffix[2:]
            object.__setattr__(self, "value", f"*.{normalize_hostname(suffix)}")
            try:
                ipaddress.ip_address(suffix)
            except ValueError:
                pass
            else:
                raise ValueError("wildcard scope cannot use an IP address")
        elif self.kind == "url_prefix":
            parsed = urlparse(self.value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "url_prefix must be an absolute HTTP(S) URL without credentials, query, or fragment"
                )
            normalize_hostname(parsed.hostname)
            if parsed.scheme not in self.schemes:
                raise ValueError(
                    "url_prefix scheme must be present in the asset schemes"
                )
            if self.ports and _origin_port(parsed) not in self.ports:
                raise ValueError("url_prefix port must be present in the asset ports")
        elif self.kind == "cidr":
            try:
                object.__setattr__(
                    self, "value", str(ipaddress.ip_network(self.value, strict=False))
                )
            except ValueError as exc:
                raise ValueError("cidr scope asset is malformed") from exc
        return self


class TestingWindow(StrictModel):
    starts_at: datetime
    ends_at: datetime

    @model_validator(mode="after")
    def chronological(self) -> "TestingWindow":
        start = self.starts_at
        end = self.ends_at
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if end <= start:
            raise ValueError("testing window ends_at must be later than starts_at")
        return self

    def contains(self, moment: datetime) -> bool:
        start = self.starts_at
        end = self.ends_at
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return start <= moment <= end


class PolicyChange(StrictModel):
    version: int = Field(ge=1)
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    updated_at: datetime
    authorization_reference: str
    snapshot: dict[str, Any]


class AccountEligibilityDecision(StrictModel):
    """Secret-free decision for the policy/context account intersection."""

    eligible: bool
    reason_code: Literal["eligible", "not_controlled", "not_allowed"]
    reason: str | None = None


class AccountEligibilityContext(StrictModel):
    """Minimal secret-free controlled-account set for transport revalidation."""

    controlled_account_ids: list[str] = Field(default_factory=list, max_length=20)


class AssessmentPolicy(StrictModel):
    profile_name: str | None = None
    policy_version: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None
    policy_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    change_history: list[PolicyChange] = Field(default_factory=list)
    cloned_from: str | None = None
    program_name: str = "local-authorized-assessment"
    authorization_reference: str | None = None
    authorization_confirmed: bool = False
    allowed_assets: list[ScopeAsset] = Field(default_factory=list, max_length=1000)
    excluded_assets: list[ScopeAsset] = Field(default_factory=list, max_length=1000)
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "HEAD", "OPTIONS"]
    )
    prohibited_techniques: list[str] = Field(
        default_factory=lambda: list(DEFAULT_PROHIBITED_TECHNIQUES)
    )
    allowed_capabilities: list[str] = Field(default_factory=list, max_length=200)
    oast_allowed: bool = False
    callback_hosts: list[str] = Field(default_factory=list, max_length=50)
    testing_windows: list[TestingWindow] = Field(default_factory=list, max_length=100)
    requests_per_second: float = Field(default=2.0, gt=0, le=100)
    max_concurrency: int = Field(default=2, ge=1, le=20)
    request_budget: int = Field(default=100, ge=1, le=5000)
    per_host_request_budget: int = Field(default=50, ge=1, le=1000)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=20_000_000)
    max_redirects: int = Field(default=5, ge=0, le=10)
    credentials_allowed: bool = False
    controlled_account_ids: list[str] = Field(default_factory=list, max_length=20)
    allow_bounded_rate_limit_verification: bool = False
    max_rate_limit_attempts: int = Field(default=0, ge=0, le=100)
    allow_state_changes: bool = False
    require_test_owned_resources: bool = True
    require_cleanup_for_state_changes: bool = True
    verify_tls: bool = True
    resolve_dns_before_request: bool = True

    def account_is_eligible(
        self,
        account_id: str,
        controlled_context: Any,
        *,
        account_controlled: bool | None = None,
    ) -> AccountEligibilityDecision:
        """Apply the one controlled-context/policy account intersection rule.

        An empty policy allowlist adds no account-ID restriction. It never
        turns an unknown or uncontrolled account into a controlled account.
        ``controlled_context`` may be the full ``ControlledContext`` or the
        gate's secret-free ``Phase2PolicyContext``.
        """

        context_controlled = False
        accounts = getattr(controlled_context, "accounts", None)
        if isinstance(accounts, list):
            matches = [
                account
                for account in accounts
                if getattr(account, "account_id", None) == account_id
            ]
            context_controlled = bool(
                len(matches) == 1 and getattr(matches[0], "controlled", False)
            )
        else:
            controlled_ids = getattr(controlled_context, "controlled_account_ids", ())
            context_controlled = account_id in controlled_ids

        if account_controlled is not None:
            context_controlled = context_controlled and account_controlled
        if not context_controlled:
            return AccountEligibilityDecision(
                eligible=False,
                reason_code="not_controlled",
                reason=ACCOUNT_NOT_ELIGIBLE_REASON,
            )
        if (
            self.controlled_account_ids
            and account_id not in self.controlled_account_ids
        ):
            return AccountEligibilityDecision(
                eligible=False,
                reason_code="not_allowed",
                reason=ACCOUNT_NOT_ELIGIBLE_REASON,
            )
        return AccountEligibilityDecision(
            eligible=True,
            reason_code="eligible",
        )

    @field_validator("profile_name")
    @classmethod
    def validate_profile_name(cls, value: str | None) -> str | None:
        return normalize_profile_name(value) if value is not None else None

    @field_validator("authorization_reference")
    @classmethod
    def normalize_authorization_reference(cls, value: str | None) -> str | None:
        cleaned = str(value).strip() if value is not None else ""
        return cleaned or None

    @field_validator("allowed_methods")
    @classmethod
    def normalize_methods(cls, methods: list[str]) -> list[str]:
        normalized = sorted({str(method).strip().upper() for method in methods})
        if not normalized or any(not method.isalpha() for method in normalized):
            raise ValueError("allowed_methods must contain HTTP method names")
        return normalized

    @field_validator("prohibited_techniques")
    @classmethod
    def preserve_non_overridable_blocks(cls, techniques: list[str]) -> list[str]:
        return sorted(
            {str(item).strip().lower() for item in techniques}
            | NON_OVERRIDABLE_TECHNIQUES
        )

    @field_validator("allowed_capabilities")
    @classmethod
    def normalize_capabilities(cls, capabilities: list[str]) -> list[str]:
        return sorted(
            {str(item).strip().lower() for item in capabilities if str(item).strip()}
        )

    @field_validator("callback_hosts")
    @classmethod
    def normalize_callback_hosts(cls, hosts: list[str]) -> list[str]:
        return sorted({normalize_hostname(host) for host in hosts})

    def is_within_testing_window(self, moment: datetime | None = None) -> bool:
        if not self.testing_windows:
            return True
        current = moment or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return any(window.contains(current) for window in self.testing_windows)

    def authorize_url(self, url: str, *, method: str = "GET") -> PolicyDecision:
        decision = self._authorize_url_base(url, method=method)
        reasons = list(decision.reasons)
        normalized_method = method.strip().upper()
        if normalized_method in STATE_CHANGING_METHODS and not self.allow_state_changes:
            reasons.append("State-changing requests are disabled by policy.")
        return PolicyDecision(
            allowed=not reasons,
            reasons=reasons,
            matched_rule=decision.matched_rule,
            remaining_request_budget=decision.remaining_request_budget,
        )

    def authorize_oast(self, callback_url: str) -> PolicyDecision:
        """Authorize use of one exact callback host without widening target scope."""
        reasons: list[str] = []
        parsed = urlparse(callback_url)
        callback_host = (parsed.hostname or "").lower().rstrip(".")
        if not self.authorization_confirmed:
            reasons.append("Explicit authorization was not confirmed by the policy.")
        if not self.oast_allowed:
            reasons.append("OAST is disabled by policy.")
        if "oast" not in self.allowed_capabilities:
            reasons.append("The OAST capability is not allowed by policy.")
        if parsed.scheme not in {"http", "https"} or not callback_host:
            reasons.append("The OAST callback URL is invalid.")
        if callback_host not in self.callback_hosts:
            reasons.append("The OAST callback host is not allowed by policy.")
        return PolicyDecision(
            allowed=not reasons,
            reasons=list(dict.fromkeys(reasons)),
            matched_rule=(
                f"callback_host:{callback_host}"
                if callback_host in self.callback_hosts
                else None
            ),
            remaining_request_budget=self.request_budget,
        )

    def _authorize_url_base(self, url: str, *, method: str) -> PolicyDecision:
        """Check authorization, scope, and method without assigning action semantics.

        This is not a complete execution authorization. It exists for typed gates,
        such as controlled session acquisition, that apply their own stricter
        semantic checks before a request can be sent.
        """
        reasons: list[str] = []
        parsed = urlparse(url)
        if not self.authorization_confirmed:
            reasons.append("Explicit authorization was not confirmed by the policy.")
        if not self.authorization_reference:
            reasons.append(
                "A verifiable authorization reference is missing from the policy."
            )
        if not self.program_name.strip():
            reasons.append("The authorized program name is missing from the policy.")
        if not self.is_within_testing_window():
            reasons.append("The current time is outside the configured testing window.")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            reasons.append("The target must be an absolute HTTP(S) URL.")
        if parsed.username is not None or parsed.password is not None:
            reasons.append("Credentials in target URLs are not permitted.")
        normalized_method = method.strip().upper()
        if normalized_method not in self.allowed_methods:
            reasons.append(f"HTTP method {normalized_method} is not allowed.")
        if any(_asset_matches(asset, url) for asset in self.excluded_assets):
            reasons.append("The target matches an explicit scope exclusion.")
        matched = next(
            (asset for asset in self.allowed_assets if _asset_matches(asset, url)), None
        )
        if matched is None:
            reasons.append("The target does not match an authorized asset rule.")
        return PolicyDecision(
            allowed=not reasons,
            reasons=reasons,
            matched_rule=(f"{matched.kind}:{matched.value}" if matched else None),
            remaining_request_budget=self.request_budget,
        )

    def authorize_step(
        self,
        step: VerificationStep,
        *,
        target: str,
        credentials_supplied: bool = False,
        test_owned_resources: list[str] | None = None,
    ) -> PolicyDecision:
        decision = self.authorize_url(target, method=step.method or "GET")
        reasons = list(decision.reasons)
        prohibited = {
            str(item).strip().lower() for item in step.metadata.get("techniques", [])
        } & set(self.prohibited_techniques)
        if step.risk == RiskLevel.prohibited:
            reasons.append("The step is classified as prohibited risk.")
        if prohibited:
            reasons.append(
                "Prohibited technique requested: " + ", ".join(sorted(prohibited))
            )
        if step.requires_credentials and not (
            self.credentials_allowed and credentials_supplied
        ):
            reasons.append(
                "The step requires controlled credentials not authorized by policy."
            )
        if step.state_changing:
            if not self.allow_state_changes:
                reasons.append("State-changing requests are disabled by policy.")
            if self.require_test_owned_resources and not (test_owned_resources or []):
                reasons.append("A confirmed test-owned resource is required.")
            if self.require_cleanup_for_state_changes and not (
                step.cleanup_required and step.cleanup_steps
            ):
                reasons.append("A deterministic cleanup plan is required.")
        if step.request_cost > self.request_budget:
            reasons.append("The step exceeds the total request budget.")
        return PolicyDecision(
            allowed=not reasons,
            reasons=reasons,
            matched_rule=decision.matched_rule,
            remaining_request_budget=max(0, self.request_budget - step.request_cost),
        )

    def authorize_plan(self, plan: VerificationPlan) -> PolicyDecision:
        reasons: list[str] = []
        if plan.estimated_requests > min(plan.request_budget, self.request_budget):
            reasons.append(
                "The verification plan exceeds its effective request budget."
            )
        for step in plan.steps:
            category = str(step.metadata.get("category") or "")
            if (
                step.tool
                in {
                    "authorization_differential_tester",
                    "graphql_authz_planner",
                }
                and len(set(plan.controlled_accounts)) < 2
            ):
                reasons.append(
                    f"{step.step_id}: Two distinct controlled accounts are required."
                )
            if category == "ssrf" and (
                not self.oast_allowed
                or "oast" not in self.allowed_capabilities
                or not self.callback_hosts
            ):
                reasons.append(
                    f"{step.step_id}: SSRF verification requires an explicitly allowed OAST capability and callback host."
                )
            result = self.authorize_step(
                step,
                target=plan.target,
                credentials_supplied=plan.credentials_supplied,
                test_owned_resources=plan.test_owned_resources,
            )
            reasons.extend(f"{step.step_id}: {reason}" for reason in result.reasons)
        return PolicyDecision(
            allowed=not reasons,
            reasons=reasons,
            remaining_request_budget=max(
                0, self.request_budget - plan.estimated_requests
            ),
        )


def _origin_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None


def _asset_matches(asset: ScopeAsset, target: str) -> bool:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or parsed.scheme not in asset.schemes:
        return False
    port = _origin_port(parsed)
    if asset.ports and port not in asset.ports:
        return False
    if asset.kind == "exact_host":
        return host == asset.value.lower().rstrip(".")
    if asset.kind == "wildcard_host":
        suffix = asset.value.lower().lstrip("*.").rstrip(".")
        return bool(suffix) and host.endswith(f".{suffix}") and host != suffix
    if asset.kind == "url_prefix":
        allowed = urlparse(
            asset.value if "://" in asset.value else f"https://{asset.value}"
        )
        same_origin = (
            parsed.scheme.lower(),
            host,
            port,
        ) == (
            allowed.scheme.lower(),
            (allowed.hostname or "").lower().rstrip("."),
            _origin_port(allowed),
        )
        allowed_path = (allowed.path or "/").rstrip("/") or "/"
        target_path = (parsed.path or "/").rstrip("/") or "/"
        return same_origin and (
            allowed_path == "/"
            or target_path == allowed_path
            or target_path.startswith(f"{allowed_path}/")
        )
    if asset.kind == "cidr":
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(
                asset.value, strict=False
            )
        except ValueError:
            return False
    return False


def compile_policy(manifest: dict[str, Any]) -> AssessmentPolicy:
    """Validate a program manifest and fail closed on ambiguous scope."""
    data = dict(manifest)
    allowed = data.get("allowed_assets", [])
    excluded = data.get("excluded_assets", [])
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("Policy manifest requires at least one allowed asset.")
    if not isinstance(excluded, list):
        raise ValueError("excluded_assets must be a list.")
    data["allowed_assets"] = [
        item if isinstance(item, dict) else {"kind": "exact_host", "value": str(item)}
        for item in allowed
    ]
    data["excluded_assets"] = [
        item if isinstance(item, dict) else {"kind": "exact_host", "value": str(item)}
        for item in excluded
    ]
    return AssessmentPolicy.model_validate(data)


def load_policy(path: str | Path) -> AssessmentPolicy:
    policy_path = Path(path)
    try:
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed policy JSON in {policy_path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Policy JSON must contain an object at the top level.")
    return compile_policy(payload)


def policy_hash(policy: AssessmentPolicy | dict[str, Any]) -> str:
    """Hash the exact saved version and history, excluding only its own hash."""
    if isinstance(policy, AssessmentPolicy):
        material = policy.model_dump(mode="json")
    else:
        material = dict(policy)
    material.pop("policy_hash", None)
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def policy_validation_errors(
    policy: AssessmentPolicy,
    *,
    moment: datetime | None = None,
    require_profile_metadata: bool = False,
) -> list[str]:
    """Return deterministic fail-closed profile errors without mutating policy."""
    errors: list[str] = []
    if not policy.authorization_confirmed:
        errors.append("authorization_confirmed must be true")
    if not policy.authorization_reference:
        errors.append("authorization_reference is required")
    if not policy.program_name.strip():
        errors.append("program_name is required")
    if not policy.allowed_assets:
        errors.append("at least one allowed asset is required")
    if not policy.is_within_testing_window(moment):
        errors.append("the testing window is expired or not currently active")
    if policy.oast_allowed and (
        "oast" not in policy.allowed_capabilities or not policy.callback_hosts
    ):
        errors.append(
            "OAST requires the oast capability and at least one callback host"
        )
    if policy.callback_hosts and not policy.oast_allowed:
        errors.append("callback hosts are configured while OAST permission is disabled")
    if require_profile_metadata:
        if not policy.profile_name:
            errors.append("profile_name metadata is required")
        if policy.created_at is None or policy.updated_at is None:
            errors.append("created_at and updated_at metadata are required")
        if not policy.policy_hash:
            errors.append("policy_hash metadata is required")
    return errors


def validate_policy(
    policy: AssessmentPolicy,
    *,
    moment: datetime | None = None,
    require_profile_metadata: bool = False,
) -> AssessmentPolicy:
    errors = policy_validation_errors(
        policy,
        moment=moment,
        require_profile_metadata=require_profile_metadata,
    )
    if errors:
        raise ValueError("Policy is not valid for execution: " + "; ".join(errors))
    return policy


def _snapshot_for_history(policy: AssessmentPolicy) -> dict[str, Any]:
    snapshot = policy.model_dump(mode="json")
    snapshot.pop("change_history", None)
    return snapshot


class PolicyProfileStore:
    """Versioned storage for immutable-at-run-time policy profiles."""

    def __init__(
        self,
        directory: str | Path = DEFAULT_POLICY_DIRECTORY,
        *,
        mapping_path: str | Path | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.mapping_path = (
            Path(mapping_path)
            if mapping_path
            else (
                DEFAULT_HOST_MAPPING_PATH
                if self.directory == DEFAULT_POLICY_DIRECTORY
                else self.directory.parent / "policy-host-mappings.json"
            )
        )

    def path_for(self, profile: str) -> Path:
        return self.directory / f"{normalize_profile_name(profile)}.json"

    def list(self) -> list[str]:
        if not self.directory.exists():
            return []
        return sorted(
            path.stem
            for path in self.directory.glob("*.json")
            if PROFILE_NAME_PATTERN.fullmatch(path.stem)
        )

    def load(
        self, profile: str, *, validate_for_execution: bool = False
    ) -> AssessmentPolicy:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if not path.is_file():
            raise ValueError(f"Policy profile '{name}' does not exist at {path}.")
        policy = load_policy(path)
        if policy.profile_name != name:
            raise ValueError(
                f"Policy profile metadata mismatch: expected '{name}', found "
                f"'{policy.profile_name or 'missing'}'."
            )
        metadata_errors = policy_validation_errors(
            policy, require_profile_metadata=True
        )
        metadata_only = [
            error for error in metadata_errors if "metadata is required" in error
        ]
        if metadata_only:
            raise ValueError(
                "Invalid policy profile metadata: " + "; ".join(metadata_only)
            )
        expected_hash = policy_hash(policy)
        if policy.policy_hash != expected_hash:
            raise ValueError(
                f"Policy profile '{name}' hash mismatch; use policy_cli.py edit so changes are versioned."
            )
        if validate_for_execution:
            validate_policy(policy, require_profile_metadata=True)
        return policy

    def create(
        self,
        profile: str,
        manifest: AssessmentPolicy | dict[str, Any],
        *,
        cloned_from: str | None = None,
    ) -> AssessmentPolicy:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if path.exists():
            raise ValueError(f"Policy profile '{name}' already exists.")
        source = (
            manifest.model_dump(mode="json")
            if isinstance(manifest, AssessmentPolicy)
            else dict(manifest)
        )
        for key in (
            "profile_name",
            "policy_version",
            "created_at",
            "updated_at",
            "policy_hash",
            "change_history",
            "cloned_from",
        ):
            source.pop(key, None)
        now = _utc_now()
        source.update(
            {
                "profile_name": name,
                "policy_version": 1,
                "created_at": now,
                "updated_at": now,
                "change_history": [],
                "cloned_from": (
                    normalize_profile_name(cloned_from) if cloned_from else None
                ),
            }
        )
        policy = compile_policy(source)
        policy.policy_hash = policy_hash(policy)
        self._write(path, policy)
        return policy

    def update(
        self, profile: str, manifest: AssessmentPolicy | dict[str, Any]
    ) -> AssessmentPolicy:
        name = normalize_profile_name(profile)
        previous = self.load(name)
        source = (
            manifest.model_dump(mode="json")
            if isinstance(manifest, AssessmentPolicy)
            else dict(manifest)
        )
        for key in (
            "profile_name",
            "policy_version",
            "created_at",
            "updated_at",
            "policy_hash",
            "change_history",
            "cloned_from",
        ):
            source.pop(key, None)
        history = list(previous.change_history)
        history.append(
            PolicyChange(
                version=previous.policy_version,
                policy_hash=str(previous.policy_hash),
                updated_at=previous.updated_at or previous.created_at or _utc_now(),
                authorization_reference=previous.authorization_reference or "",
                snapshot=_snapshot_for_history(previous),
            )
        )
        source.update(
            {
                "profile_name": name,
                "policy_version": previous.policy_version + 1,
                "created_at": previous.created_at,
                "updated_at": _utc_now(),
                "change_history": [item.model_dump(mode="json") for item in history],
                "cloned_from": previous.cloned_from,
            }
        )
        policy = compile_policy(source)
        policy.policy_hash = policy_hash(policy)
        self._write(self.path_for(name), policy)
        return policy

    def clone(self, source: str, new_profile: str) -> AssessmentPolicy:
        source_name = normalize_profile_name(source)
        policy = self.load(source_name, validate_for_execution=True)
        return self.create(new_profile, policy, cloned_from=source_name)

    def delete(self, profile: str) -> None:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if not path.is_file():
            raise ValueError(f"Policy profile '{name}' does not exist.")
        path.unlink()
        mappings = self._read_mappings()
        filtered = {host: item for host, item in mappings.items() if item != name}
        if filtered != mappings:
            self._write_mappings(filtered)

    def map_host(self, host: str, profile: str) -> None:
        normalized_host = normalize_hostname(host)
        name = normalize_profile_name(profile)
        policy = self.load(name, validate_for_execution=True)
        if not _policy_contains_host(policy, normalized_host):
            raise ValueError(
                f"Host '{normalized_host}' is not authorized by policy profile '{name}'."
            )
        mappings = self._read_mappings()
        mappings[normalized_host] = name
        self._write_mappings(mappings)

    def profile_for_host(self, host: str) -> str | None:
        """Resolve only an existing exact mapping; never infer or create scope."""
        normalized_host = normalize_hostname(host)
        profile = self._read_mappings().get(normalized_host)
        if profile is None:
            return None
        self.load(profile, validate_for_execution=True)
        return profile

    def _read_mappings(self) -> dict[str, str]:
        if not self.mapping_path.exists():
            return {}
        try:
            payload = json.loads(self.mapping_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Malformed host mapping JSON in {self.mapping_path}: {exc.msg}"
            ) from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("mappings"), dict
        ):
            raise ValueError("Host mapping file must contain a mappings object.")
        output: dict[str, str] = {}
        for host, profile in payload["mappings"].items():
            output[normalize_hostname(str(host))] = normalize_profile_name(str(profile))
        return output

    def _write_mappings(self, mappings: dict[str, str]) -> None:
        self.mapping_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "mappings": dict(sorted(mappings.items()))}
        self.mapping_path.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )

    def _write(self, path: Path, policy: AssessmentPolicy) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(policy.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )


# Manager is retained as a descriptive public alias for integrations.
PolicyProfileManager = PolicyProfileStore


def load_policy_profile(
    profile: str,
    *,
    directory: str | Path = DEFAULT_POLICY_DIRECTORY,
    validate_for_execution: bool = True,
) -> AssessmentPolicy:
    return PolicyProfileStore(directory).load(
        profile, validate_for_execution=validate_for_execution
    )


def _policy_contains_host(policy: AssessmentPolicy, host: str) -> bool:
    normalized = normalize_hostname(host)

    def host_matches(asset: ScopeAsset) -> bool:
        if asset.kind == "exact_host":
            return normalized == asset.value
        if asset.kind == "wildcard_host":
            suffix = asset.value[2:]
            return normalized.endswith(f".{suffix}") and normalized != suffix
        if asset.kind == "url_prefix":
            return normalized == normalize_hostname(
                urlparse(asset.value).hostname or ""
            )
        if asset.kind == "cidr":
            try:
                return ipaddress.ip_address(normalized) in ipaddress.ip_network(
                    asset.value
                )
            except ValueError:
                return False
        return False

    return any(host_matches(asset) for asset in policy.allowed_assets) and not any(
        host_matches(asset) for asset in policy.excluded_assets
    )


def format_policy_summary(
    policy: AssessmentPolicy,
    *,
    profile: str | None = None,
    target: str | None = None,
) -> str:
    """Render the concise authorization checkpoint shown before planning."""
    target_host = None
    if target:
        target_host = urlparse(
            target if "://" in target else f"https://{target}"
        ).hostname

    def render_asset(asset: ScopeAsset) -> str:
        value = asset.value
        if asset.kind in {"exact_host", "wildcard_host"} and asset.ports:
            value = ", ".join(f"{value}:{port}" for port in asset.ports)
        elif asset.kind == "cidr" and asset.ports:
            value = f"{value} ports {','.join(str(port) for port in asset.ports)}"
        return value

    lines = [
        "Assessment Policy",
        "-----------------",
        f"Profile: {profile or policy.profile_name or 'policy-file'}",
        f"Target: {target_host or 'capture-defined'}",
        "Authorization: "
        + ("CONFIRMED" if policy.authorization_confirmed else "NOT CONFIRMED"),
        "Scope: " + "; ".join(render_asset(asset) for asset in policy.allowed_assets),
        "Methods: " + ", ".join(policy.allowed_methods),
        f"Rate: {policy.requests_per_second:g} req/sec",
        f"Request budget: {policy.request_budget}",
        "State changes: " + ("ENABLED" if policy.allow_state_changes else "DISABLED"),
        "Credentials: " + ("ENABLED" if policy.credentials_allowed else "DISABLED"),
        "OAST: " + ("ENABLED" if policy.oast_allowed else "DISABLED"),
        "Destructive testing: BLOCKED",
        "DoS: BLOCKED",
    ]
    return "\n".join(lines)


def policy_from_runtime(
    target: str,
    *,
    profile: str,
    authorization_confirmed: bool,
    request_budget: int = 100,
) -> AssessmentPolicy:
    """Compile a narrow policy for the existing ``scan`` command."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if not parsed.hostname:
        raise ValueError("A valid target is required to compile runtime policy.")
    methods = ["GET", "HEAD", "OPTIONS"]
    credentials_allowed = profile in {"authenticated", "intrusive"}
    return AssessmentPolicy(
        program_name="legacy-scan-command",
        authorization_reference="explicit scan command",
        authorization_confirmed=authorization_confirmed,
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=target,
                schemes=[parsed.scheme or "https"],
                ports=[_origin_port(parsed)] if _origin_port(parsed) else [],
            )
        ],
        allowed_methods=methods,
        credentials_allowed=credentials_allowed,
        request_budget=request_budget,
    )
