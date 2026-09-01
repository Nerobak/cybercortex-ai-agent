"""Strict contracts and safe evidence for bounded login rate-limit verification."""

from __future__ import annotations

import json
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import urljoin

from pydantic import ConfigDict, Field, StrictInt, field_validator

from agent_core.agent_models import Hypothesis, StrictModel, VerificationPlan
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_result_status import assess_response_instability

MAX_RATE_LIMIT_ATTEMPTS = 5
_CREDENTIAL_MARKER_PREFIX = "[CREDENTIAL_REF:"
_RATE_LIMIT_HEADER_NAMES = {
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "ratelimit-policy",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
}
_ERROR_FIELDS = ("error", "code", "message", "detail", "reason")


class LoginRateLimitSurface(StrictModel):
    boundary_type: Literal["session_creation", "credential_submission"]
    method: Literal["POST"]
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: Any) -> str:
        return str(value).strip().upper()


class AuthenticationLoginRateLimitWorkflow(StrictModel):
    """One semantically classified password-based login submission surface."""

    surface: LoginRateLimitSurface

    @classmethod
    def from_hypothesis(
        cls, hypothesis: Hypothesis
    ) -> AuthenticationLoginRateLimitWorkflow:
        if hypothesis.category != "rate_limit_enforcement":
            raise ValueError("A rate-limit-enforcement hypothesis is required.")
        related = hypothesis.metadata.get("related_surfaces")
        if not isinstance(related, list) or len(related) != 1:
            raise ValueError("Login rate-limit verification requires one surface.")
        raw = related[0]
        if not isinstance(raw, dict):
            raise ValueError("Login rate-limit surface metadata is invalid.")
        boundary_type = str(raw.get("boundary_type") or "")
        semantic_classes = {
            str(item) for item in raw.get("semantic_classes", []) if item
        }
        if boundary_type == "credential_submission" and (
            "login_session_creation" not in semantic_classes
        ):
            raise ValueError(
                "Credential-submission execution requires explicit login-session semantics."
            )
        if boundary_type not in {"session_creation", "credential_submission"}:
            raise ValueError("Only a classified login submission surface is supported.")
        path = raw.get("path")
        method = str(raw.get("method") or "").strip().upper()
        if not isinstance(path, str) or not path.strip() or method != "POST":
            raise ValueError("Login rate-limit verification requires one POST surface.")
        url = urljoin(hypothesis.target.rstrip("/") + "/", path.strip().lstrip("/"))
        expected_url = hypothesis.endpoint or url
        if hypothesis.method != "POST" or expected_url != url:
            raise ValueError(
                "The hypothesis does not exactly match its classified login surface."
            )
        return cls(
            surface=LoginRateLimitSurface(
                boundary_type=boundary_type,
                method="POST",
                url=url,
            )
        )

    def validate_plan(
        self, hypothesis: Hypothesis, plan: VerificationPlan
    ) -> list[str]:
        if plan.hypothesis_id != hypothesis.hypothesis_id or plan.target != (
            hypothesis.endpoint or self.surface.url
        ):
            return ["The rate-limit plan is not bound to the classified login surface."]
        if len(plan.steps) != 1:
            return ["The rate-limit plan must contain exactly one typed step."]
        metadata = plan.steps[0].metadata
        if (
            metadata.get("category") != "rate_limit_enforcement"
            or metadata.get("supported_mode") != "authentication_login_rate_limit"
            or metadata.get("hard_attempt_cap") != MAX_RATE_LIMIT_ATTEMPTS
            or metadata.get("requests") != []
        ):
            return ["The rate-limit plan is not the bounded typed login template."]
        return []


class ExpectedRateLimitControl(StrictModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    type: Literal["throttle_or_block_within_attempts"]
    within_attempts: StrictInt = Field(ge=1, le=MAX_RATE_LIMIT_ATTEMPTS)


class RateLimitVerificationInput(StrictModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, strict=True)

    account_id: str = Field(min_length=1, max_length=100)
    mode: Literal["authentication_login_rate_limit"]
    attempts: StrictInt = Field(ge=1, le=MAX_RATE_LIMIT_ATTEMPTS)
    invalid_password_reference: str
    expected_control: ExpectedRateLimitControl

    @property
    def secret_references(self) -> tuple[str, ...]:
        return (self.invalid_password_reference,)


def stage_rate_limit_input_secret(value: Any, vault: CredentialVault) -> None:
    """Replace the one recognized raw wrong password with a process-local marker."""
    if not isinstance(value, dict):
        return
    rate_limit = value.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return
    secret = rate_limit.get("invalid_password")
    if isinstance(secret, str) and secret and _staged_reference(secret, vault) is None:
        reference = vault.put(secret, label="rate-limit:invalid-password")
        rate_limit["invalid_password"] = f"{_CREDENTIAL_MARKER_PREFIX}{reference}]"


def ingest_rate_limit_verification_input(
    payload: dict[str, Any], vault: CredentialVault
) -> tuple[RateLimitVerificationInput | None, list[str]]:
    """Vault the raw wrong password and validate the exact bounded envelope."""
    reasons: list[str] = []
    if not isinstance(payload, dict):
        return None, ["Rate-limit verification input must be an object."]
    if set(payload) != {"rate_limit", "expected_control"}:
        reasons.append(
            "Rate-limit verification input permits only rate_limit and expected_control."
        )
    rate_limit = payload.get("rate_limit")
    expected = payload.get("expected_control")
    if not isinstance(rate_limit, dict):
        return None, [*reasons, "A rate_limit object is required."]

    secret = rate_limit.pop("invalid_password", None)
    reference: str | None = None
    if not isinstance(secret, str) or not secret or len(secret) > 4096:
        reasons.append("invalid_password must be one non-empty bounded string.")
    else:
        reference = _staged_reference(secret, vault) or vault.put(
            secret, label="rate-limit:invalid-password"
        )

    if set(rate_limit) != {"account_id", "mode", "attempts"}:
        reasons.append("The rate_limit object contains unsupported fields.")
    if rate_limit.get("mode") != "authentication_login_rate_limit":
        reasons.append("Only authentication_login_rate_limit is supported.")
    account_id = rate_limit.get("account_id")
    if not isinstance(account_id, str) or not account_id.strip():
        reasons.append("Exactly one controlled account_id is required.")
    attempts = rate_limit.get("attempts")
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        reasons.append("attempts must be an integer.")
    elif attempts < 1 or attempts > MAX_RATE_LIMIT_ATTEMPTS:
        reasons.append(f"attempts must be between 1 and {MAX_RATE_LIMIT_ATTEMPTS}.")

    if not isinstance(expected, dict):
        reasons.append("An expected_control object is required.")
        within_attempts = None
    else:
        if set(expected) != {"type", "within_attempts"}:
            reasons.append("The expected_control object contains unsupported fields.")
        if expected.get("type") != "throttle_or_block_within_attempts":
            reasons.append("The expected rate-limit control type is unsupported.")
        within_attempts = expected.get("within_attempts")
        if isinstance(within_attempts, bool) or not isinstance(within_attempts, int):
            reasons.append("expected_control.within_attempts must be an integer.")
        elif (
            within_attempts < 1
            or within_attempts > MAX_RATE_LIMIT_ATTEMPTS
            or isinstance(attempts, int)
            and not isinstance(attempts, bool)
            and within_attempts > attempts
        ):
            reasons.append(
                "expected_control.within_attempts must fit within the approved attempts."
            )

    if reasons or reference is None:
        if reference is not None:
            vault.discard(reference)
        return None, list(dict.fromkeys(reasons))
    return (
        RateLimitVerificationInput(
            account_id=account_id.strip(),
            mode="authentication_login_rate_limit",
            attempts=attempts,
            invalid_password_reference=reference,
            expected_control=ExpectedRateLimitControl(
                type="throttle_or_block_within_attempts",
                within_attempts=within_attempts,
            ),
        ),
        [],
    )


def safe_rate_limit_response_summary(response: Any) -> dict[str, Any]:
    """Return only structural and classified response evidence."""
    if not isinstance(response, dict):
        response = {}
    status = response.get("status_code")
    status_code = (
        status
        if isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status < 600
        else None
    )
    raw_headers = response.get("headers")
    headers = {
        str(name).strip().lower(): str(value).strip()
        for name, value in (
            raw_headers.items() if isinstance(raw_headers, dict) else []
        )
    }
    retry_after = headers.get("retry-after")
    retry_after_class = _retry_after_class(retry_after)
    rate_headers = {
        name: _rate_header_value_class(name, value)
        for name, value in headers.items()
        if name in _RATE_LIMIT_HEADER_NAMES
    }
    error_semantics = _error_semantics(response.get("body"))
    remaining_zero = any(
        name.endswith("remaining") and value_class == "zero"
        for name, value_class in rate_headers.items()
    )
    throttle_signal = bool(
        status_code == 429
        or retry_after is not None
        or remaining_zero
        or error_semantics == "throttled"
    )
    lockout_signal = error_semantics == "locked_or_blocked"
    concrete_throttle_evidence = bool(
        retry_after is not None
        or remaining_zero
        or error_semantics == "throttled"
        or lockout_signal
    )
    service_unstable = bool(
        response.get("service_unstable")
        or status_code is None
        or 500 <= status_code < 600
        and not throttle_signal
        and not lockout_signal
    )
    summary = {
        "status_class": f"{status_code // 100}xx" if status_code else "unknown",
        "retry_after_present": retry_after is not None,
        "retry_after_value_class": retry_after_class,
        "rate_limit_header_value_classes": rate_headers,
        "error_semantics": error_semantics,
        "body_structure_hash": _body_structure_hash(response.get("body")),
        "coarse_latency_bucket": _latency_bucket(response),
        "throttle_signal": throttle_signal,
        "status_429_detected": status_code == 429,
        "concrete_throttle_evidence": concrete_throttle_evidence,
        "lockout_signal": lockout_signal,
        "service_unstable": service_unstable,
    }
    return summary


def classify_rate_limit_sequence(
    invalid_summaries: list[dict[str, Any]],
    final_summary: dict[str, Any] | None,
    *,
    within_attempts: int,
) -> tuple[Literal["verified", "rejected", "inconclusive"], bool | None]:
    """Classify only an explicit control expectation; timing is never proof."""
    threshold = invalid_summaries[:within_attempts]
    observed = [*threshold, *([final_summary] if final_summary is not None else [])]
    if observed and assess_response_instability(observed).unstable:
        return "inconclusive", None
    control_within = any(item["concrete_throttle_evidence"] for item in threshold)
    final_explicitly_blocked = bool(
        final_summary
        and final_summary["concrete_throttle_evidence"]
        and len(invalid_summaries) == within_attempts
    )
    if control_within or final_explicitly_blocked:
        return "rejected", True
    if len(threshold) != within_attempts or final_summary is None:
        return "inconclusive", None
    final_success = final_summary["status_class"] == "2xx" and not (
        final_summary["throttle_signal"] or final_summary["lockout_signal"]
    )
    deterministic_ordinary_failures = bool(
        final_success
        and threshold
        and all(item["error_semantics"] == "invalid_credentials" for item in threshold)
        and len({item["body_structure_hash"] for item in threshold}) == 1
    )
    if deterministic_ordinary_failures:
        return "verified", False
    return "inconclusive", None


def _staged_reference(value: str, vault: CredentialVault) -> str | None:
    if not value.startswith(_CREDENTIAL_MARKER_PREFIX) or not value.endswith("]"):
        return None
    reference = value[len(_CREDENTIAL_MARKER_PREFIX) : -1]
    try:
        vault.get(reference)
    except (KeyError, RuntimeError):
        return None
    return reference


def _retry_after_class(value: str | None) -> str | None:
    if value is None:
        return None
    if re.fullmatch(r"\d+", value):
        return "delta_seconds"
    try:
        parsed: datetime = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return "present_unclassified"
    return "http_date" if parsed is not None else "present_unclassified"


def _rate_header_value_class(name: str, value: str) -> str:
    if name.endswith("remaining"):
        if value == "0":
            return "zero"
        if value.isdigit():
            return "positive_integer"
    if value.isdigit():
        return "integer"
    return "present_unclassified"


def _error_semantics(body: Any) -> str:
    if not isinstance(body, dict):
        return "none"
    fragments = [
        str(body[field]).strip().lower()
        for field in _ERROR_FIELDS
        if field in body and isinstance(body[field], (str, int))
    ]
    text = " ".join(fragments)
    if not text:
        return "none"
    if any(
        phrase in text
        for phrase in (
            "account locked",
            "temporarily locked",
            "login blocked",
            "account blocked",
            "too many failed",
        )
    ):
        return "locked_or_blocked"
    if any(
        phrase in text
        for phrase in ("rate limit", "too many requests", "slow down", "retry later")
    ):
        return "throttled"
    if any(
        phrase in text
        for phrase in (
            "invalid credentials",
            "invalid password",
            "incorrect password",
            "authentication failed",
            "login failed",
        )
    ):
        return "invalid_credentials"
    return "unclassified_error"


def _body_structure_hash(body: Any) -> str:
    def structure(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): structure(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        if isinstance(value, list):
            return [structure(item) for item in value[:20]]
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        return "other"

    rendered = json.dumps(
        structure(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return "sha256:" + sha256(rendered.encode("utf-8")).hexdigest()


def _latency_bucket(response: dict[str, Any]) -> str | None:
    value = next(
        (
            response.get(name)
            for name in ("elapsed_ms", "latency_ms", "duration_ms")
            if response.get(name) is not None
        ),
        None,
    )
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    if value < 100:
        return "under_100ms"
    if value < 500:
        return "100_to_499ms"
    if value < 2000:
        return "500_to_1999ms"
    return "2000ms_or_more"
