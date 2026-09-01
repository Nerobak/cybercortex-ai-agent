"""Canonical Phase 2 result classifications and safe failure semantics."""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from pydantic import Field, StrictBool, StrictStr, field_validator

from agent_core.agent_models import StrictModel
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import sanitize_text


class Phase2ResultStatus(str, Enum):
    """The complete public vocabulary for typed Phase 2 results."""

    verified = "verified"
    rejected = "rejected"
    inconclusive = "inconclusive"
    policy_blocked = "policy_blocked"
    awaiting_controlled_evidence = "awaiting_controlled_evidence"
    verification_pending_cleanup = "verification_pending_cleanup"


TERMINAL_RESULT_STATUSES = frozenset(
    {
        Phase2ResultStatus.verified.value,
        Phase2ResultStatus.rejected.value,
        Phase2ResultStatus.inconclusive.value,
        Phase2ResultStatus.policy_blocked.value,
    }
)
INTERMEDIATE_RESULT_STATUSES = frozenset(
    {
        Phase2ResultStatus.awaiting_controlled_evidence.value,
        Phase2ResultStatus.verification_pending_cleanup.value,
    }
)
PUBLIC_RESULT_STATUSES = TERMINAL_RESULT_STATUSES | INTERMEDIATE_RESULT_STATUSES

BUDGET_PREFLIGHT_REASON = (
    "Request budget is insufficient for the required verification sequence."
)
BUDGET_PARTIAL_REASON = (
    "Verification could not complete within the approved request budget."
)
TRANSPORT_FAILURE_REASON = (
    "Verification transport failed after an authorized request attempt."
)
TRANSPORT_POLICY_BLOCKED_REASON = (
    "The verification request was blocked by shared transport policy."
)
SERVICE_UNSTABLE_REASON = (
    "Service instability prevented a reliable verification conclusion."
)
CLEANUP_UNVERIFIED_REASON = "Required cleanup could not be independently confirmed."
UNSUPPORTED_ADAPTER_REASON = (
    "The selected typed verification adapter or parameter location is unsupported."
)
UNKNOWN_RESULT_REASON = (
    "Verification ended without a documented Phase 2 result classification."
)
INVALID_INPUT_REASON = (
    "Verification input is invalid for the selected typed capability."
)
EXECUTION_FAILURE_REASON = (
    "Verification could not complete because a safe runtime invariant failed."
)


class Phase2StatusDecision(StrictModel):
    """Strict, secret-safe status and reason decision at the public boundary."""

    status: Phase2ResultStatus
    reasons: list[StrictStr] = Field(min_length=1, max_length=50)

    @field_validator("reasons")
    @classmethod
    def validate_reasons(cls, values: list[str]) -> list[str]:
        normalized = [sanitize_text(value).strip() for value in values]
        normalized = [value for value in normalized if value]
        if not normalized:
            raise ValueError("At least one safe result reason is required.")
        return list(dict.fromkeys(normalized))


class Phase2InstabilityDecision(StrictModel):
    """Shared base instability assessment used by every typed analyzer."""

    unstable: StrictBool
    reason: StrictStr | None = None


def assess_response_instability(
    responses: Iterable[Any],
) -> Phase2InstabilityDecision:
    """Detect malformed, explicitly unstable, unavailable, or 5xx responses."""

    materialized = list(responses)
    for response in materialized:
        if not isinstance(response, Mapping):
            return Phase2InstabilityDecision(
                unstable=True, reason=SERVICE_UNSTABLE_REASON
            )
        status_code = response.get("status_code")
        status_class = response.get("status_class")
        valid_status = bool(
            isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and (200 <= status_code < 300 or 400 <= status_code < 500)
            or status_code is None
            and status_class in {"2xx", "4xx"}
        )
        server_error = bool(
            isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and status_code >= 500
            or status_code is None
            and status_class == "5xx"
        )
        if not valid_status or server_error or response.get("service_unstable") is True:
            return Phase2InstabilityDecision(
                unstable=True, reason=SERVICE_UNSTABLE_REASON
            )
    return Phase2InstabilityDecision(unstable=False)


def transport_failure_reason(_: BaseException | None = None) -> str:
    """Return one deterministic reason without persisting exception text."""

    return TRANSPORT_FAILURE_REASON


def _result_reasons(result: Mapping[str, Any]) -> list[str]:
    for field in ("reasons", "evidence_summary"):
        value = result.get(field)
        if isinstance(value, list):
            reasons = [item for item in value if isinstance(item, str) and item]
            if reasons:
                return reasons
    analysis = result.get("analysis")
    if isinstance(analysis, Mapping):
        value = analysis.get("reasons")
        if isinstance(value, list):
            reasons = [item for item in value if isinstance(item, str) and item]
            if reasons:
                return reasons
    return []


def _response_summaries(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    summaries: list[Mapping[str, Any]] = []

    def is_summary(value: Mapping[str, Any]) -> bool:
        return "status_code" in value or "status_class" in value

    for field in (
        "response_summaries",
        "baseline_summary",
        "per_attempt_sanitized_summaries",
        "final_valid_login_summary",
        "baseline",
        "replay",
    ):
        value = result.get(field)
        if isinstance(value, Mapping):
            if is_summary(value):
                summaries.append(value)
            else:
                summaries.extend(
                    item
                    for item in value.values()
                    if isinstance(item, Mapping) and is_summary(item)
                )
        elif isinstance(value, list):
            summaries.extend(
                item for item in value if isinstance(item, Mapping) and is_summary(item)
            )
    return summaries


def normalize_typed_result(
    result: Mapping[str, Any], request_delta: RequestDelta
) -> dict[str, Any]:
    """Normalize one new typed result before provenance is attached.

    Internal workflow sentinels may be convenient while an executor is running,
    but none are permitted to cross this immutable public result boundary.
    """

    normalized = dict(result)
    raw_status = str(result.get("status") or "").strip().casefold()
    reasons = _result_reasons(result)
    budget_reason_present = any("budget" in reason.casefold() for reason in reasons)

    if raw_status in {"budget_blocked", "budget_exhausted"}:
        if request_delta.total == 0:
            raw_status = Phase2ResultStatus.policy_blocked.value
            reasons = [BUDGET_PREFLIGHT_REASON]
        else:
            raw_status = Phase2ResultStatus.inconclusive.value
            reasons = [BUDGET_PARTIAL_REASON]
    elif raw_status == "cleanup_failed":
        raw_status = Phase2ResultStatus.inconclusive.value
        reasons = [CLEANUP_UNVERIFIED_REASON]
    elif raw_status == "manual_adapter_required":
        raw_status = Phase2ResultStatus.policy_blocked.value
        reasons = [UNSUPPORTED_ADAPTER_REASON]
    elif raw_status == "invalid_verification_input":
        if request_delta.total == 0:
            raw_status = Phase2ResultStatus.policy_blocked.value
            reasons = [INVALID_INPUT_REASON]
        else:
            raw_status = Phase2ResultStatus.inconclusive.value
            reasons = [EXECUTION_FAILURE_REASON]
    elif raw_status not in PUBLIC_RESULT_STATUSES:
        raw_status = Phase2ResultStatus.inconclusive.value
        reasons = [UNKNOWN_RESULT_REASON]

    if budget_reason_present and raw_status in {
        Phase2ResultStatus.policy_blocked.value,
        Phase2ResultStatus.inconclusive.value,
    }:
        if request_delta.total == 0:
            raw_status = Phase2ResultStatus.policy_blocked.value
            reasons = [BUDGET_PREFLIGHT_REASON]
        else:
            raw_status = Phase2ResultStatus.inconclusive.value
            reasons = [BUDGET_PARTIAL_REASON]

    cleanup_failed = bool(
        result.get("cleanup_failed") is True
        or result.get("cleanup_attempted") is True
        and result.get("cleanup_verified") is not True
        or isinstance(result.get("analysis"), Mapping)
        and result["analysis"].get("cleanup_failed") is True
    )
    if cleanup_failed and raw_status in TERMINAL_RESULT_STATUSES:
        raw_status = Phase2ResultStatus.inconclusive.value
        reasons = [CLEANUP_UNVERIFIED_REASON]

    summaries = _response_summaries(result)
    instability = assess_response_instability(summaries) if summaries else None
    if (
        instability is not None
        and instability.unstable
        and raw_status
        in {
            Phase2ResultStatus.verified.value,
            Phase2ResultStatus.rejected.value,
        }
    ):
        raw_status = Phase2ResultStatus.inconclusive.value
        reasons = [instability.reason or SERVICE_UNSTABLE_REASON]

    if not reasons:
        defaults = {
            Phase2ResultStatus.verified.value: (
                "Independent category-specific evidence demonstrated the tested vulnerable condition."
            ),
            Phase2ResultStatus.rejected.value: (
                "A valid baseline and active comparison demonstrated the expected secure control."
            ),
            Phase2ResultStatus.inconclusive.value: (
                "The authorized verification did not establish a reliable conclusion."
            ),
            Phase2ResultStatus.policy_blocked.value: (
                "Verification was blocked by deterministic policy before required evidence traffic."
            ),
            Phase2ResultStatus.awaiting_controlled_evidence.value: (
                "Controlled out-of-band evidence is required before verification can continue."
            ),
            Phase2ResultStatus.verification_pending_cleanup.value: (
                "Verification remains pending until required cleanup is independently confirmed."
            ),
        }
        reasons = [defaults[raw_status]]

    decision = Phase2StatusDecision(status=raw_status, reasons=reasons)
    normalized["status"] = decision.status.value
    normalized["reasons"] = decision.reasons
    if "evidence_summary" in normalized:
        normalized["evidence_summary"] = decision.reasons
    analysis = normalized.get("analysis")
    if isinstance(analysis, Mapping):
        normalized_analysis = dict(analysis)
        normalized_analysis["status"] = decision.status.value
        normalized_analysis["verified"] = decision.status is Phase2ResultStatus.verified
        normalized_analysis["reasons"] = decision.reasons
        normalized["analysis"] = normalized_analysis
    return normalized
