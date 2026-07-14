from __future__ import annotations

from typing import Any

from agent_core.finding_schema import SecurityFinding
from tools.request_diff_engine import compare_responses

AUTHORIZATION_DENIAL_STATUSES = {401, 403}
SUCCESS_STATUSES = {200, 201, 202, 204}


def _build_evidence(diff_result: dict[str, Any]) -> list[str]:
    evidence: list[str] = []

    status = diff_result.get("status", {})
    body = diff_result.get("body", {})
    json_result = diff_result.get("json", {})

    baseline_status = status.get("baseline")
    candidate_status = status.get("candidate")

    if baseline_status != candidate_status:
        evidence.append(
            f"HTTP status changed from {baseline_status} to {candidate_status}."
        )

    if (
        baseline_status in AUTHORIZATION_DENIAL_STATUSES
        and candidate_status in SUCCESS_STATUSES
    ):
        evidence.append("An authorization denial changed to a successful response.")

    sensitive_fields = json_result.get("sensitive_fields_present", [])

    if sensitive_fields:
        evidence.append(
            "Candidate response exposed sensitive fields: "
            + ", ".join(sensitive_fields)
            + "."
        )

    added_fields = json_result.get("added_fields", [])

    if added_fields:
        evidence.append(
            "Candidate response added JSON fields: " + ", ".join(added_fields) + "."
        )

    changed_fields = json_result.get("changed_fields", [])

    if changed_fields:
        evidence.append(
            "Candidate response changed JSON fields: " + ", ".join(changed_fields) + "."
        )

    similarity = body.get("similarity_ratio")

    if body.get("identical") is True:
        evidence.append("Baseline and candidate response bodies were identical.")
    elif similarity is not None:
        evidence.append(f"Response body similarity ratio was {similarity}.")

    return evidence


def _determine_candidate_status(
    diff_result: dict[str, Any],
    ownership_confirmed: bool,
    separate_accounts_confirmed: bool,
) -> tuple[str, str, str]:
    """
    Return severity, confidence, and finding status.

    The tool does not mark a finding as verified unless:
    - two distinct controlled accounts were used, and
    - ownership of the tested object was confirmed.
    """
    status = diff_result.get("status", {})
    json_result = diff_result.get("json", {})
    body = diff_result.get("body", {})

    baseline_status = status.get("baseline")
    candidate_status = status.get("candidate")

    sensitive_fields = json_result.get(
        "sensitive_fields_present",
        [],
    )

    denial_to_success = (
        baseline_status in AUTHORIZATION_DENIAL_STATUSES
        and candidate_status in SUCCESS_STATUSES
    )

    successful_sensitive_response = candidate_status in SUCCESS_STATUSES and bool(
        sensitive_fields
    )

    highly_similar_success = (
        candidate_status in SUCCESS_STATUSES and body.get("similarity_ratio", 0) >= 0.95
    )

    if denial_to_success and successful_sensitive_response:
        severity = "high"
        confidence = "high"

    elif denial_to_success:
        severity = "medium"
        confidence = "medium"

    elif successful_sensitive_response and highly_similar_success:
        severity = "medium"
        confidence = "medium"

    elif highly_similar_success:
        severity = "low"
        confidence = "low"

    else:
        severity = "informational"
        confidence = "low"

    if (
        severity in {"medium", "high"}
        and ownership_confirmed
        and separate_accounts_confirmed
    ):
        finding_status = "verified"
    elif severity in {"medium", "high"}:
        finding_status = "needs_manual_verification"
    else:
        finding_status = "candidate"

    return severity, confidence, finding_status


def analyze_authorization_difference(
    baseline_response: dict[str, Any],
    candidate_response: dict[str, Any],
    endpoint: str,
    method: str = "GET",
    object_identifier: str | None = None,
    ownership_confirmed: bool = False,
    separate_accounts_confirmed: bool = False,
) -> dict[str, Any]:
    """
    Analyze two stored HTTP responses for possible authorization weaknesses.

    The caller is responsible for supplying responses from an explicitly
    authorized test using controlled accounts.

    This function does not send HTTP requests.
    """
    diff_result = compare_responses(
        baseline=baseline_response,
        candidate=candidate_response,
    )

    severity, confidence, finding_status = _determine_candidate_status(
        diff_result=diff_result,
        ownership_confirmed=ownership_confirmed,
        separate_accounts_confirmed=separate_accounts_confirmed,
    )

    evidence = _build_evidence(diff_result)

    sensitive_fields = diff_result.get("json", {}).get(
        "sensitive_fields_present",
        [],
    )

    if severity == "high":
        title = "Possible horizontal authorization bypass"
        impact = (
            "A user may be able to access data belonging to another " "user or tenant."
        )
        recommendation = (
            "Enforce server-side object ownership and authorization checks "
            "for every request."
        )

    elif severity == "medium":
        title = "Potential authorization control inconsistency"
        impact = (
            "The endpoint may return data or functionality that should be "
            "restricted to another authorization context."
        )
        recommendation = (
            "Review server-side access controls and verify ownership checks "
            "for the tested object."
        )

    elif severity == "low":
        title = "Authorization response similarity observed"
        impact = (
            "The responses were similar, but the evidence is not sufficient "
            "to establish unauthorized access."
        )
        recommendation = (
            "Repeat the test with two controlled accounts and an object with "
            "confirmed ownership."
        )

    else:
        title = "Authorization difference not established"
        impact = (
            "The available comparison did not provide enough evidence of an "
            "authorization weakness."
        )
        recommendation = (
            "Collect stronger evidence using controlled accounts and known "
            "object ownership."
        )

    manual_verification = [
        "Confirm that the baseline and candidate sessions belong to two "
        "different controlled accounts.",
        "Confirm which account owns the tested object.",
        "Repeat the test using a second controlled object.",
        "Verify whether read and write operations behave differently.",
    ]

    finding = SecurityFinding(
        title=title,
        category="broken_access_control",
        severity=severity,
        confidence=confidence,
        status=finding_status,
        endpoint=endpoint,
        method=method.upper(),
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        manual_verification=manual_verification,
        metadata={
            "object_identifier": object_identifier,
            "ownership_confirmed": ownership_confirmed,
            "separate_accounts_confirmed": (separate_accounts_confirmed),
            "sensitive_fields": sensitive_fields,
            "response_diff": diff_result,
        },
    )

    return {
        "success": True,
        "finding": finding.to_dict(),
        "response_diff": diff_result,
    }
