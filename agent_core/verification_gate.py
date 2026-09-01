"""Deterministic evidence grading and finding-state promotion."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

VOLATILE_DEFAULTS = {
    "timestamp",
    "time",
    "date",
    "request_id",
    "requestid",
    "trace_id",
    "traceid",
    "nonce",
    "csrf",
    "token",
    "expires",
    "duration",
    "latency",
}


def normalize_volatile_fields(
    value: Any, volatile_fields: Iterable[str] | None = None
) -> Any:
    volatile = {item.lower() for item in (volatile_fields or VOLATILE_DEFAULTS)}
    if isinstance(value, dict):
        return {
            key: normalize_volatile_fields(item, volatile)
            for key, item in sorted(value.items())
            if key.lower() not in volatile
        }
    if isinstance(value, list):
        return [normalize_volatile_fields(item, volatile) for item in value]
    if isinstance(value, str):
        cleaned = re.sub(
            r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b",
            "<timestamp>",
            value,
        )
        cleaned = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            "<uuid>",
            cleaned,
            flags=re.I,
        )
        return cleaned
    return value


def evidence_fingerprint(value: Any) -> str:
    normalized = normalize_volatile_fields(value)
    return sha256(
        json.dumps(normalized, sort_keys=True, default=str).encode()
    ).hexdigest()


@dataclass
class VerificationEvidence:
    repetitions: list[Any] = field(default_factory=list)
    controlled_accounts: list[str] = field(default_factory=list)
    owner_identity: str | None = None
    non_owner_identity: str | None = None
    object_identifier: str | None = None
    ownership_confirmed: bool = False
    separate_accounts_confirmed: bool = False
    controlled_canary: str | None = None
    canary_observed: bool = False
    callback_id: str | None = None
    callback_observed: bool = False
    state_change_expected: bool = False
    cleanup_required: bool = False
    cleanup_succeeded: bool = False
    scope_violations: int = 0
    unauthorized_state_changes: int = 0


def grade_verification(category: str, evidence: VerificationEvidence) -> dict[str, Any]:
    if evidence.scope_violations:
        return {
            "status": "rejected",
            "confidence": "high",
            "verified": False,
            "reasons": ["A scope violation occurred; the evidence is invalid."],
        }
    if evidence.unauthorized_state_changes:
        return {
            "status": "rejected",
            "confidence": "high",
            "verified": False,
            "reasons": ["An unauthorized or unexpected state change occurred."],
        }
    fingerprints = [evidence_fingerprint(item) for item in evidence.repetitions]
    repeatable = len(fingerprints) >= 2 and len(set(fingerprints)) == 1
    reasons: list[str] = []
    verified = False
    if category in {"bola", "tenant_isolation"}:
        verified = all(
            (
                repeatable,
                evidence.ownership_confirmed,
                evidence.separate_accounts_confirmed,
                bool(evidence.object_identifier),
                evidence.owner_identity != evidence.non_owner_identity,
            )
        )
        if not verified:
            reasons.append(
                "Known ownership, distinct controlled identities, and two repeatable observations are required."
            )
    elif category in {
        "vertical_authorization",
        "api_authorization",
        "graphql_authorization",
    }:
        verified = bool(
            repeatable
            and evidence.separate_accounts_confirmed
            and evidence.owner_identity
            and evidence.non_owner_identity
            and evidence.owner_identity != evidence.non_owner_identity
        )
        if not verified:
            reasons.append(
                "Two distinct controlled identities or roles and two repeatable observations are required."
            )
    elif category in {
        "session_security",
        "oauth_oidc",
        "account_lifecycle",
        "cache_security",
    }:
        verified = bool(
            repeatable
            and evidence.separate_accounts_confirmed
            and evidence.owner_identity != evidence.non_owner_identity
        )
        if not verified:
            reasons.append(
                "Repeatable pre/post-state evidence across distinct controlled identities or sessions is required."
            )
    elif category == "ssrf":
        verified = bool(
            repeatable
            and evidence.callback_observed
            and evidence.callback_id
            and evidence.controlled_canary
        )
        if not verified:
            reasons.append(
                "A correlated researcher-controlled callback and repeatable evidence are required."
            )
    elif category in {
        "mass_assignment",
        "property_authorization",
        "business_logic",
        "upload_security",
    }:
        verified = bool(
            repeatable
            and evidence.ownership_confirmed
            and (not evidence.cleanup_required or evidence.cleanup_succeeded)
        )
        if not verified:
            reasons.append(
                "Repeatability, test-resource ownership, and successful cleanup are required."
            )
    else:
        verified = bool(
            repeatable and (evidence.canary_observed or evidence.callback_observed)
        )
        if not verified:
            reasons.append(
                "Two normalized repetitions plus controlled proof are required."
            )
    return {
        "status": "verified" if verified else "needs_manual_verification",
        "confidence": (
            "high" if verified else "medium" if evidence.repetitions else "low"
        ),
        "verified": verified,
        "reasons": reasons
        or ["All deterministic evidence requirements were satisfied."],
        "repetition_count": len(fingerprints),
        "repeatable": repeatable,
    }
