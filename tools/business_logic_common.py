"""Shared deterministic helpers for secret-safe business-workflow analysis."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

MAX_STEPS = 100
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "card",
    "card_number",
    "cvv",
    "payment",
    "email",
    "phone",
    "name",
}
STATE_FIELDS = {"state", "status", "stage", "phase"}
IDENTIFIER_FIELDS = {
    "id",
    "account_id",
    "user_id",
    "tenant_id",
    "resource_id",
    "order_id",
    "owner_id",
    "subscription_id",
    "workflow_id",
}
BUSINESS_FIELDS = {
    "quantity",
    "amount",
    "price",
    "currency",
    "discount",
    "coupon",
    "promotion",
    "balance",
    "credit",
    "limit",
    "status",
    "state",
    "role",
    "permission",
    "approval",
    "owner",
    "account_id",
    "user_id",
    "tenant_id",
    "resource_id",
    "verification_code",
    "nonce",
    "idempotency_key",
    "timestamp",
    "expiration",
    "inventory",
}


def confidence(rank: int) -> str:
    return ("low", "medium", "high")[max(0, min(rank, 2))]


def path_template(value: Any) -> str:
    path = urlsplit(str(value or "/")).path or "/"
    parts = []
    for part in path.split("/"):
        if re.fullmatch(r"\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,}", part):
            parts.append("{id}")
        else:
            parts.append(part[:100])
    return "/".join(parts)[:500]


def field_names(step: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("parameters", "fields", "required_inputs", "observed_outputs"):
        value = step.get(key)
        if isinstance(value, dict):
            names.update(str(item).lower() for item in value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    names.add(item.lower())
                elif isinstance(item, dict):
                    names.update(str(name).lower() for name in item)
    path = str(step.get("url") or step.get("path") or "")
    names.update(name.lower() for name, _ in parse_qsl(urlsplit(path).query))
    headers = step.get("headers")
    if isinstance(headers, dict):
        names.update(str(name).lower().replace("-", "_") for name in headers)
    return {name for name in names if name not in SENSITIVE_KEYS}


def auth_present(step: dict[str, Any]) -> bool:
    actor = str(step.get("actor") or step.get("actor_context") or "").lower()
    if actor and actor not in {"anonymous", "unknown"}:
        return True
    headers = step.get("headers") or {}
    return isinstance(headers, dict) and any(
        str(name).lower() in {"authorization", "cookie"} for name in headers
    )


def structure_hash(value: Any) -> str:
    def shape(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                str(k): shape(v)
                for k, v in sorted(item.items())
                if str(k).lower() not in SENSITIVE_KEYS
            }
        if isinstance(item, list):
            return [shape(item[0])] if item else []
        return type(item).__name__

    encoded = json.dumps(shape(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()[:16]


def safe_step(step: dict[str, Any], sequence: int) -> dict[str, Any]:
    field_set = field_names(step)
    fields = sorted(field_set)
    status = step.get("status_code")
    return {
        "sequence": int(step.get("sequence") or sequence),
        "method": str(step.get("method") or "UNKNOWN").upper()[:12],
        "path": path_template(step.get("path") or step.get("url")),
        "status_class": (
            f"{int(status) // 100}xx" if isinstance(status, int) else "unknown"
        ),
        "actor": str(step.get("actor") or step.get("actor_context") or "unknown")[:80],
        "authentication_context_present": auth_present(step),
        "state_before": str(step.get("state_before") or "unknown")[:80],
        "state_after": str(step.get("state_after") or step.get("state") or "unknown")[
            :80
        ],
        "fields": fields[:50],
        "identifier_categories": sorted(field_set & IDENTIFIER_FIELDS),
        "response_structure_hash": str(
            step.get("response_structure_hash")
            or structure_hash(step.get("response_summary"))
        )[:64],
        "source": str(step.get("source") or "user_supplied")[:80],
    }


def extract_steps(evidence: Any) -> list[dict[str, Any]]:
    if isinstance(evidence, list):
        raw = evidence
    elif isinstance(evidence, dict):
        raw = (
            evidence.get("steps")
            or evidence.get("requests")
            or evidence.get("observed_steps")
            or []
        )
    else:
        raw = []
    return [
        safe_step(step, index)
        for index, step in enumerate(raw[:MAX_STEPS], 1)
        if isinstance(step, dict)
    ]
