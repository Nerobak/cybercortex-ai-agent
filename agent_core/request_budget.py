"""One fail-closed request ledger shared by Phase 2 discovery and verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, StrictInt, field_validator, model_validator

RequestKind = Literal["discovery", "auth", "verification", "cleanup"]


class RequestDelta(BaseModel):
    """Immutable network-request counts attributable to exactly one result.

    The authoritative ledger consumes an allowed request immediately before
    transport, so every consumed request is an attempt and ``attempted`` is
    exactly equal to ``total``. Requests blocked before transport consume
    neither value.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    discovery: StrictInt = 0
    auth: StrictInt = 0
    verification: StrictInt = 0
    cleanup: StrictInt = 0
    attempted: StrictInt = 0
    total: StrictInt = 0

    @field_validator(
        "discovery", "auth", "verification", "cleanup", "attempted", "total"
    )
    @classmethod
    def reject_negative_counts(cls, value: int) -> int:
        if value < 0:
            raise ValueError("Request delta counts cannot be negative.")
        return value

    @model_validator(mode="after")
    def validate_invariants(self) -> "RequestDelta":
        categorized = self.discovery + self.auth + self.verification + self.cleanup
        if self.total != categorized:
            raise ValueError("Request delta total must equal its categorized counts.")
        if self.attempted != self.total:
            raise ValueError("Request delta attempted must equal total.")
        return self

    @classmethod
    def from_snapshots(
        cls, before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> "RequestDelta":
        counts: dict[str, int] = {}
        for field_name in ("discovery", "auth", "verification", "cleanup"):
            key = f"{field_name}_requests"
            before_value = before.get(key, 0)
            after_value = after.get(key, 0)
            if (
                not isinstance(before_value, int)
                or isinstance(before_value, bool)
                or not isinstance(after_value, int)
                or isinstance(after_value, bool)
            ):
                raise ValueError(
                    "Request budget snapshots must contain strict integers."
                )
            difference = after_value - before_value
            if difference < 0:
                raise ValueError("Request budget snapshots must be monotonic.")
            counts[field_name] = difference
        total = sum(counts.values())
        before_total = before.get("total_requests", 0)
        after_total = after.get("total_requests", 0)
        if (
            not isinstance(before_total, int)
            or isinstance(before_total, bool)
            or not isinstance(after_total, int)
            or isinstance(after_total, bool)
            or after_total - before_total != total
        ):
            raise ValueError("Request delta does not match the authoritative ledger.")
        return cls(**counts, attempted=total, total=total)


def canonical_result_request_total(result: Mapping[str, Any]) -> tuple[int, str]:
    """Return an exact new-result total or a conservative legacy fallback."""

    raw_delta = result.get("request_delta")
    if isinstance(raw_delta, Mapping):
        try:
            return (
                RequestDelta.model_validate(dict(raw_delta)).total,
                "request_delta_v1",
            )
        except ValueError:
            pass
    legacy = result.get("requests_used")
    if isinstance(legacy, int) and not isinstance(legacy, bool) and legacy >= 0:
        return legacy, "legacy_requests_used"
    request_counts = result.get("request_counts")
    if isinstance(request_counts, Mapping):
        typed_total = request_counts.get("total_network_requests")
        if (
            isinstance(typed_total, int)
            and not isinstance(typed_total, bool)
            and typed_total >= 0
        ):
            return typed_total, "legacy_typed_request_counts"
    return 0, "legacy_unknown"


class RequestBudgetExceeded(RuntimeError):
    pass


@dataclass
class RequestBudget:
    limit: int
    per_host_limit: int | None = None
    _counts: dict[str, int] = field(
        default_factory=lambda: {
            "discovery": 0,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
        }
    )
    _host_counts: dict[str, int] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("Request budget must be positive.")
        if self.per_host_limit is not None and self.per_host_limit < 1:
            raise ValueError("Per-host request budget must be positive.")

    @property
    def total(self) -> int:
        with self._lock:
            return sum(self._counts.values())

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self.total)

    def consume(
        self, kind: RequestKind, count: int = 1, *, host: str | None = None
    ) -> None:
        if kind not in self._counts:
            raise ValueError(f"Unsupported request kind: {kind}")
        if count < 1:
            raise ValueError("Consumed request count must be positive.")
        normalized_host = str(host or "").strip().lower().rstrip(".")
        with self._lock:
            if self.total + count > self.limit:
                raise RequestBudgetExceeded("Global request budget exhausted.")
            if (
                normalized_host
                and self.per_host_limit is not None
                and self._host_counts.get(normalized_host, 0) + count
                > self.per_host_limit
            ):
                raise RequestBudgetExceeded("Per-host request budget exhausted.")
            self._counts[kind] += count
            if normalized_host:
                self._host_counts[normalized_host] = (
                    self._host_counts.get(normalized_host, 0) + count
                )

    def host_total(self, host: str) -> int:
        normalized_host = str(host).strip().lower().rstrip(".")
        with self._lock:
            return self._host_counts.get(normalized_host, 0)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "discovery_requests": self._counts["discovery"],
                "auth_requests": self._counts["auth"],
                "verification_requests": self._counts["verification"],
                "cleanup_requests": self._counts["cleanup"],
                "total_requests": self.total,
                "request_limit": self.limit,
                "remaining_requests": self.remaining,
            }
