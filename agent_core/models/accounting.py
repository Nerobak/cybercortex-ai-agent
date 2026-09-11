"""Authoritative model-call accounting, separate from target request ledgers."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from threading import RLock
from typing import Any, Iterator, Literal

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from agent_core.models.errors import ModelErrorCode
from agent_core.models.types import ModelContract, ModelResponse


class ModelBudgetReservation(ModelContract):
    """Conservative model budget committed when provider invocation starts."""

    input_tokens: StrictInt = Field(ge=1)
    output_tokens: StrictInt = Field(ge=1)
    total_tokens: StrictInt = Field(ge=2)
    estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)

    @model_validator(mode="after")
    def validate_reservation(self) -> "ModelBudgetReservation":
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError(
                "reserved total_tokens must equal input_tokens plus output_tokens"
            )
        return self


class ModelReservationCommit(ModelContract):
    """Process-local evidence that one provider invocation has started."""

    sequence: StrictInt = Field(ge=0)
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr | None = Field(default=None, max_length=255)
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    fallback_depth: StrictInt = Field(default=0, ge=0)
    reservation: ModelBudgetReservation
    attempt_state: Literal["provider_call_started"] = "provider_call_started"


class ModelCallRecord(ModelContract):
    """One provider attempt with actual usage separate from budget consumption."""

    sequence: StrictInt = Field(ge=0)
    provider: StrictStr = Field(min_length=1, max_length=100)
    model: StrictStr = Field(min_length=1, max_length=255)
    input_tokens: StrictInt | None = Field(default=None, ge=0)
    output_tokens: StrictInt | None = Field(default=None, ge=0)
    total_tokens: StrictInt | None = Field(default=None, ge=0)
    usage_known: StrictBool
    budget_input_tokens: StrictInt = Field(default=0, ge=0)
    budget_output_tokens: StrictInt = Field(default=0, ge=0)
    budget_total_tokens: StrictInt = Field(default=0, ge=0)
    estimated_cost_usd: StrictFloat | None = Field(default=None, ge=0.0)
    budget_estimated_cost_usd: StrictFloat | None = Field(default=0.0, ge=0.0)
    latency_seconds: StrictFloat = Field(ge=0.0)
    task_type: StrictStr = Field(min_length=1, max_length=100)
    run_id: StrictStr | None = Field(default=None, max_length=255)
    hypothesis_id: StrictStr | None = Field(default=None, max_length=255)
    fallback_depth: StrictInt = Field(default=0, ge=0)
    success: StrictBool
    outcome: Literal["success"] | ModelErrorCode
    attempt_state: Literal[
        "blocked_before_provider_call",
        "provider_call_succeeded",
        "provider_call_failed_after_start",
    ]

    @model_validator(mode="after")
    def validate_record(self) -> "ModelCallRecord":
        actual = (self.input_tokens, self.output_tokens, self.total_tokens)
        if self.usage_known:
            if any(value is None for value in actual):
                raise ValueError("known provider usage requires exact token counts")
            if self.total_tokens != self.input_tokens + self.output_tokens:
                raise ValueError(
                    "total_tokens must equal input_tokens plus output_tokens"
                )
        elif any(value is not None for value in actual):
            raise ValueError("unknown provider usage must not fabricate token counts")
        if self.budget_total_tokens != (
            self.budget_input_tokens + self.budget_output_tokens
        ):
            raise ValueError("budget token consumption must be categorized")
        if self.usage_known and (
            self.budget_input_tokens < (self.input_tokens or 0)
            or self.budget_output_tokens < (self.output_tokens or 0)
            or self.budget_total_tokens < (self.total_tokens or 0)
        ):
            raise ValueError("budget consumption cannot undercount known usage")
        if self.success != (self.outcome == "success"):
            raise ValueError("success must match the normalized outcome")
        if self.success and self.attempt_state != "provider_call_succeeded":
            raise ValueError("successful calls require the succeeded attempt state")
        if not self.success and self.attempt_state == "provider_call_succeeded":
            raise ValueError("failed calls cannot use the succeeded attempt state")
        if self.attempt_state == "blocked_before_provider_call":
            if not self.usage_known or actual != (0, 0, 0):
                raise ValueError("pre-call blocks have exact zero actual usage")
            if self.budget_total_tokens or self.budget_estimated_cost_usd not in {
                0.0,
                None,
            }:
                raise ValueError("pre-call blocks cannot consume a reservation")
        return self


class ModelUsageDelta(ModelContract):
    """Actual model usage plus distinct authoritative budget consumption."""

    attempted_calls: StrictInt = Field(default=0, ge=0)
    successful_calls: StrictInt = Field(default=0, ge=0)
    failed_calls: StrictInt = Field(default=0, ge=0)
    input_tokens: StrictInt = Field(default=0, ge=0)
    output_tokens: StrictInt = Field(default=0, ge=0)
    total_tokens: StrictInt = Field(default=0, ge=0)
    unknown_usage_calls: StrictInt = Field(default=0, ge=0)
    budget_input_tokens: StrictInt = Field(default=0, ge=0)
    budget_output_tokens: StrictInt = Field(default=0, ge=0)
    budget_total_tokens: StrictInt = Field(default=0, ge=0)
    estimated_cost_usd: StrictFloat | None = Field(default=0.0, ge=0.0)
    budget_estimated_cost_usd: StrictFloat | None = Field(default=0.0, ge=0.0)
    latency_seconds: StrictFloat = Field(default=0.0, ge=0.0)

    @model_validator(mode="before")
    @classmethod
    def default_budget_consumption(cls, value: Any) -> Any:
        """Keep legacy actual-only construction readable and correctly budgeted."""

        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        payload.setdefault("budget_input_tokens", payload.get("input_tokens", 0))
        payload.setdefault("budget_output_tokens", payload.get("output_tokens", 0))
        payload.setdefault("budget_total_tokens", payload.get("total_tokens", 0))
        payload.setdefault(
            "budget_estimated_cost_usd",
            payload.get("estimated_cost_usd", 0.0),
        )
        return payload

    @model_validator(mode="after")
    def validate_invariants(self) -> "ModelUsageDelta":
        if self.attempted_calls != self.successful_calls + self.failed_calls:
            raise ValueError(
                "attempted_calls must equal successful_calls plus failed_calls"
            )
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        if self.budget_total_tokens != (
            self.budget_input_tokens + self.budget_output_tokens
        ):
            raise ValueError("budget_total_tokens must equal its categorized values")
        if self.unknown_usage_calls > self.failed_calls:
            raise ValueError("unknown usage calls cannot exceed failed calls")
        if (
            self.budget_input_tokens < self.input_tokens
            or self.budget_output_tokens < self.output_tokens
            or self.budget_total_tokens < self.total_tokens
        ):
            raise ValueError("budget consumption cannot undercount actual usage")
        return self


class ModelLedgerSnapshot(ModelContract):
    """Stable sequence position and aggregate for deterministic interval deltas."""

    position: StrictInt = Field(ge=0)
    run_id: StrictStr | None = Field(default=None, max_length=255)
    usage: ModelUsageDelta


def add_model_usage_deltas(
    left: ModelUsageDelta,
    right: ModelUsageDelta,
) -> ModelUsageDelta:
    """Add actual usage and budget consumption without conflating either view."""

    def add_cost(
        left_value: float | None,
        right_value: float | None,
    ) -> float | None:
        if left.attempted_calls == 0:
            return right_value
        if right.attempted_calls == 0:
            return left_value
        if left_value is None or right_value is None:
            return None
        return float(left_value + right_value)

    return ModelUsageDelta(
        attempted_calls=left.attempted_calls + right.attempted_calls,
        successful_calls=left.successful_calls + right.successful_calls,
        failed_calls=left.failed_calls + right.failed_calls,
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        total_tokens=left.total_tokens + right.total_tokens,
        unknown_usage_calls=left.unknown_usage_calls + right.unknown_usage_calls,
        budget_input_tokens=(left.budget_input_tokens + right.budget_input_tokens),
        budget_output_tokens=(left.budget_output_tokens + right.budget_output_tokens),
        budget_total_tokens=left.budget_total_tokens + right.budget_total_tokens,
        estimated_cost_usd=add_cost(
            left.estimated_cost_usd,
            right.estimated_cost_usd,
        ),
        budget_estimated_cost_usd=add_cost(
            left.budget_estimated_cost_usd,
            right.budget_estimated_cost_usd,
        ),
        latency_seconds=left.latency_seconds + right.latency_seconds,
    )


def _sum_cost(values: tuple[float | None, ...]) -> float | None:
    return None if any(value is None for value in values) else float(sum(values))


def _aggregate(
    records: tuple[ModelCallRecord, ...],
    pending: tuple[ModelReservationCommit, ...] = (),
) -> ModelUsageDelta:
    actual_cost = _sum_cost(
        tuple(record.estimated_cost_usd for record in records)
        + tuple(None for _item in pending)
    )
    budget_cost = _sum_cost(
        tuple(record.budget_estimated_cost_usd for record in records)
        + tuple(item.reservation.estimated_cost_usd for item in pending)
    )
    successful = sum(record.success for record in records)
    return ModelUsageDelta(
        attempted_calls=len(records) + len(pending),
        successful_calls=successful,
        failed_calls=len(records) - successful + len(pending),
        input_tokens=sum(record.input_tokens or 0 for record in records),
        output_tokens=sum(record.output_tokens or 0 for record in records),
        total_tokens=sum(record.total_tokens or 0 for record in records),
        unknown_usage_calls=sum(not record.usage_known for record in records)
        + len(pending),
        budget_input_tokens=sum(record.budget_input_tokens for record in records)
        + sum(item.reservation.input_tokens for item in pending),
        budget_output_tokens=sum(record.budget_output_tokens for record in records)
        + sum(item.reservation.output_tokens for item in pending),
        budget_total_tokens=sum(record.budget_total_tokens for record in records)
        + sum(item.reservation.total_tokens for item in pending),
        estimated_cost_usd=actual_cost,
        budget_estimated_cost_usd=budget_cost,
        latency_seconds=float(sum(record.latency_seconds for record in records)),
    )


class ModelCallCapture:
    """Process-local observation of authoritative ledger events in one callback."""

    def __init__(self) -> None:
        self._events: dict[
            tuple[ModelCallLedger, int], ModelCallRecord | ModelReservationCommit
        ] = {}
        self._order: list[tuple[ModelCallLedger, int]] = []
        self._lock = RLock()

    def _record(
        self,
        ledger: "ModelCallLedger",
        event: ModelCallRecord | ModelReservationCommit,
    ) -> None:
        key = (ledger, event.sequence)
        with self._lock:
            if key not in self._events:
                self._order.append(key)
            self._events[key] = event

    @property
    def events(self) -> tuple[ModelCallRecord | ModelReservationCommit, ...]:
        with self._lock:
            return tuple(self._events[key] for key in self._order)

    @property
    def usage(self) -> ModelUsageDelta:
        events = self.events
        return _aggregate(
            tuple(item for item in events if isinstance(item, ModelCallRecord)),
            tuple(item for item in events if isinstance(item, ModelReservationCommit)),
        )


_ACTIVE_MODEL_CALL_CAPTURES: ContextVar[tuple[ModelCallCapture, ...]] = ContextVar(
    "active_model_call_captures",
    default=(),
)


@contextmanager
def capture_model_calls() -> Iterator[ModelCallCapture]:
    """Observe ledger-authoritative callback usage without creating another ledger."""

    capture = ModelCallCapture()
    active = _ACTIVE_MODEL_CALL_CAPTURES.get()
    token = _ACTIVE_MODEL_CALL_CAPTURES.set((*active, capture))
    try:
        yield capture
    finally:
        _ACTIVE_MODEL_CALL_CAPTURES.reset(token)


def _publish_model_call_event(
    ledger: "ModelCallLedger",
    event: ModelCallRecord | ModelReservationCommit,
) -> None:
    for capture in _ACTIVE_MODEL_CALL_CAPTURES.get():
        capture._record(ledger, event)


class ModelCallLedger:
    """Thread-safe source of truth for calls, actual usage, and reservations."""

    def __init__(self) -> None:
        self._records: list[ModelCallRecord] = []
        self._pending: dict[int, ModelReservationCommit] = {}
        self._next_sequence = 0
        self._lock = RLock()

    @contextmanager
    def routing_transaction(self) -> Iterator[None]:
        """Serialize preflight and call recording so run budgets stay authoritative."""

        with self._lock:
            yield

    def commit_reservation(
        self,
        *,
        provider: str,
        model: str,
        task_type: str,
        run_id: str | None,
        hypothesis_id: str | None,
        fallback_depth: int,
        reservation: ModelBudgetReservation,
    ) -> ModelReservationCommit:
        """Commit budget immediately before the one provider-call boundary."""

        with self._lock:
            commit = ModelReservationCommit(
                sequence=self._allocate_sequence(),
                provider=provider,
                model=model,
                task_type=task_type,
                run_id=run_id,
                hypothesis_id=hypothesis_id,
                fallback_depth=fallback_depth,
                reservation=reservation,
            )
            self._pending[commit.sequence] = commit
        _publish_model_call_event(self, commit)
        return commit

    def record_success(
        self,
        response: ModelResponse,
        *,
        fallback_depth: int,
        reservation: ModelReservationCommit | None = None,
    ) -> ModelCallRecord:
        """Reconcile a committed reservation to trustworthy actual usage."""

        with self._lock:
            commit = self._active_reservation(reservation)
            if commit is not None:
                self._validate_commit(commit, response, fallback_depth)
                sequence = commit.sequence
                reserved_cost = commit.reservation.estimated_cost_usd
            else:
                sequence = self._allocate_sequence()
                reserved_cost = response.estimated_cost_usd
            budget_cost = (
                response.estimated_cost_usd
                if response.estimated_cost_usd is not None
                else reserved_cost
            )
            record = ModelCallRecord(
                sequence=sequence,
                provider=response.provider,
                model=response.model,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                total_tokens=response.total_tokens,
                usage_known=True,
                budget_input_tokens=response.input_tokens,
                budget_output_tokens=response.output_tokens,
                budget_total_tokens=response.total_tokens,
                estimated_cost_usd=response.estimated_cost_usd,
                budget_estimated_cost_usd=budget_cost,
                latency_seconds=response.latency_seconds,
                task_type=response.task_type,
                run_id=response.run_id,
                hypothesis_id=response.hypothesis_id,
                fallback_depth=fallback_depth,
                success=True,
                outcome="success",
                attempt_state="provider_call_succeeded",
            )
            if commit is not None:
                self._pending.pop(commit.sequence)
            self._records.append(record)
        _publish_model_call_event(self, record)
        return record

    def record_failure(
        self,
        *,
        provider: str,
        model: str,
        latency_seconds: float,
        task_type: str,
        run_id: str | None,
        hypothesis_id: str | None,
        fallback_depth: int,
        outcome: ModelErrorCode,
        estimated_cost_usd: float | None,
        reservation: ModelReservationCommit | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> ModelCallRecord:
        """Finalize a started failure without refunding unknown provider usage."""

        with self._lock:
            commit = self._active_reservation(reservation)
            usage_known = input_tokens is not None and output_tokens is not None
            if (input_tokens is None) != (output_tokens is None):
                raise ValueError(
                    "partial provider usage must include both token fields"
                )
            actual_input = input_tokens if usage_known else None
            actual_output = output_tokens if usage_known else None
            actual_total = int(actual_input + actual_output) if usage_known else None
            if commit is None:
                sequence = self._allocate_sequence()
                budget_input = actual_input or 0
                budget_output = actual_output or 0
                budget_cost = estimated_cost_usd
            else:
                self._validate_commit_fields(
                    commit,
                    provider=provider,
                    model=model,
                    task_type=task_type,
                    run_id=run_id,
                    hypothesis_id=hypothesis_id,
                    fallback_depth=fallback_depth,
                )
                sequence = commit.sequence
                budget_input = max(commit.reservation.input_tokens, actual_input or 0)
                budget_output = max(
                    commit.reservation.output_tokens, actual_output or 0
                )
                reserved_cost = commit.reservation.estimated_cost_usd
                budget_cost = (
                    None
                    if reserved_cost is None
                    else max(reserved_cost, estimated_cost_usd or 0.0)
                )
            record = ModelCallRecord(
                sequence=sequence,
                provider=provider,
                model=model,
                input_tokens=actual_input,
                output_tokens=actual_output,
                total_tokens=actual_total,
                usage_known=usage_known,
                budget_input_tokens=budget_input,
                budget_output_tokens=budget_output,
                budget_total_tokens=budget_input + budget_output,
                estimated_cost_usd=estimated_cost_usd,
                budget_estimated_cost_usd=budget_cost,
                latency_seconds=latency_seconds,
                task_type=task_type,
                run_id=run_id,
                hypothesis_id=hypothesis_id,
                fallback_depth=fallback_depth,
                success=False,
                outcome=outcome,
                attempt_state="provider_call_failed_after_start",
            )
            if commit is not None:
                self._pending.pop(commit.sequence)
            self._records.append(record)
        _publish_model_call_event(self, record)
        return record

    def record_pre_call_failure(
        self,
        *,
        provider: str,
        model: str,
        latency_seconds: float,
        task_type: str,
        run_id: str | None,
        hypothesis_id: str | None,
        fallback_depth: int,
        outcome: ModelErrorCode,
    ) -> ModelCallRecord:
        """Record a definite pre-provider failure without committing a reservation."""

        with self._lock:
            record = ModelCallRecord(
                sequence=self._allocate_sequence(),
                provider=provider,
                model=model,
                input_tokens=0,
                output_tokens=0,
                total_tokens=0,
                usage_known=True,
                budget_input_tokens=0,
                budget_output_tokens=0,
                budget_total_tokens=0,
                estimated_cost_usd=0.0,
                budget_estimated_cost_usd=0.0,
                latency_seconds=latency_seconds,
                task_type=task_type,
                run_id=run_id,
                hypothesis_id=hypothesis_id,
                fallback_depth=fallback_depth,
                success=False,
                outcome=outcome,
                attempt_state="blocked_before_provider_call",
            )
            self._records.append(record)
        _publish_model_call_event(self, record)
        return record

    @property
    def records(self) -> tuple[ModelCallRecord, ...]:
        with self._lock:
            return tuple(sorted(self._records, key=lambda item: item.sequence))

    @property
    def active_reservations(self) -> tuple[ModelReservationCommit, ...]:
        with self._lock:
            return tuple(self._pending[key] for key in sorted(self._pending))

    def usage_for_run(self, run_id: str | None) -> ModelUsageDelta:
        with self._lock:
            selected = tuple(
                record for record in self._records if record.run_id == run_id
            )
            pending = tuple(
                item for item in self._pending.values() if item.run_id == run_id
            )
        return _aggregate(selected, pending)

    def snapshot(self, *, run_id: str | None) -> ModelLedgerSnapshot:
        with self._lock:
            position = self._next_sequence
            usage = _aggregate(
                tuple(record for record in self._records if record.run_id == run_id),
                tuple(item for item in self._pending.values() if item.run_id == run_id),
            )
        return ModelLedgerSnapshot(position=position, run_id=run_id, usage=usage)

    def delta(
        self, before: ModelLedgerSnapshot, after: ModelLedgerSnapshot
    ) -> ModelUsageDelta:
        if before.run_id != after.run_id:
            raise ValueError("Model ledger snapshots must use the same run_id")
        if before.position > after.position:
            raise ValueError("Model ledger snapshots must be monotonic")
        with self._lock:
            if after.position > self._next_sequence:
                raise ValueError("Model ledger snapshot is outside this ledger")
            selected = tuple(
                record
                for record in self._records
                if before.position <= record.sequence < after.position
                and record.run_id == before.run_id
            )
            pending = tuple(
                item
                for item in self._pending.values()
                if before.position <= item.sequence < after.position
                and item.run_id == before.run_id
            )
        return _aggregate(selected, pending)

    def _allocate_sequence(self) -> int:
        sequence = self._next_sequence
        self._next_sequence += 1
        return sequence

    def _active_reservation(
        self, reservation: ModelReservationCommit | None
    ) -> ModelReservationCommit | None:
        if reservation is None:
            return None
        committed = self._pending.get(reservation.sequence)
        if committed is None or committed != reservation:
            raise ValueError("model budget reservation is not active")
        return committed

    @staticmethod
    def _validate_commit(
        commit: ModelReservationCommit,
        response: ModelResponse,
        fallback_depth: int,
    ) -> None:
        ModelCallLedger._validate_commit_fields(
            commit,
            provider=response.provider,
            model=response.model,
            task_type=response.task_type,
            run_id=response.run_id,
            hypothesis_id=response.hypothesis_id,
            fallback_depth=fallback_depth,
        )

    @staticmethod
    def _validate_commit_fields(
        commit: ModelReservationCommit,
        *,
        provider: str,
        model: str,
        task_type: str,
        run_id: str | None,
        hypothesis_id: str | None,
        fallback_depth: int,
    ) -> None:
        if (
            commit.provider != provider
            or commit.model != model
            or commit.task_type != task_type
            or commit.run_id != run_id
            or commit.hypothesis_id != hypothesis_id
            or commit.fallback_depth != fallback_depth
        ):
            raise ValueError("model budget reservation identity changed")
