"""Sanitized, structured orchestration history."""

from __future__ import annotations

from agent_core.autonomy.types import AutonomyIterationRecord


class AutonomyHistory:
    def __init__(self) -> None:
        self._records: list[AutonomyIterationRecord] = []

    def record(self, record: AutonomyIterationRecord) -> None:
        if self._records and record.iteration <= self._records[-1].iteration:
            raise ValueError("autonomy iteration history must be strictly append-only")
        self._records.append(record)

    @property
    def records(self) -> tuple[AutonomyIterationRecord, ...]:
        return tuple(self._records)
