"""Deterministic public failures for Phase 3 model evaluation."""

from __future__ import annotations

from enum import Enum


class EvaluationFailureCode(str, Enum):
    subject_unavailable = "subject_unavailable"
    case_invalid = "case_invalid"
    reasoning_failed = "reasoning_failed"
    consensus_failed = "consensus_failed"
    autonomy_failed = "autonomy_failed"
    budget_exhausted = "budget_exhausted"
    external_benchmark_invalid = "external_benchmark_invalid"
    metrics_unavailable = "metrics_unavailable"
    configuration_mismatch = "configuration_mismatch"


class EvaluationError(RuntimeError):
    """Safe error that never carries a provider exception or request body."""

    def __init__(self, code: EvaluationFailureCode) -> None:
        self.code = code
        super().__init__(code.value)
