"""Deterministic, public-safe failures for advisory model reasoning."""

from __future__ import annotations

from enum import Enum


class ReasoningErrorCode(str, Enum):
    model_unavailable = "model_unavailable"
    model_budget_exhausted = "model_budget_exhausted"
    invalid_model_output = "invalid_model_output"
    unsupported_recommendation = "unsupported_recommendation"
    evidence_validation_failed = "evidence_validation_failed"
    sanitization_failed = "sanitization_failed"


_MESSAGES = {
    ReasoningErrorCode.model_unavailable: (
        "The configured reasoning model is unavailable."
    ),
    ReasoningErrorCode.model_budget_exhausted: (
        "The model budget does not permit this reasoning call."
    ),
    ReasoningErrorCode.invalid_model_output: (
        "The reasoning model returned invalid structured output."
    ),
    ReasoningErrorCode.unsupported_recommendation: (
        "The model recommendation is unsupported by deterministic constraints."
    ),
    ReasoningErrorCode.evidence_validation_failed: (
        "The reasoning evidence failed deterministic validation."
    ),
    ReasoningErrorCode.sanitization_failed: (
        "The reasoning input did not satisfy the public-safe boundary."
    ),
}


class ReasoningError(RuntimeError):
    """One safe failure code without raw model output, prompts, or exceptions."""

    def __init__(self, code: ReasoningErrorCode) -> None:
        self.code = code
        self.public_message = _MESSAGES[code]
        super().__init__(self.public_message)

    def public_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "message": self.public_message}
