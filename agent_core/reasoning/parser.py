"""Strict JSON parsing for untrusted model-authored reasoning candidates."""

from __future__ import annotations

from pydantic import TypeAdapter, ValidationError

from agent_core.reasoning.errors import ReasoningError, ReasoningErrorCode
from agent_core.reasoning.types import ReasoningCandidate

_CANDIDATE_LIST = TypeAdapter(tuple[ReasoningCandidate, ...])


def parse_reasoning_candidate(text: str) -> ReasoningCandidate:
    """Parse exactly one JSON object; no code fences or best-effort recovery."""

    try:
        return ReasoningCandidate.model_validate_json(text)
    except (TypeError, ValueError, ValidationError):
        raise ReasoningError(ReasoningErrorCode.invalid_model_output) from None


def parse_reasoning_candidates(text: str) -> tuple[ReasoningCandidate, ...]:
    """Parse a non-empty JSON array into one common strict candidate schema."""

    try:
        candidates = _CANDIDATE_LIST.validate_json(text)
    except (TypeError, ValueError, ValidationError):
        raise ReasoningError(ReasoningErrorCode.invalid_model_output) from None
    if not candidates:
        raise ReasoningError(ReasoningErrorCode.invalid_model_output)
    return candidates
