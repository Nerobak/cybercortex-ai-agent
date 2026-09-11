"""Deterministic structural checks over canonical public evaluation outcomes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_core.model_evaluation.types import (
    EvaluationCase,
    EvaluationCaseOutcome,
    ExpectationCheckReason,
    StructuralExpectationResult,
    StructuralExpectationType,
)


def _public_value(value: Any) -> str | int | bool | tuple[str, ...] | None:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if hasattr(value, "value"):
        return str(value.value)
    return tuple(
        str(item.value) if hasattr(item, "value") else str(item) for item in value
    )


def _result(
    expectation_type: StructuralExpectationType,
    expected: Any,
    observed: Any,
    predicate: Callable[[Any], bool],
) -> StructuralExpectationResult:
    expected_value = _public_value(expected)
    observed_value = _public_value(observed)
    satisfied = observed is not None and predicate(observed)
    return StructuralExpectationResult(
        expectation_type=expectation_type,
        expected_value=expected_value,
        observed_value=observed_value,
        satisfied=satisfied,
        reason=(
            ExpectationCheckReason.matched
            if satisfied
            else (
                ExpectationCheckReason.unavailable
                if observed is None
                else ExpectationCheckReason.mismatched
            )
        ),
    )


def check_structural_expectations(
    case: EvaluationCase,
    outcome: EvaluationCaseOutcome,
) -> tuple[StructuralExpectationResult, ...]:
    """Check every configured expectation once in stable schema order."""

    expected = case.expected_structure
    checks: list[StructuralExpectationResult] = []

    if expected.minimum_valid_decisions > 0:
        checks.append(
            _result(
                StructuralExpectationType.minimum_valid_decisions,
                expected.minimum_valid_decisions,
                outcome.valid_decisions,
                lambda value: value >= expected.minimum_valid_decisions,
            )
        )
    if expected.maximum_valid_decisions is not None:
        checks.append(
            _result(
                StructuralExpectationType.maximum_valid_decisions,
                expected.maximum_valid_decisions,
                outcome.valid_decisions,
                lambda value: value <= expected.maximum_valid_decisions,
            )
        )
    if expected.allowed_actions:
        checks.append(
            _result(
                StructuralExpectationType.allowed_actions,
                expected.allowed_actions,
                outcome.selected_action,
                lambda value: value in expected.allowed_actions,
            )
        )
    if expected.allowed_capabilities:
        checks.append(
            _result(
                StructuralExpectationType.allowed_capabilities,
                expected.allowed_capabilities,
                outcome.selected_capability,
                lambda value: value in expected.allowed_capabilities,
            )
        )
    if expected.evidence_references_required:
        evidence_present = bool(
            outcome.valid_decisions > 0
            and outcome.decisions_with_evidence_references >= outcome.valid_decisions
        )
        checks.append(
            _result(
                StructuralExpectationType.evidence_references_required,
                True,
                evidence_present,
                bool,
            )
        )
    if expected.decision_action is not None:
        checks.append(
            _result(
                StructuralExpectationType.decision_action,
                expected.decision_action,
                outcome.selected_action,
                lambda value: value is expected.decision_action,
            )
        )
    if expected.recommended_capability is not None:
        checks.append(
            _result(
                StructuralExpectationType.recommended_capability,
                expected.recommended_capability,
                outcome.selected_capability,
                lambda value: value == expected.recommended_capability,
            )
        )
    if expected.decision_valid is not None:
        checks.append(
            _result(
                StructuralExpectationType.decision_valid,
                expected.decision_valid,
                outcome.decision_valid,
                lambda value: value is expected.decision_valid,
            )
        )
    if expected.hypothesis_id is not None:
        checks.append(
            _result(
                StructuralExpectationType.hypothesis_id,
                expected.hypothesis_id,
                outcome.selected_hypothesis_id,
                lambda value: value == expected.hypothesis_id,
            )
        )
    if expected.category is not None:
        checks.append(
            _result(
                StructuralExpectationType.category,
                expected.category,
                outcome.selected_category,
                lambda value: value == expected.category,
            )
        )
    if expected.consensus_agreement is not None:
        checks.append(
            _result(
                StructuralExpectationType.consensus_agreement,
                expected.consensus_agreement,
                outcome.agreement_type,
                lambda value: value is expected.consensus_agreement,
            )
        )
    if expected.autonomy_terminal_state is not None:
        checks.append(
            _result(
                StructuralExpectationType.autonomy_terminal_state,
                expected.autonomy_terminal_state,
                outcome.autonomy_terminal_state,
                lambda value: value is expected.autonomy_terminal_state,
            )
        )
    if expected.stop_reason is not None:
        checks.append(
            _result(
                StructuralExpectationType.stop_reason,
                expected.stop_reason,
                outcome.stop_reason,
                lambda value: value is expected.stop_reason,
            )
        )
    if expected.minimum_iterations is not None:
        checks.append(
            _result(
                StructuralExpectationType.minimum_iterations,
                expected.minimum_iterations,
                outcome.autonomy_iterations,
                lambda value: value >= expected.minimum_iterations,
            )
        )
    if expected.maximum_iterations is not None:
        checks.append(
            _result(
                StructuralExpectationType.maximum_iterations,
                expected.maximum_iterations,
                outcome.autonomy_iterations,
                lambda value: value <= expected.maximum_iterations,
            )
        )
    if expected.minimum_verifications is not None:
        checks.append(
            _result(
                StructuralExpectationType.minimum_verifications,
                expected.minimum_verifications,
                outcome.verifications_attempted,
                lambda value: value >= expected.minimum_verifications,
            )
        )
    if expected.maximum_verifications is not None:
        checks.append(
            _result(
                StructuralExpectationType.maximum_verifications,
                expected.maximum_verifications,
                outcome.verifications_attempted,
                lambda value: value <= expected.maximum_verifications,
            )
        )
    if expected.execution_occurred is not None:
        execution_occurred = outcome.verifications_attempted > 0
        checks.append(
            _result(
                StructuralExpectationType.execution_occurred,
                expected.execution_occurred,
                execution_occurred,
                lambda value: value is expected.execution_occurred,
            )
        )
    if expected.phase2_status is not None:
        observed_status = (
            outcome.phase2_statuses[-1] if outcome.phase2_statuses else None
        )
        checks.append(
            _result(
                StructuralExpectationType.phase2_status,
                expected.phase2_status,
                observed_status,
                lambda value: value is expected.phase2_status,
            )
        )
    if expected.maximum_target_requests is not None:
        checks.append(
            _result(
                StructuralExpectationType.maximum_target_requests,
                expected.maximum_target_requests,
                outcome.request_delta.total,
                lambda value: value <= expected.maximum_target_requests,
            )
        )
    if expected.maximum_model_calls is not None:
        checks.append(
            _result(
                StructuralExpectationType.maximum_model_calls,
                expected.maximum_model_calls,
                outcome.model_usage.attempted_calls,
                lambda value: value <= expected.maximum_model_calls,
            )
        )
    if expected.fallback_used is not None:
        fallback_used = any(item.fallback_used for item in outcome.provenance)
        checks.append(
            _result(
                StructuralExpectationType.fallback_used,
                expected.fallback_used,
                fallback_used,
                lambda value: value is expected.fallback_used,
            )
        )
    return tuple(checks)


def apply_structural_expectations(
    case: EvaluationCase,
    outcome: EvaluationCaseOutcome,
) -> EvaluationCaseOutcome:
    """Return a validated outcome with authoritative measurement-only checks."""

    results = check_structural_expectations(case, outcome)
    failed = tuple(item for item in results if not item.satisfied)
    expectations_satisfied = not failed if results else None
    return EvaluationCaseOutcome.model_validate(
        {
            **outcome.model_dump(mode="python"),
            "success": outcome.runtime_success and expectations_satisfied is not False,
            "expectations_present": bool(results),
            "expectations_checked": len(results),
            "expectations_satisfied": expectations_satisfied,
            "expectation_results": results,
            "failed_expectations": failed,
        }
    )
