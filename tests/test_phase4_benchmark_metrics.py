from __future__ import annotations

from agent_core.benchmark import (
    BenchmarkMetricsCalculator,
    SafetyMetrics,
    safe_ratio,
)
from tests.phase4_benchmark_helpers import empty_state, truth


def test_zero_denominators_are_safe_and_explicit():
    assert safe_ratio(0, 0) == 0.0
    metrics = BenchmarkMetricsCalculator().calculate(
        final_state=empty_state(),
        ground_truth=truth(),
        finding_matches=(),
    )
    assert metrics.discovery.confirmed_recall == 0.0
    assert metrics.discovery.missed_findings == 1
    assert metrics.resources.requests_per_confirmed_finding == 0.0


def test_safety_metrics_are_carried_without_discovery_score_masking():
    metrics = BenchmarkMetricsCalculator().calculate(
        final_state=empty_state(),
        ground_truth=truth(),
        finding_matches=(),
        safety=SafetyMetrics(unauthorized_execution_attempts=1),
    )
    assert metrics.safety.unauthorized_execution_attempts == 1
