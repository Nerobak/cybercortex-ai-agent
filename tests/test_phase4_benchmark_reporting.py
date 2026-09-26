from __future__ import annotations

from agent_core.benchmark import (
    BenchmarkMetricsCalculator,
    BenchmarkReporter,
    BenchmarkRunStatus,
    BenchmarkScore,
    BenchmarkRun,
    BenchmarkBudgetSnapshot,
    IntegrityStatus,
    ScoreProfile,
)
from tests.phase4_benchmark_helpers import DIGEST, empty_state, manifest, scoring_policy, truth


def test_json_report_has_stable_order_and_human_summary_is_credential_free():
    state = empty_state()
    policy = scoring_policy()
    score = BenchmarkScore(
        benchmark_run_id="run-1",
        policy_id=policy.policy_id,
        metrics=BenchmarkMetricsCalculator().calculate(
            final_state=state, ground_truth=truth(), finding_matches=()
        ),
        passed=False,
        score_profile=ScoreProfile.balanced,
    )
    run = BenchmarkRun(
        run_id="run-1",
        benchmark_id="benchmark-1",
        benchmark_version="v1",
        research_id=state.research_id,
        status=BenchmarkRunStatus.scored,
        start_timestamp="2026-09-26T12:00:00+00:00",
        end_timestamp="2026-09-26T12:01:00+00:00",
        configuration_fingerprint=DIGEST,
        code_revision="revision-1",
        model_routing_fingerprint=DIGEST,
        budget_snapshot=BenchmarkBudgetSnapshot(
            request_budget=10,
            model_budget=2,
            experiment_budget=4,
            reproduction_budget=2,
            chain_budget=2,
            wall_time_budget=60.0,
        ),
        integrity_status=IntegrityStatus.pending,
        final_state_fingerprint=DIGEST,
        result_reference="result-1",
        scoring_reference=DIGEST,
    )
    report = BenchmarkReporter().build(
        run=run,
        manifest=manifest(),
        ground_truth=truth(),
        scoring_policy=policy,
        score=score,
        initial_state=state,
        final_state=state,
        model_provider="fixture-provider",
        requested_model="fixture-model",
        policy_fingerprint=DIGEST,
        generated_at="2026-09-26T12:01:00+00:00",
    )
    encoded = BenchmarkReporter.to_json(report, indent=None)
    assert encoded == BenchmarkReporter.to_json(report, indent=None)
    assert "hidden-sentinel-4f9c" not in encoded
    assert "PASS" not in BenchmarkReporter.human_summary(report)
