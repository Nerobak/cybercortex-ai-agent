from __future__ import annotations

from agent_core.benchmark import BenchmarkIntegrityVerifier, artifact_fingerprint
from tests.phase4_benchmark_helpers import empty_state, manifest, scoring_policy, truth


def test_canonical_hash_is_stable_and_tampering_is_detected():
    assert artifact_fingerprint({"b": 2, "a": 1}) == artifact_fingerprint(
        {"a": 1, "b": 2}
    )
    verifier = BenchmarkIntegrityVerifier()
    report = verifier.create_report(
        run_id="run-1",
        manifest=manifest(),
        ground_truth=truth(),
        scoring_policy=scoring_policy(),
        run_configuration={"mode": "fixture"},
        initial_state=empty_state(),
        final_state=empty_state(),
        score_report={"passed": False},
    )
    assert verifier.verify(report, manifest=manifest())
    assert not verifier.verify(
        report, manifest=manifest(title="Tampered benchmark")
    )
