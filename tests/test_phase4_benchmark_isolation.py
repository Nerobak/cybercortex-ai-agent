from __future__ import annotations

import pytest

from agent_core.benchmark import (
    BenchmarkBlindnessError,
    BenchmarkBlindnessGuard,
    BenchmarkGroundTruthStore,
    BenchmarkRunStatus,
    GroundTruthAccessError,
)
from tests.phase4_benchmark_helpers import empty_state, research_input, truth
from agent_core.research import ResearchNotFound, ResearchStore


def test_ground_truth_access_is_status_gated(tmp_path):
    store = BenchmarkGroundTruthStore(tmp_path)
    store.put("truth-1", truth())
    with pytest.raises(GroundTruthAccessError):
        store.load_for_scoring("truth-1", run_status=BenchmarkRunStatus.running)
    assert (
        store.load_for_scoring("truth-1", run_status=BenchmarkRunStatus.scoring)
        == truth()
    )


def test_blindness_guard_accepts_clean_state_and_rejects_seed_answers():
    guard = BenchmarkBlindnessGuard()
    result = guard.validate(research_input(), initial_state=empty_state())
    assert result.valid
    with pytest.raises(BenchmarkBlindnessError):
        guard.validate(
            research_input(),
            initial_state=empty_state(),
            seed_hypotheses=("preseeded",),
        )


def test_contamination_report_contains_hashes_not_hidden_material(tmp_path):
    store = BenchmarkGroundTruthStore(tmp_path)
    store.put("truth-1", truth())
    result = store.check_contamination(
        "truth-1", {"discovered_path": " /PRIVATE/object-id "}
    )
    assert result.contaminated
    assert "private" not in result.model_dump_json().lower()
    assert "hidden-sentinel-4f9c" not in result.model_dump_json()
    sentinel = store.check_contamination(
        "truth-1", {"model_packet": {"claim": "hidden sentinel 4f9c"}}
    )
    assert sentinel.contaminated


def test_default_run_storage_does_not_share_prior_research_namespace(tmp_path):
    first = ResearchStore(tmp_path / "run-a.sqlite3")
    second = ResearchStore(tmp_path / "run-b.sqlite3")
    first.create_research(
        empty_state("research-a").model_copy(
            update={"diagnostic_codes": ("run-a-private-history",)}
        )
    )
    second.create_research(empty_state("research-b"))
    with pytest.raises(ResearchNotFound):
        second.load_research("research-a")
    assert not second.load_research("research-b").diagnostic_codes
