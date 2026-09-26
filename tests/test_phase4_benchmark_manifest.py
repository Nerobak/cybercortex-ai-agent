from __future__ import annotations

import json

from agent_core.benchmark import load_benchmark_manifest, manifest_fingerprint
from tests.phase4_benchmark_helpers import manifest


def test_json_manifest_round_trip_is_deterministic(tmp_path):
    expected = manifest()
    path = tmp_path / "benchmark.json"
    path.write_text(expected.model_dump_json(), encoding="utf-8")
    observed = load_benchmark_manifest(path)
    assert observed == expected
    assert manifest_fingerprint(observed) == manifest_fingerprint(expected)


def test_manifest_json_has_only_ground_truth_reference():
    payload = json.loads(manifest().model_dump_json())
    assert payload["ground_truth_reference"] == "truth-1"
    assert "findings" not in payload
    assert "expected_exploit" not in payload
