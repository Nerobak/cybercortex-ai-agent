from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.benchmark import BenchmarkManifest, BenchmarkRunStatus
from tests.phase4_benchmark_helpers import manifest, research_input, truth


def test_manifest_and_public_input_are_frozen_and_separate_from_truth():
    public = research_input()
    private = truth()
    assert private.hidden_sentinels[0] not in public.model_dump_json()
    assert "ground_truth" not in type(public).model_fields
    with pytest.raises(ValidationError):
        public.model_copy(update={"ground_truth": private}, deep=True).model_validate(
            {**public.model_dump(), "ground_truth": private.model_dump()}
        )


def test_manifest_rejects_hidden_answer_fields_and_mutation():
    value = manifest()
    with pytest.raises(ValidationError):
        BenchmarkManifest.model_validate(
            {**value.model_dump(), "expected_exploit": "answer"}
        )
    with pytest.raises(ValidationError):
        value.title = "changed"


def test_run_status_marks_only_terminated_research_as_scoreable():
    assert not BenchmarkRunStatus.running.research_terminated
    assert BenchmarkRunStatus.completed.research_terminated
    assert BenchmarkRunStatus.scoring.research_terminated
