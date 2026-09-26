from __future__ import annotations

from types import SimpleNamespace
import json

import pytest

from agent_core.benchmark import (
    AutonomousResearchBenchmarkRunner,
    BenchmarkBudgetSnapshot,
    BenchmarkContaminationError,
    BenchmarkExecutionBindings,
    BenchmarkEventType,
    BenchmarkGroundTruthStore,
    BenchmarkResetPlan,
    BenchmarkRun,
    BenchmarkRunStatus,
    BenchmarkRunStore,
    BenchmarkScoringPolicy,
    IntegrityStatus,
    ResetStrategy,
)
from agent_core.models import ModelUsageDelta
from agent_core.research import (
    ProvenanceProducerType,
    ProvenanceRecord,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    TargetAsset,
    TargetClass,
)
from tests.phase4_benchmark_helpers import (
    DIGEST,
    NOW,
    manifest,
    research_input,
    truth,
)


def run_record():
    return BenchmarkRun(
        run_id="run-1",
        benchmark_id="benchmark-1",
        benchmark_version="v1",
        research_id="research-1",
        status=BenchmarkRunStatus.created,
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
    )


def test_run_store_rejects_reused_research_id_and_hash_chains_events(tmp_path):
    store = BenchmarkRunStore(tmp_path / "benchmark.sqlite3")
    store.create(run_record())
    first = store.append_event("run-1", BenchmarkEventType.benchmark_created)
    second = store.append_event("run-1", BenchmarkEventType.blindness_validated)
    assert second.previous_event_hash == first.event_hash
    assert store.verify_events("run-1")


def test_artifact_hash_is_verified_on_load(tmp_path):
    store = BenchmarkRunStore(tmp_path / "benchmark.sqlite3")
    store.create(run_record())
    digest = store.save_artifact("run-1", "run", run_record())
    assert digest.startswith("sha256:")
    assert store.load_artifact("run-1", "run", BenchmarkRun) == run_record()


class _Ledger:
    records = ()

    def usage_for_run(self, _run_id):
        return ModelUsageDelta()


class _RequestBudget:
    limit = 10
    total = 0

    def snapshot(self):
        return {
            "discovery_requests": 0,
            "auth_requests": 0,
            "verification_requests": 0,
            "cleanup_requests": 0,
            "total_requests": 0,
            "request_limit": 10,
            "remaining_requests": 10,
        }


class _Policy:
    authorization_reference = "policy-1"

    def model_dump(self, **_kwargs):
        return {"authorization_reference": self.authorization_reference}

    def authorize_url(self, _url, method):
        assert method == "GET"
        return SimpleNamespace(allowed=True)


class _Bootstrapper:
    def __init__(self, store):
        self.store = store
        self.policy = _Policy()
        self.controlled_context = SimpleNamespace(accounts=())
        self.calls = 0
        self.visible_states = []

    def prepare(self, state):
        self.calls += 1
        self.visible_states.append(state.model_dump_json())
        return state


class _Orchestrator:
    def __init__(self, store, budget_manager):
        self.store = store
        self.budget_manager = budget_manager
        self.calls = 0

    def run(self, research_id, max_iterations=None):
        del max_iterations
        self.calls += 1
        return SimpleNamespace(state=self.store.load_research(research_id))


class _TrackingTruthStore(BenchmarkGroundTruthStore):
    def __init__(self, root):
        super().__init__(root)
        self.scoring_loads = 0

    def load_for_scoring(self, reference, *, run_status):
        self.scoring_loads += 1
        return super().load_for_scoring(reference, run_status=run_status)


def _bindings(tmp_path):
    research_store = ResearchStore(tmp_path / "research.sqlite3")
    provenance = ProvenanceRecord(
        provenance_id="provenance-1",
        producer_type=ProvenanceProducerType.researcher,
        producer_name="benchmark-fixture",
        producer_version="v1",
        summary="Registered a controlled synthetic target.",
        occurred_at=NOW,
    )
    target = TargetAsset(
        target_id="target-1",
        canonical_reference="https://benchmark.invalid",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-1",
        provenance_id=provenance.provenance_id,
    )
    research_store.create_research(
        ResearchState(
            research_id="research-1",
            revision=0,
            status=ResearchRunStatus.initializing,
            created_at=NOW,
            updated_at=NOW,
            targets=(target,),
            provenance=(provenance,),
        )
    )
    request_budget = _RequestBudget()
    ledger = _Ledger()
    budget_manager = SimpleNamespace(
        request_budget=request_budget, model_ledger=ledger
    )
    bootstrapper = _Bootstrapper(research_store)
    orchestrator = _Orchestrator(research_store, budget_manager)
    bindings = BenchmarkExecutionBindings(
        research_store=research_store,  # type: ignore[arg-type]
        budget_manager=budget_manager,  # type: ignore[arg-type]
        model_router=SimpleNamespace(ledger=ledger),  # type: ignore[arg-type]
        request_budget=request_budget,  # type: ignore[arg-type]
        bootstrapper=bootstrapper,  # type: ignore[arg-type]
        orchestrator=orchestrator,  # type: ignore[arg-type]
        synthetic_fixture=True,
    )
    return bindings, bootstrapper, orchestrator


def _framework(tmp_path, ground_truth_store):
    return AutonomousResearchBenchmarkRunner(
        run_store=BenchmarkRunStore(tmp_path / "runs.sqlite3"),
        ground_truth_store=ground_truth_store,
        scoring_policies={
            "scoring-1": BenchmarkScoringPolicy(policy_id="scoring-1")
        },
    )


def test_contamination_blocks_before_research_or_model_activity(tmp_path):
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, bootstrapper, orchestrator = _bindings(tmp_path)
    framework = _framework(tmp_path, private)
    public = research_input(
        persistence_location=str(bindings.research_store.database)
    )
    with pytest.raises(BenchmarkContaminationError):
        framework.run(
            manifest(),
            public,
            bindings,
            BenchmarkResetPlan(
                strategy=ResetStrategy.stateless_target,
                reset_reference="stateless-reset-1",
            ),
            research_id="research-1",
            run_id="run-1",
            environment_metadata={"route": "/private/{object_id}"},
        )
    assert bootstrapper.calls == 0
    assert orchestrator.calls == 0
    assert bindings.request_budget.total == 0
    assert bindings.model_router.ledger.usage_for_run("research-1").attempted_calls == 0
    assert private.scoring_loads == 0


def test_ground_truth_load_occurs_only_after_research_termination(tmp_path):
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, bootstrapper, orchestrator = _bindings(tmp_path)
    framework = _framework(tmp_path, private)
    public = research_input(
        persistence_location=str(bindings.research_store.database)
    )
    completed = framework.run(
        manifest(),
        public,
        bindings,
        BenchmarkResetPlan(
            strategy=ResetStrategy.stateless_target,
            reset_reference="stateless-reset-1",
        ),
        research_id="research-1",
        run_id="run-1",
    )
    assert completed.status is BenchmarkRunStatus.completed
    assert private.scoring_loads == 0
    framework.score_run("run-1")
    assert private.scoring_loads == 1
    assert bootstrapper.calls == 1
    assert orchestrator.calls == 1
    assert all("hidden-sentinel-4f9c" not in item for item in bootstrapper.visible_states)
    assert "hidden-sentinel-4f9c" not in json.dumps(
        [item.model_dump(mode="json") for item in framework.run_store.events("run-1")]
    )
