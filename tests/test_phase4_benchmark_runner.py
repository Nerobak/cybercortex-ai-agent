from __future__ import annotations

from types import SimpleNamespace
import inspect
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
    BenchmarkReporter,
    BenchmarkRuntimeMetadata,
    BenchmarkRun,
    BenchmarkRunStatus,
    BenchmarkRunStore,
    BenchmarkScoringPolicy,
    IntegrityStatus,
    ResetStrategy,
    SafetyMetrics,
)
from agent_core.models import ModelCallLedger, ModelErrorCode, ModelRouter
from agent_core.research import (
    PublicSafeCandidatePacket,
    PublicSafeChainPacket,
    ProvenanceProducerType,
    ResearchBootstrapper,
    ResearchEvidencePacket,
    ResearchGraphRepository,
    ProvenanceRecord,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    TargetAsset,
    TargetClass,
    SecurityResearchOrchestrator,
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
        self.controller_private_loads = 0
        self.scoring_loads = 0

    def _load_private(self, reference):
        self.controller_private_loads += 1
        return super()._load_private(reference)

    def load_for_scoring(self, reference, *, run_status):
        self.scoring_loads += 1
        return super().load_for_scoring(reference, run_status=run_status)


def _bindings(tmp_path, *, ledger=None):
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
    ledger = ledger or ModelCallLedger()
    budget_manager = SimpleNamespace(request_budget=request_budget, model_ledger=ledger)
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


def test_run_scoped_model_baseline_excludes_unrelated_prior_usage(tmp_path):
    ledger = ModelCallLedger()
    ledger.record_pre_call_failure(
        provider="fixture-provider",
        model="fixture-model",
        latency_seconds=0.0,
        task_type="unrelated-task",
        run_id="unrelated-research",
        hypothesis_id=None,
        fallback_depth=0,
        outcome=ModelErrorCode.configuration_error,
    )
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, _, _ = _bindings(tmp_path, ledger=ledger)
    framework = _framework(tmp_path, private)
    public = research_input(persistence_location=str(bindings.research_store.database))

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
    )
    runtime = framework.run_store.load_artifact(
        "run-1", "runtime-metadata", BenchmarkRuntimeMetadata
    )
    assert isinstance(runtime, BenchmarkRuntimeMetadata)
    assert runtime.model_ledger_baseline.position == 1
    assert runtime.model_ledger_final.position == 1
    assert runtime.model_usage.attempted_calls == 0
    assert runtime.model_usage.estimated_cost_usd == 0.0
    assert framework.score_run("run-1").metrics.resources.model_calls == 0


def _framework(tmp_path, ground_truth_store):
    return AutonomousResearchBenchmarkRunner(
        run_store=BenchmarkRunStore(tmp_path / "runs.sqlite3"),
        ground_truth_store=ground_truth_store,
        scoring_policies={"scoring-1": BenchmarkScoringPolicy(policy_id="scoring-1")},
    )


def test_contamination_blocks_before_research_or_model_activity(tmp_path):
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, bootstrapper, orchestrator = _bindings(tmp_path)
    framework = _framework(tmp_path, private)
    public = research_input(persistence_location=str(bindings.research_store.database))
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


def test_controller_preflight_parse_is_private_and_scoring_load_is_terminated(
    tmp_path,
):
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, bootstrapper, orchestrator = _bindings(tmp_path)
    framework = _framework(tmp_path, private)
    public = research_input(persistence_location=str(bindings.research_store.database))
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
    assert private.controller_private_loads > 0
    framework.score_run("run-1")
    assert private.scoring_loads == 1
    assert bootstrapper.calls == 1
    assert orchestrator.calls == 1
    assert all(
        "hidden-sentinel-4f9c" not in item for item in bootstrapper.visible_states
    )
    assert "hidden-sentinel-4f9c" not in json.dumps(
        [item.model_dump(mode="json") for item in framework.run_store.events("run-1")]
    )
    research_material = json.dumps(
        {
            "bootstrapper": bootstrapper.visible_states,
            "research_store": bindings.research_store.load_research(
                "research-1"
            ).model_dump(mode="json"),
            "model_records": [
                item.model_dump(mode="json")
                for item in bindings.model_router.ledger.records
            ],
        },
        sort_keys=True,
    )
    assert "hidden-sentinel-4f9c" not in research_material
    assert "truth-1" not in research_material


def test_research_component_contracts_have_no_ground_truth_channel():
    for contract in (
        ResearchState,
        ResearchEvidencePacket,
        PublicSafeCandidatePacket,
        PublicSafeChainPacket,
    ):
        assert not any(
            "ground_truth" in field_name or "scoring_answer" in field_name
            for field_name in contract.model_fields
        )

    for component in (
        ResearchBootstrapper,
        SecurityResearchOrchestrator,
        ResearchStore,
        ResearchGraphRepository,
        ModelRouter,
    ):
        parameters = inspect.signature(component.__init__).parameters
        assert not any(
            "ground_truth" in name or "scoring_answer" in name for name in parameters
        )


def test_complete_strict_blind_benchmark_pipeline_is_offline_and_deterministic(
    tmp_path,
):
    private = _TrackingTruthStore(tmp_path / "truth")
    private.put("truth-1", truth())
    bindings, bootstrapper, orchestrator = _bindings(tmp_path)
    framework = _framework(tmp_path, private)
    benchmark_manifest = manifest()
    public = research_input(persistence_location=str(bindings.research_store.database))

    completed = framework.run(
        benchmark_manifest,
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
    assert bootstrapper.calls == orchestrator.calls == 1
    assert bindings.request_budget.total == 0
    assert bindings.model_router.ledger.usage_for_run("research-1").attempted_calls == 0

    score = framework.score_run("run-1", safety=SafetyMetrics(budget_violations=1))
    assert not score.passed
    assert any(
        item.requirement == "zero-budget-violations" and not item.passed
        for item in score.requirements
    )

    scored_run = framework.run_store.load("run-1")
    initial = framework.run_store.load_artifact("run-1", "initial-state", ResearchState)
    final = framework.run_store.load_artifact("run-1", "final-state", ResearchState)
    runtime = framework.run_store.load_artifact(
        "run-1", "runtime-metadata", BenchmarkRuntimeMetadata
    )
    policy = BenchmarkScoringPolicy(policy_id="scoring-1")
    report = BenchmarkReporter().build(
        run=scored_run,
        manifest=benchmark_manifest,
        ground_truth=truth(),
        scoring_policy=policy,
        score=score,
        initial_state=initial,
        final_state=final,
        research_input=public,
        model_provider=runtime.model_provider,
        requested_model=runtime.requested_model,
        actual_model_provenance=runtime.actual_model_provenance,
        policy_fingerprint=runtime.policy_fingerprint,
        generated_at=NOW,
    )
    assert report.integrity.valid
    assert "zero-budget-violations" in BenchmarkReporter.to_json(report)
    framework.run_store.save_artifact("run-1", "report", report)
    verified = framework.record_integrity("run-1", report.integrity)
    assert verified.integrity_status is IntegrityStatus.verified
