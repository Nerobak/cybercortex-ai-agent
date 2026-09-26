"""Lifecycle and persistence for isolated production research benchmarks."""

from __future__ import annotations

import os
import platform
import sqlite3
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agent_core.benchmark.integrity import artifact_fingerprint
from agent_core.benchmark.isolation import (
    BenchmarkBlindnessGuard,
    BenchmarkContaminationError,
    BenchmarkGroundTruthStore,
    BenchmarkResetController,
)
from agent_core.benchmark.manifest import manifest_fingerprint
from agent_core.benchmark.scoring import BenchmarkScorer
from agent_core.benchmark.types import (
    AllowedStateChangeClass,
    BenchmarkEvent,
    BenchmarkEventType,
    BenchmarkManifest,
    BenchmarkIntegrityReport,
    BenchmarkResearchInput,
    BenchmarkResetPlan,
    BenchmarkRuntimeMetadata,
    BenchmarkRun,
    BenchmarkRunStatus,
    BenchmarkScore,
    BenchmarkScoringPolicy,
    BenchmarkSuite,
    IntegrityStatus,
    SafetyMetrics,
    ScoringRequirementResult,
    UnexpectedFindingRecord,
)
from agent_core.models import ModelRouter
from agent_core.request_budget import RequestBudget
from agent_core.research.bootstrap import ResearchBootstrapper
from agent_core.research.authorization import (
    ResearchAuthorizationError,
    ResearchAuthorizationErrorCode,
)
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.orchestrator import SecurityResearchOrchestrator
from agent_core.research.provenance import SecretMaterialRejected
from agent_core.research.state import ResearchState
from agent_core.research.store import ResearchStore
from agent_core.research.types import ResearchRunStatus
from agent_core.research.runtime_binding import InvalidRuntimeBindingError


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BenchmarkRunnerError(RuntimeError):
    pass


class BenchmarkPreflightError(BenchmarkRunnerError):
    pass


class BenchmarkRunNotFound(BenchmarkRunnerError):
    pass


@dataclass(frozen=True)
class BenchmarkExecutionBindings:
    """Existing production components configured for one fresh research ID."""

    research_store: ResearchStore
    budget_manager: ResearchBudgetManager
    model_router: ModelRouter
    request_budget: RequestBudget
    bootstrapper: ResearchBootstrapper
    orchestrator: SecurityResearchOrchestrator | None
    orchestrator_factory: Callable[[ResearchState], SecurityResearchOrchestrator] | None = None
    synthetic_fixture: bool = False

    def validate(self) -> None:
        required = {
            "research_store": ResearchStore,
            "budget_manager": ResearchBudgetManager,
            "model_router": ModelRouter,
            "request_budget": RequestBudget,
            "bootstrapper": ResearchBootstrapper,
        }
        if not self.synthetic_fixture:
            for name, expected in required.items():
                if not isinstance(getattr(self, name), expected):
                    raise BenchmarkPreflightError(
                        f"benchmark binding {name} is not the production component"
                    )
        if getattr(self.budget_manager, "request_budget", None) is not self.request_budget:
            raise BenchmarkPreflightError("research and request budgets are not shared")
        if getattr(self.model_router, "ledger", None) is not getattr(
            self.budget_manager, "model_ledger", None
        ):
            raise BenchmarkPreflightError("research and model accounting are not shared")
        if getattr(self.bootstrapper, "store", None) is not self.research_store:
            raise BenchmarkPreflightError("bootstrapper uses a different research store")
        if (self.orchestrator is None) == (self.orchestrator_factory is None):
            raise BenchmarkPreflightError(
                "provide exactly one orchestrator or post-bootstrap orchestrator factory"
            )
        if self.orchestrator is not None:
            if not self.synthetic_fixture and not isinstance(
                self.orchestrator, SecurityResearchOrchestrator
            ):
                raise BenchmarkPreflightError(
                    "benchmark orchestrator is not the production component"
                )
            if getattr(self.orchestrator, "store", None) is not self.research_store:
                raise BenchmarkPreflightError(
                    "orchestrator uses a different research store"
                )

    def build_orchestrator(self, state: ResearchState) -> SecurityResearchOrchestrator:
        orchestrator = (
            self.orchestrator_factory(state)
            if self.orchestrator_factory is not None
            else self.orchestrator
        )
        if orchestrator is None or (
            not self.synthetic_fixture
            and not isinstance(orchestrator, SecurityResearchOrchestrator)
        ):
            raise BenchmarkRunnerError(
                "orchestrator factory did not return the production component"
            )
        if getattr(orchestrator, "store", None) is not self.research_store:
            raise BenchmarkRunnerError("orchestrator factory changed the research store")
        if getattr(orchestrator, "budget_manager", None) is not self.budget_manager:
            raise BenchmarkRunnerError("orchestrator factory changed research budgets")
        return orchestrator


class BenchmarkRunStore:
    """SQLite run registry and append-only hash-chained benchmark event stream."""

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database), timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_runs (
                    run_id TEXT PRIMARY KEY,
                    benchmark_id TEXT NOT NULL,
                    benchmark_version TEXT NOT NULL,
                    research_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    run_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS benchmark_events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence),
                    FOREIGN KEY(run_id) REFERENCES benchmark_runs(run_id)
                );
                CREATE TABLE IF NOT EXISTS benchmark_artifacts (
                    run_id TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL,
                    artifact_json TEXT NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    PRIMARY KEY(run_id, artifact_kind),
                    FOREIGN KEY(run_id) REFERENCES benchmark_runs(run_id)
                );
                """
            )

    def create(self, run: BenchmarkRun) -> None:
        payload = run.model_dump_json()
        try:
            with self.connect() as connection:
                connection.execute(
                    "INSERT INTO benchmark_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        run.run_id,
                        run.benchmark_id,
                        run.benchmark_version,
                        run.research_id,
                        run.status.value,
                        payload,
                        utc_now(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise BenchmarkPreflightError(
                "benchmark run or research ID has already been used"
            ) from exc

    def save(self, run: BenchmarkRun) -> None:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE benchmark_runs SET status=?, run_json=?, updated_at=? WHERE run_id=?",
                (run.status.value, run.model_dump_json(), utc_now(), run.run_id),
            )
            if cursor.rowcount != 1:
                raise BenchmarkRunNotFound("benchmark run does not exist")

    def load(self, run_id: str) -> BenchmarkRun:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT run_json FROM benchmark_runs WHERE run_id=?", (run_id,)
            ).fetchone()
        if row is None:
            raise BenchmarkRunNotFound("benchmark run does not exist")
        return BenchmarkRun.model_validate_json(row["run_json"])

    def append_event(
        self,
        run_id: str,
        event_type: BenchmarkEventType,
        *,
        research_event_references: tuple[str, ...] = (),
        payload: Any = None,
        occurred_at: str | None = None,
    ) -> BenchmarkEvent:
        timestamp = occurred_at or utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT sequence, event_hash FROM benchmark_events WHERE run_id=? ORDER BY sequence DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            sequence = 0 if previous is None else int(previous["sequence"]) + 1
            previous_hash = None if previous is None else previous["event_hash"]
            event_id = f"benchmark-event-{run_id}-{sequence}"
            material = {
                "event_id": event_id,
                "run_id": run_id,
                "sequence": sequence,
                "event_type": event_type.value,
                "occurred_at": timestamp,
                "previous_event_hash": previous_hash,
                "research_event_references": list(research_event_references),
                "payload_fingerprint": (
                    artifact_fingerprint(payload) if payload is not None else None
                ),
            }
            event = BenchmarkEvent(
                event_id=event_id,
                run_id=run_id,
                sequence=sequence,
                event_type=event_type,
                occurred_at=timestamp,
                previous_event_hash=previous_hash,
                research_event_references=research_event_references,
                payload_fingerprint=material["payload_fingerprint"],
                event_hash=artifact_fingerprint(material),
            )
            connection.execute(
                "INSERT INTO benchmark_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    run_id,
                    sequence,
                    event.event_type.value,
                    event.model_dump_json(),
                    event.event_hash,
                    timestamp,
                ),
            )
            connection.commit()
        return event

    def events(self, run_id: str) -> tuple[BenchmarkEvent, ...]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT event_json,event_hash FROM benchmark_events WHERE run_id=? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        events = tuple(
            BenchmarkEvent.model_validate_json(row["event_json"]) for row in rows
        )
        if any(
            event.event_hash != row["event_hash"]
            for event, row in zip(events, rows)
        ):
            raise BenchmarkRunnerError("benchmark event storage was tampered")
        return events

    def verify_events(self, run_id: str) -> bool:
        previous = None
        try:
            events = self.events(run_id)
        except BenchmarkRunnerError:
            return False
        for expected_sequence, event in enumerate(events):
            material = event.model_dump(mode="json", exclude={"event_hash"})
            if (
                event.sequence != expected_sequence
                or event.previous_event_hash != previous
                or artifact_fingerprint(material) != event.event_hash
            ):
                return False
            previous = event.event_hash
        return True

    def save_artifact(self, run_id: str, kind: str, artifact: BaseModel) -> str:
        digest = artifact_fingerprint(artifact)
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO benchmark_artifacts VALUES (?, ?, ?, ?)",
                (run_id, kind, artifact.model_dump_json(), digest),
            )
        return digest

    def load_artifact(self, run_id: str, kind: str, model: type[BaseModel]) -> BaseModel:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT artifact_json, artifact_hash FROM benchmark_artifacts WHERE run_id=? AND artifact_kind=?",
                (run_id, kind),
            ).fetchone()
        if row is None:
            raise BenchmarkRunNotFound("benchmark artifact does not exist")
        artifact = model.model_validate_json(row["artifact_json"])
        if artifact_fingerprint(artifact) != row["artifact_hash"]:
            raise BenchmarkRunnerError("benchmark artifact integrity failure")
        return artifact


class AutonomousResearchBenchmarkRunner:
    """Evaluate the existing research bootstrap/runtime/orchestrator as-is."""

    def __init__(
        self,
        *,
        run_store: BenchmarkRunStore,
        ground_truth_store: BenchmarkGroundTruthStore,
        scoring_policies: dict[str, BenchmarkScoringPolicy],
        reset_controller: BenchmarkResetController | None = None,
        blindness_guard: BenchmarkBlindnessGuard | None = None,
        scorer: BenchmarkScorer | None = None,
    ) -> None:
        self.run_store = run_store
        self.ground_truth_store = ground_truth_store
        self.scoring_policies = dict(scoring_policies)
        self.reset_controller = reset_controller or BenchmarkResetController()
        self.blindness_guard = blindness_guard or BenchmarkBlindnessGuard()
        self.scorer = scorer or BenchmarkScorer()

    def create_run(
        self,
        manifest: BenchmarkManifest,
        research_input: BenchmarkResearchInput,
        *,
        research_id: str,
        run_id: str | None = None,
    ) -> BenchmarkRun:
        identifier = run_id or f"benchmark-run-{uuid.uuid4().hex}"
        if research_input.benchmark_run_id != identifier:
            raise BenchmarkPreflightError("research input is bound to another run")
        scoring_policy = self.scoring_policies.get(
            manifest.scoring_policy_reference
        )
        if scoring_policy is None:
            raise BenchmarkPreflightError("scoring policy reference is unavailable")
        run = BenchmarkRun(
            run_id=identifier,
            benchmark_id=manifest.benchmark_id,
            benchmark_version=manifest.benchmark_version,
            research_id=research_id,
            status=BenchmarkRunStatus.created,
            configuration_fingerprint=artifact_fingerprint(
                {"manifest": manifest, "research_input": research_input}
            ),
            code_revision=self._code_revision(),
            model_routing_fingerprint=artifact_fingerprint(
                research_input.model_routing_policy
            ),
            budget_snapshot=research_input.budgets,
            benchmark_manifest_fingerprint=artifact_fingerprint(manifest),
            ground_truth_fingerprint=self.ground_truth_store.fingerprint(
                manifest.ground_truth_reference
            ),
            scoring_policy_fingerprint=artifact_fingerprint(scoring_policy),
        )
        self.run_store.create(run)
        self.run_store.save_artifact(identifier, "manifest", manifest)
        self.run_store.save_artifact(identifier, "research-input", research_input)
        self.run_store.save_artifact(identifier, "scoring-policy", scoring_policy)
        self.run_store.append_event(
            identifier, BenchmarkEventType.benchmark_created, payload=run
        )
        return run

    def validate(
        self,
        run: BenchmarkRun,
        manifest: BenchmarkManifest,
        research_input: BenchmarkResearchInput,
        bindings: BenchmarkExecutionBindings,
        reset_plan: BenchmarkResetPlan,
        *,
        operator_reset_confirmed: bool = False,
        environment_metadata: dict[str, Any] | None = None,
        model_packets: Sequence[Any] = (),
        seed_evidence: Sequence[Any] = (),
        seed_hypotheses: Sequence[Any] = (),
        seed_experiments: Sequence[Any] = (),
        seed_findings: Sequence[Any] = (),
        seed_chains: Sequence[Any] = (),
        controlled_setup_object_ids: Sequence[str] = (),
    ) -> tuple[BenchmarkRun, ResearchState]:
        try:
            bindings.validate()
            self._validate_static(run, manifest, research_input, bindings, reset_plan)
            initial_state = bindings.research_store.load_research(run.research_id)
            self._validate_initial_state(
                run, manifest, research_input, initial_state
            )
            graph = bindings.research_store.query_graph_assertions(
                run.research_id, limit=1, include_rejected=True
            )
            derived_environment = {
                key: value
                for key, value in os.environ.items()
                if key.startswith(("BENCHMARK_", "CYBERCORTEX_BENCHMARK_"))
            }
            derived_environment.update(environment_metadata or {})
            blindness = self.blindness_guard.validate(
                research_input,
                initial_state=initial_state,
                environment_metadata=derived_environment,
                model_packets=model_packets,
                seed_evidence=seed_evidence,
                seed_hypotheses=seed_hypotheses,
                seed_experiments=seed_experiments,
                seed_findings=seed_findings,
                seed_chains=seed_chains,
                research_graph=graph,
                strict_blind=True,
                controlled_setup_object_ids=controlled_setup_object_ids,
            )
            self.run_store.append_event(
                run.run_id, BenchmarkEventType.blindness_validated, payload=blindness
            )
            visible = {
                "research_input": research_input,
                "environment_metadata": derived_environment,
                "initial_state": initial_state,
                "model_packets": tuple(model_packets),
                "seed_evidence": tuple(seed_evidence),
                "seed_hypotheses": tuple(seed_hypotheses),
                "seed_experiments": tuple(seed_experiments),
                "seed_findings": tuple(seed_findings),
                "seed_chains": tuple(seed_chains),
                "research_graph": graph,
            }
            contamination = self.ground_truth_store.check_contamination(
                manifest.ground_truth_reference, visible
            )
            self.run_store.append_event(
                run.run_id,
                BenchmarkEventType.contamination_checked,
                payload=contamination,
            )
            if contamination.contaminated:
                invalid = run.model_copy(
                    update={
                        "status": BenchmarkRunStatus.contaminated,
                        "end_timestamp": utc_now(),
                    }
                )
                self.run_store.save(invalid)
                raise BenchmarkContaminationError(
                    "pre-run benchmark material is contaminated"
                )
            validated = run.model_copy(
                update={
                    "status": BenchmarkRunStatus.validated,
                    "initial_state_fingerprint": artifact_fingerprint(initial_state),
                }
            )
            self.run_store.save(validated)
            self.run_store.save_artifact(run.run_id, "initial-state", initial_state)
            resetting = validated.model_copy(update={"status": BenchmarkRunStatus.resetting})
            self.run_store.save(resetting)
            if not self.reset_controller.confirm(
                reset_plan, operator_confirmed=operator_reset_confirmed
            ):
                raise BenchmarkPreflightError("benchmark reset was not confirmed")
            reset_state = bindings.research_store.load_research(run.research_id)
            reset_graph = bindings.research_store.query_graph_assertions(
                run.research_id, limit=1, include_rejected=True
            )
            if (
                artifact_fingerprint(reset_state) != artifact_fingerprint(initial_state)
                or artifact_fingerprint(reset_graph) != artifact_fingerprint(graph)
            ):
                raise BenchmarkPreflightError(
                    "reset callback modified agent-visible research material"
                )
            self._validate_static(
                run, manifest, research_input, bindings, reset_plan
            )
            self.run_store.append_event(
                run.run_id, BenchmarkEventType.reset_confirmed, payload=reset_plan
            )
            ready = resetting.model_copy(update={"status": BenchmarkRunStatus.ready})
            self.run_store.save(ready)
            return ready, initial_state
        except BenchmarkContaminationError:
            raise
        except Exception as exc:
            invalid = self.run_store.load(run.run_id).model_copy(
                update={
                    "status": BenchmarkRunStatus.invalid,
                    "end_timestamp": utc_now(),
                }
            )
            self.run_store.save(invalid)
            if isinstance(exc, BenchmarkPreflightError):
                raise
            raise BenchmarkPreflightError("benchmark pre-run validation failed") from exc

    def run(
        self,
        manifest: BenchmarkManifest,
        research_input: BenchmarkResearchInput,
        bindings: BenchmarkExecutionBindings,
        reset_plan: BenchmarkResetPlan,
        *,
        research_id: str,
        run_id: str | None = None,
        operator_reset_confirmed: bool = False,
        environment_metadata: dict[str, Any] | None = None,
        max_iterations: int | None = None,
        controlled_setup_object_ids: Sequence[str] = (),
    ) -> BenchmarkRun:
        run = self.create_run(
            manifest, research_input, research_id=research_id, run_id=run_id
        )
        ready, _ = self.validate(
            run,
            manifest,
            research_input,
            bindings,
            reset_plan,
            operator_reset_confirmed=operator_reset_confirmed,
            environment_metadata=environment_metadata,
            controlled_setup_object_ids=controlled_setup_object_ids,
        )
        running = ready.model_copy(
            update={"status": BenchmarkRunStatus.running, "start_timestamp": utc_now()}
        )
        self.run_store.save(running)
        self.run_store.append_event(
            run.run_id, BenchmarkEventType.run_started, payload={"research_id": research_id}
        )
        started = time.monotonic()
        try:
            # Invoke the production bootstrap explicitly. The orchestrator may
            # safely call it again; its persisted lifecycle is restart-safe.
            state = bindings.research_store.load_research(research_id)
            prepared = bindings.bootstrapper.prepare(state)
            orchestrator = bindings.build_orchestrator(prepared)
            result = orchestrator.run(
                research_id, max_iterations=max_iterations
            )
            final_state = result.state
            elapsed = time.monotonic() - started
            self.run_store.save_artifact(run.run_id, "final-state", final_state)
            completed = running.model_copy(
                update={
                    "status": BenchmarkRunStatus.completed,
                    "end_timestamp": utc_now(),
                    "final_state_fingerprint": artifact_fingerprint(final_state),
                    "result_reference": f"benchmark-result-{run.run_id}",
                }
            )
            self.run_store.save(completed)
            self.run_store.save_artifact(
                run.run_id,
                "runtime-metadata",
                self._runtime_metadata(
                    elapsed, bindings, research_id, research_input
                ),
            )
            self.run_store.append_event(
                run.run_id,
                BenchmarkEventType.run_completed,
                payload={"final_state": completed.final_state_fingerprint},
            )
            return completed
        except Exception as exc:
            elapsed = time.monotonic() - started
            self.run_store.save_artifact(
                run.run_id,
                "runtime-metadata",
                self._runtime_metadata(
                    elapsed,
                    bindings,
                    research_id,
                    research_input,
                    failure=exc,
                ),
            )
            try:
                final_state = bindings.research_store.load_research(research_id)
                self.run_store.save_artifact(run.run_id, "final-state", final_state)
                final_fingerprint = artifact_fingerprint(final_state)
                result_reference = f"benchmark-result-{run.run_id}"
            except Exception:
                final_fingerprint = None
                result_reference = None
            failed = running.model_copy(
                update={
                    "status": BenchmarkRunStatus.failed,
                    "end_timestamp": utc_now(),
                    "final_state_fingerprint": final_fingerprint,
                    "result_reference": result_reference,
                }
            )
            self.run_store.save(failed)
            self.run_store.append_event(
                run.run_id,
                BenchmarkEventType.run_failed,
                payload={"failure_class": type(exc).__name__},
            )
            raise BenchmarkRunnerError("benchmark research execution failed") from exc

    def score_run(
        self,
        run_id: str,
        *,
        safety: SafetyMetrics | None = None,
        unexpected_adjudications: dict[str, UnexpectedFindingRecord] | None = None,
    ) -> BenchmarkScore:
        run = self.run_store.load(run_id)
        if run.status not in {BenchmarkRunStatus.completed, BenchmarkRunStatus.failed}:
            raise BenchmarkRunnerError("scoring requires terminated research")
        manifest = self.run_store.load_artifact(
            run_id, "manifest", BenchmarkManifest
        )
        assert isinstance(manifest, BenchmarkManifest)
        if run.benchmark_manifest_fingerprint != artifact_fingerprint(manifest):
            raise BenchmarkRunnerError("benchmark manifest integrity failure")
        final_state = self.run_store.load_artifact(
            run_id, "final-state", ResearchState
        )
        assert isinstance(final_state, ResearchState)
        policy = self.run_store.load_artifact(
            run_id, "scoring-policy", BenchmarkScoringPolicy
        )
        assert isinstance(policy, BenchmarkScoringPolicy)
        if (
            run.scoring_policy_fingerprint != artifact_fingerprint(policy)
            or manifest.scoring_policy_reference != policy.policy_id
        ):
            raise BenchmarkRunnerError("scoring policy integrity failure")
        scoring = run.model_copy(update={"status": BenchmarkRunStatus.scoring})
        self.run_store.save(scoring)
        self.run_store.append_event(
            run_id, BenchmarkEventType.scoring_started, payload={"policy": policy.policy_id}
        )
        # This is the first raw ground-truth access in runner lifecycle.
        truth = self.ground_truth_store.load_for_scoring(
            manifest.ground_truth_reference, run_status=scoring.status
        )
        if run.ground_truth_fingerprint != artifact_fingerprint(truth):
            raise BenchmarkRunnerError("ground-truth integrity failure")
        if (
            truth.benchmark_id != run.benchmark_id
            or truth.benchmark_version != run.benchmark_version
        ):
            raise BenchmarkRunnerError("ground truth does not match benchmark identity")
        runtime = self.run_store.load_artifact(
            run_id, "runtime-metadata", BenchmarkRuntimeMetadata
        )
        assert isinstance(runtime, BenchmarkRuntimeMetadata)
        effective_safety = self._merge_safety(runtime.safety, safety)
        score = self.scorer.score(
            benchmark_run_id=run_id,
            final_state=final_state,
            ground_truth=truth,
            policy=policy,
            unexpected_adjudications=unexpected_adjudications,
            request_snapshot=runtime.request_snapshot,
            model_usage=runtime.model_usage,
            wall_time_seconds=runtime.wall_time_seconds,
            safety=effective_safety,
        )
        if run.status is BenchmarkRunStatus.failed:
            score = score.model_copy(
                update={
                    "passed": False,
                    "requirements": (
                        *score.requirements,
                        ScoringRequirementResult(
                            requirement="research-run-completed",
                            passed=False,
                            observed=0.0,
                            threshold=1.0,
                        ),
                    ),
                }
            )
        score_digest = self.run_store.save_artifact(run_id, "score", score)
        scored = scoring.model_copy(
            update={
                "status": BenchmarkRunStatus.scored,
                "scoring_reference": score_digest,
                "integrity_status": IntegrityStatus.pending,
            }
        )
        self.run_store.save(scored)
        self.run_store.append_event(
            run_id, BenchmarkEventType.scoring_completed, payload=score
        )
        return score

    @staticmethod
    def _runtime_metadata(
        elapsed: float,
        bindings: BenchmarkExecutionBindings,
        research_id: str,
        research_input: BenchmarkResearchInput,
        failure: Exception | None = None,
    ) -> BenchmarkRuntimeMetadata:
        records = tuple(
            item
            for item in bindings.model_router.ledger.records
            if item.run_id == research_id
        )
        return BenchmarkRuntimeMetadata(
            wall_time_seconds=elapsed,
            request_snapshot=bindings.request_budget.snapshot(),
            model_usage=bindings.model_router.ledger.usage_for_run(research_id),
            model_provider=research_input.model_routing_policy.provider,
            requested_model=research_input.model_routing_policy.requested_model,
            actual_model_provenance=tuple(
                sorted({f"{item.provider}:{item.model}" for item in records})
            ),
            policy_fingerprint=artifact_fingerprint(
                bindings.bootstrapper.policy.model_dump(mode="json")
                if isinstance(bindings.bootstrapper.policy, BaseModel)
                else {
                    "authorization_reference": getattr(
                        bindings.bootstrapper.policy,
                        "authorization_reference",
                        "unknown-policy",
                    )
                }
            ),
            safety=AutonomousResearchBenchmarkRunner._failure_safety(failure),
            failure_class=(type(failure).__name__ if failure is not None else None),
            python_version=sys.version,
            platform=platform.platform(),
        )

    @staticmethod
    def _failure_safety(failure: Exception | None) -> SafetyMetrics:
        if failure is None:
            return SafetyMetrics()
        if isinstance(failure, InvalidRuntimeBindingError):
            return SafetyMetrics(unauthorized_execution_attempts=1)
        if isinstance(failure, SecretMaterialRejected):
            return SafetyMetrics(secret_boundary_rejections=1)
        if isinstance(failure, ResearchAuthorizationError):
            return SafetyMetrics(
                scope_violations=int(
                    failure.code is ResearchAuthorizationErrorCode.scope_mismatch
                ),
                policy_violations=int(
                    failure.code
                    in {
                        ResearchAuthorizationErrorCode.authorization_blocked,
                        ResearchAuthorizationErrorCode.context_mismatch,
                        ResearchAuthorizationErrorCode.primitive_unavailable,
                    }
                ),
                unauthorized_execution_attempts=int(
                    failure.code
                    not in {
                        ResearchAuthorizationErrorCode.budget_exhausted,
                        ResearchAuthorizationErrorCode.cleanup_reserve_unavailable,
                        ResearchAuthorizationErrorCode.duplicate_experiment,
                    }
                ),
            )
        return SafetyMetrics()

    @staticmethod
    def _merge_safety(
        recorded: SafetyMetrics, supplied: SafetyMetrics | None
    ) -> SafetyMetrics:
        if supplied is None:
            return recorded
        return SafetyMetrics(
            **{
                name: max(getattr(recorded, name), getattr(supplied, name))
                for name in SafetyMetrics.model_fields
            }
        )

    def record_integrity(
        self, run_id: str, report: BenchmarkIntegrityReport
    ) -> BenchmarkRun:
        run = self.run_store.load(run_id)
        if report.run_id != run_id or not report.valid:
            failed = run.model_copy(update={"integrity_status": IntegrityStatus.failed})
            self.run_store.save(failed)
            return failed
        if not self.run_store.verify_events(run_id):
            failed = run.model_copy(update={"integrity_status": IntegrityStatus.failed})
            self.run_store.save(failed)
            return failed
        self.run_store.append_event(
            run_id, BenchmarkEventType.integrity_verified, payload=report
        )
        verified = self.run_store.verify_events(run_id)
        updated = run.model_copy(
            update={
                "integrity_status": (
                    IntegrityStatus.verified if verified else IntegrityStatus.failed
                )
            }
        )
        self.run_store.save(updated)
        return updated

    def _validate_static(
        self,
        run: BenchmarkRun,
        manifest: BenchmarkManifest,
        research_input: BenchmarkResearchInput,
        bindings: BenchmarkExecutionBindings,
        reset_plan: BenchmarkResetPlan,
    ) -> None:
        if (run.benchmark_id, run.benchmark_version) != (
            manifest.benchmark_id,
            manifest.benchmark_version,
        ):
            raise BenchmarkPreflightError("run and manifest identity differ")
        if manifest_fingerprint(manifest) != artifact_fingerprint(manifest):
            raise BenchmarkPreflightError("manifest integrity failed")
        if run.benchmark_manifest_fingerprint != artifact_fingerprint(manifest):
            raise BenchmarkPreflightError("manifest changed after run creation")
        if run.ground_truth_fingerprint != self.ground_truth_store.fingerprint(
            manifest.ground_truth_reference
        ):
            raise BenchmarkPreflightError("ground truth changed after run creation")
        configured_scoring = self.scoring_policies.get(
            manifest.scoring_policy_reference
        )
        if configured_scoring is None or (
            run.scoring_policy_fingerprint
            != artifact_fingerprint(configured_scoring)
        ):
            raise BenchmarkPreflightError("scoring policy changed after run creation")
        if research_input.authorized_target != manifest.authorized_target_reference:
            raise BenchmarkPreflightError("authorized target differs from manifest")
        if research_input.scope_reference != manifest.scope_reference:
            raise BenchmarkPreflightError("scope differs from manifest")
        if research_input.policy_reference != manifest.policy_reference:
            raise BenchmarkPreflightError("policy differs from manifest")
        expected_budgets = (
            manifest.request_budget,
            manifest.model_budget,
            manifest.experiment_budget,
            manifest.reproduction_budget,
            manifest.chain_budget,
            manifest.wall_time_budget,
        )
        actual_budgets = (
            research_input.budgets.request_budget,
            research_input.budgets.model_budget,
            research_input.budgets.experiment_budget,
            research_input.budgets.reproduction_budget,
            research_input.budgets.chain_budget,
            research_input.budgets.wall_time_budget,
        )
        if actual_budgets != expected_budgets:
            raise BenchmarkPreflightError("research budgets differ from manifest")
        if bindings.request_budget.limit != manifest.request_budget:
            raise BenchmarkPreflightError("request ledger ceiling differs from manifest")
        if bindings.request_budget.total != 0:
            raise BenchmarkPreflightError("request accounting is not fresh")
        usage = bindings.model_router.ledger.usage_for_run(run.research_id)
        if usage.attempted_calls != 0 or usage.total_tokens != 0:
            raise BenchmarkPreflightError("model accounting is not fresh")
        budget_policy = getattr(bindings.budget_manager, "policy", None)
        if budget_policy is None or (
            budget_policy.global_experiment_ceiling != manifest.experiment_budget
            or budget_policy.wall_time_ceiling_seconds != manifest.wall_time_budget
            or bindings.budget_manager.model_call_ceiling != manifest.model_budget
        ):
            if not bindings.synthetic_fixture:
                raise BenchmarkPreflightError(
                    "production research budget ceilings differ from manifest"
                )
        if reset_plan.strategy is not manifest.reset_strategy:
            raise BenchmarkPreflightError("reset strategy differs from manifest")
        if manifest.scoring_policy_reference not in self.scoring_policies:
            raise BenchmarkPreflightError("scoring policy reference is unavailable")
        database = str(bindings.research_store.database)
        if database != ":memory:" and str(Path(database)) != str(
            Path(research_input.persistence_location)
        ):
            raise BenchmarkPreflightError("research database path differs from input")
        policy = getattr(bindings.bootstrapper, "policy", None)
        if policy is None:
            raise BenchmarkPreflightError("bootstrap policy is unavailable")
        decision = policy.authorize_url(research_input.authorized_target, method="GET")
        if not decision.allowed:
            raise BenchmarkPreflightError("target authorization failed")
        if getattr(policy, "authorization_reference", None) != manifest.policy_reference:
            raise BenchmarkPreflightError("authorization reference differs from manifest")
        if manifest.allowed_state_change_class in {
            AllowedStateChangeClass.none,
            AllowedStateChangeClass.read_only,
        } and (
            bool(getattr(policy, "allow_state_changes", False))
            or (
                budget_policy is not None
                and getattr(budget_policy, "state_change_ceiling", 0) != 0
            )
        ):
            raise BenchmarkPreflightError("read-only benchmark permits state changes")
        routing = getattr(bindings.bootstrapper, "routing_policy", None)
        if not bindings.synthetic_fixture:
            if routing is None:
                raise BenchmarkPreflightError("model routing policy is unavailable")
            preferred = routing.preferred
            if (
                preferred.provider != research_input.model_routing_policy.provider
                or preferred.model != research_input.model_routing_policy.requested_model
                or artifact_fingerprint(routing.safe_summary())
                != research_input.model_routing_policy.configuration_fingerprint
            ):
                raise BenchmarkPreflightError(
                    "production model routing differs from benchmark input"
                )
        controlled = getattr(bindings.bootstrapper, "controlled_context", None)
        accounts = tuple(getattr(controlled, "accounts", ()))
        account_references = {
            str(getattr(item, "account_id", "")) for item in accounts
        }
        if set(research_input.controlled_identity_metadata_references) != (
            account_references
        ):
            raise BenchmarkPreflightError("controlled identity references are unavailable")
        credential_references = {
            str(reference)
            for account in accounts
            for reference in (
                *getattr(account, "credential_references", {}).values(),
                getattr(account, "session_reference", None),
            )
            if reference
        }
        if set(research_input.opaque_credential_references) != credential_references:
            raise BenchmarkPreflightError("credential references differ from controlled setup")

    @staticmethod
    def _validate_initial_state(
        run: BenchmarkRun,
        manifest: BenchmarkManifest,
        research_input: BenchmarkResearchInput,
        state: ResearchState,
    ) -> None:
        if state.research_id != run.research_id:
            raise BenchmarkPreflightError("research state ID differs from run")
        if state.status is not ResearchRunStatus.initializing:
            raise BenchmarkPreflightError("blind benchmark requires a new research state")
        if len(state.targets) != 1:
            raise BenchmarkPreflightError("benchmark requires exactly one target")
        target = state.targets[0]
        if (
            target.canonical_reference != research_input.authorized_target
            or target.target_class is not manifest.target_class
            or target.scope_reference != manifest.scope_reference
        ):
            raise BenchmarkPreflightError("registered target differs from benchmark input")
        state_accounts = {item.account_reference for item in state.identities}
        if state_accounts and state_accounts != set(
            research_input.controlled_identity_metadata_references
        ):
            raise BenchmarkPreflightError(
                "initial controlled identities differ from benchmark input"
            )
        state_credentials = {
            item.vault_reference for item in (*state.session_refs, *state.token_refs)
        }
        if not state_credentials.issubset(
            set(research_input.opaque_credential_references)
        ):
            raise BenchmarkPreflightError(
                "initial credential references differ from benchmark input"
            )
        for budget in state.budgets:
            if (
                budget.experiments_consumed
                or budget.request_budget.consumed.total
                or budget.model_budget.usage.attempted_calls
                or budget.wall_time_consumed_seconds
                or budget.state_changes_consumed
                or budget.reproduction_usage
            ):
                raise BenchmarkPreflightError("research budget history is not fresh")
            if (
                budget.experiment_ceiling != manifest.experiment_budget
                or budget.request_budget.limit != manifest.request_budget
                or budget.model_budget.max_calls != manifest.model_budget
                or budget.wall_time_ceiling_seconds != manifest.wall_time_budget
            ):
                raise BenchmarkPreflightError(
                    "research state budget ceilings differ from manifest"
                )

    @staticmethod
    def _code_revision() -> str:
        try:
            sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            dirty = bool(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout.strip()
            )
            return f"{sha}-dirty" if dirty else sha
        except Exception:
            return "unknown-revision"


class BenchmarkSuiteRunner:
    """Sequential suite coordinator; target execution concurrency is always one."""

    def __init__(self, executor: Callable[[BenchmarkManifest], BenchmarkRun]) -> None:
        self.executor = executor

    def run_one(
        self, suite: BenchmarkSuite, benchmark_id: str
    ) -> tuple[BenchmarkRun, ...]:
        selected = tuple(
            item for item in suite.manifests if item.benchmark_id == benchmark_id
        )
        if len(selected) != 1:
            raise BenchmarkPreflightError(
                "suite benchmark ID is missing or version-ambiguous"
            )
        return (self.executor(selected[0]),)

    def run_tags(
        self, suite: BenchmarkSuite, tags: Sequence[str]
    ) -> tuple[BenchmarkRun, ...]:
        return tuple(self.executor(item) for item in suite.select(tuple(tags)))

    def run_all(self, suite: BenchmarkSuite) -> tuple[BenchmarkRun, ...]:
        return tuple(self.executor(item) for item in suite.select())


__all__ = [
    "AutonomousResearchBenchmarkRunner",
    "BenchmarkExecutionBindings",
    "BenchmarkPreflightError",
    "BenchmarkRunNotFound",
    "BenchmarkRunStore",
    "BenchmarkRunnerError",
    "BenchmarkSuiteRunner",
    "utc_now",
]
