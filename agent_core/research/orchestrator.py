"""Bounded autonomous selection, execution, evaluation, and pivot loop."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from enum import Enum

from pydantic import Field, StrictInt

from agent_core.research.authorization import (
    DuplicateExperimentError,
    ResearchAuthorizationError,
    ResearchCleanupBarrier,
    ResearchExecutionGate,
    policy_fingerprint as authorization_policy_fingerprint,
)
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.compiler import ExperimentCompiler, ExperimentCompilerContext
from agent_core.research.evaluation import (
    ExperimentEvaluator,
    ResearchConsequence,
    ResearchEvaluation,
)
from agent_core.research.experiments import ExperimentProposal, SecurityExperiment
from agent_core.research.outcomes import ExperimentOutcome
from agent_core.research.pivot import PivotPlanner
from agent_core.research.reasoning import (
    PublicSafeResearchPacketBuilder,
    ResearchReasoningEngine,
    ResearchReasoningError,
    ResearchStrategyAction,
    ResearchStrategyDecision,
)
from agent_core.research.selection import (
    ExperimentSelector,
    InformationGainEstimate,
    ProposalRankingAdvice,
    material_experiment_fingerprint,
)
from agent_core.research.state import ResearchExperimentRecord, ResearchState
from agent_core.research.store import ResearchStore
from agent_core.research.transitions import ResearchStateMachine
from agent_core.research.types import (
    HypothesisResearchStatus,
    ResearchContract,
    ResearchExperimentStatus,
    ResearchRunStatus,
)


class OrchestratorStopReason(str, Enum):
    no_research_hypotheses = "no_research_hypotheses"
    no_eligible_hypotheses = "no_eligible_hypotheses"
    no_eligible_experiments = "no_eligible_experiments"
    global_experiment_budget_exhausted = "global_experiment_budget_exhausted"
    request_budget_exhausted = "request_budget_exhausted"
    model_budget_exhausted = "model_budget_exhausted"
    wall_time_exhausted = "wall_time_exhausted"
    cleanup_barrier = "cleanup_barrier"
    all_hypotheses_resolved = "all_hypotheses_resolved"
    policy_context_changed = "policy_context_changed"
    repeated_service_instability = "repeated_service_instability"
    deterministic_safety_stop = "deterministic_safety_stop"
    invalid_model_output_limit = "invalid_model_output_limit"
    model_requested_stop = "model_requested_stop"
    candidate_requires_reproduction = "candidate_requires_reproduction"
    iteration_limit = "iteration_limit"
    interrupted_inflight = "interrupted_inflight"


class ResearchLoopResult(ResearchContract):
    research_id: str
    state: ResearchState
    iterations: StrictInt = Field(ge=0)
    evaluations: tuple[ResearchEvaluation, ...] = Field(default=(), max_length=10_000)
    stop_reason: OrchestratorStopReason | None = None
    completed: bool = False


ProposalSource = Callable[[ResearchState], Sequence[ExperimentProposal]]


class SecurityResearchOrchestrator:
    """AI selects strategy while deterministic components retain all authority."""

    def __init__(
        self,
        *,
        store: ResearchStore,
        compiler: ExperimentCompiler,
        gate: ResearchExecutionGate | object,
        selector: ExperimentSelector,
        evaluator: ExperimentEvaluator,
        pivot_planner: PivotPlanner,
        budget_manager: ResearchBudgetManager,
        proposal_source: ProposalSource | None = None,
        reasoning_engine: ResearchReasoningEngine | None = None,
        routing_policy: object | None = None,
        packet_builder: PublicSafeResearchPacketBuilder | None = None,
        compiler_context: ExperimentCompilerContext | None = None,
        runtime: object | None = None,
        policy_limitations: tuple[str, ...] = (),
        bootstrapper: object | None = None,
    ) -> None:
        self.store = store
        self.compiler = compiler
        self.gate = gate
        self.selector = selector
        self.evaluator = evaluator
        self.pivot_planner = pivot_planner
        self.budget_manager = budget_manager
        self.proposal_source = proposal_source
        self.reasoning_engine = reasoning_engine
        self.routing_policy = routing_policy
        self.packet_builder = packet_builder
        self.compiler_context = compiler_context or compiler.context
        self.runtime = runtime or getattr(gate, "runtime", None)
        self.policy_limitations = policy_limitations
        self.bootstrapper = bootstrapper
        if self.compiler_context is None:
            raise TypeError("the research orchestrator requires compiler context")
        if self.runtime is None:
            raise TypeError("the research orchestrator requires ResearchRuntime")
        if self.reasoning_engine is not None and self.routing_policy is None:
            raise TypeError("model research strategy requires a routing policy")
        if self.reasoning_engine is not None and self.packet_builder is None:
            raise TypeError("model research strategy requires a packet builder")

    def run(
        self,
        research_id: str,
        *,
        proposals: Sequence[ExperimentProposal] = (),
        max_iterations: int | None = None,
    ) -> ResearchLoopResult:
        if max_iterations is not None and max_iterations < 1:
            raise ValueError("max_iterations must be positive")
        evaluations: list[ResearchEvaluation] = []
        iterations = 0
        invalid_model_outputs = 0
        previous_experiment: SecurityExperiment | None = None
        next_is_pivot = False
        static_proposals = tuple(proposals)

        state = self._prepare(self.store.load_research(research_id))
        if self.bootstrapper is not None:
            context_adapter = getattr(self.bootstrapper, "compiler_context", None)
            if callable(context_adapter):
                self.compiler_context = context_adapter(state, self.compiler_context)
                self.compiler.context = self.compiler_context
        if state.status in {ResearchRunStatus.stopped, ResearchRunStatus.failed}:
            return ResearchLoopResult(
                research_id=research_id,
                state=state,
                iterations=0,
                completed=True,
            )
        if state.status is ResearchRunStatus.evaluating_result:
            return self._fail_interrupted(state)
        if state.status is ResearchRunStatus.awaiting_authorization:
            state = self._transition(
                state,
                ResearchRunStatus.selecting_experiment,
                "restart-before-authorization",
            )
        if state.status is ResearchRunStatus.pivoting:
            next_is_pivot = True
            state = self._transition(
                state, ResearchRunStatus.selecting_experiment, "resume-material-pivot"
            )

        while True:
            state = self.store.load_research(research_id)
            if max_iterations is not None and iterations >= max_iterations:
                return ResearchLoopResult(
                    research_id=research_id,
                    state=state,
                    iterations=iterations,
                    evaluations=tuple(evaluations),
                    stop_reason=OrchestratorStopReason.iteration_limit,
                    completed=False,
                )
            unresolved = tuple(
                item
                for item in state.hypotheses
                if item.status
                not in {
                    HypothesisResearchStatus.closed,
                    HypothesisResearchStatus.refuted,
                    HypothesisResearchStatus.supported,
                }
            )
            if not unresolved:
                reason = (
                    OrchestratorStopReason.all_hypotheses_resolved
                    if state.hypotheses
                    else (
                        OrchestratorStopReason.no_research_hypotheses
                        if self.bootstrapper is not None
                        else OrchestratorStopReason.no_eligible_hypotheses
                    )
                )
                state = self._report_and_stop(state, reason)
                return ResearchLoopResult(
                    research_id=research_id,
                    state=state,
                    iterations=iterations,
                    evaluations=tuple(evaluations),
                    stop_reason=reason,
                    completed=True,
                )
            barrier = getattr(self.gate, "cleanup_barrier", None)
            if isinstance(barrier, ResearchCleanupBarrier) and barrier.active:
                state = self._stop(state, OrchestratorStopReason.cleanup_barrier)
                return ResearchLoopResult(
                    research_id=research_id,
                    state=state,
                    iterations=iterations,
                    evaluations=tuple(evaluations),
                    stop_reason=OrchestratorStopReason.cleanup_barrier,
                    completed=True,
                )

            decision = None
            model_proposals: tuple[ExperimentProposal, ...] = ()
            if self.reasoning_engine is not None:
                try:
                    packet = self.packet_builder.build(  # type: ignore[union-attr]
                        state, policy_limitations=self.policy_limitations
                    )
                    decision = self.reasoning_engine.decide(
                        packet, self.routing_policy  # type: ignore[arg-type]
                    )
                    invalid_model_outputs = 0
                    if decision.action is ResearchStrategyAction.stop:
                        state = self._stop(
                            state, OrchestratorStopReason.model_requested_stop
                        )
                        return ResearchLoopResult(
                            research_id=research_id,
                            state=state,
                            iterations=iterations,
                            evaluations=tuple(evaluations),
                            stop_reason=OrchestratorStopReason.model_requested_stop,
                            completed=True,
                        )
                    model_proposals = decision.proposals
                except ResearchReasoningError as exc:
                    invalid_model_outputs += 1
                    if (
                        "budget" in exc.reason.value
                        and not static_proposals
                        and self.proposal_source is None
                    ):
                        state = self._stop(
                            state, OrchestratorStopReason.model_budget_exhausted
                        )
                        return ResearchLoopResult(
                            research_id=research_id,
                            state=state,
                            iterations=iterations,
                            evaluations=tuple(evaluations),
                            stop_reason=OrchestratorStopReason.model_budget_exhausted,
                            completed=True,
                        )
                    if (
                        invalid_model_outputs
                        >= self.budget_manager.policy.invalid_model_output_limit
                        and not static_proposals
                        and self.proposal_source is None
                    ):
                        state = self._stop(
                            state, OrchestratorStopReason.invalid_model_output_limit
                        )
                        return ResearchLoopResult(
                            research_id=research_id,
                            state=state,
                            iterations=iterations,
                            evaluations=tuple(evaluations),
                            stop_reason=(
                                OrchestratorStopReason.invalid_model_output_limit
                            ),
                            completed=True,
                        )
            sourced = (
                tuple(self.proposal_source(state))
                if self.proposal_source is not None
                else ()
            )
            candidates = self._rebase_proposals(
                (*model_proposals, *sourced, *static_proposals), state
            )
            advisory = self._advisory(decision, candidates)
            selection = self.selector.select(
                candidates,
                state,
                compiler_context=self.compiler_context,
                advisory=advisory,
                pivot=next_is_pivot,
                cleanup_barrier=bool(getattr(barrier, "active", False)),
                policy_reference=self.compiler_context.policy_reference,
                policy_fingerprint=self._policy_fingerprint(),
            )
            if next_is_pivot and previous_experiment is not None:
                plan = self.pivot_planner.plan(
                    previous_experiment,
                    candidates,
                    state,
                    compiler_context=self.compiler_context,
                    advisory=advisory,
                    cleanup_barrier=bool(getattr(barrier, "active", False)),
                    policy_reference=self.compiler_context.policy_reference,
                    policy_fingerprint=self._policy_fingerprint(),
                )
                selection = plan.selection or selection.model_copy(
                    update={"selected": None, "stop_reason": "no-material-pivot"}
                )
            if selection.selected is None:
                reason = self._selection_stop_reason(selection)
                state = self._stop(state, reason)
                return ResearchLoopResult(
                    research_id=research_id,
                    state=state,
                    iterations=iterations,
                    evaluations=tuple(evaluations),
                    stop_reason=reason,
                    completed=True,
                )

            selected_proposal = next(
                item
                for item in candidates
                if item.proposal_id == selection.selected.proposal_id
            )
            state = self._transition(
                state,
                ResearchRunStatus.awaiting_authorization,
                "experiment-selected",
            )
            state = self._transition(
                state,
                ResearchRunStatus.executing_experiment,
                "authorization-required",
            )
            executable_proposal = self._rebase_proposals((selected_proposal,), state)[0]
            experiment = self.compiler.compile(
                executable_proposal, state, self.compiler_context
            )
            try:
                authorization = self.gate.authorize(experiment)
                bind = getattr(self.gate, "bind", None)
                if callable(bind):
                    bind(authorization)
                outcome = self.runtime.submit(authorization)
                if not isinstance(outcome, ExperimentOutcome):
                    raise TypeError("research runtime returned an invalid outcome")
            except ResearchAuthorizationError as exc:
                state = self._record_authorization_block(state, experiment, exc)
                state = self._transition(
                    state,
                    ResearchRunStatus.evaluating_result,
                    "authorization-blocked",
                )
                state = self._transition(
                    state,
                    ResearchRunStatus.selecting_experiment,
                    "choose-after-policy-block",
                )
                next_is_pivot = False
                continue

            state = self.store.load_research(research_id)
            state = self._transition(
                state, ResearchRunStatus.evaluating_result, "outcome-available"
            )
            model_hypotheses = decision.new_hypotheses if decision is not None else ()
            evaluation = self.evaluator.evaluate_and_commit(
                experiment,
                authorization,
                outcome,
                self.store,
                budget_manager=self.budget_manager,
                was_pivot=next_is_pivot,
                proposed_hypotheses=model_hypotheses,
            )
            evaluations.append(evaluation)
            iterations += 1
            previous_experiment = experiment
            state = self.store.load_research(research_id)

            if evaluation.stop_required:
                state = self._stop(
                    state, OrchestratorStopReason.deterministic_safety_stop
                )
                return ResearchLoopResult(
                    research_id=research_id,
                    state=state,
                    iterations=iterations,
                    evaluations=tuple(evaluations),
                    stop_reason=OrchestratorStopReason.deterministic_safety_stop,
                    completed=True,
                )
            if evaluation.consequence is ResearchConsequence.pivot_recommended:
                budget = self.budget_manager.check(
                    state,
                    hypothesis_id=experiment.hypothesis_id,
                    surface_id=experiment.target.surface_id,
                    pivot=True,
                )
                if not budget.allowed:
                    reason = self._budget_stop_reason(
                        budget.reason.value if budget.reason else ""
                    )
                    state = self._stop(state, reason)
                    return ResearchLoopResult(
                        research_id=research_id,
                        state=state,
                        iterations=iterations,
                        evaluations=tuple(evaluations),
                        stop_reason=reason,
                        completed=True,
                    )
                state = self._transition(
                    state, ResearchRunStatus.pivoting, "material-pivot-recommended"
                )
                next_is_pivot = True
                if max_iterations is not None and iterations >= max_iterations:
                    continue
                state = self._transition(
                    state,
                    ResearchRunStatus.selecting_experiment,
                    "select-material-pivot",
                )
                continue
            next_is_pivot = False
            remaining = any(
                item.status
                not in {
                    HypothesisResearchStatus.closed,
                    HypothesisResearchStatus.refuted,
                    HypothesisResearchStatus.supported,
                }
                for item in state.hypotheses
            )
            if remaining:
                state = self._transition(
                    state,
                    ResearchRunStatus.selecting_experiment,
                    "continue-research",
                )
                continue
            reason = (
                OrchestratorStopReason.candidate_requires_reproduction
                if evaluation.candidate_finding is not None
                else OrchestratorStopReason.all_hypotheses_resolved
            )
            state = self._report_and_stop(state, reason)
            return ResearchLoopResult(
                research_id=research_id,
                state=state,
                iterations=iterations,
                evaluations=tuple(evaluations),
                stop_reason=reason,
                completed=True,
            )

    def _prepare(self, state: ResearchState) -> ResearchState:
        if self.bootstrapper is not None:
            prepare = getattr(self.bootstrapper, "prepare", None)
            if not callable(prepare):
                raise TypeError("research bootstrapper must provide prepare(state)")
            prepared = prepare(state)
            if not isinstance(prepared, ResearchState):
                raise TypeError("research bootstrapper returned invalid state")
            return prepared
        paths = {
            ResearchRunStatus.initializing: (
                ResearchRunStatus.discovering,
                ResearchRunStatus.modeling,
                ResearchRunStatus.hypothesizing,
                ResearchRunStatus.selecting_experiment,
            ),
            ResearchRunStatus.discovering: (
                ResearchRunStatus.modeling,
                ResearchRunStatus.hypothesizing,
                ResearchRunStatus.selecting_experiment,
            ),
            ResearchRunStatus.modeling: (
                ResearchRunStatus.hypothesizing,
                ResearchRunStatus.selecting_experiment,
            ),
            ResearchRunStatus.hypothesizing: (ResearchRunStatus.selecting_experiment,),
        }
        for next_status in paths.get(state.status, ()):
            state = self._transition(state, next_status, "autonomous-research-start")
        return state

    def _transition(
        self, state: ResearchState, next_status: ResearchRunStatus, reason: str
    ) -> ResearchState:
        occurred_at = self._now(state.updated_at)
        machine = ResearchStateMachine(state)
        event = machine.transition(
            next_status,
            reason_code=reason,
            event_id=_identifier(
                "event", state.research_id, state.revision, next_status.value, reason
            ),
            provenance_id=self._provenance_id(state),
            occurred_at=occurred_at,
        )
        next_state = machine.snapshot()
        return self.store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
            events=(event,),
        )

    def _stop(
        self, state: ResearchState, reason: OrchestratorStopReason
    ) -> ResearchState:
        if state.status is ResearchRunStatus.reporting:
            return self._transition(state, ResearchRunStatus.stopped, reason.value)
        if ResearchRunStatus.stopped in self._allowed_next(state):
            return self._transition(state, ResearchRunStatus.stopped, reason.value)
        return self._transition(state, ResearchRunStatus.failed, reason.value)

    def _report_and_stop(
        self, state: ResearchState, reason: OrchestratorStopReason
    ) -> ResearchState:
        if state.status is ResearchRunStatus.evaluating_result:
            state = self._transition(
                state, ResearchRunStatus.reporting, "prepare-research-report"
            )
        elif state.status in {
            ResearchRunStatus.hypothesizing,
            ResearchRunStatus.selecting_experiment,
            ResearchRunStatus.pivoting,
            ResearchRunStatus.chaining,
            ResearchRunStatus.impact_analysis,
        }:
            state = self._transition(
                state, ResearchRunStatus.reporting, "prepare-research-report"
            )
        return self._stop(state, reason)

    def _record_authorization_block(
        self,
        state: ResearchState,
        experiment: SecurityExperiment,
        error: ResearchAuthorizationError,
    ) -> ResearchState:
        status = (
            ResearchExperimentStatus.duplicate_blocked
            if isinstance(error, DuplicateExperimentError)
            else ResearchExperimentStatus.policy_blocked
        )
        record = ResearchExperimentRecord(
            experiment_id=experiment.experiment_id,
            proposal_id=experiment.provenance.source_proposal_id,
            hypothesis_id=experiment.hypothesis_id,
            surface_id=experiment.target.surface_id,
            fingerprint=experiment.fingerprint,
            material_fingerprint=material_experiment_fingerprint(experiment),
            status=status,
            result_classification=error.code.value,
            relevant_state_revision=state.revision,
            policy_reference=self.compiler_context.policy_reference,
            policy_fingerprint=self._policy_fingerprint(),
            occurred_at=self._now(state.updated_at),
        )
        payload = state.model_dump(mode="python")
        payload.update(
            revision=state.revision + 1,
            updated_at=record.occurred_at,
            experiment_history=(*state.experiment_history, record),
        )
        next_state = ResearchState.model_validate(payload)
        return self.store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
        )

    def _rebase_proposals(
        self, proposals: Sequence[ExperimentProposal], state: ResearchState
    ) -> tuple[ExperimentProposal, ...]:
        unique: dict[str, ExperimentProposal] = {}
        for proposal in proposals:
            if proposal.research_id != state.research_id:
                continue
            payload = proposal.model_dump(mode="python")
            payload["state_revision"] = state.revision
            unique[proposal.proposal_id] = ExperimentProposal.model_validate(payload)
        return tuple(unique[key] for key in sorted(unique))

    @staticmethod
    def _advisory(
        decision: ResearchStrategyDecision | None,
        proposals: tuple[ExperimentProposal, ...],
    ) -> tuple[ProposalRankingAdvice, ...]:
        if decision is None:
            return ()
        return tuple(
            ProposalRankingAdvice(
                proposal_id=item.proposal_id,
                expected_information_gain=(
                    decision.expected_information_gain
                    if item.proposal_id == decision.selected_proposal_id
                    else InformationGainEstimate.medium
                ),
                priority=(
                    decision.priority
                    if item.proposal_id == decision.selected_proposal_id
                    else 50
                ),
                confidence=InformationGainEstimate(decision.confidence.value),
            )
            for item in proposals
        )

    def _policy_fingerprint(self) -> str | None:
        policy = getattr(self.gate, "policy", None)
        return authorization_policy_fingerprint(policy) if policy is not None else None

    @staticmethod
    def _selection_stop_reason(selection: object) -> OrchestratorStopReason:
        assessments = getattr(selection, "assessments", ())
        reasons = {
            reason.value
            for item in assessments
            for reason in getattr(item, "reasons", ())
        }
        if "cleanup_barrier" in reasons:
            return OrchestratorStopReason.cleanup_barrier
        if "request_reserve_unavailable" in reasons:
            return OrchestratorStopReason.request_budget_exhausted
        if "global_budget_exhausted" in reasons:
            return OrchestratorStopReason.global_experiment_budget_exhausted
        if "policy_context_changed" in reasons:
            return OrchestratorStopReason.policy_context_changed
        return OrchestratorStopReason.no_eligible_experiments

    @staticmethod
    def _budget_stop_reason(reason: str) -> OrchestratorStopReason:
        if "request" in reason:
            return OrchestratorStopReason.request_budget_exhausted
        if "model" in reason:
            return OrchestratorStopReason.model_budget_exhausted
        if "wall_time" in reason:
            return OrchestratorStopReason.wall_time_exhausted
        if "cleanup" in reason:
            return OrchestratorStopReason.cleanup_barrier
        if "instability" in reason:
            return OrchestratorStopReason.repeated_service_instability
        return OrchestratorStopReason.global_experiment_budget_exhausted

    @staticmethod
    def _provenance_id(state: ResearchState) -> str:
        if not state.provenance:
            raise ValueError("research orchestration requires existing provenance")
        return state.provenance[0].provenance_id

    @staticmethod
    def _allowed_next(state: ResearchState) -> frozenset[ResearchRunStatus]:
        from agent_core.research.transitions import ALLOWED_RESEARCH_TRANSITIONS

        return ALLOWED_RESEARCH_TRANSITIONS[state.status]

    def _now(self, minimum: str) -> str:
        configured = getattr(self.gate, "current_time", None)
        candidate = configured or datetime.now(timezone.utc).isoformat()
        return max(candidate, minimum)

    def _fail_interrupted(self, state: ResearchState) -> ResearchLoopResult:
        state = self._transition(
            state,
            ResearchRunStatus.failed,
            OrchestratorStopReason.interrupted_inflight.value,
        )
        return ResearchLoopResult(
            research_id=state.research_id,
            state=state,
            iterations=0,
            stop_reason=OrchestratorStopReason.interrupted_inflight,
            completed=True,
        )


def _identifier(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256("|".join(str(item) for item in parts).encode()).hexdigest()
    return f"{prefix}-{digest[:24]}"


__all__ = [
    "OrchestratorStopReason",
    "ResearchLoopResult",
    "SecurityResearchOrchestrator",
]
