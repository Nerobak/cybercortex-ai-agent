"""Bounded P3-4 reasoning-to-Phase-2 orchestration."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from agent_core.agent_models import Hypothesis, VerificationPlan
from agent_core.autonomy.decision_gate import (
    ExecutionDecisionGate,
    controlled_context_reference,
)
from agent_core.autonomy.history import AutonomyHistory
from agent_core.autonomy.runtime_binding import (
    UNBOUND_PHASE2_RUNTIME,
    Phase2RuntimeBindingError,
    bind_authoritative_phase2_runtime,
)
from agent_core.autonomy.state import AutonomyStateMachine, utc_now
from agent_core.autonomy.types import (
    AutonomyIterationRecord,
    AutonomyRun,
    AutonomyRunConfig,
    AutonomyState,
    ExecutionIdentity,
    FailureReason,
    GateDecision,
    GateReason,
    IterationReasoningProvenance,
    ModelBudgetState,
    Phase2ResultProvenance,
    PivotReason,
    ProposedVerification,
    StopReason,
    add_model_usage,
    add_request_delta,
)
from agent_core.models import ModelRoutingPolicy, ModelUsageDelta
from agent_core.phase2_result_status import (
    BUDGET_PREFLIGHT_REASON,
    CLEANUP_UNVERIFIED_REASON,
    PUBLIC_RESULT_STATUSES,
    SERVICE_UNSTABLE_REASON,
)
from agent_core.reasoning import (
    ModelBudgetContext,
    PolicyReasoningConstraints,
    PreviousReasoningDecision,
    ReasoningAction,
    ReasoningDecision,
    ReasoningError,
    ReasoningErrorCode,
    ReasoningTaskType,
    build_reasoning_request,
)
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import public_result
from agent_core.result_provenance import verification_result_reference
from agent_core.verification_runtime import VerificationRuntime


class AutonomousOrchestrator:
    """Run one bounded advisory loop through the shared Phase 2 runtime only."""

    def __init__(
        self,
        reasoning_engine: Any,
        routing_policy: ModelRoutingPolicy,
        phase2_runtime: VerificationRuntime,
        *,
        decision_gate: ExecutionDecisionGate | None = None,
        history: AutonomyHistory | None = None,
    ) -> None:
        self.reasoning_engine = reasoning_engine
        self.routing_policy = routing_policy
        try:
            self._phase2_runtime = bind_authoritative_phase2_runtime(phase2_runtime)
        except Phase2RuntimeBindingError:
            self._phase2_runtime = UNBOUND_PHASE2_RUNTIME
        self.decision_gate = decision_gate or ExecutionDecisionGate()
        self.history = history or AutonomyHistory()

    def run(
        self,
        *,
        config: AutonomyRunConfig,
        hypotheses: Iterable[Hypothesis],
        verification_plans: Iterable[VerificationPlan],
        policy_constraints: PolicyReasoningConstraints,
    ) -> AutonomyRun:
        started = utc_now()
        run = AutonomyRun(
            run_id=config.run_id,
            phase2_run_reference=config.phase2_run_reference,
            target_reference=config.target_reference,
            started_at=started,
            updated_at=started,
        )
        machine = AutonomyStateMachine(run)
        hypothesis_map = self._hypothesis_map(hypotheses)
        plan_map = self._plan_map(verification_plans)
        previous_decisions: list[PreviousReasoningDecision] = []
        prior_results: dict[str, dict[str, Any]] = {}
        resolved: set[str] = set()
        deferred: set[str] = set()
        executions: list[ExecutionIdentity] = []
        pending_result_evaluation = False

        machine.transition(AutonomyState.observing, "autonomy_run_started")
        if not hypothesis_map:
            self._stop(machine, run, StopReason.no_eligible_hypotheses)
            return run

        for iteration in range(1, config.limits.max_iterations + 1):
            transition_start = len(machine.transitions)
            if run.current_state is AutonomyState.pivoting:
                machine.transition(AutonomyState.observing, "next_bounded_iteration")
            run.iteration = iteration
            if (
                set(hypothesis_map).issubset(resolved | deferred)
                and not pending_result_evaluation
            ):
                self._stop(machine, run, StopReason.all_relevant_hypotheses_resolved)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    stop_reason=run.stop_reason,
                )
                break

            machine.transition(AutonomyState.reasoning, "grounded_reasoning_requested")
            ledger_before = self._ledger_snapshot(config.run_id)
            try:
                request = build_reasoning_request(
                    task_type=(
                        ReasoningTaskType.result_review
                        if prior_results
                        else ReasoningTaskType.hypothesis_analysis
                    ),
                    run_id=config.run_id,
                    target_reference=config.target_reference,
                    hypotheses=tuple(hypothesis_map.values()),
                    policy_constraints=policy_constraints,
                    verification_plans={
                        hypothesis_id: plan.model_dump(mode="python")
                        for hypothesis_id, plan in plan_map.items()
                    },
                    prior_results=prior_results,
                    previous_decisions=tuple(previous_decisions),
                    model_budget_context=self._model_budget_context(run.model_usage),
                )
                decision = self.reasoning_engine.reason(request, self.routing_policy)
            except ReasoningError as exc:
                failed_usage = self._ledger_delta(ledger_before, config.run_id)
                run.model_usage = add_model_usage(run.model_usage, failed_usage)
                run.reasoning_failures += 1
                if exc.code is ReasoningErrorCode.model_budget_exhausted:
                    self._stop(machine, run, self._model_budget_stop(run.model_usage))
                elif run.reasoning_failures >= config.limits.max_reasoning_failures:
                    self._stop(machine, run, StopReason.reasoning_failure_limit)
                elif iteration >= config.limits.max_iterations:
                    self._stop(machine, run, StopReason.max_iterations)
                else:
                    machine.transition(
                        AutonomyState.pivoting, PivotReason.reasoning_retry.value
                    )
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    pivot_reason=(
                        PivotReason.reasoning_retry
                        if run.current_state is AutonomyState.pivoting
                        else None
                    ),
                    stop_reason=run.stop_reason,
                    model_usage=failed_usage,
                )
                if run.current_state is AutonomyState.stopped:
                    break
                continue
            except (TypeError, ValueError):
                failed_usage = self._ledger_delta(ledger_before, config.run_id)
                run.model_usage = add_model_usage(run.model_usage, failed_usage)
                self._fail(machine, run, FailureReason.reasoning_failed)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    model_usage=failed_usage,
                )
                break

            if not isinstance(decision, ReasoningDecision):
                failed_usage = self._ledger_delta(ledger_before, config.run_id)
                run.model_usage = add_model_usage(run.model_usage, failed_usage)
                self._fail(machine, run, FailureReason.decision_invalid)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    model_usage=failed_usage,
                )
                break

            decision_usage = decision.model_provenance.usage
            run.model_usage = add_model_usage(run.model_usage, decision_usage)
            run.reasoning_decision = decision
            run.selected_hypothesis_id = decision.hypothesis_id
            run.selected_capability = decision.recommended_capability
            run.reasoning_history_references = (
                *run.reasoning_history_references,
                decision.decision_id,
            )
            previous_decisions.append(
                PreviousReasoningDecision(
                    decision_id=decision.decision_id,
                    hypothesis_id=decision.hypothesis_id,
                    action=decision.action,
                    recommended_capability=decision.recommended_capability,
                    concise_rationale=decision.rationale,
                )
            )
            pending_result_evaluation = False
            machine.transition(
                AutonomyState.decision_validation, "reasoning_decision_received"
            )

            if decision.action is ReasoningAction.stop:
                self._stop(machine, run, StopReason.model_recommended_stop)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    stop_reason=run.stop_reason,
                )
                break
            if decision.action is ReasoningAction.manual_review:
                self._stop(machine, run, StopReason.manual_review_required)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    stop_reason=run.stop_reason,
                )
                break
            if decision.action is ReasoningAction.request_additional_evidence:
                self._stop(machine, run, StopReason.additional_evidence_required)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    stop_reason=run.stop_reason,
                )
                break
            if decision.action is ReasoningAction.prioritize:
                self._stop(machine, run, StopReason.no_verification_recommended)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    stop_reason=run.stop_reason,
                )
                break
            if decision.action is ReasoningAction.defer:
                deferred.add(decision.hypothesis_id)
                if set(hypothesis_map).issubset(resolved | deferred):
                    self._stop(machine, run, StopReason.no_eligible_hypotheses)
                    pivot = None
                else:
                    machine.transition(
                        AutonomyState.pivoting, PivotReason.decision_deferred.value
                    )
                    pivot = PivotReason.decision_deferred
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    pivot_reason=pivot,
                    stop_reason=run.stop_reason,
                )
                if run.current_state is AutonomyState.stopped:
                    break
                continue

            machine.transition(
                AutonomyState.awaiting_execution_approval,
                "deterministic_execution_gate",
            )
            model_state = self._model_budget_state(run.model_usage)
            gate = self.decision_gate.evaluate(
                decision,
                hypotheses=hypothesis_map,
                plans=plan_map,
                eligible_hypothesis_ids=frozenset(set(hypothesis_map) - deferred),
                runtime=self._phase2_runtime,
                limits=config.limits,
                iteration=iteration,
                verifications_attempted=run.verifications_attempted,
                model_budget_state=model_state,
                execution_identities=tuple(executions),
                cleanup_barrier_active=run.cleanup_barrier_active,
            )
            if not gate.approved:
                should_continue, pivot = self._handle_gate_block(
                    machine,
                    run,
                    gate,
                    config=config,
                    iteration=iteration,
                    resolved=resolved,
                    deferred=deferred,
                    hypothesis_ids=set(hypothesis_map),
                )
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    gate=gate,
                    pivot_reason=pivot,
                    stop_reason=run.stop_reason,
                )
                if not should_continue:
                    break
                continue

            if config.dry_run:
                run.proposed_verification = ProposedVerification(
                    hypothesis_id=gate.hypothesis_id or decision.hypothesis_id,
                    capability=gate.capability or decision.recommended_capability or "",
                    plan_id=gate.plan_id or "",
                    estimated_requests=gate.required_requests,
                    dry_run=True,
                )
                self._stop(machine, run, StopReason.dry_run_complete)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    gate=gate,
                    stop_reason=run.stop_reason,
                )
                break

            hypothesis = hypothesis_map[decision.hypothesis_id]
            plan = plan_map[decision.hypothesis_id]
            try:
                request_budget, request_before = self._phase2_request_snapshot()
            except (AttributeError, TypeError, ValueError, RuntimeError):
                self._fail(machine, run, FailureReason.phase2_runtime_failed)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    gate=gate,
                )
                break
            machine.transition(AutonomyState.executing, "phase2_runtime_submission")
            run.verifications_attempted += 1
            raw_result: Any = None
            runtime_failed = False
            try:
                raw_result = self._phase2_runtime.submit(
                    hypothesis,
                    plan,
                    run_id=config.phase2_run_reference,
                )
            except Exception:
                runtime_failed = True
            request_delta = self._phase2_request_delta(
                request_budget,
                request_before,
            )
            run.phase2_request_usage = add_request_delta(
                run.phase2_request_usage, request_delta
            )
            if runtime_failed:
                self._fail(machine, run, FailureReason.phase2_runtime_failed)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    gate=gate,
                    phase2_delta=request_delta,
                )
                break

            try:
                result = self._canonical_phase2_result(
                    raw_result,
                    hypothesis,
                    request_delta,
                )
                status = str(result["status"])
                reasons = {
                    item for item in result.get("reasons", ()) if isinstance(item, str)
                }
                result_reference = self._result_reference(result)
                result_provenance = self._phase2_result_provenance(
                    run.phase2_run_reference,
                    result,
                    result_reference,
                )
                execution = ExecutionIdentity(
                    hypothesis_id=hypothesis.hypothesis_id,
                    capability=(decision.recommended_capability or hypothesis.category),
                    controlled_context_reference=controlled_context_reference(
                        self._phase2_runtime, plan
                    ),
                    result_status=status,
                )
            except Exception:
                self._fail(machine, run, FailureReason.phase2_runtime_failed)
                self._record_iteration(
                    run,
                    machine,
                    transition_start,
                    decision=decision,
                    gate=gate,
                    phase2_delta=request_delta,
                )
                break

            machine.transition(AutonomyState.evaluating, "phase2_result_received")
            prior_results[hypothesis.hypothesis_id] = result
            run.verification_result_references = (
                *run.verification_result_references,
                result_reference,
            )
            executions.append(execution)

            if status == "verification_pending_cleanup" or (
                CLEANUP_UNVERIFIED_REASON in reasons
            ):
                run.cleanup_barrier_active = True
                self._stop(machine, run, StopReason.cleanup_barrier)
                pivot_reason = None
            elif SERVICE_UNSTABLE_REASON in reasons:
                self._stop(machine, run, StopReason.service_instability)
                pivot_reason = None
            elif BUDGET_PREFLIGHT_REASON in reasons:
                self._stop(machine, run, StopReason.request_budget_exhausted)
                pivot_reason = None
            elif status == "awaiting_controlled_evidence":
                self._stop(machine, run, StopReason.awaiting_controlled_evidence)
                pivot_reason = None
            else:
                resolved.add(hypothesis.hypothesis_id)
                pivot_reason = {
                    "verified": PivotReason.verified,
                    "rejected": PivotReason.rejected,
                    "inconclusive": PivotReason.inconclusive,
                    "policy_blocked": PivotReason.policy_blocked,
                }[status]
                if status == "policy_blocked":
                    run.policy_blocks += 1
                    if run.policy_blocks >= config.limits.max_policy_blocks:
                        self._stop(machine, run, StopReason.phase2_policy_blocked)
                        pivot_reason = None
                    else:
                        pending_result_evaluation = True
                else:
                    pending_result_evaluation = True
                if run.current_state is AutonomyState.evaluating:
                    if iteration >= config.limits.max_iterations:
                        self._stop(machine, run, StopReason.max_iterations)
                        pivot_reason = None
                    else:
                        machine.transition(
                            AutonomyState.pivoting,
                            (pivot_reason or PivotReason.recommendation_blocked).value,
                        )

            history_recorded = self._record_iteration(
                run,
                machine,
                transition_start,
                decision=decision,
                gate=gate,
                phase2_result=result_provenance,
                phase2_result_reference=result_reference,
                phase2_delta=request_delta,
                pivot_reason=pivot_reason,
                stop_reason=run.stop_reason,
            )
            if not history_recorded:
                run.failure_reason = FailureReason.phase2_runtime_failed
                if run.current_state not in {
                    AutonomyState.stopped,
                    AutonomyState.failed,
                }:
                    self._fail(machine, run, FailureReason.phase2_runtime_failed)
                break
            if run.current_state in {AutonomyState.stopped, AutonomyState.failed}:
                break

        if run.current_state not in {AutonomyState.stopped, AutonomyState.failed}:
            self._stop(machine, run, StopReason.max_iterations)
        return run

    @staticmethod
    def _hypothesis_map(
        hypotheses: Iterable[Hypothesis],
    ) -> dict[str, Hypothesis]:
        values = tuple(hypotheses)
        if any(not isinstance(item, Hypothesis) for item in values):
            raise TypeError("P3-4 requires typed Phase 2 hypotheses")
        mapped = {item.hypothesis_id: item for item in values}
        if len(mapped) != len(values):
            raise ValueError("Autonomy hypotheses must have unique identifiers")
        return mapped

    @staticmethod
    def _plan_map(plans: Iterable[VerificationPlan]) -> dict[str, VerificationPlan]:
        values = tuple(plans)
        if any(not isinstance(item, VerificationPlan) for item in values):
            raise TypeError("P3-4 requires typed Phase 2 verification plans")
        mapped = {item.hypothesis_id: item for item in values}
        if len(mapped) != len(values):
            raise ValueError("Autonomy plans must have unique hypothesis identifiers")
        return mapped

    def _model_budget_state(self, usage: ModelUsageDelta) -> ModelBudgetState:
        limits = self.routing_policy.budget
        if usage.attempted_calls >= limits.max_model_calls:
            return ModelBudgetState.call_budget_exhausted
        if any(
            ceiling is not None and actual >= ceiling
            for actual, ceiling in (
                (usage.budget_input_tokens, limits.max_input_tokens),
                (usage.budget_output_tokens, limits.max_output_tokens),
                (usage.budget_total_tokens, limits.max_total_tokens),
            )
        ):
            return ModelBudgetState.token_budget_exhausted
        if limits.has_monetary_ceiling and (
            usage.budget_estimated_cost_usd is None
            and limits.unknown_cost_policy == "deny"
            or limits.max_estimated_cost_usd is not None
            and usage.budget_estimated_cost_usd is not None
            and usage.budget_estimated_cost_usd >= limits.max_estimated_cost_usd
        ):
            return ModelBudgetState.cost_budget_exhausted
        return ModelBudgetState.available

    def _ledger_snapshot(self, run_id: str) -> Any:
        router = getattr(self.reasoning_engine, "router", None)
        ledger = getattr(router, "ledger", None)
        snapshot = getattr(ledger, "snapshot", None)
        if not callable(snapshot):
            return None
        try:
            return snapshot(run_id=run_id)
        except (TypeError, ValueError):
            return None

    def _ledger_delta(self, before: Any, run_id: str) -> ModelUsageDelta:
        if before is None:
            return ModelUsageDelta()
        router = getattr(self.reasoning_engine, "router", None)
        ledger = getattr(router, "ledger", None)
        snapshot = getattr(ledger, "snapshot", None)
        delta = getattr(ledger, "delta", None)
        if not callable(snapshot) or not callable(delta):
            return ModelUsageDelta()
        try:
            return delta(before, snapshot(run_id=run_id))
        except (TypeError, ValueError):
            return ModelUsageDelta()

    def _phase2_request_snapshot(self) -> tuple[Any, Mapping[str, Any]]:
        """Snapshot the one Phase 2 request authority before runtime entry."""

        budget = self._phase2_runtime.budget
        snapshot = getattr(budget, "snapshot", None)
        if not callable(snapshot):
            raise ValueError("Phase 2 runtime has no request ledger snapshot")
        value = snapshot()
        if not isinstance(value, Mapping):
            raise ValueError("Phase 2 request ledger snapshot is invalid")
        stable = dict(value)
        RequestDelta.from_snapshots(stable, stable)
        return budget, stable

    def _phase2_request_delta(
        self,
        budget: Any,
        before: Mapping[str, Any],
    ) -> RequestDelta:
        """Derive exact attempted traffic from the existing Phase 2 ledger."""

        snapshot = getattr(budget, "snapshot", None)
        if not callable(snapshot):
            raise ValueError("Phase 2 runtime request ledger became unavailable")
        after = snapshot()
        if not isinstance(after, Mapping):
            raise ValueError("Phase 2 request ledger snapshot is invalid")
        return RequestDelta.from_snapshots(before, after)

    def _model_budget_stop(self, usage: ModelUsageDelta) -> StopReason:
        state = self._model_budget_state(usage)
        return {
            ModelBudgetState.call_budget_exhausted: StopReason.model_call_budget_exhausted,
            ModelBudgetState.token_budget_exhausted: StopReason.model_token_budget_exhausted,
            ModelBudgetState.cost_budget_exhausted: StopReason.model_cost_budget_exhausted,
            ModelBudgetState.available: StopReason.model_budget_exhausted,
        }[state]

    def _model_budget_context(self, usage: ModelUsageDelta) -> ModelBudgetContext:
        limits = self.routing_policy.budget

        def remaining(limit: int | None, used: int) -> int | None:
            return None if limit is None else max(0, limit - used)

        cost_remaining = None
        if (
            limits.max_estimated_cost_usd is not None
            and usage.budget_estimated_cost_usd is not None
        ):
            cost_remaining = max(
                0.0,
                limits.max_estimated_cost_usd - usage.budget_estimated_cost_usd,
            )
        return ModelBudgetContext(
            remaining_model_calls=max(
                0, limits.max_model_calls - usage.attempted_calls
            ),
            remaining_input_tokens=remaining(
                limits.max_input_tokens, usage.budget_input_tokens
            ),
            remaining_output_tokens=remaining(
                limits.max_output_tokens, usage.budget_output_tokens
            ),
            remaining_total_tokens=remaining(
                limits.max_total_tokens, usage.budget_total_tokens
            ),
            remaining_estimated_cost_usd=cost_remaining,
            cost_known=usage.budget_estimated_cost_usd is not None,
        )

    def _handle_gate_block(
        self,
        machine: AutonomyStateMachine,
        run: AutonomyRun,
        gate: GateDecision,
        *,
        config: AutonomyRunConfig,
        iteration: int,
        resolved: set[str],
        deferred: set[str],
        hypothesis_ids: set[str],
    ) -> tuple[bool, PivotReason | None]:
        if gate.reason is GateReason.duplicate_recommendation:
            run.duplicate_recommendations += 1
            if (
                run.duplicate_recommendations
                >= config.limits.max_duplicate_recommendations
            ):
                self._stop(machine, run, StopReason.duplicate_recommendation_limit)
                return False, None
        if gate.reason is GateReason.request_budget_exhausted:
            self._stop(machine, run, StopReason.request_budget_exhausted)
            return False, None
        if gate.reason is GateReason.model_budget_exhausted:
            self._stop(machine, run, self._model_budget_stop(run.model_usage))
            return False, None
        if gate.reason is GateReason.iteration_budget_exhausted:
            self._stop(machine, run, StopReason.max_iterations)
            return False, None
        if gate.reason is GateReason.verification_budget_exhausted:
            self._stop(machine, run, StopReason.max_verifications)
            return False, None
        if gate.reason is GateReason.cleanup_barrier:
            self._stop(machine, run, StopReason.cleanup_barrier)
            return False, None

        selected = gate.hypothesis_id
        if selected:
            deferred.add(selected)
        remaining = hypothesis_ids - resolved - deferred
        manual_reasons = {
            GateReason.plan_not_found,
            GateReason.plan_only_capability,
            GateReason.typed_route_unavailable,
            GateReason.authorization_missing,
            GateReason.controlled_account_missing,
            GateReason.credentials_missing,
            GateReason.state_change_permission_missing,
            GateReason.cleanup_requirement_missing,
            GateReason.test_owned_object_missing,
            GateReason.automatic_execution_unsupported,
            GateReason.runtime_boundary_invalid,
        }
        if gate.reason in manual_reasons or not remaining:
            reason = (
                StopReason.phase2_policy_blocked
                if gate.reason is GateReason.phase2_policy_denied
                else StopReason.manual_review_required
            )
            self._stop(machine, run, reason)
            return False, None
        if iteration >= config.limits.max_iterations:
            self._stop(machine, run, StopReason.max_iterations)
            return False, None
        machine.transition(
            AutonomyState.pivoting, PivotReason.recommendation_blocked.value
        )
        return True, PivotReason.recommendation_blocked

    @staticmethod
    def _canonical_phase2_result(
        value: Any,
        hypothesis: Hypothesis,
        authoritative_delta: RequestDelta,
    ) -> dict[str, Any]:
        safe = public_result(value)
        if not isinstance(safe, dict):
            raise ValueError("Phase 2 runtime result must be a public object")
        if safe.get("status") not in PUBLIC_RESULT_STATUSES:
            raise ValueError("Phase 2 runtime result has no canonical status")
        if safe.get("hypothesis_id") not in {None, hypothesis.hypothesis_id}:
            raise ValueError("Phase 2 result hypothesis identity changed")
        if safe.get("category") not in {None, hypothesis.category}:
            raise ValueError("Phase 2 result category identity changed")
        raw_delta = safe.get("request_delta")
        if raw_delta is None and safe.get("requests_used") == 0:
            declared_delta = RequestDelta()
        else:
            declared_delta = RequestDelta.model_validate(raw_delta)
        if declared_delta != authoritative_delta:
            raise ValueError(
                "Phase 2 result request delta does not match its request ledger"
            )
        safe["request_delta"] = authoritative_delta.model_dump(mode="json")
        safe["requests_used"] = authoritative_delta.total
        safe["hypothesis_id"] = hypothesis.hypothesis_id
        safe["category"] = hypothesis.category
        return safe

    @staticmethod
    def _result_reference(result: Mapping[str, Any]) -> str:
        material = json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return "phase2-result-" + hashlib.sha256(material.encode()).hexdigest()[:24]

    @staticmethod
    def _phase2_result_provenance(
        run_id: str,
        result: Mapping[str, Any],
        result_reference: str,
    ) -> Phase2ResultProvenance:
        exact = verification_result_reference(run_id, result)
        executor = result.get("executor")
        executor_version = (
            str(executor.get("version"))
            if isinstance(executor, Mapping)
            and isinstance(executor.get("version"), str)
            else None
        )
        return Phase2ResultProvenance(
            run_id=run_id,
            result_reference=result_reference,
            result_id=exact.get("result_id"),
            result_hash=exact.get("result_hash"),
            hypothesis_id=str(result["hypothesis_id"]),
            executor_version=exact.get("executor_version") or executor_version,
            canonical_status=str(result["status"]),
        )

    def _record_iteration(
        self,
        run: AutonomyRun,
        machine: AutonomyStateMachine,
        transition_start: int,
        *,
        decision: ReasoningDecision | None = None,
        gate: GateDecision | None = None,
        phase2_result: Phase2ResultProvenance | None = None,
        phase2_result_reference: str | None = None,
        phase2_delta: RequestDelta | None = None,
        pivot_reason: PivotReason | None = None,
        stop_reason: StopReason | None = None,
        model_usage: ModelUsageDelta | None = None,
    ) -> bool:
        previous = run.iteration_history[-1] if run.iteration_history else None
        decision_provenance = (
            decision.model_provenance if decision is not None else None
        )
        reasoning = (
            IterationReasoningProvenance(
                decision_id=decision.decision_id,
                hypothesis_id=decision.hypothesis_id,
                reasoning_schema_version=decision_provenance.reasoning_schema_version,
                requested_provider=decision_provenance.provider_requested,
                requested_model=(
                    decision_provenance.requested_model
                    or self.routing_policy.preferred.model
                ),
                actual_provider=decision_provenance.provider_used,
                actual_model=decision_provenance.model_used,
                fallback_used=decision_provenance.fallback_used,
                model_call_reference=decision_provenance.model_call_id,
                action=decision.action,
                selected_capability=decision.recommended_capability,
                evidence_reference_count=len(decision.evidence_references),
                consensus=decision_provenance.consensus,
            )
            if decision is not None and decision_provenance is not None
            else None
        )
        iteration_transitions = machine.transitions[transition_start:]
        reasoning_attempted = any(
            transition.next_state is AutonomyState.reasoning
            for transition in iteration_transitions
        )
        requested_provider = (
            reasoning.requested_provider
            if reasoning is not None
            else self.routing_policy.preferred.provider if reasoning_attempted else None
        )
        requested_model = (
            reasoning.requested_model
            if reasoning is not None
            else self.routing_policy.preferred.model if reasoning_attempted else None
        )
        record = AutonomyIterationRecord(
            iteration=run.iteration,
            transitions=iteration_transitions,
            previous_iteration_reference=(
                previous.iteration if previous is not None else None
            ),
            previous_phase2_result_reference=(
                previous.phase2_result_reference if previous is not None else None
            ),
            requested_provider=requested_provider,
            requested_model=requested_model,
            reasoning=reasoning,
            reasoning_decision_reference=(
                decision.decision_id if decision is not None else None
            ),
            selected_hypothesis_id=(
                decision.hypothesis_id if decision is not None else None
            ),
            selected_action=decision.action if decision is not None else None,
            selected_capability=(
                decision.recommended_capability if decision is not None else None
            ),
            gate_outcome=gate,
            phase2_result=phase2_result,
            phase2_result_reference=phase2_result_reference,
            model_usage=(
                model_usage
                or (
                    decision.model_provenance.usage
                    if decision is not None
                    else ModelUsageDelta()
                )
            ),
            phase2_request_delta=(
                phase2_delta if phase2_delta is not None else RequestDelta()
            ),
            pivot_reason=pivot_reason,
            stop_reason=stop_reason,
            failure_reason=run.failure_reason,
            recorded_at=run.updated_at,
        )
        recorded = True
        try:
            self.history.record(record)
        except Exception:
            recorded = False
            try:
                existing = self.history.records
                if not any(item is record for item in existing):
                    AutonomyHistory.record(self.history, record)
            except Exception:
                pass
        run.iteration_history = (*run.iteration_history, record)
        aggregate_model_usage = ModelUsageDelta()
        aggregate_request_delta = RequestDelta()
        for item in run.iteration_history:
            aggregate_model_usage = add_model_usage(
                aggregate_model_usage, item.model_usage
            )
            aggregate_request_delta = add_request_delta(
                aggregate_request_delta, item.phase2_request_delta
            )
        run.model_usage = aggregate_model_usage
        run.phase2_request_usage = aggregate_request_delta
        return recorded

    @staticmethod
    def _stop(
        machine: AutonomyStateMachine, run: AutonomyRun, reason: StopReason
    ) -> None:
        run.stop_reason = reason
        machine.transition(AutonomyState.stopped, reason.value)

    @staticmethod
    def _fail(
        machine: AutonomyStateMachine, run: AutonomyRun, reason: FailureReason
    ) -> None:
        run.failure_reason = reason
        machine.transition(AutonomyState.failed, reason.value)
