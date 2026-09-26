"""Bounded deterministic budgets for autonomous security research."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from time import monotonic

from pydantic import Field, StrictFloat, StrictInt, model_validator

from agent_core.models import ModelCallLedger, ModelUsageDelta, add_model_usage_deltas
from agent_core.request_budget import RequestBudget, RequestDelta
from agent_core.research.state import (
    BudgetState,
    HypothesisBudgetUsage,
    ModelBudgetSnapshot,
    RequestBudgetSnapshot,
    ReproductionBudgetUsage,
    ResearchState,
    SurfaceBudgetUsage,
)
from agent_core.research.chains import ChainBudgetLimits, ChainBudgetState
from agent_core.research.types import (
    CleanupStatus,
    OpaqueIdentifier,
    ResearchContract,
)


class ResearchBudgetStopReason(str, Enum):
    global_experiment_budget_exhausted = "global_experiment_budget_exhausted"
    hypothesis_experiment_budget_exhausted = "hypothesis_experiment_budget_exhausted"
    hypothesis_pivot_budget_exhausted = "hypothesis_pivot_budget_exhausted"
    request_budget_exhausted = "request_budget_exhausted"
    model_budget_exhausted = "model_budget_exhausted"
    wall_time_exhausted = "wall_time_exhausted"
    state_change_budget_exhausted = "state_change_budget_exhausted"
    cleanup_barrier = "cleanup_barrier"
    repeated_service_instability = "repeated_service_instability"
    reproduction_attempt_budget_exhausted = "reproduction_attempt_budget_exhausted"
    reproduction_request_budget_exhausted = "reproduction_request_budget_exhausted"
    reproduction_model_budget_exhausted = "reproduction_model_budget_exhausted"
    reproduction_wall_time_exhausted = "reproduction_wall_time_exhausted"
    reproduction_state_change_forbidden = "reproduction_state_change_forbidden"


class ResearchBudgetPolicy(ResearchContract):
    """Operator supplied ceilings. Model output never mutates this record."""

    initial_experiments_per_hypothesis: StrictInt = Field(default=1, ge=1, le=10)
    pivots_per_hypothesis: StrictInt = Field(default=2, ge=0, le=20)
    total_experiments_per_hypothesis: StrictInt = Field(default=3, ge=1, le=30)
    experiments_per_surface: StrictInt = Field(default=8, ge=1, le=1_000)
    equivalent_retries: StrictInt = Field(default=0, ge=0, le=3)
    consecutive_service_instability_attempts: StrictInt = Field(default=2, ge=1, le=20)
    global_experiment_ceiling: StrictInt = Field(default=50, ge=1, le=10_000)
    wall_time_ceiling_seconds: StrictFloat = Field(
        default=3_600.0, ge=1.0, le=31_536_000.0
    )
    state_change_ceiling: StrictInt = Field(default=10, ge=0, le=10_000)
    cleanup_request_reserve: StrictInt = Field(default=0, ge=0, le=10_000)
    invalid_model_output_limit: StrictInt = Field(default=3, ge=1, le=20)

    @model_validator(mode="after")
    def validate_hypothesis_limits(self) -> "ResearchBudgetPolicy":
        minimum_total = self.initial_experiments_per_hypothesis
        if self.total_experiments_per_hypothesis < minimum_total:
            raise ValueError("total hypothesis budget cannot undercut initial attempts")
        if self.pivots_per_hypothesis > self.total_experiments_per_hypothesis:
            raise ValueError("pivot budget cannot exceed total hypothesis attempts")
        return self


class ResearchBudgetDecision(ResearchContract):
    allowed: bool
    reason: ResearchBudgetStopReason | None = None
    remaining_global_experiments: StrictInt = Field(ge=0)
    remaining_hypothesis_experiments: StrictInt = Field(ge=0)
    remaining_hypothesis_pivots: StrictInt = Field(ge=0)
    remaining_surface_experiments: StrictInt = Field(ge=0)
    remaining_requests: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_reason(self) -> "ResearchBudgetDecision":
        if self.allowed == (self.reason is not None):
            raise ValueError("denied budget decisions require exactly one reason")
        return self


class ReproductionBudgetDecision(ResearchContract):
    allowed: bool
    reason: ResearchBudgetStopReason | None = None
    remaining_attempts: StrictInt = Field(ge=0)
    remaining_target_requests: StrictInt = Field(ge=0)
    remaining_model_calls: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_reason(self) -> "ReproductionBudgetDecision":
        if self.allowed == (self.reason is not None):
            raise ValueError("denied reproduction budgets require exactly one reason")
        return self


class ChainBudgetStopReason(str, Enum):
    candidate_budget_exhausted = "candidate_budget_exhausted"
    active_hypothesis_budget_exhausted = "active_hypothesis_budget_exhausted"
    experiment_budget_exhausted = "experiment_budget_exhausted"
    request_budget_exhausted = "request_budget_exhausted"
    model_budget_exhausted = "model_budget_exhausted"
    reproduction_budget_exhausted = "reproduction_budget_exhausted"
    wall_time_exhausted = "wall_time_exhausted"
    state_change_budget_exhausted = "state_change_budget_exhausted"
    cleanup_barrier = "cleanup_barrier"


class ChainBudgetDecision(ResearchContract):
    allowed: bool
    reason: ChainBudgetStopReason | None = None
    remaining_candidates: StrictInt = Field(ge=0)
    remaining_active_hypotheses: StrictInt = Field(ge=0)
    remaining_experiments: StrictInt = Field(ge=0)
    remaining_target_requests: StrictInt = Field(ge=0)
    remaining_model_calls: StrictInt = Field(ge=0)
    remaining_reproductions: StrictInt = Field(ge=0)
    remaining_state_changes: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_reason(self) -> "ChainBudgetDecision":
        if self.allowed == (self.reason is not None):
            raise ValueError("denied chain budgets require exactly one reason")
        return self


class ChainBudgetManager:
    """Chain-specific ceilings layered over the authoritative research ledgers."""

    def __init__(
        self,
        research_budget_manager: "ResearchBudgetManager",
        limits: ChainBudgetLimits | None = None,
        *,
        budget_reference: str = "chain-budget-v1",
    ) -> None:
        self.research_budget_manager = research_budget_manager
        self.limits = limits or ChainBudgetLimits()
        self.budget_reference = budget_reference

    def state(self, research: ResearchState) -> ChainBudgetState:
        matches = [
            item
            for item in research.chain_budgets
            if item.budget_reference == self.budget_reference
        ]
        if len(matches) > 1:
            raise ValueError("chain budget reference is ambiguous")
        if matches:
            return matches[0]
        authoritative = self.research_budget_manager.state(research)
        return ChainBudgetState(
            budget_reference=self.budget_reference,
            limits=self.limits,
            authoritative_request_ledger_reference=(
                authoritative.request_budget.ledger_reference
            ),
            authoritative_request_total_observed=(
                authoritative.request_budget.consumed.total
            ),
            authoritative_model_calls_observed=(
                authoritative.model_budget.usage.attempted_calls
            ),
        )

    def check(
        self,
        research: ResearchState,
        *,
        estimated_requests: int = 0,
        model_calls: int = 0,
        candidate_count: int = 0,
        activate_hypothesis: bool = False,
        experiment: bool = False,
        reproduction: bool = False,
        state_changing: bool = False,
        wall_time_seconds: float = 0.0,
    ) -> ChainBudgetDecision:
        if (
            estimated_requests < 0
            or model_calls < 0
            or candidate_count < 0
            or wall_time_seconds < 0
        ):
            raise ValueError("chain budget estimates cannot be negative")
        chain = self.state(research)
        research_budget = self.research_budget_manager.state(research)
        remaining_requests = min(
            max(
                0,
                chain.limits.maximum_chain_target_requests
                - chain.target_requests_consumed,
            ),
            research_budget.request_budget.remaining,
        )
        remaining = {
            "remaining_candidates": max(
                0,
                chain.limits.maximum_chain_candidates - chain.candidates_considered,
            ),
            "remaining_active_hypotheses": max(
                0,
                chain.limits.maximum_active_chain_hypotheses - chain.active_hypotheses,
            ),
            "remaining_experiments": max(
                0,
                chain.limits.maximum_chain_experiments - chain.experiments_consumed,
            ),
            "remaining_target_requests": remaining_requests,
            "remaining_model_calls": max(
                0,
                min(
                    chain.limits.maximum_chain_model_calls
                    - chain.model_usage.attempted_calls,
                    research_budget.model_budget.remaining_calls,
                ),
            ),
            "remaining_reproductions": max(
                0,
                chain.limits.maximum_chain_reproductions - chain.reproductions_consumed,
            ),
            "remaining_state_changes": max(
                0,
                min(
                    chain.limits.state_changing_chain_ceiling
                    - chain.state_changes_consumed,
                    research_budget.state_change_ceiling
                    - research_budget.state_changes_consumed,
                ),
            ),
        }
        reason = None
        if research_budget.cleanup_barrier_reference is not None or (
            research_budget.cleanup_status
            in {
                CleanupStatus.pending,
                CleanupStatus.failed,
                CleanupStatus.externally_required,
            }
        ):
            reason = ChainBudgetStopReason.cleanup_barrier
        elif remaining["remaining_candidates"] < candidate_count:
            reason = ChainBudgetStopReason.candidate_budget_exhausted
        elif activate_hypothesis and remaining["remaining_active_hypotheses"] <= 0:
            reason = ChainBudgetStopReason.active_hypothesis_budget_exhausted
        elif (
            chain.wall_time_consumed_seconds + wall_time_seconds
            > chain.limits.wall_time_ceiling_seconds
        ):
            reason = ChainBudgetStopReason.wall_time_exhausted
        elif experiment and (
            chain.experiments_consumed >= chain.limits.maximum_chain_experiments
        ):
            reason = ChainBudgetStopReason.experiment_budget_exhausted
        elif remaining_requests < estimated_requests:
            reason = ChainBudgetStopReason.request_budget_exhausted
        elif remaining["remaining_model_calls"] < model_calls:
            reason = ChainBudgetStopReason.model_budget_exhausted
        elif reproduction and (
            chain.reproductions_consumed >= chain.limits.maximum_chain_reproductions
        ):
            reason = ChainBudgetStopReason.reproduction_budget_exhausted
        elif state_changing and remaining["remaining_state_changes"] <= 0:
            reason = ChainBudgetStopReason.state_change_budget_exhausted
        return ChainBudgetDecision(allowed=reason is None, reason=reason, **remaining)

    def consume(
        self,
        research: ResearchState,
        *,
        request_delta: RequestDelta = RequestDelta(),
        model_usage_delta: ModelUsageDelta = ModelUsageDelta(),
        candidates_considered: int = 0,
        activate_hypothesis: bool = False,
        experiment: bool = False,
        reproduction: bool = False,
        state_changing: bool = False,
        wall_time_seconds: float = 0.0,
        completed_step_id: str | None = None,
    ) -> ChainBudgetState:
        """Account actual deltas only; RequestBudget remains authoritative."""

        current = self.state(research)
        if wall_time_seconds < 0:
            raise ValueError("chain wall time cannot be negative")
        if completed_step_id is not None and completed_step_id in (
            current.completed_step_ids
        ):
            raise ValueError("chain step was already accounted")
        authoritative = self.research_budget_manager.state(research)
        request_ledger_delta = (
            authoritative.request_budget.consumed.total
            - current.authoritative_request_total_observed
        )
        model_ledger_delta = (
            authoritative.model_budget.usage.attempted_calls
            - current.authoritative_model_calls_observed
        )
        if request_ledger_delta != request_delta.total:
            raise ValueError("chain request delta does not reconcile to the ledger")
        if model_ledger_delta != model_usage_delta.attempted_calls:
            raise ValueError("chain model delta does not reconcile to the ledger")
        decision = self.check(
            research,
            estimated_requests=request_delta.total,
            model_calls=model_usage_delta.attempted_calls,
            candidate_count=candidates_considered,
            activate_hypothesis=activate_hypothesis,
            experiment=experiment,
            reproduction=reproduction,
            state_changing=state_changing,
            wall_time_seconds=wall_time_seconds,
        )
        if not decision.allowed:
            raise ValueError(f"chain budget denied: {decision.reason.value}")
        payload = current.model_dump(mode="python")
        payload.update(
            candidates_considered=(
                current.candidates_considered + candidates_considered
            ),
            active_hypotheses=(current.active_hypotheses + int(activate_hypothesis)),
            experiments_consumed=current.experiments_consumed + int(experiment),
            target_requests_consumed=(
                current.target_requests_consumed + request_delta.total
            ),
            model_usage=add_model_usage_deltas(current.model_usage, model_usage_delta),
            reproductions_consumed=(current.reproductions_consumed + int(reproduction)),
            wall_time_consumed_seconds=(
                current.wall_time_consumed_seconds + wall_time_seconds
            ),
            state_changes_consumed=(
                current.state_changes_consumed + int(state_changing)
            ),
            completed_step_ids=(
                (*current.completed_step_ids, completed_step_id)
                if completed_step_id is not None
                else current.completed_step_ids
            ),
            authoritative_request_total_observed=(
                authoritative.request_budget.consumed.total
            ),
            authoritative_model_calls_observed=(
                authoritative.model_budget.usage.attempted_calls
            ),
        )
        return ChainBudgetState.model_validate(payload)


class ResearchBudgetManager:
    """Coordinate research ceilings with existing request and model ledgers."""

    def __init__(
        self,
        policy: ResearchBudgetPolicy | None = None,
        *,
        request_budget: RequestBudget | None = None,
        model_ledger: ModelCallLedger | None = None,
        model_call_ceiling: int = 50,
        budget_reference: str = "research-budget-v1",
        request_ledger_reference: str = "request-budget-v1",
        model_ledger_reference: str = "model-call-ledger-v1",
    ) -> None:
        if not 1 <= model_call_ceiling <= 1_000_000:
            raise ValueError("model call ceiling is outside the supported bound")
        self.policy = policy or ResearchBudgetPolicy()
        self.request_budget = request_budget
        self.model_ledger = model_ledger
        self.model_call_ceiling = model_call_ceiling
        self.budget_reference: OpaqueIdentifier = budget_reference
        self.request_ledger_reference: OpaqueIdentifier = request_ledger_reference
        self.model_ledger_reference: OpaqueIdentifier = model_ledger_reference
        self._started = monotonic()

    def state(self, research: ResearchState) -> BudgetState:
        matches = [
            item
            for item in research.budgets
            if item.budget_reference == self.budget_reference
        ]
        if len(matches) > 1:
            raise ValueError("research budget reference is ambiguous")
        if matches:
            return self._synchronize(matches[0], research.research_id)
        return self._new_state(research.research_id)

    def check(
        self,
        research: ResearchState,
        *,
        hypothesis_id: str,
        surface_id: str | None,
        estimated_requests: int = 0,
        pivot: bool = False,
        state_changing: bool = False,
    ) -> ResearchBudgetDecision:
        if estimated_requests < 0:
            raise ValueError("estimated request cost cannot be negative")
        budget = self.state(research)
        hypothesis = next(
            (
                item
                for item in budget.hypothesis_usage
                if item.hypothesis_id == hypothesis_id
            ),
            HypothesisBudgetUsage(
                hypothesis_id=hypothesis_id, attempt_count=0, pivot_count=0
            ),
        )
        surface_count = next(
            (
                item.experiment_count
                for item in budget.surface_usage
                if item.surface_id == surface_id
            ),
            0,
        )
        values = {
            "remaining_global_experiments": max(
                0, self.policy.global_experiment_ceiling - budget.experiments_consumed
            ),
            "remaining_hypothesis_experiments": max(
                0,
                self.policy.total_experiments_per_hypothesis - hypothesis.attempt_count,
            ),
            "remaining_hypothesis_pivots": max(
                0, self.policy.pivots_per_hypothesis - hypothesis.pivot_count
            ),
            "remaining_surface_experiments": max(
                0, self.policy.experiments_per_surface - surface_count
            ),
            "remaining_requests": budget.request_budget.remaining,
        }
        reason = None
        if (
            budget.cleanup_status
            in {
                CleanupStatus.pending,
                CleanupStatus.failed,
                CleanupStatus.externally_required,
            }
            or budget.cleanup_barrier_reference is not None
        ):
            reason = ResearchBudgetStopReason.cleanup_barrier
        elif budget.wall_time_consumed_seconds >= self.policy.wall_time_ceiling_seconds:
            reason = ResearchBudgetStopReason.wall_time_exhausted
        elif budget.experiments_consumed >= self.policy.global_experiment_ceiling:
            reason = ResearchBudgetStopReason.global_experiment_budget_exhausted
        elif hypothesis.attempt_count >= self.policy.total_experiments_per_hypothesis:
            reason = ResearchBudgetStopReason.hypothesis_experiment_budget_exhausted
        elif pivot and hypothesis.pivot_count >= self.policy.pivots_per_hypothesis:
            reason = ResearchBudgetStopReason.hypothesis_pivot_budget_exhausted
        elif state_changing and (
            budget.state_changes_consumed >= self.policy.state_change_ceiling
        ):
            reason = ResearchBudgetStopReason.state_change_budget_exhausted
        elif budget.request_budget.remaining < (
            estimated_requests + self.policy.cleanup_request_reserve
        ):
            reason = ResearchBudgetStopReason.request_budget_exhausted
        elif budget.model_budget.remaining_calls <= 0:
            reason = ResearchBudgetStopReason.model_budget_exhausted
        elif (
            budget.consecutive_service_instability
            >= self.policy.consecutive_service_instability_attempts
        ):
            reason = ResearchBudgetStopReason.repeated_service_instability
        return ResearchBudgetDecision(allowed=reason is None, reason=reason, **values)

    def consume_experiment(
        self,
        research: ResearchState,
        *,
        hypothesis_id: str,
        surface_id: str | None,
        pivot: bool,
        state_changing: bool,
        service_instability: bool = False,
        cleanup_status: CleanupStatus = CleanupStatus.not_required,
        cleanup_barrier_reference: str | None = None,
    ) -> BudgetState:
        """Return a consumed snapshot. Consumed work is never refunded."""

        current = self.state(research)
        hypothesis_usage = {
            item.hypothesis_id: item for item in current.hypothesis_usage
        }
        prior_hypothesis = hypothesis_usage.get(
            hypothesis_id,
            HypothesisBudgetUsage(
                hypothesis_id=hypothesis_id, attempt_count=0, pivot_count=0
            ),
        )
        hypothesis_usage[hypothesis_id] = HypothesisBudgetUsage(
            hypothesis_id=hypothesis_id,
            attempt_count=prior_hypothesis.attempt_count + 1,
            pivot_count=prior_hypothesis.pivot_count + int(pivot),
        )
        surface_usage = {item.surface_id: item for item in current.surface_usage}
        if surface_id is not None:
            prior_surface = surface_usage.get(
                surface_id,
                SurfaceBudgetUsage(surface_id=surface_id, experiment_count=0),
            )
            surface_usage[surface_id] = SurfaceBudgetUsage(
                surface_id=surface_id,
                experiment_count=prior_surface.experiment_count + 1,
            )
        payload = current.model_dump(mode="python")
        payload.update(
            experiment_ceiling=self.policy.global_experiment_ceiling,
            experiments_consumed=current.experiments_consumed + 1,
            hypothesis_usage=tuple(hypothesis_usage.values()),
            surface_usage=tuple(surface_usage.values()),
            wall_time_ceiling_seconds=self.policy.wall_time_ceiling_seconds,
            wall_time_consumed_seconds=min(
                self.policy.wall_time_ceiling_seconds,
                current.wall_time_consumed_seconds,
            ),
            state_change_ceiling=self.policy.state_change_ceiling,
            state_changes_consumed=current.state_changes_consumed + int(state_changing),
            cleanup_request_reserve=self.policy.cleanup_request_reserve,
            cleanup_status=cleanup_status,
            cleanup_barrier_reference=cleanup_barrier_reference,
            consecutive_service_instability=(
                current.consecutive_service_instability + 1
                if service_instability
                else 0
            ),
        )
        self._started = monotonic()
        return self._synchronize(
            BudgetState.model_validate(payload), research.research_id
        )

    def check_reproduction(
        self,
        research: ResearchState,
        *,
        finding_id: str,
        confirmation_policy: object,
        estimated_requests: int,
        state_changing: bool = False,
        model_calls: int = 0,
    ) -> ReproductionBudgetDecision:
        """Check the independent reproduction ledger without consuming it."""

        if estimated_requests < 0 or model_calls < 0:
            raise ValueError("reproduction estimates cannot be negative")
        budget = self.state(research)
        usage = next(
            (
                item
                for item in budget.reproduction_usage
                if item.finding_id == finding_id
            ),
            ReproductionBudgetUsage(finding_id=finding_id),
        )
        attempt_ceiling = int(getattr(confirmation_policy, "maximum_attempts"))
        request_ceiling = int(getattr(confirmation_policy, "maximum_requests"))
        model_ceiling = int(getattr(confirmation_policy, "maximum_model_calls"))
        wall_ceiling = float(getattr(confirmation_policy, "maximum_wall_time_seconds"))
        state_change_allowed = bool(
            getattr(confirmation_policy, "state_changing_confirmation_permitted")
        )
        remaining_attempts = max(0, attempt_ceiling - usage.attempts_consumed)
        remaining_requests = max(0, request_ceiling - usage.target_requests_consumed)
        remaining_model_calls = max(0, model_ceiling - usage.model_calls_consumed)
        reason = None
        if usage.attempts_consumed >= attempt_ceiling:
            reason = ResearchBudgetStopReason.reproduction_attempt_budget_exhausted
        elif estimated_requests > remaining_requests:
            reason = ResearchBudgetStopReason.reproduction_request_budget_exhausted
        elif estimated_requests > budget.request_budget.remaining:
            reason = ResearchBudgetStopReason.request_budget_exhausted
        elif model_calls > remaining_model_calls:
            reason = ResearchBudgetStopReason.reproduction_model_budget_exhausted
        elif usage.wall_time_consumed_seconds >= wall_ceiling:
            reason = ResearchBudgetStopReason.reproduction_wall_time_exhausted
        elif state_changing and not state_change_allowed:
            reason = ResearchBudgetStopReason.reproduction_state_change_forbidden
        elif (
            budget.cleanup_status
            in {
                CleanupStatus.pending,
                CleanupStatus.failed,
                CleanupStatus.externally_required,
            }
            or budget.cleanup_barrier_reference is not None
        ):
            reason = ResearchBudgetStopReason.cleanup_barrier
        return ReproductionBudgetDecision(
            allowed=reason is None,
            reason=reason,
            remaining_attempts=remaining_attempts,
            remaining_target_requests=remaining_requests,
            remaining_model_calls=remaining_model_calls,
        )

    def consume_reproduction_attempt(
        self,
        research: ResearchState,
        *,
        finding_id: str,
        model_calls: int = 0,
        state_changing: bool = False,
    ) -> BudgetState:
        """Consume an attempt at plan persistence; attempts are never refunded."""

        current = self.state(research)
        usage = {item.finding_id: item for item in current.reproduction_usage}
        prior = usage.get(finding_id, ReproductionBudgetUsage(finding_id=finding_id))
        usage[finding_id] = prior.model_copy(
            update={
                "attempts_consumed": prior.attempts_consumed + 1,
                "model_calls_consumed": prior.model_calls_consumed + model_calls,
                "state_changes_consumed": prior.state_changes_consumed
                + int(state_changing),
            }
        )
        payload = current.model_dump(mode="python")
        payload["reproduction_usage"] = tuple(usage.values())
        return self._synchronize(
            BudgetState.model_validate(payload), research.research_id
        )

    def consume_reproduction_result(
        self,
        research: ResearchState,
        *,
        finding_id: str,
        request_delta: RequestDelta,
        wall_time_seconds: float = 0.0,
    ) -> BudgetState:
        """Record authoritative reproduction traffic without refund semantics."""

        current = self.state(research)
        usage = {item.finding_id: item for item in current.reproduction_usage}
        prior = usage.get(finding_id, ReproductionBudgetUsage(finding_id=finding_id))
        usage[finding_id] = prior.model_copy(
            update={
                "target_requests_consumed": prior.target_requests_consumed
                + request_delta.total,
                "cleanup_requests_consumed": prior.cleanup_requests_consumed
                + request_delta.cleanup,
                "wall_time_consumed_seconds": prior.wall_time_consumed_seconds
                + max(0.0, wall_time_seconds),
            }
        )
        payload = current.model_dump(mode="python")
        payload["reproduction_usage"] = tuple(usage.values())
        return self._synchronize(
            BudgetState.model_validate(payload), research.research_id
        )

    def _new_state(self, research_id: str) -> BudgetState:
        request = self._request_snapshot()
        model = self._model_snapshot(research_id)
        return BudgetState(
            budget_reference=self.budget_reference,
            experiment_ceiling=self.policy.global_experiment_ceiling,
            experiments_consumed=0,
            request_budget=request,
            model_budget=model,
            wall_time_ceiling_seconds=self.policy.wall_time_ceiling_seconds,
            wall_time_consumed_seconds=0.0,
            state_change_ceiling=self.policy.state_change_ceiling,
            state_changes_consumed=0,
            cleanup_request_reserve=self.policy.cleanup_request_reserve,
            cleanup_status=CleanupStatus.not_required,
        )

    def _synchronize(self, value: BudgetState, research_id: str) -> BudgetState:
        payload = value.model_dump(mode="python")
        payload.update(
            request_budget=self._request_snapshot(value.request_budget),
            model_budget=self._model_snapshot(research_id, value.model_budget),
            wall_time_consumed_seconds=min(
                self.policy.wall_time_ceiling_seconds,
                value.wall_time_consumed_seconds
                + max(0.0, monotonic() - self._started),
            ),
        )
        return BudgetState.model_validate(payload)

    def _request_snapshot(
        self, previous: RequestBudgetSnapshot | None = None
    ) -> RequestBudgetSnapshot:
        if self.request_budget is None:
            if previous is not None:
                return previous
            limit = 10_000_000
            return RequestBudgetSnapshot(
                ledger_reference=self.request_ledger_reference,
                limit=limit,
                remaining=limit,
            )
        raw = self.request_budget.snapshot()
        categorized = {
            "discovery": raw["discovery_requests"],
            "auth": raw["auth_requests"],
            "verification": raw["verification_requests"],
            "cleanup": raw["cleanup_requests"],
        }
        total = sum(categorized.values())
        consumed = RequestDelta(**categorized, attempted=total, total=total)
        live = RequestBudgetSnapshot(
            ledger_reference=self.request_ledger_reference,
            limit=self.request_budget.limit,
            consumed=consumed,
            remaining=self.request_budget.remaining,
        )
        if previous is not None and (
            live.limit != previous.limit
            or live.consumed.total < previous.consumed.total
        ):
            return previous
        return live

    def _model_snapshot(
        self, research_id: str, previous: ModelBudgetSnapshot | None = None
    ) -> ModelBudgetSnapshot:
        if self.model_ledger is None:
            if previous is not None:
                return previous
            usage = ModelUsageDelta()
        else:
            usage = self.model_ledger.usage_for_run(research_id)
        if (
            previous is not None
            and usage.attempted_calls < previous.usage.attempted_calls
        ):
            return previous
        consumed = min(self.model_call_ceiling, usage.attempted_calls)
        return ModelBudgetSnapshot(
            ledger_reference=self.model_ledger_reference,
            max_calls=self.model_call_ceiling,
            usage=usage,
            remaining_calls=self.model_call_ceiling - consumed,
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "ChainBudgetDecision",
    "ChainBudgetManager",
    "ChainBudgetStopReason",
    "ReproductionBudgetDecision",
    "ResearchBudgetDecision",
    "ResearchBudgetManager",
    "ResearchBudgetPolicy",
    "ResearchBudgetStopReason",
]
