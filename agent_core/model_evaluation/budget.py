"""Authoritative pre-invocation budgets for Phase 3 evaluation runs."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from agent_core.autonomy import AutonomyLimits
from agent_core.consensus import ConsensusBudget
from agent_core.model_evaluation.errors import EvaluationError, EvaluationFailureCode
from agent_core.model_evaluation.types import EvaluationCase, EvaluationSubject
from agent_core.models import (
    ModelBudgetLimits,
    ModelPricingCatalog,
    ModelRouter,
    ModelRoutingPolicy,
    ModelUsageDelta,
    add_model_usage_deltas,
)
from agent_core.reasoning import build_reasoning_model_request


def _minimum_optional(*values: int | float | None) -> int | float | None:
    known = tuple(value for value in values if value is not None)
    return min(known) if known else None


def _strictest_unknown_cost_policy(*values: str) -> str:
    return "deny" if "deny" in values else "allow"


def _model_unknown_cost_policy(
    left: ModelBudgetLimits,
    right: ModelBudgetLimits,
) -> str:
    applicable = tuple(
        budget.unknown_cost_policy
        for budget in (left, right)
        if budget.has_monetary_ceiling
    )
    return _strictest_unknown_cost_policy(*(applicable or ("deny",)))


def _intersect_model_limits(
    left: ModelBudgetLimits,
    right: ModelBudgetLimits,
) -> ModelBudgetLimits:
    """Return the strict intersection of two hard model budgets."""

    return ModelBudgetLimits(
        max_model_calls=min(left.max_model_calls, right.max_model_calls),
        max_input_tokens=_minimum_optional(
            left.max_input_tokens, right.max_input_tokens
        ),
        max_output_tokens=_minimum_optional(
            left.max_output_tokens, right.max_output_tokens
        ),
        max_total_tokens=_minimum_optional(
            left.max_total_tokens, right.max_total_tokens
        ),
        max_estimated_cost_usd=_minimum_optional(
            left.max_estimated_cost_usd, right.max_estimated_cost_usd
        ),
        max_per_call_cost_usd=_minimum_optional(
            left.max_per_call_cost_usd, right.max_per_call_cost_usd
        ),
        unknown_cost_policy=_model_unknown_cost_policy(left, right),
    )


def _intersect_consensus_limits(
    configured: ConsensusBudget,
    evaluation: ModelBudgetLimits,
) -> ConsensusBudget:
    return ConsensusBudget(
        max_model_calls=min(configured.max_model_calls, evaluation.max_model_calls),
        max_input_tokens=_minimum_optional(
            configured.max_input_tokens, evaluation.max_input_tokens
        ),
        max_output_tokens=_minimum_optional(
            configured.max_output_tokens, evaluation.max_output_tokens
        ),
        max_total_tokens=_minimum_optional(
            configured.max_total_tokens, evaluation.max_total_tokens
        ),
        max_estimated_cost_usd=_minimum_optional(
            configured.max_estimated_cost_usd,
            evaluation.max_estimated_cost_usd,
        ),
        unknown_cost_policy=_strictest_unknown_cost_policy(
            *(
                (
                    (configured.unknown_cost_policy,)
                    if configured.max_estimated_cost_usd is not None
                    else ()
                )
                + (
                    (evaluation.unknown_cost_policy,)
                    if evaluation.has_monetary_ceiling
                    else ()
                )
                or ("deny",)
            )
        ),
    )


def _consensus_model_limits(budget: ConsensusBudget) -> ModelBudgetLimits:
    return ModelBudgetLimits(
        max_model_calls=budget.max_model_calls,
        max_input_tokens=budget.max_input_tokens,
        max_output_tokens=budget.max_output_tokens,
        max_total_tokens=budget.max_total_tokens,
        max_estimated_cost_usd=budget.max_estimated_cost_usd,
        unknown_cost_policy=budget.unknown_cost_policy,
    )


def _intersect_autonomy_limits(
    left: AutonomyLimits,
    right: AutonomyLimits,
) -> AutonomyLimits:
    return AutonomyLimits(
        max_iterations=min(left.max_iterations, right.max_iterations),
        max_verifications=min(left.max_verifications, right.max_verifications),
        max_reasoning_failures=min(
            left.max_reasoning_failures, right.max_reasoning_failures
        ),
        max_duplicate_recommendations=min(
            left.max_duplicate_recommendations,
            right.max_duplicate_recommendations,
        ),
        max_policy_blocks=min(left.max_policy_blocks, right.max_policy_blocks),
    )


def _add_usage(left: ModelUsageDelta, right: ModelUsageDelta) -> ModelUsageDelta:
    return add_model_usage_deltas(left, right)


@dataclass(frozen=True)
class EvaluationBudgetGrant:
    """One immutable, remaining-budget view supplied to an evaluator."""

    subject: EvaluationSubject
    case: EvaluationCase
    run_id: str
    limits: ModelBudgetLimits
    usage_before: ModelUsageDelta


class EvaluationBudgetPreflight:
    """Single authority for evaluation-run reservations and reconciliation."""

    def __init__(
        self,
        cases: tuple[EvaluationCase, ...],
        *,
        pricing: ModelPricingCatalog | None = None,
        max_output_tokens: int = 4096,
    ) -> None:
        if not cases:
            raise ValueError("Evaluation budget preflight requires cases")
        if max_output_tokens < 1:
            raise ValueError("Evaluation output reservation must be positive")
        self._pricing = pricing or ModelPricingCatalog()
        self._max_output_tokens = max_output_tokens
        self._limits: dict[str, ModelBudgetLimits] = {}
        self._usage: dict[str, ModelUsageDelta] = {}
        self._lock = RLock()
        for case in cases:
            run_id = case.reasoning_request.run_id
            configured = self._limits.get(run_id)
            self._limits[run_id] = (
                case.model_budget
                if configured is None
                else _intersect_model_limits(configured, case.model_budget)
            )

    def input_token_reservation(self, case: EvaluationCase) -> int:
        """Return the router-equivalent deterministic input reservation."""

        request = build_reasoning_model_request(
            case.reasoning_request,
            max_output_tokens=self._max_output_tokens,
        )
        return ModelRouter._conservative_input_token_estimate(request)

    def preflight(
        self,
        subject: EvaluationSubject,
        case: EvaluationCase,
    ) -> EvaluationBudgetGrant:
        """Reject or bind one evaluator invocation before it can begin."""

        with self._lock:
            run_id = case.reasoning_request.run_id
            limits = self._limits[run_id]
            usage = self._usage.get(run_id, ModelUsageDelta())
            remaining = self._remaining_limits(limits, usage)
            input_tokens = self.input_token_reservation(case)
            self._require_token_reservation(remaining, input_tokens)
            bound_subject = self._bind_subject(subject, case, remaining)
            self._require_policy_reservations(
                bound_subject,
                input_tokens=input_tokens,
            )
            bound_case = EvaluationCase.model_validate(
                {
                    **case.model_dump(mode="python"),
                    "model_budget": remaining,
                    "autonomy_budget": self._bound_case_autonomy(subject, case),
                }
            )
            return EvaluationBudgetGrant(
                subject=bound_subject,
                case=bound_case,
                run_id=run_id,
                limits=limits,
                usage_before=usage,
            )

    def reconcile(
        self,
        grant: EvaluationBudgetGrant,
        usage: ModelUsageDelta,
    ) -> bool:
        """Consume truthful usage and report whether it stayed within the grant."""

        with self._lock:
            current = self._usage.get(grant.run_id, ModelUsageDelta())
            if current != grant.usage_before:
                raise EvaluationError(EvaluationFailureCode.budget_exhausted)
            total = _add_usage(current, usage)
            self._usage[grant.run_id] = total
            return self._within_limits(total, grant.limits)

    @staticmethod
    def _remaining_limits(
        limits: ModelBudgetLimits,
        usage: ModelUsageDelta,
    ) -> ModelBudgetLimits:
        if usage.attempted_calls >= limits.max_model_calls:
            raise EvaluationError(EvaluationFailureCode.budget_exhausted)

        def remaining(limit: int | None, used: int) -> int | None:
            if limit is None:
                return None
            value = limit - used
            if value < 1:
                raise EvaluationError(EvaluationFailureCode.budget_exhausted)
            return value

        cost_remaining = limits.max_estimated_cost_usd
        if cost_remaining is not None:
            if usage.attempted_calls and usage.budget_estimated_cost_usd is None:
                if limits.unknown_cost_policy == "deny":
                    raise EvaluationError(EvaluationFailureCode.budget_exhausted)
            elif usage.budget_estimated_cost_usd is not None:
                cost_remaining = max(
                    0.0,
                    cost_remaining - usage.budget_estimated_cost_usd,
                )

        return ModelBudgetLimits(
            max_model_calls=limits.max_model_calls - usage.attempted_calls,
            max_input_tokens=remaining(
                limits.max_input_tokens,
                usage.budget_input_tokens,
            ),
            max_output_tokens=remaining(
                limits.max_output_tokens,
                usage.budget_output_tokens,
            ),
            max_total_tokens=remaining(
                limits.max_total_tokens,
                usage.budget_total_tokens,
            ),
            max_estimated_cost_usd=cost_remaining,
            max_per_call_cost_usd=limits.max_per_call_cost_usd,
            unknown_cost_policy=limits.unknown_cost_policy,
        )

    @staticmethod
    def _require_token_reservation(
        limits: ModelBudgetLimits,
        input_tokens: int,
    ) -> None:
        if (
            limits.max_input_tokens is not None
            and input_tokens > limits.max_input_tokens
        ):
            raise EvaluationError(EvaluationFailureCode.budget_exhausted)
        if limits.max_output_tokens is not None and limits.max_output_tokens < 1:
            raise EvaluationError(EvaluationFailureCode.budget_exhausted)
        if (
            limits.max_total_tokens is not None
            and input_tokens + 1 > limits.max_total_tokens
        ):
            raise EvaluationError(EvaluationFailureCode.budget_exhausted)

    def _bind_subject(
        self,
        subject: EvaluationSubject,
        case: EvaluationCase,
        remaining: ModelBudgetLimits,
    ) -> EvaluationSubject:
        consensus_budget = (
            _intersect_consensus_limits(subject.consensus_budget, remaining)
            if subject.consensus_budget is not None
            else None
        )
        policy_limits = (
            _intersect_model_limits(
                remaining, _consensus_model_limits(consensus_budget)
            )
            if consensus_budget is not None
            else remaining
        )
        policies = tuple(
            self._bind_policy(policy, policy_limits)
            for policy in subject.routing_policies
        )
        autonomy_limits = (
            _intersect_autonomy_limits(subject.autonomy_limits, case.autonomy_budget)
            if subject.autonomy_limits is not None and case.autonomy_budget is not None
            else subject.autonomy_limits
        )
        return EvaluationSubject.model_validate(
            {
                **subject.model_dump(mode="python"),
                "routing_policies": policies,
                "consensus_budget": consensus_budget,
                "autonomy_limits": autonomy_limits,
            }
        )

    @staticmethod
    def _bind_policy(
        policy: ModelRoutingPolicy,
        remaining: ModelBudgetLimits,
    ) -> ModelRoutingPolicy:
        budget = _intersect_model_limits(policy.budget, remaining)
        return ModelRoutingPolicy.model_validate(
            {
                **policy.model_dump(mode="python"),
                "max_provider_attempts": min(
                    policy.max_provider_attempts, budget.max_model_calls
                ),
                "budget": budget,
            }
        )

    def _bound_case_autonomy(
        self,
        subject: EvaluationSubject,
        case: EvaluationCase,
    ) -> AutonomyLimits | None:
        if case.autonomy_budget is None or subject.autonomy_limits is None:
            return case.autonomy_budget
        return _intersect_autonomy_limits(case.autonomy_budget, subject.autonomy_limits)

    def _require_policy_reservations(
        self,
        subject: EvaluationSubject,
        *,
        input_tokens: int,
    ) -> None:
        for policy in subject.routing_policies:
            budget = policy.budget
            self._require_token_reservation(budget, input_tokens)
            output_tokens = self._max_output_tokens
            if budget.max_output_tokens is not None:
                output_tokens = min(output_tokens, budget.max_output_tokens)
            if budget.max_total_tokens is not None:
                output_tokens = min(
                    output_tokens,
                    budget.max_total_tokens - input_tokens,
                )
            if output_tokens < 1:
                raise EvaluationError(EvaluationFailureCode.budget_exhausted)
            if not budget.has_monetary_ceiling:
                continue
            route = policy.ordered_routes()[0]
            predicted = self._pricing.estimate_cost(
                route.provider,
                route.model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            if predicted is None:
                if budget.unknown_cost_policy == "deny":
                    raise EvaluationError(EvaluationFailureCode.budget_exhausted)
                continue
            if (
                budget.max_per_call_cost_usd is not None
                and predicted > budget.max_per_call_cost_usd
            ):
                raise EvaluationError(EvaluationFailureCode.budget_exhausted)
            if (
                budget.max_estimated_cost_usd is not None
                and predicted > budget.max_estimated_cost_usd
            ):
                raise EvaluationError(EvaluationFailureCode.budget_exhausted)

    @staticmethod
    def _within_limits(
        usage: ModelUsageDelta,
        limits: ModelBudgetLimits,
    ) -> bool:
        if usage.attempted_calls > limits.max_model_calls:
            return False
        if any(
            ceiling is not None and actual > ceiling
            for actual, ceiling in (
                (usage.budget_input_tokens, limits.max_input_tokens),
                (usage.budget_output_tokens, limits.max_output_tokens),
                (usage.budget_total_tokens, limits.max_total_tokens),
            )
        ):
            return False
        if limits.max_estimated_cost_usd is not None:
            if usage.attempted_calls and usage.budget_estimated_cost_usd is None:
                return limits.unknown_cost_policy == "allow"
            if (
                usage.budget_estimated_cost_usd is not None
                and usage.budget_estimated_cost_usd > limits.max_estimated_cost_usd
            ):
                return False
        return True
