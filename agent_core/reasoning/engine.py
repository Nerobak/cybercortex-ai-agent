"""Common advisory reasoning engine over the deterministic P3 model router."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_core.models import (
    ModelBudgetLimits,
    ModelErrorCode,
    ModelProviderError,
    ModelRoute,
    ModelRouter,
    ModelRoutingPolicy,
    ModelResponse,
    RoutingMode,
)
from agent_core.reasoning.errors import ReasoningError, ReasoningErrorCode
from agent_core.reasoning.parser import (
    parse_reasoning_candidate,
    parse_reasoning_candidates,
)
from agent_core.reasoning.prompt_builder import build_reasoning_model_request
from agent_core.reasoning.types import (
    ConfidenceLevel,
    InformationGain,
    ReasoningDecision,
    ReasoningHistoryEntry,
    ReasoningModelProvenance,
    ReasoningRequest,
    ReasoningTaskType,
)
from agent_core.reasoning.validation import (
    validate_reasoning_candidate,
    validate_reasoning_request,
)

_CONFIDENCE_ORDER = {
    ConfidenceLevel.low: 0,
    ConfidenceLevel.medium: 1,
    ConfidenceLevel.high: 2,
}
_INFORMATION_ORDER = {
    InformationGain.low: 0,
    InformationGain.medium: 1,
    InformationGain.high: 2,
}


class ReasoningHistory:
    """Process-local structured history without raw prompts or chain-of-thought."""

    def __init__(self) -> None:
        self._entries: list[ReasoningHistoryEntry] = []

    def record(self, decision: ReasoningDecision) -> ReasoningHistoryEntry:
        entry = ReasoningHistoryEntry(
            decision_id=decision.decision_id,
            hypothesis_id=decision.hypothesis_id,
            action=decision.action,
            recommended_capability=decision.recommended_capability,
            priority=decision.priority,
            confidence=decision.confidence,
            concise_rationale=decision.rationale,
            evidence_references=decision.evidence_references,
            missing_evidence=decision.missing_evidence,
            model_provenance=decision.model_provenance,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> tuple[ReasoningHistoryEntry, ...]:
        return tuple(self._entries)


class ReasoningEngine:
    """Parse and validate model advice; never submit it for execution."""

    def __init__(
        self,
        router: ModelRouter,
        *,
        history: ReasoningHistory | None = None,
        max_output_tokens: int = 4096,
    ) -> None:
        if max_output_tokens < 1:
            raise ValueError("Reasoning max_output_tokens must be positive")
        self.router = router
        self.history = history or ReasoningHistory()
        self.max_output_tokens = max_output_tokens

    def reason(
        self,
        request: ReasoningRequest,
        routing_policy: ModelRoutingPolicy,
    ) -> ReasoningDecision:
        if request.task_type is ReasoningTaskType.hypothesis_ranking:
            raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)
        response, provenance = self._invoke(request, routing_policy)
        candidate = parse_reasoning_candidate(response.content)
        decision = validate_reasoning_candidate(candidate, request, provenance)
        self.history.record(decision)
        return decision

    def rank(
        self,
        request: ReasoningRequest,
        routing_policy: ModelRoutingPolicy,
    ) -> tuple[ReasoningDecision, ...]:
        if request.task_type is not ReasoningTaskType.hypothesis_ranking:
            raise ReasoningError(ReasoningErrorCode.evidence_validation_failed)
        response, provenance = self._invoke(request, routing_policy)
        candidates = parse_reasoning_candidates(response.content)
        expected_ids = {packet.hypothesis_id for packet in request.evidence_packets}
        candidate_ids = [candidate.hypothesis_id for candidate in candidates]
        decision_ids = [candidate.decision_id for candidate in candidates]
        if (
            len(candidate_ids) != len(set(candidate_ids))
            or set(candidate_ids) != expected_ids
            or len(decision_ids) != len(set(decision_ids))
        ):
            raise ReasoningError(ReasoningErrorCode.unsupported_recommendation)
        decisions = tuple(
            validate_reasoning_candidate(candidate, request, provenance)
            for candidate in candidates
        )
        ordered = tuple(sorted(decisions, key=self._ranking_key))
        for decision in ordered:
            self.history.record(decision)
        return ordered

    def _invoke(
        self,
        request: ReasoningRequest,
        routing_policy: ModelRoutingPolicy,
    ):
        validate_reasoning_request(request)
        model_request = build_reasoning_model_request(
            request, max_output_tokens=self.max_output_tokens
        )
        before = self.router.ledger.snapshot(run_id=request.run_id)
        try:
            response = self.router.route(model_request, routing_policy)
        except ModelProviderError as exc:
            code = (
                ReasoningErrorCode.model_budget_exhausted
                if exc.code
                in {
                    ModelErrorCode.model_budget_exceeded,
                    ModelErrorCode.unknown_cost,
                }
                else ReasoningErrorCode.model_unavailable
            )
            raise ReasoningError(code) from None
        if not isinstance(response, ModelResponse):
            raise ReasoningError(ReasoningErrorCode.invalid_model_output)
        after = self.router.ledger.snapshot(run_id=request.run_id)
        usage = self.router.ledger.delta(before, after)
        provenance = ReasoningModelProvenance(
            provider_requested=(
                response.requested_provider or routing_policy.preferred.provider
            ),
            requested_model=(
                response.requested_model or routing_policy.preferred.model
            ),
            provider_used=response.provider,
            model_used=response.model,
            fallback_used=response.fallback_used,
            model_call_id=response.provider_call_id,
            task_type=request.task_type,
            usage=usage,
        )
        return response, provenance

    @staticmethod
    def _ranking_key(decision: ReasoningDecision) -> tuple[int, int, int, int, str]:
        return (
            -decision.priority,
            -_CONFIDENCE_ORDER[decision.confidence],
            -_INFORMATION_ORDER[decision.expected_information_gain],
            decision.estimated_request_cost,
            decision.hypothesis_id,
        )


class RoutedReasoningAgent:
    """Thin provider-policy facade over the single common reasoning engine."""

    def __init__(
        self, engine: ReasoningEngine, routing_policy: ModelRoutingPolicy
    ) -> None:
        self.engine = engine
        self.routing_policy = routing_policy

    def reason(self, request: ReasoningRequest) -> ReasoningDecision:
        return self.engine.reason(request, self.routing_policy)

    def rank(self, request: ReasoningRequest) -> tuple[ReasoningDecision, ...]:
        return self.engine.rank(request, self.routing_policy)


class GPTReasoningAgent(RoutedReasoningAgent):
    def __init__(
        self,
        engine: ReasoningEngine,
        *,
        model: str,
        budget: ModelBudgetLimits | None = None,
    ) -> None:
        super().__init__(
            engine,
            ModelRoutingPolicy(
                mode=RoutingMode.preferred,
                preferred=ModelRoute(provider="openai", model=model),
                allowed_cloud_providers=("openai",),
                budget=budget or ModelBudgetLimits(),
            ),
        )


class ClaudeReasoningAgent(RoutedReasoningAgent):
    def __init__(
        self,
        engine: ReasoningEngine,
        *,
        model: str,
        budget: ModelBudgetLimits | None = None,
    ) -> None:
        super().__init__(
            engine,
            ModelRoutingPolicy(
                mode=RoutingMode.preferred,
                preferred=ModelRoute(provider="anthropic", model=model),
                allowed_cloud_providers=("anthropic",),
                budget=budget or ModelBudgetLimits(),
            ),
        )


class DeepSeekReasoningAgent(RoutedReasoningAgent):
    def __init__(
        self,
        engine: ReasoningEngine,
        *,
        model: str,
        budget: ModelBudgetLimits | None = None,
    ) -> None:
        super().__init__(
            engine,
            ModelRoutingPolicy(
                mode=RoutingMode.local_only,
                preferred=ModelRoute(provider="ollama", model=model),
                budget=budget or ModelBudgetLimits(),
            ),
        )
