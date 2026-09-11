"""Sequential, bounded collection of independent P3-3 model decisions."""

from __future__ import annotations

import json
from typing import Any

from agent_core.consensus.agreement import classify_agreement
from agent_core.consensus.arbitration import (
    aggregate_model_usage,
    arbitrate_consensus,
)
from agent_core.consensus.history import ConsensusHistory
from agent_core.consensus.types import (
    ConsensusParticipant,
    ConsensusRequest,
    ConsensusResult,
    ParticipantFailure,
    ParticipantOutcome,
    ParticipantStatus,
)
from agent_core.models import (
    ModelErrorCode,
    ModelProviderError,
    ModelUsageDelta,
)
from agent_core.reasoning import (
    ReasoningDecision,
    ReasoningCandidate,
    ReasoningError,
    ReasoningErrorCode,
    ReasoningRequest,
    build_reasoning_model_request,
    validate_reasoning_candidate,
    validate_reasoning_request,
)


class ConsensusEngine:
    """Collect independent votes and arbitrate; never execute a recommendation."""

    def __init__(
        self,
        reasoning_engine: Any,
        *,
        history: ConsensusHistory | None = None,
    ) -> None:
        self.reasoning_engine = reasoning_engine
        self.history = history or ConsensusHistory()

    def evaluate(self, request: ConsensusRequest) -> ConsensusResult:
        validate_reasoning_request(request.reasoning_request)
        outcomes: list[ParticipantOutcome] = []
        for participant in request.ordered_participants():
            current_usage = aggregate_model_usage(tuple(outcomes))
            if not self._budget_allows(request, participant, current_usage):
                outcomes.append(
                    self._failure_outcome(
                        participant,
                        ParticipantStatus.budget_blocked,
                        ParticipantFailure.consensus_budget_exhausted,
                        ModelUsageDelta(),
                    )
                )
                continue

            independent_request = ReasoningRequest.model_validate(
                request.reasoning_request.model_dump(mode="python")
            )
            ledger_before = self._ledger_snapshot(request.run_id)
            try:
                decision = self.reasoning_engine.reason(
                    independent_request, participant.routing_policy
                )
                if not isinstance(decision, ReasoningDecision):
                    raise ReasoningError(ReasoningErrorCode.invalid_model_output)
                if (
                    decision.model_provenance.provider_requested
                    != participant.routing_policy.preferred.provider
                    or decision.model_provenance.task_type
                    != independent_request.task_type
                    or (
                        decision.model_provenance.provider_used,
                        decision.model_provenance.model_used,
                    )
                    not in {
                        (route.provider, route.model)
                        for route in participant.routing_policy.ordered_routes()
                    }
                ):
                    raise ReasoningError(ReasoningErrorCode.invalid_model_output)
                candidate_fields = {
                    name: getattr(decision, name)
                    for name in ReasoningCandidate.model_fields
                }
                validated = validate_reasoning_candidate(
                    ReasoningCandidate(**candidate_fields),
                    independent_request,
                    decision.model_provenance,
                )
                outcomes.append(
                    ParticipantOutcome(
                        participant_id=participant.participant_id,
                        configured_provider=participant.routing_policy.preferred.provider,
                        configured_model=participant.routing_policy.preferred.model,
                        actual_provider=validated.model_provenance.provider_used,
                        actual_model=validated.model_provenance.model_used,
                        status=ParticipantStatus.valid,
                        decision=validated,
                        usage=validated.model_provenance.usage,
                    )
                )
            except ReasoningError as exc:
                usage = self._failure_usage(
                    ledger_before,
                    request.run_id,
                    participant,
                )
                invalid = exc.code in {
                    ReasoningErrorCode.invalid_model_output,
                    ReasoningErrorCode.unsupported_recommendation,
                    ReasoningErrorCode.evidence_validation_failed,
                    ReasoningErrorCode.sanitization_failed,
                }
                outcomes.append(
                    self._failure_outcome(
                        participant,
                        (
                            ParticipantStatus.invalid
                            if invalid
                            else (
                                ParticipantStatus.budget_blocked
                                if exc.code is ReasoningErrorCode.model_budget_exhausted
                                else ParticipantStatus.failed
                            )
                        ),
                        (
                            ParticipantFailure.invalid_decision
                            if invalid
                            else (
                                ParticipantFailure.model_budget_exhausted
                                if exc.code is ReasoningErrorCode.model_budget_exhausted
                                else self._normalized_ledger_failure(ledger_before)
                            )
                        ),
                        usage,
                    )
                )
            except ModelProviderError as exc:
                usage = self._failure_usage(
                    ledger_before,
                    request.run_id,
                    participant,
                )
                outcomes.append(
                    self._failure_outcome(
                        participant,
                        ParticipantStatus.failed,
                        self._provider_failure(exc.code),
                        usage,
                    )
                )
            except (TypeError, ValueError, RuntimeError):
                usage = self._failure_usage(
                    ledger_before,
                    request.run_id,
                    participant,
                )
                outcomes.append(
                    self._failure_outcome(
                        participant,
                        ParticipantStatus.invalid,
                        ParticipantFailure.invalid_decision,
                        usage,
                    )
                )
            except Exception:
                # The participant boundary never exposes an unexpected provider or
                # adapter exception, and one failed participant cannot cancel quorum.
                usage = self._failure_usage(
                    ledger_before,
                    request.run_id,
                    participant,
                )
                outcomes.append(
                    self._failure_outcome(
                        participant,
                        ParticipantStatus.failed,
                        ParticipantFailure.provider_failed,
                        usage,
                    )
                )

        materialized = tuple(outcomes)
        assessment = classify_agreement(materialized, request.policy)
        decision = arbitrate_consensus(request, materialized, assessment)
        self.history.record(decision)
        return ConsensusResult(decision=decision, participants=materialized)

    def _budget_allows(
        self,
        request: ConsensusRequest,
        participant: ConsensusParticipant,
        usage: ModelUsageDelta,
    ) -> bool:
        routes = participant.routing_policy.ordered_routes()
        potential_calls = len(routes)
        budget = request.model_budget
        if usage.attempted_calls + potential_calls > budget.max_model_calls:
            return False
        model_request = build_reasoning_model_request(
            request.reasoning_request,
            max_output_tokens=int(
                getattr(self.reasoning_engine, "max_output_tokens", 4096)
            ),
        )
        evidence = json.dumps(
            model_request.evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        input_estimate = max(
            1,
            len(
                "\n".join(
                    (
                        model_request.system_instructions,
                        model_request.user_content,
                        evidence,
                    )
                ).encode("utf-8")
            ),
        )
        output_estimate = model_request.max_output_tokens
        if (
            budget.max_input_tokens is not None
            and usage.budget_input_tokens + input_estimate * potential_calls
            > budget.max_input_tokens
        ):
            return False
        if (
            budget.max_output_tokens is not None
            and usage.budget_output_tokens + output_estimate * potential_calls
            > budget.max_output_tokens
        ):
            return False
        if (
            budget.max_total_tokens is not None
            and usage.budget_total_tokens
            + (input_estimate + output_estimate) * potential_calls
            > budget.max_total_tokens
        ):
            return False
        if budget.max_estimated_cost_usd is not None:
            predicted = self._predicted_cost(
                participant,
                input_tokens=input_estimate,
                output_tokens=output_estimate,
            )
            if predicted is None and budget.unknown_cost_policy == "deny":
                return False
            if usage.attempted_calls and usage.budget_estimated_cost_usd is None:
                if budget.unknown_cost_policy == "deny":
                    return False
            elif (
                predicted is not None
                and usage.budget_estimated_cost_usd is not None
                and usage.budget_estimated_cost_usd + predicted
                > budget.max_estimated_cost_usd
            ):
                return False
        return True

    def _predicted_cost(
        self,
        participant: ConsensusParticipant,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> float | None:
        router = getattr(self.reasoning_engine, "router", None)
        registry = getattr(router, "registry", None)
        pricing = getattr(registry, "pricing", None)
        estimates: list[float] = []
        for route in participant.routing_policy.ordered_routes():
            if route.provider == "ollama":
                estimates.append(0.0)
                continue
            estimate = (
                pricing.estimate_cost(
                    route.provider,
                    route.model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
                if pricing is not None
                else None
            )
            if estimate is None:
                return None
            estimates.append(float(estimate))
        return float(sum(estimates))

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

    def _failure_usage(
        self,
        before: Any,
        run_id: str,
        participant: ConsensusParticipant,
    ) -> ModelUsageDelta:
        if before is not None:
            router = getattr(self.reasoning_engine, "router", None)
            ledger = getattr(router, "ledger", None)
            try:
                return ledger.delta(before, ledger.snapshot(run_id=run_id))
            except (AttributeError, TypeError, ValueError):
                pass
        return ModelUsageDelta(
            attempted_calls=1,
            successful_calls=0,
            failed_calls=1,
            estimated_cost_usd=(
                0.0
                if participant.routing_policy.preferred.provider == "ollama"
                else None
            ),
        )

    def _normalized_ledger_failure(self, before: Any) -> ParticipantFailure:
        if before is None:
            return ParticipantFailure.provider_failed
        router = getattr(self.reasoning_engine, "router", None)
        ledger = getattr(router, "ledger", None)
        records = getattr(ledger, "records", ())
        for record in reversed(records[before.position :]):
            if not record.success:
                return self._provider_failure(record.outcome)
        return ParticipantFailure.provider_failed

    @staticmethod
    def _provider_failure(code: ModelErrorCode | str) -> ParticipantFailure:
        normalized = code.value if isinstance(code, ModelErrorCode) else str(code)
        if normalized == ModelErrorCode.timeout.value:
            return ParticipantFailure.timeout
        if normalized == ModelErrorCode.rate_limited.value:
            return ParticipantFailure.rate_limited
        if normalized in {
            ModelErrorCode.model_budget_exceeded.value,
            ModelErrorCode.unknown_cost.value,
        }:
            return ParticipantFailure.model_budget_exhausted
        return ParticipantFailure.provider_failed

    @staticmethod
    def _failure_outcome(
        participant: ConsensusParticipant,
        status: ParticipantStatus,
        failure: ParticipantFailure,
        usage: ModelUsageDelta,
    ) -> ParticipantOutcome:
        return ParticipantOutcome(
            participant_id=participant.participant_id,
            configured_provider=participant.routing_policy.preferred.provider,
            configured_model=participant.routing_policy.preferred.model,
            status=status,
            failure=failure,
            usage=usage,
        )
