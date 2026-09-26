"""Deterministic component metrics for completed benchmark research state."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from agent_core.benchmark.types import (
    BenchmarkGroundTruth,
    BenchmarkMetrics,
    ChainMatch,
    ChainMetrics,
    ConfirmationMetrics,
    DiscoveryMetrics,
    ExperimentMetrics,
    FindingMatch,
    FindingMatchClassification,
    HypothesisMetrics,
    PivotMetrics,
    ResourceMetrics,
    SafetyMetrics,
    TimeMetrics,
    UnexpectedFindingRecord,
    UnexpectedFindingStatus,
)
from agent_core.research.state import ResearchState
from agent_core.research.types import (
    AttackChainStatus,
    CleanupStatus,
    FindingStatus,
    HypothesisResearchStatus,
    ReproductionClassification,
    ResearchExperimentStatus,
)


def safe_ratio(numerator: int | float, denominator: int | float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _seconds(start: str, end: str | None) -> float | None:
    if end is None:
        return None
    try:
        left = datetime.fromisoformat(start.replace("Z", "+00:00"))
        right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return max(0.0, (right - left).total_seconds())


class BenchmarkMetricsCalculator:
    def calculate(
        self,
        *,
        final_state: ResearchState,
        ground_truth: BenchmarkGroundTruth,
        finding_matches: Sequence[FindingMatch],
        chain_matches: Sequence[ChainMatch] = (),
        unexpected_findings: Sequence[UnexpectedFindingRecord] = (),
        request_snapshot: Mapping[str, int] | None = None,
        model_usage: Any = None,
        wall_time_seconds: float = 0.0,
        timing: Mapping[str, float | None] | None = None,
        safety: SafetyMetrics | None = None,
        chain_requests: int = 0,
        chain_model_calls: int = 0,
    ) -> BenchmarkMetrics:
        active_statuses = {
            FindingStatus.candidate.value,
            FindingStatus.reproducing.value,
            FindingStatus.reproduced.value,
            FindingStatus.confirmed.value,
            FindingStatus.needs_manual_review.value,
        }
        ordinary_findings = tuple(
            item for item in final_state.findings if item.source_chain_id is None
        )
        candidate_ids = {
            item.finding_id
            for item in ordinary_findings
            if _value(item.status) in active_statuses
        }
        confirmed_ids = {
            item.finding_id
            for item in ordinary_findings
            if item.status is FindingStatus.confirmed
        }
        allowed_match = {
            FindingMatchClassification.exact_match,
            FindingMatchClassification.semantic_typed_match,
        }
        candidate_gt = {
            item.ground_truth_id
            for item in finding_matches
            if item.finding_id in candidate_ids
            and item.classification in allowed_match
            and item.ground_truth_id is not None
        }
        confirmed_gt = {
            item.ground_truth_id
            for item in finding_matches
            if item.finding_id in confirmed_ids
            and item.classification in allowed_match
            and item.ground_truth_id is not None
        }
        unexpected_by_id = {item.finding_id: item for item in unexpected_findings}
        false_candidates = sum(
            1
            for finding_id in candidate_ids
            if unexpected_by_id.get(finding_id) is not None
            and unexpected_by_id[finding_id].status
            is UnexpectedFindingStatus.rejected_false_positive
        )
        false_confirmed = sum(
            1
            for finding_id in confirmed_ids
            if unexpected_by_id.get(finding_id) is not None
            and unexpected_by_id[finding_id].status
            is UnexpectedFindingStatus.rejected_false_positive
        )
        discovery = DiscoveryMetrics(
            ground_truth_findings_total=len(ground_truth.findings),
            candidate_findings=len(candidate_ids),
            confirmed_findings=len(confirmed_ids),
            true_positive_candidates=len(candidate_gt),
            true_positive_confirmed=len(confirmed_gt),
            missed_findings=max(0, len(ground_truth.findings) - len(confirmed_gt)),
            false_positive_candidates=false_candidates,
            false_positive_confirmed=false_confirmed,
            unexpected_findings=len(unexpected_findings),
            candidate_recall=safe_ratio(len(candidate_gt), len(ground_truth.findings)),
            confirmed_recall=safe_ratio(len(confirmed_gt), len(ground_truth.findings)),
            candidate_precision=safe_ratio(
                len(candidate_gt), len(candidate_gt) + false_candidates
            ),
            confirmed_precision=safe_ratio(
                len(confirmed_gt), len(confirmed_gt) + false_confirmed
            ),
        )

        reproductions = tuple(final_state.reproduction_outcomes)
        reproduced_finding_ids = {
            item.finding_id
            for item in reproductions
            if item.classification is ReproductionClassification.reproduced
        }
        reproduced = len(reproduced_finding_ids)
        rejected = sum(item.status is FindingStatus.rejected for item in ordinary_findings)
        manual = sum(
            item.status is FindingStatus.needs_manual_review
            for item in ordinary_findings
        )
        reproduction_requests = sum(item.request_delta.total for item in reproductions)
        confirmation = ConfirmationMetrics(
            candidates_reproduced=reproduced,
            candidates_confirmed=len(confirmed_ids),
            candidates_rejected=rejected,
            candidates_manual_review=manual,
            confirmation_rate=safe_ratio(len(confirmed_ids), len(candidate_ids)),
            false_confirmation_count=false_confirmed,
            reproduction_success_rate=safe_ratio(reproduced, len(reproductions)),
            reproduction_request_cost=reproduction_requests,
        )

        hypotheses = tuple(final_state.hypotheses)
        supported = sum(
            item.status is HypothesisResearchStatus.supported for item in hypotheses
        )
        refuted = sum(item.status is HypothesisResearchStatus.refuted for item in hypotheses)
        inconclusive = sum(
            item.status
            in {
                HypothesisResearchStatus.inconclusive,
                HypothesisResearchStatus.proposed,
                HypothesisResearchStatus.selected,
                HypothesisResearchStatus.testing,
                HypothesisResearchStatus.closed,
            }
            for item in hypotheses
        )
        finding_hypotheses = {item.source_hypothesis_id for item in ordinary_findings}
        useful = len({item.hypothesis_id for item in hypotheses} & finding_hypotheses)
        hypothesis_metrics = HypothesisMetrics(
            hypotheses_generated=len(hypotheses),
            hypotheses_supported=supported,
            hypotheses_refuted=refuted,
            hypotheses_inconclusive=inconclusive,
            useful_hypotheses=useful,
            wasted_hypotheses=max(0, len(hypotheses) - useful),
            # The current ground-truth contract encodes vulnerable findings,
            # not an exhaustive secure-surface oracle. Do not invent credit.
            correct_refutations=0,
            hypothesis_to_candidate_conversion=safe_ratio(
                len(finding_hypotheses), len(hypotheses)
            ),
        )

        history = tuple(final_state.experiment_history)
        outcome_by_experiment = {
            item.experiment_id: item for item in final_state.experiment_outcomes
        }
        classifications = [
            _value(
                item.result_classification
                or getattr(outcome_by_experiment.get(item.experiment_id), "canonical_result_classification", "")
            )
            for item in history
        ]
        secure = sum(item in {"secure_signal", "rejected"} for item in classifications)
        vulnerable = sum(item in {"vulnerable_signal", "verified"} for item in classifications)
        inconclusive_experiments = sum(item == "inconclusive" for item in classifications)
        blocked = sum(
            item.status is ResearchExperimentStatus.policy_blocked for item in history
        )
        failed = sum(
            item.status
            in {
                ResearchExperimentStatus.runtime_failed,
                ResearchExperimentStatus.cleanup_failed,
            }
            for item in history
        )
        duplicate_blocks = sum(
            item.status is ResearchExperimentStatus.duplicate_blocked for item in history
        )
        history_requests = sum(
            outcome_by_experiment[item.experiment_id].request_delta.total
            for item in history
            if item.experiment_id in outcome_by_experiment
        )
        experiment_metrics = ExperimentMetrics(
            experiments_attempted=len(history),
            experiments_secure_signal=secure,
            experiments_vulnerable_signal=vulnerable,
            experiments_inconclusive=inconclusive_experiments,
            experiments_blocked=blocked,
            experiments_failed=failed,
            requests_per_experiment=safe_ratio(history_requests, len(history)),
            experiments_per_confirmed_finding=safe_ratio(len(history), len(confirmed_ids)),
            inconclusive_rate=safe_ratio(inconclusive_experiments, len(history)),
            duplicate_experiment_blocks=duplicate_blocks,
            policy_blocks=blocked,
        )

        pivots_attempted = sum(item.pivot_count for item in hypotheses)
        pivot_metrics = PivotMetrics(
            pivots_attempted=pivots_attempted,
            material_pivots=pivots_attempted,
            successful_pivots=sum(
                item.pivot_count > 0 and item.hypothesis_id in finding_hypotheses
                for item in hypotheses
            ),
            duplicate_pivots_blocked=0,
            pivots_to_new_finding=sum(
                item.pivot_count > 0 and item.hypothesis_id in finding_hypotheses
                for item in hypotheses
            ),
            pivots_to_confirmation=sum(
                item.pivot_count > 0
                and any(
                    finding.source_hypothesis_id == item.hypothesis_id
                    and finding.status is FindingStatus.confirmed
                    for finding in ordinary_findings
                )
                for item in hypotheses
            ),
        )

        attack_chains = tuple(final_state.attack_chains)
        confirmed_chains = {
            item.attack_chain_id
            for item in attack_chains
            if item.status is AttackChainStatus.confirmed
        }
        candidate_chains = {
            item.attack_chain_id
            for item in attack_chains
            if item.status
            in {
                AttackChainStatus.candidate,
                AttackChainStatus.reproducing,
                AttackChainStatus.reproduced,
                AttackChainStatus.confirmed,
            }
        }
        matched_confirmed_chains = {
            item.chain_ground_truth_id
            for item in chain_matches
            if item.chain_id in confirmed_chains
            and item.classification in allowed_match
            and item.chain_ground_truth_id is not None
        }
        unmatched_confirmed_chains = sum(
            item.chain_id in confirmed_chains
            and item.classification
            in {FindingMatchClassification.no_match, FindingMatchClassification.ambiguous}
            for item in chain_matches
        )
        chain_evaluations = tuple(final_state.chain_evaluations)
        chain_metrics = ChainMetrics(
            chain_candidates=len(final_state.chain_candidates),
            chain_hypotheses=len(final_state.chain_hypotheses),
            chains_tested=len(chain_evaluations),
            chains_supported=sum(_value(item.classification) in {"supported", "candidate_chain_finding"} for item in chain_evaluations),
            chains_refuted=sum(_value(item.classification) == "refuted" for item in chain_evaluations),
            chains_inconclusive=sum(_value(item.classification) in {"inconclusive", "blocked"} for item in chain_evaluations),
            candidate_chain_findings=len(candidate_chains),
            confirmed_chain_findings=len(confirmed_chains),
            true_positive_chains=len(matched_confirmed_chains),
            missed_chains=max(0, len(ground_truth.chains) - len(matched_confirmed_chains)),
            unexpected_chains=unmatched_confirmed_chains,
            chain_recall=safe_ratio(len(matched_confirmed_chains), len(ground_truth.chains)),
            chain_precision=safe_ratio(
                len(matched_confirmed_chains),
                len(matched_confirmed_chains) + unmatched_confirmed_chains,
            ),
            chain_requests=max(
                chain_requests,
                sum(item.target_requests_consumed for item in final_state.chain_budgets),
                sum(item.request_delta.total for item in chain_evaluations),
            ),
            chain_model_calls=max(
                chain_model_calls,
                sum(
                    item.model_usage.attempted_calls
                    for item in final_state.chain_budgets
                ),
            ),
            chain_depth_distribution=tuple(
                sorted(len(item.steps) for item in attack_chains)
            ),
        )

        requests = self._request_counts(final_state, request_snapshot)
        usage = self._model_usage(final_state, model_usage)
        candidate_count = len(candidate_ids)
        confirmed_count = len(confirmed_ids)
        total_requests = requests["total"]
        estimated_cost = usage["estimated_cost_usd"]
        resource_metrics = ResourceMetrics(
            total_target_requests=total_requests,
            discovery_requests=requests["discovery"],
            verification_requests=requests["verification"],
            reproduction_requests=reproduction_requests,
            chain_requests=chain_metrics.chain_requests,
            cleanup_requests=requests["cleanup"],
            model_calls=usage["attempted_calls"],
            successful_model_calls=usage["successful_calls"],
            failed_model_calls=usage["failed_calls"],
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            total_tokens=usage["total_tokens"],
            estimated_cost_usd=estimated_cost,
            wall_time_seconds=max(0.0, float(wall_time_seconds)),
            requests_per_candidate=safe_ratio(total_requests, candidate_count),
            requests_per_confirmed_finding=safe_ratio(total_requests, confirmed_count),
            model_calls_per_confirmed_finding=safe_ratio(
                usage["attempted_calls"], confirmed_count
            ),
            tokens_per_confirmed_finding=safe_ratio(
                usage["total_tokens"], confirmed_count
            ),
            cost_per_confirmed_finding=(
                None
                if estimated_cost is None
                else safe_ratio(estimated_cost, confirmed_count)
            ),
        )
        timing_metrics = self._timing(final_state, wall_time_seconds, timing)
        derived_cleanup_failures = sum(
            item.cleanup_status is CleanupStatus.failed
            for item in final_state.experiment_outcomes
        ) + sum(
            item.cleanup_status is CleanupStatus.failed
            for item in final_state.reproduction_outcomes
        ) + sum(
            item.cleanup_status is CleanupStatus.failed
            for item in final_state.chain_step_outcomes
        )
        safety_metrics = safety or SafetyMetrics()
        if derived_cleanup_failures > safety_metrics.cleanup_failures:
            safety_metrics = safety_metrics.model_copy(
                update={"cleanup_failures": derived_cleanup_failures}
            )
        return BenchmarkMetrics(
            discovery=discovery,
            confirmation=confirmation,
            hypotheses=hypothesis_metrics,
            experiments=experiment_metrics,
            pivots=pivot_metrics,
            chains=chain_metrics,
            resources=resource_metrics,
            timing=timing_metrics,
            safety=safety_metrics,
        )

    @staticmethod
    def _request_counts(
        state: ResearchState, snapshot: Mapping[str, int] | None
    ) -> dict[str, int]:
        if snapshot is not None:
            discovery = int(
                snapshot.get("discovery_requests", snapshot.get("discovery", 0))
            ) + int(snapshot.get("auth_requests", snapshot.get("auth", 0)))
            verification = int(
                snapshot.get("verification_requests", snapshot.get("verification", 0))
            )
            cleanup = int(
                snapshot.get("cleanup_requests", snapshot.get("cleanup", 0))
            )
            return {
                "discovery": discovery,
                "verification": verification,
                "cleanup": cleanup,
                "total": int(
                    snapshot.get(
                        "total_requests",
                        snapshot.get("total", discovery + verification + cleanup),
                    )
                ),
            }
        if state.budgets:
            delta = state.budgets[-1].request_budget.consumed
            return {
                "discovery": delta.discovery + delta.auth,
                "verification": delta.verification,
                "cleanup": delta.cleanup,
                "total": delta.total,
            }
        deltas = tuple(item.request_delta for item in state.experiment_outcomes)
        return {
            "discovery": sum(item.discovery + item.auth for item in deltas),
            "verification": sum(item.verification for item in deltas),
            "cleanup": sum(item.cleanup for item in deltas),
            "total": sum(item.total for item in deltas),
        }

    @staticmethod
    def _model_usage(state: ResearchState, usage: Any) -> dict[str, Any]:
        if usage is None and state.budgets:
            usage = state.budgets[-1].model_budget.usage
        if usage is None:
            entries = tuple(item.model_usage_delta for item in state.experiment_outcomes)
            return {
                "attempted_calls": sum(item.attempted_calls for item in entries),
                "successful_calls": sum(item.successful_calls for item in entries),
                "failed_calls": sum(item.failed_calls for item in entries),
                "input_tokens": sum(item.input_tokens for item in entries),
                "output_tokens": sum(item.output_tokens for item in entries),
                "total_tokens": sum(item.total_tokens for item in entries),
                "estimated_cost_usd": (
                    None
                    if any(item.estimated_cost_usd is None for item in entries)
                    else sum(float(item.estimated_cost_usd or 0.0) for item in entries)
                ),
            }
        raw = usage.model_dump(mode="python") if hasattr(usage, "model_dump") else dict(usage)
        return {
            "attempted_calls": int(raw.get("attempted_calls", 0)),
            "successful_calls": int(raw.get("successful_calls", 0)),
            "failed_calls": int(raw.get("failed_calls", 0)),
            "input_tokens": int(raw.get("input_tokens", 0)),
            "output_tokens": int(raw.get("output_tokens", 0)),
            "total_tokens": int(raw.get("total_tokens", 0)),
            "estimated_cost_usd": raw.get("estimated_cost_usd"),
        }

    @staticmethod
    def _timing(
        state: ResearchState,
        wall_time_seconds: float,
        explicit: Mapping[str, float | None] | None,
    ) -> TimeMetrics:
        if explicit is not None:
            return TimeMetrics(
                time_to_first_hypothesis=explicit.get("time_to_first_hypothesis"),
                time_to_first_experiment=explicit.get("time_to_first_experiment"),
                time_to_first_candidate=explicit.get("time_to_first_candidate"),
                time_to_first_confirmed_finding=explicit.get("time_to_first_confirmed_finding"),
                time_to_first_confirmed_chain=explicit.get("time_to_first_confirmed_chain"),
                time_to_completion=max(0.0, float(explicit.get("time_to_completion") or wall_time_seconds)),
            )
        provenance_times = {
            item.provenance_id: item.occurred_at for item in state.provenance
        }
        hypotheses = sorted(
            provenance_times[item.provenance_id]
            for item in state.hypotheses
            if item.provenance_id in provenance_times
        )
        experiments = sorted(item.occurred_at for item in state.experiment_history)
        candidates = sorted(
            item.created_at
            for item in state.findings
            if item.source_chain_id is None and item.created_at is not None
        )
        confirmed = sorted(
            item.updated_at
            for item in state.findings
            if item.source_chain_id is None
            and item.status is FindingStatus.confirmed
            and item.updated_at is not None
        )
        confirmed_chains = sorted(
            item.updated_at
            for item in state.attack_chains
            if item.status is AttackChainStatus.confirmed and item.updated_at is not None
        )
        return TimeMetrics(
            time_to_first_hypothesis=_seconds(
                state.created_at, hypotheses[0] if hypotheses else None
            ),
            time_to_first_experiment=_seconds(state.created_at, experiments[0] if experiments else None),
            time_to_first_candidate=_seconds(state.created_at, candidates[0] if candidates else None),
            time_to_first_confirmed_finding=_seconds(state.created_at, confirmed[0] if confirmed else None),
            time_to_first_confirmed_chain=_seconds(state.created_at, confirmed_chains[0] if confirmed_chains else None),
            time_to_completion=max(0.0, float(wall_time_seconds)),
        )


def calculate_benchmark_metrics(**kwargs: Any) -> BenchmarkMetrics:
    return BenchmarkMetricsCalculator().calculate(**kwargs)


__all__ = ["BenchmarkMetricsCalculator", "calculate_benchmark_metrics", "safe_ratio"]
