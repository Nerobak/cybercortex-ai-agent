"""Explainable deterministic selection with bounded model advisory input."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pydantic import Field, StrictFloat, StrictInt, model_validator

from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.compiler import (
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentCompilerError,
)
from agent_core.research.experiments import ExperimentProposal, SecurityExperiment
from agent_core.research.fingerprint import canonical_experiment_semantics
from agent_core.research.primitives import PrimitiveCapabilityState
from agent_core.research.registry import ExperimentRegistry
from agent_core.research.state import ResearchState
from agent_core.research.types import (
    HypothesisResearchStatus,
    OpaqueIdentifier,
    ResearchContract,
    ResearchExperimentStatus,
    Sha256Digest,
)


class ProposalEligibilityReason(str, Enum):
    hypothesis_closed = "hypothesis_closed"
    primitive_unavailable = "primitive_unavailable"
    controlled_context_unavailable = "controlled_context_unavailable"
    fingerprint_completed = "fingerprint_completed"
    fingerprint_policy_blocked = "fingerprint_policy_blocked"
    hypothesis_budget_exhausted = "hypothesis_budget_exhausted"
    surface_budget_exhausted = "surface_budget_exhausted"
    global_budget_exhausted = "global_budget_exhausted"
    request_reserve_unavailable = "request_reserve_unavailable"
    cleanup_barrier = "cleanup_barrier"
    stale_state_revision = "stale_state_revision"
    policy_context_changed = "policy_context_changed"
    invalid_proposal = "invalid_proposal"


class InformationGainEstimate(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class ProposalRankingAdvice(ResearchContract):
    proposal_id: OpaqueIdentifier
    expected_information_gain: InformationGainEstimate = InformationGainEstimate.medium
    priority: StrictInt = Field(default=50, ge=0, le=100)
    confidence: InformationGainEstimate = InformationGainEstimate.medium


class InformationValue(ResearchContract):
    """Normalized components retained so ranking remains auditable."""

    expected_information_gain: StrictFloat = Field(ge=0.0, le=1.0)
    hypothesis_priority: StrictFloat = Field(ge=0.0, le=1.0)
    novelty: StrictFloat = Field(ge=0.0, le=1.0)
    request_efficiency: StrictFloat = Field(ge=0.0, le=1.0)
    safety: StrictFloat = Field(ge=0.0, le=1.0)
    baseline_strength: StrictFloat = Field(ge=0.0, le=1.0)
    surface_headroom: StrictFloat = Field(ge=0.0, le=1.0)
    score: StrictFloat = Field(ge=0.0, le=1.0)


class ProposalAssessment(ResearchContract):
    proposal_id: OpaqueIdentifier
    eligible: bool
    reasons: tuple[ProposalEligibilityReason, ...] = Field(default=(), max_length=20)
    experiment: SecurityExperiment | None = None
    material_fingerprint: Sha256Digest | None = None
    information_value: InformationValue | None = None

    @model_validator(mode="after")
    def validate_disposition(self) -> "ProposalAssessment":
        if self.eligible:
            if (
                self.reasons
                or self.experiment is None
                or self.information_value is None
            ):
                raise ValueError(
                    "eligible proposals require a compiled scored experiment"
                )
        elif not self.reasons:
            raise ValueError("ineligible proposals require a deterministic reason")
        return self


class ExperimentSelection(ResearchContract):
    selected: ProposalAssessment | None = None
    assessments: tuple[ProposalAssessment, ...] = Field(default=(), max_length=500)
    stop_reason: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_result(self) -> "ExperimentSelection":
        if (self.selected is None) == (self.stop_reason is None):
            raise ValueError("selection requires either one proposal or a stop reason")
        if self.selected is not None and self.selected not in self.assessments:
            raise ValueError("selected proposal must be present in assessments")
        return self


_GAIN = {
    InformationGainEstimate.low: 0.25,
    InformationGainEstimate.medium: 0.6,
    InformationGainEstimate.high: 1.0,
}
_RISK_SAFETY = {
    "passive": 1.0,
    "low": 0.9,
    "moderate": 0.6,
    "high": 0.25,
    "critical": 0.0,
}


def material_experiment_fingerprint(experiment: SecurityExperiment) -> str:
    """Fingerprint P4-0C semantics while ignoring a revision-only retry."""

    semantics = canonical_experiment_semantics(experiment)
    semantics.pop("state_revision", None)
    encoded = json.dumps(
        semantics, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ExperimentSelector:
    """Compile, filter, and rank proposals; never authorize or execute them."""

    def __init__(
        self,
        compiler: ExperimentCompiler,
        budget_manager: ResearchBudgetManager,
        *,
        registry: ExperimentRegistry | None = None,
    ) -> None:
        self.compiler = compiler
        self.budget_manager = budget_manager
        self.registry = registry or compiler.registry

    def select(
        self,
        proposals: tuple[ExperimentProposal, ...] | list[ExperimentProposal],
        state: ResearchState,
        *,
        compiler_context: ExperimentCompilerContext | None = None,
        advisory: tuple[ProposalRankingAdvice, ...] = (),
        pivot: bool = False,
        cleanup_barrier: bool = False,
        policy_reference: str | None = None,
        policy_fingerprint: str | None = None,
    ) -> ExperimentSelection:
        advice = {item.proposal_id: item for item in advisory}
        if len(advice) != len(advisory):
            raise ValueError("proposal advisory IDs must be unique")
        assessments = tuple(
            self._assess(
                proposal,
                state,
                compiler_context=compiler_context,
                advisory=advice.get(proposal.proposal_id),
                pivot=pivot,
                cleanup_barrier=cleanup_barrier,
                policy_reference=policy_reference,
                policy_fingerprint=policy_fingerprint,
            )
            for proposal in proposals
        )
        eligible = [item for item in assessments if item.eligible]
        if not eligible:
            return ExperimentSelection(
                assessments=assessments,
                stop_reason="no-eligible-experiments",
            )
        selected = sorted(
            eligible,
            key=lambda item: (
                -float(item.information_value.score),  # type: ignore[union-attr]
                item.proposal_id,
            ),
        )[0]
        return ExperimentSelection(selected=selected, assessments=assessments)

    def information_value(
        self,
        experiment: SecurityExperiment,
        state: ResearchState,
        *,
        advisory: ProposalRankingAdvice | None = None,
        materially_new: bool = True,
    ) -> InformationValue:
        hypothesis = next(
            item
            for item in state.hypotheses
            if item.hypothesis_id == experiment.hypothesis_id
        )
        gain = _GAIN[
            (
                advisory.expected_information_gain
                if advisory is not None
                else InformationGainEstimate.medium
            )
        ]
        priority = hypothesis.priority / 100.0
        novelty = 1.0 if materially_new else 0.0
        request_efficiency = max(
            0.0, 1.0 - min(experiment.request_estimate.total_reservation, 20) / 20.0
        )
        risk_value = getattr(experiment.risk.level, "value", None)
        safety = _RISK_SAFETY.get(str(risk_value or experiment.risk.level), 0.5)
        baseline = (
            1.0
            if experiment.baseline.kind.value
            in {"registered_request", "primary_identity", "prior_evidence"}
            else 0.6
        )
        surface_count = 0
        if experiment.target.surface_id is not None:
            budget = self.budget_manager.state(state)
            surface_count = next(
                (
                    item.experiment_count
                    for item in budget.surface_usage
                    if item.surface_id == experiment.target.surface_id
                ),
                0,
            )
        surface_headroom = max(
            0.0,
            1.0 - surface_count / self.budget_manager.policy.experiments_per_surface,
        )
        score = (
            0.25 * gain
            + 0.2 * priority
            + 0.15 * novelty
            + 0.15 * request_efficiency
            + 0.1 * safety
            + 0.1 * baseline
            + 0.05 * surface_headroom
        )
        return InformationValue(
            expected_information_gain=gain,
            hypothesis_priority=priority,
            novelty=novelty,
            request_efficiency=request_efficiency,
            safety=safety,
            baseline_strength=baseline,
            surface_headroom=surface_headroom,
            score=min(1.0, max(0.0, score)),
        )

    def _assess(
        self,
        proposal: ExperimentProposal,
        state: ResearchState,
        *,
        compiler_context: ExperimentCompilerContext | None,
        advisory: ProposalRankingAdvice | None,
        pivot: bool,
        cleanup_barrier: bool,
        policy_reference: str | None,
        policy_fingerprint: str | None,
    ) -> ProposalAssessment:
        reasons: list[ProposalEligibilityReason] = []
        hypothesis = next(
            (
                item
                for item in state.hypotheses
                if item.hypothesis_id == proposal.hypothesis_id
            ),
            None,
        )
        if hypothesis is None or hypothesis.status in {
            HypothesisResearchStatus.closed,
            HypothesisResearchStatus.refuted,
            HypothesisResearchStatus.supported,
        }:
            reasons.append(ProposalEligibilityReason.hypothesis_closed)
        if (
            proposal.research_id != state.research_id
            or proposal.state_revision != state.revision
        ):
            reasons.append(ProposalEligibilityReason.stale_state_revision)
        definitions = []
        for step in proposal.primitive_steps:
            try:
                definition = self.registry.resolve(step.primitive_name)
            except ValueError:
                reasons.append(ProposalEligibilityReason.primitive_unavailable)
                continue
            definitions.append(definition)
            if (
                definition.capability_state
                is not PrimitiveCapabilityState.execution_available
            ):
                reasons.append(ProposalEligibilityReason.primitive_unavailable)
        if compiler_context is not None and policy_reference is not None:
            if compiler_context.policy_reference != policy_reference:
                reasons.append(ProposalEligibilityReason.policy_context_changed)
        if cleanup_barrier:
            reasons.append(ProposalEligibilityReason.cleanup_barrier)
        if reasons:
            return self._ineligible(proposal.proposal_id, reasons)
        try:
            experiment = self.compiler.compile(proposal, state, compiler_context)
        except (ExperimentCompilerError, TypeError, ValueError):
            return self._ineligible(
                proposal.proposal_id,
                (ProposalEligibilityReason.controlled_context_unavailable,),
            )
        material = material_experiment_fingerprint(experiment)
        completed_count = sum(
            item.material_fingerprint == material
            for item in state.experiment_history
            if item.status
            in {
                ResearchExperimentStatus.completed,
                ResearchExperimentStatus.duplicate_blocked,
                ResearchExperimentStatus.runtime_failed,
                ResearchExperimentStatus.cleanup_failed,
            }
        )
        if completed_count > self.budget_manager.policy.equivalent_retries:
            reasons.append(ProposalEligibilityReason.fingerprint_completed)
        for item in state.experiment_history:
            if item.status is not ResearchExperimentStatus.policy_blocked:
                continue
            same_fingerprint = item.fingerprint == experiment.fingerprint
            same_material_context = item.material_fingerprint == material
            same_policy = policy_fingerprint is None or (
                item.policy_fingerprint == policy_fingerprint
            )
            if (same_fingerprint or same_material_context) and same_policy:
                reasons.append(ProposalEligibilityReason.fingerprint_policy_blocked)
                break
        budget = self.budget_manager.check(
            state,
            hypothesis_id=proposal.hypothesis_id,
            surface_id=proposal.surface_id,
            estimated_requests=experiment.request_estimate.total_reservation,
            pivot=pivot,
            state_changing=experiment.state_changing,
        )
        if not budget.allowed:
            reason = str(budget.reason.value if budget.reason else "")
            if "global_experiment" in reason:
                reasons.append(ProposalEligibilityReason.global_budget_exhausted)
            elif "hypothesis" in reason:
                reasons.append(ProposalEligibilityReason.hypothesis_budget_exhausted)
            elif "request" in reason:
                reasons.append(ProposalEligibilityReason.request_reserve_unavailable)
            elif "cleanup" in reason:
                reasons.append(ProposalEligibilityReason.cleanup_barrier)
            else:
                reasons.append(ProposalEligibilityReason.global_budget_exhausted)
        if budget.remaining_surface_experiments <= 0:
            reasons.append(ProposalEligibilityReason.surface_budget_exhausted)
        if reasons:
            return self._ineligible(proposal.proposal_id, reasons)
        materially_new = material not in {
            item.material_fingerprint for item in state.experiment_history
        }
        value = self.information_value(
            experiment, state, advisory=advisory, materially_new=materially_new
        )
        return ProposalAssessment(
            proposal_id=proposal.proposal_id,
            eligible=True,
            experiment=experiment,
            material_fingerprint=material,
            information_value=value,
        )

    @staticmethod
    def _ineligible(
        proposal_id: str,
        reasons: (
            tuple[ProposalEligibilityReason, ...] | list[ProposalEligibilityReason]
        ),
    ) -> ProposalAssessment:
        return ProposalAssessment(
            proposal_id=proposal_id,
            eligible=False,
            reasons=tuple(sorted(set(reasons), key=lambda item: item.value)),
        )


__all__ = [
    "ExperimentSelection",
    "ExperimentSelector",
    "InformationGainEstimate",
    "InformationValue",
    "ProposalAssessment",
    "ProposalEligibilityReason",
    "ProposalRankingAdvice",
    "material_experiment_fingerprint",
]
