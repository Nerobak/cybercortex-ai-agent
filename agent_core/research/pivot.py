"""Typed diagnosis and material pivot enforcement for research experiments."""

from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from agent_core.research.compiler import ExperimentCompilerContext
from agent_core.research.experiments import ExperimentProposal, SecurityExperiment
from agent_core.research.outcomes import (
    ExperimentOutcome,
    ExperimentResultClassification,
)
from agent_core.research.selection import (
    ExperimentSelection,
    ExperimentSelector,
    ProposalRankingAdvice,
)
from agent_core.research.state import ResearchState
from agent_core.research.types import OpaqueIdentifier, ResearchContract


class PivotReason(str, Enum):
    baseline_missing = "baseline_missing"
    identity_context_insufficient = "identity_context_insufficient"
    object_context_insufficient = "object_context_insufficient"
    signal_ambiguous = "signal_ambiguous"
    endpoint_representation_difference = "endpoint_representation_difference"
    parameter_representation_difference = "parameter_representation_difference"
    surface_alternative_available = "surface_alternative_available"
    state_changed = "state_changed"
    service_instability = "service_instability"
    policy_blocked = "policy_blocked"
    budget_limited = "budget_limited"
    duplicate_strategy = "duplicate_strategy"
    no_material_pivot = "no_material_pivot"


class PivotDimension(str, Enum):
    endpoint_operation = "endpoint_operation"
    parameter_field = "parameter_field"
    controlled_identity_relationship = "controlled_identity_relationship"
    controlled_object = "controlled_object"
    mutation_primitive = "mutation_primitive"
    baseline_strategy = "baseline_strategy"
    observation_method = "observation_method"
    surface_type = "surface_type"


class PivotDiagnosis(ResearchContract):
    reason: PivotReason
    material_pivot_useful: bool
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    summary: str = Field(min_length=1, max_length=1_000)


class PivotPlan(ResearchContract):
    diagnosis: PivotDiagnosis
    selection: ExperimentSelection | None = None
    changed_dimensions: tuple[PivotDimension, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def validate_material_change(self) -> "PivotPlan":
        if self.selection is not None and not self.changed_dimensions:
            raise ValueError("a selected pivot must change a material dimension")
        return self


class PivotPlanner:
    """Select a second experiment only when its semantics materially differ."""

    def __init__(self, selector: ExperimentSelector) -> None:
        self.selector = selector

    def diagnose(
        self,
        outcome: ExperimentOutcome,
        experiment: SecurityExperiment,
    ) -> PivotDiagnosis:
        references = outcome.evidence_references
        if outcome.result_classification is ExperimentResultClassification.blocked:
            return PivotDiagnosis(
                reason=PivotReason.policy_blocked,
                material_pivot_useful=False,
                evidence_references=references,
                summary="Deterministic policy prevented this experiment.",
            )
        if (
            outcome.result_classification
            is ExperimentResultClassification.runtime_failed
        ):
            return PivotDiagnosis(
                reason=PivotReason.service_instability,
                material_pivot_useful=True,
                evidence_references=references,
                summary="Runtime evidence did not provide a stable research signal.",
            )
        if (
            outcome.result_classification
            is ExperimentResultClassification.cleanup_failed
        ):
            return PivotDiagnosis(
                reason=PivotReason.policy_blocked,
                material_pivot_useful=False,
                evidence_references=references,
                summary="Cleanup failure requires intervention before more execution.",
            )
        if (
            outcome.result_classification
            is not ExperimentResultClassification.inconclusive
        ):
            return PivotDiagnosis(
                reason=PivotReason.no_material_pivot,
                material_pivot_useful=False,
                evidence_references=references,
                summary="The experiment produced a determinate signal.",
            )
        if (
            experiment.identity_context.primary_identity_id is None
            and experiment.identity_context.comparison_identity_id is None
        ):
            reason = PivotReason.identity_context_insufficient
        elif not experiment.mutation.controlled_object_ids and (
            "object" in experiment.objective.lower()
        ):
            reason = PivotReason.object_context_insufficient
        else:
            reason = PivotReason.signal_ambiguous
        return PivotDiagnosis(
            reason=reason,
            material_pivot_useful=True,
            evidence_references=references,
            summary="A materially different bounded experiment may resolve the signal.",
        )

    def plan(
        self,
        previous: SecurityExperiment,
        proposals: tuple[ExperimentProposal, ...] | list[ExperimentProposal],
        state: ResearchState,
        *,
        compiler_context: ExperimentCompilerContext | None = None,
        advisory: tuple[ProposalRankingAdvice, ...] = (),
        diagnosis: PivotDiagnosis | None = None,
        cleanup_barrier: bool = False,
        policy_reference: str | None = None,
        policy_fingerprint: str | None = None,
    ) -> PivotPlan:
        candidates: list[ExperimentProposal] = []
        dimensions: dict[str, tuple[PivotDimension, ...]] = {}
        for proposal in proposals:
            try:
                compiled = self.selector.compiler.compile(
                    proposal, state, compiler_context
                )
            except (TypeError, ValueError):
                candidates.append(proposal)
                continue
            changed = self.changed_dimensions(previous, compiled)
            if changed:
                candidates.append(proposal)
                dimensions[proposal.proposal_id] = changed
        selection = self.selector.select(
            candidates,
            state,
            compiler_context=compiler_context,
            advisory=advisory,
            pivot=True,
            cleanup_barrier=cleanup_barrier,
            policy_reference=policy_reference,
            policy_fingerprint=policy_fingerprint,
        )
        fallback_diagnosis = diagnosis or PivotDiagnosis(
            reason=PivotReason.signal_ambiguous,
            material_pivot_useful=True,
            summary="A materially different experiment may resolve the prior signal.",
        )
        if selection.selected is None:
            return PivotPlan(
                diagnosis=PivotDiagnosis(
                    reason=PivotReason.no_material_pivot,
                    material_pivot_useful=False,
                    evidence_references=fallback_diagnosis.evidence_references,
                    summary="No eligible proposal changes a material experiment dimension.",
                )
            )
        return PivotPlan(
            diagnosis=fallback_diagnosis,
            selection=selection,
            changed_dimensions=dimensions[selection.selected.proposal_id],
        )

    @staticmethod
    def changed_dimensions(
        previous: SecurityExperiment, candidate: SecurityExperiment
    ) -> tuple[PivotDimension, ...]:
        changed: list[PivotDimension] = []
        if (
            previous.target.endpoint_id,
            previous.target.operation_id,
            previous.target.method,
        ) != (
            candidate.target.endpoint_id,
            candidate.target.operation_id,
            candidate.target.method,
        ):
            changed.append(PivotDimension.endpoint_operation)
        if previous.target.parameter_ids != candidate.target.parameter_ids:
            changed.append(PivotDimension.parameter_field)
        previous_identity = (
            previous.identity_context.primary_identity_id,
            previous.identity_context.comparison_identity_id,
            previous.identity_context.relationship,
        )
        candidate_identity = (
            candidate.identity_context.primary_identity_id,
            candidate.identity_context.comparison_identity_id,
            candidate.identity_context.relationship,
        )
        if previous_identity != candidate_identity:
            changed.append(PivotDimension.controlled_identity_relationship)
        if (
            previous.mutation.controlled_object_ids
            != candidate.mutation.controlled_object_ids
        ):
            changed.append(PivotDimension.controlled_object)
        previous_primitives = tuple(
            (item.primitive_name, item.primitive_version, item.input.primitive)
            for item in previous.primitive_steps
        )
        candidate_primitives = tuple(
            (item.primitive_name, item.primitive_version, item.input.primitive)
            for item in candidate.primitive_steps
        )
        if (
            previous_primitives != candidate_primitives
            or previous.mutation.kind != candidate.mutation.kind
        ):
            changed.append(PivotDimension.mutation_primitive)
        if previous.baseline != candidate.baseline:
            changed.append(PivotDimension.baseline_strategy)
        previous_observation = tuple(
            (item.selector, item.predicate_reference)
            for item in previous.required_evidence
        )
        candidate_observation = tuple(
            (item.selector, item.predicate_reference)
            for item in candidate.required_evidence
        )
        if previous_observation != candidate_observation:
            changed.append(PivotDimension.observation_method)
        if previous.target.surface_id != candidate.target.surface_id:
            changed.append(PivotDimension.surface_type)
        return tuple(changed)

    @classmethod
    def is_material(
        cls, previous: SecurityExperiment, candidate: SecurityExperiment
    ) -> bool:
        return bool(cls.changed_dimensions(previous, candidate))


__all__ = [
    "PivotDiagnosis",
    "PivotDimension",
    "PivotPlan",
    "PivotPlanner",
    "PivotReason",
]
