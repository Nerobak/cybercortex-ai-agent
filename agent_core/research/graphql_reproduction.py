"""GraphQL adapter for the ordinary P4-0F reproduction lifecycle.

The adapter creates only ordinary :class:`ReproductionPlan` records.  It does
not authorize traffic, render GraphQL source, execute requests, or decide that
a finding is confirmed.  Those responsibilities remain with the existing
compiler, execution gate/runtime, GraphQL differential evaluator, and finding
confirmation evaluator.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from types import SimpleNamespace

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.candidates import (
    CandidateBaselineKind,
    CandidateMutationKind,
    ExperimentCandidate,
)
from agent_core.research.compiler import ExperimentCompilerContext
from agent_core.research.graph import GraphAssertion, ResearchGraphRepository
from agent_core.research.graphql import (
    GraphQLCandidateKind,
    GraphQLOperationRecord,
    GraphQLVariableValueSource,
    RegisteredGraphQLOperationTemplate,
    graphql_experiment_semantic_fingerprint,
)
from agent_core.research.outcomes import ExperimentOutcome
from agent_core.research.primitives import (
    DifferentialSelector,
    GraphQLOperationInput,
    GraphQLVariableMutationInput,
    IdentityRelationship,
    PrimitiveStepProposal,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.reproduction import (
    ReproductionPlanner,
    ReproductionPlanningError,
    _identifier,
    _proposal_template,
)
from agent_core.research.state import (
    ExperimentOutcome as StoredExperimentOutcome,
    FindingRecord,
    ReproductionPlan,
    ResearchState,
)
from agent_core.research.types import (
    CleanupStatus,
    DerivationType,
    FindingStatus,
    IdentityEligibility,
    OpaqueIdentifier,
    RelationshipStatus,
    ReproductionIndependentDimension,
    ReproductionKind,
    ReproductionPlanStatus,
    ResearchContract,
    ResearchPredicate,
    SessionLifecycle,
)


GRAPHQL_REPRODUCTION_VERSION = "phase4-graphql-reproduction-v1"
MAX_GRAPHQL_REPRODUCTION_OPTIONS = 8


class GraphQLReproductionOptionSummary(ResearchContract):
    reproduction_id: OpaqueIdentifier
    category: OpaqueIdentifier
    operation_id: OpaqueIdentifier
    field_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=64)
    argument_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=64)
    identity_relationship: OpaqueIdentifier | None = None
    object_relationship: OpaqueIdentifier | None = None
    independence_dimension: ReproductionIndependentDimension
    request_estimate: StrictInt = Field(ge=1, le=10_000)
    risk: OpaqueIdentifier
    evidence_distinction: OpaqueIdentifier


class PublicSafeGraphQLReproductionPacket(ResearchContract):
    """Minimal packet for an optional one-call plan-ID selection."""

    research_id: OpaqueIdentifier
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    finding_id: OpaqueIdentifier
    candidates: tuple[GraphQLReproductionOptionSummary, ...] = Field(
        min_length=2, max_length=MAX_GRAPHQL_REPRODUCTION_OPTIONS
    )

    @model_validator(mode="after")
    def enforce_public_boundary(self) -> "PublicSafeGraphQLReproductionPacket":
        reject_secret_material(
            self.model_dump(mode="json"),
            location="GraphQL reproduction selection packet",
        )
        if len({item.reproduction_id for item in self.candidates}) != len(
            self.candidates
        ):
            raise ValueError("GraphQL reproduction candidate IDs must be unique")
        return self

    def public_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_defaults=True, exclude_none=True)


class GraphQLReproductionSelectionDecision(ResearchContract):
    """A model may select one registered ID and nothing else."""

    decision_id: OpaqueIdentifier
    research_id: OpaqueIdentifier
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    finding_id: OpaqueIdentifier
    selected_reproduction_id: OpaqueIdentifier


class GraphQLReproductionSelectionResult(ResearchContract):
    plan: ReproductionPlan
    model_call_required: StrictBool


class GraphQLReproductionSelector:
    """Resolve a plan ID without accepting replacement bindings."""

    @staticmethod
    def packet(
        state: ResearchState,
        finding: FindingRecord,
        plans: Sequence[ReproductionPlan],
    ) -> PublicSafeGraphQLReproductionPacket:
        if len(plans) < 2:
            raise ValueError("a model packet requires multiple reproduction plans")
        candidates = tuple(
            GraphQLReproductionOptionSummary(
                reproduction_id=plan.reproduction_id,
                category=plan.category,
                operation_id=str(plan.graphql_operation_id),
                field_ids=plan.graphql_field_ids,
                argument_ids=plan.graphql_argument_ids,
                identity_relationship=plan.identity_relationship,
                object_relationship=(
                    "alternate-controlled-test-owned-object"
                    if plan.alternate_controlled_object_id is not None
                    else (
                        "controlled-test-owned-object"
                        if plan.controlled_object_ids
                        else None
                    )
                ),
                independence_dimension=plan.independent_dimension,
                request_estimate=plan.maximum_requests,
                risk="moderate" if plan.state_changing else "low",
                evidence_distinction=_evidence_distinction(plan),
            )
            for plan in plans
        )
        packet = PublicSafeGraphQLReproductionPacket(
            research_id=state.research_id,
            state_revision=state.revision,
            finding_id=finding.finding_id,
            candidates=candidates,
        )
        reject_secret_material(
            packet.model_dump(mode="json"),
            location="GraphQL reproduction selection packet",
        )
        return packet

    @staticmethod
    def select(
        state: ResearchState,
        finding: FindingRecord,
        plans: Sequence[ReproductionPlan],
        decision: GraphQLReproductionSelectionDecision
        | Mapping[str, object]
        | None = None,
    ) -> GraphQLReproductionSelectionResult:
        options = tuple(plans)
        if not options:
            raise ValueError("no GraphQL reproduction plan is available")
        if any(
            item.research_id != state.research_id
            or item.state_revision != state.revision
            or item.finding_id != finding.finding_id
            for item in options
        ):
            raise ValueError("GraphQL reproduction options are stale or inconsistent")
        if len(options) == 1:
            if decision is not None:
                raise ValueError("single GraphQL reproduction option needs no model")
            return GraphQLReproductionSelectionResult(
                plan=options[0], model_call_required=False
            )
        if decision is None:
            raise ValueError("multiple GraphQL reproduction options require selection")
        parsed = (
            decision
            if isinstance(decision, GraphQLReproductionSelectionDecision)
            else GraphQLReproductionSelectionDecision.model_validate(decision)
        )
        if (
            parsed.research_id != state.research_id
            or parsed.state_revision != state.revision
            or parsed.finding_id != finding.finding_id
        ):
            raise ValueError("GraphQL reproduction selection is stale")
        matches = [
            item
            for item in options
            if item.reproduction_id == parsed.selected_reproduction_id
        ]
        if len(matches) != 1:
            raise ValueError("GraphQL reproduction selection is unknown")
        return GraphQLReproductionSelectionResult(
            plan=matches[0].model_copy(
                update={"model_decision_id": parsed.decision_id}
            ),
            model_call_required=True,
        )


class GraphQLReproductionPlanner(ReproductionPlanner):
    """Create GraphQL-safe options that remain ordinary reproduction plans."""

    def plan(
        self,
        finding: FindingRecord,
        state: ResearchState,
        source_experiment: object,
        source_outcome: StoredExperimentOutcome | ExperimentOutcome,
        *,
        registry: object | None = None,
        confirmation_policy: object,
        budget_manager: ResearchBudgetManager | None = None,
        available_controlled_context: object | None = None,
        compiler_context: ExperimentCompilerContext | None = None,
        graph: object | None = None,
    ) -> tuple[ReproductionPlan, ...]:
        del available_controlled_context
        if compiler_context is None:
            raise ReproductionPlanningError("graphql_compiler_context_missing")
        source = _require_graphql_source(source_experiment)
        stored_source = _validate_source_lifecycle(
            finding, state, source_experiment, source_outcome
        )
        operation, surface, source_template = _validate_current_semantics(
            finding,
            state,
            source_experiment,
            source,
            compiler_context,
        )
        _validate_controlled_relationships(
            finding,
            state,
            source.candidate_kind,
            primary_identity_id=(
                source_experiment.identity_context.primary_identity_id
            ),
            comparison_identity_id=(
                source_experiment.identity_context.comparison_identity_id
            ),
        )
        _validate_controlled_sessions(state, source_experiment)
        _validate_cross_surface(finding, source.candidate_kind, graph)
        _validate_mutation_reproduction(
            finding,
            state,
            source_experiment,
            source_template,
            compiler_context,
            confirmation_policy,
        )
        if (
            finding.confirmation_policy_reference
            != confirmation_policy.policy_reference
        ):
            raise ReproductionPlanningError("confirmation_policy_mismatch")
        kind = _reproduction_kind(source.candidate_kind)
        if not confirmation_policy.supports(kind, source_experiment.state_changing):
            raise ReproductionPlanningError("confirmation_profile_not_applicable")
        if registry is not None:
            for step in source_experiment.primitive_steps:
                registry.resolve(step.primitive_name)
        estimate = source_experiment.request_estimate.total_reservation
        if estimate < 1:
            raise ReproductionPlanningError("reproduction_requires_target_request")
        if estimate > confirmation_policy.maximum_requests:
            raise ReproductionPlanningError("reproduction_request_ceiling_exceeded")
        if any(
            item.finding_id == finding.finding_id
            and item.status is ReproductionPlanStatus.planned
            for item in state.reproduction_plans
        ):
            raise ReproductionPlanningError("reproduction_already_planned")
        completed = sum(
            item.finding_id == finding.finding_id
            for item in state.reproduction_outcomes
        )
        if completed >= confirmation_policy.maximum_attempts:
            raise ReproductionPlanningError("reproduction_attempt_ceiling_exceeded")
        if budget_manager is not None:
            decision = budget_manager.check_reproduction(
                state,
                finding_id=finding.finding_id,
                confirmation_policy=confirmation_policy,
                estimated_requests=estimate,
                state_changing=source_experiment.state_changing,
            )
            if not decision.allowed:
                reason = decision.reason.value if decision.reason else "denied"
                raise ReproductionPlanningError(reason)

        option_specs: list[
            tuple[
                ReproductionIndependentDimension,
                RegisteredGraphQLOperationTemplate,
                tuple[PrimitiveStepProposal, ...],
                str | None,
                str | None,
                str | None,
            ]
        ] = [
            (
                ReproductionIndependentDimension.fresh_runtime_authorization,
                source_template,
                tuple(
                    PrimitiveStepProposal(step_id=item.step_id, input=item.input)
                    for item in source_experiment.primitive_steps
                ),
                None,
                source_experiment.identity_context.primary_session_ref_id,
                source_experiment.identity_context.comparison_session_ref_id,
            )
        ]
        alternate = _alternate_object_option(
            finding, state, source_experiment, source_template
        )
        if alternate is not None:
            option_specs.append(alternate)
        equivalent = _equivalent_template_option(
            source_experiment, source_template, compiler_context
        )
        if equivalent is not None:
            option_specs.append(equivalent)
        fresh_session = _fresh_session_option(state, source_experiment, source_template)
        if fresh_session is not None:
            option_specs.append(fresh_session)

        plans = tuple(
            self._build_plan(
                finding=finding,
                state=state,
                source_experiment=source_experiment,
                source_outcome=stored_source,
                source=source,
                operation=operation,
                surface_id=surface.graphql_surface_id,
                source_template=source_template,
                confirmation_policy=confirmation_policy,
                completed=completed,
                estimate=estimate,
                dimension=dimension,
                selected_template=selected_template,
                primitive_steps=primitive_steps,
                alternate_object_id=alternate_object_id,
                primary_session_id=primary_session_id,
                comparison_session_id=comparison_session_id,
            )
            for (
                dimension,
                selected_template,
                primitive_steps,
                alternate_object_id,
                primary_session_id,
                comparison_session_id,
            ) in option_specs[:MAX_GRAPHQL_REPRODUCTION_OPTIONS]
        )
        if len(plans) > 1 and budget_manager is not None:
            selection_budget = budget_manager.check_reproduction(
                state,
                finding_id=finding.finding_id,
                confirmation_policy=confirmation_policy,
                estimated_requests=estimate,
                state_changing=source_experiment.state_changing,
                model_calls=1,
            )
            if not selection_budget.allowed:
                reason = (
                    selection_budget.reason.value
                    if selection_budget.reason is not None
                    else "denied"
                )
                raise ReproductionPlanningError(reason)
        return plans

    @staticmethod
    def _build_plan(
        *,
        finding: FindingRecord,
        state: ResearchState,
        source_experiment: object,
        source_outcome: StoredExperimentOutcome,
        source: "_GraphQLSource",
        operation: GraphQLOperationRecord,
        surface_id: str,
        source_template: RegisteredGraphQLOperationTemplate,
        confirmation_policy: object,
        completed: int,
        estimate: int,
        dimension: ReproductionIndependentDimension,
        selected_template: RegisteredGraphQLOperationTemplate,
        primitive_steps: tuple[PrimitiveStepProposal, ...],
        alternate_object_id: str | None,
        primary_session_id: str | None,
        comparison_session_id: str | None,
    ) -> ReproductionPlan:
        variant = "|".join(
            item
            for item in (
                selected_template.template_id,
                alternate_object_id,
                primary_session_id,
                comparison_session_id,
            )
            if item is not None
        )
        reproduction_id = _identifier(
            "graphql-reproduction",
            finding.finding_id,
            source_experiment.experiment_id,
            completed + 1,
            dimension.value,
            variant,
        )
        provenance_id = _identifier(
            "graphql-reproduction-plan-provenance", reproduction_id
        )
        template = _proposal_template(
            source_experiment,
            reproduction_id=reproduction_id,
            provenance_id=provenance_id,
            state_revision=state.revision,
        ).model_copy(
            update={
                "baseline_reference_id": selected_template.template_id,
                "mutation_controlled_object_id": (
                    alternate_object_id
                    or (
                        source_experiment.mutation.controlled_object_ids[0]
                        if source_experiment.mutation.controlled_object_ids
                        else None
                    )
                ),
                "primary_session_ref_id": primary_session_id,
                "comparison_session_ref_id": comparison_session_id,
                "primitive_steps": primitive_steps,
            }
        )
        plan = ReproductionPlan(
            reproduction_id=reproduction_id,
            finding_id=finding.finding_id,
            source_experiment_id=source_experiment.experiment_id,
            source_fingerprint=source_experiment.fingerprint,
            source_outcome_id=source_outcome.outcome_id,
            source_hypothesis_id=source_experiment.hypothesis_id,
            research_id=state.research_id,
            state_revision=state.revision,
            category=finding.category,
            reproduction_kind=_reproduction_kind(source.candidate_kind),
            independent_dimension=dimension,
            target_id=source_experiment.target.target_id,
            surface_id=source_experiment.target.surface_id,
            endpoint_id=source_experiment.target.endpoint_id,
            graphql_candidate_kind=source.candidate_kind,
            graphql_surface_id=surface_id,
            graphql_operation_id=operation.operation_id,
            source_graphql_operation_template_id=source_template.template_id,
            graphql_operation_template_id=selected_template.template_id,
            graphql_field_ids=finding.graphql_field_ids,
            graphql_argument_ids=finding.graphql_argument_ids,
            graphql_selection_fingerprint=operation.selection_fingerprint,
            graphql_semantic_fingerprint=str(finding.graphql_semantic_fingerprint),
            primary_identity_id=source_experiment.identity_context.primary_identity_id,
            comparison_identity_id=(
                source_experiment.identity_context.comparison_identity_id
            ),
            identity_relationship=(
                source_experiment.identity_context.relationship.value
                if source_experiment.identity_context.relationship is not None
                else None
            ),
            controlled_object_ids=finding.controlled_object_ids,
            alternate_controlled_object_id=alternate_object_id,
            required_evidence_predicates=tuple(
                item.predicate_reference for item in source_experiment.required_evidence
            ),
            maximum_requests=min(estimate, confirmation_policy.maximum_requests),
            maximum_attempts=confirmation_policy.maximum_attempts,
            state_changing=source_experiment.state_changing,
            cleanup_required=source_experiment.cleanup.required,
            cleanup_reference=source_experiment.cleanup.cleanup_reference,
            confirmation_policy_reference=confirmation_policy.policy_reference,
            confirmation_policy_fingerprint=confirmation_policy.fingerprint,
            provenance_id=provenance_id,
            expires_at=source_experiment.expires_at,
            proposal_template=template,
            trace_events=("GRAPHQL_REPRODUCTION_PLAN",),
        )
        reject_secret_material(
            plan.model_dump(mode="json"), location="reproduction plan"
        )
        return plan

    @staticmethod
    def materialize_candidate(
        plan: ReproductionPlan,
        state: ResearchState,
        compiler_context: ExperimentCompilerContext,
    ) -> ExperimentCandidate:
        """Project a plan into the ordinary reference-only candidate contract."""

        validate_graphql_reproduction_context(plan, state, compiler_context)
        template = _one_template(
            compiler_context, str(plan.graphql_operation_template_id)
        )
        inputs = tuple(item.input for item in plan.proposal_template.primitive_steps)
        variable_bindings = tuple(
            binding
            for item in inputs
            for binding in (
                *getattr(item, "variable_bindings", ()),
                *(
                    (item.binding,)
                    if isinstance(item, GraphQLVariableMutationInput)
                    and item.binding is not None
                    else ()
                ),
            )
        )
        variable_bindings = tuple(
            {
                (item.variable_id, item.argument_id, item.value_reference): item
                for item in variable_bindings
            }.values()
        )
        mutation_input = next(
            (item for item in inputs if isinstance(item, GraphQLVariableMutationInput)),
            None,
        )
        selected_object_id = plan.alternate_controlled_object_id or next(
            (
                item.object_id
                for item in state.objects
                if item.object_id in plan.controlled_object_ids
                and item.owner_identity_id == plan.primary_identity_id
            ),
            next(iter(plan.controlled_object_ids), None),
        )
        selected_object = next(
            (item for item in state.objects if item.object_id == selected_object_id),
            None,
        )
        primitive_kind = (
            "graphql_variable_mutation"
            if mutation_input is not None
            else "graphql_operation"
        )
        candidate = ExperimentCandidate(
            candidate_id=_identifier(
                "graphql-reproduction-candidate", plan.reproduction_id
            ),
            research_id=state.research_id,
            state_revision=state.revision,
            hypothesis_id=plan.source_hypothesis_id,
            capability=plan.proposal_template.capability,
            primitive_kind=primitive_kind,
            target_id=plan.target_id,
            surface_id=plan.surface_id,
            endpoint_id=str(plan.endpoint_id),
            operation_id=plan.graphql_operation_id,
            primary_identity_id=plan.primary_identity_id,
            comparison_identity_id=plan.comparison_identity_id,
            identity_relationship=(
                IdentityRelationship(plan.identity_relationship)
                if plan.identity_relationship is not None
                else None
            ),
            controlled_object_id=selected_object_id,
            ownership_evidence_references=(
                selected_object.evidence_references
                if selected_object is not None
                else ()
            ),
            graphql_candidate_kind=plan.graphql_candidate_kind,
            graphql_surface_id=plan.graphql_surface_id,
            graphql_operation_template_id=plan.graphql_operation_template_id,
            graphql_field_id=(
                plan.graphql_field_ids[0] if plan.graphql_field_ids else None
            ),
            graphql_argument_id=(
                str(mutation_input.argument_id)
                if mutation_input is not None
                else (
                    plan.graphql_argument_ids[0] if plan.graphql_argument_ids else None
                )
            ),
            graphql_variable_id=(
                str(mutation_input.variable_id)
                if mutation_input is not None
                else (variable_bindings[0].variable_id if variable_bindings else None)
            ),
            graphql_variable_bindings=variable_bindings,
            selection_fingerprint=plan.graphql_selection_fingerprint,
            graphql_state_change_class=template.state_change_class,
            workflow_id=template.workflow_id,
            safe_mutation_id=(
                str(mutation_input.safe_mutation_id)
                if mutation_input is not None
                else None
            ),
            cleanup_required=plan.cleanup_required,
            cleanup_reference=plan.cleanup_reference,
            baseline_kind=CandidateBaselineKind.registered_graphql_operation,
            mutation_kind=_candidate_mutation_kind(plan.graphql_candidate_kind),
            expected_evidence_class=DifferentialSelector(
                plan.proposal_template.required_evidence[0].selector
            ),
            minimum_requests=plan.maximum_requests,
            worst_case_requests=plan.maximum_requests,
            risk_class=(RiskLevel.moderate if plan.state_changing else RiskLevel.low),
            information_predicates=plan.required_evidence_predicates,
            evidence_references=tuple(
                sorted(
                    {
                        *template.evidence_references,
                        *next(
                            item
                            for item in state.findings
                            if item.finding_id == plan.finding_id
                        ).evidence_references,
                    }
                )
            ),
            provenance_references=(template.provenance_id,),
            fingerprint_seed=_digest(
                {
                    "reproduction_id": plan.reproduction_id,
                    "dimension": plan.independent_dimension.value,
                    "template": plan.graphql_operation_template_id,
                }
            ),
        )
        reject_secret_material(
            candidate.model_dump(mode="json"),
            location="GraphQL reproduction candidate",
        )
        return candidate


class _GraphQLSource:
    __slots__ = ("candidate_kind", "operation_id", "template_id")

    def __init__(
        self,
        candidate_kind: GraphQLCandidateKind,
        operation_id: str,
        template_id: str,
    ) -> None:
        self.candidate_kind = candidate_kind
        self.operation_id = operation_id
        self.template_id = template_id


def _require_graphql_source(source_experiment: object) -> _GraphQLSource:
    inputs = tuple(
        item.input
        for item in source_experiment.primitive_steps
        if isinstance(item.input, (GraphQLOperationInput, GraphQLVariableMutationInput))
    )
    operation_ids = {str(item.operation_id) for item in inputs}
    template_ids = {
        str(item.operation_template_id)
        for item in inputs
        if item.operation_template_id is not None
    }
    kinds = {item.candidate_kind for item in inputs if item.candidate_kind is not None}
    if (
        not inputs
        or len(operation_ids) != 1
        or len(template_ids) != 1
        or len(kinds) != 1
    ):
        raise ReproductionPlanningError("graphql_source_bindings_incomplete")
    return _GraphQLSource(
        next(iter(kinds)), next(iter(operation_ids)), next(iter(template_ids))
    )


def _validate_source_lifecycle(
    finding: FindingRecord,
    state: ResearchState,
    source_experiment: object,
    source_outcome: object,
) -> StoredExperimentOutcome:
    if finding.status is not FindingStatus.candidate:
        raise ReproductionPlanningError("finding_not_candidate")
    required = (
        finding.research_id,
        finding.source_experiment_fingerprint,
        finding.source_outcome_id,
        finding.source_authorization_reference,
        finding.graphql_operation_id,
        finding.graphql_operation_template_id,
        finding.graphql_candidate_kind,
        finding.graphql_selection_fingerprint,
        finding.graphql_semantic_fingerprint,
    )
    if any(item is None for item in required) or not finding.evidence_references:
        raise ReproductionPlanningError("candidate_contract_incomplete")
    if finding.research_id != state.research_id:
        raise ReproductionPlanningError("finding_research_mismatch")
    if source_experiment.experiment_id != finding.candidate_experiment_id:
        raise ReproductionPlanningError("source_experiment_mismatch")
    if source_experiment.fingerprint != finding.source_experiment_fingerprint:
        raise ReproductionPlanningError("source_fingerprint_mismatch")
    if source_outcome.outcome_id != finding.source_outcome_id:
        raise ReproductionPlanningError("source_outcome_mismatch")
    if source_outcome.experiment_id != source_experiment.experiment_id:
        raise ReproductionPlanningError("source_outcome_experiment_mismatch")
    stored = tuple(
        item
        for item in state.experiment_outcomes
        if item.outcome_id == finding.source_outcome_id
    )
    if len(stored) != 1:
        raise ReproductionPlanningError("source_outcome_not_current")
    result = stored[0]
    if (
        result.experiment_id != source_experiment.experiment_id
        or finding.finding_id not in result.candidate_finding_ids
        or not set(finding.evidence_references).issubset(result.evidence_references)
    ):
        raise ReproductionPlanningError("source_vulnerable_evidence_invalid")
    return result


def _validate_current_semantics(
    finding: FindingRecord,
    state: ResearchState,
    source_experiment: object,
    source: _GraphQLSource,
    context: ExperimentCompilerContext,
) -> tuple[GraphQLOperationRecord, object, RegisteredGraphQLOperationTemplate]:
    operations = tuple(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
        and item.operation_id == source.operation_id
    )
    if len(operations) != 1:
        raise ReproductionPlanningError("graphql_operation_unavailable")
    operation = operations[0]
    surfaces = tuple(
        item
        for item in state.graphql_surfaces
        if item.graphql_surface_id == operation.graphql_surface_id
    )
    if len(surfaces) != 1:
        raise ReproductionPlanningError("graphql_surface_unavailable")
    surface = surfaces[0]
    if (
        surface.target_id != finding.target_id
        or surface.surface_id != finding.surface_id
        or surface.endpoint_id != finding.endpoint_id
        or operation.operation_id != finding.graphql_operation_id
        or source.candidate_kind is not finding.graphql_candidate_kind
        or operation.selection_fingerprint != finding.graphql_selection_fingerprint
        or source.template_id != finding.graphql_operation_template_id
        or source_experiment.baseline.reference_id != source.template_id
    ):
        raise ReproductionPlanningError("graphql_schema_changed_replan_required")
    source_template = _one_template(context, source.template_id)
    if (
        source_template.operation_id != operation.operation_id
        or source_template.graphql_surface_id != surface.graphql_surface_id
        or source_template.endpoint_id != surface.endpoint_id
        or source_template.selection_fingerprint != operation.selection_fingerprint
        or source_template.document_fingerprint != operation.document_fingerprint
    ):
        raise ReproductionPlanningError("graphql_schema_changed_replan_required")
    registered_fields = {
        field_id
        for path in source_template.normalized_structure.selection_paths
        for field_id in path.field_ids
    }
    if not set(finding.graphql_field_ids).issubset(registered_fields):
        raise ReproductionPlanningError("graphql_selection_changed_replan_required")
    fields = {item.field_id: item for item in state.graphql_fields}
    arguments = {item.argument_id: item for item in state.graphql_arguments}
    if any(field_id not in fields for field_id in finding.graphql_field_ids):
        raise ReproductionPlanningError("graphql_field_semantics_stale")
    if any(
        argument_id not in arguments
        or arguments[argument_id].field_id not in registered_fields
        for argument_id in finding.graphql_argument_ids
    ):
        raise ReproductionPlanningError("graphql_argument_semantics_stale")
    try:
        current_fingerprint = graphql_experiment_semantic_fingerprint(
            state, source_experiment
        )
    except ValueError as exc:
        raise ReproductionPlanningError(
            "graphql_semantics_unavailable_replan_required"
        ) from exc
    if current_fingerprint != finding.graphql_semantic_fingerprint:
        raise ReproductionPlanningError("graphql_semantics_changed_replan_required")
    return operation, surface, source_template


def _validate_controlled_relationships(
    finding: FindingRecord,
    state: ResearchState,
    kind: GraphQLCandidateKind,
    *,
    primary_identity_id: str | None,
    comparison_identity_id: str | None,
) -> None:
    identities = {item.identity_id: item for item in state.identities}
    provenance = {item.provenance_id for item in state.provenance}
    selected = tuple(
        identities.get(identity_id) for identity_id in finding.controlled_identity_ids
    )
    if any(
        item is None
        or not item.controlled
        or item.eligibility is not IdentityEligibility.eligible
        or item.provenance_id not in provenance
        for item in selected
    ):
        raise ReproductionPlanningError("controlled_identity_context_stale")
    primary = identities.get(primary_identity_id) if primary_identity_id else None
    comparison = (
        identities.get(comparison_identity_id) if comparison_identity_id else None
    )
    objects = {item.object_id: item for item in state.objects}
    selected_objects = tuple(
        objects.get(object_id) for object_id in finding.controlled_object_ids
    )
    evidence_ids = {item.evidence_id for item in state.evidence}
    if any(
        item is None
        or not item.test_owned
        or not item.evidence_references
        or not set(item.evidence_references).issubset(evidence_ids)
        for item in selected_objects
    ):
        raise ReproductionPlanningError("controlled_object_context_stale")
    relationship = finding.controlled_identity_relationship
    if kind is GraphQLCandidateKind.authentication:
        if primary is None or comparison is not None:
            raise ReproductionPlanningError("authentication_identity_context_stale")
        return
    if kind in {
        GraphQLCandidateKind.role_bound,
        GraphQLCandidateKind.field_authorization,
    }:
        if (
            primary is None
            or comparison is None
            or primary.role_reference is None
            or comparison.role_reference is None
            or primary.role_reference == comparison.role_reference
            or relationship != IdentityRelationship.different_controlled_role.value
        ):
            raise ReproductionPlanningError("controlled_role_relationship_stale")
    if kind is GraphQLCandidateKind.operation_authorization:
        role_valid = (
            primary is not None
            and comparison is not None
            and primary.role_reference is not None
            and comparison.role_reference is not None
            and primary.role_reference != comparison.role_reference
            and relationship == IdentityRelationship.different_controlled_role.value
        )
        tenant_valid = (
            primary is not None
            and comparison is not None
            and primary.tenant_reference is not None
            and comparison.tenant_reference is not None
            and primary.tenant_reference != comparison.tenant_reference
            and relationship == IdentityRelationship.different_controlled_tenant.value
        )
        if not (role_valid or tenant_valid):
            raise ReproductionPlanningError("controlled_operation_relationship_stale")
    if kind in {
        GraphQLCandidateKind.object_authorization,
        GraphQLCandidateKind.ownership,
        GraphQLCandidateKind.mutation_authorization,
        GraphQLCandidateKind.workflow_mutation,
        GraphQLCandidateKind.nested_resolver,
        GraphQLCandidateKind.cross_surface,
    }:
        if (
            primary is None
            or comparison is None
            or not selected_objects
            or not any(
                item.owner_identity_id == primary.identity_id
                for item in selected_objects
                if item is not None
            )
            or comparison.identity_id == primary.identity_id
            or relationship != IdentityRelationship.owner_non_owner.value
        ):
            raise ReproductionPlanningError("controlled_ownership_relationship_stale")
    if kind is GraphQLCandidateKind.nested_resolver and (
        primary is None
        or comparison is None
        or not any(
            item.owner_identity_id == comparison.identity_id
            for item in selected_objects
            if item is not None
        )
    ):
        raise ReproductionPlanningError("controlled_nested_relationship_stale")
    if kind is GraphQLCandidateKind.tenant_bound:
        controlled_object = next(
            (
                item
                for item in selected_objects
                if item is not None
                and primary is not None
                and item.owner_identity_id == primary.identity_id
            ),
            None,
        )
        if (
            primary is None
            or comparison is None
            or controlled_object is None
            or controlled_object.tenant_reference is None
            or primary.tenant_reference != controlled_object.tenant_reference
            or comparison.tenant_reference is None
            or comparison.tenant_reference == controlled_object.tenant_reference
            or relationship != IdentityRelationship.different_controlled_tenant.value
        ):
            raise ReproductionPlanningError("controlled_tenant_relationship_stale")


def _validate_controlled_sessions(
    state: ResearchState,
    source_experiment: object,
) -> None:
    context = source_experiment.identity_context
    for identity_id, required_session_id in (
        (context.primary_identity_id, context.primary_session_ref_id),
        (context.comparison_identity_id, context.comparison_session_ref_id),
    ):
        if identity_id is None:
            continue
        active = tuple(
            item
            for item in state.session_refs
            if item.identity_id == identity_id
            and item.lifecycle is SessionLifecycle.active
            and (
                required_session_id is None
                or item.session_ref_id == required_session_id
            )
        )
        if not active:
            raise ReproductionPlanningError("controlled_session_context_stale")


def _validate_cross_surface(
    finding: FindingRecord,
    kind: GraphQLCandidateKind,
    graph: object | None,
) -> None:
    if kind is not GraphQLCandidateKind.cross_surface:
        return
    if graph is None:
        raise ReproductionPlanningError("cross_surface_evidence_unavailable")
    assertions = (
        graph.store.query_graph_assertions(str(finding.research_id), limit=100)
        if isinstance(graph, ResearchGraphRepository)
        else tuple(graph)
    )
    relevant = {
        finding.finding_id,
        str(finding.graphql_operation_id),
        *finding.controlled_object_ids,
    }
    relations = {
        item.relation
        for item in assertions
        if isinstance(item, GraphAssertion)
        and item.derivation_type is DerivationType.deterministic
        and item.status
        not in {
            RelationshipStatus.proposed,
            RelationshipStatus.rejected,
            RelationshipStatus.superseded,
        }
        and {item.source.entity_id, item.target.entity_id}.intersection(relevant)
    }
    if not {
        ResearchPredicate.references_same_object,
        ResearchPredicate.crosses_surface,
    }.issubset(relations):
        raise ReproductionPlanningError("cross_surface_relationships_stale")


def _validate_mutation_reproduction(
    finding: FindingRecord,
    state: ResearchState,
    source_experiment: object,
    template: RegisteredGraphQLOperationTemplate,
    context: ExperimentCompilerContext,
    policy: object,
) -> None:
    if not source_experiment.state_changing:
        return
    if not bool(getattr(policy, "state_changing_confirmation_permitted", False)):
        raise ReproductionPlanningError("reproduction_state_change_forbidden")
    if not bool(getattr(policy, "cleanup_required", False)):
        raise ReproductionPlanningError("mutation_cleanup_policy_required")
    if (
        finding.cleanup_status is not CleanupStatus.completed
        or not source_experiment.cleanup.required
        or source_experiment.cleanup.cleanup_reference is None
    ):
        raise ReproductionPlanningError("mutation_baseline_not_restored")
    cleanup = tuple(
        item
        for item in context.cleanup_definitions
        if item.cleanup_reference == source_experiment.cleanup.cleanup_reference
    )
    if len(cleanup) != 1:
        raise ReproductionPlanningError("mutation_cleanup_unavailable")
    if template.workflow_id is not None:
        workflows = tuple(
            item for item in state.workflows if item.workflow_id == template.workflow_id
        )
        if len(workflows) != 1 or not workflows[0].evidence_references:
            raise ReproductionPlanningError("mutation_workflow_state_stale")
        required_states = {
            reference
            for step in workflows[0].steps
            if step.state_changing
            for reference in (
                step.state_before_reference,
                step.state_after_reference,
            )
            if reference is not None
        }
        if len(required_states) < 2 or not required_states.issubset(
            context.state_references
        ):
            raise ReproductionPlanningError("mutation_clean_state_unavailable")


def validate_graphql_reproduction_context(
    plan: ReproductionPlan,
    state: ResearchState,
    compiler_context: ExperimentCompilerContext,
    *,
    source_experiment: object | None = None,
) -> None:
    """Fail closed if a persisted GraphQL plan is stale before compilation."""

    if plan.graphql_operation_id is None:
        raise ReproductionPlanningError("plan_is_not_graphql")
    finding = next(
        (item for item in state.findings if item.finding_id == plan.finding_id), None
    )
    if finding is None or finding.status is not FindingStatus.reproducing:
        raise ReproductionPlanningError("finding_not_reproducing")
    operation = next(
        (
            item
            for item in state.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
            and item.operation_id == plan.graphql_operation_id
        ),
        None,
    )
    if (
        operation is None
        or operation.selection_fingerprint != plan.graphql_selection_fingerprint
        or finding.graphql_semantic_fingerprint != plan.graphql_semantic_fingerprint
        or finding.graphql_operation_template_id
        != plan.source_graphql_operation_template_id
    ):
        raise ReproductionPlanningError("graphql_schema_changed_replan_required")
    source_template = _one_template(
        compiler_context, str(plan.source_graphql_operation_template_id)
    )
    selected_template = _one_template(
        compiler_context, str(plan.graphql_operation_template_id)
    )
    for template in (source_template, selected_template):
        if (
            template.operation_id != operation.operation_id
            or template.graphql_surface_id != plan.graphql_surface_id
            or template.endpoint_id != plan.endpoint_id
            or template.selection_fingerprint != plan.graphql_selection_fingerprint
            or template.document_fingerprint != operation.document_fingerprint
        ):
            raise ReproductionPlanningError("graphql_schema_changed_replan_required")
    registered_fields = {
        field_id
        for path in selected_template.normalized_structure.selection_paths
        for field_id in path.field_ids
    }
    if not set(plan.graphql_field_ids).issubset(registered_fields):
        raise ReproductionPlanningError("graphql_selection_changed_replan_required")
    semantic_subject = source_experiment or SimpleNamespace(
        primitive_steps=plan.proposal_template.primitive_steps,
        hypothesis_id=plan.source_hypothesis_id,
    )
    try:
        current = graphql_experiment_semantic_fingerprint(state, semantic_subject)
    except ValueError as exc:
        raise ReproductionPlanningError(
            "graphql_semantics_unavailable_replan_required"
        ) from exc
    if current != plan.graphql_semantic_fingerprint:
        raise ReproductionPlanningError("graphql_semantics_changed_replan_required")
    _validate_controlled_relationships(
        finding,
        state,
        GraphQLCandidateKind(plan.graphql_candidate_kind),
        primary_identity_id=plan.primary_identity_id,
        comparison_identity_id=plan.comparison_identity_id,
    )
    _validate_controlled_sessions(
        state,
        SimpleNamespace(
            identity_context=SimpleNamespace(
                primary_identity_id=plan.primary_identity_id,
                comparison_identity_id=plan.comparison_identity_id,
                primary_session_ref_id=(plan.proposal_template.primary_session_ref_id),
                comparison_session_ref_id=(
                    plan.proposal_template.comparison_session_ref_id
                ),
            )
        ),
    )
    if plan.alternate_controlled_object_id is not None:
        alternate = next(
            (
                item
                for item in state.objects
                if item.object_id == plan.alternate_controlled_object_id
            ),
            None,
        )
        source_object = next(
            (
                item
                for item in state.objects
                if item.object_id in plan.controlled_object_ids
            ),
            None,
        )
        if (
            alternate is None
            or source_object is None
            or not alternate.test_owned
            or not alternate.evidence_references
            or alternate.owner_identity_id != source_object.owner_identity_id
            or alternate.tenant_reference != source_object.tenant_reference
        ):
            raise ReproductionPlanningError("alternate_controlled_object_stale")
    if plan.cleanup_required:
        if plan.cleanup_reference is None or not any(
            item.cleanup_reference == plan.cleanup_reference
            for item in compiler_context.cleanup_definitions
        ):
            raise ReproductionPlanningError("mutation_cleanup_unavailable")


def _alternate_object_option(
    finding: FindingRecord,
    state: ResearchState,
    source_experiment: object,
    source_template: RegisteredGraphQLOperationTemplate,
) -> (
    tuple[
        ReproductionIndependentDimension,
        RegisteredGraphQLOperationTemplate,
        tuple[PrimitiveStepProposal, ...],
        str | None,
        str | None,
        str | None,
    ]
    | None
):
    if len(finding.controlled_object_ids) != 1:
        return None
    original = next(
        (
            item
            for item in state.objects
            if item.object_id == finding.controlled_object_ids[0]
        ),
        None,
    )
    if original is None:
        return None
    alternate = next(
        (
            item
            for item in sorted(state.objects, key=lambda value: value.object_id)
            if item.object_id != original.object_id
            and item.test_owned
            and item.evidence_references
            and item.target_id == original.target_id
            and item.surface_id == original.surface_id
            and item.owner_identity_id == original.owner_identity_id
            and item.tenant_reference == original.tenant_reference
        ),
        None,
    )
    if alternate is None:
        return None
    argument_semantics = {
        item.argument_id: item.object_reference_semantics.research_object_id
        for item in state.graphql_arguments
    }
    replaced = False
    steps: list[PrimitiveStepProposal] = []
    for step in source_experiment.primitive_steps:
        value = step.input
        if isinstance(value, GraphQLOperationInput):
            bindings = tuple(
                (
                    binding.model_copy(update={"value_reference": alternate.object_id})
                    if binding.value_source
                    is GraphQLVariableValueSource.controlled_object
                    and binding.value_reference == original.object_id
                    and argument_semantics.get(binding.argument_id)
                    == alternate.object_id
                    else binding
                )
                for binding in value.variable_bindings
            )
            replaced = replaced or bindings != value.variable_bindings
            value = value.model_copy(update={"variable_bindings": bindings})
        steps.append(PrimitiveStepProposal(step_id=step.step_id, input=value))
    if not replaced:
        return None
    return (
        ReproductionIndependentDimension.different_owned_object,
        source_template,
        tuple(steps),
        alternate.object_id,
        source_experiment.identity_context.primary_session_ref_id,
        source_experiment.identity_context.comparison_session_ref_id,
    )


def _equivalent_template_option(
    source_experiment: object,
    source_template: RegisteredGraphQLOperationTemplate,
    context: ExperimentCompilerContext,
) -> (
    tuple[
        ReproductionIndependentDimension,
        RegisteredGraphQLOperationTemplate,
        tuple[PrimitiveStepProposal, ...],
        str | None,
        str | None,
        str | None,
    ]
    | None
):
    alternate = next(
        (
            item
            for item in sorted(
                context.graphql_operation_templates,
                key=lambda value: value.template_id,
            )
            if item.template_id != source_template.template_id
            and item.operation_id == source_template.operation_id
            and item.operation_type is source_template.operation_type
            and item.graphql_surface_id == source_template.graphql_surface_id
            and item.endpoint_id == source_template.endpoint_id
            and item.selection_fingerprint == source_template.selection_fingerprint
            and item.document_fingerprint == source_template.document_fingerprint
            and item.normalized_structure == source_template.normalized_structure
            and item.argument_bindings == source_template.argument_bindings
            and item.state_change_class is source_template.state_change_class
        ),
        None,
    )
    if alternate is None:
        return None
    steps = tuple(
        PrimitiveStepProposal(
            step_id=step.step_id,
            input=(
                step.input.model_copy(
                    update={"operation_template_id": alternate.template_id}
                )
                if isinstance(
                    step.input,
                    (GraphQLOperationInput, GraphQLVariableMutationInput),
                )
                else step.input
            ),
        )
        for step in source_experiment.primitive_steps
    )
    return (
        ReproductionIndependentDimension.equivalent_endpoint_representation,
        alternate,
        steps,
        None,
        source_experiment.identity_context.primary_session_ref_id,
        source_experiment.identity_context.comparison_session_ref_id,
    )


def _fresh_session_option(
    state: ResearchState,
    source_experiment: object,
    source_template: RegisteredGraphQLOperationTemplate,
) -> (
    tuple[
        ReproductionIndependentDimension,
        RegisteredGraphQLOperationTemplate,
        tuple[PrimitiveStepProposal, ...],
        str | None,
        str | None,
        str | None,
    ]
    | None
):
    identity_context = source_experiment.identity_context
    if identity_context.primary_session_ref_id is None:
        return None
    primary = next(
        (
            item.session_ref_id
            for item in sorted(
                state.session_refs, key=lambda value: value.session_ref_id
            )
            if item.identity_id == identity_context.primary_identity_id
            and item.lifecycle is SessionLifecycle.active
            and item.session_ref_id != identity_context.primary_session_ref_id
        ),
        None,
    )
    if primary is None:
        return None
    comparison = identity_context.comparison_session_ref_id
    if comparison is not None:
        comparison = next(
            (
                item.session_ref_id
                for item in sorted(
                    state.session_refs, key=lambda value: value.session_ref_id
                )
                if item.identity_id == identity_context.comparison_identity_id
                and item.lifecycle is SessionLifecycle.active
                and item.session_ref_id != comparison
            ),
            None,
        )
        if comparison is None:
            return None
    return (
        ReproductionIndependentDimension.fresh_session_binding,
        source_template,
        tuple(
            PrimitiveStepProposal(step_id=item.step_id, input=item.input)
            for item in source_experiment.primitive_steps
        ),
        None,
        primary,
        comparison,
    )


def _one_template(
    context: ExperimentCompilerContext, template_id: str
) -> RegisteredGraphQLOperationTemplate:
    matches = tuple(
        item
        for item in context.graphql_operation_templates
        if item.template_id == template_id
    )
    if len(matches) != 1:
        raise ReproductionPlanningError("graphql_operation_template_unavailable")
    return matches[0]


def _reproduction_kind(kind: GraphQLCandidateKind) -> ReproductionKind:
    if kind is GraphQLCandidateKind.authentication:
        return ReproductionKind.authentication_differential
    if kind is GraphQLCandidateKind.input_validation:
        return ReproductionKind.parameter_mutation
    return ReproductionKind.object_substitution


def _candidate_mutation_kind(
    kind: GraphQLCandidateKind | None,
) -> CandidateMutationKind:
    if kind is GraphQLCandidateKind.input_validation:
        return CandidateMutationKind.graphql_safe_argument_mutation
    if kind in {
        GraphQLCandidateKind.field_authorization,
        GraphQLCandidateKind.nested_resolver,
    }:
        return CandidateMutationKind.graphql_field_differential
    if kind in {
        GraphQLCandidateKind.mutation_authorization,
        GraphQLCandidateKind.workflow_mutation,
    }:
        return CandidateMutationKind.graphql_state_transition
    if kind in {
        GraphQLCandidateKind.object_authorization,
        GraphQLCandidateKind.ownership,
        GraphQLCandidateKind.tenant_bound,
        GraphQLCandidateKind.cross_surface,
    }:
        return CandidateMutationKind.graphql_object_substitution
    return CandidateMutationKind.graphql_identity_differential


def _evidence_distinction(plan: ReproductionPlan) -> str:
    return {
        ReproductionIndependentDimension.fresh_runtime_authorization: (
            "fresh-authorization-and-evidence"
        ),
        ReproductionIndependentDimension.different_owned_object: (
            "different-controlled-test-owned-object"
        ),
        ReproductionIndependentDimension.equivalent_endpoint_representation: (
            "equivalent-registered-operation-representation"
        ),
        ReproductionIndependentDimension.fresh_session_binding: (
            "fresh-controlled-session-binding"
        ),
        ReproductionIndependentDimension.identity_order_reversal: (
            "controlled-identity-order-reversal"
        ),
        ReproductionIndependentDimension.alternate_safe_observation_predicate: (
            "fresh-field-differential"
        ),
    }[plan.independent_dimension]


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "GRAPHQL_REPRODUCTION_VERSION",
    "GraphQLReproductionOptionSummary",
    "GraphQLReproductionPlanner",
    "GraphQLReproductionSelectionDecision",
    "GraphQLReproductionSelectionResult",
    "GraphQLReproductionSelector",
    "PublicSafeGraphQLReproductionPacket",
    "validate_graphql_reproduction_context",
]
