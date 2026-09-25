"""Deterministic planning and materialization of independent reproductions.

Plans in this module are inert, secret-free records.  They are compiled into the
ordinary :class:`SecurityExperiment` contract and therefore still require the
normal execution gate and runtime.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.compiler import ExperimentCompiler, ExperimentCompilerContext
from agent_core.research.events import (
    FindingStatusChangedPayload,
    ReproductionPlannedPayload,
    ResearchEvent,
    ResearchEventType,
)
from agent_core.research.experiments import (
    BaselineIntent,
    BaselineKind,
    EvidenceIntent,
    ExperimentProposal,
    MutationIntent,
    ReproductionExperiment,
    SecurityExperiment,
)
from agent_core.research.outcomes import (
    ExperimentOutcome,
    ExperimentResultClassification,
)
from agent_core.research.primitives import (
    AuthenticationDifferentialInput,
    DifferentialSelector,
    IdentityRelationship,
    MutationKind,
    ObjectSubstitutionInput,
    ParameterMutationInput,
    PrimitiveStepProposal,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import (
    ExperimentOutcome as StoredExperimentOutcome,
    FindingRecord,
    ProvenanceRecord,
    ReproductionEvidencePredicate,
    ReproductionIndependence,
    ReproductionOutcome,
    ReproductionPlan,
    ReproductionProposalTemplate,
    ResearchState,
)
from agent_core.research.types import (
    CleanupStatus,
    FindingStatus,
    ProvenanceProducerType,
    ReproductionClassification,
    ReproductionIndependentDimension,
    ReproductionKind,
    ReproductionPlanStatus,
)
from agent_core.research.transitions import validate_finding_transition

if TYPE_CHECKING:
    from agent_core.research.confirmation import FindingConfirmationPolicy
    from agent_core.research.registry import ExperimentRegistry
    from agent_core.research.store import ResearchStore


class ReproductionPlanningError(ValueError):
    """A fixed, secret-free refusal to create or materialize a reproduction."""


def _identifier(prefix: str, *values: object) -> str:
    material = "\x1f".join(str(value) for value in values).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


def _classification(value: object) -> ExperimentResultClassification | None:
    candidate = getattr(value, "result_classification", None)
    if isinstance(candidate, ExperimentResultClassification):
        return candidate
    try:
        return ExperimentResultClassification(str(candidate))
    except ValueError:
        return None


def _source_is_vulnerable(
    finding: FindingRecord, source_outcome: StoredExperimentOutcome | ExperimentOutcome
) -> bool:
    classification = _classification(source_outcome)
    return (
        classification is ExperimentResultClassification.vulnerable_signal
        or finding.finding_id in source_outcome.candidate_finding_ids
    )


def _kind(experiment: SecurityExperiment) -> ReproductionKind:
    inputs = tuple(item.input for item in experiment.primitive_steps)
    if any(isinstance(item, ObjectSubstitutionInput) for item in inputs):
        return ReproductionKind.object_substitution
    if any(isinstance(item, AuthenticationDifferentialInput) for item in inputs):
        return ReproductionKind.authentication_differential
    if any(isinstance(item, ParameterMutationInput) for item in inputs):
        return ReproductionKind.parameter_mutation
    raise ReproductionPlanningError("unsupported_reproduction_strategy")


def _proposal_template(
    source: SecurityExperiment,
    *,
    reproduction_id: str,
    provenance_id: str,
    state_revision: int,
) -> ReproductionProposalTemplate:
    mutation = source.mutation
    return ReproductionProposalTemplate(
        proposal_id=_identifier("reproduction-proposal", reproduction_id),
        research_id=source.research_id,
        state_revision=state_revision,
        hypothesis_id=source.hypothesis_id,
        capability=source.capability.name,
        target_id=source.target.target_id,
        surface_id=source.target.surface_id,
        endpoint_id=source.target.endpoint_id,
        operation_id=source.target.operation_id,
        objective="Independently reproduce the candidate security property.",
        primary_identity_id=source.identity_context.primary_identity_id,
        comparison_identity_id=source.identity_context.comparison_identity_id,
        primary_session_ref_id=source.identity_context.primary_session_ref_id,
        comparison_session_ref_id=source.identity_context.comparison_session_ref_id,
        identity_relationship=(
            source.identity_context.relationship.value
            if source.identity_context.relationship is not None
            else None
        ),
        baseline_kind=source.baseline.kind.value,
        baseline_reference_id=source.baseline.reference_id,
        mutation_kind=mutation.kind,
        mutation_parameter_id=(
            mutation.parameter_ids[0] if mutation.parameter_ids else None
        ),
        mutation_controlled_object_id=(
            mutation.controlled_object_ids[0]
            if mutation.controlled_object_ids
            else None
        ),
        mutation_value_source_reference=(
            mutation.value_source_references[0]
            if mutation.value_source_references
            else None
        ),
        expected_secure_behavior=source.expected_secure_behavior,
        expected_vulnerable_behavior=source.expected_vulnerable_behavior,
        required_evidence=tuple(
            ReproductionEvidencePredicate(
                selector=item.selector.value,
                predicate_reference=item.predicate_reference,
                minimum_artifacts=item.minimum_artifacts,
            )
            for item in source.required_evidence
        ),
        rationale="A fresh authorization and fresh requests provide independence.",
        primitive_steps=tuple(
            PrimitiveStepProposal(step_id=item.step_id, input=item.input)
            for item in source.primitive_steps
        ),
        provenance_id=provenance_id,
        expires_at=source.expires_at,
    )


def candidate_reproduction_eligible(finding: FindingRecord) -> bool:
    """Return whether the finding carries the durable P4-0F source contract."""

    return all(
        value is not None
        for value in (
            finding.research_id,
            finding.source_experiment_fingerprint,
            finding.source_outcome_id,
            finding.source_authorization_reference,
            finding.target_id,
            finding.primitive,
            finding.capability,
            finding.security_property_reference,
            finding.expected_secure_behavior,
            finding.observed_vulnerable_behavior,
            finding.created_at,
        )
    ) and bool(finding.evidence_references)


def _typed_evidence_valid(
    plan: ReproductionPlan,
    experiment: SecurityExperiment,
    outcome: ExperimentOutcome,
) -> bool:
    expected_primitive = {
        ReproductionKind.object_substitution: "object_substitution",
        ReproductionKind.authentication_differential: "authentication_differential",
        ReproductionKind.parameter_mutation: "parameter_mutation",
    }[plan.reproduction_kind]
    matching = tuple(
        item for item in outcome.evidence if item.primitive_name == expected_primitive
    )
    if not matching:
        return False
    expected_identities = {
        item
        for item in (
            experiment.identity_context.primary_identity_id,
            experiment.identity_context.comparison_identity_id,
        )
        if item is not None
    }
    expected_objects = set(experiment.mutation.controlled_object_ids)
    for evidence in matching:
        if not evidence.request_summaries or not evidence.response_summaries:
            return False
        if len(evidence.request_summaries) != len(evidence.response_summaries):
            return False
        if plan.reproduction_kind is ReproductionKind.object_substitution and (
            set(evidence.identity_references) != expected_identities
            or set(evidence.object_references) != expected_objects
            or len(evidence.request_summaries) < 2
        ):
            return False
        if plan.reproduction_kind is ReproductionKind.authentication_differential and (
            set(evidence.identity_references) != expected_identities
            or len(evidence.request_summaries) < 2
        ):
            return False
        if plan.reproduction_kind is ReproductionKind.parameter_mutation and (
            evidence.mutation_kind != experiment.mutation.kind
        ):
            return False
    return True


class ReproductionPlanner:
    """Build bounded options from registered records, never raw model output."""

    def plan(
        self,
        finding: FindingRecord,
        state: ResearchState,
        source_experiment: SecurityExperiment,
        source_outcome: StoredExperimentOutcome | ExperimentOutcome,
        *,
        registry: ExperimentRegistry | None = None,
        confirmation_policy: FindingConfirmationPolicy,
        budget_manager: ResearchBudgetManager | None = None,
        available_controlled_context: object | None = None,
    ) -> tuple[ReproductionPlan, ...]:
        del available_controlled_context
        if finding.status is not FindingStatus.candidate:
            raise ReproductionPlanningError("finding_not_candidate")
        if not candidate_reproduction_eligible(finding):
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
        if not _source_is_vulnerable(finding, source_outcome):
            raise ReproductionPlanningError("source_vulnerable_evidence_invalid")
        if (
            finding.confirmation_policy_reference
            != confirmation_policy.policy_reference
        ):
            raise ReproductionPlanningError("confirmation_policy_mismatch")
        kind = _kind(source_experiment)
        if not confirmation_policy.supports(kind, source_experiment.state_changing):
            raise ReproductionPlanningError("confirmation_profile_not_applicable")
        if registry is not None:
            for step in source_experiment.primitive_steps:
                registry.resolve(step.primitive_name)
        estimated_requests = source_experiment.request_estimate.total_reservation
        if estimated_requests < 1:
            raise ReproductionPlanningError("reproduction_requires_target_request")
        if estimated_requests > confirmation_policy.maximum_requests:
            raise ReproductionPlanningError("reproduction_request_ceiling_exceeded")
        if budget_manager is not None:
            decision = budget_manager.check_reproduction(
                state,
                finding_id=finding.finding_id,
                confirmation_policy=confirmation_policy,
                estimated_requests=estimated_requests,
                state_changing=source_experiment.state_changing,
            )
            if not decision.allowed:
                reason = (
                    decision.reason.value if decision.reason is not None else "denied"
                )
                raise ReproductionPlanningError(reason)
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

        dimension = ReproductionIndependentDimension.fresh_runtime_authorization
        reproduction_id = _identifier(
            "reproduction",
            finding.finding_id,
            source_experiment.experiment_id,
            completed + 1,
            dimension.value,
        )
        predicates = tuple(
            item.predicate_reference for item in source_experiment.required_evidence
        )
        provenance_id = _identifier("reproduction-plan-provenance", reproduction_id)
        proposal_template = _proposal_template(
            source_experiment,
            reproduction_id=reproduction_id,
            provenance_id=provenance_id,
            state_revision=state.revision,
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
            reproduction_kind=kind,
            independent_dimension=dimension,
            target_id=source_experiment.target.target_id,
            surface_id=source_experiment.target.surface_id,
            endpoint_id=source_experiment.target.endpoint_id,
            primary_identity_id=source_experiment.identity_context.primary_identity_id,
            comparison_identity_id=(
                source_experiment.identity_context.comparison_identity_id
            ),
            identity_relationship=(
                source_experiment.identity_context.relationship.value
                if source_experiment.identity_context.relationship is not None
                else None
            ),
            controlled_object_ids=source_experiment.mutation.controlled_object_ids,
            required_evidence_predicates=predicates,
            maximum_requests=min(
                estimated_requests, confirmation_policy.maximum_requests
            ),
            maximum_attempts=confirmation_policy.maximum_attempts,
            state_changing=source_experiment.state_changing,
            cleanup_required=source_experiment.cleanup.required,
            confirmation_policy_reference=confirmation_policy.policy_reference,
            confirmation_policy_fingerprint=confirmation_policy.fingerprint,
            provenance_id=provenance_id,
            expires_at=source_experiment.expires_at,
            proposal_template=proposal_template,
        )
        reject_secret_material(
            plan.model_dump(mode="json"), location="reproduction plan"
        )
        return (plan,)

    def persist_plan(
        self,
        plan: ReproductionPlan,
        store: ResearchStore,
        *,
        budget_manager: ResearchBudgetManager,
        occurred_at: str,
    ) -> ResearchState:
        """Atomically persist a plan, candidate lifecycle edge, and attempt budget."""

        state = store.load_research(plan.research_id)
        if any(
            item.reproduction_id == plan.reproduction_id
            for item in state.reproduction_plans
        ):
            return state
        finding = next(
            (item for item in state.findings if item.finding_id == plan.finding_id),
            None,
        )
        if finding is None or finding.status is not FindingStatus.candidate:
            raise ReproductionPlanningError("finding_not_candidate")
        provenance = ProvenanceRecord(
            provenance_id=plan.provenance_id,
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="reproduction-planner",
            producer_version="p4-0f-v1",
            source_references=(
                finding.finding_id,
                plan.source_experiment_id,
                plan.source_outcome_id,
                plan.source_fingerprint,
            ),
            summary="Deterministically planned one bounded independent reproduction.",
            occurred_at=occurred_at,
        )
        validate_finding_transition(finding.status, FindingStatus.reproducing)
        updated_finding = finding.model_copy(
            update={
                "status": FindingStatus.reproducing,
                "reproduction_ids": tuple(
                    sorted({*finding.reproduction_ids, plan.reproduction_id})
                ),
                "confirmation_policy_fingerprint": (
                    plan.confirmation_policy_fingerprint
                ),
                "updated_at": occurred_at,
                "state_revision": state.revision + 1,
            }
        )
        budget = budget_manager.consume_reproduction_attempt(
            state,
            finding_id=finding.finding_id,
            state_changing=plan.state_changing,
        )
        payload = state.model_dump(mode="python")
        payload.update(
            revision=state.revision + 1,
            updated_at=occurred_at,
            findings=tuple(
                updated_finding if item.finding_id == finding.finding_id else item
                for item in state.findings
            ),
            reproduction_plans=(*state.reproduction_plans, plan),
            budgets=tuple(
                item
                for item in state.budgets
                if item.budget_reference != budget.budget_reference
            )
            + (budget,),
            provenance=(*state.provenance, provenance),
        )
        next_state = ResearchState.model_validate(payload)
        events = (
            ResearchEvent(
                event_id=_identifier("event-reproduction-plan", plan.reproduction_id),
                research_id=state.research_id,
                event_type=ResearchEventType.reproduction_planned,
                state_revision=next_state.revision,
                provenance_id=plan.provenance_id,
                occurred_at=occurred_at,
                summary="Independent reproduction was planned within policy bounds.",
                payload=ReproductionPlannedPayload(
                    reproduction_id=plan.reproduction_id,
                    finding_id=finding.finding_id,
                ),
            ),
            ResearchEvent(
                event_id=_identifier("event-finding-reproducing", plan.reproduction_id),
                research_id=state.research_id,
                event_type=ResearchEventType.finding_status_changed,
                state_revision=next_state.revision,
                provenance_id=plan.provenance_id,
                occurred_at=occurred_at,
                summary="Candidate finding entered bounded reproduction.",
                payload=FindingStatusChangedPayload(
                    finding_id=finding.finding_id,
                    previous_status=FindingStatus.candidate,
                    next_status=FindingStatus.reproducing,
                ),
            ),
        )
        return store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
            events=events,
        )

    def compile(
        self,
        plan: ReproductionPlan,
        source_experiment: SecurityExperiment | None,
        state: ResearchState,
        compiler: ExperimentCompiler,
        compiler_context: ExperimentCompilerContext,
    ) -> ReproductionExperiment:
        """Materialize through the ordinary ExperimentCompiler."""

        if plan.research_id != state.research_id:
            raise ReproductionPlanningError("reproduction_research_mismatch")
        if source_experiment is not None:
            if plan.source_experiment_id != source_experiment.experiment_id:
                raise ReproductionPlanningError("reproduction_source_mismatch")
            if plan.source_fingerprint != source_experiment.fingerprint:
                raise ReproductionPlanningError("reproduction_fingerprint_mismatch")
        persisted = next(
            (
                item
                for item in state.reproduction_plans
                if item.reproduction_id == plan.reproduction_id
            ),
            None,
        )
        if persisted is None or persisted.status is not ReproductionPlanStatus.planned:
            raise ReproductionPlanningError("reproduction_plan_not_active")
        finding = next(
            (item for item in state.findings if item.finding_id == plan.finding_id),
            None,
        )
        if finding is None or finding.status is not FindingStatus.reproducing:
            raise ReproductionPlanningError("finding_not_reproducing")

        template = plan.proposal_template
        mutation_kind: MutationKind | str
        try:
            mutation_kind = MutationKind(template.mutation_kind)
        except ValueError:
            mutation_kind = template.mutation_kind
        proposal = ExperimentProposal(
            proposal_id=template.proposal_id,
            research_id=template.research_id,
            state_revision=state.revision,
            hypothesis_id=template.hypothesis_id,
            capability=template.capability,
            target_id=template.target_id,
            surface_id=template.surface_id,
            endpoint_id=template.endpoint_id,
            operation_id=template.operation_id,
            objective=template.objective,
            primary_identity_id=template.primary_identity_id,
            comparison_identity_id=template.comparison_identity_id,
            primary_session_ref_id=template.primary_session_ref_id,
            comparison_session_ref_id=template.comparison_session_ref_id,
            identity_relationship=(
                IdentityRelationship(template.identity_relationship)
                if template.identity_relationship is not None
                else None
            ),
            baseline=BaselineIntent(
                kind=BaselineKind(template.baseline_kind),
                reference_id=template.baseline_reference_id,
            ),
            mutation_intent=MutationIntent(
                kind=mutation_kind,
                parameter_id=template.mutation_parameter_id,
                controlled_object_id=template.mutation_controlled_object_id,
                value_source_reference=template.mutation_value_source_reference,
            ),
            expected_secure_behavior=template.expected_secure_behavior,
            expected_vulnerable_behavior=template.expected_vulnerable_behavior,
            required_evidence_intent=tuple(
                EvidenceIntent(
                    selector=DifferentialSelector(item.selector),
                    predicate_reference=item.predicate_reference,
                    minimum_artifacts=item.minimum_artifacts,
                )
                for item in template.required_evidence
            ),
            rationale=template.rationale,
            primitive_steps=template.primitive_steps,
            provenance_id=template.provenance_id,
            model_decision_id=plan.model_decision_id,
            expires_at=plan.expires_at,
        )
        context = compiler_context.model_copy(
            update={
                "reproduction_of": plan.source_experiment_id,
                "reproduction_finding_id": plan.finding_id,
                "reproduction_id": plan.reproduction_id,
            }
        )
        experiment = compiler.compile(proposal, state, context)
        if (
            experiment.state_changing != plan.state_changing
            or experiment.cleanup.required != plan.cleanup_required
        ):
            raise ReproductionPlanningError("compiled_reproduction_risk_changed")
        if experiment.request_estimate.total_reservation > plan.maximum_requests:
            raise ReproductionPlanningError("compiled_reproduction_exceeds_plan")
        return ReproductionExperiment(
            reproduction_id=plan.reproduction_id,
            finding_id=plan.finding_id,
            experiment=experiment,
        )


class ReproductionOutcomeEvaluator:
    """Classify runtime output and prove independence without model judgment."""

    def evaluate(
        self,
        finding: FindingRecord,
        plan: ReproductionPlan,
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
    ) -> ReproductionOutcome:
        if experiment.reproduction_id != plan.reproduction_id:
            raise ValueError("reproduction marker is absent or mismatched")
        if outcome.experiment_id != experiment.experiment_id:
            raise ValueError("reproduction outcome does not match experiment")
        source_authorization = finding.source_authorization_reference
        independence = None
        if source_authorization is not None and finding.source_outcome_id is not None:
            reproduction_evidence = tuple(outcome.evidence_references)
            source_evidence = tuple(finding.evidence_references)
            independence = ReproductionIndependence(
                independent_dimension=plan.independent_dimension,
                source_outcome_id=finding.source_outcome_id,
                outcome_id=outcome.outcome_id,
                source_evidence_references=source_evidence,
                reproduction_evidence_references=reproduction_evidence,
                source_authorization_reference=source_authorization,
                authorization_reference=outcome.authorization_reference,
                source_provenance_id=finding.provenance_id,
                reproduction_provenance_id=outcome.provenance_id,
                new_authorization=(
                    source_authorization != outcome.authorization_reference
                ),
                new_target_requests=(
                    outcome.request_delta.discovery
                    + outcome.request_delta.auth
                    + outcome.request_delta.verification
                    > 0
                ),
                new_outcome=outcome.outcome_id != finding.source_outcome_id,
                new_evidence=bool(reproduction_evidence)
                and set(reproduction_evidence).isdisjoint(source_evidence),
                new_provenance=outcome.provenance_id != finding.provenance_id,
                reproduction_marker_present=(
                    experiment.reproduction_of == finding.candidate_experiment_id
                    and experiment.reproduction_finding_id == finding.finding_id
                    and experiment.reproduction_id == plan.reproduction_id
                ),
            )
        classification = {
            ExperimentResultClassification.vulnerable_signal: (
                ReproductionClassification.reproduced
            ),
            ExperimentResultClassification.secure_signal: (
                ReproductionClassification.not_reproduced
            ),
            ExperimentResultClassification.inconclusive: (
                ReproductionClassification.inconclusive
            ),
            ExperimentResultClassification.blocked: ReproductionClassification.blocked,
            ExperimentResultClassification.runtime_failed: (
                ReproductionClassification.runtime_failed
            ),
            ExperimentResultClassification.cleanup_failed: (
                ReproductionClassification.cleanup_failed
            ),
        }[outcome.result_classification]
        if (
            outcome.request_delta.total > plan.maximum_requests
            or independence is None
            or not independence.valid
            or not _typed_evidence_valid(plan, experiment, outcome)
        ):
            classification = ReproductionClassification.blocked
        if outcome.cleanup_status is CleanupStatus.failed:
            classification = ReproductionClassification.cleanup_failed
        security_property = finding.security_property_reference
        if security_property is None:
            raise ValueError("candidate security property is missing")
        result = ReproductionOutcome(
            reproduction_id=plan.reproduction_id,
            finding_id=finding.finding_id,
            experiment_id=experiment.experiment_id,
            experiment_outcome_id=outcome.outcome_id,
            source_experiment_id=plan.source_experiment_id,
            source_outcome_id=plan.source_outcome_id,
            classification=classification,
            category=finding.category,
            target_id=experiment.target.target_id,
            surface_id=experiment.target.surface_id,
            endpoint_id=experiment.target.endpoint_id,
            security_property_reference=security_property,
            identity_relationship=(
                experiment.identity_context.relationship.value
                if experiment.identity_context.relationship is not None
                else None
            ),
            controlled_object_ids=experiment.mutation.controlled_object_ids,
            evidence_references=outcome.evidence_references,
            request_delta=outcome.request_delta,
            independence=independence,
            cleanup_status=outcome.cleanup_status,
            runtime_provenance_reference=outcome.provenance_id,
            authorization_reference=outcome.authorization_reference,
            created_at=outcome.occurred_at,
        )
        reject_secret_material(
            result.model_dump(mode="json"), location="reproduction outcome"
        )
        return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


CandidateFinding = FindingRecord


__all__ = [
    "CandidateFinding",
    "ReproductionExperiment",
    "ReproductionIndependence",
    "ReproductionOutcome",
    "ReproductionOutcomeEvaluator",
    "ReproductionPlan",
    "ReproductionPlanner",
    "ReproductionPlanningError",
    "candidate_reproduction_eligible",
]
