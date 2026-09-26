"""Policy-bound deterministic finding confirmation and atomic promotion."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum

from pydantic import Field, StrictBool, StrictFloat, StrictInt, model_validator

from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.events import (
    FindingConfirmationDecidedPayload,
    FindingStatusChangedPayload,
    ReproductionOutcomeRecordedPayload,
    ResearchEvent,
    ResearchEventType,
)
from agent_core.research.experiments import SecurityExperiment
from agent_core.research.graph import GraphAssertion, GraphRelation
from agent_core.research.outcomes import ExperimentOutcome
from agent_core.research.provenance import reject_secret_material
from agent_core.research.selection import material_experiment_fingerprint
from agent_core.research.state import (
    ControlledImpact,
    ExperimentOutcome as StoredExperimentOutcome,
    FindingConfirmationDecision,
    FindingRecord,
    ProvenanceRecord,
    ReproductionOutcome,
    ReproductionPlan,
    ResearchExperimentRecord,
    ResearchState,
)
from agent_core.research.types import (
    CleanupStatus,
    ConflictingEvidenceBehavior,
    DerivationType,
    EntityKind,
    EntityReference,
    FindingConfirmationAction,
    FindingStatus,
    ImpactLevel,
    OpaqueIdentifier,
    ProvenanceProducerType,
    RelationshipStatus,
    ResearchPredicate,
    ReproductionClassification,
    ReproductionIndependentDimension,
    ReproductionKind,
    ReproductionPlanStatus,
    ResearchContract,
    ResearchExperimentStatus,
    ServiceInstabilityBehavior,
    Sha256Digest,
)
from agent_core.research.transitions import validate_finding_transition


class ConfirmationProfile(str, Enum):
    generic = "generic"
    authorization_read_only = "authorization_read_only"
    authentication_read_only = "authentication_read_only"
    parameter_mutation_read_only = "parameter_mutation_read_only"


class FindingConfirmationPolicy(ResearchContract):
    """Operator-owned confirmation predicates; model output cannot mutate them."""

    policy_reference: OpaqueIdentifier = "finding-confirmation-policy-v1"
    profile: ConfirmationProfile = ConfirmationProfile.generic
    minimum_independent_reproductions: StrictInt = Field(default=2, ge=1, le=20)
    required_evidence_agreement: StrictBool = True
    required_identity_relationship_agreement: StrictBool = True
    required_object_relationship_agreement: StrictBool = True
    required_target_surface_agreement: StrictBool = True
    allowed_reproduction_variation: tuple[ReproductionIndependentDimension, ...] = (
        ReproductionIndependentDimension.fresh_runtime_authorization,
        ReproductionIndependentDimension.fresh_session_binding,
        ReproductionIndependentDimension.identity_order_reversal,
        ReproductionIndependentDimension.different_owned_object,
        ReproductionIndependentDimension.equivalent_endpoint_representation,
        ReproductionIndependentDimension.alternate_safe_observation_predicate,
    )
    maximum_requests: StrictInt = Field(default=10, ge=1, le=10_000)
    maximum_attempts: StrictInt = Field(default=2, ge=1, le=100)
    maximum_model_calls: StrictInt = Field(default=1, ge=0, le=10)
    maximum_wall_time_seconds: StrictFloat = Field(default=120.0, ge=1.0, le=86_400.0)
    state_changing_confirmation_permitted: StrictBool = False
    cleanup_required: StrictBool = True
    conflicting_evidence_behavior: ConflictingEvidenceBehavior = (
        ConflictingEvidenceBehavior.manual_review
    )
    service_instability_behavior: ServiceInstabilityBehavior = (
        ServiceInstabilityBehavior.remain_candidate
    )
    secure_reproductions_required_for_rejection: StrictInt = Field(
        default=1, ge=1, le=20
    )

    @model_validator(mode="after")
    def validate_bounds(self) -> "FindingConfirmationPolicy":
        variations = tuple(sorted(set(self.allowed_reproduction_variation), key=str))
        object.__setattr__(self, "allowed_reproduction_variation", variations)
        if self.maximum_attempts < self.minimum_independent_reproductions:
            raise ValueError("attempt ceiling cannot undercut required reproductions")
        if self.secure_reproductions_required_for_rejection > self.maximum_attempts:
            raise ValueError("rejection threshold exceeds attempt ceiling")
        return self

    @property
    def fingerprint(self) -> Sha256Digest:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def supports(self, kind: ReproductionKind, state_changing: bool) -> bool:
        if state_changing and not self.state_changing_confirmation_permitted:
            return False
        expected = {
            ConfirmationProfile.authorization_read_only: (
                ReproductionKind.object_substitution
            ),
            ConfirmationProfile.authentication_read_only: (
                ReproductionKind.authentication_differential
            ),
            ConfirmationProfile.parameter_mutation_read_only: (
                ReproductionKind.parameter_mutation
            ),
        }.get(self.profile)
        return expected is None or expected is kind

    @classmethod
    def authorization_read_only(
        cls,
        policy_reference: str,
        *,
        conflicting_evidence_behavior: ConflictingEvidenceBehavior = (
            ConflictingEvidenceBehavior.reject
        ),
    ) -> "FindingConfirmationPolicy":
        return cls(
            policy_reference=policy_reference,
            profile=ConfirmationProfile.authorization_read_only,
            minimum_independent_reproductions=1,
            maximum_attempts=1,
            conflicting_evidence_behavior=conflicting_evidence_behavior,
        )

    @classmethod
    def authentication_read_only(
        cls,
        policy_reference: str,
        *,
        conflicting_evidence_behavior: ConflictingEvidenceBehavior = (
            ConflictingEvidenceBehavior.manual_review
        ),
    ) -> "FindingConfirmationPolicy":
        return cls(
            policy_reference=policy_reference,
            profile=ConfirmationProfile.authentication_read_only,
            minimum_independent_reproductions=1,
            maximum_attempts=1,
            conflicting_evidence_behavior=conflicting_evidence_behavior,
        )

    @classmethod
    def parameter_mutation_read_only(
        cls, policy_reference: str
    ) -> "FindingConfirmationPolicy":
        return cls(
            policy_reference=policy_reference,
            profile=ConfirmationProfile.parameter_mutation_read_only,
        )


def _identifier(prefix: str, *values: object) -> str:
    material = "\x1f".join(str(value) for value in values).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


def _status_for_action(action: FindingConfirmationAction) -> FindingStatus:
    return {
        FindingConfirmationAction.confirm: FindingStatus.confirmed,
        FindingConfirmationAction.reject: FindingStatus.rejected,
        FindingConfirmationAction.remain_candidate: FindingStatus.candidate,
        FindingConfirmationAction.manual_review: FindingStatus.needs_manual_review,
        FindingConfirmationAction.stop: FindingStatus.candidate,
    }[action]


def _elapsed_seconds(start: str, end: str) -> float:
    def parsed(value: str) -> datetime:
        return datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )

    return max(0.0, (parsed(end) - parsed(start)).total_seconds())


class FindingConfirmationEvaluator:
    """Deterministically decide confirmation; no model result is accepted."""

    def evaluate(
        self,
        finding: FindingRecord,
        source_outcome: StoredExperimentOutcome,
        reproduction_outcomes: tuple[ReproductionOutcome, ...],
        policy: FindingConfirmationPolicy,
        state: ResearchState,
    ) -> FindingConfirmationDecision:
        if finding.status in {FindingStatus.confirmed, FindingStatus.rejected}:
            return self._decision(
                finding,
                reproduction_outcomes,
                policy,
                FindingConfirmationAction.stop,
                "finding_terminal",
            )
        if finding.research_id != state.research_id:
            return self._decision(
                finding,
                reproduction_outcomes,
                policy,
                FindingConfirmationAction.stop,
                "research_mismatch",
            )
        if finding.confirmation_policy_reference != policy.policy_reference:
            return self._decision(
                finding,
                reproduction_outcomes,
                policy,
                FindingConfirmationAction.stop,
                "confirmation_policy_mismatch",
            )
        source_valid = (
            finding.source_outcome_id == source_outcome.outcome_id
            and finding.candidate_experiment_id == source_outcome.experiment_id
            and finding.finding_id in source_outcome.candidate_finding_ids
            and set(finding.evidence_references).issubset(
                set(source_outcome.evidence_references)
            )
            and bool(finding.evidence_references)
        )
        if not source_valid:
            return self._decision(
                finding,
                reproduction_outcomes,
                policy,
                FindingConfirmationAction.remain_candidate,
                "source_vulnerable_evidence_invalid",
            )
        relevant = tuple(
            item
            for item in reproduction_outcomes
            if item.finding_id == finding.finding_id
        )
        if not relevant:
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.remain_candidate,
                "independent_reproduction_missing",
            )
        if any(item.cleanup_status is CleanupStatus.failed for item in relevant):
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.stop,
                "cleanup_failed",
            )
        if any(
            item.classification is ReproductionClassification.cleanup_failed
            for item in relevant
        ):
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.stop,
                "cleanup_failed",
            )
        if any(
            item.classification is ReproductionClassification.runtime_failed
            for item in relevant
        ):
            action = {
                ServiceInstabilityBehavior.remain_candidate: (
                    FindingConfirmationAction.remain_candidate
                ),
                ServiceInstabilityBehavior.manual_review: (
                    FindingConfirmationAction.manual_review
                ),
                ServiceInstabilityBehavior.stop: FindingConfirmationAction.stop,
            }[policy.service_instability_behavior]
            return self._decision(
                finding, relevant, policy, action, "service_instability"
            )

        secure = tuple(
            item
            for item in relevant
            if item.classification
            in {
                ReproductionClassification.not_reproduced,
                ReproductionClassification.conflicting,
            }
        )
        reproduced = tuple(
            item
            for item in relevant
            if item.classification is ReproductionClassification.reproduced
        )
        if secure:
            action = {
                ConflictingEvidenceBehavior.reject: FindingConfirmationAction.reject,
                ConflictingEvidenceBehavior.manual_review: (
                    FindingConfirmationAction.manual_review
                ),
                ConflictingEvidenceBehavior.remain_candidate: (
                    FindingConfirmationAction.remain_candidate
                ),
            }[policy.conflicting_evidence_behavior]
            if (
                action is FindingConfirmationAction.reject
                and len(secure) < policy.secure_reproductions_required_for_rejection
            ):
                action = FindingConfirmationAction.remain_candidate
            reason = "reproduction_disagreement" if reproduced else "not_reproduced"
            return self._decision(finding, relevant, policy, action, reason)
        if not reproduced:
            reason = (
                "reproduction_inconclusive"
                if any(
                    item.classification is ReproductionClassification.inconclusive
                    for item in relevant
                )
                else "reproduction_blocked"
            )
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.remain_candidate,
                reason,
            )
        invalid_reason = self._invariant_failure(finding, reproduced, policy)
        if invalid_reason is not None:
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.remain_candidate,
                invalid_reason,
            )
        if len(reproduced) < policy.minimum_independent_reproductions:
            return self._decision(
                finding,
                relevant,
                policy,
                FindingConfirmationAction.remain_candidate,
                "minimum_reproductions_not_met",
            )
        return self._decision(
            finding,
            relevant,
            policy,
            FindingConfirmationAction.confirm,
            "all_confirmation_predicates_satisfied",
        )

    @staticmethod
    def _invariant_failure(
        finding: FindingRecord,
        outcomes: tuple[ReproductionOutcome, ...],
        policy: FindingConfirmationPolicy,
    ) -> str | None:
        for item in outcomes:
            if item.independence is None or not item.independence.valid:
                return "reproduction_not_independent"
            if (
                item.independence.independent_dimension
                not in policy.allowed_reproduction_variation
            ):
                return "reproduction_variation_not_allowed"
            if item.category != finding.category:
                return "vulnerability_category_mismatch"
            if item.security_property_reference != finding.security_property_reference:
                return "security_property_mismatch"
            if policy.required_target_surface_agreement and (
                item.target_id != finding.target_id
                or item.surface_id != finding.surface_id
                or item.endpoint_id != finding.endpoint_id
            ):
                return "target_surface_mismatch"
            if policy.required_identity_relationship_agreement and (
                item.identity_relationship != finding.controlled_identity_relationship
            ):
                return "identity_relationship_mismatch"
            if policy.required_object_relationship_agreement and (
                set(item.controlled_object_ids) != set(finding.controlled_object_ids)
            ):
                return "object_relationship_mismatch"
            if policy.required_evidence_agreement and not item.evidence_references:
                return "reproduction_evidence_missing"
            if (
                item.request_delta.discovery
                + item.request_delta.auth
                + item.request_delta.verification
                < 1
            ):
                return "request_accounting_invalid"
            if policy.cleanup_required and item.cleanup_status not in {
                CleanupStatus.not_required,
                CleanupStatus.completed,
            }:
                return "cleanup_unresolved"
        return None

    @staticmethod
    def _decision(
        finding: FindingRecord,
        outcomes: tuple[ReproductionOutcome, ...],
        policy: FindingConfirmationPolicy,
        action: FindingConfirmationAction,
        reason: str,
    ) -> FindingConfirmationDecision:
        confirmed = tuple(
            reference
            for item in outcomes
            if item.classification is ReproductionClassification.reproduced
            for reference in item.evidence_references
        )
        conflicting = tuple(
            reference
            for item in outcomes
            if item.classification
            in {
                ReproductionClassification.not_reproduced,
                ReproductionClassification.conflicting,
            }
            for reference in item.evidence_references
        )
        occurred_at = max(
            (
                *(item.created_at for item in outcomes),
                finding.updated_at or finding.created_at or "1970-01-01T00:00:00+00:00",
            )
        )
        decision_id = _identifier(
            "confirmation-decision",
            finding.finding_id,
            action.value,
            reason,
            *(item.reproduction_id for item in outcomes),
        )
        result = FindingConfirmationDecision(
            decision_id=decision_id,
            finding_id=finding.finding_id,
            research_id=str(finding.research_id),
            action=action,
            reason_code=reason,
            confirmation_policy_reference=policy.policy_reference,
            confirmation_policy_fingerprint=policy.fingerprint,
            reproduction_ids=tuple(item.reproduction_id for item in outcomes),
            confirmed_evidence_references=confirmed,
            conflicting_evidence_references=conflicting,
            total_request_count=finding.source_request_delta.total
            + sum(item.request_delta.total for item in outcomes),
            provenance_id=_identifier("confirmation-provenance", decision_id),
            created_at=occurred_at,
        )
        reject_secret_material(
            result.model_dump(mode="json"), location="finding confirmation decision"
        )
        return result

    def evaluate_and_commit(
        self,
        *,
        finding_id: str,
        plan: ReproductionPlan,
        experiment: SecurityExperiment,
        runtime_outcome: ExperimentOutcome,
        policy: FindingConfirmationPolicy,
        store: object,
        budget_manager: ResearchBudgetManager,
    ) -> FindingConfirmationDecision:
        """Persist outcome, evidence, graph, budgets, and lifecycle in one revision."""

        from agent_core.research.evaluation import ExperimentEvaluator
        from agent_core.research.reproduction import ReproductionOutcomeEvaluator

        load = getattr(store, "load_research")
        commit = getattr(store, "commit_revision")
        state: ResearchState = load(plan.research_id)
        finding = next(item for item in state.findings if item.finding_id == finding_id)
        if finding.status is not FindingStatus.reproducing:
            raise ValueError("finding is not in reproduction")
        source_outcome = next(
            item
            for item in state.experiment_outcomes
            if item.outcome_id == plan.source_outcome_id
        )
        if any(
            item.reproduction_id == plan.reproduction_id
            for item in state.reproduction_outcomes
        ):
            existing = next(
                item
                for item in state.confirmation_decisions
                if plan.reproduction_id in item.reproduction_ids
            )
            return existing
        reproduction = ReproductionOutcomeEvaluator().evaluate(
            finding, plan, experiment, runtime_outcome
        )
        all_reproductions = (*state.reproduction_outcomes, reproduction)
        decision = self.evaluate(
            finding, source_outcome, all_reproductions, policy, state
        )
        runtime_provenance, evidence = ExperimentEvaluator._runtime_records(
            runtime_outcome, state
        )
        decision_provenance = ProvenanceRecord(
            provenance_id=decision.provenance_id,
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="finding-confirmation-evaluator",
            producer_version="p4-0f-v1",
            source_references=(
                finding.finding_id,
                source_outcome.outcome_id,
                reproduction.reproduction_id,
                reproduction.experiment_outcome_id,
                policy.fingerprint,
            ),
            summary="Applied deterministic policy predicates to reproduction evidence.",
            occurred_at=decision.created_at,
        )
        stored_runtime_outcome = StoredExperimentOutcome.model_validate(
            {
                **runtime_outcome.model_dump(
                    mode="python", include=set(StoredExperimentOutcome.model_fields)
                ),
                "evaluator_result_reference": decision.decision_id,
                "candidate_finding_ids": (),
            }
        )
        history_status = {
            ReproductionClassification.runtime_failed: (
                ResearchExperimentStatus.runtime_failed
            ),
            ReproductionClassification.cleanup_failed: (
                ResearchExperimentStatus.cleanup_failed
            ),
            ReproductionClassification.blocked: (
                ResearchExperimentStatus.policy_blocked
            ),
        }.get(reproduction.classification, ResearchExperimentStatus.completed)
        history = ResearchExperimentRecord(
            experiment_id=experiment.experiment_id,
            proposal_id=experiment.provenance.source_proposal_id,
            hypothesis_id=experiment.hypothesis_id,
            surface_id=experiment.target.surface_id,
            fingerprint=experiment.fingerprint,
            material_fingerprint=material_experiment_fingerprint(experiment),
            status=history_status,
            result_classification=reproduction.classification.value,
            relevant_state_revision=experiment.state_revision,
            policy_reference=runtime_outcome.runtime_provenance.policy_reference,
            policy_fingerprint=runtime_outcome.runtime_provenance.policy_hash,
            request_cost=runtime_outcome.request_delta.total,
            state_changing=experiment.state_changing,
            reproduction_of=experiment.reproduction_of,
            reproduction_finding_id=experiment.reproduction_finding_id,
            reproduction_id=experiment.reproduction_id,
            occurred_at=runtime_outcome.occurred_at,
        )
        plan_started_at = next(
            item.occurred_at
            for item in state.provenance
            if item.provenance_id == plan.provenance_id
        )
        budget = budget_manager.consume_reproduction_result(
            state,
            finding_id=finding.finding_id,
            request_delta=runtime_outcome.request_delta,
            wall_time_seconds=_elapsed_seconds(
                plan_started_at, runtime_outcome.occurred_at
            ),
        )
        next_status = _status_for_action(decision.action)
        validate_finding_transition(finding.status, next_status)
        confirmed_evidence = tuple(
            sorted(
                {
                    *finding.evidence_references,
                    *decision.confirmed_evidence_references,
                }
            )
        )
        conflicting_evidence = tuple(
            sorted(
                {
                    *finding.contradictory_evidence,
                    *decision.conflicting_evidence_references,
                }
            )
        )
        impact = finding.controlled_impact
        if decision.action is FindingConfirmationAction.confirm:
            impact = ControlledImpact(
                level=ImpactLevel.limited,
                summary="Independent controlled reproduction confirmed the boundary violation.",
                evidence_references=confirmed_evidence,
            )
        updated_finding = FindingRecord.model_validate(
            {
                **finding.model_dump(mode="python"),
                "status": next_status,
                "reproduction_experiment_ids": tuple(
                    sorted(
                        {
                            *finding.reproduction_experiment_ids,
                            experiment.experiment_id,
                        }
                    )
                ),
                "confirmation_decision_id": decision.decision_id,
                "confirmation_policy_fingerprint": policy.fingerprint,
                "evidence_references": (
                    confirmed_evidence
                    if decision.action is FindingConfirmationAction.confirm
                    else finding.evidence_references
                ),
                "confirmed_evidence_references": confirmed_evidence,
                "contradictory_evidence": conflicting_evidence,
                "conflicting_evidence_references": conflicting_evidence,
                "total_request_count": decision.total_request_count,
                "controlled_impact": impact,
                "cleanup_status": runtime_outcome.cleanup_status,
                "decision_reason_code": decision.reason_code,
                "updated_at": decision.created_at,
                "state_revision": state.revision + 1,
            }
        )
        completed_plan = plan.model_copy(
            update={
                "status": ReproductionPlanStatus.completed,
                "compiled_experiment_id": experiment.experiment_id,
            }
        )
        payload = state.model_dump(mode="python")
        payload.update(
            revision=state.revision + 1,
            updated_at=decision.created_at,
            evidence=(*state.evidence, *evidence),
            provenance=(
                *state.provenance,
                *runtime_provenance,
                decision_provenance,
            ),
            experiment_outcomes=tuple(
                item
                for item in state.experiment_outcomes
                if item.outcome_id != stored_runtime_outcome.outcome_id
            )
            + (stored_runtime_outcome,),
            experiment_history=(*state.experiment_history, history),
            reproduction_plans=tuple(
                completed_plan if item.reproduction_id == plan.reproduction_id else item
                for item in state.reproduction_plans
            ),
            reproduction_outcomes=all_reproductions,
            confirmation_decisions=(*state.confirmation_decisions, decision),
            findings=tuple(
                updated_finding if item.finding_id == finding.finding_id else item
                for item in state.findings
            ),
            budgets=tuple(
                item
                for item in state.budgets
                if item.budget_reference != budget.budget_reference
            )
            + (budget,),
        )
        next_state = ResearchState.model_validate(payload)
        events = self._events(
            finding,
            reproduction,
            decision,
            next_status,
            next_state.revision,
        )
        assertions = self._assertions(
            finding, reproduction, decision, next_status, state.research_id
        )
        commit(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
            events=events,
            graph_assertions=assertions,
        )
        return decision

    @staticmethod
    def _events(
        finding: FindingRecord,
        reproduction: ReproductionOutcome,
        decision: FindingConfirmationDecision,
        next_status: FindingStatus,
        revision: int,
    ) -> tuple[ResearchEvent, ...]:
        result = [
            ResearchEvent(
                event_id=_identifier(
                    "event-reproduction-outcome", reproduction.reproduction_id
                ),
                research_id=decision.research_id,
                event_type=ResearchEventType.reproduction_outcome_recorded,
                state_revision=revision,
                provenance_id=decision.provenance_id,
                occurred_at=decision.created_at,
                summary="Independent reproduction outcome was recorded.",
                payload=ReproductionOutcomeRecordedPayload(
                    reproduction_id=reproduction.reproduction_id,
                    finding_id=finding.finding_id,
                    outcome_id=reproduction.experiment_outcome_id,
                ),
            ),
            ResearchEvent(
                event_id=_identifier("event-confirmation", decision.decision_id),
                research_id=decision.research_id,
                event_type=ResearchEventType.finding_confirmation_decided,
                state_revision=revision,
                provenance_id=decision.provenance_id,
                occurred_at=decision.created_at,
                summary="A deterministic finding confirmation decision was recorded.",
                payload=FindingConfirmationDecidedPayload(
                    decision_id=decision.decision_id,
                    finding_id=finding.finding_id,
                    action=decision.action.value,
                ),
            ),
        ]
        if next_status is not finding.status:
            result.append(
                ResearchEvent(
                    event_id=_identifier(
                        "event-finding-decision", decision.decision_id
                    ),
                    research_id=decision.research_id,
                    event_type=ResearchEventType.finding_status_changed,
                    state_revision=revision,
                    provenance_id=decision.provenance_id,
                    occurred_at=decision.created_at,
                    summary=f"Finding status changed to {next_status.value}.",
                    payload=FindingStatusChangedPayload(
                        finding_id=finding.finding_id,
                        previous_status=finding.status,
                        next_status=next_status,
                    ),
                )
            )
        return tuple(result)

    @staticmethod
    def _assertions(
        finding: FindingRecord,
        reproduction: ReproductionOutcome,
        decision: FindingConfirmationDecision,
        next_status: FindingStatus,
        research_id: str,
    ) -> tuple[GraphAssertion, ...]:
        finding_ref = EntityReference(
            entity_kind=EntityKind.finding, entity_id=finding.finding_id
        )
        reproduction_ref = EntityReference(
            entity_kind=EntityKind.experiment_outcome,
            entity_id=reproduction.experiment_outcome_id,
        )
        source_ref = EntityReference(
            entity_kind=EntityKind.experiment_outcome,
            entity_id=reproduction.source_outcome_id,
        )
        relations: list[
            tuple[
                EntityReference,
                ResearchPredicate | GraphRelation,
                EntityReference,
                RelationshipStatus,
            ]
        ] = [
            (
                reproduction_ref,
                ResearchPredicate.reproduction_of,
                source_ref,
                RelationshipStatus.observed,
            )
        ]
        if reproduction.classification is ReproductionClassification.reproduced:
            relations.extend(
                (
                    (
                        finding_ref,
                        ResearchPredicate.finding_reproduced_by,
                        reproduction_ref,
                        RelationshipStatus.observed,
                    ),
                    (
                        finding_ref,
                        GraphRelation.supported_by,
                        reproduction_ref,
                        RelationshipStatus.observed,
                    ),
                )
            )
        if next_status is FindingStatus.confirmed:
            relations.append(
                (
                    finding_ref,
                    ResearchPredicate.finding_confirmed_by,
                    reproduction_ref,
                    RelationshipStatus.confirmed,
                )
            )
        elif next_status is FindingStatus.rejected:
            relations.append(
                (
                    finding_ref,
                    ResearchPredicate.finding_rejected_by,
                    reproduction_ref,
                    RelationshipStatus.confirmed,
                )
            )
        if reproduction.classification in {
            ReproductionClassification.not_reproduced,
            ReproductionClassification.conflicting,
        }:
            relations.append(
                (
                    finding_ref,
                    ResearchPredicate.conflicts_with,
                    reproduction_ref,
                    RelationshipStatus.observed,
                )
            )
        return tuple(
            GraphAssertion(
                assertion_id=_identifier(
                    "assertion",
                    decision.decision_id,
                    relation.value,
                    index,
                ),
                research_id=research_id,
                source=source,
                predicate=relation,
                target=target,
                status=status,
                evidence_references=reproduction.evidence_references,
                derivation_type=DerivationType.deterministic,
                provenance_id=decision.provenance_id,
                asserted_at=decision.created_at,
            )
            for index, (source, relation, target, status) in enumerate(relations)
        )


__all__ = [
    "ConfirmationProfile",
    "FindingConfirmationDecision",
    "FindingConfirmationEvaluator",
    "FindingConfirmationPolicy",
]

from agent_core.research.chain_evaluation import (  # noqa: E402
    AttackChainConfirmationEvaluator,
)
from agent_core.research.chains import (  # noqa: E402
    ChainConfirmationDecision,
    ChainConfirmationPolicy,
)

__all__ += [
    "AttackChainConfirmationEvaluator",
    "ChainConfirmationDecision",
    "ChainConfirmationPolicy",
]
