"""Deterministic experiment evaluation and atomic research-state updates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from enum import Enum
from typing import Protocol

from pydantic import Field, model_validator

from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.events import (
    ResearchEvaluationRecordedPayload,
    ResearchEvent,
    ResearchEventType,
)
from agent_core.research.experiments import AuthorizedExperiment, SecurityExperiment
from agent_core.research.graph import GraphAssertion, GraphRelation
from agent_core.research.outcomes import (
    ExperimentOutcome,
    ExperimentResultClassification,
)
from agent_core.research.selection import material_experiment_fingerprint
from agent_core.research.state import (
    EvidenceArtifact,
    ExperimentOutcome as StoredExperimentOutcome,
    Fact,
    FindingRecord,
    HypothesisRecord,
    Observation,
    ProvenanceRecord,
    Relationship,
    ResearchExperimentRecord,
    ResearchState,
)
from agent_core.research.store import ResearchStore
from agent_core.research.types import (
    CleanupStatus,
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceKind,
    FactStatus,
    FindingStatus,
    HypothesisResearchStatus,
    OpaqueIdentifier,
    ProvenanceProducerType,
    ReferenceFactObject,
    RelationshipStatus,
    ResearchConfidence,
    ResearchContract,
    ResearchExperimentStatus,
    ResearchPredicate,
)


class ResearchConsequence(str, Enum):
    support_hypothesis = "support_hypothesis"
    refute_hypothesis = "refute_hypothesis"
    insufficient_evidence = "insufficient_evidence"
    candidate_finding_signal = "candidate_finding_signal"
    pivot_recommended = "pivot_recommended"
    stop_required = "stop_required"


class HypothesisProposalSource(str, Enum):
    deterministic = "deterministic"
    model = "model"


class NewHypothesisProposal(ResearchContract):
    proposal_id: OpaqueIdentifier
    category: OpaqueIdentifier
    title: str = Field(min_length=1, max_length=1_000)
    claim: str = Field(min_length=1, max_length=4_000)
    falsification_criterion: str = Field(min_length=1, max_length=1_000)
    target_id: OpaqueIdentifier
    surface_id: OpaqueIdentifier | None = None
    confirmation_policy_reference: OpaqueIdentifier
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    fact_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=100)
    relationship_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    priority: int = Field(default=50, ge=0, le=100)
    confidence: ResearchConfidence = ResearchConfidence.low
    source: HypothesisProposalSource

    @model_validator(mode="after")
    def require_grounding(self) -> "NewHypothesisProposal":
        if not (
            self.evidence_references
            or self.fact_references
            or self.relationship_references
        ):
            raise ValueError("new hypotheses require existing research grounding")
        return self


class ResearchEvaluation(ResearchContract):
    evaluation_id: OpaqueIdentifier
    research_id: OpaqueIdentifier
    prior_state_revision: int = Field(ge=0)
    experiment_id: OpaqueIdentifier
    outcome_id: OpaqueIdentifier
    hypothesis_id: OpaqueIdentifier
    classification: ExperimentResultClassification
    consequence: ResearchConsequence
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=200
    )
    facts: tuple[Fact, ...] = Field(default=(), max_length=100)
    new_hypotheses: tuple[HypothesisRecord, ...] = Field(default=(), max_length=100)
    observation: Observation | None = None
    candidate_finding: FindingRecord | None = None
    relationships: tuple[Relationship, ...] = Field(default=(), max_length=20)
    graph_assertions: tuple[GraphAssertion, ...] = Field(default=(), max_length=20)
    pivot_recommended: bool = False
    stop_required: bool = False
    service_instability: bool = False
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_consequence(self) -> "ResearchEvaluation":
        if self.classification is not ExperimentResultClassification.vulnerable_signal:
            if self.candidate_finding is not None:
                raise ValueError(
                    "only deterministic vulnerable evidence may create a candidate"
                )
        if self.candidate_finding is not None and (
            self.candidate_finding.status is not FindingStatus.candidate
        ):
            raise ValueError("P4-0E can create candidate findings only")
        if self.stop_required != (
            self.consequence is ResearchConsequence.stop_required
        ):
            raise ValueError("stop_required must match the research consequence")
        return self


class HypothesisDerivationRule(Protocol):
    def propose(
        self,
        state: ResearchState,
        facts: tuple[Fact, ...],
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
    ) -> NewHypothesisProposal | None: ...


class EvidenceRelationshipHypothesisRule(ResearchContract):
    """A bounded F + R -> proposed hypothesis derivation rule."""

    rule_id: OpaqueIdentifier
    fact_predicate: ResearchPredicate
    relationship_predicate: ResearchPredicate
    category: OpaqueIdentifier
    title: str = Field(min_length=1, max_length=1_000)
    claim: str = Field(min_length=1, max_length=4_000)
    falsification_criterion: str = Field(min_length=1, max_length=1_000)
    confirmation_policy_reference: OpaqueIdentifier
    priority: int = Field(default=50, ge=0, le=100)

    def propose(
        self,
        state: ResearchState,
        facts: tuple[Fact, ...],
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
    ) -> NewHypothesisProposal | None:
        fact = next(
            (item for item in facts if item.predicate is self.fact_predicate), None
        )
        relationship = next(
            (
                item
                for item in state.relationships
                if item.predicate is self.relationship_predicate
                and item.status
                in {RelationshipStatus.observed, RelationshipStatus.confirmed}
            ),
            None,
        )
        if fact is None or relationship is None:
            return None
        evidence = tuple(
            sorted(set((*fact.evidence_references, *relationship.evidence_references)))
        )
        return NewHypothesisProposal(
            proposal_id=f"hypothesis-proposal-{self.rule_id}-{outcome.outcome_id}",
            category=self.category,
            title=self.title,
            claim=self.claim,
            falsification_criterion=self.falsification_criterion,
            target_id=experiment.target.target_id,
            surface_id=experiment.target.surface_id,
            confirmation_policy_reference=self.confirmation_policy_reference,
            evidence_references=evidence,
            fact_references=(fact.fact_id,),
            relationship_references=(relationship.relationship_id,),
            priority=self.priority,
            confidence=ResearchConfidence.low,
            source=HypothesisProposalSource.deterministic,
        )


class ExperimentEvaluator:
    """Convert authoritative runtime facts into bounded research consequences."""

    def __init__(
        self,
        *,
        allowed_vulnerability_categories: Iterable[str] = (),
        derivation_rules: Sequence[HypothesisDerivationRule] = (),
    ) -> None:
        self.allowed_vulnerability_categories = frozenset(
            allowed_vulnerability_categories
        )
        self.derivation_rules = tuple(derivation_rules)

    def evaluate(
        self,
        experiment: SecurityExperiment,
        authorization: AuthorizedExperiment | object,
        outcome: ExperimentOutcome,
        prior_state: ResearchState,
        *,
        proposed_hypotheses: Sequence[NewHypothesisProposal] = (),
    ) -> ResearchEvaluation:
        del authorization  # Authority is consumed by runtime, never by evaluation.
        if experiment.research_id != prior_state.research_id:
            raise ValueError("experiment does not belong to research state")
        if outcome.experiment_id != experiment.experiment_id:
            raise ValueError("outcome does not belong to experiment")
        hypothesis = next(
            (
                item
                for item in prior_state.hypotheses
                if item.hypothesis_id == experiment.hypothesis_id
            ),
            None,
        )
        if hypothesis is None:
            raise ValueError("experiment hypothesis is absent from research state")
        evaluation_id = _identifier("evaluation", outcome.outcome_id)
        provenance_id = _identifier("evaluation-provenance", outcome.outcome_id)
        evidence = outcome.evidence_references
        classification = outcome.result_classification
        consequence, pivot, stop = self._consequence(classification, bool(evidence))
        facts = self._facts(
            experiment,
            outcome,
            provenance_id=provenance_id,
        )
        hypothesis_proposals = list(proposed_hypotheses)
        for rule in self.derivation_rules:
            proposal = rule.propose(prior_state, facts, experiment, outcome)
            if proposal is not None:
                hypothesis_proposals.append(proposal)
        new_hypotheses = self._hypotheses(
            hypothesis_proposals,
            state=prior_state,
            new_facts=facts,
            provenance_id=provenance_id,
        )
        candidate = self._candidate(
            experiment,
            hypothesis,
            outcome,
            provenance_id=provenance_id,
        )
        if classification is ExperimentResultClassification.vulnerable_signal and (
            candidate is not None
        ):
            consequence = ResearchConsequence.candidate_finding_signal
        observation = None
        if evidence:
            observation = Observation(
                observation_id=_identifier("observation", outcome.outcome_id),
                observation_type="experiment-result",
                summary=f"Experiment produced {classification.value}.",
                target_id=experiment.target.target_id,
                surface_id=experiment.target.surface_id,
                evidence_references=evidence,
                provenance_id=provenance_id,
            )
        relationships, assertions = self._relationships(
            experiment,
            outcome,
            classification=classification,
            provenance_id=provenance_id,
            research_id=prior_state.research_id,
        )
        return ResearchEvaluation(
            evaluation_id=evaluation_id,
            research_id=prior_state.research_id,
            prior_state_revision=prior_state.revision,
            experiment_id=experiment.experiment_id,
            outcome_id=outcome.outcome_id,
            hypothesis_id=experiment.hypothesis_id,
            classification=classification,
            consequence=consequence,
            evidence_references=evidence,
            facts=facts,
            new_hypotheses=new_hypotheses,
            observation=observation,
            candidate_finding=candidate,
            relationships=relationships,
            graph_assertions=assertions,
            pivot_recommended=pivot,
            stop_required=stop,
            service_instability=(
                classification is ExperimentResultClassification.runtime_failed
            ),
            summary=f"Deterministically classified outcome as {classification.value}.",
        )

    def apply(
        self,
        evaluation: ResearchEvaluation,
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
        state: ResearchState,
        *,
        budget_manager: ResearchBudgetManager,
        was_pivot: bool = False,
    ) -> tuple[ResearchState, tuple[ResearchEvent, ...], tuple[GraphAssertion, ...]]:
        if evaluation.research_id != state.research_id:
            raise ValueError("evaluation does not belong to research state")
        if any(
            item.evaluator_result_reference == evaluation.evaluation_id
            for item in state.experiment_outcomes
        ):
            raise ValueError("evaluation was already applied")
        runtime_provenance, evidence = self._runtime_records(outcome, state)
        eval_provenance_id = _identifier("evaluation-provenance", outcome.outcome_id)
        evaluation_occurred_at = max(state.updated_at, outcome.occurred_at)
        eval_provenance = ProvenanceRecord(
            provenance_id=eval_provenance_id,
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="research-experiment-evaluator",
            producer_version="p4-0e-v1",
            source_references=(outcome.outcome_id, experiment.fingerprint),
            summary="Deterministically evaluated an authoritative experiment outcome.",
            occurred_at=evaluation_occurred_at,
        )
        candidate_ids = (
            (evaluation.candidate_finding.finding_id,)
            if evaluation.candidate_finding is not None
            else ()
        )
        stored_outcome = StoredExperimentOutcome.model_validate(
            {
                **outcome.model_dump(
                    mode="python", include=set(StoredExperimentOutcome.model_fields)
                ),
                "evaluator_result_reference": evaluation.evaluation_id,
                "created_fact_ids": tuple(item.fact_id for item in evaluation.facts),
                "created_hypothesis_ids": tuple(
                    item.hypothesis_id for item in evaluation.new_hypotheses
                ),
                "candidate_finding_ids": candidate_ids,
            }
        )
        outcomes = [
            item
            for item in state.experiment_outcomes
            if item.outcome_id != outcome.outcome_id
        ]
        outcomes.append(stored_outcome)
        previous_hypothesis = next(
            item
            for item in state.hypotheses
            if item.hypothesis_id == experiment.hypothesis_id
        )
        status = previous_hypothesis.status
        supporting = previous_hypothesis.supporting_evidence
        refuting = previous_hypothesis.refuting_evidence
        if (
            evaluation.classification
            is ExperimentResultClassification.vulnerable_signal
            and outcome.evidence_references
        ):
            status = HypothesisResearchStatus.supported
            supporting = tuple(sorted(set((*supporting, *outcome.evidence_references))))
        elif (
            evaluation.classification is ExperimentResultClassification.secure_signal
            and outcome.evidence_references
        ):
            status = HypothesisResearchStatus.refuted
            refuting = tuple(sorted(set((*refuting, *outcome.evidence_references))))
        elif evaluation.classification is ExperimentResultClassification.inconclusive:
            status = HypothesisResearchStatus.inconclusive
        hypothesis_payload = previous_hypothesis.model_dump(mode="python")
        hypothesis_payload.update(
            status=status,
            supporting_evidence=supporting,
            refuting_evidence=refuting,
            attempt_count=previous_hypothesis.attempt_count + 1,
            pivot_count=previous_hypothesis.pivot_count + int(was_pivot),
            experiment_references=tuple(
                sorted(
                    set(
                        (
                            *previous_hypothesis.experiment_references,
                            experiment.experiment_id,
                        )
                    )
                )
            ),
        )
        updated_hypothesis = HypothesisRecord.model_validate(hypothesis_payload)
        hypotheses = [
            item
            for item in state.hypotheses
            if item.hypothesis_id != updated_hypothesis.hypothesis_id
        ]
        hypotheses.extend((updated_hypothesis, *evaluation.new_hypotheses))
        budget = budget_manager.consume_experiment(
            state,
            hypothesis_id=experiment.hypothesis_id,
            surface_id=experiment.target.surface_id,
            pivot=was_pivot,
            state_changing=experiment.state_changing,
            service_instability=evaluation.service_instability,
            cleanup_status=outcome.cleanup_status,
            cleanup_barrier_reference=(
                str(outcome.cleanup_result.cleanup_reference)
                if outcome.cleanup_status is CleanupStatus.failed
                and outcome.cleanup_result.cleanup_reference is not None
                else None
            ),
        )
        history_status = {
            ExperimentResultClassification.runtime_failed: ResearchExperimentStatus.runtime_failed,
            ExperimentResultClassification.cleanup_failed: ResearchExperimentStatus.cleanup_failed,
            ExperimentResultClassification.blocked: ResearchExperimentStatus.policy_blocked,
        }.get(evaluation.classification, ResearchExperimentStatus.completed)
        history = ResearchExperimentRecord(
            experiment_id=experiment.experiment_id,
            proposal_id=experiment.provenance.source_proposal_id,
            hypothesis_id=experiment.hypothesis_id,
            surface_id=experiment.target.surface_id,
            fingerprint=experiment.fingerprint,
            material_fingerprint=material_experiment_fingerprint(experiment),
            status=history_status,
            result_classification=evaluation.classification.value,
            relevant_state_revision=experiment.state_revision,
            policy_reference=outcome.runtime_provenance.policy_reference,
            policy_fingerprint=outcome.runtime_provenance.policy_hash,
            request_cost=outcome.request_delta.total,
            state_changing=experiment.state_changing,
            reproduction_of=experiment.reproduction_of,
            reproduction_finding_id=experiment.reproduction_finding_id,
            reproduction_id=experiment.reproduction_id,
            occurred_at=outcome.occurred_at,
        )
        payload = state.model_dump(mode="python")
        payload.update(
            revision=state.revision + 1,
            updated_at=evaluation_occurred_at,
            evidence=(*state.evidence, *evidence),
            experiment_outcomes=tuple(outcomes),
            experiment_history=(*state.experiment_history, history),
            observations=(
                (*state.observations, evaluation.observation)
                if evaluation.observation is not None
                else state.observations
            ),
            facts=(*state.facts, *evaluation.facts),
            relationships=(*state.relationships, *evaluation.relationships),
            hypotheses=tuple(hypotheses),
            findings=(
                (*state.findings, evaluation.candidate_finding)
                if evaluation.candidate_finding is not None
                else state.findings
            ),
            budgets=tuple(
                item
                for item in state.budgets
                if item.budget_reference != budget.budget_reference
            )
            + (budget,),
            provenance=(
                *state.provenance,
                *runtime_provenance,
                eval_provenance,
            ),
        )
        next_state = ResearchState.model_validate(payload)
        event = ResearchEvent(
            event_id=_identifier("event", evaluation.evaluation_id),
            research_id=state.research_id,
            event_type=ResearchEventType.research_evaluation_recorded,
            state_revision=next_state.revision,
            provenance_id=eval_provenance_id,
            occurred_at=evaluation_occurred_at,
            summary=evaluation.summary,
            payload=ResearchEvaluationRecordedPayload(
                evaluation_id=evaluation.evaluation_id,
                outcome_id=outcome.outcome_id,
            ),
        )
        assertions = tuple(
            item.model_copy(update={"asserted_at": evaluation_occurred_at})
            for item in evaluation.graph_assertions
        )
        return next_state, (event,), assertions

    def evaluate_and_commit(
        self,
        experiment: SecurityExperiment,
        authorization: AuthorizedExperiment | object,
        outcome: ExperimentOutcome,
        store: ResearchStore,
        *,
        budget_manager: ResearchBudgetManager,
        was_pivot: bool = False,
        proposed_hypotheses: Sequence[NewHypothesisProposal] = (),
    ) -> ResearchEvaluation:
        state = store.load_research(experiment.research_id)
        evaluation = self.evaluate(
            experiment,
            authorization,
            outcome,
            state,
            proposed_hypotheses=proposed_hypotheses,
        )
        next_state, events, assertions = self.apply(
            evaluation,
            experiment,
            outcome,
            state,
            budget_manager=budget_manager,
            was_pivot=was_pivot,
        )
        store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
            events=events,
            graph_assertions=assertions,
        )
        return evaluation

    @staticmethod
    def _consequence(
        classification: ExperimentResultClassification, has_evidence: bool
    ) -> tuple[ResearchConsequence, bool, bool]:
        if classification is ExperimentResultClassification.secure_signal:
            return (
                (
                    ResearchConsequence.refute_hypothesis
                    if has_evidence
                    else ResearchConsequence.insufficient_evidence
                ),
                not has_evidence,
                False,
            )
        if classification is ExperimentResultClassification.vulnerable_signal:
            return (
                (
                    ResearchConsequence.support_hypothesis
                    if has_evidence
                    else ResearchConsequence.insufficient_evidence
                ),
                not has_evidence,
                False,
            )
        if classification is ExperimentResultClassification.inconclusive:
            return ResearchConsequence.pivot_recommended, True, False
        if classification is ExperimentResultClassification.cleanup_failed:
            return ResearchConsequence.stop_required, False, True
        if classification is ExperimentResultClassification.runtime_failed:
            return ResearchConsequence.pivot_recommended, True, False
        return ResearchConsequence.insufficient_evidence, False, False

    @staticmethod
    def _facts(
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
        *,
        provenance_id: str,
    ) -> tuple[Fact, ...]:
        if not outcome.evidence_references:
            return ()
        if outcome.result_classification not in {
            ExperimentResultClassification.secure_signal,
            ExperimentResultClassification.vulnerable_signal,
        }:
            return ()
        predicate = (
            ResearchPredicate.supported_by
            if outcome.result_classification
            is ExperimentResultClassification.vulnerable_signal
            else ResearchPredicate.refuted_by
        )
        return (
            Fact(
                fact_id=_identifier("fact", outcome.outcome_id, predicate.value),
                subject=EntityReference(
                    entity_kind=EntityKind.hypothesis,
                    entity_id=experiment.hypothesis_id,
                ),
                predicate=predicate,
                object=ReferenceFactObject(
                    reference=EntityReference(
                        entity_kind=EntityKind.experiment_outcome,
                        entity_id=outcome.outcome_id,
                    )
                ),
                status=FactStatus.observed,
                evidence_references=outcome.evidence_references,
                derivation_type=DerivationType.deterministic,
                provenance_id=provenance_id,
            ),
        )

    def _hypotheses(
        self,
        proposals: Sequence[NewHypothesisProposal],
        *,
        state: ResearchState,
        new_facts: tuple[Fact, ...],
        provenance_id: str,
    ) -> tuple[HypothesisRecord, ...]:
        available_evidence = {item.evidence_id for item in state.evidence}
        available_evidence.update(
            reference for fact in new_facts for reference in fact.evidence_references
        )
        available_facts = {item.fact_id for item in state.facts} | {
            item.fact_id for item in new_facts
        }
        available_relationships = {item.relationship_id for item in state.relationships}
        existing = {
            item.semantic_fingerprint
            or _hypothesis_fingerprint(
                item.category, item.claim, item.target_id, item.surface_id
            )
            for item in state.hypotheses
        }
        created = []
        for proposal in proposals:
            if self.allowed_vulnerability_categories and (
                proposal.category not in self.allowed_vulnerability_categories
            ):
                continue
            if proposal.target_id not in {item.target_id for item in state.targets}:
                continue
            if proposal.surface_id is not None and proposal.surface_id not in {
                item.surface_id for item in state.surfaces
            }:
                continue
            if not set(proposal.evidence_references).issubset(available_evidence):
                continue
            if not set(proposal.fact_references).issubset(available_facts):
                continue
            if not set(proposal.relationship_references).issubset(
                available_relationships
            ):
                continue
            fingerprint = _hypothesis_fingerprint(
                proposal.category,
                proposal.claim,
                proposal.target_id,
                proposal.surface_id,
            )
            if fingerprint in existing:
                continue
            derivation = (
                DerivationType.model_proposed
                if proposal.source is HypothesisProposalSource.model
                else DerivationType.deterministic
            )
            created.append(
                HypothesisRecord(
                    hypothesis_id=_identifier("hypothesis", fingerprint),
                    category=proposal.category,
                    title=proposal.title,
                    claim=proposal.claim,
                    target_id=proposal.target_id,
                    surface_id=proposal.surface_id,
                    status=HypothesisResearchStatus.proposed,
                    priority=proposal.priority,
                    confidence=proposal.confidence,
                    confirmation_policy_reference=(
                        proposal.confirmation_policy_reference
                    ),
                    supporting_evidence=proposal.evidence_references,
                    limitations=(proposal.falsification_criterion,),
                    derivation_type=derivation,
                    basis_fact_ids=proposal.fact_references,
                    basis_relationship_ids=proposal.relationship_references,
                    semantic_fingerprint=fingerprint,
                    provenance_id=provenance_id,
                )
            )
            existing.add(fingerprint)
        return tuple(created)

    @staticmethod
    def _candidate(
        experiment: SecurityExperiment,
        hypothesis: HypothesisRecord,
        outcome: ExperimentOutcome,
        *,
        provenance_id: str,
    ) -> FindingRecord | None:
        if (
            outcome.result_classification
            is not ExperimentResultClassification.vulnerable_signal
            or not outcome.evidence_references
            or outcome.cleanup_status
            not in {CleanupStatus.not_required, CleanupStatus.completed}
        ):
            return None
        return FindingRecord(
            finding_id=_identifier("finding", outcome.outcome_id),
            status=FindingStatus.candidate,
            title=hypothesis.title,
            category=hypothesis.category,
            source_hypothesis_id=hypothesis.hypothesis_id,
            candidate_experiment_id=experiment.experiment_id,
            confirmation_policy_reference=hypothesis.confirmation_policy_reference,
            evidence_references=outcome.evidence_references,
            cleanup_status=outcome.cleanup_status,
            provenance_id=provenance_id,
            research_id=experiment.research_id,
            source_experiment_fingerprint=experiment.fingerprint,
            source_outcome_id=outcome.outcome_id,
            source_authorization_reference=outcome.authorization_reference,
            target_id=experiment.target.target_id,
            surface_id=experiment.target.surface_id,
            endpoint_id=experiment.target.endpoint_id,
            primitive=experiment.primitive_steps[0].primitive_name,
            capability=experiment.capability.name,
            security_property_reference=_identifier(
                "security-property", experiment.expected_secure_behavior
            ),
            controlled_identity_ids=tuple(
                item
                for item in (
                    experiment.identity_context.primary_identity_id,
                    experiment.identity_context.comparison_identity_id,
                )
                if item is not None
            ),
            controlled_identity_relationship=(
                experiment.identity_context.relationship.value
                if experiment.identity_context.relationship is not None
                else None
            ),
            controlled_object_ids=experiment.mutation.controlled_object_ids,
            expected_secure_behavior=experiment.expected_secure_behavior,
            observed_vulnerable_behavior=experiment.expected_vulnerable_behavior,
            source_request_delta=outcome.request_delta,
            total_request_count=outcome.request_delta.total,
            created_at=outcome.occurred_at,
            updated_at=outcome.occurred_at,
            state_revision=experiment.state_revision,
        )

    @staticmethod
    def _relationships(
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
        *,
        classification: ExperimentResultClassification,
        provenance_id: str,
        research_id: str,
    ) -> tuple[tuple[Relationship, ...], tuple[GraphAssertion, ...]]:
        if not outcome.evidence_references:
            return (), ()
        relations = [ResearchPredicate.tested_by]
        if classification is ExperimentResultClassification.vulnerable_signal:
            relations.append(ResearchPredicate.supported_by)
        elif classification is ExperimentResultClassification.secure_signal:
            relations.append(ResearchPredicate.refuted_by)
        source = EntityReference(
            entity_kind=EntityKind.hypothesis, entity_id=experiment.hypothesis_id
        )
        target = EntityReference(
            entity_kind=EntityKind.experiment_outcome, entity_id=outcome.outcome_id
        )
        relationships = tuple(
            Relationship(
                relationship_id=_identifier(
                    "relationship", experiment.experiment_id, relation.value
                ),
                source=source,
                predicate=relation,
                target=target,
                status=RelationshipStatus.observed,
                evidence_references=outcome.evidence_references,
                derivation_type=DerivationType.deterministic,
                provenance_id=provenance_id,
            )
            for relation in relations
        )
        assertions = tuple(
            GraphAssertion(
                assertion_id=_identifier(
                    "assertion", experiment.experiment_id, relation.value
                ),
                research_id=research_id,
                source=source,
                predicate=GraphRelation(relation.value),
                target=target,
                status=RelationshipStatus.observed,
                evidence_references=outcome.evidence_references,
                derivation_type=DerivationType.deterministic,
                provenance_id=provenance_id,
                asserted_at=outcome.occurred_at,
            )
            for relation in relations
        )
        return relationships, assertions

    @staticmethod
    def _runtime_records(
        outcome: ExperimentOutcome, state: ResearchState
    ) -> tuple[tuple[ProvenanceRecord, ...], tuple[EvidenceArtifact, ...]]:
        provenance = ()
        if outcome.provenance_id not in {
            item.provenance_id for item in state.provenance
        }:
            provenance = (
                ProvenanceRecord(
                    provenance_id=outcome.provenance_id,
                    producer_type=ProvenanceProducerType.runtime,
                    producer_name=outcome.runtime_provenance.runtime_name,
                    producer_version=outcome.runtime_provenance.runtime_version,
                    source_references=(
                        outcome.authorization_reference,
                        outcome.experiment_id,
                    ),
                    summary="Executed one sealed deterministic research experiment.",
                    occurred_at=outcome.occurred_at,
                ),
            )
        known = {item.evidence_id for item in state.evidence}
        evidence = tuple(
            EvidenceArtifact(
                evidence_id=item.evidence_id,
                evidence_kind=(
                    EvidenceKind.differential
                    if item.selector_results or item.invariant_results
                    else EvidenceKind.response_summary
                ),
                digest=_digest(item.model_dump(mode="json")),
                summary=item.summary,
                source_reference=item.step_id,
                observed_at=outcome.occurred_at,
                provenance_id=outcome.provenance_id,
            )
            for item in outcome.evidence
            if item.evidence_id not in known
        )
        return provenance, evidence


def _identifier(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256("|".join(str(item) for item in parts).encode()).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _hypothesis_fingerprint(
    category: str, claim: str, target_id: str, surface_id: str | None
) -> str:
    normalized = {
        "category": category.strip().lower(),
        "claim": " ".join(claim.lower().split()),
        "target_id": target_id,
        "surface_id": surface_id,
    }
    return _digest(normalized)


__all__ = [
    "EvidenceRelationshipHypothesisRule",
    "ExperimentEvaluator",
    "HypothesisDerivationRule",
    "HypothesisProposalSource",
    "NewHypothesisProposal",
    "ResearchConsequence",
    "ResearchEvaluation",
]
