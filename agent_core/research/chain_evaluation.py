"""Deterministic evaluation, reproduction, and confirmation for attack chains."""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import StrictBool

from agent_core.research.chain_candidates import ChainExperimentPlan
from agent_core.research.chains import (
    AttackChainEvaluation,
    AttackChainEvaluationClassification,
    ChainConfirmationAction,
    ChainConfirmationDecision,
    ChainConfirmationPolicy,
    ChainLinkStatus,
    ChainReproductionOutcome,
    ChainReproductionPlan,
    ChainStepOutcome,
    stable_chain_identifier,
)
from agent_core.research.graph import GraphAssertion, GraphRelation
from agent_core.research.state import (
    AttackChain,
    ControlledImpact,
    FindingRecord,
    ResearchState,
)
from agent_core.research.types import (
    AttackChainStatus,
    CleanupStatus,
    DerivationType,
    EntityKind,
    EntityReference,
    FactStatus,
    FindingStatus,
    ImpactLevel,
    RelationshipStatus,
    ResearchContract,
    ResearchPredicate,
)

MEANINGFUL_CHAIN_RELATIONS = frozenset(
    {
        ResearchPredicate.references_same_object,
        ResearchPredicate.same_object_as,
        ResearchPredicate.enables,
        ResearchPredicate.depends_on,
        ResearchPredicate.reaches,
        ResearchPredicate.crosses_surface,
        ResearchPredicate.crosses_identity_boundary,
        ResearchPredicate.crosses_tenant_boundary,
        ResearchPredicate.produces_context_for,
        GraphRelation.same_object_as,
        GraphRelation.requires,
    }
)


class ChainEvaluationPolicy(ResearchContract):
    require_meaningful_combined_impact: StrictBool = True
    policy_block_is_blocked: StrictBool = True
    cleanup_failure_is_blocked: StrictBool = True
    permit_observed_deterministic_facts: StrictBool = True
    permit_candidate_findings: StrictBool = True


class AttackChainEvaluator:
    """Classify typed predicates; model output is never an input."""

    def evaluate(
        self,
        chain: AttackChain,
        step_outcomes: Sequence[ChainStepOutcome],
        state: ResearchState,
        graph: Sequence[GraphAssertion] = (),
        policy: ChainEvaluationPolicy | None = None,
        *,
        occurred_at: str | None = None,
    ) -> AttackChainEvaluation:
        selected_policy = policy or ChainEvaluationPolicy()
        if chain.research_id is not None and chain.research_id != state.research_id:
            raise ValueError("attack-chain research binding mismatch")
        if chain.state_revision > state.revision:
            raise ValueError("attack chain references a future state revision")
        outcomes = {item.step_id: item for item in step_outcomes}
        if len(outcomes) != len(step_outcomes):
            raise ValueError("chain step outcomes must be unique")
        if any(item.chain_id != chain.attack_chain_id for item in step_outcomes):
            raise ValueError("chain step outcome belongs to another chain")
        state_evidence_ids = {item.evidence_id for item in state.evidence}
        if any(
            not set(item.evidence_references).issubset(state_evidence_ids)
            for item in step_outcomes
        ):
            raise ValueError("chain step outcome cites unavailable evidence")
        chain_step_ids = {str(item.step_id) for item in chain.steps}
        if not set(outcomes).issubset(chain_step_ids):
            raise ValueError("chain outcome references an unavailable step")

        evaluated: list[str] = []
        supported: list[str] = []
        refuted: list[str] = []
        evidence: set[str] = set(chain.evidence_references)
        failure: ChainLinkStatus | None = None
        failed_sequence: int | None = None

        for step in chain.steps:
            outcome = outcomes.get(str(step.step_id))
            if outcome is not None:
                if outcome.sequence != step.sequence:
                    raise ValueError("chain outcome sequence does not match its step")
                status = (
                    ChainLinkStatus.cleanup_failed
                    if outcome.cleanup_status
                    not in {CleanupStatus.not_required, CleanupStatus.completed}
                    else outcome.status
                )
                evaluated.append(str(step.step_id))
                evidence.update(outcome.evidence_references)
            elif step.unresolved_link_id is not None:
                # The referenced entity cannot prove an explicit missing link.
                status = ChainLinkStatus.unresolved
            else:
                status = self._reference_status(
                    step.source_reference, state, selected_policy
                )
                if status is ChainLinkStatus.supported:
                    evaluated.append(str(step.step_id))
                    evidence.update(
                        self._reference_evidence(step.source_reference, state)
                    )
            if status is ChainLinkStatus.supported:
                supported.append(step.unresolved_link_id or str(step.step_id))
                continue
            failure = status
            failed_sequence = step.sequence
            if status is ChainLinkStatus.refuted:
                refuted.append(step.unresolved_link_id or str(step.step_id))
            break

        downstream = tuple(
            str(step.step_id)
            for step in chain.steps
            if failed_sequence is not None and step.sequence > failed_sequence
        )
        executed_downstream = [
            outcomes[step_id]
            for step_id in downstream
            if step_id in outcomes and outcomes[step_id].request_delta.total
        ]
        if executed_downstream:
            raise ValueError("a dependent step executed after a broken prerequisite")
        evaluated_outcomes = [
            outcomes[step_id] for step_id in evaluated if step_id in outcomes
        ]
        request_delta = _sum_request_deltas(evaluated_outcomes)
        combined = self._combined_impact_evidence(chain, state, graph, evidence)
        reason: str | None = None
        if failure is ChainLinkStatus.refuted:
            classification = AttackChainEvaluationClassification.refuted
            reason = "required_link_refuted"
        elif (
            failure is ChainLinkStatus.policy_blocked
            and not selected_policy.policy_block_is_blocked
        ) or (
            failure is ChainLinkStatus.cleanup_failed
            and not selected_policy.cleanup_failure_is_blocked
        ):
            classification = AttackChainEvaluationClassification.inconclusive
            reason = failure.value
        elif failure is not None and failure.breaks_prerequisite:
            classification = AttackChainEvaluationClassification.blocked
            reason = failure.value
        elif failure is not None:
            classification = AttackChainEvaluationClassification.inconclusive
            reason = failure.value
        elif len(evaluated) < len(chain.steps):
            classification = AttackChainEvaluationClassification.inconclusive
            reason = "required_step_not_evaluated"
        elif combined and selected_policy.permit_candidate_findings:
            classification = AttackChainEvaluationClassification.candidate_chain_finding
        else:
            classification = AttackChainEvaluationClassification.supported
            if selected_policy.require_meaningful_combined_impact:
                reason = "combined_impact_not_demonstrated"

        timestamp = occurred_at or state.updated_at
        return AttackChainEvaluation(
            evaluation_id=stable_chain_identifier(
                "chain-evaluation",
                {
                    "chain": chain.attack_chain_id,
                    "revision": state.revision,
                    "outcomes": sorted(outcomes),
                    "classification": classification.value,
                },
            ),
            research_id=state.research_id,
            chain_id=chain.attack_chain_id,
            state_revision=state.revision,
            classification=classification,
            evaluated_step_ids=tuple(evaluated),
            supported_link_ids=tuple(supported),
            refuted_link_ids=tuple(refuted),
            blocking_reason=reason,
            evidence_references=tuple(sorted(evidence)),
            combined_impact_evidence=tuple(sorted(combined)),
            downstream_steps_skipped=downstream,
            request_delta=request_delta,
            provenance_id=chain.provenance_id,
            summary=_evaluation_summary(classification, reason),
            occurred_at=timestamp,
        )

    @staticmethod
    def _reference_status(
        reference: EntityReference,
        state: ResearchState,
        policy: ChainEvaluationPolicy,
    ) -> ChainLinkStatus:
        if reference.entity_kind is EntityKind.fact:
            item = _find(state.facts, "fact_id", reference.entity_id)
            if item is None or item.status not in {
                FactStatus.observed,
                FactStatus.confirmed,
            }:
                return ChainLinkStatus.inconclusive
            if item.derivation_type is DerivationType.model_proposed:
                return ChainLinkStatus.inconclusive
            if (
                item.status is FactStatus.observed
                and not policy.permit_observed_deterministic_facts
            ):
                return ChainLinkStatus.inconclusive
            return ChainLinkStatus.supported
        if reference.entity_kind is EntityKind.relationship:
            item = _find(state.relationships, "relationship_id", reference.entity_id)
            if item is None or item.status not in {
                RelationshipStatus.observed,
                RelationshipStatus.confirmed,
            }:
                return ChainLinkStatus.inconclusive
            if item.derivation_type is DerivationType.model_proposed:
                return ChainLinkStatus.inconclusive
            return ChainLinkStatus.supported
        if reference.entity_kind is EntityKind.finding:
            item = _find(state.findings, "finding_id", reference.entity_id)
            if item is None or item.status is FindingStatus.rejected:
                return ChainLinkStatus.refuted
            if item.status in {
                FindingStatus.candidate,
                FindingStatus.reproducing,
                FindingStatus.reproduced,
                FindingStatus.confirmed,
            }:
                if (
                    item.status in {FindingStatus.candidate, FindingStatus.reproducing}
                    and not policy.permit_candidate_findings
                ):
                    return ChainLinkStatus.inconclusive
                return ChainLinkStatus.supported
            return ChainLinkStatus.inconclusive
        if reference.entity_kind is EntityKind.hypothesis:
            item = _find(state.hypotheses, "hypothesis_id", reference.entity_id)
            if item is None:
                return ChainLinkStatus.inconclusive
            if item.status.value == "refuted":
                return ChainLinkStatus.refuted
            if item.status.value == "supported":
                return ChainLinkStatus.supported
            return ChainLinkStatus.inconclusive
        collection = {
            EntityKind.identity: (state.identities, "identity_id"),
            EntityKind.session: (state.session_refs, "session_ref_id"),
            EntityKind.token: (state.token_refs, "token_ref_id"),
            EntityKind.object: (state.objects, "object_id"),
            EntityKind.surface: (state.surfaces, "surface_id"),
            EntityKind.endpoint: (state.endpoints, "endpoint_id"),
            EntityKind.parameter: (state.parameters, "parameter_id"),
            EntityKind.graphql_operation: (
                state.graphql_operations,
                "operation_id",
            ),
            EntityKind.upload: (state.uploads, "upload_id"),
            EntityKind.workflow: (state.workflows, "workflow_id"),
            EntityKind.observation: (state.observations, "observation_id"),
            EntityKind.experiment_outcome: (
                state.experiment_outcomes,
                "outcome_id",
            ),
        }.get(reference.entity_kind)
        if collection is None:
            return ChainLinkStatus.inconclusive
        item = _find(collection[0], collection[1], reference.entity_id)
        if item is None:
            return ChainLinkStatus.inconclusive
        if reference.entity_kind is EntityKind.identity and not (
            item.controlled and item.eligibility.value == "eligible"
        ):
            return ChainLinkStatus.identity_invalid
        if reference.entity_kind in {EntityKind.session, EntityKind.token} and (
            item.lifecycle.value != "active"
            or not any(
                identity.identity_id == item.identity_id
                and identity.controlled
                and identity.eligibility.value == "eligible"
                for identity in state.identities
            )
        ):
            return ChainLinkStatus.identity_invalid
        if reference.entity_kind is EntityKind.object and not item.test_owned:
            return ChainLinkStatus.object_invalid
        return ChainLinkStatus.supported

    @staticmethod
    def _reference_evidence(
        reference: EntityReference, state: ResearchState
    ) -> tuple[str, ...]:
        mapping = {
            EntityKind.fact: (state.facts, "fact_id"),
            EntityKind.relationship: (state.relationships, "relationship_id"),
            EntityKind.finding: (state.findings, "finding_id"),
            EntityKind.hypothesis: (state.hypotheses, "hypothesis_id"),
            EntityKind.object: (state.objects, "object_id"),
            EntityKind.surface: (state.surfaces, "surface_id"),
            EntityKind.workflow: (state.workflows, "workflow_id"),
            EntityKind.observation: (state.observations, "observation_id"),
            EntityKind.experiment_outcome: (
                state.experiment_outcomes,
                "outcome_id",
            ),
        }.get(reference.entity_kind)
        if mapping is None:
            return ()
        item = _find(mapping[0], mapping[1], reference.entity_id)
        if item is None:
            return ()
        return tuple(
            getattr(item, "evidence_references", ())
            or getattr(item, "supporting_evidence", ())
        )

    @staticmethod
    def _combined_impact_evidence(
        chain: AttackChain,
        state: ResearchState,
        graph: Sequence[GraphAssertion],
        supported_evidence: set[str],
    ) -> set[str]:
        combined = set(chain.combined_impact_evidence)
        relations = [
            item
            for item in state.relationships
            if item.relationship_id in chain.relationship_ids
            and item.status
            in {RelationshipStatus.observed, RelationshipStatus.confirmed}
            and item.derivation_type is not DerivationType.model_proposed
            and item.predicate in MEANINGFUL_CHAIN_RELATIONS
        ]
        relations.extend(
            item
            for item in graph
            if item.assertion_id in chain.relationship_ids
            and item.status
            in {RelationshipStatus.observed, RelationshipStatus.confirmed}
            and item.derivation_type is not DerivationType.model_proposed
            and item.predicate in MEANINGFUL_CHAIN_RELATIONS
        )
        for relation in relations:
            combined.update(relation.evidence_references)
        # Typed cross-surface object bindings are meaningful even when they are
        # represented structurally rather than duplicated as a graph edge.
        if len(chain.surface_ids) > 1 and chain.object_ids and supported_evidence:
            controlled = {
                item.object_id
                for item in state.objects
                if item.test_owned and item.owner_identity_id is not None
            }
            if set(chain.object_ids).issubset(controlled):
                combined.update(supported_evidence)
        return combined & supported_evidence


def create_chain_candidate_finding(
    chain: AttackChain,
    evaluation: AttackChainEvaluation,
    state: ResearchState,
    *,
    provenance_id: str,
    occurred_at: str | None = None,
) -> FindingRecord:
    if (
        evaluation.classification
        is not AttackChainEvaluationClassification.candidate_chain_finding
    ):
        raise ValueError("only combined-impact evidence may create a chain finding")
    if evaluation.chain_id != chain.attack_chain_id:
        raise ValueError("chain evaluation binding mismatch")
    if not chain.hypothesis_ids:
        raise ValueError("a chain finding requires component hypotheses")
    if provenance_id not in {item.provenance_id for item in state.provenance}:
        raise ValueError("chain finding provenance is unavailable")
    cleanup = CleanupStatus.not_required
    chain_outcomes = [
        item
        for item in state.chain_step_outcomes
        if item.chain_id == chain.attack_chain_id
    ]
    if any(item.cleanup_status is CleanupStatus.failed for item in chain_outcomes):
        cleanup = CleanupStatus.failed
    timestamp = occurred_at or evaluation.occurred_at
    evidence = tuple(
        sorted(
            {
                *evaluation.evidence_references,
                *evaluation.combined_impact_evidence,
            }
        )
    )
    return FindingRecord(
        finding_id=stable_chain_identifier(
            "chain-finding",
            {
                "chain": chain.attack_chain_id,
                "fingerprint": chain.semantic_fingerprint,
            },
        ),
        status=FindingStatus.candidate,
        title=f"Candidate chain: {chain.title}",
        category=f"chain:{chain.category}",
        source_hypothesis_id=chain.hypothesis_ids[0],
        candidate_experiment_id=stable_chain_identifier(
            "chain-evidence", evaluation.evaluation_id
        ),
        confirmation_policy_reference=chain.confirmation_policy_reference,
        evidence_references=evidence,
        controlled_impact=ControlledImpact(
            level=ImpactLevel.material,
            summary="The ordered sequence demonstrates broader controlled impact.",
            evidence_references=evaluation.combined_impact_evidence,
        ),
        cleanup_status=cleanup,
        provenance_id=provenance_id,
        research_id=state.research_id,
        target_id=chain.target_ids[0] if chain.target_ids else None,
        surface_id=chain.surface_ids[0] if chain.surface_ids else None,
        security_property_reference=chain.security_property,
        controlled_identity_ids=chain.identity_ids[:2],
        controlled_object_ids=chain.object_ids,
        expected_secure_behavior=chain.expected_secure_behavior,
        observed_vulnerable_behavior=chain.expected_chain_behavior,
        source_request_delta=evaluation.request_delta,
        total_request_count=evaluation.request_delta.total,
        created_at=timestamp,
        updated_at=timestamp,
        state_revision=state.revision,
        source_chain_id=chain.attack_chain_id,
        component_finding_ids=chain.finding_ids,
        component_hypothesis_ids=chain.hypothesis_ids,
        step_evidence_references=evaluation.evidence_references,
        combined_impact_evidence_references=(evaluation.combined_impact_evidence),
    )


def apply_chain_evaluation(
    chain: AttackChain, evaluation: AttackChainEvaluation
) -> AttackChain:
    """Apply only the deterministic evaluator's lifecycle classification."""

    if evaluation.chain_id != chain.attack_chain_id:
        raise ValueError("chain evaluation binding mismatch")
    status = {
        AttackChainEvaluationClassification.supported: AttackChainStatus.supported,
        AttackChainEvaluationClassification.refuted: AttackChainStatus.refuted,
        AttackChainEvaluationClassification.inconclusive: (
            AttackChainStatus.inconclusive
        ),
        AttackChainEvaluationClassification.blocked: AttackChainStatus.inconclusive,
        AttackChainEvaluationClassification.candidate_chain_finding: (
            AttackChainStatus.candidate
        ),
    }[evaluation.classification]
    payload = chain.model_dump(mode="python")
    payload.update(
        status=status,
        evidence_references=tuple(
            sorted({*chain.evidence_references, *evaluation.evidence_references})
        ),
        combined_impact_evidence=evaluation.combined_impact_evidence,
        updated_at=evaluation.occurred_at,
    )
    return AttackChain.model_validate(payload)


class ChainReproductionPlanner:
    def plan(
        self,
        finding: FindingRecord,
        chain: AttackChain,
        experiment_plans: Sequence[ChainExperimentPlan],
        state: ResearchState,
        *,
        provenance_id: str,
        maximum_target_requests: int,
        created_at: str | None = None,
    ) -> ChainReproductionPlan:
        if finding.status is not FindingStatus.candidate:
            raise ValueError("only a candidate chain finding may be reproduced")
        if finding.source_chain_id != chain.attack_chain_id:
            raise ValueError("chain reproduction finding binding mismatch")
        if not experiment_plans:
            raise ValueError("chain reproduction requires executable fresh steps")
        if tuple(item.sequence for item in experiment_plans) != tuple(
            sorted(item.sequence for item in experiment_plans)
        ):
            raise ValueError("chain reproduction plans must preserve link ordering")
        if len({item.plan_id for item in experiment_plans}) != len(experiment_plans):
            raise ValueError("chain reproduction plan IDs must be unique")
        if sum(item.request_cost_estimate for item in experiment_plans) > (
            maximum_target_requests
        ):
            raise ValueError("chain reproduction request ceiling exceeded")
        if any(item.research_id != state.research_id for item in experiment_plans):
            raise ValueError("chain reproduction plan research mismatch")
        if provenance_id not in {item.provenance_id for item in state.provenance}:
            raise ValueError("chain reproduction provenance is unavailable")
        chain_steps_by_link = {
            item.unresolved_link_id: str(item.step_id)
            for item in chain.steps
            if item.unresolved_link_id is not None
        }
        try:
            ordered_chain_step_ids = tuple(
                chain_steps_by_link[item.unresolved_link_id]
                for item in experiment_plans
            )
        except KeyError:
            raise ValueError(
                "chain reproduction plan references an unavailable chain link"
            ) from None
        return ChainReproductionPlan(
            reproduction_id=stable_chain_identifier(
                "chain-reproduction",
                {
                    "chain": chain.attack_chain_id,
                    "finding": finding.finding_id,
                    "revision": state.revision,
                    "plans": [item.plan_id for item in experiment_plans],
                },
            ),
            chain_id=chain.attack_chain_id,
            finding_id=finding.finding_id,
            research_id=state.research_id,
            state_revision=state.revision,
            ordered_step_plan_ids=tuple(item.plan_id for item in experiment_plans),
            ordered_chain_step_ids=ordered_chain_step_ids,
            component_finding_ids=chain.finding_ids,
            maximum_target_requests=maximum_target_requests,
            confirmation_policy_reference=chain.confirmation_policy_reference,
            provenance_id=provenance_id,
            created_at=created_at or state.updated_at,
        )

    @staticmethod
    def evaluate(
        plan: ChainReproductionPlan,
        step_outcomes: Sequence[ChainStepOutcome],
        *,
        occurred_at: str,
    ) -> ChainReproductionOutcome:
        if tuple(item.sequence for item in step_outcomes) != tuple(
            sorted(item.sequence for item in step_outcomes)
        ):
            raise ValueError("chain reproduction must preserve step ordering")
        ordered = tuple(sorted(step_outcomes, key=lambda item: item.sequence))
        if not ordered:
            raise ValueError("chain reproduction requires fresh step outcomes")
        if any(item.chain_id != plan.chain_id for item in ordered):
            raise ValueError("chain reproduction outcome binding mismatch")
        if tuple(item.step_id for item in ordered) != plan.ordered_chain_step_ids:
            raise ValueError("chain reproduction outcomes do not match the plan")
        if len({item.outcome_id for item in ordered}) != len(ordered):
            raise ValueError("chain reproduction outcome IDs must be unique")
        if any(item.authorization_reference is None for item in ordered):
            raise ValueError("chain reproduction must freshly authorize every step")
        if any(item.request_delta.total <= 0 for item in ordered):
            raise ValueError("chain reproduction must make fresh target requests")
        request_delta = _sum_request_deltas(ordered)
        if request_delta.total > plan.maximum_target_requests:
            raise ValueError("chain reproduction request ceiling exceeded")
        statuses = tuple(item.status for item in ordered)
        first_failed = next(
            (
                index
                for index, status in enumerate(statuses)
                if status is not ChainLinkStatus.supported
            ),
            None,
        )
        if first_failed is not None and first_failed < len(statuses) - 1:
            raise ValueError("a chain reproduction continued after a broken link")
        if any(item is ChainLinkStatus.refuted for item in statuses):
            status = ChainLinkStatus.refuted
        elif any(item.breaks_prerequisite for item in statuses):
            status = next(item for item in statuses if item.breaks_prerequisite)
        elif all(item is ChainLinkStatus.supported for item in statuses):
            status = ChainLinkStatus.supported
        else:
            status = ChainLinkStatus.inconclusive
        evidence = tuple(
            sorted({ref for item in ordered for ref in item.evidence_references})
        )
        return ChainReproductionOutcome(
            reproduction_id=plan.reproduction_id,
            chain_id=plan.chain_id,
            finding_id=plan.finding_id,
            status=status,
            step_outcome_ids=tuple(item.outcome_id for item in ordered),
            fresh_authorization_references=tuple(
                str(item.authorization_reference) for item in ordered
            ),
            evidence_references=evidence,
            combined_impact_evidence=(
                evidence if status is ChainLinkStatus.supported else ()
            ),
            request_delta=request_delta,
            cleanup_status=(
                CleanupStatus.completed
                if all(
                    item.cleanup_status
                    in {CleanupStatus.not_required, CleanupStatus.completed}
                    for item in ordered
                )
                else CleanupStatus.failed
            ),
            provenance_id=plan.provenance_id,
            occurred_at=occurred_at,
        )


class AttackChainConfirmationEvaluator:
    """Confirm chains only from deterministic state and fresh reproduction."""

    def evaluate(
        self,
        finding: FindingRecord,
        chain: AttackChain,
        reproductions: Sequence[ChainReproductionOutcome],
        policy: ChainConfirmationPolicy,
        state: ResearchState,
        *,
        occurred_at: str | None = None,
    ) -> ChainConfirmationDecision:
        if finding.status not in {
            FindingStatus.candidate,
            FindingStatus.reproducing,
            FindingStatus.reproduced,
        }:
            raise ValueError("chain confirmation requires a candidate finding")
        if chain.status not in {
            AttackChainStatus.candidate,
            AttackChainStatus.reproducing,
            AttackChainStatus.reproduced,
        }:
            raise ValueError("chain confirmation requires a candidate chain")
        reproduction_ids_seen = [item.reproduction_id for item in reproductions]
        if len(reproduction_ids_seen) != len(set(reproduction_ids_seen)):
            raise ValueError("chain reproductions must have unique IDs")
        action = ChainConfirmationAction.remain_candidate
        reason = "confirmation_requirements_incomplete"
        conflicts = tuple(finding.contradictory_evidence)
        component_findings = [
            _find(state.findings, "finding_id", item)
            for item in finding.component_finding_ids
        ]
        component_hypotheses = [
            _find(state.hypotheses, "hypothesis_id", item)
            for item in finding.component_hypothesis_ids
        ]
        valid_components = (not policy.require_component_evidence) or (
            all(
                item is not None
                and item.status is not FindingStatus.rejected
                and bool(item.evidence_references)
                for item in component_findings
            )
            and all(
                item is not None
                and item.status.value != "refuted"
                and bool(
                    item.supporting_evidence
                    or item.basis_fact_ids
                    or item.basis_relationship_ids
                )
                for item in component_hypotheses
            )
        )
        all_links_resolved = all(
            item.status is ChainLinkStatus.supported for item in chain.unresolved_links
        )
        state_evidence_ids = {item.evidence_id for item in state.evidence}
        component_evidence = set(finding.evidence_references)
        successful = []
        used_authorizations: set[str] = set()
        used_reproduction_evidence: set[str] = set()
        for item in reproductions:
            authorizations = set(item.fresh_authorization_references)
            fresh_evidence = set(item.evidence_references) - component_evidence
            if not (
                item.chain_id == chain.attack_chain_id
                and item.finding_id == finding.finding_id
                and item.status is ChainLinkStatus.supported
                and item.request_delta.total > 0
                and fresh_evidence
                and set(item.evidence_references).issubset(state_evidence_ids)
                and item.provenance_id
                in {entry.provenance_id for entry in state.provenance}
                and bool(authorizations)
                and not (authorizations & used_authorizations)
                and not (fresh_evidence & used_reproduction_evidence)
                and bool(item.combined_impact_evidence)
                and (not policy.require_ordering or item.ordering_valid)
                and item.dependencies_preserved
                and (
                    not policy.require_cleanup
                    or item.cleanup_status
                    in {CleanupStatus.not_required, CleanupStatus.completed}
                )
            ):
                continue
            successful.append(item)
            used_authorizations.update(authorizations)
            used_reproduction_evidence.update(fresh_evidence)
        reproduction_ids = tuple(item.reproduction_id for item in successful)
        confirmed_evidence = tuple(
            sorted(
                {
                    *finding.evidence_references,
                    *finding.step_evidence_references,
                    *finding.combined_impact_evidence_references,
                    *(
                        reference
                        for item in successful
                        for reference in item.evidence_references
                    ),
                }
            )
        )
        if finding.source_chain_id != chain.attack_chain_id:
            reason = "chain_finding_binding_mismatch"
        elif finding.research_id != state.research_id:
            reason = "chain_finding_research_mismatch"
        elif (
            finding.confirmation_policy_reference != policy.policy_reference
            or chain.confirmation_policy_reference != policy.policy_reference
        ):
            reason = "chain_confirmation_policy_mismatch"
        elif conflicts and policy.reject_on_contradiction:
            action = ChainConfirmationAction.reject
            reason = "contradictory_chain_evidence"
        elif not valid_components:
            reason = "component_evidence_invalid"
        elif policy.require_all_links_resolved and not all_links_resolved:
            reason = "unresolved_chain_links"
        elif policy.require_combined_impact and not (
            finding.combined_impact_evidence_references
        ):
            reason = "combined_impact_missing"
        elif policy.require_cleanup and finding.cleanup_status not in {
            CleanupStatus.not_required,
            CleanupStatus.completed,
        }:
            reason = "cleanup_incomplete"
        elif len(successful) < (
            policy.minimum_independent_reproductions
            if policy.require_live_reproduction
            else 1
        ):
            reason = "independent_reproduction_incomplete"
        else:
            action = ChainConfirmationAction.confirm
            reason = "chain_confirmation_requirements_satisfied"
        return ChainConfirmationDecision(
            decision_id=stable_chain_identifier(
                "chain-confirmation",
                {
                    "finding": finding.finding_id,
                    "policy": policy.fingerprint,
                    "reproductions": reproduction_ids,
                    "action": action.value,
                },
            ),
            chain_id=chain.attack_chain_id,
            finding_id=finding.finding_id,
            action=action,
            policy_reference=policy.policy_reference,
            policy_fingerprint=policy.fingerprint,
            reproduction_ids=reproduction_ids,
            confirmed_evidence_references=(
                confirmed_evidence if action is ChainConfirmationAction.confirm else ()
            ),
            conflicting_evidence_references=(
                conflicts if action is ChainConfirmationAction.reject else ()
            ),
            reason_code=reason,
            occurred_at=occurred_at or state.updated_at,
        )

    @staticmethod
    def promote(
        finding: FindingRecord,
        chain: AttackChain,
        decision: ChainConfirmationDecision,
        reproductions: Sequence[ChainReproductionOutcome],
    ) -> tuple[FindingRecord, AttackChain]:
        if decision.action is not ChainConfirmationAction.confirm:
            raise ValueError(
                "only a deterministic confirm decision may promote a chain"
            )
        if (
            decision.chain_id != chain.attack_chain_id
            or decision.finding_id != finding.finding_id
        ):
            raise ValueError("chain confirmation decision binding mismatch")
        by_id = {item.reproduction_id: item for item in reproductions}
        if len(by_id) != len(reproductions):
            raise ValueError("chain reproduction IDs must be unique")
        try:
            selected_reproductions = tuple(
                by_id[item] for item in decision.reproduction_ids
            )
        except KeyError:
            raise ValueError(
                "chain confirmation reproduction binding is unavailable"
            ) from None
        if any(
            item.chain_id != chain.attack_chain_id
            or item.finding_id != finding.finding_id
            or item.status is not ChainLinkStatus.supported
            or not item.combined_impact_evidence
            or item.request_delta.total <= 0
            or item.cleanup_status
            not in {CleanupStatus.not_required, CleanupStatus.completed}
            for item in selected_reproductions
        ):
            raise ValueError("chain confirmation reproduction is not promotable")
        experiment_ids = tuple(
            stable_chain_identifier(
                "chain-reproduction-experiment", item.reproduction_id
            )
            for item in selected_reproductions
        )
        finding_payload = finding.model_dump(mode="python")
        finding_payload.update(
            status=FindingStatus.confirmed,
            reproduction_experiment_ids=experiment_ids,
            chain_reproduction_ids=decision.reproduction_ids,
            confirmed_evidence_references=(decision.confirmed_evidence_references),
            confirmation_decision_id=decision.decision_id,
            confirmation_policy_fingerprint=decision.policy_fingerprint,
            cleanup_status=CleanupStatus.completed,
            total_request_count=(
                finding.total_request_count
                + sum(item.request_delta.total for item in selected_reproductions)
            ),
            updated_at=decision.occurred_at,
        )
        chain_payload = chain.model_dump(mode="python")
        chain_payload.update(
            status=AttackChainStatus.confirmed,
            reproduction_ids=decision.reproduction_ids,
            evidence_references=tuple(
                sorted(
                    {
                        *chain.evidence_references,
                        *decision.confirmed_evidence_references,
                    }
                )
            ),
            combined_impact_evidence=tuple(
                sorted(
                    {
                        *chain.combined_impact_evidence,
                        *(
                            reference
                            for item in selected_reproductions
                            for reference in item.combined_impact_evidence
                        ),
                    }
                )
            ),
            updated_at=decision.occurred_at,
        )
        return (
            FindingRecord.model_validate(finding_payload),
            AttackChain.model_validate(chain_payload),
        )


def chain_evaluation_assertion(
    evaluation: AttackChainEvaluation,
    *,
    provenance_id: str,
) -> GraphAssertion:
    relation = {
        AttackChainEvaluationClassification.refuted: (
            ResearchPredicate.chain_refuted_by
        ),
        AttackChainEvaluationClassification.blocked: (
            ResearchPredicate.chain_tested_by
        ),
    }.get(evaluation.classification, ResearchPredicate.chain_supported_by)
    evidence = (
        tuple(evaluation.evidence_references)
        if evaluation.evidence_references
        else tuple(evaluation.combined_impact_evidence)
    )
    if not evidence:
        raise ValueError("chain graph assertions require evidence")
    return GraphAssertion(
        assertion_id=stable_chain_identifier(
            "chain-assertion", evaluation.evaluation_id
        ),
        research_id=evaluation.research_id,
        source=EntityReference(
            entity_kind=EntityKind.attack_chain, entity_id=evaluation.chain_id
        ),
        predicate=relation,
        target=EntityReference(entity_kind=EntityKind.evidence, entity_id=evidence[0]),
        status=RelationshipStatus.confirmed,
        evidence_references=evidence,
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance_id,
        asserted_at=evaluation.occurred_at,
    )


def chain_step_assertion(
    outcome: ChainStepOutcome,
    *,
    research_id: str,
    provenance_id: str,
) -> GraphAssertion:
    if not outcome.evidence_references:
        raise ValueError("chain tested-by relations require step evidence")
    return GraphAssertion(
        assertion_id=stable_chain_identifier(
            "chain-step-assertion", outcome.outcome_id
        ),
        research_id=research_id,
        source=EntityReference(
            entity_kind=EntityKind.attack_chain, entity_id=outcome.chain_id
        ),
        predicate=ResearchPredicate.chain_tested_by,
        target=EntityReference(
            entity_kind=EntityKind.evidence,
            entity_id=outcome.evidence_references[0],
        ),
        status=RelationshipStatus.confirmed,
        evidence_references=outcome.evidence_references,
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance_id,
        asserted_at=outcome.occurred_at,
    )


def chain_reproduction_assertion(
    outcome: ChainReproductionOutcome,
    *,
    research_id: str,
    provenance_id: str,
) -> GraphAssertion:
    return GraphAssertion(
        assertion_id=stable_chain_identifier(
            "chain-reproduction-assertion", outcome.reproduction_id
        ),
        research_id=research_id,
        source=EntityReference(
            entity_kind=EntityKind.attack_chain, entity_id=outcome.chain_id
        ),
        predicate=ResearchPredicate.chain_reproduced_by,
        target=EntityReference(
            entity_kind=EntityKind.reproduction,
            entity_id=outcome.reproduction_id,
        ),
        status=RelationshipStatus.confirmed,
        evidence_references=outcome.evidence_references,
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance_id,
        asserted_at=outcome.occurred_at,
    )


def chain_confirmation_assertion(
    decision: ChainConfirmationDecision,
    *,
    research_id: str,
    provenance_id: str,
) -> GraphAssertion:
    if decision.action is not ChainConfirmationAction.confirm:
        raise ValueError("only confirmed chains create confirmation relations")
    return GraphAssertion(
        assertion_id=stable_chain_identifier(
            "chain-confirmation-assertion", decision.decision_id
        ),
        research_id=research_id,
        source=EntityReference(
            entity_kind=EntityKind.attack_chain, entity_id=decision.chain_id
        ),
        predicate=ResearchPredicate.chain_confirmed_by,
        target=EntityReference(
            entity_kind=EntityKind.finding, entity_id=decision.finding_id
        ),
        status=RelationshipStatus.confirmed,
        evidence_references=decision.confirmed_evidence_references,
        derivation_type=DerivationType.deterministic,
        provenance_id=provenance_id,
        asserted_at=decision.occurred_at,
    )


def _find(collection: Sequence[object], field: str, value: str) -> object | None:
    return next((item for item in collection if getattr(item, field) == value), None)


def _sum_request_deltas(outcomes: Sequence[ChainStepOutcome]):
    from agent_core.request_budget import RequestDelta

    categories = {
        name: sum(getattr(item.request_delta, name) for item in outcomes)
        for name in ("discovery", "auth", "verification", "cleanup")
    }
    total = sum(categories.values())
    return RequestDelta(**categories, attempted=total, total=total)


def _evaluation_summary(
    classification: AttackChainEvaluationClassification, reason: str | None
) -> str:
    suffix = f" ({reason})." if reason else "."
    return f"Deterministic attack-chain evaluation: {classification.value}{suffix}"


__all__ = [
    "AttackChainConfirmationEvaluator",
    "AttackChainEvaluation",
    "AttackChainEvaluator",
    "ChainEvaluationPolicy",
    "ChainReproductionPlanner",
    "MEANINGFUL_CHAIN_RELATIONS",
    "apply_chain_evaluation",
    "chain_confirmation_assertion",
    "chain_evaluation_assertion",
    "chain_reproduction_assertion",
    "chain_step_assertion",
    "create_chain_candidate_finding",
]
