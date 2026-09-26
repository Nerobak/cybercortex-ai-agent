"""Deterministic attack-chain candidate construction and bounded planning."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.research.candidates import ExperimentCandidate, materialize_candidate
from agent_core.research.chains import (
    AttackChainCandidate,
    AttackChainHypothesis,
    ChainBudgetLimits,
    ChainBudgetState,
    ChainBudgetSummary,
    ChainLinkStatus,
    ChainSelectionAction,
    ChainSelectionDecision,
    MAX_CHAIN_CANDIDATES,
    PublicSafeChainCandidateSummary,
    PublicSafeChainPacket,
    UnresolvedChainLink,
    chain_candidate_fingerprint,
    stable_chain_digest,
    stable_chain_identifier,
)
from agent_core.research.experiments import ExperimentProposal
from agent_core.research.graph import GraphAssertion, GraphRelation
from agent_core.research.state import (
    AttackChain,
    AttackChainStep,
    Fact,
    FindingRecord,
    HypothesisRecord,
    Relationship,
    ResearchState,
)
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    EntityReference,
    FactStatus,
    FindingStatus,
    HypothesisResearchStatus,
    IdentityEligibility,
    OpaqueIdentifier,
    RelationshipStatus,
    ResearchConfidence,
    ResearchContract,
    ResearchPredicate,
    AttackChainStatus,
    SurfaceType,
)

if TYPE_CHECKING:
    from agent_core.research.graph import ResearchGraphRepository


CHAIN_RELATIONS = frozenset(
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
        ResearchPredicate.references,
        GraphRelation.same_object_as,
        GraphRelation.references,
        GraphRelation.requires,
    }
)


class ChainExperimentPlan(ResearchContract):
    """One ordinary proposal for only the next unresolved chain link."""

    plan_id: OpaqueIdentifier
    research_id: OpaqueIdentifier
    chain_candidate_id: OpaqueIdentifier
    chain_hypothesis_id: OpaqueIdentifier
    unresolved_link_id: OpaqueIdentifier
    sequence: StrictInt = Field(ge=1, le=10)
    experiment_candidate_id: OpaqueIdentifier
    experiment_proposal: ExperimentProposal
    required_predecessor_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=10
    )
    current_state_authorization_required: StrictBool = True
    request_cost_estimate: StrictInt = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_plan(self) -> "ChainExperimentPlan":
        if not self.current_state_authorization_required:
            raise ValueError("every chain step requires current-state authorization")
        if self.experiment_proposal.research_id != self.research_id:
            raise ValueError("chain plan proposal belongs to another research run")
        return self


class ChainCandidatePolicy(ResearchContract):
    """Operator-owned deterministic eligibility policy."""

    maximum_risk: RiskLevel = RiskLevel.high
    allowed_categories: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=50)
    permit_single_candidate_auto_selection: StrictBool = True


class AttackChainCandidateBuilder:
    """Construct a small set of evidence-backed generic chain possibilities.

    The builder follows only typed, evidenced edges and typed structural
    relationships already present in research state. It never asks a model to
    invent a path and never treats two adjacent findings as a chain.
    """

    def __init__(
        self,
        limits: ChainBudgetLimits | None = None,
        *,
        policy: ChainCandidatePolicy | None = None,
        registered_capabilities: Iterable[str] | None = None,
        registered_primitives: Iterable[str] | None = None,
    ) -> None:
        if registered_capabilities is not None and registered_primitives is not None:
            raise ValueError("provide only one registered chain capability source")
        self.limits = limits or ChainBudgetLimits()
        self.policy = policy or ChainCandidatePolicy()
        self.registered_capabilities = (
            frozenset(registered_capabilities or registered_primitives or ())
            if registered_capabilities is not None or registered_primitives is not None
            else None
        )

    def build(
        self,
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None = None,
        *,
        experiment_candidates: Sequence[ExperimentCandidate] = (),
        expected_state_revision: int | None = None,
        budget_state: ChainBudgetState | None = None,
        policy: ChainCandidatePolicy | None = None,
    ) -> tuple[AttackChainCandidate, ...]:
        if expected_state_revision is not None and state.revision != (
            expected_state_revision
        ):
            return ()
        if budget_state is not None and (
            budget_state.candidates_considered
            >= budget_state.limits.maximum_chain_candidates
            or budget_state.active_hypotheses
            >= budget_state.limits.maximum_active_chain_hypotheses
        ):
            return ()
        maximum_results = min(
            self.limits.maximum_chain_candidates, MAX_CHAIN_CANDIDATES
        )
        if budget_state is not None:
            maximum_results = min(
                maximum_results,
                budget_state.limits.maximum_chain_candidates
                - budget_state.candidates_considered,
            )
        if maximum_results <= 0:
            return ()

        selected_policy = policy or self.policy
        eligible_experiments = tuple(
            item
            for item in experiment_candidates
            if self.registered_capabilities is None
            or item.primitive_kind in self.registered_capabilities
            or item.capability in self.registered_capabilities
        )
        assertions = self._assertions(state, graph)
        edges = [
            item
            for item in (*state.relationships, *assertions)
            if self._eligible_edge(item, state) and item.predicate in CHAIN_RELATIONS
        ]
        raw: list[AttackChainCandidate] = []
        raw.extend(self._edge_candidates(state, edges, eligible_experiments))
        raw.extend(self._path_candidates(state, edges, eligible_experiments))
        raw.extend(self._structural_object_candidates(state, eligible_experiments))

        deduplicated: dict[str, AttackChainCandidate] = {}
        for candidate in sorted(raw, key=lambda item: item.candidate_id):
            if _risk_rank(candidate.risk) > _risk_rank(selected_policy.maximum_risk):
                continue
            if selected_policy.allowed_categories and (
                candidate.category not in selected_policy.allowed_categories
            ):
                continue
            if len(candidate.ordered_references) > self.limits.maximum_chain_depth:
                continue
            if (
                len(candidate.required_unresolved_links)
                > self.limits.maximum_unresolved_links_per_chain
            ):
                continue
            if candidate.required_unresolved_links and not (
                candidate.available_experiment_candidates
            ):
                # An untestable gap is speculation, not an eligible candidate.
                continue
            deduplicated.setdefault(candidate.semantic_fingerprint, candidate)
            if len(deduplicated) >= maximum_results:
                break
        return tuple(deduplicated.values())

    def _edge_candidates(
        self,
        state: ResearchState,
        edges: Sequence[Relationship | GraphAssertion],
        experiments: tuple[ExperimentCandidate, ...],
    ) -> tuple[AttackChainCandidate, ...]:
        results: list[AttackChainCandidate] = []
        for edge in edges:
            source = edge.source
            target = edge.target
            if source == target:
                continue
            if not (
                self._eligible_reference(source, state)
                and self._eligible_reference(target, state)
            ):
                continue
            surfaces = self._surface_ids(source, state) | self._surface_ids(
                target, state
            )
            boundary_relation = edge.predicate in {
                ResearchPredicate.enables,
                ResearchPredicate.produces_context_for,
                ResearchPredicate.crosses_surface,
                ResearchPredicate.crosses_identity_boundary,
                ResearchPredicate.crosses_tenant_boundary,
                ResearchPredicate.reaches,
            }
            if len(surfaces) < 2 and not boundary_relation:
                continue

            related_experiments = self._matching_experiments(
                experiments, state, source, target, surfaces
            )
            unresolved: tuple[UnresolvedChainLink, ...] = ()
            ordered = (source, target)
            hypotheses = tuple(
                sorted(
                    reference.entity_id
                    for reference in ordered
                    if reference.entity_kind is EntityKind.hypothesis
                )
            )
            if not self._both_security_outcomes(source, target, state):
                if not related_experiments:
                    continue
                unresolved = (
                    self._unresolved_link(
                        source,
                        target,
                        related_experiments,
                        edge_id=self._edge_id(edge),
                    ),
                )

            evidence = tuple(sorted(set(edge.evidence_references)))
            provenance = (edge.provenance_id,)
            category = self._category(ordered, state)
            results.append(
                self._candidate(
                    state,
                    category=category,
                    ordered=ordered,
                    relationship_ids=(self._edge_id(edge),),
                    hypotheses=hypotheses,
                    unresolved=unresolved,
                    experiments=related_experiments,
                    evidence=evidence,
                    provenance=provenance,
                    surfaces=surfaces,
                )
            )
            if len(results) >= self.limits.maximum_chain_candidates * 2:
                break
        return tuple(results)

    def _path_candidates(
        self,
        state: ResearchState,
        edges: Sequence[Relationship | GraphAssertion],
        experiments: tuple[ExperimentCandidate, ...],
    ) -> tuple[AttackChainCandidate, ...]:
        """Compose only the first bounded, acyclic evidenced paths."""

        by_source: dict[tuple[EntityKind, str], list[Relationship | GraphAssertion]] = (
            {}
        )
        for edge in sorted(edges, key=self._edge_id):
            by_source.setdefault(
                (edge.source.entity_kind, edge.source.entity_id), []
            ).append(edge)
        paths: list[tuple[Relationship | GraphAssertion, ...]] = [
            (edge,) for edge in sorted(edges, key=self._edge_id)
        ][: self.limits.maximum_chain_candidates * 2]
        results: list[AttackChainCandidate] = []
        examined_extensions = 0
        maximum_extensions = self.limits.maximum_chain_candidates * 10
        for _depth in range(2, self.limits.maximum_chain_depth):
            extended: list[tuple[Relationship | GraphAssertion, ...]] = []
            for path in paths:
                last = path[-1]
                visited = {
                    (path[0].source.entity_kind, path[0].source.entity_id),
                    *(
                        (item.target.entity_kind, item.target.entity_id)
                        for item in path
                    ),
                }
                for edge in by_source.get(
                    (last.target.entity_kind, last.target.entity_id), ()
                ):
                    examined_extensions += 1
                    if examined_extensions > maximum_extensions:
                        return tuple(results)
                    marker = (edge.target.entity_kind, edge.target.entity_id)
                    if marker in visited:
                        continue
                    candidate_path = (*path, edge)
                    extended.append(candidate_path)
                    ordered = (
                        candidate_path[0].source,
                        *(item.target for item in candidate_path),
                    )
                    surfaces = {
                        surface
                        for reference in ordered
                        for surface in self._surface_ids(reference, state)
                    }
                    boundary = any(
                        item.predicate
                        in {
                            ResearchPredicate.enables,
                            ResearchPredicate.produces_context_for,
                            ResearchPredicate.crosses_surface,
                            ResearchPredicate.crosses_identity_boundary,
                            ResearchPredicate.crosses_tenant_boundary,
                            ResearchPredicate.reaches,
                        }
                        for item in candidate_path
                    )
                    if len(surfaces) < 2 and not boundary:
                        continue
                    related = self._matching_experiments(
                        experiments, state, ordered[-2], ordered[-1], surfaces
                    )
                    unresolved: tuple[UnresolvedChainLink, ...] = ()
                    if not self._both_security_outcomes(
                        ordered[-2], ordered[-1], state
                    ):
                        if not related:
                            continue
                        unresolved = (
                            self._unresolved_link(
                                ordered[-2],
                                ordered[-1],
                                related,
                                edge_id=self._edge_id(candidate_path[-1]),
                            ),
                        )
                    results.append(
                        self._candidate(
                            state,
                            category=self._category(ordered, state),
                            ordered=ordered,
                            relationship_ids=tuple(
                                self._edge_id(item) for item in candidate_path
                            ),
                            hypotheses=tuple(
                                reference.entity_id
                                for reference in ordered
                                if reference.entity_kind is EntityKind.hypothesis
                            ),
                            unresolved=unresolved,
                            experiments=related,
                            evidence=tuple(
                                sorted(
                                    {
                                        reference
                                        for item in candidate_path
                                        for reference in item.evidence_references
                                    }
                                )
                            ),
                            provenance=tuple(
                                sorted({item.provenance_id for item in candidate_path})
                            ),
                            surfaces=surfaces,
                        )
                    )
                    if len(results) >= self.limits.maximum_chain_candidates * 2:
                        return tuple(results)
            paths = extended
            if not paths:
                break
        return tuple(results)

    def _structural_object_candidates(
        self,
        state: ResearchState,
        experiments: tuple[ExperimentCandidate, ...],
    ) -> tuple[AttackChainCandidate, ...]:
        """Use only explicit object-to-parameter structure already in state."""

        parameters = {item.parameter_id: item for item in state.parameters}
        endpoints = {item.endpoint_id: item for item in state.endpoints}
        results: list[AttackChainCandidate] = []
        for obj in state.objects:
            if not (
                obj.test_owned
                and obj.owner_identity_id is not None
                and obj.evidence_references
                and self._controlled_identity(obj.owner_identity_id, state)
            ):
                continue
            for parameter_id in obj.parameter_references:
                parameter = parameters.get(parameter_id)
                endpoint = endpoints.get(parameter.endpoint_id) if parameter else None
                if endpoint is None or endpoint.surface_id == obj.surface_id:
                    continue
                source_fact = next(
                    (
                        item
                        for item in state.facts
                        if self._eligible_fact(item, state)
                        and self._fact_mentions(item, obj.object_id)
                    ),
                    None,
                )
                hypothesis = next(
                    (
                        item
                        for item in state.hypotheses
                        if item.target_id == obj.target_id
                        and item.surface_id == endpoint.surface_id
                        and item.status
                        not in {
                            HypothesisResearchStatus.refuted,
                            HypothesisResearchStatus.closed,
                        }
                        and (
                            item.supporting_evidence
                            or item.basis_fact_ids
                            or item.basis_relationship_ids
                        )
                    ),
                    None,
                )
                if source_fact is None or hypothesis is None:
                    continue
                ordered = (
                    EntityReference(
                        entity_kind=EntityKind.fact, entity_id=source_fact.fact_id
                    ),
                    EntityReference(
                        entity_kind=EntityKind.object, entity_id=obj.object_id
                    ),
                    EntityReference(
                        entity_kind=EntityKind.hypothesis,
                        entity_id=hypothesis.hypothesis_id,
                    ),
                )
                related = tuple(
                    item
                    for item in experiments
                    if item.research_id == state.research_id
                    and item.state_revision == state.revision
                    and item.risk_class is not RiskLevel.prohibited
                    and (
                        item.hypothesis_id == hypothesis.hypothesis_id
                        or item.controlled_object_id == obj.object_id
                    )
                )
                if not related:
                    continue
                unresolved = (
                    self._unresolved_link(
                        ordered[1],
                        ordered[2],
                        related,
                        edge_id=f"object-parameter:{obj.object_id}:{parameter_id}",
                    ),
                )
                evidence = tuple(
                    sorted(
                        {
                            *obj.evidence_references,
                            *parameter.evidence_references,
                            *endpoint.evidence_references,
                            *source_fact.evidence_references,
                            *hypothesis.supporting_evidence,
                        }
                    )
                )
                provenance = tuple(
                    sorted(
                        {
                            obj.provenance_id,
                            parameter.provenance_id,
                            endpoint.provenance_id,
                            source_fact.provenance_id,
                            hypothesis.provenance_id,
                        }
                    )
                )
                results.append(
                    self._candidate(
                        state,
                        category=self._category(ordered, state),
                        ordered=ordered,
                        relationship_ids=(),
                        hypotheses=(hypothesis.hypothesis_id,),
                        unresolved=unresolved,
                        experiments=related,
                        evidence=evidence,
                        provenance=provenance,
                        surfaces={obj.surface_id, endpoint.surface_id},
                        object_ids=(obj.object_id,),
                        identity_ids=(obj.owner_identity_id,),
                    )
                )
                if len(results) >= self.limits.maximum_chain_candidates * 2:
                    return tuple(results)
        return tuple(results)

    def _candidate(
        self,
        state: ResearchState,
        *,
        category: str,
        ordered: tuple[EntityReference, ...],
        relationship_ids: tuple[str, ...],
        hypotheses: tuple[str, ...],
        unresolved: tuple[UnresolvedChainLink, ...],
        experiments: tuple[ExperimentCandidate, ...],
        evidence: tuple[str, ...],
        provenance: tuple[str, ...],
        surfaces: set[str],
        object_ids: tuple[str, ...] = (),
        identity_ids: tuple[str, ...] = (),
    ) -> AttackChainCandidate:
        findings = tuple(
            reference.entity_id
            for reference in ordered
            if reference.entity_kind is EntityKind.finding
        )
        facts = tuple(
            reference.entity_id
            for reference in ordered
            if reference.entity_kind is EntityKind.fact
        )
        inferred_objects = {
            reference.entity_id
            for reference in ordered
            if reference.entity_kind is EntityKind.object
        }
        inferred_identities = {
            reference.entity_id
            for reference in ordered
            if reference.entity_kind is EntityKind.identity
        }
        inferred_objects.update(object_ids)
        inferred_identities.update(identity_ids)
        inferred_identities.update(
            identity_id
            for item in experiments
            for identity_id in (
                item.primary_identity_id,
                item.comparison_identity_id,
            )
            if identity_id is not None
        )
        inferred_objects.update(
            item.controlled_object_id
            for item in experiments
            if item.controlled_object_id is not None
        )
        hypotheses = tuple(
            sorted({*hypotheses, *(item.hypothesis_id for item in experiments)})
        )
        for reference in ordered:
            if reference.entity_kind is EntityKind.token:
                token = _find(state.token_refs, "token_ref_id", reference.entity_id)
                if token is not None:
                    inferred_identities.add(token.identity_id)
            elif reference.entity_kind is EntityKind.session:
                session = _find(
                    state.session_refs, "session_ref_id", reference.entity_id
                )
                if session is not None:
                    inferred_identities.add(session.identity_id)
        targets = self._target_ids(ordered, state)
        if not targets:
            raise ValueError("eligible chain references must resolve to a target")
        payload = {
            "category": category,
            "ordered_links": [
                (item.entity_kind.value, item.entity_id) for item in ordered
            ],
            "security_property": f"security-property:{category}",
            "surfaces": sorted(surfaces),
            "identities": sorted(inferred_identities),
            "objects": sorted(inferred_objects),
            "unresolved": [
                {
                    "from": (
                        item.from_reference.entity_kind.value,
                        item.from_reference.entity_id,
                    ),
                    "to": (
                        item.to_reference.entity_kind.value,
                        item.to_reference.entity_id,
                    ),
                    "capabilities": sorted(item.allowed_experiment_capabilities),
                }
                for item in unresolved
            ],
        }
        fingerprint = stable_chain_digest(payload)
        candidate = AttackChainCandidate(
            candidate_id=f"chain-candidate-{fingerprint[7:31]}",
            research_id=state.research_id,
            state_revision=state.revision,
            category=category,
            ordered_references=ordered,
            target_ids=tuple(sorted(targets)),
            surface_ids=tuple(sorted(surfaces)),
            identity_ids=tuple(sorted(inferred_identities)),
            object_ids=tuple(sorted(inferred_objects)),
            hypothesis_ids=hypotheses,
            finding_ids=findings,
            fact_ids=facts,
            relationship_ids=relationship_ids,
            entry_condition="Existing typed evidence establishes the first chain link.",
            security_property=f"security-property:{category}",
            expected_secure_behavior="A required security boundary stops the ordered chain.",
            expected_chain_behavior="The ordered links demonstrate a broader controlled impact.",
            expected_information_value=0.75 if unresolved else 0.5,
            required_unresolved_links=unresolved,
            available_experiment_candidates=tuple(
                sorted(item.candidate_id for item in experiments)
            ),
            request_cost_estimate=sum(item.request_estimate for item in unresolved),
            risk=max(
                (item.risk_class for item in experiments),
                key=_risk_rank,
                default=RiskLevel.passive,
            ),
            evidence_references=evidence,
            provenance_references=provenance,
            semantic_fingerprint=fingerprint,
        )
        # Keep the constructor and standalone deduplicator in lockstep.
        if chain_candidate_fingerprint(candidate) != fingerprint:
            raise ValueError("internal chain fingerprint mismatch")
        return candidate

    @staticmethod
    def _unresolved_link(
        source: EntityReference,
        target: EntityReference,
        experiments: tuple[ExperimentCandidate, ...],
        *,
        edge_id: str,
    ) -> UnresolvedChainLink:
        capabilities = tuple(sorted({item.primitive_kind for item in experiments}))
        request_estimate = min(
            max((item.worst_case_requests for item in experiments), default=0),
            10_000,
        )
        return UnresolvedChainLink(
            link_id=stable_chain_identifier(
                "chain-link",
                {
                    "edge": edge_id,
                    "source": source.model_dump(mode="json"),
                    "target": target.model_dump(mode="json"),
                    "capabilities": capabilities,
                },
            ),
            from_reference=source,
            to_reference=target,
            claim="A bounded experiment can determine whether this chain link holds.",
            required_evidence=("predicate:bounded-chain-link",),
            allowed_experiment_capabilities=capabilities,
            risk=max(
                (item.risk_class for item in experiments),
                key=_risk_rank,
                default=RiskLevel.passive,
            ),
            request_estimate=request_estimate,
        )

    @staticmethod
    def _matching_experiments(
        experiments: tuple[ExperimentCandidate, ...],
        state: ResearchState,
        source: EntityReference,
        target: EntityReference,
        surfaces: set[str],
    ) -> tuple[ExperimentCandidate, ...]:
        reference_ids = {source.entity_id, target.entity_id}
        return tuple(
            item
            for item in experiments
            if item.research_id == state.research_id
            and item.state_revision == state.revision
            and item.risk_class is not RiskLevel.prohibited
            and (
                item.surface_id in surfaces
                or item.hypothesis_id in reference_ids
                or item.controlled_object_id in reference_ids
            )
        )

    @staticmethod
    def _both_security_outcomes(
        source: EntityReference, target: EntityReference, state: ResearchState
    ) -> bool:
        eligible = {EntityKind.fact, EntityKind.finding}
        return source.entity_kind in eligible and target.entity_kind in eligible

    @staticmethod
    def _edge_id(edge: Relationship | GraphAssertion) -> str:
        return (
            edge.relationship_id
            if isinstance(edge, Relationship)
            else edge.assertion_id
        )

    @staticmethod
    def _eligible_edge(
        edge: Relationship | GraphAssertion, state: ResearchState
    ) -> bool:
        return (
            edge.status in {RelationshipStatus.observed, RelationshipStatus.confirmed}
            and bool(edge.evidence_references)
            and edge.derivation_type is not DerivationType.model_proposed
            and edge.provenance_id in {item.provenance_id for item in state.provenance}
            and set(edge.evidence_references).issubset(
                {item.evidence_id for item in state.evidence}
            )
        )

    def _eligible_reference(
        self, reference: EntityReference, state: ResearchState
    ) -> bool:
        if reference.entity_kind is EntityKind.fact:
            item = _find(state.facts, "fact_id", reference.entity_id)
            return isinstance(item, Fact) and self._eligible_fact(item, state)
        if reference.entity_kind is EntityKind.relationship:
            item = _find(state.relationships, "relationship_id", reference.entity_id)
            return isinstance(item, Relationship) and self._eligible_edge(item, state)
        if reference.entity_kind is EntityKind.finding:
            item = _find(state.findings, "finding_id", reference.entity_id)
            return (
                isinstance(item, FindingRecord)
                and item.status
                in {
                    FindingStatus.candidate,
                    FindingStatus.reproducing,
                    FindingStatus.reproduced,
                    FindingStatus.confirmed,
                }
                and bool(item.evidence_references)
            )
        if reference.entity_kind is EntityKind.hypothesis:
            item = _find(state.hypotheses, "hypothesis_id", reference.entity_id)
            return (
                isinstance(item, HypothesisRecord)
                and item.status
                not in {
                    HypothesisResearchStatus.refuted,
                    HypothesisResearchStatus.closed,
                }
                and bool(
                    item.supporting_evidence
                    or item.basis_fact_ids
                    or item.basis_relationship_ids
                )
            )
        if reference.entity_kind is EntityKind.identity:
            return self._controlled_identity(reference.entity_id, state)
        if reference.entity_kind is EntityKind.session:
            item = _find(state.session_refs, "session_ref_id", reference.entity_id)
            return bool(
                item
                and item.lifecycle.value == "active"
                and self._controlled_identity(item.identity_id, state)
            )
        if reference.entity_kind is EntityKind.token:
            item = _find(state.token_refs, "token_ref_id", reference.entity_id)
            return bool(
                item
                and item.lifecycle.value == "active"
                and self._controlled_identity(item.identity_id, state)
            )
        if reference.entity_kind is EntityKind.object:
            item = _find(state.objects, "object_id", reference.entity_id)
            return bool(
                item
                and item.test_owned
                and item.owner_identity_id
                and item.evidence_references
                and self._controlled_identity(item.owner_identity_id, state)
            )
        if reference.entity_kind is EntityKind.experiment_outcome:
            item = _find(state.experiment_outcomes, "outcome_id", reference.entity_id)
            return bool(item and item.evidence_references)
        collection_name = {
            EntityKind.surface: "surfaces",
            EntityKind.endpoint: "endpoints",
            EntityKind.parameter: "parameters",
            EntityKind.graphql_operation: "graphql_operations",
            EntityKind.upload: "uploads",
            EntityKind.workflow: "workflows",
            EntityKind.observation: "observations",
        }.get(reference.entity_kind)
        if collection_name is None:
            return False
        collection = getattr(state, collection_name)
        id_field = {
            EntityKind.surface: "surface_id",
            EntityKind.endpoint: "endpoint_id",
            EntityKind.parameter: "parameter_id",
            EntityKind.graphql_operation: "operation_id",
            EntityKind.upload: "upload_id",
            EntityKind.workflow: "workflow_id",
            EntityKind.observation: "observation_id",
        }[reference.entity_kind]
        item = _find(collection, id_field, reference.entity_id)
        return bool(item and getattr(item, "evidence_references", ()))

    @staticmethod
    def _eligible_fact(fact: Fact, state: ResearchState) -> bool:
        return (
            fact.status in {FactStatus.observed, FactStatus.confirmed}
            and fact.derivation_type is not DerivationType.model_proposed
            and bool(fact.evidence_references)
            and fact.provenance_id in {item.provenance_id for item in state.provenance}
            and set(fact.evidence_references).issubset(
                {item.evidence_id for item in state.evidence}
            )
        )

    @staticmethod
    def _fact_mentions(fact: Fact, entity_id: str) -> bool:
        return fact.subject.entity_id == entity_id or (
            fact.object.kind == "reference"
            and fact.object.reference.entity_id == entity_id
        )

    @staticmethod
    def _controlled_identity(identity_id: str, state: ResearchState) -> bool:
        return any(
            item.identity_id == identity_id
            and item.controlled
            and item.eligibility is IdentityEligibility.eligible
            for item in state.identities
        )

    def _surface_ids(
        self,
        reference: EntityReference,
        state: ResearchState,
        _visited: frozenset[tuple[EntityKind, str]] = frozenset(),
    ) -> set[str]:
        marker = (reference.entity_kind, reference.entity_id)
        if marker in _visited:
            return set()
        visited = _visited | {marker}
        if reference.entity_kind is EntityKind.surface:
            return {reference.entity_id}
        if reference.entity_kind is EntityKind.endpoint:
            item = _find(state.endpoints, "endpoint_id", reference.entity_id)
            return {item.surface_id} if item else set()
        if reference.entity_kind is EntityKind.parameter:
            item = _find(state.parameters, "parameter_id", reference.entity_id)
            return (
                self._surface_ids(
                    EntityReference(
                        entity_kind=EntityKind.endpoint, entity_id=item.endpoint_id
                    ),
                    state,
                    visited,
                )
                if item
                else set()
            )
        direct = {
            EntityKind.object: (state.objects, "object_id"),
            EntityKind.graphql_operation: (state.graphql_operations, "operation_id"),
            EntityKind.upload: (state.uploads, "upload_id"),
            EntityKind.workflow: (state.workflows, "workflow_id"),
            EntityKind.observation: (state.observations, "observation_id"),
            EntityKind.hypothesis: (state.hypotheses, "hypothesis_id"),
            EntityKind.finding: (state.findings, "finding_id"),
        }.get(reference.entity_kind)
        if direct is not None:
            item = _find(direct[0], direct[1], reference.entity_id)
            surface_id = getattr(item, "surface_id", None) if item else None
            return {surface_id} if surface_id else set()
        if reference.entity_kind is EntityKind.fact:
            fact = _find(state.facts, "fact_id", reference.entity_id)
            if fact is None:
                return set()
            result = self._surface_ids(fact.subject, state, visited)
            if fact.object.kind == "reference":
                result |= self._surface_ids(fact.object.reference, state, visited)
            return result
        if reference.entity_kind is EntityKind.relationship:
            relationship = _find(
                state.relationships, "relationship_id", reference.entity_id
            )
            if relationship is None:
                return set()
            return self._surface_ids(
                relationship.source, state, visited
            ) | self._surface_ids(relationship.target, state, visited)
        return set()

    def _target_ids(
        self, references: tuple[EntityReference, ...], state: ResearchState
    ) -> set[str]:
        surfaces = {
            surface
            for reference in references
            for surface in self._surface_ids(reference, state)
        }
        targets = {
            item.target_id for item in state.surfaces if item.surface_id in surfaces
        }
        for reference in references:
            if reference.entity_kind is EntityKind.finding:
                finding = _find(state.findings, "finding_id", reference.entity_id)
                if finding and finding.target_id:
                    targets.add(finding.target_id)
            elif reference.entity_kind is EntityKind.hypothesis:
                hypothesis = _find(
                    state.hypotheses, "hypothesis_id", reference.entity_id
                )
                if hypothesis:
                    targets.add(hypothesis.target_id)
        return targets

    def _category(
        self, ordered: tuple[EntityReference, ...], state: ResearchState
    ) -> str:
        kinds = {item.entity_kind for item in ordered}
        if EntityKind.token in kinds:
            return "token-to-authorization"
        if EntityKind.session in kinds:
            return "authentication-to-authorization"
        surface_ids: list[str] = []
        for reference in ordered:
            for surface_id in sorted(self._surface_ids(reference, state)):
                if surface_id not in surface_ids:
                    surface_ids.append(surface_id)
        types = [
            item.surface_type
            for surface_id in surface_ids
            for item in state.surfaces
            if item.surface_id == surface_id
        ]
        if SurfaceType.graphql in types and SurfaceType.rest in types:
            first_graphql = types.index(SurfaceType.graphql)
            first_rest = types.index(SurfaceType.rest)
            return (
                "graphql-to-rest" if first_graphql < first_rest else "rest-to-graphql"
            )
        if SurfaceType.token in types:
            return "token-to-authorization"
        if SurfaceType.authentication in types or SurfaceType.session in types:
            return "authentication-to-authorization"
        if SurfaceType.upload in types:
            return "upload-to-access-control"
        if SurfaceType.workflow in types:
            return "workflow-authorization"
        return "cross-surface-authorization"

    @staticmethod
    def _assertions(
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None,
    ) -> tuple[GraphAssertion, ...]:
        if graph is None:
            return ()
        if isinstance(graph, Sequence):
            return tuple(graph)
        references = _state_entity_ids(state)
        collected: dict[str, GraphAssertion] = {}
        for reference in references:
            if len(collected) >= 500:
                break
            for assertion in graph.neighbors(
                reference, limit=min(100, 500 - len(collected))
            ):
                collected[assertion.assertion_id] = assertion
        return tuple(collected.values())


class PublicSafeChainPacketBuilder:
    def build(
        self,
        state: ResearchState,
        candidates: Sequence[AttackChainCandidate],
        *,
        budget_state: ChainBudgetState | None = None,
        policy_limitations: tuple[str, ...] = (),
    ) -> PublicSafeChainPacket:
        if not candidates:
            raise ValueError("chain packet requires at least one candidate")
        if len(candidates) > MAX_CHAIN_CANDIDATES:
            raise ValueError("chain packet exceeds its candidate bound")
        if any(
            item.research_id != state.research_id
            or item.state_revision != state.revision
            for item in candidates
        ):
            raise ValueError("chain packet contains stale candidate bindings")
        limits = budget_state.limits if budget_state else ChainBudgetLimits()
        consumed = budget_state or ChainBudgetState(
            budget_reference="chain-budget-preview",
            authoritative_request_ledger_reference="request-budget-preview",
        )
        return PublicSafeChainPacket(
            research_id=state.research_id,
            state_revision=state.revision,
            candidates=tuple(
                PublicSafeChainCandidateSummary(
                    candidate_id=item.candidate_id,
                    category=item.category,
                    ordered_reference_ids=tuple(
                        reference.entity_id for reference in item.ordered_references
                    ),
                    surface_ids=item.surface_ids,
                    identity_context_count=len(item.identity_ids),
                    object_context_count=len(item.object_ids),
                    unresolved_link_count=len(item.required_unresolved_links),
                    available_experiment_candidate_ids=(
                        item.available_experiment_candidates
                    ),
                    request_cost_estimate=item.request_cost_estimate,
                    risk=item.risk,
                    expected_information_value=item.expected_information_value,
                    evidence_references=item.evidence_references,
                )
                for item in candidates
            ),
            remaining_budgets=ChainBudgetSummary(
                candidates=max(
                    0,
                    limits.maximum_chain_candidates - consumed.candidates_considered,
                ),
                active_hypotheses=max(
                    0,
                    limits.maximum_active_chain_hypotheses - consumed.active_hypotheses,
                ),
                experiments=max(
                    0,
                    limits.maximum_chain_experiments - consumed.experiments_consumed,
                ),
                target_requests=max(
                    0,
                    limits.maximum_chain_target_requests
                    - consumed.target_requests_consumed,
                ),
                model_calls=max(
                    0,
                    limits.maximum_chain_model_calls
                    - consumed.model_usage.attempted_calls,
                ),
                reproductions=max(
                    0,
                    limits.maximum_chain_reproductions
                    - consumed.reproductions_consumed,
                ),
                state_changes=max(
                    0,
                    limits.state_changing_chain_ceiling
                    - consumed.state_changes_consumed,
                ),
            ),
            policy_limitations=policy_limitations,
        )


def select_chain_candidate(
    candidates: Sequence[AttackChainCandidate],
    decision: ChainSelectionDecision | None,
    *,
    permit_single_candidate_auto_selection: bool = True,
) -> AttackChainCandidate | None:
    """Resolve only an existing binding; the decision cannot alter the chain."""

    if not candidates:
        return None
    by_id = {item.candidate_id: item for item in candidates}
    if decision is None:
        if len(candidates) == 1 and permit_single_candidate_auto_selection:
            return candidates[0]
        return None
    if decision.action is not ChainSelectionAction.select_candidate:
        return None
    selected = by_id.get(str(decision.selected_chain_candidate_id))
    if selected is None:
        raise ValueError("model selected an unavailable chain candidate")
    if (
        decision.research_id != selected.research_id
        or decision.state_revision != selected.state_revision
    ):
        raise ValueError("chain selection decision is stale")
    if not set(decision.evidence_references).issubset(
        set(selected.evidence_references)
    ):
        raise ValueError("chain selection cited evidence outside the candidate")
    return selected


def materialize_chain_hypothesis(
    candidate: AttackChainCandidate,
    *,
    decision: ChainSelectionDecision | None = None,
    confirmation_policy_reference: str = "chain-confirmation-policy-v1",
) -> AttackChainHypothesis:
    selected = select_chain_candidate((candidate,), decision)
    if selected is None:
        raise ValueError("chain candidate was not selected")
    return AttackChainHypothesis(
        hypothesis_id=stable_chain_identifier(
            "chain-hypothesis",
            {
                "candidate": candidate.candidate_id,
                "fingerprint": candidate.semantic_fingerprint,
            },
        ),
        research_id=candidate.research_id,
        state_revision=candidate.state_revision,
        chain_candidate_id=candidate.candidate_id,
        category=candidate.category,
        claim="The bounded ordered links may demonstrate the stated chain property.",
        falsification_criterion=(
            "Refutation or blocking of any required link falsifies this chain."
        ),
        ordered_references=candidate.ordered_references,
        unresolved_links=candidate.required_unresolved_links,
        evidence_references=candidate.evidence_references,
        confidence=ResearchConfidence.low,
        confirmation_policy_reference=confirmation_policy_reference,
        provenance_references=candidate.provenance_references,
        semantic_fingerprint=candidate.semantic_fingerprint,
    )


def materialize_attack_chain(
    candidate: AttackChainCandidate,
    hypothesis: AttackChainHypothesis,
    *,
    provenance_id: str,
    created_at: str,
) -> AttackChain:
    """Copy deterministic candidate bindings into a durable inert chain."""

    if hypothesis.chain_candidate_id != candidate.candidate_id:
        raise ValueError("chain hypothesis candidate binding changed")
    if hypothesis.semantic_fingerprint != candidate.semantic_fingerprint:
        raise ValueError("chain hypothesis fingerprint binding changed")
    unresolved_by_target = {
        (item.to_reference.entity_kind, item.to_reference.entity_id): item
        for item in hypothesis.unresolved_links
    }
    steps = []
    for sequence, reference in enumerate(candidate.ordered_references, 1):
        link = unresolved_by_target.get((reference.entity_kind, reference.entity_id))
        steps.append(
            AttackChainStep(
                step_id=stable_chain_identifier(
                    "chain-step",
                    {
                        "candidate": candidate.candidate_id,
                        "sequence": sequence,
                        "reference": reference.model_dump(mode="json"),
                    },
                ),
                sequence=sequence,
                source_reference=reference,
                target_reference=(
                    candidate.ordered_references[sequence]
                    if sequence < len(candidate.ordered_references)
                    else None
                ),
                required_preconditions=((steps[-1].step_id,) if steps else ()),
                expected_secure_behavior=candidate.expected_secure_behavior,
                expected_chain_behavior=candidate.expected_chain_behavior,
                evidence_requirements=(
                    link.required_evidence
                    if link is not None
                    else ("predicate:existing-evidence-valid",)
                ),
                unresolved_link_id=link.link_id if link is not None else None,
            )
        )
    return AttackChain(
        attack_chain_id=stable_chain_identifier(
            "chain",
            {
                "candidate": candidate.candidate_id,
                "fingerprint": candidate.semantic_fingerprint,
            },
        ),
        research_id=candidate.research_id,
        state_revision=candidate.state_revision,
        title=f"Candidate {candidate.category} chain",
        category=candidate.category,
        status=AttackChainStatus.proposed,
        target_ids=candidate.target_ids,
        surface_ids=candidate.surface_ids,
        identity_ids=candidate.identity_ids,
        object_ids=candidate.object_ids,
        hypothesis_ids=candidate.hypothesis_ids,
        finding_ids=candidate.finding_ids,
        fact_ids=candidate.fact_ids,
        relationship_ids=candidate.relationship_ids,
        steps=tuple(steps),
        entry_condition=candidate.entry_condition,
        security_property=candidate.security_property,
        expected_secure_behavior=candidate.expected_secure_behavior,
        expected_chain_behavior=candidate.expected_chain_behavior,
        unresolved_links=hypothesis.unresolved_links,
        evidence_references=candidate.evidence_references,
        provenance_id=provenance_id,
        confirmation_policy_reference=hypothesis.confirmation_policy_reference,
        semantic_fingerprint=candidate.semantic_fingerprint,
        created_at=created_at,
        updated_at=created_at,
    )


def resolve_chain_link(
    chain: AttackChain,
    *,
    link_id: str,
    status: ChainLinkStatus,
    evidence_references: tuple[str, ...],
    experiment_id: str | None,
    updated_at: str,
) -> AttackChain:
    """Apply one deterministic outcome without advancing through a broken link."""

    if status is ChainLinkStatus.unresolved:
        raise ValueError("a chain-link result must be resolved")
    if status in {ChainLinkStatus.supported, ChainLinkStatus.refuted} and not (
        evidence_references
    ):
        raise ValueError("a conclusive chain-link result requires evidence")
    found = False
    links = []
    for item in chain.unresolved_links:
        if item.link_id != link_id:
            links.append(item)
            continue
        found = True
        payload = item.model_dump(mode="python")
        payload.update(
            status=status,
            evidence_references=evidence_references,
            experiment_id=experiment_id,
        )
        links.append(UnresolvedChainLink.model_validate(payload))
    if not found:
        raise ValueError("chain unresolved-link binding is unavailable")
    payload = chain.model_dump(mode="python")
    payload.update(
        unresolved_links=tuple(links),
        status=(
            AttackChainStatus.refuted
            if status is ChainLinkStatus.refuted
            else (
                AttackChainStatus.inconclusive
                if status.breaks_prerequisite
                else AttackChainStatus.testing
            )
        ),
        evidence_references=tuple(
            sorted({*chain.evidence_references, *evidence_references})
        ),
        updated_at=updated_at,
    )
    return AttackChain.model_validate(payload)


class ChainExperimentPlanner:
    """Materialize exactly one next-link proposal through the existing stack."""

    def plan_next(
        self,
        hypothesis: AttackChainHypothesis,
        candidate: AttackChainCandidate,
        state: ResearchState,
        experiment_candidates: Sequence[ExperimentCandidate],
        *,
        completed_link_ids: Iterable[str] = (),
        model_decision_id: str | None = None,
        budget_state: ChainBudgetState | None = None,
    ) -> ChainExperimentPlan | None:
        if hypothesis.chain_candidate_id != candidate.candidate_id:
            raise ValueError("chain hypothesis candidate binding changed")
        if hypothesis.semantic_fingerprint != candidate.semantic_fingerprint:
            raise ValueError("chain hypothesis semantic binding changed")
        if state.research_id != hypothesis.research_id:
            raise ValueError("chain plan research binding mismatch")
        requested_completed = set(completed_link_ids)
        known_supported = {
            item.link_id
            for item in hypothesis.unresolved_links
            if item.status is ChainLinkStatus.supported
        }
        if any(item.status.breaks_prerequisite for item in hypothesis.unresolved_links):
            return None
        durable_chain_id = stable_chain_identifier(
            "chain",
            {
                "candidate": candidate.candidate_id,
                "fingerprint": candidate.semantic_fingerprint,
            },
        )
        persisted_chain = next(
            (
                item
                for item in state.attack_chains
                if item.attack_chain_id == durable_chain_id
            ),
            None,
        )
        if persisted_chain is not None:
            for item in persisted_chain.unresolved_links:
                if item.status is ChainLinkStatus.supported:
                    known_supported.add(item.link_id)
                elif item.status is not ChainLinkStatus.unresolved:
                    # No downstream link is eligible after a required link was
                    # refuted, blocked, or left inconclusive.
                    return None
        if not requested_completed.issubset(known_supported):
            # A caller cannot assert completion without durable supported state.
            return None
        completed = known_supported | requested_completed
        link = next(
            (
                item
                for item in hypothesis.unresolved_links
                if item.link_id not in completed
                and item.status is ChainLinkStatus.unresolved
            ),
            None,
        )
        if link is None:
            return None
        allowed_ids = set(candidate.available_experiment_candidates)
        available = next(
            (
                item
                for item in experiment_candidates
                if item.primitive_kind in link.allowed_experiment_capabilities
                and item.research_id == state.research_id
                and item.state_revision == state.revision
                and (
                    item.candidate_id in allowed_ids
                    or (
                        candidate.state_revision < state.revision
                        and item.target_id in candidate.target_ids
                        and item.surface_id in candidate.surface_ids
                        and item.hypothesis_id in candidate.hypothesis_ids
                        and (
                            item.primary_identity_id is None
                            or item.primary_identity_id in candidate.identity_ids
                        )
                        and (
                            item.comparison_identity_id is None
                            or item.comparison_identity_id in candidate.identity_ids
                        )
                        and (
                            item.controlled_object_id is None
                            or item.controlled_object_id in candidate.object_ids
                        )
                    )
                )
            ),
            None,
        )
        if available is None:
            return None
        if budget_state is not None:
            if (
                budget_state.experiments_consumed
                >= budget_state.limits.maximum_chain_experiments
            ):
                return None
            remaining_requests = max(
                0,
                budget_state.limits.maximum_chain_target_requests
                - budget_state.target_requests_consumed,
            )
            if available.worst_case_requests > remaining_requests:
                return None
        proposal = materialize_candidate(
            available, state, model_decision_id=model_decision_id
        )
        return ChainExperimentPlan(
            plan_id=stable_chain_identifier(
                "chain-plan",
                {
                    "candidate": candidate.candidate_id,
                    "link": link.link_id,
                    "experiment": available.candidate_id,
                    "revision": state.revision,
                },
            ),
            research_id=state.research_id,
            chain_candidate_id=candidate.candidate_id,
            chain_hypothesis_id=hypothesis.hypothesis_id,
            unresolved_link_id=link.link_id,
            sequence=tuple(hypothesis.unresolved_links).index(link) + 1,
            experiment_candidate_id=available.candidate_id,
            experiment_proposal=proposal,
            required_predecessor_references=tuple(
                item.link_id
                for item in hypothesis.unresolved_links
                if tuple(hypothesis.unresolved_links).index(item)
                < tuple(hypothesis.unresolved_links).index(link)
            ),
            request_cost_estimate=available.worst_case_requests,
        )

    def plan(self, *args: object, **kwargs: object) -> ChainExperimentPlan | None:
        return self.plan_next(*args, **kwargs)  # type: ignore[arg-type]


def _find(collection: Sequence[object], field: str, value: str) -> object | None:
    return next((item for item in collection if getattr(item, field) == value), None)


def _risk_rank(value: RiskLevel) -> int:
    return {
        RiskLevel.passive: 0,
        RiskLevel.low: 1,
        RiskLevel.moderate: 2,
        RiskLevel.high: 3,
        RiskLevel.prohibited: 4,
    }[value]


def _state_entity_ids(state: ResearchState) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            [
                *(item.fact_id for item in state.facts),
                *(item.relationship_id for item in state.relationships),
                *(item.finding_id for item in state.findings),
                *(item.hypothesis_id for item in state.hypotheses),
                *(item.identity_id for item in state.identities if item.controlled),
                *(item.object_id for item in state.objects if item.test_owned),
                *(item.surface_id for item in state.surfaces),
                *(item.endpoint_id for item in state.endpoints),
                *(item.operation_id for item in state.graphql_operations),
                *(item.workflow_id for item in state.workflows),
                *(item.upload_id for item in state.uploads),
            ]
        )
    )


__all__ = [
    "AttackChainCandidate",
    "AttackChainCandidateBuilder",
    "CHAIN_RELATIONS",
    "ChainCandidatePolicy",
    "ChainExperimentPlan",
    "ChainExperimentPlanner",
    "ChainSelectionDecision",
    "PublicSafeChainPacket",
    "PublicSafeChainPacketBuilder",
    "materialize_chain_hypothesis",
    "materialize_attack_chain",
    "resolve_chain_link",
    "select_chain_candidate",
]
