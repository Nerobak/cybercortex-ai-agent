"""Typed, evidence-backed graph repository for Phase 4 research."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from enum import Enum
from typing import TYPE_CHECKING, Literal

from pydantic import Field, StrictInt, model_validator

from agent_core.research.state import EvidenceArtifact, ResearchState
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceArtifactId,
    ProvenanceRecordId,
    PublicMetadata,
    RelationshipId,
    RelationshipStatus,
    ResearchContract,
    ResearchId,
    ResearchPredicate,
    Timestamp,
)

if TYPE_CHECKING:
    from agent_core.attack_surface import AttackSurfaceGraph
    from agent_core.research.events import ResearchEvent
    from agent_core.research.store import ResearchStore

GRAPH_ASSERTION_SCHEMA_VERSION = 1
MAX_GRAPH_ASSERTIONS_PER_COMMIT = 500
MAX_GRAPH_QUERY_DEPTH = 6
MAX_GRAPH_QUERY_RESULTS = 500
MAX_GRAPH_PATHS = 100

SECURITY_CRITICAL_RELATIONS = frozenset(
    {
        ResearchPredicate.owns,
        ResearchPredicate.belongs_to,
        ResearchPredicate.authenticates_to,
        ResearchPredicate.accesses,
        ResearchPredicate.controls,
    }
)


class GraphRelation(str, Enum):
    authenticates_to = "AUTHENTICATES_TO"
    owns = "OWNS"
    belongs_to = "BELONGS_TO"
    returns = "RETURNS"
    references = "REFERENCES"
    accesses = "ACCESSES"
    creates = "CREATES"
    modifies = "MODIFIES"
    derives_from = "DERIVES_FROM"
    requires = "REQUIRES"
    leaks = "LEAKS"
    controls = "CONTROLS"
    transitions_to = "TRANSITIONS_TO"
    accepts = "ACCEPTS"
    emits = "EMITS"
    same_object_as = "SAME_OBJECT_AS"
    part_of = "PART_OF"
    tested_by = "TESTED_BY"
    supported_by = "SUPPORTED_BY"
    refuted_by = "REFUTED_BY"
    confirms = "CONFIRMS"


class GraphAssertion(ResearchContract):
    """One typed graph claim whose history is retained across revisions."""

    schema_version: Literal[GRAPH_ASSERTION_SCHEMA_VERSION] = (
        GRAPH_ASSERTION_SCHEMA_VERSION
    )
    assertion_id: RelationshipId
    research_id: ResearchId
    source: EntityReference
    relation: ResearchPredicate | GraphRelation = Field(alias="predicate")
    target: EntityReference
    status: RelationshipStatus
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    derivation_type: DerivationType
    provenance_id: ProvenanceRecordId
    superseded_by_assertion_id: RelationshipId | None = None
    asserted_at: Timestamp
    metadata: PublicMetadata = Field(default_factory=PublicMetadata)

    @property
    def predicate(self) -> ResearchPredicate | GraphRelation:
        return self.relation

    @property
    def security_critical(self) -> bool:
        return self.relation in SECURITY_CRITICAL_RELATIONS

    @property
    def execution_authoritative(self) -> bool:
        return (
            self.status is RelationshipStatus.confirmed
            and self.derivation_type is DerivationType.deterministic
        )

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "GraphAssertion":
        if len(self.evidence_references) != len(set(self.evidence_references)):
            raise ValueError("graph evidence references must be unique")
        object.__setattr__(
            self, "evidence_references", tuple(sorted(self.evidence_references))
        )
        if (
            self.status
            in {
                RelationshipStatus.observed,
                RelationshipStatus.confirmed,
            }
            and not self.evidence_references
        ):
            raise ValueError("observed or confirmed graph assertions require evidence")
        if (
            self.derivation_type is DerivationType.model_proposed
            and self.status is not RelationshipStatus.proposed
        ):
            raise ValueError("model-authored graph assertions must remain proposed")
        if (
            self.status is RelationshipStatus.confirmed
            and self.derivation_type is not DerivationType.deterministic
        ):
            raise ValueError(
                "confirmed graph assertions require deterministic derivation"
            )
        if (
            self.security_critical
            and self.status is RelationshipStatus.confirmed
            and self.derivation_type is not DerivationType.deterministic
        ):
            raise ValueError(
                "security-critical graph confirmation requires deterministic provenance"
            )
        if (
            self.status is RelationshipStatus.superseded
            and self.superseded_by_assertion_id is None
        ):
            raise ValueError("superseded assertion requires its replacement reference")
        if (
            self.status is not RelationshipStatus.superseded
            and self.superseded_by_assertion_id is not None
        ):
            raise ValueError("only a superseded assertion may name its replacement")
        if self.superseded_by_assertion_id == self.assertion_id:
            raise ValueError("a graph assertion cannot supersede itself")
        return self


GraphAssertionStatus = RelationshipStatus


class BoundedGraphQuery(ResearchContract):
    max_depth: StrictInt = Field(default=3, ge=1, le=MAX_GRAPH_QUERY_DEPTH)
    max_results: StrictInt = Field(default=100, ge=1, le=MAX_GRAPH_QUERY_RESULTS)
    max_paths: StrictInt = Field(default=20, ge=1, le=MAX_GRAPH_PATHS)


_LIFECYCLE_TRANSITIONS: dict[RelationshipStatus, frozenset[RelationshipStatus]] = {
    RelationshipStatus.proposed: frozenset(
        {
            RelationshipStatus.observed,
            RelationshipStatus.confirmed,
            RelationshipStatus.rejected,
            RelationshipStatus.superseded,
        }
    ),
    RelationshipStatus.observed: frozenset(
        {
            RelationshipStatus.confirmed,
            RelationshipStatus.rejected,
            RelationshipStatus.superseded,
        }
    ),
    RelationshipStatus.confirmed: frozenset(
        {RelationshipStatus.rejected, RelationshipStatus.superseded}
    ),
    RelationshipStatus.rejected: frozenset(),
    RelationshipStatus.superseded: frozenset(),
}


class ResearchGraphRepository:
    """Bounded research interface over the store's immutable assertion journal."""

    def __init__(self, store: ResearchStore, research_id: str | None = None) -> None:
        self.store = store
        self.research_id = research_id

    def _id(self, research_id: str | None = None) -> str:
        selected = research_id or self.research_id
        if selected is None:
            raise ValueError("research_id is required for graph operations")
        return selected

    @staticmethod
    def _next_state(
        state: ResearchState, *, revision: int, updated_at: str
    ) -> ResearchState:
        payload = state.model_dump(mode="python")
        payload.update(revision=revision, updated_at=updated_at)
        return ResearchState.model_validate(payload)

    def record_assertion(
        self,
        assertion: GraphAssertion,
        *,
        expected_revision: int,
        state: ResearchState | None = None,
        events: Sequence[ResearchEvent] = (),
    ) -> ResearchState:
        research_id = self._id()
        if assertion.research_id != research_id:
            raise ValueError("graph assertion research_id mismatch")
        current = state or self.store.load_research(research_id)
        next_state = self._next_state(
            current,
            revision=expected_revision + 1,
            updated_at=assertion.asserted_at,
        )
        return self.store.commit_revision(
            research_id,
            expected_revision=expected_revision,
            state=next_state,
            events=events,
            graph_assertions=(assertion,),
        )

    def record_assertions(
        self,
        assertions: Sequence[GraphAssertion],
        *,
        expected_revision: int,
        updated_at: str,
        state: ResearchState | None = None,
        events: Sequence[ResearchEvent] = (),
        research_id: str | None = None,
    ) -> ResearchState:
        selected = self._id(research_id)
        if not assertions:
            raise ValueError("at least one graph assertion is required")
        current = state or self.store.load_research(selected)
        next_state = self._next_state(
            current, revision=expected_revision + 1, updated_at=updated_at
        )
        return self.store.commit_revision(
            selected,
            expected_revision=expected_revision,
            state=next_state,
            events=events,
            graph_assertions=tuple(assertions),
        )

    def promote_assertion(
        self,
        assertion_id: str,
        next_status: RelationshipStatus,
        *,
        expected_revision: int,
        evidence_references: Sequence[str],
        derivation_type: DerivationType,
        provenance_id: str,
        asserted_at: str,
        research_id: str | None = None,
    ) -> ResearchState:
        selected = self._id(research_id)
        previous = self.get_assertion(assertion_id, research_id=selected)
        if next_status not in _LIFECYCLE_TRANSITIONS[previous.status]:
            raise ValueError(
                f"invalid graph assertion transition: {previous.status.value} -> "
                f"{next_status.value}"
            )
        payload = previous.model_dump(mode="python")
        payload.update(
            status=next_status,
            evidence_references=tuple(evidence_references),
            derivation_type=derivation_type,
            provenance_id=provenance_id,
            asserted_at=asserted_at,
            superseded_by_assertion_id=None,
        )
        promoted = GraphAssertion.model_validate(payload)
        return self.record_assertion(promoted, expected_revision=expected_revision)

    def reject_assertion(
        self,
        assertion_id: str,
        *,
        expected_revision: int,
        evidence_references: Sequence[str],
        derivation_type: DerivationType,
        provenance_id: str,
        asserted_at: str,
        research_id: str | None = None,
    ) -> ResearchState:
        return self.promote_assertion(
            assertion_id,
            RelationshipStatus.rejected,
            expected_revision=expected_revision,
            evidence_references=evidence_references,
            derivation_type=derivation_type,
            provenance_id=provenance_id,
            asserted_at=asserted_at,
            research_id=research_id,
        )

    def supersede_assertion(
        self,
        assertion_id: str,
        replacement: GraphAssertion,
        *,
        expected_revision: int,
        provenance_id: str,
        asserted_at: str,
        derivation_type: DerivationType = DerivationType.deterministic,
        research_id: str | None = None,
    ) -> ResearchState:
        selected = self._id(research_id)
        previous = self.get_assertion(assertion_id, research_id=selected)
        if replacement.assertion_id == assertion_id:
            raise ValueError("replacement assertion must have a new identity")
        if previous.status in {
            RelationshipStatus.rejected,
            RelationshipStatus.superseded,
        }:
            raise ValueError("terminal graph assertion cannot be superseded")
        payload = previous.model_dump(mode="python")
        payload.update(
            status=RelationshipStatus.superseded,
            provenance_id=provenance_id,
            asserted_at=asserted_at,
            derivation_type=derivation_type,
            superseded_by_assertion_id=replacement.assertion_id,
        )
        superseded = GraphAssertion.model_validate(payload)
        return self.record_assertions(
            (superseded, replacement),
            expected_revision=expected_revision,
            updated_at=asserted_at,
            research_id=selected,
        )

    def get_assertion(
        self,
        assertion_id: str,
        *,
        revision: int | None = None,
        research_id: str | None = None,
    ) -> GraphAssertion:
        return self.store.load_graph_assertion(
            self._id(research_id), assertion_id, revision=revision
        )

    def assertion_history(
        self,
        assertion_id: str,
        *,
        limit: int = 100,
        research_id: str | None = None,
    ) -> tuple[GraphAssertion, ...]:
        return self.store.graph_assertion_history(
            self._id(research_id),
            assertion_id,
            limit=self._validate_limit(limit),
        )

    @staticmethod
    def _validate_limit(limit: int) -> int:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("graph query limit must be an integer")
        if limit < 1 or limit > MAX_GRAPH_QUERY_RESULTS:
            raise ValueError("graph query limit is outside the supported bound")
        return limit

    def neighbors(
        self,
        node_id: str,
        relation: ResearchPredicate | GraphRelation | None = None,
        *,
        limit: int = 100,
        include_rejected: bool = False,
        research_id: str | None = None,
    ) -> tuple[GraphAssertion, ...]:
        return self.store.query_graph_assertions(
            self._id(research_id),
            node_id=node_id,
            relation=relation,
            limit=self._validate_limit(limit),
            include_rejected=include_rejected,
        )

    def relationships_between(
        self,
        first_node_id: str,
        second_node_id: str,
        *,
        limit: int = 100,
        include_rejected: bool = False,
        research_id: str | None = None,
    ) -> tuple[GraphAssertion, ...]:
        return self.store.query_graph_assertions(
            self._id(research_id),
            first_node_id=first_node_id,
            second_node_id=second_node_id,
            limit=self._validate_limit(limit),
            include_rejected=include_rejected,
        )

    def _targets(
        self,
        node_id: str,
        relation: ResearchPredicate,
        target_kind: EntityKind,
        *,
        limit: int,
        research_id: str | None,
    ) -> tuple[str, ...]:
        assertions = self.neighbors(
            node_id,
            relation,
            limit=limit,
            research_id=research_id,
        )
        return tuple(
            sorted(
                {
                    item.target.entity_id
                    for item in assertions
                    if item.source.entity_id == node_id
                    and item.target.entity_kind is target_kind
                    and (
                        relation not in SECURITY_CRITICAL_RELATIONS
                        or item.execution_authoritative
                    )
                }
            )
        )

    def objects_owned_by(
        self, identity_id: str, *, limit: int = 100, research_id: str | None = None
    ) -> tuple[str, ...]:
        return self._targets(
            identity_id,
            ResearchPredicate.owns,
            EntityKind.object,
            limit=self._validate_limit(limit),
            research_id=research_id,
        )

    def surfaces_for_object(
        self, object_id: str, *, limit: int = 100, research_id: str | None = None
    ) -> tuple[str, ...]:
        bounded_limit = self._validate_limit(limit)
        assertions = self.neighbors(
            object_id, limit=bounded_limit, research_id=research_id
        )
        state = self.store.load_research(self._id(research_id))
        surfaces = {
            item.surface_id for item in state.objects if item.object_id == object_id
        }
        for item in assertions:
            if (
                item.source.entity_id == object_id
                and item.target.entity_kind is EntityKind.surface
            ):
                surfaces.add(item.target.entity_id)
            if (
                item.target.entity_id == object_id
                and item.source.entity_kind is EntityKind.surface
            ):
                surfaces.add(item.source.entity_id)
        return tuple(sorted(surfaces)[:bounded_limit])

    def operations_referencing_object(
        self, object_id: str, *, limit: int = 100, research_id: str | None = None
    ) -> tuple[str, ...]:
        bounded_limit = self._validate_limit(limit)
        assertions = self.neighbors(
            object_id,
            ResearchPredicate.references,
            limit=bounded_limit,
            research_id=research_id,
        )
        state = self.store.load_research(self._id(research_id))
        parameter_ids = {
            item.source.entity_id
            for item in assertions
            if item.target.entity_id == object_id
            and item.source.entity_kind is EntityKind.parameter
        }
        operations = {
            item.source.entity_id
            for item in assertions
            if item.target.entity_id == object_id
            and item.source.entity_kind is EntityKind.graphql_operation
        }
        operations.update(
            operation.operation_id
            for operation in state.graphql_operations
            if parameter_ids.intersection(operation.variable_parameter_ids)
        )
        return tuple(sorted(operations)[:bounded_limit])

    def evidence_for_assertion(
        self,
        assertion: GraphAssertion | str,
        *,
        research_id: str | None = None,
    ) -> tuple[EvidenceArtifact, ...]:
        selected = (
            assertion
            if isinstance(assertion, GraphAssertion)
            else self.get_assertion(assertion, research_id=research_id)
        )
        state = self.store.load_research(self._id(research_id or selected.research_id))
        evidence = {item.evidence_id: item for item in state.evidence}
        return tuple(evidence[item] for item in selected.evidence_references)

    def hypotheses_supported_by(
        self,
        reference_id: str,
        *,
        limit: int = 100,
        research_id: str | None = None,
    ) -> tuple[str, ...]:
        bounded_limit = self._validate_limit(limit)
        assertions = self.neighbors(
            reference_id, limit=bounded_limit, research_id=research_id
        )
        state = self.store.load_research(self._id(research_id))
        supported = {
            item.hypothesis_id
            for item in state.hypotheses
            if reference_id in item.supporting_evidence
        }
        supported.update(
            {
                endpoint.entity_id
                for item in assertions
                if item.relation
                in {ResearchPredicate.supported_by, ResearchPredicate.derives_from}
                for endpoint, support in ((item.source, item.target),)
                if support.entity_id == reference_id
                and endpoint.entity_kind is EntityKind.hypothesis
            }
        )
        return tuple(sorted(supported)[:bounded_limit])

    def find_cross_surface_paths(
        self,
        start_node_id: str,
        end_node_id: str | None = None,
        *,
        max_depth: int = 3,
        max_paths: int = 20,
        max_results: int = 200,
        research_id: str | None = None,
    ) -> tuple[tuple[GraphAssertion, ...], ...]:
        bounds = BoundedGraphQuery(
            max_depth=max_depth, max_paths=max_paths, max_results=max_results
        )
        selected = self._id(research_id)
        queue: deque[tuple[str, tuple[GraphAssertion, ...], frozenset[str]]] = deque(
            [(start_node_id, (), frozenset({start_node_id}))]
        )
        paths: list[tuple[GraphAssertion, ...]] = []
        examined = 0
        while queue and len(paths) < bounds.max_paths and examined < bounds.max_results:
            node_id, path, visited = queue.popleft()
            if len(path) >= bounds.max_depth:
                continue
            remaining = bounds.max_results - examined
            adjacent = self.neighbors(
                node_id,
                limit=min(MAX_GRAPH_QUERY_RESULTS, remaining),
                research_id=selected,
            )
            for assertion in adjacent:
                examined += 1
                next_ref = (
                    assertion.target
                    if assertion.source.entity_id == node_id
                    else assertion.source
                )
                if next_ref.entity_id in visited:
                    continue
                next_path = (*path, assertion)
                reached = (
                    next_ref.entity_id == end_node_id
                    if end_node_id is not None
                    else next_ref.entity_kind is EntityKind.surface
                    and next_ref.entity_id != start_node_id
                )
                if reached:
                    paths.append(next_path)
                    if len(paths) >= bounds.max_paths:
                        break
                if len(next_path) < bounds.max_depth:
                    queue.append(
                        (
                            next_ref.entity_id,
                            next_path,
                            visited | {next_ref.entity_id},
                        )
                    )
                if examined >= bounds.max_results:
                    break
        return tuple(paths)

    @staticmethod
    def legacy_attack_surface_snapshot(
        graph: AttackSurfaceGraph, *, max_nodes: int = 500, max_edges: int = 1_000
    ) -> dict[str, object]:
        """Read the bounded Phase 1-3 graph adapter without exposing mutation."""

        return graph.research_snapshot(max_nodes=max_nodes, max_edges=max_edges)
