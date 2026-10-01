"""Bounded GraphQL adapter for the existing P4-0G attack-chain lifecycle.

This module discovers reference-only chain paths.  It does not render GraphQL,
create requests, authorize execution, evaluate response values, or confirm a
finding.  All executable work remains an ordinary registered experiment.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field, StrictInt, model_validator

from agent_core.research.candidates import ExperimentCandidate
from agent_core.research.chains import (
    ChainLinkStatus,
    ChainSemanticBinding,
    ChainStepOutcome,
    stable_chain_digest,
    stable_chain_identifier,
)
from agent_core.research.graph import GraphAssertion
from agent_core.research.graphql import (
    GraphQLAuthenticationRequirement,
    GraphQLOperationRecord,
    GraphQLObjectReferenceKind,
)
from agent_core.research.graphql_evaluation import GraphQLEvaluationResult
from agent_core.research.outcomes import ExperimentResultClassification
from agent_core.research.state import (
    AttackChain,
    ExperimentOutcome,
    Fact,
    Relationship,
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
    GraphQLOperationType,
    HypothesisResearchStatus,
    OpaqueIdentifier,
    RelationshipStatus,
    ResearchContract,
    ResearchPredicate,
    Sha256Digest,
    SurfaceType,
)

MAX_GRAPHQL_CHAIN_SEMANTIC_ENTITIES = 256
MAX_GRAPHQL_CHAIN_PROPOSALS = 40

_GRAPHQL_KINDS = frozenset(
    {
        EntityKind.graphql_surface,
        EntityKind.graphql_type,
        EntityKind.graphql_field,
        EntityKind.graphql_argument,
        EntityKind.graphql_operation,
        EntityKind.graphql_variable,
    }
)

_MEANINGFUL_RELATIONS = frozenset(
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
        ResearchPredicate.graphql_references_object,
        ResearchPredicate.graphql_modifies_object,
    }
)


class GraphQLChainLimits(ResearchContract):
    max_semantic_entities: StrictInt = Field(
        default=MAX_GRAPHQL_CHAIN_SEMANTIC_ENTITIES, ge=1, le=2_000
    )
    max_proposals: StrictInt = Field(default=MAX_GRAPHQL_CHAIN_PROPOSALS, ge=1, le=200)


class GraphQLChainLinkSpec(ResearchContract):
    """An explicit gap to be materialized as P4-0G ``UnresolvedChainLink``."""

    from_reference: EntityReference
    to_reference: EntityReference
    edge_reference: OpaqueIdentifier
    experiment_candidate_ids: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )
    required_evidence: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=20)
    precondition_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )

    @model_validator(mode="after")
    def canonicalize(self) -> "GraphQLChainLinkSpec":
        for field_name in (
            "experiment_candidate_ids",
            "required_evidence",
            "precondition_references",
        ):
            object.__setattr__(
                self, field_name, tuple(sorted(set(getattr(self, field_name))))
            )
        return self


class GraphQLChainProposal(ResearchContract):
    """Internal, inert path proposal consumed by AttackChainCandidateBuilder."""

    category: OpaqueIdentifier
    ordered_references: tuple[EntityReference, ...] = Field(min_length=2, max_length=4)
    relationship_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    relationship_predicates: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    hypothesis_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    surface_ids: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=16)
    object_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    identity_ids: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=300
    )
    provenance_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )
    semantic_bindings: tuple[ChainSemanticBinding, ...] = Field(
        min_length=1, max_length=100
    )
    unresolved_links: tuple[GraphQLChainLinkSpec, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def canonicalize(self) -> "GraphQLChainProposal":
        markers = tuple(
            (item.entity_kind, item.entity_id) for item in self.ordered_references
        )
        if len(markers) != len(set(markers)):
            raise ValueError("GraphQL chain proposal must be acyclic")
        edges = set(zip(markers, markers[1:]))
        if any(
            (
                (link.from_reference.entity_kind, link.from_reference.entity_id),
                (link.to_reference.entity_kind, link.to_reference.entity_id),
            )
            not in edges
            for link in self.unresolved_links
        ):
            raise ValueError("GraphQL unresolved link must bind adjacent references")
        for field_name in (
            "relationship_ids",
            "relationship_predicates",
            "hypothesis_ids",
            "surface_ids",
            "object_ids",
            "identity_ids",
            "evidence_references",
            "provenance_references",
        ):
            object.__setattr__(
                self, field_name, tuple(sorted(set(getattr(self, field_name))))
            )
        return self


class GraphQLChainAdapter:
    """Discover bounded GraphQL-aware paths without duplicating P4-0G."""

    def __init__(self, limits: GraphQLChainLimits | None = None) -> None:
        self.limits = limits or GraphQLChainLimits()

    def propose(
        self,
        state: ResearchState,
        relationships: Sequence[Relationship | GraphAssertion],
        experiment_candidates: Sequence[ExperimentCandidate] = (),
    ) -> tuple[GraphQLChainProposal, ...]:
        operations = tuple(
            sorted(
                (
                    item
                    for item in state.graphql_operations
                    if isinstance(item, GraphQLOperationRecord)
                ),
                key=lambda item: item.operation_id,
            )
        )
        semantic_count = (
            len(state.graphql_surfaces)
            + len(state.graphql_types)
            + len(state.graphql_fields)
            + len(state.graphql_arguments)
            + len(operations)
            + len(state.graphql_variables)
        )
        if not operations or semantic_count > self.limits.max_semantic_entities:
            return ()

        edges = tuple(
            item
            for item in relationships
            if _eligible_relationship(item, state)
            and item.predicate in _MEANINGFUL_RELATIONS
        )
        experiments = tuple(
            item
            for item in experiment_candidates
            if item.research_id == state.research_id
            and item.state_revision == state.revision
        )
        objects_by_operation = {
            operation.operation_id: self._objects_for_operation(operation, state, edges)
            for operation in operations
        }
        proposals: list[GraphQLChainProposal] = []
        for operation in operations:
            if len(proposals) >= self.limits.max_proposals:
                break
            objects = objects_by_operation[operation.operation_id]
            for object_id in objects:
                proposals.extend(
                    self._object_proposals(
                        operation,
                        object_id,
                        state,
                        edges,
                        experiments,
                    )
                )
                if len(proposals) >= self.limits.max_proposals:
                    break
            proposals.extend(
                self._operation_relation_proposals(
                    operation,
                    state,
                    edges,
                    experiments,
                )
            )

        deduplicated: dict[str, GraphQLChainProposal] = {}
        for proposal in proposals:
            digest = stable_chain_digest(
                {
                    "category": proposal.category,
                    "ordered": [
                        (item.entity_kind.value, item.entity_id)
                        for item in proposal.ordered_references
                    ],
                    "predicates": proposal.relationship_predicates,
                    "objects": proposal.object_ids,
                    "semantics": [
                        (
                            item.reference.entity_kind.value,
                            item.reference.entity_id,
                            item.semantic_fingerprint,
                        )
                        for item in proposal.semantic_bindings
                    ],
                }
            )
            deduplicated.setdefault(digest, proposal)
            if len(deduplicated) >= self.limits.max_proposals:
                break
        return tuple(deduplicated[key] for key in sorted(deduplicated))

    def _object_proposals(
        self,
        operation: GraphQLOperationRecord,
        object_id: str,
        state: ResearchState,
        edges: Sequence[Relationship | GraphAssertion],
        experiments: Sequence[ExperimentCandidate],
    ) -> tuple[GraphQLChainProposal, ...]:
        obj = _find(state.objects, "object_id", object_id)
        surface = _operation_surface(operation, state)
        if (
            obj is None
            or surface is None
            or not obj.test_owned
            or obj.owner_identity_id is None
            or not _controlled_identity(obj.owner_identity_id, state)
        ):
            return ()
        semantic = graphql_chain_bindings_for_operation(state, operation.operation_id)
        operation_ref = EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=operation.operation_id,
        )
        object_ref = EntityReference(entity_kind=EntityKind.object, entity_id=object_id)
        relation_ids, predicates, relation_evidence, relation_provenance = (
            _relations_between(operation_ref, object_ref, edges)
        )
        evidence = {
            *operation.evidence_references,
            *obj.evidence_references,
            *relation_evidence,
        }
        provenance = {
            operation.provenance_id,
            obj.provenance_id,
            *relation_provenance,
        }
        results: list[GraphQLChainProposal] = []

        # GraphQL -> REST: the GraphQL semantic relationship supplies the
        # controlled reference; the REST component must bind that exact object.
        for component in _rest_security_components(object_id, state, experiments):
            component_ref, component_evidence, component_provenance = component
            related = _experiments_for_component(
                component_ref, None, object_id, experiments, state
            )
            link = _unresolved_component_link(object_ref, component_ref, related)
            if link is None and not _confirmed_component(component_ref, state):
                continue
            for source_ref, source_link in _graphql_source_components(
                operation, state, experiments
            ):
                source_evidence, source_provenance = (
                    _reference_support(source_ref, state)
                    if source_ref is not None
                    else ((), ())
                )
                ordered = (
                    (source_ref, operation_ref, object_ref, component_ref)
                    if source_ref is not None
                    else (operation_ref, object_ref, component_ref)
                )
                unresolved = tuple(
                    item for item in (source_link, link) if item is not None
                )
                results.append(
                    GraphQLChainProposal(
                        category="graphql-to-rest",
                        ordered_references=ordered,
                        relationship_ids=relation_ids,
                        relationship_predicates=(
                            *predicates,
                            ResearchPredicate.references_same_object.value,
                        ),
                        hypothesis_ids=tuple(
                            sorted(
                                {
                                    *_hypothesis_ids(component_ref),
                                    *(
                                        (source_ref.entity_id,)
                                        if source_ref is not None
                                        and source_ref.entity_kind
                                        is EntityKind.hypothesis
                                        else ()
                                    ),
                                }
                            )
                        ),
                        surface_ids=(surface.surface_id, obj.surface_id),
                        object_ids=(object_id,),
                        identity_ids=(obj.owner_identity_id,),
                        evidence_references=tuple(
                            sorted(
                                evidence
                                | set(component_evidence)
                                | set(source_evidence)
                            )
                        ),
                        provenance_references=tuple(
                            sorted(
                                provenance
                                | set(component_provenance)
                                | set(source_provenance)
                            )
                        ),
                        semantic_bindings=semantic,
                        unresolved_links=unresolved,
                    )
                )

        # REST -> GraphQL: the REST-owned object is the deterministic source;
        # the protected GraphQL component is always operation-specific.
        source = _rest_source_for_object(obj, state)
        if source is None:
            return tuple(results)
        source_refs = (object_ref,) if source == object_ref else (source, object_ref)
        source_evidence, source_provenance = _reference_support(source, state)
        for component in _graphql_security_components(operation, state):
            component_ref, component_evidence, component_provenance = component
            related = _experiments_for_component(
                component_ref,
                operation.operation_id,
                object_id,
                experiments,
                state,
            )
            link = _unresolved_component_link(operation_ref, component_ref, related)
            if link is None and not _confirmed_component(component_ref, state):
                continue
            ordered = (*source_refs, operation_ref, component_ref)
            if len(ordered) > 4:
                continue
            results.append(
                GraphQLChainProposal(
                    category="rest-to-graphql",
                    ordered_references=ordered,
                    relationship_ids=relation_ids,
                    relationship_predicates=(
                        *predicates,
                        ResearchPredicate.references_same_object.value,
                    ),
                    hypothesis_ids=_hypothesis_ids(component_ref),
                    surface_ids=(obj.surface_id, surface.surface_id),
                    object_ids=(object_id,),
                    identity_ids=(obj.owner_identity_id,),
                    evidence_references=tuple(
                        sorted(
                            evidence | set(source_evidence) | set(component_evidence)
                        )
                    ),
                    provenance_references=tuple(
                        sorted(
                            provenance
                            | set(source_provenance)
                            | set(component_provenance)
                        )
                    ),
                    semantic_bindings=semantic,
                    unresolved_links=(link,) if link is not None else (),
                )
            )
        return tuple(results)

    def _operation_relation_proposals(
        self,
        operation: GraphQLOperationRecord,
        state: ResearchState,
        edges: Sequence[Relationship | GraphAssertion],
        experiments: Sequence[ExperimentCandidate],
    ) -> tuple[GraphQLChainProposal, ...]:
        operation_ref = EntityReference(
            entity_kind=EntityKind.graphql_operation,
            entity_id=operation.operation_id,
        )
        surface = _operation_surface(operation, state)
        if surface is None:
            return ()
        results: list[GraphQLChainProposal] = []
        for edge in edges:
            if edge.source == operation_ref:
                other = edge.target
                forward = True
            elif edge.target == operation_ref:
                other = edge.source
                forward = False
            else:
                continue
            if edge.predicate is ResearchPredicate.depends_on:
                # ``B DEPENDS_ON A`` is traversed as the executable order A -> B.
                forward = not forward
            if other.entity_kind is EntityKind.graphql_operation:
                if not forward:
                    continue
                downstream = _find(
                    state.graphql_operations, "operation_id", other.entity_id
                )
                if not isinstance(downstream, GraphQLOperationRecord):
                    continue
                for component in _graphql_security_components(downstream, state):
                    component_ref, component_evidence, component_provenance = component
                    related = _experiments_for_component(
                        component_ref,
                        downstream.operation_id,
                        None,
                        experiments,
                        state,
                    )
                    link = _unresolved_component_link(other, component_ref, related)
                    if link is None and not _confirmed_component(component_ref, state):
                        continue
                    downstream_surface = _operation_surface(downstream, state)
                    if downstream_surface is None:
                        continue
                    results.append(
                        self._relation_proposal(
                            "graphql-to-graphql",
                            (operation_ref, other, component_ref),
                            edge,
                            state,
                            (
                                *graphql_chain_bindings_for_operation(
                                    state, operation.operation_id
                                ),
                                *graphql_chain_bindings_for_operation(
                                    state, downstream.operation_id
                                ),
                            ),
                            (surface.surface_id, downstream_surface.surface_id),
                            component_evidence,
                            component_provenance,
                            (link,) if link is not None else (),
                        )
                    )
                continue

            category = _relation_category(other, operation, state, forward=forward)
            if category is None:
                continue
            if category in {"authentication-to-graphql", "token-to-graphql"} and not (
                _protected_operation(operation, state)
            ):
                continue
            if category == "token-to-graphql" and not _token_protected_operation(
                operation, state
            ):
                continue
            ordered_prefix = (
                (other, operation_ref) if not forward else (operation_ref, other)
            )
            if category.endswith("-to-graphql"):
                for component in _graphql_security_components(operation, state):
                    component_ref, component_evidence, component_provenance = component
                    related = _experiments_for_component(
                        component_ref,
                        operation.operation_id,
                        None,
                        experiments,
                        state,
                    )
                    link = _unresolved_component_link(
                        operation_ref, component_ref, related
                    )
                    if link is None and not _confirmed_component(component_ref, state):
                        continue
                    results.append(
                        self._relation_proposal(
                            category,
                            (*ordered_prefix, component_ref),
                            edge,
                            state,
                            graphql_chain_bindings_for_operation(
                                state, operation.operation_id
                            ),
                            _surface_ids_for_refs(ordered_prefix, state),
                            component_evidence,
                            component_provenance,
                            (link,) if link is not None else (),
                        )
                    )
            elif category == "graphql-to-workflow":
                if operation.operation_type is not GraphQLOperationType.mutation:
                    continue
                workflow = _find(state.workflows, "workflow_id", other.entity_id)
                if workflow is None or not any(
                    step.state_before_reference or step.state_after_reference
                    for step in workflow.steps
                ):
                    continue
                for component in _graphql_security_components(operation, state):
                    component_ref, component_evidence, component_provenance = component
                    related = _experiments_for_component(
                        component_ref,
                        operation.operation_id,
                        None,
                        experiments,
                        state,
                    )
                    link = _unresolved_component_link(other, component_ref, related)
                    if link is None and not _confirmed_component(component_ref, state):
                        continue
                    results.append(
                        self._relation_proposal(
                            category,
                            (*ordered_prefix, component_ref),
                            edge,
                            state,
                            graphql_chain_bindings_for_operation(
                                state, operation.operation_id
                            ),
                            _surface_ids_for_refs(ordered_prefix, state),
                            (*workflow.evidence_references, *component_evidence),
                            (workflow.provenance_id, *component_provenance),
                            (link,) if link is not None else (),
                        )
                    )
            else:
                # Future upload/server-side integration is representation-only:
                # an explicit evidenced capability/finding relation is required.
                unresolved: tuple[GraphQLChainLinkSpec, ...] = ()
                if category == "graphql-to-server-side" and not _confirmed_component(
                    other, state
                ):
                    related = _experiments_for_component(
                        other,
                        None,
                        None,
                        experiments,
                        state,
                    )
                    link = _unresolved_component_link(operation_ref, other, related)
                    if link is None:
                        continue
                    unresolved = (link,)
                results.append(
                    self._relation_proposal(
                        category,
                        ordered_prefix,
                        edge,
                        state,
                        graphql_chain_bindings_for_operation(
                            state, operation.operation_id
                        ),
                        _surface_ids_for_refs(ordered_prefix, state),
                        (),
                        (),
                        unresolved,
                    )
                )
        return tuple(results)

    @staticmethod
    def _relation_proposal(
        category: str,
        ordered: tuple[EntityReference, ...],
        edge: Relationship | GraphAssertion,
        state: ResearchState,
        semantic_bindings: tuple[ChainSemanticBinding, ...],
        surfaces: tuple[str, ...],
        extra_evidence: Sequence[str],
        extra_provenance: Sequence[str],
        unresolved: tuple[GraphQLChainLinkSpec, ...],
    ) -> GraphQLChainProposal:
        hypotheses = tuple(
            item.entity_id
            for item in ordered
            if item.entity_kind is EntityKind.hypothesis
        )
        object_ids = tuple(
            item.entity_id for item in ordered if item.entity_kind is EntityKind.object
        )
        identities = tuple(
            item.entity_id
            for item in ordered
            if item.entity_kind is EntityKind.identity
        )
        evidence = {
            *edge.evidence_references,
            *extra_evidence,
            *(
                reference
                for item in ordered
                for reference in _reference_support(item, state)[0]
            ),
        }
        provenance = {
            edge.provenance_id,
            *extra_provenance,
            *(
                reference
                for item in ordered
                for reference in _reference_support(item, state)[1]
            ),
        }
        return GraphQLChainProposal(
            category=category,
            ordered_references=ordered,
            relationship_ids=(_edge_id(edge),),
            relationship_predicates=(edge.predicate.value,),
            hypothesis_ids=hypotheses,
            surface_ids=surfaces,
            object_ids=object_ids,
            identity_ids=identities,
            evidence_references=tuple(sorted(evidence)),
            provenance_references=tuple(sorted(provenance)),
            semantic_bindings=_deduplicate_bindings(semantic_bindings),
            unresolved_links=unresolved,
        )

    @staticmethod
    def _objects_for_operation(
        operation: GraphQLOperationRecord,
        state: ResearchState,
        edges: Sequence[Relationship | GraphAssertion],
    ) -> tuple[str, ...]:
        fields = {item.field_id: item for item in state.graphql_fields}
        arguments = {item.argument_id: item for item in state.graphql_arguments}
        source_ids = {operation.operation_id}
        objects: set[str] = set()
        for field_id in operation.root_field_ids:
            field = fields.get(field_id)
            if field is None:
                continue
            source_ids.add(field.field_id)
            objects.update(
                hint.research_object_id
                for hint in field.relationship_hints
                if hint.research_object_id is not None
            )
            for argument_id in field.argument_ids:
                argument = arguments.get(argument_id)
                if argument is None:
                    continue
                source_ids.add(argument.argument_id)
                semantics = argument.object_reference_semantics
                if (
                    semantics.kind is GraphQLObjectReferenceKind.research_object
                    and semantics.research_object_id is not None
                ):
                    objects.add(semantics.research_object_id)
        for edge in edges:
            if edge.predicate not in {
                ResearchPredicate.references_same_object,
                ResearchPredicate.same_object_as,
                ResearchPredicate.graphql_references_object,
                ResearchPredicate.graphql_modifies_object,
            }:
                continue
            if edge.source.entity_id in source_ids and (
                edge.target.entity_kind is EntityKind.object
            ):
                objects.add(edge.target.entity_id)
            elif edge.target.entity_id in source_ids and (
                edge.source.entity_kind is EntityKind.object
            ):
                objects.add(edge.source.entity_id)
        known = {item.object_id for item in state.objects}
        return tuple(sorted(objects & known))


def graphql_chain_semantic_digest(
    state: ResearchState, reference: EntityReference
) -> Sha256Digest:
    """Fingerprint one typed GraphQL record without query text or values."""

    mapping = {
        EntityKind.graphql_surface: (state.graphql_surfaces, "graphql_surface_id"),
        EntityKind.graphql_type: (state.graphql_types, "type_id"),
        EntityKind.graphql_field: (state.graphql_fields, "field_id"),
        EntityKind.graphql_argument: (state.graphql_arguments, "argument_id"),
        EntityKind.graphql_operation: (state.graphql_operations, "operation_id"),
        EntityKind.graphql_variable: (state.graphql_variables, "variable_id"),
    }.get(reference.entity_kind)
    if mapping is None:
        raise ValueError("chain semantic digest requires a GraphQL entity")
    item = _find(mapping[0], mapping[1], reference.entity_id)
    if item is None:
        raise ValueError("GraphQL chain semantic reference is unavailable")
    return stable_chain_digest(
        {
            "kind": reference.entity_kind.value,
            "record": item.model_dump(mode="json"),
        }
    )


def graphql_chain_bindings_for_operation(
    state: ResearchState, operation_id: str
) -> tuple[ChainSemanticBinding, ...]:
    operation = _find(state.graphql_operations, "operation_id", operation_id)
    if not isinstance(operation, GraphQLOperationRecord):
        return ()
    references = [
        EntityReference(
            entity_kind=EntityKind.graphql_operation, entity_id=operation.operation_id
        ),
        EntityReference(
            entity_kind=EntityKind.graphql_surface,
            entity_id=operation.graphql_surface_id,
        ),
    ]
    fields = {item.field_id: item for item in state.graphql_fields}
    types = {item.type_id: item for item in state.graphql_types}
    surface_types = {
        (item.graphql_surface_id, item.name): item for item in state.graphql_types
    }
    for field_id in operation.root_field_ids:
        references.append(
            EntityReference(entity_kind=EntityKind.graphql_field, entity_id=field_id)
        )
        field = fields.get(field_id)
        if field is not None:
            references.append(
                EntityReference(
                    entity_kind=EntityKind.graphql_type,
                    entity_id=field.type_id,
                )
            )
            owner = types.get(field.type_id)
            returned = (
                surface_types.get(
                    (owner.graphql_surface_id, field.return_type.named_type)
                )
                if owner is not None
                else None
            )
            if returned is not None:
                references.append(
                    EntityReference(
                        entity_kind=EntityKind.graphql_type,
                        entity_id=returned.type_id,
                    )
                )
            references.extend(
                EntityReference(
                    entity_kind=EntityKind.graphql_argument,
                    entity_id=argument_id,
                )
                for argument_id in field.argument_ids
            )
    references.extend(
        EntityReference(entity_kind=EntityKind.graphql_variable, entity_id=variable_id)
        for variable_id in operation.variable_ids
    )
    unique = {(item.entity_kind, item.entity_id): item for item in references}
    return tuple(
        ChainSemanticBinding(
            reference=reference,
            semantic_fingerprint=graphql_chain_semantic_digest(state, reference),
        )
        for _, reference in sorted(
            unique.items(), key=lambda item: (item[0][0].value, item[0][1])
        )
    )


def graphql_chain_semantics_current(
    state: ResearchState, bindings: Sequence[ChainSemanticBinding]
) -> bool:
    try:
        return all(
            item.reference.entity_kind not in _GRAPHQL_KINDS
            or graphql_chain_semantic_digest(state, item.reference)
            == item.semantic_fingerprint
            for item in bindings
        )
    except ValueError:
        return False


def revalidate_graphql_chain(
    chain: AttackChain,
    state: ResearchState,
    *,
    updated_at: str | None = None,
) -> AttackChain:
    """Move a stale GraphQL chain to manual review without executing it."""

    if graphql_chain_semantics_current(state, chain.semantic_bindings):
        return chain
    payload = chain.model_dump(mode="python")
    payload.update(
        status=AttackChainStatus.manual_review,
        updated_at=updated_at or state.updated_at,
    )
    return AttackChain.model_validate(payload)


def graphql_chain_step_outcome(
    chain: AttackChain,
    *,
    unresolved_link_id: str,
    graphql_evaluation: GraphQLEvaluationResult,
    experiment_outcome: ExperimentOutcome,
    authorization_reference: str | None,
    occurred_at: str | None = None,
) -> ChainStepOutcome:
    """Translate a P4-1F result into the existing deterministic chain signal."""

    if graphql_evaluation.experiment_id != experiment_outcome.experiment_id:
        raise ValueError("GraphQL chain evaluation experiment binding mismatch")
    if graphql_evaluation.outcome_id != experiment_outcome.outcome_id:
        raise ValueError("GraphQL chain evaluation outcome binding mismatch")
    if not set(graphql_evaluation.evidence_references).issubset(
        experiment_outcome.evidence_references
    ):
        raise ValueError("GraphQL chain evaluation cites unavailable evidence")
    link = next(
        (item for item in chain.unresolved_links if item.link_id == unresolved_link_id),
        None,
    )
    step = next(
        (item for item in chain.steps if item.unresolved_link_id == unresolved_link_id),
        None,
    )
    if link is None or step is None:
        raise ValueError("GraphQL chain link is unavailable")
    if not any(
        capability in {"graphql_operation", "graphql_variable_mutation"}
        for capability in link.allowed_experiment_capabilities
    ):
        raise ValueError("chain link does not permit a GraphQL experiment")
    if graphql_evaluation.operation_reference not in {
        item.reference.entity_id
        for item in chain.semantic_bindings
        if item.reference.entity_kind is EntityKind.graphql_operation
    }:
        raise ValueError("GraphQL evaluation operation changed from the chain")
    status = {
        ExperimentResultClassification.vulnerable_signal: ChainLinkStatus.supported,
        ExperimentResultClassification.secure_signal: ChainLinkStatus.refuted,
        ExperimentResultClassification.blocked: ChainLinkStatus.policy_blocked,
        ExperimentResultClassification.cleanup_failed: ChainLinkStatus.cleanup_failed,
        ExperimentResultClassification.runtime_failed: ChainLinkStatus.inconclusive,
        ExperimentResultClassification.inconclusive: ChainLinkStatus.inconclusive,
    }[graphql_evaluation.classification]
    cleanup = experiment_outcome.cleanup_status
    if cleanup is CleanupStatus.failed:
        status = ChainLinkStatus.cleanup_failed
    return ChainStepOutcome(
        outcome_id=stable_chain_identifier(
            "graphql-chain-outcome",
            {
                "chain": chain.attack_chain_id,
                "link": unresolved_link_id,
                "evaluation": graphql_evaluation.evaluation_id,
            },
        ),
        chain_id=chain.attack_chain_id,
        step_id=str(step.step_id),
        sequence=step.sequence,
        status=status,
        evidence_references=graphql_evaluation.evidence_references,
        experiment_id=experiment_outcome.experiment_id,
        request_delta=experiment_outcome.request_delta,
        cleanup_status=cleanup,
        authorization_reference=authorization_reference,
        provenance_id=experiment_outcome.provenance_id,
        occurred_at=occurred_at or experiment_outcome.occurred_at,
    )


def _graphql_security_components(
    operation: GraphQLOperationRecord, state: ResearchState
) -> tuple[tuple[EntityReference, tuple[str, ...], tuple[str, ...]], ...]:
    fields = set(operation.root_field_ids)
    arguments = {
        argument_id
        for item in state.graphql_fields
        if item.field_id in fields
        for argument_id in item.argument_ids
    }
    results = []
    for finding in state.findings:
        if (
            finding.graphql_operation_id == operation.operation_id
            and finding.status
            in {
                FindingStatus.candidate,
                FindingStatus.reproducing,
                FindingStatus.reproduced,
                FindingStatus.confirmed,
            }
        ):
            results.append(
                (
                    EntityReference(
                        entity_kind=EntityKind.finding,
                        entity_id=finding.finding_id,
                    ),
                    finding.evidence_references,
                    (finding.provenance_id,),
                )
            )
    for hypothesis in state.hypotheses:
        refs = {
            (item.entity_kind, item.entity_id) for item in hypothesis.entity_references
        }
        exact = (
            (EntityKind.graphql_operation, operation.operation_id) in refs
            or any((EntityKind.graphql_field, item) in refs for item in fields)
            or any((EntityKind.graphql_argument, item) in refs for item in arguments)
        )
        if exact and hypothesis.status not in {
            HypothesisResearchStatus.refuted,
            HypothesisResearchStatus.closed,
        }:
            results.append(
                (
                    EntityReference(
                        entity_kind=EntityKind.hypothesis,
                        entity_id=hypothesis.hypothesis_id,
                    ),
                    hypothesis.supporting_evidence,
                    (hypothesis.provenance_id,),
                )
            )
    return tuple(results)


def _graphql_source_components(
    operation: GraphQLOperationRecord,
    state: ResearchState,
    experiments: Sequence[ExperimentCandidate],
) -> tuple[tuple[EntityReference | None, GraphQLChainLinkSpec | None], ...]:
    """Return GraphQL findings when they can be represented honestly.

    The semantic operation remains a valid source when it establishes the
    controlled relationship on its own.  A non-confirmed finding is included
    only with an explicit ordinary-experiment dependency.
    """

    operation_ref = EntityReference(
        entity_kind=EntityKind.graphql_operation,
        entity_id=operation.operation_id,
    )
    results: list[tuple[EntityReference | None, GraphQLChainLinkSpec | None]] = [
        (None, None)
    ]
    for finding in state.findings:
        if (
            finding.graphql_operation_id != operation.operation_id
            or finding.status
            not in {
                FindingStatus.candidate,
                FindingStatus.reproducing,
                FindingStatus.reproduced,
                FindingStatus.confirmed,
            }
        ):
            continue
        reference = EntityReference(
            entity_kind=EntityKind.finding, entity_id=finding.finding_id
        )
        if finding.status is FindingStatus.confirmed:
            results.append((reference, None))
            continue
        related = _experiments_for_component(
            reference,
            operation.operation_id,
            None,
            experiments,
            state,
        )
        link = _unresolved_component_link(reference, operation_ref, related)
        if link is not None:
            results.append((reference, link))
    return tuple(results)


def _rest_security_components(
    object_id: str,
    state: ResearchState,
    experiments: Sequence[ExperimentCandidate],
) -> tuple[tuple[EntityReference, tuple[str, ...], tuple[str, ...]], ...]:
    rest_surfaces = {
        item.surface_id
        for item in state.surfaces
        if item.surface_type is SurfaceType.rest
    }
    results = []
    for finding in state.findings:
        if (
            finding.surface_id in rest_surfaces
            and object_id in finding.controlled_object_ids
            and finding.status
            in {
                FindingStatus.candidate,
                FindingStatus.reproducing,
                FindingStatus.reproduced,
                FindingStatus.confirmed,
            }
        ):
            results.append(
                (
                    EntityReference(
                        entity_kind=EntityKind.finding,
                        entity_id=finding.finding_id,
                    ),
                    finding.evidence_references,
                    (finding.provenance_id,),
                )
            )
    for hypothesis in state.hypotheses:
        binds_object = any(
            item.entity_kind is EntityKind.object and item.entity_id == object_id
            for item in hypothesis.entity_references
        ) or any(
            item.hypothesis_id == hypothesis.hypothesis_id
            and item.controlled_object_id == object_id
            for item in experiments
        )
        if (
            hypothesis.surface_id in rest_surfaces
            and binds_object
            and hypothesis.status
            not in {
                HypothesisResearchStatus.refuted,
                HypothesisResearchStatus.closed,
            }
        ):
            results.append(
                (
                    EntityReference(
                        entity_kind=EntityKind.hypothesis,
                        entity_id=hypothesis.hypothesis_id,
                    ),
                    hypothesis.supporting_evidence,
                    (hypothesis.provenance_id,),
                )
            )
    return tuple(results)


def _unresolved_component_link(
    source: EntityReference,
    target: EntityReference,
    experiments: Sequence[ExperimentCandidate],
) -> GraphQLChainLinkSpec | None:
    if not experiments:
        return None
    return GraphQLChainLinkSpec(
        from_reference=source,
        to_reference=target,
        edge_reference=stable_chain_identifier(
            "graphql-chain-gap",
            {
                "source": source.model_dump(mode="json"),
                "target": target.model_dump(mode="json"),
                "experiments": sorted(item.candidate_id for item in experiments),
            },
        ),
        experiment_candidate_ids=tuple(item.candidate_id for item in experiments),
        required_evidence=(
            "predicate:graphql-differential-link",
            "predicate:ordered-dependency",
        ),
        precondition_references=("predicate:current-graphql-semantics",),
    )


def _experiments_for_component(
    component: EntityReference,
    operation_id: str | None,
    object_id: str | None,
    experiments: Sequence[ExperimentCandidate],
    state: ResearchState,
) -> tuple[ExperimentCandidate, ...]:
    hypothesis_id = (
        component.entity_id
        if component.entity_kind is EntityKind.hypothesis
        else getattr(
            _find(state.findings, "finding_id", component.entity_id),
            "source_hypothesis_id",
            None,
        )
    )
    return tuple(
        item
        for item in experiments
        if item.hypothesis_id == hypothesis_id
        and (operation_id is None or item.operation_id == operation_id)
        and (object_id is None or item.controlled_object_id in {None, object_id})
    )


def _confirmed_component(reference: EntityReference, state: ResearchState) -> bool:
    if reference.entity_kind is not EntityKind.finding:
        return False
    finding = _find(state.findings, "finding_id", reference.entity_id)
    return bool(finding and finding.status is FindingStatus.confirmed)


def _rest_source_for_object(
    obj: object, state: ResearchState
) -> EntityReference | None:
    rest_surface_ids = {
        item.surface_id
        for item in state.surfaces
        if item.surface_type is SurfaceType.rest
    }
    parameter_ids = set(getattr(obj, "parameter_references", ()))
    rest_parameter_ids = {
        item.parameter_id
        for item in state.parameters
        if item.parameter_id in parameter_ids
        and any(
            endpoint.endpoint_id == item.endpoint_id
            and endpoint.surface_id in rest_surface_ids
            for endpoint in state.endpoints
        )
    }
    if getattr(obj, "surface_id", None) not in rest_surface_ids and not (
        rest_parameter_ids
    ):
        return None
    candidates = [
        item
        for item in state.facts
        if _eligible_fact(item, state)
        and (
            item.subject.entity_id == obj.object_id
            or (
                item.object.kind == "reference"
                and item.object.reference.entity_id == obj.object_id
            )
        )
    ]
    if candidates:
        return EntityReference(
            entity_kind=EntityKind.fact,
            entity_id=sorted(candidates, key=lambda item: item.fact_id)[0].fact_id,
        )
    return EntityReference(entity_kind=EntityKind.object, entity_id=obj.object_id)


def _relation_category(
    other: EntityReference,
    operation: GraphQLOperationRecord,
    state: ResearchState,
    *,
    forward: bool,
) -> str | None:
    if not forward:
        if other.entity_kind is EntityKind.token:
            return "token-to-graphql"
        if other.entity_kind in {EntityKind.identity, EntityKind.session}:
            return "authentication-to-graphql"
        if other.entity_kind is EntityKind.workflow:
            return "workflow-to-graphql"
        surface_types = _surface_types(other, state)
        if SurfaceType.token in surface_types:
            return "token-to-graphql"
        if surface_types.intersection(
            {SurfaceType.authentication, SurfaceType.session}
        ):
            return "authentication-to-graphql"
        if SurfaceType.workflow in surface_types:
            return "workflow-to-graphql"
        return None
    if other.entity_kind is EntityKind.workflow:
        return "graphql-to-workflow"
    if other.entity_kind is EntityKind.upload:
        return "graphql-to-upload"
    if other.entity_kind in {EntityKind.finding, EntityKind.hypothesis}:
        record = (
            _find(state.findings, "finding_id", other.entity_id)
            if other.entity_kind is EntityKind.finding
            else _find(state.hypotheses, "hypothesis_id", other.entity_id)
        )
        marker = " ".join(
            str(getattr(record, name, ""))
            for name in ("category", "security_property_reference", "capability")
        ).lower()
        if any(item in marker for item in ("server", "ssrf", "injection")):
            return "graphql-to-server-side"
    return None


def _protected_operation(
    operation: GraphQLOperationRecord, state: ResearchState
) -> bool:
    if operation.authentication_requirement not in {
        GraphQLAuthenticationRequirement.unknown,
        GraphQLAuthenticationRequirement.anonymous_observed,
    }:
        return True
    protected_fields = {item.field_id: item for item in state.graphql_fields}
    if any(
        observation.value != "unknown"
        for field_id in operation.root_field_ids
        for field in (protected_fields.get(field_id),)
        if field is not None
        for observation in field.authorization_semantics.observations
    ):
        return True
    if any(
        any(
            reference.entity_kind is EntityKind.graphql_operation
            and reference.entity_id == operation.operation_id
            for reference in hypothesis.entity_references
        )
        and str(hypothesis.security_property or "")
        in {
            "authentication-enforcement",
            "object-authorization",
            "ownership-authorization",
            "field-level-authorization",
            "operation-level-authorization",
            "role-bound-access",
            "tenant-bound-access",
        }
        for hypothesis in state.hypotheses
        if hypothesis.status
        not in {HypothesisResearchStatus.refuted, HypothesisResearchStatus.closed}
    ):
        return True
    surface = _find(
        state.graphql_surfaces,
        "graphql_surface_id",
        operation.graphql_surface_id,
    )
    return bool(
        surface
        and surface.authentication_requirement
        not in {
            GraphQLAuthenticationRequirement.unknown,
            GraphQLAuthenticationRequirement.anonymous_observed,
        }
    )


def _token_protected_operation(
    operation: GraphQLOperationRecord, state: ResearchState
) -> bool:
    if operation.authentication_requirement in {
        GraphQLAuthenticationRequirement.role_bound,
        GraphQLAuthenticationRequirement.tenant_bound,
    }:
        return True
    relevant_properties = {
        "object-authorization",
        "ownership-authorization",
        "role-bound-access",
        "tenant-bound-access",
    }
    return any(
        str(hypothesis.security_property or "") in relevant_properties
        and any(
            reference.entity_kind is EntityKind.graphql_operation
            and reference.entity_id == operation.operation_id
            for reference in hypothesis.entity_references
        )
        for hypothesis in state.hypotheses
        if hypothesis.status
        not in {HypothesisResearchStatus.refuted, HypothesisResearchStatus.closed}
    )


def _operation_surface(operation: GraphQLOperationRecord, state: ResearchState):
    return _find(
        state.graphql_surfaces,
        "graphql_surface_id",
        operation.graphql_surface_id,
    )


def _relations_between(
    source: EntityReference,
    target: EntityReference,
    edges: Sequence[Relationship | GraphAssertion],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    related = tuple(
        item
        for item in edges
        if (item.source == source and item.target == target)
        or (item.source == target and item.target == source)
    )
    return (
        tuple(_edge_id(item) for item in related),
        tuple(item.predicate.value for item in related),
        tuple(
            sorted(
                {
                    reference
                    for item in related
                    for reference in item.evidence_references
                }
            )
        ),
        tuple(sorted({item.provenance_id for item in related})),
    )


def _surface_ids_for_refs(
    references: Sequence[EntityReference], state: ResearchState
) -> tuple[str, ...]:
    surfaces: set[str] = set()
    for reference in references:
        if reference.entity_kind is EntityKind.graphql_operation:
            operation = _find(
                state.graphql_operations, "operation_id", reference.entity_id
            )
            if isinstance(operation, GraphQLOperationRecord):
                semantic_surface = _operation_surface(operation, state)
                if semantic_surface is not None:
                    surfaces.add(semantic_surface.surface_id)
        evidence, _ = _reference_support(reference, state)
        del evidence
        mapping = {
            EntityKind.workflow: (state.workflows, "workflow_id"),
            EntityKind.upload: (state.uploads, "upload_id"),
            EntityKind.finding: (state.findings, "finding_id"),
            EntityKind.hypothesis: (state.hypotheses, "hypothesis_id"),
            EntityKind.object: (state.objects, "object_id"),
        }.get(reference.entity_kind)
        if mapping is not None:
            record = _find(mapping[0], mapping[1], reference.entity_id)
            surface_id = getattr(record, "surface_id", None)
            if surface_id is not None:
                surfaces.add(surface_id)
    return tuple(sorted(surfaces))


def _surface_types(
    reference: EntityReference, state: ResearchState
) -> set[SurfaceType]:
    surface_ids = set(_surface_ids_for_refs((reference,), state))
    return {
        item.surface_type for item in state.surfaces if item.surface_id in surface_ids
    }


def _reference_support(
    reference: EntityReference, state: ResearchState
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mapping = {
        EntityKind.fact: (state.facts, "fact_id"),
        EntityKind.finding: (state.findings, "finding_id"),
        EntityKind.hypothesis: (state.hypotheses, "hypothesis_id"),
        EntityKind.object: (state.objects, "object_id"),
        EntityKind.workflow: (state.workflows, "workflow_id"),
        EntityKind.upload: (state.uploads, "upload_id"),
        EntityKind.token: (state.token_refs, "token_ref_id"),
        EntityKind.session: (state.session_refs, "session_ref_id"),
        EntityKind.identity: (state.identities, "identity_id"),
    }.get(reference.entity_kind)
    if mapping is None:
        return (), ()
    item = _find(mapping[0], mapping[1], reference.entity_id)
    if item is None:
        return (), ()
    evidence = tuple(
        getattr(item, "evidence_references", ())
        or getattr(item, "supporting_evidence", ())
    )
    provenance = getattr(item, "provenance_id", None)
    return evidence, (provenance,) if provenance else ()


def _eligible_relationship(
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


def _eligible_fact(fact: Fact, state: ResearchState) -> bool:
    return (
        fact.status in {FactStatus.observed, FactStatus.confirmed}
        and fact.derivation_type is not DerivationType.model_proposed
        and bool(fact.evidence_references)
        and set(fact.evidence_references).issubset(
            {item.evidence_id for item in state.evidence}
        )
    )


def _controlled_identity(identity_id: str, state: ResearchState) -> bool:
    return any(
        item.identity_id == identity_id
        and item.controlled
        and item.eligibility.value == "eligible"
        for item in state.identities
    )


def _hypothesis_ids(reference: EntityReference) -> tuple[str, ...]:
    return (
        (reference.entity_id,) if reference.entity_kind is EntityKind.hypothesis else ()
    )


def _edge_id(edge: Relationship | GraphAssertion) -> str:
    return edge.relationship_id if isinstance(edge, Relationship) else edge.assertion_id


def _deduplicate_bindings(
    bindings: Sequence[ChainSemanticBinding],
) -> tuple[ChainSemanticBinding, ...]:
    by_ref = {
        (item.reference.entity_kind, item.reference.entity_id): item
        for item in bindings
    }
    return tuple(
        by_ref[key] for key in sorted(by_ref, key=lambda item: (item[0].value, item[1]))
    )


def _find(collection: Sequence[object], field: str, value: str) -> object | None:
    return next((item for item in collection if getattr(item, field) == value), None)
