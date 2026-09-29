"""Deterministic, execution-neutral GraphQL security hypothesis generation.

The generator consumes only persisted Phase 4 semantics and evidence-backed graph
relations.  It has no transport, query construction, payload generation, finding,
or authorization capability.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import Field, StrictBool, StrictInt

from agent_core.research.adapters import stable_research_identifier
from agent_core.research.graph import GraphAssertion, ResearchGraphRepository
from agent_core.research.graphql import (
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLFieldRecord,
    GraphQLObjectReferenceKind,
    GraphQLOperationRecord,
    GraphQLRelationshipKind,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    graphql_semantic_id,
)
from agent_core.research.state import (
    HypothesisRecord,
    ProvenanceRecord,
    ResearchObject,
    ResearchState,
)
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    EntityReference,
    FactStatus,
    GraphQLOperationType,
    HypothesisResearchStatus,
    IdentityEligibility,
    ProvenanceProducerType,
    RelationshipStatus,
    ResearchConfidence,
    ResearchContract,
    ResearchPredicate,
)

if TYPE_CHECKING:
    from agent_core.research.store import ResearchStore


GRAPHQL_HYPOTHESIS_VERSION = "phase4-graphql-hypotheses-v1"
MAX_GRAPHQL_HYPOTHESIS_EVIDENCE = 32
MAX_GRAPHQL_HYPOTHESIS_ENTITY_REFERENCES = 16
MAX_GRAPHQL_HYPOTHESIS_CANDIDATES = 10_000


class GraphQLHypothesisProperty(str, Enum):
    object_authorization = "object-authorization"
    field_level_authorization = "field-level-authorization"
    operation_level_authorization = "operation-level-authorization"
    authentication_enforcement = "authentication-enforcement"
    role_bound_access = "role-bound-access"
    tenant_bound_access = "tenant-bound-access"
    mutation_authorization = "mutation-authorization"
    cross_surface_authorization = "cross-surface-authorization"
    relationship_traversal_authorization = "relationship-traversal-authorization"
    argument_input_validation = "argument-input-validation"
    workflow_bound_mutation = "workflow-bound-mutation"


class GraphQLHypothesisLimits(ResearchContract):
    max_hypotheses_per_surface: StrictInt = Field(default=12, ge=1, le=200)
    max_hypotheses_per_operation: StrictInt = Field(default=6, ge=1, le=100)
    max_hypotheses_per_object_relationship: StrictInt = Field(default=4, ge=1, le=50)
    max_cross_surface_hypotheses: StrictInt = Field(default=6, ge=0, le=100)
    max_total_new_hypotheses: StrictInt = Field(default=40, ge=1, le=500)


class GraphQLHypothesisGenerationResult(ResearchContract):
    hypotheses: tuple[HypothesisRecord, ...] = Field(default=(), max_length=500)
    provenance: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=1)
    graph_assertions: tuple[GraphAssertion, ...] = Field(default=(), max_length=500)
    eligible_count: StrictInt = Field(ge=0, le=100_000)
    selected_count: StrictInt = Field(ge=0, le=500)
    truncated: StrictBool
    truncation_reasons: tuple[str, ...] = Field(default=(), max_length=10)


@dataclass(frozen=True)
class _Candidate:
    security_property: GraphQLHypothesisProperty
    category: str
    title: str
    claim: str
    falsification: str
    target_id: str
    surface_id: str
    priority: int
    confidence: ResearchConfidence
    evidence_references: tuple[str, ...]
    entity_references: tuple[EntityReference, ...]
    missing_evidence: tuple[str, ...]
    required_preconditions: tuple[str, ...]
    operation_id: str | None = None
    object_relationship_key: tuple[str, ...] = ()
    basis_relationship_ids: tuple[str, ...] = ()
    requires_state_change: bool = False
    cross_surface: bool = False


def graphql_hypothesis_fingerprint(
    *,
    security_property: GraphQLHypothesisProperty | str,
    category: str,
    target_id: str,
    surface_id: str,
    entity_references: Iterable[EntityReference],
    object_relationship_key: Iterable[str] = (),
) -> str:
    """Fingerprint the security property and semantic bindings, never wording."""

    property_value = (
        security_property.value
        if isinstance(security_property, GraphQLHypothesisProperty)
        else security_property
    )
    payload = {
        "security_property": property_value,
        "category": category,
        "target_id": target_id,
        "surface_id": surface_id,
        "entities": sorted(
            (item.entity_kind.value, item.entity_id) for item in entity_references
        ),
        "object_relationship": sorted(set(object_relationship_key)),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_graphql_hypothesis_graph_assertions(
    state: ResearchState,
    hypotheses: Sequence[HypothesisRecord],
    *,
    asserted_at: str,
) -> tuple[GraphAssertion, ...]:
    """Link hypotheses to their basis entities without asserting their claims."""

    assertions: dict[str, GraphAssertion] = {}
    for hypothesis in hypotheses:
        evidence = hypothesis.supporting_evidence[:MAX_GRAPHQL_HYPOTHESIS_EVIDENCE]
        for reference in hypothesis.entity_references:
            assertion_id = graphql_semantic_id(
                "hypothesis-edge",
                hypothesis.hypothesis_id,
                reference.entity_kind.value,
                reference.entity_id,
            )
            assertions[assertion_id] = GraphAssertion(
                assertion_id=assertion_id,
                research_id=state.research_id,
                source=EntityReference(
                    entity_kind=EntityKind.hypothesis,
                    entity_id=hypothesis.hypothesis_id,
                ),
                relation=ResearchPredicate.derives_from,
                target=reference,
                status=RelationshipStatus.observed,
                evidence_references=evidence,
                derivation_type=DerivationType.deterministic,
                provenance_id=hypothesis.provenance_id,
                asserted_at=asserted_at,
            )
    return tuple(assertions[key] for key in sorted(assertions)[:500])


class GraphQLHypothesisGenerator:
    """Generate bounded GraphQL hypotheses from registered semantic evidence."""

    def __init__(
        self,
        limits: GraphQLHypothesisLimits | None = None,
        *,
        confirmation_policy_reference: str = "graphql-hypothesis-policy",
        allowed_categories: Sequence[str] | None = None,
    ) -> None:
        self.limits = limits or GraphQLHypothesisLimits()
        self.confirmation_policy_reference = confirmation_policy_reference
        self.allowed_categories = (
            frozenset(allowed_categories) if allowed_categories is not None else None
        )

    def generate(
        self,
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None = None,
        *,
        occurred_at: str | None = None,
        max_new_hypotheses: int | None = None,
    ) -> tuple[HypothesisRecord, ...]:
        return self.generate_result(
            state,
            graph,
            occurred_at=occurred_at,
            max_new_hypotheses=max_new_hypotheses,
        ).hypotheses

    def generate_result(
        self,
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None = None,
        *,
        occurred_at: str | None = None,
        max_new_hypotheses: int | None = None,
    ) -> GraphQLHypothesisGenerationResult:
        if max_new_hypotheses is not None and (
            isinstance(max_new_hypotheses, bool) or max_new_hypotheses < 0
        ):
            raise ValueError("GraphQL hypothesis bound must be a non-negative integer")
        maximum = self.limits.max_total_new_hypotheses
        if max_new_hypotheses is not None:
            maximum = min(maximum, max_new_hypotheses)
        maximum = min(maximum, max(0, 5_000 - len(state.hypotheses)))
        if maximum == 0 or not state.graphql_surfaces:
            return GraphQLHypothesisGenerationResult(
                eligible_count=0, selected_count=0, truncated=False
            )

        assertions = self._assertions(state, graph)
        candidates = self._candidates(state, assertions)
        existing = {
            item.semantic_fingerprint
            for item in state.hypotheses
            if item.semantic_fingerprint is not None
        }
        provenance_id = stable_research_identifier(
            "provenance", state.research_id, "graphql-security-hypotheses-pending"
        )
        eligible: dict[str, tuple[_Candidate, HypothesisRecord]] = {}
        for candidate in candidates:
            if self.allowed_categories is not None and (
                candidate.category not in self.allowed_categories
            ):
                continue
            fingerprint = graphql_hypothesis_fingerprint(
                security_property=candidate.security_property,
                category=candidate.category,
                target_id=candidate.target_id,
                surface_id=candidate.surface_id,
                entity_references=candidate.entity_references,
                object_relationship_key=candidate.object_relationship_key,
            )
            if fingerprint in existing or fingerprint in eligible:
                continue
            if self._secure_property_is_proven(state, candidate):
                continue
            record = HypothesisRecord(
                hypothesis_id=stable_research_identifier("hypothesis", fingerprint),
                category=candidate.category,
                title=candidate.title,
                claim=(
                    f"{candidate.claim} This hypothesis is falsified when: "
                    f"{candidate.falsification}"
                ),
                target_id=candidate.target_id,
                surface_id=candidate.surface_id,
                status=HypothesisResearchStatus.proposed,
                priority=candidate.priority,
                confidence=candidate.confidence,
                confirmation_policy_reference=self.confirmation_policy_reference,
                supporting_evidence=candidate.evidence_references,
                limitations=(
                    candidate.falsification,
                    "No GraphQL request or state change was performed by hypothesis generation.",
                ),
                derivation_type=DerivationType.deterministic,
                basis_relationship_ids=candidate.basis_relationship_ids,
                security_property=candidate.security_property.value,
                entity_references=candidate.entity_references,
                missing_evidence=candidate.missing_evidence,
                required_preconditions=candidate.required_preconditions,
                requires_state_change=candidate.requires_state_change,
                semantic_fingerprint=fingerprint,
                provenance_id=provenance_id,
            )
            eligible[fingerprint] = (candidate, record)

        selected: list[tuple[_Candidate, HypothesisRecord]] = []
        surface_counts: dict[str, int] = {}
        operation_counts: dict[str, int] = {}
        object_counts: dict[tuple[str, ...], int] = {}
        cross_count = 0
        reasons: set[str] = set()
        ordered = sorted(
            eligible.values(),
            key=lambda item: (-item[1].priority, item[1].hypothesis_id),
        )
        for candidate, record in ordered:
            if len(selected) >= maximum:
                reasons.add("maximum-total-graphql-hypotheses")
                continue
            if (
                surface_counts.get(candidate.surface_id, 0)
                >= self.limits.max_hypotheses_per_surface
            ):
                reasons.add("maximum-graphql-hypotheses-per-surface")
                continue
            if candidate.operation_id is not None and (
                operation_counts.get(candidate.operation_id, 0)
                >= self.limits.max_hypotheses_per_operation
            ):
                reasons.add("maximum-graphql-hypotheses-per-operation")
                continue
            if candidate.object_relationship_key and (
                object_counts.get(candidate.object_relationship_key, 0)
                >= self.limits.max_hypotheses_per_object_relationship
            ):
                reasons.add("maximum-graphql-hypotheses-per-object-relationship")
                continue
            if candidate.cross_surface and (
                cross_count >= self.limits.max_cross_surface_hypotheses
            ):
                reasons.add("maximum-cross-surface-graphql-hypotheses")
                continue
            selected.append((candidate, record))
            surface_counts[candidate.surface_id] = (
                surface_counts.get(candidate.surface_id, 0) + 1
            )
            if candidate.operation_id is not None:
                operation_counts[candidate.operation_id] = (
                    operation_counts.get(candidate.operation_id, 0) + 1
                )
            if candidate.object_relationship_key:
                object_counts[candidate.object_relationship_key] = (
                    object_counts.get(candidate.object_relationship_key, 0) + 1
                )
            if candidate.cross_surface:
                cross_count += 1

        selected_records = tuple(item[1] for item in selected)
        timestamp = occurred_at or state.updated_at
        if selected_records:
            batch_fingerprint = hashlib.sha256(
                json.dumps(
                    sorted(item.semantic_fingerprint for item in selected_records),
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            provenance_id = stable_research_identifier(
                "provenance",
                state.research_id,
                "graphql-security-hypotheses",
                batch_fingerprint,
            )
            hypotheses = tuple(
                item.model_copy(update={"provenance_id": provenance_id})
                for item in selected_records
            )
            source_references = tuple(
                sorted(
                    {
                        reference
                        for item in hypotheses
                        for reference in item.supporting_evidence
                    }
                )[:100]
            )
            provenance = (
                ProvenanceRecord(
                    provenance_id=provenance_id,
                    producer_type=ProvenanceProducerType.deterministic,
                    producer_name="graphql-hypothesis-generator",
                    producer_version=GRAPHQL_HYPOTHESIS_VERSION,
                    source_references=source_references,
                    summary=(
                        "Generated bounded, evidence-backed GraphQL security "
                        "hypotheses without executing target requests."
                    ),
                    occurred_at=timestamp,
                ),
            )
        else:
            hypotheses = ()
            provenance = ()
        graph_assertions = build_graphql_hypothesis_graph_assertions(
            state.model_copy(update={"hypotheses": (*state.hypotheses, *hypotheses)}),
            hypotheses,
            asserted_at=timestamp,
        )
        return GraphQLHypothesisGenerationResult(
            hypotheses=hypotheses,
            provenance=provenance,
            graph_assertions=graph_assertions,
            eligible_count=len(eligible),
            selected_count=len(hypotheses),
            truncated=bool(reasons),
            truncation_reasons=tuple(sorted(reasons)),
        )

    def persist(
        self,
        store: ResearchStore,
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None = None,
        *,
        expected_revision: int | None = None,
        occurred_at: str | None = None,
        max_new_hypotheses: int | None = None,
    ) -> ResearchState:
        """Atomically persist new records through the existing research store."""

        expected = state.revision if expected_revision is None else expected_revision
        if expected != state.revision:
            raise ValueError("GraphQL hypothesis persistence received a stale state")
        timestamp = occurred_at or state.updated_at
        result = self.generate_result(
            state,
            graph,
            occurred_at=timestamp,
            max_new_hypotheses=max_new_hypotheses,
        )
        diagnostic_codes = set(state.diagnostic_codes)
        if result.truncated:
            diagnostic_codes.add("graphql-hypothesis-generation-truncated")
        if not result.hypotheses and diagnostic_codes == set(state.diagnostic_codes):
            return state
        provenance = {item.provenance_id: item for item in state.provenance}
        provenance.update({item.provenance_id: item for item in result.provenance})
        hypotheses = {item.hypothesis_id: item for item in state.hypotheses}
        hypotheses.update({item.hypothesis_id: item for item in result.hypotheses})
        next_state = ResearchState.model_validate(
            {
                **state.model_dump(mode="python"),
                "revision": state.revision + 1,
                "updated_at": timestamp,
                "hypotheses": tuple(hypotheses[key] for key in sorted(hypotheses)),
                "provenance": tuple(provenance[key] for key in sorted(provenance)),
                "diagnostic_codes": tuple(sorted(diagnostic_codes)),
            }
        )
        new_assertions = []
        for assertion in result.graph_assertions:
            try:
                store.load_graph_assertion(state.research_id, assertion.assertion_id)
            except KeyError:
                new_assertions.append(assertion)
        return store.commit_revision(
            state.research_id,
            expected_revision=expected,
            state=next_state,
            graph_assertions=tuple(new_assertions),
        )

    def _candidates(
        self, state: ResearchState, assertions: Sequence[GraphAssertion]
    ) -> tuple[_Candidate, ...]:
        surfaces = {item.graphql_surface_id: item for item in state.graphql_surfaces}
        types = {item.type_id: item for item in state.graphql_types}
        fields = {item.field_id: item for item in state.graphql_fields}
        arguments = {item.argument_id: item for item in state.graphql_arguments}
        operations = tuple(
            item
            for item in state.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
        )
        objects = {item.object_id: item for item in state.objects}
        controlled = tuple(
            item
            for item in state.identities
            if item.controlled
            and item.eligibility is not IdentityEligibility.ineligible
        )
        graph_edges = tuple(
            item
            for item in assertions
            if item.status
            not in {RelationshipStatus.rejected, RelationshipStatus.superseded}
            and item.derivation_type is DerivationType.deterministic
        )

        def field_surface(field: GraphQLFieldRecord):
            owner = types.get(field.type_id)
            return surfaces.get(owner.graphql_surface_id) if owner is not None else None

        def operation_fields(operation: GraphQLOperationRecord):
            return tuple(
                fields[field_id]
                for field_id in operation.root_field_ids
                if field_id in fields
            )

        def operation_arguments(operation: GraphQLOperationRecord):
            return tuple(
                arguments[argument_id]
                for field in operation_fields(operation)
                for argument_id in field.argument_ids
                if argument_id in arguments
            )

        def graph_objects_for(source_ids: set[str]) -> set[str]:
            return {
                edge.target.entity_id
                for edge in graph_edges
                if edge.source.entity_id in source_ids
                and edge.target.entity_kind is EntityKind.object
                and edge.relation
                in {
                    ResearchPredicate.graphql_references_object,
                    ResearchPredicate.graphql_modifies_object,
                    ResearchPredicate.references_same_object,
                }
                and edge.target.entity_id in objects
            }

        def objects_for_type(type_id: str) -> set[str]:
            return graph_objects_for({type_id})

        def objects_for_operation(operation: GraphQLOperationRecord) -> set[str]:
            selected_fields = operation_fields(operation)
            selected_arguments = operation_arguments(operation)
            result = {
                hint.research_object_id
                for field in selected_fields
                for hint in field.relationship_hints
                if hint.research_object_id in objects
            }
            result.update(
                argument.object_reference_semantics.research_object_id
                for argument in selected_arguments
                if argument.object_reference_semantics.kind
                is GraphQLObjectReferenceKind.research_object
                and argument.object_reference_semantics.research_object_id in objects
            )
            source_ids = {
                operation.operation_id,
                *(item.field_id for item in selected_fields),
                *(item.argument_id for item in selected_arguments),
            }
            result.update(graph_objects_for(source_ids))
            for field in selected_fields:
                owner = types.get(field.type_id)
                if owner is None:
                    continue
                returned = next(
                    (
                        item
                        for item in state.graphql_types
                        if item.graphql_surface_id == owner.graphql_surface_id
                        and item.name == field.return_type.named_type
                    ),
                    None,
                )
                if returned is not None:
                    result.update(objects_for_type(returned.type_id))
                for hint in field.relationship_hints:
                    if hint.graphql_type_id is not None:
                        result.update(objects_for_type(hint.graphql_type_id))
            return {item for item in result if item is not None}

        output: list[_Candidate] = []

        for operation in operations:
            if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                break
            semantic_surface = surfaces.get(operation.graphql_surface_id)
            if semantic_surface is None:
                continue
            op_fields = operation_fields(operation)
            op_arguments = operation_arguments(operation)
            target_id = semantic_surface.target_id
            surface_id = semantic_surface.surface_id
            identities = self._identity_references(controlled, op_fields)
            object_ids = objects_for_operation(operation)
            auth_observations = {
                observation
                for field in op_fields
                for observation in field.authorization_semantics.observations
            }
            differential = any(
                item is not GraphQLAuthorizationObservation.unknown
                for item in auth_observations
            )
            evidence = self._evidence(
                semantic_surface.evidence_references,
                operation.evidence_references,
                *(field.evidence_references for field in op_fields),
                *(
                    field.authorization_semantics.evidence_references
                    for field in op_fields
                ),
            )
            base_refs = self._references(
                EntityReference(entity_kind=EntityKind.surface, entity_id=surface_id),
                EntityReference(
                    entity_kind=EntityKind.graphql_surface,
                    entity_id=semantic_surface.graphql_surface_id,
                ),
                EntityReference(
                    entity_kind=EntityKind.graphql_operation,
                    entity_id=operation.operation_id,
                ),
                *(
                    EntityReference(
                        entity_kind=EntityKind.graphql_field,
                        entity_id=field.field_id,
                    )
                    for field in op_fields
                ),
            )

            effective_auth = operation.authentication_requirement
            if effective_auth is GraphQLAuthenticationRequirement.unknown:
                effective_auth = semantic_surface.authentication_requirement
            if (
                effective_auth
                in {
                    GraphQLAuthenticationRequirement.authenticated_observed,
                    GraphQLAuthenticationRequirement.authentication_required,
                }
                and controlled
                and not self._anonymous_behavior_known(state, surface_id, set(evidence))
            ):
                output.append(
                    _Candidate(
                        security_property=(
                            GraphQLHypothesisProperty.authentication_enforcement
                        ),
                        category="authentication_enforcement",
                        title="GraphQL authentication enforcement remains unresolved",
                        claim=(
                            "The registered GraphQL operation may not enforce the "
                            "evidenced authentication boundary for an anonymous caller."
                        ),
                        falsification=(
                            "a bounded anonymous comparison is consistently rejected "
                            "while the controlled authenticated baseline remains available."
                        ),
                        target_id=target_id,
                        surface_id=surface_id,
                        priority=self._priority(
                            72,
                            differential=differential,
                            read_only=self._read_only(operation),
                        ),
                        confidence=ResearchConfidence.medium,
                        evidence_references=evidence,
                        entity_references=self._references(
                            *base_refs,
                            *(
                                EntityReference(
                                    entity_kind=EntityKind.identity,
                                    entity_id=identity_id,
                                )
                                for identity_id in identities[:1]
                            ),
                        ),
                        missing_evidence=("anonymous comparison response",),
                        required_preconditions=(
                            "controlled-authenticated-identity",
                            "registered-graphql-operation",
                            "read-only-execution-eligibility",
                            "request-budget",
                        ),
                        operation_id=operation.operation_id,
                    )
                )

            restricted_operation = effective_auth in {
                GraphQLAuthenticationRequirement.role_bound,
                GraphQLAuthenticationRequirement.tenant_bound,
            } or GraphQLAuthorizationObservation.role_dependent_operation_behavior in (
                auth_observations
            )
            if restricted_operation:
                output.append(
                    _Candidate(
                        security_property=(
                            GraphQLHypothesisProperty.operation_level_authorization
                        ),
                        category="graphql_authorization",
                        title="GraphQL operation authorization remains unresolved",
                        claim=(
                            "The registered GraphQL operation may not consistently "
                            "enforce its evidenced restricted-operation semantics."
                        ),
                        falsification=(
                            "bounded controlled comparisons consistently enforce the "
                            "evidenced operation boundary."
                        ),
                        target_id=target_id,
                        surface_id=surface_id,
                        priority=self._priority(
                            66,
                            differential=differential,
                            read_only=self._read_only(operation),
                        ),
                        confidence=ResearchConfidence.medium,
                        evidence_references=evidence,
                        entity_references=base_refs,
                        missing_evidence=("restricted operation comparison",),
                        required_preconditions=(
                            "controlled-identities",
                            "registered-graphql-operation",
                            "request-budget",
                        ),
                        operation_id=operation.operation_id,
                    )
                )

            role_identities = tuple(
                item for item in controlled if item.role_reference is not None
            )
            distinct_roles = {item.role_reference for item in role_identities}
            role_semantics = (
                effective_auth is GraphQLAuthenticationRequirement.role_bound
                or (
                    GraphQLAuthorizationObservation.role_dependent_operation_behavior
                    in auth_observations
                )
            )
            if role_semantics and len(distinct_roles) >= 2:
                selected_roles = self._first_distinct(role_identities, "role_reference")
                role_refs = self._references(
                    *base_refs,
                    *(
                        EntityReference(
                            entity_kind=EntityKind.identity,
                            entity_id=item.identity_id,
                        )
                        for item in selected_roles
                    ),
                )
                output.append(
                    _Candidate(
                        security_property=GraphQLHypothesisProperty.role_bound_access,
                        category="vertical_authorization",
                        title="GraphQL role-bound access remains unresolved",
                        claim=(
                            "The registered GraphQL operation may not consistently "
                            "enforce the evidenced boundary between two controlled roles."
                        ),
                        falsification=(
                            "a role-B comparison consistently follows the evidenced "
                            "role policy without exposing restricted behavior."
                        ),
                        target_id=target_id,
                        surface_id=surface_id,
                        priority=self._priority(74, differential=differential),
                        confidence=ResearchConfidence.medium,
                        evidence_references=evidence,
                        entity_references=role_refs,
                        missing_evidence=("role-B comparison",),
                        required_preconditions=(
                            "controlled-identities",
                            "controlled-role-metadata",
                            "registered-graphql-operation",
                            "request-budget",
                        ),
                        operation_id=operation.operation_id,
                        object_relationship_key=tuple(
                            sorted(
                                {
                                    *(item.identity_id for item in selected_roles),
                                    *(
                                        item.role_reference
                                        for item in selected_roles
                                        if item.role_reference is not None
                                    ),
                                }
                            )
                        ),
                    )
                )

            for object_id in sorted(object_ids):
                controlled_object = objects[object_id]
                if not self._owned_object_eligible(controlled_object, controlled):
                    continue
                nonowners = tuple(
                    item
                    for item in controlled
                    if item.identity_id != controlled_object.owner_identity_id
                )
                for nonowner in nonowners[: self.limits.max_total_new_hypotheses + 1]:
                    owner_id = controlled_object.owner_identity_id
                    if owner_id is None:
                        continue
                    object_evidence = self._evidence(
                        evidence, controlled_object.evidence_references
                    )
                    object_refs = self._references(
                        *base_refs,
                        EntityReference(
                            entity_kind=EntityKind.object, entity_id=object_id
                        ),
                        EntityReference(
                            entity_kind=EntityKind.identity, entity_id=owner_id
                        ),
                        EntityReference(
                            entity_kind=EntityKind.identity,
                            entity_id=nonowner.identity_id,
                        ),
                        *(
                            EntityReference(
                                entity_kind=EntityKind.graphql_argument,
                                entity_id=argument.argument_id,
                            )
                            for argument in op_arguments
                            if argument.object_reference_semantics.research_object_id
                            == object_id
                        ),
                    )
                    output.append(
                        _Candidate(
                            security_property=(
                                GraphQLHypothesisProperty.object_authorization
                            ),
                            category="graphql_object_authorization",
                            title="GraphQL controlled-object authorization remains unresolved",
                            claim=(
                                "A controlled non-owner identity may receive the "
                                "test-owned object through the registered GraphQL access path."
                            ),
                            falsification=(
                                "the controlled non-owner comparison is denied or "
                                "owner-scoped while the owner baseline remains available."
                            ),
                            target_id=target_id,
                            surface_id=surface_id,
                            priority=self._priority(
                                74,
                                controlled_object=True,
                                differential=differential,
                                read_only=self._read_only(operation),
                            ),
                            confidence=ResearchConfidence.medium,
                            evidence_references=object_evidence,
                            entity_references=object_refs,
                            missing_evidence=(
                                "non-owner controlled comparison response",
                            ),
                            required_preconditions=(
                                "controlled-identities",
                                "test-owned-object",
                                "ownership-evidence",
                                "registered-graphql-operation",
                                "read-only-execution-eligibility",
                                "request-budget",
                            ),
                            operation_id=operation.operation_id,
                            object_relationship_key=tuple(
                                sorted((object_id, owner_id, nonowner.identity_id))
                            ),
                        )
                    )

            tenant_identities = tuple(
                item for item in controlled if item.tenant_reference is not None
            )
            distinct_tenants = {item.tenant_reference for item in tenant_identities}
            tenant_semantics = (
                effective_auth is GraphQLAuthenticationRequirement.tenant_bound
                or GraphQLAuthorizationObservation.tenant_dependent_object_access
                in auth_observations
                or any(
                    argument.semantic_role is GraphQLSemanticRole.tenant_reference
                    for argument in op_arguments
                )
            )
            if tenant_semantics and len(distinct_tenants) >= 2:
                for object_id in sorted(object_ids):
                    controlled_object = objects[object_id]
                    if not controlled_object.test_owned or (
                        controlled_object.tenant_reference is None
                    ):
                        continue
                    owner_identity = next(
                        (
                            item
                            for item in tenant_identities
                            if item.identity_id == controlled_object.owner_identity_id
                        ),
                        None,
                    )
                    if owner_identity is None or (
                        owner_identity.tenant_reference
                        != controlled_object.tenant_reference
                    ):
                        continue
                    other_tenant = next(
                        (
                            item
                            for item in tenant_identities
                            if item.tenant_reference
                            != controlled_object.tenant_reference
                        ),
                        None,
                    )
                    if other_tenant is None:
                        continue
                    output.append(
                        _Candidate(
                            security_property=(
                                GraphQLHypothesisProperty.tenant_bound_access
                            ),
                            category="tenant_isolation",
                            title="GraphQL tenant-bound access remains unresolved",
                            claim=(
                                "A controlled identity from tenant B may receive the "
                                "test-owned tenant-A object through the registered "
                                "GraphQL access path."
                            ),
                            falsification=(
                                "the tenant-B comparison is consistently denied or "
                                "tenant-scoped while the tenant-A baseline remains available."
                            ),
                            target_id=target_id,
                            surface_id=surface_id,
                            priority=self._priority(
                                76, controlled_object=True, differential=differential
                            ),
                            confidence=ResearchConfidence.medium,
                            evidence_references=self._evidence(
                                evidence, controlled_object.evidence_references
                            ),
                            entity_references=self._references(
                                *base_refs,
                                EntityReference(
                                    entity_kind=EntityKind.object,
                                    entity_id=object_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.identity,
                                    entity_id=other_tenant.identity_id,
                                ),
                            ),
                            missing_evidence=("tenant-B comparison",),
                            required_preconditions=(
                                "controlled-identities",
                                "controlled-tenant-metadata",
                                "test-owned-object",
                                "registered-graphql-operation",
                                "request-budget",
                            ),
                            operation_id=operation.operation_id,
                            object_relationship_key=tuple(
                                sorted((object_id, other_tenant.identity_id))
                            ),
                        )
                    )

            controlled_mutation_objects = tuple(
                item
                for item in sorted(object_ids)
                if self._owned_object_eligible(objects[item], controlled)
            )
            mutation_context = (
                operation.operation_type is GraphQLOperationType.mutation
                and (
                    bool(controlled_mutation_objects)
                    or (operation.workflow_id is not None and bool(controlled))
                )
            )
            if mutation_context:
                mutation_objects = controlled_mutation_objects
                workflow = next(
                    (
                        item
                        for item in state.workflows
                        if item.workflow_id == operation.workflow_id
                    ),
                    None,
                )
                mutation_evidence = self._evidence(
                    evidence,
                    *(objects[item].evidence_references for item in mutation_objects),
                    *((workflow.evidence_references,) if workflow is not None else ()),
                )
                mutation_refs = self._references(
                    *base_refs,
                    *(
                        EntityReference(
                            entity_kind=EntityKind.object, entity_id=object_id
                        )
                        for object_id in mutation_objects
                    ),
                    *(
                        (
                            EntityReference(
                                entity_kind=EntityKind.workflow,
                                entity_id=workflow.workflow_id,
                            ),
                        )
                        if workflow is not None
                        else ()
                    ),
                )
                output.append(
                    _Candidate(
                        security_property=(
                            GraphQLHypothesisProperty.mutation_authorization
                        ),
                        category="graphql_mutation_authorization",
                        title="GraphQL mutation authorization remains unresolved",
                        claim=(
                            "The registered GraphQL mutation may permit an "
                            "unauthorized state change against controlled context."
                        ),
                        falsification=(
                            "a separately authorized future mutation comparison "
                            "enforces the evidenced identity or object boundary and "
                            "cleanup restores the controlled state."
                        ),
                        target_id=target_id,
                        surface_id=surface_id,
                        priority=self._priority(
                            70,
                            controlled_object=bool(mutation_objects),
                            differential=differential,
                        ),
                        confidence=ResearchConfidence.medium,
                        evidence_references=mutation_evidence,
                        entity_references=mutation_refs,
                        missing_evidence=(
                            "mutation authorization result",
                            "cleanup capability",
                        ),
                        required_preconditions=(
                            "controlled-identity",
                            "state-change-authorization",
                            "cleanup-availability",
                            "request-budget",
                            *(("test-owned-object",) if mutation_objects else ()),
                        ),
                        operation_id=operation.operation_id,
                        object_relationship_key=tuple(mutation_objects),
                        requires_state_change=True,
                    )
                )
                if workflow is not None and any(
                    step.state_changing for step in workflow.steps
                ):
                    output.append(
                        _Candidate(
                            security_property=(
                                GraphQLHypothesisProperty.workflow_bound_mutation
                            ),
                            category="business_logic_state_enforcement",
                            title="GraphQL workflow mutation invariant remains unresolved",
                            claim=(
                                "The registered GraphQL mutation may not enforce the "
                                "evidenced controlled workflow transition boundary."
                            ),
                            falsification=(
                                "an authorized future workflow comparison preserves "
                                "the registered transition invariant and controlled cleanup."
                            ),
                            target_id=target_id,
                            surface_id=surface_id,
                            priority=self._priority(
                                68, controlled_object=bool(mutation_objects)
                            ),
                            confidence=ResearchConfidence.medium,
                            evidence_references=mutation_evidence,
                            entity_references=mutation_refs,
                            missing_evidence=(
                                "workflow mutation authorization result",
                                "cleanup capability",
                            ),
                            required_preconditions=(
                                "controlled-identity",
                                "evidenced-workflow-transition",
                                "state-change-authorization",
                                "cleanup-availability",
                                "request-budget",
                            ),
                            operation_id=operation.operation_id,
                            object_relationship_key=tuple(mutation_objects),
                            requires_state_change=True,
                        )
                    )

            for argument in op_arguments:
                if argument.semantic_role not in {
                    GraphQLSemanticRole.filter,
                    GraphQLSemanticRole.search,
                    GraphQLSemanticRole.ordering,
                    GraphQLSemanticRole.workflow_input,
                }:
                    continue
                if not argument.semantic_role_evidence_references:
                    continue
                output.append(
                    _Candidate(
                        security_property=(
                            GraphQLHypothesisProperty.argument_input_validation
                        ),
                        category="graphql_authorization",
                        title="Bounded GraphQL argument validation remains unresolved",
                        claim=(
                            "The registered GraphQL argument may not enforce its "
                            "evidenced semantic input boundary."
                        ),
                        falsification=(
                            "a bounded future comparison at the registered argument "
                            "boundary is consistently rejected or normalized according "
                            "to the evidenced contract."
                        ),
                        target_id=target_id,
                        surface_id=surface_id,
                        priority=self._priority(
                            55, read_only=self._read_only(operation)
                        ),
                        confidence=ResearchConfidence.low,
                        evidence_references=self._evidence(
                            evidence,
                            argument.evidence_references,
                            argument.semantic_role_evidence_references,
                        ),
                        entity_references=self._references(
                            *base_refs,
                            EntityReference(
                                entity_kind=EntityKind.graphql_argument,
                                entity_id=argument.argument_id,
                            ),
                        ),
                        missing_evidence=("bounded argument validation response",),
                        required_preconditions=(
                            "registered-graphql-operation",
                            "registered-graphql-argument",
                            "read-only-execution-eligibility",
                            "request-budget",
                        ),
                        operation_id=operation.operation_id,
                    )
                )

        output.extend(
            self._field_candidates(
                state, assertions, controlled, fields, types, surfaces
            )
        )
        output.extend(
            self._traversal_candidates(
                state, assertions, controlled, fields, types, surfaces, objects
            )
        )
        output.extend(
            self._cross_surface_candidates(
                state, assertions, operations, fields, types, surfaces, objects
            )
        )
        return tuple(output[:MAX_GRAPHQL_HYPOTHESIS_CANDIDATES])

    def _field_candidates(
        self,
        state: ResearchState,
        assertions: Sequence[GraphAssertion],
        controlled: Sequence[object],
        fields: dict[str, GraphQLFieldRecord],
        types: dict[str, object],
        surfaces: dict[str, object],
    ) -> tuple[_Candidate, ...]:
        output = []
        operation_by_field: dict[str, str] = {}
        for operation in state.graphql_operations:
            if isinstance(operation, GraphQLOperationRecord):
                for field_id in operation.root_field_ids:
                    operation_by_field.setdefault(field_id, operation.operation_id)
        for field in fields.values():
            if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                break
            observations = set(field.authorization_semantics.observations)
            relevant = observations & {
                GraphQLAuthorizationObservation.identity_dependent_field_visibility,
                GraphQLAuthorizationObservation.ownership_sensitive_access,
                GraphQLAuthorizationObservation.role_dependent_operation_behavior,
                GraphQLAuthorizationObservation.tenant_dependent_object_access,
            }
            if not relevant:
                continue
            owner = types.get(field.type_id)
            semantic_surface = (
                surfaces.get(owner.graphql_surface_id) if owner is not None else None
            )
            if semantic_surface is None:
                continue
            identities = self._identity_references(controlled, (field,))
            evidence = self._evidence(
                semantic_surface.evidence_references,
                field.evidence_references,
                field.authorization_semantics.evidence_references,
            )
            output.append(
                _Candidate(
                    security_property=(
                        GraphQLHypothesisProperty.field_level_authorization
                    ),
                    category="graphql_field_authorization",
                    title="GraphQL field-level authorization remains unresolved",
                    claim=(
                        "The evidenced protected GraphQL field may not consistently "
                        "enforce its identity, role, tenant, or ownership boundary."
                    ),
                    falsification=(
                        "bounded controlled comparisons consistently match the "
                        "evidenced field-availability policy."
                    ),
                    target_id=semantic_surface.target_id,
                    surface_id=semantic_surface.surface_id,
                    priority=self._priority(68, differential=True),
                    confidence=ResearchConfidence.medium,
                    evidence_references=evidence,
                    entity_references=self._references(
                        EntityReference(
                            entity_kind=EntityKind.surface,
                            entity_id=semantic_surface.surface_id,
                        ),
                        EntityReference(
                            entity_kind=EntityKind.graphql_surface,
                            entity_id=semantic_surface.graphql_surface_id,
                        ),
                        EntityReference(
                            entity_kind=EntityKind.graphql_type,
                            entity_id=field.type_id,
                        ),
                        EntityReference(
                            entity_kind=EntityKind.graphql_field,
                            entity_id=field.field_id,
                        ),
                        *(
                            (
                                EntityReference(
                                    entity_kind=EntityKind.graphql_operation,
                                    entity_id=operation_by_field[field.field_id],
                                ),
                            )
                            if field.field_id in operation_by_field
                            else ()
                        ),
                        *(
                            EntityReference(
                                entity_kind=EntityKind.identity,
                                entity_id=identity_id,
                            )
                            for identity_id in identities
                        ),
                    ),
                    missing_evidence=("field authorization boundary result",),
                    required_preconditions=(
                        "controlled-identities",
                        "registered-graphql-operation",
                        "read-only-execution-eligibility",
                        "request-budget",
                    ),
                    operation_id=operation_by_field.get(field.field_id),
                )
            )
        return tuple(output)

    def _traversal_candidates(
        self,
        state: ResearchState,
        assertions: Sequence[GraphAssertion],
        controlled: Sequence[object],
        fields: dict[str, GraphQLFieldRecord],
        types: dict[str, object],
        surfaces: dict[str, object],
        objects: dict[str, ResearchObject],
    ) -> tuple[_Candidate, ...]:
        type_objects: dict[str, set[str]] = {}
        for edge in assertions:
            if (
                edge.relation is ResearchPredicate.references_same_object
                and edge.source.entity_kind is EntityKind.graphql_type
                and edge.target.entity_kind is EntityKind.object
                and edge.status
                not in {RelationshipStatus.rejected, RelationshipStatus.superseded}
                and edge.derivation_type is DerivationType.deterministic
            ):
                type_objects.setdefault(edge.source.entity_id, set()).add(
                    edge.target.entity_id
                )
        output = []
        for field in fields.values():
            if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                break
            traversal_hints = tuple(
                item
                for item in field.relationship_hints
                if item.kind is GraphQLRelationshipKind.traverses_object
            )
            if not traversal_hints:
                continue
            parent_ids = type_objects.get(field.type_id, set())
            child_ids: set[str] = set()
            for hint in traversal_hints:
                if hint.research_object_id is not None:
                    child_ids.add(hint.research_object_id)
                if hint.graphql_type_id is not None:
                    child_ids.update(type_objects.get(hint.graphql_type_id, set()))
            owner_type = types.get(field.type_id)
            semantic_surface = (
                surfaces.get(owner_type.graphql_surface_id)
                if owner_type is not None
                else None
            )
            parent_operation = next(
                (
                    operation
                    for operation in state.graphql_operations
                    if isinstance(operation, GraphQLOperationRecord)
                    and operation.graphql_surface_id
                    == getattr(owner_type, "graphql_surface_id", None)
                    and any(
                        root_field_id == field.field_id
                        or (
                            (root_field := fields.get(root_field_id)) is not None
                            and owner_type is not None
                            and root_field.return_type.named_type == owner_type.name
                        )
                        for root_field_id in operation.root_field_ids
                    )
                ),
                None,
            )
            if semantic_surface is None or parent_operation is None:
                continue
            for parent_id in sorted(parent_ids):
                for child_id in sorted(child_ids):
                    if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                        break
                    parent = objects.get(parent_id)
                    child = objects.get(child_id)
                    if (
                        parent is None
                        or child is None
                        or parent_id == child_id
                        or not parent.test_owned
                        or not child.test_owned
                        or not self._owned_object_eligible(parent, controlled)
                        or not self._owned_object_eligible(child, controlled)
                    ):
                        continue
                    boundary = parent.owner_identity_id != child.owner_identity_id or (
                        parent.tenant_reference is not None
                        and child.tenant_reference is not None
                        and parent.tenant_reference != child.tenant_reference
                    )
                    if not boundary:
                        continue
                    output.append(
                        _Candidate(
                            security_property=(
                                GraphQLHypothesisProperty.relationship_traversal_authorization
                            ),
                            category="graphql_object_authorization",
                            title="GraphQL nested relationship authorization remains unresolved",
                            claim=(
                                "Traversal from the controlled parent object may expose "
                                "the related controlled child across an evidenced identity "
                                "or tenant boundary."
                            ),
                            falsification=(
                                "a bounded nested-resolver comparison consistently "
                                "enforces the evidenced parent-to-child boundary."
                            ),
                            target_id=semantic_surface.target_id,
                            surface_id=semantic_surface.surface_id,
                            priority=self._priority(
                                73, controlled_object=True, differential=True
                            ),
                            confidence=ResearchConfidence.medium,
                            evidence_references=self._evidence(
                                semantic_surface.evidence_references,
                                field.evidence_references,
                                parent.evidence_references,
                                child.evidence_references,
                                *(item.evidence_references for item in traversal_hints),
                            ),
                            entity_references=self._references(
                                EntityReference(
                                    entity_kind=EntityKind.surface,
                                    entity_id=semantic_surface.surface_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.graphql_type,
                                    entity_id=field.type_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.graphql_field,
                                    entity_id=field.field_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.graphql_operation,
                                    entity_id=parent_operation.operation_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.object,
                                    entity_id=parent_id,
                                ),
                                EntityReference(
                                    entity_kind=EntityKind.object,
                                    entity_id=child_id,
                                ),
                            ),
                            missing_evidence=("nested resolver runtime behavior",),
                            required_preconditions=(
                                "controlled-identities",
                                "test-owned-parent-object",
                                "test-owned-related-object",
                                "registered-graphql-operation",
                                "read-only-execution-eligibility",
                                "request-budget",
                            ),
                            object_relationship_key=tuple(
                                sorted((parent_id, child_id))
                            ),
                            operation_id=parent_operation.operation_id,
                        )
                    )
                if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                    break
        return tuple(output)

    def _cross_surface_candidates(
        self,
        state: ResearchState,
        assertions: Sequence[GraphAssertion],
        operations: Sequence[GraphQLOperationRecord],
        fields: dict[str, GraphQLFieldRecord],
        types: dict[str, object],
        surfaces: dict[str, object],
        objects: dict[str, ResearchObject],
    ) -> tuple[_Candidate, ...]:
        explicit_cross = tuple(
            item
            for item in assertions
            if item.relation
            in {
                ResearchPredicate.references_same_object,
                ResearchPredicate.crosses_surface,
            }
            and item.status
            not in {RelationshipStatus.rejected, RelationshipStatus.superseded}
            and item.derivation_type is DerivationType.deterministic
        )
        if not explicit_cross:
            return ()
        known_objects, basis_relationships, known_evidence = (
            self._known_non_graphql_authorization(state, assertions)
        )
        output = []
        for operation in operations:
            if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                break
            semantic_surface = surfaces.get(operation.graphql_surface_id)
            if semantic_surface is None:
                continue
            operation_entity_ids = {operation.operation_id, *operation.root_field_ids}
            directly_mapped_objects: set[str] = set()
            relevant_type_ids: set[str] = set()
            for field_id in operation.root_field_ids:
                field = fields.get(field_id)
                if field is None:
                    continue
                relevant_type_ids.add(field.type_id)
                operation_entity_ids.update(field.argument_ids)
                directly_mapped_objects.update(
                    hint.research_object_id
                    for hint in field.relationship_hints
                    if hint.research_object_id in objects
                )
                relevant_type_ids.update(
                    hint.graphql_type_id
                    for hint in field.relationship_hints
                    if hint.graphql_type_id is not None
                )
                owner = types.get(field.type_id)
                returned = next(
                    (
                        item
                        for item in state.graphql_types
                        if owner is not None
                        and item.graphql_surface_id == owner.graphql_surface_id
                        and item.name == field.return_type.named_type
                    ),
                    None,
                )
                if returned is not None:
                    relevant_type_ids.add(returned.type_id)
            operation_entity_ids.update(relevant_type_ids)
            mapped_objects: set[str] = set()
            cross_evidence: set[str] = set()
            for edge in explicit_cross:
                endpoint_ids = {edge.source.entity_id, edge.target.entity_id}
                object_endpoints = {
                    reference.entity_id
                    for reference in (edge.source, edge.target)
                    if reference.entity_kind is EntityKind.object
                    and reference.entity_id in objects
                }
                if object_endpoints and endpoint_ids & (
                    operation_entity_ids | directly_mapped_objects
                ):
                    mapped_objects.update(object_endpoints)
                    cross_evidence.update(edge.evidence_references)
                elif not object_endpoints and endpoint_ids & operation_entity_ids:
                    mapped_objects.update(directly_mapped_objects)
                    cross_evidence.update(edge.evidence_references)
            changed = True
            while changed:
                changed = False
                for edge in explicit_cross:
                    object_endpoints = {
                        reference.entity_id
                        for reference in (edge.source, edge.target)
                        if reference.entity_kind is EntityKind.object
                        and reference.entity_id in objects
                    }
                    if object_endpoints & mapped_objects and not (
                        object_endpoints <= mapped_objects
                    ):
                        mapped_objects.update(object_endpoints)
                        cross_evidence.update(edge.evidence_references)
                        changed = True
            for object_id in sorted(mapped_objects & known_objects):
                if len(output) >= MAX_GRAPHQL_HYPOTHESIS_CANDIDATES:
                    break
                research_object = objects[object_id]
                if not research_object.test_owned:
                    continue
                rest_surface = next(
                    (
                        item
                        for item in state.surfaces
                        if item.surface_id == research_object.surface_id
                        and item.surface_type.value != "graphql"
                    ),
                    None,
                )
                if rest_surface is None:
                    continue
                relationship_ids = tuple(
                    sorted(basis_relationships.get(object_id, set()))
                )
                output.append(
                    _Candidate(
                        security_property=(
                            GraphQLHypothesisProperty.cross_surface_authorization
                        ),
                        category="graphql_authorization",
                        title="Cross-surface GraphQL authorization remains unresolved",
                        claim=(
                            "Authorization behavior known for the controlled object on "
                            "a non-GraphQL surface may not be enforced consistently by "
                            "the explicitly mapped GraphQL operation."
                        ),
                        falsification=(
                            "a bounded GraphQL comparison matches the known non-GraphQL "
                            "authorization behavior for the same controlled object."
                        ),
                        target_id=semantic_surface.target_id,
                        surface_id=semantic_surface.surface_id,
                        priority=self._priority(
                            78, controlled_object=True, cross_surface=True
                        ),
                        confidence=ResearchConfidence.medium,
                        evidence_references=self._evidence(
                            semantic_surface.evidence_references,
                            operation.evidence_references,
                            research_object.evidence_references,
                            tuple(cross_evidence),
                            tuple(known_evidence.get(object_id, set())),
                        ),
                        entity_references=self._references(
                            EntityReference(
                                entity_kind=EntityKind.surface,
                                entity_id=semantic_surface.surface_id,
                            ),
                            EntityReference(
                                entity_kind=EntityKind.surface,
                                entity_id=rest_surface.surface_id,
                            ),
                            EntityReference(
                                entity_kind=EntityKind.graphql_operation,
                                entity_id=operation.operation_id,
                            ),
                            EntityReference(
                                entity_kind=EntityKind.object,
                                entity_id=object_id,
                            ),
                        ),
                        missing_evidence=(
                            "GraphQL cross-surface authorization comparison",
                        ),
                        required_preconditions=(
                            "explicit-cross-surface-object-mapping",
                            "known-non-graphql-authorization-behavior",
                            "test-owned-object",
                            "controlled-identities",
                            "read-only-execution-eligibility",
                            "request-budget",
                        ),
                        operation_id=operation.operation_id,
                        object_relationship_key=(object_id,),
                        basis_relationship_ids=relationship_ids,
                        cross_surface=True,
                    )
                )
        return tuple(output)

    @staticmethod
    def _known_non_graphql_authorization(
        state: ResearchState, assertions: Sequence[GraphAssertion]
    ) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
        known: set[str] = set()
        relationship_ids: dict[str, set[str]] = {}
        evidence: dict[str, set[str]] = {}
        authorization_relations = {
            ResearchPredicate.accesses,
            ResearchPredicate.controls,
            ResearchPredicate.requires,
            ResearchPredicate.tested_by,
            ResearchPredicate.supported_by,
            ResearchPredicate.refuted_by,
        }
        for item in state.relationships:
            if (
                item.predicate in authorization_relations
                and item.status
                in {RelationshipStatus.observed, RelationshipStatus.confirmed}
                and item.derivation_type is DerivationType.deterministic
            ):
                object_id = next(
                    (
                        reference.entity_id
                        for reference in (item.source, item.target)
                        if reference.entity_kind is EntityKind.object
                    ),
                    None,
                )
                if object_id is not None:
                    known.add(object_id)
                    relationship_ids.setdefault(object_id, set()).add(
                        item.relationship_id
                    )
                    evidence.setdefault(object_id, set()).update(
                        item.evidence_references
                    )
        for item in assertions:
            if (
                item.relation in authorization_relations
                and item.status
                in {RelationshipStatus.observed, RelationshipStatus.confirmed}
                and item.derivation_type is DerivationType.deterministic
            ):
                object_id = next(
                    (
                        reference.entity_id
                        for reference in (item.source, item.target)
                        if reference.entity_kind is EntityKind.object
                    ),
                    None,
                )
                if object_id is not None:
                    known.add(object_id)
                    evidence.setdefault(object_id, set()).update(
                        item.evidence_references
                    )
        for hypothesis in state.hypotheses:
            if hypothesis.status not in {
                HypothesisResearchStatus.supported,
                HypothesisResearchStatus.refuted,
            }:
                continue
            for reference in hypothesis.entity_references:
                if reference.entity_kind is EntityKind.object:
                    known.add(reference.entity_id)
                    evidence.setdefault(reference.entity_id, set()).update(
                        (*hypothesis.supporting_evidence, *hypothesis.refuting_evidence)
                    )
        return known, relationship_ids, evidence

    @staticmethod
    def _owned_object_eligible(
        value: ResearchObject, controlled: Sequence[object]
    ) -> bool:
        return bool(
            value.test_owned
            and value.owner_identity_id
            and any(item.identity_id == value.owner_identity_id for item in controlled)
        )

    @staticmethod
    def _identity_references(
        controlled: Sequence[object], fields: Sequence[GraphQLFieldRecord]
    ) -> tuple[str, ...]:
        explicit = {
            identity_id
            for field in fields
            for identity_id in field.authorization_semantics.identity_references
        }
        available = {item.identity_id for item in controlled}
        selected = explicit & available
        return tuple(sorted(selected or available))[:2]

    @staticmethod
    def _first_distinct(values: Sequence[object], attribute: str) -> tuple[object, ...]:
        selected = []
        seen = set()
        for item in sorted(values, key=lambda value: value.identity_id):
            marker = getattr(item, attribute)
            if marker in seen:
                continue
            seen.add(marker)
            selected.append(item)
            if len(selected) == 2:
                break
        return tuple(selected)

    @staticmethod
    def _read_only(operation: GraphQLOperationRecord) -> bool:
        return bool(
            operation.operation_type is GraphQLOperationType.query
            and operation.state_change_class
            in {GraphQLStateChangeClass.read_only, GraphQLStateChangeClass.unknown}
        )

    @staticmethod
    def _priority(
        base: int,
        *,
        controlled_object: bool = False,
        cross_surface: bool = False,
        differential: bool = False,
        read_only: bool = False,
    ) -> int:
        return min(
            95,
            base
            + (6 if controlled_object else 0)
            + (5 if cross_surface else 0)
            + (4 if differential else 0)
            + (3 if read_only else 0),
        )

    @staticmethod
    def _evidence(*groups: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted({item for group in groups for item in group}))[
            :MAX_GRAPHQL_HYPOTHESIS_EVIDENCE
        ]

    @staticmethod
    def _references(*values: EntityReference) -> tuple[EntityReference, ...]:
        deduplicated = {
            (item.entity_kind.value, item.entity_id): item for item in values
        }
        return tuple(deduplicated[key] for key in sorted(deduplicated))[
            :MAX_GRAPHQL_HYPOTHESIS_ENTITY_REFERENCES
        ]

    @staticmethod
    def _anonymous_behavior_known(
        state: ResearchState, surface_id: str, relevant_evidence: set[str]
    ) -> bool:
        for observation in state.observations:
            if observation.surface_id != surface_id or not (
                set(observation.evidence_references) & relevant_evidence
            ):
                continue
            if observation.observation_type == "graphql_authentication_boundary":
                return True
            if observation.observation_type != "graphql_identity_differential":
                continue
            evidence_ids = set(observation.evidence_references)
            for evidence in state.evidence:
                if evidence.evidence_id not in evidence_ids:
                    continue
                metadata = {item.key: item.value for item in evidence.metadata.entries}
                if metadata.get("left_identity") == "anonymous" or (
                    metadata.get("right_identity") == "anonymous"
                ):
                    return True
        return False

    @staticmethod
    def _secure_property_is_proven(state: ResearchState, candidate: _Candidate) -> bool:
        secure_markers = {
            GraphQLHypothesisProperty.object_authorization: {
                "ownership-authorization-enforced"
            },
            GraphQLHypothesisProperty.field_level_authorization: {
                "field-authorization-enforced"
            },
            GraphQLHypothesisProperty.operation_level_authorization: {
                "authorization-enforced"
            },
            GraphQLHypothesisProperty.authentication_enforcement: {
                "authentication-enforced"
            },
            GraphQLHypothesisProperty.role_bound_access: {
                "role-bound-authorization-enforced"
            },
            GraphQLHypothesisProperty.tenant_bound_access: {
                "tenant-bound-authorization-enforced"
            },
            GraphQLHypothesisProperty.mutation_authorization: {
                "mutation-authorization-enforced"
            },
            GraphQLHypothesisProperty.cross_surface_authorization: {
                "cross-surface-authorization-enforced"
            },
            GraphQLHypothesisProperty.relationship_traversal_authorization: {
                "nested-authorization-enforced"
            },
            GraphQLHypothesisProperty.argument_input_validation: {
                "argument-validation-enforced"
            },
            GraphQLHypothesisProperty.workflow_bound_mutation: {
                "workflow-invariant-enforced"
            },
        }
        expected_markers = secure_markers[candidate.security_property]
        entity_ids = {item.entity_id for item in candidate.entity_references}
        for fact in state.facts:
            if (
                fact.status is FactStatus.confirmed
                and fact.derivation_type is DerivationType.deterministic
                and fact.subject.entity_id in entity_ids
                and fact.predicate is ResearchPredicate.requires
                and fact.object.kind == "scalar"
                and str(fact.object.value).casefold().replace("_", "-")
                in expected_markers
            ):
                return True
        return False

    @staticmethod
    def _assertions(
        state: ResearchState,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None,
    ) -> tuple[GraphAssertion, ...]:
        if graph is None:
            return ()
        if isinstance(graph, Sequence):
            if any(not isinstance(item, GraphAssertion) for item in graph):
                raise TypeError("GraphQL hypothesis graph contains invalid assertions")
            return tuple(graph)
        if not isinstance(graph, ResearchGraphRepository):
            raise TypeError("unsupported GraphQL hypothesis graph source")
        references = (
            *(item.operation_id for item in state.graphql_operations),
            *(item.field_id for item in state.graphql_fields),
            *(item.argument_id for item in state.graphql_arguments),
            *(item.type_id for item in state.graphql_types),
            *(item.object_id for item in state.objects),
            *(item.identity_id for item in state.identities if item.controlled),
            *(item.graphql_surface_id for item in state.graphql_surfaces),
            *(item.surface_id for item in state.graphql_surfaces),
        )
        collected: dict[str, GraphAssertion] = {}
        for reference in references:
            if len(collected) >= 500:
                break
            for assertion in graph.neighbors(
                reference, limit=min(100, 500 - len(collected))
            ):
                collected[assertion.assertion_id] = assertion
        return tuple(collected[key] for key in sorted(collected))


__all__ = [
    "GRAPHQL_HYPOTHESIS_VERSION",
    "GraphQLHypothesisGenerationResult",
    "GraphQLHypothesisGenerator",
    "GraphQLHypothesisLimits",
    "GraphQLHypothesisProperty",
    "build_graphql_hypothesis_graph_assertions",
    "graphql_hypothesis_fingerprint",
]
