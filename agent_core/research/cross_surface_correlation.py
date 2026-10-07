"""Deterministic controlled-object correlation across REST and GraphQL surfaces."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from enum import Enum

from pydantic import Field, model_validator

from agent_core.research.graph import GraphAssertion
from agent_core.research.graphql import (
    GraphQLOperationRecord,
    GraphQLVariableBinding,
    GraphQLVariableValueSource,
    RegisteredGraphQLOperationTemplate,
)
from agent_core.research.graphql_readiness import (
    GraphQLObjectBindingBasis,
    RegisteredGraphQLObjectBindingEvidence,
)
from agent_core.research.state import ResearchObject, ResearchState
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    IdentityEligibility,
    RelationshipStatus,
    ResearchContract,
    ResearchPredicate,
    Sha256Digest,
    SurfaceType,
)

CROSS_SURFACE_CORRELATION_VERSION = "phase4-cross-surface-correlation-v1"


class CrossSurfaceCorrelationRejectionReason(str, Enum):
    missing_object_reference_evidence = "missing_object_reference_evidence"
    missing_ownership_evidence = "missing_ownership_evidence"
    missing_rest_parameter_relation = "missing_rest_parameter_relation"
    missing_cross_surface_relation = "missing_cross_surface_relation"
    missing_graphql_argument_link = "missing_graphql_argument_link"
    missing_graphql_variable_link = "missing_graphql_variable_link"
    ambiguous_object_reference = "ambiguous_object_reference"
    conflicting_object_reference = "conflicting_object_reference"


class CorrelatedGraphQLVariableBinding(ResearchContract):
    """One closed, value-free correlation ready for GraphQL readiness."""

    operation_id: str = Field(min_length=1, max_length=255)
    source_template_id: str = Field(min_length=1, max_length=255)
    variable_id: str = Field(min_length=1, max_length=255)
    argument_id: str = Field(min_length=1, max_length=255)
    controlled_object_id: str = Field(min_length=1, max_length=255)
    owner_identity_id: str = Field(min_length=1, max_length=255)
    object_reference_evidence_id: str = Field(min_length=1, max_length=255)
    relationship_assertion_ids: tuple[str, ...] = Field(min_length=2, max_length=20)
    evidence_references: tuple[str, ...] = Field(min_length=1, max_length=100)
    binding_fingerprint: Sha256Digest
    binding: GraphQLVariableBinding
    readiness_evidence: RegisteredGraphQLObjectBindingEvidence

    @model_validator(mode="after")
    def validate_closure(self) -> "CorrelatedGraphQLVariableBinding":
        assertions = tuple(sorted(set(self.relationship_assertion_ids)))
        evidence = tuple(sorted(set(self.evidence_references)))
        if len(assertions) != len(self.relationship_assertion_ids):
            raise ValueError("correlation relationship references must be unique")
        if len(evidence) != len(self.evidence_references):
            raise ValueError("correlation evidence references must be unique")
        if (
            self.binding.variable_id != self.variable_id
            or self.binding.argument_id != self.argument_id
            or self.binding.value_reference != self.controlled_object_id
            or self.readiness_evidence.operation_id != self.operation_id
            or self.readiness_evidence.source_template_id != self.source_template_id
            or self.readiness_evidence.binding_fingerprint != self.binding_fingerprint
        ):
            raise ValueError("correlated GraphQL binding closure is inconsistent")
        object.__setattr__(self, "relationship_assertion_ids", assertions)
        object.__setattr__(self, "evidence_references", evidence)
        return self


class CrossSurfaceCorrelationRejection(ResearchContract):
    operation_id: str = Field(min_length=1, max_length=255)
    variable_id: str | None = Field(default=None, min_length=1, max_length=255)
    argument_id: str | None = Field(default=None, min_length=1, max_length=255)
    reason: CrossSurfaceCorrelationRejectionReason


class CrossSurfaceControlledObjectCorrelationResult(ResearchContract):
    correlations: tuple[CorrelatedGraphQLVariableBinding, ...] = Field(
        default=(), max_length=2_000
    )
    rejections: tuple[CrossSurfaceCorrelationRejection, ...] = Field(
        default=(), max_length=2_000
    )
    target_requests: int = Field(default=0, ge=0, le=0)
    model_calls: int = Field(default=0, ge=0, le=0)

    @property
    def bindings(self) -> tuple[GraphQLVariableBinding, ...]:
        return tuple(item.binding for item in self.correlations)

    @property
    def readiness_evidence(self) -> tuple[RegisteredGraphQLObjectBindingEvidence, ...]:
        return tuple(item.readiness_evidence for item in self.correlations)


def _fingerprint(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _active_deterministic(assertion: GraphAssertion) -> bool:
    return (
        assertion.derivation_type is DerivationType.deterministic
        and assertion.status
        in {RelationshipStatus.observed, RelationshipStatus.confirmed}
        and bool(assertion.evidence_references)
    )


class CrossSurfaceControlledObjectCorrelator:
    """Close typed evidence chains without requests, models, or name matching."""

    def correlate(
        self,
        state: ResearchState,
        *,
        graph_assertions: Sequence[GraphAssertion],
        templates: Sequence[RegisteredGraphQLOperationTemplate],
    ) -> CrossSurfaceControlledObjectCorrelationResult:
        known_evidence = {item.evidence_id for item in state.evidence}
        known_provenance = {item.provenance_id for item in state.provenance}
        assertions = tuple(
            item
            for item in graph_assertions
            if _active_deterministic(item)
            and item.research_id == state.research_id
            and item.provenance_id in known_provenance
            and set(item.evidence_references).issubset(known_evidence)
        )
        variables = {item.variable_id: item for item in state.graphql_variables}
        arguments = {item.argument_id: item for item in state.graphql_arguments}
        parameters = {item.parameter_id: item for item in state.parameters}
        endpoints = {item.endpoint_id: item for item in state.endpoints}
        surfaces = {item.surface_id: item for item in state.surfaces}
        semantic_surfaces = {
            item.graphql_surface_id: item for item in state.graphql_surfaces
        }
        identities = {item.identity_id: item for item in state.identities}
        operations = {
            item.operation_id: item
            for item in state.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
        }
        correlations: list[CorrelatedGraphQLVariableBinding] = []
        rejections: list[CrossSurfaceCorrelationRejection] = []

        def reject(
            template: RegisteredGraphQLOperationTemplate,
            reason: CrossSurfaceCorrelationRejectionReason,
            *,
            variable_id: str | None = None,
            argument_id: str | None = None,
        ) -> None:
            rejections.append(
                CrossSurfaceCorrelationRejection(
                    operation_id=template.operation_id,
                    variable_id=variable_id,
                    argument_id=argument_id,
                    reason=reason,
                )
            )

        for template in sorted(templates, key=lambda item: item.template_id):
            operation = operations.get(template.operation_id)
            semantic_surface = (
                semantic_surfaces.get(operation.graphql_surface_id)
                if operation is not None
                else None
            )
            if operation is None or semantic_surface is None:
                reject(
                    template,
                    CrossSurfaceCorrelationRejectionReason.missing_graphql_variable_link,
                )
                continue
            for variable_id in operation.variable_ids:
                variable = variables.get(variable_id)
                if variable is None or variable.operation_id != operation.operation_id:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_graphql_variable_link,
                        variable_id=variable_id,
                    )
                    continue
                argument_id = variable.linked_argument_id
                argument = arguments.get(str(argument_id)) if argument_id else None
                if (
                    argument is None
                    or argument.input_type != variable.input_type
                    or argument.argument_id
                    not in {
                        argument_id
                        for field_id in operation.root_field_ids
                        if (
                            field := next(
                                (
                                    candidate
                                    for candidate in state.graphql_fields
                                    if candidate.field_id == field_id
                                ),
                                None,
                            )
                        )
                        is not None
                        for argument_id in field.argument_ids
                    }
                ):
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_graphql_argument_link,
                        variable_id=variable.variable_id,
                        argument_id=argument_id,
                    )
                    continue
                variable_links = tuple(
                    item
                    for item in assertions
                    if item.source.entity_kind is EntityKind.graphql_variable
                    and item.source.entity_id == variable.variable_id
                    and item.relation
                    is ResearchPredicate.graphql_variable_binds_argument
                    and item.target.entity_kind is EntityKind.graphql_argument
                    and item.target.entity_id == argument.argument_id
                )
                if not variable_links:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_graphql_variable_link,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue
                cross_links = tuple(
                    item
                    for item in assertions
                    if item.source.entity_kind is EntityKind.graphql_argument
                    and item.source.entity_id == argument.argument_id
                    and item.relation is ResearchPredicate.crosses_surface
                    and item.target.entity_kind is EntityKind.parameter
                    and item.target.entity_id == argument.parameter_id
                )
                if not cross_links:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_cross_surface_relation,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue

                owned = tuple(
                    item
                    for item in state.objects
                    if self._owned_object(item, identities, known_evidence)
                )
                if not owned:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_ownership_evidence,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue
                if not any(item.reference_evidence for item in owned):
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_object_reference_evidence,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue

                rest_links = tuple(
                    item
                    for item in cross_links
                    if self._rest_parameter_surface(
                        item.target.entity_id,
                        parameters,
                        endpoints,
                        surfaces,
                        semantic_surface.surface_id,
                    )
                    is not None
                )
                if not rest_links:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_rest_parameter_relation,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue

                matches: list[tuple[ResearchObject, object, GraphAssertion]] = []
                for cross_link in rest_links:
                    parameter_id = cross_link.target.entity_id
                    parameter = parameters[parameter_id]
                    parameter_evidence = set(parameter.evidence_references)
                    for controlled_object in owned:
                        for reference in controlled_object.reference_evidence:
                            if (
                                reference.parameter_id == parameter_id
                                and reference.source_surface_id
                                == controlled_object.surface_id
                                and parameter_evidence.issubset(
                                    set(reference.evidence_references)
                                )
                            ):
                                matches.append(
                                    (controlled_object, reference, cross_link)
                                )
                if not matches:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_object_reference_evidence,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue

                fingerprints_by_object: dict[str, set[str]] = {}
                for controlled_object, reference, _ in matches:
                    fingerprints_by_object.setdefault(
                        controlled_object.object_id, set()
                    ).add(reference.value_fingerprint)
                if any(len(values) > 1 for values in fingerprints_by_object.values()):
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.conflicting_object_reference,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue
                if len(fingerprints_by_object) > 1:
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.ambiguous_object_reference,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue

                controlled_object, reference, cross_link = sorted(
                    matches,
                    key=lambda item: (
                        item[0].object_id,
                        item[1].reference_evidence_id,
                        item[2].assertion_id,
                    ),
                )[0]
                owner_identity_id = str(controlled_object.owner_identity_id)
                variable_link = sorted(
                    variable_links, key=lambda item: item.assertion_id
                )[0]
                assertion_ids = tuple(
                    sorted((variable_link.assertion_id, cross_link.assertion_id))
                )
                evidence = tuple(
                    sorted(
                        {
                            *template.evidence_references,
                            *operation.evidence_references,
                            *variable.evidence_references,
                            *argument.evidence_references,
                            *controlled_object.evidence_references,
                            *reference.evidence_references,
                            *variable_link.evidence_references,
                            *cross_link.evidence_references,
                        }
                    )
                )
                if not set(evidence).issubset(known_evidence):
                    reject(
                        template,
                        CrossSurfaceCorrelationRejectionReason.missing_object_reference_evidence,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                    )
                    continue
                binding_fingerprint = _fingerprint(
                    {
                        "version": CROSS_SURFACE_CORRELATION_VERSION,
                        "operation_id": operation.operation_id,
                        "variable_id": variable.variable_id,
                        "argument_id": argument.argument_id,
                        "controlled_object_id": controlled_object.object_id,
                        "owner_identity_id": owner_identity_id,
                        "object_reference_evidence_id": (
                            reference.reference_evidence_id
                        ),
                        "value_fingerprint": reference.value_fingerprint,
                        "relationship_assertion_ids": assertion_ids,
                        "evidence_references": evidence,
                    }
                )
                binding = GraphQLVariableBinding(
                    variable_id=variable.variable_id,
                    argument_id=argument.argument_id,
                    value_source=GraphQLVariableValueSource.controlled_object,
                    value_reference=controlled_object.object_id,
                )
                readiness_evidence = RegisteredGraphQLObjectBindingEvidence(
                    operation_id=operation.operation_id,
                    variable_id=variable.variable_id,
                    argument_id=argument.argument_id,
                    controlled_object_id=controlled_object.object_id,
                    binding_basis=(
                        GraphQLObjectBindingBasis.explicit_cross_surface_relationship
                    ),
                    evidence_references=evidence,
                    owner_identity_id=owner_identity_id,
                    source_template_id=template.template_id,
                    object_reference_evidence_id=reference.reference_evidence_id,
                    relationship_assertion_ids=assertion_ids,
                    binding_fingerprint=binding_fingerprint,
                )
                correlations.append(
                    CorrelatedGraphQLVariableBinding(
                        operation_id=operation.operation_id,
                        source_template_id=template.template_id,
                        variable_id=variable.variable_id,
                        argument_id=argument.argument_id,
                        controlled_object_id=controlled_object.object_id,
                        owner_identity_id=owner_identity_id,
                        object_reference_evidence_id=(reference.reference_evidence_id),
                        relationship_assertion_ids=assertion_ids,
                        evidence_references=evidence,
                        binding_fingerprint=binding_fingerprint,
                        binding=binding,
                        readiness_evidence=readiness_evidence,
                    )
                )

        unique = {item.binding_fingerprint: item for item in correlations}

        def rejection_key(item: CrossSurfaceCorrelationRejection) -> tuple[str, ...]:
            return (
                item.operation_id,
                item.variable_id or "",
                item.argument_id or "",
                item.reason.value,
            )

        return CrossSurfaceControlledObjectCorrelationResult(
            correlations=tuple(unique[key] for key in sorted(unique)),
            rejections=tuple(sorted(set(rejections), key=rejection_key)),
        )

    @staticmethod
    def _owned_object(
        controlled_object: ResearchObject,
        identities: dict[str, object],
        known_evidence: set[str],
    ) -> bool:
        owner = identities.get(str(controlled_object.owner_identity_id))
        return bool(
            controlled_object.test_owned
            and controlled_object.owner_identity_id is not None
            and controlled_object.evidence_references
            and set(controlled_object.evidence_references).issubset(known_evidence)
            and owner is not None
            and getattr(owner, "controlled", False)
            and getattr(owner, "eligibility", None) is IdentityEligibility.eligible
        )

    @staticmethod
    def _rest_parameter_surface(
        parameter_id: str,
        parameters: dict[str, object],
        endpoints: dict[str, object],
        surfaces: dict[str, object],
        graphql_surface_id: str,
    ) -> str | None:
        parameter = parameters.get(parameter_id)
        endpoint = (
            endpoints.get(getattr(parameter, "endpoint_id", ""))
            if parameter is not None
            else None
        )
        surface = (
            surfaces.get(getattr(endpoint, "surface_id", ""))
            if endpoint is not None
            else None
        )
        if (
            surface is None
            or surface.surface_id == graphql_surface_id
            or surface.surface_type is not SurfaceType.rest
        ):
            return None
        return surface.surface_id


__all__ = [
    "CROSS_SURFACE_CORRELATION_VERSION",
    "CorrelatedGraphQLVariableBinding",
    "CrossSurfaceControlledObjectCorrelationResult",
    "CrossSurfaceControlledObjectCorrelator",
    "CrossSurfaceCorrelationRejection",
    "CrossSurfaceCorrelationRejectionReason",
]
