"""Registered-operation GraphQL readiness from authorized observed evidence.

Schema semantics are descriptive and never become executable operations here.
Only operations already present in canonical state may become templates, and
controlled-object bindings require an exact typed evidence record.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from pydantic import Field, model_validator

from agent_core.research.adapters import stable_research_identifier
from agent_core.research.graphql import (
    GraphQLObjectReferenceKind,
    GraphQLObjectReferenceSemantics,
    GraphQLOperationRecord,
    GraphQLSemanticRole,
    GraphQLTypeKind,
)
from agent_core.research.graphql_candidates import (
    build_registered_graphql_operation_template,
)
from agent_core.research.state import ProvenanceRecord, ResearchState
from agent_core.research.types import (
    IdentityEligibility,
    ProvenanceProducerType,
    ResearchConfidence,
    ResearchContract,
)

GRAPHQL_READINESS_VERSION = "phase4-graphql-readiness-v2"


@dataclass(frozen=True)
class ControlledObjectDescriptor:
    """Safe configured semantics for one already-imported research object."""

    object_type: str
    identifier_field: str


class GraphQLObjectBindingBasis(str, Enum):
    """Closed, deterministic sources allowed to bind an operation to an object."""

    captured_variable_object_relationship = "captured_variable_object_relationship"
    registered_graphql_acquisition = "registered_graphql_acquisition"
    typed_object_relationship = "typed_object_relationship"
    explicit_cross_surface_relationship = "explicit_cross_surface_relationship"


class RegisteredGraphQLObjectBindingEvidence(ResearchContract):
    """Exact reference-only proof for one controlled GraphQL variable binding."""

    operation_id: str = Field(min_length=1, max_length=255)
    variable_id: str = Field(min_length=1, max_length=255)
    argument_id: str = Field(min_length=1, max_length=255)
    controlled_object_id: str = Field(min_length=1, max_length=255)
    binding_basis: GraphQLObjectBindingBasis
    evidence_references: tuple[str, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "RegisteredGraphQLObjectBindingEvidence":
        references = tuple(sorted(set(self.evidence_references)))
        if len(references) != len(self.evidence_references):
            raise ValueError("GraphQL binding evidence must not contain duplicates")
        object.__setattr__(self, "evidence_references", references)
        return self


_READINESS_DIAGNOSTIC_PREFIX = "graphql_readiness_"


def _with_readiness_diagnostic(state: ResearchState, code: str) -> ResearchState:
    diagnostic_codes = {
        item
        for item in state.diagnostic_codes
        if not item.startswith(_READINESS_DIAGNOSTIC_PREFIX)
    }
    diagnostic_codes.add(code)
    return state.model_copy(
        update={"diagnostic_codes": tuple(sorted(diagnostic_codes))}
    )


def derive_candidate_ready_graphql_operations(
    state: ResearchState,
    descriptors: Mapping[str, ControlledObjectDescriptor],
    *,
    occurred_at: str,
    binding_evidence: Sequence[RegisteredGraphQLObjectBindingEvidence] = (),
) -> tuple[ResearchState, tuple[str, ...]]:
    """Validate registered operations and apply only exact object bindings.

    ``descriptors`` remains part of the bootstrap interface because it records
    safe controlled-context configuration. It is deliberately insufficient to
    create an operation or object binding by itself.
    """

    del descriptors
    if not state.graphql_surfaces:
        return state, ()
    operations = {
        item.operation_id: item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    }
    if not operations:
        code = "graphql_readiness_missing_registered_operation_evidence"
        return _with_readiness_diagnostic(state, code), (code,)

    current = _apply_object_bindings(
        state,
        operations=operations,
        bindings=binding_evidence,
        occurred_at=occurred_at,
    )
    code = (
        "graphql_readiness_operation_ready"
        if candidate_ready_graphql_operation_templates(current)
        else "graphql_readiness_missing_operation_template"
    )
    current = _with_readiness_diagnostic(current, code)
    return current, (() if code == "graphql_readiness_operation_ready" else (code,))


def _apply_object_bindings(
    state: ResearchState,
    *,
    operations: Mapping[str, GraphQLOperationRecord],
    bindings: Sequence[RegisteredGraphQLObjectBindingEvidence],
    occurred_at: str,
) -> ResearchState:
    if not bindings:
        return state
    variables = {item.variable_id: item for item in state.graphql_variables}
    arguments = {item.argument_id: item for item in state.graphql_arguments}
    fields = {item.field_id: item for item in state.graphql_fields}
    objects = {item.object_id: item for item in state.objects}
    identities = {item.identity_id: item for item in state.identities}
    surfaces = {item.graphql_surface_id: item for item in state.graphql_surfaces}
    known_evidence = {item.evidence_id for item in state.evidence}
    provenance = {item.provenance_id: item for item in state.provenance}

    for binding in sorted(
        bindings,
        key=lambda item: (
            item.operation_id,
            item.variable_id,
            item.argument_id,
            item.controlled_object_id,
        ),
    ):
        operation = operations.get(binding.operation_id)
        variable = variables.get(binding.variable_id)
        argument = arguments.get(binding.argument_id)
        controlled_object = objects.get(binding.controlled_object_id)
        if operation is None or variable is None or argument is None:
            continue
        operation_argument_ids = {
            argument_id
            for field_id in operation.root_field_ids
            if (field := fields.get(field_id)) is not None
            for argument_id in field.argument_ids
        }
        if (
            variable.operation_id != operation.operation_id
            or variable.variable_id not in operation.variable_ids
            or variable.linked_argument_id != argument.argument_id
            or argument.argument_id not in operation_argument_ids
            or variable.input_type != argument.input_type
            or not set(binding.evidence_references).issubset(known_evidence)
        ):
            continue
        owner = (
            identities.get(controlled_object.owner_identity_id)
            if controlled_object is not None
            and controlled_object.owner_identity_id is not None
            else None
        )
        if (
            controlled_object is None
            or not controlled_object.test_owned
            or not controlled_object.evidence_references
            or owner is None
            or not owner.controlled
            or owner.eligibility is not IdentityEligibility.eligible
        ):
            continue
        semantic_surface = surfaces.get(operation.graphql_surface_id)
        if (
            semantic_surface is None
            or controlled_object.target_id != semantic_surface.target_id
        ):
            continue
        cross_surface = controlled_object.surface_id != semantic_surface.surface_id
        if cross_surface and binding.binding_basis is not (
            GraphQLObjectBindingBasis.explicit_cross_surface_relationship
        ):
            continue

        evidence = tuple(
            sorted(
                {
                    *operation.evidence_references,
                    *variable.evidence_references,
                    *argument.evidence_references,
                    *controlled_object.evidence_references,
                    *binding.evidence_references,
                }
            )
        )
        provenance_id = stable_research_identifier(
            "provenance",
            state.research_id,
            operation.operation_id,
            variable.variable_id,
            argument.argument_id,
            controlled_object.object_id,
            binding.binding_basis.value,
        )
        provenance.setdefault(
            provenance_id,
            ProvenanceRecord(
                provenance_id=provenance_id,
                producer_type=ProvenanceProducerType.deterministic,
                producer_name="graphql-registered-operation-binding",
                producer_version=GRAPHQL_READINESS_VERSION,
                source_references=evidence,
                summary=(
                    "Bound an exact registered GraphQL variable and argument to "
                    "an existing owner-controlled object using typed evidence."
                ),
                occurred_at=occurred_at,
            ),
        )
        variables[variable.variable_id] = variable.model_copy(
            update={
                "semantic_role": GraphQLSemanticRole.object_reference,
                "semantic_role_evidence_references": evidence,
                "controlled_value_reference": controlled_object.object_id,
                "evidence_references": evidence,
                "provenance_id": provenance_id,
            }
        )
        arguments[argument.argument_id] = argument.model_copy(
            update={
                "semantic_role": GraphQLSemanticRole.object_reference,
                "semantic_role_evidence_references": evidence,
                "object_reference_semantics": GraphQLObjectReferenceSemantics(
                    kind=GraphQLObjectReferenceKind.research_object,
                    research_object_id=controlled_object.object_id,
                    confidence=ResearchConfidence.high,
                ),
                "evidence_references": evidence,
                "provenance_id": provenance_id,
            }
        )

    payload = state.model_dump(mode="python")
    payload.update(
        graphql_arguments=tuple(arguments[key] for key in sorted(arguments)),
        graphql_variables=tuple(variables[key] for key in sorted(variables)),
        provenance=tuple(provenance[key] for key in sorted(provenance)),
    )
    return ResearchState.model_validate(payload)


def candidate_ready_graphql_operation_templates(state: ResearchState):
    """Build immutable templates only from previously registered operations."""

    fields = {item.field_id: item for item in state.graphql_fields}
    type_by_surface_name = {
        (item.graphql_surface_id, item.name): item for item in state.graphql_types
    }
    templates = []
    for operation in state.graphql_operations:
        if not isinstance(operation, GraphQLOperationRecord):
            continue
        paths: list[tuple[str, ...]] = []
        for root_id in operation.root_field_ids:
            root = fields.get(root_id)
            if root is None:
                continue
            returned = type_by_surface_name.get(
                (operation.graphql_surface_id, root.return_type.named_type)
            )
            if returned is None:
                paths.append((root_id,))
                continue
            scalar_children = [
                fields[field_id]
                for field_id in returned.field_ids
                if field_id in fields
                and not fields[field_id].argument_ids
                and (
                    (
                        child_type := type_by_surface_name.get(
                            (
                                operation.graphql_surface_id,
                                fields[field_id].return_type.named_type,
                            )
                        )
                    )
                    is None
                    or child_type.kind in {GraphQLTypeKind.scalar, GraphQLTypeKind.enum}
                )
            ]
            paths.extend(
                (root_id, child.field_id)
                for child in sorted(scalar_children, key=lambda item: item.name)[:2]
            )
            if not scalar_children:
                paths.append((root_id,))
        if paths:
            templates.append(
                build_registered_graphql_operation_template(
                    state, operation.operation_id, selection_paths=paths
                )
            )
    return tuple(sorted(templates, key=lambda item: item.template_id))


__all__ = [
    "ControlledObjectDescriptor",
    "GRAPHQL_READINESS_VERSION",
    "GraphQLObjectBindingBasis",
    "RegisteredGraphQLObjectBindingEvidence",
    "candidate_ready_graphql_operation_templates",
    "derive_candidate_ready_graphql_operations",
]
