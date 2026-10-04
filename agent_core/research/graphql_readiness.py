"""Deterministic GraphQL candidate-readiness from controlled evidence.

Schema fields alone are not executable operations.  This module creates a
registered read-only operation only when an introspected query field, one
owner-controlled object, and its configured identifier semantics match
unambiguously.  It never accepts a raw object value or model-authored document.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from agent_core.research.adapters import digest_for, stable_research_identifier
from agent_core.research.graphql import (
    GraphQLAuthenticationRequirement,
    GraphQLObjectReferenceKind,
    GraphQLObjectReferenceSemantics,
    GraphQLOperationRecord,
    GraphQLOperationType,
    GraphQLRootRole,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    GraphQLTypeKind,
    GraphQLVariableRecord,
)
from agent_core.research.graphql_candidates import (
    build_registered_graphql_operation_template,
)
from agent_core.research.state import ProvenanceRecord, ResearchState
from agent_core.research.types import ProvenanceProducerType, ResearchConfidence

GRAPHQL_READINESS_VERSION = "phase4-graphql-readiness-v1"


@dataclass(frozen=True)
class ControlledObjectDescriptor:
    """Safe configured semantics for one already-imported research object."""

    object_type: str
    identifier_field: str


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
) -> tuple[ResearchState, tuple[str, ...]]:
    """Derive bounded operations only from unambiguous controlled evidence."""

    if not state.graphql_surfaces:
        return state, ()
    if candidate_ready_graphql_operation_templates(state):
        return _with_readiness_diagnostic(
            state, "graphql_readiness_operation_ready"
        ), ()
    if not descriptors:
        code = (
            "graphql_readiness_missing_controlled_object"
            if not state.objects
            else "graphql_readiness_missing_controlled_object_descriptor"
        )
        return _with_readiness_diagnostic(state, code), (code,)

    type_by_surface_name = {
        (item.graphql_surface_id, item.name): item for item in state.graphql_types
    }
    fields = {item.field_id: item for item in state.graphql_fields}
    arguments = {item.argument_id: item for item in state.graphql_arguments}
    objects = {
        item.object_id: item
        for item in state.objects
        if item.test_owned and item.owner_identity_id and item.evidence_references
    }
    surfaces = {item.graphql_surface_id: item for item in state.graphql_surfaces}
    existing_roots = {
        (item.graphql_surface_id, root_id)
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
        for root_id in item.root_field_ids
    }

    derived_operations: list[GraphQLOperationRecord] = []
    derived_variables: list[GraphQLVariableRecord] = []
    updated_arguments = dict(arguments)
    provenance_records = {item.provenance_id: item for item in state.provenance}

    for graphql_surface_id, surface in sorted(surfaces.items()):
        query_roots = tuple(
            item
            for item in state.graphql_types
            if item.graphql_surface_id == graphql_surface_id
            and item.root_role is GraphQLRootRole.query
        )
        for query_root in query_roots:
            for field_id in query_root.field_ids:
                root_field = fields.get(field_id)
                if (
                    root_field is None
                    or (graphql_surface_id, field_id) in existing_roots
                ):
                    continue
                returned = type_by_surface_name.get(
                    (graphql_surface_id, root_field.return_type.named_type)
                )
                if returned is None or returned.kind is not GraphQLTypeKind.object:
                    continue
                scalar_children = tuple(
                    child
                    for child_id in returned.field_ids
                    if (child := fields.get(child_id)) is not None
                    and not child.argument_ids
                    and (
                        (
                            child_type := type_by_surface_name.get(
                                (graphql_surface_id, child.return_type.named_type)
                            )
                        )
                        is None
                        or child_type.kind
                        in {GraphQLTypeKind.scalar, GraphQLTypeKind.enum}
                    )
                )
                if not scalar_children:
                    continue

                matches: list[tuple[object, ControlledObjectDescriptor, object]] = []
                for object_id, descriptor in sorted(descriptors.items()):
                    controlled_object = objects.get(object_id)
                    if controlled_object is None or not _type_matches(
                        descriptor.object_type, root_field.name, returned.name
                    ):
                        continue
                    candidate_arguments = tuple(
                        argument
                        for argument_id in root_field.argument_ids
                        if (argument := arguments.get(argument_id)) is not None
                        and _identifier_argument_matches(
                            argument.name,
                            argument.semantic_role,
                            argument.input_type.named_type,
                            argument.list_depth,
                            descriptor.identifier_field,
                            descriptor.object_type,
                            root_field.name,
                        )
                    )
                    if len(candidate_arguments) == 1:
                        matches.append(
                            (controlled_object, descriptor, candidate_arguments[0])
                        )
                if not matches:
                    continue
                # Multiple owner-controlled instances do not make the operation
                # structure ambiguous.  Register the stable first binding; later
                # candidates may substitute only separately registered objects.
                controlled_object, _descriptor, argument = sorted(
                    matches, key=lambda item: item[0].object_id
                )[0]
                evidence = tuple(
                    sorted(
                        {
                            *surface.evidence_references,
                            *root_field.evidence_references,
                            *argument.evidence_references,
                            *controlled_object.evidence_references,
                            *(
                                reference
                                for child in scalar_children
                                for reference in child.evidence_references
                            ),
                        }
                    )
                )
                if not evidence:
                    continue
                provenance_id = stable_research_identifier(
                    "provenance",
                    state.research_id,
                    graphql_surface_id,
                    field_id,
                    controlled_object.object_id,
                    "graphql-readiness",
                )
                provenance_records.setdefault(
                    provenance_id,
                    ProvenanceRecord(
                        provenance_id=provenance_id,
                        producer_type=ProvenanceProducerType.deterministic,
                        producer_name="graphql-candidate-readiness",
                        producer_version=GRAPHQL_READINESS_VERSION,
                        source_references=evidence,
                        summary=(
                            "Derived one bounded read-only GraphQL operation from "
                            "introspected schema and test-owned object evidence."
                        ),
                        occurred_at=occurred_at,
                    ),
                )
                operation_id = stable_research_identifier(
                    "graphql-operation",
                    graphql_surface_id,
                    field_id,
                    argument.argument_id,
                    controlled_object.object_id,
                )
                variable_id = stable_research_identifier(
                    "graphql-variable", operation_id, argument.name
                )
                selection_fingerprint = digest_for(
                    {
                        "operation_type": "query",
                        "root_field_id": field_id,
                        "argument_id": argument.argument_id,
                        "variable_type": argument.input_type.to_syntax(),
                        "selected_child_field_ids": sorted(
                            child.field_id for child in scalar_children[:2]
                        ),
                    }
                )
                operation_name = _operation_name(root_field.name)
                derived_operations.append(
                    GraphQLOperationRecord(
                        operation_id=operation_id,
                        graphql_surface_id=graphql_surface_id,
                        operation_type=GraphQLOperationType.query,
                        operation_name=operation_name,
                        root_field_ids=(field_id,),
                        variable_ids=(variable_id,),
                        selection_fingerprint=selection_fingerprint,
                        authentication_requirement=(
                            surface.authentication_requirement
                            if surface.authentication_requirement
                            is not GraphQLAuthenticationRequirement.unknown
                            else GraphQLAuthenticationRequirement.authenticated_observed
                        ),
                        state_change_class=GraphQLStateChangeClass.read_only,
                        evidence_references=evidence,
                        provenance_id=provenance_id,
                    )
                )
                derived_variables.append(
                    GraphQLVariableRecord(
                        variable_id=variable_id,
                        operation_id=operation_id,
                        name=argument.name,
                        input_type=argument.input_type,
                        nullable=argument.nullable,
                        list_depth=argument.list_depth,
                        semantic_role=argument.semantic_role,
                        semantic_role_evidence_references=(
                            argument.semantic_role_evidence_references
                            or argument.evidence_references
                        ),
                        linked_argument_id=argument.argument_id,
                        controlled_value_reference=controlled_object.object_id,
                        evidence_references=evidence,
                        provenance_id=provenance_id,
                    )
                )
                updated_arguments[argument.argument_id] = argument.model_copy(
                    update={
                        "semantic_role": GraphQLSemanticRole.object_reference,
                        "semantic_role_evidence_references": evidence,
                        "object_reference_semantics": GraphQLObjectReferenceSemantics(
                            kind=GraphQLObjectReferenceKind.research_object,
                            graphql_type_id=returned.type_id,
                            research_object_id=controlled_object.object_id,
                            confidence=ResearchConfidence.high,
                        ),
                        "evidence_references": evidence,
                        "provenance_id": provenance_id,
                    }
                )

    if not derived_operations:
        if not state.graphql_types or not state.graphql_fields:
            code = "graphql_readiness_missing_schema_semantics"
        elif not objects:
            code = "graphql_readiness_missing_ownership_evidence"
        else:
            code = "graphql_readiness_missing_registered_operation_evidence"
        return _with_readiness_diagnostic(state, code), (code,)

    operations = {
        item.operation_id: item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    }
    operations.update({item.operation_id: item for item in derived_operations})
    variables = {item.variable_id: item for item in state.graphql_variables}
    variables.update({item.variable_id: item for item in derived_variables})
    payload = state.model_dump(mode="python")
    payload.update(
        graphql_arguments=tuple(
            updated_arguments[key] for key in sorted(updated_arguments)
        ),
        graphql_operations=tuple(operations[key] for key in sorted(operations)),
        graphql_variables=tuple(variables[key] for key in sorted(variables)),
        provenance=tuple(provenance_records[key] for key in sorted(provenance_records)),
    )
    ready = ResearchState.model_validate(payload)
    code = (
        "graphql_readiness_operation_ready"
        if candidate_ready_graphql_operation_templates(ready)
        else "graphql_readiness_missing_operation_template"
    )
    ready = _with_readiness_diagnostic(ready, code)
    return ready, (() if code == "graphql_readiness_operation_ready" else (code,))


def candidate_ready_graphql_operation_templates(state: ResearchState):
    """Build executable typed templates without retaining GraphQL source text."""

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
        if paths:
            templates.append(
                build_registered_graphql_operation_template(
                    state, operation.operation_id, selection_paths=paths
                )
            )
    return tuple(sorted(templates, key=lambda item: item.template_id))


def _semantic_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _singular(value: str) -> str:
    return value[:-1] if value.endswith("s") and len(value) > 1 else value


def _type_matches(object_type: str, field_name: str, return_type: str) -> bool:
    expected = _singular(_semantic_key(object_type))
    return bool(expected) and expected in {
        _singular(_semantic_key(field_name)),
        _singular(_semantic_key(return_type)),
    }


def _identifier_argument_matches(
    argument_name: str,
    semantic_role: GraphQLSemanticRole,
    input_type_name: str,
    list_depth: int,
    identifier_field: str,
    object_type: str,
    root_field_name: str,
) -> bool:
    if list_depth != 0 or input_type_name not in {"ID", "String"}:
        return False
    if semantic_role not in {
        GraphQLSemanticRole.identifier,
        GraphQLSemanticRole.object_reference,
    }:
        return False
    name = _semantic_key(argument_name)
    configured = _semantic_key(identifier_field)
    object_key = _singular(_semantic_key(object_type))
    field_key = _singular(_semantic_key(root_field_name))
    allowed = {
        configured,
        object_key + configured,
        field_key + configured,
        object_key + "id",
        object_key + "ref",
        field_key + "id",
        field_key + "ref",
    }
    return bool(name) and name in allowed


def _operation_name(field_name: str) -> str:
    suffix = "".join(
        part[:1].upper() + part[1:] for part in re.findall(r"[A-Za-z0-9]+", field_name)
    )
    return ("CyberCortexRead" + suffix)[:255]


__all__ = [
    "ControlledObjectDescriptor",
    "GRAPHQL_READINESS_VERSION",
    "candidate_ready_graphql_operation_templates",
    "derive_candidate_ready_graphql_operations",
]
