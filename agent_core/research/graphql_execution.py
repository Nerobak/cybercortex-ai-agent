"""Bounded trusted materialization for registered GraphQL experiments.

This module has no transport dependency.  It turns persisted GraphQL semantic
records and compiler-approved bindings into one canonical document and a
sealed, process-local request.  Raw GraphQL text is never an input.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from pydantic import Field, StrictInt

from agent_core.research.graphql import (
    MAX_GRAPHQL_ARGUMENTS_PER_FIELD,
    MAX_GRAPHQL_DOCUMENT_BYTES,
    MAX_GRAPHQL_SELECTION_DEPTH,
    MAX_GRAPHQL_SELECTION_NODES,
    MAX_GRAPHQL_VARIABLES_PER_OPERATION,
    GraphQLExperimentStateChangeClass,
    GraphQLOperationRecord,
    GraphQLReturnShape,
    GraphQLTypeKind,
    GraphQLTypeReference,
    GraphQLTypeWrapper,
    GraphQLVariableBinding,
    GraphQLVariableRecord,
    GraphQLVariableValueSource,
    RegisteredGraphQLOperationTemplate,
)
from agent_core.research.types import GraphQLOperationType, ResearchContract


GRAPHQL_EXECUTION_VERSION = "phase4-graphql-execution-v1"
MAX_GRAPHQL_EXECUTION_RESPONSE_BYTES = 262_144
MAX_GRAPHQL_EXECUTION_ERRORS = 32


class GraphQLExecutionError(ValueError):
    """A public-safe failure before a GraphQL target request is sent."""


class GraphQLExecutionLimits(ResearchContract):
    max_document_bytes: StrictInt = Field(
        default=MAX_GRAPHQL_DOCUMENT_BYTES, ge=256, le=MAX_GRAPHQL_DOCUMENT_BYTES
    )
    max_selection_depth: StrictInt = Field(
        default=8, ge=1, le=MAX_GRAPHQL_SELECTION_DEPTH
    )
    max_selection_nodes: StrictInt = Field(
        default=256, ge=1, le=MAX_GRAPHQL_SELECTION_NODES
    )
    max_variables: StrictInt = Field(
        default=32, ge=0, le=MAX_GRAPHQL_VARIABLES_PER_OPERATION
    )
    max_arguments: StrictInt = Field(
        default=64, ge=0, le=MAX_GRAPHQL_ARGUMENTS_PER_FIELD
    )
    max_operations: Literal[1] = 1
    max_response_bytes: StrictInt = Field(
        default=MAX_GRAPHQL_EXECUTION_RESPONSE_BYTES,
        ge=1_024,
        le=MAX_GRAPHQL_EXECUTION_RESPONSE_BYTES,
    )
    max_errors: StrictInt = Field(default=MAX_GRAPHQL_EXECUTION_ERRORS, ge=1, le=100)
    timeout_seconds: StrictInt = Field(default=10, ge=1, le=30)


@dataclass(frozen=True, slots=True)
class GraphQLRenderedDocument:
    document: str
    document_digest: str
    operation_name: str
    variable_names: tuple[str, ...]
    selected_field_ids: tuple[str, ...]
    selected_field_names: tuple[str, ...]


_REQUEST_ISSUER = object()


class GraphQLExecutionRequest:
    """One non-serializable, process-local GraphQL send capability.

    Construction requires the module-private issuer.  The object deliberately
    has no model-dump or dictionary conversion API and its repr omits the
    document and variables.
    """

    __slots__ = (
        "__document",
        "__document_digest",
        "__endpoint_id",
        "__expected_state_change_class",
        "__identity_id",
        "__issuer",
        "__method",
        "__object_ids",
        "__operation_id",
        "__operation_name",
        "__operation_template_id",
        "__purpose",
        "__response_byte_limit",
        "__runtime_provenance_reference",
        "__selected_field_ids",
        "__selected_field_names",
        "__surface_id",
        "__target_id",
        "__timeout_seconds",
        "__url",
        "__variables",
    )

    def __init__(
        self,
        *,
        issuer: object,
        target_id: str,
        surface_id: str,
        endpoint_id: str,
        operation_template_id: str,
        operation_id: str,
        method: str,
        url: str,
        document: str,
        document_digest: str,
        variables: Mapping[str, Any],
        operation_name: str,
        identity_id: str | None,
        object_ids: tuple[str, ...],
        selected_field_ids: tuple[str, ...],
        selected_field_names: tuple[str, ...],
        expected_state_change_class: GraphQLExperimentStateChangeClass,
        response_byte_limit: int,
        timeout_seconds: int,
        purpose: Literal["graphql_execution", "state_mutation"],
        runtime_provenance_reference: str,
    ) -> None:
        if issuer is not _REQUEST_ISSUER:
            raise TypeError("GraphQL execution request construction is restricted")
        if method != "POST":
            raise GraphQLExecutionError("registered GraphQL method is unavailable")
        if _digest_text(document) != document_digest:
            raise GraphQLExecutionError("GraphQL document digest mismatch")
        object.__setattr__(self, "_GraphQLExecutionRequest__issuer", issuer)
        for name, value in (
            ("target_id", target_id),
            ("surface_id", surface_id),
            ("endpoint_id", endpoint_id),
            ("operation_template_id", operation_template_id),
            ("operation_id", operation_id),
            ("method", method),
            ("url", url),
            ("document", document),
            ("document_digest", document_digest),
            ("operation_name", operation_name),
            ("identity_id", identity_id),
            ("object_ids", object_ids),
            ("selected_field_ids", selected_field_ids),
            ("selected_field_names", selected_field_names),
            ("expected_state_change_class", expected_state_change_class),
            ("response_byte_limit", response_byte_limit),
            ("timeout_seconds", timeout_seconds),
            ("purpose", purpose),
            ("runtime_provenance_reference", runtime_provenance_reference),
        ):
            object.__setattr__(self, f"_GraphQLExecutionRequest__{name}", value)
        object.__setattr__(
            self,
            "_GraphQLExecutionRequest__variables",
            MappingProxyType(dict(variables)),
        )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("GraphQLExecutionRequest cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("GraphQLExecutionRequest is immutable")

    def __repr__(self) -> str:
        return (
            "GraphQLExecutionRequest("
            f"operation_id={self.__operation_id!r}, endpoint_id={self.__endpoint_id!r}, "
            f"identity_id={self.__identity_id!r}, variables=[REDACTED], "
            "document=[REDACTED])"
        )

    @property
    def target_id(self) -> str:
        return self.__target_id

    @property
    def surface_id(self) -> str:
        return self.__surface_id

    @property
    def endpoint_id(self) -> str:
        return self.__endpoint_id

    @property
    def operation_template_id(self) -> str:
        return self.__operation_template_id

    @property
    def operation_id(self) -> str:
        return self.__operation_id

    @property
    def method(self) -> str:
        return self.__method

    @property
    def url(self) -> str:
        return self.__url

    @property
    def document(self) -> str:
        return self.__document

    @property
    def document_digest(self) -> str:
        return self.__document_digest

    @property
    def variables(self) -> Mapping[str, Any]:
        return self.__variables

    @property
    def operation_name(self) -> str:
        return self.__operation_name

    @property
    def identity_id(self) -> str | None:
        return self.__identity_id

    @property
    def object_ids(self) -> tuple[str, ...]:
        return self.__object_ids

    @property
    def selected_field_ids(self) -> tuple[str, ...]:
        return self.__selected_field_ids

    @property
    def selected_field_names(self) -> tuple[str, ...]:
        return self.__selected_field_names

    @property
    def expected_state_change_class(self) -> GraphQLExperimentStateChangeClass:
        return self.__expected_state_change_class

    @property
    def response_byte_limit(self) -> int:
        return self.__response_byte_limit

    @property
    def timeout_seconds(self) -> int:
        return self.__timeout_seconds

    @property
    def purpose(self) -> Literal["graphql_execution", "state_mutation"]:
        return self.__purpose

    @property
    def runtime_provenance_reference(self) -> str:
        return self.__runtime_provenance_reference

    def _is_trusted(self) -> bool:
        return self.__issuer is _REQUEST_ISSUER

    def __reduce__(self) -> None:
        raise TypeError("GraphQLExecutionRequest cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("GraphQLExecutionRequest cannot be serialized")


class GraphQLDocumentRenderer:
    """Render exactly one registered operation from semantic IDs."""

    def __init__(self, state: Any, limits: GraphQLExecutionLimits | None = None):
        self.state = state
        self.limits = limits or GraphQLExecutionLimits()

    def render(
        self,
        template: RegisteredGraphQLOperationTemplate,
        *,
        variable_bindings: Sequence[GraphQLVariableBinding] | None = None,
        selected_field_ids: Sequence[str] = (),
    ) -> GraphQLRenderedDocument:
        operation = _exactly_one(
            self.state.graphql_operations, "operation_id", template.operation_id
        )
        if not isinstance(operation, GraphQLOperationRecord):
            raise GraphQLExecutionError("registered GraphQL operation is unavailable")
        if (
            operation.graphql_surface_id != template.graphql_surface_id
            or operation.operation_type is not template.operation_type
            or operation.selection_fingerprint != template.selection_fingerprint
            or operation.operation_name is None
            or operation.operation_type is GraphQLOperationType.subscription
        ):
            raise GraphQLExecutionError("registered GraphQL operation changed")

        fields = {item.field_id: item for item in self.state.graphql_fields}
        variables = {
            item.variable_id: item
            for item in self.state.graphql_variables
            if item.operation_id == operation.operation_id
        }
        arguments = {item.argument_id: item for item in self.state.graphql_arguments}
        types = {item.type_id: item for item in self.state.graphql_types}
        type_names = {
            (item.graphql_surface_id, item.name): item
            for item in self.state.graphql_types
        }

        paths = template.normalized_structure.selection_paths
        node_count = sum(len(item.field_ids) for item in paths)
        depth = max(len(item.field_ids) for item in paths)
        if (
            depth > self.limits.max_selection_depth
            or node_count > self.limits.max_selection_nodes
        ):
            raise GraphQLExecutionError("GraphQL selection bound exceeded")
        registered_field_ids = {
            field_id for path in paths for field_id in path.field_ids
        }
        if not set(selected_field_ids).issubset(registered_field_ids):
            raise GraphQLExecutionError("GraphQL selected field is not registered")

        tree: dict[str, dict[str, Any]] = {}
        root_types = [
            item
            for item in types.values()
            if item.graphql_surface_id == template.graphql_surface_id
            and item.root_role is not None
            and item.root_role.value == template.operation_type.value
        ]
        if len(root_types) != 1:
            raise GraphQLExecutionError("GraphQL root type is unavailable")
        root_type = root_types[0]
        for path in paths:
            branch = tree
            expected_type = root_type
            for position, field_id in enumerate(path.field_ids):
                field = fields.get(field_id)
                if field is None or field.type_id != expected_type.type_id:
                    raise GraphQLExecutionError("GraphQL selection path changed")
                if position == 0 and field_id not in operation.root_field_ids:
                    raise GraphQLExecutionError("GraphQL root selection changed")
                branch = branch.setdefault(field_id, {})
                if position + 1 < len(path.field_ids):
                    expected_type = type_names.get(
                        (template.graphql_surface_id, field.return_type.named_type)
                    )
                    if expected_type is None:
                        raise GraphQLExecutionError(
                            "GraphQL nested type is unavailable"
                        )

        active_bindings = tuple(
            variable_bindings
            if variable_bindings is not None
            else template.variable_bindings
        )
        if len(active_bindings) > self.limits.max_variables:
            raise GraphQLExecutionError("GraphQL variable bound exceeded")
        binding_pairs = {
            (item.argument_id, item.variable_id) for item in active_bindings
        }
        if len(binding_pairs) != len(active_bindings) or not binding_pairs.issubset(
            {
                (item.argument_id, item.variable_id)
                for item in template.argument_bindings
            }
        ):
            raise GraphQLExecutionError("GraphQL variable binding is not registered")
        bound_by_argument = {item.argument_id: item for item in active_bindings}
        bound_variables: dict[str, GraphQLVariableRecord] = {}
        argument_count = 0
        for argument_id, binding in bound_by_argument.items():
            argument = arguments.get(argument_id)
            variable = variables.get(binding.variable_id)
            if (
                argument is None
                or variable is None
                or argument.input_type != variable.input_type
                or variable.linked_argument_id != argument.argument_id
            ):
                raise GraphQLExecutionError("GraphQL variable semantics changed")
            bound_variables[variable.variable_id] = variable
            argument_count += 1
        if argument_count > self.limits.max_arguments:
            raise GraphQLExecutionError("GraphQL argument bound exceeded")

        for field_id in registered_field_ids:
            field = fields[field_id]
            for argument_id in field.argument_ids:
                argument = arguments.get(argument_id)
                if argument is None:
                    raise GraphQLExecutionError("GraphQL argument is unavailable")
                if (
                    not argument.nullable
                    and not argument.default_presence
                    and argument_id not in bound_by_argument
                ):
                    raise GraphQLExecutionError(
                        "required GraphQL argument lacks an approved binding"
                    )

        def render_field(field_id: str, children: dict[str, Any]) -> str:
            field = fields[field_id]
            rendered_arguments = []
            for argument_id in field.argument_ids:
                binding = bound_by_argument.get(argument_id)
                if binding is None:
                    continue
                argument = arguments[argument_id]
                variable = variables[binding.variable_id]
                rendered_arguments.append(f"{argument.name}:${variable.name}")
            suffix = (
                "(" + ",".join(sorted(rendered_arguments)) + ")"
                if rendered_arguments
                else ""
            )
            nested = [render_field(key, value) for key, value in children.items()]
            nested.sort()
            if not nested and field.return_shape in {
                GraphQLReturnShape.object,
                GraphQLReturnShape.interface,
                GraphQLReturnShape.union,
            }:
                nested = ["__typename"]
            if nested:
                suffix += "{" + " ".join(nested) + "}"
            return field.name + suffix

        declarations = sorted(
            f"${item.name}:{item.input_type.to_syntax()}"
            for item in bound_variables.values()
        )
        declaration_text = "(" + ",".join(declarations) + ")" if declarations else ""
        selections = sorted(render_field(key, value) for key, value in tree.items())
        document = (
            f"{operation.operation_type.value} {operation.operation_name}"
            f"{declaration_text}{{{' '.join(selections)}}}"
        )
        if len(document.encode("utf-8")) > self.limits.max_document_bytes:
            raise GraphQLExecutionError("GraphQL document byte bound exceeded")
        selected = tuple(sorted(registered_field_ids))
        return GraphQLRenderedDocument(
            document=document,
            document_digest=_digest_text(document),
            operation_name=operation.operation_name,
            variable_names=tuple(
                sorted(item.name for item in bound_variables.values())
            ),
            selected_field_ids=selected,
            selected_field_names=tuple(sorted(fields[item].name for item in selected)),
        )


def materialize_graphql_variables(
    state: Any,
    template: RegisteredGraphQLOperationTemplate,
    bindings: Sequence[GraphQLVariableBinding],
    *,
    object_references: Mapping[str, str],
    identity_bindings: Mapping[str, object],
    controlled_values: Mapping[str, object],
    vault_references: Sequence[str] = (),
    limits: GraphQLExecutionLimits | None = None,
) -> Mapping[str, Any]:
    """Resolve approved references into bounded values at the send boundary."""

    selected_limits = limits or GraphQLExecutionLimits()
    if len(bindings) > selected_limits.max_variables:
        raise GraphQLExecutionError("GraphQL variable bound exceeded")
    variables = {
        item.variable_id: item
        for item in state.graphql_variables
        if item.operation_id == template.operation_id
    }
    registered_pairs = {
        (item.argument_id, item.variable_id) for item in template.argument_bindings
    }
    output: dict[str, Any] = {}
    for binding in bindings:
        if (binding.argument_id, binding.variable_id) not in registered_pairs:
            raise GraphQLExecutionError("GraphQL variable binding is not registered")
        variable = variables.get(binding.variable_id)
        if variable is None:
            raise GraphQLExecutionError("GraphQL variable semantics changed")
        if binding.value_source is GraphQLVariableValueSource.controlled_object:
            try:
                value = object_references[binding.value_reference]
            except KeyError as exc:
                raise GraphQLExecutionError(
                    "controlled GraphQL object reference is unavailable"
                ) from exc
        elif binding.value_source is GraphQLVariableValueSource.controlled_identity:
            identity = identity_bindings.get(binding.value_reference)
            value = getattr(identity, "account_reference", None)
            if identity is None or value is None:
                raise GraphQLExecutionError(
                    "controlled GraphQL identity reference is unavailable"
                )
        elif binding.value_source in {
            GraphQLVariableValueSource.registered_safe_constant,
            GraphQLVariableValueSource.registered_pagination_bound,
            GraphQLVariableValueSource.registered_workflow_value,
            GraphQLVariableValueSource.opaque_controlled_value,
        }:
            registration = controlled_values.get(binding.value_reference)
            if registration is None:
                raise GraphQLExecutionError("registered GraphQL value is unavailable")
            value = getattr(registration, "value", None)
        else:  # pragma: no cover - enum exhaustiveness guard
            raise GraphQLExecutionError("GraphQL variable source is prohibited")
        if isinstance(value, str) and value in set(vault_references):
            raise GraphQLExecutionError("credential references cannot be variables")
        _validate_graphql_value(value, variable.input_type, state)
        if variable.name in output:
            raise GraphQLExecutionError("GraphQL variable binding is duplicated")
        output[variable.name] = _plain_value(value)
    return MappingProxyType(dict(sorted(output.items())))


def create_graphql_execution_request(
    *,
    target_id: str,
    surface_id: str,
    endpoint_id: str,
    operation_template_id: str,
    operation_id: str,
    method: str,
    url: str,
    rendered: GraphQLRenderedDocument,
    variables: Mapping[str, Any],
    identity_id: str | None,
    object_ids: tuple[str, ...],
    expected_state_change_class: GraphQLExperimentStateChangeClass,
    response_byte_limit: int,
    timeout_seconds: int,
    purpose: Literal["graphql_execution", "state_mutation"],
    runtime_provenance_reference: str,
) -> GraphQLExecutionRequest:
    return GraphQLExecutionRequest(
        issuer=_REQUEST_ISSUER,
        target_id=target_id,
        surface_id=surface_id,
        endpoint_id=endpoint_id,
        operation_template_id=operation_template_id,
        operation_id=operation_id,
        method=method,
        url=url,
        document=rendered.document,
        document_digest=rendered.document_digest,
        variables=variables,
        operation_name=rendered.operation_name,
        identity_id=identity_id,
        object_ids=object_ids,
        selected_field_ids=rendered.selected_field_ids,
        selected_field_names=rendered.selected_field_names,
        expected_state_change_class=expected_state_change_class,
        response_byte_limit=response_byte_limit,
        timeout_seconds=timeout_seconds,
        purpose=purpose,
        runtime_provenance_reference=runtime_provenance_reference,
    )


def _validate_graphql_value(
    value: Any, reference: GraphQLTypeReference, state: Any
) -> None:
    wrappers = reference.wrappers

    def validate(item: Any, index: int) -> None:
        if index >= 0:
            wrapper = wrappers[index]
            if wrapper is GraphQLTypeWrapper.non_null:
                if item is None:
                    raise GraphQLExecutionError("non-null GraphQL variable is null")
                validate(item, index - 1)
                return
            if item is None:
                return
            if not isinstance(item, (list, tuple)) or len(item) > 100:
                raise GraphQLExecutionError("GraphQL list variable shape is invalid")
            for child in item:
                validate(child, index - 1)
            return
        if item is None:
            return
        name = reference.named_type
        valid = (
            (name == "Int" and type(item) is int and -(2**31) <= item < 2**31)
            or (name == "Float" and type(item) in {int, float})
            or (name == "Boolean" and type(item) is bool)
            or (name == "String" and isinstance(item, str))
            or (name == "ID" and (isinstance(item, str) or type(item) is int))
        )
        if name not in {"Int", "Float", "Boolean", "String", "ID"}:
            matches = [entry for entry in state.graphql_types if entry.name == name]
            if len(matches) != 1:
                raise GraphQLExecutionError("GraphQL variable type is unresolved")
            kind = matches[0].kind
            valid = (
                isinstance(item, str)
                if kind in {GraphQLTypeKind.scalar, GraphQLTypeKind.enum}
                else False
            )
        if not valid:
            raise GraphQLExecutionError("GraphQL variable type validation failed")

    validate(value, len(wrappers) - 1)


def _plain_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_plain_value(item) for item in value]
    if isinstance(value, list):
        return [_plain_value(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise GraphQLExecutionError("GraphQL variable value class is prohibited")


def _exactly_one(values: Sequence[Any], attribute: str, expected: str) -> Any:
    matches = [item for item in values if getattr(item, attribute, None) == expected]
    if len(matches) != 1:
        raise GraphQLExecutionError("registered GraphQL semantic record is unavailable")
    return matches[0]


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def graphql_execution_semantics_digest(
    state: Any, template: RegisteredGraphQLOperationTemplate
) -> str:
    """Fingerprint all state records that can affect rendering or validation."""

    field_ids = {
        field_id
        for path in template.normalized_structure.selection_paths
        for field_id in path.field_ids
    }
    argument_ids = {item.argument_id for item in template.argument_bindings} | {
        argument_id
        for item in state.graphql_fields
        if item.field_id in field_ids
        for argument_id in item.argument_ids
    }
    variable_ids = {item.variable_id for item in template.argument_bindings}
    payload = {
        "template": template.model_dump(mode="json"),
        "operation": [
            item.model_dump(mode="json")
            for item in state.graphql_operations
            if item.operation_id == template.operation_id
        ],
        "fields": [
            item.model_dump(mode="json")
            for item in state.graphql_fields
            if item.field_id in field_ids
        ],
        "arguments": [
            item.model_dump(mode="json")
            for item in state.graphql_arguments
            if item.argument_id in argument_ids
        ],
        "variables": [
            item.model_dump(mode="json")
            for item in state.graphql_variables
            if item.variable_id in variable_ids
            or item.operation_id == template.operation_id
        ],
        "types": [
            item.model_dump(mode="json")
            for item in state.graphql_types
            if item.graphql_surface_id == template.graphql_surface_id
        ],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "GRAPHQL_EXECUTION_VERSION",
    "MAX_GRAPHQL_EXECUTION_ERRORS",
    "MAX_GRAPHQL_EXECUTION_RESPONSE_BYTES",
    "GraphQLDocumentRenderer",
    "GraphQLExecutionError",
    "GraphQLExecutionLimits",
    "GraphQLExecutionRequest",
    "GraphQLRenderedDocument",
    "create_graphql_execution_request",
    "graphql_execution_semantics_digest",
    "materialize_graphql_variables",
]
