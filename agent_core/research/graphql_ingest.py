"""Bounded, secret-safe GraphQL parsing and semantic acquisition.

The parser in this module is deliberately execution neutral.  It retains only
GraphQL names, type structure, aliases, variable bindings, and normalized
selection relationships.  Literal values and response values never enter the
durable research model.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from agent_core.research.adapters import (
    digest_for,
    opaque_reference,
    stable_research_identifier,
)
from agent_core.research.graph import GraphAssertion
from agent_core.research.graphql import (
    MAX_GRAPHQL_ARGUMENTS,
    MAX_GRAPHQL_ARGUMENTS_PER_FIELD,
    MAX_GRAPHQL_DOCUMENT_BYTES,
    MAX_GRAPHQL_FIELDS,
    MAX_GRAPHQL_FIELDS_PER_TYPE,
    MAX_GRAPHQL_OPERATIONS,
    MAX_GRAPHQL_POSSIBLE_TYPES,
    MAX_GRAPHQL_SELECTION_DEPTH,
    MAX_GRAPHQL_SELECTION_NODES,
    MAX_GRAPHQL_TYPES,
    MAX_GRAPHQL_TYPES_PER_SURFACE,
    MAX_GRAPHQL_VARIABLES,
    MAX_GRAPHQL_VARIABLES_PER_OPERATION,
    GraphQLArgumentRecord,
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLAuthorizationSemantics,
    GraphQLFieldRecord,
    GraphQLErrorClass,
    GraphQLLimitExceeded,
    GraphQLOperationRecord,
    GraphQLReturnShape,
    GraphQLResponseEnvelope,
    GraphQLRootRole,
    GraphQLSchemaState,
    GraphQLSemanticConflict,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    GraphQLSurface,
    GraphQLTransport,
    GraphQLTypeKind,
    GraphQLTypeRecord,
    GraphQLTypeReference,
    GraphQLVariableRecord,
    _merge_semantic_record,
    build_graphql_graph_assertions,
    graphql_semantic_id,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import (
    Endpoint,
    EvidenceArtifact,
    Observation,
    Parameter,
    ProvenanceRecord,
    ResearchObject,
    ResearchState,
    Surface,
)
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceKind,
    GraphQLOperationType,
    HttpMethod,
    MetadataEntry,
    ParameterLocation,
    ProvenanceProducerType,
    PublicMetadata,
    RelationshipStatus,
    ResearchContract,
    ResearchPredicate,
    SurfaceType,
)

GRAPHQL_INGEST_VERSION = "phase4-graphql-ingest-v1"
MAX_GRAPHQL_TOKENS = 4_096
MAX_GRAPHQL_FRAGMENTS = 64
MAX_GRAPHQL_FRAGMENT_SPREAD_DEPTH = 8
MAX_GRAPHQL_RESPONSE_SHAPE_NODES = 1_024
MAX_GRAPHQL_RESPONSE_DEPTH = 12
MAX_GRAPHQL_RESPONSE_TYPENAMES = 128
MAX_GRAPHQL_RESPONSE_ERRORS = 100
DEFAULT_GRAPHQL_RESPONSE_ERROR_LIMIT = 32
MAX_GRAPHQL_RESPONSE_BYTES = 262_144


class GraphQLDocumentError(ValueError):
    """A document was malformed or exceeded a deterministic parser bound."""


class ParsedGraphQLArgument(ResearchContract):
    name: StrictStr = Field(min_length=1, max_length=255)
    variable_name: StrictStr | None = Field(default=None, min_length=1, max_length=255)


class ParsedGraphQLVariable(ResearchContract):
    name: StrictStr = Field(min_length=1, max_length=255)
    input_type: GraphQLTypeReference
    default_present: StrictBool = False


class ParsedGraphQLSelection(ResearchContract):
    field_name: StrictStr = Field(min_length=1, max_length=255)
    response_alias: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    arguments: tuple[ParsedGraphQLArgument, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_ARGUMENTS_PER_FIELD
    )
    type_condition: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    children: tuple["ParsedGraphQLSelection", ...] = Field(
        default=(), max_length=MAX_GRAPHQL_SELECTION_NODES
    )


class ParsedGraphQLOperation(ResearchContract):
    operation_type: GraphQLOperationType
    operation_name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    variables: tuple[ParsedGraphQLVariable, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_VARIABLES_PER_OPERATION
    )
    selections: tuple[ParsedGraphQLSelection, ...] = Field(
        min_length=1, max_length=MAX_GRAPHQL_SELECTION_NODES
    )
    selection_fingerprint: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @property
    def root_fields(self) -> tuple[str, ...]:
        return tuple(sorted({item.field_name for item in self.selections}))


class ParsedGraphQLDocument(ResearchContract):
    document_digest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    operations: tuple[ParsedGraphQLOperation, ...] = Field(
        min_length=1, max_length=MAX_GRAPHQL_OPERATIONS
    )
    fragment_count: StrictInt = Field(ge=0, le=MAX_GRAPHQL_FRAGMENTS)
    token_count: StrictInt = Field(ge=1, le=MAX_GRAPHQL_TOKENS)


class GraphQLErrorPathObservation(ResearchContract):
    """One safe error-path association retained from a GraphQL response."""

    path: tuple[StrictStr | StrictInt, ...] = Field(min_length=1, max_length=32)
    error_class: GraphQLErrorClass

    @model_validator(mode="after")
    def validate_path(self) -> "GraphQLErrorPathObservation":
        if any(
            (type(component) is int and component < 0)
            or (
                isinstance(component, str)
                and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", component) is None
            )
            for component in self.path
        ):
            raise ValueError("GraphQL error paths must contain safe path components")
        return self


class GraphQLResponseObservation(ResearchContract):
    envelope: GraphQLResponseEnvelope
    data_present: StrictBool = False
    errors_present: StrictBool = False
    error_classes: tuple[GraphQLErrorClass, ...] = Field(default=(), max_length=16)
    error_paths: tuple[GraphQLErrorPathObservation, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_RESPONSE_ERRORS
    )
    typename_observations: tuple[StrictStr, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_RESPONSE_TYPENAMES
    )
    object_shape: tuple[StrictStr, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_RESPONSE_SHAPE_NODES
    )
    null_paths: tuple[StrictStr, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_RESPONSE_SHAPE_NODES
    )
    evidence_digest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    response_bytes: StrictInt = Field(ge=0, le=MAX_GRAPHQL_RESPONSE_BYTES)
    truncated: StrictBool = False

    @property
    def is_graphql(self) -> bool:
        return self.envelope in {
            GraphQLResponseEnvelope.graphql_data,
            GraphQLResponseEnvelope.graphql_errors,
            GraphQLResponseEnvelope.graphql_data_and_errors,
        }


class GraphQLControlledObjectEvidence(ResearchContract):
    identity_id: StrictStr = Field(min_length=1, max_length=255)
    object_type: StrictStr = Field(min_length=1, max_length=255)
    object_reference: StrictStr = Field(min_length=1, max_length=255)
    ownership_basis: StrictStr = Field(
        pattern=(
            r"^(?:owner_scoped_authenticated_response|"
            r"authoritative_controlled_fixture)$"
        )
    )
    graphql_type_name: StrictStr | None = Field(
        default=None, min_length=1, max_length=255
    )
    existing_object_id: StrictStr | None = Field(
        default=None, min_length=1, max_length=255
    )
    evidence_reference: StrictStr = Field(min_length=1, max_length=255)


class GraphQLTraceEvent(ResearchContract):
    event_type: StrictStr = Field(
        pattern=(
            r"^GRAPHQL_(?:SURFACE|PROTOCOL|CAPTURE|INTROSPECTION|"
            r"SEMANTIC_UPDATE|OBJECT|CROSS_SURFACE)$"
        )
    )
    subject_reference: StrictStr = Field(min_length=1, max_length=255)
    evidence_references: tuple[StrictStr, ...] = Field(min_length=1, max_length=100)


_LEXER = re.compile(
    r"""(?:[\s,]+|\#[^\r\n]*)
    |(?P<spread>\.\.\.)
    |(?P<block>\"\"\"(?:.|\n|\r)*?\"\"\")
    |(?P<string>\"(?:\\.|[^\"\\])*\")
    |(?P<number>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
    |(?P<name>[_A-Za-z][_0-9A-Za-z]*)
    |(?P<punct>[!$():=@\[\]{}|&])""",
    re.VERBOSE,
)


class _Token(ResearchContract):
    kind: StrictStr
    value: StrictStr


def _lex(document: str, *, max_tokens: int) -> list[_Token]:
    encoded = document.encode("utf-8")
    if len(encoded) > MAX_GRAPHQL_DOCUMENT_BYTES:
        raise GraphQLLimitExceeded("GraphQL document byte limit exceeded")
    output: list[_Token] = []
    position = 0
    while position < len(document):
        match = _LEXER.match(document, position)
        if match is None:
            raise GraphQLDocumentError("unsupported GraphQL document syntax")
        position = match.end()
        if match.lastgroup is None:
            continue
        output.append(_Token(kind=match.lastgroup, value=match.group(0)))
        if len(output) > max_tokens:
            raise GraphQLLimitExceeded("GraphQL token limit exceeded")
    if not output:
        raise GraphQLDocumentError("GraphQL document is empty")
    return output


class _FieldNode:
    __slots__ = ("name", "alias", "arguments", "type_condition", "children")

    def __init__(
        self,
        name: str,
        *,
        alias: str | None = None,
        arguments: tuple[ParsedGraphQLArgument, ...] = (),
        type_condition: str | None = None,
        children: Sequence["_FieldNode | _SpreadNode"] = (),
    ) -> None:
        self.name = name
        self.alias = alias
        self.arguments = arguments
        self.type_condition = type_condition
        self.children = tuple(children)


class _SpreadNode:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class _Parser:
    def __init__(
        self,
        tokens: list[_Token],
        *,
        max_nodes: int,
        max_depth: int,
        max_fragments: int,
        max_fragment_spread_depth: int,
    ) -> None:
        self.tokens = tokens
        self.index = 0
        self.nodes = 0
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.max_fragments = max_fragments
        self.max_fragment_spread_depth = max_fragment_spread_depth
        self.expanded_nodes = 0
        self.fragments: dict[str, tuple[str, tuple[_FieldNode | _SpreadNode, ...]]] = {}
        self.operations: list[
            tuple[
                GraphQLOperationType,
                str | None,
                tuple[ParsedGraphQLVariable, ...],
                tuple[_FieldNode | _SpreadNode, ...],
            ]
        ] = []

    def peek(self, value: str | None = None) -> _Token | bool | None:
        token = self.tokens[self.index] if self.index < len(self.tokens) else None
        return token if value is None else bool(token and token.value == value)

    def pop(self, value: str | None = None) -> _Token:
        token = self.peek()
        if not isinstance(token, _Token):
            raise GraphQLDocumentError("unexpected end of GraphQL document")
        if value is not None and token.value != value:
            raise GraphQLDocumentError("malformed GraphQL document")
        self.index += 1
        return token

    def name(self) -> str:
        token = self.pop()
        if token.kind != "name":
            raise GraphQLDocumentError("expected a GraphQL name")
        return token.value

    def parse(self) -> None:
        while self.index < len(self.tokens):
            if self.peek("fragment"):
                self._fragment()
            else:
                self._operation()
        if not self.operations:
            raise GraphQLDocumentError("GraphQL document contains no operation")
        self._validate_fragment_graph()
        names = [item[1] for item in self.operations if item[1] is not None]
        if len(names) != len(set(names)):
            raise GraphQLDocumentError("duplicate GraphQL operation name")
        if len(self.operations) > 1 and any(
            item[1] is None for item in self.operations
        ):
            raise GraphQLDocumentError(
                "anonymous GraphQL operation cannot share a document"
            )

    def _validate_fragment_graph(self) -> None:
        """Reject cycles, missing spreads, and over-deep chains in every fragment."""

        validated: set[str] = set()

        def visit_nodes(
            nodes: Sequence[_FieldNode | _SpreadNode], stack: tuple[str, ...]
        ) -> None:
            for node in nodes:
                if isinstance(node, _SpreadNode):
                    visit_fragment(node.name, stack)
                else:
                    visit_nodes(node.children, stack)

        def visit_fragment(name: str, stack: tuple[str, ...]) -> None:
            if name in stack:
                raise GraphQLDocumentError("cyclic GraphQL fragment spread")
            if len(stack) >= self.max_fragment_spread_depth:
                raise GraphQLLimitExceeded(
                    "GraphQL fragment-spread depth limit exceeded"
                )
            fragment = self.fragments.get(name)
            if fragment is None:
                raise GraphQLDocumentError("undefined GraphQL fragment spread")
            if name in validated:
                return
            visit_nodes(fragment[1], (*stack, name))
            validated.add(name)

        for fragment_name in sorted(self.fragments):
            visit_fragment(fragment_name, ())

    def _operation(self) -> None:
        operation_type = GraphQLOperationType.query
        operation_name: str | None = None
        variables: tuple[ParsedGraphQLVariable, ...] = ()
        if not self.peek("{"):
            raw_type = self.name()
            try:
                operation_type = GraphQLOperationType(raw_type)
            except ValueError as exc:
                raise GraphQLDocumentError("unsupported GraphQL definition") from exc
            if not self.peek("(") and not self.peek("{") and not self.peek("@"):
                operation_name = self.name()
            if self.peek("("):
                variables = self._variables()
            self._directives()
        selections = self._selection_set(1)
        self.operations.append((operation_type, operation_name, variables, selections))

    def _fragment(self) -> None:
        self.pop("fragment")
        if len(self.fragments) >= self.max_fragments:
            raise GraphQLLimitExceeded("GraphQL fragment count limit exceeded")
        name = self.name()
        self.pop("on")
        type_condition = self.name()
        self._directives()
        if name in self.fragments:
            raise GraphQLDocumentError("duplicate GraphQL fragment definition")
        self.fragments[name] = (type_condition, self._selection_set(1))

    def _variables(self) -> tuple[ParsedGraphQLVariable, ...]:
        self.pop("(")
        output: list[ParsedGraphQLVariable] = []
        names: set[str] = set()
        while not self.peek(")"):
            self.pop("$")
            name = self.name()
            if name in names:
                raise GraphQLDocumentError("duplicate GraphQL variable")
            names.add(name)
            self.pop(":")
            syntax = self._type_reference()
            default_present = False
            if self.peek("="):
                self.pop("=")
                self._value(0)
                default_present = True
            self._directives()
            output.append(
                ParsedGraphQLVariable(
                    name=name,
                    input_type=GraphQLTypeReference.from_syntax(
                        syntax, unresolved_external=True
                    ),
                    default_present=default_present,
                )
            )
            if len(output) > MAX_GRAPHQL_VARIABLES_PER_OPERATION:
                raise GraphQLLimitExceeded("GraphQL variable limit exceeded")
        self.pop(")")
        return tuple(output)

    def _type_reference(self) -> str:
        if self.peek("["):
            self.pop("[")
            rendered = "[" + self._type_reference()
            self.pop("]")
            rendered += "]"
        else:
            rendered = self.name()
        if self.peek("!"):
            self.pop("!")
            rendered += "!"
        return rendered

    def _selection_set(self, depth: int) -> tuple[_FieldNode | _SpreadNode, ...]:
        if depth > self.max_depth:
            raise GraphQLLimitExceeded("GraphQL selection depth limit exceeded")
        self.pop("{")
        output: list[_FieldNode | _SpreadNode] = []
        while not self.peek("}"):
            if self.peek() is None:
                raise GraphQLDocumentError("unbalanced GraphQL selection set")
            self.nodes += 1
            if self.nodes > self.max_nodes:
                raise GraphQLLimitExceeded("GraphQL selection node limit exceeded")
            if self.peek("..."):
                self.pop("...")
                if self.peek("on"):
                    self.pop("on")
                    condition = self.name()
                    self._directives()
                    children = self._selection_set(depth + 1)
                    output.append(
                        _FieldNode(
                            "__inline_fragment__",
                            type_condition=condition,
                            children=children,
                        )
                    )
                else:
                    spread_name = self.name()
                    self._directives()
                    output.append(_SpreadNode(spread_name))
                continue
            first = self.name()
            alias: str | None = None
            name = first
            if self.peek(":"):
                self.pop(":")
                alias = first
                name = self.name()
            arguments = self._arguments() if self.peek("(") else ()
            self._directives()
            children = self._selection_set(depth + 1) if self.peek("{") else ()
            output.append(
                _FieldNode(
                    name,
                    alias=alias,
                    arguments=arguments,
                    children=children,
                )
            )
        self.pop("}")
        if not output:
            raise GraphQLDocumentError("GraphQL selection set is empty")
        return tuple(output)

    def _arguments(self) -> tuple[ParsedGraphQLArgument, ...]:
        self.pop("(")
        output: list[ParsedGraphQLArgument] = []
        names: set[str] = set()
        while not self.peek(")"):
            name = self.name()
            if name in names:
                raise GraphQLDocumentError("duplicate GraphQL argument")
            names.add(name)
            self.pop(":")
            variable = self._value(0)
            output.append(ParsedGraphQLArgument(name=name, variable_name=variable))
            if len(output) > MAX_GRAPHQL_ARGUMENTS_PER_FIELD:
                raise GraphQLLimitExceeded("GraphQL argument limit exceeded")
        self.pop(")")
        return tuple(sorted(output, key=lambda item: item.name))

    def _value(self, depth: int) -> str | None:
        if depth > self.max_depth:
            raise GraphQLLimitExceeded("GraphQL value depth limit exceeded")
        if self.peek("$"):
            self.pop("$")
            return self.name()
        if self.peek("["):
            self.pop("[")
            while not self.peek("]"):
                self._value(depth + 1)
            self.pop("]")
            return None
        if self.peek("{"):
            self.pop("{")
            while not self.peek("}"):
                self.name()
                self.pop(":")
                self._value(depth + 1)
            self.pop("}")
            return None
        self.pop()
        return None

    def _directives(self) -> None:
        while self.peek("@"):
            self.pop("@")
            self.name()
            if self.peek("("):
                self._arguments()

    def expanded_operations(self) -> tuple[ParsedGraphQLOperation, ...]:
        output = []
        self.expanded_nodes = 0
        for operation_type, operation_name, variables, selections in self.operations:
            expanded = self._expand(
                selections, stack=(), spread_depth=0, selection_depth=1
            )
            rendered = tuple(self._to_model(item) for item in expanded)
            normalized = _normalized_selections(rendered)
            output.append(
                ParsedGraphQLOperation(
                    operation_type=operation_type,
                    operation_name=operation_name,
                    variables=variables,
                    selections=rendered,
                    selection_fingerprint="sha256:"
                    + hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                )
            )
        return tuple(output)

    def _expand(
        self,
        nodes: Sequence[_FieldNode | _SpreadNode],
        *,
        stack: tuple[str, ...],
        spread_depth: int,
        selection_depth: int,
    ) -> tuple[_FieldNode, ...]:
        if nodes and selection_depth > self.max_depth:
            raise GraphQLLimitExceeded(
                "expanded GraphQL selection depth limit exceeded"
            )
        output: list[_FieldNode] = []
        for node in nodes:
            if isinstance(node, _SpreadNode):
                if node.name in stack:
                    raise GraphQLDocumentError("cyclic GraphQL fragment spread")
                if spread_depth >= self.max_fragment_spread_depth:
                    raise GraphQLLimitExceeded(
                        "GraphQL fragment-spread depth limit exceeded"
                    )
                fragment = self.fragments.get(node.name)
                if fragment is None:
                    raise GraphQLDocumentError("undefined GraphQL fragment spread")
                condition, children = fragment
                expanded = self._expand(
                    children,
                    stack=(*stack, node.name),
                    spread_depth=spread_depth + 1,
                    selection_depth=selection_depth + 1,
                )
                output.append(
                    _FieldNode(
                        "__inline_fragment__",
                        type_condition=condition,
                        children=expanded,
                    )
                )
            else:
                output.append(
                    _FieldNode(
                        node.name,
                        alias=node.alias,
                        arguments=node.arguments,
                        type_condition=node.type_condition,
                        children=self._expand(
                            node.children,
                            stack=stack,
                            spread_depth=spread_depth,
                            selection_depth=selection_depth + 1,
                        ),
                    )
                )
            self.expanded_nodes += 1
            if self.expanded_nodes > self.max_nodes:
                raise GraphQLLimitExceeded("expanded GraphQL node limit exceeded")
        return tuple(output)

    @staticmethod
    def _to_model(node: _FieldNode) -> ParsedGraphQLSelection:
        return ParsedGraphQLSelection(
            field_name=node.name,
            response_alias=node.alias,
            arguments=node.arguments,
            type_condition=node.type_condition,
            children=tuple(_Parser._to_model(child) for child in node.children),
        )


def _normalized_selections(selections: Sequence[ParsedGraphQLSelection]) -> str:
    def render(item: ParsedGraphQLSelection) -> str:
        arguments = ""
        if item.arguments:
            arguments = (
                "("
                + ",".join(
                    f"{argument.name}:${argument.variable_name or 'literal'}"
                    for argument in item.arguments
                )
                + ")"
            )
        condition = f"@on:{item.type_condition}" if item.type_condition else ""
        children = (
            "{" + ",".join(sorted(render(child) for child in item.children)) + "}"
            if item.children
            else ""
        )
        # Aliases intentionally do not contribute to semantic identity.
        return item.field_name + arguments + condition + children

    return "{" + ",".join(sorted(render(item) for item in selections)) + "}"


def _concrete_root_selections(
    selections: Sequence[ParsedGraphQLSelection],
) -> tuple[ParsedGraphQLSelection, ...]:
    """Unwrap only root fragments while preserving their bounded child structure."""

    output: list[ParsedGraphQLSelection] = []
    for selection in selections:
        if selection.field_name == "__inline_fragment__":
            output.extend(_concrete_root_selections(selection.children))
        else:
            output.append(selection)
    return tuple(output)


def parse_graphql_document(
    document: str,
    *,
    max_tokens: int = MAX_GRAPHQL_TOKENS,
    max_nodes: int = MAX_GRAPHQL_SELECTION_NODES,
    max_depth: int = MAX_GRAPHQL_SELECTION_DEPTH,
    max_fragments: int = MAX_GRAPHQL_FRAGMENTS,
    max_fragment_spread_depth: int = MAX_GRAPHQL_FRAGMENT_SPREAD_DEPTH,
) -> ParsedGraphQLDocument:
    """Parse and normalize one bounded document without retaining literals."""

    if not isinstance(document, str):
        raise GraphQLDocumentError("GraphQL document must be text")
    if not 1 <= max_tokens <= MAX_GRAPHQL_TOKENS:
        raise ValueError("GraphQL token bound is outside the supported range")
    if not 1 <= max_nodes <= MAX_GRAPHQL_SELECTION_NODES:
        raise ValueError("GraphQL node bound is outside the supported range")
    if not 1 <= max_depth <= MAX_GRAPHQL_SELECTION_DEPTH:
        raise ValueError("GraphQL depth bound is outside the supported range")
    if not 0 <= max_fragments <= MAX_GRAPHQL_FRAGMENTS:
        raise ValueError("GraphQL fragment bound is outside the supported range")
    if not 1 <= max_fragment_spread_depth <= MAX_GRAPHQL_FRAGMENT_SPREAD_DEPTH:
        raise ValueError("GraphQL fragment depth bound is outside the supported range")
    tokens = _lex(document, max_tokens=max_tokens)
    parser = _Parser(
        tokens,
        max_nodes=max_nodes,
        max_depth=max_depth,
        max_fragments=max_fragments,
        max_fragment_spread_depth=max_fragment_spread_depth,
    )
    parser.parse()
    result = ParsedGraphQLDocument(
        document_digest="sha256:"
        + hashlib.sha256(document.encode("utf-8")).hexdigest(),
        operations=parser.expanded_operations(),
        fragment_count=len(parser.fragments),
        token_count=len(tokens),
    )
    reject_secret_material(result.model_dump(mode="json"), location="GraphQL parser")
    return result


def _response_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _error_class(
    item: Mapping[str, Any], status_code: int | None = None
) -> GraphQLErrorClass:
    if status_code == 401:
        return GraphQLErrorClass.authentication_error
    if status_code == 403:
        return GraphQLErrorClass.authorization_error
    if status_code == 404:
        return GraphQLErrorClass.not_found
    if status_code == 429:
        return GraphQLErrorClass.rate_limited
    code_map = {
        "GRAPHQL_PARSE_FAILED": GraphQLErrorClass.parse_error,
        "GRAPHQL_VALIDATION_FAILED": GraphQLErrorClass.validation_error,
        "UNAUTHENTICATED": GraphQLErrorClass.authentication_error,
        "AUTHENTICATION_ERROR": GraphQLErrorClass.authentication_error,
        "FORBIDDEN": GraphQLErrorClass.authorization_error,
        "AUTHORIZATION_ERROR": GraphQLErrorClass.authorization_error,
        "NOT_FOUND": GraphQLErrorClass.not_found,
        "RATE_LIMITED": GraphQLErrorClass.rate_limited,
        "TOO_MANY_REQUESTS": GraphQLErrorClass.rate_limited,
        "INTERNAL_SERVER_ERROR": GraphQLErrorClass.resolver_error,
    }
    extensions = item.get("extensions")
    code = (
        str(extensions.get("code") or extensions.get("category") or "").upper()
        if isinstance(extensions, Mapping)
        else ""
    )
    if code in code_map:
        return code_map[code]
    if item.get("path") is not None:
        return GraphQLErrorClass.resolver_error
    if item.get("locations") is not None:
        return GraphQLErrorClass.validation_error
    return GraphQLErrorClass.unknown


def _error_classes(
    payload: Mapping[str, Any], status_code: int | None, *, max_errors: int
) -> tuple[GraphQLErrorClass, ...]:
    if status_code in {401, 403, 404, 429}:
        return (_error_class({}, status_code),)
    errors = payload.get("errors")
    bounded_errors = errors[:max_errors] if isinstance(errors, list) else ()
    output = {
        _error_class(item) for item in bounded_errors if isinstance(item, Mapping)
    }
    return tuple(sorted(output, key=lambda item: item.value))


def analyze_graphql_response(
    response: Any,
    *,
    status_code: int | None = None,
    content_type: str | None = None,
    max_bytes: int = MAX_GRAPHQL_RESPONSE_BYTES,
    max_errors: int = DEFAULT_GRAPHQL_RESPONSE_ERROR_LIMIT,
    request_was_graphql: bool = False,
) -> GraphQLResponseObservation:
    """Return structural response evidence without retaining response values."""

    if not 1 <= max_bytes <= MAX_GRAPHQL_RESPONSE_BYTES:
        raise ValueError("GraphQL response byte bound is outside the supported range")
    if not 1 <= max_errors <= MAX_GRAPHQL_RESPONSE_ERRORS:
        raise ValueError("GraphQL response error bound is outside the supported range")
    if isinstance(response, bytes):
        raw = response
    elif isinstance(response, str):
        raw = response.encode("utf-8", errors="replace")
    else:
        raw = json.dumps(
            response,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    digest = _response_digest(raw)
    status_errors = _error_classes({}, status_code, max_errors=max_errors)
    if len(raw) > max_bytes:
        return GraphQLResponseObservation(
            envelope=GraphQLResponseEnvelope.oversized,
            evidence_digest=digest,
            response_bytes=max_bytes,
            truncated=True,
        )
    parsed: Any = response
    if isinstance(response, (str, bytes)):
        text = raw.decode("utf-8", errors="replace")
        if "html" in str(
            content_type or ""
        ).lower() or text.lstrip().lower().startswith(("<!doctype html", "<html")):
            return GraphQLResponseObservation(
                envelope=GraphQLResponseEnvelope.html,
                error_classes=status_errors,
                evidence_digest=digest,
                response_bytes=len(raw),
            )
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return GraphQLResponseObservation(
                envelope=GraphQLResponseEnvelope.non_json,
                error_classes=status_errors,
                evidence_digest=digest,
                response_bytes=len(raw),
            )
    if not isinstance(parsed, Mapping):
        return GraphQLResponseObservation(
            envelope=GraphQLResponseEnvelope.ordinary_json,
            error_classes=status_errors,
            evidence_digest=digest,
            response_bytes=len(raw),
        )
    data_present = "data" in parsed
    errors = parsed.get("errors")
    errors_present = isinstance(errors, list)
    bounded_errors = errors[:max_errors] if isinstance(errors, list) else ()
    errors_truncated = isinstance(errors, list) and len(errors) > max_errors
    content_is_graphql = "graphql-response+json" in str(content_type or "").lower()
    structured_error = errors_present and all(
        isinstance(item, Mapping)
        and (
            isinstance(item.get("message"), str)
            or item.get("locations") is not None
            or item.get("path") is not None
            or isinstance(item.get("extensions"), Mapping)
        )
        for item in bounded_errors
    )
    is_graphql = (
        content_is_graphql
        or structured_error
        or (request_was_graphql and (data_present or errors_present))
    )
    if not is_graphql:
        return GraphQLResponseObservation(
            envelope=GraphQLResponseEnvelope.ordinary_json,
            error_classes=status_errors,
            evidence_digest=digest,
            response_bytes=len(raw),
        )

    shape: set[str] = set()
    null_paths: set[str] = set()
    typenames: set[str] = set()
    count = 0
    shape_truncated = False

    def walk(value: Any, path: str, depth: int) -> None:
        nonlocal count, shape_truncated
        if depth > MAX_GRAPHQL_RESPONSE_DEPTH:
            shape_truncated = True
            return
        if count >= MAX_GRAPHQL_RESPONSE_SHAPE_NODES:
            shape_truncated = True
            return
        if isinstance(value, Mapping):
            for raw_name, item in sorted(value.items(), key=lambda pair: str(pair[0])):
                if count >= MAX_GRAPHQL_RESPONSE_SHAPE_NODES:
                    shape_truncated = True
                    break
                name = str(raw_name)
                child_path = f"{path}.{name}" if path else name
                kind = (
                    "object"
                    if isinstance(item, Mapping)
                    else "list"
                    if isinstance(item, list)
                    else "scalar"
                )
                shape.add(f"{child_path}:{kind}")
                if item is None:
                    null_paths.add(child_path)
                count += 1
                if (
                    name == "__typename"
                    and isinstance(item, str)
                    and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", item)
                ):
                    typenames.add(item)
                if isinstance(item, (Mapping, list)):
                    walk(item, child_path, depth + 1)
        elif isinstance(value, list):
            if len(value) > 32:
                shape_truncated = True
            for item in value[:32]:
                if isinstance(item, (Mapping, list)):
                    walk(item, path + "[]", depth + 1)

    if data_present:
        walk(parsed.get("data"), "data", 1)
    if len(typenames) > MAX_GRAPHQL_RESPONSE_TYPENAMES:
        shape_truncated = True
    envelope = (
        GraphQLResponseEnvelope.graphql_data_and_errors
        if data_present and errors_present
        else GraphQLResponseEnvelope.graphql_errors
        if errors_present
        else GraphQLResponseEnvelope.graphql_data
    )
    return GraphQLResponseObservation(
        envelope=envelope,
        data_present=data_present,
        errors_present=errors_present,
        error_classes=_error_classes(parsed, status_code, max_errors=max_errors),
        error_paths=tuple(
            GraphQLErrorPathObservation(
                path=tuple(
                    component
                    for component in item.get("path", ())[:MAX_GRAPHQL_RESPONSE_DEPTH]
                    if (type(component) is int and component >= 0)
                    or (
                        isinstance(component, str)
                        and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", component)
                    )
                ),
                error_class=_error_class(item, status_code),
            )
            for item in bounded_errors
            if isinstance(item, Mapping)
            and isinstance(item.get("path"), list)
            and any(
                (type(component) is int and component >= 0)
                or (
                    isinstance(component, str)
                    and re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", component)
                )
                for component in item.get("path", ())[:MAX_GRAPHQL_RESPONSE_DEPTH]
            )
        ),
        typename_observations=tuple(sorted(typenames))[:MAX_GRAPHQL_RESPONSE_TYPENAMES],
        object_shape=tuple(sorted(shape))[:MAX_GRAPHQL_RESPONSE_SHAPE_NODES],
        null_paths=tuple(sorted(null_paths))[:MAX_GRAPHQL_RESPONSE_SHAPE_NODES],
        evidence_digest=digest,
        response_bytes=len(raw),
        truncated=(
            shape_truncated
            or errors_truncated
            or count >= MAX_GRAPHQL_RESPONSE_SHAPE_NODES
        ),
    )


class GraphQLSemanticDelta(ResearchContract):
    """One atomic, validated GraphQL semantic-state mutation."""

    surfaces: tuple[Surface, ...] = Field(default=(), max_length=32)
    endpoints: tuple[Endpoint, ...] = Field(default=(), max_length=64)
    parameters: tuple[Parameter, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_VARIABLES
    )
    graphql_surfaces: tuple[GraphQLSurface, ...] = Field(default=(), max_length=32)
    types: tuple[GraphQLTypeRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_TYPES
    )
    fields: tuple[GraphQLFieldRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_FIELDS
    )
    arguments: tuple[GraphQLArgumentRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_ARGUMENTS
    )
    operations: tuple[GraphQLOperationRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_OPERATIONS
    )
    variables: tuple[GraphQLVariableRecord, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_VARIABLES
    )
    auth_observations: tuple[Observation, ...] = Field(default=(), max_length=1_000)
    objects: tuple[ResearchObject, ...] = Field(default=(), max_length=1_000)
    object_relationships: tuple[GraphAssertion, ...] = Field(
        default=(), max_length=2_000
    )
    cross_surface_relationships: tuple[GraphAssertion, ...] = Field(
        default=(), max_length=2_000
    )
    evidence: tuple[EvidenceArtifact, ...] = Field(default=(), max_length=5_000)
    provenance: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=1_000)
    trace_events: tuple[GraphQLTraceEvent, ...] = Field(default=(), max_length=2_000)

    @model_validator(mode="after")
    def secret_safe(self) -> "GraphQLSemanticDelta":
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL semantic delta"
        )
        return self

    @classmethod
    def combine(
        cls, deltas: Sequence["GraphQLSemanticDelta"]
    ) -> "GraphQLSemanticDelta":
        """Combine bounded parser outputs for one later atomic state commit."""

        def unique(name: str, id_field: str) -> tuple[Any, ...]:
            values: dict[str, Any] = {}
            for delta in deltas:
                for item in getattr(delta, name):
                    values.setdefault(str(getattr(item, id_field)), item)
            return tuple(values[key] for key in sorted(values))

        def semantic(name: str, id_field: str) -> tuple[Any, ...]:
            values: dict[str, Any] = {}
            conflicts: list[Any] = []
            for delta in deltas:
                for item in getattr(delta, name):
                    identifier = str(getattr(item, id_field))
                    prior = values.get(identifier)
                    if prior is None:
                        values[identifier] = item
                        continue
                    try:
                        values[identifier] = _merge_semantic_record(
                            prior, item, identifier
                        )
                    except GraphQLSemanticConflict:
                        # Keep incompatible evidence so apply() can retain the
                        # prior fact and emit its deterministic conflict record.
                        conflicts.append(item)
            return (*tuple(values[key] for key in sorted(values)), *conflicts)

        trace_values: dict[str, GraphQLTraceEvent] = {}
        for delta in deltas:
            for item in delta.trace_events:
                key = json.dumps(
                    item.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                trace_values.setdefault(key, item)
        payload = {
            "surfaces": unique("surfaces", "surface_id"),
            "endpoints": unique("endpoints", "endpoint_id"),
            "parameters": unique("parameters", "parameter_id"),
            "graphql_surfaces": semantic("graphql_surfaces", "graphql_surface_id"),
            "types": semantic("types", "type_id"),
            "fields": semantic("fields", "field_id"),
            "arguments": semantic("arguments", "argument_id"),
            "operations": semantic("operations", "operation_id"),
            "variables": semantic("variables", "variable_id"),
            "auth_observations": unique("auth_observations", "observation_id"),
            "objects": unique("objects", "object_id"),
            "object_relationships": unique("object_relationships", "assertion_id"),
            "cross_surface_relationships": unique(
                "cross_surface_relationships", "assertion_id"
            ),
            "evidence": unique("evidence", "evidence_id"),
            "provenance": unique("provenance", "provenance_id"),
            "trace_events": tuple(trace_values[key] for key in sorted(trace_values)),
        }
        return cls.model_validate(payload)

    def apply(
        self,
        state: ResearchState,
        *,
        revision: int | None = None,
        updated_at: str | None = None,
    ) -> ResearchState:
        """Apply all records together or leave the caller's immutable state unchanged."""

        payload = state.model_dump(mode="python")

        def simple(name: str, incoming: Sequence[Any], id_field: str) -> None:
            values = {getattr(item, id_field): item for item in getattr(state, name)}
            for item in incoming:
                values.setdefault(getattr(item, id_field), item)
            payload[name] = tuple(values[key] for key in sorted(values))

        simple("provenance", self.provenance, "provenance_id")
        simple("evidence", self.evidence, "evidence_id")
        simple("surfaces", self.surfaces, "surface_id")
        simple("endpoints", self.endpoints, "endpoint_id")
        simple("parameters", self.parameters, "parameter_id")
        simple("objects", self.objects, "object_id")

        conflict_observations: list[Observation] = []

        def semantic(name: str, incoming: Sequence[Any], id_field: str) -> None:
            existing = {
                getattr(item, id_field): item
                for item in getattr(state, name)
                if hasattr(item, id_field)
            }
            legacy = tuple(
                item for item in getattr(state, name) if not hasattr(item, id_field)
            )
            for item in incoming:
                identifier = getattr(item, id_field)
                if identifier not in existing:
                    existing[identifier] = item
                    continue
                try:
                    existing[identifier] = _merge_semantic_record(
                        existing[identifier], item, identifier
                    )
                except GraphQLSemanticConflict:
                    prior = existing[identifier]
                    refs = tuple(
                        sorted(
                            {
                                *getattr(prior, "evidence_references", ()),
                                *getattr(item, "evidence_references", ()),
                            }
                        )
                    )
                    if refs and hasattr(prior, "evidence_references"):
                        existing[identifier] = type(prior).model_validate(
                            {
                                **prior.model_dump(mode="python"),
                                "evidence_references": refs,
                            }
                        )
                    surface_id = self.surfaces[0].surface_id if self.surfaces else None
                    target_id = (
                        self.surfaces[0].target_id
                        if self.surfaces
                        else state.targets[0].target_id
                    )
                    provenance_id = item.provenance_id
                    conflict_observations.append(
                        Observation(
                            observation_id=stable_research_identifier(
                                "observation", "graphql-conflict", identifier, *refs
                            ),
                            observation_type="graphql_semantic_conflict",
                            summary=(
                                "Conflicting GraphQL structural evidence was retained "
                                "without replacing the prior semantic fact."
                            ),
                            target_id=target_id,
                            surface_id=surface_id,
                            evidence_references=refs,
                            provenance_id=provenance_id,
                        )
                    )
            payload[name] = legacy + tuple(existing[key] for key in sorted(existing))

        semantic("graphql_surfaces", self.graphql_surfaces, "graphql_surface_id")
        semantic("graphql_types", self.types, "type_id")
        semantic("graphql_fields", self.fields, "field_id")
        semantic("graphql_arguments", self.arguments, "argument_id")
        semantic("graphql_operations", self.operations, "operation_id")
        semantic("graphql_variables", self.variables, "variable_id")
        canonical_arguments = {
            item.argument_id: item for item in payload["graphql_arguments"]
        }
        normalized_variables = []
        for variable in payload["graphql_variables"]:
            argument = (
                canonical_arguments.get(variable.linked_argument_id)
                if variable.linked_argument_id is not None
                else None
            )
            if (
                argument is not None
                and variable.input_type.to_syntax() == argument.input_type.to_syntax()
                and variable.input_type != argument.input_type
            ):
                variable = variable.model_copy(
                    update={
                        "input_type": argument.input_type,
                        "nullable": argument.input_type.nullable,
                        "list_depth": argument.input_type.list_depth,
                    }
                )
            normalized_variables.append(variable)
        payload["graphql_variables"] = tuple(normalized_variables)
        observations = {item.observation_id: item for item in state.observations}
        for item in (*self.auth_observations, *conflict_observations):
            observations.setdefault(item.observation_id, item)
        payload["observations"] = tuple(
            observations[key] for key in sorted(observations)
        )
        if revision is not None:
            payload["revision"] = revision
        if updated_at is not None:
            payload["updated_at"] = updated_at
        result = ResearchState.model_validate(payload)
        reject_secret_material(
            result.model_dump(mode="json"), location="GraphQL research state"
        )
        return result

    def commit(
        self,
        store: Any,
        state: ResearchState,
        *,
        updated_at: str | None = None,
    ) -> ResearchState:
        timestamp = updated_at or datetime.now(timezone.utc).isoformat()
        next_state = self.apply(
            state, revision=state.revision + 1, updated_at=timestamp
        )
        generated = build_graphql_graph_assertions(next_state, asserted_at=timestamp)
        assertions = {
            item.assertion_id: item
            for item in (
                *generated,
                *self.object_relationships,
                *self.cross_surface_relationships,
            )
        }
        new_assertions = []
        for assertion_id in sorted(assertions):
            try:
                store.load_graph_assertion(state.research_id, assertion_id)
            except KeyError:
                new_assertions.append(assertions[assertion_id])
        return store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
            graph_assertions=tuple(new_assertions),
        )


def _semantic_role(name: str) -> GraphQLSemanticRole:
    normalized = re.sub(r"[^a-z0-9]+", "", name.lower())
    if normalized in {"id", "uuid", "identifier", "objectid", "nodeid"}:
        return GraphQLSemanticRole.identifier
    if normalized in {"first", "last", "after", "before", "limit", "offset", "page"}:
        return GraphQLSemanticRole.pagination
    if "tenant" in normalized or "organization" in normalized:
        return GraphQLSemanticRole.tenant_reference
    if normalized in {"userid", "userref", "accountid", "accountref"}:
        return GraphQLSemanticRole.user_reference
    if normalized.endswith("id") or normalized.endswith("ref"):
        return GraphQLSemanticRole.object_reference
    if normalized in {"filter", "where"}:
        return GraphQLSemanticRole.filter
    if normalized in {"search", "query", "term"}:
        return GraphQLSemanticRole.search
    if normalized in {"sort", "order", "orderby"}:
        return GraphQLSemanticRole.ordering
    return GraphQLSemanticRole.unknown


def _type_kind(value: str) -> GraphQLTypeKind | None:
    return {
        "SCALAR": GraphQLTypeKind.scalar,
        "OBJECT": GraphQLTypeKind.object,
        "INTERFACE": GraphQLTypeKind.interface,
        "UNION": GraphQLTypeKind.union,
        "ENUM": GraphQLTypeKind.enum,
        "INPUT_OBJECT": GraphQLTypeKind.input_object,
    }.get(value.upper())


def _return_shape(kind: GraphQLTypeKind | None) -> GraphQLReturnShape:
    return {
        GraphQLTypeKind.scalar: GraphQLReturnShape.scalar,
        GraphQLTypeKind.object: GraphQLReturnShape.object,
        GraphQLTypeKind.interface: GraphQLReturnShape.interface,
        GraphQLTypeKind.union: GraphQLReturnShape.union,
        GraphQLTypeKind.enum: GraphQLReturnShape.enum,
        GraphQLTypeKind.input_object: GraphQLReturnShape.input_object,
    }.get(kind, GraphQLReturnShape.unknown)


def _authentication_requirement(
    identity_id: str | None,
    response: GraphQLResponseObservation | None,
) -> GraphQLAuthenticationRequirement:
    error_classes = set(response.error_classes if response is not None else ())
    if GraphQLErrorClass.authentication_error in error_classes:
        return GraphQLAuthenticationRequirement.authentication_required
    if GraphQLErrorClass.authorization_error in error_classes:
        return (
            GraphQLAuthenticationRequirement.role_bound
            if identity_id
            else GraphQLAuthenticationRequirement.authentication_required
        )
    return (
        GraphQLAuthenticationRequirement.authenticated_observed
        if identity_id
        else GraphQLAuthenticationRequirement.anonymous_observed
    )


def _auth_error_observation(
    *,
    response: GraphQLResponseObservation | None,
    target_id: str,
    surface_id: str,
    evidence_references: tuple[str, ...],
    provenance_id: str,
) -> Observation | None:
    relevant = tuple(
        item
        for item in (response.error_classes if response is not None else ())
        if item
        in {
            GraphQLErrorClass.authentication_error,
            GraphQLErrorClass.authorization_error,
        }
    )
    if not relevant:
        return None
    class_names = tuple(sorted(item.value for item in relevant))
    return Observation(
        observation_id=stable_research_identifier(
            "observation",
            "graphql-auth-error",
            target_id,
            surface_id,
            response.evidence_digest if response is not None else "none",
            *class_names,
        ),
        observation_type="graphql_authentication_boundary",
        summary=(
            "A deterministic GraphQL authentication or authorization error class "
            "was observed; no vulnerability conclusion was produced."
        ),
        target_id=target_id,
        surface_id=surface_id,
        evidence_references=evidence_references,
        provenance_id=provenance_id,
    )


def _introspection_type_ref(value: Any, depth: int = 0) -> GraphQLTypeReference:
    if depth > 12 or not isinstance(value, Mapping):
        raise GraphQLLimitExceeded("GraphQL introspection type depth exceeded")
    kind = str(value.get("kind") or "").upper()
    if kind == "NON_NULL":
        inner = _introspection_type_ref(value.get("ofType"), depth + 1)
        return GraphQLTypeReference.from_syntax(
            inner.to_syntax() + "!", unresolved_external=inner.unresolved_external
        )
    if kind == "LIST":
        inner = _introspection_type_ref(value.get("ofType"), depth + 1)
        return GraphQLTypeReference.from_syntax(
            "[" + inner.to_syntax() + "]",
            unresolved_external=inner.unresolved_external,
        )
    name = value.get("name")
    if not isinstance(name, str):
        raise GraphQLDocumentError("introspection type reference has no name")
    return GraphQLTypeReference.from_syntax(name)


class GraphQLSemanticIngestor:
    """Convert bounded observations into P4-1A records without mutating state."""

    def _foundation(
        self,
        state: ResearchState,
        observation: Any,
        *,
        occurred_at: str,
        evidence_kind: EvidenceKind,
        summary: str,
        schema_state: GraphQLSchemaState,
        capabilities: Sequence[GraphQLOperationType] = (),
        authentication_requirement: GraphQLAuthenticationRequirement | None = None,
    ) -> tuple[
        Surface,
        Endpoint,
        GraphQLSurface,
        EvidenceArtifact,
        ProvenanceRecord,
    ]:
        target_id = str(observation.target_id)
        url = str(observation.endpoint_url)
        parsed_url = urlparse(url)
        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.netloc:
            raise GraphQLDocumentError(
                "GraphQL endpoint must be an absolute HTTP(S) URL"
            )
        if not any(item.target_id == target_id for item in state.targets):
            raise GraphQLDocumentError("GraphQL observation target is not registered")
        identity_id = getattr(observation, "identity_id", None)
        if identity_id is not None and not any(
            item.identity_id == str(identity_id) for item in state.identities
        ):
            raise GraphQLDocumentError("GraphQL observation identity is not registered")
        raw_method = str(getattr(observation, "method", "POST") or "POST").upper()
        if raw_method not in {"GET", "POST"}:
            raise GraphQLDocumentError("GraphQL observations support only GET or POST")
        method = HttpMethod(raw_method)
        path = parsed_url.path or "/"
        source_reference = opaque_reference(
            observation.source_reference, "graphql-source"
        )
        provenance_id = stable_research_identifier(
            "provenance", state.research_id, observation.observation_id, "graphql"
        )
        evidence_id = stable_research_identifier(
            "evidence", state.research_id, observation.observation_id
        )
        surface_id = stable_research_identifier(
            "surface", target_id, "graphql", parsed_url.scheme, parsed_url.netloc, path
        )
        endpoint_id = stable_research_identifier(
            "endpoint", surface_id, "graphql", method.value
        )
        graphql_surface_id = graphql_semantic_id(
            "surface", target_id, surface_id, endpoint_id
        )
        provenance = ProvenanceRecord(
            provenance_id=provenance_id,
            producer_type=ProvenanceProducerType.deterministic,
            producer_name="graphql-semantic-ingestor",
            producer_version=GRAPHQL_INGEST_VERSION,
            source_references=(source_reference,),
            summary="Deterministic bounded GraphQL semantic acquisition.",
            occurred_at=occurred_at,
        )
        evidence = EvidenceArtifact(
            evidence_id=evidence_id,
            evidence_kind=evidence_kind,
            digest=str(observation.evidence_digest),
            summary=summary,
            source_reference=source_reference,
            observed_at=occurred_at,
            provenance_id=provenance_id,
        )
        surface = Surface(
            surface_id=surface_id,
            target_id=target_id,
            surface_type=SurfaceType.graphql,
            label="Observed GraphQL application surface.",
            evidence_references=(evidence_id,),
            provenance_id=provenance_id,
        )
        endpoint = Endpoint(
            endpoint_id=endpoint_id,
            target_id=target_id,
            surface_id=surface_id,
            method=method,
            route_template=path,
            content_types=("application/json",),
            evidence_references=(evidence_id,),
            provenance_id=provenance_id,
        )
        transport = (
            GraphQLTransport.http
            if parsed_url.scheme.lower() == "http"
            else GraphQLTransport.https
        )
        auth_requirement = authentication_requirement or (
            GraphQLAuthenticationRequirement.authenticated_observed
            if identity_id
            else GraphQLAuthenticationRequirement.anonymous_observed
        )
        semantic_surface = GraphQLSurface(
            graphql_surface_id=graphql_surface_id,
            research_id=state.research_id,
            target_id=target_id,
            surface_id=surface_id,
            endpoint_id=endpoint_id,
            transport=transport,
            schema_state=schema_state,
            operation_capabilities=tuple(
                sorted(set(capabilities), key=lambda x: x.value)
            ),
            authentication_requirement=auth_requirement,
            evidence_references=(evidence_id,),
            provenance_id=provenance_id,
        )
        return surface, endpoint, semantic_surface, evidence, provenance

    def from_surface_observation(
        self,
        state: ResearchState,
        observation: Any,
        *,
        occurred_at: str | None = None,
        response: GraphQLResponseObservation | None = None,
    ) -> GraphQLSemanticDelta:
        """Create a semantic surface from protocol evidence without inventing schema."""

        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.deterministic_discovery_observation,
            summary=(
                "Bounded deterministic evidence confirmed GraphQL protocol semantics; "
                "no vulnerability inference was made."
            ),
            schema_state=GraphQLSchemaState.partial,
            authentication_requirement=_authentication_requirement(
                getattr(observation, "identity_id", None), response
            ),
        )
        evidence_items = [evidence]
        if response is not None:
            response_evidence = EvidenceArtifact(
                evidence_id=stable_research_identifier(
                    "evidence", observation.observation_id, "graphql-protocol-response"
                ),
                evidence_kind=EvidenceKind.response_summary,
                digest=response.evidence_digest,
                summary=(
                    "A bounded GraphQL protocol response structure was observed; "
                    "response values were excluded."
                ),
                source_reference=opaque_reference(
                    observation.source_reference, "graphql-source"
                ),
                observed_at=timestamp,
                provenance_id=provenance.provenance_id,
            )
            evidence_items.append(response_evidence)
            semantic_surface = semantic_surface.model_copy(
                update={
                    "evidence_references": (
                        evidence.evidence_id,
                        response_evidence.evidence_id,
                    )
                }
            )
        refs = tuple(item.evidence_id for item in evidence_items)
        auth_observation = _auth_error_observation(
            response=response,
            target_id=str(observation.target_id),
            surface_id=surface.surface_id,
            evidence_references=refs,
            provenance_id=provenance.provenance_id,
        )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            graphql_surfaces=(semantic_surface,),
            auth_observations=(auth_observation,) if auth_observation else (),
            evidence=tuple(evidence_items),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type=(
                        "GRAPHQL_PROTOCOL"
                        if str(getattr(observation, "source_kind", ""))
                        == "active_probe"
                        else "GRAPHQL_SURFACE"
                    ),
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=refs,
                ),
            ),
        )

    def from_identity_differential(
        self,
        state: ResearchState,
        observation: Any,
        differential: Any,
        *,
        occurred_at: str | None = None,
    ) -> GraphQLSemanticDelta:
        """Persist only safe structural differences between controlled identities."""

        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.differential,
            summary=(
                "The same registered read-only GraphQL operation produced an "
                "identity-dependent structural observation; this is not a finding."
            ),
            schema_state=GraphQLSchemaState.partial,
        )

        def bounded_join(values: Sequence[Any]) -> str:
            rendered = ",".join(str(item) for item in values)
            return rendered[:1_000] or "none"

        metadata_values = {
            "left_identity": str(differential.left_identity),
            "right_identity": str(differential.right_identity),
            "added_shape": bounded_join(differential.added_shape),
            "removed_shape": bounded_join(differential.removed_shape),
            "added_typenames": bounded_join(differential.added_typenames),
            "removed_typenames": bounded_join(differential.removed_typenames),
            "left_error_classes": bounded_join(differential.left_error_classes),
            "right_error_classes": bounded_join(differential.right_error_classes),
            "left_operation_available": bool(differential.left_operation_available),
            "right_operation_available": bool(differential.right_operation_available),
        }
        evidence = evidence.model_copy(
            update={
                "digest": str(differential.evidence_digest),
                "metadata": PublicMetadata(
                    entries=tuple(
                        MetadataEntry(key=key, value=value)
                        for key, value in metadata_values.items()
                    )
                ),
            }
        )
        auth_observation = Observation(
            observation_id=stable_research_identifier(
                "observation",
                "graphql-identity-differential",
                differential.evidence_digest,
            ),
            observation_type="graphql_identity_differential",
            summary=(
                "A bounded identity-dependent GraphQL response structure was "
                "observed. No vulnerability conclusion was produced."
            ),
            target_id=str(observation.target_id),
            surface_id=surface.surface_id,
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            graphql_surfaces=(semantic_surface,),
            auth_observations=(auth_observation,),
            evidence=(evidence,),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type="GRAPHQL_SEMANTIC_UPDATE",
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=(evidence.evidence_id,),
                ),
            ),
        )

    def from_query_analysis(
        self,
        state: ResearchState,
        observation: Any,
        analysis: Mapping[str, Any],
        *,
        occurred_at: str | None = None,
    ) -> GraphQLSemanticDelta:
        """Adapt the bounded output of the existing offline query analyzer."""

        if analysis.get("success") is not True or analysis.get("executed") is True:
            raise GraphQLDocumentError("offline GraphQL query analysis is unavailable")
        try:
            operation_type = GraphQLOperationType(
                str(analysis.get("operation_type") or "").lower()
            )
        except ValueError as exc:
            raise GraphQLDocumentError(
                "offline GraphQL analysis has no supported operation type"
            ) from exc

        def names(value: Any, maximum: int) -> tuple[str, ...]:
            if not isinstance(value, Sequence) or isinstance(
                value, (str, bytes, bytearray)
            ):
                return ()
            output: list[str] = []
            for item in value:
                rendered = str(item)
                if not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", rendered):
                    continue
                if rendered not in output:
                    output.append(rendered)
                if len(output) >= maximum:
                    break
            return tuple(output)

        fields = names(analysis.get("fields"), MAX_GRAPHQL_SELECTION_NODES)
        if not fields:
            raise GraphQLDocumentError("offline GraphQL analysis has no fields")
        variables = names(
            analysis.get("variables"), MAX_GRAPHQL_VARIABLES_PER_OPERATION
        )
        operation_name = analysis.get("operation_name")
        if operation_name is not None and not re.fullmatch(
            r"[_A-Za-z][_0-9A-Za-z]{0,254}", str(operation_name)
        ):
            operation_name = None
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.graphql_document,
            summary=(
                "Existing bounded offline GraphQL query analysis supplied partial "
                "operation semantics; no document was executed."
            ),
            schema_state=GraphQLSchemaState.partial,
            capabilities=(operation_type,),
        )
        role = GraphQLRootRole(operation_type.value)
        type_id = graphql_semantic_id(
            "type", semantic_surface.graphql_surface_id, role.value.title()
        )
        root_name = fields[0]
        field_id = graphql_semantic_id("field", type_id, root_name)
        unknown = GraphQLTypeReference.from_syntax("Unknown", unresolved_external=True)
        auth = GraphQLAuthorizationSemantics(
            observations=(GraphQLAuthorizationObservation.unknown,),
            identity_references=(
                (str(observation.identity_id),)
                if getattr(observation, "identity_id", None)
                else ()
            ),
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        field = GraphQLFieldRecord(
            field_id=field_id,
            type_id=type_id,
            name=root_name,
            return_type=unknown,
            return_shape=GraphQLReturnShape.unknown,
            nullable=True,
            list_depth=0,
            authorization_semantics=auth,
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        structural_digest = digest_for(
            {
                "operation_type": operation_type.value,
                "operation_name": operation_name,
                "fields": fields,
                "variables": variables,
                "aliases": names(analysis.get("aliases"), 100),
                "fragments": names(analysis.get("fragments"), 100),
            }
        )
        operation_id = graphql_semantic_id(
            "operation",
            semantic_surface.graphql_surface_id,
            operation_type.value,
            str(operation_name or structural_digest),
        )
        variable_records: list[GraphQLVariableRecord] = []
        parameters: list[Parameter] = []
        variable_ids: list[str] = []
        for variable_name in variables:
            variable_id = graphql_semantic_id("variable", operation_id, variable_name)
            variable_ids.append(variable_id)
            role_value = _semantic_role(variable_name)
            variable_records.append(
                GraphQLVariableRecord(
                    variable_id=variable_id,
                    operation_id=operation_id,
                    name=variable_name,
                    input_type=unknown,
                    nullable=True,
                    list_depth=0,
                    semantic_role=role_value,
                    semantic_role_evidence_references=(
                        (evidence.evidence_id,)
                        if role_value is not GraphQLSemanticRole.unknown
                        else ()
                    ),
                    evidence_references=(evidence.evidence_id,),
                    provenance_id=provenance.provenance_id,
                )
            )
            parameters.append(
                Parameter(
                    parameter_id=stable_research_identifier(
                        "parameter",
                        endpoint.endpoint_id,
                        "graphql",
                        variable_name,
                    ),
                    endpoint_id=endpoint.endpoint_id,
                    name=variable_name,
                    location=ParameterLocation.graphql_variable,
                    data_type="graphql-type-unknown",
                    required=False,
                    evidence_references=(evidence.evidence_id,),
                    provenance_id=provenance.provenance_id,
                )
            )
        operation = GraphQLOperationRecord(
            operation_id=operation_id,
            graphql_surface_id=semantic_surface.graphql_surface_id,
            operation_type=operation_type,
            operation_name=(str(operation_name) if operation_name else None),
            root_field_ids=(field_id,),
            variable_ids=tuple(variable_ids),
            selection_fingerprint=structural_digest,
            authentication_requirement=(
                GraphQLAuthenticationRequirement.authenticated_observed
                if getattr(observation, "identity_id", None)
                else GraphQLAuthenticationRequirement.anonymous_observed
            ),
            state_change_class=(
                GraphQLStateChangeClass.read_only
                if operation_type is GraphQLOperationType.query
                else GraphQLStateChangeClass.potential_state_change
            ),
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        root_type = GraphQLTypeRecord(
            type_id=type_id,
            graphql_surface_id=semantic_surface.graphql_surface_id,
            name=role.value.title(),
            kind=GraphQLTypeKind.object,
            root_role=role,
            field_ids=(field_id,),
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            parameters=tuple(parameters),
            graphql_surfaces=(semantic_surface,),
            types=(root_type,),
            fields=(field,),
            operations=(operation,),
            variables=tuple(variable_records),
            evidence=(evidence,),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type="GRAPHQL_SEMANTIC_UPDATE",
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=(evidence.evidence_id,),
                ),
            ),
        )

    def from_schema_analysis(
        self,
        state: ResearchState,
        observation: Any,
        analysis: Mapping[str, Any],
        *,
        occurred_at: str | None = None,
    ) -> GraphQLSemanticDelta:
        """Adapt safe, truncated output from the existing offline schema analyzer."""

        if analysis.get("success") is not True:
            raise GraphQLDocumentError("offline GraphQL schema analysis is unavailable")
        role_inputs = (
            (GraphQLRootRole.query, analysis.get("query_operations")),
            (GraphQLRootRole.mutation, analysis.get("mutation_operations")),
            (
                GraphQLRootRole.subscription,
                analysis.get("subscription_operations"),
            ),
        )
        capabilities = tuple(
            GraphQLOperationType(role.value)
            for role, values in role_inputs
            if isinstance(values, list) and values
        )
        if not capabilities:
            raise GraphQLDocumentError(
                "offline GraphQL schema analysis has no root operations"
            )
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.schema,
            summary=(
                "Existing bounded offline GraphQL schema analysis supplied partial "
                "root field semantics; schema completeness was not asserted."
            ),
            schema_state=GraphQLSchemaState.partial,
            capabilities=capabilities,
        )
        auth = GraphQLAuthorizationSemantics(
            observations=(GraphQLAuthorizationObservation.unknown,),
            identity_references=(),
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        types: list[GraphQLTypeRecord] = []
        fields: list[GraphQLFieldRecord] = []
        arguments: list[GraphQLArgumentRecord] = []
        for role, raw_operations in role_inputs:
            if not isinstance(raw_operations, list) or not raw_operations:
                continue
            type_id = graphql_semantic_id(
                "type", semantic_surface.graphql_surface_id, role.value.title()
            )
            field_ids: list[str] = []
            for item in raw_operations[:MAX_GRAPHQL_FIELDS_PER_TYPE]:
                if not isinstance(item, Mapping):
                    continue
                name = str(item.get("name") or "")
                if not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,254}", name):
                    continue
                field_id = graphql_semantic_id("field", type_id, name)
                argument_ids: list[str] = []
                raw_arguments = item.get("arguments")
                if isinstance(raw_arguments, list):
                    for raw_argument in raw_arguments[:MAX_GRAPHQL_ARGUMENTS_PER_FIELD]:
                        argument_name = str(raw_argument)
                        if not re.fullmatch(
                            r"[_A-Za-z][_0-9A-Za-z]{0,254}", argument_name
                        ):
                            continue
                        argument_id = graphql_semantic_id(
                            "argument", field_id, argument_name
                        )
                        role_value = _semantic_role(argument_name)
                        unknown_input = GraphQLTypeReference.from_syntax(
                            "Unknown", unresolved_external=True
                        )
                        arguments.append(
                            GraphQLArgumentRecord(
                                argument_id=argument_id,
                                field_id=field_id,
                                name=argument_name,
                                input_type=unknown_input,
                                nullable=True,
                                list_depth=0,
                                default_presence=False,
                                semantic_role=role_value,
                                semantic_role_evidence_references=(
                                    (evidence.evidence_id,)
                                    if role_value is not GraphQLSemanticRole.unknown
                                    else ()
                                ),
                                evidence_references=(evidence.evidence_id,),
                                provenance_id=provenance.provenance_id,
                            )
                        )
                        argument_ids.append(argument_id)
                raw_return = str(item.get("return_type") or "Unknown")
                try:
                    return_type = GraphQLTypeReference.from_syntax(
                        raw_return, unresolved_external=True
                    )
                except ValueError:
                    return_type = GraphQLTypeReference.from_syntax(
                        "Unknown", unresolved_external=True
                    )
                fields.append(
                    GraphQLFieldRecord(
                        field_id=field_id,
                        type_id=type_id,
                        name=name,
                        return_type=return_type,
                        return_shape=GraphQLReturnShape.unknown,
                        nullable=return_type.nullable,
                        list_depth=return_type.list_depth,
                        argument_ids=tuple(argument_ids),
                        authorization_semantics=auth,
                        evidence_references=(evidence.evidence_id,),
                        provenance_id=provenance.provenance_id,
                    )
                )
                field_ids.append(field_id)
            if field_ids:
                types.append(
                    GraphQLTypeRecord(
                        type_id=type_id,
                        graphql_surface_id=semantic_surface.graphql_surface_id,
                        name=role.value.title(),
                        kind=GraphQLTypeKind.object,
                        root_role=role,
                        field_ids=tuple(field_ids),
                        evidence_references=(evidence.evidence_id,),
                        provenance_id=provenance.provenance_id,
                    )
                )
        if not types:
            raise GraphQLDocumentError(
                "offline GraphQL schema analysis had no valid root fields"
            )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            graphql_surfaces=(semantic_surface,),
            types=tuple(types),
            fields=tuple(fields),
            arguments=tuple(arguments),
            evidence=(evidence,),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type="GRAPHQL_SEMANTIC_UPDATE",
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=(evidence.evidence_id,),
                ),
            ),
        )

    def from_document(
        self,
        state: ResearchState,
        observation: Any,
        document: str | ParsedGraphQLDocument,
        *,
        occurred_at: str | None = None,
        response: GraphQLResponseObservation | None = None,
    ) -> GraphQLSemanticDelta:
        parsed = (
            document
            if isinstance(document, ParsedGraphQLDocument)
            else parse_graphql_document(document)
        )
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        capabilities = tuple(item.operation_type for item in parsed.operations)
        source_kind = str(getattr(observation, "source_kind", ""))
        static_public_document = source_kind in {
            "public_client_asset",
            "public_persisted_manifest",
        }
        authentication_requirement = (
            GraphQLAuthenticationRequirement.unknown
            if static_public_document and response is None
            else _authentication_requirement(
                getattr(observation, "identity_id", None), response
            )
        )
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=(
                EvidenceKind.graphql_document
                if static_public_document
                else EvidenceKind.graphql_request_capture
            ),
            summary=(
                "A bounded exact public GraphQL application document was statically "
                "observed; execution and authorization behavior were not observed."
                if static_public_document
                else "A bounded GraphQL request document was structurally observed."
            ),
            schema_state=(
                GraphQLSchemaState.document_derived
                if static_public_document
                else GraphQLSchemaState.capture_derived
            ),
            capabilities=capabilities,
            authentication_requirement=authentication_requirement,
        )
        if static_public_document:
            source_metadata = PublicMetadata(
                entries=(
                    MetadataEntry(
                        key="graphql.operation_source",
                        value=source_kind,
                    ),
                    MetadataEntry(
                        key="graphql.operation_executed",
                        value=False,
                    ),
                    MetadataEntry(
                        key="graphql.object_binding_observed",
                        value=False,
                    ),
                )
            )
            evidence = evidence.model_copy(update={"metadata": source_metadata})
            provenance = provenance.model_copy(update={"metadata": source_metadata})
        evidence_items = [evidence]
        if response is not None:
            evidence_items.append(
                EvidenceArtifact(
                    evidence_id=stable_research_identifier(
                        "evidence", observation.observation_id, "graphql-response"
                    ),
                    evidence_kind=EvidenceKind.graphql_response_capture,
                    digest=response.evidence_digest,
                    summary=(
                        "A bounded GraphQL response envelope and object shape were "
                        "observed; response values were excluded."
                    ),
                    source_reference=opaque_reference(
                        observation.source_reference, "graphql-source"
                    ),
                    observed_at=timestamp,
                    provenance_id=provenance.provenance_id,
                )
            )
        evidence_refs = tuple(item.evidence_id for item in evidence_items)
        semantic_surface = semantic_surface.model_copy(
            update={"evidence_references": evidence_refs}
        )
        types: dict[str, GraphQLTypeRecord] = {}
        fields: dict[str, GraphQLFieldRecord] = {}
        arguments: dict[str, GraphQLArgumentRecord] = {}
        operations: list[GraphQLOperationRecord] = []
        variables: list[GraphQLVariableRecord] = []
        parameters: dict[str, Parameter] = {}
        root_field_ids: dict[GraphQLRootRole, set[str]] = {}
        root_type_ids: dict[GraphQLRootRole, str] = {}
        auth = GraphQLAuthorizationSemantics(
            observations=(GraphQLAuthorizationObservation.unknown,),
            identity_references=(
                (str(observation.identity_id),)
                if getattr(observation, "identity_id", None)
                else ()
            ),
            evidence_references=evidence_refs,
            provenance_id=provenance.provenance_id,
        )
        auth_requirement = authentication_requirement
        for parsed_operation in parsed.operations:
            role = GraphQLRootRole(parsed_operation.operation_type.value)
            root_name = role.value.title()
            type_id = graphql_semantic_id(
                "type", semantic_surface.graphql_surface_id, root_name
            )
            root_type_ids[role] = type_id
            root_field_ids.setdefault(role, set())
            variable_by_name = {item.name: item for item in parsed_operation.variables}
            operation_key = (
                parsed_operation.operation_name
                or parsed_operation.selection_fingerprint
            )
            operation_id = graphql_semantic_id(
                "operation",
                semantic_surface.graphql_surface_id,
                parsed_operation.operation_type.value,
                operation_key,
            )
            operation_variable_ids: list[str] = []
            linked: dict[str, set[str]] = {}
            operation_root_ids: set[str] = set()
            for selection in _concrete_root_selections(parsed_operation.selections):
                field_id = graphql_semantic_id("field", type_id, selection.field_name)
                root_field_ids[role].add(field_id)
                operation_root_ids.add(field_id)
                argument_ids: list[str] = []
                for parsed_argument in selection.arguments:
                    argument_id = graphql_semantic_id(
                        "argument", field_id, parsed_argument.name
                    )
                    argument_ids.append(argument_id)
                    variable_definition = variable_by_name.get(
                        parsed_argument.variable_name or ""
                    )
                    input_type = (
                        variable_definition.input_type
                        if variable_definition is not None
                        else GraphQLTypeReference.from_syntax(
                            "String", unresolved_external=True
                        )
                    )
                    role_value = _semantic_role(parsed_argument.name)
                    parameter_id = (
                        stable_research_identifier(
                            "parameter",
                            endpoint.endpoint_id,
                            "graphql",
                            parsed_argument.variable_name,
                        )
                        if parsed_argument.variable_name
                        else None
                    )
                    arguments[argument_id] = GraphQLArgumentRecord(
                        argument_id=argument_id,
                        field_id=field_id,
                        name=parsed_argument.name,
                        input_type=input_type,
                        nullable=input_type.nullable,
                        list_depth=input_type.list_depth,
                        default_presence=(
                            variable_definition.default_present
                            if variable_definition is not None
                            else False
                        ),
                        semantic_role=role_value,
                        semantic_role_evidence_references=(
                            evidence_refs
                            if role_value is not GraphQLSemanticRole.unknown
                            else ()
                        ),
                        parameter_id=parameter_id,
                        evidence_references=evidence_refs,
                        provenance_id=provenance.provenance_id,
                    )
                    if parsed_argument.variable_name:
                        linked.setdefault(parsed_argument.variable_name, set()).add(
                            argument_id
                        )
                unknown = GraphQLTypeReference.from_syntax(
                    "Unknown", unresolved_external=True
                )
                field = GraphQLFieldRecord(
                    field_id=field_id,
                    type_id=type_id,
                    name=selection.field_name,
                    return_type=unknown,
                    return_shape=GraphQLReturnShape.unknown,
                    nullable=True,
                    list_depth=0,
                    argument_ids=tuple(argument_ids),
                    authorization_semantics=auth,
                    evidence_references=evidence_refs,
                    provenance_id=provenance.provenance_id,
                )
                prior_field = fields.get(field_id)
                fields[field_id] = (
                    field
                    if prior_field is None
                    else prior_field.model_copy(
                        update={
                            "argument_ids": tuple(
                                sorted(
                                    {
                                        *prior_field.argument_ids,
                                        *field.argument_ids,
                                    }
                                )
                            )
                        }
                    )
                )
            for parsed_variable in parsed_operation.variables:
                variable_id = graphql_semantic_id(
                    "variable", operation_id, parsed_variable.name
                )
                operation_variable_ids.append(variable_id)
                role_value = _semantic_role(parsed_variable.name)
                variables.append(
                    GraphQLVariableRecord(
                        variable_id=variable_id,
                        operation_id=operation_id,
                        name=parsed_variable.name,
                        input_type=parsed_variable.input_type,
                        nullable=parsed_variable.input_type.nullable,
                        list_depth=parsed_variable.input_type.list_depth,
                        semantic_role=role_value,
                        semantic_role_evidence_references=(
                            evidence_refs
                            if role_value is not GraphQLSemanticRole.unknown
                            else ()
                        ),
                        linked_argument_id=(
                            next(iter(linked[parsed_variable.name]))
                            if len(linked.get(parsed_variable.name, ())) == 1
                            else None
                        ),
                        evidence_references=evidence_refs,
                        provenance_id=provenance.provenance_id,
                    )
                )
                parameter_id = stable_research_identifier(
                    "parameter", endpoint.endpoint_id, "graphql", parsed_variable.name
                )
                parameters[parameter_id] = Parameter(
                    parameter_id=parameter_id,
                    endpoint_id=endpoint.endpoint_id,
                    name=parsed_variable.name,
                    location=ParameterLocation.graphql_variable,
                    data_type=opaque_reference(
                        parsed_variable.input_type.to_syntax(), "graphql-type"
                    ),
                    required=not parsed_variable.input_type.nullable,
                    evidence_references=evidence_refs,
                    provenance_id=provenance.provenance_id,
                )
            operation_roots = tuple(sorted(operation_root_ids))
            if not operation_roots:
                raise GraphQLDocumentError("operation has no concrete root fields")
            operations.append(
                GraphQLOperationRecord(
                    operation_id=operation_id,
                    graphql_surface_id=semantic_surface.graphql_surface_id,
                    operation_type=parsed_operation.operation_type,
                    operation_name=parsed_operation.operation_name,
                    root_field_ids=operation_roots,
                    variable_ids=tuple(operation_variable_ids),
                    selection_fingerprint=parsed_operation.selection_fingerprint,
                    document_fingerprint=digest_for(
                        parsed_operation.model_dump(mode="json")
                    ),
                    authentication_requirement=auth_requirement,
                    state_change_class=(
                        GraphQLStateChangeClass.read_only
                        if parsed_operation.operation_type is GraphQLOperationType.query
                        else GraphQLStateChangeClass.potential_state_change
                    ),
                    evidence_references=evidence_refs,
                    provenance_id=provenance.provenance_id,
                )
            )
        for role, type_id in root_type_ids.items():
            types[type_id] = GraphQLTypeRecord(
                type_id=type_id,
                graphql_surface_id=semantic_surface.graphql_surface_id,
                name=role.value.title(),
                kind=GraphQLTypeKind.object,
                root_role=role,
                field_ids=tuple(sorted(root_field_ids[role])),
                evidence_references=evidence_refs,
                provenance_id=provenance.provenance_id,
            )
        trace_type = (
            "GRAPHQL_CAPTURE"
            if str(getattr(observation, "source_kind", ""))
            in {"capture", "browser_capture", "graphql_document"}
            else "GRAPHQL_SEMANTIC_UPDATE"
        )
        auth_observation = _auth_error_observation(
            response=response,
            target_id=str(observation.target_id),
            surface_id=surface.surface_id,
            evidence_references=evidence_refs,
            provenance_id=provenance.provenance_id,
        )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            parameters=tuple(parameters[key] for key in sorted(parameters)),
            graphql_surfaces=(semantic_surface,),
            types=tuple(types[key] for key in sorted(types)),
            fields=tuple(fields[key] for key in sorted(fields)),
            arguments=tuple(arguments[key] for key in sorted(arguments)),
            operations=tuple(operations),
            variables=tuple(variables),
            auth_observations=(auth_observation,) if auth_observation else (),
            evidence=tuple(evidence_items),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type=trace_type,
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=evidence_refs,
                ),
            ),
        )

    def from_introspection(
        self,
        state: ResearchState,
        observation: Any,
        payload: Mapping[str, Any],
        *,
        occurred_at: str | None = None,
        max_types: int = MAX_GRAPHQL_TYPES_PER_SURFACE,
        max_fields: int = MAX_GRAPHQL_FIELDS,
        max_arguments: int = MAX_GRAPHQL_ARGUMENTS,
    ) -> GraphQLSemanticDelta:
        """Map an already obtained, bounded introspection response into P4-1A."""

        schema = payload.get("data", payload)
        if isinstance(schema, Mapping):
            schema = schema.get("__schema", schema)
        if not isinstance(schema, Mapping) or not isinstance(schema.get("types"), list):
            raise GraphQLDocumentError("no GraphQL introspection schema was present")
        if not 1 <= max_types <= MAX_GRAPHQL_TYPES_PER_SURFACE:
            raise ValueError("GraphQL type ceiling is outside the supported range")
        if not 1 <= max_fields <= MAX_GRAPHQL_FIELDS:
            raise ValueError("GraphQL field ceiling is outside the supported range")
        if not 1 <= max_arguments <= MAX_GRAPHQL_ARGUMENTS:
            raise ValueError("GraphQL argument ceiling is outside the supported range")
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        roots: dict[str, GraphQLRootRole] = {}
        for key, role in (
            ("queryType", GraphQLRootRole.query),
            ("mutationType", GraphQLRootRole.mutation),
            ("subscriptionType", GraphQLRootRole.subscription),
        ):
            value = schema.get(key)
            if isinstance(value, Mapping) and isinstance(value.get("name"), str):
                roots[str(value["name"])] = role
        capabilities = tuple(
            GraphQLOperationType(role.value) for role in roots.values()
        )
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.graphql_introspection_result,
            summary=(
                "A policy-authorized bounded GraphQL introspection structure was "
                "observed; introspection availability is not a finding."
            ),
            schema_state=GraphQLSchemaState.introspection_observed,
            capabilities=capabilities,
        )
        raw_types: list[Mapping[str, Any]] = []
        schema_types = schema["types"]
        truncated = len(schema_types) > max_types
        for item in schema_types[:max_types]:
            if (
                not isinstance(item, Mapping)
                or not isinstance(item.get("name"), str)
                or str(item["name"]).startswith("__")
                or _type_kind(str(item.get("kind") or "")) is None
            ):
                continue
            raw_types.append(item)
        type_ids = {
            str(item["name"]): graphql_semantic_id(
                "type", semantic_surface.graphql_surface_id, str(item["name"])
            )
            for item in raw_types
        }
        kind_by_name = {
            str(item["name"]): _type_kind(str(item.get("kind") or ""))
            for item in raw_types
        }
        field_records: dict[str, GraphQLFieldRecord] = {}
        argument_records: dict[str, GraphQLArgumentRecord] = {}
        field_ids_by_type: dict[str, list[str]] = {name: [] for name in type_ids}
        auth = GraphQLAuthorizationSemantics(
            observations=(GraphQLAuthorizationObservation.unknown,),
            identity_references=(
                (str(observation.identity_id),)
                if getattr(observation, "identity_id", None)
                else ()
            ),
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        field_count = argument_count = 0
        for type_item in raw_types:
            type_name = str(type_item["name"])
            owner_id = type_ids[type_name]
            raw_fields = type_item.get("fields")
            if not isinstance(raw_fields, list):
                raw_fields = []
            field_scan_limit = min(
                MAX_GRAPHQL_FIELDS_PER_TYPE,
                max(0, max_fields - field_count),
            )
            if len(raw_fields) > field_scan_limit:
                truncated = True
            for field_item in raw_fields[:field_scan_limit]:
                if not isinstance(field_item, Mapping) or not isinstance(
                    field_item.get("name"), str
                ):
                    continue
                field_name = str(field_item["name"])
                field_id = graphql_semantic_id("field", owner_id, field_name)
                field_count += 1
                argument_ids: list[str] = []
                raw_field_arguments = field_item.get("args")
                if not isinstance(raw_field_arguments, list):
                    raw_field_arguments = []
                argument_scan_limit = min(
                    MAX_GRAPHQL_ARGUMENTS_PER_FIELD,
                    max(0, max_arguments - argument_count),
                )
                if len(raw_field_arguments) > argument_scan_limit:
                    truncated = True
                for argument_item in raw_field_arguments[:argument_scan_limit]:
                    if not isinstance(argument_item, Mapping) or not isinstance(
                        argument_item.get("name"), str
                    ):
                        continue
                    argument_name = str(argument_item["name"])
                    input_ref = _introspection_type_ref(argument_item.get("type"))
                    if input_ref.named_type not in type_ids:
                        input_ref = input_ref.model_copy(
                            update={"unresolved_external": True}
                        )
                    argument_id = graphql_semantic_id(
                        "argument", field_id, argument_name
                    )
                    role_value = _semantic_role(argument_name)
                    argument_records[argument_id] = GraphQLArgumentRecord(
                        argument_id=argument_id,
                        field_id=field_id,
                        name=argument_name,
                        input_type=input_ref,
                        nullable=input_ref.nullable,
                        list_depth=input_ref.list_depth,
                        default_presence=argument_item.get("defaultValue") is not None,
                        semantic_role=role_value,
                        semantic_role_evidence_references=(
                            (evidence.evidence_id,)
                            if role_value is not GraphQLSemanticRole.unknown
                            else ()
                        ),
                        evidence_references=(evidence.evidence_id,),
                        provenance_id=provenance.provenance_id,
                    )
                    argument_ids.append(argument_id)
                    argument_count += 1
                return_ref = _introspection_type_ref(field_item.get("type"))
                if return_ref.named_type not in type_ids:
                    return_ref = return_ref.model_copy(
                        update={"unresolved_external": True}
                    )
                field_records[field_id] = GraphQLFieldRecord(
                    field_id=field_id,
                    type_id=owner_id,
                    name=field_name,
                    return_type=return_ref,
                    return_shape=_return_shape(kind_by_name.get(return_ref.named_type)),
                    nullable=return_ref.nullable,
                    list_depth=return_ref.list_depth,
                    argument_ids=tuple(argument_ids),
                    authorization_semantics=auth,
                    evidence_references=(evidence.evidence_id,),
                    provenance_id=provenance.provenance_id,
                )
                field_ids_by_type[type_name].append(field_id)
        types: list[GraphQLTypeRecord] = []
        for item in raw_types:
            name = str(item["name"])
            kind = kind_by_name[name]
            assert kind is not None
            raw_possible_types = item.get("possibleTypes")
            if not isinstance(raw_possible_types, list):
                raw_possible_types = []
            raw_interfaces = item.get("interfaces")
            if not isinstance(raw_interfaces, list):
                raw_interfaces = []
            if (
                len(raw_possible_types) > MAX_GRAPHQL_POSSIBLE_TYPES
                or len(raw_interfaces) > MAX_GRAPHQL_POSSIBLE_TYPES
            ):
                truncated = True
            possible_ids = tuple(
                sorted(
                    type_ids[str(value["name"])]
                    for value in raw_possible_types[:MAX_GRAPHQL_POSSIBLE_TYPES]
                    if isinstance(value, Mapping)
                    and str(value.get("name") or "") in type_ids
                    and kind_by_name.get(str(value.get("name")))
                    is GraphQLTypeKind.object
                )
            )
            interface_ids = tuple(
                sorted(
                    type_ids[str(value["name"])]
                    for value in raw_interfaces[:MAX_GRAPHQL_POSSIBLE_TYPES]
                    if isinstance(value, Mapping)
                    and str(value.get("name") or "") in type_ids
                    and kind_by_name.get(str(value.get("name")))
                    is GraphQLTypeKind.interface
                )
            )
            types.append(
                GraphQLTypeRecord(
                    type_id=type_ids[name],
                    graphql_surface_id=semantic_surface.graphql_surface_id,
                    name=name,
                    kind=kind,
                    root_role=roots.get(name),
                    field_ids=tuple(sorted(field_ids_by_type[name])),
                    possible_type_ids=possible_ids,
                    interface_ids=interface_ids,
                    evidence_references=(evidence.evidence_id,),
                    provenance_id=provenance.provenance_id,
                )
            )
        if truncated:
            evidence = evidence.model_copy(
                update={
                    "summary": (
                        "A bounded GraphQL introspection structure was observed and "
                        "truncated at a configured semantic ceiling; schema completeness "
                        "was not asserted."
                    )
                }
            )
            semantic_surface = semantic_surface.model_copy(
                update={"schema_state": GraphQLSchemaState.partial}
            )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            graphql_surfaces=(semantic_surface,),
            types=tuple(types),
            fields=tuple(field_records[key] for key in sorted(field_records)),
            arguments=tuple(argument_records[key] for key in sorted(argument_records)),
            evidence=(evidence,),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type="GRAPHQL_INTROSPECTION",
                    subject_reference=semantic_surface.graphql_surface_id,
                    evidence_references=(evidence.evidence_id,),
                ),
            ),
        )

    def controlled_object(
        self,
        state: ResearchState,
        observation: Any,
        controlled: GraphQLControlledObjectEvidence,
        *,
        occurred_at: str | None = None,
    ) -> GraphQLSemanticDelta:
        """Acquire one explicitly owner-scoped object; never enumerate identifiers."""

        reject_secret_material(
            controlled.model_dump(mode="json"), location="GraphQL controlled object"
        )
        identity = next(
            (
                item
                for item in state.identities
                if item.identity_id == controlled.identity_id
            ),
            None,
        )
        if (
            identity is None
            or not identity.controlled
            or identity.eligibility.value != "eligible"
        ):
            raise GraphQLDocumentError(
                "controlled GraphQL object requires an eligible controlled identity"
            )
        if str(getattr(observation, "identity_id", "")) != controlled.identity_id:
            raise GraphQLDocumentError(
                "controlled GraphQL object identity does not match the observation"
            )
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        surface, endpoint, semantic_surface, evidence, provenance = self._foundation(
            state,
            observation,
            occurred_at=timestamp,
            evidence_kind=EvidenceKind.controlled_account_observation,
            summary=(
                "A controlled identity received its own GraphQL resource with "
                "deterministic ownership evidence; response values were excluded."
            ),
            schema_state=GraphQLSchemaState.partial,
        )
        ownership_reference = opaque_reference(
            controlled.evidence_reference, "graphql-ownership"
        )
        evidence = evidence.model_copy(
            update={
                "digest": digest_for(
                    {
                        "identity_id": controlled.identity_id,
                        "object_type": opaque_reference(
                            controlled.object_type, "object-type"
                        ),
                        "object_reference": opaque_reference(
                            controlled.object_reference, "object-reference"
                        ),
                        "ownership_basis": controlled.ownership_basis,
                        "graphql_type_name": controlled.graphql_type_name,
                        "existing_object_id": controlled.existing_object_id,
                        "evidence_reference": ownership_reference,
                    }
                ),
                "source_reference": ownership_reference,
            }
        )
        provenance = provenance.model_copy(
            update={
                "source_references": tuple(
                    sorted({*provenance.source_references, ownership_reference})
                )
            }
        )
        object_id = stable_research_identifier(
            "object",
            state.research_id,
            controlled.identity_id,
            controlled.object_type,
            controlled.object_reference,
        )
        research_object = ResearchObject(
            object_id=object_id,
            target_id=str(observation.target_id),
            surface_id=surface.surface_id,
            object_type=opaque_reference(controlled.object_type, "object-type"),
            object_reference=opaque_reference(
                controlled.object_reference, "object-reference"
            ),
            owner_identity_id=controlled.identity_id,
            test_owned=True,
            evidence_references=(evidence.evidence_id,),
            provenance_id=provenance.provenance_id,
        )
        relationships: list[GraphAssertion] = []
        cross: list[GraphAssertion] = []
        if controlled.graphql_type_name:
            type_id = graphql_semantic_id(
                "type",
                semantic_surface.graphql_surface_id,
                controlled.graphql_type_name,
            )
            if any(item.type_id == type_id for item in state.graphql_types):
                relationships.append(
                    GraphAssertion(
                        assertion_id=graphql_semantic_id(
                            "edge",
                            type_id,
                            ResearchPredicate.references_same_object.value,
                            object_id,
                        ),
                        research_id=state.research_id,
                        source=EntityReference(
                            entity_kind=EntityKind.graphql_type, entity_id=type_id
                        ),
                        relation=ResearchPredicate.references_same_object,
                        target=EntityReference(
                            entity_kind=EntityKind.object, entity_id=object_id
                        ),
                        status=RelationshipStatus.observed,
                        evidence_references=(evidence.evidence_id,),
                        derivation_type=DerivationType.deterministic,
                        provenance_id=provenance.provenance_id,
                        asserted_at=timestamp,
                    )
                )
        if controlled.existing_object_id:
            safe_object_reference = opaque_reference(
                controlled.object_reference, "object-reference"
            )
            existing = next(
                (
                    item
                    for item in state.objects
                    if item.object_id == controlled.existing_object_id
                    and item.object_id != object_id
                    and item.target_id == str(observation.target_id)
                    and item.surface_id != surface.surface_id
                    and any(
                        candidate.surface_id == item.surface_id
                        and candidate.surface_type is not SurfaceType.graphql
                        for candidate in state.surfaces
                    )
                    and item.owner_identity_id == controlled.identity_id
                    and item.test_owned
                    and item.object_reference == safe_object_reference
                ),
                None,
            )
            if existing is not None:
                cross.append(
                    GraphAssertion(
                        assertion_id=graphql_semantic_id(
                            "edge",
                            object_id,
                            ResearchPredicate.references_same_object.value,
                            existing.object_id,
                        ),
                        research_id=state.research_id,
                        source=EntityReference(
                            entity_kind=EntityKind.object, entity_id=object_id
                        ),
                        relation=ResearchPredicate.references_same_object,
                        target=EntityReference(
                            entity_kind=EntityKind.object, entity_id=existing.object_id
                        ),
                        status=RelationshipStatus.observed,
                        evidence_references=(evidence.evidence_id,),
                        derivation_type=DerivationType.deterministic,
                        provenance_id=provenance.provenance_id,
                        asserted_at=timestamp,
                    )
                )
                cross.append(
                    GraphAssertion(
                        assertion_id=graphql_semantic_id(
                            "edge",
                            object_id,
                            ResearchPredicate.crosses_surface.value,
                            existing.object_id,
                        ),
                        research_id=state.research_id,
                        source=EntityReference(
                            entity_kind=EntityKind.object, entity_id=object_id
                        ),
                        relation=ResearchPredicate.crosses_surface,
                        target=EntityReference(
                            entity_kind=EntityKind.object, entity_id=existing.object_id
                        ),
                        status=RelationshipStatus.observed,
                        evidence_references=(evidence.evidence_id,),
                        derivation_type=DerivationType.deterministic,
                        provenance_id=provenance.provenance_id,
                        asserted_at=timestamp,
                    )
                )
        return GraphQLSemanticDelta(
            surfaces=(surface,),
            endpoints=(endpoint,),
            graphql_surfaces=(semantic_surface,),
            objects=(research_object,),
            object_relationships=tuple(relationships),
            cross_surface_relationships=tuple(cross),
            evidence=(evidence,),
            provenance=(provenance,),
            trace_events=(
                GraphQLTraceEvent(
                    event_type="GRAPHQL_OBJECT",
                    subject_reference=object_id,
                    evidence_references=(evidence.evidence_id,),
                ),
                *(
                    (
                        GraphQLTraceEvent(
                            event_type="GRAPHQL_CROSS_SURFACE",
                            subject_reference=object_id,
                            evidence_references=(evidence.evidence_id,),
                        ),
                    )
                    if cross
                    else ()
                ),
            ),
        )


ParsedGraphQLSelection.model_rebuild()


__all__ = [
    "GRAPHQL_INGEST_VERSION",
    "MAX_GRAPHQL_FRAGMENT_SPREAD_DEPTH",
    "MAX_GRAPHQL_FRAGMENTS",
    "MAX_GRAPHQL_RESPONSE_BYTES",
    "MAX_GRAPHQL_RESPONSE_DEPTH",
    "MAX_GRAPHQL_RESPONSE_SHAPE_NODES",
    "MAX_GRAPHQL_TOKENS",
    "GraphQLControlledObjectEvidence",
    "GraphQLDocumentError",
    "GraphQLErrorClass",
    "GraphQLErrorPathObservation",
    "GraphQLResponseEnvelope",
    "GraphQLResponseObservation",
    "GraphQLSemanticDelta",
    "GraphQLSemanticIngestor",
    "GraphQLTraceEvent",
    "ParsedGraphQLArgument",
    "ParsedGraphQLDocument",
    "ParsedGraphQLOperation",
    "ParsedGraphQLSelection",
    "ParsedGraphQLVariable",
    "analyze_graphql_response",
    "parse_graphql_document",
]
