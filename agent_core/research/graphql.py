"""Strict, execution-neutral GraphQL semantics for Phase 4 research.

This module deliberately contains no transport client, query executor, provider
adapter, or response-value persistence.  It models bounded, evidenced GraphQL
structure and produces only secret-free digests and summaries.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import (
    AfterValidator,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.research.types import (
    EndpointId,
    EntityReference,
    EvidenceArtifactId,
    GraphQLArgumentId,
    GraphQLFieldId,
    GraphQLOperationId,
    GraphQLOperationType,
    GraphQLSurfaceId,
    GraphQLTypeId,
    GraphQLVariableId,
    IdentityId,
    OpaqueIdentifier,
    ParameterId,
    ProvenanceRecordId,
    ResearchConfidence,
    ResearchContract,
    ResearchId,
    ResearchObjectId,
    ResearchPredicate,
    Sha256Digest,
    SurfaceId,
    TargetAssetId,
    WorkflowId,
)

if TYPE_CHECKING:
    from agent_core.research.graph import GraphAssertion
    from agent_core.research.state import (
        EvidenceArtifact,
        ProvenanceRecord,
        ResearchState,
    )


MAX_GRAPHQL_SURFACES = 32
MAX_GRAPHQL_TYPES_PER_SURFACE = 512
MAX_GRAPHQL_TYPES = 4_096
MAX_GRAPHQL_FIELDS_PER_TYPE = 256
MAX_GRAPHQL_FIELDS = 20_000
MAX_GRAPHQL_ARGUMENTS_PER_FIELD = 64
MAX_GRAPHQL_ARGUMENTS = 40_000
MAX_GRAPHQL_OPERATIONS = 2_000
MAX_GRAPHQL_VARIABLES_PER_OPERATION = 64
MAX_GRAPHQL_VARIABLES = 20_000
MAX_GRAPHQL_SELECTION_DEPTH = 12
MAX_GRAPHQL_SELECTION_NODES = 1_024
MAX_GRAPHQL_POSSIBLE_TYPES = 128
MAX_GRAPHQL_TYPE_WRAPPERS = 12
MAX_GRAPHQL_DOCUMENT_BYTES = 65_536
MAX_GRAPHQL_PUBLIC_PACKET_BYTES = 8_192

_GRAPHQL_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,254}$")


def normalize_graphql_name(value: str) -> str:
    """Validate a case-sensitive GraphQL name without changing its identity."""

    if _GRAPHQL_NAME.fullmatch(value) is None:
        raise ValueError("invalid GraphQL name")
    return value


GraphQLName = Annotated[
    StrictStr,
    Field(min_length=1, max_length=255),
    AfterValidator(normalize_graphql_name),
]


def _canonical_references(values: tuple[str, ...], description: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{description} must not contain duplicates")
    return tuple(sorted(values))


def _canonical_models(values: tuple[Any, ...], description: str) -> tuple[Any, ...]:
    rendered = [
        json.dumps(
            item.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        for item in values
    ]
    if len(rendered) != len(set(rendered)):
        raise ValueError(f"{description} must not contain duplicates")
    return tuple(
        item for _, item in sorted(zip(rendered, values), key=lambda pair: pair[0])
    )


class GraphQLLimitExceeded(ValueError):
    """Raised when bounded GraphQL semantics cannot be represented safely."""


class GraphQLSemanticConflict(ValueError):
    """Raised instead of silently replacing incompatible semantic facts."""


class GraphQLPublicPacketTooLarge(GraphQLLimitExceeded):
    """Raised when a public-safe packet exceeds its explicit byte budget."""


class GraphQLTransport(str, Enum):
    http = "http"
    https = "https"


class GraphQLSchemaState(str, Enum):
    unknown = "unknown"
    partial = "partial"
    introspection_observed = "introspection_observed"
    capture_derived = "capture_derived"
    document_derived = "document_derived"
    merged = "merged"


class GraphQLEvidenceOrigin(str, Enum):
    introspection_result = "introspection_result"
    captured_request = "captured_request"
    captured_response = "captured_response"
    openapi_rest_cross_reference = "openapi_rest_cross_reference"
    browser_capture = "browser_capture"
    graphql_document = "graphql_document"
    deterministic_discovery_observation = "deterministic_discovery_observation"
    controlled_account_observation = "controlled_account_observation"


class GraphQLTypeKind(str, Enum):
    scalar = "scalar"
    object = "object"
    interface = "interface"
    union = "union"
    enum = "enum"
    input_object = "input_object"


class GraphQLRootRole(str, Enum):
    query = "query"
    mutation = "mutation"
    subscription = "subscription"


class GraphQLAuthenticationRequirement(str, Enum):
    unknown = "unknown"
    anonymous_observed = "anonymous_observed"
    authenticated_observed = "authenticated_observed"
    authentication_required = "authentication_required"
    role_bound = "role_bound"
    tenant_bound = "tenant_bound"


class GraphQLAuthorizationObservation(str, Enum):
    unknown = "unknown"
    identity_dependent_field_visibility = "identity_dependent_field_visibility"
    identity_dependent_object_access = "identity_dependent_object_access"
    role_dependent_operation_behavior = "role_dependent_operation_behavior"
    tenant_dependent_object_access = "tenant_dependent_object_access"
    ownership_sensitive_access = "ownership_sensitive_access"


class GraphQLSemanticRole(str, Enum):
    identifier = "identifier"
    pagination = "pagination"
    filter = "filter"
    search = "search"
    ordering = "ordering"
    tenant_reference = "tenant_reference"
    user_reference = "user_reference"
    object_reference = "object_reference"
    workflow_input = "workflow_input"
    unknown = "unknown"


class GraphQLReturnShape(str, Enum):
    scalar = "scalar"
    object = "object"
    interface = "interface"
    union = "union"
    enum = "enum"
    input_object = "input_object"
    unknown = "unknown"


class GraphQLRelationshipKind(str, Enum):
    returns_object = "returns_object"
    returns_collection = "returns_collection"
    traverses_object = "traverses_object"
    references_object = "references_object"


class GraphQLObjectReferenceKind(str, Enum):
    unknown = "unknown"
    graphql_type = "graphql_type"
    research_object = "research_object"
    external_unresolved = "external_unresolved"


class GraphQLStateChangeClass(str, Enum):
    unknown = "unknown"
    read_only = "read_only"
    potential_state_change = "potential_state_change"
    state_change_observed = "state_change_observed"


class GraphQLTypeWrapper(str, Enum):
    non_null = "non_null"
    list = "list"


class GraphQLTypeReference(ResearchContract):
    """A bounded structural type reference; wrappers run inner-to-outer."""

    named_type: GraphQLName
    wrappers: tuple[GraphQLTypeWrapper, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_TYPE_WRAPPERS
    )
    unresolved_external: StrictBool = False

    @model_validator(mode="after")
    def validate_wrappers(self) -> "GraphQLTypeReference":
        for inner, outer in zip(self.wrappers, self.wrappers[1:]):
            if inner is outer is GraphQLTypeWrapper.non_null:
                raise ValueError("a GraphQL non-null wrapper cannot wrap non-null")
        return self

    @property
    def list_depth(self) -> int:
        return sum(item is GraphQLTypeWrapper.list for item in self.wrappers)

    @property
    def nullable(self) -> bool:
        return not self.wrappers or self.wrappers[-1] is not GraphQLTypeWrapper.non_null

    def to_syntax(self) -> str:
        rendered = self.named_type
        for wrapper in self.wrappers:
            if wrapper is GraphQLTypeWrapper.list:
                rendered = f"[{rendered}]"
            else:
                rendered = f"{rendered}!"
        return rendered

    @classmethod
    def from_syntax(
        cls, value: str, *, unresolved_external: bool = False
    ) -> "GraphQLTypeReference":
        compact = "".join(value.split())
        if not compact:
            raise ValueError("GraphQL type reference is empty")

        def parse(index: int) -> tuple[str, list[GraphQLTypeWrapper], int]:
            wrappers: list[GraphQLTypeWrapper] = []
            if index < len(compact) and compact[index] == "[":
                name, wrappers, index = parse(index + 1)
                if index >= len(compact) or compact[index] != "]":
                    raise ValueError("unbalanced GraphQL list type")
                wrappers.append(GraphQLTypeWrapper.list)
                index += 1
            else:
                match = re.match(r"[_A-Za-z][_0-9A-Za-z]*", compact[index:])
                if match is None:
                    raise ValueError("invalid GraphQL named type")
                name = match.group(0)
                index += len(name)
            if index < len(compact) and compact[index] == "!":
                wrappers.append(GraphQLTypeWrapper.non_null)
                index += 1
            return name, wrappers, index

        named_type, wrappers, end = parse(0)
        if end != len(compact):
            raise ValueError("invalid trailing GraphQL type syntax")
        return cls(
            named_type=named_type,
            wrappers=tuple(wrappers),
            unresolved_external=unresolved_external,
        )


class GraphQLAuthorizationSemantics(ResearchContract):
    observations: tuple[GraphQLAuthorizationObservation, ...] = Field(
        min_length=1, max_length=8
    )
    identity_references: tuple[IdentityId, ...] = Field(default=(), max_length=32)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def canonicalize(self) -> "GraphQLAuthorizationSemantics":
        observations = tuple(
            sorted(set(self.observations), key=lambda item: item.value)
        )
        if len(observations) != len(self.observations):
            raise ValueError("authorization observations must not contain duplicates")
        if (
            GraphQLAuthorizationObservation.unknown in observations
            and len(observations) > 1
        ):
            raise ValueError(
                "unknown authorization semantics cannot accompany observations"
            )
        object.__setattr__(self, "observations", observations)
        object.__setattr__(
            self,
            "identity_references",
            _canonical_references(self.identity_references, "identity references"),
        )
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "authorization evidence"),
        )
        return self


class GraphQLObjectReferenceSemantics(ResearchContract):
    kind: GraphQLObjectReferenceKind = GraphQLObjectReferenceKind.unknown
    graphql_type_id: GraphQLTypeId | None = None
    research_object_id: ResearchObjectId | None = None
    confidence: ResearchConfidence = ResearchConfidence.low

    @model_validator(mode="after")
    def validate_reference(self) -> "GraphQLObjectReferenceSemantics":
        if self.kind is GraphQLObjectReferenceKind.graphql_type:
            if self.graphql_type_id is None or self.research_object_id is not None:
                raise ValueError("GraphQL type semantics require only graphql_type_id")
        elif self.kind is GraphQLObjectReferenceKind.research_object:
            if self.research_object_id is None:
                raise ValueError("research object semantics require research_object_id")
        elif self.graphql_type_id is not None or self.research_object_id is not None:
            raise ValueError("unknown/external object semantics cannot carry local IDs")
        return self


class GraphQLRelationshipHint(ResearchContract):
    kind: GraphQLRelationshipKind
    graphql_type_id: GraphQLTypeId | None = None
    research_object_id: ResearchObjectId | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )

    @model_validator(mode="after")
    def validate_hint(self) -> "GraphQLRelationshipHint":
        if self.graphql_type_id is None and self.research_object_id is None:
            raise ValueError("relationship hint requires a referenced type or object")
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "relationship evidence"),
        )
        return self


class GraphQLSurface(ResearchContract):
    graphql_surface_id: GraphQLSurfaceId
    research_id: ResearchId
    target_id: TargetAssetId
    surface_id: SurfaceId
    endpoint_id: EndpointId
    transport: GraphQLTransport
    schema_state: GraphQLSchemaState = GraphQLSchemaState.unknown
    operation_capabilities: tuple[GraphQLOperationType, ...] = Field(
        default=(), max_length=3
    )
    authentication_requirement: GraphQLAuthenticationRequirement = (
        GraphQLAuthenticationRequirement.unknown
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def canonicalize(self) -> "GraphQLSurface":
        capabilities = tuple(
            sorted(set(self.operation_capabilities), key=lambda item: item.value)
        )
        if len(capabilities) != len(self.operation_capabilities):
            raise ValueError("operation capabilities must not contain duplicates")
        object.__setattr__(self, "operation_capabilities", capabilities)
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "GraphQL surface evidence"),
        )
        return self


class GraphQLTypeRecord(ResearchContract):
    type_id: GraphQLTypeId
    graphql_surface_id: GraphQLSurfaceId
    name: GraphQLName
    kind: GraphQLTypeKind
    root_role: GraphQLRootRole | None = None
    field_ids: tuple[GraphQLFieldId, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_FIELDS_PER_TYPE
    )
    possible_type_ids: tuple[GraphQLTypeId, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_POSSIBLE_TYPES
    )
    interface_ids: tuple[GraphQLTypeId, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_POSSIBLE_TYPES
    )
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_type(self) -> "GraphQLTypeRecord":
        if self.root_role is not None and self.kind is not GraphQLTypeKind.object:
            raise ValueError("only object types may have a root role")
        if self.kind not in {GraphQLTypeKind.interface, GraphQLTypeKind.union} and (
            self.possible_type_ids
        ):
            raise ValueError("only interfaces and unions may name possible types")
        if self.kind is not GraphQLTypeKind.object and self.interface_ids:
            raise ValueError("only object types may implement interfaces")
        for field_name in (
            "field_ids",
            "possible_type_ids",
            "interface_ids",
            "evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        if self.type_id in self.possible_type_ids or self.type_id in self.interface_ids:
            raise ValueError("a GraphQL type cannot reference itself structurally")
        return self


class GraphQLFieldRecord(ResearchContract):
    field_id: GraphQLFieldId
    type_id: GraphQLTypeId
    name: GraphQLName
    return_type: GraphQLTypeReference
    return_shape: GraphQLReturnShape
    nullable: StrictBool
    list_depth: StrictInt = Field(ge=0, le=MAX_GRAPHQL_TYPE_WRAPPERS)
    argument_ids: tuple[GraphQLArgumentId, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_ARGUMENTS_PER_FIELD
    )
    relationship_hints: tuple[GraphQLRelationshipHint, ...] = Field(
        default=(), max_length=32
    )
    authorization_semantics: GraphQLAuthorizationSemantics
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_field(self) -> "GraphQLFieldRecord":
        if self.nullable != self.return_type.nullable:
            raise ValueError(
                "field nullable flag conflicts with structural return type"
            )
        if self.list_depth != self.return_type.list_depth:
            raise ValueError("field list_depth conflicts with structural return type")
        object.__setattr__(
            self,
            "argument_ids",
            _canonical_references(self.argument_ids, "field argument IDs"),
        )
        object.__setattr__(
            self,
            "relationship_hints",
            _canonical_models(self.relationship_hints, "relationship hints"),
        )
        object.__setattr__(
            self,
            "evidence_references",
            _canonical_references(self.evidence_references, "field evidence"),
        )
        return self


class GraphQLArgumentRecord(ResearchContract):
    argument_id: GraphQLArgumentId
    field_id: GraphQLFieldId
    name: GraphQLName
    input_type: GraphQLTypeReference
    nullable: StrictBool
    list_depth: StrictInt = Field(ge=0, le=MAX_GRAPHQL_TYPE_WRAPPERS)
    default_presence: StrictBool
    semantic_role: GraphQLSemanticRole = GraphQLSemanticRole.unknown
    semantic_role_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    object_reference_semantics: GraphQLObjectReferenceSemantics = Field(
        default_factory=GraphQLObjectReferenceSemantics
    )
    parameter_id: ParameterId | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_argument(self) -> "GraphQLArgumentRecord":
        if self.nullable != self.input_type.nullable:
            raise ValueError(
                "argument nullable flag conflicts with structural input type"
            )
        if self.list_depth != self.input_type.list_depth:
            raise ValueError("argument list_depth conflicts with structural input type")
        if (
            self.semantic_role is not GraphQLSemanticRole.unknown
            and not self.semantic_role_evidence_references
        ):
            raise ValueError("a classified argument role requires supporting evidence")
        for field_name in (
            "semantic_role_evidence_references",
            "evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        return self


class GraphQLOperationRecord(ResearchContract):
    operation_id: GraphQLOperationId
    graphql_surface_id: GraphQLSurfaceId
    operation_type: GraphQLOperationType
    operation_name: GraphQLName | None = None
    root_field_ids: tuple[GraphQLFieldId, ...] = Field(min_length=1, max_length=100)
    variable_ids: tuple[GraphQLVariableId, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_VARIABLES_PER_OPERATION
    )
    selection_fingerprint: Sha256Digest
    authentication_requirement: GraphQLAuthenticationRequirement = (
        GraphQLAuthenticationRequirement.unknown
    )
    state_change_class: GraphQLStateChangeClass = GraphQLStateChangeClass.unknown
    workflow_id: WorkflowId | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @model_validator(mode="after")
    def validate_operation(self) -> "GraphQLOperationRecord":
        for field_name in ("root_field_ids", "variable_ids", "evidence_references"):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        if (
            self.operation_type is GraphQLOperationType.query
            and self.state_change_class
            in {
                GraphQLStateChangeClass.potential_state_change,
                GraphQLStateChangeClass.state_change_observed,
            }
        ):
            raise ValueError("query operations cannot be classified as state-changing")
        return self


class GraphQLVariableRecord(ResearchContract):
    variable_id: GraphQLVariableId
    operation_id: GraphQLOperationId
    name: GraphQLName
    input_type: GraphQLTypeReference
    nullable: StrictBool
    list_depth: StrictInt = Field(ge=0, le=MAX_GRAPHQL_TYPE_WRAPPERS)
    semantic_role: GraphQLSemanticRole = GraphQLSemanticRole.unknown
    semantic_role_evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=100
    )
    linked_argument_id: GraphQLArgumentId | None = None
    controlled_value_reference: OpaqueIdentifier | None = None
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_id: ProvenanceRecordId

    @field_validator("controlled_value_reference")
    @classmethod
    def validate_controlled_value_reference(cls, value: str | None) -> str | None:
        if value is not None:
            # Imported lazily because provenance uses the state contracts that
            # import this module. The shared detector remains authoritative.
            from agent_core.research.provenance import reject_secret_material

            reject_secret_material(value, location="GraphQL controlled-value reference")
        return value

    @model_validator(mode="after")
    def validate_variable(self) -> "GraphQLVariableRecord":
        if self.nullable != self.input_type.nullable:
            raise ValueError(
                "variable nullable flag conflicts with structural input type"
            )
        if self.list_depth != self.input_type.list_depth:
            raise ValueError("variable list_depth conflicts with structural input type")
        if (
            self.semantic_role is not GraphQLSemanticRole.unknown
            and not self.semantic_role_evidence_references
        ):
            raise ValueError("a classified variable role requires supporting evidence")
        for field_name in (
            "semantic_role_evidence_references",
            "evidence_references",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_references(getattr(self, field_name), field_name),
            )
        return self


def graphql_semantic_id(kind: str, *components: str) -> str:
    """Return an idempotent opaque ID from public structural components."""

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", kind):
        raise ValueError("invalid GraphQL semantic ID kind")
    encoded = json.dumps(
        [kind, *components], separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return f"graphql-{kind}-{hashlib.sha256(encoded).hexdigest()[:24]}"


_TOKEN = re.compile(
    r"""(?:\s+|\#[^\r\n]*)|(?P<spread>\.\.\.)|(?P<block>\"\"\"(?:.|\n|\r)*?\"\"\")|(?P<string>\"(?:\\.|[^\"\\])*\")|(?P<number>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)|(?P<name>[_A-Za-z][_0-9A-Za-z]*)|(?P<punct>[!$():=@\[\]{|}&])|(?P<comma>,)""",
    re.VERBOSE,
)


def _tokenize(document: str) -> list[str]:
    if len(document.encode("utf-8")) > MAX_GRAPHQL_DOCUMENT_BYTES:
        raise GraphQLLimitExceeded("GraphQL document byte limit exceeded")
    tokens: list[str] = []
    position = 0
    while position < len(document):
        match = _TOKEN.match(document, position)
        if match is None:
            raise ValueError("unsupported GraphQL document syntax")
        position = match.end()
        kind = match.lastgroup
        if kind in {None, "comma"}:
            continue
        value = match.group(0)
        if kind in {"string", "block", "number"}:
            value = "literal:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        tokens.append(value)
    return tokens


class _SelectionNormalizer:
    def __init__(self, tokens: list[str], *, max_depth: int, max_nodes: int) -> None:
        self.tokens = tokens
        self.index = 0
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.nodes = 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def pop(self) -> str:
        value = self.peek()
        if value is None:
            raise ValueError("unexpected end of GraphQL document")
        self.index += 1
        return value

    def value(self, depth: int) -> str:
        if depth > self.max_depth:
            raise GraphQLLimitExceeded("GraphQL value depth limit exceeded")
        token = self.pop()
        if token == "$":
            return "$" + self.pop()
        if token == "[":
            values: list[str] = []
            while self.peek() != "]":
                values.append(self.value(depth + 1))
            self.pop()
            return "[" + ",".join(values) + "]"
        if token == "{":
            fields: list[str] = []
            while self.peek() != "}":
                name = self.pop()
                if self.pop() != ":":
                    raise ValueError("invalid GraphQL input object")
                fields.append(name + ":" + self.value(depth + 1))
            self.pop()
            return "{" + ",".join(sorted(fields)) + "}"
        return token

    def arguments(self, depth: int) -> str:
        if self.pop() != "(":
            raise ValueError("invalid GraphQL argument list")
        arguments: list[str] = []
        while self.peek() != ")":
            name = self.pop()
            if self.pop() != ":":
                raise ValueError("invalid GraphQL argument")
            arguments.append(name + ":" + self.value(depth + 1))
        self.pop()
        return "(" + ",".join(sorted(arguments)) + ")"

    def directives(self, depth: int) -> str:
        directives: list[str] = []
        while self.peek() == "@":
            self.pop()
            directive = "@" + self.pop()
            if self.peek() == "(":
                directive += self.arguments(depth)
            directives.append(directive)
        return "".join(directives)

    def selection_set(self, depth: int = 1) -> str:
        if depth > self.max_depth:
            raise GraphQLLimitExceeded("GraphQL selection depth limit exceeded")
        if self.pop() != "{":
            raise ValueError("GraphQL selection set must begin with '{'")
        selections: list[str] = []
        while self.peek() != "}":
            if self.peek() is None:
                raise ValueError("unbalanced GraphQL selection set")
            self.nodes += 1
            if self.nodes > self.max_nodes:
                raise GraphQLLimitExceeded("GraphQL selection node limit exceeded")
            if self.peek() == "...":
                self.pop()
                head = "..." + self.pop()
                if head == "...on":
                    head += ":" + self.pop()
                head += self.directives(depth)
                if self.peek() == "{":
                    head += self.selection_set(depth + 1)
                selections.append(head)
                continue
            name = self.pop()
            if self.peek() == ":":
                self.pop()
                name = self.pop()  # response aliases do not change field semantics
            rendered = name
            if self.peek() == "(":
                rendered += self.arguments(depth)
            rendered += self.directives(depth)
            if self.peek() == "{":
                rendered += self.selection_set(depth + 1)
            selections.append(rendered)
        self.pop()
        return "{" + ",".join(sorted(selections)) + "}"


def _normalized_operation(
    document: str,
    *,
    max_depth: int = MAX_GRAPHQL_SELECTION_DEPTH,
    max_nodes: int = MAX_GRAPHQL_SELECTION_NODES,
) -> tuple[str, str]:
    if max_depth < 1 or max_depth > MAX_GRAPHQL_SELECTION_DEPTH:
        raise ValueError("selection depth bound is outside the supported range")
    if max_nodes < 1 or max_nodes > MAX_GRAPHQL_SELECTION_NODES:
        raise ValueError("selection node bound is outside the supported range")
    tokens = _tokenize(document)
    if not tokens:
        raise ValueError("GraphQL document is empty")
    normalizer = _SelectionNormalizer(tokens, max_depth=max_depth, max_nodes=max_nodes)
    operation_type = "query"
    header: list[str] = []
    if normalizer.peek() in {"query", "mutation", "subscription"}:
        operation_type = normalizer.pop()
        if normalizer.peek() not in {"{", "(", "@", None}:
            normalizer.pop()  # operation names do not change operation structure
        while normalizer.peek() != "{":
            token = normalizer.pop()
            if token == "(":
                chunks: list[str] = []
                current: list[str] = []
                level = 1
                while level:
                    item = normalizer.pop()
                    if item in {"(", "[", "{"}:
                        level += 1
                    elif item in {
                        ")",
                        "]",
                        "}",
                    }:
                        level -= 1
                        if level == 0:
                            if current:
                                chunks.append("".join(current))
                            break
                    if level == 1 and item == "$" and current:
                        chunks.append("".join(current))
                        current = [item]
                    else:
                        current.append(item)
                header.append("(" + ",".join(sorted(chunks)) + ")")
            else:
                header.append(token)
    selection = normalizer.selection_set()
    if normalizer.peek() is not None:
        raise ValueError(
            "multiple operations or fragment definitions require separation"
        )
    return operation_type + "".join(header) + selection, selection


def normalize_graphql_selection(
    document: str,
    *,
    max_depth: int = MAX_GRAPHQL_SELECTION_DEPTH,
    max_nodes: int = MAX_GRAPHQL_SELECTION_NODES,
) -> str:
    """Return a bounded normalized selection without raw literal values."""

    return _normalized_operation(document, max_depth=max_depth, max_nodes=max_nodes)[1]


def graphql_selection_fingerprint(
    document: str,
    *,
    max_depth: int = MAX_GRAPHQL_SELECTION_DEPTH,
    max_nodes: int = MAX_GRAPHQL_SELECTION_NODES,
) -> str:
    normalized = normalize_graphql_selection(
        document, max_depth=max_depth, max_nodes=max_nodes
    )
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def graphql_operation_fingerprint(
    document: str,
    *,
    variable_values: Mapping[str, Any] | None = None,
    max_depth: int = MAX_GRAPHQL_SELECTION_DEPTH,
    max_nodes: int = MAX_GRAPHQL_SELECTION_NODES,
) -> str:
    """Fingerprint operation structure; runtime variable values are ignored."""

    del variable_values
    normalized, _ = _normalized_operation(
        document, max_depth=max_depth, max_nodes=max_nodes
    )
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _merge_schema_state(
    left: GraphQLSchemaState, right: GraphQLSchemaState
) -> GraphQLSchemaState:
    if left is right:
        return left
    if left is GraphQLSchemaState.unknown:
        return right
    if right is GraphQLSchemaState.unknown:
        return left
    if left is GraphQLSchemaState.merged or right is GraphQLSchemaState.merged:
        return GraphQLSchemaState.merged
    return GraphQLSchemaState.merged


def _merge_scalar(left: Any, right: Any, unknown: Any, description: str) -> Any:
    if left == right:
        return left
    if left == unknown:
        return right
    if right == unknown:
        return left
    raise GraphQLSemanticConflict(f"conflicting {description}")


def _merge_authentication_requirement(
    left: GraphQLAuthenticationRequirement,
    right: GraphQLAuthenticationRequirement,
    description: str,
) -> GraphQLAuthenticationRequirement:
    if left is right:
        return left
    if left is GraphQLAuthenticationRequirement.unknown:
        return right
    if right is GraphQLAuthenticationRequirement.unknown:
        return left
    observed = {
        GraphQLAuthenticationRequirement.anonymous_observed,
        GraphQLAuthenticationRequirement.authenticated_observed,
    }
    if {left, right} == observed:
        # The surface was available in both contexts. Identity-differential
        # observations retain that distinction; this scalar records that an
        # authenticated observation also exists.
        return GraphQLAuthenticationRequirement.authenticated_observed
    precedence = (
        GraphQLAuthenticationRequirement.tenant_bound,
        GraphQLAuthenticationRequirement.role_bound,
        GraphQLAuthenticationRequirement.authentication_required,
        GraphQLAuthenticationRequirement.authenticated_observed,
    )
    if left in precedence and right in precedence:
        return min((left, right), key=precedence.index)
    raise GraphQLSemanticConflict(f"conflicting {description}")


def _merge_authorization_semantics(
    left: GraphQLAuthorizationSemantics,
    right: GraphQLAuthorizationSemantics,
) -> GraphQLAuthorizationSemantics:
    observations = set((*left.observations, *right.observations))
    if len(observations) > 1:
        observations.discard(GraphQLAuthorizationObservation.unknown)
    return GraphQLAuthorizationSemantics(
        observations=tuple(sorted(observations, key=lambda item: item.value)),
        identity_references=tuple(
            sorted({*left.identity_references, *right.identity_references})
        ),
        evidence_references=tuple(
            sorted({*left.evidence_references, *right.evidence_references})
        ),
        provenance_id=left.provenance_id,
    )


def _merge_tuple(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    by_json = {
        (
            json.dumps(
                item.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            )
            if hasattr(item, "model_dump")
            else str(item)
        ): item
        for item in (*left, *right)
    }
    return tuple(by_json[key] for key in sorted(by_json))


def _merge_semantic_record(left: Any, right: Any, identifier: str) -> Any:
    if type(left) is not type(right):
        raise GraphQLSemanticConflict(f"conflicting record types for {identifier}")
    if left == right:
        return left
    payload = left.model_dump(mode="python")
    if isinstance(left, GraphQLSurface):
        immutable = (
            "research_id",
            "target_id",
            "surface_id",
            "endpoint_id",
            "transport",
        )
        for name in immutable:
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL surface {name}")
        capture, introspection = (
            (left, right)
            if left.schema_state is GraphQLSchemaState.capture_derived
            and right.schema_state is GraphQLSchemaState.introspection_observed
            else (right, left)
        )
        if (
            capture.schema_state is GraphQLSchemaState.capture_derived
            and introspection.schema_state is GraphQLSchemaState.introspection_observed
            and not set(capture.operation_capabilities).issubset(
                introspection.operation_capabilities
            )
        ):
            raise GraphQLSemanticConflict("conflicting GraphQL operation capabilities")
        payload["schema_state"] = _merge_schema_state(
            left.schema_state, right.schema_state
        )
        payload["operation_capabilities"] = _merge_tuple(
            left.operation_capabilities, right.operation_capabilities
        )
        payload["authentication_requirement"] = _merge_authentication_requirement(
            left.authentication_requirement,
            right.authentication_requirement,
            "surface authentication semantics",
        )
    elif isinstance(left, GraphQLTypeRecord):
        for name in ("graphql_surface_id", "name", "kind", "root_role"):
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL type {name}")
        for name in ("field_ids", "possible_type_ids", "interface_ids"):
            payload[name] = _merge_tuple(getattr(left, name), getattr(right, name))
    elif isinstance(left, GraphQLFieldRecord):
        for name in ("type_id", "name"):
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL field {name}")
        if left.return_type != right.return_type:
            if left.return_type.unresolved_external:
                payload["return_type"] = right.return_type
                payload["nullable"] = right.nullable
                payload["list_depth"] = right.list_depth
            elif not right.return_type.unresolved_external:
                raise GraphQLSemanticConflict("conflicting GraphQL field return type")
        payload["return_shape"] = _merge_scalar(
            left.return_shape,
            right.return_shape,
            GraphQLReturnShape.unknown,
            "field return shape",
        )
        payload["argument_ids"] = _merge_tuple(left.argument_ids, right.argument_ids)
        payload["relationship_hints"] = _merge_tuple(
            left.relationship_hints, right.relationship_hints
        )
        if left.authorization_semantics != right.authorization_semantics:
            payload["authorization_semantics"] = _merge_authorization_semantics(
                left.authorization_semantics, right.authorization_semantics
            )
    elif isinstance(left, GraphQLArgumentRecord):
        for name in ("field_id", "name", "default_presence", "parameter_id"):
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL argument {name}")
        if left.input_type != right.input_type:
            if left.input_type.unresolved_external:
                payload["input_type"] = right.input_type
                payload["nullable"] = right.nullable
                payload["list_depth"] = right.list_depth
            elif not right.input_type.unresolved_external:
                raise GraphQLSemanticConflict("conflicting GraphQL argument input type")
        payload["semantic_role"] = _merge_scalar(
            left.semantic_role,
            right.semantic_role,
            GraphQLSemanticRole.unknown,
            "argument semantic role",
        )
        payload["semantic_role_evidence_references"] = _merge_tuple(
            left.semantic_role_evidence_references,
            right.semantic_role_evidence_references,
        )
        payload["object_reference_semantics"] = _merge_scalar(
            left.object_reference_semantics,
            right.object_reference_semantics,
            GraphQLObjectReferenceSemantics(),
            "argument object-reference semantics",
        )
    elif isinstance(left, GraphQLOperationRecord):
        for name in (
            "graphql_surface_id",
            "operation_type",
            "operation_name",
            "selection_fingerprint",
            "workflow_id",
        ):
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL operation {name}")
        payload["root_field_ids"] = _merge_tuple(
            left.root_field_ids, right.root_field_ids
        )
        payload["variable_ids"] = _merge_tuple(left.variable_ids, right.variable_ids)
        payload["authentication_requirement"] = _merge_authentication_requirement(
            left.authentication_requirement,
            right.authentication_requirement,
            "operation authentication semantics",
        )
        payload["state_change_class"] = _merge_scalar(
            left.state_change_class,
            right.state_change_class,
            GraphQLStateChangeClass.unknown,
            "operation state-change semantics",
        )
    elif isinstance(left, GraphQLVariableRecord):
        for name in (
            "operation_id",
            "name",
            "input_type",
            "nullable",
            "list_depth",
            "linked_argument_id",
            "controlled_value_reference",
        ):
            if getattr(left, name) != getattr(right, name):
                raise GraphQLSemanticConflict(f"conflicting GraphQL variable {name}")
        payload["semantic_role"] = _merge_scalar(
            left.semantic_role,
            right.semantic_role,
            GraphQLSemanticRole.unknown,
            "variable semantic role",
        )
        payload["semantic_role_evidence_references"] = _merge_tuple(
            left.semantic_role_evidence_references,
            right.semantic_role_evidence_references,
        )
    else:
        raise TypeError(f"unsupported GraphQL semantic record: {type(left).__name__}")
    payload["evidence_references"] = _merge_tuple(
        left.evidence_references, right.evidence_references
    )
    return type(left).model_validate(payload)


def _merge_collection(
    existing: tuple[Any, ...], incoming: tuple[Any, ...], id_field: str
) -> tuple[Any, ...]:
    result = {getattr(item, id_field): item for item in existing}
    for item in incoming:
        identifier = getattr(item, id_field)
        if identifier in result:
            result[identifier] = _merge_semantic_record(
                result[identifier], item, identifier
            )
        else:
            result[identifier] = item
    return tuple(result[key] for key in sorted(result))


def _merge_supporting_records(
    existing: tuple[Any, ...], incoming: Sequence[Any], id_field: str
) -> tuple[Any, ...]:
    result = {getattr(item, id_field): item for item in existing}
    for item in incoming:
        identifier = getattr(item, id_field)
        if identifier in result and result[identifier] != item:
            raise GraphQLSemanticConflict(
                f"conflicting supporting record for {identifier}"
            )
        result[identifier] = item
    return tuple(result[key] for key in sorted(result))


def merge_graphql_semantics(
    state: "ResearchState",
    *,
    graphql_surfaces: Sequence[GraphQLSurface] = (),
    graphql_types: Sequence[GraphQLTypeRecord] = (),
    graphql_fields: Sequence[GraphQLFieldRecord] = (),
    graphql_arguments: Sequence[GraphQLArgumentRecord] = (),
    graphql_operations: Sequence[GraphQLOperationRecord] = (),
    graphql_variables: Sequence[GraphQLVariableRecord] = (),
    evidence: Sequence["EvidenceArtifact"] = (),
    provenance: Sequence["ProvenanceRecord"] = (),
    revision: int | None = None,
    updated_at: str | None = None,
) -> "ResearchState":
    """Idempotently enrich a state or fail on incompatible observations."""

    from agent_core.research.state import ResearchState

    payload = state.model_dump(mode="python")
    payload["evidence"] = _merge_supporting_records(
        state.evidence, evidence, "evidence_id"
    )
    payload["provenance"] = _merge_supporting_records(
        state.provenance, provenance, "provenance_id"
    )
    payload["graphql_surfaces"] = _merge_collection(
        state.graphql_surfaces, tuple(graphql_surfaces), "graphql_surface_id"
    )
    payload["graphql_types"] = _merge_collection(
        state.graphql_types, tuple(graphql_types), "type_id"
    )
    payload["graphql_fields"] = _merge_collection(
        state.graphql_fields, tuple(graphql_fields), "field_id"
    )
    payload["graphql_arguments"] = _merge_collection(
        state.graphql_arguments, tuple(graphql_arguments), "argument_id"
    )
    legacy_operations = tuple(
        item
        for item in state.graphql_operations
        if not isinstance(item, GraphQLOperationRecord)
    )
    semantic_operations = tuple(
        item
        for item in state.graphql_operations
        if isinstance(item, GraphQLOperationRecord)
    )
    payload["graphql_operations"] = legacy_operations + _merge_collection(
        semantic_operations, tuple(graphql_operations), "operation_id"
    )
    payload["graphql_variables"] = _merge_collection(
        state.graphql_variables, tuple(graphql_variables), "variable_id"
    )
    if revision is not None:
        payload["revision"] = revision
    if updated_at is not None:
        payload["updated_at"] = updated_at
    return ResearchState.model_validate(payload)


def build_graphql_graph_assertions(
    state: "ResearchState", *, asserted_at: str
) -> tuple["GraphAssertion", ...]:
    """Materialize only evidence-backed structural GraphQL graph assertions."""

    from agent_core.research.graph import GraphAssertion
    from agent_core.research.types import (
        DerivationType,
        EntityKind,
        EntityReference,
        RelationshipStatus,
        ResearchPredicate,
    )

    assertions: dict[str, GraphAssertion] = {}

    def add(
        source_kind: EntityKind,
        source_id: str,
        relation: ResearchPredicate,
        target_kind: EntityKind,
        target_id: str,
        evidence: tuple[str, ...],
        provenance_id: str,
    ) -> None:
        if not evidence:
            return
        assertion_id = graphql_semantic_id(
            "edge",
            source_kind.value,
            source_id,
            relation.value,
            target_kind.value,
            target_id,
        )
        assertions[assertion_id] = GraphAssertion(
            assertion_id=assertion_id,
            research_id=state.research_id,
            source=EntityReference(entity_kind=source_kind, entity_id=source_id),
            relation=relation,
            target=EntityReference(entity_kind=target_kind, entity_id=target_id),
            status=RelationshipStatus.observed,
            evidence_references=evidence,
            derivation_type=DerivationType.deterministic,
            provenance_id=provenance_id,
            asserted_at=asserted_at,
        )

    types = {item.type_id: item for item in state.graphql_types}
    type_by_surface_name = {
        (item.graphql_surface_id, item.name): item for item in state.graphql_types
    }
    fields = {item.field_id: item for item in state.graphql_fields}
    arguments = {item.argument_id: item for item in state.graphql_arguments}
    variables = {item.variable_id: item for item in state.graphql_variables}

    for item in state.graphql_types:
        add(
            EntityKind.graphql_surface,
            item.graphql_surface_id,
            ResearchPredicate.graphql_has_type,
            EntityKind.graphql_type,
            item.type_id,
            item.evidence_references,
            item.provenance_id,
        )
        for field_id in item.field_ids:
            field = fields[field_id]
            add(
                EntityKind.graphql_type,
                item.type_id,
                ResearchPredicate.graphql_has_field,
                EntityKind.graphql_field,
                field_id,
                field.evidence_references,
                field.provenance_id,
            )
        for possible_id in item.possible_type_ids:
            add(
                EntityKind.graphql_type,
                item.type_id,
                ResearchPredicate.graphql_possible_type,
                EntityKind.graphql_type,
                possible_id,
                item.evidence_references,
                item.provenance_id,
            )
        for interface_id in item.interface_ids:
            add(
                EntityKind.graphql_type,
                item.type_id,
                ResearchPredicate.graphql_implements_interface,
                EntityKind.graphql_type,
                interface_id,
                item.evidence_references,
                item.provenance_id,
            )

    for item in state.graphql_fields:
        owner = types[item.type_id]
        returned = type_by_surface_name.get(
            (owner.graphql_surface_id, item.return_type.named_type)
        )
        if returned is not None:
            add(
                EntityKind.graphql_field,
                item.field_id,
                ResearchPredicate.graphql_returns_type,
                EntityKind.graphql_type,
                returned.type_id,
                item.evidence_references,
                item.provenance_id,
            )
        for argument_id in item.argument_ids:
            argument = arguments[argument_id]
            add(
                EntityKind.graphql_field,
                item.field_id,
                ResearchPredicate.graphql_has_argument,
                EntityKind.graphql_argument,
                argument_id,
                argument.evidence_references,
                argument.provenance_id,
            )
        for hint in item.relationship_hints:
            if hint.graphql_type_id is not None:
                add(
                    EntityKind.graphql_field,
                    item.field_id,
                    ResearchPredicate.graphql_references_type,
                    EntityKind.graphql_type,
                    hint.graphql_type_id,
                    hint.evidence_references,
                    item.provenance_id,
                )
            if hint.research_object_id is not None:
                add(
                    EntityKind.graphql_field,
                    item.field_id,
                    ResearchPredicate.graphql_references_object,
                    EntityKind.object,
                    hint.research_object_id,
                    hint.evidence_references,
                    item.provenance_id,
                )

    for item in state.graphql_arguments:
        field = fields[item.field_id]
        owner = types[field.type_id]
        referenced = type_by_surface_name.get(
            (owner.graphql_surface_id, item.input_type.named_type)
        )
        if referenced is not None:
            add(
                EntityKind.graphql_argument,
                item.argument_id,
                ResearchPredicate.graphql_references_type,
                EntityKind.graphql_type,
                referenced.type_id,
                item.evidence_references,
                item.provenance_id,
            )
        semantics = item.object_reference_semantics
        if semantics.research_object_id is not None:
            add(
                EntityKind.graphql_argument,
                item.argument_id,
                ResearchPredicate.graphql_references_object,
                EntityKind.object,
                semantics.research_object_id,
                item.evidence_references,
                item.provenance_id,
            )
        if item.parameter_id is not None:
            add(
                EntityKind.graphql_argument,
                item.argument_id,
                ResearchPredicate.crosses_surface,
                EntityKind.parameter,
                item.parameter_id,
                item.evidence_references,
                item.provenance_id,
            )

    for item in state.graphql_operations:
        if not isinstance(item, GraphQLOperationRecord):
            continue
        add(
            EntityKind.graphql_surface,
            item.graphql_surface_id,
            ResearchPredicate.graphql_has_operation,
            EntityKind.graphql_operation,
            item.operation_id,
            item.evidence_references,
            item.provenance_id,
        )
        if item.workflow_id is not None:
            add(
                EntityKind.graphql_operation,
                item.operation_id,
                ResearchPredicate.produces_context_for,
                EntityKind.workflow,
                item.workflow_id,
                item.evidence_references,
                item.provenance_id,
            )
        for field_id in item.root_field_ids:
            field = fields[field_id]
            add(
                EntityKind.graphql_operation,
                item.operation_id,
                ResearchPredicate.graphql_selects_field,
                EntityKind.graphql_field,
                field_id,
                item.evidence_references,
                item.provenance_id,
            )
            for argument_id in field.argument_ids:
                add(
                    EntityKind.graphql_operation,
                    item.operation_id,
                    ResearchPredicate.graphql_operation_uses_argument,
                    EntityKind.graphql_argument,
                    argument_id,
                    item.evidence_references,
                    item.provenance_id,
                )
            for hint in field.relationship_hints:
                if hint.research_object_id is not None:
                    relation = (
                        ResearchPredicate.graphql_modifies_object
                        if item.operation_type is GraphQLOperationType.mutation
                        else ResearchPredicate.graphql_references_object
                    )
                    add(
                        EntityKind.graphql_operation,
                        item.operation_id,
                        relation,
                        EntityKind.object,
                        hint.research_object_id,
                        hint.evidence_references,
                        item.provenance_id,
                    )
        for variable_id in item.variable_ids:
            variable = variables[variable_id]
            add(
                EntityKind.graphql_operation,
                item.operation_id,
                ResearchPredicate.graphql_has_variable,
                EntityKind.graphql_variable,
                variable_id,
                variable.evidence_references,
                variable.provenance_id,
            )
            if variable.linked_argument_id is not None:
                add(
                    EntityKind.graphql_variable,
                    variable_id,
                    ResearchPredicate.graphql_variable_binds_argument,
                    EntityKind.graphql_argument,
                    variable.linked_argument_id,
                    variable.evidence_references,
                    variable.provenance_id,
                )

    return tuple(assertions[key] for key in sorted(assertions))


class GraphQLPublicSurfaceSummary(ResearchContract):
    graphql_surface_id: GraphQLSurfaceId
    surface_id: SurfaceId
    schema_state: GraphQLSchemaState
    operation_capabilities: tuple[GraphQLOperationType, ...]
    authentication_requirement: GraphQLAuthenticationRequirement
    evidence_references: tuple[EvidenceArtifactId, ...]


class GraphQLPublicTypeSummary(ResearchContract):
    type_id: GraphQLTypeId
    graphql_surface_id: GraphQLSurfaceId
    name: GraphQLName
    kind: GraphQLTypeKind
    root_role: GraphQLRootRole | None
    field_ids: tuple[GraphQLFieldId, ...]
    possible_type_ids: tuple[GraphQLTypeId, ...]
    interface_ids: tuple[GraphQLTypeId, ...]
    evidence_references: tuple[EvidenceArtifactId, ...]


class GraphQLPublicFieldSummary(ResearchContract):
    field_id: GraphQLFieldId
    type_id: GraphQLTypeId
    name: GraphQLName
    return_type: StrictStr = Field(min_length=1, max_length=255)
    return_shape: GraphQLReturnShape
    argument_ids: tuple[GraphQLArgumentId, ...]
    relationship_kinds: tuple[GraphQLRelationshipKind, ...]
    authorization_observations: tuple[GraphQLAuthorizationObservation, ...]
    evidence_references: tuple[EvidenceArtifactId, ...]


class GraphQLPublicArgumentSummary(ResearchContract):
    argument_id: GraphQLArgumentId
    field_id: GraphQLFieldId
    name: GraphQLName
    input_type: StrictStr = Field(min_length=1, max_length=255)
    semantic_role: GraphQLSemanticRole
    object_reference_kind: GraphQLObjectReferenceKind
    evidence_references: tuple[EvidenceArtifactId, ...]


class GraphQLPublicOperationSummary(ResearchContract):
    operation_id: GraphQLOperationId
    graphql_surface_id: GraphQLSurfaceId
    operation_type: GraphQLOperationType
    operation_name: GraphQLName | None
    root_field_ids: tuple[GraphQLFieldId, ...]
    variable_ids: tuple[GraphQLVariableId, ...]
    selection_fingerprint: Sha256Digest
    authentication_requirement: GraphQLAuthenticationRequirement
    state_change_class: GraphQLStateChangeClass
    evidence_references: tuple[EvidenceArtifactId, ...]


class GraphQLPublicCrossSurfaceSummary(ResearchContract):
    assertion_id: OpaqueIdentifier
    source: EntityReference
    relation: ResearchPredicate
    target: EntityReference
    evidence_references: tuple[EvidenceArtifactId, ...]

    @model_validator(mode="after")
    def validate_relation(self) -> "GraphQLPublicCrossSurfaceSummary":
        if self.relation not in {
            ResearchPredicate.references_same_object,
            ResearchPredicate.crosses_surface,
            ResearchPredicate.produces_context_for,
        }:
            raise ValueError("summary relation is not cross-surface")
        return self


class GraphQLPublicSafeSummary(ResearchContract):
    research_id: ResearchId
    surfaces: tuple[GraphQLPublicSurfaceSummary, ...]
    types: tuple[GraphQLPublicTypeSummary, ...]
    fields: tuple[GraphQLPublicFieldSummary, ...]
    arguments: tuple[GraphQLPublicArgumentSummary, ...]
    operations: tuple[GraphQLPublicOperationSummary, ...]
    cross_surface_relationships: tuple[GraphQLPublicCrossSurfaceSummary, ...]

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")


def build_public_safe_graphql_summary(
    state: "ResearchState",
    *,
    graph_assertions: Sequence["GraphAssertion"] = (),
    max_bytes: int = MAX_GRAPHQL_PUBLIC_PACKET_BYTES,
) -> GraphQLPublicSafeSummary:
    """Build a deterministic packet containing structure, never captured values."""

    if max_bytes < 1 or max_bytes > MAX_GRAPHQL_PUBLIC_PACKET_BYTES:
        raise ValueError("public packet byte bound is outside the supported range")
    packet = GraphQLPublicSafeSummary(
        research_id=state.research_id,
        surfaces=tuple(
            {
                "graphql_surface_id": item.graphql_surface_id,
                "surface_id": item.surface_id,
                "schema_state": item.schema_state,
                "operation_capabilities": item.operation_capabilities,
                "authentication_requirement": item.authentication_requirement,
                "evidence_references": item.evidence_references,
            }
            for item in state.graphql_surfaces
        ),
        types=tuple(
            {
                "type_id": item.type_id,
                "graphql_surface_id": item.graphql_surface_id,
                "name": item.name,
                "kind": item.kind,
                "root_role": item.root_role,
                "field_ids": item.field_ids,
                "possible_type_ids": item.possible_type_ids,
                "interface_ids": item.interface_ids,
                "evidence_references": item.evidence_references,
            }
            for item in state.graphql_types
        ),
        fields=tuple(
            {
                "field_id": item.field_id,
                "type_id": item.type_id,
                "name": item.name,
                "return_type": item.return_type.to_syntax(),
                "return_shape": item.return_shape,
                "argument_ids": item.argument_ids,
                "relationship_kinds": tuple(
                    hint.kind for hint in item.relationship_hints
                ),
                "authorization_observations": tuple(
                    value for value in item.authorization_semantics.observations
                ),
                "evidence_references": item.evidence_references,
            }
            for item in state.graphql_fields
        ),
        arguments=tuple(
            {
                "argument_id": item.argument_id,
                "field_id": item.field_id,
                "name": item.name,
                "input_type": item.input_type.to_syntax(),
                "semantic_role": item.semantic_role,
                "object_reference_kind": item.object_reference_semantics.kind,
                "evidence_references": item.evidence_references,
            }
            for item in state.graphql_arguments
        ),
        operations=tuple(
            {
                "operation_id": item.operation_id,
                "graphql_surface_id": item.graphql_surface_id,
                "operation_type": item.operation_type,
                "operation_name": item.operation_name,
                "root_field_ids": item.root_field_ids,
                "variable_ids": item.variable_ids,
                "selection_fingerprint": item.selection_fingerprint,
                "authentication_requirement": item.authentication_requirement,
                "state_change_class": item.state_change_class,
                "evidence_references": item.evidence_references,
            }
            for item in state.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
        ),
        cross_surface_relationships=tuple(
            {
                "assertion_id": item.assertion_id,
                "source": item.source,
                "relation": item.relation,
                "target": item.target,
                "evidence_references": item.evidence_references,
            }
            for item in sorted(graph_assertions, key=lambda value: value.assertion_id)
            if item.relation
            in {
                ResearchPredicate.references_same_object,
                ResearchPredicate.crosses_surface,
                ResearchPredicate.produces_context_for,
            }
        ),
    )
    size = len(packet.canonical_bytes())
    if size > max_bytes:
        raise GraphQLPublicPacketTooLarge(
            f"public-safe GraphQL packet is {size} bytes; limit is {max_bytes}"
        )
    return packet
