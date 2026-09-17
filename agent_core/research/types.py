"""Strict provider-neutral types for Phase 4 security research state."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent_core.result_normalizer import sanitize_document_text

MAX_IDENTIFIER_LENGTH = 255
MAX_PUBLIC_TEXT_LENGTH = 4_000
MAX_METADATA_ENTRIES = 50


def _validate_public_text(value: str) -> str:
    if sanitize_document_text(value) != value:
        raise ValueError("text must already satisfy the public-safe boundary")
    return value


def _validate_timestamp(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value


OpaqueIdentifier: TypeAlias = Annotated[
    StrictStr,
    Field(
        min_length=1,
        max_length=MAX_IDENTIFIER_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$",
    ),
]
PublicText: TypeAlias = Annotated[
    StrictStr,
    Field(min_length=1, max_length=MAX_PUBLIC_TEXT_LENGTH),
    AfterValidator(_validate_public_text),
]
ShortPublicText: TypeAlias = Annotated[
    StrictStr,
    Field(min_length=1, max_length=1_000),
    AfterValidator(_validate_public_text),
]
Timestamp: TypeAlias = Annotated[
    StrictStr,
    Field(min_length=20, max_length=40),
    AfterValidator(_validate_timestamp),
]
Sha256Digest: TypeAlias = Annotated[
    StrictStr,
    Field(pattern=r"^sha256:[0-9a-f]{64}$"),
]
VaultReference: TypeAlias = Annotated[
    StrictStr,
    Field(
        min_length=8,
        max_length=255,
        pattern=r"^[A-Za-z][A-Za-z0-9._:-]{7,254}$",
    ),
]

# Distinct public aliases document intent while retaining the repository's
# string-reference convention and strict Pydantic validation.
ResearchId = OpaqueIdentifier
ResearchEventId = OpaqueIdentifier
TargetAssetId = OpaqueIdentifier
SurfaceId = OpaqueIdentifier
EndpointId = OpaqueIdentifier
ParameterId = OpaqueIdentifier
IdentityId = OpaqueIdentifier
SessionRefId = OpaqueIdentifier
TokenRefId = OpaqueIdentifier
ResearchObjectId = OpaqueIdentifier
GraphQLOperationId = OpaqueIdentifier
UploadArtifactId = OpaqueIdentifier
WorkflowId = OpaqueIdentifier
ObservationId = OpaqueIdentifier
EvidenceArtifactId = OpaqueIdentifier
FactId = OpaqueIdentifier
HypothesisRecordId = OpaqueIdentifier
ExperimentId = OpaqueIdentifier
ExperimentOutcomeId = OpaqueIdentifier
FindingId = OpaqueIdentifier
AttackChainId = OpaqueIdentifier
RelationshipId = OpaqueIdentifier
ProvenanceRecordId = OpaqueIdentifier


class ResearchContract(BaseModel):
    """Base for immutable, strict, unknown-field-rejecting research records."""

    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        strict=True,
    )


class ResearchRunStatus(str, Enum):
    initializing = "initializing"
    discovering = "discovering"
    modeling = "modeling"
    hypothesizing = "hypothesizing"
    selecting_experiment = "selecting_experiment"
    awaiting_authorization = "awaiting_authorization"
    executing_experiment = "executing_experiment"
    evaluating_result = "evaluating_result"
    pivoting = "pivoting"
    reproducing = "reproducing"
    impact_analysis = "impact_analysis"
    chaining = "chaining"
    reporting = "reporting"
    stopped = "stopped"
    failed = "failed"


class SurfaceType(str, Enum):
    rest = "rest"
    graphql = "graphql"
    authentication = "authentication"
    token = "token"
    upload = "upload"
    workflow = "workflow"
    server_side = "server_side"


class HypothesisResearchStatus(str, Enum):
    proposed = "proposed"
    selected = "selected"
    testing = "testing"
    inconclusive = "inconclusive"
    supported = "supported"
    refuted = "refuted"
    closed = "closed"


class FindingStatus(str, Enum):
    candidate = "candidate"
    reproduced = "reproduced"
    confirmed = "confirmed"
    rejected = "rejected"


class FactStatus(str, Enum):
    proposed = "proposed"
    observed = "observed"
    confirmed = "confirmed"
    rejected = "rejected"
    superseded = "superseded"


class RelationshipStatus(str, Enum):
    proposed = "proposed"
    observed = "observed"
    confirmed = "confirmed"
    rejected = "rejected"
    superseded = "superseded"


class ResearchConfidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class TargetClass(str, Enum):
    external = "external"
    local_range = "local_range"
    dedicated_lab = "dedicated_lab"


class IdentityEligibility(str, Enum):
    unknown = "unknown"
    eligible = "eligible"
    ineligible = "ineligible"


class SessionLifecycle(str, Enum):
    unknown = "unknown"
    active = "active"
    expired = "expired"
    invalidated = "invalidated"
    discarded = "discarded"


class TokenLifecycle(str, Enum):
    unknown = "unknown"
    active = "active"
    expired = "expired"
    invalidated = "invalidated"
    discarded = "discarded"


class TokenKind(str, Enum):
    access = "access"
    refresh = "refresh"
    identity = "identity"
    other = "other"


class ParameterLocation(str, Enum):
    path = "path"
    query = "query"
    header = "header"
    cookie = "cookie"
    json = "json"
    form = "form"
    graphql_variable = "graphql_variable"


class HttpMethod(str, Enum):
    get = "GET"
    head = "HEAD"
    options = "OPTIONS"
    post = "POST"
    put = "PUT"
    patch = "PATCH"
    delete = "DELETE"


class GraphQLOperationType(str, Enum):
    query = "query"
    mutation = "mutation"
    subscription = "subscription"


class UploadLifecycle(str, Enum):
    fixture_ready = "fixture_ready"
    created = "created"
    retrievable = "retrievable"
    cleanup_pending = "cleanup_pending"
    deleted = "deleted"


class DerivationType(str, Enum):
    deterministic = "deterministic"
    model_proposed = "model_proposed"
    imported = "imported"
    researcher_asserted = "researcher_asserted"


class EvidenceKind(str, Enum):
    capture = "capture"
    request_result = "request_result"
    response_summary = "response_summary"
    state_summary = "state_summary"
    schema = "schema"
    differential = "differential"
    imported = "imported"


class ExperimentRuntimeStatus(str, Enum):
    completed = "completed"
    blocked = "blocked"
    failed = "failed"
    awaiting_controlled_evidence = "awaiting_controlled_evidence"
    cleanup_pending = "cleanup_pending"


class CleanupStatus(str, Enum):
    not_required = "not_required"
    reserved = "reserved"
    pending = "pending"
    completed = "completed"
    failed = "failed"
    externally_required = "externally_required"


class AttackChainStatus(str, Enum):
    proposed = "proposed"
    candidate = "candidate"
    reproduced = "reproduced"
    confirmed = "confirmed"
    rejected = "rejected"


class ImpactLevel(str, Enum):
    none = "none"
    limited = "limited"
    material = "material"


class ProvenanceProducerType(str, Enum):
    deterministic = "deterministic"
    model = "model"
    imported = "imported"
    researcher = "researcher"
    runtime = "runtime"


class EntityKind(str, Enum):
    target = "target"
    surface = "surface"
    endpoint = "endpoint"
    parameter = "parameter"
    identity = "identity"
    session = "session"
    token = "token"
    object = "object"
    graphql_operation = "graphql_operation"
    upload = "upload"
    workflow = "workflow"
    observation = "observation"
    evidence = "evidence"
    fact = "fact"
    hypothesis = "hypothesis"
    experiment_outcome = "experiment_outcome"
    finding = "finding"
    attack_chain = "attack_chain"


class ResearchPredicate(str, Enum):
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


class MetadataEntry(ResearchContract):
    key: Annotated[
        StrictStr,
        Field(min_length=1, max_length=100, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$"),
    ]
    value: PublicText | StrictInt | StrictFloat | StrictBool

    @field_validator("key")
    @classmethod
    def reject_private_or_executable_keys(cls, value: str) -> str:
        normalized = value.lower().replace("-", "_").replace(".", "_")
        forbidden = {
            "api_key",
            "authorization",
            "body",
            "callback",
            "callable",
            "client_secret",
            "code",
            "command",
            "cookie",
            "credential",
            "headers",
            "jwt",
            "password",
            "payload",
            "private_token",
            "raw_request",
            "request_body",
            "script",
            "secret",
            "session",
            "session_value",
            "shell",
            "token",
            "token_value",
        }
        private_prefixes = (
            "api_key_",
            "authorization_",
            "cookie_",
            "credential_",
            "jwt_",
            "password_",
            "secret_",
            "session_",
            "token_",
        )
        if (
            normalized in forbidden
            or normalized.startswith(private_prefixes)
            or normalized.endswith(
                ("_password", "_secret", "_token", "_credential", "_cookie")
            )
            or set(normalized.split("_"))
            & {
                "callback",
                "callable",
                "command",
                "script",
                "shell",
            }
        ):
            raise ValueError("metadata key may contain private or executable data")
        return value


class PublicMetadata(ResearchContract):
    entries: tuple[MetadataEntry, ...] = Field(
        default=(), max_length=MAX_METADATA_ENTRIES
    )

    @model_validator(mode="after")
    def canonicalize_entries(self) -> "PublicMetadata":
        keys = [entry.key for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("metadata keys must be unique")
        object.__setattr__(
            self, "entries", tuple(sorted(self.entries, key=lambda x: x.key))
        )
        return self


class EntityReference(ResearchContract):
    entity_kind: EntityKind
    entity_id: OpaqueIdentifier


class ReferenceFactObject(ResearchContract):
    kind: Literal["reference"] = "reference"
    reference: EntityReference


class ScalarFactObject(ResearchContract):
    kind: Literal["scalar"] = "scalar"
    value: PublicText | StrictInt | StrictFloat | StrictBool


FactObject: TypeAlias = Annotated[
    ReferenceFactObject | ScalarFactObject,
    Field(discriminator="kind"),
]
