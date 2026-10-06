"""Passive-first, policy-bound GraphQL surface discovery.

Only fixed read-only probe documents defined in this module can be sent as
GraphQL requests. Public-source acquisition uses bounded same-origin GETs and
never executes an extracted document. Results retain structural evidence and
digests, never raw response values, variable values, or credentials.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Literal
from urllib.parse import urljoin, urlparse, urlunparse

from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)
from requests import RequestException

from agent_core.policy import AssessmentPolicy
from agent_core.request_budget import RequestBudget, RequestBudgetExceeded, RequestDelta
from agent_core.controlled_context import ControlledAccount, ControlledContext
from agent_core.credential_vault import CredentialVault
from agent_core.research.adapters import (
    digest_for,
    opaque_reference,
    stable_research_identifier,
)
from agent_core.research.graphql import (
    MAX_GRAPHQL_ARGUMENTS,
    MAX_GRAPHQL_FIELDS,
    MAX_GRAPHQL_SURFACES,
    MAX_GRAPHQL_TYPES_PER_SURFACE,
)
from agent_core.research.graphql_ingest import (
    MAX_GRAPHQL_RESPONSE_BYTES,
    GraphQLControlledObjectEvidence,
    GraphQLDocumentError,
    GraphQLErrorClass,
    GraphQLResponseEnvelope,
    GraphQLResponseObservation,
    GraphQLSemanticDelta,
    GraphQLSemanticIngestor,
    ParsedGraphQLDocument,
    analyze_graphql_response,
    parse_graphql_document,
)
from agent_core.research.provenance import (
    SecretMaterialRejected,
    reject_secret_material,
)
from agent_core.research.types import ResearchContract
from agent_core.research.state import ResearchState
from tools.safe_http import (
    PolicyViolationError,
    ResponseTooLargeError,
    ScopedHTTPClient,
)

GRAPHQL_DISCOVERY_VERSION = "phase4-graphql-discovery-v1"
MAX_GRAPHQL_DISCOVERY_OBSERVATIONS = MAX_GRAPHQL_SURFACES
MAX_GRAPHQL_DISCOVERY_SIGNALS = 16
MAX_GRAPHQL_DISCOVERY_TIMEOUT_SECONDS = 15.0
MAX_PUBLIC_GRAPHQL_PAGE_BYTES = 65_536
MAX_PUBLIC_GRAPHQL_ASSET_BYTES = 131_072
MAX_PUBLIC_GRAPHQL_ASSETS = 4
MAX_PUBLIC_GRAPHQL_DOCUMENTS = 32
MAX_PUBLIC_GRAPHQL_SOURCE_REQUESTS = 4


class GraphQLDiscoveryConfidence(str, Enum):
    candidate = "candidate"
    observed = "observed"
    confirmed = "confirmed"


class GraphQLIntrospectionPolicy(str, Enum):
    disabled = "disabled"
    passive_only = "passive_only"
    active_if_authorized = "active_if_authorized"


class GraphQLProbeId(str, Enum):
    protocol_confirmation = "protocol_confirmation"
    typename_probe = "typename_probe"
    introspection_probe = "introspection_probe"


class GraphQLProbeStateChangeClass(str, Enum):
    none = "none"


class PublicGraphQLOperationValidationStage(str, Enum):
    parser = "parser"
    public_source_validation = "public_source_validation"
    observation_validation = "observation_validation"
    semantic_delta_validation = "semantic_delta_validation"
    canonical_state_validation = "canonical_state_validation"
    template_validation = "template_validation"


class PublicGraphQLOperationValidationDiagnostic(ResearchContract):
    """Input-free classification for one rejected public operation source."""

    component: Literal["public_graphql_operation"] = "public_graphql_operation"
    stage: PublicGraphQLOperationValidationStage
    error_code: StrictStr = Field(
        pattern=(
            r"^public_graphql_operation_(?:parser|source|observation|semantic_delta|"
            r"canonical_state|template)_validation_rejected$"
        )
    )
    exception_class: Literal[
        "GraphQLDocumentError",
        "SecretMaterialRejected",
        "ValidationError",
        "ValueError",
    ]
    invariant_category: Literal[
        "document_syntax",
        "public_source_contract",
        "surface_observation_contract",
        "semantic_delta_contract",
        "canonical_state_contract",
        "operation_template_contract",
    ]

    @model_validator(mode="after")
    def validate_classification(self) -> "PublicGraphQLOperationValidationDiagnostic":
        expected = {
            PublicGraphQLOperationValidationStage.parser: (
                "public_graphql_operation_parser_validation_rejected",
                "document_syntax",
            ),
            PublicGraphQLOperationValidationStage.public_source_validation: (
                "public_graphql_operation_source_validation_rejected",
                "public_source_contract",
            ),
            PublicGraphQLOperationValidationStage.observation_validation: (
                "public_graphql_operation_observation_validation_rejected",
                "surface_observation_contract",
            ),
            PublicGraphQLOperationValidationStage.semantic_delta_validation: (
                "public_graphql_operation_semantic_delta_validation_rejected",
                "semantic_delta_contract",
            ),
            PublicGraphQLOperationValidationStage.canonical_state_validation: (
                "public_graphql_operation_canonical_state_validation_rejected",
                "canonical_state_contract",
            ),
            PublicGraphQLOperationValidationStage.template_validation: (
                "public_graphql_operation_template_validation_rejected",
                "operation_template_contract",
            ),
        }[self.stage]
        if (self.error_code, self.invariant_category) != expected:
            raise ValueError("public GraphQL validation classification is inconsistent")
        return self

    @property
    def persistence_codes(self) -> tuple[str, ...]:
        return (
            "public_graphql_operation_validation_rejected",
            self.error_code,
            f"public_graphql_operation_stage_{self.stage.value}",
            f"public_graphql_operation_exception_{self.exception_class}",
            f"public_graphql_operation_invariant_{self.invariant_category}",
        )


_VALIDATION_DIAGNOSTIC_FIELDS = {
    PublicGraphQLOperationValidationStage.parser: (
        "public_graphql_operation_parser_validation_rejected",
        "document_syntax",
    ),
    PublicGraphQLOperationValidationStage.public_source_validation: (
        "public_graphql_operation_source_validation_rejected",
        "public_source_contract",
    ),
    PublicGraphQLOperationValidationStage.observation_validation: (
        "public_graphql_operation_observation_validation_rejected",
        "surface_observation_contract",
    ),
    PublicGraphQLOperationValidationStage.semantic_delta_validation: (
        "public_graphql_operation_semantic_delta_validation_rejected",
        "semantic_delta_contract",
    ),
    PublicGraphQLOperationValidationStage.canonical_state_validation: (
        "public_graphql_operation_canonical_state_validation_rejected",
        "canonical_state_contract",
    ),
    PublicGraphQLOperationValidationStage.template_validation: (
        "public_graphql_operation_template_validation_rejected",
        "operation_template_contract",
    ),
}


def _public_graphql_validation_diagnostic(
    stage: PublicGraphQLOperationValidationStage,
    exc: GraphQLDocumentError | SecretMaterialRejected | ValidationError | ValueError,
) -> PublicGraphQLOperationValidationDiagnostic:
    code, invariant = _VALIDATION_DIAGNOSTIC_FIELDS[stage]
    exception_class = type(exc).__name__
    if exception_class not in {
        "GraphQLDocumentError",
        "SecretMaterialRejected",
        "ValidationError",
        "ValueError",
    }:
        exception_class = "ValueError"
    return PublicGraphQLOperationValidationDiagnostic(
        stage=stage,
        error_code=code,
        exception_class=exception_class,
        invariant_category=invariant,
    )


def _bounded_validation_diagnostics(
    values: Sequence[PublicGraphQLOperationValidationDiagnostic],
) -> tuple[PublicGraphQLOperationValidationDiagnostic, ...]:
    unique = {
        (
            item.stage.value,
            item.error_code,
            item.exception_class,
            item.invariant_category,
        ): item
        for item in values
    }
    return tuple(unique[key] for key in sorted(unique))[:100]


class GraphQLSurfaceObservation(ResearchContract):
    observation_id: StrictStr = Field(min_length=1, max_length=255)
    target_id: StrictStr = Field(min_length=1, max_length=255)
    endpoint_url: StrictStr = Field(min_length=1, max_length=2_048)
    method: StrictStr = Field(default="POST", pattern=r"^(?:GET|POST)$")
    confidence: GraphQLDiscoveryConfidence
    evidence_signals: tuple[StrictStr, ...] = Field(
        min_length=1, max_length=MAX_GRAPHQL_DISCOVERY_SIGNALS
    )
    source_kind: StrictStr = Field(min_length=1, max_length=100)
    source_reference: StrictStr = Field(min_length=1, max_length=255)
    evidence_digest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    identity_id: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    request_document_digest: StrictStr | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    response_evidence_digest: StrictStr | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    response_truncated: StrictBool = False

    @model_validator(mode="after")
    def canonicalize(self) -> "GraphQLSurfaceObservation":
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("GraphQL endpoint must be an absolute HTTP(S) URL")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GraphQL endpoint must not contain credentials or values")
        signals = tuple(sorted(set(self.evidence_signals)))
        if len(signals) != len(self.evidence_signals):
            raise ValueError("GraphQL discovery signals must not contain duplicates")
        object.__setattr__(self, "evidence_signals", signals)
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL surface observation"
        )
        return self


class GraphQLDetectedDocument(ResearchContract):
    observation_id: StrictStr = Field(min_length=1, max_length=255)
    document: ParsedGraphQLDocument
    response: GraphQLResponseObservation | None = None


class RegisteredGraphQLOperationSource(ResearchContract):
    """A parsed document from one explicitly trusted, non-model operation source."""

    endpoint_url: StrictStr = Field(min_length=1, max_length=2_048)
    method: Literal["GET", "POST"] = "POST"
    source_kind: Literal[
        "public_client_asset",
        "public_persisted_manifest",
        "registered_graphql_acquisition",
        "registered_graphql_discovery",
        "trusted_typed_operation",
    ]
    source_reference: StrictStr = Field(min_length=1, max_length=255)
    document: ParsedGraphQLDocument
    identity_id: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    response: GraphQLResponseObservation | None = None

    @model_validator(mode="after")
    def validate_safe_source(self) -> "RegisteredGraphQLOperationSource":
        if _safe_url(self.endpoint_url, None) != self.endpoint_url:
            raise ValueError("registered GraphQL endpoint must be a safe absolute URL")
        reject_secret_material(
            self.model_dump(mode="json"), location="registered GraphQL operation source"
        )
        return self


class GraphQLDetectionBatch(ResearchContract):
    observations: tuple[GraphQLSurfaceObservation, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_DISCOVERY_OBSERVATIONS
    )
    documents: tuple[GraphQLDetectedDocument, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_DISCOVERY_OBSERVATIONS
    )

    @model_validator(mode="after")
    def validate_document_references(self) -> "GraphQLDetectionBatch":
        observation_ids = {item.observation_id for item in self.observations}
        if any(item.observation_id not in observation_ids for item in self.documents):
            raise ValueError("detected GraphQL document has no surface observation")
        return self


class GraphQLDiscoveryConfig(ResearchContract):
    maximum_graphql_discovery_requests: StrictInt = Field(default=3, ge=0, le=20)
    introspection_policy: GraphQLIntrospectionPolicy = (
        GraphQLIntrospectionPolicy.disabled
    )
    maximum_response_bytes: StrictInt = Field(
        default=MAX_GRAPHQL_RESPONSE_BYTES, ge=1, le=MAX_GRAPHQL_RESPONSE_BYTES
    )
    timeout_seconds: StrictFloat = Field(
        default=5.0, gt=0.0, le=MAX_GRAPHQL_DISCOVERY_TIMEOUT_SECONDS
    )
    maximum_types: StrictInt = Field(
        default=MAX_GRAPHQL_TYPES_PER_SURFACE,
        ge=1,
        le=MAX_GRAPHQL_TYPES_PER_SURFACE,
    )
    maximum_fields: StrictInt = Field(
        default=MAX_GRAPHQL_FIELDS, ge=1, le=MAX_GRAPHQL_FIELDS
    )
    maximum_arguments: StrictInt = Field(
        default=MAX_GRAPHQL_ARGUMENTS, ge=1, le=MAX_GRAPHQL_ARGUMENTS
    )


class PublicGraphQLOperationAcquisitionConfig(ResearchContract):
    """Hard limits for passive public application-operation acquisition."""

    maximum_requests: StrictInt = Field(
        default=2, ge=0, le=MAX_PUBLIC_GRAPHQL_SOURCE_REQUESTS
    )
    maximum_assets: StrictInt = Field(default=2, ge=0, le=MAX_PUBLIC_GRAPHQL_ASSETS)
    maximum_documents: StrictInt = Field(
        default=MAX_PUBLIC_GRAPHQL_DOCUMENTS,
        ge=1,
        le=MAX_PUBLIC_GRAPHQL_DOCUMENTS,
    )
    maximum_page_bytes: StrictInt = Field(
        default=MAX_PUBLIC_GRAPHQL_PAGE_BYTES,
        ge=1,
        le=MAX_PUBLIC_GRAPHQL_PAGE_BYTES,
    )
    maximum_asset_bytes: StrictInt = Field(
        default=MAX_PUBLIC_GRAPHQL_ASSET_BYTES,
        ge=1,
        le=MAX_PUBLIC_GRAPHQL_ASSET_BYTES,
    )
    timeout_seconds: StrictFloat = Field(
        default=5.0, gt=0.0, le=MAX_GRAPHQL_DISCOVERY_TIMEOUT_SECONDS
    )


class PublicGraphQLOperationAcquisitionResult(ResearchContract):
    """Typed, execution-neutral exact documents observed in public material."""

    sources: tuple[RegisteredGraphQLOperationSource, ...] = Field(
        default=(), max_length=MAX_PUBLIC_GRAPHQL_DOCUMENTS
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    assets_examined: StrictInt = Field(default=0, ge=0, le=MAX_PUBLIC_GRAPHQL_ASSETS)
    limitations: tuple[StrictStr, ...] = Field(default=(), max_length=100)
    diagnostics: tuple[PublicGraphQLOperationValidationDiagnostic, ...] = Field(
        default=(), max_length=100
    )

    @model_validator(mode="after")
    def public_safe(self) -> "PublicGraphQLOperationAcquisitionResult":
        reject_secret_material(
            self.model_dump(mode="json"),
            location="public GraphQL operation acquisition result",
        )
        return self


class GraphQLProbeDefinition(ResearchContract):
    probe_id: GraphQLProbeId
    operation_name: StrictStr = Field(min_length=1, max_length=100)
    document: StrictStr = Field(min_length=1, max_length=32_768)
    known_request_estimate: StrictInt = Field(default=1, ge=1, le=1)
    state_change_class: GraphQLProbeStateChangeClass = GraphQLProbeStateChangeClass.none
    policy_requirement: StrictStr = Field(min_length=1, max_length=255)
    response_size_bound: StrictInt = Field(ge=1, le=MAX_GRAPHQL_RESPONSE_BYTES)
    timeout_bound_seconds: StrictFloat = Field(
        gt=0.0, le=MAX_GRAPHQL_DISCOVERY_TIMEOUT_SECONDS
    )


_TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { kind name } } }"
PROTOCOL_CONFIRMATION_DOCUMENT = "query CyberCortexProtocolConfirmation { __typename }"
TYPENAME_PROBE_DOCUMENT = "query CyberCortexTypename { __typename }"
INTROSPECTION_PROBE_DOCUMENT = f"""
query CyberCortexBoundedIntrospection {{
  __schema {{
    queryType {{ name }}
    mutationType {{ name }}
    subscriptionType {{ name }}
    types {{
      kind
      name
      fields(includeDeprecated: false) {{
        name
        args {{ name defaultValue type {{ {_TYPE_REF} }} }}
        type {{ {_TYPE_REF} }}
      }}
      interfaces {{ kind name }}
      possibleTypes {{ kind name }}
    }}
  }}
}}
""".strip()


GRAPHQL_PROBE_REGISTRY: Mapping[GraphQLProbeId, GraphQLProbeDefinition] = {
    GraphQLProbeId.protocol_confirmation: GraphQLProbeDefinition(
        probe_id=GraphQLProbeId.protocol_confirmation,
        operation_name="CyberCortexProtocolConfirmation",
        document=PROTOCOL_CONFIRMATION_DOCUMENT,
        policy_requirement="authorized in-scope read-only GraphQL discovery",
        response_size_bound=32_768,
        timeout_bound_seconds=5.0,
    ),
    GraphQLProbeId.typename_probe: GraphQLProbeDefinition(
        probe_id=GraphQLProbeId.typename_probe,
        operation_name="CyberCortexTypename",
        document=TYPENAME_PROBE_DOCUMENT,
        policy_requirement="authorized confirmed-or-observed GraphQL surface",
        response_size_bound=32_768,
        timeout_bound_seconds=5.0,
    ),
    GraphQLProbeId.introspection_probe: GraphQLProbeDefinition(
        probe_id=GraphQLProbeId.introspection_probe,
        operation_name="CyberCortexBoundedIntrospection",
        document=INTROSPECTION_PROBE_DOCUMENT,
        policy_requirement="active_if_authorized introspection policy",
        response_size_bound=MAX_GRAPHQL_RESPONSE_BYTES,
        timeout_bound_seconds=10.0,
    ),
}

_REGISTERED_CAPTURE_AUTHORITY = object()


class GraphQLDiscoveryProbe(ResearchContract):
    probe_id: GraphQLProbeId
    target_id: StrictStr = Field(min_length=1, max_length=255)
    endpoint_url: StrictStr = Field(min_length=1, max_length=2_048)
    identity_id: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    controlled_account_id: StrictStr | None = Field(
        default=None, min_length=1, max_length=255
    )

    @model_validator(mode="after")
    def validate_registered_probe(self) -> "GraphQLDiscoveryProbe":
        if self.probe_id not in GRAPHQL_PROBE_REGISTRY:
            raise ValueError("unregistered GraphQL discovery probe")
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("GraphQL probe endpoint must be absolute HTTP(S)")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "GraphQL probe endpoint must not contain credentials or values"
            )
        if (self.identity_id is None) != (self.controlled_account_id is None):
            raise ValueError(
                "authenticated GraphQL probes require identity and account references"
            )
        return self

    @property
    def definition(self) -> GraphQLProbeDefinition:
        return GRAPHQL_PROBE_REGISTRY[self.probe_id]


class GraphQLProbeOutcome(ResearchContract):
    probe_id: GraphQLProbeId
    status: StrictStr = Field(
        pattern=r"^(?:completed|skipped|blocked|transport_failure|oversized)$"
    )
    observation: GraphQLSurfaceObservation | None = None
    response: GraphQLResponseObservation | None = None
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    introspection_observed: StrictBool = False
    reason_code: StrictStr | None = Field(default=None, min_length=1, max_length=100)

    @model_validator(mode="after")
    def safe_result(self) -> "GraphQLProbeOutcome":
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL probe outcome"
        )
        return self


class GraphQLAcquisitionResult(ResearchContract):
    delta: GraphQLSemanticDelta
    observations: tuple[GraphQLSurfaceObservation, ...] = Field(
        default=(), max_length=MAX_GRAPHQL_DISCOVERY_OBSERVATIONS
    )
    probe_outcomes: tuple[GraphQLProbeOutcome, ...] = Field(default=(), max_length=64)
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    limitations: tuple[StrictStr, ...] = Field(default=(), max_length=100)
    diagnostics: tuple[PublicGraphQLOperationValidationDiagnostic, ...] = Field(
        default=(), max_length=100
    )

    @model_validator(mode="after")
    def no_findings_or_secrets(self) -> "GraphQLAcquisitionResult":
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL acquisition result"
        )
        return self


class GraphQLIdentityDifferential(ResearchContract):
    endpoint_url: StrictStr = Field(min_length=1, max_length=2_048)
    probe_id: GraphQLProbeId
    left_identity: StrictStr = Field(min_length=1, max_length=255)
    right_identity: StrictStr = Field(min_length=1, max_length=255)
    added_shape: tuple[StrictStr, ...] = Field(default=(), max_length=64)
    removed_shape: tuple[StrictStr, ...] = Field(default=(), max_length=64)
    added_typenames: tuple[StrictStr, ...] = Field(default=(), max_length=64)
    removed_typenames: tuple[StrictStr, ...] = Field(default=(), max_length=64)
    left_error_classes: tuple[StrictStr, ...] = Field(default=(), max_length=16)
    right_error_classes: tuple[StrictStr, ...] = Field(default=(), max_length=16)
    left_operation_available: StrictBool
    right_operation_available: StrictBool
    evidence_digest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def safe_differential(self) -> "GraphQLIdentityDifferential":
        for name in (
            "added_shape",
            "removed_shape",
            "added_typenames",
            "removed_typenames",
            "left_error_classes",
            "right_error_classes",
        ):
            values = tuple(sorted(set(getattr(self, name))))
            object.__setattr__(self, name, values)
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL identity differential"
        )
        return self


class GraphQLAuthenticatedDiscoveryResult(ResearchContract):
    delta: GraphQLSemanticDelta
    probe_outcomes: tuple[GraphQLProbeOutcome, ...] = Field(default=(), max_length=64)
    differentials: tuple[GraphQLIdentityDifferential, ...] = Field(
        default=(), max_length=64
    )
    request_delta: RequestDelta = Field(default_factory=RequestDelta)
    limitations: tuple[StrictStr, ...] = Field(default=(), max_length=100)


def _graphql_path_candidate(url: str) -> bool:
    words = {
        value
        for value in __import__("re").split(r"[^a-z0-9]+", urlparse(url).path.lower())
        if value
    }
    return bool(words & {"graphql", "gql"}) or urlparse(url).path.lower() == "/query"


def _method(value: Any) -> str:
    rendered = str(value or "POST").upper()
    return rendered if rendered in {"GET", "POST"} else "POST"


def _safe_url(value: Any, target_url: str | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.startswith("/") and target_url:
        candidate = urljoin(target_url, candidate)
    parsed = urlparse(candidate)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


_PUBLIC_PAGE_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_PUBLIC_CLIENT_CONTENT_TYPES = frozenset(
    {
        "application/javascript",
        "application/typescript",
        "application/x-javascript",
        "text/javascript",
        "text/plain",
        "text/typescript",
    }
)
_PUBLIC_MANIFEST_CONTENT_TYPES = frozenset(
    {
        "application/json",
        "application/manifest+json",
        "application/graphql",
        "text/plain",
    }
)
_GRAPHQL_DOCUMENT_PREFIX = re.compile(
    r"^(?:(?:\s+|#[^\r\n]*(?:\r?\n|$))*)(?:query\b|mutation\b|"
    r"subscription\b|fragment\b|\{)",
    re.IGNORECASE,
)
_PERSONAL_LITERAL = re.compile(
    r"(?:\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b|"
    r"\bpersonal[-_ ]?data(?:[-_ ](?:value[-_ ]?)?sentinel)?\b|"
    r"\b(?:api[-_ ]?key|credential|jwt|password|secret)"
    r"[-_ ](?:value[-_ ]?)?sentinel\b)",
    re.IGNORECASE,
)


def _content_type(response: Any) -> str:
    value = str(getattr(response, "headers", {}).get("Content-Type", ""))
    return value.partition(";")[0].strip().lower()


def _within_public_target(url: str, target_url: str) -> bool:
    candidate = urlparse(url)
    target = urlparse(target_url)
    if (
        candidate.scheme not in {"http", "https"}
        or candidate.scheme != target.scheme
        or candidate.netloc != target.netloc
        or candidate.username is not None
        or candidate.password is not None
        or candidate.fragment
    ):
        return False
    target_path = target.path or "/"
    if target_path in {"", "/"}:
        return True
    prefix = target_path.rstrip("/")
    return candidate.path == prefix or candidate.path.startswith(prefix + "/")


class _PublicApplicationHTMLParser(HTMLParser):
    """Collect only explicit public script and manifest references."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.asset_references: list[tuple[str, str]] = []
        self.inline_sources: list[tuple[str, str]] = []
        self._inline_kind: str | None = None
        self._inline_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.casefold(): value or "" for name, value in attrs}
        normalized_tag = tag.casefold()
        if normalized_tag == "script":
            source = attributes.get("src")
            media_type = attributes.get("type", "").partition(";")[0].casefold()
            kind = (
                "public_persisted_manifest"
                if media_type
                in {
                    "application/json",
                    "application/manifest+json",
                }
                else "public_client_asset"
            )
            if source:
                self.asset_references.append((source, kind))
            elif not media_type or media_type in (
                _PUBLIC_CLIENT_CONTENT_TYPES | _PUBLIC_MANIFEST_CONTENT_TYPES
            ):
                self._inline_kind = kind
                self._inline_parts = []
        elif normalized_tag == "link" and attributes.get("href"):
            relations = set(attributes.get("rel", "").casefold().split())
            if relations.intersection(
                {
                    "graphql-manifest",
                    "operation-manifest",
                    "persisted-operations",
                }
            ):
                self.asset_references.append(
                    (attributes["href"], "public_persisted_manifest")
                )

    def handle_data(self, data: str) -> None:
        if self._inline_kind is not None:
            self._inline_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "script" and self._inline_kind is not None:
            self.inline_sources.append(("".join(self._inline_parts), self._inline_kind))
            self._inline_kind = None
            self._inline_parts = []


def _decode_javascript_literal(quote: str, body: str) -> str | None:
    if quote == "`":
        if "${" in body or "\\" in body:
            return None
        return body
    try:
        value = ast.literal_eval(quote + body + quote)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _javascript_string_literals(source: str) -> tuple[str, ...]:
    """Read standalone string literals without evaluating or joining source."""

    output: list[str] = []
    index = 0
    length = len(source)
    while index < length and len(output) < 256:
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            index = length if close < 0 else close + 2
            continue
        quote = source[index]
        if quote not in {"'", '"', "`"}:
            index += 1
            continue
        cursor = index + 1
        escaped = False
        while cursor < length:
            character = source[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                break
            cursor += 1
        if cursor >= length:
            break
        decoded = _decode_javascript_literal(quote, source[index + 1 : cursor])
        if decoded is not None:
            output.append(decoded)
        index = cursor + 1
    return tuple(output)


def _manifest_string_values(value: Any) -> tuple[str, ...]:
    output: list[str] = []

    def visit(candidate: Any, depth: int) -> None:
        if depth > 8 or len(output) >= 256:
            return
        if isinstance(candidate, str):
            output.append(candidate)
        elif isinstance(candidate, Mapping):
            for item in list(candidate.values())[:128]:
                visit(item, depth + 1)
        elif isinstance(candidate, Sequence) and not isinstance(
            candidate, (str, bytes, bytearray)
        ):
            for item in list(candidate)[:128]:
                visit(item, depth + 1)

    visit(value, 0)
    return tuple(output)


def _exact_public_graphql_documents(
    source: str,
    *,
    source_kind: str,
    maximum_documents: int,
) -> tuple[
    tuple[ParsedGraphQLDocument, ...],
    tuple[PublicGraphQLOperationValidationDiagnostic, ...],
]:
    """Extract whole explicit literals and validate them with the bounded parser."""

    values: tuple[str, ...]
    if source_kind == "public_persisted_manifest":
        try:
            manifest = json.loads(source)
        except (TypeError, ValueError, json.JSONDecodeError):
            manifest = None
        values = (
            _manifest_string_values(manifest) if manifest is not None else (source,)
        )
    else:
        values = (
            (source, *_javascript_string_literals(source))
            if _GRAPHQL_DOCUMENT_PREFIX.match(source)
            else _javascript_string_literals(source)
        )
    documents: list[ParsedGraphQLDocument] = []
    diagnostics: list[PublicGraphQLOperationValidationDiagnostic] = []
    for value in values:
        if len(documents) >= maximum_documents:
            break
        if _GRAPHQL_DOCUMENT_PREFIX.match(value) is None:
            continue
        try:
            reject_secret_material(value, location="public GraphQL document")
            if _PERSONAL_LITERAL.search(value):
                raise SecretMaterialRejected(
                    "public GraphQL document contains personal literal material"
                )
            parsed = parse_graphql_document(value)
        except (GraphQLDocumentError, SecretMaterialRejected, ValueError) as exc:
            diagnostics.append(
                _public_graphql_validation_diagnostic(
                    PublicGraphQLOperationValidationStage.parser, exc
                )
            )
            continue
        documents.append(parsed)
    deduplicated = {document.document_digest: document for document in documents}
    return (
        tuple(deduplicated[key] for key in sorted(deduplicated)),
        _bounded_validation_diagnostics(diagnostics),
    )


class PublicGraphQLOperationAcquirer:
    """Acquire exact public application documents through the shared HTTP authority."""

    def __init__(
        self,
        *,
        client: ScopedHTTPClient,
        policy: AssessmentPolicy,
        config: PublicGraphQLOperationAcquisitionConfig | None = None,
    ) -> None:
        if client.policy is not policy or client.budget is None:
            raise ValueError(
                "public GraphQL acquisition must share policy and request budget"
            )
        self.client = client
        self.policy = policy
        self.config = config or PublicGraphQLOperationAcquisitionConfig()

    def acquire(
        self,
        *,
        target_url: str,
        endpoint_url: str,
        surface_reference: str,
        method: Literal["GET", "POST"] = "POST",
    ) -> PublicGraphQLOperationAcquisitionResult:
        if not _within_public_target(endpoint_url, target_url):
            raise ValueError("GraphQL surface is outside the canonical target boundary")
        before = self.client.budget.snapshot()
        request_allowance = min(
            self.config.maximum_requests,
            max(0, self.client.budget.remaining - 1),
        )
        limitations: set[str] = set()
        sources: list[RegisteredGraphQLOperationSource] = []
        diagnostics: list[PublicGraphQLOperationValidationDiagnostic] = []
        assets_examined = 0

        def register_source(
            *,
            source_kind: str,
            source_locator: str,
            document: ParsedGraphQLDocument,
        ) -> None:
            try:
                sources.append(
                    self._source(
                        endpoint_url=endpoint_url,
                        source_kind=source_kind,
                        source_locator=source_locator,
                        surface_reference=surface_reference,
                        document=document,
                        method=method,
                    )
                )
            except ValidationError as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.public_source_validation,
                        exc,
                    )
                )

        def fetch(url: str, byte_limit: int, accept: str) -> tuple[str, str] | None:
            consumed = RequestDelta.from_snapshots(
                before, self.client.budget.snapshot()
            ).total
            if consumed >= request_allowance:
                limitations.add("public_graphql_source_request_ceiling_reached")
                return None
            try:
                response, _ = self.client.request(
                    "GET",
                    url,
                    headers={
                        "Accept": accept,
                        "User-Agent": "CyberCortexAI-Public-GraphQL-Discovery/1",
                    },
                    timeout=self.config.timeout_seconds,
                    response_byte_limit=byte_limit,
                    follow_redirects=False,
                    max_redirects=0,
                    purpose="discovery",
                    allow_session_credentials=False,
                    isolate_session_cookies=True,
                )
            except (
                OSError,
                PolicyViolationError,
                RequestBudgetExceeded,
                RequestException,
                ResponseTooLargeError,
                TimeoutError,
            ):
                limitations.add("public_graphql_source_retrieval_failed")
                return None
            if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
                limitations.add("public_graphql_source_response_rejected")
                return None
            raw = bytes(getattr(response, "content", b"") or b"")
            try:
                return raw.decode("utf-8-sig"), _content_type(response)
            except UnicodeDecodeError:
                limitations.add("public_graphql_source_encoding_rejected")
                return None

        if request_allowance == 0:
            limitations.add("public_graphql_source_budget_unavailable")
        else:
            page = fetch(
                target_url,
                self.config.maximum_page_bytes,
                "text/html, application/xhtml+xml",
            )
            if page is not None:
                page_text, page_type = page
                if page_type in _PUBLIC_PAGE_CONTENT_TYPES:
                    parser = _PublicApplicationHTMLParser()
                    try:
                        parser.feed(page_text)
                        parser.close()
                    except (TypeError, ValueError):
                        limitations.add("public_graphql_page_parse_failed")
                    else:
                        for index, (inline, kind) in enumerate(
                            parser.inline_sources[: self.config.maximum_assets]
                        ):
                            if assets_examined >= self.config.maximum_assets:
                                break
                            assets_examined += 1
                            documents, rejected = _exact_public_graphql_documents(
                                inline,
                                source_kind=kind,
                                maximum_documents=(
                                    self.config.maximum_documents - len(sources)
                                ),
                            )
                            if rejected:
                                limitations.add("public_graphql_document_rejected")
                                diagnostics.extend(rejected)
                            for document in documents:
                                register_source(
                                    source_kind=kind,
                                    source_locator=f"inline:{index}",
                                    document=document,
                                )
                        seen_assets: set[str] = set()
                        for reference, kind in parser.asset_references:
                            if (
                                assets_examined >= self.config.maximum_assets
                                or len(sources) >= self.config.maximum_documents
                            ):
                                break
                            asset_url = urljoin(target_url, reference)
                            if asset_url in seen_assets or not _within_public_target(
                                asset_url, target_url
                            ):
                                continue
                            try:
                                reject_secret_material(
                                    asset_url,
                                    location="public GraphQL asset reference",
                                )
                            except SecretMaterialRejected:
                                limitations.add(
                                    "public_graphql_asset_reference_rejected"
                                )
                                continue
                            seen_assets.add(asset_url)
                            assets_examined += 1
                            acquired = fetch(
                                asset_url,
                                self.config.maximum_asset_bytes,
                                (
                                    "application/json, application/manifest+json, "
                                    "application/graphql, text/plain"
                                    if kind == "public_persisted_manifest"
                                    else "application/javascript, text/javascript, "
                                    "text/typescript, text/plain"
                                ),
                            )
                            if acquired is None:
                                continue
                            asset_text, asset_type = acquired
                            allowed_types = (
                                _PUBLIC_MANIFEST_CONTENT_TYPES
                                if kind == "public_persisted_manifest"
                                else _PUBLIC_CLIENT_CONTENT_TYPES
                            )
                            if asset_type not in allowed_types:
                                limitations.add(
                                    "public_graphql_asset_content_type_rejected"
                                )
                                continue
                            documents, rejected = _exact_public_graphql_documents(
                                asset_text,
                                source_kind=kind,
                                maximum_documents=(
                                    self.config.maximum_documents - len(sources)
                                ),
                            )
                            if rejected:
                                limitations.add("public_graphql_document_rejected")
                                diagnostics.extend(rejected)
                            for document in documents:
                                register_source(
                                    source_kind=kind,
                                    source_locator=asset_url,
                                    document=document,
                                )
                else:
                    limitations.add("public_graphql_page_content_type_rejected")

        after = self.client.budget.snapshot()
        return PublicGraphQLOperationAcquisitionResult(
            sources=tuple(sources[: self.config.maximum_documents]),
            request_delta=RequestDelta.from_snapshots(before, after),
            assets_examined=assets_examined,
            limitations=tuple(sorted(limitations)),
            diagnostics=_bounded_validation_diagnostics(diagnostics),
        )

    @staticmethod
    def _source(
        *,
        endpoint_url: str,
        source_kind: str,
        source_locator: str,
        surface_reference: str,
        document: ParsedGraphQLDocument,
        method: Literal["GET", "POST"],
    ) -> RegisteredGraphQLOperationSource:
        if source_kind not in {
            "public_client_asset",
            "public_persisted_manifest",
        }:
            raise ValueError("unsupported public GraphQL operation provenance")
        reference = stable_research_identifier(
            "public-graphql-operation-source",
            source_kind,
            source_locator,
            surface_reference,
            document.document_digest,
        )
        return RegisteredGraphQLOperationSource(
            endpoint_url=endpoint_url,
            method=method,
            source_kind=source_kind,
            source_reference=reference,
            document=document,
        )


def _graphql_tool_outputs(evidence: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(evidence, Mapping):
        return {}
    results = evidence.get("results")
    if not isinstance(results, Mapping):
        return {}
    output: dict[str, Mapping[str, Any]] = {}
    for name in (
        "graphql_endpoint_discovery",
        "graphql_query_analyzer",
        "graphql_schema_analyzer",
        "graphql_introspection_checker",
    ):
        envelope = results.get(name)
        if not isinstance(envelope, Mapping):
            continue
        value = envelope.get("output", envelope)
        if isinstance(value, Mapping):
            output[name] = value
    return output


class GraphQLSurfaceDetector:
    """Detect GraphQL only from bounded structural evidence, never names alone."""

    def detect(
        self,
        evidence: Any,
        *,
        target_id: str,
        target_url: str | None = None,
        vault: Any | None = None,
    ) -> GraphQLDetectionBatch:
        if hasattr(evidence, "requests") and hasattr(evidence, "source_ref"):
            return self._capture_batch(
                evidence, target_id=target_id, target_url=target_url, vault=vault
            )
        if hasattr(evidence, "model_dump"):
            evidence = evidence.model_dump(mode="python")
        observations: list[GraphQLSurfaceObservation] = []
        documents: list[GraphQLDetectedDocument] = []
        candidates = self._bounded_entries(evidence)
        for index, item in enumerate(candidates[:MAX_GRAPHQL_DISCOVERY_OBSERVATIONS]):
            url = _safe_url(
                item.get("url") or item.get("endpoint") or item.get("path"),
                target_url,
            )
            if url is None:
                continue
            document_text = self._document_text(item)
            parsed_document: ParsedGraphQLDocument | None = None
            if document_text is not None:
                try:
                    parsed_document = parse_graphql_document(document_text)
                except (GraphQLDocumentError, ValueError):
                    parsed_document = None
            registered_operation_source = self._registered_operation_source(item)
            response_value = item.get("response")
            response: GraphQLResponseObservation | None = (
                item.get("response_observation")
                if isinstance(
                    item.get("response_observation"), GraphQLResponseObservation
                )
                else None
            )
            content_type = str(
                item.get("content_type")
                or " ".join(str(value) for value in item.get("content_types") or ())
            )
            if response is None and response_value is not None:
                response = analyze_graphql_response(
                    response_value,
                    status_code=(
                        item.get("status_code")
                        if isinstance(item.get("status_code"), int)
                        else None
                    ),
                    content_type=content_type,
                    request_was_graphql=parsed_document is not None,
                )
            signals = self._signals(
                item,
                url=url,
                parsed_document=parsed_document,
                response=response,
                content_type=content_type,
            )
            if not signals:
                continue
            confidence = self._confidence(signals, parsed_document, response)
            source_reference = opaque_reference(
                item.get("source_reference")
                or item.get("source")
                or f"graphql-evidence-{index}",
                "graphql-source",
            )
            safe_digest_input = {
                "url": url,
                "method": _method(item.get("method")),
                "signals": signals,
                "document_digest": (
                    parsed_document.document_digest if parsed_document else None
                ),
                "response_digest": response.evidence_digest if response else None,
            }
            observation = GraphQLSurfaceObservation(
                observation_id=stable_research_identifier(
                    "graphql-observation",
                    target_id,
                    url,
                    source_reference,
                    digest_for(safe_digest_input),
                ),
                target_id=target_id,
                endpoint_url=url,
                method=_method(item.get("method")),
                confidence=confidence,
                evidence_signals=tuple(signals),
                source_kind=opaque_reference(
                    item.get("source_kind") or item.get("source") or "discovery",
                    "graphql-source-kind",
                ),
                source_reference=source_reference,
                evidence_digest=digest_for(safe_digest_input),
                identity_id=(
                    str(item["identity_id"]) if item.get("identity_id") else None
                ),
                request_document_digest=(
                    parsed_document.document_digest
                    if parsed_document is not None and registered_operation_source
                    else None
                ),
                response_evidence_digest=(
                    response.evidence_digest if response else None
                ),
                response_truncated=bool(response and response.truncated),
            )
            observations.append(observation)
            if parsed_document is not None and registered_operation_source:
                documents.append(
                    GraphQLDetectedDocument(
                        observation_id=observation.observation_id,
                        document=parsed_document,
                        response=response,
                    )
                )
        return self._deduplicate(observations, documents)

    @staticmethod
    def _registered_operation_source(item: Mapping[str, Any]) -> bool:
        """Accept executable semantics only from an explicit trusted source."""

        return item.get("_operation_authority") is _REGISTERED_CAPTURE_AUTHORITY

    @staticmethod
    def _bounded_entries(evidence: Any) -> list[dict[str, Any]]:
        if isinstance(evidence, Sequence) and not isinstance(
            evidence, (str, bytes, bytearray)
        ):
            return [
                item if isinstance(item, dict) else {"url": item} for item in evidence
            ][:MAX_GRAPHQL_DISCOVERY_OBSERVATIONS]
        if not isinstance(evidence, Mapping):
            return []
        output: list[dict[str, Any]] = []
        tool_outputs = _graphql_tool_outputs(evidence)
        endpoint_discovery = tool_outputs.get("graphql_endpoint_discovery", {})
        tool_endpoints: list[dict[str, Any]] = []
        for key in (
            "observed_candidates",
            "confirmed_endpoints",
            "likely_endpoints",
        ):
            values = endpoint_discovery.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                item = dict(value) if isinstance(value, Mapping) else {"url": value}
                item.setdefault("source_kind", "graphql_endpoint_discovery")
                item.setdefault("source_reference", f"tool:{key}")
                tool_endpoints.append(item)
                output.append(item)
        endpoint_urls = tuple(
            dict.fromkeys(
                str(item.get("url")) for item in tool_endpoints if item.get("url")
            )
        )
        if endpoint_urls:
            query_analysis = tool_outputs.get("graphql_query_analyzer")
            if query_analysis and query_analysis.get("success") is True:
                output.append(
                    {
                        "url": endpoint_urls[0],
                        "source_kind": "graphql_query_analyzer",
                        "source_reference": "tool:graphql_query_analyzer",
                        "evidence_types": ["query_analysis_structure"],
                    }
                )
            schema_analysis = tool_outputs.get("graphql_schema_analyzer")
            if schema_analysis and schema_analysis.get("success") is True:
                output.append(
                    {
                        "url": endpoint_urls[0],
                        "source_kind": "graphql_schema_analyzer",
                        "source_reference": "tool:graphql_schema_analyzer",
                        "evidence_types": ["schema_analysis_structure"],
                    }
                )
        introspection = tool_outputs.get("graphql_introspection_checker")
        if introspection:
            introspection_evidence = introspection.get("evidence")
            endpoint = (
                introspection_evidence.get("endpoint")
                if isinstance(introspection_evidence, Mapping)
                else None
            )
            if endpoint is None and endpoint_urls:
                endpoint = endpoint_urls[0]
            if endpoint is not None:
                available = (
                    introspection.get("introspection_status")
                    == "introspection_available"
                )
                output.append(
                    {
                        "url": endpoint,
                        "source_kind": "graphql_introspection_checker",
                        "source_reference": "tool:graphql_introspection_checker",
                        "evidence_types": [
                            (
                                "introspection_structure"
                                if available
                                else "introspection_observation"
                            )
                        ],
                    }
                )
        for key in (
            "observed_candidates",
            "confirmed_endpoints",
            "likely_endpoints",
            "requests",
            "captured_requests",
            "routes",
            "operations",
            "candidates",
        ):
            values = evidence.get(key)
            if isinstance(values, list):
                output.extend(
                    item if isinstance(item, dict) else {"url": item} for item in values
                )
            if len(output) >= MAX_GRAPHQL_DISCOVERY_OBSERVATIONS:
                break
        graphql = evidence.get("graphql")
        if isinstance(graphql, Mapping):
            for item in graphql.get("operations") or ():
                if isinstance(item, Mapping):
                    output.append(dict(item))
        if not output and any(
            key in evidence for key in ("url", "endpoint", "path", "query", "body")
        ):
            output.append(dict(evidence))
        return output[:MAX_GRAPHQL_DISCOVERY_OBSERVATIONS]

    @staticmethod
    def _document_text(item: Mapping[str, Any]) -> str | None:
        query = item.get("query") or item.get("graphql_document")
        if isinstance(query, str):
            return query
        body = item.get("request_body") or item.get("body")
        if isinstance(body, Mapping) and isinstance(body.get("query"), str):
            return str(body["query"])
        if isinstance(body, str) and len(body.encode("utf-8")) <= 262_144:
            try:
                decoded = json.loads(body)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, Mapping) and isinstance(decoded.get("query"), str):
                return str(decoded["query"])
            if body.lstrip().startswith(("query", "mutation", "subscription", "{")):
                return body
        return None

    @staticmethod
    def _signals(
        item: Mapping[str, Any],
        *,
        url: str,
        parsed_document: ParsedGraphQLDocument | None,
        response: GraphQLResponseObservation | None,
        content_type: str,
    ) -> list[str]:
        signals: set[str] = set()
        if _graphql_path_candidate(url):
            signals.add("graphql_route_name")
        if parsed_document is not None:
            signals.add("graphql_document")
        evidence_types = item.get("evidence_types") or ()
        for value in evidence_types if isinstance(evidence_types, list) else ():
            rendered = str(value)
            if rendered in {
                "graphql_content_type",
                "graphql_json_response",
                "schema_response",
                "schema_analysis_structure",
                "introspection_structure",
            }:
                signals.add(rendered)
            elif rendered != "graphql_route_name":
                signals.add("existing_discovery:" + rendered)
        if (
            "graphql-response+json" in content_type.lower()
            or "application/graphql" in content_type.lower()
        ):
            signals.add("graphql_content_type")
        if response is not None and response.is_graphql:
            signals.add("graphql_response_envelope")
            if response.errors_present:
                signals.add("graphql_error_envelope")
            if response.typename_observations:
                signals.add("typename_observation")
        raw_response = item.get("response")
        if isinstance(raw_response, Mapping):
            data = raw_response.get("data")
            if isinstance(data, Mapping) and isinstance(data.get("__schema"), Mapping):
                signals.add("introspection_structure")
        return sorted(signals)

    @staticmethod
    def _confidence(
        signals: Sequence[str],
        document: ParsedGraphQLDocument | None,
        response: GraphQLResponseObservation | None,
    ) -> GraphQLDiscoveryConfidence:
        if set(signals).intersection(
            {
                "introspection_structure",
                "schema_analysis_structure",
                "schema_response",
                "graphql_json_response",
                "graphql_content_type",
            }
        ) or (
            response is not None
            and response.is_graphql
            and (
                document is not None
                or "graphql_content_type" in signals
                or bool(response.typename_observations)
            )
        ):
            return GraphQLDiscoveryConfidence.confirmed
        if document is not None or any(
            signal != "graphql_route_name" for signal in signals
        ):
            return GraphQLDiscoveryConfidence.observed
        return GraphQLDiscoveryConfidence.candidate

    def _capture_batch(
        self,
        bundle: Any,
        *,
        target_id: str,
        target_url: str | None,
        vault: Any | None,
    ) -> GraphQLDetectionBatch:
        entries: list[dict[str, Any]] = []
        for request in list(getattr(bundle, "requests", ()) or ())[
            :MAX_GRAPHQL_DISCOVERY_OBSERVATIONS
        ]:
            item: dict[str, Any] = {
                "url": getattr(request, "url", None) or target_url,
                "method": getattr(request, "method", "POST"),
                "source": getattr(request, "source_format", "capture"),
                "source_kind": "capture",
                "source_reference": getattr(request, "request_id", None)
                or getattr(bundle, "source_ref", "capture"),
                "identity_id": getattr(request, "identity_id", None),
                "content_type": getattr(
                    getattr(request, "response", None), "content_type", None
                ),
                "_operation_authority": _REGISTERED_CAPTURE_AUTHORITY,
            }
            body_reference = getattr(request, "execution_body_ref", None)
            if body_reference and vault is not None:
                try:
                    item["body"] = vault.get(body_reference)
                except (KeyError, RuntimeError):
                    pass
            if getattr(request, "body_type", None) == "graphql" or getattr(
                request, "graphql_operation", None
            ):
                item.setdefault("evidence_types", []).append("captured_graphql_request")
            response = getattr(request, "response", None)
            if response is not None:
                graphql = getattr(response, "graphql", None)
                if isinstance(graphql, Mapping) and graphql:
                    item["response_observation"] = (
                        GraphQLResponseObservation.model_validate_json(
                            json.dumps(graphql, sort_keys=True, separators=(",", ":"))
                        )
                    )
            entries.append(item)
        return self.detect(entries, target_id=target_id, target_url=target_url)

    @staticmethod
    def _deduplicate(
        observations: Sequence[GraphQLSurfaceObservation],
        documents: Sequence[GraphQLDetectedDocument],
    ) -> GraphQLDetectionBatch:
        ranks = {
            GraphQLDiscoveryConfidence.candidate: 0,
            GraphQLDiscoveryConfidence.observed: 1,
            GraphQLDiscoveryConfidence.confirmed: 2,
        }
        by_id: dict[str, GraphQLSurfaceObservation] = {}
        for item in observations:
            prior = by_id.get(item.observation_id)
            if prior is None or ranks[item.confidence] > ranks[prior.confidence]:
                by_id[item.observation_id] = item
        retained = set(by_id)
        docs: dict[tuple[str, str], GraphQLDetectedDocument] = {}
        for item in documents:
            if item.observation_id in retained:
                docs[(item.observation_id, item.document.document_digest)] = item
        return GraphQLDetectionBatch(
            observations=tuple(
                sorted(
                    by_id.values(),
                    key=lambda item: (
                        item.endpoint_url,
                        item.identity_id or "",
                        item.observation_id,
                    ),
                )
            ),
            documents=tuple(docs[key] for key in sorted(docs)),
        )


class GraphQLDiscoverySession:
    """Execute registered probes through one authoritative scoped client/ledger."""

    def __init__(
        self,
        *,
        client: ScopedHTTPClient,
        policy: AssessmentPolicy,
        request_budget: RequestBudget,
        config: GraphQLDiscoveryConfig | None = None,
    ) -> None:
        if client.policy is not policy or client.budget is not request_budget:
            raise ValueError(
                "GraphQL discovery must share the authoritative policy and request budget"
            )
        self.client = client
        self.policy = policy
        self.request_budget = request_budget
        self.config = config or GraphQLDiscoveryConfig()
        self._request_ceiling = min(
            self.config.maximum_graphql_discovery_requests,
            max(0, self.request_budget.limit - 1),
        )
        self._requests_used = 0

    @property
    def requests_used(self) -> int:
        return self._requests_used

    def execute(
        self,
        probe: GraphQLDiscoveryProbe,
        *,
        transient_headers: Mapping[str, str] | None = None,
        identity_authorized: bool = False,
        introspection_consumer: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> GraphQLProbeOutcome:
        definition = probe.definition
        if probe.probe_id is GraphQLProbeId.introspection_probe and (
            self.config.introspection_policy
            is not GraphQLIntrospectionPolicy.active_if_authorized
        ):
            return GraphQLProbeOutcome(
                probe_id=probe.probe_id,
                status="skipped",
                reason_code="introspection_policy_disabled",
            )
        if self._requests_used >= self._request_ceiling:
            return GraphQLProbeOutcome(
                probe_id=probe.probe_id,
                status="blocked",
                reason_code="graphql_request_ceiling_exhausted",
            )
        if self.request_budget.remaining <= 1:
            return GraphQLProbeOutcome(
                probe_id=probe.probe_id,
                status="blocked",
                reason_code="global_request_budget_reserve",
            )
        if transient_headers and (
            not probe.identity_id
            or not identity_authorized
            or not self.policy.credentials_allowed
        ):
            return GraphQLProbeOutcome(
                probe_id=probe.probe_id,
                status="blocked",
                reason_code="credential_policy_blocked",
            )

        before = self.request_budget.snapshot()
        payload: Mapping[str, Any] | None = None
        response_bound = min(
            self.config.maximum_response_bytes,
            definition.response_size_bound,
            self.policy.max_response_bytes,
        )
        try:
            response, _ = self.client.request(
                "POST",
                probe.endpoint_url,
                json={"query": definition.document},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/graphql-response+json, application/json",
                    "User-Agent": "CyberCortexAI-GraphQL-Discovery/1",
                    **dict(transient_headers or {}),
                },
                timeout=min(
                    self.config.timeout_seconds, definition.timeout_bound_seconds
                ),
                response_byte_limit=response_bound,
                follow_redirects=False,
                max_redirects=0,
                purpose="graphql_discovery",
                request_context={
                    "purpose": "graphql_discovery",
                    "policy_authorized": True,
                    "configured_url": probe.endpoint_url,
                    "configured_method": "POST",
                    "configured_endpoint_match": True,
                    "controlled_account_id": probe.controlled_account_id,
                    "account_controlled": bool(probe.identity_id),
                    "account_policy_authorized": bool(
                        probe.controlled_account_id and identity_authorized
                    ),
                    "workflow_category": "graphql_discovery",
                    "generated_by": "GraphQLDiscoverySession",
                    "graphql_probe_id": probe.probe_id.value,
                },
                isolate_session_cookies=True,
            )
            raw = bytes(getattr(response, "content", b"") or b"")
            if not raw and hasattr(response, "json"):
                try:
                    payload_value = response.json()
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload_value = None
                if payload_value is not None:
                    raw = json.dumps(
                        payload_value,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("utf-8")
            response_observation = analyze_graphql_response(
                raw,
                status_code=getattr(response, "status_code", None),
                content_type=str(
                    getattr(response, "headers", {}).get("Content-Type", "")
                ),
                max_bytes=response_bound,
                request_was_graphql=True,
            )
            if len(raw) <= response_bound:
                try:
                    decoded = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    decoded = None
                if isinstance(decoded, Mapping):
                    payload = decoded
        except ResponseTooLargeError:
            response_observation = GraphQLResponseObservation(
                envelope=GraphQLResponseEnvelope.oversized,
                evidence_digest="sha256:" + hashlib.sha256(b"").hexdigest(),
                response_bytes=response_bound,
                truncated=True,
            )
        except (PolicyViolationError, OSError, TimeoutError):
            response_observation = GraphQLResponseObservation(
                envelope=GraphQLResponseEnvelope.transport_failure,
                error_classes=(GraphQLErrorClass.transport_error,),
                evidence_digest="sha256:" + hashlib.sha256(b"").hexdigest(),
                response_bytes=0,
            )

        after = self.request_budget.snapshot()
        request_delta = RequestDelta.from_snapshots(before, after)
        if request_delta.total > 1:
            raise RuntimeError("GraphQL discovery probe exceeded its request estimate")
        self._requests_used += request_delta.total
        status = (
            "oversized"
            if response_observation.envelope is GraphQLResponseEnvelope.oversized
            else "transport_failure"
            if response_observation.envelope
            is GraphQLResponseEnvelope.transport_failure
            else "completed"
        )
        introspection_observed = bool(
            probe.probe_id is GraphQLProbeId.introspection_probe
            and isinstance(payload, Mapping)
            and isinstance(payload.get("data"), Mapping)
            and isinstance(payload["data"].get("__schema"), Mapping)
        )
        protocol_confirmed = bool(
            introspection_observed
            or response_observation.typename_observations
            or (
                response_observation.errors_present
                and response_observation.envelope
                in {
                    GraphQLResponseEnvelope.graphql_errors,
                    GraphQLResponseEnvelope.graphql_data_and_errors,
                }
            )
            or (
                "graphql-response+json"
                in str(
                    getattr(locals().get("response", None), "headers", {}).get(
                        "Content-Type", ""
                    )
                ).lower()
                and response_observation.is_graphql
            )
        )
        confidence = (
            GraphQLDiscoveryConfidence.confirmed
            if protocol_confirmed
            else GraphQLDiscoveryConfidence.observed
            if response_observation.is_graphql
            else GraphQLDiscoveryConfidence.candidate
        )
        signals = ["registered_probe:" + probe.probe_id.value]
        if response_observation.is_graphql:
            signals.append("graphql_response_envelope")
        if response_observation.typename_observations:
            signals.append("typename_observation")
        if introspection_observed:
            signals.append("introspection_structure")
        if response_observation.truncated:
            signals.append("response_truncated")
        source_reference = f"probe:{probe.probe_id.value}"
        observation = GraphQLSurfaceObservation(
            observation_id=stable_research_identifier(
                "graphql-observation",
                probe.target_id,
                probe.endpoint_url,
                probe.probe_id.value,
                probe.identity_id or "anonymous",
                response_observation.evidence_digest,
            ),
            target_id=probe.target_id,
            endpoint_url=probe.endpoint_url,
            confidence=confidence,
            evidence_signals=tuple(signals),
            source_kind="active_probe",
            source_reference=source_reference,
            evidence_digest=digest_for(
                {
                    "probe_id": probe.probe_id.value,
                    "response_digest": response_observation.evidence_digest,
                    "confidence": confidence.value,
                }
            ),
            identity_id=probe.identity_id,
            request_document_digest="sha256:"
            + hashlib.sha256(definition.document.encode("utf-8")).hexdigest(),
            response_evidence_digest=response_observation.evidence_digest,
            response_truncated=response_observation.truncated,
        )
        if introspection_observed and payload is not None and introspection_consumer:
            introspection_consumer(payload)
        return GraphQLProbeOutcome(
            probe_id=probe.probe_id,
            status=status,
            observation=observation,
            response=response_observation,
            request_delta=request_delta,
            introspection_observed=introspection_observed,
            reason_code=(
                "response_too_large"
                if status == "oversized"
                else "transport_failure"
                if status == "transport_failure"
                else None
            ),
        )


class GraphQLSemanticAcquirer:
    """Produce one atomic semantic delta using passive evidence before probes."""

    def __init__(
        self,
        *,
        config: GraphQLDiscoveryConfig | None = None,
        detector: GraphQLSurfaceDetector | None = None,
        ingestor: GraphQLSemanticIngestor | None = None,
        session: GraphQLDiscoverySession | None = None,
    ) -> None:
        self.config = config or GraphQLDiscoveryConfig()
        if session is not None and session.config != self.config:
            raise ValueError("GraphQL acquisition and session configuration must match")
        self.detector = detector or GraphQLSurfaceDetector()
        self.ingestor = ingestor or GraphQLSemanticIngestor()
        self.session = session

    def register_operations(
        self,
        state: ResearchState,
        sources: Sequence[RegisteredGraphQLOperationSource],
        *,
        target_id: str,
        occurred_at: str | None = None,
    ) -> GraphQLAcquisitionResult:
        """Import trusted parsed operations without transport or model activity."""

        deltas: list[GraphQLSemanticDelta] = []
        observations: list[GraphQLSurfaceObservation] = []
        limitations: set[str] = set()
        diagnostics: list[PublicGraphQLOperationValidationDiagnostic] = []
        working = state
        target = next(
            (item for item in state.targets if item.target_id == target_id), None
        )
        if target is None:
            raise ValueError("registered GraphQL operation target is unavailable")
        target_url = urlparse(target.canonical_reference)
        for source in sources:
            source_url = urlparse(source.endpoint_url)
            if (
                source_url.scheme != target_url.scheme
                or source_url.netloc != target_url.netloc
                or (
                    target_url.path not in {"", "/"}
                    and not source_url.path.startswith(
                        target_url.path.rstrip("/") + "/"
                    )
                    and source_url.path != target_url.path
                )
            ):
                limitations.add(
                    "A registered GraphQL operation source was outside its canonical "
                    "target boundary."
                )
                continue
            if source.identity_id is not None and not any(
                item.identity_id == source.identity_id
                and item.controlled
                and item.eligibility.value == "eligible"
                for item in state.identities
            ):
                limitations.add(
                    "A registered authenticated GraphQL operation lacked an eligible "
                    "controlled identity."
                )
                continue
            safe_digest_input = {
                "endpoint_url": source.endpoint_url,
                "method": source.method,
                "source_kind": source.source_kind,
                "source_reference": source.source_reference,
                "document_digest": source.document.document_digest,
                "identity_id": source.identity_id,
            }
            try:
                observation = GraphQLSurfaceObservation(
                    observation_id=stable_research_identifier(
                        "graphql-observation",
                        target_id,
                        source.endpoint_url,
                        source.source_reference,
                        source.document.document_digest,
                    ),
                    target_id=target_id,
                    endpoint_url=source.endpoint_url,
                    method=source.method,
                    confidence=GraphQLDiscoveryConfidence.observed,
                    evidence_signals=(
                        "graphql_document",
                        "registered_graphql_operation",
                    ),
                    source_kind=source.source_kind,
                    source_reference=opaque_reference(
                        source.source_reference, "graphql-source"
                    ),
                    evidence_digest=digest_for(safe_digest_input),
                    identity_id=source.identity_id,
                    request_document_digest=source.document.document_digest,
                    response_evidence_digest=(
                        source.response.evidence_digest if source.response else None
                    ),
                    response_truncated=bool(
                        source.response and source.response.truncated
                    ),
                )
            except ValidationError as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.observation_validation,
                        exc,
                    )
                )
                continue
            try:
                delta = self.ingestor.from_document(
                    working,
                    observation,
                    source.document,
                    occurred_at=occurred_at,
                    response=source.response,
                )
            except GraphQLDocumentError as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.semantic_delta_validation,
                        exc,
                    )
                )
                continue
            except ValidationError as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.semantic_delta_validation,
                        exc,
                    )
                )
                continue
            try:
                candidate = delta.apply(working)
            except (ValidationError, SecretMaterialRejected) as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.canonical_state_validation,
                        exc,
                    )
                )
                continue
            try:
                from agent_core.research.graphql_readiness import (
                    candidate_ready_graphql_operation_templates,
                )

                candidate_ready_graphql_operation_templates(candidate)
            except ValidationError as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.template_validation,
                        exc,
                    )
                )
                continue
            working = candidate
            deltas.append(delta)
            observations.append(observation)
        try:
            combined = GraphQLSemanticDelta.combine(deltas)
        except (ValidationError, SecretMaterialRejected) as exc:
            limitations.add("public_graphql_operation_validation_rejected")
            diagnostics.append(
                _public_graphql_validation_diagnostic(
                    PublicGraphQLOperationValidationStage.semantic_delta_validation,
                    exc,
                )
            )
            combined = GraphQLSemanticDelta()
            observations.clear()
        if deltas:
            try:
                combined.apply(state)
            except (ValidationError, SecretMaterialRejected) as exc:
                limitations.add("public_graphql_operation_validation_rejected")
                diagnostics.append(
                    _public_graphql_validation_diagnostic(
                        PublicGraphQLOperationValidationStage.canonical_state_validation,
                        exc,
                    )
                )
                combined = GraphQLSemanticDelta()
                observations.clear()
        return GraphQLAcquisitionResult(
            delta=combined,
            observations=tuple(observations),
            request_delta=RequestDelta(),
            limitations=tuple(sorted(limitations)),
            diagnostics=_bounded_validation_diagnostics(diagnostics),
        )

    def acquire(
        self,
        state: ResearchState,
        evidence: Any,
        *,
        target_id: str,
        target_url: str,
        vault: Any | None = None,
        passive_introspection_payloads: Mapping[str, Mapping[str, Any]] | None = None,
        occurred_at: str | None = None,
    ) -> GraphQLAcquisitionResult:
        batch = self.detector.detect(
            evidence,
            target_id=target_id,
            target_url=target_url,
            vault=vault,
        )
        documents = {item.observation_id: item for item in batch.documents}
        passive_schemas = dict(passive_introspection_payloads or {})
        tool_outputs = _graphql_tool_outputs(evidence)
        deltas: list[GraphQLSemanticDelta] = []
        limitations: set[str] = set()
        endpoint_by_id = {item.endpoint_id: item for item in state.endpoints}
        existing_surfaces_by_url = {
            urljoin(target_url, endpoint.route_template): surface
            for surface in state.graphql_surfaces
            if surface.target_id == target_id
            and (endpoint := endpoint_by_id.get(surface.endpoint_id)) is not None
        }
        adequate_urls: set[str] = set(existing_surfaces_by_url)
        introspection_evidence_ids = {
            item.evidence_id
            for item in state.evidence
            if item.evidence_kind.value == "graphql_introspection_result"
        }
        introspected_urls: set[str] = {
            endpoint_url
            for endpoint_url, surface in existing_surfaces_by_url.items()
            if introspection_evidence_ids.intersection(surface.evidence_references)
        }
        observed_urls = {item.endpoint_url for item in batch.observations}
        introspection_eligible_urls: set[str] = (
            set(adequate_urls) - introspected_urls
        ) & observed_urls

        for detected_observation in batch.observations:
            observation = detected_observation
            document = documents.get(observation.observation_id)
            if observation.identity_id is not None:
                identity = next(
                    (
                        item
                        for item in state.identities
                        if item.identity_id == observation.identity_id
                        or item.account_reference
                        == opaque_reference(observation.identity_id, "account")
                    ),
                    None,
                )
                if identity is None:
                    limitations.add(
                        "An authenticated GraphQL capture referenced an identity absent "
                        "from the canonical controlled context."
                    )
                    continue
                if identity.identity_id != observation.identity_id:
                    observation = observation.model_copy(
                        update={"identity_id": identity.identity_id}
                    )
                    if document is not None:
                        document = document.model_copy(
                            update={"observation_id": observation.observation_id}
                        )
            try:
                if document is not None:
                    deltas.append(
                        self.ingestor.from_document(
                            state,
                            observation,
                            document.document,
                            occurred_at=occurred_at,
                            response=document.response,
                        )
                    )
                elif observation.confidence in {
                    GraphQLDiscoveryConfidence.observed,
                    GraphQLDiscoveryConfidence.confirmed,
                }:
                    deltas.append(
                        self.ingestor.from_surface_observation(
                            state, observation, occurred_at=occurred_at
                        )
                    )
                schema = passive_schemas.get(observation.observation_id)
                if schema is not None:
                    encoded = json.dumps(
                        schema,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("utf-8")
                    if len(encoded) > self.config.maximum_response_bytes:
                        limitations.add(
                            "Passive GraphQL introspection evidence exceeded the "
                            "configured response bound."
                        )
                    else:
                        deltas.append(
                            self.ingestor.from_introspection(
                                state,
                                observation,
                                schema,
                                occurred_at=occurred_at,
                                max_types=self.config.maximum_types,
                                max_fields=self.config.maximum_fields,
                                max_arguments=self.config.maximum_arguments,
                            )
                        )
                        introspected_urls.add(observation.endpoint_url)
            except (GraphQLDocumentError, ValueError):
                limitations.add(
                    "Malformed or incompatible GraphQL evidence was rejected without "
                    "mutating research state."
                )
                continue
            if observation.confidence in {
                GraphQLDiscoveryConfidence.observed,
                GraphQLDiscoveryConfidence.confirmed,
            }:
                adequate_urls.add(observation.endpoint_url)
                introspection_eligible_urls.add(observation.endpoint_url)

        representative = next(iter(batch.observations), None)
        if representative is not None:
            for tool_name, adapter in (
                ("graphql_query_analyzer", self.ingestor.from_query_analysis),
                ("graphql_schema_analyzer", self.ingestor.from_schema_analysis),
            ):
                output = tool_outputs.get(tool_name)
                if output is None or output.get("success") is not True:
                    continue
                output_digest = digest_for(output)
                tool_observation = representative.model_copy(
                    update={
                        "observation_id": stable_research_identifier(
                            "graphql-observation",
                            representative.target_id,
                            representative.endpoint_url,
                            tool_name,
                            output_digest,
                        ),
                        "source_kind": tool_name,
                        "source_reference": f"tool:{tool_name}",
                        "evidence_digest": output_digest,
                    }
                )
                try:
                    deltas.append(
                        adapter(
                            state,
                            tool_observation,
                            output,
                            occurred_at=occurred_at,
                        )
                    )
                except (GraphQLDocumentError, ValueError):
                    limitations.add(
                        f"Bounded {tool_name} output could not be normalized."
                    )

            introspection_output = tool_outputs.get("graphql_introspection_checker")
            if (
                introspection_output is not None
                and introspection_output.get("introspection_status")
                == "introspection_available"
            ):
                evidence_output = introspection_output.get("evidence")
                response_summary = (
                    evidence_output.get("response_summary")
                    if isinstance(evidence_output, Mapping)
                    else None
                )
                schema = (
                    response_summary.get("data", {}).get("__schema", {})
                    if isinstance(response_summary, Mapping)
                    and isinstance(response_summary.get("data"), Mapping)
                    else {}
                )
                bounded_schema = {
                    key: schema.get(key)
                    for key in ("queryType", "mutationType", "subscriptionType")
                    if isinstance(schema, Mapping) and schema.get(key) is not None
                }
                bounded_schema["types"] = []
                output_digest = digest_for(introspection_output)
                tool_observation = representative.model_copy(
                    update={
                        "observation_id": stable_research_identifier(
                            "graphql-observation",
                            representative.target_id,
                            representative.endpoint_url,
                            "graphql_introspection_checker",
                            output_digest,
                        ),
                        "source_kind": "graphql_introspection_checker",
                        "source_reference": "tool:graphql_introspection_checker",
                        "evidence_digest": output_digest,
                    }
                )
                try:
                    deltas.append(
                        self.ingestor.from_introspection(
                            state,
                            tool_observation,
                            {"data": {"__schema": bounded_schema}},
                            occurred_at=occurred_at,
                            max_types=self.config.maximum_types,
                            max_fields=self.config.maximum_fields,
                            max_arguments=self.config.maximum_arguments,
                        )
                    )
                except (GraphQLDocumentError, ValueError):
                    limitations.add(
                        "Existing bounded introspection-checker output could not "
                        "be normalized."
                    )

        outcomes: list[GraphQLProbeOutcome] = []
        active_observations: list[GraphQLSurfaceObservation] = []
        if self.session is not None:
            candidates_by_url: dict[str, GraphQLSurfaceObservation] = {}
            for item in batch.observations:
                if (
                    item.confidence is GraphQLDiscoveryConfidence.candidate
                    and item.endpoint_url not in adequate_urls
                ):
                    candidates_by_url.setdefault(item.endpoint_url, item)
            candidates = [candidates_by_url[key] for key in sorted(candidates_by_url)]
            for candidate in candidates:
                outcome = self.session.execute(
                    GraphQLDiscoveryProbe(
                        probe_id=GraphQLProbeId.protocol_confirmation,
                        target_id=target_id,
                        endpoint_url=candidate.endpoint_url,
                    )
                )
                outcomes.append(outcome)
                if outcome.observation is None:
                    continue
                active_observations.append(outcome.observation)
                if outcome.observation.confidence in {
                    GraphQLDiscoveryConfidence.observed,
                    GraphQLDiscoveryConfidence.confirmed,
                }:
                    deltas.append(
                        self.ingestor.from_surface_observation(
                            state,
                            outcome.observation,
                            occurred_at=occurred_at,
                            response=outcome.response,
                        )
                    )
                    adequate_urls.add(candidate.endpoint_url)
                if (
                    outcome.observation.confidence
                    is GraphQLDiscoveryConfidence.confirmed
                ):
                    introspection_eligible_urls.add(candidate.endpoint_url)

            if (
                self.config.introspection_policy
                is GraphQLIntrospectionPolicy.active_if_authorized
            ):
                for endpoint_url in sorted(
                    introspection_eligible_urls - introspected_urls
                ):
                    payloads: list[Mapping[str, Any]] = []
                    outcome = self.session.execute(
                        GraphQLDiscoveryProbe(
                            probe_id=GraphQLProbeId.introspection_probe,
                            target_id=target_id,
                            endpoint_url=endpoint_url,
                        ),
                        introspection_consumer=payloads.append,
                    )
                    outcomes.append(outcome)
                    if outcome.observation is not None:
                        active_observations.append(outcome.observation)
                    if payloads and outcome.observation is not None:
                        try:
                            deltas.append(
                                self.ingestor.from_introspection(
                                    state,
                                    outcome.observation,
                                    payloads[0],
                                    occurred_at=occurred_at,
                                    max_types=self.config.maximum_types,
                                    max_fields=self.config.maximum_fields,
                                    max_arguments=self.config.maximum_arguments,
                                )
                            )
                        except (GraphQLDocumentError, ValueError):
                            limitations.add(
                                "Active GraphQL introspection evidence was bounded "
                                "but could not be normalized."
                            )

        request_delta = _sum_request_deltas(item.request_delta for item in outcomes)
        return GraphQLAcquisitionResult(
            delta=GraphQLSemanticDelta.combine(deltas),
            observations=tuple((*batch.observations, *active_observations)),
            probe_outcomes=tuple(outcomes),
            request_delta=request_delta,
            limitations=tuple(sorted(limitations)),
        )


class GraphQLAuthenticatedDiscovery:
    """Observe one fixed probe across anonymous and controlled identities."""

    def __init__(
        self,
        *,
        session: GraphQLDiscoverySession,
        policy: AssessmentPolicy,
        controlled_context: ControlledContext,
        vault: CredentialVault,
        ingestor: GraphQLSemanticIngestor | None = None,
    ) -> None:
        if session.policy is not policy:
            raise ValueError("authenticated GraphQL discovery must share policy")
        self.session = session
        self.policy = policy
        self.controlled_context = controlled_context
        self.vault = vault
        self.ingestor = ingestor or GraphQLSemanticIngestor()

    def observe(
        self,
        state: ResearchState,
        *,
        target_id: str,
        endpoint_url: str,
        probe_id: GraphQLProbeId = GraphQLProbeId.typename_probe,
        include_anonymous: bool = True,
        account_ids: Sequence[str] = (),
        occurred_at: str | None = None,
    ) -> GraphQLAuthenticatedDiscoveryResult:
        if probe_id is GraphQLProbeId.introspection_probe:
            raise ValueError(
                "identity differential discovery does not use schema introspection"
            )
        outcomes: list[GraphQLProbeOutcome] = []
        deltas: list[GraphQLSemanticDelta] = []
        limitations: set[str] = set()
        views: list[tuple[str, GraphQLProbeOutcome]] = []
        if include_anonymous:
            outcome = self.session.execute(
                GraphQLDiscoveryProbe(
                    probe_id=probe_id,
                    target_id=target_id,
                    endpoint_url=endpoint_url,
                )
            )
            outcomes.append(outcome)
            views.append(("anonymous", outcome))

        selected_accounts = [
            item
            for item in self.controlled_context.accounts
            if not account_ids or item.account_id in set(account_ids)
        ]
        for account in selected_accounts:
            binding = self._identity_binding(state, account)
            eligibility = self.policy.account_is_eligible(
                account.account_id,
                self.controlled_context,
                account_controlled=account.controlled,
            )
            if binding is None or not eligibility.eligible:
                limitations.add(
                    "A GraphQL controlled identity was not eligible under canonical "
                    "state and policy."
                )
                continue
            try:
                headers = self._materialize_headers(account)
            except (KeyError, RuntimeError, ValueError):
                limitations.add(
                    "A controlled GraphQL credential was unavailable at send time."
                )
                continue
            try:
                outcome = self.session.execute(
                    GraphQLDiscoveryProbe(
                        probe_id=probe_id,
                        target_id=target_id,
                        endpoint_url=endpoint_url,
                        identity_id=binding,
                        controlled_account_id=account.account_id,
                    ),
                    transient_headers=headers,
                    identity_authorized=True,
                )
            finally:
                headers.clear()
            outcomes.append(outcome)
            views.append((binding, outcome))

        for _, outcome in views:
            if (
                outcome.observation is not None
                and outcome.response is not None
                and outcome.observation.confidence
                in {
                    GraphQLDiscoveryConfidence.observed,
                    GraphQLDiscoveryConfidence.confirmed,
                }
            ):
                deltas.append(
                    self.ingestor.from_surface_observation(
                        state,
                        outcome.observation,
                        occurred_at=occurred_at,
                        response=outcome.response,
                    )
                )

        differentials: list[GraphQLIdentityDifferential] = []
        if views:
            left_identity, left = views[0]
            for right_identity, right in views[1:]:
                differential = self._differential(
                    endpoint_url,
                    probe_id,
                    left_identity,
                    left,
                    right_identity,
                    right,
                )
                if differential is None or right.observation is None:
                    continue
                differentials.append(differential)
                differential_observation = right.observation.model_copy(
                    update={
                        "observation_id": stable_research_identifier(
                            "graphql-observation",
                            "identity-differential",
                            differential.evidence_digest,
                        ),
                        "source_kind": "controlled_identity_differential",
                        "source_reference": "graphql:identity-differential",
                        "evidence_digest": differential.evidence_digest,
                    }
                )
                deltas.append(
                    self.ingestor.from_identity_differential(
                        state,
                        differential_observation,
                        differential,
                        occurred_at=occurred_at,
                    )
                )

        return GraphQLAuthenticatedDiscoveryResult(
            delta=GraphQLSemanticDelta.combine(deltas),
            probe_outcomes=tuple(outcomes),
            differentials=tuple(differentials),
            request_delta=_sum_request_deltas(item.request_delta for item in outcomes),
            limitations=tuple(sorted(limitations)),
        )

    def acquire_controlled_object(
        self,
        state: ResearchState,
        observation: GraphQLSurfaceObservation,
        evidence: GraphQLControlledObjectEvidence,
        *,
        occurred_at: str | None = None,
    ) -> GraphQLSemanticDelta:
        """Normalize one explicitly owner-scoped response without object enumeration."""

        identity = next(
            (
                item
                for item in state.identities
                if item.identity_id == evidence.identity_id
                and item.controlled
                and item.eligibility.value == "eligible"
            ),
            None,
        )
        if identity is None:
            raise GraphQLDocumentError(
                "controlled GraphQL object identity is not eligible"
            )
        account = next(
            (
                item
                for item in self.controlled_context.accounts
                if opaque_reference(item.account_id, "account")
                == identity.account_reference
            ),
            None,
        )
        if account is None:
            raise GraphQLDocumentError(
                "controlled GraphQL object has no controlled account binding"
            )
        eligibility = self.policy.account_is_eligible(
            account.account_id,
            self.controlled_context,
            account_controlled=account.controlled,
        )
        if not eligibility.eligible:
            raise GraphQLDocumentError(
                "controlled GraphQL object account is outside current policy"
            )
        return self.ingestor.controlled_object(
            state,
            observation,
            evidence,
            occurred_at=occurred_at,
        )

    def _identity_binding(
        self, state: ResearchState, account: ControlledAccount
    ) -> str | None:
        account_reference = opaque_reference(account.account_id, "account")
        match = next(
            (
                item
                for item in state.identities
                if item.account_reference == account_reference
                and item.controlled
                and item.eligibility.value == "eligible"
            ),
            None,
        )
        return match.identity_id if match is not None else None

    def _materialize_headers(self, account: ControlledAccount) -> dict[str, str]:
        if not self.policy.credentials_allowed:
            raise ValueError("controlled credentials are disabled")
        if account.session_reference:
            return {
                "Authorization": "Bearer " + self.vault.get(account.session_reference)
            }
        for name in ("authorization", "token", "api_key", "cookie"):
            reference = account.credential_references.get(name)
            if not reference:
                continue
            value = self.vault.get(reference)
            if name == "authorization":
                return {"Authorization": value}
            if name == "token":
                return {"Authorization": "Bearer " + value}
            if name == "api_key":
                return {"X-Api-Key": value}
            return {"Cookie": value}
        raise ValueError("controlled identity has no supported credential reference")

    @staticmethod
    def _operation_available(response: GraphQLResponseObservation | None) -> bool:
        if response is None or not response.is_graphql:
            return False
        unavailable = {
            GraphQLErrorClass.authentication_error,
            GraphQLErrorClass.authorization_error,
            GraphQLErrorClass.transport_error,
        }
        return not bool(unavailable & set(response.error_classes))

    @classmethod
    def _differential(
        cls,
        endpoint_url: str,
        probe_id: GraphQLProbeId,
        left_identity: str,
        left: GraphQLProbeOutcome,
        right_identity: str,
        right: GraphQLProbeOutcome,
    ) -> GraphQLIdentityDifferential | None:
        left_response = left.response
        right_response = right.response
        left_shape = set(left_response.object_shape if left_response else ())
        right_shape = set(right_response.object_shape if right_response else ())
        left_typenames = set(
            left_response.typename_observations if left_response else ()
        )
        right_typenames = set(
            right_response.typename_observations if right_response else ()
        )
        left_errors = tuple(
            item.value
            for item in (left_response.error_classes if left_response else ())
        )
        right_errors = tuple(
            item.value
            for item in (right_response.error_classes if right_response else ())
        )
        values = {
            "endpoint_url": endpoint_url,
            "probe_id": probe_id,
            "left_identity": left_identity,
            "right_identity": right_identity,
            "added_shape": tuple(sorted(right_shape - left_shape))[:64],
            "removed_shape": tuple(sorted(left_shape - right_shape))[:64],
            "added_typenames": tuple(sorted(right_typenames - left_typenames))[:64],
            "removed_typenames": tuple(sorted(left_typenames - right_typenames))[:64],
            "left_error_classes": left_errors,
            "right_error_classes": right_errors,
            "left_operation_available": cls._operation_available(left_response),
            "right_operation_available": cls._operation_available(right_response),
        }
        if not any(
            values[name]
            for name in (
                "added_shape",
                "removed_shape",
                "added_typenames",
                "removed_typenames",
            )
        ) and (
            left_errors == right_errors
            and values["left_operation_available"]
            == values["right_operation_available"]
        ):
            return None
        return GraphQLIdentityDifferential(
            **values,
            evidence_digest=digest_for(values),
        )


def _sum_request_deltas(values: Sequence[RequestDelta] | Any) -> RequestDelta:
    discovery = auth = verification = cleanup = 0
    for item in values:
        discovery += item.discovery
        auth += item.auth
        verification += item.verification
        cleanup += item.cleanup
    total = discovery + auth + verification + cleanup
    return RequestDelta(
        discovery=discovery,
        auth=auth,
        verification=verification,
        cleanup=cleanup,
        attempted=total,
        total=total,
    )


__all__ = [
    "GRAPHQL_DISCOVERY_VERSION",
    "GRAPHQL_PROBE_REGISTRY",
    "INTROSPECTION_PROBE_DOCUMENT",
    "MAX_GRAPHQL_DISCOVERY_OBSERVATIONS",
    "MAX_PUBLIC_GRAPHQL_ASSET_BYTES",
    "MAX_PUBLIC_GRAPHQL_ASSETS",
    "MAX_PUBLIC_GRAPHQL_DOCUMENTS",
    "MAX_PUBLIC_GRAPHQL_PAGE_BYTES",
    "MAX_PUBLIC_GRAPHQL_SOURCE_REQUESTS",
    "PROTOCOL_CONFIRMATION_DOCUMENT",
    "TYPENAME_PROBE_DOCUMENT",
    "GraphQLDetectedDocument",
    "GraphQLDetectionBatch",
    "GraphQLAcquisitionResult",
    "GraphQLAuthenticatedDiscovery",
    "GraphQLAuthenticatedDiscoveryResult",
    "GraphQLDiscoveryConfidence",
    "GraphQLDiscoveryConfig",
    "GraphQLDiscoveryProbe",
    "GraphQLDiscoverySession",
    "GraphQLIntrospectionPolicy",
    "GraphQLIdentityDifferential",
    "GraphQLProbeDefinition",
    "GraphQLProbeId",
    "GraphQLProbeOutcome",
    "GraphQLProbeStateChangeClass",
    "GraphQLSurfaceDetector",
    "GraphQLSurfaceObservation",
    "GraphQLSemanticAcquirer",
    "PublicGraphQLOperationAcquirer",
    "PublicGraphQLOperationAcquisitionConfig",
    "PublicGraphQLOperationAcquisitionResult",
    "PublicGraphQLOperationValidationDiagnostic",
    "PublicGraphQLOperationValidationStage",
    "RegisteredGraphQLOperationSource",
]
