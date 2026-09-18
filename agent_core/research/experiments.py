"""Strict contracts for advisory proposals and compiled security experiments."""

from __future__ import annotations

import re
import hashlib
import hmac
import json
import secrets
from enum import Enum
from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.research.primitives import (
    CompiledPrimitiveStep,
    DifferentialSelector,
    IdentityRelationship,
    MutationKind,
    PrimitiveStepProposal,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.types import (
    EndpointId,
    ExperimentId,
    GraphQLOperationId,
    HypothesisRecordId,
    IdentityId,
    OpaqueIdentifier,
    ParameterId,
    PublicText,
    ResearchContract,
    ResearchId,
    ResearchObjectId,
    SessionRefId,
    Sha256Digest,
    ShortPublicText,
    SurfaceId,
    TargetAssetId,
    TargetClass,
    Timestamp,
)

EXPERIMENT_PROPOSAL_SCHEMA_VERSION = 1
SECURITY_EXPERIMENT_SCHEMA_VERSION = 1

_ARBITRARY_URL = re.compile(r"\b(?:(?:https?|ftp)://|www\.)", re.IGNORECASE)
_RAW_HTTP = re.compile(
    r"(?:^|\n)\s*(?:GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+/\S+" r"(?:\s+HTTP/\d)?",
    re.IGNORECASE,
)
_EXECUTABLE = re.compile(
    r"(?:^#!|\bcurl\s+(?:-|\S)|\bpython(?:3)?\s+-c\b|\bsubprocess\.|"
    r"\bos\.system\s*\(|\bRuntime\.getRuntime\s*\(|```|"
    r"(?:^|\n)\s*(?:def\s+\w+\s*\(|class\s+\w+\s*[:(]|"
    r"from\s+\w+(?:\.\w+)*\s+import\s+|import\s+\w+|"
    r"(?:print|exec|eval)\s*\(|(?:ba|z|fi)?sh\s+|powershell\s+|"
    r"(?:rm|wget|chmod|chown|nc|netcat)\s+-))",
    re.IGNORECASE | re.MULTILINE,
)
_RAW_CREDENTIAL = re.compile(
    r"(?:\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*|"
    r"\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{12,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)",
    re.IGNORECASE,
)


class BaselineKind(str, Enum):
    registered_request = "registered_request"
    primary_identity = "primary_identity"
    prior_evidence = "prior_evidence"
    prior_outcome = "prior_outcome"
    before_state = "before_state"


class BaselineIntent(ResearchContract):
    kind: BaselineKind
    reference_id: OpaqueIdentifier


class MutationIntent(ResearchContract):
    """Advisory mutation intent containing registered references only."""

    kind: MutationKind | Literal["none", "context_switch", "differential"]
    parameter_id: ParameterId | None = None
    controlled_object_id: ResearchObjectId | None = None
    value_source_reference: OpaqueIdentifier | None = None


class EvidenceIntent(ResearchContract):
    selector: DifferentialSelector
    predicate_reference: OpaqueIdentifier
    minimum_artifacts: StrictInt = Field(default=1, ge=1, le=20)


class ExperimentProposal(ResearchContract):
    """Model-authored advice with no request, policy, or execution authority."""

    schema_version: Literal[EXPERIMENT_PROPOSAL_SCHEMA_VERSION] = (
        EXPERIMENT_PROPOSAL_SCHEMA_VERSION
    )
    proposal_id: OpaqueIdentifier
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    hypothesis_id: HypothesisRecordId
    capability: OpaqueIdentifier
    target_id: TargetAssetId
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    operation_id: GraphQLOperationId | None = None
    objective: ShortPublicText
    primary_identity_id: IdentityId | None = None
    comparison_identity_id: IdentityId | None = None
    primary_session_ref_id: SessionRefId | None = None
    comparison_session_ref_id: SessionRefId | None = None
    identity_relationship: IdentityRelationship | None = None
    baseline: BaselineIntent = Field(alias="baseline_strategy")
    mutation_intent: MutationIntent
    expected_secure_behavior: PublicText
    expected_vulnerable_behavior: PublicText
    required_evidence_intent: tuple[EvidenceIntent, ...] = Field(
        min_length=1, max_length=20
    )
    rationale: ShortPublicText
    primitive_steps: tuple[PrimitiveStepProposal, ...] = Field(
        min_length=1, max_length=30
    )
    provenance_id: OpaqueIdentifier
    model_decision_id: OpaqueIdentifier | None = None
    expires_at: Timestamp

    @model_validator(mode="after")
    def enforce_advisory_boundary(self) -> "ExperimentProposal":
        payload = self.model_dump(mode="json")
        reject_secret_material(payload, location="experiment proposal")
        for value in _all_strings(payload):
            if _ARBITRARY_URL.search(value) or _RAW_HTTP.search(value):
                raise ValueError("proposal contains arbitrary request content")
            if _EXECUTABLE.search(value):
                raise ValueError("proposal contains executable content")
            if _RAW_CREDENTIAL.search(value):
                raise ValueError("proposal contains raw credential material")
        step_ids = tuple(step.step_id for step in self.primitive_steps)
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("primitive step IDs must be unique")
        identity_pair_present = (
            self.primary_identity_id is not None
            and self.comparison_identity_id is not None
        )
        if (self.identity_relationship is not None) != identity_pair_present:
            raise ValueError(
                "identity relationship requires primary and comparison identities"
            )
        return self


def _all_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _all_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _all_strings(item)


class CapabilityRef(ResearchContract):
    name: OpaqueIdentifier
    version: OpaqueIdentifier
    legacy_adapter_reference: OpaqueIdentifier | None = None


class TypedTargetReference(ResearchContract):
    target_id: TargetAssetId
    target_class: TargetClass
    surface_id: SurfaceId | None = None
    endpoint_id: EndpointId | None = None
    operation_id: GraphQLOperationId | None = None
    method: OpaqueIdentifier | None = None
    parameter_ids: tuple[ParameterId, ...] = Field(default=(), max_length=50)


class IdentityContext(ResearchContract):
    primary_identity_id: IdentityId | None = None
    comparison_identity_id: IdentityId | None = None
    primary_session_ref_id: SessionRefId | None = None
    comparison_session_ref_id: SessionRefId | None = None
    relationship: IdentityRelationship | None = None


class Baseline(ResearchContract):
    kind: BaselineKind
    reference_id: OpaqueIdentifier


class ControlledMutation(ResearchContract):
    kind: OpaqueIdentifier
    parameter_ids: tuple[ParameterId, ...] = Field(default=(), max_length=50)
    controlled_object_ids: tuple[ResearchObjectId, ...] = Field(
        default=(), max_length=20
    )
    object_types: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=20)
    ownership_relationships: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    value_source_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )


class EvidenceRequirement(ResearchContract):
    selector: DifferentialSelector
    predicate_reference: OpaqueIdentifier
    minimum_artifacts: StrictInt = Field(ge=1, le=20)


class RequestEstimate(ResearchContract):
    """Predicted reservation; actual request use remains a RequestDelta."""

    discovery: StrictInt = Field(ge=0, le=10_000)
    auth: StrictInt = Field(ge=0, le=10_000)
    verification: StrictInt = Field(ge=0, le=10_000)
    cleanup: StrictInt = Field(ge=0, le=10_000)
    minimum: StrictInt = Field(ge=0, le=10_000)
    worst_case: StrictInt = Field(ge=0, le=10_000)
    total_reservation: StrictInt = Field(ge=0, le=10_000)

    @model_validator(mode="after")
    def validate_totals(self) -> "RequestEstimate":
        reserved = self.discovery + self.auth + self.verification + self.cleanup
        if reserved != self.total_reservation:
            raise ValueError("request reservation must equal categorized requests")
        if self.worst_case != self.total_reservation:
            raise ValueError("worst-case requests must equal the total reservation")
        if self.minimum > self.worst_case:
            raise ValueError("minimum requests cannot exceed worst case")
        return self


class RiskClassification(ResearchContract):
    level: RiskLevel
    derivation_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=30
    )


class CleanupPlan(ResearchContract):
    required: StrictBool
    cleanup_reference: OpaqueIdentifier | None = None
    verification_predicate_reference: OpaqueIdentifier | None = None
    minimum_requests: StrictInt = Field(default=0, ge=0, le=100)
    worst_case_requests: StrictInt = Field(default=0, ge=0, le=100)

    @model_validator(mode="after")
    def validate_cleanup(self) -> "CleanupPlan":
        references = (
            self.cleanup_reference,
            self.verification_predicate_reference,
        )
        if self.required and (any(item is None for item in references)):
            raise ValueError("required cleanup needs a reference and predicate")
        if self.required and self.worst_case_requests < 1:
            raise ValueError("required cleanup needs a request reserve")
        if not self.required and (any(item is not None for item in references)):
            raise ValueError("non-required cleanup cannot contain cleanup bindings")
        if not self.required and (self.minimum_requests or self.worst_case_requests):
            raise ValueError("non-required cleanup cannot reserve requests")
        if self.worst_case_requests < self.minimum_requests:
            raise ValueError("cleanup worst case must cover its minimum")
        return self


class PreconditionCode(str, Enum):
    research_revision_current = "research_revision_current"
    target_registered = "target_registered"
    surface_registered = "surface_registered"
    endpoint_registered = "endpoint_registered"
    request_template_registered = "request_template_registered"
    controlled_identity = "controlled_identity"
    controlled_session = "controlled_session"
    test_owned_object = "test_owned_object"
    ownership_evidence_present = "ownership_evidence_present"
    cleanup_reserved = "cleanup_reserved"


class Precondition(ResearchContract):
    code: PreconditionCode
    reference_id: OpaqueIdentifier


class Preconditions(ResearchContract):
    items: tuple[Precondition, ...] = Field(min_length=1, max_length=100)


class StopConditionCode(str, Enum):
    scope_violation = "scope_violation"
    budget_exhaustion = "budget_exhaustion"
    unexpected_state_change = "unexpected_state_change"
    cleanup_barrier = "cleanup_barrier"
    response_size_bound = "response_size_bound"
    service_instability = "service_instability"
    authorization_expiry = "authorization_expiry"
    state_revision_mismatch = "state_revision_mismatch"


class StopCondition(ResearchContract):
    code: StopConditionCode
    bound: StrictInt | None = Field(default=None, ge=1, le=100_000_000)


class StopConditions(ResearchContract):
    items: tuple[StopCondition, ...] = Field(min_length=8, max_length=8)

    @model_validator(mode="after")
    def require_complete_set(self) -> "StopConditions":
        codes = tuple(item.code for item in self.items)
        if len(codes) != len(set(codes)) or set(codes) != set(StopConditionCode):
            raise ValueError("stop conditions must contain the complete fixed set")
        return self


class ExperimentProvenance(ResearchContract):
    source_proposal_id: OpaqueIdentifier
    source_provenance_id: OpaqueIdentifier
    source_hypothesis_id: HypothesisRecordId
    research_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    compiler_version: OpaqueIdentifier
    primitive_registry_version: OpaqueIdentifier
    primitive_registry_hash: Sha256Digest
    source_model_decision_id: OpaqueIdentifier | None = None
    policy_reference: OpaqueIdentifier | None = None
    context_reference: OpaqueIdentifier | None = None


class SecurityExperiment(ResearchContract):
    """Immutable compiler output.  This record carries no execution authority."""

    schema_version: Literal[SECURITY_EXPERIMENT_SCHEMA_VERSION] = (
        SECURITY_EXPERIMENT_SCHEMA_VERSION
    )
    experiment_id: ExperimentId
    research_id: ResearchId
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    hypothesis_id: HypothesisRecordId
    capability: CapabilityRef
    primitive_steps: tuple[CompiledPrimitiveStep, ...] = Field(
        min_length=1, max_length=30
    )
    target: TypedTargetReference
    objective: ShortPublicText
    identity_context: IdentityContext
    baseline: Baseline
    mutation: ControlledMutation
    expected_secure_behavior: PublicText
    expected_vulnerable_behavior: PublicText
    required_evidence: tuple[EvidenceRequirement, ...] = Field(
        min_length=1, max_length=20
    )
    request_estimate: RequestEstimate
    risk: RiskClassification
    state_changing: StrictBool
    cleanup: CleanupPlan
    preconditions: Preconditions
    stop_conditions: StopConditions
    fingerprint: Sha256Digest
    reproduction_of: ExperimentId | None = None
    expires_at: Timestamp
    provenance: ExperimentProvenance

    @model_validator(mode="after")
    def validate_compiler_invariants(self) -> "SecurityExperiment":
        if self.state_changing != self.cleanup.required:
            raise ValueError("state-changing experiments require cleanup")
        if self.request_estimate.cleanup != self.cleanup.worst_case_requests:
            raise ValueError("cleanup reserve must match the cleanup plan")
        from agent_core.research.fingerprint import experiment_fingerprint

        if experiment_fingerprint(self) != self.fingerprint:
            raise ValueError("experiment fingerprint does not match its semantics")
        return self


_AUTHORIZATION_ISSUER = object()
_AUTHORIZATION_KEY = secrets.token_bytes(32)


def _authorization_plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, tuple):
        return [_authorization_plain(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _authorization_plain(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    return value


class AuthorizedExperiment:
    """One immutable, process-local authorization issued by the research gate."""

    __slots__ = (
        "__authorization_digest",
        "__authorization_nonce",
        "__authorization_timestamp",
        "__cleanup_reservation",
        "__controlled_identity_bindings",
        "__dry_run",
        "__executor_routes",
        "__experiment",
        "__expiry",
        "__issuer",
        "__owned_object_bindings",
        "__policy_decision_id",
        "__policy_hash",
        "__policy_reference",
        "__request_budget_reservation",
        "__runtime_binding_reference",
        "__scope_reference",
        "__target_fingerprint",
    )

    def __init__(
        self,
        *_args: object,
        _issuer: object | None = None,
        experiment: SecurityExperiment | None = None,
        policy_decision_id: str = "",
        policy_hash: str = "",
        policy_reference: str = "",
        target_fingerprint: str = "",
        scope_reference: str = "",
        controlled_identity_bindings: tuple[object, ...] = (),
        owned_object_bindings: tuple[object, ...] = (),
        request_budget_reservation: object | None = None,
        cleanup_reservation: object | None = None,
        executor_routes: tuple[object, ...] = (),
        authorization_timestamp: str = "",
        expiry: str = "",
        runtime_binding_reference: str = "",
        dry_run: bool = False,
    ) -> None:
        if _issuer is not _AUTHORIZATION_ISSUER or experiment is None or _args:
            raise TypeError("AuthorizedExperiment sealing is reserved for P4-0D")
        object.__setattr__(self, "_AuthorizedExperiment__issuer", _issuer)
        object.__setattr__(self, "_AuthorizedExperiment__experiment", experiment)
        object.__setattr__(
            self, "_AuthorizedExperiment__policy_decision_id", policy_decision_id
        )
        object.__setattr__(self, "_AuthorizedExperiment__policy_hash", policy_hash)
        object.__setattr__(
            self, "_AuthorizedExperiment__policy_reference", policy_reference
        )
        object.__setattr__(
            self, "_AuthorizedExperiment__target_fingerprint", target_fingerprint
        )
        object.__setattr__(
            self, "_AuthorizedExperiment__scope_reference", scope_reference
        )
        object.__setattr__(
            self,
            "_AuthorizedExperiment__controlled_identity_bindings",
            controlled_identity_bindings,
        )
        object.__setattr__(
            self,
            "_AuthorizedExperiment__owned_object_bindings",
            owned_object_bindings,
        )
        object.__setattr__(
            self,
            "_AuthorizedExperiment__request_budget_reservation",
            request_budget_reservation,
        )
        object.__setattr__(
            self, "_AuthorizedExperiment__cleanup_reservation", cleanup_reservation
        )
        object.__setattr__(
            self, "_AuthorizedExperiment__executor_routes", executor_routes
        )
        object.__setattr__(
            self,
            "_AuthorizedExperiment__authorization_timestamp",
            authorization_timestamp,
        )
        object.__setattr__(self, "_AuthorizedExperiment__expiry", expiry)
        object.__setattr__(
            self,
            "_AuthorizedExperiment__runtime_binding_reference",
            runtime_binding_reference,
        )
        object.__setattr__(self, "_AuthorizedExperiment__dry_run", dry_run)
        object.__setattr__(
            self,
            "_AuthorizedExperiment__authorization_nonce",
            secrets.token_hex(16),
        )
        digest = hmac.new(
            _AUTHORIZATION_KEY,
            self._seal_material(),
            hashlib.sha256,
        ).hexdigest()
        object.__setattr__(
            self,
            "_AuthorizedExperiment__authorization_digest",
            f"sha256:{digest}",
        )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("AuthorizedExperiment cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("AuthorizedExperiment is immutable")

    @property
    def experiment(self) -> SecurityExperiment:
        return self.__experiment

    @property
    def experiment_id(self) -> str:
        return self.__experiment.experiment_id

    @property
    def experiment_fingerprint(self) -> str:
        return self.__experiment.fingerprint

    @property
    def research_id(self) -> str:
        return self.__experiment.research_id

    @property
    def state_revision(self) -> int:
        return self.__experiment.state_revision

    @property
    def policy_decision_id(self) -> str:
        return self.__policy_decision_id

    @property
    def policy_hash(self) -> str:
        return self.__policy_hash

    @property
    def policy_reference(self) -> str:
        return self.__policy_reference

    @property
    def target_fingerprint(self) -> str:
        return self.__target_fingerprint

    @property
    def scope_reference(self) -> str:
        return self.__scope_reference

    @property
    def controlled_identity_bindings(self) -> tuple[object, ...]:
        return self.__controlled_identity_bindings

    @property
    def owned_object_bindings(self) -> tuple[object, ...]:
        return self.__owned_object_bindings

    @property
    def request_budget_reservation(self) -> object:
        return self.__request_budget_reservation

    @property
    def cleanup_reservation(self) -> object:
        return self.__cleanup_reservation

    @property
    def executor_routes(self) -> tuple[object, ...]:
        return self.__executor_routes

    @property
    def executor_route_version(self) -> str:
        return ",".join(
            str(getattr(route, "route_reference", route))
            for route in self.__executor_routes
        )

    @property
    def authorization_timestamp(self) -> str:
        return self.__authorization_timestamp

    @property
    def expiry(self) -> str:
        return self.__expiry

    @property
    def authorization_expiry(self) -> str:
        return self.__expiry

    @property
    def sealed_authorization_digest(self) -> str:
        return self.__authorization_digest

    @property
    def sealed_experiment_digest(self) -> str:
        return self.__authorization_digest

    @property
    def authorization_reference(self) -> str:
        return self.__authorization_digest

    @property
    def runtime_binding_reference(self) -> str:
        return self.__runtime_binding_reference

    @property
    def dry_run(self) -> bool:
        return self.__dry_run

    def _seal_payload(self) -> dict[str, Any]:
        return {
            "authorization_nonce": self.__authorization_nonce,
            "authorization_timestamp": self.__authorization_timestamp,
            "cleanup_reservation": _authorization_plain(self.__cleanup_reservation),
            "controlled_identity_bindings": _authorization_plain(
                self.__controlled_identity_bindings
            ),
            "dry_run": self.__dry_run,
            "executor_routes": _authorization_plain(self.__executor_routes),
            "experiment_fingerprint": self.__experiment.fingerprint,
            "experiment_id": self.__experiment.experiment_id,
            "expiry": self.__expiry,
            "owned_object_bindings": _authorization_plain(self.__owned_object_bindings),
            "policy_decision_id": self.__policy_decision_id,
            "policy_hash": self.__policy_hash,
            "policy_reference": self.__policy_reference,
            "request_budget_reservation": _authorization_plain(
                self.__request_budget_reservation
            ),
            "research_id": self.__experiment.research_id,
            "runtime_binding_reference": self.__runtime_binding_reference,
            "scope_reference": self.__scope_reference,
            "state_revision": self.__experiment.state_revision,
            "target_fingerprint": self.__target_fingerprint,
        }

    def _seal_material(self) -> bytes:
        return json.dumps(
            self._seal_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def _seal_is_valid(self) -> bool:
        try:
            expected = (
                "sha256:"
                + hmac.new(
                    _AUTHORIZATION_KEY,
                    self._seal_material(),
                    hashlib.sha256,
                ).hexdigest()
            )
            return self.__issuer is _AUTHORIZATION_ISSUER and hmac.compare_digest(
                expected, self.__authorization_digest
            )
        except (AttributeError, TypeError, ValueError):
            return False

    def __copy__(self) -> None:
        raise TypeError("AuthorizedExperiment cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> None:
        raise TypeError("AuthorizedExperiment cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("AuthorizedExperiment cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("AuthorizedExperiment cannot be serialized")


def _seal_authorized_experiment(**fields: Any) -> AuthorizedExperiment:
    """Private issuer used only by ``ResearchExecutionGate``."""

    return AuthorizedExperiment(_issuer=_AUTHORIZATION_ISSUER, **fields)


def _is_gate_authorized(value: object) -> bool:
    return type(value) is AuthorizedExperiment and value._seal_is_valid()
