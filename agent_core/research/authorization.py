"""Deterministic authorization gate for Phase 4 research execution."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any
from urllib.parse import urljoin, urlparse

from pydantic import Field, StrictInt

from agent_core.controlled_context import ControlledContext
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy
from agent_core.request_budget import RequestBudget
from agent_core.research.compiler import ExperimentCompilerContext
from agent_core.research.experiments import (
    AuthorizedExperiment,
    SecurityExperiment,
    _seal_authorized_experiment,
)
from agent_core.research.executors import (
    DEFAULT_PRIMITIVE_EXECUTOR_REGISTRY,
    PrimitiveExecutorRegistry,
    RegisteredCleanupExecution,
    RegisteredControlledValue,
    RegisteredEvidenceSummary,
    RegisteredRuntimeRequestTemplate,
    RegisteredStateSnapshot,
)
from agent_core.research.fingerprint import experiment_fingerprint
from agent_core.research.primitives import (
    ObjectSubstitutionInput,
    ParameterMutationInput,
    PrimitiveCapabilityState,
    RequestReplayInput,
    ResponseDifferentialInput,
    StateDifferentialInput,
)
from agent_core.research.provenance import (
    SecretMaterialRejected,
    reject_secret_material,
)
from agent_core.research.registry import (
    DEFAULT_EXPERIMENT_REGISTRY,
    ExperimentRegistry,
)
from agent_core.research.state import (
    Identity,
    ResearchObject,
    ResearchState,
    SessionRef,
    TargetAsset,
)
from agent_core.research.types import (
    CleanupStatus,
    IdentityEligibility,
    OpaqueIdentifier,
    ResearchContract,
    SessionLifecycle,
)
from tools.safe_http import ScopedHTTPClient

DEFAULT_AUTHORIZATION_TTL_SECONDS = 300


class ResearchAuthorizationErrorCode(str, Enum):
    authorization_blocked = "authorization_blocked"
    stale_state = "stale_state"
    expired_authorization = "expired_authorization"
    invalid_binding = "invalid_binding"
    scope_mismatch = "scope_mismatch"
    context_mismatch = "context_mismatch"
    budget_exhausted = "budget_exhausted"
    cleanup_reserve_unavailable = "cleanup_reserve_unavailable"
    primitive_unavailable = "primitive_unavailable"
    duplicate_experiment = "duplicate_experiment"


class ResearchAuthorizationError(ValueError):
    """Public-safe authorization denial containing a stable reason code only."""

    def __init__(self, code: ResearchAuthorizationErrorCode):
        self.code = code
        super().__init__(code.value)


class AuthorizationBlockedError(ResearchAuthorizationError):
    pass


class StaleResearchStateError(ResearchAuthorizationError):
    pass


class ExpiredAuthorizationError(ResearchAuthorizationError):
    pass


class ScopeMismatchError(ResearchAuthorizationError):
    pass


class ContextMismatchError(ResearchAuthorizationError):
    pass


class ResearchBudgetExhaustedError(ResearchAuthorizationError):
    pass


class CleanupReserveUnavailableError(ResearchAuthorizationError):
    pass


class PrimitiveUnavailableError(ResearchAuthorizationError):
    pass


class DuplicateExperimentError(ResearchAuthorizationError):
    pass


class ControlledIdentityBinding(ResearchContract):
    identity_id: OpaqueIdentifier
    account_reference: OpaqueIdentifier
    role_reference: OpaqueIdentifier | None = None
    tenant_reference: OpaqueIdentifier | None = None
    session_ref_id: OpaqueIdentifier | None = None
    vault_reference: OpaqueIdentifier | None = None


class OwnedObjectBinding(ResearchContract):
    object_id: OpaqueIdentifier
    object_reference: OpaqueIdentifier
    owner_identity_id: OpaqueIdentifier
    tenant_reference: OpaqueIdentifier | None = None
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )


class RequestBudgetReservation(ResearchContract):
    reservation_reference: OpaqueIdentifier
    discovery: StrictInt = Field(ge=0, le=10_000)
    auth: StrictInt = Field(ge=0, le=10_000)
    verification: StrictInt = Field(ge=0, le=10_000)
    cleanup: StrictInt = Field(ge=0, le=10_000)
    total: StrictInt = Field(ge=0, le=10_000)
    ledger_total_at_authorization: StrictInt = Field(ge=0)
    ledger_remaining_at_authorization: StrictInt = Field(ge=0)


class CleanupReservation(ResearchContract):
    required: bool
    cleanup_reference: OpaqueIdentifier | None = None
    requests_reserved: StrictInt = Field(ge=0, le=100)


class PrimitiveExecutorRoute(ResearchContract):
    step_id: OpaqueIdentifier
    primitive_name: OpaqueIdentifier
    primitive_version: OpaqueIdentifier
    route_reference: OpaqueIdentifier
    execution_kind: str = Field(pattern=r"^(?:native|legacy_adapted)$")


class ResearchCleanupBarrier:
    """Process-local barrier activated after an unverified cleanup failure."""

    __slots__ = ("__active", "__reference", "__lock")

    def __init__(self) -> None:
        self.__active = False
        self.__reference: str | None = None
        self.__lock = threading.RLock()

    @property
    def active(self) -> bool:
        with self.__lock:
            return self.__active

    @property
    def reference(self) -> str | None:
        with self.__lock:
            return self.__reference

    def activate(self, reference: str) -> None:
        with self.__lock:
            self.__active = True
            self.__reference = reference

    def resolve(self, reference: str) -> bool:
        with self.__lock:
            if not self.__active or reference != self.__reference:
                return False
            self.__active = False
            self.__reference = None
            return True


def target_fingerprint(target: TargetAsset) -> str:
    payload = target.model_dump(mode="json")
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def policy_fingerprint(policy: AssessmentPolicy) -> str:
    payload = policy.model_dump(mode="json", exclude={"policy_hash"})
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ResearchExecutionGate:
    """The sole issuer of sealed ``AuthorizedExperiment`` objects."""

    def __init__(
        self,
        *,
        state: ResearchState,
        policy: AssessmentPolicy,
        controlled_context: ControlledContext,
        vault: CredentialVault,
        budget: RequestBudget,
        transport: ScopedHTTPClient,
        compiler_context: ExperimentCompilerContext,
        request_templates: tuple[RegisteredRuntimeRequestTemplate, ...] = (),
        controlled_values: tuple[RegisteredControlledValue, ...] = (),
        evidence_summaries: tuple[RegisteredEvidenceSummary, ...] = (),
        state_snapshots: tuple[RegisteredStateSnapshot, ...] = (),
        primitive_registry: ExperimentRegistry = DEFAULT_EXPERIMENT_REGISTRY,
        executor_registry: PrimitiveExecutorRegistry = (
            DEFAULT_PRIMITIVE_EXECUTOR_REGISTRY
        ),
        store: object | None = None,
        cleanup_handlers: Mapping[str, object] | None = None,
        cleanup_barrier: ResearchCleanupBarrier | None = None,
        target_fingerprints: Mapping[str, str] | None = None,
        scope_reference: str | None = None,
        current_time: str | None = None,
        authorization_ttl_seconds: int = DEFAULT_AUTHORIZATION_TTL_SECONDS,
    ) -> None:
        if transport.budget is not budget or transport.policy is not policy:
            raise ContextMismatchError(ResearchAuthorizationErrorCode.context_mismatch)
        if not 1 <= authorization_ttl_seconds <= 86_400:
            raise ValueError("authorization TTL is outside the supported bound")
        self.state = state
        self.policy = policy
        self.controlled_context = controlled_context
        self.vault = vault
        self.budget = budget
        self.transport = transport
        self.compiler_context = compiler_context
        self.primitive_registry = primitive_registry
        self.executor_registry = executor_registry
        self.store = store
        self.cleanup_handlers = MappingProxyType(dict(cleanup_handlers or {}))
        self.cleanup_barrier = cleanup_barrier or ResearchCleanupBarrier()
        self.target_fingerprints = MappingProxyType(dict(target_fingerprints or {}))
        self.scope_reference = scope_reference
        self.current_time = current_time
        self.authorization_ttl_seconds = authorization_ttl_seconds
        self.request_templates = _unique_map(request_templates, "template_id")
        self.controlled_values = _unique_map(controlled_values, "reference")
        self.evidence_summaries = _unique_map(evidence_summaries, "reference")
        self.state_snapshots = _unique_map(state_snapshots, "reference")

        from agent_core.research.runtime import _create_research_runtime

        self.runtime = _create_research_runtime(self)

    def authorize(
        self, experiment: SecurityExperiment, *, dry_run: bool = False
    ) -> AuthorizedExperiment:
        """Revalidate compiler output and seal its exact runtime authority."""

        if type(experiment) is not SecurityExperiment:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        try:
            validated_experiment = SecurityExperiment.model_validate(
                experiment.model_dump(mode="python")
            )
        except (TypeError, ValueError) as exc:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            ) from exc
        if validated_experiment != experiment:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        try:
            reject_secret_material(
                experiment.model_dump(mode="json"), location="security experiment"
            )
        except SecretMaterialRejected as exc:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            ) from exc
        if experiment_fingerprint(experiment) != experiment.fingerprint:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        state = self._current_state()
        if (
            experiment.research_id != state.research_id
            or experiment.state_revision != state.revision
            or experiment.provenance.research_revision != state.revision
        ):
            raise StaleResearchStateError(ResearchAuthorizationErrorCode.stale_state)
        if state.status.value in {"stopped", "failed"}:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        if (
            experiment.provenance.compiler_version
            != self.compiler_context.compiler_version
            or experiment.provenance.primitive_registry_version
            != self.primitive_registry.version
            or experiment.provenance.primitive_registry_hash
            != self.primitive_registry.fingerprint
            or (
                self.compiler_context.policy_reference is not None
                and experiment.provenance.policy_reference
                != self.compiler_context.policy_reference
            )
            or (
                self.compiler_context.context_reference is not None
                and experiment.provenance.context_reference
                != self.compiler_context.context_reference
            )
        ):
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        hypothesis = _one(state.hypotheses, "hypothesis_id", experiment.hypothesis_id)
        source_provenance = _one(
            state.provenance,
            "provenance_id",
            experiment.provenance.source_provenance_id,
        )
        if (
            hypothesis is None
            or hypothesis.target_id != experiment.target.target_id
            or (
                experiment.target.surface_id is not None
                and hypothesis.surface_id != experiment.target.surface_id
            )
            or experiment.provenance.source_hypothesis_id != experiment.hypothesis_id
            or source_provenance is None
        ):
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        now = _as_datetime(self.current_time) if self.current_time else _utc_now()
        experiment_expiry = _as_datetime(experiment.expires_at)
        if experiment_expiry <= now:
            raise ExpiredAuthorizationError(
                ResearchAuthorizationErrorCode.expired_authorization
            )
        target = _one(state.targets, "target_id", experiment.target.target_id)
        if target is None:
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        assert isinstance(target, TargetAsset)
        expected_fingerprint = self.target_fingerprints.get(
            target.target_id, target_fingerprint(target)
        )
        if expected_fingerprint != target_fingerprint(target):
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        if target.target_class is not experiment.target.target_class:
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        if (
            self.scope_reference is not None
            and target.scope_reference != self.scope_reference
        ):
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        self._validate_surface_endpoint(experiment, state, target)
        identity_bindings = self._identity_bindings(experiment, state)
        object_bindings = self._object_bindings(experiment, state, identity_bindings)
        routes = self._routes_and_requests(experiment, state, target)
        self._validate_cleanup_and_budget(experiment, state, target)
        self._validate_duplicate(experiment, state)

        timestamp = _timestamp(now)
        expiry = _timestamp(
            min(
                experiment_expiry,
                now + timedelta(seconds=self.authorization_ttl_seconds),
            )
        )
        reservation_reference = _identifier(
            "reservation", experiment.experiment_id, self.runtime.binding_reference
        )
        estimate = experiment.request_estimate
        reservation = RequestBudgetReservation(
            reservation_reference=reservation_reference,
            discovery=estimate.discovery,
            auth=estimate.auth,
            verification=estimate.verification,
            cleanup=estimate.cleanup,
            total=estimate.total_reservation,
            ledger_total_at_authorization=self.budget.total,
            ledger_remaining_at_authorization=self.budget.remaining,
        )
        cleanup_reservation = CleanupReservation(
            required=experiment.cleanup.required,
            cleanup_reference=experiment.cleanup.cleanup_reference,
            requests_reserved=experiment.cleanup.worst_case_requests,
        )
        decision_id = _identifier(
            "policy-decision",
            experiment.experiment_id,
            timestamp,
            self.runtime.binding_reference,
        )
        return _seal_authorized_experiment(
            experiment=experiment,
            policy_decision_id=decision_id,
            policy_hash=policy_fingerprint(self.policy),
            policy_reference=self.policy.authorization_reference
            or self.compiler_context.policy_reference
            or "policy:unreferenced",
            target_fingerprint=expected_fingerprint,
            scope_reference=target.scope_reference,
            controlled_identity_bindings=identity_bindings,
            owned_object_bindings=object_bindings,
            request_budget_reservation=reservation,
            cleanup_reservation=cleanup_reservation,
            executor_routes=routes,
            authorization_timestamp=timestamp,
            expiry=expiry,
            runtime_binding_reference=self.runtime.binding_reference,
            dry_run=dry_run,
        )

    def bind(self, authorization: AuthorizedExperiment):
        from agent_core.research.runtime_binding import bind_research_runtime

        return bind_research_runtime(authorization, self.runtime)

    def authorize_and_bind(
        self, experiment: SecurityExperiment, *, dry_run: bool = False
    ):
        authorization = self.authorize(experiment, dry_run=dry_run)
        return authorization, self.bind(authorization)

    def _current_state(self) -> ResearchState:
        if self.store is None:
            return self.state
        try:
            loaded = self.store.load_research(self.state.research_id)
        except Exception as exc:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            ) from exc
        if not isinstance(loaded, ResearchState):
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        return loaded

    @staticmethod
    def _validate_surface_endpoint(
        experiment: SecurityExperiment, state: ResearchState, target: TargetAsset
    ) -> None:
        surface_id = experiment.target.surface_id
        endpoint_id = experiment.target.endpoint_id
        surface = _one(state.surfaces, "surface_id", surface_id) if surface_id else None
        endpoint = (
            _one(state.endpoints, "endpoint_id", endpoint_id) if endpoint_id else None
        )
        if surface_id and (surface is None or surface.target_id != target.target_id):
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        if endpoint_id and (
            endpoint is None
            or endpoint.target_id != target.target_id
            or endpoint.surface_id != surface_id
            or endpoint.method.value != experiment.target.method
        ):
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)

    def _identity_bindings(
        self, experiment: SecurityExperiment, state: ResearchState
    ) -> tuple[ControlledIdentityBinding, ...]:
        requested = {
            value
            for value in (
                experiment.identity_context.primary_identity_id,
                experiment.identity_context.comparison_identity_id,
            )
            if value is not None
        }
        for step in experiment.primitive_steps:
            requested.update(
                value
                for value in (
                    getattr(step.input, "identity_id", None),
                    getattr(step.input, "primary_identity_id", None),
                    getattr(step.input, "comparison_identity_id", None),
                )
                if value is not None
            )
        bindings = []
        for identity_id in sorted(requested):
            identity = _one(state.identities, "identity_id", identity_id)
            if (
                not isinstance(identity, Identity)
                or not identity.controlled
                or identity.eligibility is not IdentityEligibility.eligible
            ):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            try:
                account = self.controlled_context.account(identity.account_reference)
            except KeyError as exc:
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                ) from exc
            eligibility = self.policy.account_is_eligible(
                account.account_id,
                self.controlled_context,
                account_controlled=account.controlled,
            )
            if not account.controlled or not eligibility.eligible:
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            if (
                identity.tenant_reference is not None
                and account.tenant_id != identity.tenant_reference
            ):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            session = self._session_for_identity(experiment, state, identity_id)
            vault_reference = (
                session.vault_reference if session else account.session_reference
            )
            if vault_reference is not None and not self.vault.contains(vault_reference):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            bindings.append(
                ControlledIdentityBinding(
                    identity_id=identity.identity_id,
                    account_reference=identity.account_reference,
                    role_reference=identity.role_reference,
                    tenant_reference=identity.tenant_reference,
                    session_ref_id=session.session_ref_id if session else None,
                    vault_reference=vault_reference,
                )
            )
        return tuple(bindings)

    @staticmethod
    def _session_for_identity(
        experiment: SecurityExperiment, state: ResearchState, identity_id: str
    ) -> SessionRef | None:
        explicit = {
            value
            for value in (
                experiment.identity_context.primary_session_ref_id,
                experiment.identity_context.comparison_session_ref_id,
                *(
                    getattr(step.input, "session_ref_id", None)
                    for step in experiment.primitive_steps
                ),
            )
            if value is not None
        }
        matches = [
            item
            for item in state.session_refs
            if item.identity_id == identity_id
            and item.lifecycle is SessionLifecycle.active
            and (not explicit or item.session_ref_id in explicit)
        ]
        if len(matches) > 1:
            raise ContextMismatchError(ResearchAuthorizationErrorCode.context_mismatch)
        return matches[0] if matches else None

    def _object_bindings(
        self,
        experiment: SecurityExperiment,
        state: ResearchState,
        identities: tuple[ControlledIdentityBinding, ...],
    ) -> tuple[OwnedObjectBinding, ...]:
        requested = set(experiment.mutation.controlled_object_ids)
        requested.update(
            value
            for value in (
                getattr(step.input, "controlled_object_id", None)
                for step in experiment.primitive_steps
            )
            if value is not None
        )
        identity_map = {item.identity_id: item for item in identities}
        bindings = []
        for object_id in sorted(requested):
            item = _one(state.objects, "object_id", object_id)
            if (
                not isinstance(item, ResearchObject)
                or not item.test_owned
                or item.owner_identity_id not in identity_map
                or not item.evidence_references
                or item.target_id != experiment.target.target_id
                or item.surface_id != experiment.target.surface_id
            ):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            owner = identity_map[str(item.owner_identity_id)]
            controlled = next(
                (
                    value
                    for value in self.controlled_context.objects
                    if value.object_id in {item.object_id, item.object_reference}
                    and value.owner_account_id == owner.account_reference
                    and value.test_owned
                ),
                None,
            )
            if controlled is None or (
                item.tenant_reference is not None
                and controlled.tenant_id != item.tenant_reference
            ):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )
            bindings.append(
                OwnedObjectBinding(
                    object_id=item.object_id,
                    object_reference=item.object_reference,
                    owner_identity_id=str(item.owner_identity_id),
                    tenant_reference=item.tenant_reference,
                    evidence_references=item.evidence_references,
                )
            )
        return tuple(bindings)

    def _routes_and_requests(
        self,
        experiment: SecurityExperiment,
        state: ResearchState,
        target: TargetAsset,
    ) -> tuple[PrimitiveExecutorRoute, ...]:
        routes = []
        calculated_verification = 0
        for step in experiment.primitive_steps:
            try:
                definition = self.primitive_registry.resolve(
                    step.primitive_name, step.primitive_version
                )
            except ValueError as exc:
                raise PrimitiveUnavailableError(
                    ResearchAuthorizationErrorCode.primitive_unavailable
                ) from exc
            if (
                definition.capability_state
                is not PrimitiveCapabilityState.execution_available
                or step.capability_state
                is not PrimitiveCapabilityState.execution_available
                or definition.executor_adapter_reference is None
                or target.target_class not in definition.allowed_target_classes
            ):
                raise PrimitiveUnavailableError(
                    ResearchAuthorizationErrorCode.primitive_unavailable
                )
            try:
                self.executor_registry.resolve(definition.executor_adapter_reference)
            except Exception as exc:
                raise PrimitiveUnavailableError(
                    ResearchAuthorizationErrorCode.primitive_unavailable
                ) from exc
            routes.append(
                PrimitiveExecutorRoute(
                    step_id=step.step_id,
                    primitive_name=step.primitive_name,
                    primitive_version=step.primitive_version,
                    route_reference=definition.executor_adapter_reference,
                    execution_kind=(
                        "legacy_adapted"
                        if definition.executor_adapter_reference.startswith("phase2-")
                        else "native"
                    ),
                )
            )
            step_worst = definition.worst_case_requests
            if isinstance(step.input, ParameterMutationInput):
                step_worst = min(step_worst, step.input.maximum_variants)
            calculated_verification += step_worst
            template_id = getattr(step.input, "request_template_id", None)
            if (
                isinstance(step.input, ObjectSubstitutionInput)
                and step.input.request_template_id is None
            ):
                raise PrimitiveUnavailableError(
                    ResearchAuthorizationErrorCode.primitive_unavailable
                )
            if template_id is not None:
                self._validate_template(
                    str(template_id), step.input.endpoint_id, state, target
                )
                template = self.request_templates[str(template_id)]
                parameter_id = getattr(step.input, "parameter_id", None)
                if parameter_id is not None and parameter_id not in {
                    item.parameter_id for item in template.parameters
                }:
                    raise ContextMismatchError(
                        ResearchAuthorizationErrorCode.context_mismatch
                    )
            if isinstance(step.input, RequestReplayInput):
                if any(
                    item.value_source_reference not in self.controlled_values
                    for item in step.input.bindings
                ):
                    raise ContextMismatchError(
                        ResearchAuthorizationErrorCode.context_mismatch
                    )
            if isinstance(step.input, ParameterMutationInput):
                if (
                    step.input.value_source_reference is not None
                    and step.input.value_source_reference not in self.controlled_values
                ):
                    raise ContextMismatchError(
                        ResearchAuthorizationErrorCode.context_mismatch
                    )
            if isinstance(step.input, ResponseDifferentialInput):
                if any(
                    item.reference_id not in self.evidence_summaries
                    for item in step.input.references
                ):
                    raise ContextMismatchError(
                        ResearchAuthorizationErrorCode.context_mismatch
                    )
            if isinstance(step.input, StateDifferentialInput):
                references = {
                    step.input.before_state_reference,
                    step.input.after_state_reference,
                    step.input.cleanup_state_reference,
                } - {None}
                if not references.issubset(self.state_snapshots):
                    raise ContextMismatchError(
                        ResearchAuthorizationErrorCode.context_mismatch
                    )
        if calculated_verification != experiment.request_estimate.verification:
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        estimate = experiment.request_estimate
        if (
            estimate.discovery != 0
            or estimate.auth != 0
            or estimate.total_reservation != estimate.verification + estimate.cleanup
        ):
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )
        return tuple(routes)

    def _validate_template(
        self,
        template_id: str,
        endpoint_id: str,
        state: ResearchState,
        target: TargetAsset,
    ) -> None:
        template = self.request_templates.get(template_id)
        endpoint = _one(state.endpoints, "endpoint_id", endpoint_id)
        if template is None or endpoint is None:
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        if (
            template.target_id != target.target_id
            or template.surface_id != endpoint.surface_id
            or template.endpoint_id != endpoint.endpoint_id
            or template.method is not endpoint.method
            or not _url_belongs_to_endpoint(
                target.canonical_reference, endpoint.route_template, template.url
            )
        ):
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        decision = self.policy.authorize_url(template.url, method=template.method.value)
        if not decision.allowed:
            raise ScopeMismatchError(ResearchAuthorizationErrorCode.scope_mismatch)
        state_parameters = {
            item.parameter_id: item
            for item in state.parameters
            if item.endpoint_id == endpoint.endpoint_id
        }
        for parameter in template.parameters:
            registered = state_parameters.get(parameter.parameter_id)
            if (
                registered is None
                or registered.name != parameter.name
                or registered.location is not parameter.location
            ):
                raise ContextMismatchError(
                    ResearchAuthorizationErrorCode.context_mismatch
                )

    def _validate_cleanup_and_budget(
        self, experiment: SecurityExperiment, state: ResearchState, target: TargetAsset
    ) -> None:
        if experiment.state_changing:
            cleanup_registration = self.cleanup_handlers.get(
                str(experiment.cleanup.cleanup_reference)
            )
            if (
                not self.policy.allow_state_changes
                or not self.policy.require_cleanup_for_state_changes
                or experiment.target.target_class.value == "external"
                or not experiment.cleanup.required
                or not isinstance(cleanup_registration, RegisteredCleanupExecution)
                or self.cleanup_barrier.active
            ):
                raise CleanupReserveUnavailableError(
                    ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
                )
            unresolved_state_cleanup = any(
                item.cleanup_status
                in {
                    CleanupStatus.pending,
                    CleanupStatus.failed,
                    CleanupStatus.externally_required,
                }
                for item in state.budgets
            )
            insufficient_state_reserve = any(
                item.cleanup_request_reserve < experiment.cleanup.worst_case_requests
                for item in state.budgets
            )
            if unresolved_state_cleanup or insufficient_state_reserve:
                raise CleanupReserveUnavailableError(
                    ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
                )
            assert isinstance(cleanup_registration, RegisteredCleanupExecution)
            if (
                cleanup_registration.cleanup_reference
                != experiment.cleanup.cleanup_reference
                or cleanup_registration.request_template_id
                not in self.request_templates
            ):
                raise CleanupReserveUnavailableError(
                    ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
                )
            cleanup_template = self.request_templates[
                cleanup_registration.request_template_id
            ]
            self._validate_template(
                cleanup_template.template_id,
                cleanup_template.endpoint_id,
                state,
                target,
            )
        estimate = experiment.request_estimate
        if estimate.cleanup != experiment.cleanup.worst_case_requests:
            raise CleanupReserveUnavailableError(
                ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
            )
        if estimate.total_reservation > self.budget.remaining:
            raise ResearchBudgetExhaustedError(
                ResearchAuthorizationErrorCode.budget_exhausted
            )

    def _validate_duplicate(
        self, experiment: SecurityExperiment, state: ResearchState
    ) -> None:
        completed_ids = {item.experiment_id for item in state.experiment_outcomes}
        fingerprint_seen = False
        provenance = {item.provenance_id: item for item in state.provenance}
        for outcome in state.experiment_outcomes:
            record = provenance.get(outcome.provenance_id)
            if record and experiment.fingerprint in record.source_references:
                fingerprint_seen = True
        if self.runtime.has_completed_fingerprint(experiment.fingerprint):
            fingerprint_seen = True
        duplicate = experiment.experiment_id in completed_ids or fingerprint_seen
        if not duplicate:
            return
        if experiment.reproduction_of is not None and (
            experiment.reproduction_of in completed_ids
            or self.runtime.has_completed_experiment(experiment.reproduction_of)
        ):
            return
        raise DuplicateExperimentError(
            ResearchAuthorizationErrorCode.duplicate_experiment
        )


def _url_belongs_to_endpoint(base: str, route_template: str, candidate: str) -> bool:
    base_url = urlparse(base)
    candidate_url = urlparse(candidate)
    if (
        base_url.scheme != candidate_url.scheme
        or base_url.hostname != candidate_url.hostname
        or (base_url.port or _default_port(base_url.scheme))
        != (candidate_url.port or _default_port(candidate_url.scheme))
    ):
        return False
    expected = urlparse(urljoin(base.rstrip("/") + "/", route_template.lstrip("/")))
    pattern = re.escape(expected.path)
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
    return re.fullmatch(pattern, candidate_url.path) is not None


def _default_port(scheme: str) -> int | None:
    return 443 if scheme == "https" else 80 if scheme == "http" else None


def _unique_map(values: tuple[Any, ...], attribute: str) -> Mapping[str, Any]:
    result = {str(getattr(item, attribute)): item for item in values}
    if len(result) != len(values):
        raise ValueError("runtime registrations must have unique references")
    return MappingProxyType(result)


def _one(values: tuple[Any, ...], attribute: str, key: object) -> Any | None:
    matches = [item for item in values if getattr(item, attribute) == key]
    return matches[0] if len(matches) == 1 else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _identifier(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(item) for item in parts)
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


__all__ = [
    "AuthorizationBlockedError",
    "CleanupReservation",
    "CleanupReserveUnavailableError",
    "ContextMismatchError",
    "ControlledIdentityBinding",
    "DEFAULT_AUTHORIZATION_TTL_SECONDS",
    "DuplicateExperimentError",
    "ExpiredAuthorizationError",
    "OwnedObjectBinding",
    "PrimitiveExecutorRoute",
    "PrimitiveUnavailableError",
    "RequestBudgetReservation",
    "ResearchAuthorizationError",
    "ResearchAuthorizationErrorCode",
    "ResearchBudgetExhaustedError",
    "ResearchCleanupBarrier",
    "ResearchExecutionGate",
    "ScopeMismatchError",
    "StaleResearchStateError",
    "policy_fingerprint",
    "target_fingerprint",
]
