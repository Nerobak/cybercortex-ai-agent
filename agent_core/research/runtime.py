"""Sealed deterministic runtime for authorized Phase 4 experiments."""

from __future__ import annotations

import hashlib
import json
import secrets
import re
import time
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from agent_core.models import ModelUsageDelta
from agent_core.agent_models import TransportRequestContext
from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta
from agent_core.research.authorization import (
    ExpiredAuthorizationError,
    ResearchAuthorizationErrorCode,
    ResearchBudgetExhaustedError,
    policy_fingerprint,
    target_fingerprint,
)
from agent_core.research.events import (
    ExperimentOutcomeRecordedPayload,
    ResearchEvent,
    ResearchEventType,
)
from agent_core.research.executors import (
    GraphQLRequestExecutionResult,
    PrimitiveExecutionError,
    PrimitiveExecutorContext,
    RegisteredCleanupExecution,
    RequestExecutionResult,
    ResolvedRequest,
)
from agent_core.research.graphql import GraphQLExperimentStateChangeClass
from agent_core.research.graphql_execution import (
    GraphQLDocumentRenderer,
    GraphQLExecutionRequest,
    materialize_graphql_variables,
)
from agent_core.research.graphql_ingest import (
    GraphQLErrorClass,
    GraphQLResponseEnvelope,
    GraphQLResponseObservation,
    analyze_graphql_response,
)
from agent_core.research.experiments import AuthorizedExperiment, _is_gate_authorized
from agent_core.research.outcomes import (
    CleanupExecutionResult,
    ExperimentOutcome,
    ExperimentResultClassification,
    GraphQLErrorPathEvidence,
    GraphQLRuntimeResponseEvidence,
    GraphQLRuntimeTraceEvent,
    ProposedExecutionMetadata,
    RuntimeProvenance,
    SafeRequestSummary,
    SafeResponseSummary,
)
from agent_core.research.primitives import (
    GraphQLOperationInput,
    GraphQLVariableMutationInput,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import (
    EvidenceArtifact,
    ExperimentOutcome as StoredExperimentOutcome,
    ProvenanceRecord,
    ResearchState,
    TargetAsset,
)
from agent_core.research.types import (
    CleanupStatus,
    EvidenceKind,
    ExperimentRuntimeStatus,
    IdentityEligibility,
    MetadataEntry,
    ProvenanceProducerType,
    PublicMetadata,
    ResearchRunStatus,
)
from tools.safe_http import ResponseTooLargeError

RESEARCH_RUNTIME_NAME = "cybercortex-research-runtime"
RESEARCH_RUNTIME_VERSION = "p4-1e-v1"
_RUNTIME_ISSUER = object()

if TYPE_CHECKING:
    from agent_core.research.authorization import ResearchExecutionGate
    from agent_core.research.runtime_binding import ResearchRuntimeBinding


class ResearchRuntimeError(RuntimeError):
    """Public-safe deterministic runtime failure."""


class ResearchPersistenceError(ResearchRuntimeError):
    """Durable outcome recording failed after execution."""


class ResearchRuntime:
    """Narrow runtime that accepts only one gate-sealed authorization."""

    __slots__ = (
        "__binding_reference",
        "__bindings",
        "__budget",
        "__cleanup_barrier",
        "__cleanup_handlers",
        "__compiler_context",
        "__completed_fingerprints",
        "__completed_experiment_ids",
        "__controlled_context",
        "__controlled_values",
        "__current_time",
        "__evidence_summaries",
        "__executor_registry",
        "__graphql_limits",
        "__graphql_operation_templates",
        "__graphql_safe_mutations",
        "__issuer",
        "__persistence_failed",
        "__policy",
        "__primitive_registry",
        "__request_templates",
        "__state",
        "__state_snapshots",
        "__store",
        "__transport",
        "__vault",
    )

    def __init__(self, gate: "ResearchExecutionGate", issuer: object) -> None:
        from agent_core.research.authorization import ResearchExecutionGate

        if issuer is not _RUNTIME_ISSUER or type(gate) is not ResearchExecutionGate:
            raise TypeError("ResearchRuntime construction is restricted to its gate")
        object.__setattr__(self, "_ResearchRuntime__issuer", issuer)
        object.__setattr__(
            self,
            "_ResearchRuntime__binding_reference",
            "runtime-binding-" + secrets.token_hex(16),
        )
        for name in (
            "budget",
            "cleanup_barrier",
            "compiler_context",
            "controlled_context",
            "executor_registry",
            "policy",
            "primitive_registry",
            "state",
            "store",
            "transport",
            "vault",
        ):
            object.__setattr__(self, f"_ResearchRuntime__{name}", getattr(gate, name))
        object.__setattr__(
            self,
            "_ResearchRuntime__request_templates",
            MappingProxyType(dict(gate.request_templates)),
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__controlled_values",
            MappingProxyType(dict(gate.controlled_values)),
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__evidence_summaries",
            MappingProxyType(dict(gate.evidence_summaries)),
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__state_snapshots",
            MappingProxyType(dict(gate.state_snapshots)),
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__graphql_operation_templates",
            MappingProxyType(dict(gate.graphql_operation_templates)),
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__graphql_safe_mutations",
            MappingProxyType(dict(gate.graphql_safe_mutations)),
        )
        object.__setattr__(
            self, "_ResearchRuntime__graphql_limits", gate.graphql_limits
        )
        object.__setattr__(
            self,
            "_ResearchRuntime__cleanup_handlers",
            MappingProxyType(dict(gate.cleanup_handlers)),
        )
        object.__setattr__(self, "_ResearchRuntime__current_time", gate.current_time)
        object.__setattr__(self, "_ResearchRuntime__bindings", {})
        object.__setattr__(self, "_ResearchRuntime__completed_fingerprints", set())
        object.__setattr__(self, "_ResearchRuntime__completed_experiment_ids", set())
        object.__setattr__(self, "_ResearchRuntime__persistence_failed", False)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("ResearchRuntime cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("ResearchRuntime dependencies are immutable")

    @property
    def binding_reference(self) -> str:
        return self.__binding_reference

    @property
    def budget(self):
        return self.__budget

    @property
    def controlled_context(self):
        return self.__controlled_context

    @property
    def vault(self):
        return self.__vault

    @property
    def transport(self):
        return self.__transport

    @property
    def policy(self):
        return self.__policy

    @property
    def primitive_registry(self):
        return self.__primitive_registry

    @property
    def executor_registry(self):
        return self.__executor_registry

    def target(self, target_id: str) -> TargetAsset:
        state = self._current_state()
        matches = [item for item in state.targets if item.target_id == target_id]
        if len(matches) != 1:
            raise ResearchRuntimeError("authorized target binding is unavailable")
        return matches[0]

    def has_completed_fingerprint(self, fingerprint: str) -> bool:
        return fingerprint in self.__completed_fingerprints

    def has_completed_experiment(self, experiment_id: str) -> bool:
        return experiment_id in self.__completed_experiment_ids

    def submit(self, authorization: AuthorizedExperiment) -> ExperimentOutcome:
        """Execute only an authorization already sealed into this runtime."""

        if not _is_gate_authorized(authorization):
            from agent_core.research.runtime_binding import InvalidRuntimeBindingError

            raise InvalidRuntimeBindingError()
        binding = self.__bindings.get(authorization.authorization_reference)
        if binding is None:
            from agent_core.research.runtime_binding import InvalidRuntimeBindingError

            raise InvalidRuntimeBindingError()
        return binding.submit(authorization)

    def _register_binding(self, binding: object, issuer: object) -> None:
        from agent_core.research.runtime_binding import (
            ResearchRuntimeBinding,
            _BINDING_ISSUER,
        )

        if issuer is not _BINDING_ISSUER or type(binding) is not ResearchRuntimeBinding:
            raise TypeError("ResearchRuntimeBinding issuer is invalid")
        self.__bindings[binding.authorization_reference] = binding

    def _submit_bound(
        self,
        authorization: AuthorizedExperiment,
        binding: "ResearchRuntimeBinding",
        *,
        binding_issuer: object,
    ) -> ExperimentOutcome:
        from agent_core.research.runtime_binding import (
            _BINDING_ISSUER,
            InvalidRuntimeBindingError,
        )

        if (
            binding_issuer is not _BINDING_ISSUER
            or not binding._matches(authorization, self)
            or not _is_gate_authorized(authorization)
            or authorization.runtime_binding_reference != self.binding_reference
            or self.__transport.budget is not self.__budget
            or self.__transport.policy is not self.__policy
        ):
            raise InvalidRuntimeBindingError()
        if self.__persistence_failed:
            raise ResearchPersistenceError("persistence_failure")
        now = self._now()
        if _as_datetime(authorization.expiry) <= now:
            raise ExpiredAuthorizationError(
                ResearchAuthorizationErrorCode.expired_authorization
            )
        state = self._current_state()
        if (
            state.research_id != authorization.research_id
            or not self._authorization_state_is_current(state, authorization)
            or target_fingerprint(
                self.target(authorization.experiment.target.target_id)
            )
            != authorization.target_fingerprint
            or policy_fingerprint(self.__policy) != authorization.policy_hash
        ):
            raise InvalidRuntimeBindingError()
        if any(
            step.primitive_name in {"graphql_operation", "graphql_variable_mutation"}
            for step in authorization.experiment.primitive_steps
        ) and not self._graphql_bindings_are_current(state, authorization):
            raise InvalidRuntimeBindingError()
        if self.has_completed_fingerprint(authorization.experiment_fingerprint) and (
            authorization.experiment.reproduction_of is None
            or not self.has_completed_experiment(
                authorization.experiment.reproduction_of
            )
        ):
            raise ResearchRuntimeError("duplicate_experiment")
        reservation = authorization.request_budget_reservation
        cleanup_reserve = authorization.cleanup_reservation.requests_reserved
        if reservation.total > self.__budget.remaining:
            raise ResearchBudgetExhaustedError(
                ResearchAuthorizationErrorCode.budget_exhausted
            )

        before = self.__budget.snapshot()
        if authorization.dry_run:
            return self._outcome(
                authorization,
                evidence=(),
                classification=ExperimentResultClassification.inconclusive,
                request_delta=RequestDelta(),
                cleanup_status=(
                    CleanupStatus.reserved
                    if authorization.experiment.cleanup.required
                    else CleanupStatus.not_required
                ),
                cleanup_requests=0,
                occurred_at=_timestamp(now),
                dry_run=True,
            )

        evidence = []
        classifications = []
        runtime_failed = False
        cleanup_status = (
            CleanupStatus.pending
            if authorization.experiment.cleanup.required
            else CleanupStatus.not_required
        )
        cleanup_requests = 0
        identity_bindings = {
            item.identity_id: item
            for item in authorization.controlled_identity_bindings
        }
        object_references = {
            item.object_id: item.object_reference
            for item in authorization.owned_object_bindings
        }
        context = PrimitiveExecutorContext(
            experiment_id=authorization.experiment_id,
            reproduction=authorization.experiment.reproduction_of is not None,
            request_templates=self.__request_templates,
            controlled_values=self.__controlled_values,
            evidence_summaries=self.__evidence_summaries,
            state_snapshots=self.__state_snapshots,
            graphql_operation_templates=self.__graphql_operation_templates,
            graphql_safe_mutations=self.__graphql_safe_mutations,
            graphql_state=state,
            graphql_limits=self.__graphql_limits,
            authorization_reference=authorization.authorization_reference,
            identity_bindings=MappingProxyType(identity_bindings),
            vault_references=tuple(
                sorted(
                    str(item.vault_reference)
                    for item in identity_bindings.values()
                    if item.vault_reference is not None
                )
            ),
            identity_ids=frozenset(identity_bindings),
            object_references=MappingProxyType(object_references),
            primary_identity_id=(
                authorization.experiment.identity_context.primary_identity_id
            ),
            comparison_identity_id=(
                authorization.experiment.identity_context.comparison_identity_id
            ),
            request_accounting_reference=reservation.reservation_reference,
            runtime_provenance_reference=_identifier(
                "runtime-provenance", authorization.experiment_id
            ),
            send_registered=lambda request: self._send_registered(
                authorization,
                request,
                identity_bindings,
                cleanup_reserve=cleanup_reserve,
                before=before,
            ),
            send_graphql=lambda request, template: self._send_graphql(
                authorization,
                request,
                template,
                identity_bindings,
                object_references,
                cleanup_reserve=cleanup_reserve,
                before=before,
            ),
        )
        routes = {item.step_id: item for item in authorization.executor_routes}
        try:
            for step in authorization.experiment.primitive_steps:
                route = routes.get(step.step_id)
                if (
                    route is None
                    or route.primitive_name != step.primitive_name
                    or route.primitive_version != step.primitive_version
                ):
                    raise PrimitiveExecutionError("sealed executor route is invalid")
                executor = self.__executor_registry.resolve(route.route_reference)
                result = executor.execute(step, context)
                evidence.append(result.evidence)
                classifications.append(result.classification)
        except Exception:
            runtime_failed = True

        if authorization.experiment.cleanup.required:
            cleanup_before = self.__budget.snapshot()
            cleanup_status = self._cleanup(authorization, context)
            cleanup_after = self.__budget.snapshot()
            cleanup_requests = RequestDelta.from_snapshots(
                cleanup_before, cleanup_after
            ).cleanup
            if cleanup_status is CleanupStatus.failed:
                self.__cleanup_barrier.activate(
                    str(authorization.experiment.cleanup.cleanup_reference)
                )

        after = self.__budget.snapshot()
        request_delta = RequestDelta.from_snapshots(before, after)
        if request_delta.total > reservation.total:
            runtime_failed = True
        if cleanup_status is CleanupStatus.failed:
            classification = ExperimentResultClassification.cleanup_failed
        elif runtime_failed:
            classification = ExperimentResultClassification.runtime_failed
        elif ExperimentResultClassification.vulnerable_signal in classifications:
            classification = ExperimentResultClassification.vulnerable_signal
        elif ExperimentResultClassification.secure_signal in classifications:
            classification = ExperimentResultClassification.secure_signal
        else:
            classification = ExperimentResultClassification.inconclusive
        outcome = self._outcome(
            authorization,
            evidence=tuple(evidence),
            classification=classification,
            request_delta=request_delta,
            cleanup_status=cleanup_status,
            cleanup_requests=cleanup_requests,
            occurred_at=_timestamp(self._now()),
            dry_run=False,
        )
        # A fully bound P4-0F reproduction is persisted by the confirmation
        # coordinator together with its decision, finding status, graph, and
        # budget state. Legacy ``reproduction_of`` callers keep the original
        # runtime persistence behavior for compatibility.
        if (
            authorization.experiment.reproduction_id is None
            or authorization.experiment.reproduction_finding_id is None
        ):
            self._persist(authorization, outcome)
        self.__completed_fingerprints.add(authorization.experiment_fingerprint)
        self.__completed_experiment_ids.add(authorization.experiment_id)
        return outcome

    def _graphql_bindings_are_current(
        self, state: ResearchState, authorization: AuthorizedExperiment
    ) -> bool:
        identities = {item.identity_id: item for item in state.identities}
        sealed_identities = {
            item.identity_id: item
            for item in authorization.controlled_identity_bindings
        }
        for identity_id, sealed in sealed_identities.items():
            current = identities.get(identity_id)
            if (
                current is None
                or not current.controlled
                or current.eligibility is not IdentityEligibility.eligible
                or current.account_reference != sealed.account_reference
                or current.role_reference != sealed.role_reference
                or current.tenant_reference != sealed.tenant_reference
            ):
                return False
            try:
                account = self.__controlled_context.account(sealed.account_reference)
            except KeyError:
                return False
            if (
                not account.controlled
                or account.tenant_id != sealed.tenant_reference
                and sealed.tenant_reference is not None
                or not self.__policy.account_is_eligible(
                    account.account_id,
                    self.__controlled_context,
                    account_controlled=account.controlled,
                ).eligible
                or (
                    sealed.vault_reference is not None
                    and not self.__vault.contains(sealed.vault_reference)
                )
            ):
                return False
        objects = {item.object_id: item for item in state.objects}
        for sealed in authorization.owned_object_bindings:
            current = objects.get(sealed.object_id)
            owner = sealed_identities.get(sealed.owner_identity_id)
            if (
                current is None
                or owner is None
                or not current.test_owned
                or not current.evidence_references
                or current.object_reference != sealed.object_reference
                or current.owner_identity_id != sealed.owner_identity_id
                or current.tenant_reference != sealed.tenant_reference
            ):
                return False
            controlled = next(
                (
                    item
                    for item in self.__controlled_context.objects
                    if item.object_id in {current.object_id, current.object_reference}
                    and item.owner_account_id == owner.account_reference
                    and item.test_owned
                ),
                None,
            )
            if controlled is None or (
                sealed.tenant_reference is not None
                and controlled.tenant_id != sealed.tenant_reference
            ):
                return False
        return True

    def _send_graphql(
        self,
        authorization: AuthorizedExperiment,
        request: GraphQLExecutionRequest,
        template: object,
        identity_bindings: dict[str, object],
        object_references: dict[str, str],
        *,
        cleanup_reserve: int,
        before: dict[str, int],
    ) -> GraphQLRequestExecutionResult:
        from agent_core.research.executors import RegisteredRuntimeRequestTemplate

        operation_template = self.__graphql_operation_templates.get(
            request.operation_template_id
        )
        if (
            not request._is_trusted()
            or not isinstance(template, RegisteredRuntimeRequestTemplate)
            or operation_template is None
            or request.operation_id != operation_template.operation_id
            or request.endpoint_id != template.endpoint_id
            or request.surface_id != template.surface_id
            or request.target_id != template.target_id
            or request.method != template.method.value
            or request.url != template.url
            or request.method != "POST"
            or request.response_byte_limit > self.__graphql_limits.max_response_bytes
            or request.timeout_seconds > template.timeout_seconds
            or (
                request.expected_state_change_class
                is GraphQLExperimentStateChangeClass.read_only
                and authorization.experiment.state_changing
            )
            or (
                request.expected_state_change_class
                is GraphQLExperimentStateChangeClass.reversible_state_change
                and not authorization.experiment.state_changing
            )
            or not self._graphql_request_matches_authorization(
                authorization,
                request,
                identity_bindings,
                object_references,
            )
        ):
            raise PrimitiveExecutionError("sealed GraphQL request is invalid")
        used = RequestDelta.from_snapshots(before, self.__budget.snapshot())
        reservation = authorization.request_budget_reservation
        non_cleanup = used.discovery + used.auth + used.verification
        if (
            non_cleanup >= reservation.verification
            or self.__budget.remaining <= cleanup_reserve
        ):
            raise ResearchBudgetExhaustedError(
                ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
            )

        headers = {item.name: item.value for item in template.safe_headers}
        binding = None
        if request.identity_id is not None:
            binding = identity_bindings.get(request.identity_id)
            reference = getattr(binding, "vault_reference", None)
            if binding is None:
                raise PrimitiveExecutionError(
                    "controlled GraphQL identity binding is unavailable"
                )
            if template.credential_header_name is not None:
                if reference is None:
                    raise PrimitiveExecutionError(
                        "controlled GraphQL session binding is unavailable"
                    )
                try:
                    # The credential exists in a local variable only for the
                    # immediate call into the shared scoped transport.
                    headers[template.credential_header_name] = self.__vault.get(
                        reference
                    )
                except (KeyError, RuntimeError) as exc:
                    raise PrimitiveExecutionError(
                        "controlled GraphQL session binding is unavailable"
                    ) from exc
        body = {
            "query": request.document,
            "variables": dict(request.variables),
            "operationName": request.operation_name,
        }
        transport_context = None
        if request.purpose == "graphql_execution":
            account_reference = getattr(binding, "account_reference", None)
            transport_context = TransportRequestContext(
                purpose="graphql_execution",
                policy_authorized=True,
                configured_url=template.url,
                configured_method=template.method.value,
                configured_endpoint_match=True,
                controlled_account_id=account_reference,
                account_controlled=binding is not None,
                account_policy_authorized=binding is not None,
                workflow_category="graphql_execution",
                generated_by="ResearchRuntime",
            )
        attempt_before = self.__budget.snapshot()
        started = time.monotonic()
        try:
            response, _redirects = self.__transport.request(
                request.method,
                request.url,
                timeout=request.timeout_seconds,
                follow_redirects=False,
                max_redirects=0,
                headers=headers,
                json=body,
                response_byte_limit=request.response_byte_limit,
                purpose=request.purpose,
                request_context=transport_context,
                allow_session_credentials=(request.identity_id is not None),
                isolate_session_cookies=template.credential_header_name is not None,
            )
        except Exception as exc:
            attempt_after = self.__budget.snapshot()
            consumed = RequestDelta.from_snapshots(attempt_before, attempt_after).total
            if consumed != 1:
                raise
            latency_ms = min(3_600_000, int((time.monotonic() - started) * 1000))
            oversized = isinstance(exc, ResponseTooLargeError)
            observation = GraphQLResponseObservation(
                envelope=(
                    GraphQLResponseEnvelope.oversized
                    if oversized
                    else GraphQLResponseEnvelope.transport_failure
                ),
                errors_present=True,
                error_classes=(GraphQLErrorClass.transport_error,),
                evidence_digest=_digest(
                    "graphql-response-oversized"
                    if oversized
                    else "graphql-transport-failure"
                ),
                response_bytes=0,
                truncated=oversized,
            )
            return GraphQLRequestExecutionResult(
                request_summary=_graphql_request_summary(request),
                response_summary=None,
                graphql_response=self._graphql_response_evidence(
                    authorization,
                    request,
                    observation,
                    status_code=None,
                    latency_ms=latency_ms,
                    error_count=1,
                    object_references=object_references,
                    response_raw=None,
                ),
            )
        latency_ms = min(3_600_000, int((time.monotonic() - started) * 1000))
        status = getattr(response, "status_code", None)
        if type(status) is not int or not 100 <= status <= 599:
            raise PrimitiveExecutionError(
                "transport returned an invalid response status"
            )
        raw = getattr(response, "content", b"")
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        if not isinstance(raw, bytes):
            raw = b""
        if len(raw) > request.response_byte_limit:
            raise PrimitiveExecutionError("bounded GraphQL response invariant failed")
        content_type = _response_content_type(response)
        observation = analyze_graphql_response(
            raw,
            status_code=status,
            content_type=content_type,
            max_bytes=request.response_byte_limit,
            max_errors=self.__graphql_limits.max_errors,
            request_was_graphql=True,
        )
        error_count = _bounded_graphql_error_count(
            raw, self.__graphql_limits.max_errors
        )
        if error_count >= self.__graphql_limits.max_errors:
            observation = observation.model_copy(update={"truncated": True})
        return GraphQLRequestExecutionResult(
            request_summary=_graphql_request_summary(request),
            response_summary=_safe_response_summary(response),
            graphql_response=self._graphql_response_evidence(
                authorization,
                request,
                observation,
                status_code=status,
                latency_ms=latency_ms,
                error_count=error_count,
                object_references=object_references,
                response_raw=raw,
            ),
        )

    def _graphql_response_evidence(
        self,
        authorization: AuthorizedExperiment,
        request: GraphQLExecutionRequest,
        observation: GraphQLResponseObservation,
        *,
        status_code: int | None,
        latency_ms: int,
        error_count: int,
        object_references: dict[str, str],
        response_raw: bytes | None,
    ) -> GraphQLRuntimeResponseEvidence:
        shape_names = "\n".join(observation.object_shape)
        fields = {
            item.field_id: item.name
            for item in self._current_state().graphql_fields
            if item.field_id in request.selected_field_ids
        }
        present = tuple(
            sorted(
                field_id
                for field_id, name in fields.items()
                if re.search(rf"(?:^|\.){re.escape(name)}(?:\[\])?:", shape_names)
            )
        )
        nulls = tuple(
            sorted(
                field_id
                for field_id, name in fields.items()
                if any(
                    re.search(rf"(?:^|\.){re.escape(name)}(?:\[\])?$", path)
                    for path in observation.null_paths
                )
            )
        )
        field_names = {
            item.name: item.field_id for item in self._current_state().graphql_fields
        }
        error_paths = tuple(
            GraphQLErrorPathEvidence(
                path=item.path,
                error_class=item.error_class,
            )
            for item in observation.error_paths
            if any(
                isinstance(component, str) and component in field_names
                for component in item.path
            )
        )
        controlled_match = None
        if request.object_ids:
            expected_values = tuple(
                object_references[object_id]
                for object_id in request.object_ids
                if object_id in object_references
            )
            controlled_match = (
                _response_contains_controlled_value(response_raw, expected_values)
                if response_raw is not None and expected_values
                else None
            )
        return GraphQLRuntimeResponseEvidence(
            authorized_experiment_reference=authorization.authorization_reference,
            operation_template_reference=request.operation_template_id,
            operation_reference=request.operation_id,
            identity_reference=request.identity_id,
            object_references=request.object_ids,
            request_accounting_reference=(
                authorization.request_budget_reservation.reservation_reference
            ),
            runtime_provenance_reference=request.runtime_provenance_reference,
            status_code=status_code,
            status_class=(
                f"{status_code // 100}xx"
                if status_code is not None
                else "transport_failure"
            ),
            envelope=observation.envelope,
            data_present=observation.data_present,
            errors_present=observation.errors_present,
            error_classes=observation.error_classes,
            error_paths=error_paths,
            error_count=error_count,
            typename_observations=observation.typename_observations,
            selected_field_presence=present,
            selected_field_nulls=nulls,
            object_shape_fingerprint=_digest(observation.object_shape),
            controlled_object_reference_match=controlled_match,
            response_digest=observation.evidence_digest,
            response_bytes=observation.response_bytes,
            latency_ms=latency_ms,
            truncated=observation.truncated,
        )

    def _graphql_request_matches_authorization(
        self,
        authorization: AuthorizedExperiment,
        request: GraphQLExecutionRequest,
        identity_bindings: dict[str, object],
        object_references: dict[str, str],
    ) -> bool:
        operation_template = self.__graphql_operation_templates.get(
            request.operation_template_id
        )
        if operation_template is None:
            return False
        state = self._current_state()
        vault_references = tuple(
            str(item.vault_reference)
            for item in identity_bindings.values()
            if item.vault_reference is not None
        )
        for step in authorization.experiment.primitive_steps:
            value = step.input
            if (
                not isinstance(
                    value, (GraphQLOperationInput, GraphQLVariableMutationInput)
                )
                or str(value.operation_template_id) != request.operation_template_id
            ):
                continue
            if isinstance(value, GraphQLOperationInput):
                bindings = (
                    value.variable_bindings or operation_template.variable_bindings
                )
                selected_field_ids = value.selected_field_ids
                identity_id = (
                    None
                    if value.anonymous
                    else value.identity_id
                    or authorization.experiment.identity_context.primary_identity_id
                )
            else:
                if value.binding is None:
                    continue
                bindings = (value.binding,)
                selected_field_ids = ()
                identity_id = (
                    authorization.experiment.identity_context.primary_identity_id
                )
            try:
                rendered = GraphQLDocumentRenderer(state, self.__graphql_limits).render(
                    operation_template,
                    variable_bindings=bindings,
                    selected_field_ids=selected_field_ids,
                )
                variables = materialize_graphql_variables(
                    state,
                    operation_template,
                    bindings,
                    object_references=object_references,
                    identity_bindings=identity_bindings,
                    controlled_values=self.__controlled_values,
                    vault_references=vault_references,
                    limits=self.__graphql_limits,
                )
            except Exception:
                continue
            object_ids = tuple(
                sorted(
                    item.value_reference
                    for item in bindings
                    if item.value_source.value == "controlled_object"
                )
            )
            if (
                request.identity_id == identity_id
                and request.document == rendered.document
                and request.document_digest == rendered.document_digest
                and request.operation_name == rendered.operation_name
                and request.selected_field_ids == rendered.selected_field_ids
                and request.selected_field_names == rendered.selected_field_names
                and dict(request.variables) == dict(variables)
                and request.object_ids == object_ids
            ):
                return True
        return False

    def _send_registered(
        self,
        authorization: AuthorizedExperiment,
        request: ResolvedRequest,
        identity_bindings: dict[str, object],
        *,
        cleanup_reserve: int,
        before: dict[str, int],
    ) -> RequestExecutionResult:
        template = self.__request_templates.get(request.template_id)
        if (
            template is None
            or request.target_id != template.target_id
            or request.surface_id != template.surface_id
            or request.endpoint_id != template.endpoint_id
            or request.method != template.method.value
            or not _resolved_request_matches_template(template.url, request.url)
        ):
            raise PrimitiveExecutionError(
                "resolved request does not match its template"
            )
        used = RequestDelta.from_snapshots(before, self.__budget.snapshot())
        reservation = authorization.request_budget_reservation
        if request.purpose == "cleanup":
            if used.cleanup >= reservation.cleanup:
                raise ResearchBudgetExhaustedError(
                    ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
                )
        else:
            non_cleanup = used.discovery + used.auth + used.verification
            if (
                non_cleanup >= reservation.verification
                or self.__budget.remaining <= cleanup_reserve
            ):
                raise ResearchBudgetExhaustedError(
                    ResearchAuthorizationErrorCode.cleanup_reserve_unavailable
                )
        headers = {item.name: item.value for item in template.safe_headers}
        if (
            template.credential_header_name is not None
            and request.identity_id is not None
        ):
            binding = identity_bindings.get(str(request.identity_id))
            reference = getattr(binding, "vault_reference", None)
            if binding is None or reference is None:
                raise PrimitiveExecutionError(
                    "controlled session binding is unavailable"
                )
            try:
                headers[template.credential_header_name] = self.__vault.get(reference)
            except (KeyError, RuntimeError) as exc:
                raise PrimitiveExecutionError(
                    "controlled session binding is unavailable"
                ) from exc
        kwargs: dict[str, object] = {}
        if request.query:
            kwargs["params"] = list(request.query)
        if request.json_fields is not None:
            kwargs["json"] = dict(request.json_fields)
        if request.form_fields:
            kwargs["data"] = list(request.form_fields)
        response, _redirects = self.__transport.request(
            request.method,
            request.url,
            timeout=request.timeout_seconds,
            follow_redirects=False,
            max_redirects=0,
            headers=headers,
            purpose=request.purpose,
            allow_session_credentials=(
                template.credential_header_name is None
                or request.identity_id is not None
            ),
            isolate_session_cookies=template.credential_header_name is not None,
            **kwargs,
        )
        request_summary = SafeRequestSummary(
            request_template_reference=request.template_id,
            target_reference=request.target_id,
            surface_reference=request.surface_id,
            endpoint_reference=request.endpoint_id,
            method=request.method,
            identity_reference=request.identity_id,
            parameter_references=request.parameter_ids,
            body_present=bool(request.json_fields or request.form_fields),
        )
        return RequestExecutionResult(
            request_summary=request_summary,
            response_summary=_safe_response_summary(response),
        )

    def _cleanup(
        self,
        authorization: AuthorizedExperiment,
        context: PrimitiveExecutorContext,
    ) -> CleanupStatus:
        reference = str(authorization.experiment.cleanup.cleanup_reference)
        registration = self.__cleanup_handlers.get(reference)
        if not isinstance(registration, RegisteredCleanupExecution):
            return CleanupStatus.failed
        template = self.__request_templates.get(registration.request_template_id)
        if template is None:
            return CleanupStatus.failed
        try:
            request = context.resolve(
                template,
                identity_id=registration.identity_id,
                purpose="cleanup",
            )
            result = context.send(request)
        except Exception:
            return CleanupStatus.failed
        if result.response_summary.status_code not in registration.success_status_codes:
            return CleanupStatus.failed
        return CleanupStatus.completed

    def _outcome(
        self,
        authorization: AuthorizedExperiment,
        *,
        evidence: tuple,
        classification: ExperimentResultClassification,
        request_delta: RequestDelta,
        cleanup_status: CleanupStatus,
        cleanup_requests: int,
        occurred_at: str,
        dry_run: bool,
    ) -> ExperimentOutcome:
        evidence_references = tuple(item.evidence_id for item in evidence)
        runtime_status = (
            ExperimentRuntimeStatus.failed
            if classification is ExperimentResultClassification.runtime_failed
            else (
                ExperimentRuntimeStatus.cleanup_pending
                if classification is ExperimentResultClassification.cleanup_failed
                else ExperimentRuntimeStatus.completed
            )
        )
        canonical = (
            Phase2ResultStatus.verification_pending_cleanup
            if cleanup_status is CleanupStatus.failed
            else Phase2ResultStatus.inconclusive
        )
        proposed = None
        if dry_run:
            reservation = authorization.request_budget_reservation
            proposed = ProposedExecutionMetadata(
                dry_run=True,
                primitive_routes=tuple(
                    item.route_reference for item in authorization.executor_routes
                ),
                verification_reservation=reservation.verification,
                cleanup_reservation=reservation.cleanup,
                total_reservation=reservation.total,
            )
        outcome = ExperimentOutcome(
            outcome_id=_identifier("outcome", authorization.experiment_id),
            experiment_id=authorization.experiment_id,
            runtime_status=runtime_status,
            canonical_result_classification=canonical,
            evidence_references=evidence_references,
            request_delta=request_delta,
            model_usage_delta=ModelUsageDelta(),
            cleanup_status=cleanup_status,
            evaluator_result_reference=None,
            created_fact_ids=(),
            created_hypothesis_ids=(),
            candidate_finding_ids=(),
            provenance_id=_identifier(
                "runtime-provenance", authorization.experiment_id
            ),
            occurred_at=occurred_at,
            result_classification=classification,
            evidence=evidence,
            cleanup_result=CleanupExecutionResult(
                status=cleanup_status,
                cleanup_reference=(
                    authorization.experiment.cleanup.cleanup_reference
                    if authorization.experiment.cleanup.required
                    else None
                ),
                requests_used=cleanup_requests,
                graphql_trace_event=(
                    GraphQLRuntimeTraceEvent(
                        event_type="GRAPHQL_CLEANUP",
                        experiment_reference=authorization.experiment_id,
                        operation_reference=str(
                            next(
                                step.input.operation_id
                                for step in authorization.experiment.primitive_steps
                                if step.primitive_name
                                in {
                                    "graphql_operation",
                                    "graphql_variable_mutation",
                                }
                            )
                        ),
                        identity_reference=(
                            authorization.experiment.identity_context.primary_identity_id
                        ),
                        request_count=cleanup_requests,
                        status_class=cleanup_status.value,
                    )
                    if authorization.experiment.cleanup.required
                    and any(
                        step.primitive_name
                        in {"graphql_operation", "graphql_variable_mutation"}
                        for step in authorization.experiment.primitive_steps
                    )
                    else None
                ),
            ),
            runtime_provenance=RuntimeProvenance(
                runtime_name=RESEARCH_RUNTIME_NAME,
                runtime_version=RESEARCH_RUNTIME_VERSION,
                executor_registry_hash=self.__executor_registry.fingerprint,
                primitive_registry_hash=self.__primitive_registry.fingerprint,
                policy_reference=authorization.policy_reference,
                policy_hash=authorization.policy_hash,
                target_fingerprint=authorization.target_fingerprint,
            ),
            authorization_reference=authorization.authorization_reference,
            runtime_binding_reference=authorization.runtime_binding_reference,
            proposed_execution=proposed,
        )
        reject_secret_material(
            outcome.model_dump(mode="json"), location="research experiment outcome"
        )
        return outcome

    def _persist(
        self, authorization: AuthorizedExperiment, outcome: ExperimentOutcome
    ) -> None:
        if self.__store is None:
            return
        try:
            state = self.__store.load_research(authorization.research_id)
            if not self._authorization_state_is_current(state, authorization):
                raise ValueError("research revision changed before outcome commit")
            evidence = tuple(
                EvidenceArtifact(
                    evidence_id=item.evidence_id,
                    evidence_kind=(
                        EvidenceKind.differential
                        if item.selector_results or item.invariant_results
                        else (
                            EvidenceKind.response_summary
                            if item.response_summaries
                            else EvidenceKind.request_result
                        )
                    ),
                    digest=_digest(item.model_dump(mode="json")),
                    summary=item.summary,
                    source_reference=item.step_id,
                    observed_at=outcome.occurred_at,
                    provenance_id=outcome.provenance_id,
                    metadata=PublicMetadata(
                        entries=(
                            MetadataEntry(
                                key="primitive_name", value=item.primitive_name
                            ),
                            *(
                                (
                                    MetadataEntry(
                                        key="graphql_operation",
                                        value=item.graphql_responses[
                                            0
                                        ].operation_reference,
                                    ),
                                    MetadataEntry(
                                        key="graphql_status_class",
                                        value=item.graphql_responses[0].status_class,
                                    ),
                                    MetadataEntry(
                                        key="graphql_error_class",
                                        value=(
                                            item.graphql_responses[0]
                                            .error_classes[0]
                                            .value
                                            if item.graphql_responses[0].error_classes
                                            else "none"
                                        ),
                                    ),
                                )
                                if item.graphql_responses
                                else ()
                            ),
                        )
                    ),
                )
                for item in outcome.evidence
            )
            provenance = ProvenanceRecord(
                provenance_id=outcome.provenance_id,
                producer_type=ProvenanceProducerType.runtime,
                producer_name=RESEARCH_RUNTIME_NAME,
                producer_version=RESEARCH_RUNTIME_VERSION,
                source_references=tuple(
                    sorted(
                        {
                            authorization.experiment_fingerprint,
                            authorization.authorization_reference,
                            f"research-revision:{authorization.state_revision}",
                        }
                    )
                ),
                summary="Executed one sealed deterministic research experiment.",
                occurred_at=outcome.occurred_at,
            )
            base_fields = StoredExperimentOutcome.model_fields.keys()
            stored_outcome = StoredExperimentOutcome.model_validate(
                outcome.model_dump(mode="python", include=set(base_fields))
            )
            payload = state.model_dump(mode="python")
            payload.update(
                revision=state.revision + 1,
                updated_at=outcome.occurred_at,
                evidence=(*state.evidence, *evidence),
                experiment_outcomes=(*state.experiment_outcomes, stored_outcome),
                provenance=(*state.provenance, provenance),
            )
            next_state = ResearchState.model_validate(payload)
            event = ResearchEvent(
                event_id=_identifier("event", outcome.outcome_id),
                research_id=state.research_id,
                event_type=ResearchEventType.experiment_outcome_recorded,
                state_revision=next_state.revision,
                provenance_id=outcome.provenance_id,
                occurred_at=outcome.occurred_at,
                summary="Recorded a deterministic research experiment outcome.",
                payload=ExperimentOutcomeRecordedPayload(outcome_id=outcome.outcome_id),
            )
            self.__store.commit_revision(
                state.research_id,
                expected_revision=state.revision,
                state=next_state,
                events=(event,),
            )
            object.__setattr__(self, "_ResearchRuntime__state", next_state)
        except Exception as exc:
            object.__setattr__(self, "_ResearchRuntime__persistence_failed", True)
            raise ResearchPersistenceError("persistence_failure") from exc

    def _authorization_state_is_current(
        self, state: ResearchState, authorization: AuthorizedExperiment
    ) -> bool:
        if state.revision == authorization.state_revision:
            return True
        if (
            self.__store is None
            or state.revision != authorization.state_revision + 1
            or state.status is not ResearchRunStatus.executing_experiment
        ):
            return False
        try:
            authorized_state = self.__store.load_research(
                authorization.research_id, authorization.state_revision
            )
        except Exception:
            return False
        if (
            not isinstance(authorized_state, ResearchState)
            or authorized_state.status is not ResearchRunStatus.awaiting_authorization
        ):
            return False
        authorized_payload = authorized_state.model_dump(mode="python")
        current_payload = state.model_dump(mode="python")
        for field in ("revision", "status", "updated_at"):
            authorized_payload.pop(field, None)
            current_payload.pop(field, None)
        return authorized_payload == current_payload

    def _current_state(self) -> ResearchState:
        if self.__store is None:
            return self.__state
        try:
            loaded = self.__store.load_research(self.__state.research_id)
        except Exception as exc:
            raise ResearchPersistenceError("persistence_failure") from exc
        if not isinstance(loaded, ResearchState):
            raise ResearchPersistenceError("persistence_failure")
        return loaded

    def _now(self) -> datetime:
        return (
            _as_datetime(self.__current_time)
            if self.__current_time is not None
            else datetime.now(timezone.utc)
        )

    def __copy__(self) -> None:
        raise TypeError("ResearchRuntime cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> None:
        raise TypeError("ResearchRuntime cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("ResearchRuntime cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("ResearchRuntime cannot be serialized")


def _create_research_runtime(gate: "ResearchExecutionGate") -> ResearchRuntime:
    return ResearchRuntime(gate, _RUNTIME_ISSUER)


def _graphql_request_summary(
    request: GraphQLExecutionRequest,
) -> SafeRequestSummary:
    return SafeRequestSummary(
        request_template_reference=request.operation_template_id,
        target_reference=request.target_id,
        surface_reference=request.surface_id,
        endpoint_reference=request.endpoint_id,
        method=request.method,
        identity_reference=request.identity_id,
        parameter_references=(),
        body_present=True,
    )


def _response_content_type(response: object) -> str | None:
    headers = getattr(response, "headers", {})
    if not hasattr(headers, "get"):
        return None
    raw = headers.get("Content-Type") or headers.get("content-type")
    if not isinstance(raw, str):
        return None
    value = raw.split(";", 1)[0].strip().lower()
    return value if value and len(value) <= 255 else None


def _bounded_graphql_error_count(raw: bytes, limit: int) -> int:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return 0
    if not isinstance(payload, dict) or not isinstance(payload.get("errors"), list):
        return 0
    return min(limit, len(payload["errors"]))


def _response_contains_controlled_value(
    raw: bytes, expected_values: tuple[str, ...]
) -> bool:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False
    expected = set(expected_values)
    nodes = 0

    def visit(value: object, depth: int) -> bool:
        nonlocal nodes
        if depth > 12 or nodes >= 1_024:
            return False
        nodes += 1
        if isinstance(value, str):
            return value in expected
        if isinstance(value, dict):
            return any(visit(item, depth + 1) for item in value.values())
        if isinstance(value, list):
            return any(visit(item, depth + 1) for item in value[:32])
        return False

    return visit(payload, 0)


def _safe_response_summary(response: object) -> SafeResponseSummary:
    status = getattr(response, "status_code", None)
    if type(status) is not int or not 100 <= status <= 599:
        raise PrimitiveExecutionError("transport returned an invalid response status")
    content_type = _response_content_type(response)
    content = getattr(response, "content", b"")
    if isinstance(content, str):
        raw = content.encode("utf-8", errors="replace")
    elif isinstance(content, bytes):
        raw = content
    else:
        raw = b""
    shape, top_fields = _response_shape(raw, content_type)
    length = len(raw)
    length_class = (
        "empty"
        if length == 0
        else "small"
        if length <= 1_024
        else "medium"
        if length <= 100_000
        else "large"
    )
    return SafeResponseSummary(
        status_code=status,
        status_class=f"{status // 100}xx",
        content_length_class=length_class,
        content_type=content_type,
        structural_digest=_digest(shape),
        content_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        top_level_fields=top_fields,
        body_present=bool(raw),
    )


def _response_shape(
    raw: bytes, content_type: str | None
) -> tuple[object, tuple[str, ...]]:
    if content_type == "application/json" and raw:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return "invalid-json", ()

        def shape(item: object, depth: int = 0) -> object:
            if depth >= 5:
                return "depth-bound"
            if isinstance(item, dict):
                return {
                    _safe_field_reference(str(key)): shape(value, depth + 1)
                    for key, value in sorted(
                        item.items(), key=lambda pair: str(pair[0])
                    )[:100]
                }
            if isinstance(item, list):
                return [shape(value, depth + 1) for value in item[:20]]
            if item is None:
                return "null"
            if isinstance(item, bool):
                return "boolean"
            if isinstance(item, (int, float)):
                return "number"
            return "string"

        top = (
            tuple(sorted(_safe_field_reference(str(key)) for key in value)[:100])
            if isinstance(value, dict)
            else ()
        )
        return shape(value), top
    return ("body" if raw else "empty"), ()


def _safe_field_reference(value: str) -> str:
    return "field-" + hashlib.sha256(value.encode()).hexdigest()[:16]


def _resolved_request_matches_template(template_url: str, candidate_url: str) -> bool:
    from urllib.parse import urlparse

    template = urlparse(template_url)
    candidate = urlparse(candidate_url)
    if (
        template.scheme != candidate.scheme
        or template.hostname != candidate.hostname
        or template.port != candidate.port
        or candidate.username is not None
        or candidate.password is not None
        or candidate.query
        or candidate.fragment
    ):
        return False
    pattern = re.escape(template.path)
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
    return re.fullmatch(pattern, candidate.path) is not None


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _identifier(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(item) for item in parts)
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "RESEARCH_RUNTIME_NAME",
    "RESEARCH_RUNTIME_VERSION",
    "ResearchPersistenceError",
    "ResearchRuntime",
    "ResearchRuntimeError",
]
