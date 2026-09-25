"""Sealed deterministic runtime for authorized Phase 4 experiments."""

from __future__ import annotations

import hashlib
import json
import secrets
import re
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from agent_core.models import ModelUsageDelta
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
    PrimitiveExecutionError,
    PrimitiveExecutorContext,
    RegisteredCleanupExecution,
    RequestExecutionResult,
    ResolvedRequest,
)
from agent_core.research.experiments import AuthorizedExperiment, _is_gate_authorized
from agent_core.research.outcomes import (
    CleanupExecutionResult,
    ExperimentOutcome,
    ExperimentResultClassification,
    ProposedExecutionMetadata,
    RuntimeProvenance,
    SafeRequestSummary,
    SafeResponseSummary,
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
    MetadataEntry,
    ProvenanceProducerType,
    PublicMetadata,
    ResearchRunStatus,
)

RESEARCH_RUNTIME_NAME = "cybercortex-research-runtime"
RESEARCH_RUNTIME_VERSION = "p4-0d-v1"
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


def _safe_response_summary(response: object) -> SafeResponseSummary:
    status = getattr(response, "status_code", None)
    if type(status) is not int or not 100 <= status <= 599:
        raise PrimitiveExecutionError("transport returned an invalid response status")
    headers = getattr(response, "headers", {})
    content_type = None
    if hasattr(headers, "get"):
        raw_content_type = headers.get("Content-Type") or headers.get("content-type")
        if isinstance(raw_content_type, str):
            candidate = raw_content_type.split(";", 1)[0].strip().lower()
            if candidate and len(candidate) <= 255:
                content_type = candidate
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
        else "small" if length <= 1_024 else "medium" if length <= 100_000 else "large"
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
        except (UnicodeDecodeError, json.JSONDecodeError):
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
