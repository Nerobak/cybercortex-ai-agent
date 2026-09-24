"""Bounded native executors for sealed Phase 4 research experiments.

This module deliberately has no network implementation.  Executors can only ask
their runtime context to send a request that was resolved from a registered
template.  The context is created by :mod:`agent_core.research.runtime` and is
not part of the public execution API.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from pydantic import Field, StrictBool, model_validator

from agent_core.research.outcomes import (
    ExperimentResultClassification,
    InvariantResult,
    PrimitiveExecutionEvidence,
    SafeRequestSummary,
    SafeResponseSummary,
    SelectorResult,
)
from agent_core.research.primitives import (
    AuthenticationDifferentialInput,
    CompiledPrimitiveStep,
    DifferentialSelector,
    IdentitySwitchInput,
    MutationKind,
    ObjectSubstitutionInput,
    ParameterMutationInput,
    RequestReplayInput,
    ResponseDifferentialInput,
    StateDifferentialInput,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.types import (
    HttpMethod,
    OpaqueIdentifier,
    ParameterLocation,
    ResearchContract,
)

RESEARCH_EXECUTOR_REGISTRY_VERSION = "phase4-research-executors-v1"

_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_AUTH_SUCCESS = frozenset({200, 201, 202, 204})
_AUTH_DENIAL = frozenset({401, 403, 404})
_ROUTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,2047}$")


JSONScalar = str | int | float | bool | None


class RegisteredRequestParameter(ResearchContract):
    """One parameter and its trusted baseline value in a request template."""

    parameter_id: OpaqueIdentifier
    name: OpaqueIdentifier
    location: ParameterLocation
    value: JSONScalar = None


class RegisteredSafeRequestHeader(ResearchContract):
    name: OpaqueIdentifier
    value: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def reject_credentials(self) -> "RegisteredSafeRequestHeader":
        if self.name.casefold().replace("_", "-") in _CREDENTIAL_HEADERS:
            raise ValueError("credential-bearing static headers are prohibited")
        reject_secret_material(self.value, location="registered safe request header")
        return self


class RegisteredRuntimeRequestTemplate(ResearchContract):
    """Trusted concrete request data registered outside model output."""

    template_id: OpaqueIdentifier
    target_id: OpaqueIdentifier
    surface_id: OpaqueIdentifier
    endpoint_id: OpaqueIdentifier
    method: HttpMethod
    url: str = Field(min_length=8, max_length=2_048)
    parameters: tuple[RegisteredRequestParameter, ...] = Field(
        default=(), max_length=100
    )
    safe_headers: tuple[RegisteredSafeRequestHeader, ...] = Field(
        default=(), max_length=50
    )
    credential_header_name: Literal["Authorization", "Cookie"] | None = None
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    @model_validator(mode="after")
    def validate_template(self) -> "RegisteredRuntimeRequestTemplate":
        parsed = urlparse(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("runtime request template requires an HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("runtime request template URL cannot contain credentials")
        ids = tuple(item.parameter_id for item in self.parameters)
        names = tuple((item.location, item.name) for item in self.parameters)
        if len(ids) != len(set(ids)) or len(names) != len(set(names)):
            raise ValueError("runtime request template parameters must be unique")
        header_names = tuple(item.name.casefold() for item in self.safe_headers)
        if len(header_names) != len(set(header_names)):
            raise ValueError("runtime request template headers must be unique")
        return self


# Short public alias used by tests and integrations.
RuntimeRequestTemplate = RegisteredRuntimeRequestTemplate


class RegisteredControlledValue(ResearchContract):
    reference: OpaqueIdentifier
    value: JSONScalar

    @model_validator(mode="after")
    def enforce_safe_value(self) -> "RegisteredControlledValue":
        reject_secret_material(self.value, location="registered controlled value")
        return self


class RegisteredSelectorValue(ResearchContract):
    selector: DifferentialSelector
    value: JSONScalar


class RegisteredEvidenceSummary(ResearchContract):
    reference: OpaqueIdentifier
    selector_values: tuple[RegisteredSelectorValue, ...] = Field(
        min_length=1, max_length=20
    )

    @model_validator(mode="after")
    def unique_selectors(self) -> "RegisteredEvidenceSummary":
        selectors = tuple(item.selector for item in self.selector_values)
        if len(selectors) != len(set(selectors)):
            raise ValueError("registered evidence selectors must be unique")
        reject_secret_material(
            self.model_dump(mode="json"), location="registered evidence summary"
        )
        return self


class RegisteredInvariantValue(ResearchContract):
    invariant_reference: OpaqueIdentifier
    satisfied: StrictBool


class RegisteredStateSnapshot(ResearchContract):
    reference: OpaqueIdentifier
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    invariants: tuple[RegisteredInvariantValue, ...] = Field(default=(), max_length=20)


class RegisteredCleanupExecution(ResearchContract):
    """One sealed cleanup route using another registered request template."""

    cleanup_reference: OpaqueIdentifier
    request_template_id: OpaqueIdentifier
    identity_id: OpaqueIdentifier | None = None
    success_status_codes: tuple[int, ...] = Field(
        default=(200, 204), min_length=1, max_length=10
    )

    @model_validator(mode="after")
    def validate_statuses(self) -> "RegisteredCleanupExecution":
        if any(
            type(value) is not int or not 100 <= value <= 599
            for value in self.success_status_codes
        ):
            raise ValueError("cleanup success statuses must be HTTP status codes")
        if len(self.success_status_codes) != len(set(self.success_status_codes)):
            raise ValueError("cleanup success statuses must be unique")
        return self


@dataclass(frozen=True, slots=True)
class ResolvedRequest:
    """Private request material accepted only by the sealed runtime callback."""

    template_id: str
    target_id: str
    surface_id: str
    endpoint_id: str
    method: str
    url: str
    timeout_seconds: int
    headers: Mapping[str, str]
    query: tuple[tuple[str, JSONScalar], ...] = ()
    json_fields: Mapping[str, JSONScalar] | None = None
    form_fields: tuple[tuple[str, JSONScalar], ...] = ()
    identity_id: str | None = None
    parameter_ids: tuple[str, ...] = ()
    purpose: Literal["verification", "state_mutation", "cleanup"] = "verification"


@dataclass(frozen=True, slots=True)
class RequestExecutionResult:
    request_summary: SafeRequestSummary
    response_summary: SafeResponseSummary


@dataclass(frozen=True, slots=True)
class ExecutorStepResult:
    evidence: PrimitiveExecutionEvidence
    classification: ExperimentResultClassification = (
        ExperimentResultClassification.inconclusive
    )


class PrimitiveExecutor(Protocol):
    route_reference: str

    def execute(
        self, step: CompiledPrimitiveStep, context: "PrimitiveExecutorContext"
    ) -> ExecutorStepResult: ...


@dataclass(slots=True)
class PrimitiveExecutorContext:
    """Private capability object exposed only to registered native executors."""

    experiment_id: str
    reproduction: bool
    request_templates: Mapping[str, RegisteredRuntimeRequestTemplate]
    controlled_values: Mapping[str, RegisteredControlledValue]
    evidence_summaries: Mapping[str, RegisteredEvidenceSummary]
    state_snapshots: Mapping[str, RegisteredStateSnapshot]
    identity_ids: frozenset[str]
    object_references: Mapping[str, str]
    primary_identity_id: str | None
    comparison_identity_id: str | None
    request_accounting_reference: str
    runtime_provenance_reference: str
    send_registered: Callable[[ResolvedRequest], RequestExecutionResult]
    current_identity_id: str | None = None
    produced_evidence: dict[str, PrimitiveExecutionEvidence] = field(
        default_factory=dict
    )

    def template(self, template_id: str) -> RegisteredRuntimeRequestTemplate:
        try:
            return self.request_templates[template_id]
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "registered request template is unavailable"
            ) from exc

    def controlled_value(self, reference: str) -> JSONScalar:
        try:
            return self.controlled_values[reference].value
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "registered controlled value is unavailable"
            ) from exc

    def identity(self, requested: str | None = None) -> str | None:
        selected = requested or self.current_identity_id or self.primary_identity_id
        if selected is not None and selected not in self.identity_ids:
            raise PrimitiveExecutionError("controlled identity binding is unavailable")
        return selected

    def resolve(
        self,
        template: RegisteredRuntimeRequestTemplate,
        *,
        overrides: (
            Mapping[str, JSONScalar | tuple[JSONScalar, ...] | object] | None
        ) = None,
        identity_id: str | None = None,
        purpose: Literal["verification", "state_mutation", "cleanup"] | None = None,
        anonymous: bool = False,
    ) -> ResolvedRequest:
        overrides = overrides or {}
        unknown = set(overrides) - {item.parameter_id for item in template.parameters}
        if unknown:
            raise PrimitiveExecutionError(
                "request mutation contains an unregistered parameter"
            )
        query: list[tuple[str, JSONScalar]] = []
        form: list[tuple[str, JSONScalar]] = []
        json_fields: dict[str, JSONScalar] = {}
        path = urlparse(template.url).path
        remove = _REMOVE
        for parameter in template.parameters:
            value: JSONScalar | tuple[JSONScalar, ...] | object = overrides.get(
                parameter.parameter_id, parameter.value
            )
            if parameter.location is ParameterLocation.path:
                marker = "{" + parameter.name + "}"
                if value is remove or isinstance(value, tuple):
                    raise PrimitiveExecutionError(
                        "path parameters cannot be removed or duplicated"
                    )
                rendered = _path_scalar(value)
                if marker in path:
                    path = path.replace(marker, rendered)
                elif parameter.parameter_id in overrides:
                    raise PrimitiveExecutionError(
                        "registered path parameter marker is unavailable"
                    )
            elif value is remove:
                continue
            elif parameter.location is ParameterLocation.query:
                values = value if isinstance(value, tuple) else (value,)
                query.extend((parameter.name, item) for item in values)
            elif parameter.location is ParameterLocation.form:
                values = value if isinstance(value, tuple) else (value,)
                form.extend((parameter.name, item) for item in values)
            elif parameter.location is ParameterLocation.json:
                if isinstance(value, tuple):
                    raise PrimitiveExecutionError(
                        "JSON parameters cannot be duplicated"
                    )
                json_fields[parameter.name] = value
            else:
                raise PrimitiveExecutionError(
                    "parameter location is not runtime executable"
                )
        parsed = urlparse(template.url)
        resolved_url = parsed._replace(path=path).geturl()
        selected_identity = None if anonymous else self.identity(identity_id)
        method = template.method.value
        return ResolvedRequest(
            template_id=template.template_id,
            target_id=template.target_id,
            surface_id=template.surface_id,
            endpoint_id=template.endpoint_id,
            method=method,
            url=resolved_url,
            timeout_seconds=template.timeout_seconds,
            headers=MappingProxyType(
                {item.name: item.value for item in template.safe_headers}
            ),
            query=tuple(query),
            json_fields=MappingProxyType(json_fields) if json_fields else None,
            form_fields=tuple(form),
            identity_id=selected_identity,
            parameter_ids=tuple(item.parameter_id for item in template.parameters),
            purpose=purpose
            or ("verification" if method in _SAFE_METHODS else "state_mutation"),
        )

    def send(self, request: ResolvedRequest) -> RequestExecutionResult:
        return self.send_registered(request)

    def evidence(
        self,
        step: CompiledPrimitiveStep,
        summary: str,
        *,
        request_template_reference: str | None = None,
        identity_references: tuple[str, ...] = (),
        object_references: tuple[str, ...] = (),
        mutation_kind: str | None = None,
        request_summaries: tuple[SafeRequestSummary, ...] = (),
        response_summaries: tuple[SafeResponseSummary, ...] = (),
        selector_results: tuple[SelectorResult, ...] = (),
        invariant_results: tuple[InvariantResult, ...] = (),
    ) -> PrimitiveExecutionEvidence:
        evidence_id = _identifier("evidence", self.experiment_id, step.step_id)
        item = PrimitiveExecutionEvidence(
            evidence_id=evidence_id,
            step_id=step.step_id,
            primitive_name=step.primitive_name,
            summary=summary,
            request_template_reference=request_template_reference,
            identity_references=identity_references,
            object_references=object_references,
            mutation_kind=mutation_kind,
            request_summaries=request_summaries,
            response_summaries=response_summaries,
            selector_results=selector_results,
            invariant_results=invariant_results,
            request_accounting_reference=self.request_accounting_reference,
            runtime_provenance_reference=self.runtime_provenance_reference,
        )
        self.produced_evidence[evidence_id] = item
        return item


class PrimitiveExecutionError(RuntimeError):
    """Secret-free failure raised by a bounded primitive implementation."""


class RequestReplayExecutor:
    route_reference = "research-native:request_replay/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, RequestReplayInput)
        template = context.template(value.request_template_id)
        overrides = {
            binding.parameter_id: context.controlled_value(
                binding.value_source_reference
            )
            for binding in value.bindings
        }
        request = context.resolve(
            template, overrides=overrides, identity_id=value.identity_id
        )
        result = context.send(request)
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Executed one registered request template.",
                request_template_reference=template.template_id,
                identity_references=(
                    (request.identity_id,) if request.identity_id else ()
                ),
                request_summaries=(result.request_summary,),
                response_summaries=(result.response_summary,),
            )
        )


class AuthenticationDifferentialExecutor:
    route_reference = "research-native:authentication_differential/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, AuthenticationDifferentialInput)
        template = context.template(value.request_template_id)
        if template.credential_header_name is None:
            raise PrimitiveExecutionError(
                "registered authentication mechanism is unavailable"
            )
        authenticated = context.resolve(template, identity_id=value.identity_id)
        anonymous = context.resolve(template, anonymous=True)
        authenticated_result = context.send(authenticated)
        anonymous_result = context.send(anonymous)
        authenticated_response = authenticated_result.response_summary
        anonymous_response = anonymous_result.response_summary
        authenticated_success = bool(
            authenticated_response.status_code in _AUTH_SUCCESS
            and authenticated_response.body_present
        )
        anonymous_denied = anonymous_response.status_code in _AUTH_DENIAL
        materially_equal = bool(
            authenticated_response.body_present
            and anonymous_response.body_present
            and authenticated_response.content_type == anonymous_response.content_type
            and authenticated_response.content_digest
            == anonymous_response.content_digest
            and authenticated_response.structural_digest
            == anonymous_response.structural_digest
            and authenticated_response.top_level_fields
            == anonymous_response.top_level_fields
        )
        if authenticated_success and anonymous_denied:
            classification = ExperimentResultClassification.secure_signal
        elif (
            authenticated_success
            and anonymous_response.status_code in _AUTH_SUCCESS
            and materially_equal
        ):
            classification = ExperimentResultClassification.vulnerable_signal
        else:
            classification = ExperimentResultClassification.inconclusive
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Compared one registered authenticated baseline with its anonymous form.",
                request_template_reference=template.template_id,
                identity_references=(value.identity_id,),
                request_summaries=(
                    authenticated_result.request_summary,
                    anonymous_result.request_summary,
                ),
                response_summaries=(
                    authenticated_response,
                    anonymous_response,
                ),
            ),
            classification=classification,
        )


class IdentitySwitchExecutor:
    route_reference = "research-native:identity_switch/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, IdentitySwitchInput)
        if not {value.primary_identity_id, value.comparison_identity_id}.issubset(
            context.identity_ids
        ):
            raise PrimitiveExecutionError("controlled identity binding is unavailable")
        context.current_identity_id = value.comparison_identity_id
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Selected a sealed controlled identity binding.",
                identity_references=(
                    value.primary_identity_id,
                    value.comparison_identity_id,
                ),
            )
        )


class ParameterMutationExecutor:
    route_reference = "research-native:parameter_mutation/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, ParameterMutationInput)
        template = context.template(value.request_template_id)
        parameter = _parameter(template, value.parameter_id)
        variants = _mutation_variants(value, parameter, context)
        requests: list[SafeRequestSummary] = []
        responses: list[SafeResponseSummary] = []
        for variant in variants[: value.maximum_variants]:
            resolved = context.resolve(
                template,
                overrides={value.parameter_id: variant},
            )
            result = context.send(resolved)
            requests.append(result.request_summary)
            responses.append(result.response_summary)
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Executed a bounded mutation of one registered parameter.",
                request_template_reference=template.template_id,
                identity_references=(
                    (context.identity(),) if context.identity() is not None else ()
                ),
                object_references=(
                    (value.controlled_object_id,)
                    if value.controlled_object_id is not None
                    else ()
                ),
                mutation_kind=value.mutation_kind.value,
                request_summaries=tuple(requests),
                response_summaries=tuple(responses),
            )
        )


class ObjectSubstitutionExecutor:
    route_reference = "research-native:object_substitution/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, ObjectSubstitutionInput)
        if value.request_template_id is None:
            raise PrimitiveExecutionError("GraphQL object substitution is compile-only")
        template = context.template(value.request_template_id)
        try:
            object_reference = context.object_references[value.controlled_object_id]
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "controlled object binding is unavailable"
            ) from exc
        owner = context.resolve(
            template,
            overrides={value.parameter_id: object_reference},
            identity_id=value.primary_identity_id,
        )
        comparison = context.resolve(
            template,
            overrides={value.parameter_id: object_reference},
            identity_id=value.comparison_identity_id,
        )
        sequence = [owner, comparison]
        if context.reproduction:
            sequence.append(comparison)
        results = [context.send(item) for item in sequence]
        owner_response, comparison_response = (
            results[0].response_summary,
            results[1].response_summary,
        )
        if (
            200 <= owner_response.status_code < 300
            and comparison_response.status_code in {401, 403, 404}
        ):
            classification = ExperimentResultClassification.secure_signal
        elif (
            200 <= owner_response.status_code < 300
            and 200 <= comparison_response.status_code < 300
        ):
            classification = ExperimentResultClassification.vulnerable_signal
        else:
            classification = ExperimentResultClassification.inconclusive
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Executed a controlled owner and non-owner authorization differential.",
                request_template_reference=template.template_id,
                identity_references=(
                    value.primary_identity_id,
                    value.comparison_identity_id,
                ),
                object_references=(value.controlled_object_id,),
                mutation_kind=MutationKind.replace_with_controlled_object_reference.value,
                request_summaries=tuple(item.request_summary for item in results),
                response_summaries=tuple(item.response_summary for item in results),
            ),
            classification=classification,
        )


class ResponseDifferentialExecutor:
    route_reference = "research-native:response_differential/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, ResponseDifferentialInput)
        left_ref, right_ref = value.references[0], value.references[1]
        left = _evidence_summary(context, left_ref.reference_id)
        right = _evidence_summary(context, right_ref.reference_id)
        left_values = {item.selector: item.value for item in left.selector_values}
        right_values = {item.selector: item.value for item in right.selector_values}
        results = []
        for selector in value.selectors:
            if (
                selector.selector not in left_values
                or selector.selector not in right_values
            ):
                raise PrimitiveExecutionError(
                    "registered differential selector is unavailable"
                )
            results.append(
                SelectorResult(
                    selector=selector.selector.value,
                    equal=left_values[selector.selector]
                    == right_values[selector.selector],
                    left_reference=left.reference,
                    right_reference=right.reference,
                )
            )
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Compared registered response evidence with deterministic selectors.",
                selector_results=tuple(results),
            )
        )


class StateDifferentialExecutor:
    route_reference = "research-native:state_differential/v1"

    def execute(
        self, step: CompiledPrimitiveStep, context: PrimitiveExecutorContext
    ) -> ExecutorStepResult:
        value = _input(step, StateDifferentialInput)
        try:
            before = context.state_snapshots[value.before_state_reference]
            after = context.state_snapshots[value.after_state_reference]
            cleanup = (
                context.state_snapshots[value.cleanup_state_reference]
                if value.cleanup_state_reference is not None
                else None
            )
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "registered state reference is unavailable"
            ) from exc
        available: dict[str, bool] = {}
        for snapshot in (before, after, cleanup):
            if snapshot is not None:
                available.update(
                    {
                        item.invariant_reference: item.satisfied
                        for item in snapshot.invariants
                    }
                )
        results = []
        for reference in value.invariant_references:
            if reference not in available:
                raise PrimitiveExecutionError(
                    "registered state invariant is unavailable"
                )
            results.append(
                InvariantResult(
                    invariant_reference=reference,
                    satisfied=available[reference],
                )
            )
        return ExecutorStepResult(
            evidence=context.evidence(
                step,
                "Compared sealed state references and registered invariants.",
                invariant_results=tuple(results),
            )
        )


class PrimitiveExecutorRegistry:
    """Immutable route table for the native P4-0D primitive executors."""

    __slots__ = ("__executors",)

    def __init__(self, executors: Iterable[PrimitiveExecutor] = ()) -> None:
        selected = tuple(executors) or (
            AuthenticationDifferentialExecutor(),
            RequestReplayExecutor(),
            IdentitySwitchExecutor(),
            ParameterMutationExecutor(),
            ObjectSubstitutionExecutor(),
            ResponseDifferentialExecutor(),
            StateDifferentialExecutor(),
        )
        routes: dict[str, PrimitiveExecutor] = {}
        for executor in selected:
            route = executor.route_reference
            if route in routes:
                raise ValueError("duplicate primitive executor route")
            routes[route] = executor
        object.__setattr__(self, "_PrimitiveExecutorRegistry__executors", routes)

    def resolve(self, route_reference: str) -> PrimitiveExecutor:
        try:
            return self.__executors[route_reference]
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "primitive executor route is unavailable"
            ) from exc

    @property
    def routes(self) -> tuple[str, ...]:
        return tuple(sorted(self.__executors))

    @property
    def fingerprint(self) -> str:
        return _digest(self.routes)


DEFAULT_PRIMITIVE_EXECUTOR_REGISTRY = PrimitiveExecutorRegistry()


_REMOVE = object()


def _parameter(
    template: RegisteredRuntimeRequestTemplate, parameter_id: str
) -> RegisteredRequestParameter:
    match = next(
        (item for item in template.parameters if item.parameter_id == parameter_id),
        None,
    )
    if match is None:
        raise PrimitiveExecutionError("registered parameter is unavailable")
    return match


def _mutation_variants(
    value: ParameterMutationInput,
    parameter: RegisteredRequestParameter,
    context: PrimitiveExecutorContext,
) -> tuple[JSONScalar | tuple[JSONScalar, ...] | object, ...]:
    kind = value.mutation_kind
    if kind in {
        MutationKind.replace_with_controlled_value,
        MutationKind.boundary_value,
        MutationKind.harmless_canary,
    }:
        assert value.value_source_reference is not None
        return (context.controlled_value(value.value_source_reference),)
    if kind is MutationKind.replace_with_controlled_object_reference:
        assert value.controlled_object_id is not None
        try:
            return (context.object_references[value.controlled_object_id],)
        except KeyError as exc:
            raise PrimitiveExecutionError(
                "controlled object binding is unavailable"
            ) from exc
    if kind is MutationKind.remove_parameter:
        return (_REMOVE,)
    if kind is MutationKind.duplicate_parameter:
        if parameter.location not in {ParameterLocation.query, ParameterLocation.form}:
            raise PrimitiveExecutionError("parameter location cannot be duplicated")
        return ((parameter.value, parameter.value),)
    if kind is MutationKind.change_scalar_type:
        candidates: tuple[JSONScalar, ...]
        if isinstance(parameter.value, bool):
            candidates = (0, "false", 0.0)
        elif isinstance(parameter.value, (int, float)):
            candidates = (str(parameter.value), False, "0")
        else:
            candidates = (0, False, 0.0)
        return candidates
    raise PrimitiveExecutionError("mutation kind is unavailable")


def _path_scalar(value: JSONScalar) -> str:
    if value is None or isinstance(value, (dict, list, tuple)):
        raise PrimitiveExecutionError("path parameter requires a scalar")
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    if not rendered or not _ROUTE.fullmatch(rendered) or "/" in rendered:
        raise PrimitiveExecutionError(
            "path parameter is outside the safe scalar grammar"
        )
    return rendered


def _evidence_summary(
    context: PrimitiveExecutorContext, reference: str
) -> RegisteredEvidenceSummary:
    try:
        return context.evidence_summaries[reference]
    except KeyError as exc:
        raise PrimitiveExecutionError(
            "registered evidence summary is unavailable"
        ) from exc


def _input(step: CompiledPrimitiveStep, expected: type[Any]) -> Any:
    if not isinstance(step.input, expected):
        raise PrimitiveExecutionError("primitive executor input type is invalid")
    return step.input


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _identifier(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(item) for item in parts)
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


__all__ = [
    "DEFAULT_PRIMITIVE_EXECUTOR_REGISTRY",
    "ExecutorStepResult",
    "PrimitiveExecutionError",
    "PrimitiveExecutorContext",
    "PrimitiveExecutorRegistry",
    "RESEARCH_EXECUTOR_REGISTRY_VERSION",
    "RegisteredControlledValue",
    "RegisteredCleanupExecution",
    "RegisteredEvidenceSummary",
    "RegisteredInvariantValue",
    "RegisteredRequestParameter",
    "RegisteredRuntimeRequestTemplate",
    "RegisteredSafeRequestHeader",
    "RegisteredSelectorValue",
    "RegisteredStateSnapshot",
    "RequestExecutionResult",
    "ResolvedRequest",
    "RuntimeRequestTemplate",
]
