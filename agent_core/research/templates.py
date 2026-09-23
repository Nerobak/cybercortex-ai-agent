"""Persistent request-template creation and compiler/runtime adaptation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from urllib.parse import urljoin, urlparse

from agent_core.capture_ingest import CapturedRequest
from agent_core.policy import AssessmentPolicy
from agent_core.research.adapters import (
    opaque_reference,
    stable_research_identifier,
)
from agent_core.research.compiler import RegisteredRequestTemplate
from agent_core.research.executors import (
    RegisteredRequestParameter,
    RegisteredRuntimeRequestTemplate,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import (
    Endpoint,
    RequestIdentityRequirement,
    ResearchRequestTemplate,
    ResearchState,
)
from agent_core.research.types import HttpMethod, ParameterLocation

TEMPLATE_FACTORY_VERSION = "phase4-request-template-factory-v1"
_CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
)


class RequestTemplateFactory:
    """Build secret-free registrations from existing capture/discovery records."""

    def from_capture(
        self,
        request: CapturedRequest,
        state: ResearchState,
        *,
        target_id: str,
        policy: AssessmentPolicy,
    ) -> ResearchRequestTemplate:
        endpoint = self._capture_endpoint(request, state, target_id)
        parameter_ids = self._parameter_ids(endpoint, state)
        header_names = {
            str(name).strip().casefold().replace("_", "-") for name in request.headers
        }
        mechanisms = []
        if "authorization" in header_names or "proxy-authorization" in header_names:
            mechanisms.append("authorization_header")
        if "cookie" in header_names:
            mechanisms.append("cookie")
        identity_required = bool(request.identity_id or mechanisms)
        captured_identity = (
            next(
                (
                    item
                    for item in state.identities
                    if item.account_reference
                    == opaque_reference(request.identity_id, "account")
                ),
                None,
            )
            if request.identity_id
            else None
        )
        content_type = _safe_content_type(request.headers)
        capture_reference = opaque_reference(request.request_id, "capture")
        body_shape_reference = _body_shape_reference(request)
        template = ResearchRequestTemplate(
            template_id=stable_research_identifier(
                "request-template", target_id, endpoint.endpoint_id
            ),
            target_id=target_id,
            surface_id=endpoint.surface_id,
            endpoint_id=endpoint.endpoint_id,
            method=endpoint.method,
            route_reference=endpoint.route_template,
            parameter_ids=parameter_ids,
            body_shape_reference=body_shape_reference,
            content_type=content_type,
            identity_requirement=RequestIdentityRequirement(
                required=identity_required,
                mechanisms=tuple(mechanisms),
                role_reference=(
                    captured_identity.role_reference if captured_identity else None
                ),
                tenant_bound=bool(
                    captured_identity and captured_identity.tenant_reference
                ),
            ),
            source_capture_references=(capture_reference,),
            evidence_references=endpoint.evidence_references,
            provenance_id=endpoint.provenance_id,
        )
        self.validate(template, state, policy=policy)
        return template

    def from_endpoint(
        self,
        endpoint: Endpoint,
        state: ResearchState,
        *,
        policy: AssessmentPolicy,
        identity_required: bool = False,
    ) -> ResearchRequestTemplate:
        template = ResearchRequestTemplate(
            template_id=stable_research_identifier(
                "request-template", endpoint.target_id, endpoint.endpoint_id
            ),
            target_id=endpoint.target_id,
            surface_id=endpoint.surface_id,
            endpoint_id=endpoint.endpoint_id,
            method=endpoint.method,
            route_reference=endpoint.route_template,
            parameter_ids=self._parameter_ids(endpoint, state),
            body_shape_reference=_state_body_shape_reference(endpoint, state),
            content_type=(
                endpoint.content_types[0] if endpoint.content_types else None
            ),
            identity_requirement=RequestIdentityRequirement(required=identity_required),
            evidence_references=endpoint.evidence_references,
            provenance_id=endpoint.provenance_id,
        )
        self.validate(template, state, policy=policy)
        return template

    def build_all(
        self,
        state: ResearchState,
        *,
        target_id: str,
        policy: AssessmentPolicy,
        captures: Sequence[CapturedRequest] = (),
        max_templates: int,
    ) -> tuple[ResearchRequestTemplate, ...]:
        captures_by_key = {
            (request.method.upper(), request.path): request for request in captures
        }
        auth_evidence = {
            reference
            for item in state.observations
            if item.observation_type == "authentication_boundary_candidate"
            for reference in item.evidence_references
        }
        existing_endpoint_ids = {
            item.endpoint_id
            for item in state.request_templates
            if item.target_id == target_id
        }
        remaining = max(
            0,
            max_templates
            - sum(1 for item in state.request_templates if item.target_id == target_id),
        )
        output = []
        for endpoint in sorted(
            (item for item in state.endpoints if item.target_id == target_id),
            key=lambda item: item.endpoint_id,
        ):
            if len(output) >= remaining:
                break
            if endpoint.endpoint_id in existing_endpoint_ids:
                continue
            capture = captures_by_key.get(
                (endpoint.method.value, endpoint.route_template)
            )
            try:
                if capture is not None:
                    template = self.from_capture(
                        capture, state, target_id=target_id, policy=policy
                    )
                else:
                    template = self.from_endpoint(
                        endpoint,
                        state,
                        policy=policy,
                        identity_required=bool(
                            auth_evidence.intersection(endpoint.evidence_references)
                        ),
                    )
            except ValueError:
                continue
            output.append(template)
        return tuple(output)

    @staticmethod
    def apply(
        state: ResearchState, templates: Sequence[ResearchRequestTemplate]
    ) -> ResearchState:
        existing = {item.template_id: item for item in state.request_templates}
        for item in templates:
            existing.setdefault(item.template_id, item)
        return ResearchState.model_validate(
            {
                **state.model_dump(mode="python"),
                "request_templates": tuple(existing[key] for key in sorted(existing)),
            }
        )

    @staticmethod
    def validate(
        template: ResearchRequestTemplate,
        state: ResearchState,
        *,
        policy: AssessmentPolicy,
    ) -> None:
        reject_secret_material(
            template.model_dump(mode="json"), location="research request template"
        )
        target = next(
            (item for item in state.targets if item.target_id == template.target_id),
            None,
        )
        surface = next(
            (item for item in state.surfaces if item.surface_id == template.surface_id),
            None,
        )
        endpoint = next(
            (
                item
                for item in state.endpoints
                if item.endpoint_id == template.endpoint_id
            ),
            None,
        )
        if target is None or surface is None or endpoint is None:
            raise ValueError(
                "request template references an unregistered target surface"
            )
        if (
            surface.target_id != target.target_id
            or endpoint.target_id != target.target_id
            or endpoint.surface_id != surface.surface_id
            or endpoint.method is not template.method
            or endpoint.route_template != template.route_reference
        ):
            raise ValueError(
                "request template target and endpoint relationships mismatch"
            )
        endpoint_parameters = {
            item.parameter_id
            for item in state.parameters
            if item.endpoint_id == endpoint.endpoint_id
        }
        if not set(template.parameter_ids).issubset(endpoint_parameters):
            raise ValueError("request template contains a foreign parameter")
        if not template.evidence_references or not set(
            template.evidence_references
        ).issubset({item.evidence_id for item in state.evidence}):
            raise ValueError("request template capture/discovery provenance is absent")
        if template.source_capture_references and not set(
            template.source_capture_references
        ).issubset({item.source_reference for item in state.evidence}):
            raise ValueError("request template capture provenance is absent")
        url = _runtime_url(target.canonical_reference, endpoint.route_template)
        decision = policy.authorize_url(url, method=endpoint.method.value)
        if not decision.allowed:
            raise ValueError("request template is outside current policy scope")
        if any(
            value not in {"authorization_header", "cookie"}
            for value in template.identity_requirement.mechanisms
        ):
            raise ValueError("identity requirements must remain structural")

    @staticmethod
    def to_compiler_template(
        template: ResearchRequestTemplate,
    ) -> RegisteredRequestTemplate:
        return RegisteredRequestTemplate(
            template_id=template.template_id,
            target_id=template.target_id,
            surface_id=template.surface_id,
            endpoint_id=template.endpoint_id,
            parameter_ids=template.parameter_ids,
        )

    @staticmethod
    def to_runtime_template(
        template: ResearchRequestTemplate,
        state: ResearchState,
        *,
        timeout_seconds: int = 10,
    ) -> RegisteredRuntimeRequestTemplate:
        target = next(
            item for item in state.targets if item.target_id == template.target_id
        )
        parameters = {
            item.parameter_id: item
            for item in state.parameters
            if item.endpoint_id == template.endpoint_id
        }
        mechanisms = set(template.identity_requirement.mechanisms)
        credential_header_name = (
            "Authorization"
            if "authorization_header" in mechanisms
            else ("Cookie" if "cookie" in mechanisms else None)
        )
        runtime = RegisteredRuntimeRequestTemplate(
            template_id=template.template_id,
            target_id=template.target_id,
            surface_id=template.surface_id,
            endpoint_id=template.endpoint_id,
            method=template.method,
            url=_runtime_url(target.canonical_reference, template.route_reference),
            parameters=tuple(
                RegisteredRequestParameter(
                    parameter_id=parameter_id,
                    name=parameters[parameter_id].name,
                    location=parameters[parameter_id].location,
                )
                for parameter_id in template.parameter_ids
            ),
            safe_headers=(),
            credential_header_name=credential_header_name,
            timeout_seconds=timeout_seconds,
        )
        reject_secret_material(
            runtime.model_dump(mode="json"), location="runtime request template"
        )
        return runtime

    @staticmethod
    def compiler_templates(
        state: ResearchState,
    ) -> tuple[RegisteredRequestTemplate, ...]:
        return tuple(
            RequestTemplateFactory.to_compiler_template(item)
            for item in state.request_templates
        )

    @staticmethod
    def runtime_templates(
        state: ResearchState,
    ) -> tuple[RegisteredRuntimeRequestTemplate, ...]:
        return tuple(
            RequestTemplateFactory.to_runtime_template(item, state)
            for item in state.request_templates
        )

    @staticmethod
    def _capture_endpoint(
        request: CapturedRequest, state: ResearchState, target_id: str
    ) -> Endpoint:
        try:
            method = HttpMethod(request.method.upper())
        except ValueError as exc:
            raise ValueError("capture method is unsupported") from exc
        matches = [
            item
            for item in state.endpoints
            if item.target_id == target_id
            and item.method is method
            and item.route_template == request.path
        ]
        if len(matches) != 1:
            raise ValueError("capture does not resolve to one registered endpoint")
        return matches[0]

    @staticmethod
    def _parameter_ids(endpoint: Endpoint, state: ResearchState) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.parameter_id
                for item in state.parameters
                if item.endpoint_id == endpoint.endpoint_id
            )
        )


def _safe_content_type(headers: dict[str, str]) -> str | None:
    value = next(
        (
            str(item).split(";", 1)[0].strip().lower()
            for name, item in headers.items()
            if str(name).casefold() == "content-type"
        ),
        "",
    )
    if not value:
        return None
    try:
        reject_secret_material(value, location="captured content type")
    except ValueError:
        return None
    return opaque_reference(value, "content-type")


def _body_shape_reference(request: CapturedRequest) -> str | None:
    body_parameters = sorted(
        (item.location, item.name, item.value_type, item.required)
        for item in request.parameters
        if item.location
        in {
            "json",
            "form",
            "multipart",
            "graphql_variable",
            "graphql_argument",
        }
    )
    if not body_parameters and not request.body_type:
        return None
    encoded = json.dumps(
        {"body_type": request.body_type, "parameters": body_parameters},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "body-shape-" + hashlib.sha256(encoded).hexdigest()[:24]


def _state_body_shape_reference(endpoint: Endpoint, state: ResearchState) -> str | None:
    body_parameters = sorted(
        (item.location.value, item.name, item.data_type, item.required)
        for item in state.parameters
        if item.endpoint_id == endpoint.endpoint_id
        and item.location
        in {
            ParameterLocation.json,
            ParameterLocation.form,
            ParameterLocation.graphql_variable,
        }
    )
    if not body_parameters:
        return None
    encoded = json.dumps(
        body_parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "body-shape-" + hashlib.sha256(encoded).hexdigest()[:24]


def _runtime_url(target_reference: str, route_reference: str) -> str:
    parsed = urlparse(target_reference)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("registered target does not provide a safe HTTP origin")
    origin = parsed._replace(path="/", params="", query="", fragment="").geturl()
    route = "/" + route_reference.lstrip("/")
    return urljoin(origin, route)


__all__ = [
    "RequestTemplateFactory",
    "TEMPLATE_FACTORY_VERSION",
]
