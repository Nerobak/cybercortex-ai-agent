"""Bounded owner-scoped discovery for controlled Phase 4 accounts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from agent_core.controlled_context import ControlledContext, ControlledObject
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy
from agent_core.research.adapters import stable_research_identifier
from agent_core.research.state import Endpoint, Parameter, ResearchState, TargetAsset
from agent_core.research.types import HttpMethod, ParameterLocation
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

AUTHENTICATED_DISCOVERY_VERSION = "phase4-controlled-discovery-v1"
_PATH_MARKER = re.compile(r"\{[^{}]+\}")
_SCALAR_TYPES = (str, int)


@dataclass(frozen=True, slots=True)
class AuthenticatedDiscoveryResult:
    objects: tuple[ControlledObject, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _ObjectRelationship:
    collection_endpoint: Endpoint
    detail_endpoint: Endpoint
    parameter: Parameter
    object_type: str


class ControlledAccountDiscoveryAdapter:
    """Observe only known read-only endpoints as explicitly controlled owners."""

    def __init__(
        self,
        transport: ScopedHTTPClient,
        *,
        maximum_endpoints_per_account: int = 5,
        maximum_objects_per_account: int = 20,
        timeout_seconds: int = 10,
    ) -> None:
        if not 1 <= maximum_endpoints_per_account <= 20:
            raise ValueError("authenticated discovery endpoint limit is invalid")
        if not 1 <= maximum_objects_per_account <= 20:
            raise ValueError("authenticated discovery object limit is invalid")
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("authenticated discovery timeout is invalid")
        self.transport = transport
        self.maximum_endpoints_per_account = maximum_endpoints_per_account
        self.maximum_objects_per_account = maximum_objects_per_account
        self.timeout_seconds = timeout_seconds

    def discover(
        self,
        state: ResearchState,
        *,
        target: TargetAsset,
        context: ControlledContext,
        policy: AssessmentPolicy,
        vault: CredentialVault,
        maximum_requests: int,
    ) -> AuthenticatedDiscoveryResult:
        if maximum_requests < 0:
            raise ValueError("authenticated discovery request limit is invalid")
        relationships = _object_relationships(state, target.target_id)
        endpoints = _eligible_endpoints(state, target.target_id)
        limitations: list[str] = []
        objects: list[ControlledObject] = []
        seen: set[tuple[str, str, str]] = set()
        requests_sent = 0

        for account in sorted(context.accounts, key=lambda item: item.account_id):
            eligibility = policy.account_is_eligible(
                account.account_id,
                context,
                account_controlled=account.controlled,
            )
            if not eligibility.eligible:
                continue
            credential_reference = (
                account.session_reference or account.credential_references.get("token")
            )
            if credential_reference is None:
                limitations.append("controlled_account_credential_unavailable")
                continue
            try:
                raw_credential = vault.get(credential_reference)
            except (KeyError, RuntimeError):
                limitations.append("controlled_account_credential_unavailable")
                continue
            credential = _authorization_value(raw_credential)

            account_count = 0
            for endpoint in endpoints[: self.maximum_endpoints_per_account]:
                if requests_sent >= maximum_requests:
                    limitations.append("authenticated_discovery_request_limit_reached")
                    break
                url = _endpoint_url(target.canonical_reference, endpoint.route_template)
                try:
                    requests_sent += 1
                    response, _ = self.transport.request(
                        "GET",
                        url,
                        timeout=self.timeout_seconds,
                        follow_redirects=False,
                        max_redirects=0,
                        headers={"Authorization": credential},
                        purpose="owned_object_acquisition",
                        allow_session_credentials=True,
                        isolate_session_cookies=True,
                    )
                except (PolicyViolationError, OSError, RuntimeError):
                    limitations.append("authenticated_discovery_request_failed")
                    continue
                status = getattr(response, "status_code", None)
                if type(status) is not int or not 200 <= status < 300:
                    limitations.append("authenticated_discovery_response_ineligible")
                    continue
                body = _response_json(response)
                if body is None:
                    continue
                for relationship in relationships:
                    if (
                        relationship.collection_endpoint.endpoint_id
                        != endpoint.endpoint_id
                    ):
                        continue
                    for identifier in _identifiers(body, relationship):
                        key = (account.account_id, relationship.object_type, identifier)
                        if key in seen:
                            continue
                        seen.add(key)
                        objects.append(
                            ControlledObject(
                                object_id=identifier,
                                owner_account_id=account.account_id,
                                tenant_id=account.tenant_id,
                                object_type=relationship.object_type,
                                test_owned=True,
                                parameter_ids=(relationship.parameter.parameter_id,),
                                ownership_basis="owner_scoped_authenticated_collection",
                                source_reference=stable_research_identifier(
                                    "authenticated-object-source",
                                    state.research_id,
                                    account.account_id,
                                    endpoint.endpoint_id,
                                    relationship.parameter.parameter_id,
                                    identifier,
                                ),
                            )
                        )
                        account_count += 1
                        if account_count >= self.maximum_objects_per_account:
                            break
                    if account_count >= self.maximum_objects_per_account:
                        break
                if account_count >= self.maximum_objects_per_account:
                    break
            if requests_sent >= maximum_requests:
                break

        supported = _identity_bound_owned_objects(objects)
        if objects and len(supported) != len(objects):
            limitations.append("controlled_object_ownership_evidence_insufficient")
        return AuthenticatedDiscoveryResult(
            objects=supported,
            limitations=tuple(sorted(set(limitations))),
        )


def _eligible_endpoints(state: ResearchState, target_id: str) -> tuple[Endpoint, ...]:
    auth_evidence = {
        reference
        for observation in state.observations
        if observation.observation_type == "authentication_boundary_candidate"
        for reference in observation.evidence_references
    }
    parameters_by_endpoint: dict[str, list[Parameter]] = {}
    for parameter in state.parameters:
        parameters_by_endpoint.setdefault(parameter.endpoint_id, []).append(parameter)
    output = []
    for endpoint in state.endpoints:
        if endpoint.target_id != target_id or endpoint.method is not HttpMethod.get:
            continue
        parameters = parameters_by_endpoint.get(endpoint.endpoint_id, [])
        if any(item.location is ParameterLocation.path for item in parameters):
            continue
        if any(
            item.required
            and item.location
            in {
                ParameterLocation.query,
                ParameterLocation.form,
                ParameterLocation.json,
            }
            for item in parameters
        ):
            continue
        has_authorization_header = any(
            item.location is ParameterLocation.header
            and str(item.name).strip().casefold().replace("_", "-") == "authorization"
            for item in parameters
        )
        authorization_required = any(
            item.location is ParameterLocation.header
            and str(item.name).strip().casefold().replace("_", "-") == "authorization"
            and item.required is True
            for item in parameters
        )
        if not has_authorization_header or not (
            authorization_required
            or auth_evidence.intersection(endpoint.evidence_references)
        ):
            continue
        if _PATH_MARKER.search(endpoint.route_template):
            continue
        output.append(endpoint)
    return tuple(sorted(output, key=lambda item: item.endpoint_id))


def _object_relationships(
    state: ResearchState, target_id: str
) -> tuple[_ObjectRelationship, ...]:
    endpoints = {
        (item.surface_id, item.route_template.rstrip("/")): item
        for item in state.endpoints
        if item.target_id == target_id and item.method is HttpMethod.get
    }
    output = []
    for parameter in state.parameters:
        if parameter.location not in {ParameterLocation.path, ParameterLocation.query}:
            continue
        detail = next(
            (
                item
                for item in state.endpoints
                if item.endpoint_id == parameter.endpoint_id
                and item.target_id == target_id
                and item.method is HttpMethod.get
            ),
            None,
        )
        if detail is None or parameter.location is not ParameterLocation.path:
            continue
        marker = "/{" + str(parameter.name) + "}"
        if not detail.route_template.rstrip("/").endswith(marker):
            continue
        base_route = detail.route_template.rstrip("/")[: -len(marker)] or "/"
        collection = endpoints.get((detail.surface_id, base_route))
        if collection is None or collection.endpoint_id == detail.endpoint_id:
            continue
        output.append(
            _ObjectRelationship(
                collection_endpoint=collection,
                detail_endpoint=detail,
                parameter=parameter,
                object_type=_object_type(parameter.name, base_route),
            )
        )
    return tuple(sorted(output, key=lambda item: item.parameter.parameter_id))


def _object_type(parameter_name: str, collection_route: str) -> str:
    normalized = _normalized_identifier(parameter_name)
    for suffix in ("_identifier", "_id"):
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            return normalized[: -len(suffix)]
    if normalized not in {"id", "identifier"}:
        return normalized
    segment = collection_route.rstrip("/").rsplit("/", 1)[-1]
    segment = _normalized_identifier(segment)
    return segment[:-1] if segment.endswith("s") and len(segment) > 1 else segment


def _identifiers(body: object, relationship: _ObjectRelationship) -> tuple[str, ...]:
    items: list[dict[str, object]] = []
    if isinstance(body, list):
        items.extend(item for item in body[:20] if isinstance(item, dict))
    elif isinstance(body, dict):
        items.append(body)
        for value in body.values():
            if isinstance(value, list):
                items.extend(item for item in value[:20] if isinstance(item, dict))

    parameter_name = _normalized_identifier(relationship.parameter.name)
    object_type = _normalized_identifier(relationship.object_type)
    allowed_names = {parameter_name, "id", f"{object_type}_id"}
    output = []
    for item in items[:20]:
        matches = [
            value
            for name, value in item.items()
            if _normalized_identifier(str(name)) in allowed_names
            and type(value) in _SCALAR_TYPES
        ]
        if len(matches) != 1:
            continue
        identifier = str(matches[0]).strip()
        if identifier and len(identifier) <= 500:
            output.append(identifier)
    return tuple(dict.fromkeys(output))


def _response_json(response: object) -> object | None:
    content = getattr(response, "content", b"")
    if isinstance(content, str):
        raw = content
    elif isinstance(content, bytes):
        try:
            raw = content.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _endpoint_url(base: str, route: str) -> str:
    parsed = urlparse(base)
    origin = parsed._replace(path="/", params="", query="", fragment="").geturl()
    return urljoin(origin, "/" + route.lstrip("/"))


def _normalized_identifier(value: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value).strip())
    return re.sub(r"[^a-z0-9]+", "_", separated.casefold()).strip("_")


def _authorization_value(value: str) -> str:
    return value if len(value.split(None, 1)) == 2 else f"Bearer {value}"


def _identity_bound_owned_objects(
    candidates: list[ControlledObject],
) -> tuple[ControlledObject, ...]:
    """Require account-specific, disjoint collection results before ownership."""

    groups: dict[tuple[str, tuple[str, ...]], dict[str, set[str]]] = {}
    for item in candidates:
        key = (item.object_type, item.parameter_ids)
        groups.setdefault(key, {}).setdefault(item.owner_account_id, set()).add(
            item.object_id
        )
    supported_groups = set()
    for key, by_account in groups.items():
        if len(by_account) < 2 or any(not values for values in by_account.values()):
            continue
        seen: set[str] = set()
        disjoint = True
        for values in by_account.values():
            if seen.intersection(values):
                disjoint = False
                break
            seen.update(values)
        if disjoint:
            supported_groups.add(key)
    return tuple(
        item
        for item in candidates
        if (item.object_type, item.parameter_ids) in supported_groups
    )


__all__ = [
    "AUTHENTICATED_DISCOVERY_VERSION",
    "AuthenticatedDiscoveryResult",
    "ControlledAccountDiscoveryAdapter",
]
