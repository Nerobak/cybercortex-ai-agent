"""Secret-safe adapters from existing Phase 1-3 discovery into Phase 4 state."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from pydantic import Field

from agent_core.agent_models import Hypothesis
from agent_core.attack_surface import CanonicalAttackSurface
from agent_core.controlled_context import ControlledContext, ControlledObject
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy
from agent_core.research.evaluation import (
    HypothesisProposalSource,
    NewHypothesisProposal,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import (
    Endpoint,
    EvidenceArtifact,
    Fact,
    GraphQLOperation,
    HypothesisRecord,
    Identity,
    Observation,
    Parameter,
    ProvenanceRecord,
    ResearchObject,
    ResearchState,
    SessionRef,
    Surface,
    TokenRef,
    Workflow,
    WorkflowStep,
)
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    EntityReference,
    EvidenceKind,
    FactStatus,
    GraphQLOperationType,
    HttpMethod,
    HypothesisResearchStatus,
    IdentityEligibility,
    ParameterLocation,
    ProvenanceProducerType,
    ReferenceFactObject,
    ResearchConfidence,
    ResearchContract,
    ResearchPredicate,
    SessionLifecycle,
    SurfaceType,
    TokenKind,
    TokenLifecycle,
)
from agent_core.result_normalizer import sanitize_document_text

ADAPTER_VERSION = "phase4-bootstrap-adapters-v1"


def stable_research_identifier(prefix: str, *parts: object) -> str:
    encoded = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-" + hashlib.sha256(encoded).hexdigest()[:24]


def opaque_reference(value: object, prefix: str) -> str:
    rendered = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", rendered):
        try:
            reject_secret_material(rendered, location="bootstrap reference")
        except ValueError:
            pass
        else:
            return rendered
    return stable_research_identifier(prefix, rendered)


def public_text(value: object, fallback: str, *, limit: int = 1_000) -> str:
    rendered = sanitize_document_text(str(value or "").strip())[:limit]
    return rendered or fallback


def digest_for(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _timestamp(value: str | None = None) -> str:
    return value or datetime.now(timezone.utc).isoformat()


def _merge(existing: Sequence[Any], new: Iterable[Any], field: str) -> tuple[Any, ...]:
    values = {getattr(item, field): item for item in existing}
    for item in new:
        values.setdefault(getattr(item, field), item)
    return tuple(values[key] for key in sorted(values))


class AttackSurfaceResearchRecords(ResearchContract):
    surfaces: tuple[Surface, ...] = Field(default=(), max_length=20)
    endpoints: tuple[Endpoint, ...] = Field(default=(), max_length=5_000)
    parameters: tuple[Parameter, ...] = Field(default=(), max_length=10_000)
    objects: tuple[ResearchObject, ...] = Field(default=(), max_length=5_000)
    graphql_operations: tuple[GraphQLOperation, ...] = Field(
        default=(), max_length=5_000
    )
    workflows: tuple[Workflow, ...] = Field(default=(), max_length=2_000)
    observations: tuple[Observation, ...] = Field(default=(), max_length=20_000)
    evidence: tuple[EvidenceArtifact, ...] = Field(default=(), max_length=20_000)
    facts: tuple[Fact, ...] = Field(default=(), max_length=20_000)
    provenance: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=100)


class ControlledContextResearchRecords(ResearchContract):
    identities: tuple[Identity, ...] = Field(default=(), max_length=200)
    session_refs: tuple[SessionRef, ...] = Field(default=(), max_length=1_000)
    token_refs: tuple[TokenRef, ...] = Field(default=(), max_length=1_000)
    objects: tuple[ResearchObject, ...] = Field(default=(), max_length=5_000)
    evidence: tuple[EvidenceArtifact, ...] = Field(default=(), max_length=5_000)
    provenance: tuple[ProvenanceRecord, ...] = Field(default=(), max_length=100)
    limitations: tuple[str, ...] = Field(default=(), max_length=100)


class AttackSurfaceResearchAdapter:
    """Map the existing canonical attack surface into immutable Phase 4 records."""

    def adapt(
        self,
        surface: CanonicalAttackSurface,
        state: ResearchState,
        *,
        target_id: str,
        max_endpoints: int,
        max_parameters: int,
        occurred_at: str | None = None,
    ) -> AttackSurfaceResearchRecords:
        target = next(
            (item for item in state.targets if item.target_id == target_id), None
        )
        if target is None:
            raise ValueError("bootstrap target is not registered")
        timestamp = _timestamp(occurred_at)
        provenance_id = stable_research_identifier(
            "provenance", state.research_id, target_id, "attack-surface-import"
        )
        provenance = ProvenanceRecord(
            provenance_id=provenance_id,
            producer_type=ProvenanceProducerType.imported,
            producer_name="attack-surface-research-adapter",
            producer_version=ADAPTER_VERSION,
            source_references=tuple(
                sorted(
                    {
                        opaque_reference(
                            item.reference or item.source, "surface-source"
                        )
                        for item in surface.evidence_sources[:100]
                    }
                )
            ),
            summary="Imported a bounded canonical discovery surface.",
            occurred_at=timestamp,
        )
        surface_id = stable_research_identifier(
            "surface", target_id, "canonical-http-surface"
        )
        surface_record = Surface(
            surface_id=surface_id,
            target_id=target_id,
            surface_type=(
                SurfaceType.graphql
                if surface.graphql and not surface.routes
                else SurfaceType.rest
            ),
            label="Canonical discovered application surface.",
            provenance_id=provenance_id,
        )

        evidence: list[EvidenceArtifact] = []
        endpoints: list[Endpoint] = []
        observations: list[Observation] = []
        facts: list[Fact] = []
        endpoint_by_key: dict[tuple[str, str], Endpoint] = {}
        route_evidence: dict[tuple[str, str], str] = {}
        for route in surface.routes[:max_endpoints]:
            method_value = str(route.get("method") or "GET").upper()
            path = str(route.get("path") or "/")
            try:
                method = HttpMethod(method_value)
            except ValueError:
                continue
            endpoint_id = stable_research_identifier(
                "endpoint", target_id, method.value, path
            )
            evidence_id = stable_research_identifier(
                "evidence", endpoint_id, "discovery"
            )
            source = next(
                (
                    opaque_reference(item, "capture")
                    for item in route.get("evidence_refs", [])
                    if item
                ),
                opaque_reference(route.get("source") or "canonical-surface", "source"),
            )
            structural = {
                "method": method.value,
                "path": path,
                "content_types": sorted(
                    str(item)
                    for item in (
                        route.get("content_types")
                        or (
                            [route.get("content_type")]
                            if route.get("content_type")
                            else []
                        )
                    )
                    if item
                ),
            }
            evidence.append(
                EvidenceArtifact(
                    evidence_id=evidence_id,
                    evidence_kind=EvidenceKind.schema,
                    digest=digest_for(structural),
                    summary=f"Observed {method.value} route {public_text(path, '/')}",
                    source_reference=source,
                    observed_at=timestamp,
                    provenance_id=provenance_id,
                )
            )
            content_types = tuple(
                opaque_reference(item, "content-type")
                for item in structural["content_types"][:30]
            )
            endpoint = Endpoint(
                endpoint_id=endpoint_id,
                target_id=target_id,
                surface_id=surface_id,
                method=method,
                route_template=public_text(path, "/", limit=2_048),
                content_types=content_types,
                evidence_references=(evidence_id,),
                provenance_id=provenance_id,
            )
            endpoints.append(endpoint)
            key = (method.value, path)
            endpoint_by_key[key] = endpoint
            route_evidence[key] = evidence_id
            observations.append(
                Observation(
                    observation_id=stable_research_identifier(
                        "observation", endpoint_id, "route"
                    ),
                    observation_type="discovered_endpoint",
                    summary=f"Discovery observed {method.value} {public_text(path, '/')}.",
                    target_id=target_id,
                    surface_id=surface_id,
                    evidence_references=(evidence_id,),
                    provenance_id=provenance_id,
                )
            )
            facts.append(
                Fact(
                    fact_id=stable_research_identifier(
                        "fact", endpoint_id, "part-of", surface_id
                    ),
                    subject=EntityReference(
                        entity_kind=EntityKind.endpoint, entity_id=endpoint_id
                    ),
                    predicate=ResearchPredicate.part_of,
                    object=ReferenceFactObject(
                        reference=EntityReference(
                            entity_kind=EntityKind.surface, entity_id=surface_id
                        )
                    ),
                    status=FactStatus.observed,
                    evidence_references=(evidence_id,),
                    derivation_type=DerivationType.deterministic,
                    provenance_id=provenance_id,
                )
            )

        # Preserve typed discovery signals that do not have a more specific
        # Phase 4 record without copying their potentially sensitive values.
        for observation_type, metadata in (
            ("graphql_discovery_metadata", surface.graphql),
            ("jwt_discovery_metadata", surface.jwt),
            ("upload_discovery_metadata", surface.uploads),
        ):
            if not metadata:
                continue
            evidence_id = stable_research_identifier(
                "evidence", surface_id, observation_type
            )
            evidence.append(
                EvidenceArtifact(
                    evidence_id=evidence_id,
                    evidence_kind=EvidenceKind.schema,
                    digest=digest_for(metadata),
                    summary=f"Discovery produced {observation_type.replace('_', ' ')}.",
                    source_reference="canonical-surface",
                    observed_at=timestamp,
                    provenance_id=provenance_id,
                )
            )
            observations.append(
                Observation(
                    observation_id=stable_research_identifier(
                        "observation", surface_id, observation_type
                    ),
                    observation_type=observation_type,
                    summary=(
                        "Discovery produced structural metadata; behavior remains "
                        "unverified."
                    ),
                    target_id=target_id,
                    surface_id=surface_id,
                    evidence_references=(evidence_id,),
                    provenance_id=provenance_id,
                )
            )

        parameters: list[Parameter] = []
        for item in surface.parameters:
            if len(parameters) >= max_parameters:
                break
            method = str(item.get("method") or "GET").upper()
            path = str(item.get("path") or "/")
            endpoint = endpoint_by_key.get((method, path))
            if endpoint is None:
                continue
            raw_location = str(item.get("in") or item.get("location") or "")
            location = _parameter_location(raw_location)
            name = str(item.get("field_path") or item.get("name") or "").strip()
            if location is None or not name:
                continue
            parameter_id = stable_research_identifier(
                "parameter", endpoint.endpoint_id, location.value, name
            )
            parameters.append(
                Parameter(
                    parameter_id=parameter_id,
                    endpoint_id=endpoint.endpoint_id,
                    name=opaque_reference(name, "parameter-name"),
                    location=location,
                    data_type=(
                        opaque_reference(item.get("schema_type"), "data-type")
                        if item.get("schema_type")
                        else None
                    ),
                    required=(bool(item["required"]) if "required" in item else None),
                    evidence_references=(route_evidence[(method, path)],),
                    provenance_id=provenance_id,
                )
            )

        # Canonical discovery object candidates do not prove control or ownership.
        # Only the controlled-context/acquisition adapter creates ResearchObject.
        research_objects: tuple[ResearchObject, ...] = ()
        graphql_operations = self._graphql_operations(
            surface,
            surface_id=surface_id,
            endpoint_by_key=endpoint_by_key,
            parameters=tuple(parameters),
            route_evidence=route_evidence,
            provenance_id=provenance_id,
        )
        workflows = self._workflows(
            surface.workflows,
            surface_id=surface_id,
            endpoint_by_key=endpoint_by_key,
            route_evidence=route_evidence,
            provenance_id=provenance_id,
        )
        for boundary in surface.auth_boundaries:
            key = (
                str(boundary.get("method") or "GET").upper(),
                str(boundary.get("path") or "/"),
            )
            endpoint = endpoint_by_key.get(key)
            evidence_id = route_evidence.get(key)
            if endpoint is None or evidence_id is None:
                continue
            observations.append(
                Observation(
                    observation_id=stable_research_identifier(
                        "observation", endpoint.endpoint_id, "auth-boundary"
                    ),
                    observation_type="authentication_boundary_candidate",
                    summary="Discovery metadata indicates an authentication boundary candidate; enforcement is unverified.",
                    target_id=target_id,
                    surface_id=surface_id,
                    evidence_references=(evidence_id,),
                    provenance_id=provenance_id,
                )
            )

        surface_evidence = tuple(item.evidence_id for item in evidence[:200])
        surface_record = surface_record.model_copy(
            update={"evidence_references": surface_evidence}
        )
        records = AttackSurfaceResearchRecords(
            surfaces=(surface_record,),
            endpoints=tuple(endpoints),
            parameters=tuple(parameters),
            objects=research_objects,
            graphql_operations=graphql_operations,
            workflows=workflows,
            observations=tuple(observations),
            evidence=tuple(evidence),
            facts=tuple(facts),
            provenance=(provenance,),
        )
        reject_secret_material(
            records.model_dump(mode="json"), location="attack surface research import"
        )
        return records

    @staticmethod
    def apply(
        state: ResearchState, records: AttackSurfaceResearchRecords
    ) -> ResearchState:
        payload = state.model_dump(mode="python")
        for name, field in (
            ("surfaces", "surface_id"),
            ("endpoints", "endpoint_id"),
            ("parameters", "parameter_id"),
            ("objects", "object_id"),
            ("graphql_operations", "operation_id"),
            ("workflows", "workflow_id"),
            ("observations", "observation_id"),
            ("evidence", "evidence_id"),
            ("facts", "fact_id"),
            ("provenance", "provenance_id"),
        ):
            payload[name] = _merge(getattr(state, name), getattr(records, name), field)
        return ResearchState.model_validate(payload)

    @staticmethod
    def to_canonical_surface(
        state: ResearchState, *, target_id: str
    ) -> CanonicalAttackSurface:
        target = next(item for item in state.targets if item.target_id == target_id)
        surface_ids = {
            item.surface_id for item in state.surfaces if item.target_id == target_id
        }
        endpoints = [item for item in state.endpoints if item.surface_id in surface_ids]
        endpoint_map = {item.endpoint_id: item for item in endpoints}
        routes = [
            {
                "method": item.method.value,
                "path": item.route_template,
                "confidence": "high",
                "source": "phase4-research-state",
                "evidence_refs": list(item.evidence_references),
                "content_types": list(item.content_types),
            }
            for item in endpoints
        ]
        parameters = [
            {
                "method": endpoint_map[item.endpoint_id].method.value,
                "path": endpoint_map[item.endpoint_id].route_template,
                "name": item.name,
                "in": item.location.value,
                "schema_type": item.data_type or "unknown",
                "required": item.required,
                "confidence": "high",
                "source": "phase4-research-state",
                "evidence_refs": list(item.evidence_references),
            }
            for item in state.parameters
            if item.endpoint_id in endpoint_map
        ]
        auth_boundaries = []
        for observation in state.observations:
            if (
                observation.surface_id not in surface_ids
                or observation.observation_type != "authentication_boundary_candidate"
            ):
                continue
            evidence_ids = set(observation.evidence_references)
            endpoint = next(
                (
                    item
                    for item in endpoints
                    if evidence_ids.intersection(item.evidence_references)
                ),
                None,
            )
            if endpoint is not None:
                auth_boundaries.append(
                    {
                        "method": endpoint.method.value,
                        "path": endpoint.route_template,
                        "boundary_type": "authenticated_resource",
                        "confidence": "medium",
                        "evidence_refs": list(observation.evidence_references),
                    }
                )
        return CanonicalAttackSurface(
            target=target.canonical_reference,
            routes=routes,
            parameters=parameters,
            auth_boundaries=auth_boundaries,
            evidence_sources=[],
            limitations=[
                "Reconstructed from persisted Phase 4 discovery records for restart-safe hypothesis generation."
            ],
        )

    @staticmethod
    def _graphql_operations(
        surface: CanonicalAttackSurface,
        *,
        surface_id: str,
        endpoint_by_key: dict[tuple[str, str], Endpoint],
        parameters: tuple[Parameter, ...],
        route_evidence: dict[tuple[str, str], str],
        provenance_id: str,
    ) -> tuple[GraphQLOperation, ...]:
        output = []
        for item in (surface.graphql.get("operations") or [])[:5_000]:
            path = str(item.get("path") or "/graphql")
            operation_type_value = str(item.get("type") or "query").lower()
            method = "GET" if operation_type_value == "query" else "POST"
            endpoint = endpoint_by_key.get((method, path)) or next(
                (value for key, value in endpoint_by_key.items() if key[1] == path),
                None,
            )
            if endpoint is None:
                continue
            try:
                operation_type = GraphQLOperationType(operation_type_value)
            except ValueError:
                continue
            name = str(item.get("name") or "observed-operation")
            operation_parameters = tuple(
                value.parameter_id
                for value in parameters
                if value.endpoint_id == endpoint.endpoint_id
                and value.location is ParameterLocation.graphql_variable
            )
            evidence_id = route_evidence[
                (endpoint.method.value, endpoint.route_template)
            ]
            output.append(
                GraphQLOperation(
                    operation_id=stable_research_identifier(
                        "graphql-operation",
                        endpoint.endpoint_id,
                        operation_type.value,
                        name,
                    ),
                    surface_id=surface_id,
                    endpoint_id=endpoint.endpoint_id,
                    operation_name=opaque_reference(name, "graphql-operation"),
                    operation_type=operation_type,
                    root_fields=(opaque_reference(name, "graphql-field"),),
                    variable_parameter_ids=operation_parameters,
                    evidence_references=(evidence_id,),
                    provenance_id=provenance_id,
                )
            )
        return tuple(output)

    @staticmethod
    def _workflows(
        values: Sequence[dict[str, Any]],
        *,
        surface_id: str,
        endpoint_by_key: dict[tuple[str, str], Endpoint],
        route_evidence: dict[tuple[str, str], str],
        provenance_id: str,
    ) -> tuple[Workflow, ...]:
        output = []
        for index, item in enumerate(values[:2_000], start=1):
            raw_steps = item.get("steps") or [item]
            steps: list[WorkflowStep] = []
            evidence_ids: list[str] = []
            for sequence, raw in enumerate(raw_steps, start=1):
                if not isinstance(raw, dict):
                    continue
                key = (
                    str(raw.get("method") or "GET").upper(),
                    str(raw.get("path") or "/"),
                )
                endpoint = endpoint_by_key.get(key)
                if endpoint is None:
                    continue
                steps.append(
                    WorkflowStep(
                        step_id=stable_research_identifier(
                            "workflow-step",
                            surface_id,
                            index,
                            sequence,
                            endpoint.endpoint_id,
                        ),
                        sequence=sequence,
                        endpoint_id=endpoint.endpoint_id,
                        method=endpoint.method,
                        state_before_reference=(
                            opaque_reference(raw.get("state_before"), "state")
                            if raw.get("state_before")
                            else None
                        ),
                        state_after_reference=(
                            opaque_reference(raw.get("state_after"), "state")
                            if raw.get("state_after")
                            else None
                        ),
                        state_changing=bool(
                            raw.get("state_changing")
                            or endpoint.method
                            not in {HttpMethod.get, HttpMethod.head, HttpMethod.options}
                        ),
                    )
                )
                evidence_ids.append(route_evidence[key])
            if not steps:
                continue
            name = str(
                item.get("name") or item.get("workflow_type") or f"workflow-{index}"
            )
            output.append(
                Workflow(
                    workflow_id=stable_research_identifier(
                        "workflow", surface_id, item.get("workflow_id") or name
                    ),
                    surface_id=surface_id,
                    name=public_text(name, "Observed workflow."),
                    steps=tuple(steps),
                    evidence_references=tuple(sorted(set(evidence_ids))),
                    provenance_id=provenance_id,
                )
            )
        return tuple(output)


class ControlledContextResearchAdapter:
    """Import only safe account handles, vault references, and owned objects."""

    def adapt(
        self,
        context: ControlledContext,
        state: ResearchState,
        *,
        policy: AssessmentPolicy,
        target_id: str,
        vault: CredentialVault | None = None,
        acquired_objects: Sequence[ControlledObject] = (),
        occurred_at: str | None = None,
    ) -> ControlledContextResearchRecords:
        if target_id not in {item.target_id for item in state.targets}:
            raise ValueError("controlled context target is not registered")
        timestamp = _timestamp(occurred_at)
        provenance_id = stable_research_identifier(
            "provenance", state.research_id, target_id, "controlled-context-import"
        )
        provenance = ProvenanceRecord(
            provenance_id=provenance_id,
            producer_type=ProvenanceProducerType.imported,
            producer_name="controlled-context-research-adapter",
            producer_version=ADAPTER_VERSION,
            summary="Imported controlled identity and ownership references without credential values.",
            occurred_at=timestamp,
        )
        identities: list[Identity] = []
        account_to_identity: dict[str, str] = {}
        sessions: list[SessionRef] = []
        tokens: list[TokenRef] = []
        for account in context.accounts:
            identity_id = stable_research_identifier(
                "identity", state.research_id, account.account_id
            )
            account_to_identity[account.account_id] = identity_id
            decision = policy.account_is_eligible(
                account.account_id, context, account_controlled=account.controlled
            )
            eligibility = (
                IdentityEligibility.eligible
                if decision.eligible
                else IdentityEligibility.ineligible
            )
            identities.append(
                Identity(
                    identity_id=identity_id,
                    account_reference=opaque_reference(account.account_id, "account"),
                    role_reference=(
                        opaque_reference(account.role, "role") if account.role else None
                    ),
                    tenant_reference=(
                        opaque_reference(account.tenant_id, "tenant")
                        if account.tenant_id
                        else None
                    ),
                    controlled=bool(account.controlled),
                    eligibility=eligibility,
                    provenance_id=provenance_id,
                )
            )
            if account.session_reference:
                active = _vault_contains(vault, account.session_reference)
                sessions.append(
                    SessionRef(
                        session_ref_id=stable_research_identifier(
                            "session", identity_id, account.session_reference
                        ),
                        identity_id=identity_id,
                        vault_reference=account.session_reference,
                        lifecycle=(
                            SessionLifecycle.active
                            if active
                            else SessionLifecycle.unknown
                        ),
                        provenance_id=provenance_id,
                    )
                )
            for name, reference in account.credential_references.items():
                kind = _token_kind(name)
                if kind is None:
                    continue
                tokens.append(
                    TokenRef(
                        token_ref_id=stable_research_identifier(
                            "token", identity_id, name, reference
                        ),
                        identity_id=identity_id,
                        vault_reference=reference,
                        token_kind=kind,
                        lifecycle=(
                            TokenLifecycle.active
                            if _vault_contains(vault, reference)
                            else TokenLifecycle.unknown
                        ),
                        provenance_id=provenance_id,
                    )
                )

        surfaces = [item for item in state.surfaces if item.target_id == target_id]
        limitations: list[str] = []
        evidence: list[EvidenceArtifact] = []
        objects: list[ResearchObject] = []
        controlled_objects = {
            (item.owner_account_id, item.object_id): item
            for item in (*context.objects, *acquired_objects)
            if item.test_owned
        }
        if controlled_objects and len(surfaces) != 1:
            limitations.append(
                "Controlled objects require exactly one unambiguous target surface before import."
            )
        elif surfaces:
            for controlled_object in controlled_objects.values():
                owner_identity = account_to_identity.get(
                    controlled_object.owner_account_id
                )
                owner_account = next(
                    (
                        item
                        for item in context.accounts
                        if item.account_id == controlled_object.owner_account_id
                    ),
                    None,
                )
                if (
                    owner_identity is None
                    or owner_account is None
                    or not owner_account.controlled
                ):
                    limitations.append(
                        "A controlled object owner was absent from the controlled account set."
                    )
                    continue
                evidence_id = stable_research_identifier(
                    "evidence",
                    state.research_id,
                    controlled_object.owner_account_id,
                    controlled_object.object_id,
                    "ownership",
                )
                evidence.append(
                    EvidenceArtifact(
                        evidence_id=evidence_id,
                        evidence_kind=EvidenceKind.imported,
                        digest=digest_for(
                            {
                                "owner": controlled_object.owner_account_id,
                                "object_type": controlled_object.object_type,
                                "test_owned": True,
                            }
                        ),
                        summary="Controlled context records researcher-authorized test ownership.",
                        source_reference=stable_research_identifier(
                            "controlled-object-source",
                            controlled_object.owner_account_id,
                            controlled_object.object_id,
                        ),
                        observed_at=timestamp,
                        provenance_id=provenance_id,
                    )
                )
                objects.append(
                    ResearchObject(
                        object_id=stable_research_identifier(
                            "object",
                            target_id,
                            controlled_object.object_type,
                            controlled_object.object_id,
                        ),
                        target_id=target_id,
                        surface_id=surfaces[0].surface_id,
                        object_type=opaque_reference(
                            controlled_object.object_type, "object-type"
                        ),
                        object_reference=opaque_reference(
                            controlled_object.object_id, "object-reference"
                        ),
                        owner_identity_id=owner_identity,
                        tenant_reference=(
                            opaque_reference(controlled_object.tenant_id, "tenant")
                            if controlled_object.tenant_id
                            else None
                        ),
                        test_owned=True,
                        evidence_references=(evidence_id,),
                        provenance_id=provenance_id,
                    )
                )

        records = ControlledContextResearchRecords(
            identities=tuple(identities),
            session_refs=tuple(sessions),
            token_refs=tuple(tokens),
            objects=tuple(objects),
            evidence=tuple(evidence),
            provenance=(provenance,),
            limitations=tuple(sorted(set(limitations))),
        )
        reject_secret_material(
            records.model_dump(mode="json"),
            location="controlled context research import",
        )
        return records

    @staticmethod
    def apply(
        state: ResearchState, records: ControlledContextResearchRecords
    ) -> ResearchState:
        payload = state.model_dump(mode="python")
        for name, field in (
            ("identities", "identity_id"),
            ("session_refs", "session_ref_id"),
            ("token_refs", "token_ref_id"),
            ("objects", "object_id"),
            ("evidence", "evidence_id"),
            ("provenance", "provenance_id"),
        ):
            payload[name] = _merge(getattr(state, name), getattr(records, name), field)
        return ResearchState.model_validate(payload)

    def adapt_acquired_objects(
        self,
        objects: Sequence[ControlledObject],
        context: ControlledContext,
        state: ResearchState,
        *,
        policy: AssessmentPolicy,
        target_id: str,
        vault: CredentialVault | None = None,
        occurred_at: str | None = None,
    ) -> ControlledContextResearchRecords:
        """Adapt results emitted by the existing bounded ``OwnedObjectAcquirer``."""

        return self.adapt(
            context,
            state,
            policy=policy,
            target_id=target_id,
            vault=vault,
            acquired_objects=objects,
            occurred_at=occurred_at,
        )


def adapt_surface_hypotheses(
    hypotheses: Sequence[Hypothesis],
    state: ResearchState,
    *,
    target_id: str,
    confirmation_policy_reference: str,
    max_hypotheses: int,
    occurred_at: str | None = None,
) -> tuple[tuple[HypothesisRecord, ...], tuple[ProvenanceRecord, ...]]:
    timestamp = _timestamp(occurred_at)
    provenance_id = stable_research_identifier(
        "provenance", state.research_id, target_id, "surface-hypotheses"
    )
    provenance = ProvenanceRecord(
        provenance_id=provenance_id,
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="generate-surface-hypotheses-adapter",
        producer_version=ADAPTER_VERSION,
        summary="Adapted deterministic surface hypotheses as unconfirmed proposals.",
        occurred_at=timestamp,
    )
    endpoint_by_key = {
        (item.method.value, item.route_template): item
        for item in state.endpoints
        if item.target_id == target_id
    }
    parameters_by_endpoint: dict[str, list[Parameter]] = {}
    for parameter in state.parameters:
        parameters_by_endpoint.setdefault(parameter.endpoint_id, []).append(parameter)
    existing = {
        item.semantic_fingerprint
        or _hypothesis_fingerprint(
            item.category, item.claim, item.target_id, item.surface_id
        )
        for item in state.hypotheses
    }
    records: list[HypothesisRecord] = []
    for item in sorted(
        hypotheses, key=lambda value: (-value.priority, value.hypothesis_id)
    ):
        if len(records) >= max_hypotheses:
            break
        path = str(item.target_surface.get("path") or "")
        method = str(item.target_surface.get("method") or item.method or "GET").upper()
        endpoint = endpoint_by_key.get((method, path))
        if endpoint is None:
            continue
        evidence_ids = set(endpoint.evidence_references)
        parameter_name = str(
            item.target_surface.get("parameter") or item.parameter or ""
        )
        if parameter_name:
            parameter = next(
                (
                    value
                    for value in parameters_by_endpoint.get(endpoint.endpoint_id, [])
                    if value.name == opaque_reference(parameter_name, "parameter-name")
                ),
                None,
            )
            if parameter is not None:
                evidence_ids.update(parameter.evidence_references)
        if not evidence_ids:
            continue
        falsification = public_text(
            item.metadata.get("bounded_verification_objective"),
            "A bounded controlled comparison produces no evidence of the proposed behavior.",
        )
        claim = public_text(
            f"{item.rationale} This claim is falsified when: {falsification}",
            "A bounded controlled comparison is required to resolve this hypothesis.",
            limit=4_000,
        )
        fingerprint = _hypothesis_fingerprint(
            item.category, claim, target_id, endpoint.surface_id
        )
        if fingerprint in existing:
            continue
        limitations = tuple(
            public_text(value, "Discovery evidence is limited.")
            for value in [*item.limitations, falsification]
        )
        records.append(
            HypothesisRecord(
                hypothesis_id=stable_research_identifier("hypothesis", fingerprint),
                category=opaque_reference(item.category, "category"),
                title=public_text(item.title, "Proposed surface hypothesis."),
                claim=claim,
                target_id=target_id,
                surface_id=endpoint.surface_id,
                status=HypothesisResearchStatus.proposed,
                priority=item.priority,
                confidence=ResearchConfidence(item.confidence),
                confirmation_policy_reference=confirmation_policy_reference,
                supporting_evidence=tuple(sorted(evidence_ids)),
                limitations=limitations,
                derivation_type=DerivationType.deterministic,
                semantic_fingerprint=fingerprint,
                provenance_id=provenance_id,
            )
        )
        existing.add(fingerprint)
    return tuple(records), (provenance,)


def adapt_model_hypotheses(
    proposals: Sequence[NewHypothesisProposal],
    state: ResearchState,
    *,
    allowed_categories: Sequence[str],
    confirmation_policy_reference: str,
    max_hypotheses: int,
    occurred_at: str | None = None,
) -> tuple[tuple[HypothesisRecord, ...], tuple[ProvenanceRecord, ...]]:
    timestamp = _timestamp(occurred_at)
    provenance_id = stable_research_identifier(
        "provenance", state.research_id, state.revision, "model-hypotheses"
    )
    provenance = ProvenanceRecord(
        provenance_id=provenance_id,
        producer_type=ProvenanceProducerType.model,
        producer_name="research-reasoning-engine",
        producer_version=ADAPTER_VERSION,
        summary="Imported evidence-grounded model hypotheses as unconfirmed proposals.",
        occurred_at=timestamp,
    )
    evidence_ids = {item.evidence_id for item in state.evidence}
    fact_ids = {item.fact_id for item in state.facts}
    relationship_ids = {item.relationship_id for item in state.relationships}
    target_ids = {item.target_id for item in state.targets}
    surface_ids = {item.surface_id for item in state.surfaces}
    allowed = set(allowed_categories)
    existing = {
        item.semantic_fingerprint
        or _hypothesis_fingerprint(
            item.category, item.claim, item.target_id, item.surface_id
        )
        for item in state.hypotheses
    }
    output = []
    for item in proposals:
        if len(output) >= max_hypotheses:
            break
        if (
            item.source is not HypothesisProposalSource.model
            or item.category not in allowed
            or item.target_id not in target_ids
            or (item.surface_id is not None and item.surface_id not in surface_ids)
            or not set(item.evidence_references).issubset(evidence_ids)
            or not set(item.fact_references).issubset(fact_ids)
            or not set(item.relationship_references).issubset(relationship_ids)
        ):
            continue
        fingerprint = _hypothesis_fingerprint(
            item.category, item.claim, item.target_id, item.surface_id
        )
        if fingerprint in existing:
            continue
        output.append(
            HypothesisRecord(
                hypothesis_id=stable_research_identifier("hypothesis", fingerprint),
                category=item.category,
                title=public_text(item.title, "Model-proposed hypothesis."),
                claim=public_text(item.claim, "A falsifiable model hypothesis."),
                target_id=item.target_id,
                surface_id=item.surface_id,
                status=HypothesisResearchStatus.proposed,
                priority=item.priority,
                confidence=item.confidence,
                # Policy authority is deterministic; model prose cannot select or
                # replace the confirmation policy used by the run.
                confirmation_policy_reference=confirmation_policy_reference,
                supporting_evidence=item.evidence_references,
                limitations=(
                    public_text(
                        item.falsification_criterion,
                        "A bounded controlled comparison can falsify this claim.",
                    ),
                ),
                derivation_type=DerivationType.model_proposed,
                basis_fact_ids=item.fact_references,
                basis_relationship_ids=item.relationship_references,
                semantic_fingerprint=fingerprint,
                provenance_id=provenance_id,
            )
        )
        existing.add(fingerprint)
    return tuple(output), ((provenance,) if output else ())


def _hypothesis_fingerprint(
    category: str, claim: str, target_id: str, surface_id: str | None
) -> str:
    return digest_for(
        {
            "category": category,
            "claim": " ".join(claim.casefold().split()),
            "surface_id": surface_id,
            "target_id": target_id,
        }
    )


def _parameter_location(value: str) -> ParameterLocation | None:
    aliases = {
        "body": ParameterLocation.json,
        "request_body": ParameterLocation.json,
        "multipart": ParameterLocation.form,
        "graphql_argument": ParameterLocation.graphql_variable,
    }
    try:
        return ParameterLocation(value)
    except ValueError:
        return aliases.get(value)


def _token_kind(value: str) -> TokenKind | None:
    normalized = value.casefold().replace("-", "_")
    if not any(marker in normalized for marker in ("token", "jwt")):
        return None
    if "refresh" in normalized:
        return TokenKind.refresh
    if "identity" in normalized or "id_token" in normalized:
        return TokenKind.identity
    if "access" in normalized or normalized in {"token", "jwt"}:
        return TokenKind.access
    return TokenKind.other


def _vault_contains(vault: CredentialVault | None, reference: str) -> bool:
    if vault is None:
        return False
    try:
        return vault.contains(reference)
    except RuntimeError:
        return False


__all__ = [
    "ADAPTER_VERSION",
    "AttackSurfaceResearchAdapter",
    "AttackSurfaceResearchRecords",
    "ControlledContextResearchAdapter",
    "ControlledContextResearchRecords",
    "adapt_model_hypotheses",
    "adapt_surface_hypotheses",
    "digest_for",
    "opaque_reference",
    "stable_research_identifier",
]
