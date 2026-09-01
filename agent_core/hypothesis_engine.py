"""Deterministic hypothesis generation and verification-plan construction."""

from __future__ import annotations

from collections.abc import Callable, Iterable
import json
from urllib.parse import urlparse

from pydantic import TypeAdapter, ValidationError

from agent_core.agent_models import (
    EvidenceRequirement,
    Hypothesis,
    RiskLevel,
    VerificationPlan,
    VerificationStep,
    stable_identifier,
)
from agent_core.capture_ingest import CaptureBundle, CapturedParameter, CapturedRequest
from agent_core.attack_surface import CanonicalAttackSurface
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    CAPABILITY_SCHEMA_VERSION,
    CapabilityState,
    capability_metadata,
    get_verification_capability,
    request_cost_for,
)
from tool_registry import TOOLS

CATEGORY_PRIORITY = {
    "bola": 100,
    "vertical_authorization": 96,
    "tenant_isolation": 94,
    "mass_assignment": 90,
    "property_authorization": 88,
    "session_security": 84,
    "oauth_oidc": 82,
    "account_lifecycle": 80,
    "business_logic": 76,
    "api_authorization": 75,
    "graphql_authorization": 74,
    "ssrf": 70,
    "upload_security": 66,
    "injection": 62,
    "cache_security": 58,
    "excessive_data_exposure": 72,
    "authentication_enforcement": 86,
    "session_invalidation": 82,
    "recovery_state_enforcement": 81,
    "rate_limit_enforcement": 78,
    "jwt_enforcement": 80,
    "graphql_object_authorization": 78,
    "graphql_field_authorization": 77,
    "graphql_mutation_authorization": 79,
    "sql_injection": 68,
    "command_injection": 68,
    "path_traversal": 68,
    "file_upload_validation": 66,
    "upload_ownership": 70,
    "business_logic_state_enforcement": 76,
}

if set(CATEGORY_PRIORITY) != set(CAPABILITY_REGISTRY):
    raise RuntimeError(
        "Every emitted Phase 2 category must have exactly one capability entry."
    )

OBJECT_HINTS = {
    "id",
    "uuid",
    "guid",
    "user_id",
    "userid",
    "account_id",
    "order_id",
    "project_id",
    "file_id",
    "object_id",
    "tenant_id",
    "organization_id",
    "org_id",
}
PRIVILEGE_HINTS = {
    "role",
    "roles",
    "admin",
    "is_admin",
    "permissions",
    "permission",
    "owner_id",
    "tenant_id",
    "organization_id",
    "status",
    "approved",
    "verified",
}
SSRF_HINTS = {"url", "uri", "webhook", "callback", "host", "domain", "redirect"}
UPLOAD_HINTS = {"file", "upload", "filename", "attachment", "document", "image"}
INJECTION_HINTS = {
    "id",
    "q",
    "query",
    "search",
    "filter",
    "sort",
    "name",
    "template",
    "path",
    "command",
}
ACCOUNT_PATHS = {
    "login",
    "logout",
    "register",
    "signup",
    "password",
    "reset",
    "verify",
    "invite",
    "oauth",
    "authorize",
    "callback",
    "token",
}
PRIVILEGED_PATHS = {
    "admin",
    "administrator",
    "manage",
    "management",
    "roles",
    "permissions",
    "internal",
    "staff",
    "moderator",
}
READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}


def _meaningful_state(value: object) -> bool:
    return str(value or "").strip().lower() not in {"", "unknown", "none"}


def _workflow_evidence_route(workflow: object) -> dict[str, object] | None:
    """Return a concrete route only when workflow/state evidence is present."""
    if not isinstance(workflow, dict):
        return None

    raw_steps = workflow.get("steps") or workflow.get("observed_steps") or []
    steps = [item for item in raw_steps if isinstance(item, dict)]
    sequences = [item.get("sequence") for item in steps]
    ordered_steps = bool(
        len(steps) > 1
        and all(isinstance(item, int) and item > 0 for item in sequences)
        and sequences == sorted(set(sequences))
    )
    stateful_steps = [
        item
        for item in steps
        if _meaningful_state(item.get("state_before"))
        or _meaningful_state(item.get("state_after"))
        or _meaningful_state(item.get("state"))
    ]
    mutating_steps = [
        item
        for item in steps
        if str(item.get("method") or "GET").upper() not in READ_ONLY_METHODS
    ]

    transitions = workflow.get("transitions") or []
    observations = workflow.get("observations") or []
    transition_observed = any(
        isinstance(item, dict)
        and item.get("type")
        in {
            "prerequisite_step_observed",
            "state_changing_operation_observed",
            "state_transition_observed",
        }
        for item in observations
    )
    detailed_evidence = bool(
        (isinstance(transitions, list) and transitions)
        or transition_observed
        or (ordered_steps and (mutating_steps or stateful_steps))
    )

    method = str(workflow.get("method") or "GET").upper()
    directly_state_changing = bool(workflow.get("state_changing")) or (
        workflow.get("source") == "captured_request" and method not in READ_ONLY_METHODS
    )
    if not (detailed_evidence or directly_state_changing):
        return None

    route_source = next(
        (
            item
            for item in [*reversed(mutating_steps), *reversed(steps)]
            if item.get("path") or item.get("path_template") or item.get("url")
        ),
        workflow,
    )
    path = (
        workflow.get("path")
        or workflow.get("url")
        or route_source.get("path")
        or route_source.get("path_template")
        or route_source.get("url")
    )
    if not path:
        return None
    return {
        "method": workflow.get("method") or route_source.get("method") or "GET",
        "path": path,
        "source": workflow.get("source") or route_source.get("source") or "workflow",
        "evidence_refs": workflow.get("evidence_refs")
        or route_source.get("evidence_refs")
        or [],
    }


def _normalized_name(parameter: CapturedParameter) -> str:
    return parameter.name.lower().replace("-", "_").split(".")[-1]


def _make_hypothesis(
    request: CapturedRequest,
    category: str,
    title: str,
    rationale: str,
    *,
    parameter: CapturedParameter | None = None,
    tools: Iterable[str] = (),
    requirements: Iterable[EvidenceRequirement] = (),
    requires_credentials: bool = False,
    risk: RiskLevel = RiskLevel.low,
    state_changing: bool = False,
) -> Hypothesis:
    identifier = stable_identifier(
        "hyp",
        category,
        request.method,
        request.url,
        parameter.location if parameter else "",
        parameter.name if parameter else "",
    )
    return Hypothesis(
        hypothesis_id=identifier,
        category=category,
        title=title,
        rationale=rationale,
        target=request.url,
        endpoint=request.url,
        method=request.method,
        parameter=parameter.name if parameter else None,
        parameter_location=parameter.location if parameter else None,
        confidence="medium",
        priority=CATEGORY_PRIORITY[category],
        risk=risk,
        proposed_tools=list(tools),
        evidence_refs=[request.request_id],
        evidence_requirements=list(requirements),
        requires_credentials=requires_credentials,
        state_changing=state_changing,
        cleanup_required=state_changing,
        metadata={
            "request_id": request.request_id,
            "body_type": request.body_type,
            "graphql_operation": request.graphql_operation,
            **capability_metadata(category),
        },
        target_surface={
            "method": request.method,
            "url": request.url,
            "parameter": parameter.name if parameter else None,
            "parameter_location": parameter.location if parameter else None,
        },
        evidence_basis=[
            {
                "source": request.source_format,
                "reference": request.request_id,
                "observation": rationale,
            }
        ],
        impact_if_confirmed="The observed surface may permit access or behavior outside the intended security boundary.",
        required_context=(
            ["explicit controlled credential context"] if requires_credentials else []
        ),
        safe_verification_possible=risk in {RiskLevel.passive, RiskLevel.low},
        limitations=[
            "This is an evidence-derived hypothesis, not a verified vulnerability."
        ],
    )


def _surface_hypothesis(
    surface: CanonicalAttackSurface,
    *,
    category: str,
    title: str,
    route: dict[str, object] | None = None,
    parameter: dict[str, object] | None = None,
    rationale: str,
    confidence: str = "medium",
    impact: str,
    context: Iterable[str] = (),
    safe: bool = True,
    risk: RiskLevel = RiskLevel.low,
    state_changing: bool = False,
    limitations: Iterable[str] = (),
    verification_objective: str | None = None,
    related_surfaces: Iterable[dict[str, object]] = (),
    workflow_identity: str | None = None,
    typed_route_supported: bool = True,
) -> Hypothesis:
    route = route or {}
    parameter = parameter or {}
    method = str(route.get("method") or parameter.get("method") or "GET").upper()
    path = str(route.get("path") or parameter.get("path") or "/")
    endpoint = str(route.get("url") or surface.target.rstrip("/") + path)
    name = str(parameter.get("name") or parameter.get("field_path") or "")
    location = str(parameter.get("in") or parameter.get("location") or "")
    evidence_refs = sorted(
        {
            str(item)
            for item in [
                *(route.get("evidence_refs") or []),
                *(parameter.get("evidence_refs") or []),
            ]
            if item
        }
    )
    basis = [
        {
            "source": str(
                parameter.get("source") or route.get("source") or "attack_surface"
            ),
            "reference": evidence_refs[0] if evidence_refs else None,
            "observation": rationale,
        }
    ]
    for observation in list(route.get("evidence") or [])[:20]:
        if not observation or str(observation) == rationale:
            continue
        basis.append(
            {
                "source": str(route.get("source") or "attack_surface"),
                "reference": evidence_refs[0] if evidence_refs else None,
                "observation": str(observation),
            }
        )
    required = list(context)
    tool_by_category = {
        "bola": "authorization_differential_tester",
        "tenant_isolation": "authorization_differential_tester",
        "vertical_authorization": "authorization_differential_tester",
        "authentication_enforcement": "request_replay_engine",
        "mass_assignment": "request_replay_engine",
        "excessive_data_exposure": "request_diff_engine",
        "session_invalidation": "workflow_replay_checker",
        "recovery_state_enforcement": "workflow_replay_checker",
        "rate_limit_enforcement": "request_replay_engine",
        "jwt_enforcement": "jwt_replay_checker",
        "graphql_object_authorization": "graphql_authz_planner",
        "graphql_field_authorization": "graphql_authz_planner",
        "graphql_mutation_authorization": "graphql_authz_planner",
        "sql_injection": "authenticated_injection_verifier",
        "command_injection": "authenticated_injection_verifier",
        "path_traversal": "authenticated_injection_verifier",
        "file_upload_validation": "upload_replay_checker",
        "upload_ownership": "upload_replay_checker",
        "business_logic_state_enforcement": "workflow_replay_checker",
    }
    requirement_kind = (
        "controlled_identity_differential"
        if category
        in {
            "bola",
            "tenant_isolation",
            "vertical_authorization",
            "graphql_object_authorization",
            "graphql_field_authorization",
            "graphql_mutation_authorization",
        }
        else (
            "workflow_transition"
            if category
            in {
                "session_invalidation",
                "recovery_state_enforcement",
                "business_logic_state_enforcement",
            }
            else (
                "manual_confirmation"
                if category == "rate_limit_enforcement"
                else (
                    "controlled_canary"
                    if category
                    in {
                        "sql_injection",
                        "command_injection",
                        "path_traversal",
                        "file_upload_validation",
                        "upload_ownership",
                    }
                    else "response_differential"
                )
            )
        )
    )
    identity_parts = ("hyp", category, method, path, location, name)
    if workflow_identity:
        identity_parts = (*identity_parts, workflow_identity)
    return Hypothesis(
        hypothesis_id=stable_identifier(*identity_parts),
        category=category,
        title=title,
        rationale=rationale,
        target=surface.target,
        endpoint=endpoint,
        method=method,
        parameter=name or None,
        parameter_location=(
            location
            if location
            in {
                "path",
                "query",
                "header",
                "cookie",
                "form",
                "json",
                "multipart",
                "graphql_variable",
                "graphql_argument",
            }
            else None
        ),
        confidence=confidence,  # type: ignore[arg-type]
        priority=CATEGORY_PRIORITY[category],
        risk=risk,
        proposed_tools=[tool_by_category[category]],
        evidence_refs=evidence_refs,
        evidence_requirements=[
            EvidenceRequirement(
                kind=requirement_kind,  # type: ignore[arg-type]
                minimum_repetitions=(
                    1
                    if requirement_kind in {"controlled_canary", "manual_confirmation"}
                    else 2
                ),
                description="Collect controlled, correlated evidence sufficient for deterministic classification.",
            )
        ],
        requires_credentials=any(
            "account" in item or "credential" in item for item in required
        ),
        state_changing=state_changing,
        cleanup_required=state_changing,
        target_surface={"method": method, "path": path, "parameter": name or None},
        evidence_basis=basis,
        impact_if_confirmed=impact,
        required_context=required,
        safe_verification_possible=safe,
        limitations=[
            "The observation does not establish runtime vulnerability behavior.",
            *limitations,
        ],
        metadata={
            "source_confidence": confidence,
            "evidence_sources": list(route.get("evidence_sources") or []),
            "request_body_field": location
            in {"json", "form", "multipart", "request_body"},
            "bounded_verification_objective": verification_objective
            or "Collect the minimum controlled evidence needed to classify this hypothesis.",
            "related_surfaces": list(related_surfaces),
            "workflow_identity": workflow_identity,
            "workflow_completeness": 1.0 if workflow_identity else None,
            **capability_metadata(
                category, typed_route_supported=typed_route_supported
            ),
        },
    )


def generate_surface_hypotheses(
    surface: CanonicalAttackSurface,
) -> list[Hypothesis]:
    """Generate Phase 2 hypotheses from the canonical observed surface.

    Every result remains ``proposed``. Names, schemas, and status codes alone
    never promote an item to a finding.
    """
    generated: dict[str, Hypothesis] = {}
    routes_by_key = {
        (
            str(route.get("method") or "GET").upper(),
            str(route.get("path") or "/"),
        ): route
        for route in surface.routes
    }

    def add(item: Hypothesis) -> None:
        generated[item.hypothesis_id] = item

    def semantic_route(boundary: dict[str, object]) -> dict[str, object]:
        key = (
            str(boundary.get("method") or "GET").upper(),
            str(boundary.get("path") or "/"),
        )
        route = dict(routes_by_key.get(key, boundary))
        route["method"] = key[0]
        route["path"] = key[1]
        route["source"] = boundary.get("source") or route.get("source")
        route["evidence_sources"] = list(boundary.get("evidence_sources") or [])
        route["evidence"] = list(boundary.get("evidence") or [])
        route["evidence_refs"] = sorted(
            {
                str(item)
                for item in [
                    *(route.get("evidence_refs") or []),
                    *(boundary.get("evidence_refs") or []),
                ]
                if item
            }
        )
        return route

    for parameter in surface.parameters:
        method = str(parameter.get("method") or "GET").upper()
        path = str(parameter.get("path") or "/")
        route = routes_by_key.get((method, path), {"method": method, "path": path})
        raw_name = str(parameter.get("field_path") or parameter.get("name") or "")
        name = raw_name.lower().replace("-", "_").split(".")[-1]
        location = str(parameter.get("in") or parameter.get("location") or "")
        writable = location in {
            "json",
            "form",
            "multipart",
            "request_body",
            "graphql_variable",
        }
        if location == "path" and (name in OBJECT_HINTS or name.endswith("_id")):
            add(
                _surface_hypothesis(
                    surface,
                    category="bola",
                    title="Object ownership enforcement may require controlled comparison",
                    route=route,
                    parameter=parameter,
                    rationale=f"Observed path identifier '{raw_name}' can select an object.",
                    impact="A controlled user could access protected data belonging to another controlled user.",
                    context=(
                        "two distinct controlled accounts",
                        "researcher-controlled object with confirmed ownership",
                    ),
                )
            )
        if "tenant" in name or name in {"organization_id", "org_id"}:
            add(
                _surface_hypothesis(
                    surface,
                    category="tenant_isolation",
                    title="Tenant isolation may require a controlled cross-tenant comparison",
                    route=route,
                    parameter=parameter,
                    rationale=f"Observed tenant-scoped identifier '{raw_name}'.",
                    impact="One controlled tenant could access protected resources belonging to another controlled tenant.",
                    context=(
                        "two controlled accounts in distinct controlled tenants",
                        "test-owned tenant resource",
                    ),
                )
            )
        if writable and name in PRIVILEGE_HINTS | {"credit_limit"}:
            add(
                _surface_hypothesis(
                    surface,
                    category="mass_assignment",
                    title="Privilege-sensitive fields may require mass-assignment validation",
                    route=route,
                    parameter=parameter,
                    rationale=f"Documented writable request field '{raw_name}' is privilege-, ownership-, or policy-sensitive.",
                    impact="A controlled user could persist a field that the user is not permitted to control.",
                    context=(
                        "controlled account",
                        "test-owned resource",
                        "known reversible before state",
                    ),
                    safe=False,
                    risk=RiskLevel.moderate,
                    state_changing=True,
                )
            )
        if name in {"q", "query", "search", "filter", "sort", "where"}:
            add(
                _surface_hypothesis(
                    surface,
                    category="sql_injection",
                    title="Query-handling behavior may require a bounded differential probe",
                    route=route,
                    parameter=parameter,
                    rationale=f"Observed query-like input '{raw_name}'; no database behavior is inferred.",
                    confidence="low",
                    impact="Untrusted input could alter a backend query if server-side parameterization is absent.",
                    context=("explicitly classified local or dedicated lab",),
                    limitations=("Parameter semantics alone do not imply a SQL sink.",),
                )
            )
        if name in {"cmd", "command", "exec", "shell"}:
            add(
                _surface_hypothesis(
                    surface,
                    category="command_injection",
                    title="Command-like input may require a harmless fixed-canary probe",
                    route=route,
                    parameter=parameter,
                    rationale=f"Observed command-like input '{raw_name}'; no interpreter reachability is inferred.",
                    confidence="low",
                    impact="Untrusted input could reach a command interpreter.",
                    context=("explicitly classified local or dedicated lab",),
                    limitations=(
                        "The input name alone does not prove a command sink.",
                    ),
                )
            )
        if name in {"path", "filepath", "file_path", "filename", "template"}:
            add(
                _surface_hypothesis(
                    surface,
                    category="path_traversal",
                    title="Path-like input may require a synthetic-fixture boundary check",
                    route=route,
                    parameter=parameter,
                    rationale=f"Observed path-like input '{raw_name}'; filesystem access is not inferred.",
                    confidence="low",
                    impact="A path boundary failure could expose a synthetic lab fixture outside the intended directory.",
                    context=("explicitly classified local or dedicated lab",),
                    limitations=(
                        "The input name alone does not prove filesystem use.",
                    ),
                )
            )

    for route in surface.routes:
        path = str(route.get("path") or "/")
        words = {word.lower() for word in path.replace("-", "_").split("/") if word}
        if words & PRIVILEGED_PATHS:
            add(
                _surface_hypothesis(
                    surface,
                    category="vertical_authorization",
                    title="Role-level authorization may require a controlled privilege comparison",
                    route=route,
                    rationale="A privileged-area route was observed; its name does not establish broken authorization.",
                    confidence="low",
                    impact="A lower-privileged controlled user could receive protected administrative data or functionality.",
                    context=("controlled normal account", "controlled admin account"),
                )
            )

    boundaries_by_type: dict[str, list[dict[str, object]]] = {}
    for boundary in surface.auth_boundaries:
        boundary_type = str(boundary.get("boundary_type") or "authenticated_resource")
        boundaries_by_type.setdefault(boundary_type, []).append(boundary)
        if boundary_type != "authenticated_resource":
            continue
        route = semantic_route(boundary)
        method = str(route.get("method") or "GET").upper()
        add(
            _surface_hypothesis(
                surface,
                category="authentication_enforcement",
                title="Authentication enforcement may require an unauthenticated comparison",
                route=route,
                rationale="Authenticated-resource semantics were observed; enforcement requires runtime verification.",
                confidence=str(boundary.get("confidence") or "medium"),
                impact="An unauthenticated client could receive protected data or functionality.",
                context=("controlled authenticated account",),
                safe=method in READ_ONLY_METHODS,
                limitations=boundary.get("limitations") or (),
                verification_objective="Compare one unauthenticated request with one controlled authenticated request without mutating application state.",
            )
        )

    for workflow in surface.workflows:
        if (
            workflow.get("semantic_domain") != "authentication"
            or workflow.get("workflow_type") != "session_lifecycle"
        ):
            continue
        steps = [item for item in workflow.get("steps", []) if isinstance(item, dict)]
        step_types = [str(item.get("boundary_type") or "") for item in steps]
        required_types = [
            "session_creation",
            "authenticated_resource",
            "session_termination",
        ]
        if step_types != required_types:
            continue
        resource = steps[1]
        route = semantic_route(resource)
        route["evidence"] = list(
            dict.fromkeys(
                [
                    *list(workflow.get("evidence") or []),
                    *[
                        str(observation)
                        for step in steps
                        for observation in step.get("evidence", []) or []
                        if observation
                    ],
                    "correlation:session_creation_then_authenticated_resource_then_session_termination",
                ]
            )
        )
        route["evidence_refs"] = sorted(
            {
                str(reference)
                for reference in [
                    *(route.get("evidence_refs") or []),
                    *(workflow.get("evidence_refs") or []),
                    *[
                        reference
                        for step in steps
                        for reference in step.get("evidence_refs", []) or []
                    ],
                ]
                if reference
            }
        )
        related = [
            {
                "method": item.get("method"),
                "path": item.get("path"),
                "boundary_type": item.get("boundary_type"),
                **(
                    {"identity_fields": list(item.get("identity_fields") or [])}
                    if item.get("boundary_type") == "recovery_start"
                    and item.get("identity_fields")
                    else {}
                ),
            }
            for item in steps
        ]
        workflow_identity = str(
            workflow.get("workflow_id")
            or json.dumps(related, sort_keys=True, separators=(",", ":"))
        )
        add(
            _surface_hypothesis(
                surface,
                category="session_invalidation",
                title="Session invalidation may require controlled runtime verification",
                route=route,
                rationale="A coherent session-creation, authenticated-resource, and session-termination workflow candidate was observed.",
                confidence=str(workflow.get("confidence") or "medium"),
                impact="Previously issued authentication material might remain usable after explicit session termination.",
                context=(
                    "one controlled authenticated account",
                    "controlled session acquisition capability",
                ),
                safe=True,
                state_changing=True,
                limitations=(
                    *list(workflow.get("limitations") or []),
                    "Route and workflow semantics do not prove a session invalidation vulnerability.",
                ),
                verification_objective="Acquire one controlled session, confirm the authenticated-resource baseline, perform the configured controlled logout, then replay the same previously issued session against the same resource.",
                related_surfaces=related,
                workflow_identity=workflow_identity,
            )
        )

    for workflow in surface.workflows:
        if (
            workflow.get("semantic_domain") != "authentication"
            or workflow.get("workflow_type") != "account_recovery"
        ):
            continue
        steps = [item for item in workflow.get("steps", []) if isinstance(item, dict)]
        step_types = [str(item.get("boundary_type") or "") for item in steps]
        if step_types != ["recovery_start", "recovery_completion"]:
            continue
        completion = next(
            (
                item
                for item in steps
                if item.get("boundary_type") == "recovery_completion"
            ),
            None,
        )
        if completion is None:
            continue
        route = semantic_route(completion)
        route["evidence"] = [
            *list(workflow.get("evidence") or []),
            "correlation:recovery_start_plus_recovery_completion",
        ]
        route["evidence_refs"] = sorted(
            {
                str(reference)
                for reference in [
                    *(route.get("evidence_refs") or []),
                    *(workflow.get("evidence_refs") or []),
                    *[
                        reference
                        for step in steps
                        for reference in step.get("evidence_refs", []) or []
                    ],
                ]
                if reference
            }
        )
        related = [
            {
                "method": item.get("method"),
                "path": item.get("path"),
                "boundary_type": item.get("boundary_type"),
                **(
                    {"identity_fields": list(item.get("identity_fields") or [])}
                    if item.get("boundary_type") == "recovery_start"
                    and item.get("identity_fields")
                    else {}
                ),
            }
            for item in steps
        ]
        workflow_identity = str(
            workflow.get("workflow_id")
            or json.dumps(related, sort_keys=True, separators=(",", ":"))
        )
        add(
            _surface_hypothesis(
                surface,
                category="recovery_state_enforcement",
                title="Recovery state enforcement may require a controlled ordered-step comparison",
                route=route,
                rationale="A correlated recovery-start and recovery-completion workflow candidate was observed.",
                confidence=str(workflow.get("confidence") or "medium"),
                impact="A recovery completion operation could accept a missing, stale, or mismatched controlled recovery state.",
                context=(
                    "controlled recovery account",
                    "researcher-controlled recovery destination where applicable",
                    "explicitly supplied synthetic recovery state/evidence",
                ),
                safe=True,
                risk=RiskLevel.moderate,
                state_changing=True,
                limitations=(
                    *list(workflow.get("limitations") or []),
                    "Route and workflow semantics do not prove a recovery-state vulnerability.",
                    "Codes and tokens must not be guessed, brute-forced, or obtained through account enumeration.",
                ),
                verification_objective="Using only explicitly supplied researcher-controlled recovery state, validate prerequisite ordering and issued one-time evidence without guessing, brute force, or account enumeration.",
                related_surfaces=related,
                workflow_identity=workflow_identity,
            )
        )

    rate_boundaries: dict[tuple[str, str], list[dict[str, object]]] = {}
    for boundary_type in (
        "session_creation",
        "credential_submission",
        "recovery_completion",
    ):
        for boundary in boundaries_by_type.get(boundary_type, []):
            if not boundary.get("rate_sensitive_candidate"):
                continue
            key = (
                str(boundary.get("method") or "GET").upper(),
                str(boundary.get("path") or "/"),
            )
            rate_boundaries.setdefault(key, []).append(boundary)
    for key in sorted(rate_boundaries):
        candidates = rate_boundaries[key]
        boundary = candidates[0]
        login_adapter_supported = bool(
            boundary.get("boundary_type") == "session_creation"
            and "login_session_creation" in set(boundary.get("semantic_classes") or [])
        )
        route = semantic_route(boundary)
        route["evidence"] = sorted(
            {
                str(item)
                for candidate in candidates
                for item in candidate.get("evidence", []) or []
                if item
            }
            | {
                "security_sensitivity:repeated_authentication_or_recovery_submission",
                "runtime_controls:unknown",
            }
        )
        related = [
            {
                "method": boundary.get("method"),
                "path": boundary.get("path"),
                "boundary_type": boundary.get("boundary_type"),
                "semantic_classes": list(boundary.get("semantic_classes") or []),
            }
        ]
        rate_hypothesis = _surface_hypothesis(
            surface,
            category="rate_limit_enforcement",
            title="Authentication rate-limit enforcement may require a pre-approved bounded check",
            route=route,
            rationale="A high-confidence authentication or recovery credential-submission boundary was observed; repeated submission is security-sensitive and runtime controls are unknown.",
            confidence=str(boundary.get("confidence") or "medium"),
            impact="Insufficient request throttling could permit repeated authentication or recovery attempts.",
            context=(
                "explicit authorization for rate-limit verification",
                "explicit bounded attempt policy",
                "controlled account or researcher-controlled recovery resource",
            ),
            safe=login_adapter_supported,
            limitations=(
                "Route semantics do not prove a rate-limit vulnerability or establish whether throttling is configured.",
                "No repeated requests or brute-force behavior are authorized automatically.",
            ),
            verification_objective="Only after an explicit bounded-attempt policy is supplied, assess the documented throttle boundary with a separately approved minimal sequence; never brute force credentials or recovery artifacts.",
            related_surfaces=related,
            typed_route_supported=login_adapter_supported,
        )
        add(rate_hypothesis)

    response_by_request = {
        item.get("request_id"): item for item in surface.response_summaries
    }
    request_by_id = {item.get("request_id"): item for item in surface.captured_requests}
    sensitive = {
        "email",
        "role",
        "credit_limit",
        "authorization",
        "balance",
        "owner_id",
        "tenant_id",
    }
    for request_id, response in response_by_request.items():
        fields = {
            str(item).lower().split(".")[-1]
            for item in response.get("schema_fields", [])
        }
        if not fields & sensitive:
            continue
        request = request_by_id.get(request_id) or {}
        add(
            _surface_hypothesis(
                surface,
                category="excessive_data_exposure",
                title="Protected response fields may require role-aware exposure comparison",
                route=request,
                rationale="A captured response summary included potentially protected field names.",
                impact="A response could expose protected fields unnecessary for the controlled caller.",
                context=(
                    "controlled account with known role",
                    "documented field expectation",
                ),
            )
        )

    jwt_observed = int(surface.jwt.get("tokens_observed") or 0) > 0
    if jwt_observed:
        add(
            _surface_hypothesis(
                surface,
                category="jwt_enforcement",
                title="JWT expiration, audience, and role enforcement may require controlled comparison",
                rationale="JWT metadata was observed without treating token structure as a vulnerability.",
                impact="The service could accept an expired or wrong-audience controlled lab token, or inconsistently enforce role/scope claims.",
                context=("explicitly supplied controlled lab tokens",),
            )
        )

    operations = surface.graphql.get("operations") or []
    if not operations and int(surface.graphql.get("operations_observed") or 0) > 0:
        operations = [{"name": "observed-operation", "type": "unknown"}]
    for operation in operations:
        route = {
            "path": operation.get("path") or urlparse(surface.target).path or "/",
            "url": operation.get("url") or surface.target,
            "method": "POST",
        }
        for category, title in (
            (
                "graphql_object_authorization",
                "GraphQL object authorization may require controlled comparison",
            ),
            (
                "graphql_field_authorization",
                "GraphQL field authorization may require role-aware comparison",
            ),
        ):
            add(
                _surface_hypothesis(
                    surface,
                    category=category,
                    title=title,
                    route=route,
                    rationale="A GraphQL operation was observed; no schema-wide amplification is proposed.",
                    impact="A controlled caller could receive an unauthorized object or protected field.",
                    context=("two controlled accounts", "captured bounded operation"),
                )
            )
        if str(operation.get("type") or "").lower() == "mutation":
            add(
                _surface_hypothesis(
                    surface,
                    category="graphql_mutation_authorization",
                    title="GraphQL mutation authorization may require a reversible controlled comparison",
                    route=route,
                    rationale="A captured GraphQL mutation was observed.",
                    impact="A lower-privileged controlled caller could perform a protected mutation.",
                    context=("two controlled accounts", "test-owned resource"),
                    safe=False,
                    risk=RiskLevel.moderate,
                    state_changing=True,
                )
            )

    if surface.uploads.get("surface_observed") or surface.uploads.get("observations"):
        for category, title, impact in (
            (
                "file_upload_validation",
                "Upload validation may require a harmless fixture comparison",
                "The service could accept a benign fixture that violates its documented MIME or extension policy.",
            ),
            (
                "upload_ownership",
                "Upload storage ownership may require controlled cross-account comparison",
                "One controlled user could retrieve another controlled user's uploaded fixture.",
            ),
        ):
            add(
                _surface_hypothesis(
                    surface,
                    category=category,
                    title=title,
                    rationale="An upload surface was observed; acceptance or storage weakness is not inferred.",
                    impact=impact,
                    context=("controlled account", "harmless text or image fixture"),
                    safe=False,
                    risk=RiskLevel.moderate,
                    state_changing=True,
                )
            )

    for workflow in surface.workflows:
        if workflow.get("semantic_domain") == "authentication":
            continue
        route = _workflow_evidence_route(workflow)
        if route is None:
            continue
        add(
            _surface_hypothesis(
                surface,
                category="business_logic_state_enforcement",
                title="Workflow state enforcement may require a controlled transition comparison",
                route=route,
                rationale="An ordered or explicitly state-changing workflow observation was recorded.",
                impact="A controlled user could skip a prerequisite, repeat a one-time action, or cross an account workflow boundary.",
                context=("controlled account", "test-owned workflow state"),
                safe=False,
                risk=RiskLevel.moderate,
                state_changing=True,
            )
        )
    return sorted(
        generated.values(), key=lambda item: (-item.priority, item.hypothesis_id)
    )


def generate_hypotheses(bundle: CaptureBundle) -> list[Hypothesis]:
    """Generate ranked, evidence-linked hypotheses without claiming findings."""
    hypotheses: dict[str, Hypothesis] = {}
    controlled_identities = [
        identity for identity in bundle.identities if identity.controlled
    ]
    for request in bundle.requests:
        path_words = {
            word for word in request.path.lower().replace("-", "_").split("/") if word
        }
        for parameter in request.parameters:
            name = _normalized_name(parameter)
            if name in OBJECT_HINTS or name.endswith("_id"):
                hypothesis = _make_hypothesis(
                    request,
                    "bola",
                    "Object-level authorization may depend on a client-controlled reference",
                    "An object identifier is present in a captured request and should be compared across known controlled identities and owned objects.",
                    parameter=parameter,
                    tools=("authorization_differential_tester",),
                    requirements=(
                        EvidenceRequirement(
                            kind="controlled_identity_differential",
                            minimum_repetitions=2,
                            description="Known owner and non-owner controlled identities receive repeatable object responses.",
                        ),
                    ),
                    requires_credentials=True,
                )
                if len(controlled_identities) < 2:
                    hypothesis.confidence = "low"
                    hypothesis.rationale += (
                        " Two controlled identities have not yet been confirmed."
                    )
                hypotheses[hypothesis.hypothesis_id] = hypothesis
                if "tenant" in name or "organization" in name or name == "org_id":
                    tenant = _make_hypothesis(
                        request,
                        "tenant_isolation",
                        "Tenant boundary may depend on a client-controlled identifier",
                        "A tenant or organization identifier is present and requires a controlled cross-tenant differential.",
                        parameter=parameter,
                        tools=("authorization_differential_tester",),
                        requirements=(
                            EvidenceRequirement(
                                kind="controlled_identity_differential",
                                minimum_repetitions=2,
                                description="Controlled accounts from distinct tenants produce a repeatable unauthorized success differential.",
                            ),
                        ),
                        requires_credentials=True,
                    )
                    hypotheses[tenant.hypothesis_id] = tenant
            if name in PRIVILEGE_HINTS and parameter.location in {
                "json",
                "form",
                "multipart",
                "graphql_variable",
            }:
                category = (
                    "property_authorization"
                    if name in {"owner_id", "tenant_id", "organization_id"}
                    else "mass_assignment"
                )
                mass = _make_hypothesis(
                    request,
                    category,
                    "Sensitive property may be client assignable",
                    "A privilege-, ownership-, or state-related property appears in a client-controlled request body.",
                    parameter=parameter,
                    tools=(
                        "request_replay_engine",
                        "authorization_differential_tester",
                    ),
                    requirements=(
                        EvidenceRequirement(
                            kind="response_differential",
                            minimum_repetitions=2,
                            description="A controlled, reversible property mutation is accepted and its effect is independently observed.",
                        ),
                        EvidenceRequirement(
                            kind="manual_confirmation",
                            description="The resource is researcher-owned and cleanup succeeded.",
                        ),
                    ),
                    requires_credentials=True,
                    risk=RiskLevel.moderate,
                    state_changing=True,
                )
                hypotheses[mass.hypothesis_id] = mass
            if name in SSRF_HINTS:
                ssrf = _make_hypothesis(
                    request,
                    "ssrf",
                    "Server-side URL processing may be reachable",
                    "A URL-like parameter is present; only a researcher-controlled callback can establish server-side interaction.",
                    parameter=parameter,
                    tools=("request_mutation_engine",),
                    requirements=(
                        EvidenceRequirement(
                            kind="oast_callback",
                            description="A unique per-request callback is observed by an authorized researcher-controlled service.",
                        ),
                    ),
                    requires_credentials=bool(request.identity_id),
                )
                hypotheses[ssrf.hypothesis_id] = ssrf
            if name in UPLOAD_HINTS or parameter.value_type == "file":
                upload = _make_hypothesis(
                    request,
                    "upload_security",
                    "File upload validation and authorization require verification",
                    "A multipart or file-like parameter was observed; verification must use a benign researcher-owned file and cleanup.",
                    parameter=parameter,
                    tools=("upload_security_planner", "upload_replay_checker"),
                    requirements=(
                        EvidenceRequirement(
                            kind="controlled_canary",
                            description="One benign, inert, researcher-owned file produces bounded validation/storage evidence.",
                        ),
                    ),
                    requires_credentials=bool(request.identity_id),
                    risk=RiskLevel.moderate,
                    state_changing=True,
                )
                hypotheses[upload.hypothesis_id] = upload
            if name in INJECTION_HINTS:
                injection = _make_hypothesis(
                    request,
                    "injection",
                    "Input may reach an unsafe interpreter or output context",
                    "The parameter is semantically relevant to bounded differential or canary-based verification.",
                    parameter=parameter,
                    tools=(
                        "authenticated_injection_verifier",
                        "request_mutation_engine",
                    ),
                    requirements=(
                        EvidenceRequirement(
                            kind="response_differential",
                            minimum_repetitions=2,
                            description="A repeatable control/test differential or unique canary proof is observed without extraction.",
                        ),
                    ),
                    requires_credentials=bool(request.identity_id),
                )
                hypotheses[injection.hypothesis_id] = injection
        if path_words & ACCOUNT_PATHS:
            category = (
                "oauth_oidc"
                if path_words & {"oauth", "authorize", "callback", "token"}
                else "account_lifecycle"
            )
            account = _make_hypothesis(
                request,
                category,
                "Account or federation lifecycle controls require stateful review",
                "The captured route participates in account, session, recovery, invitation, or OAuth/OIDC behavior.",
                tools=("workflow_model_builder", "business_logic_test_planner"),
                requirements=(
                    EvidenceRequirement(
                        kind="workflow_transition",
                        minimum_repetitions=2,
                        description="Expected and modified controlled workflow traces establish an enforcement differential.",
                    ),
                ),
                requires_credentials=bool(request.identity_id),
            )
            hypotheses[account.hypothesis_id] = account
        if request.identity_id and (
            path_words & ACCOUNT_PATHS
            or (request.response and request.response.sets_cookie)
        ):
            session = _make_hypothesis(
                request,
                "session_security",
                "Session lifecycle and binding controls require comparison",
                "A controlled authenticated capture participates in session issuance, use, rotation, recovery, or termination.",
                tools=("request_replay_engine", "workflow_model_builder"),
                requirements=(
                    EvidenceRequirement(
                        kind="controlled_identity_differential",
                        minimum_repetitions=2,
                        description="Controlled pre/post-login or pre/post-logout sessions establish rotation, invalidation, and identity binding.",
                    ),
                ),
                requires_credentials=True,
            )
            hypotheses[session.hypothesis_id] = session
        if path_words & PRIVILEGED_PATHS:
            vertical = _make_hypothesis(
                request,
                "vertical_authorization",
                "Role-level authorization may require a controlled privilege differential",
                "A privileged application area or role-management route was captured and should be compared using controlled lower- and higher-role identities.",
                tools=("authorization_differential_tester",),
                requirements=(
                    EvidenceRequirement(
                        kind="controlled_identity_differential",
                        minimum_repetitions=2,
                        description="Distinct controlled roles produce repeatable evidence of a lower role receiving privileged behavior.",
                    ),
                ),
                requires_credentials=True,
            )
            hypotheses[vertical.hypothesis_id] = vertical
        if "api" in path_words and request.identity_id:
            api_authz = _make_hypothesis(
                request,
                "api_authorization",
                "API operation may require role, action, or property authorization",
                "An authenticated API request was captured and can be compared across controlled identities without guessing routes.",
                tools=("authorization_differential_tester",),
                requirements=(
                    EvidenceRequirement(
                        kind="controlled_identity_differential",
                        minimum_repetitions=2,
                        description="Two known controlled identities establish repeatable API authorization behavior.",
                    ),
                ),
                requires_credentials=True,
            )
            hypotheses[api_authz.hypothesis_id] = api_authz
        if request.graphql_operation:
            gql = _make_hypothesis(
                request,
                "graphql_authorization",
                "GraphQL operation may require object and field authorization checks",
                "Captured GraphQL variables and operation metadata permit controlled authorization comparison without schema guessing.",
                tools=("graphql_query_analyzer", "graphql_authz_planner"),
                requirements=(
                    EvidenceRequirement(
                        kind="controlled_identity_differential",
                        minimum_repetitions=2,
                        description="Known controlled identities receive repeatable operation or field-level authorization differences.",
                    ),
                ),
                requires_credentials=True,
            )
            hypotheses[gql.hypothesis_id] = gql
        cache_headers = request.response.cache_headers if request.response else {}
        cache_control = cache_headers.get("cache-control", "").lower()
        cache_signal = (
            "public" in cache_control
            or "s-maxage" in cache_control
            or cache_headers.get("age", "0").strip("0")
            or "hit" in cache_headers.get("x-cache", "").lower()
            or "hit" in cache_headers.get("cf-cache-status", "").lower()
        )
        if request.identity_id and request.method == "GET" and cache_signal:
            cache = _make_hypothesis(
                request,
                "cache_security",
                "Authenticated response may interact with shared caching",
                "The authenticated GET response contains shared-cache or cache-hit indicators; controlled identity isolation and cache-key behavior require review.",
                tools=("request_replay_engine",),
                requirements=(
                    EvidenceRequirement(
                        kind="controlled_identity_differential",
                        minimum_repetitions=2,
                        description="Controlled identities and uncached/cache-hit controls establish whether personalized content crosses identity boundaries.",
                    ),
                ),
                requires_credentials=True,
            )
            hypotheses[cache.hypothesis_id] = cache
        if request.state_changing:
            workflow = _make_hypothesis(
                request,
                "business_logic",
                "State transition enforcement requires workflow comparison",
                "A state-changing request was captured; skipped, reordered, repeated, or cross-role transitions require controlled test-owned resources.",
                tools=("workflow_transition_analyzer", "business_logic_test_planner"),
                requirements=(
                    EvidenceRequirement(
                        kind="workflow_transition",
                        minimum_repetitions=2,
                        description="A normal controlled trace and one bounded modified trace establish the server-side transition behavior.",
                    ),
                ),
                requires_credentials=True,
                risk=RiskLevel.moderate,
                state_changing=True,
            )
            hypotheses[workflow.hypothesis_id] = workflow
    return sorted(
        hypotheses.values(), key=lambda item: (-item.priority, item.hypothesis_id)
    )


def propose_llm_hypotheses(
    bundle: CaptureBundle,
    llm: Callable[[str], str],
) -> list[Hypothesis]:
    """Accept only typed, evidence-linked advisory hypotheses from the model."""
    adapter = TypeAdapter(list[Hypothesis])
    request_ids = {request.request_id for request in bundle.requests}
    endpoints = {request.url for request in bundle.requests}
    context = {
        "capture_summary": bundle.summary(),
        "requests": [
            {
                "request_id": request.request_id,
                "method": request.method,
                "url": request.url,
                "path": request.path,
                "parameters": [
                    {
                        "name": parameter.name,
                        "location": parameter.location,
                        "value_type": parameter.value_type,
                    }
                    for parameter in request.parameters
                ],
                "body_type": request.body_type,
                "graphql_operation": request.graphql_operation,
                "state_changing": request.state_changing,
                "identity_context_present": bool(request.identity_id),
            }
            for request in bundle.requests[:200]
        ],
        "available_tools": sorted(TOOLS),
    }
    prompt = json.dumps(
        {
            "instruction": (
                "Return only a JSON array of evidence-linked vulnerability hypotheses. "
                "Do not authorize execution, invent evidence, or claim verification."
            ),
            "context": context,
            "schema": adapter.json_schema(),
        },
        separators=(",", ":"),
    )
    try:
        hypotheses = adapter.validate_json(llm(prompt))
    except (ValidationError, ValueError):
        return []
    accepted: list[Hypothesis] = []
    for hypothesis in hypotheses:
        if hypothesis.category not in CAPABILITY_REGISTRY:
            continue
        if hypothesis.status.value not in {"proposed", "policy_blocked"}:
            continue
        if hypothesis.target not in endpoints or (
            hypothesis.endpoint and hypothesis.endpoint not in endpoints
        ):
            continue
        if not set(hypothesis.evidence_refs) <= request_ids:
            continue
        if not set(hypothesis.proposed_tools) <= set(TOOLS):
            continue
        hypothesis.status = "proposed"
        hypothesis.metadata.update(capability_metadata(hypothesis.category))
        accepted.append(hypothesis)
    return accepted


def build_verification_plan(
    hypothesis: Hypothesis,
    *,
    profile: str,
    authorization_confirmed: bool,
    credentials_supplied: bool,
    controlled_accounts: list[str] | None = None,
    test_owned_resources: list[str] | None = None,
    request_budget: int = 20,
) -> VerificationPlan:
    capability = get_verification_capability(hypothesis.category)
    steps: list[VerificationStep] = []
    test_owned_resource_required = capability.requires_test_owned_resource
    canonical_cost = request_cost_for(hypothesis.category)
    for index, tool in enumerate(hypothesis.proposed_tools, 1):
        network = bool(
            capability.capability_state is CapabilityState.typed_verification
            and canonical_cost
        )
        request_cost = canonical_cost if index == 1 else 0
        steps.append(
            VerificationStep(
                step_id=stable_identifier(
                    "step", hypothesis.hypothesis_id, index, tool
                ),
                name=f"Evaluate {hypothesis.category} evidence with {tool}",
                tool=tool,
                input_ref=str(hypothesis.metadata.get("request_id") or "") or None,
                risk=hypothesis.risk,
                network=network,
                method=hypothesis.method if network else None,
                request_cost=request_cost,
                requires_credentials=capability.requires_credentials,
                state_changing=hypothesis.state_changing and network,
                test_owned_resource_required=test_owned_resource_required and network,
                cleanup_required=hypothesis.cleanup_required and network,
                cleanup_steps=(
                    [
                        "Restore or remove the researcher-owned test resource and verify cleanup."
                    ]
                    if hypothesis.cleanup_required and network
                    else []
                ),
                expected_evidence=hypothesis.evidence_requirements,
                stop_conditions=[
                    "Any scope or policy violation",
                    "Any unexpected state change",
                    "Any response suggesting instability or service degradation",
                    "Request budget exhaustion",
                ],
                metadata={
                    "category": hypothesis.category,
                    "parameter": hypothesis.parameter,
                    "parameter_location": hypothesis.parameter_location,
                    "capability_schema_version": CAPABILITY_SCHEMA_VERSION,
                    "capability_state": capability.capability_state.value,
                    "typed_adapter_required": (
                        capability.capability_state
                        is not CapabilityState.typed_verification
                    ),
                    "typed_executor_available": capability.executor_available,
                    "executor_version": capability.executor_version,
                    "min_requests": capability.min_requests,
                    "worst_case_requests": capability.worst_case_requests,
                },
            )
        )
    return VerificationPlan(
        plan_id=stable_identifier("plan", hypothesis.hypothesis_id, profile),
        hypothesis_id=hypothesis.hypothesis_id,
        target=hypothesis.endpoint or hypothesis.target,
        profile=profile,  # type: ignore[arg-type]
        steps=steps,
        request_budget=request_budget,
        authorization_confirmed=authorization_confirmed,
        credentials_supplied=credentials_supplied,
        controlled_accounts=controlled_accounts or [],
        test_owned_resources=test_owned_resources or [],
        test_owned_resources_required=test_owned_resource_required,
        automatic_execution_allowed=False,
        capability_schema_version=CAPABILITY_SCHEMA_VERSION,
        capability_state=capability.capability_state.value,
        typed_executor_available=capability.executor_available,
        executor_name=capability.executor_name,
        executor_version=capability.executor_version,
        input_schema=capability_metadata(hypothesis.category)["input_schema"],
        minimum_requests=capability.min_requests,
        worst_case_requests=capability.worst_case_requests,
        major_preconditions=capability_metadata(hypothesis.category)[
            "major_preconditions"
        ],
    )
