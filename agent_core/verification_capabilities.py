"""Authoritative Phase 2 verification capability and request-cost registry.

This registry describes active implementation contracts.  It is intentionally
separate from the quarantined legacy ``verification_registry`` module.
"""

from __future__ import annotations

from enum import Enum
from importlib import import_module
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from agent_core.agent_models import StrictModel
from agent_core.rate_limit_enforcement import MAX_RATE_LIMIT_ATTEMPTS
from agent_core.result_provenance import ExecutorProvenance

CAPABILITY_SCHEMA_VERSION = 1
PLAN_ONLY_VERIFICATION_REASON = (
    "This hypothesis is plan-only; no typed verification adapter is available."
)


class CapabilityState(str, Enum):
    discovery_only = "discovery_only"
    plan_only = "plan_only"
    typed_verification = "typed_verification"


class CompatibilityStatus(str, Enum):
    current = "current"
    legacy_broad_category = "legacy_broad_category"


class VerificationCapability(StrictModel):
    """One immutable, strict declaration of implemented category behavior."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        strict=True,
        frozen=True,
    )

    category: StrictStr = Field(min_length=2, max_length=100)
    capability_state: CapabilityState
    executor_name: StrictStr | None = None
    executor_version: StrictStr | None = None
    executor_reference: StrictStr | None = None
    input_schema: StrictStr | None = None
    planning_schema: StrictStr | None = "agent_core.agent_models:VerificationPlan"
    automatic_execution: StrictBool
    requires_credentials: StrictBool
    required_account_count: StrictInt = Field(ge=0, le=2)
    requires_test_owned_resource: StrictBool
    state_changing: StrictBool
    requires_state_change_policy: StrictBool
    cleanup_required: StrictBool
    dedicated_lab_only: StrictBool
    lab_only: StrictBool
    oast_required: StrictBool
    min_requests: StrictInt = Field(ge=0, le=100)
    worst_case_requests: StrictInt = Field(ge=0, le=100)
    multi_stage: StrictBool
    supported_methods: tuple[StrictStr, ...] = ()
    supported_parameter_locations: tuple[StrictStr, ...] = ()
    parameter_binding_required: StrictBool = False
    legacy_request_body_is_json: StrictBool = False
    allowed_target_classes: tuple[
        Literal["external", "local_range", "dedicated_lab"], ...
    ] = ("external", "local_range", "dedicated_lab")
    required_policy_opt_in: StrictStr | None = None
    optional_request_components: Mapping[StrictStr, StrictInt] = Field(
        default_factory=dict
    )
    per_stage_request_costs: Mapping[StrictStr, StrictInt] = Field(default_factory=dict)
    request_cost_formula: StrictStr | None = None
    compatibility_status: CompatibilityStatus = CompatibilityStatus.current
    notes: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def validate_contract(self) -> VerificationCapability:
        if self.worst_case_requests < self.min_requests:
            raise ValueError("worst_case_requests must be >= min_requests")
        typed = self.capability_state is CapabilityState.typed_verification
        route_fields = (
            self.executor_name,
            self.executor_version,
            self.executor_reference,
            self.input_schema,
        )
        if typed and any(value is None for value in route_fields):
            raise ValueError(
                "typed_verification requires an executor, version, route, and input schema"
            )
        if not typed and any(value is not None for value in route_fields):
            raise ValueError(
                "non-typed capabilities cannot declare an active typed route"
            )
        if not typed and self.automatic_execution:
            raise ValueError("non-typed capabilities cannot execute automatically")
        if not typed and (self.min_requests or self.worst_case_requests):
            raise ValueError(
                "non-typed capabilities cannot claim executable network requests"
            )
        if self.dedicated_lab_only and self.allowed_target_classes != (
            "dedicated_lab",
        ):
            raise ValueError(
                "dedicated_lab_only requires exactly the dedicated_lab target class"
            )
        if self.lab_only and "external" in self.allowed_target_classes:
            raise ValueError("lab_only capabilities cannot allow external targets")
        return self

    @property
    def executor_available(self) -> bool:
        return self.executor_reference is not None

    @property
    def input_schema_name(self) -> str | None:
        return self.input_schema.rsplit(":", 1)[-1] if self.input_schema else None


_EXECUTOR_REFERENCE = "agent_core.controlled_executor:ControlledVerificationExecutor"


def _typed(
    category: str,
    schema: str,
    *,
    min_requests: int,
    worst_case_requests: int,
    requires_credentials: bool,
    required_account_count: int,
    requires_test_owned_resource: bool = False,
    state_changing: bool = False,
    requires_state_change_policy: bool | None = None,
    cleanup_required: bool = False,
    lab_only: bool = False,
    multi_stage: bool = False,
    supported_methods: tuple[str, ...] = (),
    supported_parameter_locations: tuple[str, ...] = (),
    parameter_binding_required: bool = False,
    legacy_request_body_is_json: bool = False,
    required_policy_opt_in: str | None = None,
    optional_request_components: Mapping[str, int] | None = None,
    per_stage_request_costs: Mapping[str, int] | None = None,
    request_cost_formula: str | None = None,
    notes: tuple[str, ...] = (),
) -> VerificationCapability:
    allowed_targets: tuple[Literal["external", "local_range", "dedicated_lab"], ...]
    allowed_targets = (
        ("local_range", "dedicated_lab")
        if lab_only
        else ("external", "local_range", "dedicated_lab")
    )
    provenance = ExecutorProvenance(
        name="ControlledVerificationExecutor",
        version=f"{category}/v1",
        implementation_family="phase2_controlled_execution",
    ).model_dump(mode="json")
    return VerificationCapability(
        category=category,
        capability_state=CapabilityState.typed_verification,
        executor_name=provenance["name"],
        executor_version=provenance["version"],
        executor_reference=_EXECUTOR_REFERENCE,
        input_schema=schema,
        automatic_execution=True,
        requires_credentials=requires_credentials,
        required_account_count=required_account_count,
        requires_test_owned_resource=requires_test_owned_resource,
        state_changing=state_changing,
        requires_state_change_policy=(
            state_changing
            if requires_state_change_policy is None
            else requires_state_change_policy
        ),
        cleanup_required=cleanup_required,
        dedicated_lab_only=False,
        lab_only=lab_only,
        oast_required=False,
        min_requests=min_requests,
        worst_case_requests=worst_case_requests,
        multi_stage=multi_stage,
        supported_methods=supported_methods,
        supported_parameter_locations=supported_parameter_locations,
        parameter_binding_required=parameter_binding_required,
        legacy_request_body_is_json=legacy_request_body_is_json,
        allowed_target_classes=allowed_targets,
        required_policy_opt_in=required_policy_opt_in,
        optional_request_components=dict(optional_request_components or {}),
        per_stage_request_costs=dict(per_stage_request_costs or {}),
        request_cost_formula=request_cost_formula,
        notes=notes,
    )


def _plan_only(
    category: str,
    *,
    requires_credentials: bool = False,
    required_account_count: int = 0,
    requires_test_owned_resource: bool = False,
    state_changing: bool = False,
    cleanup_required: bool = False,
    oast_required: bool = False,
    compatibility_status: CompatibilityStatus = CompatibilityStatus.current,
    notes: tuple[str, ...] = (),
) -> VerificationCapability:
    return VerificationCapability(
        category=category,
        capability_state=CapabilityState.plan_only,
        automatic_execution=False,
        requires_credentials=requires_credentials,
        required_account_count=required_account_count,
        requires_test_owned_resource=requires_test_owned_resource,
        state_changing=state_changing,
        requires_state_change_policy=False,
        cleanup_required=cleanup_required,
        dedicated_lab_only=False,
        lab_only=False,
        oast_required=oast_required,
        min_requests=0,
        worst_case_requests=0,
        multi_stage=False,
        compatibility_status=compatibility_status,
        notes=(
            "Bounded manual planning guidance is available; no typed request sequence is executable.",
            *notes,
        ),
    )


_CAPABILITIES = (
    _typed(
        "bola",
        "agent_core.controlled_executor:BOLAVerificationInput",
        min_requests=2,
        worst_case_requests=5,
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        supported_methods=("GET",),
        supported_parameter_locations=("path", "query"),
        optional_request_components={
            "controlled_session_acquisition": 2,
            "owned_object_acquisition": 1,
        },
        notes=(
            "Two distinct controlled accounts and an exactly owner-bound object remain mandatory.",
        ),
    ),
    _typed(
        "vertical_authorization",
        "agent_core.controlled_executor:VerticalAuthorizationVerificationInput",
        min_requests=2,
        worst_case_requests=4,
        requires_credentials=True,
        required_account_count=2,
        supported_methods=("GET",),
        optional_request_components={"controlled_session_acquisition": 2},
        notes=(
            "The two controlled accounts require recognized, distinct privilege roles.",
        ),
    ),
    _typed(
        "tenant_isolation",
        "agent_core.controlled_executor:TenantIsolationVerificationInput",
        min_requests=2,
        worst_case_requests=5,
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        supported_methods=("GET",),
        supported_parameter_locations=("path", "query"),
        optional_request_components={
            "controlled_session_acquisition": 2,
            "owned_object_acquisition": 1,
        },
        notes=(
            "Both controlled accounts require distinct tenant metadata and exact object consistency.",
        ),
    ),
    _typed(
        "mass_assignment",
        "agent_core.controlled_executor:MassAssignmentVerificationInput",
        min_requests=5,
        worst_case_requests=6,
        requires_credentials=True,
        required_account_count=1,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
        lab_only=True,
        supported_methods=("GET", "PATCH"),
        supported_parameter_locations=("json",),
        parameter_binding_required=True,
        legacy_request_body_is_json=True,
        optional_request_components={"controlled_session_acquisition": 1},
        notes=(
            "One JSON scalar field is tested through the exact GET/PATCH/GET/PATCH/GET restore workflow.",
        ),
    ),
    _plan_only(
        "property_authorization",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _typed(
        "authentication_enforcement",
        "agent_core.controlled_executor:AuthenticationEnforcementVerificationInput",
        min_requests=2,
        worst_case_requests=3,
        requires_credentials=True,
        required_account_count=1,
        supported_methods=("GET",),
        optional_request_components={"controlled_session_acquisition": 1},
    ),
    _plan_only(
        "session_security",
        requires_credentials=True,
        required_account_count=1,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "oauth_oidc",
        requires_credentials=True,
        required_account_count=1,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _typed(
        "session_invalidation",
        "agent_core.controlled_executor:SessionInvalidationVerificationInput",
        min_requests=4,
        worst_case_requests=4,
        requires_credentials=True,
        required_account_count=1,
        state_changing=True,
        cleanup_required=True,
        supported_methods=("GET", "HEAD", "OPTIONS", "POST", "DELETE"),
        per_stage_request_costs={
            "session_acquisition": 1,
            "authenticated_baseline": 1,
            "session_termination": 1,
            "same_session_replay": 1,
        },
    ),
    _typed(
        "recovery_state_enforcement",
        "agent_core.recovery_state_enforcement:RecoveryVerificationInput",
        min_requests=1,
        worst_case_requests=5,
        requires_credentials=True,
        required_account_count=1,
        state_changing=True,
        cleanup_required=True,
        multi_stage=True,
        supported_methods=("POST",),
        per_stage_request_costs={
            "issue_challenge": 1,
            "resume_with_controlled_evidence": 3,
            "confirm_external_cleanup": 1,
        },
        request_cost_formula="1 challenge + 2 completion + 1 auth confirmation + 1 cleanup confirmation",
    ),
    _plan_only(
        "account_lifecycle",
        requires_credentials=True,
        required_account_count=1,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "jwt_enforcement",
        requires_credentials=True,
        required_account_count=1,
    ),
    _plan_only(
        "graphql_mutation_authorization",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
    ),
    _typed(
        "rate_limit_enforcement",
        "agent_core.rate_limit_enforcement:RateLimitVerificationInput",
        min_requests=3,
        worst_case_requests=MAX_RATE_LIMIT_ATTEMPTS + 2,
        requires_credentials=True,
        required_account_count=1,
        state_changing=True,
        requires_state_change_policy=False,
        supported_methods=("POST",),
        required_policy_opt_in="bounded_rate_limit_verification",
        per_stage_request_costs={
            "valid_baseline": 1,
            "invalid_attempts_minimum": 1,
            "valid_final": 1,
        },
        request_cost_formula="N + 2 where 1 <= N <= 5",
        notes=(
            "Only sequential authentication-login checks are supported; recovery-rate checks remain plan-only.",
        ),
    ),
    _plan_only(
        "graphql_object_authorization",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
    ),
    _plan_only(
        "graphql_field_authorization",
        requires_credentials=True,
        required_account_count=2,
    ),
    _plan_only(
        "business_logic",
        requires_credentials=True,
        required_account_count=1,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "business_logic_state_enforcement",
        requires_credentials=True,
        required_account_count=1,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
    ),
    _plan_only(
        "api_authorization",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "graphql_authorization",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only("excessive_data_exposure"),
    _plan_only(
        "ssrf",
        requires_test_owned_resource=True,
        oast_required=True,
    ),
    _plan_only(
        "upload_ownership",
        requires_credentials=True,
        required_account_count=2,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
    ),
    _typed(
        "sql_injection",
        "agent_core.controlled_executor:SQLInjectionVerificationInput",
        min_requests=3,
        worst_case_requests=4,
        requires_credentials=False,
        required_account_count=0,
        lab_only=True,
        supported_methods=("GET",),
        supported_parameter_locations=("query",),
        parameter_binding_required=True,
        optional_request_components={"controlled_session_acquisition": 1},
        notes=(
            "Only the fixed three-request, query-parameter, inert lab probe is implemented.",
        ),
    ),
    _typed(
        "command_injection",
        "agent_core.controlled_executor:CommandInjectionVerificationInput",
        min_requests=3,
        worst_case_requests=4,
        requires_credentials=False,
        required_account_count=0,
        lab_only=True,
        supported_methods=("GET",),
        supported_parameter_locations=("query",),
        parameter_binding_required=True,
        optional_request_components={"controlled_session_acquisition": 1},
        notes=(
            "Only the fixed three-request, query-parameter, synthetic-fixture lab probe is implemented.",
        ),
    ),
    _typed(
        "path_traversal",
        "agent_core.controlled_executor:PathTraversalVerificationInput",
        min_requests=3,
        worst_case_requests=4,
        requires_credentials=False,
        required_account_count=0,
        lab_only=True,
        supported_methods=("GET",),
        supported_parameter_locations=("query",),
        parameter_binding_required=True,
        optional_request_components={"controlled_session_acquisition": 1},
        notes=(
            "Only the fixed three-request, query-parameter, synthetic-fixture lab probe is implemented.",
        ),
    ),
    _plan_only(
        "upload_security",
        requires_credentials=True,
        required_account_count=1,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "file_upload_validation",
        requires_credentials=True,
        required_account_count=1,
        requires_test_owned_resource=True,
        state_changing=True,
        cleanup_required=True,
    ),
    _plan_only(
        "injection",
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
    _plan_only(
        "cache_security",
        requires_credentials=True,
        required_account_count=2,
        compatibility_status=CompatibilityStatus.legacy_broad_category,
    ),
)

if len({item.category for item in _CAPABILITIES}) != len(_CAPABILITIES):
    raise RuntimeError("Phase 2 capability categories must be unique.")

CAPABILITY_REGISTRY: Mapping[str, VerificationCapability] = MappingProxyType(
    {item.category: item for item in _CAPABILITIES}
)
TYPED_VERIFICATION_CATEGORIES = frozenset(
    category
    for category, capability in CAPABILITY_REGISTRY.items()
    if capability.capability_state is CapabilityState.typed_verification
)


def get_verification_capability(category: str) -> VerificationCapability:
    try:
        return CAPABILITY_REGISTRY[category]
    except KeyError as exc:
        raise ValueError(f"Unknown Phase 2 category: {category}.") from exc


def _resolve_reference(reference: str) -> Any:
    module_name, attribute_name = reference.split(":", 1)
    return getattr(import_module(module_name), attribute_name)


def resolve_verification_input_schema(category: str) -> type[StrictModel] | None:
    capability = get_verification_capability(category)
    if capability.input_schema is None:
        return None
    model = _resolve_reference(capability.input_schema)
    if not isinstance(model, type) or not issubclass(model, StrictModel):
        raise RuntimeError(f"Capability schema for {category} is not a StrictModel.")
    return model


def resolve_verification_executor(category: str) -> type[Any] | None:
    capability = get_verification_capability(category)
    if capability.executor_reference is None:
        return None
    executor = _resolve_reference(capability.executor_reference)
    if not isinstance(executor, type):
        raise RuntimeError(f"Capability executor for {category} is not a class.")
    return executor


def plan_only_command_metadata(category: str, hypothesis_id: str) -> dict[str, Any]:
    """Return non-result metadata for an unavailable typed verification route."""

    capability = get_verification_capability(category)
    if capability.capability_state is not CapabilityState.plan_only:
        raise ValueError(f"Phase 2 category is not plan-only: {category}.")
    return {
        "success": False,
        "hypothesis_id": str(hypothesis_id),
        "category": category,
        "capability_state": CapabilityState.plan_only.value,
        "typed_verification_available": False,
        "verification_result_created": False,
        "requests_used": 0,
        "reasons": [PLAN_ONLY_VERIFICATION_REASON],
    }


def typed_producer_provenance(category: str) -> dict[str, str]:
    """Resolve exact producer metadata only for a complete typed registry route."""

    capability = get_verification_capability(category)
    if capability.capability_state is not CapabilityState.typed_verification:
        raise ValueError(
            f"Phase 2 category has no typed verification route: {category}."
        )
    executor = resolve_verification_executor(category)
    schema = resolve_verification_input_schema(category)
    if executor is None or schema is None:
        raise ValueError(f"Typed verification route is incomplete: {category}.")
    if executor.__name__ != capability.executor_name:
        raise ValueError(
            f"Typed verification executor contract is invalid: {category}."
        )
    return ExecutorProvenance(
        name=str(capability.executor_name),
        version=str(capability.executor_version),
        implementation_family="phase2_controlled_execution",
    ).model_dump(mode="json")


def validate_typed_producer_provenance(category: str, value: Any) -> dict[str, str]:
    """Validate caller-supplied producer metadata against the typed registry."""

    expected = typed_producer_provenance(category)
    try:
        supplied = ExecutorProvenance.model_validate(value).model_dump(mode="json")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "New typed result requires valid producer provenance."
        ) from exc
    if supplied["name"] != expected["name"]:
        raise ValueError("New typed result executor name does not match the registry.")
    if supplied["version"] != expected["version"]:
        raise ValueError(
            "New typed result executor version does not match the registry."
        )
    if supplied["implementation_family"] != expected["implementation_family"]:
        raise ValueError(
            "New typed result implementation family does not match the registry."
        )
    return supplied


def request_cost_for(
    category: str,
    *,
    rate_limit_attempts: int | None = None,
    recovery_phase: str | None = None,
) -> int:
    """Return a registry-bound cost, optionally narrowed by typed runtime input."""

    capability = get_verification_capability(category)
    if category == "rate_limit_enforcement" and rate_limit_attempts is not None:
        if (
            isinstance(rate_limit_attempts, bool)
            or not isinstance(rate_limit_attempts, int)
            or not 1 <= rate_limit_attempts <= MAX_RATE_LIMIT_ATTEMPTS
        ):
            raise ValueError("Rate-limit attempts must be between 1 and 5.")
        return rate_limit_attempts + 2
    if category == "recovery_state_enforcement" and recovery_phase is not None:
        try:
            return int(capability.per_stage_request_costs[recovery_phase])
        except KeyError as exc:
            raise ValueError("Unsupported recovery execution phase.") from exc
    return capability.worst_case_requests


def capability_support_reasons(
    category: str,
    *,
    method: str | None,
    parameter: str | None,
    parameter_location: str | None,
    request_body_field: bool = False,
    target_class: str | None = None,
) -> list[str]:
    """Explain why an observed surface is outside a typed registry contract."""

    capability = get_verification_capability(category)
    reasons: list[str] = []
    normalized_method = str(method or "").upper()
    if capability.supported_methods and normalized_method not in set(
        capability.supported_methods
    ):
        reasons.append(
            "The observed HTTP method is not supported by this typed capability."
        )
    if capability.parameter_binding_required:
        implicit_json = bool(
            capability.legacy_request_body_is_json
            and parameter
            and request_body_field
            and parameter_location is None
        )
        if not parameter or (parameter_location is None and not implicit_json):
            reasons.append(
                "A discovered parameter and supported parameter location are required by this typed capability."
            )
        elif not implicit_json and parameter_location not in set(
            capability.supported_parameter_locations
        ):
            reasons.append(
                "The observed parameter location is not supported by this typed capability."
            )
    elif (
        capability.supported_parameter_locations
        and parameter_location is not None
        and parameter_location not in set(capability.supported_parameter_locations)
    ):
        reasons.append(
            "The observed parameter location is not supported by this typed capability."
        )
    if (
        target_class is not None
        and target_class not in capability.allowed_target_classes
    ):
        reasons.append("This typed capability is restricted to an explicit lab target.")
    return reasons


def capability_metadata(
    category: str, *, typed_route_supported: bool = True
) -> dict[str, Any]:
    capability = get_verification_capability(category)
    typed_route_available = bool(
        typed_route_supported
        and capability.capability_state is CapabilityState.typed_verification
    )
    preconditions = [
        *(
            [f"{capability.required_account_count} controlled account(s)"]
            if capability.required_account_count
            else []
        ),
        *(["controlled credentials"] if capability.requires_credentials else []),
        *(["test-owned resource"] if capability.requires_test_owned_resource else []),
        *(["mandatory cleanup"] if capability.cleanup_required else []),
        *(["explicit local or dedicated lab"] if capability.lab_only else []),
        *(["authorized OAST service"] if capability.oast_required else []),
        *(
            [f"policy opt-in: {capability.required_policy_opt_in}"]
            if capability.required_policy_opt_in
            else []
        ),
        *(
            ["methods: " + ", ".join(capability.supported_methods)]
            if capability.supported_methods
            else []
        ),
        *(
            [
                "parameter locations: "
                + ", ".join(capability.supported_parameter_locations)
            ]
            if capability.supported_parameter_locations
            else []
        ),
        *capability.notes,
    ]
    return {
        "capability_schema_version": CAPABILITY_SCHEMA_VERSION,
        "capability_state": capability.capability_state.value,
        "typed_executor_available": bool(
            capability.executor_available and typed_route_supported
        ),
        "typed_route_supported": typed_route_supported,
        "automatic_execution": capability.automatic_execution,
        "automatic_execution_allowed": bool(
            capability.automatic_execution and typed_route_supported
        ),
        "executor_name": capability.executor_name,
        "executor_version": capability.executor_version,
        "input_schema": (
            f"{category}/strict-v1" if capability.input_schema is not None else None
        ),
        "min_requests": capability.min_requests,
        "worst_case_requests": capability.worst_case_requests,
        "estimated_requests": capability.worst_case_requests,
        "execution_status": (
            "typed_verification_available"
            if typed_route_available
            else (
                "plan_only_surface"
                if capability.capability_state is CapabilityState.typed_verification
                else capability.capability_state.value
            )
        ),
        "typed_adapter_required": not typed_route_available,
        "major_preconditions": preconditions,
    }


def render_capability_markdown_table() -> str:
    """Render the compact documentation table from the authoritative registry."""

    rows = [
        "| Category | State | Executor | Auto | Accounts | Credentials | Test-owned | State / cleanup | Requests | Methods | Locations |",
        "|---|---|---|---:|---:|---:|---:|---|---:|---|---|",
    ]
    for capability in CAPABILITY_REGISTRY.values():
        rows.append(
            "| "
            + " | ".join(
                (
                    f"`{capability.category}`",
                    f"`{capability.capability_state.value}`",
                    capability.executor_name or "none",
                    "yes" if capability.automatic_execution else "no",
                    str(capability.required_account_count),
                    "yes" if capability.requires_credentials else "no",
                    "yes" if capability.requires_test_owned_resource else "no",
                    ("yes" if capability.state_changing else "no")
                    + " / "
                    + ("yes" if capability.cleanup_required else "no"),
                    f"{capability.min_requests}–{capability.worst_case_requests}",
                    ", ".join(capability.supported_methods) or "none",
                    ", ".join(capability.supported_parameter_locations) or "none",
                )
            )
            + " |"
        )
    return "\n".join(rows)
