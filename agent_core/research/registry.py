"""Deterministic registry of typed Phase 4 experiment primitives."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from types import MappingProxyType
from pydantic import Field, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.research.primitives import (
    CleanupBehavior,
    PrimitiveCapabilityState,
    StateChangeBehavior,
    primitive_reference,
)
from agent_core.research.types import OpaqueIdentifier, ResearchContract, TargetClass

EXPERIMENT_REGISTRY_VERSION = "phase4-primitives-v1"


class PrimitiveDefinition(ResearchContract):
    name: OpaqueIdentifier
    version: OpaqueIdentifier
    input_schema_reference: OpaqueIdentifier
    output_type_reference: OpaqueIdentifier
    capability_state: PrimitiveCapabilityState
    minimum_requests: StrictInt = Field(ge=0, le=100)
    worst_case_requests: StrictInt = Field(ge=0, le=100)
    risk_class: RiskLevel
    allowed_target_classes: tuple[TargetClass, ...] = Field(min_length=1, max_length=3)
    context_requirements: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    state_change_behavior: StateChangeBehavior
    cleanup_behavior: CleanupBehavior
    executor_adapter_reference: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_definition(self) -> "PrimitiveDefinition":
        if self.worst_case_requests < self.minimum_requests:
            raise ValueError("primitive worst case must cover its minimum")
        available = (
            self.capability_state is PrimitiveCapabilityState.execution_available
        )
        if available != (self.executor_adapter_reference is not None):
            raise ValueError(
                "only execution-available primitives may declare an executor adapter"
            )
        if len(self.allowed_target_classes) != len(set(self.allowed_target_classes)):
            raise ValueError("allowed target classes must be unique")
        if len(self.context_requirements) != len(set(self.context_requirements)):
            raise ValueError("context requirements must be unique")
        if (
            self.state_change_behavior is StateChangeBehavior.always
            and self.cleanup_behavior is CleanupBehavior.not_required
        ):
            raise ValueError("always-state-changing primitives require cleanup")
        return self

    @property
    def registry_key(self) -> str:
        return primitive_reference(self.name, self.version)


class DuplicatePrimitiveError(ValueError):
    pass


class UnknownPrimitiveError(ValueError):
    pass


class ExperimentRegistry(Mapping[str, PrimitiveDefinition]):
    """A deterministic registry keyed by ``name@version``."""

    def __init__(
        self,
        definitions: Iterable[PrimitiveDefinition] = (),
        *,
        include_defaults: bool = True,
    ) -> None:
        self._definitions: dict[str, PrimitiveDefinition] = {}
        source = (*(_DEFAULT_DEFINITIONS if include_defaults else ()), *definitions)
        for definition in source:
            self.register(definition)

    def register(self, definition: PrimitiveDefinition) -> None:
        key = definition.registry_key
        if key in self._definitions:
            raise DuplicatePrimitiveError("duplicate primitive name and version")
        self._definitions[key] = definition

    def resolve(self, name: str, version: str = "1") -> PrimitiveDefinition:
        key = primitive_reference(name, version)
        try:
            return self._definitions[key]
        except KeyError as exc:
            raise UnknownPrimitiveError("unknown experiment primitive") from exc

    def __getitem__(self, key: str) -> PrimitiveDefinition:
        try:
            return self._definitions[key]
        except KeyError as exc:
            raise UnknownPrimitiveError("unknown experiment primitive") from exc

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._definitions))

    def __len__(self) -> int:
        return len(self._definitions)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._definitions

    @property
    def definitions(self) -> tuple[PrimitiveDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))

    @property
    def by_key(self) -> Mapping[str, PrimitiveDefinition]:
        return MappingProxyType(dict(sorted(self._definitions.items())))

    @property
    def version(self) -> str:
        return EXPERIMENT_REGISTRY_VERSION

    @property
    def fingerprint(self) -> str:
        payload = [item.model_dump(mode="json") for item in self.definitions]
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


_ALL_TARGETS = (
    TargetClass.external,
    TargetClass.local_range,
    TargetClass.dedicated_lab,
)


def _definition(
    name: str,
    input_model: str,
    output_model: str,
    *,
    state: PrimitiveCapabilityState,
    minimum: int,
    worst: int,
    risk: RiskLevel,
    requirements: tuple[str, ...] = (),
    state_change: StateChangeBehavior = StateChangeBehavior.never,
    cleanup: CleanupBehavior = CleanupBehavior.not_required,
) -> PrimitiveDefinition:
    return PrimitiveDefinition(
        name=name,
        version="1",
        input_schema_reference=f"research.primitives:{input_model}",
        output_type_reference=f"research.primitives:{output_model}",
        capability_state=state,
        minimum_requests=minimum,
        worst_case_requests=worst,
        risk_class=risk,
        allowed_target_classes=_ALL_TARGETS,
        context_requirements=requirements,
        state_change_behavior=state_change,
        cleanup_behavior=cleanup,
    )


_DEFAULT_DEFINITIONS = (
    _definition(
        "request_replay",
        "RequestReplayInput",
        "ReplayEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=1,
        risk=RiskLevel.low,
        requirements=("registered_request_template",),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "identity_switch",
        "IdentitySwitchInput",
        "ContextEvidence",
        state=PrimitiveCapabilityState.defined,
        minimum=0,
        worst=0,
        risk=RiskLevel.passive,
        requirements=("controlled_identity_pair",),
    ),
    _definition(
        "parameter_mutation",
        "ParameterMutationInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=3,
        risk=RiskLevel.moderate,
        requirements=("registered_request_template", "registered_parameter"),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "object_substitution",
        "ObjectSubstitutionInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=2,
        worst=5,
        risk=RiskLevel.low,
        requirements=(
            "controlled_identity_pair",
            "test_owned_object",
            "ownership_evidence",
        ),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "header_mutation",
        "HeaderMutationInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=1,
        risk=RiskLevel.low,
        requirements=("registered_safe_header",),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "cookie_mutation",
        "CookieMutationInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=1,
        risk=RiskLevel.moderate,
        requirements=("controlled_session",),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "response_differential",
        "ResponseDifferentialInput",
        "DifferentialEvidence",
        state=PrimitiveCapabilityState.defined,
        minimum=0,
        worst=0,
        risk=RiskLevel.passive,
        requirements=("recorded_evidence_or_outcome",),
    ),
    _definition(
        "state_differential",
        "StateDifferentialInput",
        "StateChangeEvidence",
        state=PrimitiveCapabilityState.defined,
        minimum=0,
        worst=0,
        risk=RiskLevel.passive,
        requirements=("registered_state_references",),
    ),
    _definition(
        "graphql_operation",
        "GraphQLOperationInput",
        "ReplayEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=1,
        risk=RiskLevel.low,
        requirements=("registered_graphql_operation",),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "graphql_variable_mutation",
        "GraphQLVariableMutationInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=3,
        risk=RiskLevel.moderate,
        requirements=("registered_graphql_operation", "registered_parameter"),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    _definition(
        "token_mutation",
        "TokenMutationInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=1,
        worst=1,
        risk=RiskLevel.moderate,
        requirements=("controlled_token",),
        state_change=StateChangeBehavior.method_dependent,
        cleanup=CleanupBehavior.method_dependent,
    ),
    *(
        _definition(
            name,
            "WorkflowPrimitiveInput",
            "MutationEvidence",
            state=PrimitiveCapabilityState.compile_only,
            minimum=1,
            worst=5,
            risk=RiskLevel.moderate,
            requirements=("registered_workflow",),
            state_change=StateChangeBehavior.method_dependent,
            cleanup=CleanupBehavior.method_dependent,
        )
        for name in ("workflow_step_replay", "workflow_step_skip", "workflow_reorder")
    ),
    _definition(
        "upload_variant",
        "UploadVariantInput",
        "MutationEvidence",
        state=PrimitiveCapabilityState.compile_only,
        minimum=2,
        worst=4,
        risk=RiskLevel.moderate,
        requirements=("registered_test_owned_upload",),
        state_change=StateChangeBehavior.always,
        cleanup=CleanupBehavior.required,
    ),
)

DEFAULT_EXPERIMENT_REGISTRY = ExperimentRegistry()
