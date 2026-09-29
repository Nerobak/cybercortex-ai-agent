"""Deterministic, provider-neutral compiler for security experiment proposals.

This module resolves references and derives bounded metadata.  It deliberately
has no transport, provider, policy authorization, or executor dependency.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable, Mapping

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.research.experiments import (
    Baseline,
    BaselineKind,
    CapabilityRef,
    CleanupPlan,
    ControlledMutation,
    EvidenceRequirement,
    ExperimentProposal,
    ExperimentProvenance,
    IdentityContext,
    Preconditions,
    Precondition,
    PreconditionCode,
    RequestEstimate,
    RiskClassification,
    SecurityExperiment,
    StopCondition,
    StopConditionCode,
    StopConditions,
    TypedTargetReference,
)
from agent_core.research.fingerprint import experiment_fingerprint
from agent_core.research.graphql import (
    GraphQLArgumentRecord,
    GraphQLAuthenticationRequirement,
    GraphQLCandidateKind,
    GraphQLExperimentStateChangeClass,
    GraphQLFieldRecord,
    GraphQLOperationRecord,
    GraphQLStateChangeClass,
    GraphQLSurface,
    GraphQLVariableBinding,
    GraphQLVariableRecord,
    GraphQLVariableValueSource,
    RegisteredGraphQLOperationTemplate,
    RegisteredGraphQLSafeMutation,
)
from agent_core.research.primitives import (
    AuthenticationDifferentialInput,
    CompiledPrimitiveStep,
    CookieMutationInput,
    GraphQLOperationInput,
    GraphQLVariableMutationInput,
    HeaderMutationInput,
    IdentityRelationship,
    IdentitySwitchInput,
    ObjectSubstitutionInput,
    ParameterMutationInput,
    PrimitiveCapabilityState,
    PrimitiveInput,
    RequestReplayInput,
    ResponseDifferentialInput,
    StateChangeBehavior,
    StateDifferentialInput,
    TokenMutationInput,
    UploadVariantInput,
    WorkflowPrimitiveInput,
)
from agent_core.research.registry import ExperimentRegistry
from agent_core.research.state import (
    Endpoint,
    GraphQLOperation,
    Identity,
    Parameter,
    ResearchObject,
    ResearchState,
    SessionRef,
)
from agent_core.research.types import (
    EndpointId,
    HttpMethod,
    IdentityEligibility,
    OpaqueIdentifier,
    ParameterId,
    ResearchContract,
    SessionLifecycle,
    SurfaceId,
    TargetAssetId,
    TargetClass,
    Timestamp,
    TokenLifecycle,
)
from agent_core.verification_capabilities import (
    ResearchExperimentCapabilityAdapter,
    get_research_experiment_capability_adapter,
)

EXPERIMENT_COMPILER_VERSION = "phase4-experiment-compiler-v1"
DEFAULT_EXPERIMENT_TTL_SECONDS = 900
DEFAULT_MAX_RESPONSE_BYTES = 2_000_000

_SAFE_METHODS = frozenset({HttpMethod.get, HttpMethod.head, HttpMethod.options})
_CREDENTIAL_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "api-key",
        "apikey",
        "x-api-key",
    }
)
_RISK_ORDER = {
    RiskLevel.passive: 0,
    RiskLevel.low: 1,
    RiskLevel.moderate: 2,
    RiskLevel.high: 3,
    RiskLevel.prohibited: 4,
}


class CompilerErrorCode(str, Enum):
    invalid_proposal = "invalid_proposal"
    research_mismatch = "research_mismatch"
    stale_state_revision = "stale_state_revision"
    expired_proposal = "expired_proposal"
    unknown_hypothesis = "unknown_hypothesis"
    unknown_capability = "unknown_capability"
    unknown_primitive = "unknown_primitive"
    primitive_not_execution_available = "primitive_not_execution_available"
    target_class_not_allowed = "target_class_not_allowed"
    unknown_target = "unknown_target"
    unknown_surface = "unknown_surface"
    unknown_endpoint = "unknown_endpoint"
    unknown_parameter = "unknown_parameter"
    unknown_operation = "unknown_operation"
    unknown_graphql_operation_template = "unknown_graphql_operation_template"
    unknown_graphql_surface = "unknown_graphql_surface"
    unknown_graphql_field = "unknown_graphql_field"
    unknown_graphql_argument = "unknown_graphql_argument"
    unknown_graphql_variable = "unknown_graphql_variable"
    unknown_graphql_safe_mutation = "unknown_graphql_safe_mutation"
    graphql_template_mismatch = "graphql_template_mismatch"
    graphql_binding_mismatch = "graphql_binding_mismatch"
    graphql_selection_invalid = "graphql_selection_invalid"
    graphql_state_change_disallowed = "graphql_state_change_disallowed"
    unknown_identity = "unknown_identity"
    uncontrolled_identity = "uncontrolled_identity"
    ineligible_identity = "ineligible_identity"
    unknown_session = "unknown_session"
    inactive_session = "inactive_session"
    unknown_token = "unknown_token"
    inactive_token = "inactive_token"
    unknown_object = "unknown_object"
    unowned_object = "unowned_object"
    unknown_request_template = "unknown_request_template"
    unknown_value_source = "unknown_value_source"
    unknown_safe_header = "unknown_safe_header"
    credential_header_prohibited = "credential_header_prohibited"
    unknown_evidence = "unknown_evidence"
    unknown_provenance = "unknown_provenance"
    unknown_outcome = "unknown_outcome"
    unknown_state_reference = "unknown_state_reference"
    unknown_workflow = "unknown_workflow"
    unknown_workflow_step = "unknown_workflow_step"
    unknown_upload = "unknown_upload"
    target_surface_mismatch = "target_surface_mismatch"
    endpoint_surface_mismatch = "endpoint_surface_mismatch"
    endpoint_target_mismatch = "endpoint_target_mismatch"
    parameter_endpoint_mismatch = "parameter_endpoint_mismatch"
    operation_endpoint_mismatch = "operation_endpoint_mismatch"
    request_template_mismatch = "request_template_mismatch"
    missing_authentication_mechanism = "missing_authentication_mechanism"
    incomplete_authentication_differential = "incomplete_authentication_differential"
    identity_binding_mismatch = "identity_binding_mismatch"
    identity_relationship_mismatch = "identity_relationship_mismatch"
    object_binding_mismatch = "object_binding_mismatch"
    missing_required_evidence = "missing_required_evidence"
    unsupported_method = "unsupported_method"
    unsupported_parameter_location = "unsupported_parameter_location"
    missing_cleanup = "missing_cleanup"
    request_estimate_exceeded = "request_estimate_exceeded"


class ExperimentCompilerError(ValueError):
    """A public-safe deterministic compiler failure."""

    def __init__(self, code: CompilerErrorCode):
        self.code = code
        super().__init__(code.value)


class RegisteredRequestTemplate(ResearchContract):
    template_id: OpaqueIdentifier
    target_id: TargetAssetId
    surface_id: SurfaceId
    endpoint_id: EndpointId
    parameter_ids: tuple[ParameterId, ...] = Field(default=(), max_length=100)
    authentication_mechanisms: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=2
    )


class RegisteredSafeHeader(ResearchContract):
    header_definition_id: OpaqueIdentifier
    normalized_name: OpaqueIdentifier
    credential_bearing: StrictBool = False


class CleanupDefinition(ResearchContract):
    cleanup_reference: OpaqueIdentifier
    verification_predicate_reference: OpaqueIdentifier
    capability_names: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=30)
    primitive_names: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=30)
    allowed_target_classes: tuple[TargetClass, ...] = Field(
        default=(
            TargetClass.external,
            TargetClass.local_range,
            TargetClass.dedicated_lab,
        ),
        min_length=1,
        max_length=3,
    )
    minimum_requests: StrictInt = Field(ge=1, le=100)
    worst_case_requests: StrictInt = Field(ge=1, le=100)

    @model_validator(mode="after")
    def validate_definition(self) -> "CleanupDefinition":
        if not self.capability_names and not self.primitive_names:
            raise ValueError("cleanup definition needs a capability or primitive")
        if self.worst_case_requests < self.minimum_requests:
            raise ValueError("cleanup worst case must cover its minimum")
        return self


class ExperimentCompilerContext(ResearchContract):
    current_time: Timestamp
    execution_ready: StrictBool = False
    compiler_version: OpaqueIdentifier = EXPERIMENT_COMPILER_VERSION
    experiment_ttl_seconds: StrictInt = Field(
        default=DEFAULT_EXPERIMENT_TTL_SECONDS, ge=1, le=86_400
    )
    max_response_bytes: StrictInt = Field(
        default=DEFAULT_MAX_RESPONSE_BYTES, ge=1_024, le=100_000_000
    )
    max_request_reservation: StrictInt = Field(default=10_000, ge=0, le=10_000)
    request_templates: tuple[RegisteredRequestTemplate, ...] = Field(
        default=(), max_length=5_000
    )
    controlled_value_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=5_000
    )
    safe_headers: tuple[RegisteredSafeHeader, ...] = Field(default=(), max_length=500)
    state_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=5_000)
    cleanup_definitions: tuple[CleanupDefinition, ...] = Field(
        default=(), max_length=200
    )
    graphql_operation_templates: tuple[RegisteredGraphQLOperationTemplate, ...] = Field(
        default=(), max_length=2_000
    )
    graphql_safe_mutations: tuple[RegisteredGraphQLSafeMutation, ...] = Field(
        default=(), max_length=2_000
    )
    policy_reference: OpaqueIdentifier | None = None
    context_reference: OpaqueIdentifier | None = None
    reproduction_of: OpaqueIdentifier | None = None
    reproduction_finding_id: OpaqueIdentifier | None = None
    reproduction_id: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_unique_registrations(self) -> "ExperimentCompilerContext":
        for values, attribute in (
            (self.request_templates, "template_id"),
            (self.safe_headers, "header_definition_id"),
            (self.cleanup_definitions, "cleanup_reference"),
            (self.graphql_operation_templates, "template_id"),
            (self.graphql_safe_mutations, "mutation_id"),
        ):
            identifiers = tuple(getattr(item, attribute) for item in values)
            if len(identifiers) != len(set(identifiers)):
                raise ValueError("compiler context registrations must be unique")
        if len(self.controlled_value_references) != len(
            set(self.controlled_value_references)
        ):
            raise ValueError("controlled value references must be unique")
        if len(self.state_references) != len(set(self.state_references)):
            raise ValueError("state references must be unique")
        markers = (
            self.reproduction_finding_id is not None,
            self.reproduction_id is not None,
        )
        if any(markers) and (self.reproduction_of is None or not all(markers)):
            raise ValueError("compiler reproduction markers must be supplied together")
        return self


# Short alias used by callers that already live under agent_core.research.
CompilerContext = ExperimentCompilerContext


class ExperimentCompiler:
    """Compile model advice into an immutable, non-authorized experiment."""

    def __init__(
        self,
        registry: ExperimentRegistry | None = None,
        context: ExperimentCompilerContext | None = None,
    ) -> None:
        self.registry = registry if registry is not None else ExperimentRegistry()
        self.context = context

    def compile(
        self,
        proposal: ExperimentProposal | Mapping[str, object],
        state: ResearchState,
        context: ExperimentCompilerContext | None = None,
    ) -> SecurityExperiment:
        compiler_context = context or self.context
        if compiler_context is None:
            raise TypeError("an ExperimentCompilerContext is required")
        try:
            proposal = ExperimentProposal.model_validate(
                proposal.model_dump(mode="python")
                if isinstance(proposal, ExperimentProposal)
                else proposal
            )
        except (TypeError, ValueError) as exc:
            raise ExperimentCompilerError(CompilerErrorCode.invalid_proposal) from exc

        self._validate_revision(proposal, state, compiler_context)
        indexes = _StateIndexes(state)
        target = indexes.target(proposal.target_id)
        hypothesis = indexes.hypothesis(proposal.hypothesis_id)
        indexes.provenance(proposal.provenance_id)
        indexes.provenance(hypothesis.provenance_id)
        for evidence_id in hypothesis.supporting_evidence:
            indexes.evidence(evidence_id)
        if hypothesis.target_id != target.target_id:
            _fail(CompilerErrorCode.endpoint_target_mismatch)

        surface = indexes.optional_surface(proposal.surface_id)
        if surface is not None and surface.target_id != target.target_id:
            _fail(CompilerErrorCode.target_surface_mismatch)
        if (
            hypothesis.surface_id is not None
            and surface is not None
            and hypothesis.surface_id != surface.surface_id
        ):
            _fail(CompilerErrorCode.target_surface_mismatch)

        endpoint = indexes.optional_endpoint(proposal.endpoint_id)
        self._validate_endpoint(endpoint, target.target_id, proposal.surface_id)
        operation = indexes.optional_operation(proposal.operation_id)
        graphql_template: RegisteredGraphQLOperationTemplate | None = None
        if isinstance(operation, GraphQLOperationRecord):
            referenced_template_ids = {
                value
                for step in proposal.primitive_steps
                if (value := getattr(step.input, "operation_template_id", None))
                is not None
            }
            if len(referenced_template_ids) != 1:
                _fail(CompilerErrorCode.unknown_graphql_operation_template)
            graphql_template = _graphql_template(
                compiler_context, next(iter(referenced_template_ids))
            )
            self._validate_graphql_template(
                graphql_template, operation, proposal, indexes
            )
            operation_endpoint = indexes.endpoint(graphql_template.endpoint_id)
            self._validate_endpoint(
                operation_endpoint, target.target_id, proposal.surface_id
            )
            if endpoint is None:
                endpoint = operation_endpoint
        else:
            self._validate_operation(operation, endpoint, proposal.surface_id)
            if operation is not None:
                operation_endpoint = indexes.endpoint(operation.endpoint_id)
                self._validate_endpoint(
                    operation_endpoint, target.target_id, proposal.surface_id
                )
                if endpoint is None:
                    endpoint = operation_endpoint

        adapter = self._resolve_capability(proposal.capability)
        definitions = []
        compiled_steps = []
        endpoints: list[Endpoint] = []
        parameters: list[Parameter] = []
        objects: list[ResearchObject] = []
        identities: list[Identity] = []
        sessions: list[SessionRef] = []
        preconditions: list[Precondition] = [
            Precondition(
                code=PreconditionCode.research_revision_current,
                reference_id=f"revision:{state.revision}",
            ),
            Precondition(
                code=PreconditionCode.target_registered,
                reference_id=target.target_id,
            ),
        ]
        if surface is not None:
            preconditions.append(
                Precondition(
                    code=PreconditionCode.surface_registered,
                    reference_id=surface.surface_id,
                )
            )
        if endpoint is not None:
            endpoints.append(endpoint)
            preconditions.append(
                Precondition(
                    code=PreconditionCode.endpoint_registered,
                    reference_id=endpoint.endpoint_id,
                )
            )

        for step in proposal.primitive_steps:
            try:
                definition = self.registry.resolve(step.primitive_name)
            except ValueError as exc:
                raise ExperimentCompilerError(
                    CompilerErrorCode.unknown_primitive
                ) from exc
            if (
                compiler_context.execution_ready
                and definition.capability_state
                is not PrimitiveCapabilityState.execution_available
            ):
                _fail(CompilerErrorCode.primitive_not_execution_available)
            if target.target_class not in definition.allowed_target_classes:
                _fail(CompilerErrorCode.target_class_not_allowed)
            self._validate_primitive_input(
                step.input,
                proposal=proposal,
                indexes=indexes,
                context=compiler_context,
                endpoints=endpoints,
                parameters=parameters,
                objects=objects,
                identities=identities,
                sessions=sessions,
                preconditions=preconditions,
            )
            definitions.append(definition)
            compiled_steps.append(
                CompiledPrimitiveStep(
                    step_id=step.step_id,
                    primitive_name=definition.name,
                    primitive_version=definition.version,
                    input=step.input,
                    output_type=definition.output_type_reference,
                    capability_state=definition.capability_state,
                )
            )

        self._validate_direct_identity_context(
            proposal, indexes, compiler_context, identities, sessions, preconditions
        )
        if proposal.identity_relationship is not None:
            self._validate_identity_relationship(
                self._controlled_identity(indexes, str(proposal.primary_identity_id)),
                self._controlled_identity(
                    indexes, str(proposal.comparison_identity_id)
                ),
                proposal.identity_relationship,
            )
        if proposal.mutation_intent.parameter_id is not None:
            direct_parameter = indexes.parameter(proposal.mutation_intent.parameter_id)
            _validate_parameter(direct_parameter, endpoint, None)
            parameters.append(direct_parameter)
        if proposal.mutation_intent.controlled_object_id is not None:
            direct_object = self._owned_object(
                indexes,
                proposal.mutation_intent.controlled_object_id,
                proposal.target_id,
                None if graphql_template is not None else proposal.surface_id,
            )
            if (
                proposal.primary_identity_id is not None
                and direct_object.owner_identity_id != proposal.primary_identity_id
            ):
                _fail(CompilerErrorCode.object_binding_mismatch)
            objects.append(direct_object)
            preconditions.extend(
                (
                    Precondition(
                        code=PreconditionCode.test_owned_object,
                        reference_id=direct_object.object_id,
                    ),
                    Precondition(
                        code=PreconditionCode.ownership_evidence_present,
                        reference_id=direct_object.evidence_references[0],
                    ),
                )
            )
        if proposal.mutation_intent.value_source_reference is not None:
            _require_value_source(
                compiler_context,
                proposal.mutation_intent.value_source_reference,
            )
        self._validate_baseline(proposal, indexes, compiler_context)
        if proposal.capability == "authentication_enforcement" and not any(
            isinstance(item.input, AuthenticationDifferentialInput)
            or (
                isinstance(item.input, GraphQLOperationInput)
                and item.input.candidate_kind is GraphQLCandidateKind.authentication
            )
            for item in compiled_steps
        ):
            _fail(CompilerErrorCode.incomplete_authentication_differential)
        if graphql_template is not None:
            self._validate_graphql_candidate_shape(
                proposal,
                hypothesis,
                graphql_template,
                compiled_steps,
                identities,
                objects,
                indexes,
                compiler_context,
            )
        else:
            self._validate_legacy_surface(
                adapter, endpoint, parameters, target.target_class
            )
            self._validate_legacy_requirements(adapter, identities, objects)

        resolved_endpoint = _single_endpoint(endpoint, endpoints)
        resolved_surface_id = proposal.surface_id or (
            resolved_endpoint.surface_id if resolved_endpoint is not None else None
        )
        if resolved_surface_id is not None:
            resolved_surface = indexes.surface(resolved_surface_id)
            if resolved_surface.target_id != target.target_id:
                _fail(CompilerErrorCode.target_surface_mismatch)
        if resolved_endpoint is not None:
            self._validate_endpoint(
                resolved_endpoint, target.target_id, resolved_surface_id
            )

        state_changing = self._derive_state_changing(
            definitions, compiled_steps, resolved_endpoint, adapter, indexes
        )
        if state_changing and graphql_template is not None:
            if compiler_context.policy_reference is None:
                _fail(CompilerErrorCode.graphql_state_change_disallowed)
            preconditions.append(
                Precondition(
                    code=PreconditionCode.state_change_authorization_required,
                    reference_id=compiler_context.policy_reference,
                )
            )
        cleanup = self._derive_cleanup(
            state_changing,
            proposal.capability,
            tuple(item.name for item in definitions),
            target.target_class,
            adapter,
            compiler_context,
        )
        if cleanup.required:
            preconditions.append(
                Precondition(
                    code=PreconditionCode.cleanup_reserved,
                    reference_id=str(cleanup.cleanup_reference),
                )
            )

        request_estimate = self._derive_request_estimate(
            definitions,
            compiled_steps,
            None if graphql_template is not None else adapter,
            cleanup,
        )
        if (
            request_estimate.total_reservation
            > compiler_context.max_request_reservation
        ):
            _fail(CompilerErrorCode.request_estimate_exceeded)
        risk = self._derive_risk(definitions, state_changing)
        mutation = self._derive_mutation(proposal, parameters, objects)
        identity_context = self._derive_identity_context(
            proposal, tuple(compiled_steps), indexes
        )
        parameter_ids = tuple(sorted({item.parameter_id for item in parameters}))
        target_reference = TypedTargetReference(
            target_id=target.target_id,
            target_class=target.target_class,
            surface_id=resolved_surface_id,
            endpoint_id=(
                resolved_endpoint.endpoint_id if resolved_endpoint is not None else None
            ),
            operation_id=_single_operation_id(operation, compiled_steps),
            method=(
                resolved_endpoint.method.value
                if resolved_endpoint is not None
                else None
            ),
            parameter_ids=parameter_ids,
        )
        capability = CapabilityRef(
            name=proposal.capability,
            version=(
                adapter.capability_version
                if adapter is not None
                else self.registry.resolve(proposal.capability).version
            ),
            legacy_adapter_reference=(
                adapter.metadata_reference if adapter is not None else None
            ),
        )
        required_evidence = tuple(
            EvidenceRequirement(
                selector=item.selector,
                predicate_reference=item.predicate_reference,
                minimum_artifacts=item.minimum_artifacts,
            )
            for item in proposal.required_evidence_intent
        )
        provenance = ExperimentProvenance(
            source_proposal_id=proposal.proposal_id,
            source_provenance_id=proposal.provenance_id,
            source_hypothesis_id=proposal.hypothesis_id,
            research_revision=state.revision,
            compiler_version=compiler_context.compiler_version,
            primitive_registry_version=self.registry.version,
            primitive_registry_hash=self.registry.fingerprint,
            source_model_decision_id=proposal.model_decision_id,
            policy_reference=compiler_context.policy_reference,
            context_reference=compiler_context.context_reference,
        )
        expires_at = _derive_expiry(proposal.expires_at, compiler_context)
        stop_conditions = _stop_conditions(compiler_context.max_response_bytes)
        canonical_preconditions = Preconditions(
            items=tuple(
                sorted(
                    set(preconditions),
                    key=lambda item: (item.code.value, item.reference_id),
                )
            )
        )
        fields = {
            "experiment_id": _experiment_id(proposal),
            "research_id": proposal.research_id,
            "state_revision": state.revision,
            "hypothesis_id": proposal.hypothesis_id,
            "capability": capability,
            "primitive_steps": tuple(compiled_steps),
            "target": target_reference,
            "objective": proposal.objective,
            "identity_context": identity_context,
            "baseline": Baseline(
                kind=proposal.baseline.kind,
                reference_id=proposal.baseline.reference_id,
            ),
            "mutation": mutation,
            "expected_secure_behavior": proposal.expected_secure_behavior,
            "expected_vulnerable_behavior": proposal.expected_vulnerable_behavior,
            "required_evidence": required_evidence,
            "request_estimate": request_estimate,
            "risk": risk,
            "state_changing": state_changing,
            "cleanup": cleanup,
            "preconditions": canonical_preconditions,
            "stop_conditions": stop_conditions,
            "reproduction_of": compiler_context.reproduction_of,
            "reproduction_finding_id": compiler_context.reproduction_finding_id,
            "reproduction_id": compiler_context.reproduction_id,
            "expires_at": expires_at,
            "provenance": provenance,
        }
        fields["fingerprint"] = experiment_fingerprint(fields)
        return SecurityExperiment.model_validate(fields)

    @staticmethod
    def _validate_revision(
        proposal: ExperimentProposal,
        state: ResearchState,
        context: ExperimentCompilerContext,
    ) -> None:
        if proposal.research_id != state.research_id:
            _fail(CompilerErrorCode.research_mismatch)
        if proposal.state_revision != state.revision:
            _fail(CompilerErrorCode.stale_state_revision)
        if proposal.expires_at is not None and _parse_timestamp(
            proposal.expires_at
        ) <= _parse_timestamp(context.current_time):
            _fail(CompilerErrorCode.expired_proposal)

    @staticmethod
    def _validate_endpoint(
        endpoint: Endpoint | None,
        target_id: str,
        surface_id: str | None,
    ) -> None:
        if endpoint is None:
            return
        if endpoint.target_id != target_id:
            _fail(CompilerErrorCode.endpoint_target_mismatch)
        if surface_id is not None and endpoint.surface_id != surface_id:
            _fail(CompilerErrorCode.endpoint_surface_mismatch)

    @staticmethod
    def _validate_operation(
        operation: GraphQLOperation | None,
        endpoint: Endpoint | None,
        surface_id: str | None,
    ) -> None:
        if operation is None:
            return
        if endpoint is not None and operation.endpoint_id != endpoint.endpoint_id:
            _fail(CompilerErrorCode.operation_endpoint_mismatch)
        if surface_id is not None and operation.surface_id != surface_id:
            _fail(CompilerErrorCode.endpoint_surface_mismatch)

    @staticmethod
    def _validate_graphql_template(
        template: RegisteredGraphQLOperationTemplate,
        operation: GraphQLOperationRecord,
        proposal: ExperimentProposal,
        indexes: "_StateIndexes",
    ) -> None:
        semantic_surface = indexes.graphql_surface(template.graphql_surface_id)
        if (
            template.operation_id != operation.operation_id
            or template.graphql_surface_id != operation.graphql_surface_id
            or template.operation_type is not operation.operation_type
            or template.selection_fingerprint != operation.selection_fingerprint
            or template.normalized_structure.root_field_ids != operation.root_field_ids
            or semantic_surface.endpoint_id != template.endpoint_id
            or semantic_surface.surface_id != proposal.surface_id
            or semantic_surface.target_id != proposal.target_id
        ):
            _fail(CompilerErrorCode.graphql_template_mismatch)
        if template.state_change_class is (
            GraphQLExperimentStateChangeClass.irreversible_or_disallowed
        ):
            _fail(CompilerErrorCode.graphql_state_change_disallowed)
        effective_authentication = operation.authentication_requirement
        if effective_authentication is GraphQLAuthenticationRequirement.unknown:
            effective_authentication = semantic_surface.authentication_requirement
        if template.authentication_requirement is not effective_authentication:
            _fail(CompilerErrorCode.graphql_template_mismatch)
        if (
            operation.state_change_class is GraphQLStateChangeClass.read_only
            and template.state_change_class
            is not GraphQLExperimentStateChangeClass.read_only
        ):
            _fail(CompilerErrorCode.graphql_template_mismatch)
        if (
            operation.state_change_class
            in {
                GraphQLStateChangeClass.potential_state_change,
                GraphQLStateChangeClass.state_change_observed,
            }
            and template.state_change_class
            is GraphQLExperimentStateChangeClass.read_only
        ):
            _fail(CompilerErrorCode.graphql_template_mismatch)
        if template.workflow_id != operation.workflow_id:
            _fail(CompilerErrorCode.graphql_template_mismatch)
        if template.provenance_id not in {
            item.provenance_id for item in indexes.state.provenance
        } or not set(template.evidence_references).issubset(
            {item.evidence_id for item in indexes.state.evidence}
        ):
            _fail(CompilerErrorCode.missing_required_evidence)
        fields = {item.field_id: item for item in indexes.state.graphql_fields}
        types = {item.type_id: item for item in indexes.state.graphql_types}
        for path in template.normalized_structure.selection_paths:
            previous: GraphQLFieldRecord | None = None
            for field_id in path.field_ids:
                field = fields.get(field_id)
                if field is None:
                    _fail(CompilerErrorCode.unknown_graphql_field)
                if previous is None:
                    if field_id not in operation.root_field_ids:
                        _fail(CompilerErrorCode.graphql_selection_invalid)
                else:
                    owner = types.get(field.type_id)
                    previous_owner = types.get(previous.type_id)
                    if (
                        owner is None
                        or previous_owner is None
                        or owner.graphql_surface_id
                        != semantic_surface.graphql_surface_id
                        or previous.return_type.named_type != owner.name
                    ):
                        _fail(CompilerErrorCode.graphql_selection_invalid)
                previous = field
        expected_pairs = {
            (item.argument_id, item.variable_id) for item in template.argument_bindings
        }
        for argument_id, variable_id in expected_pairs:
            argument = indexes.graphql_argument(argument_id)
            variable = indexes.graphql_variable(variable_id)
            if (
                variable.operation_id != operation.operation_id
                or variable.linked_argument_id != argument.argument_id
                or variable.input_type != argument.input_type
                or argument.field_id not in fields
                or argument.field_id
                not in {
                    field_id
                    for path in template.normalized_structure.selection_paths
                    for field_id in path.field_ids
                }
            ):
                _fail(CompilerErrorCode.graphql_binding_mismatch)
        for binding in template.variable_bindings:
            if (binding.argument_id, binding.variable_id) not in expected_pairs:
                _fail(CompilerErrorCode.graphql_binding_mismatch)

    def _resolve_capability(
        self, capability_name: str
    ) -> ResearchExperimentCapabilityAdapter | None:
        try:
            return get_research_experiment_capability_adapter(capability_name)
        except ValueError:
            try:
                self.registry.resolve(capability_name)
            except ValueError as exc:
                raise ExperimentCompilerError(
                    CompilerErrorCode.unknown_capability
                ) from exc
            return None

    def _validate_primitive_input(
        self,
        primitive: PrimitiveInput,
        *,
        proposal: ExperimentProposal,
        indexes: "_StateIndexes",
        context: ExperimentCompilerContext,
        endpoints: list[Endpoint],
        parameters: list[Parameter],
        objects: list[ResearchObject],
        identities: list[Identity],
        sessions: list[SessionRef],
        preconditions: list[Precondition],
    ) -> None:
        endpoint_id = getattr(primitive, "endpoint_id", None)
        endpoint = indexes.optional_endpoint(endpoint_id)
        if endpoint is not None:
            self._validate_endpoint(endpoint, proposal.target_id, proposal.surface_id)
            if proposal.endpoint_id is not None and endpoint.endpoint_id != (
                proposal.endpoint_id
            ):
                _fail(CompilerErrorCode.request_template_mismatch)
            endpoints.append(endpoint)

        template_id = getattr(primitive, "request_template_id", None)
        if template_id is not None:
            template = _template(context, template_id)
            _validate_template(template, endpoint, proposal)
            preconditions.append(
                Precondition(
                    code=PreconditionCode.request_template_registered,
                    reference_id=template.template_id,
                )
            )
        if isinstance(primitive, AuthenticationDifferentialInput):
            _require_authentication_mechanism(template)
            identities.append(self._controlled_identity(indexes, primitive.identity_id))
        elif isinstance(primitive, RequestReplayInput):
            if (
                primitive.identity_id is not None
                or primitive.session_ref_id is not None
            ):
                _require_authentication_mechanism(template)
            if primitive.identity_id is not None:
                identities.append(
                    self._controlled_identity(indexes, primitive.identity_id)
                )
            if primitive.session_ref_id is not None:
                session = self._active_session(indexes, primitive.session_ref_id)
                sessions.append(session)
                if (
                    primitive.identity_id is not None
                    and session.identity_id != primitive.identity_id
                ):
                    _fail(CompilerErrorCode.identity_binding_mismatch)
            template = _template(context, primitive.request_template_id)
            for binding in primitive.bindings:
                parameter = indexes.parameter(binding.parameter_id)
                _validate_parameter(parameter, endpoint, template)
                _require_value_source(context, binding.value_source_reference)
                parameters.append(parameter)
        elif isinstance(primitive, IdentitySwitchInput):
            primary = self._controlled_identity(indexes, primitive.primary_identity_id)
            comparison = self._controlled_identity(
                indexes, primitive.comparison_identity_id
            )
            self._validate_identity_relationship(
                primary, comparison, primitive.relationship
            )
            identities.extend((primary, comparison))
        elif isinstance(primitive, ParameterMutationInput):
            template = _template(context, primitive.request_template_id)
            parameter = indexes.parameter(primitive.parameter_id)
            _validate_parameter(parameter, endpoint, template)
            parameters.append(parameter)
            if primitive.value_source_reference is not None:
                _require_value_source(context, primitive.value_source_reference)
            if primitive.controlled_object_id is not None:
                objects.append(
                    self._owned_object(
                        indexes,
                        primitive.controlled_object_id,
                        proposal.target_id,
                        proposal.surface_id,
                    )
                )
        elif isinstance(primitive, ObjectSubstitutionInput):
            parameter = indexes.parameter(primitive.parameter_id)
            _validate_parameter(parameter, endpoint, None)
            parameters.append(parameter)
            primary = self._controlled_identity(indexes, primitive.primary_identity_id)
            comparison = self._controlled_identity(
                indexes, primitive.comparison_identity_id
            )
            self._validate_identity_relationship(
                primary, comparison, primitive.relationship
            )
            identities.extend((primary, comparison))
            owned = self._owned_object(
                indexes,
                primitive.controlled_object_id,
                proposal.target_id,
                proposal.surface_id,
            )
            if owned.owner_identity_id != primitive.primary_identity_id:
                _fail(CompilerErrorCode.object_binding_mismatch)
            if (
                owned.parameter_references
                and primitive.parameter_id not in owned.parameter_references
            ):
                _fail(CompilerErrorCode.object_binding_mismatch)
            if not set(primitive.ownership_evidence_ids).issubset(
                set(owned.evidence_references)
            ):
                _fail(CompilerErrorCode.missing_required_evidence)
            for evidence_id in primitive.ownership_evidence_ids:
                indexes.evidence(evidence_id)
            objects.append(owned)
            if primitive.request_template_id is not None:
                template = _template(context, primitive.request_template_id)
                _require_authentication_mechanism(template)
                _validate_template(template, endpoint, proposal)
                _validate_parameter(parameter, endpoint, template)
            if primitive.operation_id is not None:
                operation = indexes.operation(primitive.operation_id)
                self._validate_operation(operation, endpoint, proposal.surface_id)
                if parameter.parameter_id not in operation.variable_parameter_ids:
                    _fail(CompilerErrorCode.parameter_endpoint_mismatch)
        elif isinstance(primitive, HeaderMutationInput):
            header = _safe_header(context, primitive.header_definition_id)
            if header.credential_bearing or _credential_header(header.normalized_name):
                _fail(CompilerErrorCode.credential_header_prohibited)
            if primitive.value_source_reference is not None:
                _require_value_source(context, primitive.value_source_reference)
        elif isinstance(primitive, CookieMutationInput):
            template = _template(context, primitive.request_template_id)
            _validate_template(template, endpoint, proposal)
            sessions.append(
                self._active_session(indexes, primitive.primary_session_ref_id)
            )
            if primitive.replacement_session_ref_id is not None:
                replacement = self._active_session(
                    indexes, primitive.replacement_session_ref_id
                )
                if replacement.identity_id == sessions[-1].identity_id:
                    _fail(CompilerErrorCode.identity_binding_mismatch)
                sessions.append(replacement)
        elif isinstance(primitive, ResponseDifferentialInput):
            for reference in primitive.references:
                if reference.kind == "evidence":
                    indexes.evidence(reference.reference_id)
                else:
                    indexes.outcome(reference.reference_id)
        elif isinstance(primitive, StateDifferentialInput):
            for reference in (
                primitive.before_state_reference,
                primitive.after_state_reference,
                primitive.cleanup_state_reference,
            ):
                if reference is not None and reference not in set(
                    context.state_references
                ):
                    _fail(CompilerErrorCode.unknown_state_reference)
        elif isinstance(primitive, GraphQLOperationInput):
            operation = indexes.operation(primitive.operation_id)
            if isinstance(operation, GraphQLOperationRecord):
                if (
                    primitive.operation_template_id is None
                    or primitive.candidate_kind is None
                ):
                    _fail(CompilerErrorCode.unknown_graphql_operation_template)
                graphql_template = _graphql_template(
                    context, primitive.operation_template_id
                )
                preconditions.append(
                    Precondition(
                        code=PreconditionCode.graphql_operation_template_registered,
                        reference_id=graphql_template.template_id,
                    )
                )
                self._validate_graphql_template(
                    graphql_template, operation, proposal, indexes
                )
                operation_endpoint = indexes.endpoint(graphql_template.endpoint_id)
                endpoints.append(operation_endpoint)
                bindings = (
                    primitive.variable_bindings or graphql_template.variable_bindings
                )
                registered_fields = {
                    field_id
                    for path in graphql_template.normalized_structure.selection_paths
                    for field_id in path.field_ids
                }
                if not set(primitive.selected_field_ids).issubset(registered_fields):
                    _fail(CompilerErrorCode.graphql_selection_invalid)
                for binding in bindings:
                    self._validate_graphql_variable_binding(
                        binding,
                        template=graphql_template,
                        proposal=proposal,
                        indexes=indexes,
                        context=context,
                        objects=objects,
                        identities=identities,
                    )
            else:
                self._validate_operation(operation, endpoint, proposal.surface_id)
                endpoints.append(indexes.endpoint(operation.endpoint_id))
            if primitive.identity_id is not None:
                identities.append(
                    self._controlled_identity(indexes, primitive.identity_id)
                )
        elif isinstance(primitive, GraphQLVariableMutationInput):
            operation = indexes.operation(primitive.operation_id)
            if isinstance(operation, GraphQLOperationRecord):
                graphql_template = _graphql_template(
                    context, str(primitive.operation_template_id)
                )
                preconditions.append(
                    Precondition(
                        code=PreconditionCode.graphql_operation_template_registered,
                        reference_id=graphql_template.template_id,
                    )
                )
                self._validate_graphql_template(
                    graphql_template, operation, proposal, indexes
                )
                safe_mutation = _graphql_safe_mutation(
                    context, str(primitive.safe_mutation_id)
                )
                if (
                    safe_mutation.operation_template_id != graphql_template.template_id
                    or safe_mutation.variable_id != primitive.variable_id
                    or safe_mutation.argument_id != primitive.argument_id
                    or safe_mutation.binding != primitive.binding
                    or safe_mutation.binding.value_reference
                    != primitive.value_source_reference
                ):
                    _fail(CompilerErrorCode.graphql_binding_mismatch)
                self._validate_graphql_variable_binding(
                    safe_mutation.binding,
                    template=graphql_template,
                    proposal=proposal,
                    indexes=indexes,
                    context=context,
                    objects=objects,
                    identities=identities,
                )
                if safe_mutation.provenance_id not in {
                    item.provenance_id for item in indexes.state.provenance
                } or not set(safe_mutation.evidence_references).issubset(
                    {item.evidence_id for item in indexes.state.evidence}
                ):
                    _fail(CompilerErrorCode.missing_required_evidence)
                endpoints.append(indexes.endpoint(graphql_template.endpoint_id))
            else:
                operation_endpoint = indexes.endpoint(operation.endpoint_id)
                self._validate_endpoint(
                    operation_endpoint, proposal.target_id, proposal.surface_id
                )
                parameter = indexes.parameter(str(primitive.parameter_id))
                if primitive.parameter_id not in operation.variable_parameter_ids:
                    _fail(CompilerErrorCode.parameter_endpoint_mismatch)
                _validate_parameter(parameter, operation_endpoint, None)
                endpoints.append(operation_endpoint)
                parameters.append(parameter)
                if primitive.value_source_reference is not None:
                    _require_value_source(context, primitive.value_source_reference)
        elif isinstance(primitive, TokenMutationInput):
            token = indexes.token(primitive.token_ref_id)
            if token.lifecycle is not TokenLifecycle.active:
                _fail(CompilerErrorCode.inactive_token)
            identities.append(self._controlled_identity(indexes, token.identity_id))
            if primitive.replacement_token_ref_id is not None:
                replacement = indexes.token(primitive.replacement_token_ref_id)
                if replacement.lifecycle is not TokenLifecycle.active:
                    _fail(CompilerErrorCode.inactive_token)
                identities.append(
                    self._controlled_identity(indexes, replacement.identity_id)
                )
        elif isinstance(primitive, WorkflowPrimitiveInput):
            workflow = indexes.workflow(primitive.workflow_id)
            available_steps = {item.step_id for item in workflow.steps}
            if not set(primitive.step_ids).issubset(available_steps):
                _fail(CompilerErrorCode.unknown_workflow_step)
            if proposal.surface_id is not None and workflow.surface_id != (
                proposal.surface_id
            ):
                _fail(CompilerErrorCode.endpoint_surface_mismatch)
        elif isinstance(primitive, UploadVariantInput):
            upload = indexes.upload(primitive.upload_id)
            if upload.endpoint_id != primitive.endpoint_id:
                _fail(CompilerErrorCode.request_template_mismatch)
            if not upload.test_owned:
                _fail(CompilerErrorCode.unowned_object)
            identities.append(
                self._controlled_identity(indexes, upload.owner_identity_id)
            )

        for identity in identities:
            preconditions.append(
                Precondition(
                    code=PreconditionCode.controlled_identity,
                    reference_id=identity.identity_id,
                )
            )
        for session in sessions:
            preconditions.append(
                Precondition(
                    code=PreconditionCode.controlled_session,
                    reference_id=session.session_ref_id,
                )
            )
        for item in objects:
            preconditions.extend(
                (
                    Precondition(
                        code=PreconditionCode.test_owned_object,
                        reference_id=item.object_id,
                    ),
                    Precondition(
                        code=PreconditionCode.ownership_evidence_present,
                        reference_id=item.evidence_references[0],
                    ),
                )
            )

    @staticmethod
    def _derive_identity_context(
        proposal: ExperimentProposal,
        steps: tuple[CompiledPrimitiveStep, ...],
        indexes: "_StateIndexes",
    ) -> IdentityContext:
        primary_identity = proposal.primary_identity_id
        comparison_identity = proposal.comparison_identity_id
        primary_session = proposal.primary_session_ref_id
        comparison_session = proposal.comparison_session_ref_id
        relationship = proposal.identity_relationship

        def merge(current: str | None, candidate: str | None) -> str | None:
            if candidate is None:
                return current
            if current is not None and current != candidate:
                _fail(CompilerErrorCode.identity_binding_mismatch)
            return candidate

        for step in steps:
            primitive = step.input
            if isinstance(primitive, (IdentitySwitchInput, ObjectSubstitutionInput)):
                primary_identity = merge(
                    primary_identity, primitive.primary_identity_id
                )
                comparison_identity = merge(
                    comparison_identity, primitive.comparison_identity_id
                )
                if relationship is not None and relationship != primitive.relationship:
                    _fail(CompilerErrorCode.identity_binding_mismatch)
                relationship = relationship or primitive.relationship
            elif isinstance(primitive, AuthenticationDifferentialInput):
                primary_identity = merge(primary_identity, primitive.identity_id)
            elif isinstance(primitive, RequestReplayInput):
                primary_identity = merge(primary_identity, primitive.identity_id)
                primary_session = merge(primary_session, primitive.session_ref_id)
            elif isinstance(primitive, CookieMutationInput):
                primary_session = merge(
                    primary_session, primitive.primary_session_ref_id
                )
                comparison_session = merge(
                    comparison_session, primitive.replacement_session_ref_id
                )
            elif isinstance(primitive, GraphQLOperationInput):
                if primitive.identity_role == "comparison":
                    comparison_identity = merge(
                        comparison_identity, primitive.identity_id
                    )
                else:
                    primary_identity = merge(primary_identity, primitive.identity_id)

        if primary_session is not None:
            primary_identity = merge(
                primary_identity, indexes.session(primary_session).identity_id
            )
        if comparison_session is not None:
            comparison_identity = merge(
                comparison_identity, indexes.session(comparison_session).identity_id
            )
        return IdentityContext(
            primary_identity_id=primary_identity,
            comparison_identity_id=comparison_identity,
            primary_session_ref_id=primary_session,
            comparison_session_ref_id=comparison_session,
            relationship=relationship,
        )

    def _validate_direct_identity_context(
        self,
        proposal: ExperimentProposal,
        indexes: "_StateIndexes",
        context: ExperimentCompilerContext,
        identities: list[Identity],
        sessions: list[SessionRef],
        preconditions: list[Precondition],
    ) -> None:
        direct: dict[str, Identity] = {}
        for identity_id in (
            proposal.primary_identity_id,
            proposal.comparison_identity_id,
        ):
            if identity_id is not None:
                direct[identity_id] = self._controlled_identity(indexes, identity_id)
        for session_id, identity_id in (
            (proposal.primary_session_ref_id, proposal.primary_identity_id),
            (proposal.comparison_session_ref_id, proposal.comparison_identity_id),
        ):
            if session_id is None:
                continue
            session = self._active_session(indexes, session_id)
            if identity_id is not None and session.identity_id != identity_id:
                _fail(CompilerErrorCode.identity_binding_mismatch)
            sessions.append(session)
            direct[session.identity_id] = self._controlled_identity(
                indexes, session.identity_id
            )
        if context.execution_ready:
            for identity in direct.values():
                if identity.eligibility is not IdentityEligibility.eligible:
                    _fail(CompilerErrorCode.ineligible_identity)
        identities.extend(direct.values())
        for identity in direct.values():
            preconditions.append(
                Precondition(
                    code=PreconditionCode.controlled_identity,
                    reference_id=identity.identity_id,
                )
            )
        for session in sessions:
            preconditions.append(
                Precondition(
                    code=PreconditionCode.controlled_session,
                    reference_id=session.session_ref_id,
                )
            )

    @staticmethod
    def _controlled_identity(indexes: "_StateIndexes", identity_id: str) -> Identity:
        identity = indexes.identity(identity_id)
        if not identity.controlled:
            _fail(CompilerErrorCode.uncontrolled_identity)
        return identity

    @classmethod
    def _validate_graphql_variable_binding(
        cls,
        binding: GraphQLVariableBinding,
        *,
        template: RegisteredGraphQLOperationTemplate,
        proposal: ExperimentProposal,
        indexes: "_StateIndexes",
        context: ExperimentCompilerContext,
        objects: list[ResearchObject],
        identities: list[Identity],
    ) -> None:
        if (binding.argument_id, binding.variable_id) not in {
            (item.argument_id, item.variable_id) for item in template.argument_bindings
        }:
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        variable = indexes.graphql_variable(binding.variable_id)
        argument = indexes.graphql_argument(binding.argument_id)
        if (
            variable.operation_id != template.operation_id
            or variable.linked_argument_id != argument.argument_id
            or argument.field_id
            not in {
                field_id
                for path in template.normalized_structure.selection_paths
                for field_id in path.field_ids
            }
            or variable.input_type != argument.input_type
        ):
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        source = binding.value_source
        reference = binding.value_reference
        if source is GraphQLVariableValueSource.controlled_object:
            owned = cls._owned_object(indexes, reference, proposal.target_id, None)
            semantics = argument.object_reference_semantics
            if semantics.research_object_id != owned.object_id:
                _fail(CompilerErrorCode.object_binding_mismatch)
            objects.append(owned)
        elif source is GraphQLVariableValueSource.controlled_identity:
            identities.append(cls._controlled_identity(indexes, reference))
        elif source is GraphQLVariableValueSource.registered_workflow_value:
            if template.workflow_id is None:
                _fail(CompilerErrorCode.graphql_binding_mismatch)
            indexes.workflow(template.workflow_id)
            _require_value_source(context, reference)
        elif source in {
            GraphQLVariableValueSource.registered_safe_constant,
            GraphQLVariableValueSource.registered_pagination_bound,
            GraphQLVariableValueSource.opaque_controlled_value,
        }:
            _require_value_source(context, reference)
        else:  # pragma: no cover - enum validation closes the value set
            _fail(CompilerErrorCode.graphql_binding_mismatch)

    @staticmethod
    def _validate_identity_relationship(
        primary: Identity,
        comparison: Identity,
        relationship: IdentityRelationship,
    ) -> None:
        valid = True
        if relationship is IdentityRelationship.same_identity:
            valid = primary.identity_id == comparison.identity_id
        elif relationship is IdentityRelationship.same_tenant_different_account:
            valid = bool(
                primary.identity_id != comparison.identity_id
                and primary.tenant_reference is not None
                and primary.tenant_reference == comparison.tenant_reference
            )
        elif relationship is IdentityRelationship.different_controlled_tenant:
            valid = bool(
                primary.identity_id != comparison.identity_id
                and primary.tenant_reference is not None
                and comparison.tenant_reference is not None
                and primary.tenant_reference != comparison.tenant_reference
            )
        elif relationship is IdentityRelationship.user_admin:
            primary_role = str(primary.role_reference or "").casefold()
            comparison_role = str(comparison.role_reference or "").casefold()
            valid = bool(
                primary.identity_id != comparison.identity_id
                and primary_role
                and comparison_role
                and "admin" not in primary_role
                and "admin" in comparison_role
            )
        elif relationship is IdentityRelationship.different_controlled_role:
            valid = bool(
                primary.identity_id != comparison.identity_id
                and primary.role_reference is not None
                and comparison.role_reference is not None
                and primary.role_reference != comparison.role_reference
            )
        elif relationship is IdentityRelationship.owner_non_owner:
            valid = primary.identity_id != comparison.identity_id
        if not valid:
            _fail(CompilerErrorCode.identity_relationship_mismatch)

    @staticmethod
    def _active_session(indexes: "_StateIndexes", session_id: str) -> SessionRef:
        session = indexes.session(session_id)
        if session.lifecycle is not SessionLifecycle.active:
            _fail(CompilerErrorCode.inactive_session)
        identity = indexes.identity(session.identity_id)
        if not identity.controlled:
            _fail(CompilerErrorCode.uncontrolled_identity)
        return session

    @staticmethod
    def _owned_object(
        indexes: "_StateIndexes",
        object_id: str,
        target_id: str,
        surface_id: str | None,
    ) -> ResearchObject:
        item = indexes.object(object_id)
        if not item.test_owned or item.owner_identity_id is None:
            _fail(CompilerErrorCode.unowned_object)
        if item.target_id != target_id:
            _fail(CompilerErrorCode.object_binding_mismatch)
        if surface_id is not None and item.surface_id != surface_id:
            _fail(CompilerErrorCode.object_binding_mismatch)
        owner = indexes.identity(item.owner_identity_id)
        if not owner.controlled:
            _fail(CompilerErrorCode.unowned_object)
        return item

    @staticmethod
    def _validate_baseline(
        proposal: ExperimentProposal,
        indexes: "_StateIndexes",
        context: ExperimentCompilerContext,
    ) -> None:
        baseline = proposal.baseline
        if baseline.kind is BaselineKind.registered_request:
            _template(context, baseline.reference_id)
        elif baseline.kind is BaselineKind.registered_graphql_operation:
            _graphql_template(context, baseline.reference_id)
        elif baseline.kind is BaselineKind.primary_identity:
            identity = indexes.identity(baseline.reference_id)
            if not identity.controlled:
                _fail(CompilerErrorCode.uncontrolled_identity)
        elif baseline.kind is BaselineKind.prior_evidence:
            indexes.evidence(baseline.reference_id)
        elif baseline.kind is BaselineKind.prior_outcome:
            indexes.outcome(baseline.reference_id)
        elif baseline.kind is BaselineKind.before_state:
            if baseline.reference_id not in set(context.state_references):
                _fail(CompilerErrorCode.unknown_state_reference)

    @staticmethod
    def _validate_legacy_surface(
        adapter: ResearchExperimentCapabilityAdapter | None,
        endpoint: Endpoint | None,
        parameters: list[Parameter],
        target_class: TargetClass,
    ) -> None:
        if adapter is None:
            return
        if target_class.value not in set(adapter.allowed_target_classes):
            _fail(CompilerErrorCode.target_class_not_allowed)
        if (
            endpoint is not None
            and adapter.supported_methods
            and (endpoint.method.value not in set(adapter.supported_methods))
        ):
            _fail(CompilerErrorCode.unsupported_method)
        for parameter in parameters:
            if adapter.supported_parameter_locations and (
                parameter.location.value
                not in set(adapter.supported_parameter_locations)
            ):
                _fail(CompilerErrorCode.unsupported_parameter_location)

    @staticmethod
    def _validate_legacy_requirements(
        adapter: ResearchExperimentCapabilityAdapter | None,
        identities: list[Identity],
        objects: list[ResearchObject],
    ) -> None:
        if adapter is None:
            return
        identity_ids = {item.identity_id for item in identities}
        if len(identity_ids) < adapter.required_account_count:
            _fail(CompilerErrorCode.uncontrolled_identity)
        if adapter.requires_test_owned_resource and not objects:
            _fail(CompilerErrorCode.unowned_object)

    @classmethod
    def _validate_graphql_candidate_shape(
        cls,
        proposal: ExperimentProposal,
        hypothesis: object,
        template: RegisteredGraphQLOperationTemplate,
        steps: list[CompiledPrimitiveStep],
        identities: list[Identity],
        objects: list[ResearchObject],
        indexes: "_StateIndexes",
        context: ExperimentCompilerContext,
    ) -> None:
        graphql_inputs = [
            item.input
            for item in steps
            if isinstance(
                item.input, (GraphQLOperationInput, GraphQLVariableMutationInput)
            )
        ]
        kinds = {
            item.candidate_kind
            for item in graphql_inputs
            if item.candidate_kind is not None
        }
        if len(kinds) != 1:
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        kind = next(iter(kinds))
        expected_properties = {
            GraphQLCandidateKind.object_authorization: "object-authorization",
            GraphQLCandidateKind.authentication: "authentication-enforcement",
            GraphQLCandidateKind.field_authorization: "field-level-authorization",
            GraphQLCandidateKind.role_bound: "role-bound-access",
            GraphQLCandidateKind.tenant_bound: "tenant-bound-access",
            GraphQLCandidateKind.ownership: "object-authorization",
            GraphQLCandidateKind.mutation_authorization: "mutation-authorization",
            GraphQLCandidateKind.cross_surface: "cross-surface-authorization",
            GraphQLCandidateKind.nested_resolver: (
                "relationship-traversal-authorization"
            ),
            GraphQLCandidateKind.input_validation: "argument-input-validation",
            GraphQLCandidateKind.workflow_mutation: "workflow-bound-mutation",
        }
        if getattr(hypothesis, "security_property", None) != expected_properties[kind]:
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        entity_ids = {
            item.entity_id for item in getattr(hypothesis, "entity_references", ())
        }
        if template.operation_id not in entity_ids:
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        identity_ids = {item.identity_id for item in identities}
        object_ids = {item.object_id for item in objects}
        operation_steps = [
            item for item in graphql_inputs if isinstance(item, GraphQLOperationInput)
        ]
        if kind is GraphQLCandidateKind.authentication:
            if (
                len(operation_steps) != 2
                or not any(item.anonymous for item in operation_steps)
                or not any(item.identity_id is not None for item in operation_steps)
            ):
                _fail(CompilerErrorCode.incomplete_authentication_differential)
        if kind in {
            GraphQLCandidateKind.object_authorization,
            GraphQLCandidateKind.ownership,
            GraphQLCandidateKind.tenant_bound,
            GraphQLCandidateKind.cross_surface,
        } and (len(identity_ids) < 2 or not object_ids):
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        if kind is GraphQLCandidateKind.role_bound and len(identity_ids) < 2:
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        if kind is GraphQLCandidateKind.input_validation and not any(
            isinstance(item, GraphQLVariableMutationInput) for item in graphql_inputs
        ):
            _fail(CompilerErrorCode.graphql_binding_mismatch)
        selected_fields = {
            field_id for item in operation_steps for field_id in item.selected_field_ids
        }
        if kind in {
            GraphQLCandidateKind.field_authorization,
            GraphQLCandidateKind.nested_resolver,
        } and (not selected_fields or not selected_fields.issubset(entity_ids)):
            _fail(CompilerErrorCode.graphql_selection_invalid)
        if kind in {
            GraphQLCandidateKind.mutation_authorization,
            GraphQLCandidateKind.workflow_mutation,
        } and template.state_change_class is not (
            GraphQLExperimentStateChangeClass.reversible_state_change
        ):
            _fail(CompilerErrorCode.graphql_state_change_disallowed)
        if kind is GraphQLCandidateKind.workflow_mutation:
            if template.workflow_id is None:
                _fail(CompilerErrorCode.unknown_workflow)
            workflow = indexes.workflow(template.workflow_id)
            controlled_states = set()
            for step in workflow.steps:
                if not step.state_changing:
                    continue
                controlled_states.update(
                    reference
                    for reference in (
                        step.state_before_reference,
                        step.state_after_reference,
                    )
                    if reference is not None
                )
            if len(controlled_states) < 2 or not controlled_states.issubset(
                set(context.state_references)
            ):
                _fail(CompilerErrorCode.unknown_state_reference)
        protected = template.authentication_requirement in {
            GraphQLAuthenticationRequirement.authenticated_observed,
            GraphQLAuthenticationRequirement.authentication_required,
            GraphQLAuthenticationRequirement.role_bound,
            GraphQLAuthenticationRequirement.tenant_bound,
        }
        if (
            protected
            and kind is not GraphQLCandidateKind.authentication
            and not (identity_ids)
        ):
            _fail(CompilerErrorCode.uncontrolled_identity)
        for evidence_id in getattr(hypothesis, "supporting_evidence", ()):
            indexes.evidence(evidence_id)

    @staticmethod
    def _derive_state_changing(
        definitions: list[object],
        steps: list[CompiledPrimitiveStep],
        endpoint: Endpoint | None,
        adapter: ResearchExperimentCapabilityAdapter | None,
        indexes: "_StateIndexes",
    ) -> bool:
        if adapter is not None and adapter.state_changing:
            return True
        for definition, step in zip(definitions, steps, strict=True):
            behavior = definition.state_change_behavior
            if behavior is StateChangeBehavior.always:
                return True
            if behavior is StateChangeBehavior.never:
                continue
            primitive = step.input
            if (
                isinstance(
                    primitive,
                    (
                        GraphQLOperationInput,
                        GraphQLVariableMutationInput,
                        ObjectSubstitutionInput,
                    ),
                )
                and getattr(primitive, "operation_id", None) is not None
            ):
                operation = indexes.operation(primitive.operation_id)
                if operation.operation_type.value == "mutation":
                    return True
                continue
            if isinstance(primitive, WorkflowPrimitiveInput):
                workflow = indexes.workflow(primitive.workflow_id)
                selected = set(primitive.step_ids)
                if any(
                    item.state_changing
                    for item in workflow.steps
                    if item.step_id in selected
                ):
                    return True
                continue
            step_endpoint_id = getattr(primitive, "endpoint_id", None)
            step_endpoint = (
                indexes.endpoint(step_endpoint_id)
                if step_endpoint_id is not None
                else endpoint
            )
            if step_endpoint is not None and step_endpoint.method not in _SAFE_METHODS:
                return True
        return False

    @staticmethod
    def _derive_cleanup(
        state_changing: bool,
        capability_name: str,
        primitive_names: tuple[str, ...],
        target_class: TargetClass,
        adapter: ResearchExperimentCapabilityAdapter | None,
        context: ExperimentCompilerContext,
    ) -> CleanupPlan:
        if not state_changing:
            return CleanupPlan(required=False)
        matches = [
            item
            for item in context.cleanup_definitions
            if target_class in item.allowed_target_classes
            and (
                capability_name in item.capability_names
                or bool(set(primitive_names) & set(item.primitive_names))
            )
        ]
        if len(matches) > 1:
            matches.sort(key=lambda item: item.cleanup_reference)
        if matches:
            selected = matches[0]
            return CleanupPlan(
                required=True,
                cleanup_reference=selected.cleanup_reference,
                verification_predicate_reference=(
                    selected.verification_predicate_reference
                ),
                minimum_requests=selected.minimum_requests,
                worst_case_requests=selected.worst_case_requests,
            )
        if (
            adapter is not None
            and adapter.cleanup_required
            and (adapter.typed_phase2_executor_available)
        ):
            return CleanupPlan(
                required=True,
                cleanup_reference=f"phase2-cleanup:{capability_name}",
                verification_predicate_reference=(
                    f"phase2-cleanup-verified:{capability_name}"
                ),
                minimum_requests=1,
                worst_case_requests=1,
            )
        _fail(CompilerErrorCode.missing_cleanup)

    @staticmethod
    def _derive_request_estimate(
        definitions: list[object],
        steps: list[CompiledPrimitiveStep],
        adapter: ResearchExperimentCapabilityAdapter | None,
        cleanup: CleanupPlan,
    ) -> RequestEstimate:
        minimum = 0
        worst = 0
        for definition, step in zip(definitions, steps, strict=True):
            step_minimum = definition.minimum_requests
            step_worst = definition.worst_case_requests
            if isinstance(step.input, ParameterMutationInput):
                step_worst = min(step_worst, step.input.maximum_variants)
            minimum += step_minimum
            worst += step_worst
        if adapter is not None and not any(
            isinstance(step.input, AuthenticationDifferentialInput) for step in steps
        ):
            minimum = max(
                minimum,
                max(0, adapter.min_requests - cleanup.minimum_requests),
            )
            worst = max(
                worst,
                max(0, adapter.worst_case_requests - cleanup.worst_case_requests),
            )
        minimum_total = minimum + cleanup.minimum_requests
        total = worst + cleanup.worst_case_requests
        return RequestEstimate(
            discovery=0,
            auth=0,
            verification=worst,
            cleanup=cleanup.worst_case_requests,
            minimum=minimum_total,
            worst_case=total,
            total_reservation=total,
        )

    @staticmethod
    def _derive_risk(
        definitions: list[object], state_changing: bool
    ) -> RiskClassification:
        levels = [item.risk_class for item in definitions]
        if state_changing:
            levels.append(RiskLevel.moderate)
        level = max(levels, key=_RISK_ORDER.__getitem__)
        references = tuple(
            sorted(
                {
                    *(f"primitive:{item.name}/v{item.version}" for item in definitions),
                    *(("method:state-changing",) if state_changing else ()),
                }
            )
        )
        return RiskClassification(level=level, derivation_references=references)

    @staticmethod
    def _derive_mutation(
        proposal: ExperimentProposal,
        parameters: list[Parameter],
        objects: list[ResearchObject],
    ) -> ControlledMutation:
        object_types = tuple(sorted({item.object_type for item in objects}))
        relationships = tuple(
            sorted(
                {
                    *(
                        [proposal.identity_relationship.value]
                        if proposal.identity_relationship is not None
                        else []
                    ),
                    *("test-owned" for _item in objects),
                }
            )
        )
        value_sources = tuple(
            sorted(
                {
                    *(
                        [proposal.mutation_intent.value_source_reference]
                        if proposal.mutation_intent.value_source_reference is not None
                        else []
                    ),
                    *(
                        item.input.value_source_reference
                        for item in proposal.primitive_steps
                        if hasattr(item.input, "value_source_reference")
                        and item.input.value_source_reference is not None
                    ),
                }
            )
        )
        return ControlledMutation(
            kind=str(
                proposal.mutation_intent.kind.value
                if hasattr(proposal.mutation_intent.kind, "value")
                else proposal.mutation_intent.kind
            ),
            parameter_ids=tuple(
                sorted(
                    {
                        *(item.parameter_id for item in parameters),
                        *(
                            [proposal.mutation_intent.parameter_id]
                            if proposal.mutation_intent.parameter_id is not None
                            else []
                        ),
                    }
                )
            ),
            controlled_object_ids=tuple(
                sorted(
                    {
                        *(item.object_id for item in objects),
                        *(
                            [proposal.mutation_intent.controlled_object_id]
                            if proposal.mutation_intent.controlled_object_id is not None
                            else []
                        ),
                    }
                )
            ),
            object_types=object_types,
            ownership_relationships=relationships,
            value_source_references=value_sources,
        )


class _StateIndexes:
    def __init__(self, state: ResearchState) -> None:
        self.state = state

    def _required(self, collection: Iterable[object], field: str, value: str, code):
        for item in collection:
            if getattr(item, field) == value:
                return item
        _fail(code)

    def target(self, value: str):
        return self._required(
            self.state.targets,
            "target_id",
            value,
            CompilerErrorCode.unknown_target,
        )

    def surface(self, value: str):
        return self._required(
            self.state.surfaces,
            "surface_id",
            value,
            CompilerErrorCode.unknown_surface,
        )

    def optional_surface(self, value: str | None):
        return None if value is None else self.surface(value)

    def endpoint(self, value: str):
        return self._required(
            self.state.endpoints,
            "endpoint_id",
            value,
            CompilerErrorCode.unknown_endpoint,
        )

    def optional_endpoint(self, value: str | None):
        return None if value is None else self.endpoint(value)

    def parameter(self, value: str):
        return self._required(
            self.state.parameters,
            "parameter_id",
            value,
            CompilerErrorCode.unknown_parameter,
        )

    def identity(self, value: str):
        return self._required(
            self.state.identities,
            "identity_id",
            value,
            CompilerErrorCode.unknown_identity,
        )

    def session(self, value: str):
        return self._required(
            self.state.session_refs,
            "session_ref_id",
            value,
            CompilerErrorCode.unknown_session,
        )

    def token(self, value: str):
        return self._required(
            self.state.token_refs,
            "token_ref_id",
            value,
            CompilerErrorCode.unknown_token,
        )

    def object(self, value: str):
        return self._required(
            self.state.objects,
            "object_id",
            value,
            CompilerErrorCode.unknown_object,
        )

    def operation(self, value: str):
        return self._required(
            self.state.graphql_operations,
            "operation_id",
            value,
            CompilerErrorCode.unknown_operation,
        )

    def optional_operation(self, value: str | None):
        return None if value is None else self.operation(value)

    def graphql_surface(self, value: str) -> GraphQLSurface:
        return self._required(
            self.state.graphql_surfaces,
            "graphql_surface_id",
            value,
            CompilerErrorCode.unknown_graphql_surface,
        )

    def graphql_field(self, value: str) -> GraphQLFieldRecord:
        return self._required(
            self.state.graphql_fields,
            "field_id",
            value,
            CompilerErrorCode.unknown_graphql_field,
        )

    def graphql_argument(self, value: str) -> GraphQLArgumentRecord:
        return self._required(
            self.state.graphql_arguments,
            "argument_id",
            value,
            CompilerErrorCode.unknown_graphql_argument,
        )

    def graphql_variable(self, value: str) -> GraphQLVariableRecord:
        return self._required(
            self.state.graphql_variables,
            "variable_id",
            value,
            CompilerErrorCode.unknown_graphql_variable,
        )

    def evidence(self, value: str):
        return self._required(
            self.state.evidence,
            "evidence_id",
            value,
            CompilerErrorCode.unknown_evidence,
        )

    def provenance(self, value: str):
        return self._required(
            self.state.provenance,
            "provenance_id",
            value,
            CompilerErrorCode.unknown_provenance,
        )

    def outcome(self, value: str):
        return self._required(
            self.state.experiment_outcomes,
            "outcome_id",
            value,
            CompilerErrorCode.unknown_outcome,
        )

    def hypothesis(self, value: str):
        return self._required(
            self.state.hypotheses,
            "hypothesis_id",
            value,
            CompilerErrorCode.unknown_hypothesis,
        )

    def workflow(self, value: str):
        return self._required(
            self.state.workflows,
            "workflow_id",
            value,
            CompilerErrorCode.unknown_workflow,
        )

    def upload(self, value: str):
        return self._required(
            self.state.uploads,
            "upload_id",
            value,
            CompilerErrorCode.unknown_upload,
        )


def _fail(code: CompilerErrorCode):
    raise ExperimentCompilerError(code)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value
    )
    return parsed.astimezone(timezone.utc)


def _derive_expiry(
    proposal_expiry: str | None, context: ExperimentCompilerContext
) -> str:
    deadline = _parse_timestamp(context.current_time) + timedelta(
        seconds=context.experiment_ttl_seconds
    )
    expiry = (
        deadline
        if proposal_expiry is None
        else min(_parse_timestamp(proposal_expiry), deadline)
    )
    return expiry.isoformat()


def _experiment_id(proposal: ExperimentProposal) -> str:
    seed = f"{proposal.research_id}\0{proposal.proposal_id}\0{proposal.state_revision}"
    return "experiment-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _template(
    context: ExperimentCompilerContext, template_id: str
) -> RegisteredRequestTemplate:
    for item in context.request_templates:
        if item.template_id == template_id:
            return item
    _fail(CompilerErrorCode.unknown_request_template)


def _graphql_template(
    context: ExperimentCompilerContext, template_id: str
) -> RegisteredGraphQLOperationTemplate:
    for item in context.graphql_operation_templates:
        if item.template_id == template_id:
            return item
    _fail(CompilerErrorCode.unknown_graphql_operation_template)


def _graphql_safe_mutation(
    context: ExperimentCompilerContext, mutation_id: str
) -> RegisteredGraphQLSafeMutation:
    for item in context.graphql_safe_mutations:
        if item.mutation_id == mutation_id:
            return item
    _fail(CompilerErrorCode.unknown_graphql_safe_mutation)


def _safe_header(
    context: ExperimentCompilerContext, header_id: str
) -> RegisteredSafeHeader:
    for item in context.safe_headers:
        if item.header_definition_id == header_id:
            return item
    _fail(CompilerErrorCode.unknown_safe_header)


def _require_authentication_mechanism(template: RegisteredRequestTemplate) -> None:
    if not set(template.authentication_mechanisms).intersection(
        {"authorization_header", "cookie"}
    ):
        _fail(CompilerErrorCode.missing_authentication_mechanism)


def _credential_header(name: str) -> bool:
    normalized = name.casefold().replace("_", "-")
    return normalized in _CREDENTIAL_HEADERS or any(
        marker in normalized for marker in ("credential", "api-key", "auth-token")
    )


def _require_value_source(
    context: ExperimentCompilerContext, value_reference: str
) -> None:
    if value_reference not in set(context.controlled_value_references):
        _fail(CompilerErrorCode.unknown_value_source)


def _validate_template(
    template: RegisteredRequestTemplate,
    endpoint: Endpoint | None,
    proposal: ExperimentProposal,
) -> None:
    if template.target_id != proposal.target_id:
        _fail(CompilerErrorCode.request_template_mismatch)
    if proposal.surface_id is not None and template.surface_id != proposal.surface_id:
        _fail(CompilerErrorCode.request_template_mismatch)
    if endpoint is not None and template.endpoint_id != endpoint.endpoint_id:
        _fail(CompilerErrorCode.request_template_mismatch)


def _validate_parameter(
    parameter: Parameter,
    endpoint: Endpoint | None,
    template: RegisteredRequestTemplate | None,
) -> None:
    if endpoint is not None and parameter.endpoint_id != endpoint.endpoint_id:
        _fail(CompilerErrorCode.parameter_endpoint_mismatch)
    if template is not None and parameter.parameter_id not in template.parameter_ids:
        _fail(CompilerErrorCode.parameter_endpoint_mismatch)


def _single_endpoint(
    proposal_endpoint: Endpoint | None, endpoints: Iterable[Endpoint]
) -> Endpoint | None:
    unique = {item.endpoint_id: item for item in endpoints}
    if proposal_endpoint is not None:
        unique[proposal_endpoint.endpoint_id] = proposal_endpoint
    if len(unique) > 1:
        _fail(CompilerErrorCode.request_template_mismatch)
    return next(iter(unique.values()), None)


def _single_operation_id(
    direct: GraphQLOperation | None,
    steps: Iterable[CompiledPrimitiveStep],
) -> str | None:
    identifiers = {
        value
        for item in steps
        if (value := getattr(item.input, "operation_id", None)) is not None
    }
    if direct is not None:
        identifiers.add(direct.operation_id)
    if len(identifiers) > 1:
        _fail(CompilerErrorCode.operation_endpoint_mismatch)
    return next(iter(identifiers), None)


def _stop_conditions(max_response_bytes: int) -> StopConditions:
    return StopConditions(
        items=tuple(
            StopCondition(
                code=code,
                bound=(
                    max_response_bytes
                    if code is StopConditionCode.response_size_bound
                    else None
                ),
            )
            for code in StopConditionCode
        )
    )
