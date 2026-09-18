"""Typed, reference-only building blocks for Phase 4 security experiments.

Primitive inputs describe registered research objects.  They never contain a
destination URL, request bytes, credential value, or executable content.
P4-0C validates and compiles these records but does not execute them.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, StrictInt, model_validator

from agent_core.research.types import (
    EndpointId,
    EvidenceArtifactId,
    GraphQLOperationId,
    IdentityId,
    OpaqueIdentifier,
    ParameterId,
    ResearchContract,
    ResearchObjectId,
    SessionRefId,
    TokenRefId,
    UploadArtifactId,
    WorkflowId,
)

PRIMITIVE_SCHEMA_VERSION = 1


class PrimitiveCapabilityState(str, Enum):
    """How far a primitive is implemented in the current architecture."""

    defined = "defined"
    compile_only = "compile_only"
    execution_available = "execution_available"


class StateChangeBehavior(str, Enum):
    never = "never"
    method_dependent = "method_dependent"
    always = "always"


class CleanupBehavior(str, Enum):
    not_required = "not_required"
    method_dependent = "method_dependent"
    required = "required"


class IdentityRelationship(str, Enum):
    same_tenant_different_account = "same_tenant_different_account"
    different_controlled_tenant = "different_controlled_tenant"
    user_admin = "user_admin"
    owner_non_owner = "owner_non_owner"
    same_identity = "same_identity"


class MutationKind(str, Enum):
    replace_with_controlled_value = "replace_with_controlled_value"
    replace_with_controlled_object_reference = (
        "replace_with_controlled_object_reference"
    )
    remove_parameter = "remove_parameter"
    duplicate_parameter = "duplicate_parameter"
    change_scalar_type = "change_scalar_type"
    boundary_value = "boundary_value"
    harmless_canary = "harmless_canary"


class HeaderMutationOperation(str, Enum):
    remove = "remove"
    replace_with_registered_value = "replace_with_registered_value"


class CookieMutationOperation(str, Enum):
    remove_controlled_session_cookie = "remove_controlled_session_cookie"
    replace_with_controlled_session = "replace_with_controlled_session"


class TokenMutationOperation(str, Enum):
    remove_controlled_token = "remove_controlled_token"
    replace_with_controlled_token = "replace_with_controlled_token"


class DifferentialSelector(str, Enum):
    status_class = "status_class"
    content_length_class = "content_length_class"
    content_type = "content_type"
    selected_json_path_presence = "selected_json_path_presence"
    selected_graphql_error_class = "selected_graphql_error_class"
    state_marker = "state_marker"
    protected_field_presence = "protected_field_presence"
    semantic_result_class = "semantic_result_class"


class SafeValueBinding(ResearchContract):
    """Bind a registered parameter to a registered, non-secret value source."""

    parameter_id: ParameterId
    value_source_reference: OpaqueIdentifier


class RequestReplayInput(ResearchContract):
    primitive: Literal["request_replay"] = "request_replay"
    request_template_id: OpaqueIdentifier
    endpoint_id: EndpointId
    identity_id: IdentityId | None = None
    session_ref_id: SessionRefId | None = None
    bindings: tuple[SafeValueBinding, ...] = Field(default=(), max_length=50)


class IdentitySwitchInput(ResearchContract):
    primitive: Literal["identity_switch"] = "identity_switch"
    primary_identity_id: IdentityId
    comparison_identity_id: IdentityId
    relationship: IdentityRelationship

    @model_validator(mode="after")
    def validate_pair(self) -> "IdentitySwitchInput":
        if (
            self.primary_identity_id == self.comparison_identity_id
            and self.relationship is not IdentityRelationship.same_identity
        ):
            raise ValueError("identity relationship requires distinct identities")
        if (
            self.primary_identity_id != self.comparison_identity_id
            and self.relationship is IdentityRelationship.same_identity
        ):
            raise ValueError("same_identity requires one identity reference")
        return self


class ParameterMutationInput(ResearchContract):
    primitive: Literal["parameter_mutation"] = "parameter_mutation"
    request_template_id: OpaqueIdentifier
    endpoint_id: EndpointId
    parameter_id: ParameterId
    mutation_kind: MutationKind
    value_source_reference: OpaqueIdentifier | None = None
    controlled_object_id: ResearchObjectId | None = None
    maximum_variants: StrictInt = Field(default=1, ge=1, le=3)

    @model_validator(mode="after")
    def validate_value_source(self) -> "ParameterMutationInput":
        if (
            self.mutation_kind
            in {
                MutationKind.replace_with_controlled_value,
                MutationKind.boundary_value,
                MutationKind.harmless_canary,
            }
            and self.value_source_reference is None
        ):
            raise ValueError("mutation kind requires a registered value source")
        if (
            self.mutation_kind is MutationKind.replace_with_controlled_object_reference
            and self.controlled_object_id is None
        ):
            raise ValueError("object-reference mutation requires a controlled object")
        return self


class ObjectSubstitutionInput(ResearchContract):
    primitive: Literal["object_substitution"] = "object_substitution"
    request_template_id: OpaqueIdentifier | None = None
    operation_id: GraphQLOperationId | None = None
    endpoint_id: EndpointId
    parameter_id: ParameterId
    primary_identity_id: IdentityId
    comparison_identity_id: IdentityId
    controlled_object_id: ResearchObjectId
    relationship: IdentityRelationship
    ownership_evidence_ids: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=20
    )

    @model_validator(mode="after")
    def require_template_or_operation(self) -> "ObjectSubstitutionInput":
        if (self.request_template_id is None) == (self.operation_id is None):
            raise ValueError("exactly one request template or operation is required")
        if self.primary_identity_id == self.comparison_identity_id:
            raise ValueError("object substitution requires distinct identities")
        return self


class HeaderMutationInput(ResearchContract):
    primitive: Literal["header_mutation"] = "header_mutation"
    request_template_id: OpaqueIdentifier
    endpoint_id: EndpointId
    header_definition_id: OpaqueIdentifier
    operation: HeaderMutationOperation
    value_source_reference: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_value_source(self) -> "HeaderMutationInput":
        if (
            self.operation is HeaderMutationOperation.replace_with_registered_value
            and self.value_source_reference is None
        ):
            raise ValueError("header replacement requires a registered value source")
        return self


class CookieMutationInput(ResearchContract):
    primitive: Literal["cookie_mutation"] = "cookie_mutation"
    request_template_id: OpaqueIdentifier
    endpoint_id: EndpointId
    primary_session_ref_id: SessionRefId
    operation: CookieMutationOperation
    replacement_session_ref_id: SessionRefId | None = None

    @model_validator(mode="after")
    def validate_replacement(self) -> "CookieMutationInput":
        requires_replacement = (
            self.operation is CookieMutationOperation.replace_with_controlled_session
        )
        if requires_replacement != (self.replacement_session_ref_id is not None):
            raise ValueError("cookie operation has an invalid replacement session")
        return self


class DifferentialReference(ResearchContract):
    kind: Literal["evidence", "experiment_outcome"]
    reference_id: OpaqueIdentifier


class SelectorSpec(ResearchContract):
    selector: DifferentialSelector
    path_reference: OpaqueIdentifier | None = None

    @model_validator(mode="after")
    def validate_path(self) -> "SelectorSpec":
        if (
            self.selector is DifferentialSelector.selected_json_path_presence
            and self.path_reference is None
        ):
            raise ValueError("JSON path selector requires a registered path reference")
        return self


class ResponseDifferentialInput(ResearchContract):
    primitive: Literal["response_differential"] = "response_differential"
    references: tuple[DifferentialReference, ...] = Field(min_length=2, max_length=20)
    selectors: tuple[SelectorSpec, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def validate_comparison(self) -> "ResponseDifferentialInput":
        references = tuple((item.kind, item.reference_id) for item in self.references)
        selectors = tuple(
            (item.selector, item.path_reference) for item in self.selectors
        )
        if len(references) != len(set(references)):
            raise ValueError("response differential references must be unique")
        if len(selectors) != len(set(selectors)):
            raise ValueError("response differential selectors must be unique")
        return self


class StateDifferentialInput(ResearchContract):
    primitive: Literal["state_differential"] = "state_differential"
    before_state_reference: OpaqueIdentifier
    after_state_reference: OpaqueIdentifier
    cleanup_state_reference: OpaqueIdentifier | None = None
    invariant_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=20
    )

    @model_validator(mode="after")
    def validate_states(self) -> "StateDifferentialInput":
        if self.before_state_reference == self.after_state_reference:
            raise ValueError(
                "state differential requires distinct before and after states"
            )
        if len(self.invariant_references) != len(set(self.invariant_references)):
            raise ValueError("state differential invariants must be unique")
        return self


class GraphQLOperationInput(ResearchContract):
    primitive: Literal["graphql_operation"] = "graphql_operation"
    operation_id: GraphQLOperationId
    identity_id: IdentityId | None = None


class GraphQLVariableMutationInput(ResearchContract):
    primitive: Literal["graphql_variable_mutation"] = "graphql_variable_mutation"
    operation_id: GraphQLOperationId
    parameter_id: ParameterId
    mutation_kind: MutationKind
    value_source_reference: OpaqueIdentifier | None = None


class TokenMutationInput(ResearchContract):
    primitive: Literal["token_mutation"] = "token_mutation"
    endpoint_id: EndpointId
    token_ref_id: TokenRefId
    operation: TokenMutationOperation
    replacement_token_ref_id: TokenRefId | None = None


class WorkflowPrimitiveInput(ResearchContract):
    primitive: Literal["workflow_step_replay", "workflow_step_skip", "workflow_reorder"]
    workflow_id: WorkflowId
    step_ids: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=20)


class UploadVariantInput(ResearchContract):
    primitive: Literal["upload_variant"] = "upload_variant"
    upload_id: UploadArtifactId
    endpoint_id: EndpointId
    variant_reference: OpaqueIdentifier


PrimitiveInput: TypeAlias = Annotated[
    RequestReplayInput
    | IdentitySwitchInput
    | ParameterMutationInput
    | ObjectSubstitutionInput
    | HeaderMutationInput
    | CookieMutationInput
    | ResponseDifferentialInput
    | StateDifferentialInput
    | GraphQLOperationInput
    | GraphQLVariableMutationInput
    | TokenMutationInput
    | WorkflowPrimitiveInput
    | UploadVariantInput,
    Field(discriminator="primitive"),
]


class PrimitiveStepProposal(ResearchContract):
    step_id: OpaqueIdentifier
    input: PrimitiveInput

    @property
    def primitive_name(self) -> str:
        return self.input.primitive


class CompiledPrimitiveStep(ResearchContract):
    step_id: OpaqueIdentifier
    primitive_name: OpaqueIdentifier
    primitive_version: OpaqueIdentifier
    input: PrimitiveInput
    output_type: OpaqueIdentifier
    capability_state: PrimitiveCapabilityState

    @model_validator(mode="after")
    def validate_name(self) -> "CompiledPrimitiveStep":
        if self.primitive_name != self.input.primitive:
            raise ValueError("primitive step name must match its typed input")
        return self


class ReplayEvidence(ResearchContract):
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=20
    )


class ContextEvidence(ResearchContract):
    identity_ids: tuple[IdentityId, ...] = Field(min_length=1, max_length=2)


class MutationEvidence(ResearchContract):
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        min_length=1, max_length=20
    )


class DifferentialEvidence(ResearchContract):
    selector_results: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=20)
    evidence_references: tuple[EvidenceArtifactId, ...] = Field(
        default=(), max_length=20
    )


class StateChangeEvidence(ResearchContract):
    invariant_results: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=20)
    before_evidence_id: EvidenceArtifactId
    after_evidence_id: EvidenceArtifactId
    cleanup_evidence_id: EvidenceArtifactId | None = None


def primitive_reference(name: str, version: str) -> str:
    """Return the canonical, bounded registry key for a primitive."""

    return f"{name}@{version}"
