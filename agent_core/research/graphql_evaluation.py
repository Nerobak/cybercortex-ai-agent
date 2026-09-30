"""Deterministic GraphQL differential evaluation for Phase 4 research.

The evaluator consumes only registered semantics and bounded runtime structure.
It never consumes response text or values, and its signal is still subject to
the ordinary :class:`ExperimentEvaluator` candidate-finding lifecycle.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from pydantic import Field, model_validator

from agent_core.research.experiments import SecurityExperiment
from agent_core.research.graphql import (
    GraphQLAuthenticationRequirement,
    GraphQLAuthorizationObservation,
    GraphQLCandidateKind,
    GraphQLErrorClass,
    GraphQLFieldRecord,
    GraphQLOperationRecord,
    GraphQLSemanticRole,
)
from agent_core.research.outcomes import (
    ExperimentOutcome,
    ExperimentResultClassification,
    GraphQLRuntimeResponseEvidence,
    GraphQLStateDifferentialEvidence,
)
from agent_core.research.primitives import (
    GraphQLOperationInput,
    GraphQLVariableMutationInput,
    IdentityRelationship,
    StateDifferentialInput,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.state import HypothesisRecord, ResearchState
from agent_core.research.types import (
    CleanupStatus,
    EntityKind,
    IdentityEligibility,
    OpaqueIdentifier,
    ResearchContract,
)


GRAPHQL_EVALUATION_VERSION = "phase4-graphql-evaluation-v1"


class GraphQLSecurityProperty(str, Enum):
    authentication_enforcement = "authentication_enforcement"
    object_authorization = "object_authorization"
    field_authorization = "field_authorization"
    operation_authorization = "operation_authorization"
    role_authorization = "role_authorization"
    tenant_authorization = "tenant_authorization"
    ownership_authorization = "ownership_authorization"
    mutation_authorization = "mutation_authorization"
    nested_resolver_authorization = "nested_resolver_authorization"
    cross_surface_authorization = "cross_surface_authorization"
    bounded_input_validation = "bounded_input_validation"
    workflow_mutation_authorization = "workflow_mutation_authorization"


_PROPERTY_ALIASES = {
    "authentication-enforcement": GraphQLSecurityProperty.authentication_enforcement,
    "authentication_enforcement": GraphQLSecurityProperty.authentication_enforcement,
    "object-authorization": GraphQLSecurityProperty.object_authorization,
    "object_authorization": GraphQLSecurityProperty.object_authorization,
    "field-level-authorization": GraphQLSecurityProperty.field_authorization,
    "field-authorization": GraphQLSecurityProperty.field_authorization,
    "field_authorization": GraphQLSecurityProperty.field_authorization,
    "operation-level-authorization": GraphQLSecurityProperty.operation_authorization,
    "operation-authorization": GraphQLSecurityProperty.operation_authorization,
    "operation_authorization": GraphQLSecurityProperty.operation_authorization,
    "role-bound-access": GraphQLSecurityProperty.role_authorization,
    "role-authorization": GraphQLSecurityProperty.role_authorization,
    "role_authorization": GraphQLSecurityProperty.role_authorization,
    "tenant-bound-access": GraphQLSecurityProperty.tenant_authorization,
    "tenant-authorization": GraphQLSecurityProperty.tenant_authorization,
    "tenant_authorization": GraphQLSecurityProperty.tenant_authorization,
    "ownership-authorization": GraphQLSecurityProperty.ownership_authorization,
    "ownership_authorization": GraphQLSecurityProperty.ownership_authorization,
    "mutation-authorization": GraphQLSecurityProperty.mutation_authorization,
    "mutation_authorization": GraphQLSecurityProperty.mutation_authorization,
    "relationship-traversal-authorization": (
        GraphQLSecurityProperty.nested_resolver_authorization
    ),
    "nested-resolver-authorization": (
        GraphQLSecurityProperty.nested_resolver_authorization
    ),
    "nested_resolver_authorization": (
        GraphQLSecurityProperty.nested_resolver_authorization
    ),
    "cross-surface-authorization": (
        GraphQLSecurityProperty.cross_surface_authorization
    ),
    "cross_surface_authorization": (
        GraphQLSecurityProperty.cross_surface_authorization
    ),
    "argument-input-validation": GraphQLSecurityProperty.bounded_input_validation,
    "bounded-input-validation": GraphQLSecurityProperty.bounded_input_validation,
    "bounded_input_validation": GraphQLSecurityProperty.bounded_input_validation,
    "workflow-bound-mutation": (
        GraphQLSecurityProperty.workflow_mutation_authorization
    ),
    "workflow-mutation-authorization": (
        GraphQLSecurityProperty.workflow_mutation_authorization
    ),
    "workflow_mutation_authorization": (
        GraphQLSecurityProperty.workflow_mutation_authorization
    ),
}


_KIND_PROPERTY = {
    GraphQLCandidateKind.authentication: (
        GraphQLSecurityProperty.authentication_enforcement
    ),
    GraphQLCandidateKind.object_authorization: (
        GraphQLSecurityProperty.object_authorization
    ),
    GraphQLCandidateKind.field_authorization: (
        GraphQLSecurityProperty.field_authorization
    ),
    GraphQLCandidateKind.operation_authorization: (
        GraphQLSecurityProperty.operation_authorization
    ),
    GraphQLCandidateKind.role_bound: GraphQLSecurityProperty.role_authorization,
    GraphQLCandidateKind.tenant_bound: GraphQLSecurityProperty.tenant_authorization,
    GraphQLCandidateKind.ownership: (GraphQLSecurityProperty.ownership_authorization),
    GraphQLCandidateKind.mutation_authorization: (
        GraphQLSecurityProperty.mutation_authorization
    ),
    GraphQLCandidateKind.nested_resolver: (
        GraphQLSecurityProperty.nested_resolver_authorization
    ),
    GraphQLCandidateKind.cross_surface: (
        GraphQLSecurityProperty.cross_surface_authorization
    ),
    GraphQLCandidateKind.input_validation: (
        GraphQLSecurityProperty.bounded_input_validation
    ),
    GraphQLCandidateKind.workflow_mutation: (
        GraphQLSecurityProperty.workflow_mutation_authorization
    ),
}


class GraphQLControlledRelationships(ResearchContract):
    """Caller-supplied relationship claims, validated against ``ResearchState``."""

    primary_identity_id: OpaqueIdentifier | None = None
    comparison_identity_id: OpaqueIdentifier | None = None
    identity_relationship: IdentityRelationship | None = None
    controlled_object_ids: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )


class GraphQLStructuralEvidence(ResearchContract):
    """A secret-free projection of the GraphQL evidence in one runtime outcome."""

    responses: tuple[GraphQLRuntimeResponseEvidence, ...] = Field(
        default=(), max_length=200
    )
    state_differentials: tuple[GraphQLStateDifferentialEvidence, ...] = Field(
        default=(), max_length=200
    )
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=200
    )

    @classmethod
    def from_outcome(cls, outcome: ExperimentOutcome) -> "GraphQLStructuralEvidence":
        return cls(
            responses=tuple(
                response
                for item in outcome.evidence
                for response in item.graphql_responses
            ),
            state_differentials=tuple(
                differential
                for item in outcome.evidence
                for differential in item.graphql_state_differentials
            ),
            evidence_references=outcome.evidence_references,
        )


class GraphQLEvaluationResult(ResearchContract):
    """Typed deterministic signal passed into the generic experiment evaluator."""

    evaluation_id: OpaqueIdentifier
    evaluator_version: OpaqueIdentifier = GRAPHQL_EVALUATION_VERSION
    experiment_id: OpaqueIdentifier
    outcome_id: OpaqueIdentifier
    hypothesis_id: OpaqueIdentifier
    security_property: GraphQLSecurityProperty | None = None
    classification: ExperimentResultClassification
    operation_reference: OpaqueIdentifier | None = None
    field_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=64)
    argument_references: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=64)
    controlled_identity_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=2
    )
    controlled_object_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=200
    )
    baseline_evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    comparison_evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    request_accounting_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    runtime_provenance_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=100
    )
    missing_evidence: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=50)
    conflict_codes: tuple[OpaqueIdentifier, ...] = Field(default=(), max_length=50)
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_signal(self) -> "GraphQLEvaluationResult":
        for name in (
            "field_references",
            "argument_references",
            "controlled_identity_references",
            "controlled_object_references",
            "evidence_references",
            "baseline_evidence_references",
            "comparison_evidence_references",
            "request_accounting_references",
            "runtime_provenance_references",
            "missing_evidence",
            "conflict_codes",
        ):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicates")
            object.__setattr__(self, name, tuple(sorted(values)))
        if self.classification in {
            ExperimentResultClassification.secure_signal,
            ExperimentResultClassification.vulnerable_signal,
        }:
            if self.security_property is None:
                raise ValueError("a GraphQL security signal requires a tested property")
            if not self.evidence_references:
                raise ValueError("a GraphQL security signal requires runtime evidence")
            if self.missing_evidence or self.conflict_codes:
                raise ValueError("a conclusive GraphQL signal cannot be insufficient")
        reject_secret_material(
            self.model_dump(mode="json"), location="GraphQL evaluation result"
        )
        return self

    def classified_outcome(self, outcome: ExperimentOutcome) -> ExperimentOutcome:
        """Return the same authoritative outcome with only its signal replaced."""

        if outcome.outcome_id != self.outcome_id:
            raise ValueError("GraphQL evaluation result belongs to another outcome")
        return outcome.model_copy(update={"result_classification": self.classification})


class _Access(str, Enum):
    available = "available"
    denied = "denied"
    unknown = "unknown"
    failed = "failed"
    conflicting = "conflicting"


@dataclass(frozen=True)
class _BoundResponse:
    evidence_id: str
    role: str
    response: GraphQLRuntimeResponseEvidence


class GraphQLDifferentialEvaluator:
    """Apply registered, property-specific predicates to GraphQL structure."""

    @staticmethod
    def applies_to(experiment: SecurityExperiment) -> bool:
        return any(
            isinstance(
                item.input, (GraphQLOperationInput, GraphQLVariableMutationInput)
            )
            and item.input.candidate_kind is not None
            for item in experiment.primitive_steps
        )

    def evaluate(
        self,
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
        source_hypothesis: HypothesisRecord | None = None,
        state: ResearchState | None = None,
        *,
        structural_evidence: GraphQLStructuralEvidence | None = None,
        relevant_semantic_records: Sequence[object] = (),
        controlled_relationships: GraphQLControlledRelationships | None = None,
    ) -> GraphQLEvaluationResult:
        if outcome.experiment_id != experiment.experiment_id:
            raise ValueError("GraphQL outcome does not belong to experiment")
        if state is None:
            raise ValueError("GraphQL evaluation requires the authoritative state")
        hypothesis = source_hypothesis or next(
            (
                item
                for item in state.hypotheses
                if item.hypothesis_id == experiment.hypothesis_id
            ),
            None,
        )
        if hypothesis is None or hypothesis.hypothesis_id != experiment.hypothesis_id:
            raise ValueError("GraphQL source hypothesis is unavailable")
        if hypothesis.target_id != experiment.target.target_id:
            raise ValueError("GraphQL hypothesis target changed")

        authoritative_structure = GraphQLStructuralEvidence.from_outcome(outcome)
        structure = structural_evidence or authoritative_structure
        if structure != authoritative_structure:
            raise ValueError("GraphQL structural evidence changed from runtime outcome")
        if set(structure.evidence_references) != set(outcome.evidence_references):
            raise ValueError("GraphQL structural evidence does not match outcome")
        property_ = _PROPERTY_ALIASES.get(str(hypothesis.security_property or ""))
        kinds = {
            item.input.candidate_kind
            for item in experiment.primitive_steps
            if isinstance(
                item.input, (GraphQLOperationInput, GraphQLVariableMutationInput)
            )
            and item.input.candidate_kind is not None
        }
        registered_kind = next(iter(kinds)) if len(kinds) == 1 else None
        missing: set[str] = set()
        conflicts: set[str] = set()
        if property_ is None:
            missing.add("registered-tested-security-property")
        if registered_kind is None:
            missing.add("consistent-graphql-candidate-kind")
        elif (
            property_ is not None
            and _KIND_PROPERTY.get(registered_kind) is not property_
        ):
            conflicts.add("security-property-kind-mismatch")

        operation_id = self._operation_id(experiment)
        operation = next(
            (
                item
                for item in (*state.graphql_operations, *relevant_semantic_records)
                if isinstance(item, GraphQLOperationRecord)
                and item.operation_id == operation_id
            ),
            None,
        )
        if operation is None:
            missing.add("registered-graphql-operation")
        hypothesis_field_ids = {
            item.entity_id
            for item in hypothesis.entity_references
            if item.entity_kind is EntityKind.graphql_field
        }
        selected_field_ids = {
            field_id
            for step in experiment.primitive_steps
            if isinstance(step.input, GraphQLOperationInput)
            for field_id in step.input.selected_field_ids
        }
        field_ids = tuple(sorted(selected_field_ids or hypothesis_field_ids))
        argument_ids = tuple(
            sorted(
                item.entity_id
                for item in hypothesis.entity_references
                if item.entity_kind is EntityKind.graphql_argument
            )
        )
        fields = tuple(
            item
            for item in (*state.graphql_fields, *relevant_semantic_records)
            if isinstance(item, GraphQLFieldRecord) and item.field_id in field_ids
        )
        identities = tuple(
            item
            for item in (
                experiment.identity_context.primary_identity_id,
                experiment.identity_context.comparison_identity_id,
            )
            if item is not None
        )
        object_ids = tuple(
            sorted(
                {
                    *experiment.mutation.controlled_object_ids,
                    *(
                        item.entity_id
                        for item in hypothesis.entity_references
                        if item.entity_kind is EntityKind.object
                    ),
                }
            )
        )
        relations = controlled_relationships or GraphQLControlledRelationships(
            primary_identity_id=experiment.identity_context.primary_identity_id,
            comparison_identity_id=experiment.identity_context.comparison_identity_id,
            identity_relationship=experiment.identity_context.relationship,
            controlled_object_ids=object_ids,
        )
        if (
            relations.primary_identity_id
            != experiment.identity_context.primary_identity_id
            or relations.comparison_identity_id
            != experiment.identity_context.comparison_identity_id
            or relations.identity_relationship
            != experiment.identity_context.relationship
            or set(relations.controlled_object_ids) != set(object_ids)
        ):
            conflicts.add("controlled-relationship-mismatch")

        bound = self._bind_responses(experiment, outcome)
        response_count = len(bound)
        if response_count != len(structure.responses):
            conflicts.add("graphql-response-binding-mismatch")
        baseline = tuple(item for item in bound if item.role == "baseline")
        comparison = tuple(item for item in bound if item.role == "comparison")
        all_responses = tuple(item.response for item in bound)
        if any(
            item.authorized_experiment_reference != outcome.authorization_reference
            or item.operation_reference != operation_id
            or item.operation_template_reference != experiment.baseline.reference_id
            for item in all_responses
        ):
            conflicts.add("stale-or-cross-operation-runtime-evidence")
        if any(item.role == "identity-mismatch" for item in bound):
            conflicts.add("identity-context-changed")
        runtime_object_ids = set(experiment.mutation.controlled_object_ids)
        if runtime_object_ids and any(
            set(item.object_references) != runtime_object_ids for item in all_responses
        ):
            conflicts.add("controlled-object-context-changed")
        if any(item.truncated for item in all_responses):
            missing.add("complete-graphql-response-structure")
        if (
            property_ is GraphQLSecurityProperty.workflow_mutation_authorization
            and operation is not None
        ):
            workflow = next(
                (
                    item
                    for item in state.workflows
                    if item.workflow_id == operation.workflow_id
                ),
                None,
            )
            workflow_states = {
                reference
                for step in (() if workflow is None else workflow.steps)
                for reference in (
                    step.state_before_reference,
                    step.state_after_reference,
                )
                if reference is not None
            }
            if any(
                item.workflow_state_reference not in workflow_states
                for item in structure.state_differentials
            ):
                conflicts.add("workflow-state-evidence-mismatch")

        classification = self._barrier_classification(outcome, all_responses)
        if classification is None and (missing or conflicts):
            classification = ExperimentResultClassification.inconclusive
        if classification is None and property_ is not None:
            policy_missing = self._policy_requirements(
                property_, experiment, hypothesis, state, operation, fields
            )
            missing.update(policy_missing)
            relationship_missing = self._relationship_requirements(
                property_, experiment, hypothesis, state, object_ids
            )
            missing.update(relationship_missing)
            if missing:
                classification = ExperimentResultClassification.inconclusive

        if classification is None and property_ is not None:
            if property_ in {
                GraphQLSecurityProperty.mutation_authorization,
                GraphQLSecurityProperty.workflow_mutation_authorization,
            }:
                classification, extra_missing, extra_conflicts = self._mutation(
                    property_,
                    experiment,
                    baseline,
                    comparison,
                    fields,
                    structure.state_differentials,
                )
            elif property_ is GraphQLSecurityProperty.bounded_input_validation:
                classification, extra_missing, extra_conflicts = self._input_validation(
                    experiment, baseline, comparison, fields, outcome
                )
            else:
                classification, extra_missing, extra_conflicts = self._authorization(
                    property_, baseline, comparison, fields
                )
            missing.update(extra_missing)
            conflicts.update(extra_conflicts)
            if conflicts or (
                missing
                and classification
                in {
                    ExperimentResultClassification.secure_signal,
                    ExperimentResultClassification.vulnerable_signal,
                }
            ):
                classification = ExperimentResultClassification.inconclusive

        prior_signals = {
            item.result_classification
            for item in state.experiment_history
            if item.hypothesis_id == experiment.hypothesis_id
            and item.result_classification
            in {
                ExperimentResultClassification.secure_signal.value,
                ExperimentResultClassification.vulnerable_signal.value,
            }
        }
        if (
            classification
            in {
                ExperimentResultClassification.secure_signal,
                ExperimentResultClassification.vulnerable_signal,
            }
            and prior_signals
            and classification.value not in prior_signals
        ):
            conflicts.add("conflicting-repeated-bounded-evidence")
            classification = ExperimentResultClassification.inconclusive

        classification = classification or ExperimentResultClassification.inconclusive
        request_refs = tuple(
            sorted({item.request_accounting_reference for item in all_responses})
        )
        runtime_refs = tuple(
            sorted({item.runtime_provenance_reference for item in all_responses})
        )
        baseline_refs = tuple(sorted({item.evidence_id for item in baseline}))
        comparison_refs = tuple(sorted({item.evidence_id for item in comparison}))
        evaluation_id = _identifier(
            "graphql-evaluation",
            experiment.experiment_id,
            outcome.outcome_id,
            property_.value if property_ is not None else "unregistered",
        )
        return GraphQLEvaluationResult(
            evaluation_id=evaluation_id,
            experiment_id=experiment.experiment_id,
            outcome_id=outcome.outcome_id,
            hypothesis_id=hypothesis.hypothesis_id,
            security_property=property_,
            classification=classification,
            operation_reference=operation_id,
            field_references=field_ids,
            argument_references=argument_ids,
            controlled_identity_references=identities,
            controlled_object_references=object_ids,
            evidence_references=outcome.evidence_references,
            baseline_evidence_references=baseline_refs,
            comparison_evidence_references=comparison_refs,
            request_accounting_references=request_refs,
            runtime_provenance_references=runtime_refs,
            missing_evidence=tuple(sorted(missing)),
            conflict_codes=tuple(sorted(conflicts)),
            summary=(
                "Deterministically evaluated registered GraphQL property "
                f"{property_.value if property_ is not None else 'unregistered'} as "
                f"{classification.value}."
            ),
        )

    def classify_outcome(
        self,
        experiment: SecurityExperiment,
        outcome: ExperimentOutcome,
        state: ResearchState,
        source_hypothesis: HypothesisRecord | None = None,
    ) -> tuple[ExperimentOutcome, GraphQLEvaluationResult]:
        result = self.evaluate(experiment, outcome, source_hypothesis, state)
        return result.classified_outcome(outcome), result

    @staticmethod
    def _operation_id(experiment: SecurityExperiment) -> str:
        operation_ids = {
            str(item.input.operation_id)
            for item in experiment.primitive_steps
            if isinstance(
                item.input, (GraphQLOperationInput, GraphQLVariableMutationInput)
            )
        }
        if len(operation_ids) != 1:
            return str(experiment.target.operation_id or "unregistered-operation")
        return next(iter(operation_ids))

    @staticmethod
    def _bind_responses(
        experiment: SecurityExperiment, outcome: ExperimentOutcome
    ) -> tuple[_BoundResponse, ...]:
        evidence_by_step = {item.step_id: item for item in outcome.evidence}
        output: list[_BoundResponse] = []
        for index, step in enumerate(experiment.primitive_steps):
            value = step.input
            if not isinstance(
                value, (GraphQLOperationInput, GraphQLVariableMutationInput)
            ):
                continue
            evidence = evidence_by_step.get(step.step_id)
            if evidence is None:
                continue
            role = "baseline"
            if isinstance(value, GraphQLVariableMutationInput):
                role = "comparison"
            elif value.anonymous or value.identity_role == "comparison":
                role = "comparison"
            elif index > 0:
                role = "comparison"
            expected_identity = (
                None
                if getattr(value, "anonymous", False)
                else (
                    getattr(value, "identity_id", None)
                    or experiment.identity_context.primary_identity_id
                )
            )
            if isinstance(value, GraphQLOperationInput) and (
                value.identity_role == "comparison"
            ):
                expected_identity = experiment.identity_context.comparison_identity_id
            for response in evidence.graphql_responses:
                if response.identity_reference != expected_identity:
                    # Retain it so the caller observes a binding conflict.
                    role = "identity-mismatch"
                output.append(_BoundResponse(evidence.evidence_id, role, response))
        return tuple(output)

    @staticmethod
    def _barrier_classification(
        outcome: ExperimentOutcome,
        responses: Sequence[GraphQLRuntimeResponseEvidence],
    ) -> ExperimentResultClassification | None:
        if (
            outcome.cleanup_status is CleanupStatus.failed
            or outcome.result_classification
            is ExperimentResultClassification.cleanup_failed
        ):
            return ExperimentResultClassification.cleanup_failed
        if outcome.result_classification is ExperimentResultClassification.blocked:
            return ExperimentResultClassification.blocked
        if (
            outcome.result_classification
            is ExperimentResultClassification.runtime_failed
        ):
            return ExperimentResultClassification.runtime_failed
        failed = sum(
            GraphQLErrorClass.transport_error in item.error_classes
            or item.status_class == "transport_failure"
            for item in responses
        )
        if responses and failed == len(responses):
            return ExperimentResultClassification.runtime_failed
        return None

    @staticmethod
    def _policy_requirements(
        property_: GraphQLSecurityProperty,
        experiment: SecurityExperiment,
        hypothesis: HypothesisRecord,
        state: ResearchState,
        operation: GraphQLOperationRecord | None,
        fields: Sequence[GraphQLFieldRecord],
    ) -> set[str]:
        missing: set[str] = set()
        if operation is None:
            return {"registered-graphql-operation"}
        surface = next(
            (
                item
                for item in state.graphql_surfaces
                if item.graphql_surface_id == operation.graphql_surface_id
            ),
            None,
        )
        auth = operation.authentication_requirement
        if auth is GraphQLAuthenticationRequirement.unknown and surface is not None:
            auth = surface.authentication_requirement
        if (
            property_ is GraphQLSecurityProperty.authentication_enforcement
            and auth is not (GraphQLAuthenticationRequirement.authentication_required)
        ):
            missing.add("anonymous-denial-policy")
        if property_ in {
            GraphQLSecurityProperty.field_authorization,
            GraphQLSecurityProperty.nested_resolver_authorization,
        }:
            if not fields:
                missing.add("registered-protected-field")
            elif all(
                item.authorization_semantics.observations
                == (GraphQLAuthorizationObservation.unknown,)
                for item in fields
            ):
                missing.add("registered-field-authorization-policy")
        if property_ is GraphQLSecurityProperty.nested_resolver_authorization:
            if not fields or any(
                item.field_id in operation.root_field_ids for item in fields
            ):
                missing.add("registered-protected-nested-path")
        if property_ is GraphQLSecurityProperty.operation_authorization:
            restricted = auth in {
                GraphQLAuthenticationRequirement.role_bound,
                GraphQLAuthenticationRequirement.tenant_bound,
            } or any(
                GraphQLAuthorizationObservation.role_dependent_operation_behavior
                in item.authorization_semantics.observations
                for item in fields
            )
            if not restricted:
                missing.add("registered-operation-authorization-policy")
        if property_ is GraphQLSecurityProperty.role_authorization:
            role_policy = auth is GraphQLAuthenticationRequirement.role_bound or any(
                GraphQLAuthorizationObservation.role_dependent_operation_behavior
                in item.authorization_semantics.observations
                for item in fields
            )
            if not role_policy:
                missing.add("registered-role-boundary")
        if property_ is GraphQLSecurityProperty.tenant_authorization:
            tenant_policy = (
                auth is GraphQLAuthenticationRequirement.tenant_bound
                or any(
                    GraphQLAuthorizationObservation.tenant_dependent_object_access
                    in item.authorization_semantics.observations
                    for item in fields
                )
            )
            if not tenant_policy:
                missing.add("registered-tenant-boundary")
        if property_ is GraphQLSecurityProperty.bounded_input_validation:
            arguments = {item.argument_id: item for item in state.graphql_arguments}
            referenced = [
                arguments[item.entity_id]
                for item in hypothesis.entity_references
                if item.entity_kind is EntityKind.graphql_argument
                and item.entity_id in arguments
            ]
            if not referenced or any(
                item.semantic_role is GraphQLSemanticRole.unknown
                or not item.semantic_role_evidence_references
                for item in referenced
            ):
                missing.add("registered-input-invariant")
        if property_ is GraphQLSecurityProperty.workflow_mutation_authorization:
            workflows = {
                item.entity_id
                for item in hypothesis.entity_references
                if item.entity_kind is EntityKind.workflow
            }
            if operation.workflow_id is None or operation.workflow_id not in workflows:
                missing.add("registered-workflow-state-policy")
        if experiment.target.operation_id not in {None, operation.operation_id}:
            missing.add("stable-operation-binding")
        return missing

    @staticmethod
    def _relationship_requirements(
        property_: GraphQLSecurityProperty,
        experiment: SecurityExperiment,
        hypothesis: HypothesisRecord,
        state: ResearchState,
        controlled_object_ids: Sequence[str],
    ) -> set[str]:
        missing: set[str] = set()
        identity_by_id = {item.identity_id: item for item in state.identities}
        primary = identity_by_id.get(experiment.identity_context.primary_identity_id)
        comparison = identity_by_id.get(
            experiment.identity_context.comparison_identity_id
        )
        relationship = experiment.identity_context.relationship
        differential_properties = {
            GraphQLSecurityProperty.object_authorization,
            GraphQLSecurityProperty.field_authorization,
            GraphQLSecurityProperty.operation_authorization,
            GraphQLSecurityProperty.role_authorization,
            GraphQLSecurityProperty.tenant_authorization,
            GraphQLSecurityProperty.ownership_authorization,
            GraphQLSecurityProperty.mutation_authorization,
            GraphQLSecurityProperty.workflow_mutation_authorization,
            GraphQLSecurityProperty.nested_resolver_authorization,
            GraphQLSecurityProperty.cross_surface_authorization,
        }
        if property_ in differential_properties:
            if primary is None or comparison is None or primary == comparison:
                missing.add("controlled-identity-pair")
            elif any(
                not item.controlled
                or item.eligibility is IdentityEligibility.ineligible
                for item in (primary, comparison)
            ):
                missing.add("eligible-controlled-identities")
        if property_ is GraphQLSecurityProperty.role_authorization:
            if (
                primary is None
                or comparison is None
                or primary.role_reference is None
                or comparison.role_reference is None
                or primary.role_reference == comparison.role_reference
                or relationship
                not in {
                    IdentityRelationship.different_controlled_role,
                    IdentityRelationship.user_admin,
                }
            ):
                missing.add("controlled-role-relationship")
        object_properties = {
            GraphQLSecurityProperty.object_authorization,
            GraphQLSecurityProperty.tenant_authorization,
            GraphQLSecurityProperty.ownership_authorization,
            GraphQLSecurityProperty.mutation_authorization,
            GraphQLSecurityProperty.nested_resolver_authorization,
            GraphQLSecurityProperty.cross_surface_authorization,
        }
        if property_ in object_properties:
            objects = [
                item
                for item in state.objects
                if item.object_id in controlled_object_ids
            ]
            if not objects or len(objects) != len(controlled_object_ids):
                missing.add("controlled-object-relationship")
            elif any(
                not item.test_owned or not item.evidence_references for item in objects
            ):
                missing.add("test-owned-object-ownership-evidence")
            elif (
                property_ is not GraphQLSecurityProperty.nested_resolver_authorization
                and any(
                    item.owner_identity_id
                    != experiment.identity_context.primary_identity_id
                    for item in objects
                )
            ):
                missing.add("test-owned-object-ownership-evidence")
            if (
                property_ is not GraphQLSecurityProperty.tenant_authorization
                and relationship is not IdentityRelationship.owner_non_owner
            ):
                missing.add("owner-non-owner-relationship")
        if property_ is GraphQLSecurityProperty.nested_resolver_authorization:
            nested_objects = [
                item
                for item in state.objects
                if item.object_id
                in {
                    reference.entity_id
                    for reference in hypothesis.entity_references
                    if reference.entity_kind is EntityKind.object
                }
            ]
            if (
                len(nested_objects) < 2
                or len({item.owner_identity_id for item in nested_objects}) < 2
            ):
                missing.add("controlled-nested-object-boundary")
        if property_ is GraphQLSecurityProperty.tenant_authorization:
            obj = next(
                (
                    item
                    for item in state.objects
                    if item.object_id in controlled_object_ids
                ),
                None,
            )
            if (
                obj is None
                or primary is None
                or comparison is None
                or obj.tenant_reference is None
                or primary.tenant_reference != obj.tenant_reference
                or comparison.tenant_reference is None
                or comparison.tenant_reference == obj.tenant_reference
                or relationship is not IdentityRelationship.different_controlled_tenant
            ):
                missing.add("controlled-cross-tenant-relationship")
        return missing

    def _authorization(
        self,
        property_: GraphQLSecurityProperty,
        baseline: Sequence[_BoundResponse],
        comparison: Sequence[_BoundResponse],
        fields: Sequence[GraphQLFieldRecord],
    ) -> tuple[ExperimentResultClassification, set[str], set[str]]:
        missing: set[str] = set()
        conflicts: set[str] = set()
        require_object = property_ in {
            GraphQLSecurityProperty.object_authorization,
            GraphQLSecurityProperty.tenant_authorization,
            GraphQLSecurityProperty.ownership_authorization,
            GraphQLSecurityProperty.cross_surface_authorization,
        }
        baseline_access = self._aggregate_access(baseline, fields, require_object)
        comparison_access = self._aggregate_access(comparison, fields, require_object)
        if baseline_access is not _Access.available:
            missing.add("valid-authorized-baseline")
        if not comparison:
            missing.add("bounded-unauthorized-comparison")
        if _Access.conflicting in {baseline_access, comparison_access}:
            conflicts.add("conflicting-graphql-access-evidence")
        if _Access.failed in {baseline_access, comparison_access}:
            conflicts.add("partial-runtime-failure")
        if missing or conflicts:
            return ExperimentResultClassification.inconclusive, missing, conflicts
        if comparison_access is _Access.available:
            return ExperimentResultClassification.vulnerable_signal, missing, conflicts
        if comparison_access is _Access.denied:
            return ExperimentResultClassification.secure_signal, missing, conflicts
        missing.add("tested-property-comparison-result")
        return ExperimentResultClassification.inconclusive, missing, conflicts

    def _mutation(
        self,
        property_: GraphQLSecurityProperty,
        experiment: SecurityExperiment,
        baseline: Sequence[_BoundResponse],
        comparison: Sequence[_BoundResponse],
        fields: Sequence[GraphQLFieldRecord],
        state_evidence: Sequence[GraphQLStateDifferentialEvidence],
    ) -> tuple[ExperimentResultClassification, set[str], set[str]]:
        missing: set[str] = set()
        conflicts: set[str] = set()
        primary = experiment.identity_context.primary_identity_id
        comparison_id = experiment.identity_context.comparison_identity_id
        authoritative = tuple(item for item in state_evidence if item.authoritative)
        registered_invariants = self._registered_invariants(experiment)
        if any(
            item.invariant_reference not in registered_invariants
            for item in authoritative
        ):
            conflicts.add("unregistered-state-invariant-evidence")
        expected_objects = set(experiment.mutation.controlled_object_ids)
        if any(
            item.identity_reference not in {primary, comparison_id}
            or (expected_objects and set(item.object_references) != expected_objects)
            for item in authoritative
        ):
            conflicts.add("state-evidence-context-mismatch")
        primary_effects = tuple(
            item.protected_effect_observed
            for item in authoritative
            if item.identity_reference == primary
        )
        comparison_effects = tuple(
            item.protected_effect_observed
            for item in authoritative
            if item.identity_reference == comparison_id
        )
        if len(set(primary_effects)) > 1 or len(set(comparison_effects)) > 1:
            conflicts.add("conflicting-authoritative-state-evidence")
        baseline_access = self._aggregate_access(baseline, fields, False)
        comparison_access = self._aggregate_access(comparison, fields, False)
        baseline_valid = (
            all(primary_effects)
            if primary_effects
            else baseline_access is _Access.available
        )
        if not baseline_valid:
            missing.add("valid-authorized-mutation-baseline")
        if (
            primary_effects
            and not any(primary_effects)
            and (baseline_access is _Access.available)
        ):
            conflicts.add("baseline-state-response-disagreement")
        if (
            comparison_effects
            and all(comparison_effects)
            and (comparison_access is _Access.denied)
        ):
            conflicts.add("comparison-state-response-disagreement")
        if (
            comparison_effects
            and not any(comparison_effects)
            and (comparison_access is _Access.available)
        ):
            conflicts.add("comparison-state-response-disagreement")
        if comparison_id is not None and comparison_effects and all(comparison_effects):
            if missing or conflicts:
                return ExperimentResultClassification.inconclusive, missing, conflicts
            return ExperimentResultClassification.vulnerable_signal, missing, conflicts
        if (
            comparison_id is not None
            and comparison_effects
            and not any(comparison_effects)
            and not conflicts
        ):
            if baseline_valid and not conflicts:
                return ExperimentResultClassification.secure_signal, missing, conflicts
        if comparison_access is _Access.denied and baseline_valid:
            return ExperimentResultClassification.secure_signal, missing, conflicts
        if comparison_access is _Access.available:
            missing.add("authoritative-protected-state-differential")
        elif comparison_id is None:
            missing.add("unauthorized-mutation-context")
        else:
            missing.add("unauthorized-mutation-result")
        return ExperimentResultClassification.inconclusive, missing, conflicts

    def _input_validation(
        self,
        experiment: SecurityExperiment,
        baseline: Sequence[_BoundResponse],
        comparison: Sequence[_BoundResponse],
        fields: Sequence[GraphQLFieldRecord],
        outcome: ExperimentOutcome,
    ) -> tuple[ExperimentResultClassification, set[str], set[str]]:
        missing: set[str] = set()
        conflicts: set[str] = set()
        baseline_access = self._aggregate_access(baseline, fields, False)
        if baseline_access is not _Access.available:
            missing.add("valid-input-validation-baseline")
        invariants = tuple(
            item for evidence in outcome.evidence for item in evidence.invariant_results
        )
        registered_invariants = self._registered_invariants(experiment)
        if any(
            item.invariant_reference not in registered_invariants for item in invariants
        ):
            conflicts.add("unregistered-input-invariant-result")
        results = {item.satisfied for item in invariants}
        if len(results) > 1:
            conflicts.add("conflicting-registered-input-invariants")
        if missing or conflicts:
            return ExperimentResultClassification.inconclusive, missing, conflicts
        if results == {False}:
            return ExperimentResultClassification.vulnerable_signal, missing, conflicts
        if results == {True}:
            return ExperimentResultClassification.secure_signal, missing, conflicts
        if any(
            GraphQLErrorClass.validation_error in item.response.error_classes
            for item in comparison
        ) and not any(
            field.field_id in item.response.selected_field_presence
            and field.field_id not in item.response.selected_field_nulls
            for item in comparison
            for field in fields
        ):
            return ExperimentResultClassification.secure_signal, missing, conflicts
        missing.add("registered-input-invariant-result")
        return ExperimentResultClassification.inconclusive, missing, conflicts

    @staticmethod
    def _registered_invariants(experiment: SecurityExperiment) -> set[str]:
        return {item.predicate_reference for item in experiment.required_evidence} | {
            reference
            for step in experiment.primitive_steps
            if isinstance(step.input, StateDifferentialInput)
            for reference in step.input.invariant_references
        }

    @classmethod
    def _aggregate_access(
        cls,
        responses: Sequence[_BoundResponse],
        fields: Sequence[GraphQLFieldRecord],
        require_object: bool,
    ) -> _Access:
        if not responses:
            return _Access.unknown
        values = {
            cls._response_access(item.response, fields, require_object)
            for item in responses
        }
        if _Access.failed in values:
            return _Access.failed if len(values) == 1 else _Access.conflicting
        decisive = values & {_Access.available, _Access.denied}
        if len(decisive) > 1:
            return _Access.conflicting
        if len(decisive) == 1:
            return next(iter(decisive))
        return _Access.unknown

    @staticmethod
    def _response_access(
        response: GraphQLRuntimeResponseEvidence,
        fields: Sequence[GraphQLFieldRecord],
        require_object: bool,
    ) -> _Access:
        if (
            GraphQLErrorClass.transport_error in response.error_classes
            or response.status_class == "transport_failure"
        ):
            return _Access.failed
        field_ids = {item.field_id for item in fields}
        field_names = {item.name for item in fields}
        present = field_ids & set(response.selected_field_presence)
        nulls = field_ids & set(response.selected_field_nulls)
        available_fields = present - nulls
        path_denial = any(
            item.error_class
            in {
                GraphQLErrorClass.authentication_error,
                GraphQLErrorClass.authorization_error,
                GraphQLErrorClass.not_found,
            }
            and any(
                isinstance(component, str) and component in field_names
                for component in item.path
            )
            for item in response.error_paths
        )
        denial_class = bool(
            set(response.error_classes)
            & {
                GraphQLErrorClass.authentication_error,
                GraphQLErrorClass.authorization_error,
            }
        )
        global_denial = denial_class and not response.error_paths
        object_denied = (
            require_object
            and response.controlled_object_reference_match is False
            and (
                global_denial
                or GraphQLErrorClass.not_found in response.error_classes
                or not available_fields
            )
        )
        policy_omission = (
            bool(field_ids)
            and not present
            and any(
                GraphQLAuthorizationObservation.identity_dependent_field_visibility
                in item.authorization_semantics.observations
                for item in fields
            )
        )
        if require_object:
            available = response.controlled_object_reference_match is True and (
                bool(available_fields) if field_ids else response.data_present
            )
        elif field_ids:
            available = bool(available_fields)
        else:
            # Operation-level evidence needs a registered field, not HTTP 200 or
            # the mere presence of a GraphQL data envelope.
            available = bool(response.selected_field_presence) and bool(
                set(response.selected_field_presence)
                - set(response.selected_field_nulls)
            )
        denied = (
            path_denial
            or object_denied
            or policy_omission
            or (global_denial and not available)
        )
        if available and path_denial:
            return _Access.conflicting
        if available:
            return _Access.available
        if denied:
            return _Access.denied
        return _Access.unknown


def _identifier(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(item) for item in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:24]}"


__all__ = [
    "GRAPHQL_EVALUATION_VERSION",
    "GraphQLControlledRelationships",
    "GraphQLDifferentialEvaluator",
    "GraphQLEvaluationResult",
    "GraphQLSecurityProperty",
    "GraphQLStructuralEvidence",
]
