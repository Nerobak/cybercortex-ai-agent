"""Bounded GraphQL experiment candidates and deterministic materialization.

This module is intentionally execution-neutral.  It consumes only registered
semantic records and produces ordinary :class:`ExperimentCandidate` and
:class:`ExperimentProposal` records for the existing compiler.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from pydantic import Field, StrictBool, StrictInt

from agent_core.agent_models import RiskLevel
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.candidates import (
    CandidateBaselineKind,
    CandidateMutationKind,
    ExperimentCandidate,
)
from agent_core.research.compiler import ExperimentCompiler, ExperimentCompilerContext
from agent_core.research.experiments import (
    BaselineIntent,
    BaselineKind,
    EvidenceIntent,
    ExperimentProposal,
    MutationIntent,
)
from agent_core.research.graph import GraphAssertion, ResearchGraphRepository
from agent_core.research.graphql import (
    GraphQLArgumentBinding,
    GraphQLArgumentRecord,
    GraphQLAuthenticationRequirement,
    GraphQLCandidateKind,
    GraphQLExperimentStateChangeClass,
    GraphQLNormalizedOperationStructure,
    GraphQLOperationRecord,
    GraphQLSelectionPath,
    GraphQLSemanticRole,
    GraphQLStateChangeClass,
    GraphQLVariableBinding,
    GraphQLVariableValueSource,
    RegisteredGraphQLOperationTemplate,
)
from agent_core.research.graphql_hypotheses import GraphQLHypothesisProperty
from agent_core.research.primitives import (
    DifferentialSelector,
    GraphQLOperationInput,
    GraphQLVariableMutationInput,
    IdentityRelationship,
    MutationKind,
    PrimitiveCapabilityState,
    PrimitiveStepProposal,
    StateDifferentialInput,
)
from agent_core.research.registry import ExperimentRegistry
from agent_core.research.state import (
    HypothesisRecord,
    Identity,
    ResearchObject,
    ResearchState,
)
from agent_core.research.types import (
    DerivationType,
    EntityKind,
    HypothesisResearchStatus,
    IdentityEligibility,
    RelationshipStatus,
    ResearchContract,
    ResearchPredicate,
)
from agent_core.verification_capabilities import (
    get_research_experiment_capability_adapter,
)

GRAPHQL_CANDIDATE_VERSION = "phase4-graphql-candidates-v1"
MAX_GRAPHQL_CANDIDATES = 100


class GraphQLCandidateLimits(ResearchContract):
    max_candidates_per_hypothesis: StrictInt = Field(default=4, ge=1, le=20)
    max_candidates_per_operation: StrictInt = Field(default=12, ge=1, le=100)
    max_candidates_per_field: StrictInt = Field(default=4, ge=1, le=20)
    max_mutation_candidates: StrictInt = Field(default=8, ge=0, le=50)
    max_total_candidates: StrictInt = Field(default=40, ge=1, le=MAX_GRAPHQL_CANDIDATES)
    max_selection_depth: StrictInt = Field(default=8, ge=1, le=12)
    max_selection_nodes: StrictInt = Field(default=128, ge=1, le=1_024)


class GraphQLCandidatePolicy(ResearchContract):
    allow_read_only_candidates: StrictBool = True
    allow_state_change_candidates: StrictBool = False
    allow_cross_surface_candidates: StrictBool = True
    require_cleanup_for_state_change: StrictBool = True


_PROPERTY_KIND = {
    GraphQLHypothesisProperty.object_authorization.value: (
        GraphQLCandidateKind.object_authorization
    ),
    GraphQLHypothesisProperty.authentication_enforcement.value: (
        GraphQLCandidateKind.authentication
    ),
    GraphQLHypothesisProperty.field_level_authorization.value: (
        GraphQLCandidateKind.field_authorization
    ),
    GraphQLHypothesisProperty.operation_level_authorization.value: (
        GraphQLCandidateKind.operation_authorization
    ),
    GraphQLHypothesisProperty.ownership_authorization.value: (
        GraphQLCandidateKind.ownership
    ),
    GraphQLHypothesisProperty.role_bound_access.value: GraphQLCandidateKind.role_bound,
    GraphQLHypothesisProperty.tenant_bound_access.value: (
        GraphQLCandidateKind.tenant_bound
    ),
    GraphQLHypothesisProperty.mutation_authorization.value: (
        GraphQLCandidateKind.mutation_authorization
    ),
    GraphQLHypothesisProperty.cross_surface_authorization.value: (
        GraphQLCandidateKind.cross_surface
    ),
    GraphQLHypothesisProperty.relationship_traversal_authorization.value: (
        GraphQLCandidateKind.nested_resolver
    ),
    GraphQLHypothesisProperty.argument_input_validation.value: (
        GraphQLCandidateKind.input_validation
    ),
    GraphQLHypothesisProperty.workflow_bound_mutation.value: (
        GraphQLCandidateKind.workflow_mutation
    ),
}


def build_registered_graphql_operation_template(
    state: ResearchState,
    operation_id: str,
    *,
    selection_paths: Sequence[Sequence[str]] | None = None,
    variable_bindings: Sequence[GraphQLVariableBinding] | None = None,
    state_change_class: GraphQLExperimentStateChangeClass | None = None,
) -> RegisteredGraphQLOperationTemplate:
    """Build a stable typed registration from persisted semantic records."""

    operation = _operation(state, operation_id)
    surface = next(
        item
        for item in state.graphql_surfaces
        if item.graphql_surface_id == operation.graphql_surface_id
    )
    variables = {
        item.variable_id: item
        for item in state.graphql_variables
        if item.operation_id == operation.operation_id
    }
    if variable_bindings is None:
        controlled_object_ids = {item.object_id for item in state.objects}
        variable_bindings = tuple(
            GraphQLVariableBinding(
                variable_id=variable.variable_id,
                argument_id=str(variable.linked_argument_id),
                value_source=GraphQLVariableValueSource.controlled_object,
                value_reference=variable.controlled_value_reference,
            )
            for variable in sorted(
                variables.values(), key=lambda item: item.variable_id
            )
            if variable.linked_argument_id is not None
            and variable.controlled_value_reference is not None
            and variable.controlled_value_reference in controlled_object_ids
        )
    argument_bindings = tuple(
        GraphQLArgumentBinding(
            argument_id=str(variable.linked_argument_id),
            variable_id=variable.variable_id,
        )
        for variable in sorted(variables.values(), key=lambda item: item.variable_id)
        if variable.linked_argument_id is not None
    )
    paths = tuple(selection_paths or ((item,) for item in operation.root_field_ids))
    normalized = GraphQLNormalizedOperationStructure(
        root_field_ids=operation.root_field_ids,
        selection_paths=tuple(
            GraphQLSelectionPath(field_ids=tuple(path)) for path in paths
        ),
    )
    derived_state_change = state_change_class
    if derived_state_change is None:
        derived_state_change = (
            GraphQLExperimentStateChangeClass.read_only
            if operation.state_change_class is GraphQLStateChangeClass.read_only
            else GraphQLExperimentStateChangeClass.irreversible_or_disallowed
        )
    seed = _digest(
        {
            "operation_id": operation.operation_id,
            "selection_fingerprint": operation.selection_fingerprint,
            "document_fingerprint": operation.document_fingerprint,
            "paths": [list(item.field_ids) for item in normalized.selection_paths],
            "bindings": [
                item.model_dump(mode="json")
                for item in sorted(
                    variable_bindings,
                    key=lambda item: (item.variable_id, item.argument_id),
                )
            ],
            "state_change_class": derived_state_change.value,
        }
    )
    evidence = tuple(
        sorted({*surface.evidence_references, *operation.evidence_references})
    )
    return RegisteredGraphQLOperationTemplate(
        template_id=f"graphql-template-{seed[7:31]}",
        graphql_surface_id=surface.graphql_surface_id,
        endpoint_id=surface.endpoint_id,
        operation_id=operation.operation_id,
        operation_type=operation.operation_type,
        normalized_structure=normalized,
        variable_bindings=tuple(variable_bindings),
        argument_bindings=argument_bindings,
        selection_fingerprint=operation.selection_fingerprint,
        document_fingerprint=operation.document_fingerprint,
        authentication_requirement=(
            operation.authentication_requirement
            if operation.authentication_requirement
            is not GraphQLAuthenticationRequirement.unknown
            else surface.authentication_requirement
        ),
        state_change_class=derived_state_change,
        workflow_id=operation.workflow_id,
        evidence_references=evidence,
        provenance_id=operation.provenance_id,
    )


class GraphQLExperimentCandidateBuilder:
    """Construct bounded GraphQL candidates without authorizing or sending traffic."""

    def __init__(
        self,
        registry: ExperimentRegistry,
        budget_manager: ResearchBudgetManager,
        compiler: ExperimentCompiler,
        *,
        limits: GraphQLCandidateLimits | None = None,
        policy: GraphQLCandidatePolicy | None = None,
    ) -> None:
        if compiler.registry is not registry:
            raise ValueError(
                "GraphQL candidate builder and compiler must share a registry"
            )
        self.registry = registry
        self.budget_manager = budget_manager
        self.compiler = compiler
        self.limits = limits or GraphQLCandidateLimits()
        self.policy = policy or GraphQLCandidatePolicy()

    def build(
        self,
        state: ResearchState,
        *,
        compiler_context: ExperimentCompilerContext,
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None = None,
        expected_state_revision: int | None = None,
        controlled_identity_ids: Sequence[str] | None = None,
        controlled_object_ids: Sequence[str] | None = None,
        policy: GraphQLCandidatePolicy | None = None,
        policy_reference: str | None = None,
    ) -> tuple[ExperimentCandidate, ...]:
        if (
            expected_state_revision is not None
            and state.revision != expected_state_revision
        ):
            return ()
        if compiler_context.execution_ready:
            # P4-1D GraphQL primitives are deliberately compile-only.
            return ()
        if (
            policy_reference is not None
            and compiler_context.policy_reference != policy_reference
        ):
            return ()
        selected_policy = policy or self.policy
        identity_allow = set(controlled_identity_ids or ())
        object_allow = set(controlled_object_ids or ())
        identities = tuple(
            item
            for item in state.identities
            if item.controlled
            and item.eligibility is IdentityEligibility.eligible
            and (not identity_allow or item.identity_id in identity_allow)
        )
        objects = tuple(
            item
            for item in state.objects
            if item.test_owned
            and item.evidence_references
            and (not object_allow or item.object_id in object_allow)
        )
        assertions = self._assertions(graph, state)
        templates = tuple(
            sorted(
                compiler_context.graphql_operation_templates,
                key=lambda item: item.template_id,
            )
        )
        raw: list[ExperimentCandidate] = []
        for hypothesis in sorted(state.hypotheses, key=lambda item: item.hypothesis_id):
            if hypothesis.status not in {
                HypothesisResearchStatus.proposed,
                HypothesisResearchStatus.selected,
                HypothesisResearchStatus.inconclusive,
            }:
                continue
            kind = _PROPERTY_KIND.get(str(hypothesis.security_property or ""))
            if (
                kind is None
                or hypothesis.derivation_type is not DerivationType.deterministic
                or not hypothesis.supporting_evidence
            ):
                continue
            if not set(hypothesis.supporting_evidence).issubset(
                {item.evidence_id for item in state.evidence}
            ):
                continue
            try:
                adapter = get_research_experiment_capability_adapter(
                    hypothesis.category
                )
            except ValueError:
                continue
            primitive = (
                "graphql_variable_mutation"
                if kind is GraphQLCandidateKind.input_validation
                else "graphql_operation"
            )
            if primitive not in adapter.primitive_names:
                continue
            try:
                definition = self.registry.resolve(primitive)
            except ValueError:
                continue
            if definition.capability_state not in {
                PrimitiveCapabilityState.compile_only,
                PrimitiveCapabilityState.execution_available,
            }:
                continue
            for template in templates:
                candidate = self._construct(
                    state,
                    hypothesis,
                    kind,
                    template,
                    identities,
                    objects,
                    assertions,
                    compiler_context,
                    selected_policy,
                )
                if candidate is not None:
                    raw.append(candidate)

        unique = {item.fingerprint_seed: item for item in raw}
        eligible: list[ExperimentCandidate] = []
        hypothesis_counts: dict[str, int] = {}
        operation_counts: dict[str, int] = {}
        field_counts: dict[str, int] = {}
        mutation_count = 0
        for candidate in sorted(unique.values(), key=lambda item: item.candidate_id):
            if len(eligible) >= self.limits.max_total_candidates:
                break
            if (
                hypothesis_counts.get(candidate.hypothesis_id, 0)
                >= self.limits.max_candidates_per_hypothesis
            ):
                continue
            operation_id = str(candidate.operation_id)
            if (
                operation_counts.get(operation_id, 0)
                >= self.limits.max_candidates_per_operation
            ):
                continue
            if (
                candidate.graphql_field_id is not None
                and field_counts.get(candidate.graphql_field_id, 0)
                >= self.limits.max_candidates_per_field
            ):
                continue
            is_mutation = (
                candidate.graphql_state_change_class
                is GraphQLExperimentStateChangeClass.reversible_state_change
            )
            if is_mutation and mutation_count >= self.limits.max_mutation_candidates:
                continue
            try:
                proposal = materialize_graphql_candidate(candidate, state)
                experiment = self.compiler.compile(proposal, state, compiler_context)
            except (TypeError, ValueError):
                continue
            budget = self.budget_manager.check(
                state,
                hypothesis_id=candidate.hypothesis_id,
                surface_id=candidate.surface_id,
                estimated_requests=experiment.request_estimate.total_reservation,
                state_changing=experiment.state_changing,
            )
            if not budget.allowed:
                continue
            if (
                experiment.request_estimate.minimum != candidate.minimum_requests
                or experiment.request_estimate.total_reservation
                != candidate.worst_case_requests
                or experiment.state_changing != is_mutation
                or experiment.cleanup.required != candidate.cleanup_required
                or experiment.cleanup.cleanup_reference != candidate.cleanup_reference
            ):
                continue
            eligible.append(
                candidate.model_copy(update={"risk_class": experiment.risk.level})
            )
            hypothesis_counts[candidate.hypothesis_id] = (
                hypothesis_counts.get(candidate.hypothesis_id, 0) + 1
            )
            operation_counts[operation_id] = operation_counts.get(operation_id, 0) + 1
            if candidate.graphql_field_id is not None:
                field_counts[candidate.graphql_field_id] = (
                    field_counts.get(candidate.graphql_field_id, 0) + 1
                )
            mutation_count += int(is_mutation)
        return tuple(eligible)

    def _construct(
        self,
        state: ResearchState,
        hypothesis: HypothesisRecord,
        kind: GraphQLCandidateKind,
        template: RegisteredGraphQLOperationTemplate,
        identities: Sequence[Identity],
        objects: Sequence[ResearchObject],
        assertions: Sequence[GraphAssertion],
        context: ExperimentCompilerContext,
        policy: GraphQLCandidatePolicy,
    ) -> ExperimentCandidate | None:
        operation_refs = _entity_ids(hypothesis, EntityKind.graphql_operation)
        field_refs = _entity_ids(hypothesis, EntityKind.graphql_field)
        argument_refs = _entity_ids(hypothesis, EntityKind.graphql_argument)
        object_refs = _entity_ids(hypothesis, EntityKind.object)
        identity_refs = _entity_ids(hypothesis, EntityKind.identity)
        if operation_refs and template.operation_id not in operation_refs:
            return None
        selected_fields = {
            field_id
            for path in template.normalized_structure.selection_paths
            for field_id in path.field_ids
        }
        if field_refs and not field_refs.intersection(selected_fields):
            return None
        operation = _operation(state, template.operation_id)
        semantic_surface = next(
            (
                item
                for item in state.graphql_surfaces
                if item.graphql_surface_id == template.graphql_surface_id
            ),
            None,
        )
        if (
            semantic_surface is None
            or semantic_surface.target_id != hypothesis.target_id
            or semantic_surface.surface_id != hypothesis.surface_id
            or operation.selection_fingerprint != template.selection_fingerprint
            or operation.document_fingerprint != template.document_fingerprint
            or operation.operation_type is not template.operation_type
        ):
            return None
        depth = max(
            len(item.field_ids)
            for item in template.normalized_structure.selection_paths
        )
        nodes = sum(
            len(item.field_ids)
            for item in template.normalized_structure.selection_paths
        )
        if (
            depth > self.limits.max_selection_depth
            or nodes > self.limits.max_selection_nodes
        ):
            return None
        state_changing = (
            template.state_change_class
            is GraphQLExperimentStateChangeClass.reversible_state_change
        )
        if (
            template.state_change_class
            is GraphQLExperimentStateChangeClass.irreversible_or_disallowed
        ):
            return None
        if state_changing:
            if (
                not policy.allow_state_change_candidates
                or context.policy_reference is None
            ):
                return None
        elif not policy.allow_read_only_candidates:
            return None
        if kind is GraphQLCandidateKind.cross_surface:
            if (
                not policy.allow_cross_surface_candidates
                or not self._cross_surface_evidence(hypothesis, assertions)
            ):
                return None

        identity_index = {item.identity_id: item for item in identities}
        object_index = {item.object_id: item for item in objects}
        bound_objects = [
            object_index[item] for item in sorted(object_refs) if item in object_index
        ]
        controlled_object = bound_objects[0] if bound_objects else None
        if kind is GraphQLCandidateKind.nested_resolver:
            controlled_object = next(
                (
                    item
                    for item in bound_objects
                    if _object_binding(state, template, item.object_id, argument_refs)
                    is not None
                ),
                None,
            )
        primary: Identity | None = None
        comparison: Identity | None = None
        relationship: IdentityRelationship | None = None
        if controlled_object is not None:
            primary = identity_index.get(str(controlled_object.owner_identity_id))
        referenced_identities = [
            identity_index[item] for item in identity_refs if item in identity_index
        ]
        if primary is None and referenced_identities:
            primary = referenced_identities[0]
        if kind is GraphQLCandidateKind.authentication:
            primary = primary or (identities[0] if identities else None)
            if primary is None:
                return None
        elif kind is GraphQLCandidateKind.role_bound:
            pair = _distinct_pair(identities, "role_reference", referenced_identities)
            if pair is None:
                return None
            primary, comparison = pair
            relationship = IdentityRelationship.different_controlled_role
        elif kind is GraphQLCandidateKind.operation_authorization:
            if (
                operation.authentication_requirement
                is GraphQLAuthenticationRequirement.tenant_bound
            ):
                pair = _distinct_pair(
                    identities, "tenant_reference", referenced_identities
                )
                relationship = IdentityRelationship.different_controlled_tenant
            else:
                pair = _distinct_pair(
                    identities, "role_reference", referenced_identities
                )
                relationship = IdentityRelationship.different_controlled_role
            if pair is None:
                return None
            primary, comparison = pair
        elif kind is GraphQLCandidateKind.tenant_bound:
            if (
                controlled_object is None
                or primary is None
                or controlled_object.tenant_reference is None
            ):
                return None
            comparison = next(
                (
                    item
                    for item in referenced_identities or identities
                    if item.identity_id != primary.identity_id
                    and item.tenant_reference is not None
                    and item.tenant_reference != controlled_object.tenant_reference
                ),
                None,
            )
            if comparison is None:
                return None
            relationship = IdentityRelationship.different_controlled_tenant
        elif kind in {
            GraphQLCandidateKind.object_authorization,
            GraphQLCandidateKind.ownership,
            GraphQLCandidateKind.cross_surface,
            GraphQLCandidateKind.mutation_authorization,
        }:
            if controlled_object is None or primary is None:
                return None
            comparison = next(
                (
                    item
                    for item in referenced_identities or identities
                    if item.identity_id != primary.identity_id
                ),
                None,
            )
            if comparison is None:
                return None
            relationship = IdentityRelationship.owner_non_owner
        elif kind is GraphQLCandidateKind.field_authorization:
            pair = _distinct_pair(identities, "role_reference", referenced_identities)
            if pair is None:
                return None
            primary, comparison = pair
            relationship = IdentityRelationship.different_controlled_role
        elif kind is GraphQLCandidateKind.nested_resolver:
            if len(bound_objects) < 2:
                return None
            related = next(
                (item for item in bound_objects if item != controlled_object), None
            )
            if controlled_object is None or related is None:
                return None
            primary = identity_index.get(str(controlled_object.owner_identity_id))
            comparison = identity_index.get(str(related.owner_identity_id))
            if primary is None or comparison is None or primary == comparison:
                return None
            relationship = IdentityRelationship.owner_non_owner
            if not any(
                len(path.field_ids) > 1 and field_refs.intersection(path.field_ids)
                for path in template.normalized_structure.selection_paths
            ):
                return None
        elif kind is GraphQLCandidateKind.workflow_mutation:
            if template.workflow_id is None:
                return None
            workflow = next(
                (
                    item
                    for item in state.workflows
                    if item.workflow_id == template.workflow_id
                ),
                None,
            )
            state_references = {
                reference
                for item in (() if workflow is None else workflow.steps)
                if item.state_changing
                for reference in (
                    item.state_before_reference,
                    item.state_after_reference,
                )
                if reference is not None
            }
            if (
                workflow is None
                or not workflow.evidence_references
                or not any(item.state_changing for item in workflow.steps)
                or len(state_references) < 2
                or not state_references.issubset(set(context.state_references))
            ):
                return None
            primary = primary or (identities[0] if identities else None)
            comparison = next(
                (
                    item
                    for item in referenced_identities or identities
                    if primary is not None and item.identity_id != primary.identity_id
                ),
                None,
            )
            if primary is None or comparison is None:
                return None
            relationship = IdentityRelationship.owner_non_owner

        if state_changing and kind not in {
            GraphQLCandidateKind.mutation_authorization,
            GraphQLCandidateKind.workflow_mutation,
        }:
            return None
        if not state_changing and kind in {
            GraphQLCandidateKind.mutation_authorization,
            GraphQLCandidateKind.workflow_mutation,
        }:
            return None

        variable_bindings: tuple[GraphQLVariableBinding, ...] = ()
        argument_id: str | None = None
        variable_id: str | None = None
        safe_mutation_id: str | None = None
        if controlled_object is not None:
            binding = _object_binding(
                state, template, controlled_object.object_id, argument_refs
            )
            if binding is None and kind in {
                GraphQLCandidateKind.object_authorization,
                GraphQLCandidateKind.ownership,
                GraphQLCandidateKind.tenant_bound,
                GraphQLCandidateKind.cross_surface,
                GraphQLCandidateKind.nested_resolver,
            }:
                return None
            if binding is not None:
                variable_bindings = _replace_binding(
                    template.variable_bindings, binding
                )
                argument_id = binding.argument_id
                variable_id = binding.variable_id
        primitive_kind = "graphql_operation"
        if kind is GraphQLCandidateKind.input_validation:
            matches = [
                item
                for item in context.graphql_safe_mutations
                if item.operation_template_id == template.template_id
                and (not argument_refs or item.argument_id in argument_refs)
            ]
            if not matches:
                return None
            safe = sorted(matches, key=lambda item: item.mutation_id)[0]
            primitive_kind = "graphql_variable_mutation"
            safe_mutation_id = safe.mutation_id
            variable_bindings = (safe.binding,)
            argument_id = safe.argument_id
            variable_id = safe.variable_id

        cleanup_reference: str | None = None
        cleanup_minimum = 0
        cleanup_worst = 0
        if state_changing:
            cleanup = _cleanup_definition(context, hypothesis.category)
            if cleanup is None and policy.require_cleanup_for_state_change:
                return None
            if cleanup is not None:
                cleanup_reference = cleanup.cleanup_reference
                cleanup_minimum = cleanup.minimum_requests
                cleanup_worst = cleanup.worst_case_requests
        steps = (
            2
            if kind
            in {
                GraphQLCandidateKind.authentication,
                GraphQLCandidateKind.object_authorization,
                GraphQLCandidateKind.ownership,
                GraphQLCandidateKind.tenant_bound,
                GraphQLCandidateKind.cross_surface,
                GraphQLCandidateKind.field_authorization,
                GraphQLCandidateKind.role_bound,
                GraphQLCandidateKind.operation_authorization,
                GraphQLCandidateKind.nested_resolver,
                GraphQLCandidateKind.mutation_authorization,
                GraphQLCandidateKind.workflow_mutation,
            }
            else 1
        )
        definition = self.registry.resolve(primitive_kind)
        minimum = steps + cleanup_minimum
        worst = steps * definition.worst_case_requests + cleanup_worst
        if primitive_kind == "graphql_variable_mutation":
            # One registered baseline plus one bounded mutation primitive.
            minimum = 1 + definition.minimum_requests + cleanup_minimum
            worst = 1 + definition.worst_case_requests + cleanup_worst
        risk = definition.risk_class
        if state_changing:
            risk = RiskLevel.moderate
        field_id = (
            sorted(field_refs.intersection(selected_fields))[0]
            if field_refs.intersection(selected_fields)
            else None
        )
        graph_evidence = {
            reference
            for item in assertions
            if item.relation
            in {
                ResearchPredicate.references_same_object,
                ResearchPredicate.crosses_surface,
            }
            and (
                {item.source.entity_id, item.target.entity_id}
                & {reference.entity_id for reference in hypothesis.entity_references}
            )
            for reference in item.evidence_references
        }
        evidence = tuple(
            sorted(
                {
                    *hypothesis.supporting_evidence,
                    *template.evidence_references,
                    *graph_evidence,
                }
            )
        )
        provenance = tuple(sorted({hypothesis.provenance_id, template.provenance_id}))
        if not set(evidence).issubset({item.evidence_id for item in state.evidence}):
            return None
        if not set(provenance).issubset(
            {item.provenance_id for item in state.provenance}
        ):
            return None
        semantic = {
            "hypothesis": hypothesis.semantic_fingerprint or hypothesis.hypothesis_id,
            "kind": kind.value,
            "operation": template.operation_id,
            "field": field_id,
            "argument": argument_id,
            "identity_relationship": relationship.value if relationship else None,
            "identities": sorted(
                item.identity_id for item in (primary, comparison) if item is not None
            ),
            "object_relationship": sorted(object_refs),
            "mutation_class": safe_mutation_id,
            "selection_fingerprint": template.selection_fingerprint,
            "document_fingerprint": template.document_fingerprint,
        }
        seed = _digest(semantic)
        return ExperimentCandidate(
            candidate_id=f"graphql-candidate-{seed[7:31]}",
            research_id=state.research_id,
            state_revision=state.revision,
            hypothesis_id=hypothesis.hypothesis_id,
            capability=hypothesis.category,
            primitive_kind=primitive_kind,
            target_id=hypothesis.target_id,
            surface_id=hypothesis.surface_id,
            endpoint_id=template.endpoint_id,
            operation_id=template.operation_id,
            request_template_id=None,
            primary_identity_id=primary.identity_id if primary else None,
            comparison_identity_id=comparison.identity_id if comparison else None,
            identity_relationship=relationship,
            controlled_object_id=controlled_object.object_id
            if controlled_object
            else None,
            ownership_evidence_references=(
                controlled_object.evidence_references if controlled_object else ()
            ),
            graphql_candidate_kind=kind,
            graphql_surface_id=template.graphql_surface_id,
            graphql_operation_template_id=template.template_id,
            graphql_field_id=field_id,
            graphql_argument_id=argument_id,
            graphql_variable_id=variable_id,
            graphql_variable_bindings=variable_bindings,
            selection_fingerprint=template.selection_fingerprint,
            graphql_state_change_class=template.state_change_class,
            workflow_id=template.workflow_id,
            safe_mutation_id=safe_mutation_id,
            cleanup_required=state_changing,
            cleanup_reference=cleanup_reference,
            baseline_kind=CandidateBaselineKind.registered_graphql_operation,
            mutation_kind=_mutation_kind(kind),
            expected_evidence_class=(
                DifferentialSelector.protected_field_presence
                if kind
                in {
                    GraphQLCandidateKind.field_authorization,
                    GraphQLCandidateKind.nested_resolver,
                }
                else DifferentialSelector.selected_graphql_error_class
            ),
            minimum_requests=minimum,
            worst_case_requests=worst,
            risk_class=risk,
            information_predicates=(f"predicate:graphql-{kind.value}",),
            evidence_references=evidence,
            provenance_references=provenance,
            fingerprint_seed=seed,
        )

    @staticmethod
    def _assertions(
        graph: ResearchGraphRepository | Sequence[GraphAssertion] | None,
        state: ResearchState,
    ) -> tuple[GraphAssertion, ...]:
        if graph is None:
            return ()
        if not isinstance(graph, ResearchGraphRepository):
            return tuple(graph)
        gathered: dict[str, GraphAssertion] = {}
        for hypothesis in state.hypotheses:
            for reference in hypothesis.entity_references:
                for assertion in graph.neighbors(
                    reference.entity_id,
                    limit=100,
                    research_id=state.research_id,
                ):
                    gathered[assertion.assertion_id] = assertion
        return tuple(gathered[key] for key in sorted(gathered))

    @staticmethod
    def _cross_surface_evidence(
        hypothesis: HypothesisRecord, assertions: Sequence[GraphAssertion]
    ) -> bool:
        relevant = {
            item.entity_id
            for item in hypothesis.entity_references
            if item.entity_kind
            in {
                EntityKind.object,
                EntityKind.surface,
                EntityKind.graphql_surface,
                EntityKind.graphql_operation,
                EntityKind.graphql_type,
            }
        }
        relations = {
            item.relation
            for item in assertions
            if item.derivation_type is DerivationType.deterministic
            and item.status
            not in {
                RelationshipStatus.proposed,
                RelationshipStatus.rejected,
                RelationshipStatus.superseded,
            }
            and {item.source.entity_id, item.target.entity_id}.intersection(relevant)
        }
        return {
            ResearchPredicate.references_same_object,
            ResearchPredicate.crosses_surface,
        }.issubset(relations)


def materialize_graphql_candidate(
    candidate: ExperimentCandidate,
    state: ResearchState,
    *,
    model_decision_id: str | None = None,
) -> ExperimentProposal:
    """Materialize only registered candidate bindings; model text is not accepted."""

    if candidate.primitive_kind not in {
        "graphql_operation",
        "graphql_variable_mutation",
    }:
        raise ValueError("candidate is not GraphQL")
    if (
        candidate.research_id != state.research_id
        or candidate.state_revision != state.revision
    ):
        raise ValueError("candidate is stale or belongs to another research run")
    hypothesis = next(
        (
            item
            for item in state.hypotheses
            if item.hypothesis_id == candidate.hypothesis_id
        ),
        None,
    )
    if hypothesis is None or candidate.operation_id not in {
        item.entity_id
        for item in hypothesis.entity_references
        if item.entity_kind is EntityKind.graphql_operation
    }:
        raise ValueError("candidate operation is not bound to its hypothesis")
    operation_id = str(candidate.operation_id)
    template_id = str(candidate.graphql_operation_template_id)
    kind = candidate.graphql_candidate_kind
    if kind is None:
        raise ValueError("GraphQL candidate kind is unavailable")
    common = {
        "operation_id": operation_id,
        "operation_template_id": template_id,
        "candidate_kind": kind,
        "variable_bindings": candidate.graphql_variable_bindings,
        "selected_field_ids": (
            (candidate.graphql_field_id,) if candidate.graphql_field_id else ()
        ),
    }
    inputs: list[object] = []
    if kind is GraphQLCandidateKind.authentication:
        inputs.extend(
            (
                GraphQLOperationInput(
                    **common, identity_id=str(candidate.primary_identity_id)
                ),
                GraphQLOperationInput(**common, anonymous=True),
            )
        )
    elif candidate.primitive_kind == "graphql_variable_mutation":
        inputs.append(
            GraphQLOperationInput(
                operation_id=operation_id,
                operation_template_id=template_id,
                candidate_kind=kind,
                identity_id=candidate.primary_identity_id,
            )
        )
        binding = candidate.graphql_variable_bindings[0]
        inputs.append(
            GraphQLVariableMutationInput(
                operation_id=operation_id,
                operation_template_id=template_id,
                candidate_kind=kind,
                variable_id=str(candidate.graphql_variable_id),
                argument_id=str(candidate.graphql_argument_id),
                mutation_kind=MutationKind.replace_with_controlled_value,
                value_source_reference=binding.value_reference,
                safe_mutation_id=str(candidate.safe_mutation_id),
                binding=binding,
            )
        )
    elif candidate.comparison_identity_id is not None:
        inputs.extend(
            (
                GraphQLOperationInput(
                    **common, identity_id=str(candidate.primary_identity_id)
                ),
                GraphQLOperationInput(
                    **common,
                    identity_id=candidate.comparison_identity_id,
                    identity_role="comparison",
                ),
            )
        )
    else:
        inputs.append(
            GraphQLOperationInput(**common, identity_id=candidate.primary_identity_id)
        )
    if kind is GraphQLCandidateKind.workflow_mutation:
        workflow = next(
            (
                item
                for item in state.workflows
                if item.workflow_id == candidate.workflow_id
            ),
            None,
        )
        changing = (
            next((item for item in workflow.steps if item.state_changing), None)
            if workflow is not None
            else None
        )
        if (
            changing is None
            or changing.state_before_reference is None
            or changing.state_after_reference is None
        ):
            raise ValueError("GraphQL workflow state differential is unavailable")
        inputs.append(
            StateDifferentialInput(
                before_state_reference=changing.state_before_reference,
                after_state_reference=changing.state_after_reference,
                invariant_references=candidate.information_predicates,
            )
        )
    proposal_seed = _digest(
        {
            "candidate_id": candidate.candidate_id,
            "research_id": candidate.research_id,
            "state_revision": candidate.state_revision,
        }
    )
    mutation_intent = MutationIntent(
        kind=(
            MutationKind.replace_with_controlled_value
            if kind is GraphQLCandidateKind.input_validation
            else "differential"
        ),
        controlled_object_id=candidate.controlled_object_id,
        value_source_reference=(
            candidate.graphql_variable_bindings[0].value_reference
            if kind is GraphQLCandidateKind.input_validation
            else None
        ),
    )
    return ExperimentProposal(
        proposal_id=f"proposal-{proposal_seed[7:31]}",
        research_id=candidate.research_id,
        state_revision=candidate.state_revision,
        hypothesis_id=candidate.hypothesis_id,
        capability=candidate.capability,
        target_id=candidate.target_id,
        surface_id=candidate.surface_id,
        endpoint_id=candidate.endpoint_id,
        operation_id=operation_id,
        objective=f"Measure the registered GraphQL {kind.value} boundary.",
        primary_identity_id=candidate.primary_identity_id,
        comparison_identity_id=candidate.comparison_identity_id,
        identity_relationship=candidate.identity_relationship,
        baseline_strategy=BaselineIntent(
            kind=BaselineKind.registered_graphql_operation,
            reference_id=template_id,
        ),
        mutation_intent=mutation_intent,
        expected_secure_behavior="The registered GraphQL boundary is consistently enforced.",
        expected_vulnerable_behavior="The bounded comparison produces a security-relevant differential signal.",
        required_evidence_intent=tuple(
            EvidenceIntent(
                selector=candidate.expected_evidence_class,
                predicate_reference=item,
            )
            for item in candidate.information_predicates
        ),
        rationale="Deterministically materialized from registered GraphQL semantics.",
        primitive_steps=tuple(
            PrimitiveStepProposal(
                step_id=f"step-{proposal_seed[7:19]}-{index}", input=item
            )
            for index, item in enumerate(inputs, start=1)
        ),
        provenance_id=candidate.provenance_references[0],
        model_decision_id=model_decision_id,
    )


def materialize_selected_graphql_candidate(
    decision: object,
    candidates: Sequence[ExperimentCandidate],
    state: ResearchState,
) -> ExperimentProposal:
    """Resolve a lightweight decision to exactly one immutable candidate."""

    selected_id = getattr(decision, "selected_candidate_id", None)
    if (
        selected_id is None
        or getattr(decision, "research_id", None) != state.research_id
        or getattr(decision, "state_revision", None) != state.revision
    ):
        raise ValueError("GraphQL candidate selection is stale or incomplete")
    matches = [item for item in candidates if item.candidate_id == selected_id]
    if len(matches) != 1 or matches[0].hypothesis_id != getattr(
        decision, "selected_hypothesis_id", None
    ):
        raise ValueError("GraphQL candidate selection is unknown or inconsistent")
    return materialize_graphql_candidate(
        matches[0],
        state,
        model_decision_id=str(getattr(decision, "decision_id")),
    )


def _operation(state: ResearchState, operation_id: str) -> GraphQLOperationRecord:
    operation = next(
        (
            item
            for item in state.graphql_operations
            if isinstance(item, GraphQLOperationRecord)
            and item.operation_id == operation_id
        ),
        None,
    )
    if operation is None:
        raise ValueError("registered semantic GraphQL operation is unavailable")
    return operation


def _entity_ids(hypothesis: HypothesisRecord, kind: EntityKind) -> set[str]:
    return {
        item.entity_id
        for item in hypothesis.entity_references
        if item.entity_kind is kind
    }


def _object_binding(
    state: ResearchState,
    template: RegisteredGraphQLOperationTemplate,
    object_id: str,
    required_argument_ids: set[str],
) -> GraphQLVariableBinding | None:
    durable = {
        (
            item.binding.variable_id,
            item.binding.argument_id,
            item.binding.value_reference,
        )
        for item in state.graphql_variable_bindings
        if item.operation_id == template.operation_id
    }
    for binding in template.variable_bindings:
        if (
            binding.value_source is GraphQLVariableValueSource.controlled_object
            and binding.value_reference == object_id
            and (
                not required_argument_ids
                or binding.argument_id in required_argument_ids
            )
            and (
                binding.variable_id,
                binding.argument_id,
                binding.value_reference,
            )
            in durable
        ):
            return binding
    arguments: dict[str, GraphQLArgumentRecord] = {
        item.argument_id: item for item in state.graphql_arguments
    }
    variables = {item.variable_id: item for item in state.graphql_variables}
    for registered in template.argument_bindings:
        argument = arguments.get(registered.argument_id)
        variable = variables.get(registered.variable_id)
        if (
            argument is None
            or variable is None
            or (
                required_argument_ids
                and argument.argument_id not in required_argument_ids
            )
            or argument.semantic_role
            not in {
                GraphQLSemanticRole.identifier,
                GraphQLSemanticRole.object_reference,
            }
            or argument.object_reference_semantics.research_object_id != object_id
            or variable.operation_id != template.operation_id
        ):
            continue
        return GraphQLVariableBinding(
            variable_id=variable.variable_id,
            argument_id=argument.argument_id,
            value_source=GraphQLVariableValueSource.controlled_object,
            value_reference=object_id,
        )
    return None


def _replace_binding(
    existing: Sequence[GraphQLVariableBinding], replacement: GraphQLVariableBinding
) -> tuple[GraphQLVariableBinding, ...]:
    retained = [
        item
        for item in existing
        if (item.variable_id, item.argument_id)
        != (replacement.variable_id, replacement.argument_id)
    ]
    return tuple(
        sorted(
            (*retained, replacement),
            key=lambda item: (item.variable_id, item.argument_id),
        )
    )


def _distinct_pair(
    identities: Sequence[Identity],
    attribute: str,
    preferred: Sequence[Identity],
) -> tuple[Identity, Identity] | None:
    source = tuple(preferred) if len(preferred) >= 2 else tuple(identities)
    for first in source:
        first_value = getattr(first, attribute)
        if first_value is None:
            continue
        for second in source:
            if (
                first.identity_id != second.identity_id
                and getattr(second, attribute) is not None
                and getattr(second, attribute) != first_value
            ):
                return first, second
    return None


def _cleanup_definition(context: ExperimentCompilerContext, capability: str):
    matches = [
        item
        for item in context.cleanup_definitions
        if capability in item.capability_names
        or "graphql_operation" in item.primitive_names
    ]
    return (
        sorted(matches, key=lambda item: item.cleanup_reference)[0] if matches else None
    )


def _mutation_kind(kind: GraphQLCandidateKind) -> CandidateMutationKind:
    if kind is GraphQLCandidateKind.input_validation:
        return CandidateMutationKind.graphql_safe_argument_mutation
    if kind in {
        GraphQLCandidateKind.mutation_authorization,
        GraphQLCandidateKind.workflow_mutation,
    }:
        return CandidateMutationKind.graphql_state_transition
    if kind in {
        GraphQLCandidateKind.object_authorization,
        GraphQLCandidateKind.ownership,
        GraphQLCandidateKind.tenant_bound,
        GraphQLCandidateKind.cross_surface,
        GraphQLCandidateKind.nested_resolver,
    }:
        return CandidateMutationKind.graphql_object_substitution
    if kind is GraphQLCandidateKind.field_authorization:
        return CandidateMutationKind.graphql_field_differential
    return CandidateMutationKind.graphql_identity_differential


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "GRAPHQL_CANDIDATE_VERSION",
    "MAX_GRAPHQL_CANDIDATES",
    "GraphQLCandidateLimits",
    "GraphQLCandidatePolicy",
    "GraphQLExperimentCandidateBuilder",
    "build_registered_graphql_operation_template",
    "materialize_graphql_candidate",
    "materialize_selected_graphql_candidate",
]
