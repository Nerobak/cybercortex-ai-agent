"""Deterministic, evidence-backed experiment candidates for routine research.

Candidates are inert references to experiment possibilities.  They contain no
request data, credentials, policy authority, or execution method.  The model
may select a candidate identifier; deterministic code owns every binding and
materializes the corresponding proposal for the existing compiler.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from agent_core.agent_models import RiskLevel
from agent_core.result_normalizer import public_result
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.compiler import ExperimentCompiler, ExperimentCompilerContext
from agent_core.research.experiments import (
    BaselineIntent,
    BaselineKind,
    EvidenceIntent,
    ExperimentProposal,
    MutationIntent,
)
from agent_core.research.primitives import (
    AuthenticationDifferentialInput,
    DifferentialSelector,
    IdentityRelationship,
    MutationKind,
    ObjectSubstitutionInput,
    ParameterMutationInput,
    PrimitiveCapabilityState,
    PrimitiveStepProposal,
)
from agent_core.research.provenance import reject_secret_material
from agent_core.research.registry import ExperimentRegistry
from agent_core.research.selection import ExperimentSelector
from agent_core.research.state import (
    HypothesisRecord,
    Identity,
    ResearchObject,
    ResearchRequestTemplate,
    ResearchState,
)
from agent_core.research.types import (
    HypothesisResearchStatus,
    IdentityEligibility,
    OpaqueIdentifier,
    ResearchContract,
    Sha256Digest,
)
from agent_core.verification_capabilities import (
    ResearchExperimentCapabilityAdapter,
    get_research_experiment_capability_adapter,
)

MAX_EXPERIMENT_CANDIDATES = 200


class CandidateBaselineKind(str, Enum):
    registered_request = "registered_request"
    primary_identity = "primary_identity"


class CandidateMutationKind(str, Enum):
    authentication_differential = "authentication_differential"
    controlled_object_substitution = "controlled_object_substitution"
    remove_parameter = "remove_parameter"


class ExperimentCandidate(ResearchContract):
    """An immutable, already-compiled research possibility without authority."""

    candidate_id: OpaqueIdentifier
    research_id: OpaqueIdentifier
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    hypothesis_id: OpaqueIdentifier
    capability: OpaqueIdentifier
    primitive_kind: Literal[
        "authentication_differential", "object_substitution", "parameter_mutation"
    ]
    target_id: OpaqueIdentifier
    surface_id: OpaqueIdentifier | None = None
    endpoint_id: OpaqueIdentifier
    operation_id: OpaqueIdentifier | None = None
    request_template_id: OpaqueIdentifier
    parameter_id: OpaqueIdentifier | None = None
    primary_identity_id: OpaqueIdentifier | None = None
    comparison_identity_id: OpaqueIdentifier | None = None
    identity_relationship: IdentityRelationship | None = None
    controlled_object_id: OpaqueIdentifier | None = None
    ownership_evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        default=(), max_length=20
    )
    baseline_kind: CandidateBaselineKind
    mutation_kind: CandidateMutationKind
    expected_evidence_class: DifferentialSelector
    minimum_requests: StrictInt = Field(ge=0, le=10_000)
    worst_case_requests: StrictInt = Field(ge=0, le=10_000)
    risk_class: RiskLevel
    information_predicates: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=20
    )
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )
    provenance_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )
    fingerprint_seed: Sha256Digest

    @model_validator(mode="after")
    def validate_shape(self) -> "ExperimentCandidate":
        payload = self.model_dump(mode="json")
        if public_result(payload) != payload:
            raise ValueError("experiment candidate is outside the public boundary")
        reject_secret_material(payload, location="experiment candidate")
        object_fields = (
            self.parameter_id,
            self.primary_identity_id,
            self.comparison_identity_id,
            self.identity_relationship,
            self.controlled_object_id,
        )
        if self.primitive_kind == "object_substitution" and any(
            item is None for item in object_fields
        ):
            raise ValueError("object substitution candidate bindings are incomplete")
        if self.primitive_kind != "object_substitution" and (
            self.comparison_identity_id is not None
            or self.identity_relationship is not None
        ):
            raise ValueError("non-object candidate contains object bindings")
        if self.primitive_kind == "authentication_differential" and (
            self.primary_identity_id is None
            or self.parameter_id is not None
            or self.controlled_object_id is not None
            or self.ownership_evidence_references
        ):
            raise ValueError("authentication candidate bindings are invalid")
        if self.primitive_kind == "parameter_mutation" and self.parameter_id is None:
            raise ValueError("parameter candidate bindings are invalid")
        if (self.controlled_object_id is None) != (
            not self.ownership_evidence_references
        ):
            raise ValueError("controlled object requires ownership evidence")
        if self.worst_case_requests < self.minimum_requests:
            raise ValueError("candidate request estimate is invalid")
        return self


class CandidateHypothesisSummary(ResearchContract):
    hypothesis_id: OpaqueIdentifier
    category: OpaqueIdentifier
    priority: StrictInt = Field(ge=0, le=100)
    confidence: OpaqueIdentifier
    candidate_count: StrictInt = Field(ge=0, le=MAX_EXPERIMENT_CANDIDATES)


class PublicSafeCandidateSummary(ResearchContract):
    candidate_id: OpaqueIdentifier
    hypothesis_id: OpaqueIdentifier
    capability: OpaqueIdentifier
    primitive_kind: OpaqueIdentifier
    endpoint_id: OpaqueIdentifier
    parameter_id: OpaqueIdentifier | None = None
    has_identity_context: StrictBool
    identity_relationship: IdentityRelationship | None = None
    has_controlled_object: StrictBool
    expected_evidence_class: DifferentialSelector
    minimum_requests: StrictInt = Field(ge=0, le=10_000)
    worst_case_requests: StrictInt = Field(ge=0, le=10_000)
    risk_class: RiskLevel
    information_predicates: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=20
    )
    evidence_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=100
    )


class CandidateBudgetSummary(ResearchContract):
    global_experiments: StrictInt = Field(ge=0)
    requests: StrictInt = Field(ge=0)
    model_calls: StrictInt = Field(ge=0)
    state_changes: StrictInt = Field(ge=0)
    cleanup_barrier: StrictBool


class PublicSafeCandidatePacket(ResearchContract):
    """Minimal reference closure supplied for one routine model decision."""

    research_id: OpaqueIdentifier
    state_revision: StrictInt = Field(ge=0, le=1_000_000_000)
    target_references: tuple[OpaqueIdentifier, ...] = Field(min_length=1, max_length=64)
    surface_references: tuple[OpaqueIdentifier, ...] = Field(
        min_length=1, max_length=200
    )
    hypotheses: tuple[CandidateHypothesisSummary, ...] = Field(
        min_length=1, max_length=200
    )
    candidates: tuple[PublicSafeCandidateSummary, ...] = Field(
        min_length=1, max_length=MAX_EXPERIMENT_CANDIDATES
    )
    remaining_budgets: CandidateBudgetSummary
    attempted_fingerprints: tuple[Sha256Digest, ...] = Field(default=(), max_length=500)
    policy_limitations: tuple[str, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def enforce_public_boundary(self) -> "PublicSafeCandidatePacket":
        payload = self.model_dump(mode="json")
        if public_result(payload) != payload:
            raise ValueError("candidate packet is outside the public boundary")
        reject_secret_material(payload, location="research candidate packet")
        candidate_hypotheses = {item.hypothesis_id for item in self.candidates}
        if not candidate_hypotheses.issubset(
            {item.hypothesis_id for item in self.hypotheses}
        ):
            raise ValueError("candidate packet hypothesis closure is incomplete")
        return self

    def public_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude_defaults=True, exclude_none=True)


class ExperimentCandidateBuilder:
    """Construct and compile-screen generic candidates from registered state."""

    def __init__(
        self,
        registry: ExperimentRegistry,
        budget_manager: ResearchBudgetManager,
        compiler: ExperimentCompiler,
        *,
        maximum_candidates: int = MAX_EXPERIMENT_CANDIDATES,
    ) -> None:
        if not 1 <= maximum_candidates <= MAX_EXPERIMENT_CANDIDATES:
            raise ValueError("candidate bound is outside the supported range")
        if compiler.registry is not registry:
            raise ValueError("candidate builder and compiler must share a registry")
        self.registry = registry
        self.budget_manager = budget_manager
        self.compiler = compiler
        self.maximum_candidates = maximum_candidates
        self._selector = ExperimentSelector(compiler, budget_manager, registry=registry)

    def build(
        self,
        state: ResearchState,
        *,
        compiler_context: ExperimentCompilerContext,
        expected_state_revision: int | None = None,
        pivot: bool = False,
        cleanup_barrier: bool = False,
        policy_reference: str | None = None,
        policy_fingerprint: str | None = None,
    ) -> tuple[ExperimentCandidate, ...]:
        if expected_state_revision is not None and state.revision != (
            expected_state_revision
        ):
            return ()
        if (
            not compiler_context.execution_ready
            or cleanup_barrier
            or (
                policy_reference is not None
                and compiler_context.policy_reference != policy_reference
            )
        ):
            return ()

        raw: list[ExperimentCandidate] = []
        for hypothesis in state.hypotheses:
            if hypothesis.status in {
                HypothesisResearchStatus.closed,
                HypothesisResearchStatus.refuted,
                HypothesisResearchStatus.supported,
            }:
                continue
            try:
                adapter = get_research_experiment_capability_adapter(
                    hypothesis.category
                )
            except ValueError:
                continue
            available = {
                name
                for name in adapter.primitive_names
                if self._execution_available(name)
            }
            if "authentication_differential" in available:
                raw.extend(self._authentication_candidates(state, hypothesis, adapter))
            if "object_substitution" in available:
                raw.extend(self._object_candidates(state, hypothesis, adapter))
            if "parameter_mutation" in available:
                raw.extend(self._parameter_candidates(state, hypothesis, adapter))

        eligible: list[ExperimentCandidate] = []
        for candidate in sorted(raw, key=lambda item: item.candidate_id):
            if len(eligible) >= self.maximum_candidates:
                break
            try:
                proposal = materialize_candidate(candidate, state)
                selection = self._selector.select(
                    (proposal,),
                    state,
                    compiler_context=compiler_context,
                    pivot=pivot,
                    cleanup_barrier=cleanup_barrier,
                    policy_reference=policy_reference,
                    policy_fingerprint=policy_fingerprint,
                )
            except (TypeError, ValueError):
                continue
            if selection.selected is None or selection.selected.experiment is None:
                continue
            experiment = selection.selected.experiment
            eligible.append(
                candidate.model_copy(
                    update={
                        "minimum_requests": experiment.request_estimate.minimum,
                        "worst_case_requests": (
                            experiment.request_estimate.total_reservation
                        ),
                        "risk_class": experiment.risk.level,
                    }
                )
            )
        return tuple(eligible)

    def _execution_available(self, name: str) -> bool:
        try:
            definition = self.registry.resolve(name)
        except ValueError:
            return False
        return (
            definition.capability_state is PrimitiveCapabilityState.execution_available
        )

    def _authentication_candidates(
        self,
        state: ResearchState,
        hypothesis: HypothesisRecord,
        adapter: ResearchExperimentCapabilityAdapter,
    ) -> tuple[ExperimentCandidate, ...]:
        identities = self._eligible_identities(state)[:1]
        results = []
        for template in self._templates(state, hypothesis):
            if (
                not template.identity_requirement.required
                or not template.identity_requirement.mechanisms
            ):
                continue
            for identity in identities:
                results.append(
                    self._candidate(
                        state,
                        hypothesis,
                        adapter,
                        primitive_kind="authentication_differential",
                        template=template,
                        primary_identity=identity,
                        baseline_kind=CandidateBaselineKind.registered_request,
                        mutation_kind=CandidateMutationKind.authentication_differential,
                        evidence_class=DifferentialSelector.status_class,
                        predicate="predicate:authentication-boundary",
                    )
                )
        return tuple(results)

    def _object_candidates(
        self,
        state: ResearchState,
        hypothesis: HypothesisRecord,
        adapter: ResearchExperimentCapabilityAdapter,
    ) -> tuple[ExperimentCandidate, ...]:
        identities = {
            item.identity_id: item for item in self._eligible_identities(state)
        }
        parameters = {item.parameter_id: item for item in state.parameters}
        results = []
        for controlled_object in state.objects:
            owner = identities.get(str(controlled_object.owner_identity_id or ""))
            if (
                not controlled_object.test_owned
                or owner is None
                or not controlled_object.evidence_references
                or controlled_object.target_id != hypothesis.target_id
                or (
                    hypothesis.surface_id is not None
                    and controlled_object.surface_id != hypothesis.surface_id
                )
            ):
                continue
            for parameter_id in controlled_object.parameter_references:
                parameter = parameters.get(parameter_id)
                if parameter is None:
                    continue
                for template in self._templates(state, hypothesis):
                    if (
                        template.endpoint_id != parameter.endpoint_id
                        or parameter_id not in template.parameter_ids
                        or not template.identity_requirement.required
                        or not template.identity_requirement.mechanisms
                    ):
                        continue
                    for comparison in identities.values():
                        if comparison.identity_id == owner.identity_id:
                            continue
                        results.append(
                            self._candidate(
                                state,
                                hypothesis,
                                adapter,
                                primitive_kind="object_substitution",
                                template=template,
                                parameter_id=parameter_id,
                                primary_identity=owner,
                                comparison_identity=comparison,
                                controlled_object=controlled_object,
                                baseline_kind=CandidateBaselineKind.primary_identity,
                                mutation_kind=(
                                    CandidateMutationKind.controlled_object_substitution
                                ),
                                evidence_class=DifferentialSelector.semantic_result_class,
                                predicate="predicate:object-authorization-boundary",
                            )
                        )
        return tuple(results)

    def _parameter_candidates(
        self,
        state: ResearchState,
        hypothesis: HypothesisRecord,
        adapter: ResearchExperimentCapabilityAdapter,
    ) -> tuple[ExperimentCandidate, ...]:
        parameters = {item.parameter_id: item for item in state.parameters}
        identities = {
            item.identity_id: item for item in self._eligible_identities(state)
        }
        results = []
        for template in self._templates(state, hypothesis):
            if adapter.requires_credentials and (
                not template.identity_requirement.required
                or not template.identity_requirement.mechanisms
            ):
                continue
            for parameter_id in template.parameter_ids:
                if parameter_id not in parameters:
                    continue
                controlled_object = None
                primary_identity = None
                if adapter.requires_test_owned_resource:
                    controlled_object = next(
                        (
                            item
                            for item in state.objects
                            if item.test_owned
                            and item.target_id == hypothesis.target_id
                            and item.surface_id == template.surface_id
                            and parameter_id in item.parameter_references
                            and item.owner_identity_id in identities
                            and item.evidence_references
                        ),
                        None,
                    )
                    if controlled_object is None:
                        continue
                    primary_identity = identities[
                        str(controlled_object.owner_identity_id)
                    ]
                elif adapter.required_account_count == 1:
                    primary_identity = next(iter(identities.values()), None)
                if adapter.required_account_count and primary_identity is None:
                    continue
                if adapter.required_account_count > 1:
                    continue
                results.append(
                    self._candidate(
                        state,
                        hypothesis,
                        adapter,
                        primitive_kind="parameter_mutation",
                        template=template,
                        parameter_id=parameter_id,
                        primary_identity=primary_identity,
                        controlled_object=controlled_object,
                        baseline_kind=CandidateBaselineKind.registered_request,
                        mutation_kind=CandidateMutationKind.remove_parameter,
                        evidence_class=DifferentialSelector.semantic_result_class,
                        predicate="predicate:parameter-enforcement",
                    )
                )
        return tuple(results)

    def _candidate(
        self,
        state: ResearchState,
        hypothesis: HypothesisRecord,
        adapter: ResearchExperimentCapabilityAdapter,
        *,
        primitive_kind: Literal[
            "authentication_differential", "object_substitution", "parameter_mutation"
        ],
        template: ResearchRequestTemplate,
        baseline_kind: CandidateBaselineKind,
        mutation_kind: CandidateMutationKind,
        evidence_class: DifferentialSelector,
        predicate: str,
        parameter_id: str | None = None,
        primary_identity: Identity | None = None,
        comparison_identity: Identity | None = None,
        controlled_object: ResearchObject | None = None,
    ) -> ExperimentCandidate:
        definition = self.registry.resolve(primitive_kind)
        binding = {
            "research_id": state.research_id,
            "state_revision": state.revision,
            "hypothesis_id": hypothesis.hypothesis_id,
            "capability": adapter.category,
            "primitive_kind": primitive_kind,
            "target_id": hypothesis.target_id,
            "surface_id": template.surface_id,
            "endpoint_id": template.endpoint_id,
            "request_template_id": template.template_id,
            "parameter_id": parameter_id,
            "primary_identity_id": (
                primary_identity.identity_id if primary_identity else None
            ),
            "comparison_identity_id": (
                comparison_identity.identity_id if comparison_identity else None
            ),
            "controlled_object_id": (
                controlled_object.object_id if controlled_object else None
            ),
        }
        seed = _digest(binding)
        evidence = {
            *hypothesis.supporting_evidence,
            *template.evidence_references,
        }
        provenance = {hypothesis.provenance_id, template.provenance_id}
        ownership_evidence: tuple[str, ...] = ()
        if parameter_id is not None:
            parameter = next(
                item for item in state.parameters if item.parameter_id == parameter_id
            )
            evidence.update(parameter.evidence_references)
            provenance.add(parameter.provenance_id)
        if controlled_object is not None:
            evidence.update(controlled_object.evidence_references)
            provenance.add(controlled_object.provenance_id)
            ownership_evidence = controlled_object.evidence_references
        return ExperimentCandidate(
            candidate_id=f"candidate-{seed[7:31]}",
            research_id=state.research_id,
            state_revision=state.revision,
            hypothesis_id=hypothesis.hypothesis_id,
            capability=adapter.category,
            primitive_kind=primitive_kind,
            target_id=hypothesis.target_id,
            surface_id=template.surface_id,
            endpoint_id=template.endpoint_id,
            request_template_id=template.template_id,
            parameter_id=parameter_id,
            primary_identity_id=(
                primary_identity.identity_id if primary_identity else None
            ),
            comparison_identity_id=(
                comparison_identity.identity_id if comparison_identity else None
            ),
            identity_relationship=(
                IdentityRelationship.owner_non_owner
                if primitive_kind == "object_substitution"
                else None
            ),
            controlled_object_id=(
                controlled_object.object_id if controlled_object else None
            ),
            ownership_evidence_references=ownership_evidence,
            baseline_kind=baseline_kind,
            mutation_kind=mutation_kind,
            expected_evidence_class=evidence_class,
            minimum_requests=definition.minimum_requests,
            worst_case_requests=definition.worst_case_requests,
            risk_class=definition.risk_class,
            information_predicates=(predicate,),
            evidence_references=tuple(sorted(evidence)),
            provenance_references=tuple(sorted(provenance)),
            fingerprint_seed=seed,
        )

    @staticmethod
    def _eligible_identities(state: ResearchState) -> tuple[Identity, ...]:
        return tuple(
            item
            for item in state.identities
            if item.controlled and item.eligibility is IdentityEligibility.eligible
        )

    @staticmethod
    def _templates(
        state: ResearchState, hypothesis: HypothesisRecord
    ) -> tuple[ResearchRequestTemplate, ...]:
        endpoints = {
            item.endpoint_id
            for item in state.endpoints
            if item.target_id == hypothesis.target_id
            and (
                hypothesis.surface_id is None
                or item.surface_id == hypothesis.surface_id
            )
        }
        return tuple(
            item
            for item in state.request_templates
            if item.endpoint_id in endpoints and item.target_id == hypothesis.target_id
        )


class PublicSafeCandidatePacketBuilder:
    def __init__(self, budget_manager: ResearchBudgetManager) -> None:
        self.budget_manager = budget_manager

    def build(
        self,
        state: ResearchState,
        candidates: tuple[ExperimentCandidate, ...],
        *,
        policy_limitations: tuple[str, ...] = (),
    ) -> PublicSafeCandidatePacket:
        if not candidates:
            raise ValueError("candidate packet requires eligible candidates")
        if any(
            item.research_id != state.research_id
            or item.state_revision != state.revision
            for item in candidates
        ):
            raise ValueError("candidate packet contains stale candidates")
        by_hypothesis: dict[str, list[ExperimentCandidate]] = {}
        for candidate in candidates:
            by_hypothesis.setdefault(candidate.hypothesis_id, []).append(candidate)
        hypothesis_index = {item.hypothesis_id: item for item in state.hypotheses}
        hypotheses = []
        for hypothesis_id in sorted(by_hypothesis):
            hypothesis = hypothesis_index[hypothesis_id]
            hypotheses.append(
                CandidateHypothesisSummary(
                    hypothesis_id=hypothesis_id,
                    category=hypothesis.category,
                    priority=hypothesis.priority,
                    confidence=hypothesis.confidence.value,
                    candidate_count=len(by_hypothesis[hypothesis_id]),
                )
            )
        budget = self.budget_manager.state(state)
        return PublicSafeCandidatePacket(
            research_id=state.research_id,
            state_revision=state.revision,
            target_references=tuple(sorted({item.target_id for item in candidates})),
            surface_references=tuple(
                sorted(
                    {
                        item.surface_id
                        for item in candidates
                        if item.surface_id is not None
                    }
                )
            ),
            hypotheses=tuple(hypotheses),
            candidates=tuple(
                PublicSafeCandidateSummary(
                    candidate_id=item.candidate_id,
                    hypothesis_id=item.hypothesis_id,
                    capability=item.capability,
                    primitive_kind=item.primitive_kind,
                    endpoint_id=item.endpoint_id,
                    parameter_id=item.parameter_id,
                    has_identity_context=item.primary_identity_id is not None,
                    identity_relationship=item.identity_relationship,
                    has_controlled_object=item.controlled_object_id is not None,
                    expected_evidence_class=item.expected_evidence_class,
                    minimum_requests=item.minimum_requests,
                    worst_case_requests=item.worst_case_requests,
                    risk_class=item.risk_class,
                    information_predicates=item.information_predicates,
                    evidence_references=item.evidence_references,
                )
                for item in candidates
            ),
            remaining_budgets=CandidateBudgetSummary(
                global_experiments=max(
                    0,
                    self.budget_manager.policy.global_experiment_ceiling
                    - budget.experiments_consumed,
                ),
                requests=budget.request_budget.remaining,
                model_calls=budget.model_budget.remaining_calls,
                state_changes=max(
                    0,
                    budget.state_change_ceiling - budget.state_changes_consumed,
                ),
                cleanup_barrier=budget.cleanup_barrier_reference is not None,
            ),
            attempted_fingerprints=tuple(
                sorted({item.material_fingerprint for item in state.experiment_history})
            ),
            policy_limitations=policy_limitations,
        )


def materialize_candidate(
    candidate: ExperimentCandidate,
    state: ResearchState,
    *,
    model_decision_id: str | None = None,
) -> ExperimentProposal:
    """Materialize one immutable candidate without granting execution authority."""

    if (
        candidate.research_id != state.research_id
        or candidate.state_revision != state.revision
    ):
        raise ValueError("candidate is stale or belongs to another research run")
    if candidate.hypothesis_id not in {item.hypothesis_id for item in state.hypotheses}:
        raise ValueError("candidate hypothesis is unavailable")

    step_input: object
    if candidate.primitive_kind == "authentication_differential":
        step_input = AuthenticationDifferentialInput(
            request_template_id=candidate.request_template_id,
            endpoint_id=candidate.endpoint_id,
            identity_id=str(candidate.primary_identity_id),
        )
        baseline = BaselineIntent(
            kind=BaselineKind.registered_request,
            reference_id=candidate.request_template_id,
        )
        mutation = MutationIntent(kind="differential")
        objective = "Measure the registered authentication boundary differential."
        secure = "The protected operation rejects the unauthenticated comparison."
        vulnerable = "The protected operation does not distinguish the comparison."
    elif candidate.primitive_kind == "object_substitution":
        step_input = ObjectSubstitutionInput(
            request_template_id=candidate.request_template_id,
            endpoint_id=candidate.endpoint_id,
            parameter_id=str(candidate.parameter_id),
            primary_identity_id=str(candidate.primary_identity_id),
            comparison_identity_id=str(candidate.comparison_identity_id),
            controlled_object_id=str(candidate.controlled_object_id),
            relationship=candidate.identity_relationship,
            ownership_evidence_ids=candidate.ownership_evidence_references,
        )
        baseline = BaselineIntent(
            kind=BaselineKind.primary_identity,
            reference_id=str(candidate.primary_identity_id),
        )
        mutation = MutationIntent(
            kind=MutationKind.replace_with_controlled_object_reference,
            parameter_id=candidate.parameter_id,
            controlled_object_id=candidate.controlled_object_id,
        )
        objective = "Measure access behavior for a controlled ownership substitution."
        secure = "The ownership boundary prevents unauthorized controlled access."
        vulnerable = "The ownership comparison produces a boundary-breaking signal."
    elif candidate.primitive_kind == "parameter_mutation":
        step_input = ParameterMutationInput(
            request_template_id=candidate.request_template_id,
            endpoint_id=candidate.endpoint_id,
            parameter_id=str(candidate.parameter_id),
            mutation_kind=MutationKind.remove_parameter,
            controlled_object_id=candidate.controlled_object_id,
            maximum_variants=1,
        )
        baseline = BaselineIntent(
            kind=BaselineKind.registered_request,
            reference_id=candidate.request_template_id,
        )
        mutation = MutationIntent(
            kind=MutationKind.remove_parameter,
            parameter_id=candidate.parameter_id,
            controlled_object_id=candidate.controlled_object_id,
        )
        objective = "Measure enforcement behavior for a registered parameter mutation."
        secure = "The registered operation safely handles the bounded mutation."
        vulnerable = "The mutation produces a security-relevant differential signal."
    else:  # pragma: no cover - the strict contract makes this unreachable
        raise ValueError("unsupported candidate primitive")

    proposal_seed = _digest(
        {
            "candidate_id": candidate.candidate_id,
            "research_id": candidate.research_id,
            "state_revision": candidate.state_revision,
        }
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
        operation_id=candidate.operation_id,
        objective=objective,
        primary_identity_id=candidate.primary_identity_id,
        comparison_identity_id=candidate.comparison_identity_id,
        identity_relationship=candidate.identity_relationship,
        baseline_strategy=baseline,
        mutation_intent=mutation,
        expected_secure_behavior=secure,
        expected_vulnerable_behavior=vulnerable,
        required_evidence_intent=tuple(
            EvidenceIntent(
                selector=candidate.expected_evidence_class,
                predicate_reference=predicate,
            )
            for predicate in candidate.information_predicates
        ),
        rationale="Deterministically constructed from registered typed research context.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id=f"step-{proposal_seed[7:23]}", input=step_input
            ),
        ),
        provenance_id=candidate.provenance_references[0],
        model_decision_id=model_decision_id,
    )


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "CandidateBaselineKind",
    "CandidateBudgetSummary",
    "CandidateHypothesisSummary",
    "CandidateMutationKind",
    "ExperimentCandidate",
    "ExperimentCandidateBuilder",
    "MAX_EXPERIMENT_CANDIDATES",
    "PublicSafeCandidatePacket",
    "PublicSafeCandidatePacketBuilder",
    "PublicSafeCandidateSummary",
    "materialize_candidate",
]
