from __future__ import annotations

import json

import pytest

from agent_core.models import (
    ModelCallLedger,
    ModelResponse,
    ModelRoute,
    ModelRoutingPolicy,
    RoutingMode,
)
from agent_core.research import (
    AttackChainCandidate,
    AttackChainCandidateBuilder,
    ChainBudgetLimits,
    ChainBudgetState,
    ChainExperimentPlanner,
    ChainLinkStatus,
    ChainSelectionAction,
    ChainSelectionDecision,
    PublicSafeChainPacketBuilder,
    ResearchConfidence,
    ResearchReasoningEngine,
    DerivationType,
    EntityKind,
    EntityReference,
    Relationship,
    RelationshipStatus,
    ResearchPredicate,
    ResearchState,
    SurfaceType,
    TokenKind,
    TokenLifecycle,
    TokenRef,
    UnresolvedChainLink,
    materialize_attack_chain,
    materialize_chain_hypothesis,
    resolve_chain_link,
    select_chain_candidate,
    stable_chain_digest,
)
from tests.phase4_chain_helpers import (
    chain_state,
    experiment_candidate,
    unrelated_findings_state,
)


def test_graphql_to_rest_candidate_is_evidence_backed_and_bounded():
    state = chain_state()
    experiment = experiment_candidate(state)
    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment,)
    )

    assert len(candidates) == 1
    assert candidates[0].category == "graphql-to-rest"
    assert candidates[0].available_experiment_candidates == (experiment.candidate_id,)
    assert len(candidates[0].required_unresolved_links) == 1
    assert len(candidates[0].ordered_references) <= 4


def test_unresolved_chain_is_ineligible_without_an_ordinary_experiment():
    assert AttackChainCandidateBuilder().build(chain_state()) == ()


def test_rest_to_graphql_and_token_authorization_patterns_are_generic():
    rest_graphql = chain_state(
        source_type=SurfaceType.rest, target_type=SurfaceType.graphql
    )
    token_rest = chain_state(
        source_type=SurfaceType.token, target_type=SurfaceType.rest
    )

    assert (
        AttackChainCandidateBuilder()
        .build(
            rest_graphql, experiment_candidates=(experiment_candidate(rest_graphql),)
        )[0]
        .category
        == "rest-to-graphql"
    )
    assert (
        AttackChainCandidateBuilder()
        .build(token_rest, experiment_candidates=(experiment_candidate(token_rest),))[0]
        .category
        == "token-to-authorization"
    )


def test_typed_token_claim_relationship_creates_authorization_candidate():
    state = chain_state()
    token = TokenRef(
        token_ref_id="token-opaque-reference",
        identity_id="identity-controlled",
        vault_reference="credential_reference_123456",
        token_kind=TokenKind.access,
        lifecycle=TokenLifecycle.active,
        issuer_reference="issuer-reference",
        provenance_id="prov-chain",
    )
    relationship = Relationship(
        relationship_id="relationship-token-claim-context",
        source=EntityReference(
            entity_kind=EntityKind.token, entity_id=token.token_ref_id
        ),
        predicate=ResearchPredicate.produces_context_for,
        target=EntityReference(
            entity_kind=EntityKind.hypothesis,
            entity_id="hypothesis-destination-authz",
        ),
        status=RelationshipStatus.observed,
        evidence_references=("evidence-chain",),
        derivation_type=DerivationType.deterministic,
        provenance_id="prov-chain",
    )
    payload = state.model_dump(mode="python")
    payload.update(token_refs=(token,), relationships=(relationship,))
    token_state = ResearchState.model_validate(payload)
    candidate = AttackChainCandidateBuilder().build(
        token_state, experiment_candidates=(experiment_candidate(token_state),)
    )[0]

    assert candidate.category == "token-to-authorization"
    assert candidate.identity_ids == ("identity-controlled",)
    assert "token-opaque-reference" in {
        item.entity_id for item in candidate.ordered_references
    }


def test_unrelated_findings_do_not_become_a_chain_candidate():
    state = unrelated_findings_state()
    assert AttackChainCandidateBuilder().build(state) == ()


def test_candidate_deduplication_ignores_iteration_order():
    state = chain_state()
    experiment = experiment_candidate(state)
    builder = AttackChainCandidateBuilder()
    first = builder.build(state, experiment_candidates=(experiment,))
    second = builder.build(state, experiment_candidates=(experiment,))
    assert len(first) == len(second) == 1
    assert first[0].semantic_fingerprint == second[0].semantic_fingerprint
    assert first[0].candidate_id == second[0].candidate_id


def test_builder_composes_a_bounded_two_edge_evidence_path():
    state = chain_state()
    relationships = (
        Relationship(
            relationship_id="relationship-fact-to-object",
            source=EntityReference(
                entity_kind=EntityKind.fact, entity_id="fact-source-object"
            ),
            predicate=ResearchPredicate.produces_context_for,
            target=EntityReference(
                entity_kind=EntityKind.object, entity_id="object-controlled"
            ),
            status=RelationshipStatus.confirmed,
            evidence_references=("evidence-chain",),
            derivation_type=DerivationType.deterministic,
            provenance_id="prov-chain",
        ),
        Relationship(
            relationship_id="relationship-object-to-hypothesis",
            source=EntityReference(
                entity_kind=EntityKind.object, entity_id="object-controlled"
            ),
            predicate=ResearchPredicate.enables,
            target=EntityReference(
                entity_kind=EntityKind.hypothesis,
                entity_id="hypothesis-destination-authz",
            ),
            status=RelationshipStatus.confirmed,
            evidence_references=("evidence-chain",),
            derivation_type=DerivationType.deterministic,
            provenance_id="prov-chain",
        ),
    )
    payload = state.model_dump(mode="python")
    payload.update(relationships=relationships)
    path_state = ResearchState.model_validate(payload)
    candidates = AttackChainCandidateBuilder().build(
        path_state, experiment_candidates=(experiment_candidate(path_state),)
    )
    composed = next(item for item in candidates if len(item.relationship_ids) == 2)

    assert len(composed.ordered_references) == 3
    assert len(composed.required_unresolved_links) == 1
    assert composed.relationship_ids == (
        "relationship-fact-to-object",
        "relationship-object-to-hypothesis",
    )


def test_public_packet_is_compact_and_contains_only_reference_closure():
    state = chain_state()
    candidates = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )
    packet = PublicSafeChainPacketBuilder().build(state, candidates)

    assert packet.serialized_size < 5_120
    rendered = str(packet.public_payload()).lower()
    assert "bearer" not in rendered
    assert "raw_request" not in rendered


def test_model_selection_can_only_resolve_an_existing_candidate_id():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    decision = ChainSelectionDecision(
        decision_id="chain-decision-1",
        research_id=state.research_id,
        state_revision=state.revision,
        action=ChainSelectionAction.select_candidate,
        selected_chain_candidate_id=candidate.candidate_id,
        priority=80,
        confidence=ResearchConfidence.medium,
        expected_information_gain=0.8,
        reasoning_summary="This fixed candidate has the highest bounded value.",
        evidence_references=candidate.evidence_references,
    )

    selected = select_chain_candidate((candidate,), decision)
    hypothesis = materialize_chain_hypothesis(candidate, decision=decision)
    assert selected is candidate
    assert hypothesis.ordered_references == candidate.ordered_references
    assert hypothesis.unresolved_links == candidate.required_unresolved_links


def test_one_lightweight_model_call_selects_c2_without_mutating_bindings():
    state = chain_state()
    base = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    candidates = tuple(
        base.model_copy(update={"candidate_id": f"chain-candidate-C{index}"})
        for index in (1, 2, 3)
    )
    decision = ChainSelectionDecision(
        decision_id="chain-model-decision",
        research_id=state.research_id,
        state_revision=state.revision,
        action=ChainSelectionAction.select_candidate,
        selected_chain_candidate_id="chain-candidate-C2",
        priority=90,
        confidence=ResearchConfidence.high,
        expected_information_gain=0.9,
        reasoning_summary="C2 has the highest bounded information value.",
        evidence_references=base.evidence_references,
    )

    class FakeRouter:
        def __init__(self):
            self.ledger = ModelCallLedger()
            self.requests = []

        def route(self, request, policy):
            del policy
            self.requests.append(request)
            response = ModelResponse(
                provider="ollama",
                model="fake-chain-model",
                content=json.dumps(decision.model_dump(mode="json")),
                finish_reason="stop",
                input_tokens=5,
                output_tokens=5,
                total_tokens=10,
                estimated_cost_usd=0.0,
                latency_seconds=0.01,
                task_type=request.task_type,
                run_id=request.run_id,
                requested_provider="ollama",
                requested_model="fake-chain-model",
            )
            self.ledger.record_success(response, fallback_depth=0)
            return response

    router = FakeRouter()
    packet = PublicSafeChainPacketBuilder().build(state, candidates)
    result = ResearchReasoningEngine(router).select_chain(
        packet,
        ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="fake-chain-model"),
        ),
    )
    selected = select_chain_candidate(candidates, result)

    assert len(router.requests) == 1
    assert selected is candidates[1]
    assert selected.ordered_references == base.ordered_references
    assert candidates[0].candidate_id != selected.candidate_id


def test_chain_planner_materializes_only_the_next_ordinary_experiment():
    state = chain_state()
    experiment = experiment_candidate(state)
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment,)
    )[0]
    hypothesis = materialize_chain_hypothesis(candidate)
    plan = ChainExperimentPlanner().plan_next(
        hypothesis, candidate, state, (experiment,)
    )

    assert plan is not None
    assert plan.unresolved_link_id == hypothesis.unresolved_links[0].link_id
    assert plan.experiment_candidate_id == experiment.candidate_id
    assert plan.current_state_authorization_required
    assert len(plan.experiment_proposal.primitive_steps) == 1


def test_restart_with_refuted_prerequisite_never_plans_downstream_link():
    state = chain_state()
    experiment = experiment_candidate(state)
    base = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment,)
    )[0]
    middle = EntityReference(
        entity_kind=EntityKind.object, entity_id="object-controlled"
    )
    ordered = (base.ordered_references[0], middle, base.ordered_references[1])
    links = tuple(
        UnresolvedChainLink(
            link_id=f"chain-link-{index}",
            from_reference=ordered[index - 1],
            to_reference=ordered[index],
            claim="A bounded experiment can determine whether this link holds.",
            required_evidence=("predicate:bounded-chain-link",),
            allowed_experiment_capabilities=(experiment.primitive_kind,),
            risk=experiment.risk_class,
            request_estimate=experiment.worst_case_requests,
        )
        for index in (1, 2)
    )
    fingerprint = stable_chain_digest(
        {
            "category": base.category,
            "ordered_links": [
                (item.entity_kind.value, item.entity_id) for item in ordered
            ],
            "security_property": base.security_property,
            "surfaces": sorted(base.surface_ids),
            "identities": sorted(base.identity_ids),
            "objects": ["object-controlled"],
            "unresolved": [
                {
                    "from": (
                        item.from_reference.entity_kind.value,
                        item.from_reference.entity_id,
                    ),
                    "to": (
                        item.to_reference.entity_kind.value,
                        item.to_reference.entity_id,
                    ),
                    "capabilities": sorted(item.allowed_experiment_capabilities),
                }
                for item in links
            ],
        }
    )
    payload = base.model_dump(mode="python")
    payload.update(
        candidate_id="chain-candidate-two-links",
        ordered_references=ordered,
        object_ids=("object-controlled",),
        required_unresolved_links=links,
        request_cost_estimate=4,
        semantic_fingerprint=fingerprint,
    )
    candidate = AttackChainCandidate.model_validate(payload)
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate, hypothesis, provenance_id="prov-chain", created_at=state.created_at
    )
    broken = resolve_chain_link(
        chain,
        link_id=links[0].link_id,
        status=ChainLinkStatus.refuted,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-refuted-prerequisite",
        updated_at=state.updated_at,
    )
    state_payload = state.model_dump(mode="python")
    state_payload.update(
        chain_candidates=(candidate,),
        chain_hypotheses=(hypothesis,),
        attack_chains=(broken,),
    )
    restarted = ResearchState.model_validate(state_payload)

    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis, candidate, restarted, (experiment,)
        )
        is None
    )


def test_chain_planner_enforces_experiment_and_request_budgets():
    state = chain_state()
    experiment = experiment_candidate(state)
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment,)
    )[0]
    hypothesis = materialize_chain_hypothesis(candidate)
    exhausted = ChainBudgetState(
        budget_reference="chain-budget-v1",
        limits=ChainBudgetLimits(
            maximum_chain_experiments=0,
            maximum_chain_target_requests=1,
        ),
        authoritative_request_ledger_reference="request-budget-v1",
    )

    assert (
        ChainExperimentPlanner().plan_next(
            hypothesis,
            candidate,
            state,
            (experiment,),
            budget_state=exhausted,
        )
        is None
    )


def test_model_output_cannot_add_or_modify_chain_bindings():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    decision = ChainSelectionDecision(
        decision_id="chain-decision-fixed-binding",
        research_id=state.research_id,
        state_revision=state.revision,
        action=ChainSelectionAction.select_candidate,
        selected_chain_candidate_id=candidate.candidate_id,
        priority=80,
        confidence=ResearchConfidence.medium,
        expected_information_gain=0.8,
        reasoning_summary="Select the supplied fixed candidate.",
        evidence_references=candidate.evidence_references,
    )
    payload = decision.model_dump(mode="python")
    payload["ordered_references"] = [
        {"entity_kind": "target", "entity_id": "invented-binding"}
    ]

    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        ChainSelectionDecision.model_validate(payload)


def test_chain_contract_rejects_raw_secret_material():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    payload = candidate.model_dump(mode="python")
    payload["entry_condition"] = "Bearer secret-material-that-must-not-leak"

    with pytest.raises(ValueError, match="public-safe boundary|private material"):
        AttackChainCandidate.model_validate(payload)


def test_model_proposed_cross_surface_relation_is_not_chain_eligible():
    state = chain_state()
    proposed = state.relationships[0].model_copy(
        update={
            "status": RelationshipStatus.proposed,
            "derivation_type": DerivationType.model_proposed,
        }
    )
    payload = state.model_dump(mode="python")
    payload.update(relationships=(proposed,))
    proposed_state = ResearchState.model_validate(payload)

    assert (
        AttackChainCandidateBuilder().build(
            proposed_state,
            experiment_candidates=(experiment_candidate(proposed_state),),
        )
        == ()
    )


def test_chain_selection_schema_contains_no_authority_or_confirmation_surface():
    assert set(ChainSelectionDecision.model_fields) == {
        "decision_id",
        "research_id",
        "state_revision",
        "action",
        "selected_chain_candidate_id",
        "priority",
        "confidence",
        "expected_information_gain",
        "reasoning_summary",
        "evidence_references",
        "missing_evidence",
        "stop_reason",
    }
