from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.agent_models import RiskLevel
from agent_core.research import (
    AttackChainStatus,
    AttackChainStepKind,
    ChainLinkStatus,
    EntityKind,
    EntityReference,
    UnresolvedChainLink,
    materialize_attack_chain,
    materialize_chain_hypothesis,
    resolve_chain_link,
)
from agent_core.research.chain_candidates import AttackChainCandidateBuilder
from tests.phase4_chain_helpers import TS, TS_1, chain_state, experiment_candidate


def test_attack_chain_contract_is_immutable_strict_and_reference_only():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate,
        hypothesis,
        provenance_id="prov-chain",
        created_at=TS,
    )

    assert chain.chain_id == chain.attack_chain_id
    assert chain.status is AttackChainStatus.proposed
    assert chain.steps[0].step_kind is AttackChainStepKind.fact
    assert chain.steps[1].unresolved_link_id == hypothesis.unresolved_links[0].link_id
    with pytest.raises(ValidationError, match="frozen_instance"):
        chain.title = "mutated"  # type: ignore[misc]
    assert "authorization" not in chain.model_dump(mode="json")


def test_unresolved_link_requires_evidence_when_resolved():
    with pytest.raises(ValidationError, match="requires evidence"):
        UnresolvedChainLink(
            link_id="link-1",
            from_reference=EntityReference(
                entity_kind=EntityKind.fact, entity_id="fact-1"
            ),
            to_reference=EntityReference(
                entity_kind=EntityKind.hypothesis, entity_id="hypothesis-1"
            ),
            claim="The bounded link may hold.",
            required_evidence=("predicate:one",),
            allowed_experiment_capabilities=("authentication_differential",),
            risk=RiskLevel.low,
            request_estimate=2,
            status=ChainLinkStatus.supported,
        )


def test_link_resolution_is_deterministic_and_cannot_change_bindings():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    hypothesis = materialize_chain_hypothesis(candidate)
    chain = materialize_attack_chain(
        candidate,
        hypothesis,
        provenance_id="prov-chain",
        created_at=TS,
    )
    resolved = resolve_chain_link(
        chain,
        link_id=chain.unresolved_links[0].link_id,
        status=ChainLinkStatus.supported,
        evidence_references=("evidence-chain",),
        experiment_id="experiment-chain-link",
        updated_at=TS_1,
    )

    assert resolved.unresolved_links[0].status is ChainLinkStatus.supported
    assert resolved.semantic_fingerprint == chain.semantic_fingerprint
    assert resolved.status is AttackChainStatus.testing


def test_chain_status_terminal_semantics_are_explicit():
    assert AttackChainStatus.confirmed.terminal
    assert AttackChainStatus.refuted.terminal
    assert AttackChainStatus.rejected.terminal
    assert not AttackChainStatus.testing.terminal


def test_attack_chain_rejects_noncontiguous_and_forward_dependent_steps():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    chain = materialize_attack_chain(
        candidate,
        materialize_chain_hypothesis(candidate),
        provenance_id="prov-chain",
        created_at=TS,
    )

    noncontiguous = chain.model_dump(mode="python")
    noncontiguous["steps"] = (
        chain.steps[0],
        chain.steps[1].model_copy(update={"sequence": 3}),
    )
    with pytest.raises(ValidationError, match="contiguous"):
        type(chain).model_validate(noncontiguous)

    forward_dependent = chain.model_dump(mode="python")
    forward_dependent["steps"] = (
        chain.steps[0].model_copy(
            update={"required_preconditions": (str(chain.steps[1].step_id),)}
        ),
        chain.steps[1],
    )
    with pytest.raises(ValidationError, match="earlier chain steps"):
        type(chain).model_validate(forward_dependent)


def test_confirmed_chain_requires_combined_impact_evidence():
    state = chain_state()
    candidate = AttackChainCandidateBuilder().build(
        state, experiment_candidates=(experiment_candidate(state),)
    )[0]
    chain = materialize_attack_chain(
        candidate,
        materialize_chain_hypothesis(candidate),
        provenance_id="prov-chain",
        created_at=TS,
    )
    payload = chain.model_dump(mode="python")
    payload.update(
        status=AttackChainStatus.confirmed,
        reproduction_ids=("chain-reproduction-1",),
    )

    with pytest.raises(ValidationError, match="combined impact"):
        type(chain).model_validate(payload)
