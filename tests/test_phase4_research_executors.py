from __future__ import annotations

from agent_core.research import (
    DifferentialSelector,
    ExperimentProposal,
    MutationKind,
    RegisteredEvidenceSummary,
    RegisteredInvariantValue,
    RegisteredSelectorValue,
    RegisteredStateSnapshot,
)
from tests.test_phase4_research_compiler import (
    mutation_proposal,
    offline_proposal,
)
from tests.test_phase4_research_runtime import build_runtime_fixture


def _with_primary_identity(proposal: ExperimentProposal) -> ExperimentProposal:
    payload = proposal.model_dump(mode="python")
    payload["primary_identity_id"] = "identity-1"
    payload["primary_session_ref_id"] = "session-1"
    return ExperimentProposal.model_validate(payload)


def test_identity_switch_is_zero_request_context_evidence():
    fixture = build_runtime_fixture(proposal=offline_proposal("identity_switch"))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert fixture.calls == []
    assert outcome.request_delta.total == 0
    assert outcome.evidence[0].identity_references == (
        "identity-1",
        "identity-2",
    )


def test_parameter_mutation_changes_only_registered_parameter_once():
    proposal = _with_primary_identity(mutation_proposal())
    fixture = build_runtime_fixture(proposal=proposal, statuses=(200,))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert [call[1] for call in fixture.calls] == [
        "https://research.example.test/objects-1/bounded"
    ]
    assert outcome.request_delta.total == 1
    assert outcome.evidence[0].mutation_kind == "replace_with_controlled_value"


def test_change_scalar_type_is_bounded_by_maximum_variants():
    payload = mutation_proposal().model_dump(mode="python")
    payload["primary_identity_id"] = "identity-1"
    payload["primary_session_ref_id"] = "session-1"
    payload["primitive_steps"][0]["input"].update(
        mutation_kind=MutationKind.change_scalar_type,
        value_source_reference=None,
        maximum_variants=3,
    )
    proposal = ExperimentProposal.model_validate(payload)
    fixture = build_runtime_fixture(proposal=proposal, statuses=(200, 200, 200))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert len(fixture.calls) == 3
    assert outcome.request_delta.total == 3
    assert all("objects-1" in call[1] for call in fixture.calls)


def test_response_differential_is_deterministic_and_zero_request():
    summaries = (
        RegisteredEvidenceSummary(
            reference="evidence-1",
            selector_values=(
                RegisteredSelectorValue(
                    selector=DifferentialSelector.status_class, value="2xx"
                ),
            ),
        ),
        RegisteredEvidenceSummary(
            reference="evidence-2",
            selector_values=(
                RegisteredSelectorValue(
                    selector=DifferentialSelector.status_class, value="4xx"
                ),
            ),
        ),
    )
    fixture = build_runtime_fixture(
        proposal=offline_proposal("response_differential"),
        evidence_summaries=summaries,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert fixture.calls == []
    assert outcome.request_delta.total == 0
    assert outcome.evidence[0].selector_results[0].equal is False


def test_state_differential_is_deterministic_and_zero_request():
    snapshots = tuple(
        RegisteredStateSnapshot(
            reference=reference,
            digest="sha256:" + character * 64,
            invariants=(
                RegisteredInvariantValue(
                    invariant_reference="invariant-1",
                    satisfied=reference == "state-cleanup",
                ),
            ),
        )
        for reference, character in (
            ("state-before", "1"),
            ("state-after", "2"),
            ("state-cleanup", "3"),
        )
    )
    fixture = build_runtime_fixture(
        proposal=offline_proposal("state_differential"),
        state_snapshots=snapshots,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert fixture.calls == []
    assert outcome.request_delta.total == 0
    assert outcome.evidence[0].invariant_results[0].satisfied is True


def test_executor_evidence_contains_no_raw_destination_or_credential_fields():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    serialized = outcome.model_dump_json().casefold()
    assert "https://research.example.test" not in serialized
    assert 'authorization"' not in serialized
    assert 'cookie"' not in serialized
