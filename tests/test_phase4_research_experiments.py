from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.research import (
    AuthorizedExperiment,
    BaselineIntent,
    BaselineKind,
    DifferentialSelector,
    EvidenceIntent,
    ExperimentProposal,
    MutationIntent,
    IdentityRelationship,
    PrimitiveStepProposal,
    RequestReplayInput,
)

NOW = "2026-09-17T12:00:00+00:00"
FUTURE = "2026-09-17T13:00:00+00:00"


def proposal_payload() -> dict[str, object]:
    return {
        "proposal_id": "proposal-1",
        "research_id": "research-1",
        "state_revision": 3,
        "hypothesis_id": "hypothesis-1",
        "capability": "request_replay",
        "target_id": "target-1",
        "surface_id": "surface-1",
        "endpoint_id": "endpoint-1",
        "objective": "Replay one registered request in a controlled context.",
        "primary_identity_id": "identity-1",
        "baseline": BaselineIntent(
            kind=BaselineKind.registered_request,
            reference_id="template-1",
        ),
        "mutation_intent": MutationIntent(kind="none"),
        "expected_secure_behavior": "The registered endpoint enforces access.",
        "expected_vulnerable_behavior": "The endpoint returns a protected result.",
        "required_evidence_intent": (
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="predicate-1",
            ),
        ),
        "rationale": "One bounded replay distinguishes the outcomes.",
        "primitive_steps": (
            PrimitiveStepProposal(
                step_id="step-1",
                input=RequestReplayInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    identity_id="identity-1",
                ),
            ),
        ),
        "provenance_id": "provenance-1",
        "model_decision_id": "decision-1",
        "expires_at": FUTURE,
    }


def test_proposal_is_strict_immutable_and_reference_only():
    proposal = ExperimentProposal.model_validate(proposal_payload())
    assert proposal.schema_version == 1
    assert proposal.primitive_steps[0].primitive_name == "request_replay"
    with pytest.raises(ValidationError, match="frozen_instance"):
        proposal.objective = "changed"  # type: ignore[misc]


def test_proposal_rejects_unknown_fields():
    payload = proposal_payload()
    payload["unknown"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ExperimentProposal.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    (
        "request_estimate",
        "request_cost",
        "risk",
        "state_changing",
        "cleanup",
        "executor",
        "network_route",
        "policy_authorization",
        "scope_authorization",
        "owned_resource_authorization",
        "authorization_expiry",
    ),
)
def test_proposal_rejects_model_authored_authoritative_fields(field: str):
    payload = proposal_payload()
    payload[field] = "model-supplied"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ExperimentProposal.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("objective", "Send curl -X GET registered-target", "executable"),
        ("rationale", "Run python -c 'import os'", "executable"),
        ("objective", "Try https://unregistered.example/path", "arbitrary request"),
        (
            "rationale",
            "GET /admin HTTP/1.1\nHost: arbitrary.example",
            "arbitrary request",
        ),
        ("rationale", "Use sk-abcdefghijklmnop as the key", "credential"),
    ),
)
def test_proposal_rejects_raw_executable_request_and_secret_content(
    field: str, value: str, message: str
):
    payload = proposal_payload()
    payload[field] = value
    with pytest.raises(ValidationError, match=message):
        ExperimentProposal.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    ("shell_command", "python_code", "raw_http_request", "url", "authorization"),
)
def test_proposal_has_no_raw_execution_or_authorization_slots(field: str):
    payload = proposal_payload()
    payload[field] = "untrusted"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ExperimentProposal.model_validate(payload)


def test_authorized_experiment_boundary_has_no_public_constructor():
    with pytest.raises(TypeError, match="reserved for P4-0D"):
        AuthorizedExperiment(ExperimentProposal.model_validate(proposal_payload()))


def test_identity_relationship_requires_two_explicit_identity_references():
    payload = proposal_payload()
    payload["identity_relationship"] = IdentityRelationship.owner_non_owner
    with pytest.raises(ValidationError, match="primary and comparison"):
        ExperimentProposal.model_validate(payload)
