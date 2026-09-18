from __future__ import annotations

import pytest

from agent_core.request_budget import RequestBudgetExceeded
from agent_core.research import (
    AuthorizedExperiment,
    ContextMismatchError,
    DuplicateExperimentError,
    ExpiredAuthorizationError,
    PrimitiveCapabilityState,
    PrimitiveUnavailableError,
    ResearchBudgetExhaustedError,
    ScopeMismatchError,
    StaleResearchStateError,
)
from agent_core.research.experiments import _is_gate_authorized
from tests.test_phase4_research_runtime import build_runtime_fixture


def test_only_gate_can_construct_authorized_experiment():
    with pytest.raises(TypeError, match="reserved"):
        AuthorizedExperiment()
    forged = object.__new__(AuthorizedExperiment)
    assert not _is_gate_authorized(forged)


def test_gate_authorization_has_all_sealed_authority_bindings():
    fixture = build_runtime_fixture()
    authorization = fixture.gate.authorize(fixture.experiment)
    assert _is_gate_authorized(authorization)
    assert authorization.experiment_id == fixture.experiment.experiment_id
    assert authorization.research_id == "research-1"
    assert authorization.state_revision == 4
    assert authorization.policy_decision_id
    assert authorization.policy_hash.startswith("sha256:")
    assert authorization.target_fingerprint.startswith("sha256:")
    assert authorization.scope_reference == "scope-1"
    assert len(authorization.controlled_identity_bindings) == 2
    assert len(authorization.owned_object_bindings) == 1
    assert authorization.request_budget_reservation.verification == 5
    assert authorization.executor_routes[0].execution_kind == "native"
    assert authorization.runtime_binding_reference


def test_authorization_digest_tampering_is_rejected_before_traffic():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    object.__setattr__(
        authorization,
        "_AuthorizedExperiment__target_fingerprint",
        "sha256:" + "0" * 64,
    )
    assert not _is_gate_authorized(authorization)
    with pytest.raises(Exception, match="invalid_binding"):
        binding.submit(authorization)
    assert fixture.calls == []


def test_expired_gate_authorization_is_rejected_before_traffic():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    object.__setattr__(
        fixture.gate.runtime,
        "_ResearchRuntime__current_time",
        "2026-09-17T13:00:00+00:00",
    )
    with pytest.raises(ExpiredAuthorizationError, match="expired_authorization"):
        binding.submit(authorization)
    assert fixture.calls == []


def test_registered_target_fingerprint_mismatch_is_rejected():
    fixture = build_runtime_fixture(
        target_fingerprints={"target-1": "sha256:" + "0" * 64}
    )
    with pytest.raises(ScopeMismatchError, match="scope_mismatch"):
        fixture.gate.authorize(fixture.experiment)


def test_stale_research_revision_is_rejected():
    fixture = build_runtime_fixture()
    fixture.gate.state = fixture.gate.state.model_copy(update={"revision": 5})
    with pytest.raises(StaleResearchStateError, match="stale_state"):
        fixture.gate.authorize(fixture.experiment)


def test_scope_reference_mismatch_is_rejected():
    fixture = build_runtime_fixture()
    fixture.gate.scope_reference = "different-scope"
    with pytest.raises(ScopeMismatchError, match="scope_mismatch"):
        fixture.gate.authorize(fixture.experiment)


def test_uncontrolled_or_missing_context_identity_is_rejected():
    fixture = build_runtime_fixture()
    fixture.gate.controlled_context.accounts.pop()
    with pytest.raises(ContextMismatchError, match="context_mismatch"):
        fixture.gate.authorize(fixture.experiment)


def test_unowned_object_binding_is_rejected():
    fixture = build_runtime_fixture()
    fixture.gate.controlled_context.objects.clear()
    with pytest.raises(ContextMismatchError, match="context_mismatch"):
        fixture.gate.authorize(fixture.experiment)


def test_compiler_derived_request_reservation_is_enforced():
    fixture = build_runtime_fixture(request_limit=5)
    fixture.budget.consume("discovery")
    with pytest.raises(ResearchBudgetExhaustedError, match="budget_exhausted"):
        fixture.gate.authorize(fixture.experiment)


def test_compile_only_primitive_is_rejected_by_runtime_gate():
    fixture = build_runtime_fixture()
    step = fixture.experiment.primitive_steps[0].model_copy(
        update={"capability_state": PrimitiveCapabilityState.compile_only}
    )
    compiled = fixture.experiment.model_copy(update={"primitive_steps": (step,)})
    with pytest.raises(PrimitiveUnavailableError, match="primitive_unavailable"):
        fixture.gate.authorize(compiled)


def test_duplicate_authorization_is_blocked_after_runtime_completion():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    binding.submit(authorization)
    with pytest.raises(DuplicateExperimentError, match="duplicate_experiment"):
        fixture.gate.authorize(fixture.experiment)


def test_budget_ledger_itself_remains_authoritative():
    fixture = build_runtime_fixture(request_limit=5)
    for _ in range(5):
        fixture.budget.consume("verification")
    with pytest.raises(RequestBudgetExceeded):
        fixture.budget.consume("verification")
