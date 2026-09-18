from __future__ import annotations

import copy

import pytest

from agent_core.credential_vault import CredentialVault
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    InvalidRuntimeBindingError,
    ResearchRuntime,
    ResearchRuntimeBinding,
    is_research_runtime_binding,
)
from tests.test_phase4_research_runtime import build_runtime_fixture


def test_runtime_construction_has_no_public_alternate_path():
    with pytest.raises(TypeError, match="restricted"):
        ResearchRuntime(object(), object())  # type: ignore[arg-type]


def test_binding_construction_requires_private_issuer():
    fixture = build_runtime_fixture()
    authorization = fixture.gate.authorize(fixture.experiment)
    with pytest.raises(InvalidRuntimeBindingError, match="invalid_binding"):
        ResearchRuntimeBinding(authorization, fixture.gate.runtime, object())


def test_gate_issued_binding_is_sealed_and_nonserializable():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    assert is_research_runtime_binding(binding)
    assert binding.binding_reference == authorization.runtime_binding_reference
    with pytest.raises(TypeError, match="immutable"):
        binding.transport = object()  # type: ignore[misc]
    with pytest.raises(TypeError, match="copied"):
        copy.copy(binding)


@pytest.mark.parametrize(
    ("attribute", "replacement"),
    (
        ("_ResearchRuntime__budget", RequestBudget(10)),
        ("_ResearchRuntime__vault", CredentialVault()),
        ("_ResearchRuntime__controlled_context", object()),
        ("_ResearchRuntime__transport", object()),
        ("_ResearchRuntime__primitive_registry", object()),
        ("_ResearchRuntime__executor_registry", object()),
    ),
)
def test_dependency_swap_invalidates_binding(attribute: str, replacement: object):
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    object.__setattr__(fixture.gate.runtime, attribute, replacement)
    with pytest.raises(InvalidRuntimeBindingError, match="invalid_binding"):
        binding.submit(authorization)
    assert fixture.calls == []


def test_one_binding_cannot_submit_another_authorization():
    first = build_runtime_fixture()
    second = build_runtime_fixture()
    first_authorization, first_binding = first.gate.authorize_and_bind(first.experiment)
    second_authorization = second.gate.authorize(second.experiment)
    assert first_authorization.authorization_reference != (
        second_authorization.authorization_reference
    )
    with pytest.raises(InvalidRuntimeBindingError, match="invalid_binding"):
        first_binding.submit(second_authorization)
