from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_core.agent_models import RiskLevel
from agent_core.research import (
    DEFAULT_EXPERIMENT_REGISTRY,
    DuplicatePrimitiveError,
    DifferentialSelector,
    ExperimentRegistry,
    IdentityRelationship,
    IdentitySwitchInput,
    PrimitiveCapabilityState,
    PrimitiveDefinition,
    ResponseDifferentialInput,
    StateDifferentialInput,
    UnknownPrimitiveError,
)
from agent_core.research.primitives import (
    CleanupBehavior,
    DifferentialReference,
    SelectorSpec,
    StateChangeBehavior,
)
from agent_core.research.types import TargetClass
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    RESEARCH_EXPERIMENT_CAPABILITY_ADAPTERS,
    ResearchExperimentAdapterState,
    get_research_experiment_capability_adapter,
)


def test_initial_registry_inventory_and_capability_states_are_explicit():
    names = {item.name for item in DEFAULT_EXPERIMENT_REGISTRY.definitions}
    assert names == {
        "request_replay",
        "identity_switch",
        "parameter_mutation",
        "object_substitution",
        "header_mutation",
        "cookie_mutation",
        "response_differential",
        "state_differential",
        "graphql_operation",
        "graphql_variable_mutation",
        "token_mutation",
        "workflow_step_replay",
        "workflow_step_skip",
        "workflow_reorder",
        "upload_variant",
    }
    assert {
        item.name
        for item in DEFAULT_EXPERIMENT_REGISTRY.definitions
        if item.capability_state is PrimitiveCapabilityState.execution_available
    } == {
        "request_replay",
        "identity_switch",
        "parameter_mutation",
        "object_substitution",
        "response_differential",
        "state_differential",
    }
    assert all(
        DEFAULT_EXPERIMENT_REGISTRY.resolve(name).capability_state
        is PrimitiveCapabilityState.compile_only
        for name in {
            "graphql_operation",
            "graphql_variable_mutation",
            "token_mutation",
            "workflow_step_replay",
            "workflow_step_skip",
            "workflow_reorder",
            "upload_variant",
        }
    )


def test_no_arbitrary_request_primitive_or_input_schema_exists():
    assert "raw_http_request@1" not in DEFAULT_EXPERIMENT_REGISTRY
    replay = DEFAULT_EXPERIMENT_REGISTRY.resolve("request_replay")
    assert replay.input_schema_reference.endswith(":RequestReplayInput")


def test_zero_request_primitive_semantics_are_exact():
    for name in (
        "identity_switch",
        "response_differential",
        "state_differential",
    ):
        item = DEFAULT_EXPERIMENT_REGISTRY.resolve(name)
        assert (item.minimum_requests, item.worst_case_requests) == (0, 0)
        assert item.risk_class is RiskLevel.passive


def test_registry_order_and_hash_are_deterministic():
    first = ExperimentRegistry()
    second = ExperimentRegistry(reversed(first.definitions), include_defaults=False)
    assert tuple(first) == tuple(second)
    assert first.definitions == second.definitions
    assert first.fingerprint == second.fingerprint


def test_duplicate_name_and_version_fails_closed():
    registry = ExperimentRegistry()
    with pytest.raises(DuplicatePrimitiveError, match="duplicate"):
        registry.register(registry.resolve("request_replay"))


def test_unknown_primitive_fails_closed():
    with pytest.raises(UnknownPrimitiveError, match="unknown"):
        DEFAULT_EXPERIMENT_REGISTRY.resolve("arbitrary_request")


def test_execution_available_definition_requires_real_adapter_reference():
    payload = {
        "name": "fixture",
        "version": "1",
        "input_schema_reference": "fixture:Input",
        "output_type_reference": "fixture:Output",
        "capability_state": PrimitiveCapabilityState.execution_available,
        "minimum_requests": 0,
        "worst_case_requests": 0,
        "risk_class": RiskLevel.passive,
        "allowed_target_classes": (TargetClass.dedicated_lab,),
        "state_change_behavior": StateChangeBehavior.never,
        "cleanup_behavior": CleanupBehavior.not_required,
    }
    with pytest.raises(ValidationError, match="executor adapter"):
        PrimitiveDefinition.model_validate(payload)


def test_identity_switch_is_typed_and_cannot_invent_identity_values():
    value = IdentitySwitchInput(
        primary_identity_id="identity-1",
        comparison_identity_id="identity-2",
        relationship=IdentityRelationship.owner_non_owner,
    )
    assert value.primitive == "identity_switch"
    payload = value.model_dump(mode="python")
    payload["comparison_identity"] = "arbitrary-user"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        IdentitySwitchInput.model_validate(payload)


def test_response_differential_uses_references_and_typed_selectors_only():
    value = ResponseDifferentialInput(
        references=(
            DifferentialReference(kind="evidence", reference_id="evidence-1"),
            DifferentialReference(kind="experiment_outcome", reference_id="outcome-1"),
        ),
        selectors=(SelectorSpec(selector=DifferentialSelector.status_class),),
    )
    assert value.primitive == "response_differential"
    payload = value.model_dump(mode="python")
    payload["response_body"] = "raw body"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResponseDifferentialInput.model_validate(payload)


def test_state_differential_contains_only_registered_reference_slots():
    value = StateDifferentialInput(
        before_state_reference="state-before",
        after_state_reference="state-after",
        cleanup_state_reference="state-cleanup",
        invariant_references=("invariant-1",),
    )
    assert value.primitive == "state_differential"


def test_legacy_capability_adapters_are_metadata_only_and_do_not_change_phase2():
    assert len(CAPABILITY_REGISTRY) == 30
    required = {
        "bola",
        "authentication_enforcement",
        "session_invalidation",
        "tenant_isolation",
        "vertical_authorization",
        "mass_assignment",
        "rate_limit_enforcement",
        "recovery_state_enforcement",
    }
    assert required.issubset(RESEARCH_EXPERIMENT_CAPABILITY_ADAPTERS)
    for category in required:
        adapter = get_research_experiment_capability_adapter(category)
        original = CAPABILITY_REGISTRY[category]
        assert adapter.adapter_state is ResearchExperimentAdapterState.metadata_only
        assert adapter.min_requests == original.min_requests
        assert adapter.worst_case_requests == original.worst_case_requests
        assert adapter.state_changing == original.state_changing
        assert adapter.cleanup_required == original.cleanup_required
