"""P2-2 complete material evaluation configuration identity regressions."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import agent_core.model_evaluation as evaluation_package
from agent_core.autonomy import AutonomyLimits, AutonomyState
from agent_core.consensus import ConsensusBudget, ConsensusPolicy, SplitBehavior
from agent_core.model_evaluation import (
    CanonicalPhase2ExpectationStatus,
    ConfigurationCompatibility,
    ConfigurationFingerprintSchema,
    EvaluationCase,
    EvaluationExecutionMode,
    EvaluationRun,
    EvaluationRunner,
    EvaluationSubject,
    EvaluationSubjectType,
    ExpectedStructuralProperties,
    SyntheticScenario,
    compare_external_configuration,
    compare_runs,
    configuration_fingerprint,
    configuration_fingerprint_source,
    configuration_fingerprint_source_json,
    import_external_baseline,
    synthetic_case,
    synthetic_outcome,
    synthetic_route,
    synthetic_subject,
)
from agent_core.models import (
    ModelBudgetLimits,
    ModelPrice,
    ModelPricingCatalog,
    ModelRoute,
    ModelRoutingPolicy,
    ModelUsageDelta,
    RoutingMode,
)
from agent_core.reasoning import PriorVerificationOutcome, ReasoningAction

START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:00:01+00:00"


def fingerprint(subject=None, case=None, *, max_output_tokens=4096):
    return configuration_fingerprint(
        subject or synthetic_subject(),
        (case or synthetic_case(),),
        evaluation_max_output_tokens=max_output_tokens,
    )


def evaluation_run(
    subject=None,
    case=None,
    *,
    run_id="fingerprint-run",
    started_at=START,
    ended_at=END,
    observed=None,
    max_output_tokens=4096,
):
    subject = subject or synthetic_subject()
    case = case or synthetic_case()
    observed = observed or synthetic_outcome(
        subject, case, 0, SyntheticScenario.grounded_recommendation
    )
    return EvaluationRunner(max_output_tokens=max_output_tokens).run(
        evaluation_run_id=run_id,
        subject=subject,
        cases=(case,),
        evaluator=lambda *_: observed,
        started_at=started_at,
        ended_at=ended_at,
    )


def fallback_policy(order):
    routes = tuple(
        ModelRoute(provider=provider, model=model) for provider, model in order
    )
    return ModelRoutingPolicy(
        mode=RoutingMode.fallback_chain,
        preferred=routes[0],
        fallbacks=routes[1:],
        fallback_allowed=True,
        max_provider_attempts=len(routes),
        allowed_cloud_providers=tuple(
            sorted({route.provider for route in routes if route.provider != "ollama"})
        ),
        budget=ModelBudgetLimits(),
    )


def subject_with_policy(policy, *, subject_id="material-subject"):
    base = synthetic_subject(subject_id)
    return EvaluationSubject.model_validate(
        {
            **base.model_dump(mode="python"),
            "routing_policies": (policy,),
            "local_only": policy.mode is RoutingMode.local_only,
        }
    )


def consensus_subject(routes, *, policy=None, budget=None):
    base = synthetic_subject(
        "material-consensus",
        subject_type=EvaluationSubjectType.consensus_reasoning,
    )
    return EvaluationSubject.model_validate(
        {
            **base.model_dump(mode="python"),
            "routing_policies": tuple(routes),
            "consensus_policy": policy
            or ConsensusPolicy(
                minimum_participants=2,
                minimum_valid_participants=2,
            ),
            "consensus_budget": budget or ConsensusBudget(),
        }
    )


def case_with_expectation(**values):
    return synthetic_case().model_copy(
        update={"expected_structure": ExpectedStructuralProperties(**values)}
    )


def test_same_semantic_configuration_has_same_fingerprint():
    assert fingerprint() == fingerprint(
        synthetic_subject().model_copy(deep=True),
        synthetic_case().model_copy(deep=True),
    )


def test_timestamps_do_not_alter_fingerprint():
    first = evaluation_run(started_at=START, ended_at=END)
    second = evaluation_run(
        run_id="later-run",
        started_at="2026-08-01T10:00:00+00:00",
        ended_at="2026-08-01T10:00:02+00:00",
    )
    assert first.configuration_fingerprint == second.configuration_fingerprint


def test_random_evaluation_and_reasoning_run_ids_do_not_alter_identity():
    case = synthetic_case()
    renamed = case.model_copy(
        update={
            "reasoning_request": case.reasoning_request.model_copy(
                update={"run_id": "random-run-id-987"}
            )
        }
    )
    first = evaluation_run(case=case, run_id="evaluation-random-a")
    second = evaluation_run(case=renamed, run_id="evaluation-random-b")
    assert first.configuration_fingerprint == second.configuration_fingerprint


def test_budget_sharing_group_semantics_are_material_without_run_id_leakage():
    first = synthetic_case().model_copy(update={"case_id": "case-a"})
    second = synthetic_case(SyntheticScenario.invalid_capability).model_copy(
        update={"case_id": "case-b"}
    )
    shared = second.model_copy(
        update={
            "reasoning_request": second.reasoning_request.model_copy(
                update={"run_id": first.reasoning_request.run_id}
            )
        }
    )
    subject = synthetic_subject()
    shared_hash = configuration_fingerprint(subject, (first, shared))
    separate_hash = configuration_fingerprint(subject, (first, second))
    source = configuration_fingerprint_source_json(subject, (first, shared))
    assert shared_hash != separate_hash
    assert first.reasoning_request.run_id not in source


def test_implicit_and_explicit_defaults_are_semantically_equal():
    case = synthetic_case()
    payload = case.model_dump(mode="python")
    payload.pop("model_budget")
    implicit = EvaluationCase.model_validate(payload)
    explicit = case.model_copy(update={"model_budget": ModelBudgetLimits()})
    assert fingerprint(case=implicit) == fingerprint(case=explicit)


@pytest.mark.parametrize(
    ("provider", "model"),
    (("anthropic", "claude-sonnet"), ("ollama", "deepseek-r1:32b")),
)
def test_gpt_route_differs_from_other_model_routes(provider, model):
    gpt = synthetic_subject("same-subject", provider="openai", model="gpt-model")
    other = synthetic_subject("same-subject", provider=provider, model=model)
    assert fingerprint(gpt) != fingerprint(other)


def test_subject_identifier_is_material():
    assert fingerprint(synthetic_subject("subject-a")) != fingerprint(
        synthetic_subject("subject-b")
    )


def test_fallback_enabled_differs_from_disabled():
    plain = synthetic_subject("same-subject")
    fallback = synthetic_subject(
        "same-subject",
        fallback_provider="anthropic",
        fallback_model="claude-fallback",
    )
    assert fingerprint(plain) != fingerprint(fallback)


def test_fallback_order_is_material_and_preserved():
    left = subject_with_policy(
        fallback_policy(
            (
                ("openai", "gpt"),
                ("anthropic", "claude"),
                ("ollama", "deepseek"),
            )
        )
    )
    right = subject_with_policy(
        fallback_policy(
            (
                ("openai", "gpt"),
                ("ollama", "deepseek"),
                ("anthropic", "claude"),
            )
        )
    )
    source = configuration_fingerprint_source(left, (synthetic_case(),))
    fallbacks = source.subject["routing_policies"][0]["fallbacks"]
    assert [item["provider"] for item in fallbacks] == ["anthropic", "ollama"]
    assert fingerprint(left) != fingerprint(right)


def test_local_only_differs_from_cloud_configuration():
    local = synthetic_subject("same-subject", provider="ollama", model="deepseek")
    cloud = synthetic_subject("same-subject", provider="openai", model="gpt")
    assert fingerprint(local) != fingerprint(cloud)


def test_cloud_allowlist_difference_is_material_but_order_is_not():
    base = synthetic_route("openai", "gpt")
    one = subject_with_policy(base)
    expanded = subject_with_policy(
        ModelRoutingPolicy.model_validate(
            {
                **base.model_dump(mode="python"),
                "allowed_cloud_providers": ("openai", "anthropic"),
            }
        )
    )
    reordered = subject_with_policy(
        ModelRoutingPolicy.model_validate(
            {
                **base.model_dump(mode="python"),
                "allowed_cloud_providers": ("anthropic", "openai"),
            }
        )
    )
    assert fingerprint(one) != fingerprint(expanded)
    assert fingerprint(expanded) == fingerprint(reordered)


@pytest.mark.parametrize(
    ("field", "left", "right"),
    (
        ("max_model_calls", 2, 3),
        ("max_input_tokens", 100, 200),
        ("max_output_tokens", 100, 200),
        ("max_total_tokens", 1000, 2000),
        ("max_estimated_cost_usd", 1.0, 2.0),
    ),
)
def test_case_model_budget_differences_are_material(field, left, right):
    left_case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(**{field: left})}
    )
    right_case = synthetic_case().model_copy(
        update={"model_budget": ModelBudgetLimits(**{field: right})}
    )
    assert fingerprint(case=left_case) != fingerprint(case=right_case)


def test_runner_output_token_reservation_is_material():
    assert fingerprint(max_output_tokens=256) != fingerprint(max_output_tokens=512)


def test_pricing_configuration_is_material_to_cost_budget_semantics():
    subject = synthetic_subject()
    cases = (synthetic_case(),)
    low = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="gpt-synthetic",
                input_per_million_usd=1.0,
                output_per_million_usd=1.0,
            ),
        )
    )
    high = ModelPricingCatalog(
        (
            ModelPrice(
                provider="openai",
                model="gpt-synthetic",
                input_per_million_usd=2.0,
                output_per_million_usd=2.0,
            ),
        )
    )
    assert configuration_fingerprint(
        subject, cases, pricing=low
    ) != configuration_fingerprint(subject, cases, pricing=high)


def test_consensus_participant_set_is_material():
    openai = synthetic_route("openai", "gpt")
    anthropic = synthetic_route("anthropic", "claude")
    local = synthetic_route("ollama", "deepseek")
    assert fingerprint(consensus_subject((openai, anthropic))) != fingerprint(
        consensus_subject((openai, local))
    )


@pytest.mark.parametrize(
    ("left_update", "right_update"),
    (
        (
            {"require_majority": True, "require_unanimity": False},
            {"require_majority": True, "require_unanimity": True},
        ),
        ({"minimum_aggregate_confidence": 0.5}, {"minimum_aggregate_confidence": 0.8}),
        (
            {"split_behavior": SplitBehavior.manual_review},
            {"split_behavior": SplitBehavior.defer},
        ),
    ),
)
def test_consensus_policy_differences_are_material(left_update, right_update):
    routes = (synthetic_route("openai", "gpt"), synthetic_route("anthropic", "claude"))
    base = ConsensusPolicy(minimum_participants=2, minimum_valid_participants=2)
    left = consensus_subject(routes, policy=base.model_copy(update=left_update))
    right = consensus_subject(routes, policy=base.model_copy(update=right_update))
    assert fingerprint(left) != fingerprint(right)


def test_consensus_budget_is_material():
    routes = (synthetic_route("openai", "gpt"), synthetic_route("anthropic", "claude"))
    left = consensus_subject(routes, budget=ConsensusBudget(max_model_calls=2))
    right = consensus_subject(routes, budget=ConsensusBudget(max_model_calls=3))
    assert fingerprint(left) != fingerprint(right)


def test_consensus_participant_order_is_canonicalized():
    routes = (synthetic_route("openai", "gpt"), synthetic_route("anthropic", "claude"))
    assert fingerprint(consensus_subject(routes)) == fingerprint(
        consensus_subject(tuple(reversed(routes)))
    )


def test_dry_run_differs_from_controlled_autonomy():
    dry_subject = synthetic_subject(
        "same-subject", subject_type=EvaluationSubjectType.dry_run_autonomy
    )
    controlled_subject = synthetic_subject(
        "same-subject", subject_type=EvaluationSubjectType.controlled_autonomy
    )
    dry_case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    controlled_case = synthetic_case(execution_mode=EvaluationExecutionMode.controlled)
    assert fingerprint(dry_subject, dry_case) != fingerprint(
        controlled_subject, controlled_case
    )


@pytest.mark.parametrize(
    ("field", "left", "right"),
    (("max_iterations", 2, 5), ("max_verifications", 1, 3)),
)
def test_autonomy_limit_differences_are_material(field, left, right):
    base = synthetic_subject(
        "autonomy-subject", subject_type=EvaluationSubjectType.dry_run_autonomy
    )
    left_subject = base.model_copy(
        update={"autonomy_limits": AutonomyLimits(**{field: left})}
    )
    right_subject = base.model_copy(
        update={"autonomy_limits": AutonomyLimits(**{field: right})}
    )
    case = synthetic_case(execution_mode=EvaluationExecutionMode.dry_run)
    assert fingerprint(left_subject, case) != fingerprint(right_subject, case)


@pytest.mark.parametrize(
    ("left", "right"),
    (
        (
            {"decision_action": ReasoningAction.recommend_verification},
            {"decision_action": ReasoningAction.stop},
        ),
        ({"recommended_capability": "bola"}, {"recommended_capability": "ssrf"}),
        (
            {"phase2_status": CanonicalPhase2ExpectationStatus.verified},
            {"phase2_status": CanonicalPhase2ExpectationStatus.rejected},
        ),
        (
            {"autonomy_terminal_state": AutonomyState.stopped},
            {"autonomy_terminal_state": AutonomyState.failed},
        ),
        ({"maximum_target_requests": 0}, {"maximum_target_requests": 1}),
        ({"execution_occurred": False}, {"execution_occurred": True}),
    ),
)
def test_structural_expectation_differences_are_material(left, right):
    assert fingerprint(case=case_with_expectation(**left)) != fingerprint(
        case=case_with_expectation(**right)
    )


def test_capability_schema_identity_is_material():
    case = synthetic_case()
    catalog = case.reasoning_request.capability_catalog
    entries = list(catalog.entries)
    index = next(
        i for i, item in enumerate(entries) if item.executor_version is not None
    )
    entries[index] = entries[index].model_copy(
        update={"executor_version": "authentication_enforcement/v99"}
    )
    changed = case.model_copy(
        update={
            "reasoning_request": case.reasoning_request.model_copy(
                update={
                    "capability_catalog": catalog.model_copy(
                        update={"entries": tuple(entries)}
                    )
                }
            )
        }
    )
    assert fingerprint(case=case) != fingerprint(case=changed)


def test_reasoning_policy_semantics_are_material():
    case = synthetic_case()
    policy = case.reasoning_request.policy_constraints
    changed_policy = case.model_copy(
        update={
            "reasoning_request": case.reasoning_request.model_copy(
                update={
                    "policy_constraints": policy.model_copy(
                        update={"remaining_target_request_budget": 1}
                    )
                }
            )
        }
    )
    assert fingerprint(case=case) != fingerprint(case=changed_policy)


def test_prior_result_semantics_are_material():
    case = synthetic_case()
    packet = case.reasoning_request.evidence_packets[0]

    def with_status(status):
        changed_packet = packet.model_copy(
            update={
                "prior_verification": PriorVerificationOutcome(
                    status=status,
                    reasons=("Canonical public prior result.",),
                )
            }
        )
        request = case.reasoning_request.model_copy(
            update={"evidence_packets": (changed_packet,)}
        )
        return case.model_copy(update={"reasoning_request": request})

    assert fingerprint(case=with_status("verified")) != fingerprint(
        case=with_status("rejected")
    )


@pytest.mark.parametrize(
    ("environment_name", "sentinel"),
    (
        ("OPENAI_API_KEY", "CCX_FP_API_KEY_11aa"),
        ("FP_AUTHORIZATION", "CCX_FP_AUTH_22bb"),
        ("FP_COOKIE", "CCX_FP_COOKIE_33cc"),
        ("FP_SESSION_TOKEN", "CCX_FP_SESSION_44dd"),
        ("FP_PASSWORD", "CCX_FP_PASSWORD_55ee"),
        ("FP_RECOVERY_SECRET", "CCX_FP_RECOVERY_66ff"),
        ("FP_PRIVATE_RECOVERY_STATE", "CCX_FP_PRIVATE_77aa"),
        ("FP_RAW_PROMPT", "CCX_FP_PROMPT_88bb"),
        ("FP_RAW_PROVIDER_RESPONSE", "CCX_FP_RESPONSE_99cc"),
        ("FP_CHAIN_OF_THOUGHT", "CCX_FP_THOUGHT_00dd"),
    ),
)
def test_secret_and_private_process_values_are_excluded(
    monkeypatch, environment_name, sentinel
):
    before = fingerprint()
    monkeypatch.setenv(environment_name, sentinel)
    source = configuration_fingerprint_source_json(
        synthetic_subject(), (synthetic_case(),)
    )
    assert sentinel not in source
    assert fingerprint() == before


def test_temporary_filesystem_paths_are_normalized_out_of_public_content():
    case = synthetic_case()
    packet = case.reasoning_request.evidence_packets[0]

    def with_path(path):
        changed_packet = packet.model_copy(update={"limitations": (path,)})
        request = case.reasoning_request.model_copy(
            update={"evidence_packets": (changed_packet,)}
        )
        return case.model_copy(update={"reasoning_request": request})

    left = with_path("/tmp/evaluation-a/private.json")
    right = with_path("/private/tmp/evaluation-b/private.json")
    source = configuration_fingerprint_source_json(synthetic_subject(), (left,))
    assert "/tmp/" not in source
    assert "/private/tmp/" not in source
    assert fingerprint(case=left) == fingerprint(case=right)


@pytest.mark.parametrize("changed_field", ("tokens", "cost", "latency"))
def test_execution_usage_cost_and_latency_do_not_affect_identity(changed_field):
    subject = synthetic_subject()
    case = synthetic_case()
    base = synthetic_outcome(
        subject, case, 0, SyntheticScenario.grounded_recommendation
    )
    if changed_field == "tokens":
        usage = ModelUsageDelta(
            attempted_calls=1,
            successful_calls=1,
            input_tokens=40,
            output_tokens=20,
            total_tokens=60,
            estimated_cost_usd=0.002,
            latency_seconds=0.1,
        )
        changed = base.model_copy(update={"model_usage": usage})
    elif changed_field == "cost":
        changed = base.model_copy(
            update={
                "model_usage": base.model_usage.model_copy(
                    update={"estimated_cost_usd": 9.0}
                )
            }
        )
    else:
        changed = base.model_copy(
            update={
                "elapsed_seconds": 99.0,
                "model_usage": base.model_usage.model_copy(
                    update={"latency_seconds": 88.0}
                ),
            }
        )
    left = evaluation_run(subject, case, run_id="usage-left", observed=base)
    right = evaluation_run(subject, case, run_id="usage-right", observed=changed)
    assert left.configuration_fingerprint == right.configuration_fingerprint


def test_comparison_detects_material_mismatch_and_still_reports_metrics():
    left = evaluation_run(case=case_with_expectation(maximum_target_requests=0))
    right = evaluation_run(
        case=case_with_expectation(maximum_target_requests=1),
        run_id="comparison-right",
    )
    comparison = compare_runs(left, right)
    assert (
        comparison.configuration_compatibility
        is ConfigurationCompatibility.incompatible
    )
    assert comparison.configuration_compatible is False
    assert comparison.mismatch_reasons == ("material_configuration_mismatch",)
    assert comparison.metrics


def test_compatible_material_configurations_compare_cleanly():
    left = evaluation_run(run_id="compatible-left")
    right = evaluation_run(
        run_id="compatible-right",
        started_at="2026-09-01T00:00:00+00:00",
        ended_at="2026-09-01T00:00:03+00:00",
    )
    comparison = compare_runs(left, right)
    assert (
        comparison.configuration_compatibility is ConfigurationCompatibility.compatible
    )
    assert comparison.configuration_compatible is True
    assert comparison.mismatch_reasons == ()


def test_external_baseline_missing_fingerprint_is_unknown():
    run = evaluation_run()
    external = import_external_baseline(
        {
            "baseline_name": "external",
            "run_id": "external-run",
            "aggregate_metrics": {"valid_rate": 1.0},
            "recorded_at": START,
            "configuration_reference": "supplied-reference",
        }
    )
    result = compare_external_configuration(run, external)
    assert result.compatibility is ConfigurationCompatibility.unknown
    assert result.reason.value == "configuration_identity_missing"


def test_external_supplied_material_fingerprint_is_preserved_and_verified():
    run = evaluation_run()
    external = import_external_baseline(
        {
            "baseline_name": "external",
            "run_id": "external-run",
            "aggregate_metrics": {"valid_rate": 1.0},
            "recorded_at": START,
            "configuration_reference": "supplied-reference",
            "configuration_fingerprint": run.configuration_fingerprint,
            "configuration_fingerprint_schema": "material-v2",
        }
    )
    assert external.configuration_fingerprint == run.configuration_fingerprint
    result = compare_external_configuration(run, external)
    assert result.compatibility is ConfigurationCompatibility.compatible
    assert result.reason.value == "fingerprint_match"


def test_legacy_fingerprint_record_remains_readable_but_unverified():
    current = evaluation_run()
    payload = current.model_dump(mode="python")
    payload.pop("configuration_fingerprint_schema")
    legacy = EvaluationRun.model_validate(payload)
    assert (
        legacy.configuration_fingerprint_schema
        is ConfigurationFingerprintSchema.legacy_v1_incomplete
    )
    comparison = compare_runs(current, legacy)
    assert comparison.configuration_compatibility is ConfigurationCompatibility.unknown
    assert comparison.configuration_compatible is None


def test_new_fingerprint_schema_is_distinguishable_from_legacy():
    run = evaluation_run()
    assert (
        run.configuration_fingerprint_schema
        is ConfigurationFingerprintSchema.material_v2
    )
    assert (
        run.configuration_fingerprint_schema
        is not ConfigurationFingerprintSchema.legacy_v1_incomplete
    )
    assert (
        configuration_fingerprint_source(
            run.subject, run.cases
        ).fingerprint_schema_version
        == 2
    )


def test_stable_lowercase_sha256_format():
    value = fingerprint()
    assert re.fullmatch(r"[0-9a-f]{64}", value)
    assert len(bytes.fromhex(value)) == 32


def test_canonical_json_has_no_python_repr_or_memory_address_instability():
    source = configuration_fingerprint_source_json(
        synthetic_subject(), (synthetic_case(),)
    )
    assert json.loads(source)
    assert "object at 0x" not in source
    assert "<" not in source
    assert source == configuration_fingerprint_source_json(
        synthetic_subject(), (synthetic_case(),)
    )


def test_fingerprint_module_has_no_range_dependency_or_identifiers():
    source = (
        Path(evaluation_package.__file__)
        .parent.joinpath("fingerprint.py")
        .read_text(encoding="utf-8")
    )
    banned = "cybercortex" + "_range"
    assert banned not in source.casefold()
    assert "range_id" not in source.casefold()
