from __future__ import annotations

from agent_core.benchmark import (
    AllowedStateChangeClass,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkModelRouting,
    BenchmarkResearchInput,
    BenchmarkScoringPolicy,
    GroundTruthFinding,
    ResetStrategy,
    build_research_input,
)
from agent_core.research import ResearchRunStatus, ResearchState, TargetClass

NOW = "2026-09-26T12:00:00+00:00"
DIGEST = "sha256:" + "a" * 64


def manifest(**changes):
    values = dict(
        benchmark_id="benchmark-1",
        benchmark_version="v1",
        title="Synthetic blind benchmark",
        description="A deterministic local benchmark.",
        target_class=TargetClass.dedicated_lab,
        authorized_target_reference="https://benchmark.invalid",
        scope_reference="scope-1",
        controlled_account_metadata_references=(),
        policy_reference="policy-1",
        request_budget=10,
        model_budget=2,
        experiment_budget=4,
        reproduction_budget=2,
        chain_budget=2,
        wall_time_budget=60.0,
        allowed_state_change_class=AllowedStateChangeClass.read_only,
        reset_strategy=ResetStrategy.stateless_target,
        ground_truth_reference="truth-1",
        scoring_policy_reference="scoring-1",
        benchmark_tags=("authorization",),
        created_at=NOW,
    )
    values.update(changes)
    return BenchmarkManifest(**values)


def research_input(**changes) -> BenchmarkResearchInput:
    item = manifest()
    values = dict(
        manifest=item,
        benchmark_run_id="run-1",
        authorized_target=item.authorized_target_reference,
        model_routing_policy=BenchmarkModelRouting(
            policy_reference="model-policy-1",
            provider="fixture-provider",
            requested_model="fixture-model",
            configuration_fingerprint=DIGEST,
        ),
        persistence_location=":memory:",
    )
    values.update(changes)
    return build_research_input(**values)


def truth() -> BenchmarkGroundTruth:
    return BenchmarkGroundTruth(
        benchmark_id="benchmark-1",
        benchmark_version="v1",
        findings=(
            GroundTruthFinding(
                ground_truth_id="truth-finding-1",
                category="authorization",
                affected_surface_class="rest",
                affected_endpoint_reference="/private/{object_id}",
                affected_parameter_reference="object_id",
                security_property="ownership-enforced",
                required_controlled_identity_relationship="different-owner",
                required_controlled_object_relationship="foreign-controlled-object",
                expected_vulnerable_behavior_class="foreign-read-succeeds",
                expected_secure_behavior_class="foreign-read-denied",
                severity_reference="high",
                confirmation_requirements=("independent-reproduction",),
            ),
        ),
        hidden_sentinels=("hidden-sentinel-4f9c",),
    )


def empty_state(research_id: str = "research-1") -> ResearchState:
    return ResearchState(
        research_id=research_id,
        revision=0,
        status=ResearchRunStatus.initializing,
        created_at=NOW,
        updated_at=NOW,
    )


def scoring_policy() -> BenchmarkScoringPolicy:
    return BenchmarkScoringPolicy(policy_id="scoring-1")
