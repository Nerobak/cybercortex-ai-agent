"""Deterministic, network-free benchmark fixtures for framework evaluation."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from agent_core.benchmark.types import (
    BenchmarkContract,
    BenchmarkGroundTruth,
    BenchmarkObservedChain,
    BenchmarkObservedFinding,
    GroundTruthChain,
    GroundTruthFinding,
    UnexpectedFindingRecord,
    UnexpectedFindingStatus,
)
from agent_core.research.types import FindingStatus, ReproductionClassification


class SyntheticReproductionResult(BenchmarkContract):
    """Post-research reproduction semantics for a synthetic observed finding."""

    finding_id: str
    attempted: Literal[True] = True
    classification: ReproductionClassification
    finding_status: FindingStatus

    @model_validator(mode="after")
    def validate_confirmation_state(self) -> "SyntheticReproductionResult":
        if self.classification is ReproductionClassification.reproduced:
            if self.finding_status is not FindingStatus.confirmed:
                raise ValueError("successful reproduction must confirm the finding")
        elif self.finding_status is FindingStatus.confirmed:
            raise ValueError("failed reproduction cannot confirm the finding")
        return self


class SyntheticBenchmarkFixture(BenchmarkContract):
    fixture_id: str
    ground_truth: BenchmarkGroundTruth
    observed_findings: tuple[BenchmarkObservedFinding, ...] = ()
    observed_chains: tuple[BenchmarkObservedChain, ...] = ()
    reproduction_results: tuple[SyntheticReproductionResult, ...] = ()
    adjudications: tuple[UnexpectedFindingRecord, ...] = ()
    expected_true_positive_candidates: int = Field(ge=0)
    expected_confirmed_recall: float = Field(ge=0.0, le=1.0)
    expected_true_positive_confirmed: int = Field(ge=0)
    expected_false_positive_candidates: int = Field(ge=0)
    expected_true_positive_chains: int = Field(ge=0)
    expected_reproduction_attempts: int = Field(ge=0)
    expected_reproduction_successes: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_expected_reproduction_metrics(self) -> "SyntheticBenchmarkFixture":
        finding_statuses = {
            item.finding_id: item.status for item in self.observed_findings
        }
        if any(
            finding_statuses.get(item.finding_id) != item.finding_status.value
            for item in self.reproduction_results
        ):
            raise ValueError(
                "synthetic reproduction result is not bound to its finding"
            )
        successes = sum(
            item.classification is ReproductionClassification.reproduced
            for item in self.reproduction_results
        )
        if self.expected_reproduction_attempts != len(self.reproduction_results):
            raise ValueError(
                "expected reproduction attempts do not match fixture results"
            )
        if self.expected_reproduction_successes != successes:
            raise ValueError(
                "expected reproduction successes do not match fixture results"
            )
        return self


def _finding(identifier: str, endpoint: str) -> GroundTruthFinding:
    return GroundTruthFinding(
        ground_truth_id=identifier,
        category="authorization",
        affected_surface_class="rest",
        affected_endpoint_reference=endpoint,
        affected_parameter_reference="object_id",
        security_property="object-ownership-enforced",
        required_controlled_identity_relationship="different-controlled-owner",
        required_controlled_object_relationship="other-controlled-owner-object",
        expected_vulnerable_behavior_class="cross-owner-read-succeeds",
        expected_secure_behavior_class="cross-owner-read-denied",
        severity_reference="severity-high",
        confirmation_requirements=("independent-reproduction",),
    )


def _observed(
    identifier: str,
    endpoint: str,
    *,
    status: str = "confirmed",
) -> BenchmarkObservedFinding:
    return BenchmarkObservedFinding(
        finding_id=identifier,
        status=status,
        category="authorization",
        surface_class="rest",
        endpoint_reference=endpoint,
        parameter_reference="object_id",
        security_property="object-ownership-enforced",
        identity_relationship="different-controlled-owner",
        object_relationship="other-controlled-owner-object",
        primitive="object-substitution",
        evidence_class="differential",
    )


def synthetic_benchmark_fixtures() -> tuple[SyntheticBenchmarkFixture, ...]:
    one = _finding("truth-authz-1", "/objects/{object_id}")
    two = _finding("truth-authz-2", "/projects/{object_id}")
    empty = BenchmarkGroundTruth(benchmark_id="synthetic-clean", benchmark_version="v1")
    one_truth = BenchmarkGroundTruth(
        benchmark_id="synthetic-authz", benchmark_version="v1", findings=(one,)
    )
    two_truth = BenchmarkGroundTruth(
        benchmark_id="synthetic-two", benchmark_version="v1", findings=(one, two)
    )
    chain_truth = BenchmarkGroundTruth(
        benchmark_id="synthetic-chain",
        benchmark_version="v1",
        findings=(one, two),
        chains=(
            GroundTruthChain(
                chain_ground_truth_id="truth-chain-1",
                component_ground_truth_ids=(one.ground_truth_id, two.ground_truth_id),
                ordered_relationship_classes=("exposes-reference",),
                combined_security_property="cross-surface-object-isolation",
                expected_combined_impact="cross-owner-project-read",
                confirmation_requirements=("ordered-independent-reproduction",),
            ),
        ),
    )
    found_one = _observed("finding-1", one.affected_endpoint_reference)
    found_two = _observed("finding-2", two.affected_endpoint_reference)
    extra = BenchmarkObservedFinding(
        finding_id="finding-extra",
        status="candidate",
        category="injection",
        surface_class="rest",
        endpoint_reference="/clean",
        parameter_reference="q",
        security_property="query-data-boundary",
    )
    chain = BenchmarkObservedChain(
        chain_id="chain-1",
        status="confirmed",
        component_finding_ids=(found_one.finding_id, found_two.finding_id),
        ordered_relationship_classes=("exposes-reference",),
        surface_classes=("rest", "graphql"),
        combined_security_property="cross-surface-object-isolation",
        combined_impact="cross-owner-project-read",
    )
    reproduced_one = SyntheticReproductionResult(
        finding_id=found_one.finding_id,
        classification=ReproductionClassification.reproduced,
        finding_status=FindingStatus.confirmed,
    )
    reproduced_two = SyntheticReproductionResult(
        finding_id=found_two.finding_id,
        classification=ReproductionClassification.reproduced,
        finding_status=FindingStatus.confirmed,
    )
    return (
        SyntheticBenchmarkFixture(
            fixture_id="A-clean-target",
            ground_truth=empty,
            expected_true_positive_candidates=0,
            expected_confirmed_recall=0.0,
            expected_true_positive_confirmed=0,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=0,
            expected_reproduction_successes=0,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="B-one-authorization-vulnerability",
            ground_truth=one_truth,
            observed_findings=(found_one,),
            reproduction_results=(reproduced_one,),
            expected_true_positive_candidates=1,
            expected_confirmed_recall=1.0,
            expected_true_positive_confirmed=1,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=1,
            expected_reproduction_successes=1,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="C-two-findings-discovers-one",
            ground_truth=two_truth,
            observed_findings=(found_one,),
            reproduction_results=(reproduced_one,),
            expected_true_positive_candidates=1,
            expected_confirmed_recall=0.5,
            expected_true_positive_confirmed=1,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=1,
            expected_reproduction_successes=1,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="D-extra-false-candidate",
            ground_truth=one_truth,
            observed_findings=(found_one, extra),
            reproduction_results=(reproduced_one,),
            adjudications=(
                UnexpectedFindingRecord(
                    finding_id=extra.finding_id,
                    status=UnexpectedFindingStatus.rejected_false_positive,
                    adjudication_reference="synthetic-adjudication",
                ),
            ),
            expected_true_positive_candidates=1,
            expected_confirmed_recall=1.0,
            expected_true_positive_confirmed=1,
            expected_false_positive_candidates=1,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=1,
            expected_reproduction_successes=1,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="E-candidate-failed-reproduction",
            ground_truth=one_truth,
            observed_findings=(found_one.model_copy(update={"status": "candidate"}),),
            reproduction_results=(
                SyntheticReproductionResult(
                    finding_id=found_one.finding_id,
                    classification=ReproductionClassification.not_reproduced,
                    finding_status=FindingStatus.candidate,
                ),
            ),
            expected_true_positive_candidates=1,
            expected_confirmed_recall=0.0,
            expected_true_positive_confirmed=0,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=1,
            expected_reproduction_successes=0,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="F-confirmed-finding",
            ground_truth=one_truth,
            observed_findings=(found_one,),
            reproduction_results=(reproduced_one,),
            expected_true_positive_candidates=1,
            expected_confirmed_recall=1.0,
            expected_true_positive_confirmed=1,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=1,
            expected_reproduction_successes=1,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="G-valid-attack-chain",
            ground_truth=chain_truth,
            observed_findings=(found_one, found_two),
            observed_chains=(chain,),
            reproduction_results=(reproduced_one, reproduced_two),
            expected_true_positive_candidates=2,
            expected_confirmed_recall=1.0,
            expected_true_positive_confirmed=2,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=1,
            expected_reproduction_attempts=2,
            expected_reproduction_successes=2,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="H-two-unrelated-findings",
            ground_truth=chain_truth,
            observed_findings=(found_one, found_two),
            reproduction_results=(reproduced_one, reproduced_two),
            expected_true_positive_candidates=2,
            expected_confirmed_recall=1.0,
            expected_true_positive_confirmed=2,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=2,
            expected_reproduction_successes=2,
        ),
        SyntheticBenchmarkFixture(
            fixture_id="I-unexpected-valid-finding",
            ground_truth=empty,
            observed_findings=(extra,),
            adjudications=(
                UnexpectedFindingRecord(
                    finding_id=extra.finding_id,
                    status=UnexpectedFindingStatus.accepted_valid,
                    adjudication_reference="synthetic-adjudication",
                ),
            ),
            expected_true_positive_candidates=0,
            expected_confirmed_recall=0.0,
            expected_true_positive_confirmed=0,
            expected_false_positive_candidates=0,
            expected_true_positive_chains=0,
            expected_reproduction_attempts=0,
            expected_reproduction_successes=0,
        ),
    )


__all__ = [
    "SyntheticBenchmarkFixture",
    "SyntheticReproductionResult",
    "synthetic_benchmark_fixtures",
]
