from __future__ import annotations

from agent_core.benchmark import (
    BenchmarkObservedChain,
    BenchmarkObservedFinding,
    ChainMatcher,
    FindingMatchClassification,
    FindingMatcher,
    GroundTruthChain,
)
from tests.phase4_benchmark_helpers import truth


def observed(identifier="finding-1", endpoint="/private/{object_id}"):
    return BenchmarkObservedFinding(
        finding_id=identifier,
        status="confirmed",
        category="authorization",
        surface_class="rest",
        endpoint_reference=endpoint,
        parameter_reference="object_id",
        security_property="ownership-enforced",
        identity_relationship="different-owner",
        object_relationship="foreign-controlled-object",
    )


def test_typed_finding_match_does_not_require_generated_id_equality():
    match = FindingMatcher().match(observed(), truth().findings)
    assert match.classification is FindingMatchClassification.exact_match
    assert match.ground_truth_id == "truth-finding-1"


def test_nonmatching_endpoint_is_not_credited():
    match = FindingMatcher().match(observed(endpoint="/unrelated"), truth().findings)
    assert match.classification is FindingMatchClassification.no_match


def test_chain_match_requires_components_and_ordered_typed_relationships():
    second_truth = truth().findings[0].model_copy(
        update={
            "ground_truth_id": "truth-finding-2",
            "affected_endpoint_reference": "/second",
        }
    )
    findings = (
        FindingMatcher().match(observed(), truth().findings),
        FindingMatcher().match(
            observed("finding-2", "/second"), (second_truth,)
        ),
    )
    expected = GroundTruthChain(
        chain_ground_truth_id="truth-chain-1",
        component_ground_truth_ids=("truth-finding-1", "truth-finding-2"),
        ordered_relationship_classes=("exposes-reference",),
        combined_security_property="combined-isolation",
        expected_combined_impact="foreign-read",
    )
    chain = BenchmarkObservedChain(
        chain_id="chain-1",
        status="confirmed",
        component_finding_ids=("finding-1", "finding-2"),
        ordered_relationship_classes=("exposes-reference",),
        surface_classes=("rest", "graphql"),
        combined_security_property="combined-isolation",
        combined_impact="foreign-read",
    )
    match = ChainMatcher().match(chain, (expected,), findings)
    assert match.classification is FindingMatchClassification.exact_match
