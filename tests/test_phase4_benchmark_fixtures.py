from __future__ import annotations

import pytest

from agent_core.benchmark import (
    ChainMatcher,
    FindingMatchClassification,
    FindingMatcher,
    UnexpectedFindingStatus,
    safe_ratio,
    synthetic_benchmark_fixtures,
)
from agent_core.research import ReproductionClassification

FIXTURES = synthetic_benchmark_fixtures()
MATCHED = {
    FindingMatchClassification.exact_match,
    FindingMatchClassification.semantic_typed_match,
}
ACTIVE_FINDING_STATUSES = {
    "candidate",
    "reproducing",
    "reproduced",
    "confirmed",
    "needs_manual_review",
}


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda item: item.fixture_id)
def test_synthetic_fixtures_a_through_i_prove_declared_semantics(fixture):
    finding_matches = FindingMatcher().match_all(
        fixture.observed_findings, fixture.ground_truth.findings
    )
    active_ids = {
        item.finding_id
        for item in fixture.observed_findings
        if item.status in ACTIVE_FINDING_STATUSES
    }
    confirmed_ids = {
        item.finding_id
        for item in fixture.observed_findings
        if item.status == "confirmed"
    }
    true_candidate_ids = {
        item.finding_id
        for item in finding_matches
        if item.finding_id in active_ids and item.classification in MATCHED
    }
    true_confirmed_ids = true_candidate_ids & confirmed_ids
    adjudications = {item.finding_id: item for item in fixture.adjudications}
    false_candidates = sum(
        finding_id in active_ids
        and adjudications.get(finding_id) is not None
        and adjudications[finding_id].status
        is UnexpectedFindingStatus.rejected_false_positive
        for finding_id in adjudications
    )
    chain_matches = tuple(
        ChainMatcher().match(chain, fixture.ground_truth.chains, finding_matches)
        for chain in fixture.observed_chains
    )
    true_chains = sum(item.classification in MATCHED for item in chain_matches)
    reproduction_successes = sum(
        item.classification is ReproductionClassification.reproduced
        for item in fixture.reproduction_results
    )

    assert len(true_candidate_ids) == fixture.expected_true_positive_candidates
    assert len(true_confirmed_ids) == fixture.expected_true_positive_confirmed
    assert false_candidates == fixture.expected_false_positive_candidates
    assert true_chains == fixture.expected_true_positive_chains
    assert (
        safe_ratio(len(true_confirmed_ids), len(fixture.ground_truth.findings))
        == fixture.expected_confirmed_recall
    )
    assert len(fixture.reproduction_results) == fixture.expected_reproduction_attempts
    assert reproduction_successes == fixture.expected_reproduction_successes


def test_fixture_e_records_attempted_failed_reproduction_without_confirmation():
    fixture = next(item for item in FIXTURES if item.fixture_id.startswith("E-"))
    result = fixture.reproduction_results[0]
    finding = fixture.observed_findings[0]

    assert result.attempted
    assert result.classification is ReproductionClassification.not_reproduced
    assert finding.status == "candidate"
    assert fixture.expected_true_positive_candidates == 1
    assert fixture.expected_true_positive_confirmed == 0
    assert fixture.expected_reproduction_attempts == 1
    assert fixture.expected_reproduction_successes == 0
