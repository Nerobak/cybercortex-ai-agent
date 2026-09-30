from __future__ import annotations

import json

import pytest

from agent_core.research import (
    ExperimentEvaluator,
    ExperimentResultClassification,
    FindingStatus,
    GraphQLCandidateKind,
    GraphQLDifferentialEvaluator,
    ResearchBudgetManager,
    ResearchStore,
)
from test_phase4_graphql_runtime import FakeResponse, _runtime_fixture


def _execute(kind: GraphQLCandidateKind, responses=None):
    fixture = _runtime_fixture(candidate_kind=kind, responses=responses)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    return fixture, authorization, outcome


@pytest.mark.parametrize(
    ("responses", "expected"),
    (
        (
            (FakeResponse(), FakeResponse()),
            ExperimentResultClassification.vulnerable_signal,
        ),
        (None, ExperimentResultClassification.secure_signal),
        (
            (
                FakeResponse(
                    403,
                    b'{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}',
                ),
                FakeResponse(
                    403,
                    b'{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}',
                ),
            ),
            ExperimentResultClassification.inconclusive,
        ),
    ),
)
def test_authentication_differential_requires_a_valid_baseline(responses, expected):
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.authentication, responses
    )

    result = GraphQLDifferentialEvaluator().evaluate(
        fixture.experiment, outcome, state=fixture.gate.state
    )

    assert result.security_property.value == "authentication_enforcement"
    assert result.classification is expected


def test_http_200_authorization_error_is_secure_not_vulnerable():
    denied = FakeResponse(
        200,
        b'{"data":{"resource":null},"errors":[{"path":["resource"],'
        b'"extensions":{"code":"FORBIDDEN"}}]}',
    )
    fixture, _authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), denied),
    )

    result = GraphQLDifferentialEvaluator().evaluate(
        fixture.experiment, outcome, state=fixture.gate.state
    )
    comparison = outcome.evidence[1].graphql_responses[0]

    assert comparison.status_code == 200
    assert comparison.data_present and comparison.errors_present
    assert comparison.selected_field_nulls == ("field-query-resource",)
    assert comparison.error_paths[0].path == ("resource",)
    assert result.classification is ExperimentResultClassification.secure_signal


def test_graphql_vulnerable_signal_reuses_candidate_lifecycle_only():
    fixture, authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (FakeResponse(), FakeResponse()),
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment,
        authorization,
        outcome,
        fixture.gate.state,
    )

    assert evaluation.classification is (
        ExperimentResultClassification.vulnerable_signal
    )
    assert evaluation.graphql_evaluation is not None
    assert evaluation.candidate_finding is not None
    assert evaluation.candidate_finding.status is FindingStatus.candidate
    assert evaluation.candidate_finding.status is not FindingStatus.confirmed
    assert evaluation.candidate_finding.graphql_operation_id == (
        fixture.experiment.target.operation_id
    )
    assert evaluation.candidate_finding.security_property_reference == (
        "graphql-security-property:authentication_enforcement"
    )


def test_graphql_evaluation_and_finding_are_reference_only():
    synthetic_secret = "synthetic-person@example.test"
    fixture, authorization, outcome = _execute(
        GraphQLCandidateKind.authentication,
        (
            FakeResponse(
                body=json.dumps(
                    {"data": {"resource": {"status": synthetic_secret}}}
                ).encode()
            ),
            FakeResponse(
                body=json.dumps(
                    {"data": {"resource": {"status": synthetic_secret}}}
                ).encode()
            ),
        ),
    )

    evaluation = ExperimentEvaluator().evaluate(
        fixture.experiment, authorization, outcome, fixture.gate.state
    )
    serialized = json.dumps(evaluation.model_dump(mode="json"), sort_keys=True)

    assert evaluation.candidate_finding is not None
    assert synthetic_secret not in serialized
    assert "query" not in evaluation.candidate_finding.model_dump(mode="json")


def test_graphql_evaluation_persists_once_and_survives_restart(tmp_path):
    database = tmp_path / "graphql-evaluation.sqlite3"
    stores = []

    def create_store(state):
        store = ResearchStore(database)
        store.create_research(state)
        stores.append(store)
        return store

    fixture = _runtime_fixture(
        candidate_kind=GraphQLCandidateKind.authentication,
        responses=(FakeResponse(), FakeResponse()),
        store_factory=create_store,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    evaluation = ExperimentEvaluator().evaluate_and_commit(
        fixture.experiment,
        authorization,
        outcome,
        stores[0],
        budget_manager=ResearchBudgetManager(),
    )
    finding_id = evaluation.candidate_finding.finding_id

    restarted = ResearchStore(database).load_research(fixture.experiment.research_id)

    assert [item.finding_id for item in restarted.findings] == [finding_id]
    assert restarted.experiment_outcomes[0].candidate_finding_ids == (finding_id,)
    assert restarted.experiment_history[0].result_classification == (
        ExperimentResultClassification.vulnerable_signal.value
    )
