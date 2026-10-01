from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_core.benchmark import (
    AutonomousResearchBenchmarkRunner,
    BenchmarkBlindnessGuard,
    BenchmarkGroundTruthStore,
    BenchmarkObservedFinding,
    BenchmarkRunStatus,
    BenchmarkRunStore,
    BenchmarkScorer,
    FindingMatchClassification,
    FindingMatcher,
    GroundTruthAccessError,
    graphql_benchmark_execution_factory,
    graphql_benchmark_manifest,
    graphql_benchmark_scoring_policy,
    install_graphql_benchmark_ground_truth,
)
from agent_core.benchmark.graphql_lab import (
    GRAPHQL_BENCHMARK_LAB,
)
from agent_core.controlled_context import ControlledContext
from agent_core.research import (
    CleanupStatus,
    ControlledImpact,
    Endpoint,
    EvidenceArtifact,
    EvidenceKind,
    FindingRecord,
    FindingStatus,
    HttpMethod,
    HypothesisRecord,
    HypothesisResearchStatus,
    ImpactLevel,
    ProvenanceProducerType,
    ProvenanceRecord,
    ResearchConfidence,
    ResearchExperimentRecord,
    ResearchRunStatus,
    ResearchState,
    SecurityResearchOrchestrator,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
)
from agent_core.research.bootstrap import ResearchBootstrapper
from agent_core.research.types import ResearchExperimentStatus

NOW = "2026-10-01T00:00:00+00:00"
DIGEST = "sha256:" + "a" * 64
IDENTITY_A = "controlled-identity-a"
IDENTITY_B = "controlled-identity-b"


def _client() -> TestClient:
    GRAPHQL_BENCHMARK_LAB.reset()
    return TestClient(GRAPHQL_BENCHMARK_LAB.app)


def _graphql(
    client: TestClient,
    token: str | None,
    query: str,
    variables: dict[str, str] | None = None,
):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post(
        "/query",
        headers=headers,
        json={"query": query, "variables": variables or {}},
    )


def _truth(tmp_path: Path):
    store = BenchmarkGroundTruthStore(tmp_path / "private-truth")
    install_graphql_benchmark_ground_truth(store)
    return store.load_for_scoring(
        graphql_benchmark_manifest().ground_truth_reference,
        run_status=BenchmarkRunStatus.completed,
    )


def _observed(
    *,
    identifier: str = "finding-graphql-1",
    status: str = "confirmed",
    category: str = "graphql_object_authorization",
    security_property: str = "graphql-security-property:object_authorization",
) -> BenchmarkObservedFinding:
    return BenchmarkObservedFinding(
        finding_id=identifier,
        status=status,
        category=category,
        surface_class="graphql",
        endpoint_reference="/query",
        security_property=security_property,
        identity_relationship="owner_non_owner",
        object_relationship="controlled_object",
        primitive="graphql_operation",
        evidence_class="graphql_object_authorization",
    )


def _scoring_state(
    *,
    status: FindingStatus,
    category: str = "graphql_object_authorization",
    security_property: str = "graphql-security-property:object_authorization",
) -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="provenance-scoring",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="blind-graphql-test",
        producer_version="v1",
        summary="Synthetic post-run scoring fixture.",
        occurred_at=NOW,
    )
    evidence = EvidenceArtifact(
        evidence_id="evidence-scoring",
        evidence_kind=EvidenceKind.differential,
        digest=DIGEST,
        summary="Synthetic controlled differential evidence.",
        source_reference="outcome-scoring",
        observed_at=NOW,
        provenance_id=provenance.provenance_id,
    )
    target = TargetAsset(
        target_id="target-scoring",
        canonical_reference="http://127.0.0.1:8765",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-scoring",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    surface = Surface(
        surface_id="surface-scoring",
        target_id=target.target_id,
        surface_type=SurfaceType.graphql,
        label="Observed GraphQL surface.",
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    endpoint = Endpoint(
        endpoint_id="endpoint-scoring",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        method=HttpMethod.post,
        route_template="/query",
        content_types=("application/json",),
        evidence_references=(evidence.evidence_id,),
        provenance_id=provenance.provenance_id,
    )
    confirmed = status is FindingStatus.confirmed
    finding = FindingRecord(
        finding_id="finding-scoring",
        status=status,
        title="Controlled GraphQL object authorization differential.",
        category=category,
        source_hypothesis_id="hypothesis-scoring",
        candidate_experiment_id="experiment-scoring",
        reproduction_experiment_ids=("experiment-reproduction",) if confirmed else (),
        confirmation_policy_reference="confirmation-scoring",
        evidence_references=(evidence.evidence_id,),
        controlled_impact=(
            ControlledImpact(
                level=ImpactLevel.material,
                summary="A controlled non-owner read was independently reproduced.",
                evidence_references=(evidence.evidence_id,),
            )
            if confirmed
            else None
        ),
        cleanup_status=CleanupStatus.not_required,
        provenance_id=provenance.provenance_id,
        research_id="research-scoring",
        target_id=target.target_id,
        surface_id=surface.surface_id,
        endpoint_id=endpoint.endpoint_id,
        primitive="graphql_operation",
        capability="graphql_object_authorization",
        security_property_reference=security_property,
        controlled_identity_ids=("identity-owner", "identity-non-owner"),
        controlled_identity_relationship="owner_non_owner",
        controlled_object_ids=("controlled-object",),
        reproduction_ids=("reproduction-scoring",) if confirmed else (),
        confirmed_evidence_references=(evidence.evidence_id,) if confirmed else (),
        created_at=NOW,
        updated_at=NOW,
    )
    state = ResearchState(
        research_id="research-scoring",
        revision=0,
        status=ResearchRunStatus.stopped,
        created_at=NOW,
        updated_at=NOW,
        targets=(target,),
        surfaces=(surface,),
        endpoints=(endpoint,),
        evidence=(evidence,),
        provenance=(provenance,),
    )
    return state.model_copy(update={"findings": (finding,)})


def test_lab_health_and_introspection_are_deterministic_without_answer_disclosure():
    client = _client()

    assert client.get("/healthz").json() == {"status": "ok"}
    response = _graphql(
        client,
        None,
        "query Schema { __schema { queryType { name } types { name } } }",
    )
    schema = response.json()["data"]["__schema"]

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/graphql-response+json"
    )
    assert schema["queryType"] == {"name": "Query"}
    assert {item["name"] for item in schema["types"]} >= {
        "Query",
        "User",
        "Resource",
    }
    assert "private-sentinel" not in response.text


def test_lab_owner_can_access_own_controlled_object():
    client = _client()
    token = GRAPHQL_BENCHMARK_LAB.token_for_fixture(IDENTITY_A)
    resource = GRAPHQL_BENCHMARK_LAB.resource_for_fixture(IDENTITY_A)

    response = _graphql(
        client,
        token,
        "query Read($ref: ID!) { resource(ref: $ref) { id label } }",
        {"ref": resource},
    )

    assert response.status_code == 200
    assert response.json()["data"]["resource"]["id"] == resource
    assert "errors" not in response.json()


def test_lab_non_owner_can_access_owner_object_on_hidden_vulnerable_path():
    client = _client()
    non_owner_token = GRAPHQL_BENCHMARK_LAB.token_for_fixture(IDENTITY_B)
    owner_resource = GRAPHQL_BENCHMARK_LAB.resource_for_fixture(IDENTITY_A)

    response = _graphql(
        client,
        non_owner_token,
        "query Read($ref: ID!) { resource(ref: $ref) { id label } }",
        {"ref": owner_resource},
    )

    assert response.status_code == 200
    assert response.json()["data"]["resource"]["id"] == owner_resource
    assert "errors" not in response.json()


def test_lab_secure_controls_deny_anonymous_viewer_and_non_owner_field():
    client = _client()
    owner_resource = GRAPHQL_BENCHMARK_LAB.resource_for_fixture(IDENTITY_A)
    non_owner_token = GRAPHQL_BENCHMARK_LAB.token_for_fixture(IDENTITY_B)

    anonymous = _graphql(client, None, "query Viewer { viewer { id } }")
    protected = _graphql(
        client,
        non_owner_token,
        "query Read($ref: ID!) { resource(ref: $ref) { id protectedNote } }",
        {"ref": owner_resource},
    )

    assert anonymous.status_code == 200
    assert anonymous.json()["data"]["viewer"] is None
    assert anonymous.json()["errors"][0]["extensions"]["code"] == "UNAUTHENTICATED"
    assert protected.status_code == 200
    assert protected.json()["data"]["resource"]["id"] == owner_resource
    assert protected.json()["data"]["resource"]["protectedNote"] is None
    assert protected.json()["errors"][0]["extensions"]["code"] == "FORBIDDEN"


def test_lab_reset_restores_tokens_objects_ownership_and_request_visible_state():
    client = _client()
    original = GRAPHQL_BENCHMARK_LAB.snapshot_for_fixture()
    owner_token = GRAPHQL_BENCHMARK_LAB.token_for_fixture(IDENTITY_A)
    owner_resource = GRAPHQL_BENCHMARK_LAB.resource_for_fixture(IDENTITY_A)
    GRAPHQL_BENCHMARK_LAB.revoke_identity_for_fixture(IDENTITY_A)
    GRAPHQL_BENCHMARK_LAB.transfer_resource_for_fixture(owner_resource, IDENTITY_B)
    denied = _graphql(client, owner_token, "query Viewer { viewer { id } }")

    assert denied.json()["errors"][0]["extensions"]["code"] == "UNAUTHENTICATED"
    assert GRAPHQL_BENCHMARK_LAB.snapshot_for_fixture() != original
    assert GRAPHQL_BENCHMARK_LAB.reset()
    restored = GRAPHQL_BENCHMARK_LAB.snapshot_for_fixture()

    assert restored == original
    allowed = _graphql(client, owner_token, "query Viewer { viewer { id } }")
    assert allowed.json()["data"]["viewer"]["id"] == IDENTITY_A


def test_endpoint_operation_and_schema_are_discoverable_but_not_public_input(tmp_path):
    client = _client()
    manifest = graphql_benchmark_manifest()
    research_input, _, _ = graphql_benchmark_execution_factory(
        manifest=manifest,
        run_id="run-discovery-blindness",
        research_id="research-discovery-blindness",
        storage_root=tmp_path / "factory",
    )
    landing = client.get("/").text
    script = client.get("/client.js").text
    openapi = client.get("/openapi.json").json()
    public = research_input.model_dump_json()

    assert 'type="application/graphql" href="/query"' in landing
    assert "query ResourceByReference($ref: ID!)" in script
    assert "/query" in openapi["paths"]
    assert "/query" not in public
    assert "ResourceByReference" not in public
    assert "Resource" not in public
    assert "object_authorization" not in public
    assert "graphql" not in public.lower()
    assert "authorization" not in public.lower()


def test_private_truth_is_status_gated_typed_and_contains_only_one_finding(tmp_path):
    store = BenchmarkGroundTruthStore(tmp_path / "private")
    install_graphql_benchmark_ground_truth(store)

    with pytest.raises(GroundTruthAccessError):
        store.load_for_scoring(
            graphql_benchmark_manifest().ground_truth_reference,
            run_status=BenchmarkRunStatus.ready,
        )

    truth = store.load_for_scoring(
        graphql_benchmark_manifest().ground_truth_reference,
        run_status=BenchmarkRunStatus.completed,
    )
    finding = truth.findings[0]

    assert len(truth.findings) == 1
    assert finding.category == "graphql_object_authorization"
    assert finding.affected_surface_class == "graphql"
    assert finding.required_controlled_identity_relationship == "owner_non_owner"
    assert finding.required_controlled_object_relationship == "controlled_object"
    assert finding.confirmation_requirements == (
        "independent-reproduction",
        "deterministic-confirmation",
    )
    assert all("protected" not in item.ground_truth_id for item in truth.findings)


def test_pre_run_state_is_graphql_blind_and_hidden_sentinel_is_not_contaminated(
    tmp_path,
):
    manifest = graphql_benchmark_manifest()
    research_input, bindings, _ = graphql_benchmark_execution_factory(
        manifest=manifest,
        run_id="run-blindness",
        research_id="research-blindness",
        storage_root=tmp_path / "factory",
    )
    state = bindings.research_store.load_research("research-blindness")
    guard = BenchmarkBlindnessGuard().validate(
        research_input,
        initial_state=state,
        model_packets=(),
        seed_hypotheses=(),
        seed_findings=(),
        research_graph=(),
    )
    visible = {
        "research_input": research_input,
        "initial_state": state,
        "model_packets": (),
        "hypotheses": (),
        "candidates": (),
        "chains": (),
    }
    private = BenchmarkGroundTruthStore(tmp_path / "private")
    install_graphql_benchmark_ground_truth(private)
    contamination = private.check_contamination(
        manifest.ground_truth_reference, visible
    )
    truth = private.load_for_scoring(
        manifest.ground_truth_reference,
        run_status=BenchmarkRunStatus.completed,
    )
    hidden_sentinel = truth.hidden_sentinels[0]
    serialized = json.dumps(
        {
            "research_input": research_input.model_dump(mode="json"),
            "initial_state": state.model_dump(mode="json"),
        },
        sort_keys=True,
    )

    assert guard.valid
    assert not contamination.contaminated
    assert hidden_sentinel not in serialized
    assert "graphql" not in research_input.scope_reference.lower()
    assert "graphql" not in research_input.policy_reference.lower()
    assert "authorization" not in research_input.scope_reference.lower()
    assert "authorization" not in research_input.policy_reference.lower()
    assert not state.graphql_surfaces
    assert not state.graphql_types
    assert not state.graphql_fields
    assert not state.graphql_operations
    assert not state.hypotheses
    assert not state.findings


def test_graphql_bola_finding_matches_by_typed_equivalence_not_generated_ids(tmp_path):
    truth = _truth(tmp_path)

    matched = FindingMatcher().match(_observed(), truth.findings)
    wrong = FindingMatcher().match(
        _observed(
            identifier="finding-wrong",
            category="graphql_field_authorization",
            security_property="graphql-security-property:field_authorization",
        ),
        truth.findings,
    )

    assert matched.classification in {
        FindingMatchClassification.exact_match,
        FindingMatchClassification.semantic_typed_match,
    }
    assert matched.ground_truth_id == truth.findings[0].ground_truth_id
    assert wrong.classification is FindingMatchClassification.no_match
    assert wrong.ground_truth_id is None


def test_candidate_only_match_gets_candidate_credit_but_zero_confirmed_credit(tmp_path):
    score = BenchmarkScorer().score(
        benchmark_run_id="run-candidate-only",
        final_state=_scoring_state(status=FindingStatus.candidate),
        ground_truth=_truth(tmp_path),
        policy=graphql_benchmark_scoring_policy(),
    )

    assert score.metrics.discovery.candidate_recall == 1.0
    assert score.metrics.discovery.confirmed_recall == 0.0
    assert score.metrics.discovery.true_positive_confirmed == 0
    assert not score.passed


def test_confirmed_credit_requires_reproduction_and_wrong_finding_is_false_positive(
    tmp_path,
):
    candidate = _scoring_state(status=FindingStatus.candidate).findings[0]
    with pytest.raises(ValueError, match="require reproduction"):
        FindingRecord.model_validate(
            {
                **candidate.model_dump(mode="python"),
                "status": FindingStatus.confirmed,
                "controlled_impact": ControlledImpact(
                    level=ImpactLevel.material,
                    summary="A controlled impact summary.",
                    evidence_references=("evidence-scoring",),
                ),
            }
        )

    confirmed = BenchmarkScorer().score(
        benchmark_run_id="run-confirmed",
        final_state=_scoring_state(status=FindingStatus.confirmed),
        ground_truth=_truth(tmp_path / "confirmed"),
        policy=graphql_benchmark_scoring_policy(),
    )
    false_positive = BenchmarkScorer().score(
        benchmark_run_id="run-false-positive",
        final_state=_scoring_state(
            status=FindingStatus.confirmed,
            category="graphql_field_authorization",
            security_property="graphql-security-property:field_authorization",
        ),
        ground_truth=_truth(tmp_path / "false-positive"),
        policy=graphql_benchmark_scoring_policy(),
    )

    assert confirmed.metrics.discovery.confirmed_recall == 1.0
    assert confirmed.passed
    assert false_positive.metrics.discovery.confirmed_recall == 0.0
    assert false_positive.metrics.confirmation.false_confirmation_count == 1
    assert not false_positive.passed


def test_secure_control_signal_is_generic_diagnostic_and_never_truth_credit(tmp_path):
    state = _scoring_state(status=FindingStatus.candidate).model_copy(
        update={"findings": ()}
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="hypothesis-secure-control",
        category="authentication_enforcement",
        title="Authentication boundary control.",
        claim="Anonymous access may be accepted.",
        target_id=state.targets[0].target_id,
        surface_id=state.surfaces[0].surface_id,
        status=HypothesisResearchStatus.refuted,
        priority=50,
        confidence=ResearchConfidence.medium,
        confirmation_policy_reference="confirmation-secure-control",
        supporting_evidence=(state.evidence[0].evidence_id,),
        refuting_evidence=(state.evidence[0].evidence_id,),
        provenance_id=state.provenance[0].provenance_id,
    )
    experiment = ResearchExperimentRecord(
        experiment_id="experiment-secure-control",
        proposal_id="proposal-secure-control",
        hypothesis_id=hypothesis.hypothesis_id,
        surface_id=state.surfaces[0].surface_id,
        fingerprint=DIGEST,
        material_fingerprint="sha256:" + "b" * 64,
        status=ResearchExperimentStatus.completed,
        result_classification="secure_signal",
        relevant_state_revision=0,
        occurred_at=NOW,
    )
    diagnostic_state = state.model_copy(
        update={
            "hypotheses": (hypothesis,),
            "experiment_history": (experiment,),
        }
    )
    score = BenchmarkScorer().score(
        benchmark_run_id="run-secure-control",
        final_state=diagnostic_state,
        ground_truth=_truth(tmp_path),
        policy=graphql_benchmark_scoring_policy(),
    )

    assert score.metrics.experiments.experiments_secure_signal == 1
    assert score.metrics.hypotheses.hypotheses_refuted == 1
    assert score.metrics.discovery.true_positive_candidates == 0
    assert score.metrics.discovery.confirmed_recall == 0.0


def test_trusted_factory_preflight_uses_production_components_without_calls(tmp_path):
    manifest = graphql_benchmark_manifest()
    private = BenchmarkGroundTruthStore(tmp_path / "private")
    install_graphql_benchmark_ground_truth(private)
    research_input, bindings, reset_plan = graphql_benchmark_execution_factory(
        manifest=manifest,
        run_id="run-factory",
        research_id="research-factory",
        storage_root=tmp_path / "factory",
    )
    runner = AutonomousResearchBenchmarkRunner(
        run_store=BenchmarkRunStore(tmp_path / "runs.sqlite3"),
        ground_truth_store=private,
        scoring_policies={
            manifest.scoring_policy_reference: graphql_benchmark_scoring_policy()
        },
    )
    run = runner.create_run(
        manifest,
        research_input,
        research_id="research-factory",
        run_id="run-factory",
    )
    ready, initial = runner.validate(
        run, manifest, research_input, bindings, reset_plan
    )
    orchestrator = bindings.build_orchestrator(initial)

    assert ready.status is BenchmarkRunStatus.ready
    assert type(bindings.research_store).__name__ == "ResearchStore"
    assert type(bindings.request_budget).__name__ == "RequestBudget"
    assert type(bindings.model_router).__name__ == "ModelRouter"
    assert isinstance(bindings.bootstrapper, ResearchBootstrapper)
    assert isinstance(orchestrator, SecurityResearchOrchestrator)
    assert isinstance(bindings.bootstrapper.controlled_context, ControlledContext)
    assert len(bindings.bootstrapper.controlled_context.accounts) == 2
    assert bindings.bootstrapper.controlled_context.objects == []
    assert bindings.request_budget.total == 0
    assert (
        bindings.model_router.ledger.usage_for_run("research-factory").attempted_calls
        == 0
    )


def test_no_graphql_benchmark_special_case_exists_in_production_research_modules():
    pattern = re.compile(
        r"if\s+[^\n]*(?:benchmark[^\n]*graphql|graphql[^\n]*benchmark)", re.I
    )
    matches = []
    for path in Path("agent_core/research").glob("*.py"):
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if pattern.search(line):
                matches.append(f"{path}:{line_number}")

    assert matches == []
