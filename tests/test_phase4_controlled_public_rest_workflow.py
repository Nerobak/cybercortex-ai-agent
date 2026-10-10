from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from agent_core.attack_surface import build_canonical_attack_surface
from agent_core.benchmark.graphql_lab import ControlledGraphQLLab
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    OwnedObjectAcquirer,
    OwnedObjectAcquisition,
)
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    AttackSurfaceResearchAdapter,
    ControlledContextResearchAdapter,
    CrossSurfaceControlledObjectCorrelator,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentRegistry,
    GraphQLExperimentCandidateBuilder,
    GraphQLHypothesisGenerator,
    GraphQLSemanticAcquirer,
    PublicGraphQLOperationAcquirer,
    PublicSafeCandidatePacketBuilder,
    ResearchBudgetManager,
    ResearchPredicate,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    RequestTemplateFactory,
    TargetAsset,
    TargetClass,
    build_graphql_graph_assertions,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)
from agent_core.research.state import ProvenanceRecord
from agent_core.research.types import ProvenanceProducerType
from agent_core.result_normalizer import build_evidence_package, normalize_url_evidence
from tools.openapi_surface_analyzer import openapi_surface_analyzer

TARGET = "https://controlled-workspace.example"
NOW = "2026-10-09T12:00:00+00:00"
ACCOUNT_IDS = ("controlled-identity-a", "controlled-identity-b")
SECRET_SENTINEL = "synthetic-rest-workflow-secret-41f0d8"
PERSONAL_SENTINEL = "Synthetic Person 41f0d8"


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="controlled-public-rest-workflow",
        authorization_reference="authorization-controlled-public-rest-workflow",
        authorization_confirmed=True,
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        controlled_account_ids=list(ACCOUNT_IDS),
        credentials_allowed=True,
        request_budget=32,
        per_host_request_budget=32,
        resolve_dns_before_request=False,
    )


def _initial_state() -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="provenance-controlled-public-rest-workflow",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="controlled-public-rest-workflow-fixture",
        producer_version="v1",
        summary="Created a synthetic authorized target without private truth.",
        occurred_at=NOW,
    )
    target = TargetAsset(
        target_id="target-controlled-workspace",
        canonical_reference=TARGET,
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-controlled-workspace",
        provenance_id=provenance.provenance_id,
    )
    return ResearchState(
        research_id="research-controlled-public-rest-workflow",
        revision=0,
        status=ResearchRunStatus.modeling,
        created_at=NOW,
        updated_at=NOW,
        targets=(target,),
        provenance=(provenance,),
    )


def _canonical_surface(client: TestClient, *, include_operation_links: bool = True):
    document = deepcopy(client.get("/openapi.json").json())
    if not include_operation_links:
        document["paths"]["/owned-resources"]["get"]["responses"]["200"].pop(
            "links", None
        )
        document["paths"]["/resources/{resource_id}"]["get"]["responses"]["200"].pop(
            "links", None
        )
    analyzed = openapi_surface_analyzer(document, source_url=f"{TARGET}/openapi.json")
    results = {
        "http_probe": {
            "status": "completed",
            "output": {
                "reachable": True,
                "status_code": 200,
                "effective_url": TARGET,
            },
        },
        "api_metadata_discovery": {
            "status": "completed",
            "output": {"documents": [{"source_url": f"{TARGET}/openapi.json"}]},
        },
        "openapi_surface_analyzer": {
            "status": "completed",
            "output": analyzed,
        },
    }
    normalized = normalize_url_evidence(TARGET, results)
    package = build_evidence_package(
        TARGET,
        "observe",
        results,
        NOW,
        NOW,
        surface=normalized,
    )
    return (
        analyzed,
        build_canonical_attack_surface(
            TARGET, assessment={"evidence_package": package}
        ),
    )


class _LocalPublicClient:
    def __init__(
        self,
        client: TestClient,
        policy: AssessmentPolicy,
        budget: RequestBudget,
    ) -> None:
        self._client = client
        self.policy = policy
        self.budget = budget

    def request(self, method: str, url: str, **_kwargs):
        self.budget.consume("discovery", host="controlled-workspace.example")
        parsed = urlparse(url)
        response = self._client.request(
            method,
            parsed.path + (("?" + parsed.query) if parsed.query else ""),
        )
        return response, ()


@dataclass(frozen=True)
class _PipelineResult:
    state: ResearchState
    ready: ResearchState
    correlation: object
    hypotheses: tuple[object, ...]
    candidates: tuple[object, ...]
    budget_total_before_correlation: int
    budget_total_after_correlation: int
    acquired_request_count: int
    public_request_count: int
    acquired_response_pointers: tuple[str | None, ...]


def _pipeline(*, include_operation_links: bool = True) -> _PipelineResult:
    lab = ControlledGraphQLLab()
    client = TestClient(lab.app)
    _, canonical = _canonical_surface(
        client, include_operation_links=include_operation_links
    )
    surface_adapter = AttackSurfaceResearchAdapter()
    state = _initial_state()
    surface_records = surface_adapter.adapt(
        canonical,
        state,
        target_id="target-controlled-workspace",
        max_endpoints=100,
        max_parameters=200,
        occurred_at=NOW,
    )
    state = surface_adapter.apply(state, surface_records)

    policy = _policy()
    budget = RequestBudget(32, per_host_limit=32)
    vault = CredentialVault()
    accounts: list[ControlledAccount] = []
    acquisitions: list[OwnedObjectAcquisition] = []
    acquired = []
    acquired_requests = 0
    try:
        for account_id in ACCOUNT_IDS:
            token_reference = vault.put(
                lab.token_for_fixture(account_id), label=f"token:{account_id}"
            )
            account = ControlledAccount(
                account_id=account_id,
                credential_references={"token": token_reference},
            )
            acquisition = OwnedObjectAcquisition(
                owner_account_id=account_id,
                collection_url=f"{TARGET}/owned-resources",
                object_type="Resource",
                identifier_field="id",
                items_field="items",
            )

            def sender(request, *, _client=client):
                nonlocal acquired_requests
                acquired_requests += 1
                response = _client.get(
                    urlparse(request["url"]).path,
                    headers=request.get("headers") or {},
                )
                return {"status_code": response.status_code, "body": response.json()}

            acquired.append(
                OwnedObjectAcquirer(vault, budget).acquire(account, acquisition, sender)
            )
            accounts.append(account)
            acquisitions.append(acquisition)

        context = ControlledContext(accounts=accounts, object_acquisition=acquisitions)
        context_adapter = ControlledContextResearchAdapter()
        context_records = context_adapter.adapt_acquired_objects(
            acquired,
            context,
            state,
            policy=policy,
            target_id="target-controlled-workspace",
            vault=vault,
            occurred_at=NOW,
        )
        state = context_adapter.apply(state, context_records)

        public_start = budget.total
        public = PublicGraphQLOperationAcquirer(
            client=_LocalPublicClient(client, policy, budget),  # type: ignore[arg-type]
            policy=policy,
        ).acquire(
            target_url=TARGET,
            endpoint_url=f"{TARGET}/query",
            surface_reference="public-client-workflow",
        )
        registered = GraphQLSemanticAcquirer().register_operations(
            state,
            public.sources,
            target_id="target-controlled-workspace",
            occurred_at=NOW,
        )
        state = registered.delta.apply(state)
        public_requests = budget.total - public_start
        templates = RequestTemplateFactory().build_all(
            state,
            target_id="target-controlled-workspace",
            policy=policy,
            captures=(),
            max_templates=100,
        )
        state = RequestTemplateFactory().apply(state, templates)
    finally:
        vault.close()

    before_correlation = budget.total
    graph = build_graphql_graph_assertions(state, asserted_at=NOW)
    correlation = CrossSurfaceControlledObjectCorrelator().correlate(
        state,
        graph_assertions=graph,
        templates=candidate_ready_graphql_operation_templates(state),
    )
    ready, _ = derive_candidate_ready_graphql_operations(
        state,
        {},
        occurred_at=NOW,
        binding_evidence=correlation.readiness_evidence,
    )
    ready_graph = build_graphql_graph_assertions(ready, asserted_at=NOW)
    generated = GraphQLHypothesisGenerator().generate_result(ready, ready_graph)
    prepared = ResearchState.model_validate(
        {
            **ready.model_dump(mode="python"),
            "hypotheses": generated.hypotheses,
            "provenance": (*ready.provenance, *generated.provenance),
        }
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    compiler_context = ExperimentCompilerContext(
        current_time=NOW,
        graphql_operation_templates=candidate_ready_graphql_operation_templates(
            prepared
        ),
        policy_reference="policy-controlled-public-rest-workflow",
    )
    compiler = ExperimentCompiler(registry, compiler_context)
    candidates = GraphQLExperimentCandidateBuilder(registry, budgets, compiler).build(
        prepared,
        compiler_context=compiler_context,
        graph=ready_graph,
    )
    return _PipelineResult(
        state=state,
        ready=prepared,
        correlation=correlation,
        hypotheses=generated.hypotheses,
        candidates=candidates,
        budget_total_before_correlation=before_correlation,
        budget_total_after_correlation=budget.total,
        acquired_request_count=acquired_requests,
        public_request_count=public_requests,
        acquired_response_pointers=tuple(
            item.identifier_response_pointer for item in acquired
        ),
    )


def test_controlled_rest_detail_enforces_owner_and_non_owner_policy():
    lab = ControlledGraphQLLab()
    client = TestClient(lab.app)
    owner_id, non_owner_id = ACCOUNT_IDS
    resource_id = lab.resource_for_fixture(owner_id)
    owner_headers = {"Authorization": f"Bearer {lab.token_for_fixture(owner_id)}"}
    non_owner_headers = {
        "Authorization": f"Bearer {lab.token_for_fixture(non_owner_id)}"
    }

    owner = client.get(f"/resources/{resource_id}", headers=owner_headers)
    non_owner = client.get(f"/resources/{resource_id}", headers=non_owner_headers)
    anonymous = client.get(f"/resources/{resource_id}")

    assert owner.status_code == 200
    assert owner.json()["id"] == resource_id
    assert "protected_note" not in owner.json()
    assert non_owner.status_code == 404
    assert anonymous.status_code == 401


def test_openapi_and_public_client_expose_exact_read_only_workflow():
    lab = ControlledGraphQLLab()
    client = TestClient(lab.app)
    analyzed, canonical = _canonical_surface(client)
    javascript = client.get("/client.js").text

    assert {item["path"] for item in analyzed["routes"]} >= {
        "/owned-resources",
        "/resources/{resource_id}",
        "/query",
    }
    assert len(analyzed["workflows"]) == 2
    collection_flow, graphql_flow = (
        workflow["value_flows"][0] for workflow in analyzed["workflows"]
    )
    assert collection_flow == {
        "source_step_sequence": 1,
        "source_location": "response_body",
        "source_reference": "/items/0/id",
        "target_step_sequence": 2,
        "target_location": "path",
        "target_reference": "resource_id",
    }
    assert graphql_flow["source_location"] == "path"
    assert graphql_flow["target_location"] == "graphql_variable"
    assert graphql_flow["target_operation_name"] == "ResourceByReference"
    assert len(canonical.workflows) == 2
    assert 'fetch("/owned-resources"' in javascript
    assert "encodeURIComponent(owned.id)" in javascript
    assert "variables: {ref: owned.id}" in javascript


def test_production_discovery_and_acquisition_close_the_full_chain_offline():
    result = _pipeline()

    assert len(result.state.objects) == 2
    assert len({item.owner_identity_id for item in result.state.objects}) == 2
    assert all(len(item.reference_evidence) == 1 for item in result.state.objects)
    assert result.acquired_response_pointers == (
        "/items/0/id",
        "/items/0/id",
    )
    endpoints = {item.endpoint_id: item for item in result.state.endpoints}
    assert any(
        endpoints[item.endpoint_id].route_template == "/resources/{resource_id}"
        and any(
            parameter_id
            in {
                parameter.parameter_id
                for parameter in result.state.parameters
                if parameter.location.value == "path"
            }
            for parameter_id in item.parameter_ids
        )
        for item in result.state.request_templates
    )
    assert len(result.correlation.bindings) == 2
    assert len(result.ready.graphql_variable_bindings) == 2
    assert (
        len(
            {
                item.binding.value_reference
                for item in result.ready.graphql_variable_bindings
            }
        )
        == 2
    )
    typed_links = [
        item
        for item in build_graphql_graph_assertions(result.ready, asserted_at=NOW)
        if item.relation is ResearchPredicate.crosses_surface
        and item.target.entity_kind.value == "parameter"
    ]
    assert typed_links
    assert result.hypotheses
    assert result.candidates
    assert result.acquired_request_count == 2
    assert result.public_request_count == 2
    assert result.budget_total_after_correlation == (
        result.budget_total_before_correlation
    )


def test_missing_public_detail_workflow_preserves_benchmark8_blocked_shape():
    result = _pipeline(include_operation_links=False)

    assert len(result.state.objects) == 2
    assert all(not item.reference_evidence for item in result.state.objects)
    assert result.correlation.bindings == ()
    assert result.ready.graphql_variable_bindings == ()
    assert result.candidates == ()


def test_graphql_variable_parameter_cannot_impersonate_rest_parameter_relation():
    result = _pipeline()
    parameters = {item.parameter_id: item for item in result.state.parameters}
    endpoints = {item.endpoint_id: item for item in result.state.endpoints}
    surfaces = {item.surface_id: item for item in result.state.surfaces}
    graph = tuple(
        item
        for item in build_graphql_graph_assertions(result.state, asserted_at=NOW)
        if not (
            item.relation is ResearchPredicate.crosses_surface
            and item.target.entity_kind.value == "parameter"
            and (parameter := parameters.get(item.target.entity_id)) is not None
            and surfaces[endpoints[parameter.endpoint_id].surface_id].surface_type.value
            == "rest"
        )
    )

    assert not any(
        item.relation is ResearchPredicate.crosses_surface
        and item.target.entity_kind.value == "parameter"
        and (parameter := parameters.get(item.target.entity_id)) is not None
        and parameter.location.value == "graphql_variable"
        for item in build_graphql_graph_assertions(result.state, asserted_at=NOW)
    )

    invalid_only = CrossSurfaceControlledObjectCorrelator().correlate(
        result.state,
        graph_assertions=graph,
        templates=candidate_ready_graphql_operation_templates(result.state),
    )

    assert any(
        item.location.value == "graphql_variable" for item in result.state.parameters
    )
    assert invalid_only.bindings == ()


def test_workflow_bindings_are_restart_safe_and_idempotent(tmp_path):
    result = _pipeline()
    store = ResearchStore(tmp_path / "public-rest-workflow.sqlite3")
    store.create_research(result.ready)

    reloaded = store.load_research(result.ready.research_id)
    graph = build_graphql_graph_assertions(reloaded, asserted_at=NOW)
    repeated = CrossSurfaceControlledObjectCorrelator().correlate(
        reloaded,
        graph_assertions=graph,
        templates=candidate_ready_graphql_operation_templates(reloaded),
    )
    ready_again, _ = derive_candidate_ready_graphql_operations(
        reloaded,
        {},
        occurred_at=NOW,
        binding_evidence=repeated.readiness_evidence,
    )

    assert store.verify_integrity(reloaded.research_id).valid is True
    assert ready_again == reloaded
    assert len(ready_again.graphql_variable_bindings) == 2


def test_public_safe_packets_exclude_identifiers_secrets_and_personal_data():
    result = _pipeline()
    packet = PublicSafeCandidatePacketBuilder(ResearchBudgetManager()).build(
        result.ready, result.candidates
    )
    rendered = json.dumps(packet.public_payload(), sort_keys=True)

    assert SECRET_SENTINEL not in rendered
    assert PERSONAL_SENTINEL not in rendered
    assert "lab-token-" not in rendered
    assert all(item.object_reference not in rendered for item in result.ready.objects)


@pytest.mark.parametrize(
    "mutation",
    [
        {
            "parameters": {
                "ref": "$response.body#/items/0/id",
            }
        },
        {
            "parameters": {
                "resource_id": "$response.body#/items/0/resource_id",
            }
        },
    ],
)
def test_invalid_or_name_only_openapi_links_do_not_create_reference_flow(mutation):
    lab = ControlledGraphQLLab()
    document = TestClient(lab.app).get("/openapi.json").json()
    link = document["paths"]["/owned-resources"]["get"]["responses"]["200"]["links"][
        "resourceDetail"
    ]
    link.clear()
    link.update({"operationId": "executeGraphQL", **mutation})

    analyzed = openapi_surface_analyzer(document)

    assert not any(
        item["workflow_id"].startswith("openapi-link:listOwnedResources:resourceDetail")
        for item in analyzed["workflows"]
    )


def test_detail_requests_do_not_change_controlled_lab_state():
    lab = ControlledGraphQLLab()
    client = TestClient(lab.app)
    before = lab.snapshot_for_fixture()
    for account_id in ACCOUNT_IDS:
        resource_id = lab.resource_for_fixture(account_id)
        client.get(
            f"/resources/{resource_id}",
            headers={"Authorization": f"Bearer {lab.token_for_fixture(account_id)}"},
        )
    after = lab.snapshot_for_fixture()

    assert after.active_identity_ids == before.active_identity_ids
    assert after.resource_ownership == before.resource_ownership
