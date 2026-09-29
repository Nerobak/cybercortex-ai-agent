from __future__ import annotations

import json
from typing import Any

import requests

from agent_core.controlled_context import ControlledAccount, ControlledContext
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research.graphql_discovery import (
    GRAPHQL_PROBE_REGISTRY,
    GraphQLDiscoveryConfidence,
    GraphQLDiscoveryConfig,
    GraphQLDiscoveryProbe,
    GraphQLDiscoverySession,
    GraphQLAuthenticatedDiscovery,
    GraphQLIntrospectionPolicy,
    GraphQLProbeId,
    GraphQLProbeStateChangeClass,
    GraphQLSemanticAcquirer,
    GraphQLSurfaceDetector,
)
from agent_core.research.graphql_ingest import GraphQLControlledObjectEvidence
from tools.safe_http import ScopedHTTPClient


TARGET = "https://authorized.example"
ENDPOINT = TARGET + "/api/gql"


def policy(
    *, credentials: bool = False, controlled_ids: list[str] | None = None
) -> AssessmentPolicy:
    return AssessmentPolicy(
        program_name="graphql-discovery-test",
        authorization_reference="authorization-graphql-discovery",
        authorization_confirmed=True,
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=TARGET,
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
        credentials_allowed=credentials,
        controlled_account_ids=controlled_ids or ["identity-a"],
        request_budget=20,
        per_host_request_budget=20,
        max_response_bytes=262_144,
        resolve_dns_before_request=False,
    )


def response(
    payload: Any, *, content_type: str = "application/json"
) -> requests.Response:
    result = requests.Response()
    result.status_code = 200
    result.url = ENDPOINT
    result.headers["Content-Type"] = content_type
    result._content = json.dumps(payload).encode("utf-8")
    result._content_consumed = True
    return result


def session_for(
    requester,
    *,
    config: GraphQLDiscoveryConfig | None = None,
    credentials: bool = False,
    controlled_ids: list[str] | None = None,
):
    selected_policy = policy(credentials=credentials, controlled_ids=controlled_ids)
    budget = RequestBudget(20, per_host_limit=20)
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=requester,
    )
    return (
        GraphQLDiscoverySession(
            client=client,
            policy=selected_policy,
            request_budget=budget,
            config=config,
        ),
        budget,
    )


def test_surface_detector_requires_structure_for_observed_or_confirmed_confidence():
    detector = GraphQLSurfaceDetector()
    batch = detector.detect(
        [
            {"url": TARGET + "/graphql"},
            {
                "url": ENDPOINT,
                "body": {
                    "query": "query Viewer($id: ID!) { viewer(id: $id) { id } }",
                    "variables": {"id": "must-not-persist"},
                },
            },
            {
                "url": TARGET + "/gateway",
                "query": "query Protocol { __typename }",
                "response": {"data": {"__typename": "Query"}},
            },
        ],
        target_id="target-1",
        target_url=TARGET,
    )

    by_url = {item.endpoint_url: item for item in batch.observations}
    assert by_url[TARGET + "/graphql"].confidence is (
        GraphQLDiscoveryConfidence.candidate
    )
    assert by_url[ENDPOINT].confidence is GraphQLDiscoveryConfidence.observed
    assert by_url[TARGET + "/gateway"].confidence is (
        GraphQLDiscoveryConfidence.confirmed
    )
    serialized = batch.model_dump_json()
    assert "must-not-persist" not in serialized


def test_existing_discovery_route_name_alone_never_becomes_confirmed():
    batch = GraphQLSurfaceDetector().detect(
        {
            "observed_candidates": [
                {
                    "url": TARGET + "/graphql",
                    "confidence": "confirmed",
                    "evidence_types": ["graphql_route_name"],
                }
            ]
        },
        target_id="target-1",
    )
    assert batch.observations[0].confidence is GraphQLDiscoveryConfidence.candidate


def test_api_metadata_graphql_content_type_is_structural_confirmation():
    batch = GraphQLSurfaceDetector().detect(
        {
            "routes": [
                {
                    "method": "POST",
                    "path": "/service",
                    "content_types": ["application/graphql"],
                }
            ]
        },
        target_id="target-1",
        target_url=TARGET,
    )

    assert batch.observations[0].endpoint_url == TARGET + "/service"
    assert batch.observations[0].confidence is GraphQLDiscoveryConfidence.confirmed


def test_probe_registry_contains_only_known_read_only_bounded_templates():
    assert set(GRAPHQL_PROBE_REGISTRY) == set(GraphQLProbeId)
    for definition in GRAPHQL_PROBE_REGISTRY.values():
        assert definition.known_request_estimate == 1
        assert definition.state_change_class is GraphQLProbeStateChangeClass.none
        assert definition.response_size_bound <= 262_144
        assert definition.timeout_bound_seconds <= 15
        assert definition.document.lstrip().startswith("query ")
        assert not definition.document.lstrip().lower().startswith("mutation ")


def test_protocol_probe_confirms_graphql_but_not_ordinary_rest_json_and_accounts_exactly():
    calls: list[dict[str, Any]] = []

    def graphql_requester(method: str, url: str, **kwargs: Any):
        calls.append({"method": method, "url": url, **kwargs})
        return response({"data": {"__typename": "Query"}})

    discovery, budget = session_for(graphql_requester)
    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.protocol_confirmation,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        )
    )
    assert outcome.observation.confidence is GraphQLDiscoveryConfidence.confirmed
    assert outcome.request_delta.total == 1
    assert budget.total == 1
    assert calls[0]["json"] == {
        "query": GRAPHQL_PROBE_REGISTRY[GraphQLProbeId.protocol_confirmation].document
    }

    rest_discovery, rest_budget = session_for(
        lambda *_args, **_kwargs: response({"ok": True, "value": 1})
    )
    rest = rest_discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.protocol_confirmation,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        )
    )
    assert rest.observation.confidence is GraphQLDiscoveryConfidence.candidate
    assert rest_budget.total == 1


def test_graphql_request_ceiling_blocks_without_consuming_global_budget():
    config = GraphQLDiscoveryConfig(maximum_graphql_discovery_requests=1)
    discovery, budget = session_for(
        lambda *_args, **_kwargs: response({"data": {"__typename": "Query"}}),
        config=config,
    )
    probe = GraphQLDiscoveryProbe(
        probe_id=GraphQLProbeId.protocol_confirmation,
        target_id="target-1",
        endpoint_url=ENDPOINT,
    )
    assert discovery.execute(probe).request_delta.total == 1
    blocked = discovery.execute(probe)
    assert blocked.status == "blocked"
    assert blocked.reason_code == "graphql_request_ceiling_exhausted"
    assert budget.total == 1


def test_graphql_discovery_reserves_part_of_the_global_request_budget():
    selected_policy = policy()
    budget = RequestBudget(1, per_host_limit=1)
    calls: list[object] = []
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    discovery = GraphQLDiscoverySession(
        client=client,
        policy=selected_policy,
        request_budget=budget,
        config=GraphQLDiscoveryConfig(maximum_graphql_discovery_requests=1),
    )
    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.protocol_confirmation,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        )
    )

    assert outcome.status == "blocked"
    assert outcome.reason_code == "graphql_request_ceiling_exhausted"
    assert budget.total == 0
    assert not calls


def test_graphql_discovery_preserves_the_current_global_budget_reserve():
    selected_policy = policy()
    budget = RequestBudget(2, per_host_limit=2)
    budget.consume("discovery", host="authorized.example")
    calls: list[object] = []
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    discovery = GraphQLDiscoverySession(
        client=client,
        policy=selected_policy,
        request_budget=budget,
        config=GraphQLDiscoveryConfig(maximum_graphql_discovery_requests=1),
    )

    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.protocol_confirmation,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        )
    )

    assert outcome.status == "blocked"
    assert outcome.reason_code == "global_request_budget_reserve"
    assert budget.total == 1
    assert not calls


def test_introspection_disabled_or_passive_only_makes_zero_requests():
    calls: list[object] = []
    for mode in (
        GraphQLIntrospectionPolicy.disabled,
        GraphQLIntrospectionPolicy.passive_only,
    ):
        discovery, budget = session_for(
            lambda *args, **kwargs: calls.append((args, kwargs)),
            config=GraphQLDiscoveryConfig(introspection_policy=mode),
        )
        outcome = discovery.execute(
            GraphQLDiscoveryProbe(
                probe_id=GraphQLProbeId.introspection_probe,
                target_id="target-1",
                endpoint_url=ENDPOINT,
            )
        )
        assert outcome.status == "skipped"
        assert budget.total == 0
    assert not calls


def test_active_authorized_introspection_passes_bounded_payload_to_consumer():
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"kind": "OBJECT", "name": "Query", "fields": []}],
            }
        }
    }
    consumed: list[dict[str, Any]] = []
    discovery, budget = session_for(
        lambda *_args, **_kwargs: response(schema),
        config=GraphQLDiscoveryConfig(
            introspection_policy=GraphQLIntrospectionPolicy.active_if_authorized
        ),
    )
    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.introspection_probe,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        ),
        introspection_consumer=lambda payload: consumed.append(dict(payload)),
    )
    assert outcome.introspection_observed
    assert outcome.observation.confidence is GraphQLDiscoveryConfidence.confirmed
    assert budget.total == 1
    assert consumed == [schema]


def test_probe_response_ceiling_marks_truncation_without_parsing_schema():
    consumed: list[object] = []
    large = {"data": {"__schema": {"padding": "x" * 40_000}}}
    discovery, budget = session_for(
        lambda *_args, **_kwargs: response(large),
        config=GraphQLDiscoveryConfig(
            introspection_policy=GraphQLIntrospectionPolicy.active_if_authorized,
            maximum_response_bytes=1_024,
        ),
    )
    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.introspection_probe,
            target_id="target-1",
            endpoint_url=ENDPOINT,
        ),
        introspection_consumer=consumed.append,
    )
    assert outcome.status == "oversized"
    assert outcome.response.truncated
    assert not outcome.introspection_observed
    assert not consumed
    assert budget.total == 1


def test_authenticated_probe_materializes_only_transient_headers():
    sentinel = "synthetic-secret-graphql-wire-only"
    wire_headers: list[dict[str, str]] = []

    def requester(_method: str, _url: str, **kwargs: Any):
        wire_headers.append(dict(kwargs["headers"]))
        return response({"data": {"__typename": "Query"}})

    discovery, _ = session_for(requester, credentials=True)
    outcome = discovery.execute(
        GraphQLDiscoveryProbe(
            probe_id=GraphQLProbeId.typename_probe,
            target_id="target-1",
            endpoint_url=ENDPOINT,
            identity_id="identity-a",
            controlled_account_id="identity-a",
        ),
        transient_headers={"Authorization": "Bearer " + sentinel},
        identity_authorized=True,
    )
    assert sentinel in wire_headers[0]["Authorization"]
    assert sentinel not in outcome.model_dump_json()


def test_semantic_acquirer_is_passive_first_when_document_evidence_is_sufficient():
    calls: list[object] = []
    discovery, budget = session_for(
        lambda *args, **kwargs: calls.append((args, kwargs))
    )
    acquirer = GraphQLSemanticAcquirer(
        config=discovery.config,
        session=discovery,
    )
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    result = acquirer.acquire(
        state,
        [
            {
                "url": ENDPOINT,
                "query": "query Viewer { viewer { id } }",
                "source_reference": "capture:viewer",
            }
        ],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)

    assert not calls
    assert budget.total == result.request_delta.total == 0
    assert any(
        getattr(item, "operation_name", None) == "Viewer"
        for item in enriched.graphql_operations
    )
    assert not enriched.findings


def test_semantic_acquirer_preserves_multiple_documents_from_one_endpoint():
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    result = GraphQLSemanticAcquirer().acquire(
        state,
        [
            {
                "url": ENDPOINT,
                "query": "query FirstObserved { firstObserved { id } }",
                "source_reference": "capture:first",
            },
            {
                "url": ENDPOINT,
                "query": "query SecondObserved { secondObserved { id } }",
                "source_reference": "capture:second",
            },
        ],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)

    assert len(result.observations) == 2
    operation_names = {item.operation_name for item in enriched.graphql_operations}
    assert {"FirstObserved", "SecondObserved"}.issubset(operation_names)


def test_semantic_acquirer_probes_only_path_candidates_and_populates_surface():
    calls: list[dict[str, Any]] = []

    def requester(method: str, url: str, **kwargs: Any):
        calls.append({"method": method, "url": url, **kwargs})
        return response({"data": {"__typename": "Query"}})

    discovery, budget = session_for(requester)
    acquirer = GraphQLSemanticAcquirer(
        config=discovery.config,
        session=discovery,
    )
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    result = acquirer.acquire(
        state,
        [{"url": TARGET + "/new/graphql"}],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)

    assert len(calls) == 1
    assert budget.total == result.request_delta.total == 1
    assert result.observations[-1].confidence is GraphQLDiscoveryConfidence.confirmed
    assert any(
        item.endpoint_id not in {"endpoint-graphql"}
        for item in enriched.graphql_surfaces
    )
    assert not enriched.graphql_types[-1:] or all(
        item.name != "__Schema" for item in enriched.graphql_types
    )
    assert not enriched.findings


def test_structured_anonymous_auth_error_marks_surface_for_controlled_discovery():
    discovery, budget = session_for(
        lambda *_args, **_kwargs: response(
            {
                "errors": [
                    {
                        "message": "not persisted as an authorization inference",
                        "extensions": {"code": "UNAUTHENTICATED"},
                    }
                ]
            }
        )
    )
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    result = GraphQLSemanticAcquirer(
        config=discovery.config, session=discovery
    ).acquire(
        state,
        [{"url": TARGET + "/auth/graphql"}],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)
    acquired = next(
        item
        for item in enriched.graphql_surfaces
        if any(
            endpoint.endpoint_id == item.endpoint_id
            and endpoint.route_template == "/auth/graphql"
            for endpoint in enriched.endpoints
        )
    )

    assert acquired.authentication_requirement.value == "authentication_required"
    assert any(
        item.observation_type == "graphql_authentication_boundary"
        for item in enriched.observations
    )
    assert budget.total == result.request_delta.total == 1
    assert "not persisted" not in result.delta.model_dump_json()
    assert not enriched.findings


def test_semantic_acquirer_runs_optional_introspection_only_after_confirmation():
    calls: list[str] = []

    def requester(_method: str, _url: str, **kwargs: Any):
        document = kwargs["json"]["query"]
        calls.append(document)
        if "__schema" in document:
            return response(
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": None,
                            "subscriptionType": None,
                            "types": [
                                {
                                    "kind": "OBJECT",
                                    "name": "Query",
                                    "fields": [
                                        {
                                            "name": "viewer",
                                            "args": [],
                                            "type": {
                                                "kind": "SCALAR",
                                                "name": "String",
                                            },
                                        }
                                    ],
                                    "interfaces": [],
                                },
                                {"kind": "SCALAR", "name": "String"},
                            ],
                        }
                    }
                }
            )
        return response({"data": {"__typename": "Query"}})

    config = GraphQLDiscoveryConfig(
        maximum_graphql_discovery_requests=2,
        introspection_policy=GraphQLIntrospectionPolicy.active_if_authorized,
    )
    discovery, budget = session_for(requester, config=config)
    acquirer = GraphQLSemanticAcquirer(config=config, session=discovery)
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    result = acquirer.acquire(
        state,
        [{"url": TARGET + "/new/graphql"}],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)

    assert len(calls) == budget.total == result.request_delta.total == 2
    acquired_surface_ids = {
        item.graphql_surface_id
        for item in enriched.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    }
    assert any(
        item.graphql_surface_id in acquired_surface_ids and item.name == "Query"
        for item in enriched.graphql_types
    )
    assert any(
        item.graphql_surface_id in acquired_surface_ids
        and item.schema_state.value in {"introspection_observed", "merged"}
        for item in enriched.graphql_surfaces
    )
    assert not enriched.findings


def test_restart_enriches_a_persisted_partial_surface_without_protocol_reprobe():
    from test_phase4_graphql_semantics import semantic_state

    initial = semantic_state()
    partial_result = GraphQLSemanticAcquirer().acquire(
        initial,
        [
            {
                "url": TARGET + "/restart/graphql",
                "query": "query Restarted { restarted { id } }",
                "source_reference": "capture:restart",
            }
        ],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    persisted = partial_result.delta.apply(initial)
    calls: list[str] = []

    def requester(_method: str, _url: str, **kwargs: Any):
        calls.append(kwargs["json"]["query"])
        return response(
            {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": None,
                        "subscriptionType": None,
                        "types": [{"kind": "OBJECT", "name": "Query", "fields": []}],
                    }
                }
            }
        )

    config = GraphQLDiscoveryConfig(
        maximum_graphql_discovery_requests=1,
        introspection_policy=GraphQLIntrospectionPolicy.active_if_authorized,
    )
    discovery, budget = session_for(requester, config=config)
    enriched_result = GraphQLSemanticAcquirer(config=config, session=discovery).acquire(
        persisted,
        [{"url": TARGET + "/restart/graphql"}],
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:01+00:00",
    )
    enriched = enriched_result.delta.apply(persisted)

    assert calls == [
        GRAPHQL_PROBE_REGISTRY[GraphQLProbeId.introspection_probe].document
    ]
    assert budget.total == enriched_result.request_delta.total == 1
    assert any(
        item.schema_state.value in {"introspection_observed", "merged"}
        and any(
            endpoint.endpoint_id == item.endpoint_id
            and endpoint.route_template == "/restart/graphql"
            for endpoint in enriched.endpoints
        )
        for item in enriched.graphql_surfaces
    )


def test_authenticated_identity_differentials_are_structural_secret_safe_and_not_findings():
    sentinel_a = "synthetic-secret-graphql-identity-a"
    sentinel_b = "synthetic-secret-graphql-identity-b"
    vault = CredentialVault()
    session_a = vault.put(sentinel_a, label="graphql-session-a")
    session_b = vault.put(sentinel_b, label="graphql-session-b")
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="account-a", session_reference=session_a),
            ControlledAccount(account_id="account-b", session_reference=session_b),
        ]
    )
    wire_authorization: list[str | None] = []

    def requester(_method: str, _url: str, **kwargs: Any):
        authorization = kwargs["headers"].get("Authorization")
        wire_authorization.append(authorization)
        if authorization is None:
            return response(
                {
                    "errors": [
                        {
                            "message": "redacted",
                            "extensions": {"code": "UNAUTHENTICATED"},
                        }
                    ]
                }
            )
        typename = "User" if sentinel_a in authorization else "Administrator"
        return response({"data": {"__typename": typename}})

    selected_policy = policy(
        credentials=True, controlled_ids=["account-a", "account-b"]
    )
    budget = RequestBudget(10, per_host_limit=10)
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=requester,
    )
    discovery = GraphQLDiscoverySession(
        client=client,
        policy=selected_policy,
        request_budget=budget,
        config=GraphQLDiscoveryConfig(maximum_graphql_discovery_requests=3),
    )
    authenticated = GraphQLAuthenticatedDiscovery(
        session=discovery,
        policy=selected_policy,
        controlled_context=context,
        vault=vault,
    )

    from agent_core.research import Identity, IdentityEligibility, ResearchState
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    identity_a = state.identities[0].model_copy(
        update={"account_reference": "account-a"}
    )
    identity_b = Identity(
        identity_id="identity-b",
        account_reference="account-b",
        controlled=True,
        eligibility=IdentityEligibility.eligible,
        provenance_id="prov-graphql",
    )
    state = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "identities": (identity_a, identity_b),
        }
    )
    result = authenticated.observe(
        state,
        target_id="target-1",
        endpoint_url=ENDPOINT,
        account_ids=("account-a", "account-b"),
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)

    assert wire_authorization == [
        None,
        "Bearer " + sentinel_a,
        "Bearer " + sentinel_b,
    ]
    assert result.request_delta.total == budget.total == 3
    assert len(result.differentials) == 2
    assert {item.right_identity for item in result.differentials} == {
        "identity-a",
        "identity-b",
    }
    assert any(
        item.observation_type == "graphql_identity_differential"
        for item in enriched.observations
    )
    persistent = result.model_dump_json() + enriched.model_dump_json()
    assert sentinel_a not in persistent
    assert sentinel_b not in persistent
    assert not enriched.findings


def test_authenticated_discovery_accepts_only_policy_eligible_owned_object_evidence():
    from test_phase4_graphql_semantics import semantic_state

    state = semantic_state()
    vault = CredentialVault()
    session_reference = vault.put(
        "synthetic-secret-controlled-object", label="graphql-object-session"
    )
    context = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="controlled-account-a",
                session_reference=session_reference,
            )
        ]
    )
    selected_policy = policy(credentials=True, controlled_ids=["controlled-account-a"])
    budget = RequestBudget(10, per_host_limit=10)
    calls: list[object] = []
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    discovery = GraphQLAuthenticatedDiscovery(
        session=GraphQLDiscoverySession(
            client=client,
            policy=selected_policy,
            request_budget=budget,
        ),
        policy=selected_policy,
        controlled_context=context,
        vault=vault,
    )
    observation = (
        GraphQLSurfaceDetector()
        .detect(
            {
                "url": ENDPOINT,
                "query": "query OwnResource { resource { id } }",
                "identity_id": "identity-a",
                "source_reference": "controlled:own-resource",
            },
            target_id="target-1",
            target_url=TARGET,
        )
        .observations[0]
    )

    delta = discovery.acquire_controlled_object(
        state,
        observation,
        GraphQLControlledObjectEvidence(
            identity_id="identity-a",
            object_type="Resource",
            object_reference="controlled-resource-ref",
            ownership_basis="owner_scoped_authenticated_response",
            graphql_type_name="Resource",
            existing_object_id="object-resource-1",
            evidence_reference="controlled-fixture:resource-1",
        ),
        occurred_at="2026-09-29T12:00:00+00:00",
    )

    assert delta.objects[0].test_owned
    assert delta.objects[0].owner_identity_id == "identity-a"
    assert {item.relation.value for item in delta.cross_surface_relationships} == {
        "CROSSES_SURFACE",
        "REFERENCES_SAME_OBJECT",
    }
    assert budget.total == 0
    assert not calls
    assert "synthetic-secret-controlled-object" not in delta.model_dump_json()


def test_existing_graphql_tool_outputs_enrich_p4_semantics_without_new_requests():
    from test_phase4_graphql_semantics import semantic_state

    evidence = {
        "results": {
            "graphql_endpoint_discovery": {
                "output": {
                    "success": True,
                    "observed_candidates": [
                        {
                            "url": ENDPOINT,
                            "confidence": "confirmed",
                            "evidence_types": ["graphql_content_type"],
                            "source": "captured_response",
                        }
                    ],
                    "confirmed_endpoints": [],
                    "likely_endpoints": [],
                }
            },
            "graphql_query_analyzer": {
                "output": {
                    "success": True,
                    "operation_type": "query",
                    "operation_name": "Viewer",
                    "fields": ["viewer", "id"],
                    "variables": ["id"],
                    "aliases": [],
                    "fragments": [],
                    "executed": False,
                }
            },
            "graphql_schema_analyzer": {
                "output": {
                    "success": True,
                    "query_operations": [
                        {
                            "name": "viewer",
                            "arguments": ["id"],
                            "return_type": "User",
                        }
                    ],
                    "mutation_operations": [],
                    "subscription_operations": [],
                    "planning_only": True,
                }
            },
            "graphql_introspection_checker": {
                "output": {
                    "success": True,
                    "introspection_status": "introspection_available",
                    "network_checked": True,
                    "evidence": {
                        "endpoint": ENDPOINT,
                        "response_summary": {
                            "data": {
                                "__schema": {
                                    "queryType": {"name": "Query"},
                                    "mutationType": None,
                                    "subscriptionType": None,
                                }
                            }
                        },
                    },
                }
            },
        }
    }
    state = semantic_state()
    result = GraphQLSemanticAcquirer().acquire(
        state,
        evidence,
        target_id="target-1",
        target_url=TARGET,
        occurred_at="2026-09-29T12:00:00+00:00",
    )
    enriched = result.delta.apply(state)
    acquired_surface = next(
        item
        for item in enriched.graphql_surfaces
        if item.endpoint_id != "endpoint-graphql"
    )
    query = next(
        item
        for item in enriched.graphql_types
        if item.graphql_surface_id == acquired_surface.graphql_surface_id
        and item.name == "Query"
    )
    viewer = next(
        item
        for item in enriched.graphql_fields
        if item.type_id == query.type_id and item.name == "viewer"
    )

    assert result.request_delta.total == 0
    assert result.observations[0].confidence is GraphQLDiscoveryConfidence.confirmed
    assert any(
        getattr(item, "operation_name", None) == "Viewer"
        for item in enriched.graphql_operations
    )
    assert viewer.return_type.named_type == "User"
    assert viewer.argument_ids
    assert acquired_surface.schema_state.value in {
        "introspection_observed",
        "merged",
    }
    assert not enriched.findings
