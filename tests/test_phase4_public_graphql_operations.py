from __future__ import annotations

import json
from typing import Any

import requests

from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    GraphQLAuthenticationRequirement,
    MAX_GRAPHQL_SELECTION_DEPTH,
    GraphQLSemanticAcquirer,
    PublicGraphQLOperationAcquirer,
    PublicGraphQLOperationAcquisitionConfig,
    ResearchState,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)
from tools.safe_http import ScopedHTTPClient

from test_phase4_graphql_semantics import TS, semantic_state


TARGET = "https://public-graphql.invalid"
ENDPOINT = TARGET + "/graphql"
DOCUMENT = "query PublicViewer { viewer { id displayName } }"


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        program_name="public-graphql-operation-test",
        authorization_reference="authorization-public-graphql-operation",
        authorization_confirmed=True,
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
        request_budget=20,
        per_host_request_budget=20,
        max_response_bytes=262_144,
        resolve_dns_before_request=False,
    )


def _response(
    body: str,
    *,
    url: str,
    content_type: str,
    status_code: int = 200,
) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.url = url
    response.headers["Content-Type"] = content_type
    response._content = body.encode("utf-8")
    response._content_consumed = True
    return response


def _acquirer(
    requester: Any,
    *,
    maximum_requests: int = 2,
    maximum_assets: int = 2,
) -> tuple[PublicGraphQLOperationAcquirer, RequestBudget]:
    selected_policy = _policy()
    budget = RequestBudget(20, per_host_limit=20)
    client = ScopedHTTPClient(
        policy=selected_policy,
        budget=budget,
        requester=requester,
    )
    return (
        PublicGraphQLOperationAcquirer(
            client=client,
            policy=selected_policy,
            config=PublicGraphQLOperationAcquisitionConfig(
                maximum_requests=maximum_requests,
                maximum_assets=maximum_assets,
            ),
        ),
        budget,
    )


def _state_without_graphql_semantics() -> ResearchState:
    state = semantic_state()
    return ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "targets": (
                state.targets[0].model_copy(update={"canonical_reference": TARGET}),
            ),
            "graphql_surfaces": (),
            "graphql_types": (),
            "graphql_fields": (),
            "graphql_arguments": (),
            "graphql_operations": (),
            "graphql_variables": (),
        }
    )


def _acquire(acquirer: PublicGraphQLOperationAcquirer):
    return acquirer.acquire(
        target_url=TARGET,
        endpoint_url=ENDPOINT,
        surface_reference="graphql-surface-public",
    )


def test_public_client_exact_documents_register_without_execution_or_binding():
    calls: list[dict[str, Any]] = []

    def requester(method: str, url: str, **kwargs: Any) -> requests.Response:
        calls.append({"method": method, "url": url, **kwargs})
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const ordinaryOperation = `{DOCUMENT}`;",
            url=url,
            content_type="application/javascript",
        )

    public_acquirer, budget = _acquirer(requester)
    result = _acquire(public_acquirer)
    state = _state_without_graphql_semantics()
    registered = GraphQLSemanticAcquirer().register_operations(
        state,
        result.sources,
        target_id=state.targets[0].target_id,
        occurred_at=TS,
    )
    enriched = registered.delta.apply(state)
    ready, _ = derive_candidate_ready_graphql_operations(enriched, {}, occurred_at=TS)

    assert budget.total == result.request_delta.total == 2
    assert [call["method"] for call in calls] == ["GET", "GET"]
    assert all("json" not in call and "data" not in call for call in calls)
    assert len(result.sources) == 1
    assert result.sources[0].source_kind == "public_client_asset"
    assert registered.observations[0].source_kind == "public_client_asset"
    assert len(enriched.graphql_operations) == 1
    assert enriched.graphql_operations[0].document_fingerprint is not None
    assert enriched.graphql_operations[0].selection_fingerprint.startswith("sha256:")
    assert any(
        item.evidence_kind.value == "graphql_document" for item in enriched.evidence
    )
    public_evidence = next(
        item
        for item in enriched.evidence
        if item.evidence_kind.value == "graphql_document"
        and item.evidence_id in enriched.graphql_operations[0].evidence_references
    )
    metadata = {item.key: item.value for item in public_evidence.metadata.entries}
    assert metadata == {
        "graphql.object_binding_observed": False,
        "graphql.operation_executed": False,
        "graphql.operation_source": "public_client_asset",
    }
    assert len(candidate_ready_graphql_operation_templates(enriched)) == 1
    assert enriched.graphql_operations[0].authentication_requirement is (
        GraphQLAuthenticationRequirement.unknown
    )
    assert (
        candidate_ready_graphql_operation_templates(enriched)[0].variable_bindings == ()
    )
    assert candidate_ready_graphql_operation_templates(ready)[0].variable_bindings == ()
    assert not enriched.experiment_history
    assert not enriched.experiment_outcomes
    assert not enriched.findings
    assert DOCUMENT not in enriched.model_dump_json()


def test_schema_only_public_page_does_not_create_operation_or_template():
    public_acquirer, budget = _acquirer(
        lambda _method, url, **_kwargs: _response(
            "<html><body>GraphQL application</body></html>",
            url=url,
            content_type="text/html",
        )
    )

    result = _acquire(public_acquirer)
    state = _state_without_graphql_semantics()

    assert result.sources == ()
    assert budget.total == 1
    assert state.graphql_operations == ()
    assert candidate_ready_graphql_operation_templates(state) == ()


def test_malformed_and_fragment_cycle_documents_are_safely_rejected():
    cycle = (
        "query Cycle { viewer { ...ViewerFields } } "
        "fragment ViewerFields on Viewer { ...ViewerFields }"
    )

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const malformed = `query Broken {{`; const cycle = `{cycle}`;",
            url=url,
            content_type="text/javascript",
        )

    public_acquirer, _ = _acquirer(requester)
    result = _acquire(public_acquirer)

    assert result.sources == ()
    assert "public_graphql_document_rejected" in result.limitations


def test_public_client_document_selection_depth_limit_is_enforced():
    nested = "id"
    for index in range(MAX_GRAPHQL_SELECTION_DEPTH + 2):
        nested = f"level{index} {{ {nested} }}"
    document = f"query TooDeep {{ {nested} }}"

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const operation = `{document}`;",
            url=url,
            content_type="application/javascript",
        )

    public_acquirer, _ = _acquirer(requester)
    result = _acquire(public_acquirer)

    assert result.sources == ()
    assert "public_graphql_document_rejected" in result.limitations


def test_secret_and_personal_literals_never_enter_typed_sources():
    sentinels = (
        "api-key-value-sentinel",
        "person@example.invalid",
        "credential-value-sentinel",
    )
    documents = (
        f'query Key {{ viewer(apiKey: "{sentinels[0]}") {{ id }} }}',
        f'query Person {{ viewer(email: "{sentinels[1]}") {{ id }} }}',
        f'query Credential {{ viewer(value: "{sentinels[2]}") {{ id }} }}',
    )

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        body = "\n".join(
            f"const operation{index} = `{document}`;"
            for index, document in enumerate(documents)
        )
        return _response(body, url=url, content_type="application/javascript")

    public_acquirer, _ = _acquirer(requester)
    result = _acquire(public_acquirer)
    serialized = result.model_dump_json()

    assert result.sources == ()
    assert "public_graphql_document_rejected" in result.limitations
    assert all(sentinel not in serialized for sentinel in sentinels)


def test_duplicate_public_assets_converge_on_one_semantic_operation():
    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/a.js"></script><script src="/b.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const operation = `{DOCUMENT}`;",
            url=url,
            content_type="application/javascript",
        )

    public_acquirer, budget = _acquirer(requester, maximum_requests=3, maximum_assets=2)
    result = _acquire(public_acquirer)
    state = _state_without_graphql_semantics()
    registered = (
        GraphQLSemanticAcquirer()
        .register_operations(
            state,
            result.sources,
            target_id=state.targets[0].target_id,
            occurred_at=TS,
        )
        .delta.apply(state)
    )

    assert budget.total == 3
    assert len(result.sources) == 2
    assert len(registered.graphql_operations) == 1
    assert len(candidate_ready_graphql_operation_templates(registered)) == 1


def test_public_exact_manifest_uses_manifest_provenance():
    manifest = json.dumps(
        {
            "operations": {
                "public-viewer-fingerprint": {"document": DOCUMENT},
                "hash-only-entry": {"sha256": "0" * 64},
            }
        }
    )

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><link rel="graphql-manifest" href="/operations.json"></html>',
                url=url,
                content_type="text/html",
            )
        return _response(manifest, url=url, content_type="application/json")

    public_acquirer, _ = _acquirer(requester)
    result = _acquire(public_acquirer)

    assert len(result.sources) == 1
    assert result.sources[0].source_kind == "public_persisted_manifest"


def test_public_asset_content_type_and_request_ceiling_are_enforced():
    calls: list[str] = []

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        calls.append(url)
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const operation = `{DOCUMENT}`;",
            url=url,
            content_type="application/octet-stream",
        )

    public_acquirer, budget = _acquirer(requester, maximum_requests=1)
    result = _acquire(public_acquirer)

    assert calls == [TARGET]
    assert budget.total == 1
    assert result.sources == ()
    assert "public_graphql_source_request_ceiling_reached" in result.limitations


def test_public_asset_byte_ceiling_is_enforced_before_extraction():
    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        response = _response(
            f"const operation = `{DOCUMENT}`;",
            url=url,
            content_type="application/javascript",
        )
        response.headers["Content-Length"] = str(131_073)
        return response

    public_acquirer, budget = _acquirer(requester)
    result = _acquire(public_acquirer)

    assert budget.total == 2
    assert result.sources == ()
    assert "public_graphql_source_retrieval_failed" in result.limitations
