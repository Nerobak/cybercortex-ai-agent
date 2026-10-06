from __future__ import annotations

import json
from typing import Any

import pytest
import requests
from pydantic import ValidationError

from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    GraphQLAuthenticationRequirement,
    GraphQLSemanticIngestor,
    MAX_GRAPHQL_SELECTION_DEPTH,
    GraphQLSemanticAcquirer,
    PublicGraphQLOperationValidationStage,
    PublicGraphQLOperationAcquirer,
    PublicGraphQLOperationAcquisitionConfig,
    RegisteredGraphQLOperationSource,
    ResearchState,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
    parse_graphql_document,
)
from tools.safe_http import ScopedHTTPClient

from test_phase4_graphql_semantics import TS, semantic_state


TARGET = "https://public-graphql.invalid"
ENDPOINT = TARGET + "/graphql"
DOCUMENT = "query PublicViewer { viewer { id displayName } }"
VARIABLE_DOCUMENT = (
    "query PublicResource($resourceRef: ID!) "
    "{ resource(resourceRef: $resourceRef) { status } }"
)
INVALID_VARIABLE_DOCUMENT = (
    "query InvalidPublicResource($resourceRef: String!) "
    "{ resource(resourceRef: $resourceRef) { status } }"
)
SECRET_VALIDATION_SENTINEL = "semantic-validation-secret-sentinel"
PERSONAL_VALIDATION_SENTINEL = "person-validation@example.invalid"


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


def _registered_public_source(
    document: str = VARIABLE_DOCUMENT,
) -> RegisteredGraphQLOperationSource:
    return RegisteredGraphQLOperationSource(
        endpoint_url=ENDPOINT,
        source_kind="public_client_asset",
        source_reference="public-client-asset:synthetic",
        document=parse_graphql_document(document),
    )


def _introspection_payload() -> dict[str, Any]:
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "resource",
                                "args": [
                                    {
                                        "name": "resourceRef",
                                        "defaultValue": None,
                                        "type": {
                                            "kind": "NON_NULL",
                                            "ofType": {
                                                "kind": "SCALAR",
                                                "name": "ID",
                                            },
                                        },
                                    }
                                ],
                                "type": {"kind": "OBJECT", "name": "Resource"},
                            }
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Resource",
                        "fields": [
                            {
                                "name": "status",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String"},
                            }
                        ],
                    },
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "SCALAR", "name": "String"},
                ],
            }
        }
    }


def _existing_schema_state() -> tuple[ResearchState, RegisteredGraphQLOperationSource]:
    state = _state_without_graphql_semantics()
    source = _registered_public_source()
    acquirer = GraphQLSemanticAcquirer()
    observation = acquirer.register_operations(
        state,
        (source,),
        target_id=state.targets[0].target_id,
        occurred_at=TS,
    ).observations[0]
    schema = acquirer.ingestor.from_introspection(
        state,
        observation,
        _introspection_payload(),
        occurred_at=TS,
    ).apply(state)
    return schema, source


def _synthetic_validation_error(sentinel: str) -> ValidationError:
    return ValidationError.from_exception_data(
        "SyntheticPublicGraphQLContract",
        [
            {
                "type": "value_error",
                "loc": ("synthetic_input",),
                "input": sentinel,
                "ctx": {"error": ValueError("synthetic contract rejection")},
            }
        ],
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


def test_public_operation_merges_into_existing_schema_and_preserves_context():
    schema, source = _existing_schema_state()
    second_identity = schema.identities[0].model_copy(
        update={
            "identity_id": "identity-b",
            "account_reference": "controlled-account-b",
        }
    )
    second_object = schema.objects[0].model_copy(
        update={
            "object_id": "object-resource-2",
            "object_reference": "controlled-resource-ref-2",
            "owner_identity_id": second_identity.identity_id,
        }
    )
    schema = ResearchState.model_validate(
        {
            **schema.model_dump(mode="python"),
            "identities": (*schema.identities, second_identity),
            "objects": (*schema.objects, second_object),
        }
    )
    controlled_context = (schema.identities, schema.objects)
    acquirer = GraphQLSemanticAcquirer()

    result = acquirer.register_operations(
        schema,
        (source,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )
    enriched = result.delta.apply(schema)
    templates = candidate_ready_graphql_operation_templates(enriched)

    assert result.diagnostics == ()
    assert len(enriched.graphql_operations) == len(templates) == 1
    assert enriched.graphql_surfaces[0].schema_state.value == "merged"
    assert enriched.graphql_operations[0].graphql_surface_id == (
        schema.graphql_surfaces[0].graphql_surface_id
    )
    assert enriched.graphql_variables[0].input_type == (
        enriched.graphql_arguments[0].input_type
    )
    assert not enriched.graphql_variables[0].input_type.unresolved_external
    assert enriched.identities == controlled_context[0]
    assert enriched.objects == controlled_context[1]
    assert enriched.graphql_variables[0].controlled_value_reference is None
    assert templates[0].variable_bindings == ()
    assert not enriched.experiment_history
    assert not enriched.experiment_outcomes


def test_invalid_semantic_source_is_rejected_without_losing_valid_sibling():
    schema, valid = _existing_schema_state()
    invalid = _registered_public_source(INVALID_VARIABLE_DOCUMENT)
    acquirer = GraphQLSemanticAcquirer()

    rejected = acquirer.register_operations(
        schema,
        (invalid,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )
    recovered = acquirer.register_operations(
        schema,
        (invalid, valid),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )
    enriched = recovered.delta.apply(schema)

    assert rejected.delta.operations == ()
    assert rejected.delta.variables == ()
    assert rejected.observations == ()
    assert rejected.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.canonical_state_validation
    )
    assert rejected.diagnostics[0].exception_class == "ValidationError"
    assert "public_graphql_operation_validation_rejected" in rejected.limitations
    assert len(enriched.graphql_operations) == 1
    assert len(candidate_ready_graphql_operation_templates(enriched)) == 1
    assert recovered.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.canonical_state_validation
    )


def test_public_operation_reimport_is_semantically_idempotent():
    schema, source = _existing_schema_state()
    acquirer = GraphQLSemanticAcquirer()
    first = acquirer.register_operations(
        schema,
        (source,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    ).delta.apply(schema)
    second = acquirer.register_operations(
        first,
        (source,),
        target_id=first.targets[0].target_id,
        occurred_at=TS,
    ).delta.apply(first)

    assert second == first
    assert len(second.graphql_operations) == 1
    assert len(second.graphql_variables) == 1
    assert len(candidate_ready_graphql_operation_templates(second)) == 1


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
    assert {item.stage for item in result.diagnostics} == {
        PublicGraphQLOperationValidationStage.parser
    }


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


def test_typed_public_source_validation_is_safe_and_keeps_request_charge(
    monkeypatch,
):
    sentinel = SECRET_VALIDATION_SENTINEL

    def reject_source(**_kwargs):
        raise _synthetic_validation_error(sentinel)

    monkeypatch.setattr(
        PublicGraphQLOperationAcquirer, "_source", staticmethod(reject_source)
    )

    def requester(_method: str, url: str, **_kwargs: Any) -> requests.Response:
        if url == TARGET:
            return _response(
                '<html><script src="/client.js"></script></html>',
                url=url,
                content_type="text/html",
            )
        return _response(
            f"const operation = `{VARIABLE_DOCUMENT}`;",
            url=url,
            content_type="application/javascript",
        )

    public_acquirer, budget = _acquirer(requester)
    result = _acquire(public_acquirer)
    serialized = result.model_dump_json()

    assert budget.total == result.request_delta.total == 2
    assert result.sources == ()
    assert result.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.public_source_validation
    )
    assert result.diagnostics[0].exception_class == "ValidationError"
    assert sentinel not in serialized


def test_typed_observation_validation_has_distinct_safe_diagnostic(monkeypatch):
    from agent_core.research import graphql_discovery

    schema, source = _existing_schema_state()

    def reject_observation(**_kwargs):
        raise _synthetic_validation_error(SECRET_VALIDATION_SENTINEL)

    monkeypatch.setattr(
        graphql_discovery, "GraphQLSurfaceObservation", reject_observation
    )
    result = GraphQLSemanticAcquirer().register_operations(
        schema,
        (source,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )

    assert result.delta.operations == ()
    assert result.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.observation_validation
    )
    assert SECRET_VALIDATION_SENTINEL not in result.model_dump_json()


@pytest.mark.parametrize(
    "sentinel", (SECRET_VALIDATION_SENTINEL, PERSONAL_VALIDATION_SENTINEL)
)
def test_semantic_delta_validation_rejection_never_exposes_input(sentinel):
    schema, source = _existing_schema_state()

    class RejectingIngestor(GraphQLSemanticIngestor):
        def from_document(self, *_args, **_kwargs):
            raise _synthetic_validation_error(sentinel)

    result = GraphQLSemanticAcquirer(ingestor=RejectingIngestor()).register_operations(
        schema,
        (source,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )
    serialized = json.dumps(
        {
            "result": result.model_dump(mode="json"),
            "state": schema.model_dump(mode="json"),
        },
        sort_keys=True,
    )

    assert result.delta.operations == ()
    assert result.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.semantic_delta_validation
    )
    assert result.diagnostics[0].exception_class == "ValidationError"
    assert sentinel not in serialized


def test_template_validation_rejection_has_distinct_safe_diagnostic(
    monkeypatch,
):
    from agent_core.research import graphql_readiness

    schema, source = _existing_schema_state()

    def reject_template(_state):
        raise _synthetic_validation_error(SECRET_VALIDATION_SENTINEL)

    monkeypatch.setattr(
        graphql_readiness,
        "candidate_ready_graphql_operation_templates",
        reject_template,
    )
    result = GraphQLSemanticAcquirer().register_operations(
        schema,
        (source,),
        target_id=schema.targets[0].target_id,
        occurred_at=TS,
    )

    assert result.delta.operations == ()
    assert result.diagnostics[0].stage is (
        PublicGraphQLOperationValidationStage.template_validation
    )
    assert SECRET_VALIDATION_SENTINEL not in result.model_dump_json()


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
