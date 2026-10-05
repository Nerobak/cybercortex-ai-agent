from __future__ import annotations

import json

import pytest

from agent_core.capture_ingest import CaptureBundle, CapturedRequest
from agent_core.controlled_context import (
    ControlledAccount,
    OwnedObjectAcquirer,
    OwnedObjectAcquisition,
    OwnedObjectAcquisitionError,
)
from agent_core.credential_vault import CredentialVault
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    GraphQLAuthenticationRequirement,
    GraphQLDocumentRenderer,
    GraphQLExecutionError,
    GraphQLSemanticAcquirer,
    RegisteredGraphQLOperationSource,
    ResearchState,
    candidate_ready_graphql_operation_templates,
    parse_graphql_document,
)

from test_phase4_graphql_semantics import TS, semantic_state

TARGET = "https://registered-operation.invalid"
ENDPOINT = TARGET + "/graphql"
DOCUMENT = (
    "query RegisteredResource($resourceRef: ID!) "
    "{ resource(resourceRef: $resourceRef) { status } }"
)


def _without_graphql_semantics() -> ResearchState:
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


def _registered_source(*, identity_id: str | None = None):
    return RegisteredGraphQLOperationSource(
        endpoint_url=ENDPOINT,
        source_kind="registered_graphql_acquisition",
        source_reference="owned-object-acquisition:synthetic-registration",
        document=parse_graphql_document(DOCUMENT),
        identity_id=identity_id,
    )


def test_arbitrary_document_on_schema_evidence_is_not_registered():
    state = _without_graphql_semantics()
    result = GraphQLSemanticAcquirer().acquire(
        state,
        {
            "url": ENDPOINT,
            "query": DOCUMENT,
            "response": {"data": {"resource": {"status": "visible"}}},
            "source_kind": "capture",
            "source_reference": "capture:untyped-claim",
        },
        target_id="target-1",
        target_url=TARGET,
        occurred_at=TS,
    )

    assert result.delta.operations == ()
    assert result.delta.variables == ()
    assert result.request_delta.total == 0
    assert result.observations[0].request_document_digest is None


def test_registered_source_requires_target_boundary_and_controlled_identity():
    state = _without_graphql_semantics()
    acquirer = GraphQLSemanticAcquirer()
    outside = _registered_source().model_copy(
        update={"endpoint_url": "https://outside.invalid/graphql"}
    )
    unknown_identity = _registered_source(identity_id="identity-not-registered")

    result = acquirer.register_operations(
        state,
        (outside, unknown_identity),
        target_id="target-1",
        occurred_at=TS,
    )

    assert result.delta.operations == ()
    assert result.request_delta.total == 0
    assert len(result.limitations) == 2


def test_registered_authenticated_operation_import_is_zero_request_and_idempotent():
    state = _without_graphql_semantics()
    acquirer = GraphQLSemanticAcquirer()
    source = _registered_source(identity_id="identity-a")

    first_result = acquirer.register_operations(
        state, (source,), target_id="target-1", occurred_at=TS
    )
    first = first_result.delta.apply(state)
    second_result = acquirer.register_operations(
        first, (source,), target_id="target-1", occurred_at=TS
    )
    second = second_result.delta.apply(first)
    templates = candidate_ready_graphql_operation_templates(second)

    assert first_result.request_delta.total == second_result.request_delta.total == 0
    assert first == second
    assert len(second.graphql_operations) == len(templates) == 1
    assert second.graphql_operations[0].document_fingerprint is not None
    assert templates[0].document_fingerprint == (
        second.graphql_operations[0].document_fingerprint
    )
    assert second.graphql_operations[0].authentication_requirement is (
        GraphQLAuthenticationRequirement.authenticated_observed
    )
    assert not second.findings


def test_equivalent_observed_document_formatting_does_not_duplicate_operation():
    state = _without_graphql_semantics()
    acquirer = GraphQLSemanticAcquirer()
    first = acquirer.register_operations(
        state, (_registered_source(),), target_id="target-1", occurred_at=TS
    ).delta.apply(state)
    formatted_source = RegisteredGraphQLOperationSource(
        endpoint_url=ENDPOINT,
        source_kind="trusted_typed_operation",
        source_reference="trusted-operation:formatted-copy",
        document=parse_graphql_document(
            """
            query RegisteredResource($resourceRef: ID!) {
              resource(resourceRef: $resourceRef) {
                status
              }
            }
            """
        ),
    )
    second = acquirer.register_operations(
        first, (formatted_source,), target_id="target-1", occurred_at=TS
    ).delta.apply(first)

    assert len(second.graphql_operations) == 1
    assert len(candidate_ready_graphql_operation_templates(second)) == 1
    assert second.graphql_operations[0].document_fingerprint == (
        first.graphql_operations[0].document_fingerprint
    )


def test_passive_capture_import_excludes_variable_and_response_values():
    state = _without_graphql_semantics()
    sentinels = (
        "credential-value-sentinel",
        "cookie-value-sentinel",
        "jwt-value-sentinel",
        "secret-variable-sentinel",
        "personal-data-sentinel",
    )
    vault = CredentialVault()
    body_reference = vault.put(
        json.dumps(
            {
                "query": DOCUMENT,
                "variables": {
                    "resourceRef": sentinels[3],
                    "credential": sentinels[0],
                    "cookie": sentinels[1],
                    "jwt": sentinels[2],
                    "personalData": sentinels[4],
                },
            }
        ),
        label="authorized-graphql-capture",
    )
    bundle = CaptureBundle(
        source_format="graphql",
        source_ref="authorized-passive-capture",
        requests=[
            CapturedRequest(
                request_id="capture-registered-resource",
                source_format="graphql",
                source_ref="authorized-passive-capture",
                method="POST",
                url=ENDPOINT,
                path="/graphql",
                body_type="graphql",
                graphql_operation="RegisteredResource",
                graphql_operation_type="query",
                execution_body_ref=body_reference,
            )
        ],
    )
    try:
        result = GraphQLSemanticAcquirer().acquire(
            state,
            bundle,
            target_id="target-1",
            target_url=TARGET,
            vault=vault,
            occurred_at=TS,
        )
        enriched = result.delta.apply(state)
        templates = candidate_ready_graphql_operation_templates(enriched)
        serialized = json.dumps(
            {
                "result": result.model_dump(mode="json"),
                "state": enriched.model_dump(mode="json"),
                "templates": [item.model_dump(mode="json") for item in templates],
            },
            sort_keys=True,
        )

        assert result.request_delta.total == 0
        assert len(enriched.graphql_operations) == len(templates) == 1
        assert all(value not in serialized for value in sentinels)
    finally:
        vault.close()


def test_partial_schema_enrichment_preserves_operation_identity():
    state = _without_graphql_semantics()
    acquirer = GraphQLSemanticAcquirer()
    source = _registered_source()
    result = acquirer.register_operations(
        state, (source,), target_id="target-1", occurred_at=TS
    )
    partial = result.delta.apply(state)
    operation_id = partial.graphql_operations[0].operation_id
    introspection = {
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
                                        "type": {
                                            "kind": "NON_NULL",
                                            "ofType": {"kind": "SCALAR", "name": "ID"},
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
    enriched = acquirer.ingestor.from_introspection(
        partial,
        result.observations[0],
        introspection,
        occurred_at=TS,
    ).apply(partial)

    assert enriched.graphql_operations[0].operation_id == operation_id
    assert enriched.graphql_operations[0].document_fingerprint == (
        partial.graphql_operations[0].document_fingerprint
    )
    assert enriched.graphql_surfaces[0].schema_state.value == "merged"
    assert len(candidate_ready_graphql_operation_templates(enriched)) == 1


def test_document_fingerprint_change_invalidates_registered_template():
    state = _without_graphql_semantics()
    result = GraphQLSemanticAcquirer().register_operations(
        state, (_registered_source(),), target_id="target-1", occurred_at=TS
    )
    registered = result.delta.apply(state)
    template = candidate_ready_graphql_operation_templates(registered)[0]
    changed_operation = registered.graphql_operations[0].model_copy(
        update={"document_fingerprint": "sha256:" + "f" * 64}
    )
    changed = registered.model_copy(update={"graphql_operations": (changed_operation,)})

    with pytest.raises(
        GraphQLExecutionError, match="registered GraphQL operation changed"
    ):
        GraphQLDocumentRenderer(changed).render(template)


def test_registered_graphql_acquisition_uses_one_existing_transport_request():
    vault = CredentialVault()
    budget = RequestBudget(3, per_host_limit=3)
    credential = "credential-wire-only-sentinel"
    document_reference = vault.put(DOCUMENT, label="registered-graphql-document")
    token_reference = vault.put(credential, label="controlled-token")
    account = ControlledAccount(
        account_id="account-a", credential_references={"token": token_reference}
    )
    config = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=ENDPOINT,
        method="POST",
        object_type="Resource",
        identifier_field="resourceRef",
        items_field="items",
        registered_graphql_document_reference=document_reference,
    )
    wire_requests = []

    def sender(request):
        wire_requests.append(request)
        return {
            "status_code": 200,
            "body": {"items": [{"resourceRef": "controlled-object-wire-value"}]},
        }

    try:
        acquired = OwnedObjectAcquirer(vault, budget).acquire(account, config, sender)
        serialized = json.dumps(
            {
                "config": config.model_dump(mode="json"),
                "acquired": acquired.model_dump(mode="json"),
            },
            sort_keys=True,
        )

        assert budget.total == 1
        assert len(wire_requests) == 1
        assert wire_requests[0]["json"] == {"query": DOCUMENT}
        assert credential in wire_requests[0]["headers"]["Authorization"]
        assert credential not in serialized
        assert DOCUMENT not in serialized
    finally:
        vault.close()


def test_registered_graphql_acquisition_rejects_mutation_before_transport():
    vault = CredentialVault()
    budget = RequestBudget(3, per_host_limit=3)
    token_reference = vault.put("wire-only-token", label="controlled-token")
    document_reference = vault.put(
        "mutation ChangeResource { changeResource { status } }",
        label="registered-graphql-mutation",
    )
    account = ControlledAccount(
        account_id="account-a", credential_references={"token": token_reference}
    )
    config = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=ENDPOINT,
        method="POST",
        object_type="Resource",
        identifier_field="resourceRef",
        registered_graphql_document_reference=document_reference,
    )
    calls = []

    try:
        with pytest.raises(OwnedObjectAcquisitionError, match="read-only"):
            OwnedObjectAcquirer(vault, budget).acquire(
                account, config, lambda request: calls.append(request)
            )
        assert calls == []
        assert budget.total == 0
    finally:
        vault.close()
