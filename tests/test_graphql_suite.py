from __future__ import annotations

import json

import requests

import agent
from agent_core.result_normalizer import normalize_findings
from agent_core.tool_explainer import explain
from tool_registry import DESCRIPTIVE_FIELDS, TOOLS
from tools.graphql_authz_planner import graphql_authz_planner
from tools.graphql_endpoint_discovery import graphql_endpoint_discovery
from tools.graphql_introspection_checker import graphql_introspection_checker
from tools.graphql_query_analyzer import analyze_graphql_query
from tools.graphql_schema_analyzer import analyze_graphql_schema


def allow_scope(monkeypatch):
    monkeypatch.setattr(
        "tools.graphql_endpoint_discovery.enforce_scope",
        lambda url: {"allowed": "example.test" in url},
    )
    monkeypatch.setattr(
        "tools.graphql_introspection_checker.enforce_scope",
        lambda url: {"allowed": "example.test" in url},
    )


def test_endpoint_discovery_confidence_static_and_scope(monkeypatch):
    allow_scope(monkeypatch)
    result = graphql_endpoint_discovery(
        [
            "https://example.test/graphql",
            "https://example.test/assets/graphql-client.js",
            {
                "url": "https://example.test/api",
                "body": '{"errors":[{"message":"query required"}]}',
            },
            {
                "url": "https://example.test/gql",
                "operationName": "Mine",
                "query": "query Mine { me { id } }",
            },
            "https://outside.test/graphql",
        ]
    )
    assert result["observed_candidates"][0]["confidence"] == "likely"
    assert any(
        x["confidence"] == "route_name_only" for x in result["observed_candidates"]
    )
    assert not any(".js" in x["url"] for x in result["observed_candidates"])
    assert result["errors"] and all(
        x["vulnerability_status"] == "observation"
        for x in result["observed_candidates"]
    )


def test_query_analyzer_is_offline_and_structured():
    query = """query GetAccount($id: ID!) { alias: account(id: $id) { id email ...Details } } fragment Details on Account { role }"""
    result = analyze_graphql_query(query)
    assert result["operation_type"] == "query"
    assert result["operation_name"] == "GetAccount"
    assert "id" in result["variables"] and "Details" in result["fragments"]
    assert result["nesting_depth"] >= 2
    assert result["sensitive_field_observations"]
    assert result["executed"] is False
    assert analyze_graphql_query("query Broken {")["success"] is False
    assert (
        analyze_graphql_query("mutation Rename { rename(id: 1) { id } }")[
            "operation_type"
        ]
        == "mutation"
    )


def schema_fixture():
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": {"name": "Subscription"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "account",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {"kind": "SCALAR", "name": "ID"},
                                    }
                                ],
                                "type": {"name": "Account"},
                            }
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "grantAdminRole",
                                "args": [],
                                "type": {"name": "Account"},
                            },
                            {
                                "name": "uploadFile",
                                "args": [],
                                "type": {"name": "File"},
                            },
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Subscription",
                        "fields": [
                            {"name": "updates", "args": [], "type": {"name": "Event"}}
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Account",
                        "fields": [
                            {
                                "name": "email",
                                "isDeprecated": True,
                                "deprecationReason": "legacy",
                                "type": {"name": "String"},
                            }
                        ],
                    },
                    {"kind": "SCALAR", "name": "Upload"},
                ],
            }
        }
    }


def test_schema_analyzer_categories_and_bounds():
    result = analyze_graphql_schema(schema_fixture())
    assert result["counts"]["query_operations"] == 1
    assert result["mutation_operations"] and result["subscription_operations"]
    assert result["classifications"]["object_authorization_candidate"]
    assert result["classifications"]["administrative_candidate"]
    assert result["upload_scalars"] == ["Upload"]
    assert result["deprecated_fields"]
    assert len(result["representative_fields"]) <= 50
    assert analyze_graphql_schema([])["success"] is False


class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "application/json", "Authorization": "secret"}
    is_redirect = False
    is_permanent_redirect = False
    content = b""

    def iter_content(self, chunk_size=8192):
        del chunk_size
        yield json.dumps(
            {"data": {"__schema": {"queryType": {"name": "Query"}}}, "token": "secret"}
        ).encode()

    def json(self):
        return json.loads(self._content)


def test_introspection_defaults_confirmation_availability_and_limits(monkeypatch):
    allow_scope(monkeypatch)
    endpoint = {"url": "https://example.test/graphql", "confidence": "confirmed"}
    assert graphql_introspection_checker(endpoint, enabled=False)["status"] == "skipped"
    assert (
        graphql_introspection_checker(
            {"url": endpoint["url"], "confidence": "route_name_only"}, enabled=True
        )["classification"]
        == "endpoint_not_confirmed"
    )
    available = graphql_introspection_checker(
        endpoint, enabled=True, requester=lambda *a, **k: FakeResponse()
    )
    assert available["classification"] == "introspection_available"
    assert available["vulnerability_status"] == "observation"
    assert available["evidence"]["response_summary"]["token"] == "[REDACTED]"
    limited = graphql_introspection_checker(
        endpoint,
        enabled=True,
        max_response_bytes=5,
        requester=lambda *a, **k: FakeResponse(),
    )
    assert limited["classification"] == "failed"

    def timeout(*args, **kwargs):
        raise requests.Timeout()

    assert (
        graphql_introspection_checker(endpoint, enabled=True, requester=timeout)[
            "status"
        ]
        == "timed_out"
    )


def test_authorization_planner_requires_controlled_evidence():
    endpoint = {"url": "https://example.test/graphql", "confidence": "confirmed"}
    assert not graphql_authz_planner(endpoint)["plans"]
    result = graphql_authz_planner(
        endpoint,
        [
            {
                "name": "account",
                "operation_type": "query",
                "sensitive_field_observations": [{"field": "email"}],
            }
        ],
        object_identifiers=["owned-id"],
        authentication_context={"controlled_accounts": ["A", "B"]},
    )
    assert result["plans"] and result["automatic_execution"] is False
    assert (
        result["plans"][0]["stop_conditions"]
        and result["plans"][0]["prohibited_actions"]
    )


def test_registry_explain_cli_and_conservative_findings(tmp_path):
    names = [name for name in TOOLS if name.startswith("graphql_")]
    assert len(names) == 5
    assert all(
        all(TOOLS[name].get(field) for field in DESCRIPTIVE_FIELDS) for name in names
    )
    assert all("Safety notes:" in explain(name) for name in names)
    query = tmp_path / "query.graphql"
    query.write_text("query Mine { me { email } }", encoding="utf-8")
    assert agent.process_user_input(f"graphql analyze {query}")["executed"] is False
    findings = normalize_findings(
        {
            "graphql_introspection_checker": {
                "output": {"introspection_status": "introspection_available"}
            }
        }
    )
    assert findings[0]["status"] == "observation"
    assert "vulnerability" not in findings[0]["title"].lower()
