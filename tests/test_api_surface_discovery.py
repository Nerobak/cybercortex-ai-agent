from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests

import agent_core.result_normalizer as normalizer_module
import agent_core.tool_runner as runner_module
import tools.api_metadata_discovery as metadata_module
import tools.api_object_discovery as object_module
from agent_core.result_normalizer import build_evidence_package
from agent_core.tool_runner import ToolRunner
from agent_core.tool_explainer import explain
from agent_core.doctor import doctor
from tools.api_metadata_discovery import METADATA_PATHS, api_metadata_discovery
from tools.api_object_discovery import crawl_and_discover_ids
from tools.api_target_analyzer import analyze_api_target
from tools.ai_report_writer import ai_report_writer
from tools.endpoint_analyzer import endpoint_analyzer
from tools.misconfiguration_detector import misconfiguration_detector
from tools.openapi_surface_analyzer import (
    is_openapi_document,
    openapi_surface_analyzer,
    sanitize_openapi_document,
)
from tools.parameter_analyzer import parameter_analyzer
from tools.safe_http import UnsafeRedirectError


def _response(
    url: str,
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "application/json",
) -> requests.Response:
    response = requests.Response()
    response.url = url
    response.status_code = status
    response.headers["Content-Type"] = content_type
    response._content = body
    return response


class FakeClient:
    def __init__(self, responses: dict[str, requests.Response | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any):
        self.calls.append((method, url, kwargs))
        value = self.responses.get(url)
        if isinstance(value, Exception):
            raise value
        if value is None:
            value = _response(url, b'{"detail":"Not Found"}', status=404)
        return value, []


def _openapi_three() -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "OrderInput": {
                    "type": "object",
                    "required": ["account_id"],
                    "properties": {
                        "account_id": {"type": "string"},
                        "note": {"type": "string"},
                        "password": {
                            "type": "string",
                            "example": "must-not-survive",
                        },
                    },
                },
                "Order": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "owner_id": {"type": "string"},
                    },
                },
            },
        },
        "paths": {
            "/api/orders/{order_id}": {
                "get": {
                    "operationId": "getOrder",
                    "tags": ["orders"],
                    "parameters": [
                        {
                            "name": "order_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "expand",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"}
                                }
                            }
                        }
                    },
                },
                "post": {
                    "security": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/OrderInput"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "created"}},
                },
            }
        },
    }


def _swagger_two() -> dict[str, Any]:
    return {
        "swagger": "2.0",
        "basePath": "/api",
        "paths": {
            "/pets/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "type": "string"}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


def test_api_likelihood_uses_combined_signals_and_sparse_crawl():
    result = analyze_api_target(
        "http://127.0.0.1:8765",
        {
            "reachable": True,
            "root_status": 404,
            "content_type": "application/json",
            "server": "uvicorn",
        },
        {},
        {"urls": ["http://127.0.0.1:8765"]},
    )
    assert result["api_likelihood"] in {"medium", "high"}
    assert result["decision"] == {
        "decision": "api_metadata_discovery",
        "reason": "reachable API-oriented target with insufficient crawler surface",
        "automatic": True,
        "bounded": True,
    }
    assert result["root_status"] == 404 and result["reachable"] is True


def test_html_site_with_many_urls_does_not_pivot():
    result = analyze_api_target(
        "https://example.test",
        {"reachable": True, "root_status": 200, "content_type": "text/html"},
        {},
        {"urls": [f"https://example.test/page/{index}" for index in range(10)]},
    )
    assert result["decision"]["decision"] == "normal_discovery"
    assert result["decision"]["automatic"] is False


def test_json_response_alone_is_not_openapi():
    assert not is_openapi_document({"message": "openapi service", "items": []})
    assert not is_openapi_document("openapi documentation")


def test_api_tools_are_explainable_and_doctor_checks_bounds():
    metadata_explanation = explain("api_metadata_discovery")
    parser_explanation = explain("openapi_surface_analyzer")
    for heading in (
        "Purpose:",
        "Traffic:",
        "Profiles:",
        "Prerequisites:",
        "Evidence collected:",
        "Does not prove:",
        "Common false positives:",
        "Safety notes:",
    ):
        assert heading in metadata_explanation
        assert heading in parser_explanation
    assert "API metadata discovery configuration" in doctor(quick=True)


def test_metadata_discovery_enforces_request_bound(monkeypatch):
    monkeypatch.setattr(metadata_module, "enforce_scope", lambda url: {"allowed": True})
    client = FakeClient({})
    result = api_metadata_discovery(
        "https://example.test", max_requests=3, http_client=client
    )
    assert result["request_count"] == 3
    assert len(client.calls) == 3
    assert all(call[0] == "GET" for call in client.calls)


def test_metadata_discovery_blocks_out_of_scope_redirect(monkeypatch):
    monkeypatch.setattr(metadata_module, "enforce_scope", lambda url: {"allowed": True})
    first = "https://example.test/openapi.json"
    client = FakeClient(
        {
            first: UnsafeRedirectError(
                "outside",
                [
                    {
                        "from": first,
                        "to": "https://outside.test/spec",
                        "status_code": 302,
                        "allowed": False,
                    }
                ],
            )
        }
    )
    result = api_metadata_discovery(
        "https://example.test", max_requests=1, http_client=client
    )
    assert result["documents"] == []
    assert result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert result["metadata_requests"][0]["redirect_chain"][0]["allowed"] is False


def test_metadata_response_size_is_enforced(monkeypatch):
    monkeypatch.setattr(metadata_module, "enforce_scope", lambda url: {"allowed": True})
    url = "https://example.test/openapi.json"
    client = FakeClient({url: _response(url, b"x" * 101)})
    result = api_metadata_discovery(
        "https://example.test",
        max_requests=1,
        max_response_bytes=100,
        http_client=client,
    )
    assert result["documents"] == []
    assert result["metadata_requests"][0]["status"] == "response_too_large"


def test_metadata_rejects_invalid_and_html_but_accepts_openapi_versions(monkeypatch):
    monkeypatch.setattr(metadata_module, "enforce_scope", lambda url: {"allowed": True})
    origin = "https://example.test"
    responses = {
        origin
        + METADATA_PATHS[0]: _response(
            origin + METADATA_PATHS[0], b'{"message":"not a specification"}'
        ),
        origin
        + METADATA_PATHS[1]: _response(
            origin + METADATA_PATHS[1],
            b"<html>OpenAPI docs</html>",
            content_type="text/html",
        ),
        origin
        + METADATA_PATHS[2]: _response(
            origin + METADATA_PATHS[2], json.dumps(_openapi_three()).encode()
        ),
        origin
        + METADATA_PATHS[3]: _response(
            origin + METADATA_PATHS[3], json.dumps(_swagger_two()).encode()
        ),
    }
    result = api_metadata_discovery(
        origin, max_requests=4, http_client=FakeClient(responses)
    )
    assert result["document_count"] == 2
    assert {item["openapi_version"] for item in result["documents"]} == {
        "2.0",
        "3.0.3",
    }


def test_openapi_parser_extracts_operations_parameters_bodies_security_and_objects():
    result = openapi_surface_analyzer(_openapi_three())
    assert result["success"] is True
    assert result["route_count"] == 1 and result["operation_count"] == 2
    get_route = next(item for item in result["routes"] if item["method"] == "GET")
    post_route = next(item for item in result["routes"] if item["method"] == "POST")
    assert {item["name"] for item in get_route["parameters"]} == {
        "order_id",
        "expand",
    }
    assert {item["name"] for item in post_route["request_fields"]} >= {
        "account_id",
        "password",
    }
    assert get_route["security_required"] is True
    assert get_route["security_schemes"] == ["bearerAuth"]
    assert post_route["security_required"] is False
    assert "Order" in get_route["response_schema_names"]
    assert any(
        item["type"] == "order"
        and item["identifier"] == "order_id"
        and item["source"] == "OpenAPI path parameter"
        for item in result["objects"]
    )
    assert result["vulnerability_status"] == "not_assessed"


def test_swagger_two_and_yaml_are_supported():
    swagger = openapi_surface_analyzer(_swagger_two())
    yaml_document = """
openapi: 3.0.0
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        '200':
          description: ok
"""
    yaml_result = openapi_surface_analyzer(yaml_document)
    assert swagger["routes"][0]["path"] == "/api/pets/{id}"
    assert swagger["routes"][0]["method"] == "GET"
    assert yaml_result["success"] is True
    assert yaml_result["routes"][0]["parameters"][0]["name"] == "limit"


def test_recursive_refs_stop_and_sensitive_examples_are_removed():
    document = _openapi_three()
    document["components"]["schemas"]["Recursive"] = {
        "type": "object",
        "properties": {
            "self": {"$ref": "#/components/schemas/Recursive"},
            "api_key": {"type": "string", "example": "private-api-key"},
        },
    }
    document["paths"]["/recursive"] = {
        "post": {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Recursive"}
                    }
                }
            },
            "responses": {"200": {"description": "ok"}},
        }
    }
    result = openapi_surface_analyzer(document, max_ref_depth=4, max_items=50)
    encoded = json.dumps(sanitize_openapi_document(document))
    assert result["success"] is True
    assert result["parameter_count"] <= 50
    assert "private-api-key" not in encoded
    assert "must-not-survive" not in encoded


def test_authorized_loopback_target_is_not_a_suspicious_reference():
    result = misconfiguration_detector(
        ["http://127.0.0.1:8765", "http://127.0.0.1:8765/api"],
        "127.0.0.1",
    )
    assert not any(
        item["type"] == "suspicious_reference" for item in result["findings"]
    )


def test_production_content_reference_to_loopback_remains_observable():
    result = misconfiguration_detector(
        ["https://production.test/callback?url=http://localhost:9000"],
        "production.test",
    )
    assert any(item["type"] == "suspicious_reference" for item in result["findings"])


def test_sparse_api_openapi_surface_flows_to_existing_analyzers(monkeypatch):
    target = "http://127.0.0.1:8765"
    specification = _openapi_three()
    calls: dict[str, Any] = {}

    def endpoint(values, hostname):
        calls["endpoint"] = list(values)
        return endpoint_analyzer(values, hostname)

    def parameters(values):
        calls["parameters"] = list(values)
        return parameter_analyzer(values)

    def objects(url, **kwargs):
        calls["objects"] = kwargs["normalized_url_evidence"]["attack_surface"]
        return crawl_and_discover_ids(url, **kwargs)

    functions = {
        "http_probe": lambda url: {
            "success": True,
            "reachable": True,
            "root_status": 404,
            "status_code": 404,
            "server": "uvicorn",
            "content_type": "application/json",
            "effective_url": url,
        },
        "tech_fingerprint": lambda url: {"success": True, "technologies": []},
        "katana_crawl": lambda url: {"success": True, "urls": [url], "count": 1},
        "api_target_analyzer": analyze_api_target,
        "api_metadata_discovery": lambda url: {
            "success": True,
            "documents": [
                {
                    "source_url": url + "/openapi.json",
                    "openapi_version": "3.0.3",
                    "document": specification,
                }
            ],
            "metadata_requests": [],
            "network_tested": True,
        },
        "openapi_surface_analyzer": openapi_surface_analyzer,
        "endpoint_analyzer": endpoint,
        "parameter_analyzer": parameters,
        "api_object_discovery": objects,
        "ai_report_writer": lambda target, evidence, **kwargs: {
            "success": True,
            "report_generated": True,
        },
    }
    monkeypatch.setattr(runner_module, "resolve_tool", lambda name: functions[name])
    monkeypatch.setattr(
        normalizer_module, "enforce_scope", lambda url: {"allowed": True}
    )
    monkeypatch.setattr(object_module, "enforce_scope", lambda url: {"allowed": True})
    selected = set(functions)
    result = ToolRunner(tool_timeout=2).run(target, selected_tools=selected)

    assert result["results"]["api_metadata_discovery"]["status"] == "completed"
    openapi_output = result["results"]["openapi_surface_analyzer"]["output"]
    assert openapi_output["operation_count"] == 2
    assert any("/api/orders/{order_id}" in url for url in calls["endpoint"])
    parameter_output = result["results"]["parameter_analyzer"]["output"]
    assert {item["parameter"] for item in parameter_output["parameters"]} >= {
        "order_id",
        "account_id",
    }
    object_output = result["results"]["api_object_discovery"]["output"]
    assert any(item["name"] == "order" for item in object_output["objects"])
    decision = result["normalized_urls"]["adaptive_decision"]
    assert decision["decision"] == "api_metadata_discovery"
    assert decision["automatic"] is True and decision["bounded"] is True


def test_api_reporting_counts_are_grounded_without_vulnerability_promotion():
    results = {
        "api_target_analyzer": {
            "output": {
                "api_likelihood": "high",
                "signals": ["JSON"],
                "decision": {"decision": "api_metadata_discovery"},
            }
        },
        "api_metadata_discovery": {"output": {"document_count": 1}},
        "openapi_surface_analyzer": {
            "output": {
                "route_count": 12,
                "operation_count": 18,
                "parameter_count": 24,
                "object_reference_count": 5,
                "authentication_protected_operation_count": 9,
            }
        },
    }
    package = build_evidence_package(
        "https://example.test", "baseline", results, "start", "end"
    )
    api_surface = package["observed_surface"]["api_surface"]
    assert api_surface["routes_documented"] == 12
    assert api_surface["operations_observed"] == 18
    assert api_surface["object_reference_candidates"] == 5
    assert not package["candidate_findings"]
    assert not package["verified_findings"]


def test_api_surface_report_section_uses_deterministic_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tools.ai_report_writer.ask_agent",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    evidence = {
        "observed_surface": {
            "api_surface": {
                "relevant": True,
                "openapi_document_discovered": True,
                "routes_documented": 12,
                "operations_observed": 18,
                "parameters_observed": 24,
                "object_reference_candidates": 5,
                "authentication_protected_operations": 9,
                "vulnerability_status": "not_assessed",
            }
        },
        "observations": [],
        "candidate_findings": [],
        "verified_findings": [],
        "manual_verification_queue": [],
        "tool_results": {},
        "execution_summary": {},
        "coverage": {},
    }
    result = ai_report_writer(
        "https://example.test", evidence, output_dir=str(tmp_path)
    )
    report = Path(result["report_file"]).read_text(encoding="utf-8")
    assert "## API Surface" in report
    assert "- Routes documented: 12" in report
    assert "- Operations observed: 18" in report
    assert "- Authentication-protected operations: 9" in report
    assert "API vulnerabilities detected" not in report
