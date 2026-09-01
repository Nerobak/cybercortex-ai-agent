from __future__ import annotations

import json
from typing import Any

import pytest
import requests

import agent_core.result_normalizer as normalizer_module
import tools.api_metadata_discovery as metadata_module
import tools.openapi_surface_analyzer as openapi_module
from agent_core.attack_surface import build_canonical_attack_surface
from agent_core.result_normalizer import build_evidence_package, normalize_url_evidence
from agent_core.tool_runner import ToolRunner
from tools.api_metadata_discovery import api_metadata_discovery
from tools.openapi_surface_analyzer import openapi_surface_analyzer


def _json_request_body(schema: dict[str, Any]) -> dict[str, Any]:
    return {"content": {"application/json": {"schema": schema}}}


def _route_preservation_document() -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "PasswordResetRequest": {
                    "type": "object",
                    "required": ["email"],
                    "properties": {"email": {"type": "string"}},
                },
                "PasswordResetConfirmation": {
                    "type": "object",
                    "required": ["verification_code", "new_password"],
                    "properties": {
                        "verification_code": {
                            "anyOf": [{"type": "string"}, {"type": "null"}],
                            "nullable": True,
                        },
                        "new_password": {
                            "anyOf": [{"type": "string"}, {"type": "null"}]
                        },
                    },
                },
                "SessionCredentials": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": {"type": "string"},
                        "password": {"type": "string"},
                    },
                },
            },
        },
        "paths": {
            "/account/reset": {
                "post": {
                    "operationId": "request_account_reset",
                    "summary": "Start account recovery",
                    "requestBody": _json_request_body(
                        {"$ref": "#/components/schemas/PasswordResetRequest"}
                    ),
                    "responses": {
                        "202": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/UnavailableReply"
                                    }
                                }
                            }
                        }
                    },
                }
            },
            "/account/reset/confirm": {
                "post": {
                    "operationId": "confirm_account_reset",
                    "summary": "Complete account recovery",
                    "requestBody": _json_request_body(
                        {"$ref": ("#/components/schemas/PasswordResetConfirmation")}
                    ),
                    "responses": {"204": {}},
                }
            },
            "/credentials/password": {
                "post": {
                    "operationId": "rotate_primary_credential",
                    "responses": {"202": {}},
                }
            },
            "/sessions": {
                "post": {
                    "operationId": "create_auth_session",
                    "summary": "Sign in",
                    "requestBody": _json_request_body(
                        {"$ref": "#/components/schemas/SessionCredentials"}
                    ),
                    "responses": {
                        "200": {
                            "headers": {"Set-Cookie": {"schema": {"type": "string"}}}
                        }
                    },
                }
            },
            "/sessions/current": {
                "delete": {
                    "operationId": "delete_current_session",
                    "summary": "Sign out",
                    "responses": {"204": {}},
                }
            },
            "/me": {
                "get": {
                    "operationId": "read_current_profile",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {}},
                }
            },
            "/accounts/{account_id}/settings": {
                "get": {
                    "operationId": "read_account_settings",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "account_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {}},
                }
            },
        },
    }


class _MetadataClient:
    requests_used = 0

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    def request(self, method: str, url: str, **kwargs: Any):
        del method, kwargs
        self.requests_used += 1
        response = requests.Response()
        response.url = url
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(self.document).encode()
        return response, []


@pytest.fixture
def recovery_pipeline(monkeypatch):
    target = "https://routes.example"
    document = _route_preservation_document()
    monkeypatch.setattr(metadata_module, "enforce_scope", lambda url: {"allowed": True})
    monkeypatch.setattr(
        normalizer_module, "enforce_scope", lambda url: {"allowed": True}
    )

    fetched = api_metadata_discovery(
        target,
        max_requests=1,
        http_client=_MetadataClient(document),
    )
    metadata_envelope = ToolRunner()._envelope(
        "api_metadata_discovery", "completed", output=fetched
    )
    analyzed = openapi_surface_analyzer(metadata_envelope["output"]["documents"])
    results = {
        "api_metadata_discovery": metadata_envelope,
        "openapi_surface_analyzer": {
            "status": "completed",
            "success": True,
            "output": analyzed,
        },
    }
    normalized = normalize_url_evidence(target, results)
    package = build_evidence_package(
        target,
        "baseline",
        results,
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:01+00:00",
        surface=normalized,
    )
    canonical = build_canonical_attack_surface(target, assessment=package)
    return {
        "document": document,
        "fetched": fetched,
        "metadata_envelope": metadata_envelope,
        "analyzed": analyzed,
        "normalized": normalized,
        "package": package,
        "canonical": canonical,
    }


def _identities(routes: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {(item["method"], item["path"]) for item in routes}


def test_routes_exist_at_every_openapi_and_attack_surface_stage(recovery_pipeline):
    expected = {
        ("POST", "/account/reset"),
        ("POST", "/account/reset/confirm"),
        ("POST", "/credentials/password"),
        ("POST", "/sessions"),
        ("DELETE", "/sessions/current"),
        ("GET", "/me"),
        ("GET", "/accounts/{account_id}/settings"),
    }
    fetched_paths = recovery_pipeline["fetched"]["documents"][0]["document"]["paths"]
    envelope_paths = recovery_pipeline["metadata_envelope"]["output"]["documents"][0][
        "document"
    ]["paths"]

    assert set(fetched_paths) == {path for _, path in expected}
    assert set(envelope_paths) == {path for _, path in expected}
    assert _identities(recovery_pipeline["analyzed"]["routes"]) == expected
    assert _identities(recovery_pipeline["normalized"]["routes"]) == expected
    packaged_routes = recovery_pipeline["package"]["observed_surface"][
        "attack_surface"
    ]["routes"]
    assert _identities(packaged_routes) == expected
    assert _identities(recovery_pipeline["canonical"].routes) == expected


def test_related_post_routes_remain_distinct_normalized_routes(recovery_pipeline):
    recovery_routes = {
        (item["method"], item["path"], item["operation_id"])
        for item in recovery_pipeline["canonical"].routes
        if item["path"].startswith("/account/reset")
    }
    assert recovery_routes == {
        ("POST", "/account/reset", "request_account_reset"),
        ("POST", "/account/reset/confirm", "confirm_account_reset"),
    }


def test_request_ref_and_nullable_anyof_fields_survive(recovery_pipeline):
    routes = {item["path"]: item for item in recovery_pipeline["canonical"].routes}
    assert {item["name"] for item in routes["/account/reset"]["request_fields"]} == {
        "email"
    }
    completion_fields = {
        item["name"]: item["schema_type"]
        for item in routes["/account/reset/confirm"]["request_fields"]
    }
    assert completion_fields == {
        "new_password": "string",
        "verification_code": "string",
    }


def test_incomplete_response_no_parameters_and_no_security_preserve_route(
    recovery_pipeline,
):
    route = next(
        item
        for item in recovery_pipeline["canonical"].routes
        if item["path"] == "/account/reset"
    )
    assert route["response_status_codes"] == ["202"]
    assert route["parameters"] == []
    assert route["security_required"] is False
    assert route["operation_id"] == "request_account_reset"
    assert route["summary"] == "start account recovery"
    assert route["limitations"] == [
        "OpenAPI response schema metadata contains an unresolved local reference; "
        "route identity was preserved."
    ]


def test_session_and_bola_routes_remain_unchanged(recovery_pipeline):
    surface = recovery_pipeline["canonical"]
    routes = {(item["method"], item["path"]) for item in surface.routes}
    assert {
        ("POST", "/sessions"),
        ("DELETE", "/sessions/current"),
        ("GET", "/me"),
    } <= routes
    assert any(
        item["type"] == "account"
        and item["identifier"] == "account_id"
        and item["path"] == "/accounts/{account_id}/settings"
        for item in surface.objects
    )


def test_exact_method_and_normalized_path_duplicates_are_deduplicated():
    duplicated = [
        {
            "method": "post",
            "path": "/account/reset/",
            "url": "https://one.example/account/reset/",
            "source": "openapi",
        },
        {
            "method": "POST",
            "path": "//account//reset",
            "url": "https://two.example/account/reset",
            "source": "captured_request",
        },
    ]
    surface = build_canonical_attack_surface(
        "https://routes.example",
        assessment={"observed_surface": {"attack_surface": {"routes": duplicated}}},
    )

    assert [(item["method"], item["path"]) for item in surface.routes] == [
        ("POST", "/account/reset")
    ]


def test_metadata_extraction_error_preserves_minimal_route_and_continues(monkeypatch):
    document = {
        "openapi": "3.0.3",
        "paths": {
            "/account/reset": {
                "post": {
                    "operationId": "request_account_reset",
                    "summary": "Start account recovery",
                    "requestBody": _json_request_body(
                        {
                            "type": "object",
                            "properties": {"email": {"type": "string"}},
                        }
                    ),
                    "responses": {"202": {}},
                }
            },
            "/health": {"get": {"responses": {"200": {}}}},
        },
    }

    def fail_schema_extraction(*args: Any, **kwargs: Any):
        del args, kwargs
        raise RuntimeError("synthetic metadata failure")

    monkeypatch.setattr(openapi_module, "_schema_fields", fail_schema_extraction)
    analyzed = openapi_surface_analyzer(document)
    routes = {(item["method"], item["path"]): item for item in analyzed["routes"]}
    preserved = routes[("POST", "/account/reset")]

    assert analyzed["success"] is True
    assert set(routes) == {("POST", "/account/reset"), ("GET", "/health")}
    assert preserved["operation_id"] == "request_account_reset"
    assert preserved["summary"] == "start account recovery"
    assert preserved["request_fields"] == []
    assert preserved["limitations"] == [
        "OpenAPI operation metadata extraction was incomplete (RuntimeError); "
        "route identity was preserved."
    ]

    surface = build_canonical_attack_surface(
        "https://routes.example",
        assessment={
            "observed_surface": {"attack_surface": {"routes": analyzed["routes"]}}
        },
    )
    assert preserved["limitations"][0] in surface.limitations


def test_recovery_semantics_create_two_boundaries_and_one_workflow(
    recovery_pipeline,
):
    surface = recovery_pipeline["canonical"]
    recovery_boundaries = {
        (item["boundary_type"], item["path"])
        for item in surface.auth_boundaries
        if item["boundary_type"].startswith("recovery_")
    }
    assert recovery_boundaries == {
        ("recovery_start", "/account/reset"),
        ("recovery_completion", "/account/reset/confirm"),
    }
    workflows = [
        item
        for item in surface.workflows
        if item["workflow_type"] == "account_recovery"
    ]
    assert len(workflows) == 1
