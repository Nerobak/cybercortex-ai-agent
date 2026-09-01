from __future__ import annotations

import json

import pytest

from agent_core.attack_surface import build_canonical_attack_surface
from agent_core.hypothesis_engine import generate_surface_hypotheses
from agent_core.phase2_reporter import render_phase2_report
from agent_core.result_normalizer import build_evidence_package, normalize_url_evidence
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from tools.openapi_surface_analyzer import openapi_surface_analyzer


def _request_schema(*fields: str) -> dict[str, object]:
    return {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {name: {"type": "string"} for name in fields},
                }
            }
        }
    }


def _authorization_parameter() -> dict[str, object]:
    return {
        "name": "Authorization",
        "in": "header",
        "required": False,
        "schema": {"type": "string"},
    }


def _surface(document: dict[str, object]):
    analyzed = openapi_surface_analyzer(document)
    assert analyzed["success"] is True
    return build_canonical_attack_surface(
        "https://synthetic.example",
        assessment={
            "observed_surface": {
                "attack_surface": {
                    "routes": analyzed["routes"],
                    "parameters": analyzed["parameters"],
                    "objects": analyzed["objects"],
                    "authentication_boundaries": analyzed["authentication_boundaries"],
                    "sources": {"openapi": "synthetic document"},
                }
            }
        },
    )


def _semantic_document() -> dict[str, object]:
    return {
        "openapi": "3.0.3",
        "paths": {
            "/auth/login": {
                "post": {
                    "operationId": "create_auth_session",
                    "summary": "Sign in",
                    "requestBody": _request_schema("email", "password"),
                    "responses": {
                        "200": {
                            "headers": {"Set-Cookie": {"schema": {"type": "string"}}},
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "access_token": {"type": "string"}
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/signout": {
                "delete": {
                    "operationId": "invalidate_current_session",
                    "summary": "Sign out",
                    "parameters": [_authorization_parameter()],
                    "responses": {"204": {"description": "done"}},
                }
            },
            "/profile": {
                "get": {
                    "operationId": "read_current_profile",
                    "summary": "Current profile",
                    "parameters": [_authorization_parameter()],
                    "responses": {
                        "200": {"description": "ok"},
                        "401": {"description": "authentication required"},
                    },
                }
            },
            "/account/reset/request": {
                "post": {
                    "operationId": "request_account_reset",
                    "summary": "Start account recovery",
                    "requestBody": _request_schema("email"),
                    "responses": {"202": {"description": "accepted"}},
                }
            },
            "/account/reset/confirm": {
                "post": {
                    "operationId": "confirm_account_reset",
                    "summary": "Complete account recovery",
                    "requestBody": _request_schema("reset_token", "new_password"),
                    "responses": {"204": {"description": "done"}},
                }
            },
            "/projects/{project_id}/settings": {
                "get": {
                    "operationId": "read_project_settings",
                    "parameters": [
                        {
                            "name": "project_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        _authorization_parameter(),
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def test_openapi_auth_semantics_populate_boundaries_workflows_and_hypotheses():
    surface = _surface(_semantic_document())

    assert (
        next(
            item["summary"] for item in surface.routes if item["path"] == "/auth/login"
        )
        == "sign in"
    )

    by_type: dict[str, set[str]] = {}
    for boundary in surface.auth_boundaries:
        by_type.setdefault(boundary["boundary_type"], set()).add(boundary["path"])

    assert "/auth/login" in by_type["session_creation"]
    assert "/signout" in by_type["session_termination"]
    assert {"/profile", "/projects/{project_id}/settings"} <= by_type[
        "authenticated_resource"
    ]
    assert by_type["recovery_start"] == {"/account/reset/request"}
    assert by_type["recovery_completion"] == {"/account/reset/confirm"}
    login = next(
        item
        for item in surface.auth_boundaries
        if item["path"] == "/auth/login" and item["boundary_type"] == "session_creation"
    )
    assert "response_metadata:sets_session_cookie" in login["evidence"]
    assert "response_shape:credential_or_token_field" in login["evidence"]
    profile = next(
        item
        for item in surface.auth_boundaries
        if item["path"] == "/profile"
        and item["boundary_type"] == "authenticated_resource"
    )
    assert "current_user_resource" in profile["semantic_classes"]
    assert "header_parameter:authorization_or_session" in profile["evidence"]
    assert profile["confidence"] == "medium"

    workflows = {item["workflow_type"]: item for item in surface.workflows}
    assert [
        step["boundary_type"] for step in workflows["account_recovery"]["steps"]
    ] == ["recovery_start", "recovery_completion"]
    assert [
        step["boundary_type"] for step in workflows["session_lifecycle"]["steps"]
    ] == ["session_creation", "authenticated_resource", "session_termination"]

    hypotheses = generate_surface_hypotheses(surface)
    categories = {item.category for item in hypotheses}
    assert {
        "authentication_enforcement",
        "session_invalidation",
        "recovery_state_enforcement",
        "rate_limit_enforcement",
        "bola",
    } <= categories
    assert "business_logic_state_enforcement" not in categories
    assert sum(item.category == "rate_limit_enforcement" for item in hypotheses) == 2
    assert sum(item.category == "session_invalidation" for item in hypotheses) == 1
    assert (
        sum(item.category == "recovery_state_enforcement" for item in hypotheses) == 1
    )
    assert (
        sum(
            item.category == "rate_limit_enforcement"
            and item.target_surface["path"] == "/auth/login"
            for item in hypotheses
        )
        == 1
    )
    assert any(
        item.category == "bola"
        and item.target_surface["path"] == "/projects/{project_id}/settings"
        for item in hypotheses
    )

    auth_categories = {
        "authentication_enforcement",
        "session_invalidation",
        "recovery_state_enforcement",
        "rate_limit_enforcement",
    }
    for hypothesis in (item for item in hypotheses if item.category in auth_categories):
        assert hypothesis.target_surface["method"]
        assert hypothesis.target_surface["path"].startswith("/")
        assert hypothesis.evidence_basis
        assert hypothesis.required_context
        assert isinstance(hypothesis.safe_verification_possible, bool)
        assert hypothesis.limitations
        assert hypothesis.metadata["bounded_verification_objective"]
        assert hypothesis.status.value == "proposed"
        if hypothesis.category == "rate_limit_enforcement":
            assert hypothesis.metadata["automatic_execution_allowed"] is (
                hypothesis.target_surface["path"] == "/auth/login"
            )
        if hypothesis.category == "recovery_state_enforcement":
            assert hypothesis.metadata["typed_adapter_required"] is False
            assert (
                hypothesis.metadata["execution_status"]
                == "typed_verification_available"
            )
        if hypothesis.category == "session_invalidation":
            assert hypothesis.metadata["typed_adapter_required"] is False
            assert (
                hypothesis.metadata["execution_status"]
                == "typed_verification_available"
            )

    session = next(
        item for item in hypotheses if item.category == "session_invalidation"
    )
    assert session.target_surface["path"] == "/profile"
    assert [item["boundary_type"] for item in session.metadata["related_surfaces"]] == [
        "session_creation",
        "authenticated_resource",
        "session_termination",
    ]
    assert session.required_context == [
        "one controlled authenticated account",
        "controlled session acquisition capability",
    ]


@pytest.mark.parametrize(
    ("path", "operation_id", "summary"),
    [
        ("/auth/login", "login_with_credentials", "Login"),
        ("/api/session", "create_api_session", "Create authenticated session"),
        ("/sign-in", "sign_in_with_credentials", "Sign in"),
    ],
)
def test_login_alternate_naming_requires_credentials_and_semantics(
    path: str, operation_id: str, summary: str
):
    surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                path: {
                    "post": {
                        "operationId": operation_id,
                        "summary": summary,
                        "requestBody": _request_schema("username", "passphrase"),
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
    )

    boundaries = {item["boundary_type"] for item in surface.auth_boundaries}
    assert "session_creation" in boundaries


def test_openapi_security_metadata_becomes_typed_authenticated_resource():
    surface = _surface(
        {
            "openapi": "3.0.3",
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
            },
            "paths": {
                "/private/dashboard": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
    )

    assert len(surface.auth_boundaries) == 1
    boundary = surface.auth_boundaries[0]
    assert boundary["boundary_type"] == "authenticated_resource"
    assert boundary["semantic_classes"] == ["protected_authenticated_resource"]
    assert boundary["method"] == "GET"
    assert boundary["path"] == "/private/dashboard"
    assert "openapi_security:declared" in boundary["evidence"]
    assert boundary["evidence_sources"] == ["openapi"]
    assert boundary["confidence"] == "high"
    assert boundary["rate_sensitive_candidate"] is False
    assert boundary["source"] == "auth_semantic_classifier"


def test_nullable_and_ambiguous_credential_types_preserve_login_semantics():
    nullable_surface = _surface(
        {
            "openapi": "3.1.0",
            "components": {
                "schemas": {
                    "CredentialText": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "LoginInput": {
                        "type": "object",
                        "properties": {
                            "username": {"$ref": "#/components/schemas/CredentialText"},
                            "password": {
                                "nullable": True,
                                "allOf": [
                                    {"$ref": "#/components/schemas/CredentialText"}
                                ],
                            },
                        },
                    },
                }
            },
            "paths": {
                "/session": {
                    "post": {
                        "operationId": "login_session",
                        "summary": "Login",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/LoginInput"
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
    )
    fields = {
        item["name"]: item["schema_type"]
        for item in nullable_surface.routes[0]["request_fields"]
    }
    assert fields == {"password": "string", "username": "string"}
    assert any(
        item["boundary_type"] == "session_creation"
        for item in nullable_surface.auth_boundaries
    )

    ambiguous_surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                "/auth/login": {
                    "post": {
                        "operationId": "login_with_credentials",
                        "summary": "Login",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "email": {"type": "string"},
                                            "password": {"type": "object"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
    )
    login = next(
        item
        for item in ambiguous_surface.auth_boundaries
        if item["boundary_type"] == "session_creation"
    )
    assert login["confidence"] == "high"
    assert "request_shape:credential_field_types_ambiguous" in login["evidence"]


def test_session_lifecycle_alternate_route_names_correlate():
    surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                "/sign-in": {
                    "post": {
                        "operationId": "sign_in",
                        "requestBody": _request_schema("username", "password"),
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/whoami": {
                    "get": {
                        "operationId": "whoami",
                        "parameters": [_authorization_parameter()],
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/session/current": {
                    "delete": {
                        "operationId": "delete_current_session",
                        "parameters": [_authorization_parameter()],
                        "responses": {"204": {"description": "done"}},
                    }
                },
            },
        }
    )

    assert {item["boundary_type"] for item in surface.auth_boundaries} >= {
        "session_creation",
        "authenticated_resource",
        "session_termination",
    }
    workflow = next(
        item
        for item in surface.workflows
        if item["workflow_type"] == "session_lifecycle"
    )
    assert [item["path"] for item in workflow["steps"]] == [
        "/sign-in",
        "/whoami",
        "/session/current",
    ]


def test_unrelated_recovery_families_do_not_correlate_by_host():
    surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                "/account/reset/request": {
                    "post": {
                        "operationId": "request_account_reset",
                        "requestBody": _request_schema("email"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/auth/password-recovery/confirm": {
                    "post": {
                        "operationId": "confirm_password_recovery",
                        "requestBody": _request_schema("reset_token", "new_password"),
                        "responses": {"204": {"description": "done"}},
                    }
                },
            },
        }
    )

    assert {item["boundary_type"] for item in surface.auth_boundaries} >= {
        "recovery_start",
        "recovery_completion",
    }
    assert not any(
        item["workflow_type"] == "account_recovery" for item in surface.workflows
    )


def test_all_openapi_operations_survive_evidence_normalization():
    shared_operation = {
        "operationId": "submit_catalog_entry",
        "requestBody": _request_schema("email"),
        "responses": {"202": {"description": "accepted"}},
    }
    paths = {
        f"/{index:03d}/catalog": {"post": shared_operation} for index in range(105)
    }
    paths["/account/reset/request"] = {
        "post": {
            **shared_operation,
            "operationId": "request_account_reset",
            "summary": "Start account recovery",
        }
    }
    paths["/account/reset/confirm"] = {
        "post": {
            **shared_operation,
            "operationId": "confirm_account_reset",
            "summary": "Complete account recovery",
            "requestBody": _request_schema("reset_token", "new_password"),
        }
    }
    analyzed = openapi_surface_analyzer({"openapi": "3.0.3", "paths": paths})
    assert analyzed["success"] is True
    results = {
        "openapi_surface_analyzer": {
            "status": "completed",
            "success": True,
            "output": analyzed,
        }
    }
    normalized = normalize_url_evidence("https://synthetic.example", results)
    package = build_evidence_package(
        "https://synthetic.example",
        "baseline",
        results,
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:01+00:00",
        surface=normalized,
    )
    routes = package["observed_surface"]["attack_surface"]["routes"]

    assert len(routes) == len(paths)
    assert {(item["method"], item["path"]) for item in routes} == {
        ("POST", path) for path in paths
    }
    canonical = build_canonical_attack_surface(
        "https://synthetic.example", assessment=package
    )
    assert len(canonical.routes) == len(paths)
    assert {item["path"] for item in canonical.routes} >= {
        "/account/reset/request",
        "/account/reset/confirm",
    }
    assert {item["boundary_type"] for item in canonical.auth_boundaries} >= {
        "recovery_start",
        "recovery_completion",
    }


def test_false_positive_routes_and_business_token_field_are_not_auth_boundaries():
    surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                "/newsletter/subscribe": {
                    "post": {
                        "summary": "Subscribe to news",
                        "requestBody": _request_schema("email"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/newsletter": {
                    "post": {
                        "summary": "Subscribe",
                        "requestBody": _request_schema("email"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/data-recovery/start": {
                    "post": {
                        "summary": "Start data recovery",
                        "requestBody": _request_schema("email"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/user/preferences": {
                    "post": {
                        "summary": "Update user preferences",
                        "requestBody": _request_schema("password_hint"),
                        "responses": {"204": {"description": "done"}},
                    }
                },
                "/sessions/archive": {
                    "delete": {
                        "operationId": "archive_session_records",
                        "summary": "Archive old records",
                        "responses": {"204": {"description": "done"}},
                    }
                },
                "/records/archive": {
                    "delete": {
                        "summary": "Archive session records after logout",
                        "responses": {"204": {"description": "done"}},
                    }
                },
                "/media/me.jpg": {
                    "get": {"responses": {"200": {"description": "image"}}}
                },
                "/reports/complete": {
                    "post": {
                        "summary": "Complete report",
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/ops/disaster/recovery/confirm": {
                    "post": {
                        "summary": "Confirm disaster recovery",
                        "requestBody": _request_schema("verification_code"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/files/recovery/complete": {
                    "post": {
                        "summary": "Complete file recovery",
                        "requestBody": _request_schema("reset_token"),
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/data/restore/complete": {
                    "post": {
                        "summary": "Complete data restore",
                        "responses": {"202": {"description": "accepted"}},
                    }
                },
                "/inventory/token": {
                    "post": {
                        "summary": "Store business token",
                        "requestBody": _request_schema("token"),
                        "responses": {"201": {"description": "created"}},
                    }
                },
            },
        }
    )

    assert surface.auth_boundaries == []
    assert surface.workflows == []
    categories = {item.category for item in generate_surface_hypotheses(surface)}
    assert not categories & {
        "authentication_enforcement",
        "session_invalidation",
        "recovery_state_enforcement",
        "rate_limit_enforcement",
    }


def test_incomplete_session_and_recovery_workflows_do_not_generate_hypotheses():
    login_without_logout = _semantic_document()
    del login_without_logout["paths"]["/signout"]
    categories = {
        item.category
        for item in generate_surface_hypotheses(_surface(login_without_logout))
    }
    assert "session_invalidation" not in categories
    assert "authentication_enforcement" in categories

    login_and_logout_without_resource = _semantic_document()
    del login_and_logout_without_resource["paths"]["/profile"]
    del login_and_logout_without_resource["paths"]["/projects/{project_id}/settings"]
    categories = {
        item.category
        for item in generate_surface_hypotheses(
            _surface(login_and_logout_without_resource)
        )
    }
    assert "session_invalidation" not in categories

    recovery_start_only = _semantic_document()
    del recovery_start_only["paths"]["/account/reset/confirm"]
    categories = {
        item.category
        for item in generate_surface_hypotheses(_surface(recovery_start_only))
    }
    assert "recovery_state_enforcement" not in categories


def test_duplicate_semantic_channels_generate_one_hypothesis_per_workflow_category():
    hypotheses = generate_surface_hypotheses(_surface(_semantic_document()))

    assert sum(item.category == "session_invalidation" for item in hypotheses) == 1
    assert (
        sum(item.category == "recovery_state_enforcement" for item in hypotheses) == 1
    )


def test_duplicate_route_metadata_does_not_duplicate_boundaries_or_workflows():
    analyzed = openapi_surface_analyzer(_semantic_document())
    surface = build_canonical_attack_surface(
        "https://synthetic.example",
        assessment={
            "observed_surface": {
                "attack_surface": {
                    "routes": [*analyzed["routes"], *analyzed["routes"]],
                    "parameters": [
                        *analyzed["parameters"],
                        *analyzed["parameters"],
                    ],
                    "authentication_boundaries": [
                        *analyzed["authentication_boundaries"],
                        *analyzed["authentication_boundaries"],
                    ],
                }
            }
        },
    )

    identities = [
        (item["method"], item["path"], item["boundary_type"])
        for item in surface.auth_boundaries
    ]
    assert len(identities) == len(set(identities))
    assert [item["workflow_type"] for item in surface.workflows].count(
        "session_lifecycle"
    ) == 1
    assert [item["workflow_type"] for item in surface.workflows].count(
        "account_recovery"
    ) == 1
    hypotheses = generate_surface_hypotheses(surface)
    assert (
        sum(
            item.category == "rate_limit_enforcement"
            and item.target_surface["path"] == "/auth/login"
            for item in hypotheses
        )
        == 1
    )


def test_one_time_code_auth_verification_is_rate_sensitive_but_not_executable():
    surface = _surface(
        {
            "openapi": "3.0.3",
            "paths": {
                "/auth/mfa/verify": {
                    "post": {
                        "operationId": "verify_authentication_otp",
                        "summary": "Verify authentication factor",
                        "requestBody": _request_schema("otp"),
                        "responses": {"204": {"description": "done"}},
                    }
                }
            },
        }
    )

    hypotheses = generate_surface_hypotheses(surface)
    rate = next(
        item for item in hypotheses if item.category == "rate_limit_enforcement"
    )
    assert rate.safe_verification_possible is False
    assert "runtime controls are unknown" in rate.rationale
    assert rate.metadata["automatic_execution_allowed"] is False
    assert rate.required_context == [
        "explicit authorization for rate-limit verification",
        "explicit bounded attempt policy",
        "controlled account or researcher-controlled recovery resource",
    ]


def test_auth_workflow_plans_are_bounded_and_expose_typed_adapter_status():
    hypotheses = generate_surface_hypotheses(_surface(_semantic_document()))
    planner = VerificationPlanner()
    context = VerificationPlanningContext(
        controlled_accounts=["controlled-a"],
        credential_accounts=["controlled-a"],
    )

    session = next(
        item for item in hypotheses if item.category == "session_invalidation"
    )
    session_plan = planner.create_plan(session, context)
    session_requests = session_plan.steps[0].metadata["requests"]
    assert len(session_requests) == 4
    assert session_requests[1]["url"] == session_requests[3]["url"]
    assert session_requests[1]["replay"] is False
    assert session_requests[3]["replay"] is True
    assert session_plan.steps[0].metadata["session_binding"] == (
        "same_controlled_session"
    )
    assert session_plan.automatic_execution_allowed is True
    assert session_plan.steps[0].metadata["typed_adapter_required"] is False

    recovery = next(
        item for item in hypotheses if item.category == "recovery_state_enforcement"
    )
    recovery_plan = planner.create_plan(recovery, context)
    assert recovery_plan.estimated_requests == 5
    assert recovery_plan.automatic_execution_allowed is True
    assert recovery_plan.steps[0].metadata["request_accounting"] == {
        "challenge_issuance_recovery_requests": 1,
        "resume_recovery_completion_requests": 2,
        "resume_authentication_state_confirmation_requests": 1,
        "external_cleanup_verification_requests": 1,
        "phase_a1_challenge_issuance_requests": 1,
        "phase_a2_resume_requests": 3,
        "phase_b_cleanup_confirmation_requests": 1,
        "external_cleanup_may_be_required": True,
    }
    assert all(
        request["account_id"] == "controlled-a"
        for request in recovery_plan.steps[0].metadata["requests"]
    )

    rate = next(
        item
        for item in hypotheses
        if item.category == "rate_limit_enforcement"
        and item.target_surface["path"] == "/auth/login"
    )
    rate_plan = planner.create_plan(rate, context)
    assert rate_plan.estimated_requests == 7
    assert rate_plan.request_budget == 7
    assert rate_plan.steps[0].network is True
    assert rate_plan.steps[0].metadata["requests"] == []
    assert rate_plan.automatic_execution_allowed is False


def test_report_explains_auth_surface_without_credential_values():
    document = _semantic_document()
    document["paths"]["/auth/login"]["post"][
        "summary"
    ] = "Login synthetic-summary-secret-must-not-survive"
    password_schema = document["paths"]["/auth/login"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]["properties"]["password"]
    password_schema["example"] = "synthetic-secret-must-not-survive"
    surface = _surface(document)
    hypotheses = generate_surface_hypotheses(surface)
    report = render_phase2_report(
        {
            "attack_surface": surface.model_dump(mode="json"),
            "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
        }
    )

    assert "Authentication boundary types:" in report
    assert "Authentication workflow candidates: 2" in report
    assert (
        "Authentication workflow types: account_recovery=1, session_lifecycle=1"
        in report
    )
    assert "Workflow candidate account_recovery" in report
    assert "evidence source=openapi" in report
    assert "does not prove runtime enforcement" in report
    assert "Related authentication surfaces:" in report
    assert "Evidence basis:" in report
    assert "Required context:" in report
    assert "Safe verification possible:" in report
    assert "Adapter status: plan_only_surface" in report
    encoded = json.dumps(surface.model_dump(mode="json")) + report
    assert "synthetic-secret-must-not-survive" not in encoded
    assert "synthetic-summary-secret-must-not-survive" not in encoded
