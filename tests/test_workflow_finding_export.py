from __future__ import annotations

import json
from typing import Any

import pytest

from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.phase2_campaign import build_campaign_export

TARGET = "https://service.example"


def _session_hypothesis(
    hypothesis_id: str = "hyp-session",
    *,
    resource: str = "/me",
    termination: str = "/sessions/current",
    metadata_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = {
        "workflow_identity": (
            f"session_lifecycle:POST:/sessions->GET:{resource}"
            f"->DELETE:{termination}"
        ),
        "related_surfaces": [
            {
                "boundary_type": "session_creation",
                "method": "POST",
                "path": "/sessions",
            },
            {
                "boundary_type": "authenticated_resource",
                "method": "GET",
                "path": resource,
            },
            {
                "boundary_type": "session_termination",
                "method": "DELETE",
                "path": termination,
            },
        ],
    }
    metadata.update(metadata_overrides or {})
    return {
        "hypothesis_id": hypothesis_id,
        "category": "session_invalidation",
        "status": "verified",
        "confidence": "high",
        "method": "GET",
        "endpoint": f"{TARGET}{resource}",
        "target_surface": {"method": "GET", "path": resource},
        "metadata": metadata,
        "evidence_basis": [{"observation": "structured workflow observed"}],
    }


def _authentication_hypothesis() -> dict[str, Any]:
    return {
        "hypothesis_id": "hyp-authentication",
        "category": "authentication_enforcement",
        "status": "proposed",
        "confidence": "medium",
        "method": "GET",
        "endpoint": f"{TARGET}/me",
        "target_surface": {"method": "GET", "path": "/me"},
        "evidence_basis": [{"observation": "protected resource observed"}],
    }


def _run(run_id: str, hypotheses: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "target": TARGET,
        "assessment_mode": "plan+verify",
        "profile": "authenticated",
        "hypotheses": hypotheses,
        "verification_results": [
            {
                "hypothesis_id": item["hypothesis_id"],
                "status": "verified",
                "confidence": "high",
                "evidence_summary": ["controlled runtime differential"],
                "requests_used": 3,
            }
            for item in hypotheses
            if item["category"] == "session_invalidation"
        ],
        "metrics": {"hypotheses_generated": len(hypotheses)},
    }


def _campaign(*run_ids: str) -> dict[str, Any]:
    return {
        "campaign_id": "workflow-export",
        "name": "workflow-export",
        "target": TARGET,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "run_ids": list(run_ids),
    }


def test_session_workflow_exports_affected_verification_and_workflow_structure() -> (
    None
):
    payload = build_benchmark_export(_run("run-session", [_session_hypothesis()]))
    finding = payload["findings"][0]

    assert finding["affected_functionality"] == "DELETE /sessions/current"
    assert finding["affected_functionality"] != "GET /me"
    assert finding["verification_resource"] == {
        "method": "GET",
        "route_template": "/me",
    }
    assert finding["workflow"] == {
        "type": "session_lifecycle",
        "identity": (
            "session_lifecycle:POST:/sessions->GET:/me" "->DELETE:/sessions/current"
        ),
        "surfaces": [
            {
                "boundary_type": "session_creation",
                "method": "POST",
                "route_template": "/sessions",
            },
            {
                "boundary_type": "authenticated_resource",
                "method": "GET",
                "route_template": "/me",
            },
            {
                "boundary_type": "session_termination",
                "method": "DELETE",
                "route_template": "/sessions/current",
            },
        ],
    }


def test_single_run_and_campaign_agree_on_session_affected_operation() -> None:
    run = _run("run-session", [_session_hypothesis()])
    single = build_benchmark_export(run)["findings"][0]
    campaign = build_campaign_export(_campaign("run-session"), [run])["findings"][0]

    assert single["affected_functionality"] == campaign["affected_functionality"]
    assert single["affected_functionality"] == "DELETE /sessions/current"
    assert single["verification_resource"] == campaign["verification_resource"]
    assert single["workflow"] == campaign["workflow"]


def test_authentication_and_session_findings_on_same_resource_remain_distinct() -> None:
    run = _run(
        "run-combined",
        [_authentication_hypothesis(), _session_hypothesis()],
    )
    findings = build_campaign_export(_campaign("run-combined"), [run])["findings"]

    assert len(findings) == 2
    by_category = {item["category"]: item for item in findings}
    assert by_category["authentication_enforcement"]["affected_functionality"] == (
        "GET /me"
    )
    assert by_category["session_invalidation"]["affected_functionality"] == (
        "DELETE /sessions/current"
    )


def test_campaign_deduplicates_session_workflows_by_termination_operation() -> None:
    first = _run("run-one", [_session_hypothesis("hyp-one", resource="/me")])
    second = _run(
        "run-two",
        [_session_hypothesis("hyp-two", resource="/account")],
    )
    findings = build_campaign_export(_campaign("run-one", "run-two"), [first, second])[
        "findings"
    ]

    assert len(findings) == 1
    assert findings[0]["category"] == "session_invalidation"
    assert findings[0]["affected_functionality"] == "DELETE /sessions/current"


@pytest.mark.parametrize(
    ("category", "method", "route", "parameter"),
    [
        ("bola", "GET", "/orders/{order_id}", "order_id"),
        ("tenant_isolation", "GET", "/tenants/{tenant_id}", "tenant_id"),
        ("vertical_authorization", "GET", "/admin/audit", ""),
        ("mass_assignment", "PATCH", "/profiles/{profile_id}", "role"),
    ],
)
def test_non_workflow_benchmark_export_shape_is_unchanged(
    category: str, method: str, route: str, parameter: str
) -> None:
    hypothesis = {
        "hypothesis_id": f"hyp-{category}",
        "category": category,
        "status": "proposed",
        "confidence": "medium",
        "method": method,
        "parameter": parameter or None,
        "target_surface": {
            "method": method,
            "path": route,
            "parameter": parameter or None,
        },
        "evidence_basis": [{"observation": "structural observation"}],
    }
    finding = build_benchmark_export(_run("run-non-workflow", [hypothesis]))[
        "findings"
    ][0]

    assert finding == {
        "category": category,
        "status": "discovered",
        "confidence": "medium",
        "affected_functionality": " ".join(
            item for item in (method, route, parameter) if item
        ),
        "evidence_summary": ["structural observation"],
        "requests_used": 0,
    }


def test_non_workflow_endpoint_fallback_remains_backward_compatible() -> None:
    hypothesis = {
        "hypothesis_id": "hyp-endpoint-fallback",
        "category": "authentication_enforcement",
        "status": "proposed",
        "confidence": "medium",
        "method": "GET",
        "endpoint": f"{TARGET}/health",
        "evidence_basis": [{"observation": "endpoint observed"}],
    }
    run = _run("run-endpoint-fallback", [hypothesis])

    single = build_benchmark_export(run)["findings"][0]
    campaign = build_campaign_export(_campaign(run["run_id"]), [run])["findings"][0]

    assert single["affected_functionality"] == f"{TARGET}/health"
    assert campaign["affected_functionality"] == "GET /health"


def test_exported_workflow_metadata_excludes_secrets_and_nonstructural_fields() -> None:
    secret = "WORKFLOW_SUPER_SECRET"
    hypothesis = _session_hypothesis(
        metadata_overrides={
            "workflow_identity": f"token:{secret}",
            "related_surfaces": [
                {
                    "boundary_type": "session_creation",
                    "method": f"POST {secret}",
                    "path": "/sessions",
                    "headers": {"Authorization": f"Bearer {secret}"},
                    "password": secret,
                },
                {
                    "boundary_type": "authenticated_resource",
                    "method": "GET",
                    "path": f"/me?token={secret}",
                    "cookie": secret,
                    "parameter": secret,
                },
                {
                    "boundary_type": "session_termination",
                    "method": "DELETE",
                    "path": "/sessions/current",
                    "credential_reference": secret,
                },
                {
                    "boundary_type": f"credential_reference:{secret}",
                    "method": "GET",
                    "path": "/must-not-export",
                },
            ],
        }
    )
    finding = build_benchmark_export(_run("run-secret-safe", [hypothesis]))["findings"][
        0
    ]
    rendered = json.dumps(finding["workflow"])

    assert secret not in rendered
    assert finding["verification_resource"]["route_template"] == "/me"
    assert all(
        set(surface) <= {"boundary_type", "method", "route_template", "parameter"}
        for surface in finding["workflow"]["surfaces"]
    )
