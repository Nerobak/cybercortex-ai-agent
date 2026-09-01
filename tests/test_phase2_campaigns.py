from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.phase2_campaign import (
    Phase2CampaignStore,
    build_campaign_export,
    campaign_snapshot_hash,
)
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.result_normalizer import redact
from agent_core.result_provenance import RESULT_SCHEMA_VERSION
from agent_core.verification_capabilities import typed_producer_provenance
from phase2_cli import build_parser

TARGET = "http://127.0.0.1:8101"


def _hypothesis(
    hypothesis_id: str,
    category: str,
    route: str,
    parameter: str,
    *,
    status: str = "proposed",
    confidence: str = "medium",
    source: str = "openapi",
) -> dict[str, Any]:
    return {
        "hypothesis_id": hypothesis_id,
        "category": category,
        "status": status,
        "confidence": confidence,
        "method": "GET",
        "parameter": parameter,
        "target_surface": {
            "method": "GET",
            "path": route,
            "parameter": parameter,
        },
        "evidence_refs": [f"{source}-reference"],
        "evidence_basis": [
            {
                "source": source,
                "reference": f"{source}-reference",
                "observation": f"Observed {parameter} on {route}",
            }
        ],
    }


def _run(
    run_id: str,
    hypothesis: dict[str, Any],
    *,
    result_status: str | None = None,
    result_confidence: str = "high",
    evidence: str = "controlled differential",
    target: str = TARGET,
    mode: str = "plan",
    metrics: dict[str, int] | None = None,
) -> dict[str, Any]:
    results = []
    if result_status:
        results.append(
            {
                "hypothesis_id": hypothesis["hypothesis_id"],
                "category": hypothesis["category"],
                "status": result_status,
                "confidence": result_confidence,
                "evidence_summary": [evidence],
                "correlated_sources": [f"verification-{run_id}"],
                "requests_used": 2,
                "result_schema_version": RESULT_SCHEMA_VERSION,
                "executor": typed_producer_provenance(hypothesis["category"]),
            }
        )
    return {
        "run_id": run_id,
        "target": target,
        "assessment_mode": mode,
        "profile": "authenticated",
        "hypotheses": [hypothesis],
        "verification_results": results,
        "metrics": metrics
        or {
            "discovery_requests": 1,
            "auth_requests": 2,
            "object_acquisition_requests": 0,
            "verification_requests": 2 if result_status else 0,
            "total_requests": 5 if result_status else 1,
            "hypotheses_generated": 1,
        },
    }


@pytest.fixture
def campaign_storage(tmp_path: Path) -> tuple[Phase2RunStore, Phase2CampaignStore]:
    runs = Phase2RunStore(tmp_path / "runs")
    campaigns = Phase2CampaignStore(tmp_path / "campaigns", run_store=runs)
    campaigns.create("api-lab-phase2", TARGET)
    return runs, campaigns


def test_campaign_accumulates_independent_verified_runs_without_secret_leakage(
    campaign_storage: tuple[Phase2RunStore, Phase2CampaignStore], tmp_path: Path
) -> None:
    runs, campaigns = campaign_storage
    bola = _hypothesis(
        "hyp-bola-a", "bola", "/orders/{order_id}", "order_id", source="openapi-a"
    )
    tenant = _hypothesis(
        "hyp-tenant-b",
        "tenant_isolation",
        "/tenants/{tenant_id}/projects",
        "tenant_id",
        source="openapi-b",
    )
    run_a = _run(
        "run-a",
        bola,
        result_status="verified",
        evidence="Authorization: Bearer CAMPAIGN_SECRET_TOKEN",
        metrics={
            "discovery_requests": 1,
            "auth_requests": 2,
            "object_acquisition_requests": 1,
            "verification_requests": 2,
            "total_requests": 5,
            "hypotheses_generated": 1,
        },
    )
    run_a["benchmark_answer_id"] = "BENCHMARK-ANSWER-A"
    run_a["verification_results"][0]["token"] = "RAW_RESULT_TOKEN"
    run_b = _run(
        "run-b",
        tenant,
        result_status="verified",
        evidence="token=ANOTHER_CAMPAIGN_SECRET",
        mode="verify",
        metrics={
            "discovery_requests": 2,
            "auth_requests": 2,
            "object_acquisition_requests": 0,
            "verification_requests": 2,
            "total_requests": 6,
            "hypotheses_generated": 1,
        },
    )
    runs.save(run_a)
    runs.save(run_b)
    campaigns.add_run("api-lab-phase2", "run-a")
    campaigns.add_run("api-lab-phase2", "run-b")

    output = tmp_path / "campaign-export.json"
    campaigns.export("api-lab-phase2", output)
    payload = json.loads(output.read_text(encoding="utf-8"))
    rendered = json.dumps(payload)

    assert payload["run_ids"] == ["run-a", "run-b"]
    assert payload["assessment_mode"] == "plan+verify"
    assert {(item["category"], item["status"]) for item in payload["findings"]} == {
        ("bola", "verified"),
        ("tenant_isolation", "verified"),
    }
    assert payload["metrics"] == {
        "runs": 2,
        "discovery_requests": 3,
        "auth_requests": 4,
        "object_acquisition_requests": 1,
        "verification_requests": 4,
        "cleanup_requests": 0,
        "typed_executor_requests": 4,
        "total_requests": 11,
        "hypotheses_generated": 2,
        "unique_findings": 2,
        "verified_findings": 2,
        "rejected_findings": 0,
    }
    assert len(payload["run_metrics"]) == 2
    for secret in (
        "CAMPAIGN_SECRET_TOKEN",
        "ANOTHER_CAMPAIGN_SECRET",
        "RAW_RESULT_TOKEN",
        "BENCHMARK-ANSWER-A",
    ):
        assert secret not in rendered
    for forbidden_key in (
        "ground_truth_id",
        "benchmark_answer_id",
        "vulnerability_id",
    ):
        assert forbidden_key not in rendered


def test_duplicate_finding_uses_status_precedence_and_highest_confidence_evidence(
    campaign_storage: tuple[Phase2RunStore, Phase2CampaignStore],
) -> None:
    runs, campaigns = campaign_storage
    discovered = _run(
        "run-discovered",
        _hypothesis(
            "hyp-discovered", "bola", "/orders/{id}", "order_id", confidence="high"
        ),
    )
    verified_low = _run(
        "run-verified-low",
        _hypothesis("hyp-verified-low", "bola", "/orders/{order_id}", "order_id"),
        result_status="verified",
        result_confidence="low",
        evidence="low-confidence verification",
    )
    verified_high = _run(
        "run-verified-high",
        _hypothesis("hyp-verified-high", "bola", "/orders/{order_id}", "order_id"),
        result_status="verified",
        result_confidence="high",
        evidence="highest-confidence verification",
    )
    rejected = _run(
        "run-rejected",
        _hypothesis("hyp-rejected", "bola", "/orders/{id}", "order_id"),
        result_status="rejected",
        evidence="later rejection",
    )
    for run in (discovered, verified_low, verified_high, rejected):
        runs.save(run)
        campaigns.add_run("api-lab-phase2", run["run_id"])

    campaign, resolved = campaigns.resolve("api-lab-phase2")
    payload = build_campaign_export(campaign, resolved)
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["status"] == "verified"
    assert finding["confidence"] == "high"
    assert finding["evidence_summary"] == ["highest-confidence verification"]
    reference = finding["verification_result_reference"]
    assert reference["run_id"] == "run-verified-high"
    assert reference["hypothesis_id"] == "hyp-verified-high"
    assert reference["result_id"].startswith("res_")
    assert reference["result_hash"].startswith("sha256:")
    assert reference["executor_version"] == "bola/v1"
    assert len(finding["correlated_sources"]) >= 4
    assert payload["metrics"]["unique_findings"] == 1
    assert payload["metrics"]["verified_findings"] == 1
    assert payload["metrics"]["rejected_findings"] == 0


def test_campaign_rejects_different_target_and_missing_run_without_mutation(
    campaign_storage: tuple[Phase2RunStore, Phase2CampaignStore],
) -> None:
    runs, campaigns = campaign_storage
    other = _run(
        "run-other-target",
        _hypothesis("hyp-other", "bola", "/orders/{id}", "id"),
        target="http://127.0.0.1:8202",
    )
    runs.save(other)

    with pytest.raises(ValueError, match="different targets"):
        campaigns.add_run("api-lab-phase2", "run-other-target")
    with pytest.raises(FileNotFoundError):
        campaigns.add_run("api-lab-phase2", "missing-run")

    assert campaigns.show("api-lab-phase2")["run_ids"] == []


def test_campaign_export_fails_closed_when_referenced_run_is_missing(
    campaign_storage: tuple[Phase2RunStore, Phase2CampaignStore], tmp_path: Path
) -> None:
    _, campaigns = campaign_storage
    campaign = campaigns.load("api-lab-phase2")
    campaign["run_ids"] = ["missing-run"]
    campaign["run_references"] = [
        {
            "run_id": "missing-run",
            "revision": 1,
            "run_snapshot_hash": "sha256:" + "0" * 64,
            "target_fingerprint": campaign["target_fingerprint"],
        }
    ]
    campaign["campaign_snapshot_hash"] = campaign_snapshot_hash(campaign)
    campaigns.campaign_path("api-lab-phase2").write_text(
        json.dumps(campaign), encoding="utf-8"
    )
    output = tmp_path / "must-not-be-created.json"

    with pytest.raises(FileNotFoundError):
        campaigns.export("api-lab-phase2", output)
    assert not output.exists()


def test_run_files_remain_addressable_after_latest_run_changes(
    campaign_storage: tuple[Phase2RunStore, Phase2CampaignStore],
) -> None:
    runs, _ = campaign_storage
    first = _run("run-first", _hypothesis("hyp-first", "bola", "/orders/{id}", "id"))
    second = _run(
        "run-second",
        _hypothesis(
            "hyp-second",
            "tenant_isolation",
            "/tenants/{tenant_id}",
            "tenant_id",
        ),
    )
    runs.save(first)
    runs.save(second)

    assert runs.load()["run_id"] == "run-second"
    assert runs.load_run("run-first")["run_id"] == "run-first"
    assert runs.load_run("run-first")["created_at"]
    assert runs.load_run("run-second")["created_at"]


def test_phase2_cli_parser_supports_campaign_commands_and_scan_association() -> None:
    parser = build_parser()
    create = parser.parse_args(["campaign", "create", "api-lab", "--target", TARGET])
    add = parser.parse_args(["campaign", "add-run", "api-lab", "run-a"])
    refresh = parser.parse_args(["campaign", "refresh-run", "api-lab", "run-a"])
    export = parser.parse_args(
        ["campaign", "export", "api-lab", "reports/campaign.json"]
    )
    scan = parser.parse_args(
        ["scan", TARGET, "--mode", "plan", "--campaign", "api-lab"]
    )

    assert create.campaign_action == "create"
    assert add.run_id == "run-a"
    assert refresh.run_id == "run-a"
    assert export.path == "reports/campaign.json"
    assert scan.campaign == "api-lab"


def _direct_campaign(*runs: dict[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": "direct-campaign",
        "name": "direct-campaign",
        "target": TARGET,
        "created_at": "2026-08-28T00:00:00+00:00",
        "updated_at": "2026-08-28T00:00:00+00:00",
        "run_ids": [run["run_id"] for run in runs],
    }


def _direct_export(*runs: dict[str, Any]) -> dict[str, Any]:
    return build_campaign_export(_direct_campaign(*runs), list(runs))


def test_typed_rate_limit_result_exports_provenance_and_network_request_total(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis(
        "hyp-rate-limit",
        "rate_limit_enforcement",
        "/sessions",
        "",
        status="verified",
        confidence="high",
    )
    hypothesis["method"] = "POST"
    hypothesis["target_surface"]["method"] = "POST"
    run = _run(
        "run-rate-limit",
        hypothesis,
        metrics={
            "discovery_requests": 0,
            "auth_requests": 5,
            "verification_requests": 0,
            "total_requests": 5,
            "hypotheses_generated": 1,
        },
    )
    run["verification_results"] = [
        {
            "hypothesis_id": hypothesis["hypothesis_id"],
            "category": hypothesis["category"],
            "status": "verified",
            "reasons": ["Bounded same-account sequence found no configured control."],
            "request_counts": {
                "valid_baseline_auth_requests": 1,
                "invalid_password_auth_requests": 3,
                "final_valid_auth_requests": 1,
                "auth_requests": 5,
                "total_network_requests": 5,
            },
            "result_schema_version": RESULT_SCHEMA_VERSION,
            "executor": typed_producer_provenance(hypothesis["category"]),
        }
    ]
    store = Phase2RunStore(tmp_path / "runs")
    store.save(run)
    stored = store.load_run(run["run_id"])
    payload = _direct_export(stored)
    finding = payload["findings"][0]

    assert finding["status"] == "verified"
    assert finding["requests_used"] == 5
    reference = finding["verification_result_reference"]
    assert reference["run_id"] == "run-rate-limit"
    assert reference["hypothesis_id"] == "hyp-rate-limit"
    assert reference["result_id"].startswith("res_")
    assert reference["result_hash"].startswith("sha256:")
    assert reference["executor_version"] == "rate_limit_enforcement/v1"
    assert finding["evidence_summary"] == [
        "Bounded same-account sequence found no configured control."
    ]
    assert (
        stored["verification_results"][0]["request_counts"][
            "invalid_password_auth_requests"
        ]
        == 3
    )
    assert payload["run_metrics"][0]["typed_executor_requests"] == 5
    assert payload["metrics"]["typed_executor_requests"] == 5
    assert payload["metrics"]["total_requests"] == 5


@pytest.mark.parametrize("status", ["verified", "rejected", "inconclusive"])
def test_completed_typed_result_wins_over_discovery_and_carries_provenance(
    status: str,
) -> None:
    hypothesis = _hypothesis(f"hyp-{status}", "bola", "/orders/{order_id}", "order_id")
    run = _run(f"run-{status}", hypothesis, result_status=status)
    payload = _direct_export(run)
    finding = payload["findings"][0]

    assert finding["status"] == status
    assert finding["verification_result_reference"] == {
        "run_id": f"run-{status}",
        "hypothesis_id": f"hyp-{status}",
        "provenance_status": "legacy_unversioned",
    }


@pytest.mark.parametrize("status", ["rejected", "verified"])
def test_final_recovery_result_wins_over_intermediate_states(status: str) -> None:
    hypothesis = _hypothesis(
        f"hyp-recovery-{status}",
        "recovery_state_enforcement",
        "/recovery/complete",
        "",
        status=status,
        confidence="high",
    )
    run = _run(
        f"run-recovery-{status}",
        hypothesis,
        metrics={"total_requests": 5, "hypotheses_generated": 1},
    )
    common = {
        "hypothesis_id": hypothesis["hypothesis_id"],
        "category": "recovery_state_enforcement",
        "recovery_run_id": run["run_id"],
        "challenge_reference": "sha256:safe-workflow-reference",
        "comparison_type": "reused_same_challenge_and_code",
    }
    run["verification_results"] = [
        {
            **common,
            "status": "awaiting_controlled_evidence",
            "recovery_phase": "challenge_issued",
            "requests_used": 1,
            "request_budget": {"total_requests": 1},
        },
        {
            **common,
            "status": "verification_pending_cleanup",
            "recovery_phase": "verification_pending_cleanup",
            "requests_used": 2,
            "request_budget": {"total_requests": 3},
        },
        {
            **common,
            "status": status,
            "recovery_phase": "completed",
            "confidence": "high",
            "evidence_summary": [f"Final recovery classification: {status}."],
            "requests_used": 0,
            "request_budget": {"total_requests": 1},
        },
    ]

    payload = _direct_export(run)
    finding = payload["findings"][0]

    assert finding["status"] == status
    assert finding["evidence_summary"] == [f"Final recovery classification: {status}."]
    assert finding["requests_used"] == 0
    assert finding["workflow_request_total"] == 3
    assert finding["verification_result_reference"] == {
        "run_id": run["run_id"],
        "hypothesis_id": hypothesis["hypothesis_id"],
        "provenance_status": "legacy_unversioned",
    }
    assert payload["metrics"]["typed_executor_requests"] == 3


def test_mutated_hypothesis_status_without_typed_result_remains_discovered() -> None:
    hypothesis = _hypothesis(
        "hyp-discovery-only",
        "bola",
        "/orders/{order_id}",
        "order_id",
        status="verified",
    )
    finding = _direct_export(_run("run-discovery-only", hypothesis))["findings"][0]

    assert finding["status"] == "discovered"
    assert finding["verification_result_reference"] is None
    assert finding["requests_used"] == 0


def test_campaign_deduplication_uses_structural_finding_identity() -> None:
    def structural_run(
        run_id: str,
        *,
        category: str = "bola",
        method: str = "GET",
        route: str = "/records/{id}",
        parameter: str = "record_id",
    ) -> dict[str, Any]:
        hypothesis = _hypothesis(run_id, category, route, parameter)
        hypothesis["method"] = method
        hypothesis["target_surface"]["method"] = method
        return _run(run_id, hypothesis)

    same_structure = structural_run("same-structure", route="/records/{record}")
    runs = [
        structural_run("base"),
        same_structure,
        structural_run("different-method", method="POST"),
        structural_run("different-parameter", parameter="tenant_id"),
        structural_run("different-category", category="tenant_isolation"),
    ]
    findings = _direct_export(*runs)["findings"]

    assert len(findings) == 4
    assert (
        sum(
            item["category"] == "bola"
            and item["http_method"] == "GET"
            and item["parameter"] == "record_id"
            for item in findings
        )
        == 1
    )


@pytest.mark.parametrize(
    "category",
    ["bola", "tenant_isolation", "vertical_authorization", "mass_assignment"],
)
def test_existing_typed_category_shapes_only_gain_verification_provenance(
    category: str,
) -> None:
    hypothesis = _hypothesis(
        f"hyp-{category}", category, "/resources/{resource_id}", "resource_id"
    )
    finding = _direct_export(
        _run(f"run-{category}", hypothesis, result_status="verified")
    )["findings"][0]

    assert finding["category"] == category
    assert finding["http_method"] == "GET"
    assert finding["route_template"] == "/resources/{resource_id}"
    assert finding["parameter"] == "resource_id"
    assert finding["affected_functionality"] == (
        "GET /resources/{resource_id} resource_id"
    )
    assert finding["requests_used"] == 2
    assert finding["verification_result_reference"] == {
        "run_id": f"run-{category}",
        "hypothesis_id": f"hyp-{category}",
        "provenance_status": "legacy_unversioned",
    }


def test_explicit_executor_request_count_is_preserved() -> None:
    hypothesis = _hypothesis(
        "hyp-explicit-zero", "mass_assignment", "/profiles/{profile_id}", "role"
    )
    run = _run("run-explicit-zero", hypothesis)
    run["verification_results"] = [
        {
            "hypothesis_id": hypothesis["hypothesis_id"],
            "category": hypothesis["category"],
            "status": "inconclusive",
            "requests_used": 0,
            "request_counts": {"total_network_requests": 9},
        }
    ]

    assert _direct_export(run)["findings"][0]["requests_used"] == 0


def test_secret_safe_numeric_telemetry_is_type_aware() -> None:
    cleaned = redact(
        {
            "invalid_password_auth_requests": 3,
            "password_field_count": 1,
            "token_request_count": 2,
            "credential_attempt_count": 3,
            "invalid_password": "actual-invalid-password-secret",
            "password": "actual-password-secret",
            "access_token": "actual-access-token-secret",
            "authorization": "Bearer actual-authorization-secret",
            "cookie": "session=actual-cookie-secret",
            "unsafe_typed_like_values": {
                "invalid_password_auth_requests": "3",
                "password_field_count": "1",
                "token_request_count": "2",
            },
        }
    )

    assert cleaned["invalid_password_auth_requests"] == 3
    assert cleaned["password_field_count"] == 1
    assert cleaned["token_request_count"] == 2
    assert cleaned["credential_attempt_count"] == 3
    for key in (
        "invalid_password",
        "password",
        "access_token",
        "authorization",
        "cookie",
    ):
        assert cleaned[key] == "[REDACTED]"
    assert set(cleaned["unsafe_typed_like_values"].values()) == {"[REDACTED]"}


def test_secrets_remain_absent_from_all_phase2_export_formats(tmp_path: Path) -> None:
    secrets = {
        "password": "secret-password-value",
        "invalid_password": "secret-invalid-password-value",
        "access_token": "secret-access-token-value",
        "authorization": "Bearer secret-authorization-value",
        "cookie": "session=secret-cookie-value",
    }
    hypothesis = _hypothesis(
        "hyp-secret-safe", "rate_limit_enforcement", "/sessions", ""
    )
    run = _run(
        "run-secret-safe",
        hypothesis,
        metrics={"auth_requests": 5, "total_requests": 5},
    )
    run["verification_results"] = [
        {
            "hypothesis_id": hypothesis["hypothesis_id"],
            "category": hypothesis["category"],
            "status": "verified",
            "reasons": ["Safe typed evidence."],
            "request_counts": {
                "invalid_password_auth_requests": 3,
                "total_network_requests": 5,
            },
            "result_schema_version": RESULT_SCHEMA_VERSION,
            "executor": typed_producer_provenance(hypothesis["category"]),
            **secrets,
        }
    ]
    store = Phase2RunStore(tmp_path / "runs")
    run_path = Path(store.save(run))
    stored = store.load_run(run["run_id"])
    outputs = {
        "run": run_path.read_text(encoding="utf-8"),
        "campaign": json.dumps(_direct_export(stored)),
        "benchmark": json.dumps(build_benchmark_export(stored)),
        "markdown": render_phase2_report(stored),
    }

    for output in outputs.values():
        for secret in secrets.values():
            assert secret not in output
    result = stored["verification_results"][0]
    assert result["invalid_password"] == "[REDACTED]"
    assert result["request_counts"]["invalid_password_auth_requests"] == 3
