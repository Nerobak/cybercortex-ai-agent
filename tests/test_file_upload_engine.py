from __future__ import annotations

import json
from pathlib import Path

from agent import process_user_input
from agent_core.result_normalizer import build_evidence_package
from tool_registry import DESCRIPTIVE_FIELDS, TOOLS, validate_registry
from tools.ai_report_writer import _deterministic_report
from tools.upload_discovery import discover_upload_surface
from tools.upload_metadata_analyzer import analyze_upload_metadata
from tools.upload_replay_checker import check_upload_replay
from tools.upload_security_planner import plan_upload_security
from tools.upload_storage_analyzer import analyze_upload_storage
from tools.upload_validation_analyzer import analyze_upload_validation


def upload_evidence():
    return {
        "html": '<form enctype="multipart/form-data"><input type="file" accept=".png,.pdf"></form>',
        "requests": [
            {
                "method": "POST",
                "url": "https://example.test/api/upload",
                "headers": {
                    "Content-Type": "multipart/form-data; boundary=controlled",
                    "Content-Disposition": "attachment",
                },
                "max_file_size": "2 MB",
            }
        ],
        "javascript_strings": [
            "const data = new FormData(); data.append('file', selected);"
        ],
        "graphql_schema": {"types": [{"kind": "SCALAR", "name": "Upload"}]},
        "implementation_hints": ["secure_filename uuid object_key strip_metadata"],
        "storage": ["https://bucket.s3.amazonaws.com/redacted-object"],
        "filename": "third-party-name-must-not-appear.pdf",
    }


def test_discovery_covers_forms_multipart_graphql_javascript_and_endpoints():
    result = discover_upload_surface(upload_evidence())
    kinds = {item["type"] for item in result["observations"]}
    assert {
        "file_input_observed",
        "multipart_observed",
        "graphql_upload_scalar_observed",
        "javascript_upload_observed",
        "upload_endpoint_observed",
    } <= kinds
    assert result["network_tested"] is False
    assert all(
        item["classification"] == "observation" for item in result["observations"]
    )


def test_validation_is_evidence_driven_and_does_not_infer_server_behavior():
    result = analyze_upload_validation(upload_evidence())
    kinds = {item["type"] for item in result["observations"]}
    assert "accepted_types_observed" in kinds
    assert "mime_validation_observed" in kinds
    assert "size_limit_observed" in kinds
    assert result["server_behavior_inferred"] is False
    client_only = analyze_upload_validation(
        {"html": '<input type="file" accept=".png">'}
    )
    assert client_only["candidates"][0]["status"] == "needs_manual_verification"


def test_metadata_never_discloses_supplied_filenames():
    result = analyze_upload_metadata(upload_evidence())
    kinds = {item["type"] for item in result["observations"]}
    assert "uuid_naming_observed" in kinds
    assert "metadata_stripping_observed" in kinds
    assert result["filenames_disclosed"] is False
    assert "third-party-name-must-not-appear" not in str(result)


def test_storage_is_observation_only():
    result = analyze_upload_storage(upload_evidence())
    assert result["providers_observed"] == ["s3"]
    assert result["classification"] == "observation"
    assert result["exposure_verified"] is False


def test_planner_is_non_executing_and_has_all_safe_categories():
    result = plan_upload_security(discover_upload_surface(upload_evidence()))
    categories = {plan["category"] for plan in result["plans"]}
    assert len(categories) == 8
    assert {"ownership", "download_authorization", "overwrite_protection"} <= categories
    assert result["automatic_execution"] is False
    assert all(
        plan["stop_conditions"] and plan["prohibited_actions"]
        for plan in result["plans"]
    )


def test_replay_disabled_and_blocks_unsafe_files(tmp_path, monkeypatch):
    safe = tmp_path / "owned.txt"
    safe.write_text("benign controlled evidence", encoding="utf-8")
    request = {
        "url": "https://example.test/upload",
        "file_path": str(safe),
        "researcher_owned_file_confirmed": True,
        "test_owned_resource_confirmed": True,
    }
    assert check_upload_replay(request, enabled=False)["status"] == "disabled"
    monkeypatch.setattr(
        "tools.upload_replay_checker.enforce_scope", lambda url: {"allowed": True}
    )
    assert (
        check_upload_replay(request, enabled=True, authenticated_profile=True)["status"]
        == "ready_for_bounded_replay"
    )
    unsafe = tmp_path / "fake.txt"
    unsafe.write_bytes(b"MZ executable")
    request["file_path"] = str(unsafe)
    assert (
        check_upload_replay(request, enabled=True, authenticated_profile=True)["status"]
        == "blocked_by_policy"
    )


def test_registry_and_explain_metadata_are_complete():
    names = {
        "upload_discovery",
        "upload_validation_analyzer",
        "upload_metadata_analyzer",
        "upload_storage_analyzer",
        "upload_security_planner",
        "upload_replay_checker",
    }
    assert names <= TOOLS.keys()
    assert all(
        all(TOOLS[name].get(field) for field in DESCRIPTIVE_FIELDS) for name in names
    )
    diagnostics = {item["name"]: item for item in validate_registry()}
    assert all(diagnostics[name]["callable_exists"] for name in names)
    assert "upload_discovery" in process_user_input("upload explain")


def test_upload_cli_analyze_plan_and_default_replay(tmp_path):
    evidence_file = tmp_path / "upload.json"
    evidence_file.write_text(json.dumps(upload_evidence()), encoding="utf-8")
    analyzed = process_user_input(f"upload analyze {evidence_file}")
    assert analyzed["discovery"]["upload_surface_observed"] is True
    planned = process_user_input(f"upload plan {evidence_file}")
    assert planned["plan_count"] == 8
    replay_file = tmp_path / "replay.json"
    replay_file.write_text(
        json.dumps({"url": "https://example.test/upload"}), encoding="utf-8"
    )
    assert process_user_input(f"upload replay {replay_file}")["status"] == "disabled"


def test_evidence_package_and_report_have_conservative_upload_sections():
    output = discover_upload_surface(upload_evidence())
    results = {
        "upload_discovery": {"status": "completed", "output": output},
        "upload_validation_analyzer": {
            "status": "completed",
            "output": analyze_upload_validation(upload_evidence()),
        },
        "upload_metadata_analyzer": {
            "status": "completed",
            "output": analyze_upload_metadata(upload_evidence()),
        },
        "upload_storage_analyzer": {
            "status": "completed",
            "output": analyze_upload_storage(upload_evidence()),
        },
        "upload_security_planner": {
            "status": "completed",
            "output": plan_upload_security(output),
        },
    }
    package = build_evidence_package(
        "https://example.test", "baseline", results, "start", "end"
    )
    upload = package["observed_surface"]["upload"]
    assert upload["surface_observed"] is True
    assert upload["filenames_disclosed"] is False
    report = _deterministic_report("https://example.test", package, "not_requested")
    assert "## Upload Surface" in report
    assert "## Upload Observations" in report
    assert "## Manual Upload Verification" in report
    assert "No file was uploaded automatically" in report


def test_dashboard_contains_concise_upload_summary():
    html = Path("web/dashboard.html").read_text(encoding="utf-8")
    assert "<summary>Upload surface</summary>" in html
    assert "upload.storage_observations" in html
    assert "filename" not in html.lower()
