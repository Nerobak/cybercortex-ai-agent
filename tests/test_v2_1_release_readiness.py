from __future__ import annotations

from pathlib import Path

import agent
from agent_core.doctor import doctor
from agent_core.tool_explainer import explain_latest
from agent_core.version import __version__
from config import BUSINESS_LOGIC_REPLAY_ENABLED, JWT_REPLAY_ENABLED
from tool_registry import DESCRIPTIVE_FIELDS, TOOLS
from tools.ai_report_writer import _deterministic_report, sanitize_value
from web_app import _public_job, dashboard, health


def test_canonical_release_version_and_surfaces(capsys, monkeypatch):
    assert __version__ == "2.1.0-beta"
    assert health()["version"] == __version__
    assert f"v{__version__}" in dashboard().body.decode()
    assert __version__ in doctor(quick=True)
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))
    agent.main()
    assert f"v{__version__}" in capsys.readouterr().out


def test_help_includes_release_candidate_commands_and_boundaries(capsys):
    agent.print_help()
    text = capsys.readouterr().out
    for command in (
        "scan <target> --profile authenticated",
        "graphql analyze <file>",
        "jwt analyze [token]",
        "workflow compare <file-a> <file-b>",
        "upload replay <file>",
        "doctor [--quick]",
    ):
        assert command in text
    assert "Offline analysis is the default" in text
    assert "No engine automatically proves a vulnerability" in text


def test_report_feature_sections_are_evidence_driven():
    base = {
        "observations": [],
        "candidate_findings": [],
        "verified_findings": [],
        "manual_verification_queue": [],
        "observed_surface": {},
        "execution_summary": {},
        "coverage": {},
    }
    report = _deterministic_report("https://example.test", base, "unavailable")
    assert "## GraphQL Surface" not in report
    assert "## JWT Surface" not in report
    assert "## Business Workflow Surface" not in report
    assert "## File Upload Surface" not in report
    assert "No evidence-supported manual test was queued" in report


def test_report_has_standard_sections_and_conservative_conclusion():
    report = _deterministic_report("https://example.test", {}, "timed_out")
    for section in (
        "## Executive Summary",
        "## Scope and Authorization",
        "## Assessment Coverage",
        "## Confirmed Security Controls",
        "## Verified Findings",
        "## Candidate Findings Requiring Manual Verification",
        "## Informational and Defense-in-Depth Observations",
        "## Incomplete or Failed Checks",
        "## Prioritized Next Manual Tests",
        "## Limitations",
        "## Conclusion",
    ):
        assert section in report
    assert (
        "No evidence collected during this assessment demonstrated an exploitable vulnerability."
        in report
    )


def test_dashboard_contract_omits_raw_and_sensitive_evidence():
    marker = "eyJhbGciOiJIUzI1NiJ9.private.signature"
    public = _public_job(
        {
            "id": "1",
            "target": "https://example.test",
            "profile": "baseline",
            "status": "completed",
            "results": {"raw_request": marker},
            "observed_surface": {"schema": marker},
            "tool_statuses": {
                "jwt_decoder": {
                    "status": "completed",
                    "output": {"authorization": marker},
                    "error": marker,
                }
            },
        }
    )
    assert "results" not in public
    assert "observed_surface" not in public
    assert marker not in str(public)


def test_report_sanitizer_removes_sensitive_key_variants():
    marker = "private-value"
    sanitized = sanitize_value(
        {
            "access_token": marker,
            "request_body_json": marker,
            "graphql_raw_schema": marker,
            "verification_code_value": marker,
            "safe_count": 2,
        }
    )
    assert sanitized == {"safe_count": 2}


def test_explain_latest_includes_all_capability_summaries():
    text = explain_latest(
        {
            "evidence_package": {
                "assessment": {
                    "requested_target": "example.test",
                    "profile": "baseline",
                },
                "execution_summary": {},
                "observed_surface": {},
            },
            "results": {},
        }
    )
    for label in ("GraphQL", "JWT", "Business logic", "File upload"):
        assert f"{label} summary:" in text


def test_replay_defaults_registry_and_documentation():
    assert JWT_REPLAY_ENABLED is False
    assert BUSINESS_LOGIC_REPLAY_ENABLED is False
    assert all(
        all(info.get(field) for field in DESCRIPTIVE_FIELDS) for info in TOOLS.values()
    )
    for name in (
        "README.md",
        "docs/ARCHITECTURE.md",
        "docs/INSTALL.md",
        "docs/TOOLS.md",
        "docs/ROADMAP.md",
        "docs/GRAPHQL_SUITE.md",
        "docs/JWT_WORKFLOW.md",
        "docs/BUSINESS_LOGIC_ENGINE.md",
        "docs/FILE_UPLOAD_ENGINE.md",
        "docs/RELEASE_NOTES_V2_BETA.md",
        "docs/RELEASE_NOTES_V2_1_BETA.md",
    ):
        assert Path(name).is_file()
