from __future__ import annotations

import json
from pathlib import Path

import agent
from agent_core.doctor import doctor
from agent_core.result_normalizer import normalize_findings
from agent_core.tool_explainer import explain, explain_latest
from agent_core.version import __version__
from tool_registry import DESCRIPTIVE_FIELDS, TOOLS
from tools.api_object_discovery import crawl_and_discover_ids
from tools.endpoint_analyzer import classify_resource_kind, endpoint_analyzer
from tools.ai_report_writer import ai_report_writer
from web_app import dashboard, health


def test_explain_known_unknown_and_profiles():
    known = explain("js_secret_scanner")
    assert "Tool: js_secret_scanner" in known
    assert "Does not prove:" in known
    assert "Safety notes:" in known
    assert "Unknown tool" in explain("js_sekret_scanner")
    assert "js_secret_scanner" in explain("js_sekret_scanner")
    assert "baseline |" in explain("profiles")


def test_explain_latest_before_and_after_scan():
    assert "No previous scan" in explain_latest(None)
    result = {
        "assessment_status": "completed",
        "coverage": {"coverage_percentage": 100},
        "evidence_package": {
            "assessment": {
                "requested_target": "https://example.test",
                "profile": "baseline",
            },
            "execution_summary": {
                "completed": ["http_probe"],
                "failed": [],
                "timed_out": [],
                "timed_out_partial": [],
                "skipped": [],
            },
            "observations": [{}],
            "candidate_findings": [],
            "verified_findings": [],
        },
        "results": {
            "ai_report_writer": {
                "output": {
                    "report_mode": "deterministic_fallback",
                    "report_file": "reports/report.md",
                    "evidence_file": "reports/evidence.json",
                }
            }
        },
    }
    text = explain_latest(result)
    assert "https://example.test" in text and "Completed tools: http_probe" in text


def test_registry_descriptions_are_complete():
    assert all(info["name"] == name for name, info in TOOLS.items())
    assert all(
        all(info.get(field) for field in DESCRIPTIVE_FIELDS) for info in TOOLS.values()
    )


def test_resource_kind_and_static_asset_filtering():
    assert (
        classify_resource_kind("https://example.test/assets/api-abc123.js")
        == "static_asset"
    )
    assert (
        classify_resource_kind("https://example.test/scripts/user-profile.js")
        == "static_asset"
    )
    assert classify_resource_kind("https://example.test/api") == "api_related_route"
    result = endpoint_analyzer(
        [
            "https://example.test/api/users/1001",
            "https://example.test/assets/api-abc123.js",
        ],
        "example.test",
    )
    assert result["interesting_endpoints"][0]["resource_kind"] == "api_related_route"
    assert result["interesting_endpoints"][0]["observed_identifiers"]
    assert len(result["static_assets"]) == 1


def test_object_discovery_output_is_bounded(monkeypatch):
    urls = [f"https://example.test/api/items/{index}" for index in range(100)]
    monkeypatch.setattr(
        "tools.api_object_discovery.enforce_scope", lambda url: {"allowed": True}
    )
    result = crawl_and_discover_ids(
        "https://example.test",
        normalized_url_evidence={"all_urls": urls},
        allow_network_crawl=False,
    )
    assert len(result["sample_classifications"]) <= 20
    assert len(result["candidate_authorization_tests"]) <= 20
    assert "path_segment_classifications" not in result
    assert len(json.dumps(result)) < 100_000


def test_public_contacts_are_observations_and_headers_stay_informational():
    results = {
        "js_secret_scanner": {
            "output": {
                "findings": [
                    {
                        "match_kind": "public_contact",
                        "confidence": "high",
                        "url": "https://example.test/a.js",
                        "context_hash": "abc",
                    }
                ]
            }
        },
        "security_headers_checker": {
            "output": {
                "headers_checked": {"Cross-Origin-Opener-Policy": {"present": False}}
            }
        },
    }
    findings = normalize_findings(results)
    assert all(item["status"] == "observation" for item in findings)
    assert any(item["category"] == "public_contact" for item in findings)


def test_doctor_quick_version_help_and_secret_safety(capsys):
    output = doctor(quick=True)
    assert __version__ in output and "[" in output
    marker = "eyJhbGciOiJIUzI1NiJ9.secret.signature"
    assert marker not in output
    agent.print_help()
    help_text = capsys.readouterr().out
    for command in (
        "ask <question>",
        "scan <target>",
        "list tools",
        "explain <tool>",
        "explain latest",
        "explain scan",
        "explain profiles",
        "jwt analyze",
        "doctor",
        "help",
        "exit",
    ):
        assert command in help_text


def test_fallback_report_wording_and_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tools.ai_report_writer.ask_agent",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError()),
    )
    result = ai_report_writer(
        "https://example.test",
        {
            "observations": [
                {
                    "title": "Contact",
                    "category": "public_contact",
                    "confidence": "high",
                    "status": "observation",
                    "source_tool": "js_secret_scanner",
                }
            ],
            "candidate_findings": [],
            "verified_findings": [],
            "manual_verification_queue": [],
            "tool_results": {},
            "execution_summary": {},
            "evidence_files": [],
        },
        output_dir=str(tmp_path),
    )
    report = Path(result["report_file"]).read_text(encoding="utf-8")
    assert f"v{__version__}" in report
    assert "Public contact information observed in JavaScript." in report
    assert "No credential-like secrets were confirmed." in report
    assert "does not establish a vulnerability or direct exploit path" in report
    assert "Identified API endpoints" not in report


def test_version_appears_in_dashboard_and_health():
    assert health()["version"] == __version__
    assert f"v{__version__}" in dashboard().body.decode()
