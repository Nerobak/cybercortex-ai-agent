from __future__ import annotations

import json

import pytest
import requests

import agent_core.tool_runner as runner_module
from agent_core.result_normalizer import (
    MAX_EVIDENCE_BYTES,
    build_evidence_package,
    normalize_findings,
    normalize_finding_list,
    redact,
)
from agent_core.tool_runner import ToolRunner
from agent_core.workflow_manager import run_workflow
from tool_registry import TOOLS, resolve_tool, validate_registry
from tool_registry import tools_for_profile
from tools.safe_http import UnsafeRedirectError, scoped_get


def test_registry_names_resolve_and_parameter_analyzer_is_registered():
    assert "parameter_analyzer" in TOOLS
    assert resolve_tool("parameter_analyzer") is not None
    assert all(item["callable_exists"] for item in validate_registry())


def test_intrusive_profile_uses_authenticated_tool_eligibility():
    assert set(tools_for_profile("intrusive")) == set(
        tools_for_profile("authenticated")
    )


def _response(url, status=200, location=None):
    response = requests.Response()
    response.url = url
    response.status_code = status
    if location:
        response.headers["Location"] = location
    return response


def test_safe_redirect_follows_allowed_prefix(monkeypatch):
    monkeypatch.setattr(
        "tools.safe_http.enforce_scope",
        lambda url: {"allowed": url.startswith("https://example.test/app")},
    )
    responses = iter(
        [
            _response("https://example.test/app", 302, "/app/home"),
            _response("https://example.test/app/home"),
        ]
    )
    monkeypatch.setattr(
        requests.Session, "get", lambda *args, **kwargs: next(responses)
    )
    response, chain = scoped_get("https://example.test/app")
    assert response.url == "https://example.test/app/home"
    assert len(chain) == 1


@pytest.mark.parametrize("location", ["/outside", "https://evil.test/app"])
def test_safe_redirect_blocks_out_of_scope_and_cross_domain(monkeypatch, location):
    monkeypatch.setattr(
        "tools.safe_http.enforce_scope",
        lambda url: {"allowed": url.startswith("https://example.test/app")},
    )
    monkeypatch.setattr(
        requests.Session,
        "get",
        lambda *args, **kwargs: _response("https://example.test/app", 302, location),
    )
    with pytest.raises(UnsafeRedirectError):
        scoped_get("https://example.test/app")


def test_safe_redirect_loop_is_bounded(monkeypatch):
    monkeypatch.setattr("tools.safe_http.enforce_scope", lambda url: {"allowed": True})
    monkeypatch.setattr(
        requests.Session,
        "get",
        lambda *args, **kwargs: _response("https://example.test/app", 302, "/app"),
    )
    with pytest.raises(UnsafeRedirectError, match="loop"):
        scoped_get("https://example.test/app")


def test_runner_partial_crawl_flows_and_failure_does_not_stop(monkeypatch):
    calls = {}

    def fake_resolve(name):
        functions = {
            "dns_lookup": lambda host: {"success": True},
            "http_probe": lambda url: {"success": True, "effective_url": url},
            "security_headers_checker": lambda url: {"success": False, "error": "boom"},
            "tech_fingerprint": lambda url: {"success": True},
            "katana_crawl": lambda url: {
                "success": True,
                "status": "timed_out_partial",
                "urls": [url + "/api/users?id=1", "https://outside.test/x"],
                "out_of_scope_urls": ["https://outside.test/x"],
                "count": 1,
            },
            "endpoint_analyzer": lambda urls, host: (
                calls.setdefault("endpoint", list(urls)),
                {"success": True},
            )[1],
            "parameter_analyzer": lambda urls: (
                calls.setdefault("parameter", list(urls)),
                {"success": True},
            )[1],
            "misconfiguration_detector": lambda urls, host: {"success": True},
            "js_secret_scanner": lambda urls, host: {"success": True},
            "api_object_discovery": lambda url, **kwargs: {
                "success": True,
                "pages": [],
                "objects": [],
            },
            "nuclei_scan": lambda url: {"success": True},
            "ai_report_writer": lambda target, evidence, **kwargs: {"success": True},
        }
        return functions[name]

    monkeypatch.setattr(runner_module, "resolve_tool", fake_resolve)
    monkeypatch.setattr(
        "agent_core.result_normalizer.enforce_scope",
        lambda url: {"allowed": url.startswith("https://example.test")},
    )
    result = ToolRunner(tool_timeout=2).run("https://example.test/app")
    assert result["results"]["katana_crawl"]["status"] == "timed_out_partial"
    assert result["results"]["security_headers_checker"]["status"] == "failed"
    assert any("/api/users" in url for url in calls["parameter"])
    assert "https://outside.test/x" not in calls["endpoint"]
    assert result["results"]["ai_report_writer"]["status"] == "completed"


def test_empty_crawl_skips_list_analyzers_and_jwt_is_not_baseline(monkeypatch):
    monkeypatch.setattr(
        runner_module,
        "resolve_tool",
        lambda name: (
            lambda *args, **kwargs: (
                {"success": True, "urls": []}
                if name == "katana_crawl"
                else {"success": True, "pages": []}
            )
        ),
    )
    monkeypatch.setattr(
        "agent_core.result_normalizer.enforce_scope", lambda url: {"allowed": False}
    )
    result = ToolRunner(tool_timeout=2).run("https://example.test/app")
    assert result["results"]["parameter_analyzer"]["status"] == "skipped"
    assert "jwt_security_analyzer" not in result["results"]


def test_secrets_are_redacted_and_evidence_is_bounded():
    token = "aaa.bbb.ccc"
    cleaned = redact({"Authorization": "Bearer secret", "jwt": token, "safe": token})
    assert cleaned["Authorization"] == "[REDACTED]"
    assert cleaned["jwt"] == "[REDACTED]"
    assert cleaned["safe"] == token
    package = build_evidence_package(
        "https://example.test", "baseline", {}, "start", "end"
    )
    assert len(json.dumps(package).encode()) <= MAX_EVIDENCE_BYTES


def test_redaction_preserves_structured_collection_types():
    cleaned = redact(
        {"candidate_authorization_tests": [{"observed_identifier": "private-value"}]}
    )
    assert cleaned["candidate_authorization_tests"] == []
    assert cleaned["candidate_authorization_test_count"] == 1
    assert isinstance(cleaned["candidate_authorization_tests"], list)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, []),
        ("[REDACTED]", []),
        (4, []),
        ({"title": "one"}, [{"title": "one"}]),
        ([{"title": "one"}, "bad", 2], [{"title": "one"}]),
    ],
)
def test_finding_list_normalization_is_strict(value, expected):
    diagnostics = []
    assert normalize_finding_list(value, diagnostics=diagnostics) == expected
    if value not in (None, {"title": "one"}):
        if value != [{"title": "one"}]:
            assert diagnostics


def test_one_hundred_partial_urls_feed_all_dependent_analyzers(monkeypatch):
    calls = {}
    urls = [
        f"https://example.test/assets/api-{index}.js?id={index}" for index in range(100)
    ]

    def record(name, value):
        calls[name] = list(value)
        return {"success": True}

    def fake_resolve(name):
        functions = {
            "dns_lookup": lambda host: {"success": True},
            "http_probe": lambda url: {"success": True, "effective_url": url},
            "security_headers_checker": lambda url: {"success": True},
            "tech_fingerprint": lambda url: {"success": True},
            "katana_crawl": lambda url: {
                "success": True,
                "status": "timed_out_partial",
                "urls": urls,
                "count": 100,
            },
            "endpoint_analyzer": lambda values, host: record("endpoint", values),
            "parameter_analyzer": lambda values: record("parameter", values),
            "misconfiguration_detector": lambda values, host: record(
                "misconfiguration", values
            ),
            "js_secret_scanner": lambda values, host: record("javascript", values),
            "api_object_discovery": lambda url, **kwargs: (
                calls.setdefault(
                    "api", list(kwargs["normalized_url_evidence"]["all_urls"])
                ),
                {"success": True, "objects": [], "pages": []},
            )[1],
            "nuclei_scan": lambda url: {"success": True, "findings": []},
            "ai_report_writer": lambda target, evidence, **kwargs: {
                "success": True,
                "report_generated": True,
                "ai_status": "completed",
            },
        }
        return functions[name]

    monkeypatch.setattr(runner_module, "resolve_tool", fake_resolve)
    monkeypatch.setattr(
        "agent_core.result_normalizer.enforce_scope", lambda url: {"allowed": True}
    )
    result = ToolRunner(tool_timeout=2).run("https://example.test/exchange")
    assert result["results"]["katana_crawl"]["status"] == "timed_out_partial"
    assert all(
        len(calls[name]) == 101
        for name in ("endpoint", "parameter", "misconfiguration", "api")
    )
    assert len(calls["javascript"]) == 100


def test_cross_origin_headers_remain_informational():
    headers = {
        name: {"present": False}
        for name in (
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        )
    }
    findings = normalize_findings(
        {"security_headers_checker": {"output": {"headers_checked": headers}}}
    )
    assert findings and all(
        item["severity"] == "informational" and item["status"] == "observation"
        for item in findings
    )


def test_console_stages_are_printed_in_execution_order(monkeypatch, capsys):
    class FakeRunner:
        def __init__(self, *, phase_callback, **kwargs):
            self.phase_callback = phase_callback

        def run(self, *args, **kwargs):
            for phase in (
                "normalize_surface",
                "dependent_analyzers",
                "optional_tools",
                "evidence_package",
                "ai_analysis",
                "report_writing",
            ):
                self.phase_callback(phase)
            return {
                "assessment_status": "completed_with_limitations",
                "coverage": {"coverage_percentage": 83.3},
                "results": {
                    "ai_report_writer": {
                        "output": {
                            "ai_status": "timed_out",
                            "report_mode": "deterministic_fallback",
                            "report": "reports/report.md",
                            "evidence": "reports/evidence.json",
                        }
                    }
                },
                "evidence_package": {
                    "execution_summary": {
                        "completed": [],
                        "completed_with_fallback": ["ai_report_writer"],
                        "timed_out_partial": ["katana_crawl"],
                        "timed_out": [],
                        "failed": [],
                        "skipped": [],
                    },
                    "observations": [],
                    "candidate_findings": [],
                    "manual_verification_queue": [],
                    "verified_findings": [],
                },
            }

    monkeypatch.setattr("agent_core.workflow_manager.ToolRunner", FakeRunner)
    run_workflow("assess", "https://example.test", "example.test")
    output = capsys.readouterr().out
    stages = [
        "[1] Scope validation",
        "[2] Creating dependency-aware plan",
        "[3] Running independent baseline tools",
        "[4] Normalizing discovered surface",
        "[5] Running dependent analyzers",
        "[6] Running optional tools",
        "[7] Building sanitized evidence package",
        "[8] DeepSeek evidence analysis",
        "[9] Writing report",
    ]
    assert [output.index(stage) for stage in stages] == sorted(
        output.index(stage) for stage in stages
    )
    assert "Assessment status: Completed with limitations" in output
    assert "Success: True" not in output
