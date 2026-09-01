from __future__ import annotations

import json

import agent_core.capture_verification_orchestrator as campaign


def _request_file(tmp_path):
    path = tmp_path / "capture.txt"
    path.write_text(
        "GET /search?id=7&q=test&url=https%3A%2F%2Fexample.test HTTP/1.1\n"
        "Host: authorized.example\nAuthorization: Bearer PRIVATE\n\n",
        encoding="utf-8",
    )
    return path


def test_plan_selects_parameters_and_enforces_scope(tmp_path, monkeypatch):
    capture = _request_file(tmp_path)
    monkeypatch.setattr(campaign, "enforce_scope", lambda url: {"allowed": True})
    plan = campaign.build_campaign_plan(
        {
            "requests": [str(capture)],
            "enabled_families": ["sqli", "xss", "ssrf"],
            "callback_url": "https://callback.example",
        }
    )
    assert plan["success"] is True
    by_parameter = {item["parameter"]: item["families"] for item in plan["candidates"]}
    assert "sqli" in by_parameter["id"]
    assert "xss" in by_parameter["q"]
    assert "ssrf" in by_parameter["url"]


def test_campaign_requires_authorization(tmp_path):
    result = campaign.run_campaign({"requests": [str(_request_file(tmp_path))]})
    assert result["success"] is False
    assert "authorization" in result["error"].lower()


def test_campaign_active_execution_is_phase2_plan_only(tmp_path, monkeypatch):
    capture = _request_file(tmp_path)
    monkeypatch.setattr(campaign, "enforce_scope", lambda url: {"allowed": True})
    result = campaign.run_campaign(
        {
            "requests": [str(capture)],
            "enabled_families": ["sqli", "ssrf"],
            "callback_url": "https://callback.example",
            "observed_callbacks": ["CALLBACK-1"],
            "request_budget": 20,
        },
        authorization_confirmed=True,
    )
    assert result["success"] is False
    assert result["status"] == "plan_only"
    assert result["requests_used"] == 0
    assert result["executed_candidate_count"] == 0
    assert result["findings"] == []
    assert result["results"] == []
    assert "PRIVATE" not in json.dumps(result)
    assert "plan/offline-only" in result["error"]


def test_out_of_scope_capture_is_not_planned(tmp_path, monkeypatch):
    monkeypatch.setattr(campaign, "enforce_scope", lambda url: {"allowed": False})
    plan = campaign.build_campaign_plan({"requests": [str(_request_file(tmp_path))]})
    assert plan["candidate_count"] == 0
    assert "outside configured scope" in plan["diagnostics"][0]["error"]
