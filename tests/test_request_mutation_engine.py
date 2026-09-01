from __future__ import annotations

from types import SimpleNamespace

import tools.request_mutation_engine as engine

RAW = """GET /render?name=test HTTP/1.1
Host: authorized.example
Authorization: Bearer PRIVATE

"""


def _response(text: str):
    return SimpleNamespace(
        content=text.encode(),
        status_code=200,
        headers={"Content-Type": "text/html"},
        encoding="utf-8",
    )


def test_probe_plan_requires_controlled_inputs():
    try:
        engine.build_probes(["ssrf"], seed="x")
        assert False
    except ValueError as exc:
        assert "callback" in str(exc).lower()
    try:
        engine.build_probes(
            ["traversal"],
            seed="x",
            traversal_canary_path="../../etc/passwd",
            traversal_expected_marker="x",
        )
        assert False
    except ValueError as exc:
        assert "safe relative" in str(exc).lower()


def test_scope_and_authorization_are_mandatory(monkeypatch):
    assert engine.verify_request_mutations(RAW, "name", ["xss"])["success"] is False
    monkeypatch.setattr(
        engine, "enforce_scope", lambda url: {"allowed": False, "error": "outside"}
    )
    result = engine.verify_request_mutations(
        RAW, "name", ["xss"], authorization_confirmed=True
    )
    assert result["error"] == "outside"


def test_ssti_evaluation_is_verified_and_secrets_are_not_returned(monkeypatch):
    monkeypatch.setattr(engine, "enforce_scope", lambda url: {"allowed": True})
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        if len(calls) == 1:
            return _response("baseline")
        marker = engine._marker("ssti", "/render:name")
        return _response(marker + "49")

    monkeypatch.setattr(engine.requests, "get", fake_get)
    result = engine.verify_request_mutations(
        RAW, "name", ["ssti"], authorization_confirmed=True
    )
    assert result["success"] is True
    assert result["request_count"] == 3
    assert all(item["status"] == "verified" for item in result["findings"])
    assert "PRIVATE" not in str(result)
    assert all(call[1]["allow_redirects"] is False for call in calls)


def test_reflection_is_not_mislabeled_as_executed_xss(monkeypatch):
    monkeypatch.setattr(engine, "enforce_scope", lambda url: {"allowed": True})
    calls = 0

    def fake_get(url, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _response("baseline")
        return _response(engine._marker("xss", "/render:name"))

    monkeypatch.setattr(engine.requests, "get", fake_get)
    result = engine.verify_request_mutations(
        RAW, "name", ["xss"], authorization_confirmed=True
    )
    assert result["findings"][0]["status"] == "needs_manual_verification"
    assert result["findings"][0]["proof_type"] == "reflection"
