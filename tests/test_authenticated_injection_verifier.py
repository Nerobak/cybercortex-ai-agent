from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import tools.authenticated_injection_verifier as verifier

RAW_REQUEST = """GET /search?id=7 HTTP/1.1
Host: authorized.example
Authorization: Bearer CONTROLLED_TOKEN
Accept: application/json

"""


def _response(body: bytes, status: int = 200):
    return SimpleNamespace(
        content=body,
        status_code=status,
        headers={"Content-Type": "application/json"},
        elapsed=timedelta(milliseconds=10),
        encoding="utf-8",
    )


def test_requires_explicit_authorization():
    result = verifier.verify_boolean_sql_injection(RAW_REQUEST, "id")
    assert result["success"] is False
    assert "authorization" in result["error"].lower()


def test_blocks_non_get_requests():
    result = verifier.verify_boolean_sql_injection(
        RAW_REQUEST.replace("GET ", "POST ", 1),
        "id",
        authorization_confirmed=True,
    )
    assert result["success"] is False
    assert "Only GET" in result["error"]


def test_boolean_differential_produces_candidate_without_leaking_credentials(
    monkeypatch,
):
    monkeypatch.setattr(verifier, "enforce_scope", lambda url: {"allowed": True})
    responses = iter(
        (
            _response(b'{"result":"normal-record"}'),
            _response(b'{"result":"normal-record"}'),
            _response(b'{"result":"no-match-and-a-very-different-response"}'),
        )
    )
    observed = []

    def fake_get(url, **kwargs):
        observed.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr(verifier.requests, "get", fake_get)
    result = verifier.verify_boolean_sql_injection(
        RAW_REQUEST, "id", authorization_confirmed=True
    )

    assert result["success"] is True
    assert len(observed) == 3
    assert result["finding"]["status"] == "needs_manual_verification"
    assert result["finding"]["severity"] == "high"
    assert "CONTROLLED_TOKEN" not in str(result)
    assert all(item[1]["allow_redirects"] is False for item in observed)


def test_stable_responses_remain_observation(monkeypatch):
    monkeypatch.setattr(verifier, "enforce_scope", lambda url: {"allowed": True})
    monkeypatch.setattr(
        verifier.requests,
        "get",
        lambda *args, **kwargs: _response(b'{"result":"same"}'),
    )
    result = verifier.verify_boolean_sql_injection(
        RAW_REQUEST, "id", authorization_confirmed=True
    )
    assert result["finding"]["severity"] == "informational"
    assert result["finding"]["status"] == "observation"


def test_out_of_scope_is_blocked_before_requests(monkeypatch):
    monkeypatch.setattr(
        verifier,
        "enforce_scope",
        lambda url: {"allowed": False, "error": "outside scope"},
    )
    result = verifier.verify_boolean_sql_injection(
        RAW_REQUEST, "id", authorization_confirmed=True
    )
    assert result["success"] is False
    assert result["error"] == "outside scope"
