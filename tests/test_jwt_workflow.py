import base64
import json

import agent
from agent_core.result_normalizer import redact
from tool_registry import TOOLS, validate_registry
from tools.jwt_claims_analyzer import analyze_jwt_claims
from tools.jwt_comparison_analyzer import compare_jwts
from tools.jwt_decoder import jwt_decoder
from tools.jwt_discovery import discover_jwts
from tools.jwt_replay_checker import check_jwt_replay
from tools.jwt_verification_planner import plan_jwt_verification


def _segment(value):
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def _token(payload=None, header=None, signature="signature"):
    return ".".join(
        (
            _segment(header or {"alg": "RS256", "typ": "JWT"}),
            _segment(
                payload or {"sub": "user", "iss": "issuer", "aud": "api", "exp": 2000}
            ),
            signature,
        )
    )


def test_discovery_returns_metadata_only_and_deterministic_fingerprint():
    token = _token()
    evidence = {
        "headers": {"Authorization": f"Bearer {token}"},
        "cookies": {"session": token},
        "javascript": ["assets.api.client", "one.two.three"],
    }
    first = discover_jwts(evidence)
    second = discover_jwts(evidence)
    assert first["token_count"] == 1
    assert (
        first["tokens_observed"][0]["redacted_fingerprint"]
        == second["tokens_observed"][0]["redacted_fingerprint"]
    )
    assert token not in repr(first)
    assert "signature" not in repr(first)


def test_decoder_redacts_claims_signature_and_malformed_inputs():
    token = _token(
        {
            "sub": "personal-user-id",
            "email": "person@example.test",
            "phone": "555-0100",
            "role": "admin",
            "scope": "read write",
            "iat": 1000,
            "exp": 2000,
        }
    )
    result = jwt_decoder(token)
    assert result["valid_structure"] is True
    assert result["signature_verified"] is False
    assert result["verification_status"] == "not_verified"
    assert result["redacted_claims"]["email"] == "[REDACTED]"
    assert "personal-user-id" not in repr(result)
    assert "controlled-signature" not in repr(result)
    assert jwt_decoder("bad.value.signature")["success"] is False
    assert jwt_decoder(token, max_token_bytes=10)["success"] is False


def test_header_and_claim_time_observations_never_promote():
    token = _token(
        {
            "iss": "issuer",
            "aud": "api",
            "role": "admin",
            "scope": "all",
            "iat": 3000,
            "nbf": 3000,
            "exp": 5000,
        },
        {"alg": "none", "typ": "unusual", "kid": "key", "jku": "https://keys"},
        "",
    )
    result = analyze_jwt_claims(token, current_time=2000, max_lifetime_seconds=100)
    kinds = {item["type"] for item in result["header_observations"]}
    assert {
        "unsigned_algorithm_observed",
        "key_identifier_present",
        "remote_key_reference_present",
        "unusual_type_value",
    } <= kinds
    assert {"not_yet_valid", "future_issued_at", "long_lived"} <= set(
        result["time_analysis"]["observations"]
    )
    assert result["vulnerability_status"] == "observation"


def test_claim_expired_missing_exp_and_valid_time_states():
    expired = analyze_jwt_claims(_token({"iat": 100, "exp": 200}), current_time=1000)
    missing = analyze_jwt_claims(_token({"iat": 100}), current_time=1000)
    valid = analyze_jwt_claims(_token({"iat": 900, "exp": 1100}), current_time=1000)
    assert "expired" in expired["time_analysis"]["observations"]
    assert "missing_expiration" in missing["time_analysis"]["observations"]
    assert "valid_at_analysis_time" in valid["time_analysis"]["observations"]


def test_comparison_reports_safe_differences_only():
    first = _token(
        {
            "sub": "account-a",
            "iss": "one",
            "aud": "api",
            "role": "user",
            "iat": 1,
            "exp": 101,
        }
    )
    second = _token(
        {
            "sub": "account-b",
            "iss": "two",
            "aud": "api",
            "role": "admin",
            "iat": 1,
            "exp": 201,
        },
        {"alg": "HS256"},
    )
    result = compare_jwts([first, second])
    assert "alg" in result["header_differences"]
    assert "role" in result["role_scope_differences"]
    assert "sub_value_differs" in result["authorization_boundary_observations"]
    assert "account-a" not in repr(result)
    assert result["vulnerability_status"] == "observation"
    assert compare_jwts([first])["status"] == "not_applicable"


def test_planner_requires_evidence_and_never_executes():
    assert plan_jwt_verification({})["status"] == "not_applicable"
    result = plan_jwt_verification({"claims_summary": {"exp_present": True}})
    assert result["plans"]
    assert all(plan["automatic_execution"] is False for plan in result["plans"])
    assert all(plan["stop_conditions"] for plan in result["plans"])
    assert all(plan["prohibited_actions"] for plan in result["plans"])


def test_replay_disabled_and_safety_blocks(monkeypatch):
    request = {"url": "https://example.test/me", "token": _token(), "method": "GET"}
    assert check_jwt_replay(request, enabled=False)["status"] == "disabled"
    assert (
        check_jwt_replay(request, enabled=True, authenticated_profile=False)["status"]
        == "authentication_required"
    )
    monkeypatch.setattr(
        "tools.jwt_replay_checker.enforce_scope", lambda url: {"allowed": False}
    )
    assert (
        check_jwt_replay(request, enabled=True, authenticated_profile=True)["status"]
        == "blocked"
    )


def test_replay_acceptance_is_observation_and_authorization_is_not_returned(
    monkeypatch,
):
    class Response:
        status_code = 200
        content = b'{"ok":true}'
        headers = {"Content-Type": "application/json", "Set-Cookie": "secret"}
        is_redirect = False

    captured = {}

    def requester(method, url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(
        "tools.jwt_replay_checker.enforce_scope", lambda url: {"allowed": True}
    )
    result = check_jwt_replay(
        {"url": "https://example.test/me", "token": _token(), "method": "GET"},
        enabled=True,
        authenticated_profile=True,
        requester=requester,
    )
    assert result["status"] == "token_accepted"
    assert result["vulnerability_status"] == "observation"
    assert result["response_headers"]["Set-Cookie"] == "[REDACTED]"
    assert "Authorization" in captured["headers"]
    assert _token() not in repr(result)


def test_registry_explain_cli_and_normalizer_are_secret_safe(tmp_path):
    names = {
        "jwt_discovery",
        "jwt_decoder",
        "jwt_claims_analyzer",
        "jwt_comparison_analyzer",
        "jwt_verification_planner",
        "jwt_replay_checker",
    }
    assert names <= TOOLS.keys()
    diagnostics = {item["name"]: item for item in validate_registry()}
    assert all(diagnostics[name]["metadata_complete"] for name in names)
    assert all(diagnostics[name]["callable_exists"] for name in names)
    token = _token({"email": "secret@example.test", "exp": 2000})
    path = tmp_path / "controlled.jwt"
    path.write_text(token, encoding="utf-8")
    result = agent.process_user_input(f"jwt analyze --file {path}")
    assert token not in repr(result)
    assert "secret@example.test" not in repr(result)
    assert "JWT-related" not in repr(
        redact({"tokens_observed": [{"token_length": 10}]})
    )
    assert redact({"tokens_observed": [{"token_length": 10}]})["tokens_observed"]
