from __future__ import annotations

import base64
import json
from pathlib import Path

import agent
import phase2_cli
import pytest
from agent_core.agent_models import (
    Hypothesis,
    StrictModel,
    VerificationPlan,
    VerificationStep,
)
from agent_core.benchmark_exporter import build_benchmark_export, export_benchmark
from agent_core.phase2_campaign import build_campaign_export, export_campaign
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.result_normalizer import public_result, sanitize_text
from agent_core.result_provenance import canonical_result_json, result_content_hash
from agent_core.verification_capabilities import typed_producer_provenance
from tools.ai_report_writer import ai_report_writer, sanitize_value

AUTH = "CCX_SECRET_AUTH_001"
COOKIE = "CCX_SECRET_COOKIE_002"
JWT = "CCX_SECRET_JWT_003"
RECOVERY = "CCX_SECRET_RECOVERY_004"
PASSWORD = "CCX_SECRET_PASSWORD_005"
QUERY = "CCX_SECRET_QUERY_006"
QUOTED_PASSWORD = "CCX_QUOTED_PASSWORD_001"
QUOTED_ACCESS = "CCX_QUOTED_ACCESS_002"
QUOTED_REFRESH = "CCX_QUOTED_REFRESH_003"
QUOTED_SESSION = "CCX_QUOTED_SESSION_004"
QUOTED_AUTH = "CCX_QUOTED_AUTH_005"
QUOTED_COOKIE = "CCX_QUOTED_COOKIE_006"
QUOTED_JWT = "CCX_QUOTED_JWT_007"
QUOTED_IDENTITY = "CCX_QUOTED_IDENTITY_008"


def _jwt_segment(value: dict[str, str]) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return encoded.rstrip(b"=").decode("ascii")


RAW_JWT = (
    f'{_jwt_segment({"alg": "HS256", "typ": "JWT"})}.'
    f'{_jwt_segment({"sub": QUOTED_JWT})}.controlled-signature'
)
SENTINELS = (
    AUTH,
    COOKIE,
    JWT,
    RECOVERY,
    PASSWORD,
    QUERY,
    QUOTED_PASSWORD,
    QUOTED_ACCESS,
    QUOTED_REFRESH,
    QUOTED_SESSION,
    QUOTED_AUTH,
    QUOTED_COOKIE,
    QUOTED_JWT,
    QUOTED_IDENTITY,
    RAW_JWT,
)


class NestedModel(StrictModel):
    error: str
    token_request_count: int


def _assert_no_sentinels(value: object) -> None:
    rendered = json.dumps(value, sort_keys=True, default=str)
    for secret in SENTINELS:
        assert secret not in rendered


def _quoted_secret_diagnostics() -> list[str]:
    return [
        f'HTTP error body: {{"password":"{QUOTED_PASSWORD}"}}',
        f'transport error {{"access_token": "{QUOTED_ACCESS}"}}',
        f'payload={{"refresh_token":"{QUOTED_REFRESH}"}}',
        f'error payload={{"session_token":"{QUOTED_SESSION}"}}',
        f'response={{"Authorization":"Bearer {QUOTED_AUTH}"}}',
        f'response={{"Cookie":"sid={QUOTED_COOKIE}"}}',
        f'response={{"Set-Cookie":"session={QUOTED_COOKIE}; HttpOnly"}}',
        f'diagnostic {{"jwt":"{RAW_JWT}"}}',
        f'identity={{"email":"{QUOTED_IDENTITY}@example.test"}}',
    ]


def _run() -> dict:
    return {
        "run_id": "sanitizer-run",
        "target": "https://example.test/api",
        "assessment_mode": "verify",
        "attack_surface": {
            "routes": [],
            "parameters": [],
            "objects": [],
            "jwt": {
                "raw_jwt": JWT,
                "tokens_observed": 1,
                "sources": ["authorization_header"],
                "algorithms": ["RS256"],
                "signature_present": True,
            },
        },
        "hypotheses": [
            {
                "hypothesis_id": "hyp-sanitizer",
                "category": "bola",
                "title": "Controlled object authorization hypothesis",
                "confidence": "medium",
                "status": "verified",
                "endpoint": "https://example.test/orders/1",
                "target_surface": {
                    "method": "GET",
                    "path": "/orders/{order_id}",
                    "parameter": "order_id",
                },
                "evidence_basis": [{"observation": f"Authorization: Bearer {AUTH}"}],
            }
        ],
        "verification_plans": [],
        "verification_results": [
            {
                "hypothesis_id": "hyp-sanitizer",
                "category": "bola",
                "status": "verified",
                "confidence": "high",
                "requests_used": 2,
                "result_schema_version": 2,
                "executor": typed_producer_provenance("bola"),
                "evidence_summary": [
                    f"Cookie: sid={COOKIE}",
                    f"request failed at https://example.test/a?access_token={QUERY}",
                    *_quoted_secret_diagnostics(),
                ],
                "password": PASSWORD,
                "recovery_code": RECOVERY,
                "private_recovery_state": {"challenge": RECOVERY},
            }
        ],
        "metrics": {
            "request_count": 2,
            "auth_requests": 5,
            "invalid_password_auth_requests": 3,
            "token_request_count": 2,
            "password_field_count": 1,
        },
    }


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        (f'{{"password":"{QUOTED_PASSWORD}"}}', QUOTED_PASSWORD),
        (f'{{"password": "{QUOTED_PASSWORD}"}}', QUOTED_PASSWORD),
        (f"{{'password':'{QUOTED_PASSWORD}'}}", QUOTED_PASSWORD),
        (f'"{{\\"password\\":\\"{QUOTED_PASSWORD}\\"}}"', QUOTED_PASSWORD),
        (f'{{"access_token":"{QUOTED_ACCESS}"}}', QUOTED_ACCESS),
        (f'{{"access_token":"{RAW_JWT}"}}', RAW_JWT),
        (f'"{{\\"access_token\\":\\"{QUOTED_ACCESS}\\"}}"', QUOTED_ACCESS),
        (f'{{"refresh_token":"{QUOTED_REFRESH}"}}', QUOTED_REFRESH),
        (f'{{"session_token":"{QUOTED_SESSION}"}}', QUOTED_SESSION),
        (f'{{"recovery_code":"{RECOVERY}"}}', RECOVERY),
        (f'{{"authorization_code":"{RECOVERY}"}}', RECOVERY),
        (f'{{"api_key":"{QUOTED_ACCESS}"}}', QUOTED_ACCESS),
        (f'{{"client_secret":"{QUOTED_ACCESS}"}}', QUOTED_ACCESS),
        (f'{{"credential_reference":"{QUOTED_ACCESS}"}}', QUOTED_ACCESS),
        (f'{{"vault_reference":"{QUOTED_ACCESS}"}}', QUOTED_ACCESS),
        (f'{{"Authorization":"Bearer {QUOTED_AUTH}"}}', QUOTED_AUTH),
        (f'{{"Authorization":"Basic {QUOTED_AUTH}"}}', QUOTED_AUTH),
        (f'{{"Proxy-Authorization":"Bearer {QUOTED_AUTH}"}}', QUOTED_AUTH),
        (f'{{"Cookie":"sid={QUOTED_COOKIE}"}}', QUOTED_COOKIE),
        (
            f'{{"Set-Cookie":"session={QUOTED_COOKIE}; HttpOnly"}}',
            QUOTED_COOKIE,
        ),
        (f'{{"jwt":"{RAW_JWT}"}}', RAW_JWT),
        (f'{{"email":"{QUOTED_IDENTITY}@example.test"}}', QUOTED_IDENTITY),
        (f'{{"username":"{QUOTED_IDENTITY}"}}', QUOTED_IDENTITY),
        (
            f'prefix {{"password":"{QUOTED_PASSWORD}"}} middle '
            f'{{"access_token":"{QUOTED_ACCESS}"}} suffix',
            QUOTED_PASSWORD,
        ),
        (f'HTTP error body: {{"password":"{QUOTED_PASSWORD}"}}', QUOTED_PASSWORD),
        (
            f'transport error {{"access_token":"{QUOTED_ACCESS}"}}',
            QUOTED_ACCESS,
        ),
        (f'response={{"cookie":"sid={QUOTED_COOKIE}"}}', QUOTED_COOKIE),
    ],
)
def test_quoted_structured_secret_matrix(raw: str, secret: str) -> None:
    cleaned = sanitize_text(raw)

    assert secret not in cleaned
    assert "[REDACTED]" in cleaned
    _assert_no_sentinels(public_result({"diagnostic": raw}))


def test_quoted_multiple_and_nested_diagnostics_are_sanitized() -> None:
    payload = {
        "nested": {
            "diagnostics": [
                f'prefix {{"password":"{QUOTED_PASSWORD}"}} middle '
                f'{{"access_token":"{QUOTED_ACCESS}"}} suffix',
                (f"{{'refresh_token':'{QUOTED_REFRESH}'}}",),
            ]
        }
    }

    cleaned = public_result(payload)

    _assert_no_sentinels(cleaned)
    assert json.dumps(cleaned).count("[REDACTED]") == 3


def test_structured_and_embedded_identity_and_secret_values_have_privacy_parity() -> (
    None
):
    cases = {
        "password": QUOTED_PASSWORD,
        "email": f"{QUOTED_IDENTITY}@example.test",
        "username": QUOTED_IDENTITY,
    }

    for key, secret in cases.items():
        structured = public_result({key: secret})
        embedded = public_result({"diagnostic": json.dumps({key: secret})})
        assert structured[key] == "[REDACTED]"
        assert secret not in embedded["diagnostic"]
        assert f'"{key}": "[REDACTED]"' in embedded["diagnostic"]


def test_quoted_safe_telemetry_is_preserved_verbatim() -> None:
    telemetry = (
        '{"status_code":200,"auth_requests":5,'
        '"invalid_password_auth_requests":3,"token_request_count":2,'
        '"password_field_count":1,"authorization_present":true,'
        '"jwt_algorithm":"HS256","cookie_count":2,"secure":true,'
        '"same_site":"Lax"}'
    )

    assert sanitize_text(telemetry) == telemetry
    assert public_result({"diagnostic": telemetry})["diagnostic"] == telemetry


def test_canonical_sanitizer_handles_nested_models_strings_and_safe_telemetry() -> None:
    payload = {
        "authorization": f"Bearer {AUTH}",
        "cookie": f"sid={COOKIE}",
        "set_cookie": f"session={COOKIE}; HttpOnly",
        "password": PASSWORD,
        "recovery_code": RECOVERY,
        "url": f"https://example.test/path?id=7&token={QUERY}",
        "diagnostics": [
            f"Authorization: Basic {AUTH}",
            f"Proxy-Authorization: Custom {AUTH}",
            f"access_token={QUERY}",
            f"Cookie: sid={COOKIE}",
        ],
        "model": NestedModel(
            error=f"failed with Authorization: Bearer {AUTH}",
            token_request_count=2,
        ),
        "tuple_value": (f"Bearer {AUTH}",),
        "set_value": {f"session={COOKIE}"},
        "invalid_password_auth_requests": 3,
        "token_request_count": 2,
        "password_field_count": 1,
        "credential_attempt_count": 3,
        "status_code": 200,
        "status_class": "2xx",
        "schema_fields": ["id", "owner_id"],
        "structure_hash": "sha256:structure",
        "body_hash": "sha256:body",
        "retry_after_present": True,
        "cookie_metadata": {
            "cookie_present": True,
            "cookie_count": 2,
            "cookie_names": ["session", "csrf"],
            "secure": True,
            "http_only": True,
            "same_site": "Lax",
        },
        "jwt": {
            "raw_jwt": JWT,
            "signature": JWT,
            "tokens_observed": 1,
            "sources": ["authorization_header"],
            "algorithms": ["RS256"],
            "token_type": "JWT",
            "signature_present": True,
        },
        "preserved_challenge": {"challenge_id": RECOVERY},
    }

    cleaned = public_result(payload)
    _assert_no_sentinels(cleaned)
    assert "preserved_challenge" not in cleaned
    assert cleaned["invalid_password_auth_requests"] == 3
    assert cleaned["token_request_count"] == 2
    assert cleaned["password_field_count"] == 1
    assert cleaned["credential_attempt_count"] == 3
    assert cleaned["jwt"] == {
        "tokens_observed": 1,
        "sources": ["authorization_header"],
        "algorithms": ["RS256"],
        "token_type": "JWT",
        "signature_present": True,
    }
    assert cleaned["cookie_metadata"]["cookie_count"] == 2
    assert cleaned["cookie_metadata"]["cookie_names"] == ["session", "csrf"]
    assert cleaned["model"]["token_request_count"] == 2


def test_embedded_headers_urls_and_exception_text_are_sanitized() -> None:
    values = [
        f"request failed with Authorization: Bearer {AUTH} at endpoint",
        f"Authorization: Basic {AUTH}",
        f"Proxy-Authorization: Custom {AUTH}",
        f"Cookie: sid={COOKIE}",
        f"Set-Cookie: session={COOKIE}; Secure; HttpOnly",
        f"https://example.test/a?id=9&api_key={QUERY}&code={RECOVERY}",
        str(RuntimeError(f"transport error: access_token={QUERY}")),
    ]
    cleaned = [sanitize_text(item) for item in values]
    _assert_no_sentinels(cleaned)
    assert "id=9" in cleaned[5]
    assert "Authorization: [REDACTED] at endpoint" in cleaned[0]


def test_public_persistence_campaign_benchmark_and_report_boundaries(
    tmp_path: Path,
) -> None:
    run = _run()
    hash_basis = canonical_result_json(run["verification_results"][0])
    store = Phase2RunStore(tmp_path / "runs")
    run_path = Path(store.save(run))
    base_run = store.load(run_path)
    run["verification_results"].append(
        {
            "hypothesis_id": "hyp-sanitizer",
            "category": "bola",
            "status": "inconclusive",
            "confidence": "medium",
            "requests_used": 0,
            "result_schema_version": 2,
            "executor": typed_producer_provenance("bola"),
            "evidence_summary": [
                f'revision diagnostic {{"session_token":"{QUOTED_SESSION}"}}'
            ],
        }
    )
    revision_path = Path(store.save(run))
    latest = store.latest_path
    stored = store.load_run("sanitizer-run")

    benchmark_path = tmp_path / "benchmark.json"
    export_benchmark(run, benchmark_path)
    benchmark = build_benchmark_export(run)
    campaign = {
        "campaign_id": "sanitizer-campaign",
        "name": "sanitizer-campaign",
        "target": "https://example.test/api",
        "run_ids": ["sanitizer-run"],
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    campaign_path = tmp_path / "campaign.json"
    export_campaign(campaign, [run], campaign_path)
    campaign_export = build_campaign_export(campaign, [run])
    markdown = render_phase2_report(run)

    artifacts = [
        hash_basis,
        base_run,
        stored,
        run_path.read_text(encoding="utf-8"),
        revision_path.read_text(encoding="utf-8"),
        latest.read_text(encoding="utf-8"),
        benchmark,
        benchmark_path.read_text(encoding="utf-8"),
        campaign_export,
        campaign_path.read_text(encoding="utf-8"),
        markdown,
    ]
    _assert_no_sentinels(artifacts)
    assert revision_path == store.revision_path("sanitizer-run", 2)
    for result in stored["verification_results"]:
        assert result["result_hash"] == result_content_hash(result)
    for exported_finding in (
        benchmark["findings"][0],
        campaign_export["findings"][0],
    ):
        reference = exported_finding["verification_result_reference"]
        exact = store.load_result(
            reference["run_id"],
            reference["result_id"],
            result_hash=reference["result_hash"],
        )
        assert exact["result_hash"] == reference["result_hash"]
    assert stored["metrics"]["invalid_password_auth_requests"] == 3
    assert stored["attack_surface"]["jwt"]["algorithms"] == ["RS256"]
    assert "private_recovery_state" not in json.dumps(stored)


def test_ai_report_grounding_and_rendered_report_receive_only_public_data(
    tmp_path: Path,
) -> None:
    run = _run()
    input_payload = {
        "target": "https://example.test",
        "phase2": run,
        "observed_surface": run["attack_surface"],
        "tool_results": {
            "transport": {
                "status": "failed",
                "error": f"Authorization: Bearer {AUTH}",
            }
        },
        "execution_summary": {},
        "coverage": {},
        "coverage_detail": {},
    }
    cleaned = sanitize_value(input_payload)
    result = ai_report_writer(
        "https://example.test",
        input_payload,
        output_dir=str(tmp_path / "reports"),
        allow_network_analysis=False,
    )
    artifacts = [
        cleaned,
        result,
        Path(result["evidence_file"]).read_text(encoding="utf-8"),
        Path(result["report_file"]).read_text(encoding="utf-8"),
    ]
    _assert_no_sentinels(artifacts)
    assert cleaned["observed_surface"]["jwt"]["algorithms"] == ["RS256"]


def test_agent_scan_returns_the_canonical_public_result(monkeypatch) -> None:
    monkeypatch.setattr(agent, "enforce_scope", lambda _target: {"allowed": True})
    monkeypatch.setattr(
        agent,
        "run_workflow",
        lambda *_args, **_kwargs: {
            "success": True,
            "phase2": _run(),
            "error": f"Authorization: Bearer {AUTH}",
        },
    )
    result = agent.run_scan_command("https://example.test --mode observe")
    _assert_no_sentinels(result)
    assert "private_recovery_state" not in json.dumps(result)


def test_phase2_cli_returns_the_canonical_public_result(
    tmp_path: Path, monkeypatch
) -> None:
    hypothesis = Hypothesis(
        hypothesis_id="hyp-cli-sanitizer",
        category="bola",
        title="CLI sanitizer boundary",
        rationale="The public CLI result must use the canonical serializer.",
        target="https://example.test/api",
    )
    plan = VerificationPlan(
        plan_id="plan-cli-sanitizer",
        hypothesis_id=hypothesis.hypothesis_id,
        target=hypothesis.target,
        profile="baseline",
        steps=[
            VerificationStep(
                step_id="step-cli-sanitizer",
                name="Return deterministic diagnostic",
                tool="controlled_verification_executor",
            )
        ],
    )
    run = {
        "run_id": "cli-sanitizer-run",
        "target": hypothesis.target,
        "hypotheses": [hypothesis.model_dump(mode="json")],
        "verification_plans": [plan.model_dump(mode="json")],
        "verification_results": [],
        "metrics": {},
    }

    class FakeStore:
        def load(self) -> dict:
            return run

        def save(self, candidate: dict) -> str:
            cleaned = public_result(candidate)
            candidate.clear()
            candidate.update(cleaned)
            return str(tmp_path / "cli-sanitizer-run.json")

    class FakeRuntime:
        def execute_selected(self, *_args, **_kwargs) -> dict:
            return {
                "status": "inconclusive",
                "confidence": "low",
                "requests_used": 0,
                "request_delta": {
                    "discovery": 0,
                    "auth": 0,
                    "verification": 0,
                    "cleanup": 0,
                    "attempted": 0,
                    "total": 0,
                },
                "evidence_summary": [f'CLI error={{"access_token":"{QUOTED_ACCESS}"}}'],
            }

    input_path = tmp_path / "input.json"
    input_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(phase2_cli, "Phase2RunStore", FakeStore)
    monkeypatch.setattr(phase2_cli, "load_policy", lambda _path: object())
    monkeypatch.setattr(
        phase2_cli,
        "load_controlled_context",
        lambda _path, _vault: object(),
    )
    monkeypatch.setattr(
        phase2_cli,
        "create_verification_runtime",
        lambda **_kwargs: FakeRuntime(),
    )

    result = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(tmp_path / "policy.json"),
            "--context",
            str(tmp_path / "context.json"),
            "--input",
            str(input_path),
        ]
    )

    _assert_no_sentinels(result)
    assert result["evidence_summary"] == ['CLI error={"access_token":"[REDACTED]"}']


def test_vault_handles_and_private_state_fail_closed_at_public_boundary() -> None:
    cleaned = public_result(
        {
            "credential_reference": "vault:reusable-handle",
            "session_reference": "vault:session-handle",
            "credential_bound": True,
            "session_reference_present": True,
            "private_recovery_state": {"challenge": RECOVERY},
        }
    )
    assert cleaned["credential_reference"] == "[REDACTED]"
    assert cleaned["session_reference"] == "[REDACTED]"
    assert cleaned["credential_bound"] is True
    assert cleaned["session_reference_present"] is True
    assert "private_recovery_state" not in cleaned
