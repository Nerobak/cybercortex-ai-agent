from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import agent_cli
from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.attack_surface import AttackSurfaceGraph
from agent_core.audit_log import TamperEvidentAuditLog
from agent_core.context import ContextProfileStore, compile_context
from agent_core.policy import (
    PolicyProfileStore,
    compile_policy,
    load_policy,
    policy_validation_errors,
)
from tools.safe_http import ScopedHTTPClient, UnsafeRedirectError


def _manifest(**overrides):
    manifest = {
        "program_name": "Authorized Test Program",
        "authorization_reference": "Written program policy",
        "authorization_confirmed": True,
        "allowed_assets": [
            {
                "kind": "exact_host",
                "value": "allowed.example",
                "schemes": ["https"],
                "ports": [443],
            },
            {
                "kind": "wildcard_host",
                "value": "*.wild.example",
                "schemes": ["https"],
                "ports": [443],
            },
            {
                "kind": "url_prefix",
                "value": "https://prefix.example/authorized",
                "schemes": ["https"],
                "ports": [443],
            },
        ],
        "excluded_assets": [
            {
                "kind": "exact_host",
                "value": "blocked.wild.example",
                "schemes": ["https"],
                "ports": [443],
            }
        ],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
        "request_budget": 100,
    }
    manifest.update(overrides)
    return manifest


def _store(tmp_path: Path) -> PolicyProfileStore:
    return PolicyProfileStore(
        tmp_path / "policies", mapping_path=tmp_path / "host-mappings.json"
    )


def _har(path: Path, host: str = "allowed.example") -> Path:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": f"https://{host}/",
                                "headers": [],
                            },
                            "response": {"status": 200, "content": {"size": 0}},
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_create_load_clone_and_version_policy_profiles(tmp_path):
    store = _store(tmp_path)
    created = store.create("program-a", _manifest())
    assert created.profile_name == "program-a"
    assert len(created.policy_hash or "") == 64
    assert store.list() == ["program-a"]
    assert (
        store.load("program-a", validate_for_execution=True).program_name
        == "Authorized Test Program"
    )

    updated_manifest = _manifest(request_budget=75)
    updated = store.update("program-a", updated_manifest)
    assert updated.created_at == created.created_at
    assert updated.updated_at >= created.updated_at
    assert updated.policy_version == 2
    assert updated.policy_hash != created.policy_hash
    assert updated.change_history[0].policy_hash == created.policy_hash
    assert updated.change_history[0].snapshot["request_budget"] == 100

    cloned = store.clone("program-a", "program-b")
    assert cloned.policy_version == 1
    assert cloned.cloned_from == "program-a"
    assert cloned.request_budget == 75
    assert cloned.change_history == []


def test_invalid_malformed_unconfirmed_and_expired_profiles_fail_closed(tmp_path):
    with pytest.raises(ValueError, match="at least one allowed asset"):
        compile_policy({"authorization_confirmed": True})
    malformed = tmp_path / "bad.json"
    malformed.write_text("{bad", encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed policy JSON"):
        load_policy(malformed)

    store = _store(tmp_path)
    store.create("unconfirmed", _manifest(authorization_confirmed=False))
    with pytest.raises(ValueError, match="authorization_confirmed"):
        store.load("unconfirmed", validate_for_execution=True)

    now = datetime.now(timezone.utc)
    store.create(
        "expired",
        _manifest(
            testing_windows=[
                {
                    "starts_at": now - timedelta(days=2),
                    "ends_at": now - timedelta(days=1),
                }
            ]
        ),
    )
    with pytest.raises(ValueError, match="testing window"):
        store.load("expired", validate_for_execution=True)


def test_scope_exact_wildcard_prefix_exclusion_and_methods():
    policy = compile_policy(_manifest())
    assert policy.authorize_url("https://allowed.example/").allowed
    assert not policy.authorize_url("https://allowed.example.attacker.com/").allowed
    assert policy.authorize_url("https://child.wild.example/").allowed
    assert not policy.authorize_url("https://wild.example/").allowed
    assert not policy.authorize_url("https://blocked.wild.example/").allowed
    assert policy.authorize_url("https://prefix.example/authorized/users").allowed
    assert not policy.authorize_url("https://prefix.example/authorized-evil").allowed
    assert not policy.authorize_url("https://allowed.example/", method="POST").allowed


def test_exact_auto_policy_mapping_never_infers_scope(tmp_path):
    store = _store(tmp_path)
    store.create("program-a", _manifest())
    store.map_host("allowed.example", "program-a")
    assert store.profile_for_host("allowed.example") == "program-a"
    assert store.profile_for_host("sub.allowed.example") is None
    with pytest.raises(ValueError, match="not authorized"):
        store.map_host("unknown.example", "program-a")


def test_context_profiles_are_credential_free_and_support_accounts_and_objects(
    tmp_path,
):
    store = ContextProfileStore(tmp_path / "contexts")
    public = store.create("public-site", {"identities": [], "objects": []})
    assert public.model_dump(mode="json") == {"identities": [], "objects": []}
    controlled = store.create(
        "two-account",
        {
            "identities": [
                {
                    "captured_label": "captured-session-1",
                    "label": "account-a",
                    "role": "member",
                    "tenant": "tenant-a",
                    "controlled": True,
                },
                {
                    "captured_label": "captured-session-2",
                    "label": "account-b",
                    "role": "admin",
                    "tenant": "tenant-b",
                    "controlled": True,
                },
            ],
            "objects": [
                {
                    "object_id": "researcher-object",
                    "owner_identity_id": "account-a",
                    "tenant": "tenant-a",
                    "test_owned": True,
                }
            ],
        },
    )
    assert len(controlled.identities) == 2
    assert controlled.objects[0].test_owned is True
    with pytest.raises(ValueError, match="cannot store credentials"):
        compile_context(
            {
                "identities": [
                    {"label": "account-a", "controlled": True, "password": "PRIVATE"}
                ],
                "objects": [],
            }
        )


def test_cli_conflicts_and_auto_policy_unknown_host_fail_closed(tmp_path, capsys):
    capture = _har(tmp_path / "capture.har", "unknown.example")
    store = _store(tmp_path)
    store.create("program-a", _manifest())
    contexts = ContextProfileStore(tmp_path / "contexts")
    contexts.create("public-site", {"identities": [], "objects": []})
    with pytest.raises(SystemExit):
        agent_cli.main(
            [
                "--capture",
                str(capture),
                "--policy",
                "one.json",
                "--policy-profile",
                "program-a",
            ],
            policy_store=store,
            context_store=contexts,
        )
    result = agent_cli.main(
        ["--capture", str(capture), "--auto-policy"],
        policy_store=store,
        context_store=contexts,
    )
    assert result == 2
    assert "No exact policy mapping" in capsys.readouterr().out


def test_profile_selection_summary_and_policy_metadata_in_evidence(
    tmp_path, monkeypatch, capsys
):
    capture = _har(tmp_path / "capture.har")
    store = _store(tmp_path)
    policy = store.create("program-a", _manifest())
    contexts = ContextProfileStore(tmp_path / "contexts")
    contexts.create("public-site", {"identities": [], "objects": []})
    monkeypatch.setattr(
        agent_cli,
        "AdaptiveAssessmentOrchestrator",
        lambda: AdaptiveAssessmentOrchestrator(
            graph=AttackSurfaceGraph(tmp_path / "surface.sqlite3"),
            audit_log=TamperEvidentAuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    output = tmp_path / "assessment.json"
    result = agent_cli.main(
        [
            "--capture",
            str(capture),
            "--policy-profile",
            "program-a",
            "--context-profile",
            "public-site",
            "--profile",
            "intrusive",
            "--output",
            str(output),
        ],
        policy_store=store,
        context_store=contexts,
    )
    assert result == 0
    rendered = capsys.readouterr().out
    assert "Assessment Policy" in rendered
    assert "Authorization: CONFIRMED" in rendered
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["policy_metadata"] == {
        "profile_name": "program-a",
        "policy_version": 1,
        "policy_hash": policy.policy_hash,
        "authorization_reference": "Written program policy",
        "source": "saved_profile",
    }
    assert evidence["context_metadata"] == {
        "profile_name": "public-site",
        "source": "saved_profile",
    }


def test_auto_policy_selects_only_mapped_capture_host(tmp_path, monkeypatch):
    capture = _har(tmp_path / "capture.har")
    store = _store(tmp_path)
    store.create("program-a", _manifest())
    store.map_host("allowed.example", "program-a")
    contexts = ContextProfileStore(tmp_path / "contexts")
    monkeypatch.setattr(
        agent_cli,
        "AdaptiveAssessmentOrchestrator",
        lambda: AdaptiveAssessmentOrchestrator(
            graph=AttackSurfaceGraph(tmp_path / "surface.sqlite3"),
            audit_log=TamperEvidentAuditLog(tmp_path / "audit.jsonl"),
        ),
    )
    output = tmp_path / "auto.json"
    assert (
        agent_cli.main(
            ["--capture", str(capture), "--auto-policy", "--output", str(output)],
            policy_store=store,
            context_store=contexts,
        )
        == 0
    )
    assert (
        json.loads(output.read_text(encoding="utf-8"))["policy_metadata"][
            "profile_name"
        ]
        == "program-a"
    )


def test_external_redirect_is_blocked_by_selected_policy():
    policy = compile_policy(_manifest())

    class Redirect:
        is_redirect = True
        is_permanent_redirect = False
        status_code = 302
        content = b""
        headers = {"Location": "https://attacker.example/landing"}
        url = ""

    client = ScopedHTTPClient(
        policy=policy,
        requester=lambda method, url, **kwargs: Redirect(),
    )
    policy.resolve_dns_before_request = False
    with pytest.raises(UnsafeRedirectError, match="outside authorized scope"):
        client.request("GET", "https://allowed.example/", follow_redirects=True)


def test_out_of_band_profile_edit_breaks_hash_validation(tmp_path):
    store = _store(tmp_path)
    store.create("program-a", _manifest())
    path = store.path_for("program-a")
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["request_budget"] = 5000
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        store.load("program-a", validate_for_execution=True)


def test_missing_authorization_reference_is_ambiguous_and_blocked():
    policy = compile_policy(_manifest(authorization_reference=None))
    assert "authorization_reference is required" in policy_validation_errors(policy)
    assert not policy.authorize_url("https://allowed.example/").allowed
