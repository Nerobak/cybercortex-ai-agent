from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any

import pytest

from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.phase2_campaign import Phase2CampaignStore, build_campaign_export
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.result_provenance import (
    RESULT_SCHEMA_VERSION,
    result_content_hash,
    target_identity,
)
from agent_core.verification_capabilities import typed_producer_provenance

TARGET = "https://service.example/api"
RESULT_ID = re.compile(r"res_[0-9a-f]{32}")
RESULT_HASH = re.compile(r"sha256:[0-9a-f]{64}")


def _delta(total: int = 1) -> dict[str, int]:
    return {
        "discovery": 0,
        "auth": 0,
        "verification": total,
        "cleanup": 0,
        "attempted": total,
        "total": total,
    }


def _hypothesis(hypothesis_id: str = "hyp-provenance") -> dict[str, Any]:
    return {
        "hypothesis_id": hypothesis_id,
        "category": "bola",
        "status": "proposed",
        "confidence": "medium",
        "method": "GET",
        "target_surface": {
            "method": "GET",
            "path": "/objects/{object_id}",
            "parameter": "object_id",
        },
        "evidence_basis": [{"observation": "controlled object route observed"}],
    }


def _result(
    status: str,
    *,
    hypothesis_id: str = "hyp-provenance",
    evidence: str | None = None,
    stage: str | None = None,
    total: int = 1,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hypothesis_id": hypothesis_id,
        "category": "bola",
        "status": status,
        "confidence": "high",
        "evidence_summary": [evidence or f"controlled {status} evidence"],
        "request_delta": _delta(total),
        "requests_used": total,
        "runtime_binding": {
            "required_accounts": 2,
            "bound_accounts": 2,
            "policy_authorized": True,
        },
    }
    if stage is not None:
        result["recovery_phase"] = stage
        result["category"] = "recovery_state_enforcement"
    result["result_schema_version"] = RESULT_SCHEMA_VERSION
    result["executor"] = typed_producer_provenance(result["category"])
    return result


def _run(
    run_id: str,
    *,
    target: str = TARGET,
    results: list[dict[str, Any]] | None = None,
    hypothesis_id: str = "hyp-provenance",
    category: str = "bola",
) -> dict[str, Any]:
    hypothesis = _hypothesis(hypothesis_id)
    hypothesis["category"] = category
    return {
        "run_id": run_id,
        "target": target,
        "assessment_mode": "verify",
        "profile": "authenticated",
        "hypotheses": [hypothesis],
        "verification_results": results or [],
        "metrics": {
            "total_requests": sum(_result_total(item) for item in results or [])
        },
    }


def _result_total(result: dict[str, Any]) -> int:
    delta = result.get("request_delta") or {}
    return int(delta.get("total") or 0)


def _campaign_payload(run: dict[str, Any]) -> dict[str, Any]:
    campaign = {
        "campaign_id": "provenance",
        "name": "provenance",
        "target": run["target"],
        "target_fingerprint": run.get("target_fingerprint"),
        "created_at": "2026-08-29T00:00:00+00:00",
        "updated_at": "2026-08-29T00:00:00+00:00",
        "run_ids": [run["run_id"]],
    }
    return build_campaign_export(campaign, [run])


def test_new_result_has_stable_identity_hash_executor_and_schema(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-new-provenance", results=[_result("verified")])

    path = Path(store.save(run))
    stored = store.load(path)
    result = stored["verification_results"][0]

    assert RESULT_ID.fullmatch(result["result_id"])
    assert RESULT_HASH.fullmatch(result["result_hash"])
    assert result["result_hash"] == result_content_hash(result)
    assert result["result_schema_version"] == RESULT_SCHEMA_VERSION
    assert result["executor"] == {
        "name": "ControlledVerificationExecutor",
        "version": "bola/v1",
        "implementation_family": "phase2_controlled_execution",
    }
    assert run["verification_results"][0] == result


def test_result_hash_canonicalization_is_deterministic_and_content_sensitive() -> None:
    first = {
        "status": "verified",
        "hypothesis_id": "hyp-canonical",
        "nested": {"b": [2, {"z": True, "a": None}], "a": 1},
    }
    equivalent = {
        "nested": {"a": 1, "b": [2, {"a": None, "z": True}]},
        "hypothesis_id": "hyp-canonical",
        "status": "verified",
    }
    changed = {**equivalent, "status": "rejected"}

    assert result_content_hash(first) == result_content_hash(equivalent)
    assert result_content_hash(first) != result_content_hash(changed)


def test_idempotent_save_is_accepted_and_conflict_cannot_corrupt_history(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-idempotent", results=[_result("inconclusive")])
    original_path = Path(store.save(run))
    original_bytes = original_path.read_bytes()
    original_result = deepcopy(run["verification_results"][0])

    assert Path(store.save(run)) == original_path
    assert not store.revision_path(run["run_id"], 2).exists()

    conflict = deepcopy(run)
    conflict["verification_results"][0]["status"] = "verified"
    with pytest.raises(ValueError, match="Immutable persisted result content"):
        store.save(conflict)

    assert original_path.read_bytes() == original_bytes
    assert store.load_run(run["run_id"])["verification_results"][0] == original_result
    assert not store.revision_path(run["run_id"], 2).exists()


def test_same_hypothesis_appends_distinct_results_and_preserves_old_result(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-multiple-results", results=[_result("inconclusive")])
    first_path = Path(store.save(run))
    first_snapshot = store.load(first_path)["verification_results"][0]
    first_bytes = first_path.read_bytes()

    run["verification_results"].append(
        _result("verified", evidence="stronger evidence")
    )
    second_path = Path(store.save(run))
    latest = store.load_run(run["run_id"])
    first, second = latest["verification_results"]

    assert second_path == store.revision_path(run["run_id"], 2)
    assert first_path.read_bytes() == first_bytes
    assert first == first_snapshot
    assert first["result_id"] != second["result_id"]
    assert (
        store.load_result(
            run["run_id"], first["result_id"], result_hash=first["result_hash"]
        )
        == first_snapshot
    )
    finding = _campaign_payload(latest)["findings"][0]
    assert finding["status"] == "verified"
    assert finding["verification_result_reference"]["result_id"] == second["result_id"]


def test_recovery_public_stages_are_append_only_and_private_state_is_absent(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    hypothesis_id = "hyp-recovery-history"
    issued = _result(
        "awaiting_controlled_evidence",
        hypothesis_id=hypothesis_id,
        stage="challenge_issued",
    )
    issued["private_recovery_state"] = {"challenge": "PRIVATE_CHALLENGE_SENTINEL"}
    run = _run(
        "run-recovery-history",
        results=[issued],
        hypothesis_id=hypothesis_id,
        category="recovery_state_enforcement",
    )
    first_path = Path(store.save(run))
    first_bytes = first_path.read_bytes()
    first_result = deepcopy(run["verification_results"][0])

    run["verification_results"].append(
        _result(
            "verification_pending_cleanup",
            hypothesis_id=hypothesis_id,
            stage="verification_pending_cleanup",
            total=3,
        )
    )
    second_path = Path(store.save(run))
    second_bytes = second_path.read_bytes()
    pending_result = deepcopy(run["verification_results"][1])

    run["verification_results"].append(
        _result(
            "rejected",
            hypothesis_id=hypothesis_id,
            stage="completed",
            total=1,
        )
    )
    third_path = Path(store.save(run))
    latest = store.load(third_path)

    assert first_path.read_bytes() == first_bytes
    assert second_path.read_bytes() == second_bytes
    assert store.load(first_path)["verification_results"] == [first_result]
    assert store.load(second_path)["verification_results"][1] == pending_result
    assert len({item["result_id"] for item in latest["verification_results"]}) == 3
    assert "PRIVATE_CHALLENGE_SENTINEL" not in json.dumps(latest)
    assert "private_recovery_state" not in json.dumps(latest)


def test_campaign_reference_remains_resolvable_after_later_verification(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    campaigns = Phase2CampaignStore(tmp_path / "campaigns", run_store=store)
    run = _run("run-campaign-stability", results=[_result("inconclusive")])
    store.save(run)
    campaigns.create("stable-campaign", TARGET)
    campaigns.add_run("stable-campaign", run["run_id"])
    campaign, resolved = campaigns.resolve("stable-campaign")
    export_a = build_campaign_export(campaign, resolved)
    old_reference = deepcopy(export_a["findings"][0]["verification_result_reference"])
    old_result = store.load_result(
        old_reference["run_id"],
        old_reference["result_id"],
        result_hash=old_reference["result_hash"],
    )

    run["verification_results"].append(_result("verified", evidence="later proof"))
    store.save(run)
    campaign, resolved = campaigns.resolve("stable-campaign")
    export_b = build_campaign_export(campaign, resolved)
    pinned_reference = export_b["findings"][0]["verification_result_reference"]

    assert export_a["findings"][0]["verification_result_reference"] == old_reference
    assert pinned_reference == old_reference
    assert export_b == export_a

    campaigns.refresh_run("stable-campaign", run["run_id"])
    campaign, resolved = campaigns.resolve("stable-campaign")
    export_c = build_campaign_export(campaign, resolved)
    refreshed_reference = export_c["findings"][0]["verification_result_reference"]

    assert refreshed_reference["result_id"] != old_reference["result_id"]
    assert (
        store.load_result(
            old_reference["run_id"],
            old_reference["result_id"],
            result_hash=old_reference["result_hash"],
        )
        == old_result
    )


def test_exact_target_fingerprint_is_confidential_normalized_and_enforced(
    tmp_path: Path,
) -> None:
    first_raw = "HTTPS://Service.Example:443/api?token=FIRST_SECRET&b=2#a"
    second_raw = "https://service.example/api?b=2&token=SECOND_SECRET#b"
    equivalent = "https://service.example/api?b=2&token=FIRST_SECRET"
    first_public, first_fingerprint = target_identity(first_raw)
    second_public, second_fingerprint = target_identity(second_raw)

    assert first_public == second_public
    assert first_fingerprint != second_fingerprint
    assert first_fingerprint == target_identity(equivalent)[1]
    assert "FIRST_SECRET" not in first_public
    assert "SECOND_SECRET" not in second_public

    store = Phase2RunStore(tmp_path / "runs")
    campaigns = Phase2CampaignStore(tmp_path / "campaigns", run_store=store)
    first_run = _run("run-target-first", target=first_raw)
    second_run = _run("run-target-second", target=second_raw)
    store.save(first_run)
    store.save(second_run)
    campaigns.create("target-bound", first_raw)
    campaigns.add_run("target-bound", first_run["run_id"])

    with pytest.raises(ValueError, match="different targets"):
        campaigns.add_run("target-bound", second_run["run_id"])


def test_target_userinfo_is_removed_publicly_but_part_of_exact_fingerprint() -> None:
    first_public, first_fingerprint = target_identity(
        "https://user:FIRST_PASSWORD@service.example/api"
    )
    second_public, second_fingerprint = target_identity(
        "https://user:SECOND_PASSWORD@service.example/api"
    )

    assert first_public == second_public == TARGET
    assert first_fingerprint != second_fingerprint
    assert "PASSWORD" not in first_public + second_public


def test_campaign_benchmark_report_and_request_delta_use_exact_stored_result(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    original_delta = _delta(2)
    result = _result("verified", total=2)
    result["request_delta"] = deepcopy(original_delta)
    run = _run("run-export-provenance", results=[result])
    store.save(run)
    stored = store.load_run(run["run_id"])
    stored_result = stored["verification_results"][0]
    expected_reference = {
        "run_id": stored["run_id"],
        "result_id": stored_result["result_id"],
        "result_hash": stored_result["result_hash"],
        "hypothesis_id": stored_result["hypothesis_id"],
        "executor_version": "bola/v1",
    }

    campaign_finding = _campaign_payload(stored)["findings"][0]
    benchmark_finding = build_benchmark_export(stored)["findings"][0]
    report = render_phase2_report(stored)

    assert campaign_finding["verification_result_reference"] == expected_reference
    assert benchmark_finding["verification_result_reference"] == expected_reference
    assert campaign_finding["requests_used"] == original_delta["total"]
    assert benchmark_finding["requests_used"] == original_delta["total"]
    assert stored_result["request_delta"] == original_delta
    assert stored_result["result_id"] in report
    assert stored_result["result_hash"][:23] in report
    assert "ControlledVerificationExecutor bola/v1" in report


def test_legacy_run_and_campaign_remain_readable_without_fabricated_provenance(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    legacy = _run("run-legacy", results=[_result("verified")])
    legacy_result = legacy["verification_results"][0]
    legacy_result.pop("request_delta")
    legacy_result.pop("result_schema_version")
    legacy_result.pop("executor")
    store.directory.mkdir(parents=True)
    store.run_path(legacy["run_id"]).write_text(
        json.dumps(legacy, indent=2) + "\n", encoding="utf-8"
    )

    loaded = store.load_run(legacy["run_id"])
    result = loaded["verification_results"][0]
    assert "result_id" not in result
    assert "result_hash" not in result
    assert "executor" not in result
    assert "target_fingerprint" not in loaded

    campaigns = Phase2CampaignStore(tmp_path / "campaigns", run_store=store)
    campaigns.directory.mkdir(parents=True)
    legacy_campaign = {
        "campaign_id": "legacy-campaign",
        "name": "legacy-campaign",
        "target": TARGET,
        "run_ids": [legacy["run_id"]],
        "created_at": "2026-08-29T00:00:00+00:00",
        "updated_at": "2026-08-29T00:00:00+00:00",
    }
    campaigns.campaign_path("legacy-campaign").write_text(
        json.dumps(legacy_campaign), encoding="utf-8"
    )
    campaign, runs = campaigns.resolve("legacy-campaign")
    reference = build_campaign_export(campaign, runs)["findings"][0][
        "verification_result_reference"
    ]
    benchmark_reference = build_benchmark_export(loaded)["findings"][0][
        "verification_result_reference"
    ]

    assert (
        reference
        == benchmark_reference
        == {
            "run_id": legacy["run_id"],
            "hypothesis_id": legacy_result["hypothesis_id"],
            "provenance_status": "legacy_unversioned",
        }
    )


def test_conflicting_explicit_result_id_is_rejected(tmp_path: Path) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-conflicting-id", results=[_result("inconclusive")])
    store.save(run)
    duplicate = _result("verified")
    duplicate["result_id"] = run["verification_results"][0]["result_id"]
    run["verification_results"].append(duplicate)

    with pytest.raises(ValueError, match="Conflicting immutable result_id"):
        store.save(run)

    assert len(store.load_run(run["run_id"])["verification_results"]) == 1


def test_public_record_and_hash_basis_exclude_raw_secrets(tmp_path: Path) -> None:
    sentinel = "CCX_PROVENANCE_SECRET_SENTINEL"
    target = f"https://service.example/api?access_token={sentinel}"
    result = _result(
        "inconclusive",
        evidence=f"request failed with Authorization: Bearer {sentinel}",
    )
    result["password"] = sentinel
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-secret-safe-provenance", target=target, results=[result])
    historical_path = Path(store.save(run))
    stored = store.load_run(run["run_id"])

    rendered = "\n".join(
        (
            historical_path.read_text(encoding="utf-8"),
            store.latest_path.read_text(encoding="utf-8"),
            json.dumps(stored, sort_keys=True),
            result_content_hash(stored["verification_results"][0]),
        )
    )
    assert sentinel not in rendered
    assert stored["target_fingerprint"].startswith("sha256:")
    assert stored["verification_results"][0]["result_hash"] == result_content_hash(
        stored["verification_results"][0]
    )


def test_exact_result_lookup_fails_closed_on_reference_hash_mismatch(
    tmp_path: Path,
) -> None:
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("run-exact-lookup", results=[_result("verified")])
    store.save(run)
    result = run["verification_results"][0]

    with pytest.raises(ValueError, match="reference hash"):
        store.load_result(
            run["run_id"], result["result_id"], result_hash="sha256:" + "0" * 64
        )
