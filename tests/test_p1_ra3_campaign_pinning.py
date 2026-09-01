from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

import phase2_cli
from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.phase2_campaign import (
    CAMPAIGN_SCHEMA_VERSION,
    Phase2CampaignStore,
    build_campaign_export,
    campaign_snapshot_hash,
    canonical_campaign_snapshot_json,
)
from agent_core.phase2_store import (
    Phase2RunStore,
    canonical_run_snapshot_json,
    run_snapshot_hash,
)
from agent_core.result_provenance import RESULT_SCHEMA_VERSION, target_identity
from agent_core.verification_capabilities import typed_producer_provenance

TARGET = "https://campaign-pinning.example/api"
ZERO_DELTA = {
    "discovery": 0,
    "auth": 0,
    "verification": 0,
    "cleanup": 0,
    "attempted": 0,
    "total": 0,
}


def _result(
    status: str,
    *,
    hypothesis_id: str = "hyp-campaign-pin",
    category: str = "bola",
    evidence: str | None = None,
    total: int = 0,
    recovery_phase: str | None = None,
) -> dict[str, Any]:
    delta = dict(ZERO_DELTA)
    delta["verification"] = total
    delta["attempted"] = total
    delta["total"] = total
    result: dict[str, Any] = {
        "hypothesis_id": hypothesis_id,
        "category": category,
        "status": status,
        "confidence": "high",
        "evidence_summary": [evidence or f"Pinned {status} evidence."],
        "request_delta": delta,
        "requests_used": total,
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "executor": typed_producer_provenance(category),
    }
    if recovery_phase is not None:
        result.update(
            {
                "recovery_phase": recovery_phase,
                "recovery_run_id": "recovery-workflow",
                "comparison_type": "reused_same_challenge_and_code",
            }
        )
    return result


def _run(
    run_id: str,
    *,
    target: str = TARGET,
    category: str = "bola",
    results: list[dict[str, Any]] | None = None,
    total_requests: int | None = None,
) -> dict[str, Any]:
    selected_results = results or []
    hypothesis_id = (
        str(selected_results[0]["hypothesis_id"])
        if selected_results
        else "hyp-campaign-pin"
    )
    total = (
        sum(
            int((item.get("request_delta") or {}).get("total") or 0)
            for item in selected_results
        )
        if total_requests is None
        else total_requests
    )
    return {
        "run_id": run_id,
        "target": target,
        "assessment_mode": "verify",
        "profile": "authenticated",
        "hypotheses": [
            {
                "hypothesis_id": hypothesis_id,
                "category": category,
                "status": "proposed",
                "confidence": "medium",
                "method": "GET",
                "target_surface": {
                    "method": "GET",
                    "path": "/objects/{object_id}",
                    "parameter": "object_id",
                },
                "evidence_basis": [{"observation": "Pinned route observed."}],
            }
        ],
        "verification_results": selected_results,
        "metrics": {
            "discovery_requests": 1,
            "verification_requests": total,
            "total_requests": total + 1,
            "hypotheses_generated": 1,
        },
    }


def _stores(tmp_path: Path) -> tuple[Phase2RunStore, Phase2CampaignStore]:
    runs = Phase2RunStore(tmp_path / "runs")
    campaigns = Phase2CampaignStore(tmp_path / "campaigns", run_store=runs)
    return runs, campaigns


def _publish_manifest(
    campaigns: Phase2CampaignStore,
    campaign: dict[str, Any],
    *,
    revision: int,
) -> Path:
    campaign["campaign_revision"] = revision
    campaign["campaign_snapshot_hash"] = campaign_snapshot_hash(campaign)
    path = campaigns.campaign_revision_path(campaign["campaign_id"], revision)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")
    return path


def test_new_campaign_adds_ordered_exact_run_revision_and_snapshot_pins(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    first = _run("run-first")
    second = _run("run-second")
    runs.save(first)
    runs.save(second)

    created = campaigns.create("pinned", TARGET)
    created_bytes = campaigns.campaign_path("pinned").read_bytes()
    after_first = campaigns.add_run("pinned", first["run_id"])
    after_second = campaigns.add_run("pinned", second["run_id"])

    assert created["campaign_schema_version"] == CAMPAIGN_SCHEMA_VERSION == 2
    assert created["campaign_revision"] == 1
    assert created["run_references"] == []
    assert after_first["campaign_revision"] == 2
    assert after_second["campaign_revision"] == 3
    assert after_second["run_ids"] == ["run-first", "run-second"]
    assert [item["revision"] for item in after_second["run_references"]] == [1, 1]
    assert [item["run_snapshot_hash"] for item in after_second["run_references"]] == [
        run_snapshot_hash(runs.load_revision("run-first", 1)),
        run_snapshot_hash(runs.load_revision("run-second", 1)),
    ]
    assert all(
        item["target_fingerprint"] == after_second["target_fingerprint"]
        for item in after_second["run_references"]
    )
    assert after_second["campaign_snapshot_hash"] == campaign_snapshot_hash(
        after_second
    )
    assert campaigns.campaign_path("pinned").read_bytes() == created_bytes
    assert campaigns.load_revision("pinned", 1) == created
    assert campaigns.load_revision("pinned", 2) == after_first
    assert campaigns.load_revision("pinned", 3) == after_second


def test_exact_run_revision_api_never_falls_back_to_latest(tmp_path: Path) -> None:
    runs, _ = _stores(tmp_path)
    run = _run("run-exact", results=[_result("inconclusive", total=1)])
    runs.save(run)
    first = deepcopy(run)
    run["verification_results"].append(
        _result("verified", evidence="Later exact evidence.", total=2)
    )
    run["metrics"]["verification_requests"] = 3
    run["metrics"]["total_requests"] = 4
    runs.save(run)

    assert runs.load_revision("run-exact", 1) == first
    assert runs.load_revision("run-exact", 2) == run
    assert runs.load_run("run-exact") == run
    with pytest.raises(FileNotFoundError, match="does not exist"):
        runs.load_revision("run-exact", 3)


def test_unchanged_campaign_exports_metrics_findings_and_deltas_stay_pinned(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    run = _run("run-stable", results=[_result("inconclusive", total=1)])
    runs.save(run)
    campaigns.create("stable", TARGET)
    pinned = campaigns.add_run("stable", run["run_id"])
    campaign_bytes = campaigns.campaign_revision_path("stable", 2).read_bytes()
    campaign, resolved = campaigns.resolve("stable")
    export_a = build_campaign_export(campaign, resolved)
    benchmark_a = build_benchmark_export(resolved[0])
    finding_a = deepcopy(export_a["findings"])
    metrics_a = deepcopy(export_a["metrics"])
    delta_a = deepcopy(resolved[0]["verification_results"][0]["request_delta"])
    assert export_a["campaign_schema_version"] == CAMPAIGN_SCHEMA_VERSION
    assert export_a["campaign_revision"] == pinned["campaign_revision"]
    assert export_a["campaign_snapshot_hash"] == pinned["campaign_snapshot_hash"]
    assert export_a["findings"][0]["campaign_reference"] == {
        "campaign_id": pinned["campaign_id"],
        "campaign_revision": pinned["campaign_revision"],
        "campaign_snapshot_hash": pinned["campaign_snapshot_hash"],
    }

    run["verification_results"].append(
        _result("verified", evidence="Later verified evidence.", total=2)
    )
    run["metrics"]["verification_requests"] = 3
    run["metrics"]["total_requests"] = 4
    runs.save(run)
    run["verification_results"].append(
        _result("rejected", evidence="Even later evidence.", total=1)
    )
    run["metrics"]["verification_requests"] = 4
    run["metrics"]["total_requests"] = 5
    runs.save(run)

    campaign, resolved = campaigns.resolve("stable")
    export_b = build_campaign_export(campaign, resolved)
    benchmark_b = build_benchmark_export(resolved[0])

    assert campaign == pinned
    assert campaign["run_references"][0]["revision"] == 1
    assert export_b == export_a
    assert benchmark_b == benchmark_a
    assert export_b["findings"] == finding_a
    assert export_b["metrics"] == metrics_a
    assert resolved[0]["verification_results"][0]["request_delta"] == delta_a
    assert campaigns.show("stable") == pinned
    assert campaigns.campaign_revision_path("stable", 2).read_bytes() == campaign_bytes


def test_explicit_refresh_adopts_latest_without_reordering_and_preserves_history(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    first = _run("run-refresh", results=[_result("inconclusive", total=1)])
    second = _run("run-other")
    runs.save(first)
    runs.save(second)
    campaigns.create("refreshable", TARGET)
    campaigns.add_run("refreshable", first["run_id"])
    before = campaigns.add_run("refreshable", second["run_id"])
    before_bytes = campaigns.campaign_revision_path("refreshable", 3).read_bytes()
    before_export = build_campaign_export(*campaigns.resolve("refreshable"))

    first["verification_results"].append(
        _result("verified", evidence="Explicitly adopted evidence.", total=2)
    )
    first["metrics"]["verification_requests"] = 3
    first["metrics"]["total_requests"] = 4
    runs.save(first)
    refreshed = campaigns.refresh_run("refreshable", first["run_id"])
    after_export = build_campaign_export(*campaigns.resolve("refreshable"))

    assert refreshed["campaign_revision"] == 4
    assert refreshed["run_ids"] == before["run_ids"] == ["run-refresh", "run-other"]
    assert [item["revision"] for item in refreshed["run_references"]] == [2, 1]
    assert refreshed["campaign_snapshot_hash"] != before["campaign_snapshot_hash"]
    assert after_export["findings"][0]["status"] == "verified"
    assert after_export != before_export
    assert (
        campaigns.campaign_revision_path("refreshable", 3).read_bytes() == before_bytes
    )
    old_campaign, old_runs = campaigns.resolve_revision("refreshable", 3)
    assert old_campaign == before
    assert old_runs[0]["run_revision"] == 1


def test_recovery_stages_remain_at_original_pin_until_explicit_refresh(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    hypothesis_id = "hyp-recovery-pin"
    issued = _result(
        "awaiting_controlled_evidence",
        hypothesis_id=hypothesis_id,
        category="recovery_state_enforcement",
        total=1,
        recovery_phase="challenge_issued",
    )
    run = _run(
        "run-recovery-pin",
        category="recovery_state_enforcement",
        results=[issued],
    )
    runs.save(run)
    campaigns.create("recovery", TARGET)
    campaigns.add_run("recovery", run["run_id"])
    original_campaign, original_runs = campaigns.resolve("recovery")
    original_export = build_campaign_export(original_campaign, original_runs)

    run["verification_results"].append(
        _result(
            "verification_pending_cleanup",
            hypothesis_id=hypothesis_id,
            category="recovery_state_enforcement",
            total=2,
            recovery_phase="verification_pending_cleanup",
        )
    )
    run["metrics"]["verification_requests"] = 3
    run["metrics"]["total_requests"] = 4
    runs.save(run)
    run["verification_results"].append(
        _result(
            "rejected",
            hypothesis_id=hypothesis_id,
            category="recovery_state_enforcement",
            evidence="Final recovery rejection.",
            recovery_phase="completed",
        )
    )
    runs.save(run)

    still_campaign, still_runs = campaigns.resolve("recovery")
    still_export = build_campaign_export(still_campaign, still_runs)
    assert still_export == original_export
    assert len(still_runs[0]["verification_results"]) == 1
    assert still_runs[0]["verification_results"][0]["status"] == (
        "awaiting_controlled_evidence"
    )
    assert still_export["findings"][0]["status"] == "discovered"
    assert still_export["findings"][0]["verification_result_reference"] is None

    campaigns.refresh_run("recovery", run["run_id"])
    refreshed_campaign, refreshed_runs = campaigns.resolve("recovery")
    refreshed_export = build_campaign_export(refreshed_campaign, refreshed_runs)
    assert refreshed_campaign["run_references"][0]["revision"] == 3
    assert refreshed_export["findings"][0]["status"] == "rejected"
    reference = refreshed_export["findings"][0]["verification_result_reference"]
    assert (
        reference["result_id"]
        == refreshed_runs[0]["verification_results"][-1]["result_id"]
    )


@pytest.mark.parametrize(
    "corruption",
    (
        "missing_revision",
        "run_snapshot",
        "target_fingerprint",
        "result_hash",
        "campaign_hash",
    ),
)
def test_campaign_integrity_failures_are_closed_and_never_partially_exported(
    corruption: str,
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    run = _run("run-integrity", results=[_result("inconclusive", total=1)])
    runs.save(run)
    campaigns.create("integrity", TARGET)
    campaign = campaigns.add_run("integrity", run["run_id"])

    if corruption == "missing_revision":
        corrupt = deepcopy(campaign)
        corrupt["run_references"][0]["revision"] = 99
        _publish_manifest(campaigns, corrupt, revision=3)
    elif corruption == "run_snapshot":
        path = runs.run_path(run["run_id"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["profile"] = "baseline"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    elif corruption == "target_fingerprint":
        corrupt = deepcopy(campaign)
        wrong = "sha256:" + "f" * 64
        corrupt["target_fingerprint"] = wrong
        corrupt["run_references"][0]["target_fingerprint"] = wrong
        _publish_manifest(campaigns, corrupt, revision=3)
    elif corruption == "result_hash":
        path = runs.run_path(run["run_id"])
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["verification_results"][0]["evidence_summary"] = ["Corrupted."]
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    else:
        path = campaigns.campaign_revision_path("integrity", 2)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["name"] = "corrupted-name"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    output = tmp_path / f"{corruption}.json"
    with pytest.raises((FileNotFoundError, ValueError)):
        campaigns.export("integrity", output)
    assert not output.exists()


def test_duplicate_and_failed_mutations_leave_campaign_history_unchanged(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    run = _run("run-atomic")
    other_target = _run("run-other-target", target="https://other.example/api")
    runs.save(run)
    runs.save(other_target)
    campaigns.create("atomic", TARGET)
    pinned = campaigns.add_run("atomic", run["run_id"])
    pinned_path = campaigns.campaign_revision_path("atomic", 2)
    pinned_bytes = pinned_path.read_bytes()

    with pytest.raises(ValueError, match="refresh-run"):
        campaigns.add_run("atomic", run["run_id"])
    with pytest.raises(FileNotFoundError):
        campaigns.add_run("atomic", "missing-run")
    with pytest.raises(ValueError, match="different targets"):
        campaigns.add_run("atomic", other_target["run_id"])
    with pytest.raises(ValueError, match="already pins"):
        campaigns.refresh_run("atomic", run["run_id"])
    with pytest.raises(ValueError, match="does not contain"):
        campaigns.refresh_run("atomic", "missing-run")

    assert campaigns.load("atomic") == pinned
    assert pinned_path.read_bytes() == pinned_bytes
    assert not campaigns.campaign_revision_path("atomic", 3).exists()


def test_legacy_campaign_stays_unpinned_until_explicit_migration_mutation(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    run = _run("run-legacy-campaign")
    runs.save(run)
    campaigns.directory.mkdir(parents=True)
    legacy = {
        "campaign_id": "auth-lab-phase2",
        "name": "auth-lab-phase2",
        "target": TARGET,
        "run_ids": [run["run_id"]],
        "created_at": "2026-08-31T00:00:00+00:00",
        "updated_at": "2026-08-31T00:00:00+00:00",
    }
    base = campaigns.campaign_path("auth-lab-phase2")
    base.write_text(json.dumps(legacy, indent=2) + "\n", encoding="utf-8")
    base_bytes = base.read_bytes()

    shown = campaigns.show("auth-lab-phase2")
    campaign, resolved = campaigns.resolve("auth-lab-phase2")
    exported = build_campaign_export(campaign, resolved)

    assert shown["campaign_provenance_status"] == "legacy_unpinned"
    assert exported["campaign_provenance_status"] == "legacy_unpinned"
    for field in (
        "campaign_schema_version",
        "campaign_revision",
        "campaign_snapshot_hash",
        "run_references",
    ):
        assert field not in shown
    assert base.read_bytes() == base_bytes
    assert campaigns.load_revision("auth-lab-phase2", 0) == shown

    migrated = campaigns.refresh_run("auth-lab-phase2", run["run_id"])
    assert migrated["campaign_schema_version"] == CAMPAIGN_SCHEMA_VERSION
    assert migrated["campaign_revision"] == 1
    assert migrated["campaign_provenance_status"] == "pinned"
    assert migrated["run_references"][0]["revision"] == 1
    assert base.read_bytes() == base_bytes
    assert campaigns.load_revision("auth-lab-phase2", 0) == shown
    assert campaigns.load("auth-lab-phase2") == migrated


def test_same_public_target_with_different_exact_fingerprint_cannot_be_added(
    tmp_path: Path,
) -> None:
    runs, campaigns = _stores(tmp_path)
    first_target = "https://campaign-pinning.example/api?token=FIRST_SECRET"
    second_target = "https://campaign-pinning.example/api?token=SECOND_SECRET"
    first = _run("run-target-first", target=first_target)
    second = _run("run-target-second", target=second_target)
    runs.save(first)
    runs.save(second)
    first_public, first_fingerprint = target_identity(first_target)
    second_public, second_fingerprint = target_identity(second_target)
    assert first_public == second_public
    assert first_fingerprint != second_fingerprint

    campaigns.create("target-pinned", first_target)
    campaigns.add_run("target-pinned", first["run_id"])
    with pytest.raises(ValueError, match="different targets"):
        campaigns.add_run("target-pinned", second["run_id"])


def test_campaign_and_run_hash_bases_are_public_and_secret_safe(tmp_path: Path) -> None:
    sentinel = "CCX_RA3_QUOTED_SECRET_001"
    runs, campaigns = _stores(tmp_path)
    run = _run("run-secret-safe")
    run["diagnostic"] = f'error="{{\\"password\\":\\"{sentinel}\\"}}"'
    run["private_recovery_state"] = {"code": sentinel}
    runs.save(run)
    campaigns.create("secret-safe", TARGET)
    campaign = campaigns.add_run("secret-safe", run["run_id"])
    stored = runs.load_revision(run["run_id"], 1)

    rendered = "\n".join(
        (
            canonical_run_snapshot_json(stored),
            run_snapshot_hash(stored),
            canonical_campaign_snapshot_json(campaign),
            campaign_snapshot_hash(campaign),
            json.dumps(build_campaign_export(*campaigns.resolve("secret-safe"))),
        )
    )
    assert sentinel not in rendered
    assert "private_recovery_state" not in rendered


def test_cli_show_and_refresh_expose_safe_exact_campaign_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runs, campaigns = _stores(tmp_path)
    run = _run("run-cli", results=[_result("inconclusive", total=1)])
    runs.save(run)
    campaigns.create("cli-pinned", TARGET)
    campaigns.add_run("cli-pinned", run["run_id"])
    run["verification_results"].append(
        _result("verified", evidence="CLI refresh evidence.", total=1)
    )
    run["metrics"]["verification_requests"] = 2
    run["metrics"]["total_requests"] = 3
    runs.save(run)

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: runs)
    monkeypatch.setattr(
        phase2_cli,
        "Phase2CampaignStore",
        lambda **_kwargs: campaigns,
    )
    assert phase2_cli.main(["campaign", "show", "cli-pinned"]) == 0
    shown = json.loads(capsys.readouterr().out)["campaign"]
    assert shown["campaign_revision"] == 2
    assert shown["run_references"][0]["revision"] == 1

    assert phase2_cli.main(["campaign", "refresh-run", "cli-pinned", "run-cli"]) == 0
    refreshed = json.loads(capsys.readouterr().out)["campaign"]
    assert refreshed["campaign_revision"] == 3
    assert refreshed["run_references"][0]["revision"] == 2
    assert refreshed["campaign_snapshot_hash"].startswith("sha256:")
    assert campaigns.resolve_revision("cli-pinned", 2)[1][0]["run_revision"] == 1
