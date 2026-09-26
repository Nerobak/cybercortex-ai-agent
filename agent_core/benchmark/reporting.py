"""Deterministic machine and human benchmark reports."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_core.benchmark.integrity import BenchmarkIntegrityVerifier, artifact_fingerprint
from agent_core.benchmark.types import (
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkReport,
    BenchmarkResearchInput,
    BenchmarkRun,
    BenchmarkScore,
    BenchmarkScoringPolicy,
    ReproducibilityMetadata,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_metadata() -> tuple[str, bool]:
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        )
        return sha, dirty
    except Exception:
        return "unknown-revision", True


class BenchmarkReporter:
    def build(
        self,
        *,
        run: BenchmarkRun,
        manifest: BenchmarkManifest,
        ground_truth: BenchmarkGroundTruth,
        scoring_policy: BenchmarkScoringPolicy,
        score: BenchmarkScore,
        initial_state: Any,
        final_state: Any,
        research_input: BenchmarkResearchInput | None = None,
        model_provider: str,
        requested_model: str,
        actual_model_provenance: tuple[str, ...] = (),
        policy_fingerprint: str,
        cybercortex_version: str | None = None,
        python_version: str | None = None,
        platform_name: str | None = None,
        include_ground_truth_details: bool = False,
        generated_at: str | None = None,
    ) -> BenchmarkReport:
        if run.code_revision.endswith("-dirty"):
            sha, dirty = run.code_revision.removesuffix("-dirty"), True
        elif run.code_revision == "unknown-revision":
            sha, dirty = _git_metadata()
        else:
            sha, dirty = run.code_revision, False
        reproducibility = ReproducibilityMetadata(
            git_commit_sha=sha,
            dirty_working_tree=dirty,
            python_version=python_version or sys.version,
            platform=platform_name or platform.platform(),
            cybercortex_version=cybercortex_version,
            model_provider=model_provider,
            requested_model=requested_model,
            actual_model_provenance=actual_model_provenance,
            model_configuration_fingerprint=run.model_routing_fingerprint,
            policy_fingerprint=policy_fingerprint,
            benchmark_manifest_fingerprint=artifact_fingerprint(manifest),
            ground_truth_fingerprint=artifact_fingerprint(ground_truth),
            scoring_policy_fingerprint=artifact_fingerprint(scoring_policy),
        )
        run_configuration: Any = (
            {"manifest": manifest, "research_input": research_input}
            if research_input is not None
            else {
                "configuration_fingerprint": run.configuration_fingerprint,
                "budget_snapshot": run.budget_snapshot,
                "model_routing_fingerprint": run.model_routing_fingerprint,
            }
        )
        calculated = {
            "manifest": artifact_fingerprint(manifest),
            "ground-truth": artifact_fingerprint(ground_truth),
            "scoring-policy": artifact_fingerprint(scoring_policy),
            "run-configuration": artifact_fingerprint(run_configuration),
            "initial-state": artifact_fingerprint(initial_state),
            "final-state": artifact_fingerprint(final_state),
            "score-report": artifact_fingerprint(score),
        }
        expected = dict(calculated)
        if run.benchmark_manifest_fingerprint is not None:
            expected["manifest"] = run.benchmark_manifest_fingerprint
        if run.ground_truth_fingerprint is not None:
            expected["ground-truth"] = run.ground_truth_fingerprint
        if run.scoring_policy_fingerprint is not None:
            expected["scoring-policy"] = run.scoring_policy_fingerprint
        if research_input is not None:
            expected["run-configuration"] = run.configuration_fingerprint
        if run.initial_state_fingerprint is not None:
            expected["initial-state"] = run.initial_state_fingerprint
        if run.final_state_fingerprint is not None:
            expected["final-state"] = run.final_state_fingerprint
        if run.scoring_reference is not None:
            expected["score-report"] = run.scoring_reference
        integrity = BenchmarkIntegrityVerifier().create_report(
            run_id=run.run_id,
            manifest=manifest,
            ground_truth=ground_truth,
            scoring_policy=scoring_policy,
            run_configuration=run_configuration,
            initial_state=initial_state,
            final_state=final_state,
            score_report=score,
            expected_fingerprints=expected,
        )
        # The typed report intentionally carries matches by opaque IDs only.
        # The flag records policy disposition without adding hidden notes/text.
        return BenchmarkReport(
            benchmark_id=run.benchmark_id,
            benchmark_version=run.benchmark_version,
            run_id=run.run_id,
            research_id=run.research_id,
            generated_at=generated_at or _now(),
            reproducibility=reproducibility,
            score=score,
            integrity=integrity,
            ground_truth_details_included=include_ground_truth_details,
            ground_truth=(ground_truth if include_ground_truth_details else None),
        )

    @staticmethod
    def to_json(report: BenchmarkReport, *, indent: int | None = 2) -> str:
        payload = report.model_dump(mode="json", exclude_none=True)
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":") if indent is None else None,
            indent=indent,
            ensure_ascii=True,
            allow_nan=False,
        )

    def export_json(
        self, report: BenchmarkReport, destination: str | Path
    ) -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(report) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def human_summary(report: BenchmarkReport) -> str:
        metrics = report.score.metrics
        outcome = "PASS" if report.score.passed else "FAIL"
        integrity = "verified" if report.integrity.valid else "FAILED"
        return "\n".join(
            (
                f"Benchmark {report.benchmark_id} {report.benchmark_version}",
                f"Run: {report.run_id} ({outcome})",
                f"Confirmed recall: {metrics.discovery.confirmed_recall:.3f}",
                f"Confirmed precision: {metrics.discovery.confirmed_precision:.3f}",
                f"Confirmed findings: {metrics.discovery.true_positive_confirmed}",
                f"False confirmations: {metrics.confirmation.false_confirmation_count}",
                f"Unexpected findings awaiting/after adjudication: {metrics.discovery.unexpected_findings}",
                f"Confirmed chain recall: {metrics.chains.chain_recall:.3f}",
                f"Requests / model calls / tokens: {metrics.resources.total_target_requests} / {metrics.resources.model_calls} / {metrics.resources.total_tokens}",
                f"Wall time: {metrics.resources.wall_time_seconds:.3f}s",
                f"Integrity: {integrity}",
            )
        )


__all__ = ["BenchmarkReporter"]
