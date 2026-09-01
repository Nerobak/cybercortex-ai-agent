"""Ground-truth-independent normalized CyberCortex benchmark export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_core.finding_export import ExportOperation, resolve_finding_export
from agent_core.request_budget import canonical_result_request_total
from agent_core.result_normalizer import public_result
from agent_core.result_provenance import verification_result_reference

FORBIDDEN_KEYS = {
    "ground_truth",
    "ground_truth_id",
    "ground_truth_ids",
    "answer_id",
    "answer_ids",
    "benchmark_answer_id",
    "benchmark_answer_ids",
    "vulnerability_id",
    "vulnerability_ids",
}


def assert_benchmark_integrity(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_KEYS:
                raise ValueError(
                    "Benchmark export cannot contain ground-truth identifiers."
                )
            assert_benchmark_integrity(item)
    elif isinstance(value, list):
        for item in value:
            assert_benchmark_integrity(item)


def build_benchmark_export(run: dict[str, Any]) -> dict[str, Any]:
    run = public_result(run)
    assert_benchmark_integrity(run)
    results_by_id = {
        item.get("hypothesis_id"): item
        for item in run.get("verification_results", [])
        if isinstance(item, dict)
    }
    findings: list[dict[str, Any]] = []
    for hypothesis in run.get("hypotheses", []):
        if not isinstance(hypothesis, dict):
            continue
        identifier = hypothesis.get("hypothesis_id") or hypothesis.get("id")
        result = results_by_id.get(identifier, {})
        raw_status = str(result.get("status") or hypothesis.get("status") or "proposed")
        status = (
            raw_status
            if raw_status in {"verified", "rejected", "inconclusive"}
            else "discovered"
        )
        surface = hypothesis.get("target_surface") or {}
        functionality = " ".join(
            str(item)
            for item in (
                surface.get("method"),
                surface.get("path"),
                surface.get("parameter"),
            )
            if item
        )
        default_functionality = functionality or hypothesis.get("endpoint", "unknown")
        structure = resolve_finding_export(
            hypothesis,
            default_operation=ExportOperation(
                method="",
                route_template=str(default_functionality),
            ),
        )
        requests_used, request_accounting_source = canonical_result_request_total(
            result
        )
        finding = {
            "category": hypothesis.get("category", "unknown"),
            "status": status,
            "confidence": result.get("confidence", hypothesis.get("confidence", "low")),
            "affected_functionality": (
                structure.affected_operation.affected_functionality
            ),
            "evidence_summary": result.get("evidence_summary")
            or [
                str(item.get("observation") or item)
                for item in hypothesis.get("evidence_basis", [])
            ],
            "requests_used": requests_used,
        }
        if result:
            finding["request_accounting_source"] = request_accounting_source
            finding["verification_result_reference"] = verification_result_reference(
                str(run.get("run_id") or "unknown"), result
            )
        finding.update(structure.optional_fields())
        findings.append(finding)
    metrics = dict(run.get("metrics") or {})
    normalized_metrics = {
        "duration_seconds": float(metrics.get("duration_seconds") or 0),
        "request_count": int(
            metrics.get("request_count", metrics.get("total_requests", 0)) or 0
        ),
        "model_calls": int(metrics.get("model_calls") or 0),
        "hypotheses_generated": int(
            metrics.get("hypotheses_generated", len(findings)) or 0
        ),
        "hypotheses_verified": int(metrics.get("hypotheses_verified") or 0),
        "hypotheses_rejected": int(metrics.get("hypotheses_rejected") or 0),
        "pivots": int(metrics.get("pivots") or 0),
    }
    payload = {
        "run_id": str(run.get("run_id") or "unknown"),
        "target": str(run.get("target") or "unknown"),
        "assessment_mode": str(
            run.get("assessment_mode") or run.get("mode") or "observe"
        ),
        "model": str(run.get("model") or "deterministic"),
        "findings": findings,
        "metrics": normalized_metrics,
    }
    if run.get("target_fingerprint") is not None:
        payload["target_fingerprint"] = run["target_fingerprint"]
    else:
        payload["target_identity_status"] = "legacy_unversioned"
    assert_benchmark_integrity(payload)
    return public_result(payload)


def export_benchmark(run: dict[str, Any], output_path: str | Path) -> str:
    payload = public_result(build_benchmark_export(run))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return str(path)
