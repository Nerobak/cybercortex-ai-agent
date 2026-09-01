"""Public workflow facade backed by the dependency-aware runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.attack_surface import build_canonical_attack_surface
from agent_core.controlled_context import ControlledContext
from agent_core.memory_manager import record_assessment
from agent_core.phase2_reporter import render_phase2_report
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, policy_from_runtime
from agent_core.request_budget import RequestBudget
from agent_core.result_normalizer import (
    public_result,
    sanitize_document_text,
    sanitize_text,
)
from agent_core.tool_runner import ToolRunner
from config import (
    ADAPTIVE_MAX_REQUESTS,
    AGENT_ISOLATE_NETWORK_TOOLS,
    AGENT_REQUEST_BUDGET,
)
from tool_registry import resolve_tool
from tools.safe_http import ScopedHTTPClient

PHASE2_MODES = {"observe", "plan", "verify"}
PHASE2_REPORT_MARKER = "<!-- CYBERCORTEX PHASE 2 -->"
HIGH_PRIORITY_SCORE = 50


def _integrate_phase2_report(result: dict[str, Any], phase2: dict[str, Any]) -> None:
    """Append deterministic Phase 2 sections to the primary scan report."""
    report = ((result.get("results") or {}).get("ai_report_writer") or {}).get(
        "output"
    ) or {}
    report_path = report.get("report_file") or report.get("report")
    if not report_path:
        return
    path = Path(str(report_path))
    if not path.is_file():
        return
    existing = sanitize_document_text(path.read_text(encoding="utf-8"))
    if PHASE2_REPORT_MARKER in existing:
        existing = existing.split(PHASE2_REPORT_MARKER, 1)[0].rstrip()
    integrated = (
        existing + "\n\n" + PHASE2_REPORT_MARKER + "\n\n" + render_phase2_report(phase2)
    )
    path.write_text(integrated, encoding="utf-8")
    report["phase2_integrated"] = True


def _phase2_completed_steps(mode: str) -> list[str]:
    steps = ["phase2_attack_surface_model", "phase2_adaptive_orchestrator_pass"]
    if mode in {"plan", "verify"}:
        steps[1:1] = [
            "phase2_hypothesis_generation",
            "phase2_hypothesis_prioritization",
            "phase2_verification_planning",
            "phase2_policy_evaluation",
        ]
    return steps


def _print_phase2_summary(phase2: dict[str, Any], *, limit: int = 5) -> None:
    surface = phase2.get("attack_surface") or {}
    hypotheses = phase2.get("hypotheses") or []
    plans = phase2.get("verification_plans") or []
    results = phase2.get("verification_results") or []
    high_priority = sum(
        int((item.get("metadata") or {}).get("priority_score") or 0)
        >= HIGH_PRIORITY_SCORE
        for item in hypotheses
        if isinstance(item, dict)
    )
    print("\nPhase 2:")
    print(f"Mode: {phase2.get('assessment_mode') or phase2.get('mode', 'observe')}")
    print(f"Attack-surface routes: {len(surface.get('routes') or [])}")
    print(f"Objects: {len(surface.get('objects') or [])}")
    print(f"Hypotheses generated: {len(hypotheses)}")
    print(f"High priority: {high_priority}")
    print(f"Verification plans: {len(plans)}")
    print(f"Executed: {len(results)}")
    print(f"Verified: {sum(item.get('status') == 'verified' for item in results)}")
    print(f"Rejected: {sum(item.get('status') == 'rejected' for item in results)}")
    print(
        f"Inconclusive: {sum(item.get('status') == 'inconclusive' for item in results)}"
    )
    if hypotheses:
        print("Top hypotheses:")
    for item in hypotheses[:limit]:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") or {}
        surface_item = item.get("target_surface") or {}
        endpoint = (
            surface_item.get("path") or item.get("endpoint") or item.get("target")
        )
        print(
            "- "
            f"{item.get('hypothesis_id', 'unknown')} "
            f"[{item.get('category', 'unknown')}] "
            f"priority {metadata.get('priority', 'n/a')} "
            f"score {metadata.get('priority_score', item.get('priority', 0))} "
            f"status {item.get('status', 'proposed')} — {endpoint}"
        )


def run_tool(
    tool_name: str, target: str, allowed_domain: str, results: dict[str, Any]
) -> dict[str, Any]:
    """Compatibility dispatcher; only canonical registered names execute."""
    function = resolve_tool(tool_name)
    if function is None:
        return {"success": False, "error": f"Unknown or unavailable tool: {tool_name}"}
    if tool_name == "parameter_analyzer":
        return function((results.get("katana_crawl") or {}).get("urls", []))
    return {"success": False, "error": "Use ToolRunner for dependency-aware execution."}


def _console_status(name: str, envelope: dict[str, Any]) -> None:
    status = envelope.get("status")
    if status == "running":
        print(f"[+] Running: {name}")
        return
    output = envelope.get("output") or {}
    if not isinstance(output, dict):
        output = {}
    count = output.get("count") or output.get("findings_count")
    suffix = f": {count}" if count is not None else ""
    if status == "completed":
        print(f"[✓] Completed: {name}{suffix}")
    elif status in {"timed_out", "timed_out_partial"}:
        partial = f" with partial results: {count} URLs" if count else ""
        print(f"[!] Timed out{partial}: {name}")
    elif status == "completed_with_fallback":
        print(f"[✓] Completed with fallback: {name}{suffix}")
    elif status in {"skipped", "not_applicable"}:
        print(
            f"[-] {status.replace('_', ' ').title()}: {name} — "
            f"{sanitize_text(str(envelope.get('error') or ''))}"
        )
    elif status == "failed":
        print(
            f"[x] Failed: {name} — "
            f"{sanitize_text(str(envelope.get('error') or ''))}"
        )


def run_workflow(
    goal: str,
    target: str,
    allowed_domain: str,
    *,
    profile: str = "baseline",
    assessment_mode: str = "observe",
    jwt_token: str | None = None,
    status_callback=None,
    phase2_policy: AssessmentPolicy | None = None,
    target_class: str = "external",
    controlled_context: ControlledContext | None = None,
    phase2_executor=None,
    phase2_store: Phase2RunStore | None = None,
) -> dict[str, Any]:
    if assessment_mode not in PHASE2_MODES:
        raise ValueError("Assessment mode must be observe, plan, or verify.")
    del allowed_domain  # Scope is enforced centrally and for every discovered URL.
    effective_policy = phase2_policy or policy_from_runtime(
        target,
        profile=profile,
        authorization_confirmed=True,
        request_budget=AGENT_REQUEST_BUDGET,
    )
    target_decision = effective_policy.authorize_url(target, method="GET")
    if not target_decision.allowed:
        raise ValueError("; ".join(target_decision.reasons))
    authoritative_budget = RequestBudget(
        min(effective_policy.request_budget, ADAPTIVE_MAX_REQUESTS),
        per_host_limit=effective_policy.per_host_request_budget,
    )
    network_client = ScopedHTTPClient(
        policy=effective_policy,
        budget=authoritative_budget,
    )
    if phase2_executor is not None:
        setattr(phase2_executor, "network_client", network_client)
    print("[1] Scope validation")
    print("[2] Creating dependency-aware plan")
    print("[3] Running independent baseline tools")
    phase_messages = {
        "adaptive_api_discovery": "[4] Running bounded adaptive API metadata discovery",
        "normalize_surface": "[4] Normalizing discovered surface",
        "dependent_analyzers": "[5] Running dependent analyzers",
        "optional_tools": "[6] Running optional tools",
        "evidence_package": "[7] Building sanitized evidence package",
        "ai_analysis": "[8] DeepSeek evidence analysis",
        "report_writing": "[9] Writing report",
    }
    callback = status_callback or _console_status
    orchestrator = AdaptiveAssessmentOrchestrator()
    typed_plan = orchestrator.initial_surface_plan(
        goal=goal,
        target=target,
        profile=profile,
        request_budget=AGENT_REQUEST_BUDGET,
    )
    runner = ToolRunner(
        status_callback=callback,
        phase_callback=lambda phase: print(phase_messages[phase]),
        isolate_network_tools=AGENT_ISOLATE_NETWORK_TOOLS,
        policy=effective_policy,
        request_budget=authoritative_budget,
        http_client=network_client,
    )
    result = runner.run(
        target,
        profile=profile,
        assessment_mode=assessment_mode,
        jwt_token=jwt_token,
        selected_tools=typed_plan.selected_tools,
    )
    result["goal"] = goal
    result["assessment_mode"] = assessment_mode
    result["agent_plan"] = typed_plan.model_dump(mode="json")
    result["agent_plan"]["assessment_mode"] = assessment_mode
    evidence = result.get("evidence_package") or {}
    result["evidence_package"] = evidence
    assessment = evidence.setdefault("assessment", {})
    assessment["assessment_mode"] = assessment_mode
    try:
        result["surface_graph"] = orchestrator.ingest_scan_result(typed_plan, result)
        memory = record_assessment(
            target,
            evidence,
            mode=assessment_mode,
        )
        result["memory"] = {
            "success": memory.get("success"),
            "assessment_count": memory.get("assessment_count"),
        }
    except (OSError, ValueError) as exc:
        result["persistence_warning"] = str(exc)

    # Phase 2 consumes the normalized evidence package produced above. It does
    # not repeat discovery and runs even when AI analysis/reporting fell back.
    surface = build_canonical_attack_surface(target, assessment=result)
    internal_phase2 = orchestrator.run_phase2(
        surface,
        effective_policy,
        mode=assessment_mode,
        target_class=target_class,
        controlled_context=controlled_context,
        request_budget=authoritative_budget,
        executor=phase2_executor if assessment_mode == "verify" else None,
        profile=profile,
    )
    completed_steps = result.setdefault("completed_steps", [])
    for step in _phase2_completed_steps(assessment_mode):
        if step not in completed_steps:
            completed_steps.append(step)
    store = phase2_store or Phase2RunStore()
    try:
        phase2_path = store.save(internal_phase2)
        phase2 = public_result(internal_phase2)
        standalone_report = store.directory / f"{phase2['run_id']}.md"
        standalone_report.write_text(render_phase2_report(phase2), encoding="utf-8")
        result["phase2_artifacts"] = {
            "run": phase2_path,
            "report": str(standalone_report),
        }
        _integrate_phase2_report(result, phase2)
    except OSError as exc:
        result["phase2_persistence_warning"] = str(exc)
        phase2 = public_result(internal_phase2)
    result["phase2"] = phase2
    evidence["phase2"] = phase2

    summary = result["evidence_package"]
    execution = summary["execution_summary"]
    print(f"Completed: {len(execution['completed'])}")
    print(
        f"Completed with fallback: {len(execution.get('completed_with_fallback', []))}"
    )
    print(f"Partial: {len(execution.get('timed_out_partial', []))}")
    print(f"Timed out: {len(execution['timed_out'])}")
    print(f"Failed: {len(execution['failed'])}")
    print(f"Skipped: {len(execution['skipped'])}")
    print(f"Observations: {len(summary['observations'])}")
    print(f"Candidates: {len(summary['candidate_findings'])}")
    print(f"Needs manual verification: {len(summary['manual_verification_queue'])}")
    print(f"Verified findings: {len(summary['verified_findings'])}")
    report = result.get("results", {}).get("ai_report_writer", {}).get("output") or {}
    display_status = result["assessment_status"].replace("_", " ").capitalize()
    print(f"Assessment status: {display_status}")
    print(f"Coverage: {result['coverage']['coverage_percentage']}%")
    print(f"AI analysis: {report.get('ai_status', 'not_requested')}")
    print(f"Report mode: {report.get('report_mode', 'deterministic_fallback')}")
    print(f"Report: {report.get('report', '')}")
    print(f"Evidence: {report.get('evidence', '')}")
    _print_phase2_summary(phase2)
    return public_result(result)
