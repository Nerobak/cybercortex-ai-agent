"""Public workflow facade backed by the dependency-aware runner."""

from __future__ import annotations

from typing import Any

from agent_core.tool_runner import ToolRunner
from tool_registry import resolve_tool


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
            f"[-] {status.replace('_', ' ').title()}: {name} — {envelope.get('error')}"
        )
    elif status == "failed":
        print(f"[x] Failed: {name} — {envelope.get('error')}")


def run_workflow(
    goal: str,
    target: str,
    allowed_domain: str,
    *,
    profile: str = "baseline",
    jwt_token: str | None = None,
    status_callback=None,
) -> dict[str, Any]:
    del allowed_domain  # Scope is enforced centrally and for every discovered URL.
    print("[1] Scope validation")
    print("[2] Creating dependency-aware plan")
    print("[3] Running independent baseline tools")
    phase_messages = {
        "normalize_surface": "[4] Normalizing discovered surface",
        "dependent_analyzers": "[5] Running dependent analyzers",
        "optional_tools": "[6] Running optional tools",
        "evidence_package": "[7] Building sanitized evidence package",
        "ai_analysis": "[8] DeepSeek evidence analysis",
        "report_writing": "[9] Writing report",
    }
    callback = status_callback or _console_status
    runner = ToolRunner(
        status_callback=callback,
        phase_callback=lambda phase: print(phase_messages[phase]),
    )
    result = runner.run(target, profile=profile, jwt_token=jwt_token)
    result["goal"] = goal
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
    return result
