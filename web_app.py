"""Local web dashboard for authorized CyberCortex assessments."""

from __future__ import annotations

import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from agent_core.workflow_manager import run_workflow
from agent_core.version import __version__
from tools.scope_guard import (
    enforce_scope,
    get_allowed_domains,
    get_allowed_url_prefixes,
)

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "web" / "dashboard.html"
MAX_RETAINED_JOBS = 50
PUBLIC_JOB_FIELDS = {
    "id",
    "target",
    "profile",
    "status",
    "assessment_status",
    "coverage",
    "progress",
    "current_step",
    "created_at",
    "started_at",
    "completed_at",
    "tool_statuses",
    "graphql",
    "jwt",
    "business_logic",
    "upload",
    "observations",
    "candidates",
    "verified_findings",
    "findings",
    "report_mode",
    "report_file",
    "error",
}

app = FastAPI(
    title="CyberCortex Bug Bounty Cockpit",
    description="A local dashboard for explicitly authorized, non-destructive web checks.",
    version=__version__,
)

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=2048)
    profile: str = Field(default="baseline", pattern="^(baseline|deep)$")
    authorization_confirmed: bool = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_job(job_id: str, **changes: Any) -> None:
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(changes)


def _get_job(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return deepcopy(job)


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    """Return the dashboard contract without raw evidence or credentials."""
    public = {
        key: deepcopy(value) for key, value in job.items() if key in PUBLIC_JOB_FIELDS
    }
    public["version"] = __version__
    public["tool_statuses"] = {
        name: {
            "tool": name,
            "status": envelope.get("status", "unknown"),
        }
        for name, envelope in (job.get("tool_statuses") or {}).items()
        if isinstance(envelope, dict)
    }
    return public


def _finding_summary(results: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    headers = results.get("security_headers", {}).get("headers_checked", {})
    for name, data in headers.items():
        if isinstance(data, dict) and not data.get("present"):
            findings.append(
                {
                    "severity": "low",
                    "title": f"Missing {name}",
                    "evidence": data.get("description", "Header was not present."),
                    "status": "needs manual validation",
                }
            )

    technologies = results.get("technology", {}).get("technologies", [])
    for technology in technologies:
        if str(technology).lower().startswith(("server:", "x-powered-by:")):
            findings.append(
                {
                    "severity": "info",
                    "title": "Technology information disclosed",
                    "evidence": str(technology),
                    "status": "observation",
                }
            )
    return findings


def _business_logic_summary(results: dict[str, Any]) -> dict[str, Any]:
    """Project only counts and classifications; never raw workflow evidence."""
    discovery = (results.get("workflow_evidence_discovery") or {}).get("output") or {}
    model_output = (results.get("workflow_model_builder") or {}).get("output") or {}
    model = model_output.get("model") or {}
    transition = (results.get("workflow_transition_analyzer") or {}).get("output") or {}
    planner = (results.get("business_logic_test_planner") or {}).get("output") or {}
    replay = (results.get("workflow_replay_checker") or {}).get("output") or {}
    return {
        "workflow_candidates": len(discovery.get("workflow_candidates") or []),
        "modeled_workflows": 1 if model else 0,
        "steps_observed": len(model.get("steps") or []),
        "transitions_observed": len(model.get("transitions") or []),
        "sensitive_operations": sum(
            1
            for step in model.get("steps") or []
            if step.get("side_effect_class")
            in {"sensitive", "destructive", "financial"}
        ),
        "manual_plans": len(planner.get("plans") or []),
        "replay_status": replay.get("status", "not_applicable"),
        "limitations": len(
            [
                item
                for item in transition.get("observations") or []
                if item.get("type") == "incomplete_sequence"
            ]
        ),
    }


def _run_assessment(job_id: str, target: str, profile: str = "baseline") -> None:
    parsed = urlparse(target)

    try:
        _set_job(job_id, status="running", started_at=_now())

        def status_callback(name: str, envelope: dict[str, Any]) -> None:
            job = _get_job(job_id)
            statuses = job.get("tool_statuses", {})
            statuses[name] = deepcopy(envelope)
            done = sum(
                1
                for value in statuses.values()
                if value.get("status") not in {"running", "queued"}
            )
            _set_job(
                job_id,
                current_step=name if envelope.get("status") == "running" else None,
                tool_statuses=statuses,
                progress=min(95, done * 7),
            )

        workflow = run_workflow(
            f"Authorized {profile} dashboard assessment",
            target,
            parsed.hostname or "",
            profile=profile,
            status_callback=status_callback,
        )
        evidence = workflow["evidence_package"]

        _set_job(
            job_id,
            status="completed",
            assessment_status=workflow.get("assessment_status", "completed"),
            coverage=workflow.get("coverage", {}),
            current_step=None,
            progress=100,
            completed_at=_now(),
            results=workflow["results"],
            observed_surface=evidence["observed_surface"],
            graphql=evidence["observed_surface"].get("graphql", {}),
            jwt=evidence["observed_surface"].get("jwt", {}),
            upload=evidence["observed_surface"].get("upload", {}),
            business_logic=_business_logic_summary(workflow["results"]),
            observations=evidence["observations"],
            candidates=evidence["candidate_findings"],
            verified_findings=evidence["verified_findings"],
            findings=evidence["observations"]
            + evidence["candidate_findings"]
            + evidence["verified_findings"],
            report_mode=(
                (workflow["results"].get("ai_report_writer") or {}).get("output") or {}
            ).get("report_mode", "not_available"),
            report_file=(
                (workflow["results"].get("ai_report_writer") or {}).get("output") or {}
            ).get("report_file"),
        )
    except Exception as exc:
        _set_job(
            job_id,
            status="failed",
            current_step=None,
            completed_at=_now(),
            error=str(exc),
        )


def _render_report(job: dict[str, Any]) -> str:
    observations = job.get("observations", [])
    candidates = job.get("candidates", [])
    verified = job.get("verified_findings", [])
    coverage = job.get("coverage") or {}
    lines = [
        f"# CyberCortex AI Agent v{__version__} Security Assessment Report",
        "",
        f"**Target:** {job['target']}",
        f"**Generated:** {_now()}",
        f"**Assessment ID:** `{job['id']}`",
        "",
        "## Executive Summary",
        "",
        "No evidence collected during this assessment demonstrated an exploitable vulnerability.",
        "",
        f"- Observations: {len(observations)}",
        f"- Candidates: {len(candidates)}",
        f"- Verified findings: {len(verified)}",
        "",
        "## Scope and Authorization",
        "",
        "The operator confirmed authorization. Testing remained restricted to the configured scope and program rules.",
        "",
        "## Assessment Coverage",
        "",
        f"- Profile: {job.get('profile', 'unknown')}",
        f"- Assessment status: {job.get('assessment_status', job.get('status', 'unknown'))}",
        f"- Coverage: {coverage.get('coverage_percentage', 0)}%",
        "",
        "## Confirmed Security Controls",
        "",
        "No controls are claimed unless supported by the retained normalized evidence.",
        "",
        "## Verified Findings",
        "",
    ]
    lines.append("No verified findings were recorded." if not verified else "")
    for finding in verified[:20]:
        lines.extend(_report_finding(finding))
    lines.extend(["", "## Candidate Findings Requiring Manual Verification", ""])
    if not candidates:
        lines.append("No candidate findings were recorded.")
    for finding in candidates[:20]:
        lines.extend(_report_finding(finding))
    lines.extend(["", "## Informational and Defense-in-Depth Observations", ""])
    if not observations:
        lines.append("No informational observations were recorded.")
    for finding in observations[:20]:
        lines.extend(_report_finding(finding))
    for title, key, phrase in (
        (
            "GraphQL Surface",
            "graphql",
            "GraphQL-related application behavior was observed.",
        ),
        ("JWT Surface", "jwt", "JWT-related authentication metadata was observed."),
        (
            "Business Workflow Surface",
            "business_logic",
            "Business-workflow-related application behavior was observed.",
        ),
        (
            "File Upload Surface",
            "upload",
            "File-upload-related application behavior was observed.",
        ),
    ):
        data = job.get(key) or {}
        relevant = bool(
            data.get("endpoints_observed")
            or data.get("tokens_observed")
            or data.get("workflow_candidates")
            or data.get("surface_observed")
        )
        if relevant:
            lines.extend(["", f"## {title}", "", phrase])
    lines.extend(
        [
            "",
            "## Incomplete or Failed Checks",
            "",
            "See the coverage summary for partial or failed checks.",
            "",
            "## Prioritized Next Manual Tests",
            "",
            "Manually verify only candidates supported by the evidence above, using controlled accounts and test-owned resources.",
            "",
            "## Limitations",
            "",
            "Automated and offline analysis cannot by itself prove exploitability. Authenticated behavior requires explicit controlled input.",
            "",
            "## Conclusion",
            "",
            "No engine automatically proves a vulnerability. Review all evidence and program rules before further testing.",
            "",
        ]
    )
    return "\n".join(line for line in lines if line is not None)


def _report_finding(finding: dict[str, Any]) -> list[str]:
    """Render only normalized, secret-safe finding fields."""
    return [
        f"### {finding.get('title', 'Untitled observation')}",
        "",
        f"- Severity: {str(finding.get('severity', 'informational')).title()}",
        f"- Status: {finding.get('status', 'Observation')}",
        f"- Confidence: {finding.get('confidence', 'unknown')}",
        f"- Source tool: {finding.get('source_tool', 'unknown')}",
        f"- Evidence summary: {finding.get('evidence_summary', finding.get('evidence', 'No secret-safe summary available.'))}",
        f"- What it proves: {finding.get('what_it_proves', 'Only the described behavior was observed.')}",
        f"- What it does not prove: {finding.get('what_it_does_not_prove', 'Exploitability or security impact was not established.')}",
        f"- Manual verification: {finding.get('manual_verification', 'Review with controlled evidence if permitted.')}",
        f"- Limitations: {finding.get('limitations', 'Automated evidence is limited.')}",
        "",
    ]


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    html = DASHBOARD_FILE.read_text(encoding="utf-8").replace(
        "{{VERSION}}", __version__
    )
    return HTMLResponse(html)


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "cybercortex-web", "version": __version__}


@app.get("/api/scope")
def scope() -> dict[str, Any]:
    return {
        "domains": get_allowed_domains(),
        "url_prefixes": get_allowed_url_prefixes(),
    }


@app.post("/api/scans", status_code=202)
def start_scan(
    request: ScanRequest, background_tasks: BackgroundTasks
) -> dict[str, Any]:
    if not request.authorization_confirmed:
        raise HTTPException(
            status_code=400, detail="Explicit authorization confirmation is required"
        )

    target = request.target.strip()
    if "://" not in target:
        target = f"https://{target}"
    scope_result = enforce_scope(target)
    if not scope_result.get("allowed"):
        raise HTTPException(
            status_code=403, detail=scope_result.get("error", "Target is outside scope")
        )

    parsed = urlparse(target)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=400,
            detail="A valid HTTP(S) target without embedded credentials is required",
        )

    job_id = uuid4().hex
    job = {
        "id": job_id,
        "target": target,
        "profile": request.profile,
        "status": "queued",
        "progress": 0,
        "current_step": None,
        "created_at": _now(),
        "started_at": None,
        "completed_at": None,
        "results": {},
        "tool_statuses": {},
        "observed_surface": {},
        "graphql": {
            "endpoints_observed": 0,
            "confirmed_endpoints": 0,
            "introspection_status": "not_tested",
            "operations_observed": 0,
            "manual_authorization_plans": 0,
        },
        "jwt": {
            "tokens_observed": 0,
            "algorithms": [],
            "expiration_observations": [],
            "issuer_present": False,
            "audience_present": False,
            "comparison_count": 0,
            "manual_plans": 0,
            "replay_status": "not_applicable",
        },
        "upload": {
            "surface_observed": False,
            "observations": 0,
            "validation_observations": 0,
            "metadata_observations": 0,
            "storage_observations": [],
            "manual_plans": 0,
            "replay_status": "not_applicable",
            "filenames_disclosed": False,
        },
        "observations": [],
        "candidates": [],
        "verified_findings": [],
        "deepseek_status": "queued",
        "findings": [],
        "error": None,
    }
    with _jobs_lock:
        if len(_jobs) >= MAX_RETAINED_JOBS:
            oldest = min(_jobs, key=lambda key: _jobs[key]["created_at"])
            del _jobs[oldest]
        _jobs[job_id] = job
    background_tasks.add_task(_run_assessment, job_id, target, request.profile)
    return _public_job(job)


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    return _public_job(_get_job(job_id))


@app.get("/api/scans/{job_id}/report", response_class=PlainTextResponse)
def download_report(job_id: str) -> PlainTextResponse:
    job = _get_job(job_id)
    if job["status"] != "completed":
        raise HTTPException(status_code=409, detail="Assessment is not complete")
    return PlainTextResponse(
        _render_report(job),
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="cybercortex-{job_id[:8]}.md"'
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("web_app:app", host="127.0.0.1", port=8000, reload=False)
