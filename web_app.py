"""Local web dashboard for authorized CyberCortex assessments."""

from __future__ import annotations

import json
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

from tools.dns_lookup import dns_lookup
from tools.http_probe import http_probe
from tools.scope_guard import (
    enforce_scope,
    get_allowed_domains,
    get_allowed_url_prefixes,
)
from tools.security_headers_checker import security_headers_checker
from tools.tech_fingerprint import tech_fingerprint

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "web" / "dashboard.html"
MAX_RETAINED_JOBS = 50

app = FastAPI(
    title="CyberCortex Bug Bounty Cockpit",
    description="A local dashboard for explicitly authorized, non-destructive web checks.",
    version="1.0.0",
)

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=2048)
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


def _run_assessment(job_id: str, target: str) -> None:
    steps = ["dns", "http_probe", "security_headers", "technology"]
    results: dict[str, Any] = {}
    parsed = urlparse(target)

    try:
        _set_job(job_id, status="running", started_at=_now())
        runners = (
            ("dns", lambda: dns_lookup(parsed.hostname or "")),
            ("http_probe", lambda: http_probe(target)),
            ("security_headers", lambda: security_headers_checker(target)),
            ("technology", lambda: tech_fingerprint(target)),
        )
        for index, (name, runner) in enumerate(runners, start=1):
            _set_job(
                job_id, current_step=name, progress=int((index - 1) / len(steps) * 100)
            )
            results[name] = runner()
            _set_job(
                job_id,
                results=deepcopy(results),
                progress=int(index / len(steps) * 100),
            )

        _set_job(
            job_id,
            status="completed",
            current_step=None,
            completed_at=_now(),
            findings=_finding_summary(results),
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
    findings = job.get("findings", [])
    lines = [
        "# CyberCortex Authorized Assessment Report",
        "",
        f"**Target:** {job['target']}",
        f"**Generated:** {_now()}",
        f"**Assessment ID:** `{job['id']}`",
        "",
        "## Scope and methodology",
        "",
        "The operator explicitly confirmed authorization. CyberCortex performed only low-impact DNS and HTTP configuration checks against the configured in-scope target.",
        "",
        "## Findings requiring manual validation",
        "",
    ]
    if not findings:
        lines.append(
            "No candidate findings were produced by the safe checks. This does not prove the target is vulnerability-free."
        )
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding['title']}",
                "",
                f"- Severity: {finding['severity'].upper()}",
                f"- Status: {finding['status']}",
                f"- Evidence: {finding['evidence']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Raw evidence",
            "",
            "```json",
            json.dumps(job.get("results", {}), indent=2),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(DASHBOARD_FILE.read_text(encoding="utf-8"))


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "cybercortex-web"}


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
        "status": "queued",
        "progress": 0,
        "current_step": None,
        "created_at": _now(),
        "started_at": None,
        "completed_at": None,
        "results": {},
        "findings": [],
        "error": None,
    }
    with _jobs_lock:
        if len(_jobs) >= MAX_RETAINED_JOBS:
            oldest = min(_jobs, key=lambda key: _jobs[key]["created_at"])
            del _jobs[oldest]
        _jobs[job_id] = job
    background_tasks.add_task(_run_assessment, job_id, target)
    return deepcopy(job)


@app.get("/api/scans/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    return _get_job(job_id)


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
