import json
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from config import ENABLE_ACTIVE_SCANNING, REPORT_DIR
from tools.scope_guard import enforce_scope


def _result(
    target: str,
    status: str,
    findings: list[dict] | None = None,
    *,
    evidence_file: str | None = None,
    error: str | None = None,
) -> dict:
    findings = findings or []
    counts = Counter(item.get("severity", "unknown") for item in findings)
    summary = {
        name: counts.get(name, 0)
        for name in ("critical", "high", "medium", "low", "info", "unknown")
    }
    return {
        "success": status == "completed",
        "target": target,
        "status": status,
        "finding_count": len(findings),
        "severity_summary": summary,
        "findings": findings[:50],
        "evidence_file": evidence_file,
        "timeout": status == "timed_out",
        "failure": status == "failed",
        "error": error,
        # Compatibility aliases for existing consumers.
        "url": target,
        "findings_count": len(findings),
        "raw_output_file": evidence_file,
    }


def safe_filename_from_url(url: str) -> str:
    """
    Convert a URL into a safe filename component.
    """

    parsed = urlparse(url)

    host = parsed.hostname or "target"
    path = parsed.path.strip("/").replace("/", "_")

    name = host

    if path:
        name = f"{host}_{path}"

    return "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "_"
        for character in name
    )


def parse_nuclei_finding(raw_line: str) -> dict | None:
    """
    Parse one Nuclei JSONL result and return only useful fields.

    Raw requests, responses, curl commands, and other large fields are
    intentionally excluded from console output and AI report input.
    """

    try:
        data = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    info = data.get("info", {})

    return {
        "template_id": data.get("template-id"),
        "template_path": data.get("template-path"),
        "name": info.get("name"),
        "severity": info.get("severity", "unknown").lower(),
        "description": info.get("description", "").strip(),
        "matcher_name": data.get("matcher-name"),
        "type": data.get("type"),
        "host": data.get("host"),
        "port": data.get("port"),
        "scheme": data.get("scheme"),
        "url": data.get("url"),
        "matched_at": data.get("matched-at"),
        "ip": data.get("ip"),
        "timestamp": data.get("timestamp"),
        "classification": info.get("classification", {}),
        "tags": info.get("tags", []),
    }


def nuclei_scan(url: str, severity: str = "low") -> dict:
    """
    Run a limited Nuclei scan and return structured findings.

    Full raw JSONL evidence is saved to a file rather than printed to
    the terminal or passed directly to the AI report writer.
    """

    scope = enforce_scope(url)

    if not scope.get("allowed"):
        return scope

    if not ENABLE_ACTIVE_SCANNING:
        return _result(
            url,
            "failed",
            error=(
                "Active scanning is disabled. "
                "Set ENABLE_ACTIVE_SCANNING=true in .env"
            ),
        )

    report_directory = Path(REPORT_DIR)
    report_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = safe_filename_from_url(url)

    raw_output_file = report_directory / f"nuclei_{safe_target}_{timestamp}.jsonl"

    command = [
        "nuclei",
        "-u",
        url,
        "-t",
        "http/misconfiguration/http-missing-security-headers.yaml",
        "-jsonl",
        "-silent",
        "-retries",
        "0",
        "-rl",
        "3",
        "-timeout",
        "5",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    except subprocess.TimeoutExpired:
        return _result(
            url, "timed_out", error="Nuclei scan timed out after 60 seconds."
        )

    except FileNotFoundError:
        return _result(
            url,
            "failed",
            error=(
                "Nuclei executable was not found. "
                "Confirm that Nuclei is installed and available in PATH."
            ),
        )

    except Exception as exc:
        return _result(url, "failed", error=str(exc))

    raw_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    if raw_lines:
        raw_output_file.write_text(
            "\n".join(raw_lines) + "\n",
            encoding="utf-8",
        )

    findings = []

    for raw_line in raw_lines:
        finding = parse_nuclei_finding(raw_line)

        if finding is not None:
            findings.append(finding)

    stderr = result.stderr.strip()
    status = "completed" if result.returncode == 0 else "failed"
    return _result(
        url,
        status,
        findings,
        evidence_file=str(raw_output_file) if raw_lines else None,
        error=stderr or None,
    )
