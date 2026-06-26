import subprocess

from config import ENABLE_ACTIVE_SCANNING
from tools.scope_guard import enforce_scope


def nuclei_scan(url: str, severity: str = "low"):
    scope = enforce_scope(url)

    if not scope["allowed"]:
        return scope

    if not ENABLE_ACTIVE_SCANNING:
        return {
            "success": False,
            "error": "Active scanning is disabled. Set ENABLE_ACTIVE_SCANNING=true in .env",
        }

    try:
        result = subprocess.run(
            [
                "nuclei",
                "-u", url,
                "-t", "http/misconfiguration/http-missing-security-headers.yaml",
                "-jsonl",
                "-silent",
                "-retries", "0",
                "-rl", "3",
                "-timeout", "5",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        findings = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        return {
            "success": result.returncode == 0,
            "url": url,
            "severity": severity,
            "findings_count": len(findings),
            "findings": findings[:50],
            "error": result.stderr.strip(),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
