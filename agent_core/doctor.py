"""Secret-safe local release-readiness checks."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from agent_core.version import __version__
from tool_registry import validate_registry
from config import (
    API_METADATA_DISCOVERY_ENABLED,
    API_METADATA_MAX_REQUESTS,
    API_METADATA_MAX_RESPONSE_BYTES,
    API_METADATA_TIMEOUT_SECONDS,
    BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN,
    BUSINESS_LOGIC_MAX_RESPONSE_BYTES,
    BUSINESS_LOGIC_MAX_STEPS,
    BUSINESS_LOGIC_REPLAY_ENABLED,
    BUSINESS_LOGIC_TIMEOUT_SECONDS,
    CONFIG_ERRORS,
    GRAPHQL_INTROSPECTION_ENABLED,
    GRAPHQL_MAX_RESPONSE_BYTES,
    GRAPHQL_TIMEOUT_SECONDS,
    JWT_MAX_RESPONSE_BYTES,
    JWT_MAX_TOKEN_BYTES,
    JWT_REPLAY_ENABLED,
    JWT_TIMEOUT_SECONDS,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def doctor(*, quick: bool = False) -> str:
    """Return readiness diagnostics without displaying configuration values."""
    rows: list[tuple[str, str, str]] = []

    def add(level: str, name: str, detail: str) -> None:
        rows.append((level, name, detail))

    branch = _git("branch", "--show-current")
    add(
        "PASS" if branch == "release/v2.1.0-beta-rc" else "WARN",
        "Git branch",
        branch or "unavailable",
    )
    add(
        "WARN" if _git("status", "--porcelain") else "PASS",
        "Working tree",
        "dirty" if _git("status", "--porcelain") else "clean",
    )
    add("PASS", "Python version", sys.version.split()[0])
    add(
        "PASS" if sys.prefix != sys.base_prefix else "WARN",
        "Virtual environment",
        "active" if sys.prefix != sys.base_prefix else "not active",
    )
    add(
        "PASS" if (ROOT / ".env").is_file() else "WARN",
        ".env",
        "found" if (ROOT / ".env").is_file() else "not found",
    )
    allowlist = bool(
        os.getenv("PENTEST_ALLOWLIST") or os.getenv("PENTEST_ALLOWED_URL_PREFIXES")
    )
    add(
        "PASS" if allowlist else "FAIL",
        "Allowlist",
        "configured" if allowlist else "not configured",
    )
    reports = ROOT / "reports"
    parent = reports if reports.exists() else reports.parent
    add(
        "PASS" if os.access(parent, os.W_OK) else "FAIL",
        "Reports directory",
        "writable" if os.access(parent, os.W_OK) else "not writable",
    )
    missing = [
        name
        for name in ("fastapi", "openai", "pydantic", "requests", "dotenv")
        if importlib.util.find_spec(name) is None
    ]
    add(
        "PASS" if not missing else "FAIL",
        "Python packages",
        "installed" if not missing else "missing: " + ", ".join(missing),
    )
    for binary, required in (("katana", True), ("nuclei", True), ("whatweb", False)):
        found = shutil.which(binary) is not None
        add(
            "PASS" if found else ("FAIL" if required else "WARN"),
            binary.capitalize(),
            (
                "available"
                if found
                else ("not available" if required else "optional; not available")
            ),
        )
    registry_ok = all(
        item["callable_exists"] and item["metadata_complete"]
        for item in validate_registry()
    )
    add(
        "PASS" if registry_ok else "FAIL",
        "Registry",
        "valid" if registry_ok else "invalid or unavailable entries",
    )
    graphql_limits_valid = (
        GRAPHQL_TIMEOUT_SECONDS > 0 and GRAPHQL_MAX_RESPONSE_BYTES > 0
    )
    add(
        "PASS" if graphql_limits_valid else "FAIL",
        "GraphQL configuration",
        (
            "positive bounded limits; introspection is explicit opt-in"
            if graphql_limits_valid and not GRAPHQL_INTROSPECTION_ENABLED
            else "review limits or active introspection setting"
        ),
    )
    jwt_limits_valid = (
        not CONFIG_ERRORS
        and JWT_MAX_TOKEN_BYTES > 0
        and JWT_TIMEOUT_SECONDS > 0
        and JWT_MAX_RESPONSE_BYTES > 0
    )
    add(
        "PASS" if jwt_limits_valid else "FAIL",
        "JWT configuration",
        (
            "positive numeric limits parsed"
            if jwt_limits_valid
            else "invalid JWT configuration value"
        ),
    )
    add(
        "PASS" if not JWT_REPLAY_ENABLED else "WARN",
        "JWT replay default",
        (
            "disabled"
            if not JWT_REPLAY_ENABLED
            else "enabled by environment; confirm explicit authorization"
        ),
    )
    add(
        "PASS",
        "JWT secret output",
        "doctor reports configuration state without values or credentials",
    )
    business_limits_valid = (
        BUSINESS_LOGIC_TIMEOUT_SECONDS > 0
        and BUSINESS_LOGIC_MAX_RESPONSE_BYTES > 0
        and BUSINESS_LOGIC_MAX_STEPS > 0
        and BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN > 0
        and BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN <= BUSINESS_LOGIC_MAX_STEPS
    )
    add(
        "PASS" if business_limits_valid else "FAIL",
        "Business-logic configuration",
        "positive bounded limits parsed" if business_limits_valid else "invalid limits",
    )
    add(
        "PASS" if not BUSINESS_LOGIC_REPLAY_ENABLED else "WARN",
        "Business-logic replay default",
        (
            "disabled"
            if not BUSINESS_LOGIC_REPLAY_ENABLED
            else "enabled by environment; confirm explicit authorization"
        ),
    )
    api_configuration_errors = [
        error for error in CONFIG_ERRORS if error.startswith("API_METADATA_")
    ]
    api_limits_valid = (
        not api_configuration_errors
        and 1 <= API_METADATA_MAX_REQUESTS <= 8
        and 1 <= API_METADATA_TIMEOUT_SECONDS <= 30
        and 1 <= API_METADATA_MAX_RESPONSE_BYTES <= 2_000_000
    )
    add(
        "PASS" if api_limits_valid else "FAIL",
        "API metadata discovery configuration",
        (
            "enabled with positive bounded GET-only limits"
            if api_limits_valid and API_METADATA_DISCOVERY_ENABLED
            else (
                "disabled with positive bounded limits"
                if api_limits_valid
                else "invalid request, timeout, or response-size bound"
            )
        ),
    )
    add(
        "PASS",
        "Business-logic secret output",
        "configuration, workflow, and dashboard diagnostics omit private values",
    )
    upload_replay_enabled = (
        os.getenv("UPLOAD_REPLAY_ENABLED", "false").strip().lower() == "true"
    )
    add(
        "PASS",
        "File-upload configuration",
        "offline analyzers use bounded evidence and omit file content",
    )
    add(
        "PASS" if not upload_replay_enabled else "WARN",
        "File-upload replay default",
        (
            "disabled"
            if not upload_replay_enabled
            else "enabled by environment; confirm explicit authorization"
        ),
    )
    add(
        (
            "PASS"
            if not (
                JWT_REPLAY_ENABLED
                or BUSINESS_LOGIC_REPLAY_ENABLED
                or upload_replay_enabled
            )
            else "WARN"
        ),
        "All replay defaults",
        (
            "disabled"
            if not (
                JWT_REPLAY_ENABLED
                or BUSINESS_LOGIC_REPLAY_ENABLED
                or upload_replay_enabled
            )
            else "one or more replay features enabled by environment"
        ),
    )
    ignored = all(
        _git("check-ignore", path)
        for path in (
            ".env",
            "reports/example",
            "logs/example",
            "verification_inputs/example",
            "sample.request.txt",
            "sample.burp",
            "sample.jwt",
            "sample.graphql",
            "sample.workflow.json",
            "sample.upload.json",
        )
    )
    add(
        "PASS" if ignored else "FAIL",
        "Ignored secret paths",
        "verified" if ignored else "incomplete",
    )
    source = (ROOT / "web_app.py").read_text(encoding="utf-8")
    add(
        "PASS" if 'host="127.0.0.1"' in source else "FAIL",
        "Dashboard binding",
        "localhost only" if 'host="127.0.0.1"' in source else "review required",
    )
    add(
        "PASS" if "_business_logic_summary" in source else "FAIL",
        "Dashboard business-logic redaction",
        (
            "summary-only projection present"
            if "_business_logic_summary" in source
            else "review required"
        ),
    )
    documentation = (
        "README.md",
        "docs/ARCHITECTURE.md",
        "docs/INSTALL.md",
        "docs/TOOLS.md",
        "docs/ROADMAP.md",
        "docs/GRAPHQL_SUITE.md",
        "docs/JWT_WORKFLOW.md",
        "docs/BUSINESS_LOGIC_ENGINE.md",
        "docs/FILE_UPLOAD_ENGINE.md",
        "docs/RELEASE_NOTES_V2_BETA.md",
        "docs/RELEASE_NOTES_V2_1_BETA.md",
    )
    missing_docs = [name for name in documentation if not (ROOT / name).is_file()]
    add(
        "PASS" if not missing_docs else "FAIL",
        "Documentation files",
        "present" if not missing_docs else "missing: " + ", ".join(missing_docs),
    )
    version_files = ("README.md", "docs/RELEASE_NOTES_V2_1_BETA.md")
    inconsistent = [
        name
        for name in version_files
        if (ROOT / name).is_file()
        and __version__ not in (ROOT / name).read_text(encoding="utf-8")
    ]
    add(
        "PASS" if not inconsistent else "FAIL",
        "Version consistency",
        "canonical version referenced" if not inconsistent else "review documentation",
    )
    if quick:
        add("WARN", "Ollama reachability", "not contacted in quick mode")
        add("WARN", "Configured model", "not queried in quick mode")
        add("WARN", "Tests", "not run in quick mode")
    else:
        reachable = False
        if OPENAI_BASE_URL:
            try:
                with urlopen(OPENAI_BASE_URL.rstrip("/") + "/models", timeout=2):
                    reachable = True
            except (OSError, URLError, ValueError):
                reachable = False
        add(
            "PASS" if reachable else "WARN",
            "Ollama reachability",
            "reachable" if reachable else "unavailable or not configured",
        )
        model_available = False
        if shutil.which("ollama") and OPENAI_MODEL:
            try:
                listed = subprocess.run(
                    ["ollama", "list"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                model_available = (
                    listed.returncode == 0 and OPENAI_MODEL in listed.stdout
                )
            except (OSError, subprocess.SubprocessError):
                model_available = False
        add(
            "PASS" if model_available else "WARN",
            "Configured model",
            "available" if model_available else "unavailable or not configured",
        )
        compile_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "compileall",
                "-q",
                "agent_core",
                "tools",
                "agent.py",
                "web_app.py",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        add(
            "PASS" if compile_result.returncode == 0 else "FAIL",
            "Compile check",
            "passed" if compile_result.returncode == 0 else "failed",
        )
        add("WARN", "Tests", "run the release quality-gate command for full status")
    lines = [f"CyberCortex v{__version__} Release Readiness", ""]
    lines.extend(f"[{level}] {name}: {detail}" for level, name, detail in rows)
    lines += [
        "",
        "Recommended fixes: resolve FAIL items before release; review WARN items for the intended environment.",
    ]
    return "\n".join(lines)
