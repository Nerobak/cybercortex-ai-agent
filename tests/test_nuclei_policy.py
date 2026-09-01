from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import tools.nuclei_scan as nuclei_module
import agent_core.tool_runner as runner_module
from agent_core.result_normalizer import normalize_findings


def test_command_uses_approved_bounded_policy():
    command, policy = nuclei_module.build_nuclei_command(
        "https://authorized.example", "medium"
    )

    assert command[:3] == ["nuclei", "-u", "https://authorized.example"]
    assert command[command.index("-severity") + 1] == "medium,high,critical"
    assert "-no-interactsh" in command
    assert "dos" in command[command.index("-exclude-tags") + 1]
    assert policy["included_severities"] == ["medium", "high", "critical"]
    assert policy["rate_limit_per_second"] > 0


def test_command_rejects_unknown_severity():
    with pytest.raises(ValueError, match="Invalid minimum severity"):
        nuclei_module.build_nuclei_command("https://authorized.example", "urgent")


def test_intrusive_policy_keeps_destructive_classes_excluded():
    command, policy = nuclei_module.build_nuclei_command(
        "https://authorized.example", "low", intrusive=True
    )
    excluded = command[command.index("-exclude-tags") + 1].split(",")
    assert policy["intrusive_templates_enabled"] is True
    assert "intrusive" not in excluded
    assert {"dos", "fuzz", "bruteforce", "destructive"}.issubset(excluded)


def test_scan_parses_structured_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_module, "ENABLE_ACTIVE_SCANNING", True)
    monkeypatch.setattr(nuclei_module, "REPORT_DIR", str(tmp_path))
    monkeypatch.setattr(
        nuclei_module,
        "enforce_scope",
        lambda url: {"allowed": True, "target": url},
    )
    output = json.dumps(
        {
            "template-id": "example-cve",
            "info": {
                "name": "Example vulnerable component",
                "severity": "high",
                "description": "Version-specific response evidence matched.",
                "tags": ["cve"],
            },
            "matcher-name": "version",
            "matched-at": "https://authorized.example/component",
        }
    )
    monkeypatch.setattr(
        nuclei_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=output + "\n", stderr="", returncode=0
        ),
    )

    result = nuclei_module.nuclei_scan("https://authorized.example", "medium")

    assert result["success"] is True
    assert result["finding_count"] == 1
    assert result["findings"][0]["template_id"] == "example-cve"
    assert result["scan_policy"]["minimum_severity"] == "medium"
    assert result["evidence_file"]


def test_configured_nuclei_timeout_is_used_by_subprocess(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr(nuclei_module, "ENABLE_ACTIVE_SCANNING", True)
    monkeypatch.setattr(nuclei_module, "NUCLEI_TIMEOUT_SECONDS", 137)
    monkeypatch.setattr(nuclei_module, "REPORT_DIR", str(tmp_path))
    monkeypatch.setattr(nuclei_module, "enforce_scope", lambda url: {"allowed": True})

    def fake_run(*args, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(nuclei_module.subprocess, "run", fake_run)
    result = nuclei_module.nuclei_scan("https://authorized.example")

    assert result["success"] is True
    assert observed["timeout"] == 137


def test_nuclei_runner_timeout_adds_only_cleanup_grace(monkeypatch):
    monkeypatch.setattr(runner_module, "NUCLEI_TIMEOUT_SECONDS", 120)
    assert runner_module._nuclei_runner_timeout_seconds() == 125
    assert runner_module._nuclei_runner_timeout_seconds() > 120
    assert runner_module.DEFAULT_TOOL_TIMEOUT == 90


def test_runner_passes_nuclei_specific_outer_timeout(monkeypatch):
    observed = {}
    monkeypatch.setattr(runner_module, "NUCLEI_TIMEOUT_SECONDS", 120)
    monkeypatch.setattr(
        runner_module, "tools_for_profile", lambda profile: ["nuclei_scan"]
    )

    def fake_execute(self, name, args, kwargs, input_summary, timeout=None):
        observed[name] = timeout
        return {
            "tool": name,
            "status": "completed",
            "success": True,
            "output": {"success": True, "findings": []},
            "error": None,
        }

    monkeypatch.setattr(runner_module.ToolRunner, "_execute", fake_execute)
    runner_module.ToolRunner().run("https://authorized.example")

    assert observed["nuclei_scan"] == 125


def test_nuclei_matches_enter_manual_verification_queue():
    findings = normalize_findings(
        {
            "nuclei_scan": {
                "output": {
                    "findings": [
                        {
                            "template_id": "example-cve",
                            "name": "Example vulnerable component",
                            "severity": "high",
                            "description": "A deterministic matcher fired.",
                            "matched_at": "https://authorized.example/component",
                        }
                    ]
                }
            }
        }
    )

    assert findings[0]["status"] == "needs_manual_verification"
    assert findings[0]["category"] == "vulnerability_candidate"
    assert findings[0]["severity"] == "high"
