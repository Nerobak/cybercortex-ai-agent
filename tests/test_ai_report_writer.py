from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.ai_report_writer import ai_report_writer


def _run(tmp_path: Path, monkeypatch, response):
    def fake_ask(*args, **kwargs):
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr("tools.ai_report_writer.ask_agent", fake_ask)
    return ai_report_writer(
        "https://example.test",
        {
            "observations": [{"title": "Observed control"}],
            "candidate_findings": [],
            "verified_findings": [],
            "manual_verification_queue": [],
            "tool_results": {},
            "execution_summary": {},
            "evidence_files": [],
        },
        output_dir=str(tmp_path),
    )


def _assert_files(result):
    assert result["success"] is True
    assert result["report_generated"] is True
    assert Path(result["report"]).is_file()
    assert Path(result["evidence"]).is_file()


def test_valid_plain_text_deepseek_response_writes_report(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch, "# Valid report\n")
    _assert_files(result)
    assert result["report_mode"] == "deepseek"
    assert result["ai_status"] == "completed"
    assert result["ai_error"] is None


@pytest.mark.parametrize(
    ("response", "ai_status"),
    [
        (TimeoutError("slow"), "timed_out"),
        (ConnectionError("offline"), "failed"),
        ({"unexpected": "structure"}, "failed"),
        ("", "failed"),
    ],
)
def test_ai_failures_always_generate_deterministic_report(
    tmp_path, monkeypatch, response, ai_status
):
    result = _run(tmp_path, monkeypatch, response)
    _assert_files(result)
    assert result["status"] == "completed_with_fallback"
    assert result["report_mode"] == "deterministic_fallback"
    assert result["ai_status"] == ai_status
    assert "slow" not in (result["ai_error"] or "")
    assert "offline" not in (result["ai_error"] or "")


def test_malformed_sections_are_skipped_with_safe_diagnostics(tmp_path, monkeypatch):
    marker = "private malformed evidence"
    monkeypatch.setattr(
        "tools.ai_report_writer.ask_agent", lambda *args, **kwargs: "# report"
    )
    result = ai_report_writer(
        "https://example.test",
        {
            "observations": marker,
            "candidate_findings": [{"title": "valid"}, marker, 4],
            "verified_findings": None,
            "manual_verification_queue": {"title": "single"},
            "tool_results": marker,
            "execution_summary": [],
            "evidence_files": ["safe.json", 2],
        },
        output_dir=str(tmp_path),
    )
    _assert_files(result)
    evidence_text = Path(result["evidence"]).read_text(encoding="utf-8")
    evidence = json.loads(evidence_text)["evidence"]
    assert evidence["observations"] == []
    assert evidence["candidate_findings"] == [{"title": "valid"}]
    assert evidence["manual_verification_queue"] == [{"title": "single"}]
    assert evidence["tool_results"] == {}
    assert marker not in evidence_text
    assert result["diagnostics"]


def test_empty_evidence_package_still_generates_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tools.ai_report_writer.ask_agent", lambda *args, **kwargs: TimeoutError()
    )
    result = ai_report_writer("https://example.test", {}, output_dir=str(tmp_path))
    _assert_files(result)
