from __future__ import annotations

from pathlib import Path

import pytest

import benchmark_cli


def test_run_help_marks_execution_factory_trusted_and_not_sandboxed(capsys):
    with pytest.raises(SystemExit) as exc:
        benchmark_cli.build_parser().parse_args(["run", "--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out.lower()
    assert "trusted operator execution factory" in help_text
    assert "not sandboxed" in help_text


def test_factory_trust_boundary_documentation_disclaims_python_sandbox():
    text = Path("docs/BENCHMARKS.md").read_text(encoding="utf-8").lower()
    assert "trusted operator code" in text
    assert "not a security sandbox" in text
    assert "malicious factory" in text
    assert "does not claim to protect ground truth" in text
