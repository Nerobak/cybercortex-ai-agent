from __future__ import annotations

import pytest

from agent_core.benchmark.lab_preflight import (
    GraphQLLabPreflightConfig,
    GraphQLLabPreflightError,
    verify_graphql_lab_preflight,
)

EXPECTED_COMMAND = (
    "python -m uvicorn agent_core.benchmark.graphql_lab:app "
    "--host 127.0.0.1 --port 8765"
)


def _files(tmp_path):
    pid_file = tmp_path / "p4-1i8-graphql-lab.pid"
    log_file = tmp_path / "p4-1i8-graphql-lab.log"
    pid_file.write_text("4242\n", encoding="utf-8")
    log_file.write_text("synthetic startup log\n", encoding="utf-8")
    return GraphQLLabPreflightConfig(pid_file=pid_file, log_file=log_file)


def test_lab_preflight_checks_same_process_around_exactly_one_health_request(tmp_path):
    config = _files(tmp_path)
    process_checks = []
    listener_checks = []
    health_checks = []

    result = verify_graphql_lab_preflight(
        config,
        process_exists=lambda pid: not process_checks.append(pid),
        process_command=lambda pid: EXPECTED_COMMAND,
        pid_owns_listener=lambda pid: not listener_checks.append(pid),
        health_check=lambda timeout: health_checks.append(timeout),
    )

    assert result.ready
    assert result.pid == 4242
    assert result.health_requests == 1
    assert process_checks == [4242, 4242]
    assert listener_checks == [4242, 4242]
    assert health_checks == [2.0]


@pytest.mark.parametrize("missing_name", ("pid", "log"))
def test_lab_preflight_stops_before_health_when_preserved_file_is_missing(
    tmp_path,
    missing_name,
):
    config = _files(tmp_path)
    missing = config.pid_file if missing_name == "pid" else config.log_file
    missing.unlink()
    health_checks = []

    with pytest.raises(GraphQLLabPreflightError, match=f"lab_{missing_name}_file"):
        verify_graphql_lab_preflight(
            config,
            process_exists=lambda pid: True,
            process_command=lambda pid: EXPECTED_COMMAND,
            pid_owns_listener=lambda pid: True,
            health_check=lambda timeout: health_checks.append(timeout),
        )

    assert health_checks == []


def test_lab_preflight_rejects_wrong_process_before_health(tmp_path):
    config = _files(tmp_path)
    health_checks = []

    with pytest.raises(GraphQLLabPreflightError, match="lab_process_command_mismatch"):
        verify_graphql_lab_preflight(
            config,
            process_exists=lambda pid: True,
            process_command=lambda pid: "python unrelated_server.py --port 8765",
            pid_owns_listener=lambda pid: True,
            health_check=lambda timeout: health_checks.append(timeout),
        )

    assert health_checks == []


def test_lab_preflight_stops_when_same_pid_loses_listener_after_health(tmp_path):
    config = _files(tmp_path)
    listener_results = iter((True, False))
    health_checks = []

    with pytest.raises(
        GraphQLLabPreflightError, match="lab_listener_lost_after_health_check"
    ):
        verify_graphql_lab_preflight(
            config,
            process_exists=lambda pid: True,
            process_command=lambda pid: EXPECTED_COMMAND,
            pid_owns_listener=lambda pid: next(listener_results),
            health_check=lambda timeout: health_checks.append(timeout),
        )

    assert health_checks == [2.0]
