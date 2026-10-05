"""Operator-side liveness preflight for the controlled GraphQL benchmark lab."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_PID_FILE = Path("/tmp/p4-1i8-graphql-lab.pid")
DEFAULT_LOG_FILE = Path("/tmp/p4-1i8-graphql-lab.log")
EXPECTED_APP = "agent_core.benchmark.graphql_lab:app"
EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 8765
HEALTH_PATH = "/healthz"
MAX_HEALTH_RESPONSE_BYTES = 256


class GraphQLLabPreflightError(RuntimeError):
    """Safe controller-side failure that must prevent benchmark execution."""


@dataclass(frozen=True, slots=True)
class GraphQLLabPreflightConfig:
    pid_file: Path = DEFAULT_PID_FILE
    log_file: Path = DEFAULT_LOG_FILE
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not 0.1 <= self.timeout_seconds <= 10.0:
            raise ValueError("lab preflight timeout is outside the safe bound")


@dataclass(frozen=True, slots=True)
class GraphQLLabPreflightResult:
    pid: int
    host: str
    port: int
    health_requests: int
    ready: bool = True


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _read_pid(path: Path) -> int:
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise GraphQLLabPreflightError("lab_pid_file_unavailable")
    try:
        rendered = path.read_text(encoding="utf-8").strip()
    except OSError:
        raise GraphQLLabPreflightError("lab_pid_file_unavailable") from None
    if not rendered.isascii() or not rendered.isdecimal():
        raise GraphQLLabPreflightError("lab_pid_file_invalid")
    pid = int(rendered)
    if pid <= 1:
        raise GraphQLLabPreflightError("lab_pid_file_invalid")
    return pid


def _require_log(path: Path) -> None:
    if not path.exists() or not path.is_file() or path.is_symlink():
        raise GraphQLLabPreflightError("lab_log_file_unavailable")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_command(pid: int) -> str:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        raise GraphQLLabPreflightError("lab_process_inspection_failed") from None
    if result.returncode != 0 or not result.stdout.strip():
        raise GraphQLLabPreflightError("lab_process_unavailable")
    return result.stdout.strip()


def _option_value(tokens: Sequence[str], option: str) -> str | None:
    for index, token in enumerate(tokens):
        if token == option and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith(f"{option}="):
            return token.split("=", 1)[1]
    return None


def _command_matches_expected_lab(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    uvicorn = any(Path(token).name == "uvicorn" for token in tokens) or any(
        left == "-m" and right == "uvicorn" for left, right in zip(tokens, tokens[1:])
    )
    return bool(
        uvicorn
        and EXPECTED_APP in tokens
        and _option_value(tokens, "--host") == EXPECTED_HOST
        and _option_value(tokens, "--port") == str(EXPECTED_PORT)
    )


def _pid_owns_listener(pid: int) -> bool:
    try:
        result = subprocess.run(
            [
                "lsof",
                "-nP",
                "-a",
                "-p",
                str(pid),
                f"-iTCP:{EXPECTED_PORT}",
                "-sTCP:LISTEN",
                "-Fpn",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        raise GraphQLLabPreflightError("lab_listener_inspection_failed") from None
    fields = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    return bool(
        result.returncode == 0
        and f"p{pid}" in fields
        and any(
            field.startswith("n") and field.rsplit(":", 1)[-1] == str(EXPECTED_PORT)
            for field in fields
        )
    )


def _health_check(timeout_seconds: float) -> None:
    opener = build_opener(_RejectRedirects())
    request = Request(
        f"http://{EXPECTED_HOST}:{EXPECTED_PORT}{HEALTH_PATH}", method="GET"
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            status = response.getcode()
            body = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise GraphQLLabPreflightError("lab_health_check_failed") from None
    if status != 200 or len(body) > MAX_HEALTH_RESPONSE_BYTES:
        raise GraphQLLabPreflightError("lab_health_check_failed")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GraphQLLabPreflightError("lab_health_check_failed") from None
    if payload != {"status": "ok"}:
        raise GraphQLLabPreflightError("lab_health_check_failed")


def verify_graphql_lab_preflight(
    config: GraphQLLabPreflightConfig,
    *,
    process_exists: Callable[[int], bool] | None = None,
    process_command: Callable[[int], str] | None = None,
    pid_owns_listener: Callable[[int], bool] | None = None,
    health_check: Callable[[float], None] | None = None,
) -> GraphQLLabPreflightResult:
    """Validate the controller-owned lab around exactly one health request."""

    exists = process_exists or _process_exists
    command_for = process_command or _process_command
    owns_listener = pid_owns_listener or _pid_owns_listener
    check_health = health_check or _health_check

    pid = _read_pid(config.pid_file)
    _require_log(config.log_file)
    if not exists(pid):
        raise GraphQLLabPreflightError("lab_process_unavailable")
    if not _command_matches_expected_lab(command_for(pid)):
        raise GraphQLLabPreflightError("lab_process_command_mismatch")
    if not owns_listener(pid):
        raise GraphQLLabPreflightError("lab_listener_owner_mismatch")

    check_health(config.timeout_seconds)

    if _read_pid(config.pid_file) != pid:
        raise GraphQLLabPreflightError("lab_pid_changed_after_health_check")
    if not exists(pid):
        raise GraphQLLabPreflightError("lab_process_died_after_health_check")
    if not owns_listener(pid):
        raise GraphQLLabPreflightError("lab_listener_lost_after_health_check")
    return GraphQLLabPreflightResult(
        pid=pid,
        host=EXPECTED_HOST,
        port=EXPECTED_PORT,
        health_requests=1,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the controlled GraphQL lab immediately before one run."
    )
    parser.add_argument("--pid-file", type=Path, default=DEFAULT_PID_FILE)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_graphql_lab_preflight(
            GraphQLLabPreflightConfig(
                pid_file=args.pid_file,
                log_file=args.log_file,
                timeout_seconds=args.timeout_seconds,
            )
        )
    except (GraphQLLabPreflightError, ValueError) as exc:
        print(f"lab_preflight_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
