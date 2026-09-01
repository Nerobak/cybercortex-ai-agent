"""Killable local execution with fail-closed handling for network tools."""

from __future__ import annotations

import multiprocessing
import queue
import time
from dataclasses import dataclass
from typing import Any

from agent_core.result_normalizer import redact


def _tool_worker(
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    output_queue,
) -> None:
    try:
        from tool_registry import resolve_tool

        function = resolve_tool(tool_name)
        if function is None:
            output_queue.put((False, None, "Tool is unavailable."))
            return
        output_queue.put((True, function(*args, **kwargs), None))
    except BaseException as exc:  # child must always return a bounded envelope
        output_queue.put((False, None, f"{type(exc).__name__}: {exc}"))


@dataclass
class IsolatedExecutionResult:
    status: str
    output: Any = None
    error: str | None = None
    duration_ms: int = 0
    terminated: bool = False


class SubprocessToolExecutor:
    """Execute local tools in a process; network tools require shared runtime."""

    def __init__(self, start_method: str = "spawn") -> None:
        available = multiprocessing.get_all_start_methods()
        self.start_method = start_method if start_method in available else available[0]

    def execute(
        self,
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        timeout: float,
    ) -> IsolatedExecutionResult:
        from tool_registry import TOOLS

        metadata = TOOLS.get(tool_name) or {}
        if (
            metadata.get("sends_network_traffic")
            and metadata.get("network_adapter") != "offline_fallback"
        ):
            return IsolatedExecutionResult(
                status="failed",
                error=(
                    "Network execution is disabled in isolated subprocesses because "
                    "the shared policy and request ledger cannot be preserved."
                ),
            )
        if metadata.get("network_adapter") == "offline_fallback":
            kwargs = {**kwargs, "allow_network_analysis": False}
        context = multiprocessing.get_context(self.start_method)
        output_queue = context.Queue(maxsize=1)
        process = context.Process(
            target=_tool_worker,
            args=(tool_name, args, kwargs, output_queue),
            daemon=True,
        )
        started = time.monotonic()
        process.start()
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join(2)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(1)
            return IsolatedExecutionResult(
                status="timed_out",
                error=f"Tool exceeded {timeout} second timeout and was terminated.",
                duration_ms=round((time.monotonic() - started) * 1000),
                terminated=True,
            )
        try:
            success, output, error = output_queue.get_nowait()
        except queue.Empty:
            success, output, error = (
                False,
                None,
                (f"Tool process exited with code {process.exitcode} without a result."),
            )
        return IsolatedExecutionResult(
            status="completed" if success else "failed",
            output=redact(output),
            error=error,
            duration_ms=round((time.monotonic() - started) * 1000),
        )
