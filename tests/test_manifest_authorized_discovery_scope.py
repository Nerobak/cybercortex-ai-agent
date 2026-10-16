from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
from contextvars import copy_context
from pathlib import Path
from queue import Queue
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests

import tools.scope_guard as scope_guard
import agent_core.tool_runner as tool_runner_module
from agent_core.benchmark.discovery_scope import (
    DiscoveryScopeHandoffError,
    manifest_authorized_discovery_scope,
    validate_manifest_authorized_discovery_scope,
)
from agent_core.benchmark.types import (
    AllowedStateChangeClass,
    BenchmarkManifest,
    ResetStrategy,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research.types import TargetClass
from agent_core.tool_runner import ToolRunner
from tools.api_metadata_discovery import api_metadata_discovery
from tools.api_object_discovery import crawl_and_discover_ids

_ROOT_A = "https://research-a.example.test"
_ROOT_B = "https://research-b.example.test"


@pytest.fixture(autouse=True)
def restore_legacy_scope_globals():
    previous = (
        scope_guard.PENTEST_ALLOWLIST,
        scope_guard.PENTEST_ALLOWED_URL_PREFIXES,
    )
    try:
        yield
    finally:
        scope_guard.PENTEST_ALLOWLIST, scope_guard.PENTEST_ALLOWED_URL_PREFIXES = (
            previous
        )


def _manifest(root: str = _ROOT_A) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmark_id="synthetic-concurrent-scope",
        benchmark_version="v1",
        title="Synthetic concurrent discovery scope",
        description="Public-only synthetic manifest for offline scope tests.",
        target_class=TargetClass.dedicated_lab,
        authorized_target_reference=root,
        scope_reference="synthetic-scope",
        policy_reference="synthetic-policy",
        request_budget=8,
        model_budget=0,
        experiment_budget=0,
        reproduction_budget=0,
        chain_budget=0,
        wall_time_budget=30.0,
        allowed_state_change_class=AllowedStateChangeClass.read_only,
        reset_strategy=ResetStrategy.stateless_target,
        ground_truth_reference="unread-synthetic-truth",
        scoring_policy_reference="unread-synthetic-scoring",
        created_at="2026-10-15T00:00:00+00:00",
    )


def _policy(
    root: str = _ROOT_A,
    *,
    additional_assets: list[ScopeAsset] | None = None,
) -> AssessmentPolicy:
    parsed = urlsplit(root)
    asset = ScopeAsset(
        kind="url_prefix",
        value=root,
        schemes=[parsed.scheme],
        ports=[parsed.port] if parsed.port is not None else [],
    )
    return AssessmentPolicy(
        authorization_reference="synthetic-policy",
        authorization_confirmed=True,
        allowed_assets=[asset, *(additional_assets or [])],
        allowed_methods=["GET"],
        request_budget=8,
        per_host_request_budget=8,
        resolve_dns_before_request=False,
    )


def _response(url: str) -> requests.Response:
    response = requests.Response()
    response.url = url
    response.status_code = 200
    response.headers["Content-Type"] = "application/json"
    response._content = b"{}"
    return response


class _FakeClient:
    def __init__(
        self,
        *,
        policy: AssessmentPolicy | None = None,
        budget: RequestBudget | None = None,
    ) -> None:
        self.policy = policy
        self.budget = budget
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    @property
    def requests_used(self) -> int:
        return len(self.calls)

    def request(self, method: str, url: str, **kwargs: Any):
        self.calls.append((method, url, kwargs))
        return _response(url), []


class _BlockingAuthorizationPolicy:
    def __init__(self, *, block_on_call: int = 2, raise_on_call: int | None = None):
        self.block_on_call = block_on_call
        self.raise_on_call = raise_on_call
        self.calls = 0
        self.authorization_started = threading.Event()
        self.release_authorization = threading.Event()

    def authorize_url(self, target: str, *, method: str):
        del target, method
        self.calls += 1
        if self.calls == self.raise_on_call:
            raise RuntimeError("synthetic authorization failure")
        if self.calls == self.block_on_call:
            self.authorization_started.set()
            self.release_authorization.wait(timeout=5)
        return SimpleNamespace(allowed=True)


class _BlockingClient(_FakeClient):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.dispatch_started = threading.Event()
        self.release_dispatch = threading.Event()

    def request(self, method: str, url: str, **kwargs: Any):
        self.calls.append((method, url, kwargs))
        self.dispatch_started.set()
        self.release_dispatch.wait(timeout=5)
        return _response(url), []


class _RaisingClient(_FakeClient):
    def request(self, method: str, url: str, **kwargs: Any):
        self.calls.append((method, url, kwargs))
        raise requests.ConnectionError("synthetic client failure")


def _process_scope_probe(
    policy: AssessmentPolicy,
    root: str,
    unrelated: str,
    output: multiprocessing.Queue,
) -> None:
    import tools.scope_guard as child_scope

    child_scope.PENTEST_ALLOWLIST = ""
    child_scope.PENTEST_ALLOWED_URL_PREFIXES = ""
    output.put(
        {
            "implicit": child_scope.enforce_scope(root)["allowed"],
            "missing": child_scope.enforce_scope(root, assessment_policy=None)[
                "allowed"
            ],
            "explicit": child_scope.enforce_scope(root, assessment_policy=policy)[
                "allowed"
            ],
            "unrelated": child_scope.enforce_scope(unrelated, assessment_policy=policy)[
                "allowed"
            ],
        }
    )


def test_manifest_and_policy_validation_fail_closed() -> None:
    assert (
        validate_manifest_authorized_discovery_scope(
            manifest=_manifest(), policy=_policy()
        )
        == _ROOT_A
    )
    missing_values = _manifest().model_dump(exclude={"authorized_target_reference"})
    missing = BenchmarkManifest.model_construct(**missing_values)
    with pytest.raises(DiscoveryScopeHandoffError, match="missing or invalid"):
        validate_manifest_authorized_discovery_scope(
            manifest=missing,
            policy=_policy(),
        )
    ambiguous = _manifest().model_copy(
        update={"authorized_target_reference": f"{_ROOT_A},{_ROOT_B}"}
    )
    with pytest.raises(DiscoveryScopeHandoffError):
        validate_manifest_authorized_discovery_scope(
            manifest=ambiguous,
            policy=_policy(),
        )
    with pytest.raises(DiscoveryScopeHandoffError, match="outside"):
        validate_manifest_authorized_discovery_scope(
            manifest=_manifest(),
            policy=_policy(_ROOT_B),
        )


def test_manifest_root_trailing_slash_is_normalized_without_broadening() -> None:
    trailing_slash = f"{_ROOT_A}/"
    assert (
        validate_manifest_authorized_discovery_scope(
            manifest=_manifest(trailing_slash),
            policy=_policy(trailing_slash),
        )
        == _ROOT_A
    )


def test_ambiguous_policy_fails_closed() -> None:
    second = ScopeAsset(kind="url_prefix", value=_ROOT_B, schemes=["https"])
    with pytest.raises(DiscoveryScopeHandoffError, match="one authorized root"):
        validate_manifest_authorized_discovery_scope(
            manifest=_manifest(),
            policy=_policy(additional_assets=[second]),
        )


def test_metadata_and_object_discovery_use_explicit_policy() -> None:
    policy = _policy()
    metadata_client = _FakeClient(policy=policy)
    object_client = _FakeClient()
    metadata = api_metadata_discovery(
        _ROOT_A,
        max_requests=1,
        http_client=metadata_client,
        assessment_policy=policy,
    )
    objects = crawl_and_discover_ids(
        _ROOT_A,
        max_depth=0,
        max_pages=1,
        delay_seconds=0,
        http_client=object_client,
        assessment_policy=policy,
    )
    assert metadata["success"] is True
    assert metadata["request_count"] == len(metadata_client.calls) == 1
    assert objects["success"] is True
    assert objects["summary"]["pages_visited"] == len(object_client.calls) == 1


@pytest.mark.parametrize(
    "target",
    [
        _ROOT_B,
        "https://research-a.example.test.attacker.invalid",
        f"{_ROOT_A}/application",
    ],
)
def test_explicit_policy_rejects_out_of_scope_before_request(target: str) -> None:
    policy = _policy(f"{_ROOT_A}/app")
    metadata_client = _FakeClient()
    object_client = _FakeClient()
    metadata = api_metadata_discovery(
        target,
        max_requests=1,
        http_client=metadata_client,
        assessment_policy=policy,
    )
    objects = crawl_and_discover_ids(
        target,
        max_depth=0,
        max_pages=1,
        delay_seconds=0,
        http_client=object_client,
        assessment_policy=policy,
    )
    assert metadata["success"] is False
    assert objects["success"] is False
    assert metadata_client.calls == []
    assert object_client.calls == []


def test_prefix_boundary_is_enforced() -> None:
    root = f"{_ROOT_A}/app"
    policy = _policy(root)
    assert scope_guard.enforce_scope(root, assessment_policy=policy)["allowed"]
    assert scope_guard.enforce_scope(f"{root}/objects", assessment_policy=policy)[
        "allowed"
    ]
    assert not scope_guard.enforce_scope(
        f"{_ROOT_A}/application", assessment_policy=policy
    )["allowed"]


def test_explicit_policy_precedes_legacy_and_conflicts_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "research-b.example.test")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")
    policy_a = _policy(_ROOT_A)
    policy_b = _policy(_ROOT_B)
    assert scope_guard.enforce_scope(_ROOT_B)["allowed"]
    assert scope_guard.enforce_scope(_ROOT_A, assessment_policy=policy_a)["allowed"]
    assert not scope_guard.enforce_scope(_ROOT_B, assessment_policy=policy_a)["allowed"]
    assert not scope_guard.enforce_scope(_ROOT_B, assessment_policy=None)["allowed"]
    with scope_guard.assessment_policy_scope(policy_a):
        assert not scope_guard.enforce_scope(_ROOT_B, assessment_policy=policy_b)[
            "allowed"
        ]


def test_legacy_environment_compatibility(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(
        scope_guard,
        "PENTEST_ALLOWED_URL_PREFIXES",
        f"{_ROOT_A}/app",
    )
    assert scope_guard.enforce_scope(f"{_ROOT_A}/app/items")["allowed"]
    assert not scope_guard.enforce_scope(f"{_ROOT_A}/application")["allowed"]
    assert not scope_guard.enforce_scope(_ROOT_B)["allowed"]


def test_discovery_request_permits_preserve_legacy_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", _ROOT_A)
    metadata_client = _FakeClient()
    object_client = _FakeClient()
    metadata = api_metadata_discovery(
        _ROOT_A,
        max_requests=1,
        http_client=metadata_client,
    )
    objects = crawl_and_discover_ids(
        _ROOT_A,
        max_depth=0,
        max_pages=1,
        delay_seconds=0,
        http_client=object_client,
    )
    assert metadata["success"] is True
    assert objects["success"] is True
    assert len(metadata_client.calls) == 1
    assert len(object_client.calls) == 1


def test_overlapping_thread_contexts_are_independent_and_do_not_mutate_env() -> None:
    before = dict(os.environ)
    barrier = threading.Barrier(2)
    a_done = threading.Event()
    results: Queue[tuple[str, bool]] = Queue()

    def research_a() -> None:
        with manifest_authorized_discovery_scope(
            manifest=_manifest(_ROOT_A), policy=_policy(_ROOT_A)
        ):
            barrier.wait()
            results.put(("a_own", scope_guard.enforce_scope(_ROOT_A)["allowed"]))
            results.put(("a_other", scope_guard.enforce_scope(_ROOT_B)["allowed"]))
        a_done.set()

    def research_b() -> None:
        with manifest_authorized_discovery_scope(
            manifest=_manifest(_ROOT_B), policy=_policy(_ROOT_B)
        ):
            barrier.wait()
            results.put(("b_own", scope_guard.enforce_scope(_ROOT_B)["allowed"]))
            results.put(("b_other", scope_guard.enforce_scope(_ROOT_A)["allowed"]))
            assert a_done.wait(timeout=5)
            results.put(("b_after_a", scope_guard.enforce_scope(_ROOT_B)["allowed"]))

    threads = [threading.Thread(target=research_a), threading.Thread(target=research_b)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    observed = dict(results.queue)
    assert observed == {
        "a_own": True,
        "a_other": False,
        "b_own": True,
        "b_other": False,
        "b_after_a": True,
    }
    assert dict(os.environ) == before


def test_concurrent_exception_restores_only_failing_context() -> None:
    barrier = threading.Barrier(2)
    a_failed = threading.Event()
    results: Queue[tuple[str, bool]] = Queue()

    def failing_a() -> None:
        try:
            with manifest_authorized_discovery_scope(
                manifest=_manifest(_ROOT_A), policy=_policy(_ROOT_A)
            ):
                barrier.wait()
                raise RuntimeError("synthetic failure")
        except RuntimeError:
            a_failed.set()

    def surviving_b() -> None:
        with manifest_authorized_discovery_scope(
            manifest=_manifest(_ROOT_B), policy=_policy(_ROOT_B)
        ):
            barrier.wait()
            assert a_failed.wait(timeout=5)
            results.put(("b_survived", scope_guard.enforce_scope(_ROOT_B)["allowed"]))

    threads = [threading.Thread(target=failing_a), threading.Thread(target=surviving_b)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert dict(results.queue) == {"b_survived": True}


def test_nested_contexts_restore_outer_scope() -> None:
    policy_a = _policy(_ROOT_A)
    policy_b = _policy(_ROOT_B)
    with manifest_authorized_discovery_scope(
        manifest=_manifest(_ROOT_A), policy=policy_a
    ):
        assert scope_guard.enforce_scope(_ROOT_A)["allowed"]
        with manifest_authorized_discovery_scope(
            manifest=_manifest(_ROOT_B), policy=policy_b
        ):
            assert scope_guard.enforce_scope(_ROOT_B)["allowed"]
            assert not scope_guard.enforce_scope(_ROOT_A)["allowed"]
        assert scope_guard.enforce_scope(_ROOT_A)["allowed"]
        assert not scope_guard.enforce_scope(_ROOT_B)["allowed"]


def test_async_tasks_keep_independent_contexts() -> None:
    async def run() -> tuple[tuple[bool, bool], tuple[bool, bool]]:
        ready_a = asyncio.Event()
        ready_b = asyncio.Event()

        async def research(
            root: str,
            other: str,
            ready: asyncio.Event,
            peer_ready: asyncio.Event,
        ) -> tuple[bool, bool]:
            with manifest_authorized_discovery_scope(
                manifest=_manifest(root), policy=_policy(root)
            ):
                ready.set()
                await peer_ready.wait()
                await asyncio.sleep(0)
                return (
                    scope_guard.enforce_scope(root)["allowed"],
                    scope_guard.enforce_scope(other)["allowed"],
                )

        return await asyncio.gather(
            research(_ROOT_A, _ROOT_B, ready_a, ready_b),
            research(_ROOT_B, _ROOT_A, ready_b, ready_a),
        )

    assert asyncio.run(run()) == [(True, False), (True, False)]


def test_copied_async_context_is_revoked_after_owner_exit() -> None:
    async def run() -> bool:
        with manifest_authorized_discovery_scope(
            manifest=_manifest(), policy=_policy()
        ):
            copied = copy_context()

        async def probe() -> bool:
            return scope_guard.enforce_scope(_ROOT_A)["allowed"]

        return await asyncio.create_task(probe(), context=copied)

    assert asyncio.run(run()) is False


def test_async_child_created_inside_scope_is_revoked_after_exit() -> None:
    async def run() -> bool:
        started = asyncio.Event()
        release = asyncio.Event()

        async def child() -> bool:
            started.set()
            await release.wait()
            return scope_guard.enforce_scope(_ROOT_A)["allowed"]

        with manifest_authorized_discovery_scope(
            manifest=_manifest(), policy=_policy()
        ):
            task = asyncio.create_task(child())
            await started.wait()
        release.set()
        return await task

    assert asyncio.run(run()) is False


def test_thread_boundary_fails_closed_unless_context_is_propagated() -> None:
    raw_result: Queue[bool] = Queue()
    propagated_result: Queue[bool] = Queue()
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=_policy()):
        raw = threading.Thread(
            target=lambda: raw_result.put(scope_guard.enforce_scope(_ROOT_A)["allowed"])
        )
        explicit_context = copy_context()
        propagated = threading.Thread(
            target=lambda: explicit_context.run(
                lambda: propagated_result.put(
                    scope_guard.enforce_scope(_ROOT_A)["allowed"]
                )
            )
        )
        raw.start()
        propagated.start()
        raw.join(timeout=5)
        propagated.join(timeout=5)
    assert raw_result.get_nowait() is False
    assert propagated_result.get_nowait() is True


def test_copied_thread_context_is_revoked_after_owner_exit() -> None:
    result: Queue[bool] = Queue()
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=_policy()):
        copied = copy_context()

    thread = threading.Thread(
        target=lambda: copied.run(
            lambda: result.put(scope_guard.enforce_scope(_ROOT_A)["allowed"])
        )
    )
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result.get_nowait() is False


def test_revoked_transfer_cannot_reactivate_and_revocation_is_idempotent() -> None:
    policy = _policy()
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=policy):
        transfer = scope_guard.capture_assessment_policy_scope(policy)
    assert transfer is not None
    assert transfer._lease.revoke() is False
    assert transfer._lease.revoke() is False
    with pytest.raises(
        scope_guard.AssessmentScopeAuthorizationError,
        match="expired",
    ):
        with scope_guard.propagated_assessment_policy_scope(transfer):
            pytest.fail("a revoked authorization was reactivated")


def test_nested_scope_leases_have_independent_lifetimes() -> None:
    policy_a = _policy(_ROOT_A)
    policy_b = _policy(_ROOT_B)
    with manifest_authorized_discovery_scope(
        manifest=_manifest(_ROOT_A), policy=policy_a
    ):
        outer = scope_guard.capture_assessment_policy_scope(policy_a)
        with manifest_authorized_discovery_scope(
            manifest=_manifest(_ROOT_B), policy=policy_b
        ):
            inner = scope_guard.capture_assessment_policy_scope(policy_b)
        assert inner is not None
        with pytest.raises(scope_guard.AssessmentScopeAuthorizationError):
            with scope_guard.propagated_assessment_policy_scope(inner):
                pytest.fail("the expired inner scope was reactivated")
        with scope_guard.propagated_assessment_policy_scope(outer):
            assert scope_guard.enforce_scope(_ROOT_A)["allowed"]

    assert outer is not None
    with pytest.raises(scope_guard.AssessmentScopeAuthorizationError):
        with scope_guard.propagated_assessment_policy_scope(outer):
            pytest.fail("the expired outer scope was reactivated")


def test_exception_revokes_only_its_scope_lease() -> None:
    policy = _policy()
    transfer = None
    with pytest.raises(RuntimeError, match="synthetic scope failure"):
        with manifest_authorized_discovery_scope(manifest=_manifest(), policy=policy):
            transfer = scope_guard.capture_assessment_policy_scope(policy)
            raise RuntimeError("synthetic scope failure")
    assert transfer is not None
    with pytest.raises(scope_guard.AssessmentScopeAuthorizationError):
        with scope_guard.propagated_assessment_policy_scope(transfer):
            pytest.fail("the failed scope remained active")


def test_legacy_scope_cannot_override_a_revoked_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "research-b.example.test")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=_policy()):
        copied = copy_context()

    assert copied.run(lambda: scope_guard.enforce_scope(_ROOT_B)["allowed"]) is False
    assert scope_guard.enforce_scope(_ROOT_B)["allowed"] is True


def test_process_boundary_requires_explicit_policy_transfer() -> None:
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_process_scope_probe,
        args=(_policy(_ROOT_A), _ROOT_A, _ROOT_B, output),
    )
    process.start()
    process.join(timeout=10)
    assert not process.is_alive()
    assert process.exitcode == 0
    assert output.get(timeout=2) == {
        "implicit": False,
        "missing": False,
        "explicit": True,
        "unrelated": False,
    }


@pytest.mark.parametrize(
    ("tool_name", "kwargs"),
    [
        ("api_metadata_discovery", {"max_requests": 1}),
        (
            "api_object_discovery",
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_tool_runner_injects_policy_into_worker_thread(
    tool_name: str,
    kwargs: dict[str, Any],
) -> None:
    policy = _policy()
    budget = RequestBudget(8, per_host_limit=8)
    client = _FakeClient(policy=policy, budget=budget)
    runner = ToolRunner(
        policy=policy,
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=policy):
        result = runner._execute(
            tool_name,
            (_ROOT_A,),
            kwargs,
            {"target": _ROOT_A},
        )
    assert result["status"] == "completed"
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    ("tool_name", "kwargs"),
    [
        ("api_metadata_discovery", {"max_requests": 1}),
        (
            "api_object_discovery",
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_tool_runner_rejects_cross_context_policy_before_dispatch(
    tool_name: str,
    kwargs: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_executor(*args: Any, **kwargs: Any) -> None:
        pytest.fail("cross-context authorization reached worker dispatch")

    monkeypatch.setattr(
        tool_runner_module.concurrent.futures,
        "ThreadPoolExecutor",
        unexpected_executor,
    )
    policy_a = _policy(_ROOT_A)
    policy_b = _policy(_ROOT_B)
    budget = RequestBudget(8, per_host_limit=8)
    client = _FakeClient(policy=policy_b, budget=budget)
    runner = ToolRunner(
        policy=policy_b,
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    with manifest_authorized_discovery_scope(
        manifest=_manifest(_ROOT_A), policy=policy_a
    ):
        result = runner._execute(
            tool_name,
            (_ROOT_B,),
            kwargs,
            {"target": _ROOT_B},
        )
    assert result["status"] == "failed"
    assert "conflicts with the active research scope" in result["error"]
    assert client.calls == []


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    [
        (api_metadata_discovery, {"max_requests": 1}),
        (
            crawl_and_discover_ids,
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_discovery_tools_reject_stale_context_before_dispatch(
    tool: Any,
    kwargs: dict[str, Any],
) -> None:
    policy = _policy()
    client = _FakeClient()
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=policy):
        copied = copy_context()
    result = copied.run(
        lambda: tool(
            _ROOT_A,
            http_client=client,
            assessment_policy=policy,
            **kwargs,
        )
    )
    assert result["success"] is False
    assert client.calls == []


def test_worker_revalidates_scope_revoked_after_scheduling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduled = threading.Event()
    release = threading.Event()

    class _DelayedExecutor:
        def __init__(self, max_workers: int) -> None:
            assert max_workers == 1

        def submit(self, function: Any):
            future: tool_runner_module.concurrent.futures.Future[Any] = (
                tool_runner_module.concurrent.futures.Future()
            )

            def delayed() -> None:
                scheduled.set()
                release.wait(timeout=5)
                try:
                    future.set_result(function())
                except BaseException as exc:
                    future.set_exception(exc)

            threading.Thread(target=delayed).start()
            return future

        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
            assert wait is False
            assert cancel_futures is True

    monkeypatch.setattr(
        tool_runner_module.concurrent.futures,
        "ThreadPoolExecutor",
        _DelayedExecutor,
    )
    policy = _policy()
    budget = RequestBudget(8, per_host_limit=8)
    client = _FakeClient(policy=policy, budget=budget)
    runner = ToolRunner(
        policy=policy,
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    result: Queue[dict[str, Any]] = Queue()
    with manifest_authorized_discovery_scope(manifest=_manifest(), policy=policy):
        caller = copy_context()
        dispatch = threading.Thread(
            target=lambda: caller.run(
                lambda: result.put(
                    runner._execute(
                        "api_metadata_discovery",
                        (_ROOT_A,),
                        {"max_requests": 1},
                        {"target": _ROOT_A},
                    )
                )
            )
        )
        dispatch.start()
        assert scheduled.wait(timeout=5)
    release.set()
    dispatch.join(timeout=5)
    assert not dispatch.is_alive()
    assert result.get_nowait()["status"] == "failed"
    assert client.calls == []


@pytest.mark.parametrize(
    ("tool_name", "kwargs"),
    [
        ("api_metadata_discovery", {"max_requests": 1}),
        (
            "api_object_discovery",
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_revocation_during_final_policy_authorization_prevents_dispatch(
    tool_name: str,
    kwargs: dict[str, Any],
) -> None:
    policy = _BlockingAuthorizationPolicy()
    budget = RequestBudget(8, per_host_limit=8)
    client = _FakeClient(policy=policy, budget=budget)  # type: ignore[arg-type]
    runner = ToolRunner(
        policy=policy,  # type: ignore[arg-type]
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    result: Queue[dict[str, Any]] = Queue()
    with scope_guard.assessment_policy_scope(policy):
        caller = copy_context()
        dispatch = threading.Thread(
            target=lambda: caller.run(
                lambda: result.put(
                    runner._execute(
                        tool_name,
                        (_ROOT_A,),
                        kwargs,
                        {"target": _ROOT_A},
                    )
                )
            )
        )
        dispatch.start()
        assert policy.authorization_started.wait(timeout=5)
    policy.release_authorization.set()
    dispatch.join(timeout=5)
    assert not dispatch.is_alive()
    assert result.get_nowait()["status"] == "completed"
    assert client.calls == []


def test_admitted_request_completes_before_revocation_returns() -> None:
    policy = _policy()
    client = _FakeClient()
    admitted = threading.Event()
    release_dispatch = threading.Event()
    request_finished = threading.Event()
    revocation_finished = threading.Event()
    with scope_guard.assessment_policy_scope(policy):
        transfer = scope_guard.capture_assessment_policy_scope(policy)
        assert transfer is not None
        caller = copy_context()

        def dispatch() -> None:
            def invoke() -> None:
                with scope_guard.request_dispatch_permit(
                    _ROOT_A,
                    assessment_policy=policy,
                ):
                    admitted.set()
                    release_dispatch.wait(timeout=5)
                    client.request("GET", _ROOT_A)
                request_finished.set()

            caller.run(invoke)

        request_thread = threading.Thread(target=dispatch)
        request_thread.start()
        assert admitted.wait(timeout=5)
        revoker = threading.Thread(
            target=lambda: (
                transfer._lease.revoke(),
                revocation_finished.set(),
            )
        )
        revoker.start()
        assert not revocation_finished.wait(timeout=0.05)
        release_dispatch.set()
        request_thread.join(timeout=5)
        revoker.join(timeout=5)
        assert not request_thread.is_alive()
        assert not revoker.is_alive()
        assert request_finished.is_set()
        assert revocation_finished.is_set()
    assert len(client.calls) == 1


def test_revocation_completed_before_permit_admission_fails_closed() -> None:
    policy = _policy()
    with scope_guard.assessment_policy_scope(policy):
        copied = copy_context()

    def admit() -> None:
        with scope_guard.request_dispatch_permit(
            _ROOT_A,
            assessment_policy=policy,
        ):
            pytest.fail("a revoked lease acquired a request permit")

    with pytest.raises(scope_guard.RequestPermitDenied, match="expired"):
        copied.run(admit)


@pytest.mark.parametrize(
    ("tool_name", "kwargs"),
    [
        ("api_metadata_discovery", {"max_requests": 1}),
        (
            "api_object_discovery",
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_authorization_exception_prevents_discovery_dispatch(
    tool_name: str,
    kwargs: dict[str, Any],
) -> None:
    policy = _BlockingAuthorizationPolicy(block_on_call=99, raise_on_call=2)
    budget = RequestBudget(8, per_host_limit=8)
    client = _FakeClient(policy=policy, budget=budget)  # type: ignore[arg-type]
    runner = ToolRunner(
        policy=policy,  # type: ignore[arg-type]
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    with scope_guard.assessment_policy_scope(policy):
        result = runner._execute(
            tool_name,
            (_ROOT_A,),
            kwargs,
            {"target": _ROOT_A},
        )
    assert result["status"] == "completed"
    assert client.calls == []


@pytest.mark.parametrize(
    ("tool_name", "kwargs"),
    [
        ("api_metadata_discovery", {"max_requests": 1}),
        (
            "api_object_discovery",
            {"max_depth": 0, "max_pages": 1, "delay_seconds": 0},
        ),
    ],
)
def test_client_exception_releases_request_permit(
    tool_name: str,
    kwargs: dict[str, Any],
) -> None:
    policy = _policy()
    budget = RequestBudget(8, per_host_limit=8)
    client = _RaisingClient(policy=policy, budget=budget)
    runner = ToolRunner(
        policy=policy,
        request_budget=budget,
        http_client=client,  # type: ignore[arg-type]
        tool_timeout=5,
    )
    with scope_guard.assessment_policy_scope(policy):
        transfer = scope_guard.capture_assessment_policy_scope(policy)
        assert transfer is not None
        result = runner._execute(
            tool_name,
            (_ROOT_A,),
            kwargs,
            {"target": _ROOT_A},
        )
        assert transfer._lease.revoke() is True
    assert result["status"] == "completed"
    assert len(client.calls) == 1


def test_nested_request_permits_release_without_deadlock() -> None:
    policy = _policy()
    with scope_guard.assessment_policy_scope(policy):
        with scope_guard.request_dispatch_permit(
            _ROOT_A,
            assessment_policy=policy,
        ):
            with scope_guard.request_dispatch_permit(
                f"{_ROOT_A}/nested",
                assessment_policy=policy,
            ):
                assert scope_guard.enforce_scope(_ROOT_A)["allowed"]


def test_concurrent_independent_request_permits_do_not_block_each_other() -> None:
    barrier = threading.Barrier(2)
    clients = {_ROOT_A: _FakeClient(), _ROOT_B: _FakeClient()}

    def research(root: str) -> None:
        policy = _policy(root)
        with scope_guard.assessment_policy_scope(policy):
            with scope_guard.request_dispatch_permit(
                root,
                assessment_policy=policy,
            ):
                barrier.wait(timeout=5)
                clients[root].request("GET", root)

    threads = [
        threading.Thread(target=research, args=(_ROOT_A,)),
        threading.Thread(target=research, args=(_ROOT_B,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(clients[_ROOT_A].calls) == 1
    assert len(clients[_ROOT_B].calls) == 1


def test_async_cancellation_during_authorization_cannot_dispatch() -> None:
    async def run() -> int:
        policy = _BlockingAuthorizationPolicy()
        budget = RequestBudget(8, per_host_limit=8)
        client = _FakeClient(policy=policy, budget=budget)  # type: ignore[arg-type]
        runner = ToolRunner(
            policy=policy,  # type: ignore[arg-type]
            request_budget=budget,
            http_client=client,  # type: ignore[arg-type]
            tool_timeout=5,
        )
        worker_finished = threading.Event()

        def invoke() -> None:
            try:
                runner._execute(
                    "api_metadata_discovery",
                    (_ROOT_A,),
                    {"max_requests": 1},
                    {"target": _ROOT_A},
                )
            finally:
                worker_finished.set()

        with scope_guard.assessment_policy_scope(policy):
            task = asyncio.create_task(asyncio.to_thread(invoke))
            assert await asyncio.to_thread(policy.authorization_started.wait, 5)
            task.cancel()
        policy.release_authorization.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(worker_finished.wait, 5)
        return len(client.calls)

    assert asyncio.run(run()) == 0


def test_thread_exception_releases_request_permit() -> None:
    policy = _policy()
    finished = threading.Event()
    with scope_guard.assessment_policy_scope(policy):
        transfer = scope_guard.capture_assessment_policy_scope(policy)
        assert transfer is not None
        caller = copy_context()

        def terminate() -> None:
            try:
                with scope_guard.request_dispatch_permit(
                    _ROOT_A,
                    assessment_policy=policy,
                ):
                    raise SystemExit("synthetic thread termination")
            except SystemExit:
                finished.set()

        thread = threading.Thread(target=lambda: caller.run(terminate))
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert finished.is_set()
        assert transfer._lease.revoke() is True


def test_repeated_activation_is_idempotent_and_never_mutates_environment() -> None:
    before = dict(os.environ)
    manifest = _manifest()
    policy = _policy()
    for _ in range(2):
        with manifest_authorized_discovery_scope(manifest=manifest, policy=policy):
            assert scope_guard.enforce_scope(_ROOT_A)["allowed"]
            assert dict(os.environ) == before
        assert dict(os.environ) == before


def test_scope_module_contains_no_benchmark_discovery_hints() -> None:
    source = (
        Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("agent_core", "benchmark", "discovery_scope.py")
        .read_text(encoding="utf-8")
    )
    forbidden = (
        "graphql endpoint",
        "graphql operation",
        "object identifier",
        "hypothesis",
        "vulnerability",
        "expected answer",
    )
    assert all(value not in source.lower() for value in forbidden)
