from __future__ import annotations

import inspect
import threading
from types import SimpleNamespace
from typing import Any

import pytest
import requests

import agent_core.workflow_manager as workflow_module
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.tool_runner import ToolRunner
from tool_registry import TOOLS, resolve_tool
from tools.safe_http import PolicyViolationError, ScopedHTTPClient

TARGET = "https://allowed.example/app"


def _policy(
    *,
    authorization_confirmed: bool = True,
    schemes: list[str] | None = None,
    ports: list[int] | None = None,
    methods: list[str] | None = None,
    excluded: bool = False,
    request_budget: int = 10,
    per_host_budget: int = 10,
    max_concurrency: int = 2,
    requests_per_second: float = 100,
    oast_allowed: bool = False,
) -> AssessmentPolicy:
    asset = ScopeAsset(
        kind="exact_host",
        value="allowed.example",
        schemes=schemes or ["https"],
        ports=ports or [443],
    )
    return AssessmentPolicy(
        program_name="phase2-network-policy-test",
        authorization_reference="test-authorization",
        authorization_confirmed=authorization_confirmed,
        allowed_assets=[asset],
        excluded_assets=[asset] if excluded else [],
        allowed_methods=methods or ["GET", "HEAD", "OPTIONS"],
        request_budget=request_budget,
        per_host_request_budget=per_host_budget,
        requests_per_second=requests_per_second,
        max_concurrency=max_concurrency,
        credentials_allowed=True,
        controlled_account_ids=["alice"],
        oast_allowed=oast_allowed,
        allowed_capabilities=["oast"] if oast_allowed else [],
        callback_hosts=["callback.example"] if oast_allowed else [],
        resolve_dns_before_request=False,
    )


def _response(url: str = TARGET) -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response.headers["Content-Type"] = "application/json"
    response._content = b"{}"
    response._content_consumed = True
    return response


def _client(
    policy: AssessmentPolicy,
    ledger: RequestBudget,
    calls: list[tuple[str, str]],
) -> ScopedHTTPClient:
    def requester(method: str, url: str, **_kwargs: Any) -> requests.Response:
        calls.append((method, url))
        return _response(url)

    return ScopedHTTPClient(policy=policy, budget=ledger, requester=requester)


def test_workflow_creates_selected_policy_and_same_ledger_before_discovery(
    monkeypatch, tmp_path
):
    policy = _policy()
    observed: dict[str, Any] = {}

    class TestClient(ScopedHTTPClient):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(
                **kwargs,
                requester=lambda method, url, **request_kwargs: _response(url),
            )

    class FakeRunner:
        def __init__(self, **kwargs: Any) -> None:
            observed["runner_policy"] = kwargs["policy"]
            observed["runner_budget"] = kwargs["request_budget"]
            observed["client"] = kwargs["http_client"]

        def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
            client = observed["client"]
            assert client.policy is policy
            assert client.budget is observed["runner_budget"]
            client.request("GET", target, purpose="discovery")
            return {
                "success": True,
                "target": target,
                "profile": kwargs["profile"],
                "assessment_status": "completed",
                "coverage": {"coverage_percentage": 100, "failed_tools": []},
                "completed_steps": [],
                "results": {"ai_report_writer": {"output": {}}},
                "evidence_package": {
                    "assessment": {},
                    "execution_summary": {
                        "completed": [],
                        "completed_with_fallback": [],
                        "timed_out_partial": [],
                        "timed_out": [],
                        "failed": [],
                        "skipped": [],
                    },
                    "observations": [],
                    "candidate_findings": [],
                    "manual_verification_queue": [],
                    "verified_findings": [],
                },
            }

    class FakeOrchestrator:
        def initial_surface_plan(self, **_kwargs: Any):
            return SimpleNamespace(
                selected_tools=["http_probe"],
                model_dump=lambda mode: {"selected_tools": ["http_probe"]},
            )

        def ingest_scan_result(self, *_args: Any) -> dict[str, Any]:
            return {}

        def run_phase2(self, surface, selected_policy, **kwargs: Any):
            observed["phase2_budget"] = kwargs["request_budget"]
            assert selected_policy is policy
            return {
                "run_id": "network-policy-run",
                "target": surface.target,
                "assessment_mode": "observe",
                "mode": "observe",
                "attack_surface": surface.model_dump(mode="json"),
                "hypotheses": [],
                "verification_plans": [],
                "verification_results": [],
                "metrics": kwargs["request_budget"].snapshot(),
            }

    monkeypatch.setattr(workflow_module, "ScopedHTTPClient", TestClient)
    monkeypatch.setattr(workflow_module, "ToolRunner", FakeRunner)
    monkeypatch.setattr(
        workflow_module, "AdaptiveAssessmentOrchestrator", FakeOrchestrator
    )
    monkeypatch.setattr(
        workflow_module,
        "record_assessment",
        lambda *args, **kwargs: {"success": True, "assessment_count": 1},
    )

    result = workflow_module.run_workflow(
        "authorized observe assessment",
        TARGET,
        "allowed.example",
        phase2_policy=policy,
        phase2_store=Phase2RunStore(tmp_path / "runs"),
    )

    assert observed["runner_policy"] is policy
    assert observed["runner_budget"] is observed["phase2_budget"]
    assert observed["phase2_budget"].snapshot()["discovery_requests"] == 1
    assert result["phase2"]["metrics"]["discovery_requests"] == 1


@pytest.mark.parametrize(
    ("policy", "method", "url", "reason"),
    [
        (_policy(authorization_confirmed=False), "GET", TARGET, "authorization"),
        (_policy(), "GET", "https://outside.example/app", "authorized asset"),
        (_policy(), "GET", "http://allowed.example/app", "authorized asset"),
        (_policy(), "GET", "https://allowed.example:444/app", "authorized asset"),
        (_policy(), "POST", TARGET, "HTTP method POST is not allowed"),
        (_policy(excluded=True), "GET", TARGET, "scope exclusion"),
    ],
)
def test_policy_denials_never_reach_transport(policy, method, url, reason):
    calls: list[tuple[str, str]] = []
    ledger = RequestBudget(10, per_host_limit=10)
    client = _client(policy, ledger, calls)

    with pytest.raises(PolicyViolationError, match=reason):
        client.request(method, url, purpose="discovery")

    assert calls == []
    assert ledger.total == 0


def test_global_budget_blocks_next_request_before_transport():
    policy = _policy(request_budget=1)
    ledger = RequestBudget(1, per_host_limit=10)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)

    client.request("GET", TARGET, purpose="discovery")
    with pytest.raises(PolicyViolationError, match="Global request budget exhausted"):
        client.request("GET", TARGET, purpose="verification")

    assert len(calls) == 1
    assert ledger.total == 1


def test_per_host_budget_blocks_next_request_before_transport():
    policy = _policy(request_budget=3, per_host_budget=1)
    ledger = RequestBudget(3, per_host_limit=1)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)

    client.request("GET", TARGET, purpose="discovery")
    with pytest.raises(PolicyViolationError, match="Per-host request budget exhausted"):
        client.request("GET", TARGET, purpose="verification")

    assert len(calls) == 1
    assert ledger.total == 1
    assert ledger.host_total("allowed.example") == 1


def test_failed_transport_attempt_consumes_ledger_once_and_is_not_retried():
    policy = _policy()
    ledger = RequestBudget(3, per_host_limit=3)
    calls = 0

    def fail(method: str, url: str, **kwargs: Any):
        nonlocal calls
        calls += 1
        raise requests.ConnectionError("synthetic transport failure")

    client = ScopedHTTPClient(policy=policy, budget=ledger, requester=fail)
    with pytest.raises(requests.ConnectionError):
        client.request("GET", TARGET, purpose="discovery")

    assert calls == 1
    assert ledger.snapshot()["discovery_requests"] == 1
    assert client.requests_used == 1


def test_discovery_auth_and_verification_share_one_authoritative_ledger():
    policy = _policy(methods=["GET", "POST"], request_budget=3)
    ledger = RequestBudget(3, per_host_limit=3)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)
    gate = DeterministicPolicyGate(
        policy,
        Phase2PolicyContext(
            mode="verify",
            target_class="local_range",
            controlled_account_ids=["alice"],
        ),
        ledger,
    )

    client.request("GET", TARGET, purpose="discovery")
    client.request(
        "POST",
        "https://allowed.example/sessions",
        purpose="session_acquisition",
        request_context={
            "purpose": "session_acquisition",
            "policy_authorized": True,
            "configured_url": "https://allowed.example/sessions",
            "configured_method": "POST",
            "configured_endpoint_match": True,
            "controlled_account_id": "alice",
            "account_controlled": True,
            "account_policy_authorized": True,
        },
    )
    client.request("GET", TARGET, purpose="verification")

    assert client.budget is ledger
    assert gate.budget is ledger
    assert ledger.snapshot() == {
        "discovery_requests": 1,
        "auth_requests": 1,
        "verification_requests": 1,
        "cleanup_requests": 0,
        "total_requests": 3,
        "request_limit": 3,
        "remaining_requests": 0,
    }


def test_discovery_reduces_budget_available_to_verification():
    policy = _policy(request_budget=1)
    ledger = RequestBudget(1, per_host_limit=1)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)

    client.request("GET", TARGET, purpose="discovery")
    with pytest.raises(PolicyViolationError, match="Global request budget exhausted"):
        client.request("GET", TARGET, purpose="verification")

    assert ledger.snapshot()["verification_requests"] == 0
    assert len(calls) == 1


def test_max_concurrency_one_blocks_overlapping_transport():
    policy = _policy(max_concurrency=1)
    ledger = RequestBudget(3, per_host_limit=3)
    entered = threading.Event()
    release = threading.Event()
    active = 0
    max_active = 0
    errors: list[BaseException] = []

    def requester(method: str, url: str, **kwargs: Any) -> requests.Response:
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        entered.set()
        release.wait(timeout=2)
        active -= 1
        return _response(url)

    client = ScopedHTTPClient(policy=policy, budget=ledger, requester=requester)

    def first_request() -> None:
        try:
            client.request("GET", TARGET, purpose="discovery")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=first_request)
    thread.start()
    assert entered.wait(timeout=2)
    with pytest.raises(PolicyViolationError, match="Concurrency limit reached"):
        client.request("GET", TARGET, purpose="discovery")
    release.set()
    thread.join(timeout=2)

    assert errors == []
    assert not thread.is_alive()
    assert max_active == 1
    assert ledger.total == 1


def test_policy_rate_limiter_applies_to_discovery(monkeypatch):
    policy = _policy(requests_per_second=2)
    ledger = RequestBudget(2, per_host_limit=2)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)
    clock = [1.0]
    sleeps: list[float] = []

    monkeypatch.setattr("tools.safe_http.time.monotonic", lambda: clock[0])

    def advance(delay: float) -> None:
        sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr("tools.safe_http.time.sleep", advance)
    client._last_request_at = clock[0]
    client.request("GET", TARGET, purpose="discovery")

    assert sleeps == [pytest.approx(0.5)]
    assert ledger.snapshot()["discovery_requests"] == 1


def test_oast_disabled_blocks_before_transport_and_ledger():
    policy = _policy(oast_allowed=False)
    ledger = RequestBudget(2, per_host_limit=2)
    calls: list[tuple[str, str]] = []
    client = _client(policy, ledger, calls)

    with pytest.raises(PolicyViolationError, match="OAST is disabled"):
        client.request(
            "GET",
            TARGET,
            purpose="oast",
            techniques=["oast"],
            oast_callback_url="https://callback.example/correlation",
        )

    assert calls == []
    assert ledger.total == 0


def test_registered_network_tools_are_adapted_or_fail_closed():
    adapted = {
        "dns_lookup",
        "http_probe",
        "security_headers_checker",
        "tech_fingerprint",
        "api_metadata_discovery",
        "js_secret_scanner",
        "api_object_discovery",
    }
    for name, metadata in TOOLS.items():
        if not metadata["sends_network_traffic"]:
            continue
        adapter = metadata["network_adapter"]
        assert adapter in {
            "shared_http",
            "shared_dns",
            "offline_fallback",
            "fail_closed",
        }
        if name == "ai_report_writer":
            assert adapter == "offline_fallback"
            assert (
                "allow_network_analysis"
                in inspect.signature(resolve_tool(name)).parameters
            )
            continue
        if name in adapted:
            assert adapter in {"shared_http", "shared_dns"}
            assert "http_client" in inspect.signature(resolve_tool(name)).parameters
        else:
            assert adapter == "fail_closed"


def test_fail_closed_registered_network_tool_is_not_invoked():
    policy = _policy()
    ledger = RequestBudget(2, per_host_limit=2)
    client = _client(policy, ledger, [])
    runner = ToolRunner(policy=policy, request_budget=ledger, http_client=client)

    result = runner._execute(
        "katana_crawl",
        (TARGET,),
        {},
        {"target": TARGET},
    )

    assert result["status"] == "skipped"
    assert "no shared policy-aware transport adapter" in result["error"]
    assert ledger.total == 0
