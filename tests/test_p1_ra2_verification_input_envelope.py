from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

import pytest

import agent
import agent_core.phase2_store as store_module
import agent_core.verification_runtime as runtime_module
import phase2_cli
from agent_core.agent_models import Hypothesis, VerificationPlan, VerificationStep
from agent_core.controlled_context import ControlledContext
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate
from agent_core.phase2_result_status import INVALID_INPUT_REASON
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    CapabilityState,
    plan_only_command_metadata,
)
from agent_core.verification_runtime import (
    build_verification_policy_context,
    create_verification_runtime,
)
from tools.safe_http import ScopedHTTPClient

TARGET = "https://p1-ra2.example/api"
SENTINEL = "CCX_RA2_MALFORMED_SECRET_001"
ZERO_DELTA = {
    "discovery": 0,
    "auth": 0,
    "verification": 0,
    "cleanup": 0,
    "attempted": 0,
    "total": 0,
}

MALFORMED_ENVELOPES = (
    pytest.param("scalar-root", id="root-scalar"),
    pytest.param([], id="root-list"),
    pytest.param(None, id="root-null"),
    pytest.param({"defaults": []}, id="defaults-list"),
    pytest.param({"defaults": 7}, id="defaults-scalar"),
    pytest.param({"defaults": "not-an-object"}, id="defaults-string"),
    pytest.param({"defaults": None}, id="defaults-null"),
    pytest.param({"hypotheses": []}, id="hypotheses-list"),
    pytest.param({"hypotheses": 7}, id="hypotheses-scalar"),
    pytest.param({"hypotheses": "not-an-object"}, id="hypotheses-string"),
    pytest.param(
        {"defaults": {"safe": True}, "hypotheses": {"hyp-bola": []}},
        id="selected-entry-list",
    ),
    pytest.param(
        {"defaults": {"safe": True}, "hypotheses": {"hyp-bola": 7}},
        id="selected-entry-scalar",
    ),
    pytest.param(
        {
            "defaults": {"safe": True},
            "hypotheses": {"hyp-bola": "not-an-object"},
        },
        id="selected-entry-string",
    ),
    pytest.param(
        {"defaults": {"safe": True}, "hypotheses": {"hyp-bola": None}},
        id="selected-entry-null",
    ),
    pytest.param(
        {"hypotheses": {"hyp-other": []}},
        id="unselected-entry-list",
    ),
    pytest.param(
        {"defaults": {}, "unexpected": {"nested": True}},
        id="unknown-structured-root-member",
    ),
    pytest.param({1: {}}, id="non-string-root-key"),
    pytest.param({"x" * 201: {}}, id="unbounded-root-key"),
    pytest.param(
        {"defaults": {f"field-{index}": index for index in range(201)}},
        id="unbounded-defaults-map",
    ),
    pytest.param(
        {"hypotheses": {"x" * 201: {}}},
        id="unbounded-hypothesis-key",
    ),
    pytest.param(
        {"hypotheses": {"hyp-bola": {f"field-{index}": index for index in range(201)}}},
        id="unbounded-selected-map",
    ),
)


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="p1-ra2-input-boundary",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        credentials_allowed=True,
        allow_state_changes=True,
        request_budget=20,
        per_host_request_budget=20,
        requests_per_second=100,
        resolve_dns_before_request=False,
    )


def _hypothesis_and_plan(
    category: str = "bola",
) -> tuple[Hypothesis, VerificationPlan]:
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-{category}",
        category=category,
        title=f"{category} input boundary",
        rationale="Structured input must be validated before typed traffic.",
        target=TARGET,
        endpoint=TARGET,
        method="GET",
        parameter="q" if category == "sql_injection" else None,
        parameter_location="query" if category == "sql_injection" else None,
        safe_verification_possible=True,
    )
    plan = VerificationPlan(
        plan_id=f"plan-{category}",
        hypothesis_id=hypothesis.hypothesis_id,
        target=TARGET,
        profile="baseline",
        steps=[
            VerificationStep(
                step_id=f"step-{category}",
                name="Strict verification input boundary",
                tool="controlled_verification_executor",
                network=False,
                request_cost=0,
                metadata={"requests": []},
            )
        ],
        request_budget=20,
        authorization_confirmed=True,
        automatic_execution_allowed=True,
    )
    return hypothesis, plan


def _runtime_pair(
    tmp_path: Path,
    verification_inputs: Any,
    requester: Any,
) -> tuple[Any, Any, DeterministicPolicyGate, CredentialVault, CredentialVault]:
    policy = _policy()
    context = ControlledContext()
    vault_a = CredentialVault()
    vault_b = CredentialVault()
    budget_a = RequestBudget(20, per_host_limit=20)
    budget_b = RequestBudget(20, per_host_limit=20)
    client_a = ScopedHTTPClient(policy=policy, budget=budget_a, requester=requester)
    client_b = ScopedHTTPClient(policy=policy, budget=budget_b, requester=requester)
    standalone = create_verification_runtime(
        policy=policy,
        controlled_context=context,
        vault=vault_a,
        verification_inputs=deepcopy(verification_inputs),
        target=TARGET,
        target_class="dedicated_lab",
        store=Phase2RunStore(tmp_path / "standalone"),
        budget=budget_a,
        network_client=client_a,
    )
    scan = create_verification_runtime(
        policy=policy,
        controlled_context=context,
        vault=vault_b,
        verification_inputs=deepcopy(verification_inputs),
        target=TARGET,
        target_class="dedicated_lab",
        store=Phase2RunStore(tmp_path / "scan"),
        budget=budget_b,
        network_client=client_b,
    )
    gate = DeterministicPolicyGate(
        policy,
        build_verification_policy_context(
            context,
            target_class="dedicated_lab",
        ),
        budget_b,
    )
    return standalone, scan, gate, vault_a, vault_b


@pytest.mark.parametrize("verification_inputs", MALFORMED_ENVELOPES)
def test_every_malformed_envelope_is_the_same_zero_traffic_policy_block(
    verification_inputs: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network_calls: list[str] = []
    executor_constructions: list[str] = []

    def forbidden_request(*_args: Any, **_kwargs: Any) -> Any:
        network_calls.append("called")
        raise AssertionError("Malformed envelope reached transport.")

    class ForbiddenExecutor:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            executor_constructions.append("constructed")
            raise AssertionError("Malformed envelope constructed a typed executor.")

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        lambda _category: ForbiddenExecutor,
    )
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path,
        verification_inputs,
        forbidden_request,
    )
    hypothesis, plan = _hypothesis_and_plan()
    try:
        standalone_result = standalone.execute_selected(hypothesis, plan)
        scan_result = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert standalone_result["status"] == scan_result["status"] == "policy_blocked"
    assert (
        standalone_result["reasons"] == scan_result["reasons"] == [INVALID_INPUT_REASON]
    )
    assert standalone_result["request_delta"] == scan_result["request_delta"]
    assert standalone_result["request_delta"] == ZERO_DELTA
    assert standalone_result["requests_used"] == scan_result["requests_used"] == 0
    assert executor_constructions == []
    assert network_calls == []
    assert "error" not in standalone_result
    assert "error" not in scan_result


def test_unknown_nested_category_member_is_rejected_before_traffic(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    def forbidden_request(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("called")
        raise AssertionError("Unknown category input reached transport.")

    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path,
        {"defaults": {"unknown_nested": {"secret": SENTINEL}}},
        forbidden_request,
    )
    hypothesis, plan = _hypothesis_and_plan("sql_injection")
    try:
        standalone_result = standalone.execute_selected(hypothesis, plan)
        scan_result = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert standalone_result["status"] == scan_result["status"] == "policy_blocked"
    assert standalone_result["request_delta"] == scan_result["request_delta"]
    assert standalone_result["request_delta"] == ZERO_DELTA
    assert calls == []
    assert SENTINEL not in json.dumps(standalone_result, sort_keys=True)
    assert SENTINEL not in json.dumps(scan_result, sort_keys=True)


@pytest.mark.parametrize(
    ("verification_inputs", "expected"),
    (
        ({"defaults": {"source": "default"}}, {"source": "default"}),
        (
            {"hypotheses": {"hyp-bola": {"source": "selected"}}},
            {"source": "selected"},
        ),
        (
            {
                "defaults": {"source": "default", "shared": True},
                "hypotheses": {"hyp-bola": {"source": "selected"}},
            },
            {"source": "selected", "shared": True},
        ),
        ({"source": "direct", "shared": True}, {"source": "direct", "shared": True}),
    ),
)
def test_valid_envelope_selection_and_direct_compatibility_remain_shared(
    verification_inputs: dict[str, Any],
    expected: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[dict[str, Any]] = []

    class RecordingExecutor:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def execute(
            self,
            _hypothesis: Hypothesis,
            _plan: VerificationPlan,
            *,
            inputs: dict[str, Any],
            **_kwargs: Any,
        ) -> dict[str, Any]:
            observed.append(deepcopy(inputs))
            return {
                "status": "inconclusive",
                "reasons": ["Deterministic selection fixture."],
                "request_delta": dict(ZERO_DELTA),
                "requests_used": 0,
            }

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        lambda _category: RecordingExecutor,
    )
    standalone, scan, gate, vault_a, vault_b = _runtime_pair(
        tmp_path,
        verification_inputs,
        lambda *_args, **_kwargs: None,
    )
    hypothesis, plan = _hypothesis_and_plan()
    try:
        standalone_result = standalone.execute_selected(hypothesis, plan)
        scan_result = scan(hypothesis, plan, gate)
    finally:
        vault_a.close()
        vault_b.close()

    assert observed == [expected, expected]
    assert standalone_result["status"] == scan_result["status"] == "inconclusive"
    assert standalone_result["request_delta"] == scan_result["request_delta"]


def _write_public_command_files(
    tmp_path: Path,
    verification_inputs: Any,
) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.json"
    context_path = tmp_path / "context.json"
    input_path = tmp_path / "verification-input.json"
    policy_path.write_text(
        json.dumps(_policy().model_dump(mode="json")),
        encoding="utf-8",
    )
    context_path.write_text("{}", encoding="utf-8")
    input_path.write_text(json.dumps(verification_inputs), encoding="utf-8")
    return policy_path, context_path, input_path


def _stored_run(hypothesis: Hypothesis, plan: VerificationPlan) -> dict[str, Any]:
    return {
        "run_id": "run-p1-ra2-public-parity",
        "target": TARGET,
        "assessment_mode": "verify",
        "hypotheses": [hypothesis.model_dump(mode="json")],
        "verification_plans": [plan.model_dump(mode="json")],
        "verification_results": [],
        "metrics": {"total_requests": 0},
    }


def test_phase2_cli_and_agent_scan_share_invalid_status_reason_delta_and_secrecy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = {"defaults": [SENTINEL]}
    policy_path, context_path, input_path = _write_public_command_files(
        tmp_path,
        malformed,
    )
    hypothesis, plan = _hypothesis_and_plan()
    standalone_store = Phase2RunStore(tmp_path / "standalone-public")
    standalone_store.save(_stored_run(hypothesis, plan))
    scan_store = Phase2RunStore(tmp_path / "scan-public")
    network_calls: list[str] = []

    def forbidden_request(*_args: Any, **_kwargs: Any) -> Any:
        network_calls.append("called")
        raise AssertionError("Malformed public input reached transport.")

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: standalone_store)
    monkeypatch.setattr(ScopedHTTPClient, "request", forbidden_request)
    standalone_result = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(policy_path),
            "--context",
            str(context_path),
            "--input",
            str(input_path),
            "--dedicated-lab",
        ]
    )

    def run_shared_runtime(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        runtime = kwargs["phase2_executor"]
        assert runtime is not None
        return runtime.execute_selected(hypothesis, plan)

    monkeypatch.setattr(agent, "enforce_scope", lambda _target: {"allowed": True})
    monkeypatch.setattr(agent, "run_workflow", run_shared_runtime)
    monkeypatch.setattr(store_module, "Phase2RunStore", lambda: scan_store)
    scan_result = agent.run_scan_command(
        " ".join(
            (
                TARGET,
                "--mode verify",
                "--dedicated-lab",
                f"--policy {policy_path}",
                f"--verification-input {input_path}",
            )
        )
    )

    assert standalone_result["status"] == scan_result["status"] == "policy_blocked"
    assert (
        standalone_result["reasons"] == scan_result["reasons"] == [INVALID_INPUT_REASON]
    )
    assert standalone_result["request_delta"] == scan_result["request_delta"]
    assert standalone_result["request_delta"] == ZERO_DELTA
    assert standalone_result["requests_used"] == scan_result["requests_used"] == 0
    assert standalone_result["executor"]["name"] == "ControlledVerificationExecutor"
    assert network_calls == []
    for result in (standalone_result, scan_result):
        rendered = json.dumps(result, sort_keys=True)
        assert SENTINEL not in rendered
        assert "Workflow error" not in rendered
        assert "command failed" not in rendered.casefold()


def test_plan_only_preflight_precedes_malformed_typed_input_interpretation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    category = next(
        category
        for category, capability in CAPABILITY_REGISTRY.items()
        if capability.capability_state is CapabilityState.plan_only
    )
    hypothesis, plan = _hypothesis_and_plan(category)
    executor_calls: list[str] = []

    def forbidden_executor(_category: str) -> type[Any]:
        executor_calls.append("resolved")
        raise AssertionError("Plan-only input resolved a typed executor.")

    monkeypatch.setattr(
        runtime_module,
        "resolve_verification_executor",
        forbidden_executor,
    )
    vault = CredentialVault()
    runtime = create_verification_runtime(
        policy=_policy(),
        controlled_context=ControlledContext(),
        vault=vault,
        verification_inputs={"defaults": [SENTINEL]},
        target=TARGET,
        target_class="dedicated_lab",
        store=Phase2RunStore(tmp_path / "plan-only"),
        defer_transport=True,
    )
    try:
        result = runtime.execute_selected(hypothesis, plan)
    finally:
        vault.close()

    assert result == plan_only_command_metadata(category, hypothesis.hypothesis_id)
    assert result["verification_result_created"] is False
    assert result["requests_used"] == 0
    assert executor_calls == []
    assert "status" not in result
    assert "request_delta" not in result
    assert "executor" not in result
    assert "result_id" not in result
    assert "result_hash" not in result
    assert SENTINEL not in json.dumps(result, sort_keys=True)
