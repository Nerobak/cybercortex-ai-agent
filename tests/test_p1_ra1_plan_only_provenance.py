from __future__ import annotations

from copy import deepcopy
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

import phase2_cli
import agent_core.adaptive_orchestrator as adaptive_module
import agent_core.phase2_store as store_module
import agent_core.verification_runtime as runtime_module
from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.agent_models import Hypothesis, VerificationPlan, VerificationStep
from agent_core.attack_surface import AttackSurfaceGraph, CanonicalAttackSurface
from agent_core.audit_log import TamperEvidentAuditLog
from agent_core.benchmark_exporter import build_benchmark_export
from agent_core.controlled_context import ControlledContext
from agent_core.phase2_campaign import build_campaign_export
from agent_core.phase2_result_status import PUBLIC_RESULT_STATUSES
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.result_provenance import (
    RESULT_HASH_PATTERN,
    RESULT_ID_PATTERN,
    RESULT_SCHEMA_VERSION,
    controlled_executor_provenance,
    result_content_hash,
)
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    PLAN_ONLY_VERIFICATION_REASON,
    CapabilityState,
    plan_only_command_metadata,
    resolve_verification_input_schema,
    typed_producer_provenance,
)
from tools.safe_http import ScopedHTTPClient

TARGET = "https://plan-only.example/api"
PLAN_ONLY_CATEGORIES = tuple(
    sorted(
        category
        for category, capability in CAPABILITY_REGISTRY.items()
        if capability.capability_state is CapabilityState.plan_only
    )
)
TYPED_CATEGORIES = tuple(
    sorted(
        category
        for category, capability in CAPABILITY_REGISTRY.items()
        if capability.capability_state is CapabilityState.typed_verification
    )
)


def _policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="p1-ra1-plan-only",
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST", "PATCH", "DELETE"],
        credentials_allowed=True,
        allow_state_changes=True,
        request_budget=10,
        per_host_request_budget=10,
        requests_per_second=100,
        resolve_dns_before_request=False,
    )


def _hypothesis_and_plan(category: str) -> tuple[Hypothesis, VerificationPlan]:
    capability = CAPABILITY_REGISTRY[category]
    hypothesis = Hypothesis(
        hypothesis_id=f"hyp-{category}",
        category=category,
        title=f"{category} capability boundary",
        rationale="The registry decides whether typed verification is available.",
        target=TARGET,
        endpoint=TARGET,
        method="GET",
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
                name="Registry capability boundary",
                tool="manual" if not capability.executor_available else "typed",
                network=False,
                request_cost=0,
            )
        ],
        request_budget=10,
        capability_state=capability.capability_state.value,
        typed_executor_available=capability.executor_available,
        executor_name=capability.executor_name,
        executor_version=capability.executor_version,
        automatic_execution_allowed=capability.automatic_execution,
    )
    return hypothesis, plan


def _write_command_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    policy_path = tmp_path / "policy.json"
    context_path = tmp_path / "context.json"
    input_path = tmp_path / "input.json"
    policy_path.write_text(
        json.dumps(_policy().model_dump(mode="json")), encoding="utf-8"
    )
    context_path.write_text("{}", encoding="utf-8")
    input_path.write_text("{}", encoding="utf-8")
    return policy_path, context_path, input_path


def _run(
    run_id: str,
    hypothesis: Hypothesis,
    *,
    results: list[dict[str, Any]] | None = None,
    plan: VerificationPlan | None = None,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "target": TARGET,
        "assessment_mode": "verify",
        "hypotheses": [hypothesis.model_dump(mode="json")],
        "verification_plans": (
            [plan.model_dump(mode="json")] if plan is not None else []
        ),
        "verification_results": results or [],
        "metrics": {"total_requests": 0},
    }


def _typed_result(category: str, hypothesis_id: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hypothesis_id,
        "category": category,
        "status": "inconclusive",
        "confidence": "low",
        "reasons": ["Deterministic typed persistence fixture."],
        "requests_used": 0,
        "request_delta": {
            "discovery": 0,
            "auth": 0,
            "verification": 0,
            "cleanup": 0,
            "attempted": 0,
            "total": 0,
        },
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "executor": typed_producer_provenance(category),
    }


def _fabricated_producer(category: str) -> dict[str, str]:
    return {
        "name": "ControlledVerificationExecutor",
        "version": f"{category}/v1",
        "implementation_family": "phase2_controlled_execution",
    }


@pytest.mark.parametrize("category", PLAN_ONLY_CATEGORIES)
def test_each_plan_only_standalone_command_creates_no_typed_result_or_export_reference(
    category: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hypothesis, plan = _hypothesis_and_plan(category)
    store = Phase2RunStore(tmp_path / "runs")
    run = _run(f"run-{category}", hypothesis, plan=plan)
    base_path = Path(store.save(run))
    base_before = base_path.read_bytes()
    latest_before = store.latest_path.read_bytes()
    policy_path, context_path, input_path = _write_command_files(tmp_path)
    network_calls: list[str] = []

    def forbidden_request(*_args: Any, **_kwargs: Any) -> Any:
        network_calls.append("called")
        raise AssertionError("Plan-only command reached transport.")

    def forbidden_executor(_category: str) -> type[Any]:
        raise AssertionError("Plan-only command resolved a typed executor.")

    monkeypatch.setattr(phase2_cli, "Phase2RunStore", lambda: store)
    monkeypatch.setattr(ScopedHTTPClient, "request", forbidden_request)
    monkeypatch.setattr(
        runtime_module, "resolve_verification_executor", forbidden_executor
    )

    output = phase2_cli.run_verification_command(
        [
            hypothesis.hypothesis_id,
            "--policy",
            str(policy_path),
            "--context",
            str(context_path),
            "--input",
            str(input_path),
        ]
    )

    assert output == plan_only_command_metadata(category, hypothesis.hypothesis_id)
    assert output["requests_used"] == 0
    assert output["reasons"] == [PLAN_ONLY_VERIFICATION_REASON]
    assert network_calls == []
    assert "status" not in output
    assert "request_delta" not in output
    assert "result_id" not in output
    assert "result_hash" not in output
    assert "executor" not in output
    assert base_path.read_bytes() == base_before
    assert store.latest_path.read_bytes() == latest_before
    stored = store.load_run(run["run_id"])
    assert stored["verification_results"] == []
    assert not store.revision_path(run["run_id"], 2).exists()

    campaign = {
        "campaign_id": f"campaign-{category}",
        "name": f"campaign-{category}",
        "target": stored["target"],
        "target_fingerprint": stored["target_fingerprint"],
        "created_at": "2026-08-31T00:00:00+00:00",
        "updated_at": "2026-08-31T00:00:00+00:00",
        "run_ids": [stored["run_id"]],
    }
    campaign_finding = build_campaign_export(campaign, [stored])["findings"][0]
    benchmark_finding = build_benchmark_export(stored)["findings"][0]
    assert campaign_finding.get("verification_result_reference") is None
    assert benchmark_finding.get("verification_result_reference") is None
    assert "executor" not in campaign_finding
    assert "executor" not in benchmark_finding


def test_agent_scan_preflight_matches_standalone_plan_only_semantics_for_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected: list[Hypothesis] = []
    monkeypatch.setattr(
        adaptive_module,
        "generate_surface_hypotheses",
        lambda _surface: list(selected),
    )
    monkeypatch.setattr(
        adaptive_module,
        "rank_hypotheses",
        lambda hypotheses, **_kwargs: hypotheses,
    )

    class ForbiddenScanExecutor:
        defers_runtime_policy_authorization = True

        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            self.calls += 1
            raise AssertionError("Scan invoked a typed executor for plan-only work.")

    for index, category in enumerate(PLAN_ONLY_CATEGORIES):
        hypothesis, _plan = _hypothesis_and_plan(category)
        selected[:] = [hypothesis]
        executor = ForbiddenScanExecutor()
        orchestrator = AdaptiveAssessmentOrchestrator(
            graph=AttackSurfaceGraph(tmp_path / f"surface-{index}.db"),
            audit_log=TamperEvidentAuditLog(tmp_path / f"audit-{index}.jsonl"),
        )
        result = orchestrator.run_phase2(
            CanonicalAttackSurface(target=TARGET),
            _policy(),
            mode="verify",
            target_class="external",
            controlled_context=ControlledContext(),
            executor=executor,
            run_id=f"scan-{category}",
        )
        expected = plan_only_command_metadata(category, hypothesis.hypothesis_id)
        plan = result["verification_plans"][0]

        assert executor.calls == 0
        assert result["verification_results"] == []
        assert result["metrics"]["verification_requests"] == 0
        assert result["metrics"]["verifications_attempted"] == 0
        assert plan["capability_state"] == expected["capability_state"]
        assert plan["policy_reasons"] == expected["reasons"]
        assert plan["automatic_execution_allowed"] is False
        assert result["hypotheses"][0]["status"] == "proposed"


@pytest.mark.parametrize(
    "case",
    (
        "plan_only",
        "unknown",
        "wrong_executor_name",
        "wrong_executor_version",
        "missing_producer",
        "wrong_schema_version",
        "hypothesis_category_mismatch",
    ),
)
def test_store_rejects_untrusted_new_typed_producer_claims(
    case: str, tmp_path: Path
) -> None:
    hypothesis, _plan = _hypothesis_and_plan("bola")
    result = _typed_result("bola", hypothesis.hypothesis_id)
    if case == "plan_only":
        hypothesis, _plan = _hypothesis_and_plan(PLAN_ONLY_CATEGORIES[0])
        result = {
            **result,
            "hypothesis_id": hypothesis.hypothesis_id,
            "category": hypothesis.category,
            "executor": _fabricated_producer(hypothesis.category),
        }
    elif case == "unknown":
        hypothesis.category = "fabricated_unknown_category"
        result = {
            **result,
            "category": hypothesis.category,
            "executor": _fabricated_producer(hypothesis.category),
        }
    elif case == "wrong_executor_name":
        result["executor"] = {
            **result["executor"],
            "name": "FabricatedVerificationExecutor",
        }
    elif case == "wrong_executor_version":
        result["executor"] = {
            **result["executor"],
            "version": typed_producer_provenance("tenant_isolation")["version"],
        }
    elif case == "missing_producer":
        result.pop("executor")
    elif case == "wrong_schema_version":
        result["result_schema_version"] = RESULT_SCHEMA_VERSION + 1
    elif case == "hypothesis_category_mismatch":
        hypothesis.category = "tenant_isolation"

    store = Phase2RunStore(tmp_path / "runs")
    with pytest.raises(ValueError):
        store.save(_run(f"rejected-{case}", hypothesis, results=[result]))

    assert not store.run_path(f"rejected-{case}").exists()
    assert not store.latest_path.exists()


def test_rejected_fake_append_preserves_immutable_history_and_latest(
    tmp_path: Path,
) -> None:
    hypothesis, _plan = _hypothesis_and_plan("bola")
    legitimate = _typed_result("bola", hypothesis.hypothesis_id)
    store = Phase2RunStore(tmp_path / "runs")
    run = _run("immutable-before-fake", hypothesis, results=[legitimate])
    base_path = Path(store.save(run))
    base_before = base_path.read_bytes()
    latest_before = store.latest_path.read_bytes()
    original = deepcopy(store.load_run(run["run_id"])["verification_results"])
    run["verification_results"].append(
        {
            **legitimate,
            "hypothesis_id": "hyp-fabricated-plan-only",
            "category": PLAN_ONLY_CATEGORIES[0],
            "executor": _fabricated_producer(PLAN_ONLY_CATEGORIES[0]),
        }
    )

    with pytest.raises(ValueError, match="no typed verification route"):
        store.save(run)

    assert base_path.read_bytes() == base_before
    assert store.latest_path.read_bytes() == latest_before
    assert store.load_run(run["run_id"])["verification_results"] == original
    assert not store.revision_path(run["run_id"], 2).exists()


@pytest.mark.parametrize("category", TYPED_CATEGORIES)
def test_each_typed_category_persists_exact_registry_provenance(
    category: str, tmp_path: Path
) -> None:
    hypothesis, _plan = _hypothesis_and_plan(category)
    result = _typed_result(category, hypothesis.hypothesis_id)
    store = Phase2RunStore(tmp_path / "runs")
    run = _run(f"typed-{category}", hypothesis, results=[result])

    store.save(run)

    stored = run["verification_results"][0]
    capability = CAPABILITY_REGISTRY[category]
    schema = resolve_verification_input_schema(category)
    assert schema is not None
    assert schema.model_config.get("extra") == "forbid"
    assert stored["executor"] == typed_producer_provenance(category)
    assert stored["executor"]["name"] == capability.executor_name
    assert stored["executor"]["version"] == capability.executor_version
    assert stored["result_schema_version"] == RESULT_SCHEMA_VERSION
    assert RESULT_ID_PATTERN.fullmatch(stored["result_id"])
    assert RESULT_HASH_PATTERN.fullmatch(stored["result_hash"])
    assert stored["result_hash"] == result_content_hash(stored)
    assert stored["request_delta"] == result["request_delta"]


def test_plan_only_is_not_a_terminal_result_and_generic_producer_is_registry_gated() -> (
    None
):
    assert CapabilityState.plan_only.value not in PUBLIC_RESULT_STATUSES
    for category in PLAN_ONLY_CATEGORIES:
        with pytest.raises(ValueError, match="no typed verification route"):
            controlled_executor_provenance(category)
    with pytest.raises(ValueError, match="Unknown Phase 2 category"):
        controlled_executor_provenance("fabricated_unknown_category")
    for category in TYPED_CATEGORIES:
        assert controlled_executor_provenance(category) == typed_producer_provenance(
            category
        )


def test_active_store_and_runtime_have_no_category_only_producer_fallback() -> None:
    store_source = inspect.getsource(store_module.Phase2RunStore._prepare_new_result)
    runtime_source = inspect.getsource(
        runtime_module.VerificationRuntime.execute_selected
    )

    assert 'setdefault("executor"' not in store_source
    assert "controlled_executor_provenance" not in store_source
    assert "validate_typed_producer_provenance" in store_source
    assert "resolve_verification_executor" in runtime_source
    assert "typed_producer_provenance" in runtime_source
