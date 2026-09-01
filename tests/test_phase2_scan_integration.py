from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

import agent
import agent_core.phase2_store as phase2_store_module
import agent_core.workflow_manager as workflow_module
from agent_core.phase2_store import Phase2RunStore
from agent_core.workflow_manager import run_workflow
from tools.openapi_surface_analyzer import openapi_surface_analyzer


def _synthetic_evidence() -> dict[str, Any]:
    analyzed = openapi_surface_analyzer(
        {
            "openapi": "3.0.3",
            "paths": {
                "/orders/{order_id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "order_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/tenants/{tenant_id}/projects": {
                    "get": {
                        "parameters": [
                            {
                                "name": "tenant_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/admin/audit": {"get": {"responses": {"200": {"description": "ok"}}}},
                "/users/me": {
                    "patch": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "role": {"type": "string"},
                                            "tenant_id": {"type": "string"},
                                            "credit_limit": {"type": "number"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "ok"}},
                    }
                },
            },
        },
        source_url="https://authorized.example/openapi.json",
    )
    assert analyzed["success"] is True
    execution = {
        "completed": ["openapi_surface_analyzer"],
        "completed_with_fallback": ["ai_report_writer"],
        "timed_out_partial": [],
        "timed_out": [],
        "failed": [],
        "skipped": [],
        "not_applicable": [],
    }
    return {
        "assessment": {
            "requested_target": "https://authorized.example",
            "profile": "baseline",
        },
        "observed_surface": {
            "http": {
                "reachable": True,
                "root_status": 404,
                "content_type": "application/json",
            },
            "attack_surface": {
                "routes": analyzed["routes"],
                "parameters": analyzed["parameters"],
                "objects": analyzed["objects"],
                "authentication_boundaries": analyzed["authentication_boundaries"],
                "sources": {"openapi": {"documents": 1, "routes": 4}},
            },
        },
        "execution_summary": execution,
        "observations": [],
        "candidate_findings": [],
        "manual_verification_queue": [],
        "verified_findings": [],
    }


class _SyntheticRunner:
    seen_mode: str | None = None
    report_path: str | None = None

    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        self.__class__.seen_mode = kwargs.get("assessment_mode")
        return {
            "success": True,
            "assessment_status": "completed_with_limitations",
            "coverage": {"coverage_percentage": 100, "failed_tools": []},
            "target": target,
            "profile": kwargs.get("profile", "baseline"),
            "assessment_mode": kwargs.get("assessment_mode"),
            "completed_steps": ["openapi_surface_analyzer"],
            "results": {
                "ai_report_writer": {
                    "status": "completed_with_fallback",
                    "output": {
                        "ai_status": "failed",
                        "report_mode": "deterministic_fallback",
                        "report_file": self.__class__.report_path,
                    },
                }
            },
            "evidence_package": _synthetic_evidence(),
        }


@pytest.fixture
def synthetic_workflow(monkeypatch, tmp_path):
    _SyntheticRunner.report_path = None
    monkeypatch.setattr(workflow_module, "ToolRunner", _SyntheticRunner)
    monkeypatch.setattr(
        workflow_module,
        "record_assessment",
        lambda *args, **kwargs: {"success": True, "assessment_count": 1},
    )
    return Phase2RunStore(tmp_path / "phase2")


def _run(mode: str, store: Phase2RunStore, **kwargs: Any) -> dict[str, Any]:
    return run_workflow(
        f"authorized {mode} assessment",
        "https://authorized.example",
        "authorized.example",
        assessment_mode=mode,
        phase2_store=store,
        **kwargs,
    )


def test_plan_scan_invokes_phase2_after_normalized_evidence(synthetic_workflow):
    result = _run("plan", synthetic_workflow)

    assert _SyntheticRunner.seen_mode == "plan"
    assert result["assessment_mode"] == "plan"
    assert result["evidence_package"]["assessment"]["assessment_mode"] == "plan"
    phase2 = result["phase2"]
    assert phase2["assessment_mode"] == "plan"
    assert {item["path"] for item in phase2["attack_surface"]["routes"]} >= {
        "/orders/{order_id}",
        "/tenants/{tenant_id}/projects",
        "/admin/audit",
        "/users/me",
    }
    assert {item["name"] for item in phase2["attack_surface"]["parameters"]} >= {
        "order_id",
        "tenant_id",
        "role",
        "credit_limit",
    }
    assert {item["type"] for item in phase2["attack_surface"]["objects"]} >= {
        "order",
        "tenant",
    }
    categories = {item["category"] for item in phase2["hypotheses"]}
    assert {
        "bola",
        "tenant_isolation",
        "vertical_authorization",
        "mass_assignment",
    } <= categories
    assert len(phase2["verification_plans"]) >= 4
    assert all(
        item["automatic_execution_allowed"] is False
        for item in phase2["verification_plans"]
    )
    assert all(item["status"] == "proposed" for item in phase2["hypotheses"])
    assert phase2["verification_results"] == []
    assert phase2["metrics"]["verification_requests"] == 0
    assert synthetic_workflow.load()["run_id"] == phase2["run_id"]
    report_path = result["phase2_artifacts"]["report"]
    report = synthetic_workflow.directory.joinpath(
        report_path.split("/")[-1]
    ).read_text(encoding="utf-8")
    assert "## Attack Surface" in report
    assert "## Security Hypotheses" in report
    assert "## Planned Verification" in report
    assert "Automatic execution: false" in report
    assert "No evidence-backed verified findings" in report


def test_bola_plan_and_rendered_view_require_test_owned_resource(
    synthetic_workflow, monkeypatch, capsys
):
    phase2 = _run("plan", synthetic_workflow)["phase2"]
    bola = next(item for item in phase2["hypotheses"] if item["category"] == "bola")
    plan = next(
        item
        for item in phase2["verification_plans"]
        if item["hypothesis_id"] == bola["hypothesis_id"]
    )

    assert (
        "researcher-controlled object with confirmed ownership" in plan["prerequisites"]
    )
    assert plan["test_owned_resources_required"] is True

    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", {"phase2": phase2})
    result = agent.process_user_input(f"verification plan {bola['hypothesis_id']}")
    assert result["verification_plan"]["test_owned_resources_required"] is True

    agent.print_result(result)
    assert "Test-owned resources required: True" in capsys.readouterr().out


def test_phase2_commands_read_the_latest_scan_state(
    synthetic_workflow, monkeypatch, capsys
):
    phase2 = _run("plan", synthetic_workflow)["phase2"]
    hypothesis_id = phase2["hypotheses"][0]["hypothesis_id"]
    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", {"phase2": phase2})
    monkeypatch.setattr(
        phase2_store_module, "Phase2RunStore", lambda: synthetic_workflow
    )

    listed = agent.process_user_input("hypotheses")
    explained = agent.process_user_input(f"hypothesis explain {hypothesis_id}")
    planned = agent.process_user_input(f"verification plan {hypothesis_id}")

    assert any(item["id"] == hypothesis_id for item in listed["hypotheses"])
    assert explained["hypothesis"]["hypothesis_id"] == hypothesis_id
    assert planned["verification_plan"]["hypothesis_id"] == hypothesis_id

    capsys.readouterr()
    for result in (listed, explained, planned):
        agent.print_result(result)
    output = capsys.readouterr().out

    for label in (
        "ID:",
        "Category:",
        "Priority:",
        "Score:",
        "Confidence:",
        "Status:",
        "Affected route/functionality:",
        "Evidence basis:",
        "Hypothesis ID:",
        "Title:",
        "Target surface:",
        "Impact if confirmed:",
        "Required context:",
        "Safe verification possible:",
        "Current status:",
        "Limitations:",
        "Priority rationale:",
        "Objective:",
        "Prerequisites:",
        "Controlled accounts required:",
        "Test-owned resources required:",
        "Minimal requests:",
        "Expected secure behavior:",
        "Expected vulnerable behavior:",
        "Evidence to compare:",
        "Stop conditions:",
        "Cleanup:",
        "Max requests:",
        "Side-effect risk:",
        "Automatic execution allowed:",
    ):
        assert label in output


def test_phase2_commands_use_in_session_plan_state_when_store_is_missing(
    synthetic_workflow, monkeypatch
):
    phase2 = _run("plan", synthetic_workflow)["phase2"]
    hypothesis_id = phase2["hypotheses"][0]["hypothesis_id"]
    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", {"phase2": phase2})

    class MissingStore:
        def load(self):
            raise FileNotFoundError

    monkeypatch.setattr(phase2_store_module, "Phase2RunStore", MissingStore)

    assert agent.process_user_input("hypotheses")["success"] is True
    assert (
        agent.process_user_input(f"hypothesis explain {hypothesis_id}")["success"]
        is True
    )
    assert (
        agent.process_user_input(f"verification plan {hypothesis_id}")["success"]
        is True
    )


def test_phase2_commands_report_when_no_state_is_loaded(monkeypatch, capsys):
    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", None)

    class MissingStore:
        def load(self):
            raise FileNotFoundError

    monkeypatch.setattr(phase2_store_module, "Phase2RunStore", MissingStore)

    result = agent.process_user_input("hypotheses")
    assert result == {
        "success": False,
        "error": "No Phase 2 assessment state is loaded. Run a plan or verify scan first.",
    }

    agent.print_result(result)
    output = capsys.readouterr().out
    assert "Success: False" in output
    assert result["error"] in output


@pytest.mark.parametrize(
    "command", ("hypothesis explain missing-id", "verification plan missing-id")
)
def test_phase2_commands_reject_unknown_hypothesis_id(
    synthetic_workflow, monkeypatch, command
):
    phase2 = _run("plan", synthetic_workflow)["phase2"]
    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", {"phase2": phase2})

    result = agent.process_user_input(command)

    assert result["success"] is False
    assert "hypothesis not found" in result["error"].lower()


def test_phase2_command_views_do_not_render_secrets_or_tokens(
    synthetic_workflow, monkeypatch, capsys
):
    phase2 = deepcopy(_run("plan", synthetic_workflow)["phase2"])
    hypothesis = phase2["hypotheses"][0]
    hypothesis_id = hypothesis["hypothesis_id"]
    hypothesis["metadata"]["api_token"] = "PHASE2_API_TOKEN_SECRET"
    hypothesis["target_surface"][
        "url"
    ] = "https://authorized.example/orders?access_token=URL_TOKEN_SECRET"
    hypothesis["evidence_basis"].append(
        {"token": "EVIDENCE_TOKEN_SECRET", "source": "controlled"}
    )
    hypothesis["evidence_basis"].append(
        {"observation": "Observed Authorization: Bearer INLINE_TOKEN_SECRET"}
    )
    plan = next(
        item
        for item in phase2["verification_plans"]
        if item["hypothesis_id"] == hypothesis_id
    )
    plan["controlled_accounts"] = ["CONTROLLED_ACCOUNT_TOKEN_SECRET"]
    plan["test_owned_resources"] = ["TEST_RESOURCE_SECRET"]
    plan["prerequisites"].append("token=PREREQUISITE_TOKEN_SECRET")
    plan["steps"][0]["metadata"]["requests"][0][
        "authorization"
    ] = "Bearer REQUEST_TOKEN_SECRET"
    monkeypatch.setattr(agent, "LATEST_SCAN_RESULT", {"phase2": phase2})

    for command in (
        "hypotheses",
        f"hypothesis explain {hypothesis_id}",
        f"verification plan {hypothesis_id}",
    ):
        agent.print_result(agent.process_user_input(command))
    output = capsys.readouterr().out

    for secret in (
        "PHASE2_API_TOKEN_SECRET",
        "URL_TOKEN_SECRET",
        "EVIDENCE_TOKEN_SECRET",
        "INLINE_TOKEN_SECRET",
        "CONTROLLED_ACCOUNT_TOKEN_SECRET",
        "TEST_RESOURCE_SECRET",
        "PREREQUISITE_TOKEN_SECRET",
        "REQUEST_TOKEN_SECRET",
    ):
        assert secret not in output


def test_plan_sections_are_integrated_into_fallback_report(
    synthetic_workflow, tmp_path
):
    primary_report = tmp_path / "assessment.md"
    primary_report.write_text(
        "# Assessment\n\n## Verified Findings\n\nNo verified findings were recorded.\n",
        encoding="utf-8",
    )
    _SyntheticRunner.report_path = str(primary_report)

    _run("plan", synthetic_workflow)

    report = primary_report.read_text(encoding="utf-8")
    assert "<!-- CYBERCORTEX PHASE 2 -->" in report
    assert "## Attack Surface" in report
    assert "## Security Hypotheses" in report
    assert "## Planned Verification" in report
    assert "No evidence-backed verified findings were recorded." in report


def test_observe_builds_surface_without_active_verification(synthetic_workflow):
    phase2 = _run("observe", synthetic_workflow)["phase2"]
    assert phase2["attack_surface"]["routes"]
    assert phase2["verification_plans"] == []
    assert phase2["verification_results"] == []
    assert phase2["metrics"]["verification_requests"] == 0


def test_verify_requires_policy_preflight_before_execution(synthetic_workflow):
    calls = []

    def executor(*args: Any) -> dict[str, Any]:
        calls.append(args)
        return {"status": "verified", "requests_used": 1}

    phase2 = _run("verify", synthetic_workflow, phase2_executor=executor)["phase2"]
    assert phase2["verification_plans"]
    assert all(
        item["policy_decision"] in {"allowed", "blocked"}
        for item in phase2["verification_plans"]
    )
    assert all(
        item["automatic_execution_allowed"] is False
        for item in phase2["verification_plans"]
    )
    assert phase2["verification_results"] == []
    assert calls == []


def test_cli_scan_preserves_plan_mode_in_workflow_request(monkeypatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(agent, "enforce_scope", lambda target: {"allowed": True})

    def fake_workflow(goal: str, target: str, domain: str, **kwargs: Any):
        captured.update({"goal": goal, "target": target, "domain": domain, **kwargs})
        return {
            "success": True,
            "target": target,
            "assessment_mode": kwargs["assessment_mode"],
            "results": {},
            "evidence_package": {"assessment": {"assessment_mode": "plan"}},
        }

    monkeypatch.setattr(agent, "run_workflow", fake_workflow)
    result = agent.run_scan_command("https://authorized.example --mode plan")

    assert result["success"] is True
    assert captured["assessment_mode"] == "plan"
    assert "plan-mode" in captured["goal"]
