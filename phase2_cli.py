"""Command-line interface for CyberCortex Phase 2 stored runs."""

from __future__ import annotations

import argparse
import json
import shlex
from pathlib import Path
from typing import Any

from agent_core.agent_models import Hypothesis, VerificationPlan
from agent_core.benchmark_exporter import export_benchmark
from agent_core.controlled_context import load_controlled_context
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_campaign import Phase2CampaignStore
from agent_core.phase2_result_status import PUBLIC_RESULT_STATUSES
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import load_policy
from agent_core.request_budget import RequestDelta
from agent_core.result_normalizer import public_result
from agent_core.verification_runtime import (
    canonical_target_class,
    create_verification_runtime,
)

NO_PHASE2_STATE_MESSAGE = (
    "No Phase 2 assessment state is loaded. Run a plan or verify scan first."
)


def _read_json(path: str) -> Any:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return payload


def _parse_verification_options(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="verification run")
    parser.add_argument("hypothesis_id")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--input", required=True)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--lab", action="store_true")
    target.add_argument("--dedicated-lab", action="store_true")
    return parser.parse_args(argv)


def run_verification_command(argv: list[str]) -> dict[str, Any]:
    args = _parse_verification_options(argv)
    store = Phase2RunStore()
    run = store.load()
    raw_hypothesis = next(
        (
            item
            for item in run.get("hypotheses", [])
            if item.get("hypothesis_id") == args.hypothesis_id
        ),
        None,
    )
    raw_plan = next(
        (
            item
            for item in run.get("verification_plans", [])
            if item.get("hypothesis_id") == args.hypothesis_id
        ),
        None,
    )
    if raw_hypothesis is None or raw_plan is None:
        raise ValueError("The latest run does not contain that hypothesis and plan.")
    hypothesis = Hypothesis.model_validate(raw_hypothesis)
    plan = VerificationPlan.model_validate(raw_plan)
    policy = load_policy(args.policy)
    inputs = _read_json(args.input)
    target_class = canonical_target_class(
        lab=args.lab, dedicated_lab=args.dedicated_lab
    )
    vault = CredentialVault()
    try:
        controlled = load_controlled_context(args.context, vault)
        runtime = create_verification_runtime(
            policy=policy,
            controlled_context=controlled,
            vault=vault,
            verification_inputs=inputs,
            target=str(run.get("target") or plan.target),
            target_class=target_class,
            store=store,
            parent_run=run,
        )
        output = runtime.execute_selected(
            hypothesis,
            plan,
            run_id=str(run.get("run_id") or plan.plan_id),
        )
        if output.get("verification_result_created") is False:
            return public_result(output)
        for item in run.get("hypotheses", []):
            if (
                item.get("hypothesis_id") == args.hypothesis_id
                and output.get("status") in PUBLIC_RESULT_STATUSES
            ):
                item["status"] = output["status"]
        stored_output = {
            "hypothesis_id": hypothesis.hypothesis_id,
            "category": hypothesis.category,
            **output,
        }
        run.setdefault("verification_results", []).append(stored_output)
        metrics = run.setdefault("metrics", {})
        raw_request_delta = output.get("request_delta")
        if raw_request_delta is None and output.get("requests_used") == 0:
            # Compatibility for a no-traffic legacy/injected result. Non-zero
            # traffic without a typed delta is intentionally not accepted.
            request_delta = RequestDelta()
            output["request_delta"] = request_delta.model_dump(mode="json")
            stored_output["request_delta"] = output["request_delta"]
        else:
            request_delta = RequestDelta.model_validate(raw_request_delta)
        metrics["auth_requests"] = (
            int(metrics.get("auth_requests") or 0) + request_delta.auth
        )
        metrics["discovery_requests"] = (
            int(metrics.get("discovery_requests") or 0) + request_delta.discovery
        )
        metrics["verification_requests"] = (
            int(metrics.get("verification_requests") or 0) + request_delta.verification
        )
        metrics["cleanup_requests"] = (
            int(metrics.get("cleanup_requests") or 0) + request_delta.cleanup
        )
        acquisition = output.get("owned_object_acquisition") or {}
        metrics["object_acquisition_requests"] = int(
            metrics.get("object_acquisition_requests") or 0
        ) + int(bool(acquisition.get("attempted")))
        metrics["request_count"] = (
            int(metrics.get("request_count") or 0) + request_delta.total
        )
        metrics["total_requests"] = (
            int(metrics.get("total_requests") or 0) + request_delta.total
        )
        metrics["hypotheses_verified"] = sum(
            item.get("status") == "verified"
            for item in run.get("verification_results", [])
        )
        metrics["hypotheses_rejected"] = sum(
            item.get("status") == "rejected"
            for item in run.get("verification_results", [])
        )
        store.save(run)
        persisted_result = run["verification_results"][-1]
        return public_result({"success": True, **persisted_result})
    finally:
        vault.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberCortex Phase 2 CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument(
        "--mode", choices=("observe", "plan", "verify"), default="observe"
    )
    scan.add_argument("--profile", default="baseline")
    scan.add_argument("--policy")
    scan.add_argument("--context")
    scan.add_argument("--verification-input")
    scan_target = scan.add_mutually_exclusive_group()
    scan_target.add_argument("--lab", action="store_true")
    scan_target.add_argument("--dedicated-lab", action="store_true")
    scan.add_argument("--campaign")
    commands.add_parser("hypotheses")
    hypothesis = commands.add_parser("hypothesis")
    hypothesis.add_argument("action", choices=("explain",))
    hypothesis.add_argument("hypothesis_id")
    verification = commands.add_parser("verification")
    verification.add_argument("action", choices=("plan", "run"))
    verification.add_argument("remaining", nargs=argparse.REMAINDER)
    benchmark = commands.add_parser("benchmark")
    benchmark.add_argument("action", choices=("export",))
    benchmark.add_argument("path")
    campaign = commands.add_parser("campaign")
    campaign_commands = campaign.add_subparsers(dest="campaign_action", required=True)
    campaign_create = campaign_commands.add_parser("create")
    campaign_create.add_argument("name")
    campaign_create.add_argument("--target", required=True)
    campaign_add = campaign_commands.add_parser("add-run")
    campaign_add.add_argument("name")
    campaign_add.add_argument("run_id")
    campaign_refresh = campaign_commands.add_parser("refresh-run")
    campaign_refresh.add_argument("name")
    campaign_refresh.add_argument("run_id")
    campaign_show = campaign_commands.add_parser("show")
    campaign_show.add_argument("name")
    campaign_export = campaign_commands.add_parser("export")
    campaign_export.add_argument("name")
    campaign_export.add_argument("path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Phase2RunStore()
    campaigns = Phase2CampaignStore(run_store=store)
    try:
        if args.command == "scan":
            from agent import normalize_target, run_scan_command

            if args.campaign:
                campaigns.validate_target(args.campaign, normalize_target(args.target))
            options = [args.target, "--mode", args.mode, "--profile", args.profile]
            if args.policy:
                options.extend(("--policy", args.policy))
            if args.context:
                options.extend(("--context", args.context))
            if args.verification_input:
                options.extend(("--verification-input", args.verification_input))
            if args.lab:
                options.append("--lab")
            if args.dedicated_lab:
                options.append("--dedicated-lab")
            result = run_scan_command(shlex.join(options))
            if args.campaign and result.get("success", False):
                phase2 = result.get("phase2") or {}
                run_id = phase2.get("run_id")
                if not run_id:
                    raise ValueError("Completed scan did not return a Phase 2 run ID.")
                result["campaign"] = campaigns.add_run(args.campaign, run_id)
        elif args.command == "hypotheses":
            run = store.load()
            result = {"success": True, "hypotheses": run.get("hypotheses", [])}
        elif args.command == "hypothesis":
            hypothesis = store.hypothesis(args.hypothesis_id)
            result = (
                {"success": True, "hypothesis": hypothesis}
                if hypothesis is not None
                else {
                    "success": False,
                    "error": f"Hypothesis not found: {args.hypothesis_id}.",
                }
            )
        elif args.command == "verification" and args.action == "plan":
            if len(args.remaining) != 1:
                raise ValueError("verification plan requires one hypothesis ID")
            hypothesis_id = args.remaining[0]
            hypothesis = store.hypothesis(hypothesis_id)
            plan = store.plan(hypothesis_id) if hypothesis is not None else None
            if hypothesis is None:
                result = {
                    "success": False,
                    "error": f"Hypothesis not found: {hypothesis_id}.",
                }
            elif plan is None:
                result = {
                    "success": False,
                    "error": f"No verification plan exists for hypothesis: {hypothesis_id}.",
                }
            else:
                result = {"success": True, "verification_plan": plan}
        elif args.command == "verification":
            result = run_verification_command(args.remaining)
        elif args.command == "campaign" and args.campaign_action == "create":
            result = {
                "success": True,
                "campaign": campaigns.create(args.name, args.target),
            }
        elif args.command == "campaign" and args.campaign_action == "add-run":
            result = {
                "success": True,
                "campaign": campaigns.add_run(args.name, args.run_id),
            }
        elif args.command == "campaign" and args.campaign_action == "refresh-run":
            result = {
                "success": True,
                "campaign": campaigns.refresh_run(args.name, args.run_id),
            }
        elif args.command == "campaign" and args.campaign_action == "show":
            result = {"success": True, "campaign": campaigns.show(args.name)}
        elif args.command == "campaign":
            result = {
                "success": True,
                "output": campaigns.export(args.name, args.path),
            }
        else:
            result = {"output": export_benchmark(store.load(), args.path)}
        print(json.dumps(public_result(result), indent=2))
        return 0 if result.get("success", True) else 2
    except FileNotFoundError as exc:
        message = (
            f"Campaign or referenced run was not found: {exc.filename or exc}."
            if args.command == "campaign" or getattr(args, "campaign", None)
            else NO_PHASE2_STATE_MESSAGE
        )
        print(json.dumps(public_result({"success": False, "error": message}), indent=2))
        return 2
    except (OSError, ValueError, TypeError) as exc:
        print(
            json.dumps(public_result({"success": False, "error": str(exc)}), indent=2)
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
