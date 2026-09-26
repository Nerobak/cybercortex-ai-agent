"""Operator CLI for blind autonomous-security research benchmarks.

Execution wiring is supplied by an explicit ``module:function`` factory.  The
factory must return ``(BenchmarkResearchInput, BenchmarkExecutionBindings,
BenchmarkResetPlan)`` and therefore cannot receive private ground truth.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

from agent_core.benchmark import (
    AutonomousResearchBenchmarkRunner,
    BenchmarkExecutionBindings,
    BenchmarkGroundTruthStore,
    BenchmarkManifest,
    BenchmarkReporter,
    BenchmarkResearchInput,
    BenchmarkResetPlan,
    BenchmarkRuntimeMetadata,
    BenchmarkRunStatus,
    BenchmarkRunStore,
    BenchmarkScore,
    BenchmarkScoringPolicy,
    artifact_fingerprint,
    load_benchmark_manifest,
)
from agent_core.research.state import ResearchState
from agent_core.version import __version__


class BenchmarkCLIError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CyberCortex formal autonomous research benchmarks"
    )
    commands = parser.add_subparsers(dest="command")

    validate = commands.add_parser("validate", help="Validate a public manifest")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--ground-truth-store")

    run = commands.add_parser("run", help="Run one benchmark using production wiring")
    run.add_argument("--manifest", required=True)
    run.add_argument("--factory", required=True, help="module:function execution factory")
    run.add_argument("--run-store", required=True)
    run.add_argument("--ground-truth-store", required=True)
    run.add_argument("--scoring-policy", required=True)
    run.add_argument("--research-id", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--operator-reset-confirmed", action="store_true")
    run.add_argument("--max-iterations", type=int)

    score = commands.add_parser("score", help="Score a terminated benchmark run")
    score.add_argument("--run", required=True)
    score.add_argument("--run-store", required=True)
    score.add_argument("--ground-truth-store", required=True)
    score.add_argument("--scoring-policy", required=True)

    report = commands.add_parser("report", help="Render a scored benchmark run")
    report.add_argument("--run", required=True)
    report.add_argument("--run-store", required=True)
    report.add_argument("--ground-truth-store", required=True)
    report.add_argument("--scoring-policy", required=True)
    report.add_argument("--output")
    report.add_argument("--format", choices=("json", "text"), default="text")
    return parser


def _load_policy(path: str | Path) -> BenchmarkScoringPolicy:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
        if source.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise BenchmarkCLIError("yaml_support_is_unavailable") from exc
            payload = yaml.safe_load(text)
        else:
            payload = json.loads(text)
        return BenchmarkScoringPolicy.model_validate_json(json.dumps(payload))
    except Exception as exc:
        raise BenchmarkCLIError("scoring_policy_is_invalid") from exc


def _runner(args: argparse.Namespace) -> AutonomousResearchBenchmarkRunner:
    policy = _load_policy(args.scoring_policy)
    return AutonomousResearchBenchmarkRunner(
        run_store=BenchmarkRunStore(args.run_store),
        ground_truth_store=BenchmarkGroundTruthStore(args.ground_truth_store),
        scoring_policies={policy.policy_id: policy},
    )


def _load_factory(reference: str) -> Callable[..., Any]:
    if reference.count(":") != 1:
        raise BenchmarkCLIError("factory_must_use_module_function_syntax")
    module_name, function_name = reference.split(":", 1)
    try:
        function = getattr(importlib.import_module(module_name), function_name)
    except Exception as exc:
        raise BenchmarkCLIError("benchmark_factory_is_unavailable") from exc
    if not callable(function):
        raise BenchmarkCLIError("benchmark_factory_is_not_callable")
    return function


def _execute_validate(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_benchmark_manifest(args.manifest)
    result: dict[str, Any] = {
        "benchmark_id": manifest.benchmark_id,
        "benchmark_version": manifest.benchmark_version,
        "manifest_fingerprint": artifact_fingerprint(manifest),
        "valid": True,
    }
    if args.ground_truth_store:
        store = BenchmarkGroundTruthStore(args.ground_truth_store)
        result["ground_truth_fingerprint"] = store.fingerprint(
            manifest.ground_truth_reference
        )
    return result


def _execute_run(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_benchmark_manifest(args.manifest)
    policy = _load_policy(args.scoring_policy)
    if policy.policy_id != manifest.scoring_policy_reference:
        raise BenchmarkCLIError("scoring_policy_reference_mismatch")
    factory = _load_factory(args.factory)
    built = factory(
        manifest=manifest,
        run_id=args.run_id,
        research_id=args.research_id,
    )
    if not isinstance(built, tuple) or len(built) != 3:
        raise BenchmarkCLIError("benchmark_factory_return_is_invalid")
    research_input, bindings, reset_plan = built
    if not isinstance(research_input, BenchmarkResearchInput):
        raise BenchmarkCLIError("benchmark_factory_input_is_invalid")
    if not isinstance(bindings, BenchmarkExecutionBindings):
        raise BenchmarkCLIError("benchmark_factory_bindings_are_invalid")
    if not isinstance(reset_plan, BenchmarkResetPlan):
        raise BenchmarkCLIError("benchmark_factory_reset_plan_is_invalid")
    runner = AutonomousResearchBenchmarkRunner(
        run_store=BenchmarkRunStore(args.run_store),
        ground_truth_store=BenchmarkGroundTruthStore(args.ground_truth_store),
        scoring_policies={policy.policy_id: policy},
    )
    run = runner.run(
        manifest,
        research_input,
        bindings,
        reset_plan,
        research_id=args.research_id,
        run_id=args.run_id,
        operator_reset_confirmed=args.operator_reset_confirmed,
        max_iterations=args.max_iterations,
    )
    return {
        "run_id": run.run_id,
        "research_id": run.research_id,
        "status": run.status.value,
        "target_requests": bindings.request_budget.total,
        "model_calls": bindings.model_router.ledger.usage_for_run(run.research_id).attempted_calls,
    }


def _execute_score(args: argparse.Namespace) -> dict[str, Any]:
    runner = _runner(args)
    score = runner.score_run(args.run)
    return score.model_dump(mode="json", exclude_none=True)


def _execute_report(args: argparse.Namespace) -> str:
    runner = _runner(args)
    run = runner.run_store.load(args.run)
    if run.status is not BenchmarkRunStatus.scored:
        raise BenchmarkCLIError("benchmark_run_is_not_scored")
    manifest = runner.run_store.load_artifact(args.run, "manifest", BenchmarkManifest)
    score = runner.run_store.load_artifact(args.run, "score", BenchmarkScore)
    initial = runner.run_store.load_artifact(args.run, "initial-state", ResearchState)
    final = runner.run_store.load_artifact(args.run, "final-state", ResearchState)
    research_input = runner.run_store.load_artifact(
        args.run, "research-input", BenchmarkResearchInput
    )
    runtime = runner.run_store.load_artifact(
        args.run, "runtime-metadata", BenchmarkRuntimeMetadata
    )
    assert isinstance(manifest, BenchmarkManifest)
    assert isinstance(research_input, BenchmarkResearchInput)
    assert isinstance(score, BenchmarkScore)
    assert isinstance(runtime, BenchmarkRuntimeMetadata)
    policy = _load_policy(args.scoring_policy)
    truth = runner.ground_truth_store.load_for_scoring(
        manifest.ground_truth_reference, run_status=run.status
    )
    report = BenchmarkReporter().build(
        run=run,
        manifest=manifest,
        ground_truth=truth,
        scoring_policy=policy,
        score=score,
        initial_state=initial,
        final_state=final,
        research_input=research_input,
        model_provider=runtime.model_provider,
        requested_model=runtime.requested_model,
        actual_model_provenance=runtime.actual_model_provenance,
        python_version=runtime.python_version,
        platform_name=runtime.platform,
        policy_fingerprint=runtime.policy_fingerprint,
        cybercortex_version=__version__,
    )
    runner.run_store.save_artifact(args.run, "report", report)
    runner.record_integrity(args.run, report.integrity)
    rendered = (
        BenchmarkReporter.to_json(report)
        if args.format == "json"
        else BenchmarkReporter.human_summary(report)
    )
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "validate":
            print(json.dumps(_execute_validate(args), sort_keys=True))
        elif args.command == "run":
            print(json.dumps(_execute_run(args), sort_keys=True))
        elif args.command == "score":
            print(json.dumps(_execute_score(args), sort_keys=True))
        else:
            print(_execute_report(args))
        return 0
    except (BenchmarkCLIError, ValueError, RuntimeError) as exc:
        print(f"benchmark_error:{str(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
