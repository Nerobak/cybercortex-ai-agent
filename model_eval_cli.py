"""Credential-free CLI for synthetic P3-6 evaluation and saved-report analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

from agent_core.model_evaluation import (
    EvaluationRun,
    EvaluationRunner,
    SyntheticScenario,
    compare_runs,
    comparison_table,
    evaluation_json,
    human_summary,
    synthetic_case,
    synthetic_outcome,
    synthetic_subject,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberCortex Phase 3 evaluation")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-subjects", help="List credential-free synthetic subjects")
    synthetic = commands.add_parser(
        "run-synthetic", help="Run an offline deterministic synthetic observation"
    )
    synthetic.add_argument("--run-id", default="synthetic-evaluation")
    summarize = commands.add_parser("summarize", help="Summarize an evaluation JSON")
    summarize.add_argument("report")
    compare = commands.add_parser("compare", help="Compare two evaluation JSON files")
    compare.add_argument("left")
    compare.add_argument("right")
    return parser


def _read_run(path: str) -> EvaluationRun:
    return EvaluationRun.model_validate_json(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-subjects":
        print("synthetic-gpt\nsynthetic-claude\nsynthetic-local")
        return 0
    if args.command == "run-synthetic":
        subject = synthetic_subject()
        case = synthetic_case()
        run = EvaluationRunner().run(
            evaluation_run_id=args.run_id,
            subject=subject,
            cases=(case,),
            evaluator=lambda selected, item, repetition: synthetic_outcome(
                selected,
                item,
                repetition,
                scenario=SyntheticScenario.grounded_recommendation,
            ),
        )
        print(evaluation_json(run))
        return 0
    if args.command == "summarize":
        print(human_summary(_read_run(args.report)))
        return 0
    left = _read_run(args.left)
    right = _read_run(args.right)
    print(comparison_table((left, right)))
    comparison = compare_runs(left, right)
    return 0 if comparison.configuration_compatible else 2


if __name__ == "__main__":
    raise SystemExit(main())
