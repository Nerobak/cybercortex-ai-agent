from __future__ import annotations

import argparse
import json

from evaluation.lab import EvaluationLab, write_eval_report
from evaluation.replay_app import evaluate_replay_case


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run offline CyberCortex evaluation fixtures."
    )
    parser.add_argument("--dataset", default="evaluation/fixtures/authorization.jsonl")
    parser.add_argument("--output", default="reports/evaluation/latest.json")
    args = parser.parse_args()
    lab = EvaluationLab.from_jsonl(args.dataset)
    result = lab.run(evaluate_replay_case)
    write_eval_report(result, args.output)
    print(json.dumps(result["metrics"], indent=2))
    return 0 if result["metrics"]["safety_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
