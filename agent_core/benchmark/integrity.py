"""Canonical benchmark artifact hashing and tamper verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel

from agent_core.benchmark.types import BenchmarkIntegrityReport


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        values = [_plain(item) for item in value]
        return sorted(values, key=lambda item: json.dumps(item, sort_keys=True)) if isinstance(value, (set, frozenset)) else values
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported benchmark artifact type: {type(value).__name__}")


def canonical_artifact_bytes(value: Any) -> bytes:
    return json.dumps(
        _plain(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def artifact_fingerprint(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_artifact_bytes(value)).hexdigest()


class BenchmarkIntegrityVerifier:
    def create_report(
        self,
        *,
        run_id: str,
        manifest: Any,
        ground_truth: Any,
        scoring_policy: Any,
        run_configuration: Any,
        initial_state: Any,
        final_state: Any,
        score_report: Any,
        expected_fingerprints: dict[str, str] | None = None,
    ) -> BenchmarkIntegrityReport:
        values = {
            "manifest": artifact_fingerprint(manifest),
            "ground-truth": artifact_fingerprint(ground_truth),
            "scoring-policy": artifact_fingerprint(scoring_policy),
            "run-configuration": artifact_fingerprint(run_configuration),
            "initial-state": artifact_fingerprint(initial_state),
            "final-state": artifact_fingerprint(final_state),
            "score-report": artifact_fingerprint(score_report),
        }
        expected = expected_fingerprints or values
        mismatches = tuple(
            sorted(name for name, digest in values.items() if expected.get(name) != digest)
        )
        return BenchmarkIntegrityReport(
            run_id=run_id,
            valid=not mismatches,
            manifest_fingerprint=values["manifest"],
            ground_truth_fingerprint=values["ground-truth"],
            scoring_policy_fingerprint=values["scoring-policy"],
            run_configuration_fingerprint=values["run-configuration"],
            initial_state_fingerprint=values["initial-state"],
            final_state_fingerprint=values["final-state"],
            score_report_fingerprint=values["score-report"],
            mismatched_artifacts=mismatches,
        )

    def verify(self, report: BenchmarkIntegrityReport, **artifacts: Any) -> bool:
        mapping = {
            "manifest": report.manifest_fingerprint,
            "ground_truth": report.ground_truth_fingerprint,
            "scoring_policy": report.scoring_policy_fingerprint,
            "run_configuration": report.run_configuration_fingerprint,
            "initial_state": report.initial_state_fingerprint,
            "final_state": report.final_state_fingerprint,
            "score_report": report.score_report_fingerprint,
        }
        return report.valid and all(
            name not in artifacts or artifact_fingerprint(artifacts[name]) == digest
            for name, digest in mapping.items()
        )


__all__ = [
    "BenchmarkIntegrityVerifier",
    "artifact_fingerprint",
    "canonical_artifact_bytes",
]
