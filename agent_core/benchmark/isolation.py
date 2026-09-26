"""Blindness, contamination detection, reset, and private truth storage."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field, StrictBool

from agent_core.benchmark.integrity import artifact_fingerprint, canonical_artifact_bytes
from agent_core.benchmark.types import (
    BenchmarkContract,
    BenchmarkGroundTruth,
    BenchmarkResearchInput,
    BenchmarkResetPlan,
    BenchmarkRunStatus,
    Digest,
    Identifier,
    ResetStrategy,
)
from agent_core.research.state import ResearchState


class BenchmarkIsolationError(RuntimeError):
    pass


class BenchmarkBlindnessError(BenchmarkIsolationError):
    pass


class BenchmarkContaminationError(BenchmarkIsolationError):
    pass


class GroundTruthAccessError(BenchmarkIsolationError):
    pass


class BlindnessCheckResult(BenchmarkContract):
    valid: StrictBool
    input_fingerprint: Digest
    violations: tuple[Identifier, ...] = ()


class ContaminationMatch(BenchmarkContract):
    material_fingerprint: Digest
    visible_location_fingerprint: Digest
    match_kind: Identifier


class ContaminationCheckResult(BenchmarkContract):
    contaminated: StrictBool
    visible_material_fingerprint: Digest
    ground_truth_fingerprint: Digest
    matches: tuple[ContaminationMatch, ...] = Field(default=(), max_length=10_000)


def _flatten(value: Any, path: str = "root") -> list[tuple[str, str]]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        rows: list[tuple[str, str]] = []
        for key in sorted(value, key=str):
            rows.extend(_flatten(value[key], f"{path}.{key}"))
        return rows
    if isinstance(value, (list, tuple)):
        rows = []
        for index, item in enumerate(value):
            rows.extend(_flatten(item, f"{path}[{index}]"))
        return rows
    if value is None:
        return []
    return [(path, str(value))]


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _safe_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class BenchmarkBlindnessGuard:
    """Reject structurally non-blind initial inputs before any activity."""

    _FORBIDDEN_INPUT_KEYS = frozenset(
        {
            "ground_truth",
            "ground_truth_id",
            "ground_truth_category",
            "ground_truth_endpoint",
            "ground_truth_parameter",
            "ground_truth_object",
            "ground_truth_chain",
            "hidden_vulnerability_category",
            "hidden_vulnerable_endpoint",
            "hidden_vulnerable_parameter",
            "hidden_object_identifier",
            "vulnerability_category",
            "vulnerable_endpoint",
            "vulnerable_parameter",
            "expected_exploit",
            "expected_response",
            "expected_finding",
            "expected_chain",
            "scoring_answer",
            "scoring_rubric",
            "score_threshold",
            "remaining_ground_truth_findings",
            "missed_findings",
            "current_score",
        }
    )

    def validate(
        self,
        research_input: BenchmarkResearchInput,
        *,
        initial_state: ResearchState,
        environment_metadata: Mapping[str, Any] | None = None,
        model_packets: Sequence[Any] = (),
        seed_evidence: Sequence[Any] = (),
        seed_hypotheses: Sequence[Any] = (),
        seed_experiments: Sequence[Any] = (),
        seed_findings: Sequence[Any] = (),
        seed_chains: Sequence[Any] = (),
        research_graph: Sequence[Any] = (),
        strict_blind: bool = True,
        controlled_setup_object_ids: Sequence[str] = (),
    ) -> BlindnessCheckResult:
        visible = {
            "research_input": research_input,
            "environment_metadata": dict(environment_metadata or {}),
            "initial_state": initial_state,
            "model_packets": tuple(model_packets),
            "seed_evidence": tuple(seed_evidence),
            "seed_hypotheses": tuple(seed_hypotheses),
            "seed_experiments": tuple(seed_experiments),
            "seed_findings": tuple(seed_findings),
            "seed_chains": tuple(seed_chains),
            "research_graph": tuple(research_graph),
        }
        violations: set[str] = set()
        self._check_keys(visible, violations)
        if strict_blind:
            counts = {
                "initial-endpoints-present": len(initial_state.endpoints),
                "initial-parameters-present": len(initial_state.parameters),
                "initial-hypotheses-present": len(initial_state.hypotheses),
                "initial-experiments-present": len(initial_state.experiment_history)
                + len(initial_state.experiment_outcomes),
                "initial-findings-present": len(initial_state.findings),
                "initial-chains-present": len(initial_state.chain_candidates)
                + len(initial_state.chain_hypotheses)
                + len(initial_state.attack_chains),
            }
            permitted_objects = set(controlled_setup_object_ids)
            unknown_objects = {
                item.object_id for item in initial_state.objects
            } - permitted_objects
            if unknown_objects:
                counts["initial-objects-present"] = len(unknown_objects)
            for code, count in counts.items():
                if count:
                    violations.add(code)
            seeds = {
                "seed-evidence-present": seed_evidence,
                "seed-hypotheses-present": seed_hypotheses,
                "seed-experiments-present": seed_experiments,
                "seed-findings-present": seed_findings,
                "seed-chains-present": seed_chains,
            }
            for code, values in seeds.items():
                if values:
                    violations.add(code)
            if research_graph:
                violations.add("initial-research-graph-present")
        result = BlindnessCheckResult(
            valid=not violations,
            input_fingerprint=artifact_fingerprint(visible),
            violations=tuple(sorted(violations)),
        )
        if violations:
            raise BenchmarkBlindnessError(
                "blind benchmark input failed: " + ", ".join(result.violations)
            )
        return result

    def _check_keys(self, value: Any, violations: set[str]) -> None:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json", exclude_none=True)
        if isinstance(value, Mapping):
            for key, item in value.items():
                normalized = str(key).casefold().replace("-", "_")
                if normalized in self._FORBIDDEN_INPUT_KEYS:
                    violations.add("forbidden-answer-field")
                self._check_keys(item, violations)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._check_keys(item, violations)


class BenchmarkContaminationDetector:
    """Exact/normalized deterministic comparison with fingerprint-only output."""

    def inspect(
        self, ground_truth: BenchmarkGroundTruth, agent_visible_material: Any
    ) -> ContaminationCheckResult:
        sensitive = self._sensitive_values(ground_truth)
        visible = _flatten(agent_visible_material)
        matches: set[tuple[str, str, str]] = set()
        for secret in sensitive:
            normalized_secret = _normalize(secret)
            if len(normalized_secret) < 3:
                continue
            for location, material in visible:
                normalized_material = _normalize(material)
                if not normalized_material:
                    continue
                kind = None
                if material.casefold().strip() == secret.casefold().strip():
                    kind = "exact"
                elif normalized_secret == normalized_material:
                    kind = "normalized-exact"
                elif len(normalized_secret) >= 6 and normalized_secret in normalized_material:
                    kind = "normalized-contained"
                if kind is not None:
                    matches.add((_safe_hash(normalized_secret), _safe_hash(location), kind))
        ordered = tuple(
            ContaminationMatch(
                material_fingerprint=material,
                visible_location_fingerprint=location,
                match_kind=kind,
            )
            for material, location, kind in sorted(matches)
        )
        return ContaminationCheckResult(
            contaminated=bool(ordered),
            visible_material_fingerprint=artifact_fingerprint(agent_visible_material),
            ground_truth_fingerprint=artifact_fingerprint(ground_truth),
            matches=ordered,
        )

    @staticmethod
    def _sensitive_values(ground_truth: BenchmarkGroundTruth) -> tuple[str, ...]:
        values: list[str] = list(ground_truth.hidden_sentinels)
        for finding in ground_truth.findings:
            values.extend(
                str(item)
                for item in (
                    finding.ground_truth_id,
                    finding.category,
                    finding.affected_endpoint_reference,
                    finding.affected_parameter_reference,
                    finding.affected_object_reference,
                    finding.security_property,
                    finding.required_controlled_identity_relationship,
                    finding.required_controlled_object_relationship,
                    finding.expected_vulnerable_behavior_class,
                    finding.expected_secure_behavior_class,
                    finding.notes_safe_for_post_run_scoring_only,
                )
                if item is not None
            )
        for chain in ground_truth.chains:
            values.extend(
                (
                    chain.chain_ground_truth_id,
                    *chain.component_ground_truth_ids,
                    *chain.ordered_relationship_classes,
                    *chain.required_cross_surface_transitions,
                    chain.combined_security_property,
                    chain.expected_combined_impact,
                )
            )
        return tuple(sorted(set(values)))


class BenchmarkGroundTruthStore:
    """Private file vault with status-gated raw truth access.

    Pre-run code can request a contamination decision, but cannot obtain the
    ground-truth object through that operation.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, reference: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}", reference):
            raise GroundTruthAccessError("invalid ground-truth reference")
        return self.root / f"{reference}.ground-truth.json"

    def put(self, reference: str, truth: BenchmarkGroundTruth) -> str:
        path = self._path(reference)
        if path.exists():
            raise GroundTruthAccessError("ground-truth reference already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, canonical_artifact_bytes(truth))
        finally:
            os.close(descriptor)
        return artifact_fingerprint(truth)

    def _load_private(self, reference: str) -> BenchmarkGroundTruth:
        try:
            return BenchmarkGroundTruth.model_validate_json(
                self._path(reference).read_text(encoding="utf-8")
            )
        except Exception as exc:
            raise GroundTruthAccessError("ground truth is unavailable or invalid") from exc

    def fingerprint(self, reference: str) -> str:
        return artifact_fingerprint(self._load_private(reference))

    def check_contamination(
        self, reference: str, agent_visible_material: Any
    ) -> ContaminationCheckResult:
        truth = self._load_private(reference)
        return BenchmarkContaminationDetector().inspect(truth, agent_visible_material)

    def load_for_scoring(
        self, reference: str, *, run_status: BenchmarkRunStatus
    ) -> BenchmarkGroundTruth:
        if not run_status.research_terminated:
            raise GroundTruthAccessError(
                "ground truth cannot be loaded before research termination"
            )
        return self._load_private(reference)


class BenchmarkSecretStore:
    """Opaque benchmark-only secrets; values never enter research records."""

    def __init__(self) -> None:
        self.__values: dict[str, bytes] = {}

    def put(self, reference: str, value: bytes) -> None:
        if reference in self.__values:
            raise GroundTruthAccessError("benchmark secret reference already exists")
        self.__values[reference] = bytes(value)

    def resolve_for_fixture(self, reference: str) -> bytes:
        try:
            return bytes(self.__values[reference])
        except KeyError as exc:
            raise GroundTruthAccessError("benchmark secret reference is unavailable") from exc


class BenchmarkResetController:
    """Execute only pre-registered fixture callbacks; never shell commands."""

    def __init__(self, callbacks: Mapping[str, Callable[[], bool]] | None = None) -> None:
        self._callbacks = dict(callbacks or {})

    def confirm(self, plan: BenchmarkResetPlan, *, operator_confirmed: bool = False) -> bool:
        if plan.strategy is ResetStrategy.stateless_target:
            return True
        if plan.strategy is ResetStrategy.external_operator_reset:
            return bool(operator_confirmed)
        callback = self._callbacks.get(str(plan.fixture_reference))
        if callback is None:
            return False
        return callback() is True


__all__ = [
    "BenchmarkBlindnessError",
    "BenchmarkBlindnessGuard",
    "BenchmarkContaminationDetector",
    "BenchmarkContaminationError",
    "BenchmarkGroundTruthStore",
    "BenchmarkIsolationError",
    "BenchmarkResetController",
    "BenchmarkSecretStore",
    "BlindnessCheckResult",
    "ContaminationCheckResult",
    "ContaminationMatch",
    "GroundTruthAccessError",
]
