"""Loading, fingerprinting, and public-input derivation for benchmarks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_core.benchmark.integrity import artifact_fingerprint
from agent_core.benchmark.types import (
    BenchmarkBudgetSnapshot,
    BenchmarkManifest,
    BenchmarkMetadataEntry,
    BenchmarkModelRouting,
    BenchmarkResearchInput,
)


class BenchmarkManifestError(ValueError):
    pass


def load_benchmark_manifest(path: str | Path) -> BenchmarkManifest:
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8")
        if source.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise BenchmarkManifestError("YAML support is unavailable") from exc
            payload: Any = yaml.safe_load(raw)
            encoded = json.dumps(payload)
        else:
            payload = json.loads(raw)
            encoded = raw
        if not isinstance(payload, dict):
            raise BenchmarkManifestError("benchmark manifest must be an object")
        return BenchmarkManifest.model_validate_json(encoded)
    except BenchmarkManifestError:
        raise
    except Exception as exc:
        raise BenchmarkManifestError("benchmark manifest is invalid") from exc


def manifest_fingerprint(manifest: BenchmarkManifest) -> str:
    return artifact_fingerprint(manifest)


def build_research_input(
    manifest: BenchmarkManifest,
    *,
    benchmark_run_id: str,
    authorized_target: str,
    model_routing_policy: BenchmarkModelRouting,
    persistence_location: str,
    opaque_credential_references: tuple[str, ...] = (),
    safe_benchmark_metadata: tuple[BenchmarkMetadataEntry, ...] = (),
    persistent_learning: bool = False,
) -> BenchmarkResearchInput:
    """Derive the deliberately narrow agent-visible object from a manifest."""

    if authorized_target != manifest.authorized_target_reference:
        raise BenchmarkManifestError("authorized target does not match the manifest")
    return BenchmarkResearchInput(
        benchmark_run_id=benchmark_run_id,
        authorized_target=authorized_target,
        target_class=manifest.target_class,
        scope_reference=manifest.scope_reference,
        policy_reference=manifest.policy_reference,
        controlled_identity_metadata_references=(
            manifest.controlled_account_metadata_references
        ),
        opaque_credential_references=opaque_credential_references,
        budgets=BenchmarkBudgetSnapshot(
            request_budget=manifest.request_budget,
            model_budget=manifest.model_budget,
            experiment_budget=manifest.experiment_budget,
            reproduction_budget=manifest.reproduction_budget,
            chain_budget=manifest.chain_budget,
            wall_time_budget=manifest.wall_time_budget,
        ),
        model_routing_policy=model_routing_policy,
        safe_benchmark_metadata=safe_benchmark_metadata,
        persistence_location=persistence_location,
        persistent_learning=persistent_learning,
    )


__all__ = [
    "BenchmarkManifestError",
    "build_research_input",
    "load_benchmark_manifest",
    "manifest_fingerprint",
]
