"""Canonical semantic fingerprinting and deduplication helpers."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Iterable, Mapping

from pydantic import BaseModel

FINGERPRINT_SCHEMA_VERSION = 1

_NON_SEMANTIC_INPUT_KEYS = frozenset(
    {
        "request_template_id",
        "session_ref_id",
        "primary_session_ref_id",
        "replacement_session_ref_id",
        "token_ref_id",
        "replacement_token_ref_id",
        "ownership_evidence_ids",
        "primary_identity_id",
        "comparison_identity_id",
        "identity_id",
        "controlled_object_id",
        "value_source_reference",
        "references",
        "before_state_reference",
        "after_state_reference",
        "cleanup_state_reference",
    }
)


def _plain(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _semantic_input(value: Any) -> Any:
    candidate = _plain(value)
    if isinstance(candidate, dict):
        return {
            key: _semantic_input(item)
            for key, item in sorted(candidate.items())
            if key not in _NON_SEMANTIC_INPUT_KEYS
        }
    if isinstance(candidate, list):
        return [_semantic_input(item) for item in candidate]
    return candidate


def canonical_experiment_semantics(experiment: Any) -> dict[str, Any]:
    """Return only fields that materially define an experiment's semantics."""

    value = _plain(experiment)
    if not isinstance(value, Mapping):
        raise TypeError("experiment must be a SecurityExperiment or mapping")
    capability = value["capability"]
    target = value["target"]
    baseline = value["baseline"]
    mutation = value["mutation"]
    requirements = value["required_evidence"]
    steps = value["primitive_steps"]
    return {
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "capability": {
            "name": capability["name"],
            "version": capability["version"],
        },
        "target": {
            "target_id": target["target_id"],
            "target_class": target["target_class"],
            "surface_id": target.get("surface_id"),
            "endpoint_id": target.get("endpoint_id"),
            "operation_id": target.get("operation_id"),
            "method": target.get("method"),
            "parameter_ids": sorted(target.get("parameter_ids", [])),
        },
        "identity_relationship": value["identity_context"].get("relationship"),
        "primitive_steps": [
            {
                "primitive_name": step["primitive_name"],
                "primitive_version": step["primitive_version"],
                "input": _semantic_input(step["input"]),
            }
            for step in steps
        ],
        "mutation": {
            "kind": mutation["kind"],
            "parameter_ids": sorted(mutation.get("parameter_ids", [])),
            "object_types": sorted(mutation.get("object_types", [])),
            "ownership_relationships": sorted(
                mutation.get("ownership_relationships", [])
            ),
        },
        "baseline_kind": baseline["kind"],
        "expected_evidence": sorted(
            (
                requirement["selector"],
                requirement["predicate_reference"],
                requirement["minimum_artifacts"],
            )
            for requirement in requirements
        ),
        "state_revision": value["state_revision"],
    }


def experiment_fingerprint(experiment: Any) -> str:
    """Return a SHA-256 digest of canonical, secret-free experiment semantics."""

    encoded = json.dumps(
        canonical_experiment_semantics(experiment),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def equivalent_experiment(first: Any, second: Any) -> bool:
    return experiment_fingerprint(first) == experiment_fingerprint(second)


def equivalent_experiments(first: Any, second: Any) -> bool:
    return equivalent_experiment(first, second)


def _fingerprint_value(value: Any) -> str:
    if isinstance(value, str) and value.startswith("sha256:"):
        return value
    return experiment_fingerprint(value)


def previously_attempted_fingerprint(
    candidate: Any, attempted_fingerprints: Iterable[str]
) -> bool:
    return _fingerprint_value(candidate) in frozenset(attempted_fingerprints)


def blocked_fingerprint(candidate: Any, blocked_fingerprints: Iterable[str]) -> bool:
    return _fingerprint_value(candidate) in frozenset(blocked_fingerprints)


class ReproductionFingerprintRelationship(str, Enum):
    equivalent = "equivalent"
    material_variant = "material_variant"


def reproduction_fingerprint_relationship(
    reproduction: Any, original: Any
) -> ReproductionFingerprintRelationship:
    if equivalent_experiment(reproduction, original):
        return ReproductionFingerprintRelationship.equivalent
    return ReproductionFingerprintRelationship.material_variant
