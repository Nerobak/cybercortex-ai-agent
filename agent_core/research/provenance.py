"""Secret-safe provenance helpers for durable Phase 4 research mutations."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from agent_core.result_normalizer import sanitize_document_text
from agent_core.research.state import ProvenanceRecord
from agent_core.research.types import (
    ProvenanceProducerType,
    PublicMetadata,
)

MAX_PROVENANCE_REFERENCES = 100

_REFERENCE_KINDS = frozenset(
    {
        "event",
        "evidence",
        "model-decision",
        "phase2-result",
        "phase2-run",
        "policy",
        "research-revision",
        "runtime-result",
    }
)
_SENSITIVE_KEY = re.compile(
    r"^(?:api_key|authorization|client_secret|cookie|credential|jwt|password|"
    r"private_key|raw_session|secret|session_value|token_value)$",
    re.IGNORECASE,
)
_REASONING_KEY = re.compile(
    r"(?:^|_)(?:chain_of_thought|hidden_reasoning|model_prompt|prompt|reasoning_trace|"
    r"scratchpad)(?:$|_)",
    re.IGNORECASE,
)
_SYNTHETIC_SECRET = re.compile(
    r"(?:synthetic|fake|raw)[-_ ](?:api[-_ ]?key|cookie|credential|jwt|password|"
    r"secret|session|token)",
    re.IGNORECASE,
)
_API_KEY = re.compile(r"^(?:sk|pk|api)[-_][A-Za-z0-9_-]{12,}$", re.IGNORECASE)
_SAFE_API_IDENTIFIER = re.compile(r"^api[-_]authorization$", re.IGNORECASE)
_REDACTED_VALUES = frozenset({"[redacted]", "[redacted jwt]", "<redacted>", "redacted"})


class SecretMaterialRejected(ValueError):
    """Raised before a value that looks like raw secret material is persisted."""


def provenance_reference(kind: str, value: str | int) -> str:
    """Return one bounded, typed opaque reference for a provenance record."""

    if kind not in _REFERENCE_KINDS:
        raise ValueError(f"unsupported provenance reference kind: {kind}")
    rendered = f"{kind}:{value}"
    if len(rendered) > 255 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", rendered
    ):
        raise ValueError("provenance reference is not a valid opaque identifier")
    return rendered


def _is_redacted(value: object) -> bool:
    return isinstance(value, str) and value.strip().casefold() in _REDACTED_VALUES


def reject_secret_material(value: Any, *, location: str = "research mutation") -> None:
    """Reject raw secrets and hidden reasoning recursively without logging values."""

    def inspect(candidate: Any, path: tuple[str, ...]) -> None:
        if isinstance(candidate, Mapping):
            for raw_key, item in candidate.items():
                key = str(raw_key)
                normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
                if (
                    normalized == "key"
                    and isinstance(item, str)
                    and _REASONING_KEY.search(
                        re.sub(r"[^a-z0-9]+", "_", item.casefold()).strip("_")
                    )
                ):
                    raise SecretMaterialRejected(
                        f"{location} contains a prohibited model-reasoning field"
                    )
                if _REASONING_KEY.search(normalized):
                    raise SecretMaterialRejected(
                        f"{location} contains a prohibited model-reasoning field"
                    )
                if _SENSITIVE_KEY.search(normalized) and not (
                    item is None or isinstance(item, (bool, int)) or _is_redacted(item)
                ):
                    raise SecretMaterialRejected(
                        f"{location} contains a raw secret-bearing field"
                    )
                inspect(item, (*path, normalized))
            return
        if isinstance(candidate, Sequence) and not isinstance(
            candidate, (str, bytes, bytearray)
        ):
            for index, item in enumerate(candidate):
                inspect(item, (*path, str(index)))
            return
        if isinstance(candidate, (bytes, bytearray)):
            raise SecretMaterialRejected(f"{location} contains raw binary material")
        if not isinstance(candidate, str) or _is_redacted(candidate):
            return
        if sanitize_document_text(candidate) != candidate:
            raise SecretMaterialRejected(
                f"{location} contains embedded secret material"
            )
        if _SYNTHETIC_SECRET.search(candidate) or (
            _API_KEY.fullmatch(candidate.strip())
            and not _SAFE_API_IDENTIFIER.fullmatch(candidate.strip())
        ):
            raise SecretMaterialRejected(
                f"{location} contains secret sentinel material"
            )

    inspect(value, ())


def build_provenance_record(
    *,
    provenance_id: str,
    producer_type: ProvenanceProducerType,
    producer_name: str,
    producer_version: str,
    summary: str,
    occurred_at: str,
    research_revision: int | None = None,
    source_event_ids: Sequence[str] = (),
    source_evidence_ids: Sequence[str] = (),
    source_phase2_run: str | None = None,
    source_phase2_results: Sequence[str] = (),
    model_decision_id: str | None = None,
    policy_reference: str | None = None,
    runtime_result_reference: str | None = None,
    parent_provenance_id: str | None = None,
    metadata: PublicMetadata | None = None,
) -> ProvenanceRecord:
    """Build canonical provenance without accepting prompt or reasoning content."""

    references: list[str] = []
    if research_revision is not None:
        references.append(provenance_reference("research-revision", research_revision))
    references.extend(provenance_reference("event", item) for item in source_event_ids)
    references.extend(
        provenance_reference("evidence", item) for item in source_evidence_ids
    )
    if source_phase2_run is not None:
        references.append(provenance_reference("phase2-run", source_phase2_run))
    references.extend(
        provenance_reference("phase2-result", item) for item in source_phase2_results
    )
    if model_decision_id is not None:
        references.append(provenance_reference("model-decision", model_decision_id))
    if policy_reference is not None:
        references.append(provenance_reference("policy", policy_reference))
    if runtime_result_reference is not None:
        references.append(
            provenance_reference("runtime-result", runtime_result_reference)
        )
    references = sorted(set(references))
    if len(references) > MAX_PROVENANCE_REFERENCES:
        raise ValueError("provenance reference limit exceeded")
    record = ProvenanceRecord(
        provenance_id=provenance_id,
        producer_type=producer_type,
        producer_name=producer_name,
        producer_version=producer_version,
        source_references=tuple(references),
        parent_provenance_id=parent_provenance_id,
        summary=summary,
        occurred_at=occurred_at,
        metadata=metadata or PublicMetadata(),
    )
    reject_secret_material(record.model_dump(mode="json"), location="provenance")
    return record
