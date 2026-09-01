"""Cumulative, secret-safe aggregation of immutable Phase 2 run records."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import ConfigDict, Field, StrictInt, StrictStr, model_validator

from agent_core.agent_models import StrictModel
from agent_core.benchmark_exporter import assert_benchmark_integrity
from agent_core.finding_export import (
    ExportOperation,
    FindingExportStructure,
    resolve_finding_export,
)
from agent_core.phase2_store import (
    RUN_SNAPSHOT_HASH_PATTERN,
    Phase2RunStore,
    _atomic_write,
    run_snapshot_hash,
    validate_run_snapshot_hash,
)
from agent_core.request_budget import canonical_result_request_total
from agent_core.result_normalizer import public_result, sanitize_text, sanitize_url
from agent_core.result_provenance import (
    target_identity,
    validate_result_provenance,
    validate_target_fingerprint,
    verification_result_reference,
)

_CAMPAIGN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CAMPAIGN_REVISION_PATTERN = re.compile(
    r"^(?P<campaign>.+)\.revision_(?P<revision>[0-9]+)\.json$"
)
CAMPAIGN_SCHEMA_VERSION = 2
CAMPAIGN_SNAPSHOT_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_ROUTE_PARAMETER = re.compile(r"\{[^{}]+\}")

_STATUS_RANK = {
    "discovered": 1,
    "inconclusive": 2,
    "rejected": 3,
    "verified": 4,
}
_COMPLETED_VERIFICATION_STATUSES = {"verified", "rejected", "inconclusive"}
_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_MODE_ORDER = {"observe": 0, "plan": 1, "verify": 2}


class CampaignRunReference(StrictModel):
    """Exact immutable run view adopted by a versioned campaign."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        strict=True,
        frozen=True,
    )

    run_id: StrictStr = Field(pattern=r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
    revision: StrictInt = Field(ge=1)
    run_snapshot_hash: StrictStr = Field(pattern=RUN_SNAPSHOT_HASH_PATTERN.pattern)
    target_fingerprint: StrictStr = Field(pattern=r"sha256:[0-9a-f]{64}")


class CampaignManifestV2(StrictModel):
    """Strict append-only campaign manifest with ordered run pins."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        strict=True,
    )

    campaign_schema_version: Literal[CAMPAIGN_SCHEMA_VERSION]
    campaign_id: StrictStr = Field(pattern=_CAMPAIGN_ID_PATTERN.pattern)
    campaign_revision: StrictInt = Field(ge=1)
    campaign_snapshot_hash: StrictStr = Field(
        pattern=CAMPAIGN_SNAPSHOT_HASH_PATTERN.pattern
    )
    campaign_provenance_status: Literal["pinned"] = "pinned"
    name: StrictStr = Field(min_length=1, max_length=128)
    target: StrictStr = Field(min_length=1, max_length=8192)
    target_fingerprint: StrictStr = Field(pattern=r"sha256:[0-9a-f]{64}")
    run_ids: list[StrictStr] = Field(default_factory=list, max_length=500)
    run_references: list[CampaignRunReference] = Field(
        default_factory=list,
        max_length=500,
    )
    created_at: StrictStr = Field(min_length=1, max_length=100)
    updated_at: StrictStr = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_membership(self) -> CampaignManifestV2:
        pinned_ids = [item.run_id for item in self.run_references]
        if self.run_ids != pinned_ids:
            raise ValueError("Campaign run_ids do not match ordered run references.")
        if len(pinned_ids) != len(set(pinned_ids)):
            raise ValueError("Campaign contains duplicate run references.")
        if any(
            item.target_fingerprint != self.target_fingerprint
            for item in self.run_references
        ):
            raise ValueError(
                "Campaign run reference target fingerprint is inconsistent."
            )
        return self


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _campaign_identity(name: str) -> tuple[str, str]:
    display_name = str(name).strip()
    if not _CAMPAIGN_ID_PATTERN.fullmatch(display_name):
        raise ValueError(
            "Campaign name must use only letters, numbers, '.', '_', or '-'."
        )
    return display_name.lower(), display_name


def canonical_campaign_snapshot_json(campaign: Any) -> str:
    """Return canonical public campaign state excluding its recursive hash."""

    payload = public_result(campaign)
    if not isinstance(payload, dict):
        raise ValueError("Campaign snapshot must normalize to a public object.")
    payload.pop("campaign_snapshot_hash", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def campaign_snapshot_hash(campaign: Any) -> str:
    """Fingerprint one sanitized immutable campaign revision."""

    material = canonical_campaign_snapshot_json(campaign).encode("utf-8")
    return "sha256:" + sha256(material).hexdigest()


def validate_campaign_snapshot_hash(value: Any) -> str:
    if not isinstance(value, str) or not CAMPAIGN_SNAPSHOT_HASH_PATTERN.fullmatch(
        value
    ):
        raise ValueError("Campaign snapshot hash is invalid.")
    return value


def _validated_campaign_v2(campaign: Any) -> dict[str, Any]:
    try:
        model = CampaignManifestV2.model_validate(campaign)
    except (TypeError, ValueError) as exc:
        raise ValueError("Stored versioned campaign manifest is invalid.") from exc
    payload = model.model_dump(mode="json")
    canonical_target(payload["target"])
    validate_target_fingerprint(payload["target_fingerprint"])
    supplied_hash = validate_campaign_snapshot_hash(payload["campaign_snapshot_hash"])
    if campaign_snapshot_hash(payload) != supplied_hash:
        raise ValueError("Campaign snapshot hash does not match its public content.")
    return payload


def canonical_target(target: str) -> str:
    """Return a strict, secret-safe target identity used to prevent cross-target merges."""

    raw = sanitize_url(str(target).strip())
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("Campaign target must be an absolute HTTP(S) URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Campaign target contains an invalid port.") from exc
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path or ""
    if path == "/":
        path = ""
    query_items = list(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(sorted(query_items))
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


def _target_matches(
    expected_target: str,
    expected_fingerprint: Any,
    actual_target: str,
    actual_fingerprint: Any,
) -> bool:
    if expected_fingerprint is not None:
        expected = validate_target_fingerprint(expected_fingerprint)
        if actual_fingerprint is None:
            return False
        return validate_target_fingerprint(actual_fingerprint) == expected
    return canonical_target(actual_target) == canonical_target(expected_target)


def _safe_text(value: Any) -> str:
    return sanitize_text(str(value or ""))


def _safe_payload(value: Any) -> Any:
    return public_result(value)


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _normalize_status(value: Any) -> str:
    status = str(value or "").strip().lower()
    if status in {"verified", "rejected", "inconclusive"}:
        return status
    return "discovered"


def _normalize_confidence(value: Any) -> str:
    confidence = str(value or "low").strip().lower()
    return confidence if confidence in _CONFIDENCE_RANK else "low"


def _route_details(hypothesis: dict[str, Any]) -> tuple[str, str, str, str]:
    surface = hypothesis.get("target_surface") or {}
    if not isinstance(surface, dict):
        surface = {}
    method = str(surface.get("method") or hypothesis.get("method") or "GET").upper()
    route = str(surface.get("path") or "").strip()
    endpoint = str(hypothesis.get("endpoint") or "").strip()
    if not route and endpoint:
        parsed = urlsplit(endpoint)
        route = parsed.path if parsed.scheme and parsed.netloc else endpoint
    parameter = str(
        surface.get("parameter") or hypothesis.get("parameter") or ""
    ).strip()
    functionality = " ".join(item for item in (method, route, parameter) if item)
    if not functionality:
        functionality = endpoint or "unknown"
    return method, route or "unknown", parameter, functionality


def _dedupe_key(
    hypothesis: dict[str, Any], structure: FindingExportStructure
) -> tuple[str, str, str, str, str]:
    operation = structure.affected_operation
    method = operation.method
    route = operation.route_template
    parameter = operation.parameter
    functionality = operation.affected_functionality
    canonical_route = _ROUTE_PARAMETER.sub("{parameter}", route)
    fallback = "" if route != "unknown" else functionality.casefold()
    return (
        str(hypothesis.get("category") or "unknown").strip().casefold(),
        method,
        canonical_route,
        parameter.casefold(),
        fallback,
    )


def _evidence_summary(
    hypothesis: dict[str, Any], result: dict[str, Any] | None
) -> list[str]:
    if result is not None:
        for raw in (
            result.get("evidence_summary"),
            result.get("reasons"),
            (
                (result.get("analysis") or {}).get("reasons")
                if isinstance(result.get("analysis"), dict)
                else None
            ),
        ):
            if isinstance(raw, str):
                return [_safe_text(raw)]
            if isinstance(raw, list):
                evidence = [_safe_text(item) for item in raw if item is not None]
                if evidence:
                    return evidence
        return []
    evidence: list[str] = []
    for item in hypothesis.get("evidence_basis") or []:
        if isinstance(item, dict):
            observation = item.get("observation")
            if observation:
                evidence.append(_safe_text(observation))
        elif item:
            evidence.append(_safe_text(item))
    return evidence


def _correlated_sources(
    hypothesis: dict[str, Any], result: dict[str, Any] | None
) -> list[str]:
    sources: set[str] = set()
    for item in hypothesis.get("evidence_refs") or []:
        if item:
            sources.add(_safe_text(item))
    for item in hypothesis.get("evidence_basis") or []:
        if not isinstance(item, dict):
            continue
        for key in ("source", "reference"):
            if item.get(key):
                sources.add(_safe_text(item[key]))
    if result:
        for field in ("correlated_sources", "sources", "evidence_refs"):
            values = result.get(field) or []
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                sources.update(_safe_text(item) for item in values if item)
    return sorted(sources)


def _completed_result_status(result: dict[str, Any]) -> str | None:
    status = str(result.get("status") or "").strip().lower()
    return status if status in _COMPLETED_VERIFICATION_STATUSES else None


def _select_completed_result(
    hypothesis: dict[str, Any], matching_results: list[dict[str, Any]]
) -> tuple[str, str, dict[str, Any] | None]:
    completed = [
        (index, result, status)
        for index, result in enumerate(matching_results)
        if (status := _completed_result_status(result)) is not None
    ]
    if not completed:
        return (
            "discovered",
            _normalize_confidence(hypothesis.get("confidence")),
            None,
        )

    category = str(hypothesis.get("category") or "").strip().casefold()
    if category == "recovery_state_enforcement":
        _, selected, status = completed[-1]
    else:
        _, selected, status = max(
            completed,
            key=lambda item: (
                _STATUS_RANK[item[2]],
                _CONFIDENCE_RANK[
                    _normalize_confidence(
                        item[1].get("confidence") or hypothesis.get("confidence")
                    )
                ],
                len(_evidence_summary(hypothesis, item[1])),
                _result_requests(item[1], category=category),
                item[0],
            ),
        )
    return (
        status,
        _normalize_confidence(
            selected.get("confidence") or hypothesis.get("confidence")
        ),
        selected,
    )


def _same_recovery_workflow(
    result: dict[str, Any], selected_result: dict[str, Any]
) -> bool:
    for field in (
        "workflow_id",
        "recovery_workflow_id",
        "recovery_run_id",
        "challenge_reference",
        "comparison_type",
    ):
        left = result.get(field)
        right = selected_result.get(field)
        if left is not None and right is not None and left != right:
            return False
    return True


def _candidate_requests(
    hypothesis: dict[str, Any],
    matching_results: list[dict[str, Any]],
    selected_result: dict[str, Any] | None,
) -> int:
    if selected_result is None:
        return 0
    return _result_requests(
        selected_result, category=str(hypothesis.get("category") or "")
    )


def _candidate_workflow_request_total(
    hypothesis: dict[str, Any],
    matching_results: list[dict[str, Any]],
    selected_result: dict[str, Any] | None,
) -> int | None:
    if selected_result is None or str(hypothesis.get("category") or "").casefold() != (
        "recovery_state_enforcement"
    ):
        return None

    requests = 0
    for result in matching_results:
        if _same_recovery_workflow(result, selected_result):
            requests += _result_requests(result, category="recovery_state_enforcement")
        if result is selected_result:
            break
    return requests


def _candidate_for_hypothesis(
    run: dict[str, Any], hypothesis: dict[str, Any]
) -> dict[str, Any]:
    hypothesis_id = str(
        hypothesis.get("hypothesis_id") or hypothesis.get("id") or "unknown"
    )
    matching_results = [
        item
        for item in run.get("verification_results") or []
        if isinstance(item, dict) and item.get("hypothesis_id") == hypothesis_id
    ]
    status, confidence, selected_result = _select_completed_result(
        hypothesis, matching_results
    )
    default_method, default_route, default_parameter, _ = _route_details(hypothesis)
    structure = resolve_finding_export(
        hypothesis,
        default_operation=ExportOperation(
            method=default_method,
            route_template=default_route,
            parameter=default_parameter,
        ),
    )
    operation = structure.affected_operation
    method = operation.method
    route = operation.route_template
    parameter = operation.parameter
    functionality = operation.affected_functionality
    verification_reference = None
    if selected_result is not None:
        verification_reference = verification_result_reference(
            str(run.get("run_id") or "unknown"), selected_result
        )
    candidate = {
        "_dedupe_key": _dedupe_key(hypothesis, structure),
        "_selection_key": (
            -_STATUS_RANK[status],
            -_CONFIDENCE_RANK[confidence],
            -len(_evidence_summary(hypothesis, selected_result)),
            str(run.get("run_id") or "unknown"),
            hypothesis_id,
        ),
        "category": str(hypothesis.get("category") or "unknown"),
        "status": status,
        "confidence": confidence,
        "http_method": method,
        "route_template": route,
        "parameter": parameter or None,
        "affected_functionality": functionality,
        "evidence_summary": _evidence_summary(hypothesis, selected_result),
        "correlated_sources": _correlated_sources(hypothesis, selected_result),
        "requests_used": _candidate_requests(
            hypothesis, matching_results, selected_result
        ),
        "verification_result_reference": verification_reference,
        **structure.optional_fields(),
    }
    if selected_result is not None:
        candidate["request_accounting_source"] = canonical_result_request_total(
            selected_result
        )[1]
    workflow_request_total = _candidate_workflow_request_total(
        hypothesis, matching_results, selected_result
    )
    if workflow_request_total is not None:
        candidate["workflow_request_total"] = workflow_request_total
    return candidate


def _result_requests(
    result: dict[str, Any] | None, *, category: str | None = None
) -> int:
    if not result:
        return 0
    return canonical_result_request_total(result)[0]


def _typed_executor_requests(run: dict[str, Any]) -> int:
    categories_by_hypothesis = {
        str(item.get("hypothesis_id") or item.get("id") or ""): str(
            item.get("category") or ""
        )
        for item in run.get("hypotheses") or []
        if isinstance(item, dict)
    }
    return sum(
        _result_requests(
            item,
            category=(
                item.get("category")
                or categories_by_hypothesis.get(str(item.get("hypothesis_id") or ""))
            ),
        )
        for item in run.get("verification_results") or []
        if isinstance(item, dict)
    )


def _aggregate_findings(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for run in runs:
        for hypothesis in run.get("hypotheses") or []:
            if not isinstance(hypothesis, dict):
                continue
            candidate = _candidate_for_hypothesis(run, hypothesis)
            grouped.setdefault(candidate["_dedupe_key"], []).append(candidate)
    findings: list[dict[str, Any]] = []
    for key in sorted(grouped):
        candidates = grouped[key]
        selected = min(candidates, key=lambda item: item["_selection_key"])
        finding = {
            field: value
            for field, value in selected.items()
            if not field.startswith("_")
        }
        finding["correlated_sources"] = sorted(
            {
                source
                for candidate in candidates
                for source in candidate["correlated_sources"]
            }
        )
        findings.append(finding)
    return findings


def _run_metrics(run: dict[str, Any]) -> dict[str, Any]:
    metrics = run.get("metrics") or {}
    if not isinstance(metrics, dict):
        metrics = {}
    recorded_discovery = _nonnegative_int(metrics.get("discovery_requests"))
    observed_discovery = _nonnegative_int(metrics.get("discovery_requests_observed"))
    discovery = max(recorded_discovery, observed_discovery)
    total = metrics.get("total_requests")
    if total is None:
        total = metrics.get("request_count")
    if total is None:
        total = (
            recorded_discovery
            + _nonnegative_int(metrics.get("auth_requests"))
            + _nonnegative_int(metrics.get("verification_requests"))
            + _nonnegative_int(metrics.get("cleanup_requests"))
        )
    total = _nonnegative_int(total) + max(0, observed_discovery - recorded_discovery)
    object_acquisition = metrics.get("object_acquisition_requests")
    if object_acquisition is None:
        object_acquisition = sum(
            bool((item.get("owned_object_acquisition") or {}).get("attempted"))
            for item in run.get("verification_results") or []
            if isinstance(item, dict)
        )
    base_mode = str(run.get("assessment_mode") or run.get("mode") or "observe")
    activities = {item for item in base_mode.split("+") if item}
    if run.get("verification_results"):
        activities.add("verify")
    effective_mode = "+".join(
        sorted(
            activities,
            key=lambda item: (_MODE_ORDER.get(item, 99), item),
        )
    )
    return {
        "run_id": str(run.get("run_id") or "unknown"),
        "mode": effective_mode,
        "profile": str(run.get("profile") or "baseline"),
        "discovery_requests": discovery,
        "auth_requests": _nonnegative_int(metrics.get("auth_requests")),
        "object_acquisition_requests": _nonnegative_int(object_acquisition),
        "verification_requests": _nonnegative_int(metrics.get("verification_requests")),
        "cleanup_requests": _nonnegative_int(metrics.get("cleanup_requests")),
        "typed_executor_requests": _typed_executor_requests(run),
        "total_requests": total,
        "hypotheses_generated": _nonnegative_int(
            metrics.get("hypotheses_generated", len(run.get("hypotheses") or []))
        ),
    }


def build_campaign_export(
    campaign: dict[str, Any], runs: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a deterministic campaign export without copying benchmark IDs."""

    versioned = campaign.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION
    if versioned:
        campaign = _validated_campaign_v2(campaign)
        run_references = list(campaign["run_references"])
        expected_ids = [item["run_id"] for item in run_references]
    else:
        run_references = []
        expected_ids = list(campaign.get("run_ids") or [])
    actual_ids = [str(run.get("run_id") or "") for run in runs]
    if actual_ids != expected_ids:
        raise ValueError("Resolved campaign runs do not match the campaign run IDs.")
    target = canonical_target(str(campaign.get("target") or ""))
    target_fingerprint = campaign.get("target_fingerprint")
    if target_fingerprint is not None:
        target_fingerprint = validate_target_fingerprint(target_fingerprint)
    for index, run in enumerate(runs):
        if not _target_matches(
            target,
            target_fingerprint,
            str(run.get("target") or ""),
            run.get("target_fingerprint"),
        ):
            raise ValueError("Campaign cannot combine runs from different targets.")
        for result in run.get("verification_results") or []:
            if isinstance(result, dict) and result.get("result_id") is not None:
                validate_result_provenance(result)
        if versioned:
            reference = run_references[index]
            if run.get("run_revision") != reference["revision"]:
                raise ValueError(
                    "Resolved run revision does not match its campaign pin."
                )
            expected_hash = validate_run_snapshot_hash(reference["run_snapshot_hash"])
            if run_snapshot_hash(run) != expected_hash:
                raise ValueError(
                    "Pinned run snapshot hash does not match stored content."
                )
            if (
                validate_target_fingerprint(run.get("target_fingerprint"))
                != reference["target_fingerprint"]
            ):
                raise ValueError(
                    "Pinned run target fingerprint does not match its campaign pin."
                )
    findings = _aggregate_findings(runs)
    per_run = [_run_metrics(run) for run in runs]
    if versioned:
        campaign_reference = {
            "campaign_id": campaign["campaign_id"],
            "campaign_revision": campaign["campaign_revision"],
            "campaign_snapshot_hash": campaign["campaign_snapshot_hash"],
        }
        for finding in findings:
            finding["campaign_reference"] = dict(campaign_reference)
        for metrics, reference in zip(per_run, run_references, strict=True):
            metrics["run_revision"] = reference["revision"]
            metrics["run_snapshot_hash"] = reference["run_snapshot_hash"]
    modes = sorted(
        {
            activity
            for item in per_run
            for activity in item["mode"].split("+")
            if activity
        },
        key=lambda item: (_MODE_ORDER.get(item, 99), item),
    )
    aggregate_metrics = {
        "runs": len(runs),
        "discovery_requests": sum(item["discovery_requests"] for item in per_run),
        "auth_requests": sum(item["auth_requests"] for item in per_run),
        "object_acquisition_requests": sum(
            item["object_acquisition_requests"] for item in per_run
        ),
        "verification_requests": sum(item["verification_requests"] for item in per_run),
        "cleanup_requests": sum(item["cleanup_requests"] for item in per_run),
        "typed_executor_requests": sum(
            item["typed_executor_requests"] for item in per_run
        ),
        "total_requests": sum(item["total_requests"] for item in per_run),
        "hypotheses_generated": sum(item["hypotheses_generated"] for item in per_run),
        "unique_findings": len(findings),
        "verified_findings": sum(item["status"] == "verified" for item in findings),
        "rejected_findings": sum(item["status"] == "rejected" for item in findings),
    }
    campaign_payload = {
        "campaign_id": str(campaign.get("campaign_id") or "unknown"),
        "name": str(campaign.get("name") or "unknown"),
        "target": target,
        "created_at": str(campaign.get("created_at") or "unknown"),
        "updated_at": str(campaign.get("updated_at") or "unknown"),
        "run_ids": expected_ids,
        "assessment_mode": "+".join(modes) if modes else "observe",
        "profiles": sorted({item["profile"] for item in per_run}),
        "findings": findings,
        "run_metrics": per_run,
        "metrics": aggregate_metrics,
    }
    if target_fingerprint is not None:
        campaign_payload["target_fingerprint"] = target_fingerprint
    else:
        campaign_payload["target_identity_status"] = "legacy_unversioned"
    if versioned:
        campaign_payload.update(
            {
                "campaign_schema_version": CAMPAIGN_SCHEMA_VERSION,
                "campaign_revision": campaign["campaign_revision"],
                "campaign_snapshot_hash": campaign["campaign_snapshot_hash"],
                "campaign_provenance_status": "pinned",
                "run_references": run_references,
            }
        )
    else:
        campaign_payload["campaign_provenance_status"] = "legacy_unpinned"
    payload = _safe_payload(campaign_payload)
    assert_benchmark_integrity(payload)
    return payload


def export_campaign(
    campaign: dict[str, Any], runs: list[dict[str, Any]], output_path: str | Path
) -> str:
    payload = build_campaign_export(campaign, runs)
    path = Path(output_path)
    _atomic_write(path, json.dumps(payload, indent=2) + "\n", replace=True)
    return str(path)


class Phase2CampaignStore:
    """Append-only pinned campaigns plus explicit legacy compatibility."""

    def __init__(
        self,
        directory: str | Path | None = None,
        *,
        run_store: Phase2RunStore | None = None,
    ) -> None:
        self.run_store = run_store or Phase2RunStore()
        self.directory = (
            Path(directory)
            if directory is not None
            else self.run_store.directory / "campaigns"
        )

    def campaign_path(self, name: str) -> Path:
        campaign_id, _ = _campaign_identity(name)
        return self.directory / f"{campaign_id}.json"

    def campaign_revision_path(self, name: str, revision: int) -> Path:
        campaign_id, _ = _campaign_identity(name)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("Campaign revision must be a positive integer.")
        return self.directory / f"{campaign_id}.revision_{revision}.json"

    def create(self, name: str, target: str) -> dict[str, Any]:
        campaign_id, display_name = _campaign_identity(name)
        path = self.campaign_path(campaign_id)
        if path.exists():
            raise FileExistsError(f"Campaign already exists: {campaign_id}.")
        now = _utc_timestamp()
        public_target, target_fingerprint = target_identity(target)
        campaign = self._versioned_manifest(
            {
                "campaign_id": campaign_id,
                "name": display_name,
                "target": public_target,
                "target_fingerprint": target_fingerprint,
                "created_at": now,
                "updated_at": now,
            },
            references=[],
            revision=1,
        )
        self._write_immutable(path, campaign)
        return campaign

    def load(self, name: str) -> dict[str, Any]:
        selected, revision = self._latest_campaign_path(name)
        if selected is None:
            raise FileNotFoundError(f"Campaign does not exist: {name}.")
        return self._load_path(name, selected, expected_revision=revision)

    def load_revision(self, name: str, revision: int) -> dict[str, Any]:
        """Load exactly one immutable campaign state without latest fallback."""

        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ValueError("Campaign revision must be a non-negative integer.")
        base = self.campaign_path(name)
        if revision == 0:
            payload = self._load_path(name, base, expected_revision=0)
            if payload.get("campaign_schema_version") is not None:
                raise FileNotFoundError("Campaign has no legacy revision zero.")
            return payload
        selected = self.campaign_revision_path(name, revision)
        if revision == 1 and base.exists():
            try:
                raw_base = json.loads(base.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("Stored campaign JSON is invalid.") from exc
            if (
                isinstance(raw_base, dict)
                and raw_base.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION
            ):
                selected = base
        if not selected.exists():
            raise FileNotFoundError(
                f"Stored campaign revision does not exist: {name}@{revision}."
            )
        return self._load_path(name, selected, expected_revision=revision)

    def _load_path(
        self,
        name: str,
        path: Path,
        *,
        expected_revision: int,
    ) -> dict[str, Any]:
        expected_id, _ = _campaign_identity(name)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Stored campaign must be a JSON object.")
        if payload.get("campaign_id") != expected_id:
            raise ValueError("Stored campaign ID does not match its filename.")
        if payload.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION:
            validated = _validated_campaign_v2(payload)
            if validated["campaign_revision"] != expected_revision:
                raise ValueError("Stored campaign revision metadata is inconsistent.")
            return validated
        if expected_revision != 0:
            raise ValueError("Versioned campaign revision is missing its schema.")
        required = {
            "campaign_id",
            "name",
            "target",
            "run_ids",
            "created_at",
            "updated_at",
        }
        if not required <= payload.keys():
            raise ValueError("Stored campaign is missing required fields.")
        run_ids = payload.get("run_ids")
        if not isinstance(run_ids, list) or any(
            not isinstance(item, str) for item in run_ids
        ):
            raise ValueError("Stored campaign run_ids must be a list of strings.")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("Stored campaign contains duplicate run IDs.")
        canonical_target(str(payload.get("target") or ""))
        if payload.get("target_fingerprint") is not None:
            validate_target_fingerprint(payload["target_fingerprint"])
        assert_benchmark_integrity(payload)
        legacy = public_result(payload)
        if not isinstance(legacy, dict):
            raise ValueError("Legacy campaign must normalize to an object.")
        legacy["campaign_provenance_status"] = "legacy_unpinned"
        return legacy

    def _latest_campaign_path(self, name: str) -> tuple[Path | None, int]:
        campaign_id, _ = _campaign_identity(name)
        candidates: list[tuple[int, Path]] = []
        base = self.campaign_path(campaign_id)
        if base.exists():
            try:
                payload = json.loads(base.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("Stored campaign JSON is invalid.") from exc
            base_revision = (
                payload.get("campaign_revision")
                if isinstance(payload, dict)
                and payload.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION
                else 0
            )
            if not isinstance(base_revision, int) or isinstance(base_revision, bool):
                raise ValueError("Stored campaign revision metadata is invalid.")
            candidates.append((base_revision, base))
        for path in self.directory.glob(f"{campaign_id}.revision_*.json"):
            match = _CAMPAIGN_REVISION_PATTERN.fullmatch(path.name)
            if match and match.group("campaign") == campaign_id:
                candidates.append((int(match.group("revision")), path))
        revision, selected = max(
            candidates, default=(-1, None), key=lambda item: item[0]
        )
        return selected, revision

    def validate_target(self, name: str, target: str) -> dict[str, Any]:
        campaign = self.load(name)
        public_target, fingerprint = target_identity(target)
        if not _target_matches(
            str(campaign["target"]),
            campaign.get("target_fingerprint"),
            public_target,
            fingerprint,
        ):
            raise ValueError("Campaign target does not match the assessment target.")
        return campaign

    def add_run(self, name: str, run_id: str) -> dict[str, Any]:
        campaign = self.load(name)
        if run_id in campaign["run_ids"]:
            raise ValueError(
                "Campaign already contains that run; use refresh-run to adopt newer evidence."
            )
        if campaign.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION:
            reference, run = self._latest_reference(run_id)
            self._require_exact_target(campaign["target_fingerprint"], run)
            references = [*campaign["run_references"], reference]
            revision = campaign["campaign_revision"] + 1
            target_fingerprint = campaign["target_fingerprint"]
        else:
            references, target_fingerprint = self._pin_legacy_members(
                campaign,
                [*campaign["run_ids"], run_id],
            )
            revision = 1
        updated = self._versioned_manifest(
            campaign,
            references=references,
            revision=revision,
            target_fingerprint=target_fingerprint,
        )
        self._write_immutable(self.campaign_revision_path(name, revision), updated)
        return updated

    def refresh_run(self, name: str, run_id: str) -> dict[str, Any]:
        """Explicitly adopt current run evidence in a new campaign revision."""

        campaign = self.load(name)
        if run_id not in campaign["run_ids"]:
            raise ValueError("Campaign does not contain that run.")
        if campaign.get("campaign_schema_version") != CAMPAIGN_SCHEMA_VERSION:
            references, target_fingerprint = self._pin_legacy_members(
                campaign,
                list(campaign["run_ids"]),
            )
            revision = 1
        else:
            replacement, run = self._latest_reference(run_id)
            self._require_exact_target(campaign["target_fingerprint"], run)
            references = list(campaign["run_references"])
            index = campaign["run_ids"].index(run_id)
            if references[index] == replacement:
                raise ValueError("Campaign already pins the latest run revision.")
            references[index] = replacement
            target_fingerprint = campaign["target_fingerprint"]
            revision = campaign["campaign_revision"] + 1
        updated = self._versioned_manifest(
            campaign,
            references=references,
            revision=revision,
            target_fingerprint=target_fingerprint,
        )
        self._write_immutable(self.campaign_revision_path(name, revision), updated)
        return updated

    def resolve(self, name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        campaign = self.load(name)
        return campaign, self._resolve_campaign(campaign)

    def resolve_revision(
        self, name: str, revision: int
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        campaign = self.load_revision(name, revision)
        return campaign, self._resolve_campaign(campaign)

    def _resolve_campaign(self, campaign: dict[str, Any]) -> list[dict[str, Any]]:
        if campaign.get("campaign_schema_version") == CAMPAIGN_SCHEMA_VERSION:
            runs = []
            for raw_reference in campaign["run_references"]:
                reference = CampaignRunReference.model_validate(raw_reference)
                run = self.run_store.load_revision(
                    reference.run_id,
                    reference.revision,
                )
                if run_snapshot_hash(run) != reference.run_snapshot_hash:
                    raise ValueError(
                        "Pinned run snapshot hash does not match stored content."
                    )
                self._require_exact_target(campaign["target_fingerprint"], run)
                if run["target_fingerprint"] != reference.target_fingerprint:
                    raise ValueError(
                        "Pinned run target fingerprint does not match its campaign pin."
                    )
                runs.append(run)
        else:
            # Compatibility only: legacy manifests never claimed immutable pins.
            runs = [self.run_store.load_run(run_id) for run_id in campaign["run_ids"]]
        target = campaign["target"]
        if any(
            not _target_matches(
                str(target),
                campaign.get("target_fingerprint"),
                str(run.get("target") or ""),
                run.get("target_fingerprint"),
            )
            for run in runs
        ):
            raise ValueError("Campaign cannot combine runs from different targets.")
        return runs

    def show(self, name: str) -> dict[str, Any]:
        campaign, _ = self.resolve(name)
        return campaign

    def export(self, name: str, output_path: str | Path) -> str:
        campaign, runs = self.resolve(name)
        return export_campaign(campaign, runs, output_path)

    def export_revision(
        self,
        name: str,
        revision: int,
        output_path: str | Path,
    ) -> str:
        campaign, runs = self.resolve_revision(name, revision)
        return export_campaign(campaign, runs, output_path)

    def _latest_reference(self, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        revision, run = self.run_store.load_latest_revision(run_id)
        fingerprint = validate_target_fingerprint(run.get("target_fingerprint"))
        reference = CampaignRunReference(
            run_id=str(run["run_id"]),
            revision=revision,
            run_snapshot_hash=run_snapshot_hash(run),
            target_fingerprint=fingerprint,
        ).model_dump(mode="json")
        return reference, run

    def _pin_legacy_members(
        self,
        campaign: dict[str, Any],
        run_ids: list[str],
    ) -> tuple[list[dict[str, Any]], str]:
        references: list[dict[str, Any]] = []
        expected_fingerprint = campaign.get("target_fingerprint")
        if expected_fingerprint is not None:
            expected_fingerprint = validate_target_fingerprint(expected_fingerprint)
        for run_id in run_ids:
            reference, run = self._latest_reference(run_id)
            if canonical_target(str(run.get("target") or "")) != canonical_target(
                str(campaign["target"])
            ):
                raise ValueError("Campaign cannot combine runs from different targets.")
            if expected_fingerprint is None:
                expected_fingerprint = reference["target_fingerprint"]
            self._require_exact_target(expected_fingerprint, run)
            references.append(reference)
        if expected_fingerprint is None:
            raise ValueError("Pinned campaigns require an exact target fingerprint.")
        return references, expected_fingerprint

    @staticmethod
    def _require_exact_target(expected_fingerprint: Any, run: dict[str, Any]) -> None:
        expected = validate_target_fingerprint(expected_fingerprint)
        actual = validate_target_fingerprint(run.get("target_fingerprint"))
        if actual != expected:
            raise ValueError("Campaign cannot combine runs from different targets.")

    @staticmethod
    def _versioned_manifest(
        campaign: dict[str, Any],
        *,
        references: list[dict[str, Any]],
        revision: int,
        target_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        fingerprint = validate_target_fingerprint(
            target_fingerprint or campaign.get("target_fingerprint")
        )
        payload = {
            "campaign_schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": str(campaign["campaign_id"]),
            "campaign_revision": revision,
            "campaign_snapshot_hash": "sha256:" + "0" * 64,
            "campaign_provenance_status": "pinned",
            "name": str(campaign["name"]),
            "target": str(campaign["target"]),
            "target_fingerprint": fingerprint,
            "run_ids": [item["run_id"] for item in references],
            "run_references": references,
            "created_at": str(campaign["created_at"]),
            "updated_at": (
                str(campaign["updated_at"])
                if revision == 1 and not references
                else _utc_timestamp()
            ),
        }
        payload["campaign_snapshot_hash"] = campaign_snapshot_hash(payload)
        return _validated_campaign_v2(payload)

    @staticmethod
    def _write_immutable(path: Path, campaign: dict[str, Any]) -> None:
        payload = _validated_campaign_v2(campaign)
        assert_benchmark_integrity(payload)
        _atomic_write(
            path,
            json.dumps(payload, indent=2) + "\n",
            replace=False,
        )
