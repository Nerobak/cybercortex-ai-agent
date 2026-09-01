"""Persistent SQLite attack-surface graph.

Only normalized, redacted metadata is stored. Credentials, request bodies, and
raw responses are intentionally excluded from this database.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator, Literal
from urllib.parse import parse_qsl, urlparse, urlunparse

from agent_core.auth_semantics import (
    discover_auth_semantics,
    safe_auth_semantic_summary,
)
from agent_core.result_normalizer import redact
from agent_core.route_identity import normalize_route_path, route_identity
from agent_core.agent_models import StrictModel
from pydantic import Field

DEFAULT_SURFACE_DB = Path("memory/attack_surface.sqlite3")


class SurfaceEvidence(StrictModel):
    """Secret-safe provenance for one attack-surface observation."""

    source: str
    confidence: Literal["low", "medium", "high"] = "medium"
    reference: str | None = None
    observed: bool = True
    limitation: str | None = None


class CanonicalAttackSurface(StrictModel):
    """Canonical Phase 2 input assembled only from observed evidence.

    Schema-derived entries remain observations; this model deliberately has no
    vulnerability or runtime-behavior fields.
    """

    target: str
    routes: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    parameters: list[dict[str, Any]] = Field(default_factory=list, max_length=10000)
    objects: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    auth_boundaries: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    graphql: dict[str, Any] = Field(default_factory=dict)
    jwt: dict[str, Any] = Field(default_factory=dict)
    uploads: dict[str, Any] = Field(default_factory=dict)
    workflows: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    captured_requests: list[dict[str, Any]] = Field(
        default_factory=list, max_length=5000
    )
    response_summaries: list[dict[str, Any]] = Field(
        default_factory=list, max_length=5000
    )
    evidence_sources: list[SurfaceEvidence] = Field(
        default_factory=list, max_length=1000
    )
    limitations: list[str] = Field(default_factory=list, max_length=1000)


def _deduplicate(
    items: list[dict[str, Any]], fields: tuple[str, ...]
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = tuple(str(item.get(field) or "") for field in fields)
        if key in seen:
            continue
        seen.add(key)
        output.append(redact(item))
    return output


def build_canonical_attack_surface(
    target: str,
    *,
    assessment: dict[str, Any] | None = None,
    capture_bundle: Any | None = None,
) -> CanonicalAttackSurface:
    """Normalize scan output and/or a sanitized capture into one surface model."""
    routes: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    boundaries: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    sources: list[SurfaceEvidence] = []
    limitations: list[str] = []
    graphql: dict[str, Any] = {}
    jwt: dict[str, Any] = {}
    uploads: dict[str, Any] = {}

    if isinstance(assessment, dict):
        package = assessment.get("evidence_package") or assessment
        observed = package.get("observed_surface") or {}
        attack = observed.get("attack_surface") or {}
        routes.extend(attack.get("routes") or [])
        parameters.extend(attack.get("parameters") or observed.get("parameters") or [])
        objects.extend(attack.get("objects") or observed.get("objects") or [])
        boundaries.extend(attack.get("authentication_boundaries") or [])
        graphql = redact(observed.get("graphql") or {})
        jwt = redact(observed.get("jwt") or {})
        uploads = redact(observed.get("upload") or {})
        business = observed.get("business_logic") or {}
        workflows.extend(business.get("workflows") or [])
        source_map = attack.get("sources") or {}
        if isinstance(source_map, dict):
            for name in sorted(source_map):
                sources.append(
                    SurfaceEvidence(source=str(name), reference=str(source_map[name]))
                )
        sources.append(
            SurfaceEvidence(source="assessment", reference="evidence_package")
        )
        coverage = package.get("coverage") or assessment.get("coverage") or {}
        for name in coverage.get("failed_tools", []) or []:
            limitations.append(f"Tool did not complete: {name}")
        for name in coverage.get("timed_out_tools", []) or []:
            limitations.append(f"Tool timed out: {name}")

    if capture_bundle is not None:
        for request in getattr(capture_bundle, "requests", []) or []:
            request_ref = str(getattr(request, "request_id", ""))
            route = {
                "method": str(getattr(request, "method", "GET")).upper(),
                "path": str(getattr(request, "path", "/")),
                "url": str(getattr(request, "url", target)),
                "source": getattr(request, "source_format", "capture"),
                "confidence": "high",
                "evidence_refs": [request_ref] if request_ref else [],
                "request_body_fields": [],
            }
            for parameter in getattr(request, "parameters", []) or []:
                entry = {
                    "name": getattr(parameter, "name", ""),
                    "in": getattr(parameter, "location", "unknown"),
                    "path": route["path"],
                    "method": route["method"],
                    "schema_type": getattr(parameter, "value_type", "unknown"),
                    "source": getattr(request, "source_format", "capture"),
                    "confidence": "high",
                    "evidence_refs": [request_ref] if request_ref else [],
                }
                parameters.append(entry)
                if entry["in"] in {"json", "form", "multipart", "graphql_variable"}:
                    route["request_body_fields"].append(entry)
            routes.append(route)
            identity_id = getattr(request, "identity_id", None)
            headers = getattr(request, "headers", {}) or {}
            if identity_id or any(
                str(key).lower() == "authorization" for key in headers
            ):
                boundaries.append(
                    {
                        "path": route["path"],
                        "method": route["method"],
                        "authenticated_observation": True,
                        "source": "captured_request",
                        "evidence_refs": [request_ref] if request_ref else [],
                    }
                )
            request_summary = {
                "request_id": request_ref,
                "method": route["method"],
                "url": route["url"],
                "identity_context_present": bool(identity_id),
                "state_changing": bool(getattr(request, "state_changing", False)),
            }
            requests.append(request_summary)
            response = getattr(request, "response", None)
            if response is not None:
                responses.append(
                    {
                        "request_id": request_ref,
                        "status_code": getattr(response, "status_code", None),
                        "content_type": getattr(response, "content_type", None),
                        "body_size": getattr(response, "body_size", None),
                        "schema_fields": list(
                            getattr(response, "schema_fields", []) or []
                        ),
                        "sets_cookie": bool(getattr(response, "sets_cookie", False)),
                    }
                )
            if getattr(request, "graphql_operation", None):
                graphql.setdefault("operations", []).append(
                    {
                        "name": request.graphql_operation,
                        "type": getattr(request, "graphql_operation_type", None),
                        "path": route["path"],
                        "evidence_refs": [request_ref] if request_ref else [],
                    }
                )
            if getattr(request, "state_changing", False):
                workflows.append(
                    {
                        "path": route["path"],
                        "method": route["method"],
                        "state_changing": True,
                        "source": "captured_request",
                        "evidence_refs": [request_ref] if request_ref else [],
                    }
                )
        for obj in getattr(capture_bundle, "objects", []) or []:
            objects.append(redact(obj.model_dump(mode="json")))
        sources.append(
            SurfaceEvidence(
                source=f"capture:{getattr(capture_bundle, 'source_format', 'unknown')}",
                reference=str(getattr(capture_bundle, "source_ref", "capture")),
                confidence="high",
            )
        )

    normalized_routes: list[dict[str, Any]] = []
    seen_route_identities: set[tuple[str, str]] = set()
    for raw_route in routes:
        if not isinstance(raw_route, dict):
            continue
        route = {
            **raw_route,
            "method": str(raw_route.get("method") or "GET").upper(),
            "path": normalize_route_path(
                raw_route.get("path") or raw_route.get("url") or "/"
            ),
        }
        identity = route_identity(route)
        if identity in seen_route_identities:
            continue
        seen_route_identities.add(identity)
        normalized_routes.append(redact(route))
    for route in normalized_routes:
        if route.get("summary"):
            route["summary"] = safe_auth_semantic_summary(route["summary"])
        route_limitations = route.get("limitations")
        if isinstance(route_limitations, list):
            limitations.extend(
                str(item) for item in route_limitations if isinstance(item, str)
            )
    normalized_parameters = _deduplicate(
        parameters, ("method", "path", "in", "name", "field_path")
    )
    normalized_boundaries, auth_workflows = discover_auth_semantics(
        normalized_routes,
        normalized_parameters,
        boundaries,
    )
    workflows.extend(auth_workflows)
    if normalized_boundaries:
        limitations.append(
            "Authentication semantics are metadata-derived observations; runtime enforcement was not tested."
        )

    return CanonicalAttackSurface(
        target=target,
        routes=normalized_routes,
        parameters=normalized_parameters,
        objects=_deduplicate(objects, ("object_id", "identifier", "path", "type")),
        auth_boundaries=_deduplicate(
            normalized_boundaries, ("method", "path", "boundary_type")
        ),
        graphql=graphql,
        jwt=jwt,
        uploads=uploads,
        workflows=_deduplicate(
            workflows,
            ("workflow_id", "method", "path", "name", "workflow_type"),
        ),
        captured_requests=requests,
        response_summaries=responses,
        evidence_sources=sources,
        limitations=sorted(set(limitations)),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _node_id(kind: str, canonical_key: str) -> str:
    return sha256(f"{kind}\x1f{canonical_key}".encode()).hexdigest()


class AttackSurfaceGraph:
    def __init__(self, database: str | Path = DEFAULT_SURFACE_DB) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT,
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    canonical_key TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    first_run_id TEXT,
                    last_run_id TEXT,
                    UNIQUE(kind, canonical_key)
                );
                CREATE TABLE IF NOT EXISTS edges (
                    edge_id TEXT PRIMARY KEY,
                    source_node_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    target_node_id TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_run_id TEXT,
                    UNIQUE(source_node_id, relation, target_node_id),
                    FOREIGN KEY(source_node_id) REFERENCES nodes(node_id),
                    FOREIGN KEY(target_node_id) REFERENCES nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    node_id TEXT,
                    source TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    UNIQUE(run_id, source, fingerprint)
                );
                CREATE TABLE IF NOT EXISTS hypotheses (
                    hypothesis_id TEXT PRIMARY KEY,
                    target_node_id TEXT,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    data_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_run_id TEXT
                );
                CREATE TABLE IF NOT EXISTS node_versions (
                    node_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    data_hash TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY(node_id, run_id),
                    FOREIGN KEY(node_id) REFERENCES nodes(node_id)
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
                CREATE INDEX IF NOT EXISTS idx_nodes_last_run ON nodes(last_run_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);
                CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);
                """)

    def start_run(self, run_id: str, target: str, profile: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO runs(run_id,target,profile,started_at,summary_json) VALUES(?,?,?,?,?)",
                (run_id, target, profile, _now(), "{}"),
            )

    def finish_run(self, run_id: str, status: str, summary: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE runs SET completed_at=?, status=?, summary_json=? WHERE run_id=?",
                (_now(), status, json.dumps(redact(summary), sort_keys=True), run_id),
            )

    def upsert_node(
        self,
        kind: str,
        canonical_key: str,
        data: dict[str, Any],
        *,
        run_id: str | None = None,
    ) -> str:
        node_id = _node_id(kind, canonical_key)
        sanitized = json.dumps(redact(data), sort_keys=True)
        data_hash = sha256(sanitized.encode()).hexdigest()
        now = _now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO nodes(node_id,kind,canonical_key,data_json,first_seen,last_seen,first_run_id,last_run_id)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(node_id) DO UPDATE SET
                    data_json=excluded.data_json,
                    last_seen=excluded.last_seen,
                    last_run_id=excluded.last_run_id
                """,
                (node_id, kind, canonical_key, sanitized, now, now, run_id, run_id),
            )
            if run_id:
                connection.execute(
                    """
                    INSERT INTO node_versions(node_id,run_id,data_hash,observed_at)
                    VALUES(?,?,?,?)
                    ON CONFLICT(node_id,run_id) DO UPDATE SET
                        data_hash=excluded.data_hash,
                        observed_at=excluded.observed_at
                    """,
                    (node_id, run_id, data_hash, now),
                )
        return node_id

    def add_edge(
        self,
        source_node_id: str,
        relation: str,
        target_node_id: str,
        data: dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
    ) -> str:
        edge_id = sha256(
            f"{source_node_id}\x1f{relation}\x1f{target_node_id}".encode()
        ).hexdigest()
        now = _now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO edges(edge_id,source_node_id,relation,target_node_id,data_json,first_seen,last_seen,last_run_id)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    data_json=excluded.data_json,
                    last_seen=excluded.last_seen,
                    last_run_id=excluded.last_run_id
                """,
                (
                    edge_id,
                    source_node_id,
                    relation,
                    target_node_id,
                    json.dumps(redact(data or {}), sort_keys=True),
                    now,
                    now,
                    run_id,
                ),
            )
        return edge_id

    def add_evidence(
        self,
        run_id: str,
        source: str,
        kind: str,
        data: dict[str, Any],
        *,
        node_id: str | None = None,
    ) -> str:
        sanitized = redact(data)
        serialized = json.dumps(sanitized, sort_keys=True)
        fingerprint = sha256(serialized.encode()).hexdigest()
        evidence_id = sha256(
            f"{run_id}\x1f{source}\x1f{fingerprint}".encode()
        ).hexdigest()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO evidence(evidence_id,run_id,node_id,source,kind,fingerprint,data_json,observed_at)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    evidence_id,
                    run_id,
                    node_id,
                    source,
                    kind,
                    fingerprint,
                    serialized,
                    _now(),
                ),
            )
        return evidence_id

    def record_hypothesis(self, hypothesis: dict[str, Any], run_id: str) -> None:
        now = _now()
        endpoint = hypothesis.get("endpoint") or hypothesis.get("target")
        target_node = (
            _node_id("endpoint", _canonical_url(endpoint)) if endpoint else None
        )
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO hypotheses(hypothesis_id,target_node_id,status,priority,data_json,first_seen,last_seen,last_run_id)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(hypothesis_id) DO UPDATE SET
                    status=excluded.status,
                    priority=excluded.priority,
                    data_json=excluded.data_json,
                    last_seen=excluded.last_seen,
                    last_run_id=excluded.last_run_id
                """,
                (
                    hypothesis["hypothesis_id"],
                    target_node,
                    hypothesis.get("status", "proposed"),
                    int(hypothesis.get("priority", 0)),
                    json.dumps(redact(hypothesis), sort_keys=True),
                    now,
                    now,
                    run_id,
                ),
            )

    def ingest_assessment(self, run_id: str, result: dict[str, Any]) -> dict[str, int]:
        target = str(result.get("target") or "")
        target_url = _canonical_url(target) if target else target
        asset = self.upsert_node(
            "asset", target_url, {"url": target_url}, run_id=run_id
        )
        urls = (result.get("normalized_urls") or {}).get("all_urls", [])
        endpoint_count = parameter_count = evidence_count = 0
        for raw_url in urls:
            if not isinstance(raw_url, str):
                continue
            url = _canonical_url(raw_url)
            parsed = urlparse(url)
            endpoint = self.upsert_node(
                "endpoint",
                url,
                {
                    "url": url,
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                    "path": parsed.path or "/",
                },
                run_id=run_id,
            )
            self.add_edge(asset, "exposes", endpoint, run_id=run_id)
            endpoint_count += 1
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                parameter = self.upsert_node(
                    "parameter",
                    f"{url}\x1fquery\x1f{name}",
                    {"name": name, "location": "query", "endpoint": url},
                    run_id=run_id,
                )
                self.add_edge(endpoint, "accepts", parameter, run_id=run_id)
                parameter_count += 1
        package = result.get("evidence_package") or {}
        technologies = (
            ((result.get("results") or {}).get("tech_fingerprint") or {})
            .get("output", {})
            .get("technologies", [])
        )
        for technology in technologies if isinstance(technologies, list) else []:
            if isinstance(technology, str) and technology:
                technology_node = self.upsert_node(
                    "technology",
                    technology,
                    {"name": technology},
                    run_id=run_id,
                )
                self.add_edge(asset, "uses", technology_node, run_id=run_id)
        for section in (
            "observations",
            "candidate_findings",
            "manual_verification_queue",
            "verified_findings",
        ):
            for item in package.get(section, []) if isinstance(package, dict) else []:
                if not isinstance(item, dict):
                    continue
                endpoint_url = item.get("endpoint")
                node_id = (
                    self.upsert_node(
                        "endpoint",
                        _canonical_url(endpoint_url),
                        {"url": _canonical_url(endpoint_url)},
                        run_id=run_id,
                    )
                    if isinstance(endpoint_url, str) and endpoint_url
                    else asset
                )
                self.add_evidence(
                    run_id,
                    str(item.get("source_tool") or "normalizer"),
                    section,
                    item,
                    node_id=node_id,
                )
                evidence_count += 1
        return {
            "assets": 1,
            "endpoints": endpoint_count,
            "parameters": parameter_count,
            "evidence": evidence_count,
        }

    def snapshot(self, target: str | None = None) -> dict[str, Any]:
        with self.connect() as connection:
            node_rows = connection.execute(
                "SELECT kind, COUNT(*) AS count FROM nodes GROUP BY kind"
            ).fetchall()
            edge_count = connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence"
            ).fetchone()[0]
            hypotheses = connection.execute(
                "SELECT status, COUNT(*) AS count FROM hypotheses GROUP BY status"
            ).fetchall()
            latest_run = (
                connection.execute(
                    "SELECT run_id, completed_at FROM runs WHERE target=? ORDER BY started_at DESC LIMIT 1",
                    (target,),
                ).fetchone()
                if target
                else None
            )
        payload = {
            "node_counts": {row["kind"]: row["count"] for row in node_rows},
            "edge_count": edge_count,
            "evidence_count": evidence_count,
            "hypothesis_counts": {row["status"]: row["count"] for row in hypotheses},
        }
        if latest_run:
            payload["latest_run_id"] = latest_run["run_id"]
            payload["latest_run_completed_at"] = latest_run["completed_at"]
        payload["surface_version"] = sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()[:16]
        return payload

    def changed_nodes(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT n.node_id,n.kind,n.canonical_key,n.data_json,n.first_run_id,
                       current.data_hash,
                       (
                           SELECT prior.data_hash
                           FROM node_versions prior
                           WHERE prior.node_id=n.node_id AND prior.run_id<>?
                           ORDER BY prior.observed_at DESC LIMIT 1
                       ) AS previous_hash
                FROM nodes n
                JOIN node_versions current ON current.node_id=n.node_id AND current.run_id=?
                WHERE n.last_run_id=?
                """,
                (run_id, run_id, run_id),
            ).fetchall()
        return [
            {
                "node_id": row["node_id"],
                "kind": row["kind"],
                "canonical_key": row["canonical_key"],
                "is_new": row["first_run_id"] == run_id,
                "is_changed": bool(
                    row["previous_hash"] and row["previous_hash"] != row["data_hash"]
                ),
                "data": json.loads(row["data_json"]),
            }
            for row in rows
        ]

    def get_hypothesis(self, hypothesis_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT status,priority,data_json,last_run_id FROM hypotheses WHERE hypothesis_id=?",
                (hypothesis_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "status": row["status"],
            "priority": row["priority"],
            "data": json.loads(row["data_json"]),
            "last_run_id": row["last_run_id"],
        }
