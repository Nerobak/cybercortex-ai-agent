"""Atomic, revisioned SQLite persistence for Phase 4 research state."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal

from pydantic import Field, StrictInt

from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.request_budget import RequestDelta, canonical_result_request_total
from agent_core.research.events import (
    RESEARCH_EVENT_SCHEMA_VERSION,
    ResearchEvent,
    ResearchEventType,
    ResearchStartedPayload,
)
from agent_core.research.graph import (
    GRAPH_ASSERTION_SCHEMA_VERSION,
    MAX_GRAPH_ASSERTIONS_PER_COMMIT,
    MAX_GRAPH_QUERY_RESULTS,
    GraphAssertion,
    GraphRelation,
)
from agent_core.research.migrations import (
    DEFAULT_MIGRATIONS,
    RESEARCH_STORE_SCHEMA_VERSION,
    MigrationRegistry,
    UnsupportedResearchSchemaVersion,
    validate_schema_version,
)
from agent_core.research.provenance import (
    build_provenance_record,
    reject_secret_material,
)
from agent_core.research.state import (
    EvidenceArtifact,
    ExperimentOutcome,
    Fact,
    HypothesisRecord,
    ProvenanceRecord,
    ResearchState,
    TargetAsset,
    canonical_research_state_bytes,
    research_state_hash,
)
from agent_core.research.types import (
    CleanupStatus,
    DerivationType,
    EntityKind,
    EvidenceKind,
    ExperimentRuntimeStatus,
    FactStatus,
    HypothesisResearchStatus,
    MetadataEntry,
    ProvenanceProducerType,
    PublicMetadata,
    ResearchConfidence,
    ResearchContract,
    ResearchPredicate,
    ResearchRunStatus,
    RelationshipStatus,
    TargetClass,
)

DEFAULT_RESEARCH_DATABASE = Path("memory/research.sqlite3")
MAX_EVENTS_PER_COMMIT = 100
MAX_RESEARCH_STATE_BYTES = 25_000_000
MAX_RESEARCH_RUN_LIST = 1_000


class ResearchStoreError(RuntimeError):
    """Base error for persistent Phase 4 research state."""


class ResearchNotFound(ResearchStoreError):
    pass


class ResearchAlreadyExists(ResearchStoreError):
    pass


class StaleResearchRevision(ResearchStoreError):
    pass


class ResearchIntegrityError(ResearchStoreError):
    pass


class OversizedResearchMutation(ResearchStoreError):
    pass


class ResearchRunSummary(ResearchContract):
    research_id: str = Field(min_length=1, max_length=255)
    current_revision: StrictInt = Field(ge=0)
    status: ResearchRunStatus
    state_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: str
    updated_at: str


class IntegrityReport(ResearchContract):
    valid: Literal[True] = True
    research_id: str
    current_revision: StrictInt = Field(ge=0)
    state_hash: str
    revision_count: StrictInt = Field(ge=1)
    event_count: StrictInt = Field(ge=0)
    assertion_version_count: StrictInt = Field(ge=0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _record_hash(serialized: str) -> str:
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _model_json(model: Any) -> str:
    return _canonical_json(model.model_dump(mode="json"))


def _commit_hash(
    *,
    research_id: str,
    revision: int,
    previous_state_hash: str | None,
    state_hash: str,
    event_hashes: Sequence[str],
    assertion_hashes: Sequence[str],
) -> str:
    return _record_hash(
        _canonical_json(
            {
                "assertion_hashes": list(assertion_hashes),
                "event_hashes": list(event_hashes),
                "previous_state_hash": previous_state_hash,
                "research_id": research_id,
                "revision": revision,
                "schema_version": RESEARCH_STORE_SCHEMA_VERSION,
                "state_hash": state_hash,
            }
        )
    )


def _opaque(value: object, prefix: str) -> str:
    rendered = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}", rendered):
        return rendered
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _bounded_public_text(value: object, fallback: str, limit: int = 1_000) -> str:
    rendered = str(value or "").strip() or fallback
    return rendered[:limit]


class ResearchStore:
    """Store canonical state snapshots and mutation records in one transaction."""

    def __init__(
        self,
        database: str | Path = DEFAULT_RESEARCH_DATABASE,
        *,
        migrations: MigrationRegistry = DEFAULT_MIGRATIONS,
    ) -> None:
        self.database = Path(database)
        self._connection_target = str(self.database)
        self._connection_is_uri = False
        self._memory_anchor: sqlite3.Connection | None = None
        if str(database) == ":memory:":
            self._connection_target = (
                f"file:cybercortex-research-{id(self)}?mode=memory&cache=shared"
            )
            self._connection_is_uri = True
            self._memory_anchor = sqlite3.connect(
                self._connection_target, uri=True, timeout=30.0
            )
        else:
            self.database.parent.mkdir(parents=True, exist_ok=True)
        self.migrations = migrations
        self._initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self._connection_target,
            timeout=30.0,
            uri=self._connection_is_uri,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
        finally:
            connection.close()

    def close(self) -> None:
        """Compatibility hook; connections are scoped to individual operations."""

        if self._memory_anchor is not None:
            self._memory_anchor.close()
            self._memory_anchor = None

    def __enter__(self) -> "ResearchStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            schema_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='research_schema'"
            ).fetchone()
            if schema_exists:
                row = connection.execute(
                    "SELECT schema_version FROM research_schema WHERE singleton = 1"
                ).fetchone()
                if row is None:
                    raise UnsupportedResearchSchemaVersion(
                        "research schema metadata is missing"
                    )
                version = validate_schema_version(row["schema_version"])
                if version < RESEARCH_STORE_SCHEMA_VERSION:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self.migrations.migrate(
                            connection, version, RESEARCH_STORE_SCHEMA_VERSION
                        )
                        connection.commit()
                    except Exception:
                        connection.rollback()
                        raise
                self._verify_schema_objects(connection)
                return

            existing = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'research_%'"
            ).fetchall()
            if existing:
                raise UnsupportedResearchSchemaVersion(
                    "unversioned research tables cannot be migrated safely"
                )
            connection.executescript("""
                CREATE TABLE research_schema (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE research_runs (
                    research_id TEXT PRIMARY KEY,
                    current_revision INTEGER NOT NULL CHECK(current_revision >= 0),
                    current_state_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE research_revisions (
                    research_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision >= 0),
                    schema_version INTEGER NOT NULL,
                    previous_state_hash TEXT,
                    state_hash TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    event_count INTEGER NOT NULL CHECK(event_count >= 0),
                    assertion_count INTEGER NOT NULL CHECK(assertion_count >= 0),
                    commit_hash TEXT NOT NULL,
                    committed_at TEXT NOT NULL,
                    PRIMARY KEY(research_id, revision),
                    FOREIGN KEY(research_id) REFERENCES research_runs(research_id)
                );
                CREATE TABLE research_events (
                    event_id TEXT PRIMARY KEY,
                    research_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    event_order INTEGER NOT NULL CHECK(event_order >= 0),
                    event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1),
                    schema_version INTEGER NOT NULL,
                    event_hash TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    UNIQUE(research_id, revision, event_order),
                    UNIQUE(research_id, event_sequence),
                    FOREIGN KEY(research_id, revision)
                        REFERENCES research_revisions(research_id, revision)
                );
                CREATE TABLE research_graph_assertions (
                    research_id TEXT NOT NULL,
                    assertion_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL,
                    source_id TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assertion_hash TEXT NOT NULL,
                    assertion_json TEXT NOT NULL,
                    PRIMARY KEY(research_id, assertion_id, revision),
                    FOREIGN KEY(research_id, revision)
                        REFERENCES research_revisions(research_id, revision)
                );
                CREATE TABLE research_phase2_imports (
                    source_run_id TEXT NOT NULL,
                    source_revision INTEGER NOT NULL CHECK(source_revision >= 1),
                    source_hash TEXT NOT NULL,
                    research_id TEXT NOT NULL UNIQUE,
                    imported_revision INTEGER NOT NULL CHECK(imported_revision >= 0),
                    imported_at TEXT NOT NULL,
                    PRIMARY KEY(source_run_id, source_revision),
                    FOREIGN KEY(research_id, imported_revision)
                        REFERENCES research_revisions(research_id, revision)
                );
                CREATE INDEX idx_research_events_revision
                    ON research_events(research_id, revision, event_order);
                CREATE INDEX idx_research_assertions_source
                    ON research_graph_assertions(research_id, source_id, relation);
                CREATE INDEX idx_research_assertions_target
                    ON research_graph_assertions(research_id, target_id, relation);
                """)
            connection.execute(
                "INSERT INTO research_schema(singleton, schema_version, created_at) "
                "VALUES(1, ?, ?)",
                (RESEARCH_STORE_SCHEMA_VERSION, _utc_now()),
            )
            connection.execute(f"PRAGMA user_version = {RESEARCH_STORE_SCHEMA_VERSION}")
            connection.commit()

    @staticmethod
    def _verify_schema_objects(connection: sqlite3.Connection) -> None:
        required = {
            "research_runs",
            "research_revisions",
            "research_events",
            "research_graph_assertions",
            "research_phase2_imports",
        }
        actual = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = required - actual
        if missing:
            raise UnsupportedResearchSchemaVersion(
                f"research schema is incomplete: {', '.join(sorted(missing))}"
            )

    @staticmethod
    def _validate_bounds(
        state: ResearchState,
        events: Sequence[ResearchEvent],
        assertions: Sequence[GraphAssertion],
    ) -> None:
        if len(events) > MAX_EVENTS_PER_COMMIT:
            raise OversizedResearchMutation("event limit per research commit exceeded")
        if len(assertions) > MAX_GRAPH_ASSERTIONS_PER_COMMIT:
            raise OversizedResearchMutation(
                "graph assertion limit per research commit exceeded"
            )
        if len(canonical_research_state_bytes(state)) > MAX_RESEARCH_STATE_BYTES:
            raise OversizedResearchMutation("canonical research state is too large")

    @staticmethod
    def _validate_records(
        state: ResearchState,
        events: Sequence[ResearchEvent],
        assertions: Sequence[GraphAssertion],
        revision: int,
    ) -> None:
        evidence_ids = {item.evidence_id for item in state.evidence}
        provenance_ids = {item.provenance_id for item in state.provenance}
        entity_ids = {
            EntityKind.target: {item.target_id for item in state.targets},
            EntityKind.surface: {item.surface_id for item in state.surfaces},
            EntityKind.endpoint: {item.endpoint_id for item in state.endpoints},
            EntityKind.parameter: {item.parameter_id for item in state.parameters},
            EntityKind.identity: {item.identity_id for item in state.identities},
            EntityKind.session: {item.session_ref_id for item in state.session_refs},
            EntityKind.token: {item.token_ref_id for item in state.token_refs},
            EntityKind.object: {item.object_id for item in state.objects},
            EntityKind.graphql_operation: {
                item.operation_id for item in state.graphql_operations
            },
            EntityKind.upload: {item.upload_id for item in state.uploads},
            EntityKind.workflow: {item.workflow_id for item in state.workflows},
            EntityKind.observation: {
                item.observation_id for item in state.observations
            },
            EntityKind.evidence: evidence_ids,
            EntityKind.fact: {item.fact_id for item in state.facts},
            EntityKind.hypothesis: {item.hypothesis_id for item in state.hypotheses},
            EntityKind.experiment_outcome: {
                item.outcome_id for item in state.experiment_outcomes
            },
            EntityKind.reproduction: {
                item.reproduction_id for item in state.reproduction_plans
            },
            EntityKind.finding: {item.finding_id for item in state.findings},
            EntityKind.attack_chain: {
                item.attack_chain_id for item in state.attack_chains
            },
        }
        budget_ids = {item.budget_reference for item in state.budgets}
        event_ids: set[str] = set()
        for event in events:
            if event.event_id in event_ids:
                raise ValueError("event IDs in a commit must be unique")
            event_ids.add(event.event_id)
            if event.research_id != state.research_id:
                raise ValueError("event research_id does not match state")
            if event.state_revision != revision:
                raise ValueError("event state revision does not match commit")
            if event.provenance_id not in provenance_ids:
                raise ValueError("event provenance is absent from canonical state")
            event_payload = event.payload
            referenced_ids: tuple[tuple[str, set[str], str], ...] = ()
            if event.event_type is ResearchEventType.research_started:
                referenced_ids = tuple(
                    (item, entity_ids[EntityKind.target], "target")
                    for item in event_payload.target_ids
                )
            elif event.event_type is ResearchEventType.surface_observed:
                referenced_ids = (
                    (
                        event_payload.surface_id,
                        entity_ids[EntityKind.surface],
                        "surface",
                    ),
                )
            elif event.event_type is ResearchEventType.endpoint_observed:
                referenced_ids = (
                    (
                        event_payload.endpoint_id,
                        entity_ids[EntityKind.endpoint],
                        "endpoint",
                    ),
                    (
                        event_payload.surface_id,
                        entity_ids[EntityKind.surface],
                        "surface",
                    ),
                )
            elif event.event_type is ResearchEventType.observation_recorded:
                referenced_ids = (
                    (
                        event_payload.observation_id,
                        entity_ids[EntityKind.observation],
                        "observation",
                    ),
                )
            elif event.event_type in {
                ResearchEventType.fact_proposed,
                ResearchEventType.fact_confirmed,
            }:
                referenced_ids = (
                    (event_payload.fact_id, entity_ids[EntityKind.fact], "fact"),
                )
            elif event.event_type in {
                ResearchEventType.hypothesis_created,
                ResearchEventType.hypothesis_status_changed,
            }:
                referenced_ids = (
                    (
                        event_payload.hypothesis_id,
                        entity_ids[EntityKind.hypothesis],
                        "hypothesis",
                    ),
                )
            elif event.event_type is ResearchEventType.experiment_outcome_recorded:
                referenced_ids = (
                    (
                        event_payload.outcome_id,
                        entity_ids[EntityKind.experiment_outcome],
                        "experiment outcome",
                    ),
                )
            elif event.event_type is ResearchEventType.finding_status_changed:
                referenced_ids = (
                    (
                        event_payload.finding_id,
                        entity_ids[EntityKind.finding],
                        "finding",
                    ),
                )
            elif event.event_type is ResearchEventType.reproduction_planned:
                referenced_ids = (
                    (
                        event_payload.reproduction_id,
                        entity_ids[EntityKind.reproduction],
                        "reproduction",
                    ),
                    (
                        event_payload.finding_id,
                        entity_ids[EntityKind.finding],
                        "finding",
                    ),
                )
            elif event.event_type is ResearchEventType.reproduction_outcome_recorded:
                referenced_ids = (
                    (
                        event_payload.reproduction_id,
                        entity_ids[EntityKind.reproduction],
                        "reproduction",
                    ),
                    (
                        event_payload.finding_id,
                        entity_ids[EntityKind.finding],
                        "finding",
                    ),
                    (
                        event_payload.outcome_id,
                        entity_ids[EntityKind.experiment_outcome],
                        "experiment outcome",
                    ),
                )
            elif event.event_type is ResearchEventType.finding_confirmation_decided:
                referenced_ids = (
                    (
                        event_payload.finding_id,
                        entity_ids[EntityKind.finding],
                        "finding",
                    ),
                    (
                        event_payload.decision_id,
                        {item.decision_id for item in state.confirmation_decisions},
                        "confirmation decision",
                    ),
                )
            elif event.event_type is ResearchEventType.budget_updated:
                referenced_ids = (
                    (event_payload.budget_reference, budget_ids, "budget"),
                )
            for reference, available, description in referenced_ids:
                if reference not in available:
                    raise ValueError(
                        f"event contains a dangling {description} reference"
                    )
        assertion_ids: set[str] = set()
        for assertion in assertions:
            if assertion.assertion_id in assertion_ids:
                raise ValueError("assertion IDs in a commit must be unique")
            assertion_ids.add(assertion.assertion_id)
            if assertion.research_id != state.research_id:
                raise ValueError("graph assertion research_id does not match state")
            if assertion.provenance_id not in provenance_ids:
                raise ValueError("graph assertion provenance is absent from state")
            missing_evidence = set(assertion.evidence_references) - evidence_ids
            if missing_evidence:
                raise ValueError(
                    "graph assertion contains dangling evidence references"
                )
            for reference in (assertion.source, assertion.target):
                if reference.entity_id not in entity_ids[reference.entity_kind]:
                    raise ValueError(
                        "graph assertion contains a dangling entity reference"
                    )
        reject_secret_material(state.model_dump(mode="json"), location="research state")
        for event in events:
            reject_secret_material(
                event.model_dump(mode="json"), location="research event"
            )
        for assertion in assertions:
            reject_secret_material(
                assertion.model_dump(mode="json"), location="graph assertion"
            )

    @staticmethod
    def _validate_assertion_lifecycle(
        connection: sqlite3.Connection,
        assertion: GraphAssertion,
        proposed_ids: set[str],
    ) -> None:
        row = connection.execute(
            "SELECT assertion_json FROM research_graph_assertions "
            "WHERE research_id=? AND assertion_id=? ORDER BY revision DESC LIMIT 1",
            (assertion.research_id, assertion.assertion_id),
        ).fetchone()
        if row is None:
            if assertion.status is RelationshipStatus.superseded:
                raise ValueError("a new graph assertion cannot begin superseded")
        else:
            previous = GraphAssertion.model_validate_json(row["assertion_json"])
            if (previous.source, previous.relation, previous.target) != (
                assertion.source,
                assertion.relation,
                assertion.target,
            ):
                raise ValueError("graph assertion identity cannot change")
            transitions = {
                RelationshipStatus.proposed: {
                    RelationshipStatus.observed,
                    RelationshipStatus.confirmed,
                    RelationshipStatus.rejected,
                    RelationshipStatus.superseded,
                },
                RelationshipStatus.observed: {
                    RelationshipStatus.confirmed,
                    RelationshipStatus.rejected,
                    RelationshipStatus.superseded,
                },
                RelationshipStatus.confirmed: {
                    RelationshipStatus.rejected,
                    RelationshipStatus.superseded,
                },
                RelationshipStatus.rejected: set(),
                RelationshipStatus.superseded: set(),
            }
            if assertion.status not in transitions[previous.status]:
                raise ValueError(
                    "invalid or duplicate graph assertion lifecycle change"
                )
        replacement = assertion.superseded_by_assertion_id
        if replacement is not None and replacement not in proposed_ids:
            exists = connection.execute(
                "SELECT 1 FROM research_graph_assertions "
                "WHERE research_id=? AND assertion_id=? LIMIT 1",
                (assertion.research_id, replacement),
            ).fetchone()
            if exists is None:
                raise ValueError("superseding graph assertion does not exist")

    def _insert_components(
        self,
        connection: sqlite3.Connection,
        *,
        research_id: str,
        revision: int,
        events: Sequence[ResearchEvent],
        assertions: Sequence[GraphAssertion],
    ) -> tuple[list[str], list[str]]:
        prior_events = connection.execute(
            "SELECT COUNT(*) FROM research_events WHERE research_id=?",
            (research_id,),
        ).fetchone()[0]
        event_hashes: list[str] = []
        for order, event in enumerate(events):
            serialized = _model_json(event)
            digest = _record_hash(serialized)
            connection.execute(
                "INSERT INTO research_events(event_id,research_id,revision,event_order,"
                "event_sequence,schema_version,event_hash,event_json) VALUES(?,?,?,?,?,?,?,?)",
                (
                    event.event_id,
                    research_id,
                    revision,
                    order,
                    prior_events + order + 1,
                    RESEARCH_EVENT_SCHEMA_VERSION,
                    digest,
                    serialized,
                ),
            )
            event_hashes.append(digest)
        assertion_hashes: list[str] = []
        proposed_ids = {item.assertion_id for item in assertions}
        for assertion in assertions:
            self._validate_assertion_lifecycle(connection, assertion, proposed_ids)
            assertion_hashes.append(
                self._insert_graph_assertion(
                    connection, research_id, revision, assertion
                )
            )
        return event_hashes, assertion_hashes

    @staticmethod
    def _current_graph_assertions(
        connection: sqlite3.Connection, research_id: str, revision: int
    ) -> tuple[GraphAssertion, ...]:
        rows = connection.execute(
            "WITH latest AS ("
            "SELECT assertion_id,MAX(revision) AS revision "
            "FROM research_graph_assertions WHERE research_id=? AND revision<=? "
            "GROUP BY assertion_id) "
            "SELECT a.assertion_json FROM research_graph_assertions a "
            "JOIN latest l ON l.assertion_id=a.assertion_id AND l.revision=a.revision "
            "WHERE a.research_id=? AND a.status NOT IN ('rejected','superseded') "
            "ORDER BY a.assertion_id",
            (research_id, revision, research_id),
        ).fetchall()
        return tuple(
            GraphAssertion.model_validate_json(row["assertion_json"]) for row in rows
        )

    @staticmethod
    def _insert_graph_assertion(
        connection: sqlite3.Connection,
        research_id: str,
        revision: int,
        assertion: GraphAssertion,
    ) -> str:
        serialized = _model_json(assertion)
        digest = _record_hash(serialized)
        connection.execute(
            "INSERT INTO research_graph_assertions(research_id,assertion_id,revision,"
            "schema_version,source_id,source_kind,relation,target_id,target_kind,status,"
            "assertion_hash,assertion_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                research_id,
                assertion.assertion_id,
                revision,
                GRAPH_ASSERTION_SCHEMA_VERSION,
                assertion.source.entity_id,
                assertion.source.entity_kind.value,
                assertion.relation.value,
                assertion.target.entity_id,
                assertion.target.entity_kind.value,
                assertion.status.value,
                digest,
                serialized,
            ),
        )
        return digest

    def _create_in_transaction(
        self,
        connection: sqlite3.Connection,
        state: ResearchState,
        events: Sequence[ResearchEvent],
        assertions: Sequence[GraphAssertion],
    ) -> None:
        state_json = canonical_research_state_bytes(state).decode("utf-8")
        state_hash = research_state_hash(state)
        connection.execute(
            "INSERT INTO research_runs(research_id,current_revision,current_state_hash,"
            "status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (
                state.research_id,
                0,
                state_hash,
                state.status.value,
                state.created_at,
                state.updated_at,
            ),
        )
        connection.execute(
            "INSERT INTO research_revisions(research_id,revision,schema_version,"
            "previous_state_hash,state_hash,state_json,event_count,assertion_count,"
            "commit_hash,committed_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                state.research_id,
                0,
                RESEARCH_STORE_SCHEMA_VERSION,
                None,
                state_hash,
                state_json,
                len(events),
                len(assertions),
                "pending",
                state.updated_at,
            ),
        )
        event_hashes, assertion_hashes = self._insert_components(
            connection,
            research_id=state.research_id,
            revision=0,
            events=events,
            assertions=assertions,
        )
        self._validate_records(
            state,
            (),
            self._current_graph_assertions(connection, state.research_id, 0),
            0,
        )
        digest = _commit_hash(
            research_id=state.research_id,
            revision=0,
            previous_state_hash=None,
            state_hash=state_hash,
            event_hashes=event_hashes,
            assertion_hashes=assertion_hashes,
        )
        connection.execute(
            "UPDATE research_revisions SET commit_hash=? "
            "WHERE research_id=? AND revision=0",
            (digest, state.research_id),
        )

    def create_research(
        self,
        state: ResearchState | None = None,
        *,
        research_id: str | None = None,
        created_at: str | None = None,
        status: ResearchRunStatus = ResearchRunStatus.initializing,
        provenance: Sequence[ProvenanceRecord] = (),
        events: Sequence[ResearchEvent] = (),
        graph_assertions: Sequence[GraphAssertion] = (),
    ) -> ResearchState:
        if state is None:
            if research_id is None:
                raise ValueError("research_id is required")
            timestamp = created_at or _utc_now()
            state = ResearchState(
                research_id=research_id,
                revision=0,
                status=status,
                created_at=timestamp,
                updated_at=timestamp,
                provenance=tuple(provenance),
            )
        if research_id is not None and state.research_id != research_id:
            raise ValueError("research_id does not match initial state")
        if state.revision != 0:
            raise ValueError("new research must begin at revision zero")
        events = tuple(events)
        assertions = tuple(sorted(graph_assertions, key=lambda item: item.assertion_id))
        self._validate_bounds(state, events, assertions)
        self._validate_records(state, events, assertions, 0)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._create_in_transaction(connection, state, events, assertions)
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                if connection.execute(
                    "SELECT 1 FROM research_runs WHERE research_id=?",
                    (state.research_id,),
                ).fetchone():
                    raise ResearchAlreadyExists(state.research_id) from exc
                raise
            except Exception:
                connection.rollback()
                raise
        return state

    def load_research(
        self, research_id: str, revision: int | None = None
    ) -> ResearchState:
        with self.connect() as connection:
            if revision is None:
                run = connection.execute(
                    "SELECT current_revision FROM research_runs WHERE research_id=?",
                    (research_id,),
                ).fetchone()
                if run is None:
                    raise ResearchNotFound(research_id)
                revision = run["current_revision"]
            if (
                not isinstance(revision, int)
                or isinstance(revision, bool)
                or revision < 0
            ):
                raise ValueError("research revision must be a non-negative integer")
            row = connection.execute(
                "SELECT state_json,state_hash,schema_version FROM research_revisions "
                "WHERE research_id=? AND revision=?",
                (research_id, revision),
            ).fetchone()
        if row is None:
            raise ResearchNotFound(f"{research_id}@{revision}")
        if row["schema_version"] != RESEARCH_STORE_SCHEMA_VERSION:
            raise ResearchIntegrityError(
                "stored revision schema version is unsupported"
            )
        try:
            state = ResearchState.model_validate_json(row["state_json"])
        except Exception as exc:
            raise ResearchIntegrityError(
                "stored canonical research state is invalid"
            ) from exc
        if state.research_id != research_id or state.revision != revision:
            raise ResearchIntegrityError("stored state association is invalid")
        if research_state_hash(state) != row["state_hash"]:
            raise ResearchIntegrityError("stored canonical state hash does not match")
        return state

    def current_revision(self, research_id: str) -> int:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT current_revision FROM research_runs WHERE research_id=?",
                (research_id,),
            ).fetchone()
        if row is None:
            raise ResearchNotFound(research_id)
        return int(row["current_revision"])

    def append_event(
        self,
        research_id: str | ResearchEvent,
        event: ResearchEvent | None = None,
        *,
        expected_revision: int,
        state: ResearchState | None = None,
    ) -> ResearchState:
        if isinstance(research_id, ResearchEvent):
            if event is not None:
                raise ValueError("event was supplied twice")
            event = research_id
            research_id = event.research_id
        if event is None:
            raise ValueError("event is required")
        if state is None:
            current = self.load_research(research_id)
            payload = current.model_dump(mode="python")
            payload.update(revision=expected_revision + 1, updated_at=event.occurred_at)
            state = ResearchState.model_validate(payload)
        return self.commit_revision(
            research_id,
            expected_revision=expected_revision,
            state=state,
            events=(event,),
        )

    def commit_revision(
        self,
        research_id: str,
        *,
        expected_revision: int,
        state: ResearchState | None = None,
        new_state: ResearchState | None = None,
        events: Sequence[ResearchEvent] = (),
        graph_assertions: Sequence[GraphAssertion] = (),
    ) -> ResearchState:
        if state is not None and new_state is not None:
            raise ValueError("supply state or new_state, not both")
        state = state or new_state
        if state is None:
            current = self.load_research(research_id)
            payload = current.model_dump(mode="python")
            event_times = [item.occurred_at for item in events]
            assertion_times = [item.asserted_at for item in graph_assertions]
            payload.update(
                revision=expected_revision + 1,
                updated_at=max((*event_times, *assertion_times), default=_utc_now()),
            )
            state = ResearchState.model_validate(payload)
        if state.research_id != research_id:
            raise ValueError("state research_id does not match commit")
        if not isinstance(expected_revision, int) or isinstance(
            expected_revision, bool
        ):
            raise ValueError("expected_revision must be an integer")
        revision = expected_revision + 1
        if state.revision != revision:
            raise ValueError("state revision must be exactly expected_revision + 1")
        events = tuple(events)
        assertions = tuple(sorted(graph_assertions, key=lambda item: item.assertion_id))
        self._validate_bounds(state, events, assertions)
        self._validate_records(state, events, assertions, revision)
        state_json = canonical_research_state_bytes(state).decode("utf-8")
        state_hash = research_state_hash(state)

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                run = connection.execute(
                    "SELECT current_revision,current_state_hash,created_at,updated_at "
                    "FROM research_runs "
                    "WHERE research_id=?",
                    (research_id,),
                ).fetchone()
                if run is None:
                    raise ResearchNotFound(research_id)
                if run["current_revision"] != expected_revision:
                    raise StaleResearchRevision(
                        f"expected revision {expected_revision}; current revision is "
                        f"{run['current_revision']}"
                    )
                if state.created_at != run["created_at"]:
                    raise ValueError("research creation timestamp is immutable")
                if datetime.fromisoformat(
                    state.updated_at.replace("Z", "+00:00")
                ) < datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00")):
                    raise ValueError("research update timestamp must be monotonic")
                previous_hash = run["current_state_hash"]
                connection.execute(
                    "INSERT INTO research_revisions(research_id,revision,schema_version,"
                    "previous_state_hash,state_hash,state_json,event_count,assertion_count,"
                    "commit_hash,committed_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        research_id,
                        revision,
                        RESEARCH_STORE_SCHEMA_VERSION,
                        previous_hash,
                        state_hash,
                        state_json,
                        len(events),
                        len(assertions),
                        "pending",
                        state.updated_at,
                    ),
                )
                event_hashes, assertion_hashes = self._insert_components(
                    connection,
                    research_id=research_id,
                    revision=revision,
                    events=events,
                    assertions=assertions,
                )
                self._validate_records(
                    state,
                    (),
                    self._current_graph_assertions(connection, research_id, revision),
                    revision,
                )
                digest = _commit_hash(
                    research_id=research_id,
                    revision=revision,
                    previous_state_hash=previous_hash,
                    state_hash=state_hash,
                    event_hashes=event_hashes,
                    assertion_hashes=assertion_hashes,
                )
                connection.execute(
                    "UPDATE research_revisions SET commit_hash=? "
                    "WHERE research_id=? AND revision=?",
                    (digest, research_id, revision),
                )
                updated = connection.execute(
                    "UPDATE research_runs SET current_revision=?,current_state_hash=?,"
                    "status=?,updated_at=? WHERE research_id=? AND current_revision=?",
                    (
                        revision,
                        state_hash,
                        state.status.value,
                        state.updated_at,
                        research_id,
                        expected_revision,
                    ),
                )
                if updated.rowcount != 1:
                    raise StaleResearchRevision(
                        "research revision changed during commit"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return state

    def list_research_runs(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: ResearchRunStatus | None = None,
    ) -> tuple[ResearchRunSummary, ...]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > MAX_RESEARCH_RUN_LIST
        ):
            raise ValueError("research run list limit is outside the supported bound")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("research run list offset must be non-negative")
        query = (
            "SELECT research_id,current_revision,current_state_hash,status,created_at,updated_at "
            "FROM research_runs"
        )
        parameters: list[object] = []
        if status is not None:
            query += " WHERE status=?"
            parameters.append(status.value)
        query += " ORDER BY created_at,research_id LIMIT ? OFFSET ?"
        parameters.extend((limit, offset))
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(
            ResearchRunSummary(
                research_id=row["research_id"],
                current_revision=row["current_revision"],
                status=ResearchRunStatus(row["status"]),
                state_hash=row["current_state_hash"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        )

    def verify_integrity(self, research_id: str) -> IntegrityReport:
        try:
            with self.connect() as connection:
                schema = connection.execute(
                    "SELECT schema_version FROM research_schema WHERE singleton=1"
                ).fetchone()
                if schema is None:
                    raise ResearchIntegrityError("research schema metadata is missing")
                validate_schema_version(schema["schema_version"])
                run = connection.execute(
                    "SELECT * FROM research_runs WHERE research_id=?", (research_id,)
                ).fetchone()
                if run is None:
                    raise ResearchNotFound(research_id)
                revisions = connection.execute(
                    "SELECT * FROM research_revisions WHERE research_id=? ORDER BY revision",
                    (research_id,),
                ).fetchall()
                expected_revisions = list(range(run["current_revision"] + 1))
                if [row["revision"] for row in revisions] != expected_revisions:
                    raise ResearchIntegrityError(
                        "research revision ordering is invalid"
                    )
                prior_hash: str | None = None
                all_sequences: list[int] = []
                total_events = 0
                total_assertions = 0
                for revision_row in revisions:
                    revision = revision_row["revision"]
                    if revision_row["schema_version"] != RESEARCH_STORE_SCHEMA_VERSION:
                        raise ResearchIntegrityError(
                            "revision schema version is invalid"
                        )
                    state = ResearchState.model_validate_json(
                        revision_row["state_json"]
                    )
                    canonical = canonical_research_state_bytes(state).decode("utf-8")
                    if canonical != revision_row["state_json"]:
                        raise ResearchIntegrityError("stored state is not canonical")
                    if state.research_id != research_id or state.revision != revision:
                        raise ResearchIntegrityError(
                            "state revision association is invalid"
                        )
                    state_hash = research_state_hash(state)
                    if state_hash != revision_row["state_hash"]:
                        raise ResearchIntegrityError("canonical state hash is invalid")
                    if revision_row["previous_state_hash"] != prior_hash:
                        raise ResearchIntegrityError("state hash chain is invalid")
                    event_rows = connection.execute(
                        "SELECT * FROM research_events WHERE research_id=? AND revision=? "
                        "ORDER BY event_order",
                        (research_id, revision),
                    ).fetchall()
                    if len(event_rows) != revision_row["event_count"] or [
                        row["event_order"] for row in event_rows
                    ] != list(range(len(event_rows))):
                        raise ResearchIntegrityError("event ordering is invalid")
                    event_hashes: list[str] = []
                    revision_events: list[ResearchEvent] = []
                    for event_row in event_rows:
                        if event_row["schema_version"] != RESEARCH_EVENT_SCHEMA_VERSION:
                            raise ResearchIntegrityError(
                                "event schema version is invalid"
                            )
                        event = ResearchEvent.model_validate_json(
                            event_row["event_json"]
                        )
                        serialized = _model_json(event)
                        digest = _record_hash(serialized)
                        if digest != event_row["event_hash"]:
                            raise ResearchIntegrityError("event hash is invalid")
                        if (
                            event.event_id != event_row["event_id"]
                            or event.research_id != research_id
                            or event.state_revision != revision
                        ):
                            raise ResearchIntegrityError("event association is invalid")
                        event_hashes.append(digest)
                        revision_events.append(event)
                        all_sequences.append(event_row["event_sequence"])
                    assertion_rows = connection.execute(
                        "SELECT * FROM research_graph_assertions WHERE research_id=? "
                        "AND revision=? ORDER BY assertion_id",
                        (research_id, revision),
                    ).fetchall()
                    if len(assertion_rows) != revision_row["assertion_count"]:
                        raise ResearchIntegrityError(
                            "graph assertion association is invalid"
                        )
                    assertion_hashes: list[str] = []
                    revision_assertions: list[GraphAssertion] = []
                    for assertion_row in assertion_rows:
                        if (
                            assertion_row["schema_version"]
                            != GRAPH_ASSERTION_SCHEMA_VERSION
                        ):
                            raise ResearchIntegrityError(
                                "graph assertion schema version is invalid"
                            )
                        assertion = GraphAssertion.model_validate_json(
                            assertion_row["assertion_json"]
                        )
                        serialized = _model_json(assertion)
                        digest = _record_hash(serialized)
                        if digest != assertion_row["assertion_hash"]:
                            raise ResearchIntegrityError(
                                "graph assertion hash is invalid"
                            )
                        if (
                            assertion.assertion_id != assertion_row["assertion_id"]
                            or assertion.research_id != research_id
                        ):
                            raise ResearchIntegrityError(
                                "graph assertion identity is invalid"
                            )
                        assertion_hashes.append(digest)
                        revision_assertions.append(assertion)
                    self._validate_bounds(state, revision_events, revision_assertions)
                    self._validate_records(
                        state, revision_events, revision_assertions, revision
                    )
                    self._validate_records(
                        state,
                        (),
                        self._current_graph_assertions(
                            connection, research_id, revision
                        ),
                        revision,
                    )
                    expected_commit_hash = _commit_hash(
                        research_id=research_id,
                        revision=revision,
                        previous_state_hash=prior_hash,
                        state_hash=state_hash,
                        event_hashes=event_hashes,
                        assertion_hashes=assertion_hashes,
                    )
                    if revision_row["commit_hash"] != expected_commit_hash:
                        raise ResearchIntegrityError("revision commit hash is invalid")
                    prior_hash = state_hash
                    total_events += len(event_rows)
                    total_assertions += len(assertion_rows)
                if all_sequences != list(range(1, len(all_sequences) + 1)):
                    raise ResearchIntegrityError("global event ordering is invalid")
                if prior_hash != run["current_state_hash"]:
                    raise ResearchIntegrityError("current state hash is invalid")
                latest = ResearchState.model_validate_json(revisions[-1]["state_json"])
                if latest.status.value != run["status"]:
                    raise ResearchIntegrityError("current research status is invalid")
                if (
                    latest.created_at != run["created_at"]
                    or latest.updated_at != run["updated_at"]
                ):
                    raise ResearchIntegrityError(
                        "current research timestamps are invalid"
                    )
                import_rows = connection.execute(
                    "SELECT source_hash,imported_revision FROM research_phase2_imports "
                    "WHERE research_id=?",
                    (research_id,),
                ).fetchall()
                for import_row in import_rows:
                    if (
                        not re.fullmatch(
                            r"sha256:[0-9a-f]{64}", import_row["source_hash"]
                        )
                        or import_row["imported_revision"] not in expected_revisions
                    ):
                        raise ResearchIntegrityError(
                            "Phase 2 import reference is invalid"
                        )
                return IntegrityReport(
                    research_id=research_id,
                    current_revision=run["current_revision"],
                    state_hash=prior_hash,
                    revision_count=len(revisions),
                    event_count=total_events,
                    assertion_version_count=total_assertions,
                )
        except (ResearchStoreError, UnsupportedResearchSchemaVersion):
            raise
        except Exception as exc:
            raise ResearchIntegrityError(
                "research integrity verification failed"
            ) from exc

    def load_graph_assertion(
        self, research_id: str, assertion_id: str, *, revision: int | None = None
    ) -> GraphAssertion:
        if revision is None:
            revision = self.current_revision(research_id)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT assertion_json,assertion_hash FROM research_graph_assertions "
                "WHERE research_id=? AND assertion_id=? AND revision<=? "
                "ORDER BY revision DESC LIMIT 1",
                (research_id, assertion_id, revision),
            ).fetchone()
        if row is None:
            raise KeyError(assertion_id)
        assertion = GraphAssertion.model_validate_json(row["assertion_json"])
        if _record_hash(_model_json(assertion)) != row["assertion_hash"]:
            raise ResearchIntegrityError("graph assertion hash is invalid")
        return assertion

    def graph_assertion_history(
        self, research_id: str, assertion_id: str, *, limit: int = 100
    ) -> tuple[GraphAssertion, ...]:
        if limit < 1 or limit > MAX_GRAPH_QUERY_RESULTS:
            raise ValueError("graph history limit is outside the supported bound")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT assertion_json,assertion_hash FROM "
                "(SELECT assertion_json,assertion_hash,revision "
                "FROM research_graph_assertions WHERE research_id=? AND assertion_id=? "
                "ORDER BY revision DESC LIMIT ?) ORDER BY revision",
                (research_id, assertion_id, limit),
            ).fetchall()
        assertions: list[GraphAssertion] = []
        for row in rows:
            assertion = GraphAssertion.model_validate_json(row["assertion_json"])
            if _record_hash(_model_json(assertion)) != row["assertion_hash"]:
                raise ResearchIntegrityError("graph assertion history hash is invalid")
            assertions.append(assertion)
        return tuple(assertions)

    def query_graph_assertions(
        self,
        research_id: str,
        *,
        node_id: str | None = None,
        relation: ResearchPredicate | GraphRelation | None = None,
        first_node_id: str | None = None,
        second_node_id: str | None = None,
        limit: int = 100,
        include_rejected: bool = False,
    ) -> tuple[GraphAssertion, ...]:
        if limit < 1 or limit > MAX_GRAPH_QUERY_RESULTS:
            raise ValueError("graph query limit is outside the supported bound")
        revision = self.current_revision(research_id)
        filters: list[str] = []
        parameters: list[object] = [research_id, revision]
        if node_id is not None:
            filters.append("(a.source_id=? OR a.target_id=?)")
            parameters.extend((node_id, node_id))
        if first_node_id is not None or second_node_id is not None:
            if first_node_id is None or second_node_id is None:
                raise ValueError("both relationship endpoint IDs are required")
            filters.append(
                "((a.source_id=? AND a.target_id=?) OR "
                "(a.source_id=? AND a.target_id=?))"
            )
            parameters.extend(
                (first_node_id, second_node_id, second_node_id, first_node_id)
            )
        if relation is not None:
            filters.append("a.relation=?")
            parameters.append(relation.value)
        if not include_rejected:
            filters.append("a.status NOT IN ('rejected','superseded')")
        where = " AND " + " AND ".join(filters) if filters else ""
        parameters.append(limit)
        query = f"""
            WITH latest AS (
                SELECT assertion_id, MAX(revision) AS revision
                FROM research_graph_assertions
                WHERE research_id=? AND revision<=?
                GROUP BY assertion_id
            )
            SELECT a.assertion_json,a.assertion_hash
            FROM research_graph_assertions a
            JOIN latest l ON l.assertion_id=a.assertion_id AND l.revision=a.revision
            WHERE a.research_id=? {where}
            ORDER BY a.assertion_id
            LIMIT ?
        """
        parameters.insert(2, research_id)
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        result: list[GraphAssertion] = []
        for row in rows:
            assertion = GraphAssertion.model_validate_json(row["assertion_json"])
            if _record_hash(_model_json(assertion)) != row["assertion_hash"]:
                raise ResearchIntegrityError("queried graph assertion hash is invalid")
            result.append(assertion)
        return tuple(result)

    def record_fact(
        self,
        research_id: str,
        fact: Fact,
        *,
        expected_revision: int,
        updated_at: str,
        events: Sequence[ResearchEvent] = (),
        provenance: Sequence[ProvenanceRecord] = (),
    ) -> ResearchState:
        current = self.load_research(research_id)
        if any(item.fact_id == fact.fact_id for item in current.facts):
            raise ValueError("fact already exists")
        payload = current.model_dump(mode="python")
        payload.update(
            revision=expected_revision + 1,
            updated_at=updated_at,
            facts=(*current.facts, fact),
            provenance=(*current.provenance, *provenance),
        )
        state = ResearchState.model_validate(payload)
        return self.commit_revision(
            research_id,
            expected_revision=expected_revision,
            state=state,
            events=events,
        )

    def promote_fact(
        self,
        research_id: str,
        fact_id: str,
        next_status: FactStatus,
        *,
        expected_revision: int,
        evidence_references: Sequence[str],
        derivation_type: DerivationType,
        provenance_id: str,
        updated_at: str,
        events: Sequence[ResearchEvent] = (),
        provenance: Sequence[ProvenanceRecord] = (),
    ) -> ResearchState:
        current = self.load_research(research_id)
        matches = [item for item in current.facts if item.fact_id == fact_id]
        if len(matches) != 1:
            raise KeyError(fact_id)
        previous = matches[0]
        allowed = {
            FactStatus.proposed: {
                FactStatus.observed,
                FactStatus.rejected,
            },
            FactStatus.observed: {FactStatus.confirmed, FactStatus.rejected},
            FactStatus.confirmed: {FactStatus.rejected},
            FactStatus.rejected: set(),
            FactStatus.superseded: set(),
        }
        if next_status not in allowed[previous.status]:
            raise ValueError("invalid fact lifecycle transition")
        fact_payload = previous.model_dump(mode="python")
        fact_payload.update(
            status=next_status,
            evidence_references=tuple(evidence_references),
            derivation_type=derivation_type,
            provenance_id=provenance_id,
            supersedes_fact_id=None,
        )
        promoted = Fact.model_validate(fact_payload)
        facts = tuple(
            promoted if item.fact_id == fact_id else item for item in current.facts
        )
        state_payload = current.model_dump(mode="python")
        state_payload.update(
            revision=expected_revision + 1,
            updated_at=updated_at,
            facts=facts,
            provenance=(*current.provenance, *provenance),
        )
        state = ResearchState.model_validate(state_payload)
        return self.commit_revision(
            research_id,
            expected_revision=expected_revision,
            state=state,
            events=events,
        )

    def reject_fact(
        self, research_id: str, fact_id: str, **kwargs: Any
    ) -> ResearchState:
        return self.promote_fact(research_id, fact_id, FactStatus.rejected, **kwargs)

    def supersede_fact(
        self,
        research_id: str,
        fact_id: str,
        replacement: Fact,
        *,
        expected_revision: int,
        provenance_id: str,
        updated_at: str,
        derivation_type: DerivationType = DerivationType.deterministic,
        provenance: Sequence[ProvenanceRecord] = (),
    ) -> ResearchState:
        current = self.load_research(research_id)
        matches = [item for item in current.facts if item.fact_id == fact_id]
        if len(matches) != 1:
            raise KeyError(fact_id)
        previous = matches[0]
        if previous.status in {FactStatus.rejected, FactStatus.superseded}:
            raise ValueError("terminal fact cannot be superseded")
        if replacement.fact_id == fact_id or any(
            item.fact_id == replacement.fact_id for item in current.facts
        ):
            raise ValueError("replacement fact must have a new identity")
        previous_payload = previous.model_dump(mode="python")
        previous_payload.update(
            status=FactStatus.superseded,
            supersedes_fact_id=replacement.fact_id,
            provenance_id=provenance_id,
            derivation_type=derivation_type,
        )
        superseded = Fact.model_validate(previous_payload)
        facts = tuple(
            superseded if item.fact_id == fact_id else item for item in current.facts
        ) + (replacement,)
        state_payload = current.model_dump(mode="python")
        state_payload.update(
            revision=expected_revision + 1,
            updated_at=updated_at,
            facts=facts,
            provenance=(*current.provenance, *provenance),
        )
        state = ResearchState.model_validate(state_payload)
        return self.commit_revision(
            research_id, expected_revision=expected_revision, state=state
        )

    def import_phase2_run(
        self,
        phase2_store: Any,
        run_id: str,
        *,
        research_id: str | None = None,
        source_revision: int | None = None,
        occurred_at: str | None = None,
        target_class: TargetClass = TargetClass.external,
    ) -> ResearchState:
        """Import safe immutable references from one exact Phase 2 run revision."""

        from agent_core.phase2_store import run_snapshot_hash

        if source_revision is None:
            source_revision, source = phase2_store.load_latest_revision(run_id)
        else:
            source = phase2_store.load_revision(run_id, source_revision)
        original = deepcopy(source)
        reject_secret_material(source, location="Phase 2 import")
        source_hash = run_snapshot_hash(source)
        with self.connect() as connection:
            imported = connection.execute(
                "SELECT source_hash,research_id FROM research_phase2_imports "
                "WHERE source_run_id=? AND source_revision=?",
                (run_id, source_revision),
            ).fetchone()
        if imported is not None:
            if imported["source_hash"] != source_hash:
                raise ResearchIntegrityError("Phase 2 import source hash changed")
            if research_id is not None and imported["research_id"] != research_id:
                raise ValueError(
                    "Phase 2 revision was imported under another research_id"
                )
            return self.load_research(imported["research_id"])

        digest = hashlib.sha256(
            f"{run_id}\x1f{source_revision}\x1f{source_hash}".encode("utf-8")
        ).hexdigest()
        selected_id = research_id or f"research-phase2-{digest[:24]}"
        timestamp = occurred_at or source.get("created_at") or _utc_now()
        try:
            parsed_timestamp = datetime.fromisoformat(
                str(timestamp).replace("Z", "+00:00")
            )
            if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
                timestamp = _utc_now()
        except ValueError:
            timestamp = _utc_now()
        root_provenance_id = f"prov-phase2-{digest[:24]}"
        root_provenance = build_provenance_record(
            provenance_id=root_provenance_id,
            producer_type=ProvenanceProducerType.imported,
            producer_name="phase2-run-store-importer",
            producer_version="v1",
            summary="Imported immutable Phase 2 public run references.",
            occurred_at=timestamp,
            research_revision=0,
            source_phase2_run=(f"{_opaque(run_id, 'run')}:revision:{source_revision}"),
            runtime_result_reference=source_hash,
        )
        run_evidence_id = f"evidence-phase2-run-{digest[:20]}"
        evidence: list[EvidenceArtifact] = [
            EvidenceArtifact(
                evidence_id=run_evidence_id,
                evidence_kind=EvidenceKind.imported,
                digest=source_hash,
                summary="Immutable Phase 2 run snapshot reference.",
                source_reference=_opaque(
                    f"phase2-run:{run_id}:revision:{source_revision}", "phase2-run"
                ),
                observed_at=timestamp,
                provenance_id=root_provenance_id,
                metadata=PublicMetadata(
                    entries=(
                        MetadataEntry(
                            key="retention_class", value="phase2-public-reference"
                        ),
                    )
                ),
            )
        ]

        surface_material = (
            source.get("attack_surface")
            or (source.get("evidence_package") or {}).get("observed_surface")
            or source.get("surface")
        )
        if surface_material:
            surface_json = _canonical_json(surface_material)
            evidence.append(
                EvidenceArtifact(
                    evidence_id=f"evidence-phase2-surface-{digest[:20]}",
                    evidence_kind=EvidenceKind.imported,
                    digest=_record_hash(surface_json),
                    summary="Phase 2 attack-surface snapshot reference.",
                    source_reference=_opaque(
                        f"phase2-run:{run_id}:attack-surface", "phase2-surface"
                    ),
                    observed_at=timestamp,
                    provenance_id=root_provenance_id,
                    metadata=PublicMetadata(
                        entries=(
                            MetadataEntry(
                                key="retention_class",
                                value="phase2-public-reference",
                            ),
                        )
                    ),
                )
            )
        plans = source.get("verification_plans") or []
        if plans:
            evidence.append(
                EvidenceArtifact(
                    evidence_id=f"evidence-phase2-plans-{digest[:20]}",
                    evidence_kind=EvidenceKind.imported,
                    digest=_record_hash(_canonical_json(plans)),
                    summary="Phase 2 verification-plan collection reference.",
                    source_reference=_opaque(
                        f"phase2-run:{run_id}:verification-plans", "phase2-plans"
                    ),
                    observed_at=timestamp,
                    provenance_id=root_provenance_id,
                    metadata=PublicMetadata(
                        entries=(
                            MetadataEntry(
                                key="retention_class",
                                value="phase2-public-reference",
                            ),
                        )
                    ),
                )
            )

        target_id = f"target-phase2-{digest[:20]}"
        target = TargetAsset(
            target_id=target_id,
            canonical_reference=_bounded_public_text(
                source.get("target"), "Phase 2 target reference"
            ),
            target_class=target_class,
            scope_reference=_opaque(
                source.get("target_fingerprint") or f"phase2-scope:{run_id}",
                "phase2-scope",
            ),
            evidence_references=tuple(item.evidence_id for item in evidence),
            provenance_id=root_provenance_id,
        )

        hypotheses: list[HypothesisRecord] = []
        hypothesis_ids: dict[str, str] = {}
        raw_hypotheses = source.get("hypotheses") or []
        if len(raw_hypotheses) > 5_000:
            raise OversizedResearchMutation("Phase 2 hypothesis import limit exceeded")
        for index, raw in enumerate(raw_hypotheses):
            if not isinstance(raw, Mapping):
                continue
            raw_id = str(raw.get("hypothesis_id") or raw.get("id") or index)
            hypothesis_id = _opaque(raw_id, f"hypothesis-phase2-{index}")
            if hypothesis_id in hypothesis_ids.values():
                hypothesis_id = f"hypothesis-phase2-{digest[:12]}-{index}"
            hypothesis_ids[raw_id] = hypothesis_id
            hypotheses.append(
                HypothesisRecord(
                    hypothesis_id=hypothesis_id,
                    category=_opaque(
                        raw.get("category") or "phase2-imported", "category"
                    ),
                    title=_bounded_public_text(
                        raw.get("title") or raw.get("category"),
                        "Imported Phase 2 hypothesis.",
                    ),
                    claim=_bounded_public_text(
                        raw.get("claim") or raw.get("description") or raw.get("title"),
                        "Phase 2 proposed hypothesis; no Phase 4 confirmation inferred.",
                        4_000,
                    ),
                    target_id=target_id,
                    status=HypothesisResearchStatus.proposed,
                    priority=(
                        raw.get("priority")
                        if isinstance(raw.get("priority"), int)
                        and not isinstance(raw.get("priority"), bool)
                        and 0 <= raw["priority"] <= 100
                        else 0
                    ),
                    confidence=ResearchConfidence.low,
                    confirmation_policy_reference="phase2-import-requires-reverification",
                    provenance_id=root_provenance_id,
                )
            )

        outcomes: list[ExperimentOutcome] = []
        provenance: list[ProvenanceRecord] = [root_provenance]
        raw_results = source.get("verification_results") or []
        if len(raw_results) > 10_000:
            raise OversizedResearchMutation("Phase 2 result import limit exceeded")
        for index, raw in enumerate(raw_results):
            if not isinstance(raw, Mapping):
                continue
            raw_result_id = str(raw.get("result_id") or f"result-{index}")
            result_id = _opaque(raw_result_id, f"result-{index}")
            result_material = _canonical_json(raw)
            result_hash = raw.get("result_hash")
            if not isinstance(result_hash, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", result_hash
            ):
                result_hash = _record_hash(result_material)
            evidence_id = f"evidence-phase2-result-{digest[:12]}-{index}"
            result_provenance_id = f"prov-phase2-result-{digest[:12]}-{index}"
            provenance.append(
                build_provenance_record(
                    provenance_id=result_provenance_id,
                    producer_type=ProvenanceProducerType.imported,
                    producer_name="phase2-run-store-importer",
                    producer_version="v1",
                    summary="Imported one immutable Phase 2 result reference.",
                    occurred_at=timestamp,
                    research_revision=0,
                    source_phase2_run=(
                        f"{_opaque(run_id, 'run')}:revision:{source_revision}"
                    ),
                    source_phase2_results=(result_id,),
                    runtime_result_reference=result_hash,
                    parent_provenance_id=root_provenance_id,
                )
            )
            evidence.append(
                EvidenceArtifact(
                    evidence_id=evidence_id,
                    evidence_kind=EvidenceKind.imported,
                    digest=result_hash,
                    summary="Immutable Phase 2 verification-result reference.",
                    source_reference=_opaque(
                        f"phase2-result:{run_id}:{result_id}", "phase2-result"
                    ),
                    observed_at=timestamp,
                    provenance_id=result_provenance_id,
                    metadata=PublicMetadata(
                        entries=(
                            MetadataEntry(
                                key="retention_class",
                                value="phase2-public-reference",
                            ),
                        )
                    ),
                )
            )
            raw_delta = raw.get("request_delta")
            try:
                if not isinstance(raw_delta, Mapping):
                    raise ValueError("legacy request accounting")
                request_delta = RequestDelta.model_validate(raw_delta)
            except ValueError:
                total, _ = canonical_result_request_total(raw)
                request_delta = RequestDelta(
                    verification=total, attempted=total, total=total
                )
            try:
                classification = Phase2ResultStatus(str(raw.get("status")))
            except ValueError:
                classification = Phase2ResultStatus.inconclusive
            runtime_status = (
                ExperimentRuntimeStatus.awaiting_controlled_evidence
                if classification is Phase2ResultStatus.awaiting_controlled_evidence
                else (
                    ExperimentRuntimeStatus.cleanup_pending
                    if classification is Phase2ResultStatus.verification_pending_cleanup
                    else (
                        ExperimentRuntimeStatus.blocked
                        if classification is Phase2ResultStatus.policy_blocked
                        else ExperimentRuntimeStatus.completed
                    )
                )
            )
            outcomes.append(
                ExperimentOutcome(
                    outcome_id=f"outcome-phase2-{digest[:12]}-{index}",
                    experiment_id=_opaque(
                        raw.get("experiment_id") or f"phase2-experiment-{result_id}",
                        f"phase2-experiment-{index}",
                    ),
                    runtime_status=runtime_status,
                    canonical_result_classification=classification,
                    evidence_references=(evidence_id,),
                    request_delta=request_delta,
                    cleanup_status=(
                        CleanupStatus.pending
                        if runtime_status is ExperimentRuntimeStatus.cleanup_pending
                        else CleanupStatus.not_required
                    ),
                    evaluator_result_reference=result_hash,
                    provenance_id=result_provenance_id,
                    occurred_at=timestamp,
                )
            )

        state = ResearchState(
            research_id=selected_id,
            revision=0,
            status=ResearchRunStatus.initializing,
            created_at=timestamp,
            updated_at=timestamp,
            targets=(target,),
            evidence=tuple(evidence),
            hypotheses=tuple(hypotheses),
            experiment_outcomes=tuple(outcomes),
            provenance=tuple(provenance),
        )
        event = ResearchEvent(
            event_id=f"event-phase2-import-{digest[:20]}",
            research_id=selected_id,
            event_type=ResearchEventType.research_started,
            state_revision=0,
            provenance_id=root_provenance_id,
            occurred_at=timestamp,
            summary="Phase 4 research was created from immutable Phase 2 references.",
            payload=ResearchStartedPayload(target_ids=(target_id,)),
        )
        self._validate_bounds(state, (event,), ())
        self._validate_records(state, (event,), (), 0)
        if source != original:
            raise ResearchIntegrityError("Phase 2 source changed during import")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT source_hash,research_id FROM research_phase2_imports "
                    "WHERE source_run_id=? AND source_revision=?",
                    (run_id, source_revision),
                ).fetchone()
                if existing is not None:
                    if existing["source_hash"] != source_hash:
                        raise ResearchIntegrityError(
                            "Phase 2 import source hash changed"
                        )
                    connection.rollback()
                    return self.load_research(existing["research_id"])
                self._create_in_transaction(connection, state, (event,), ())
                connection.execute(
                    "INSERT INTO research_phase2_imports(source_run_id,source_revision,"
                    "source_hash,research_id,imported_revision,imported_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (run_id, source_revision, source_hash, selected_id, 0, timestamp),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return state
