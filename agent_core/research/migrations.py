"""Deterministic, fail-closed schema migrations for Phase 4 research storage."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

RESEARCH_STORE_SCHEMA_VERSION = 1


class ResearchMigrationError(RuntimeError):
    """Raised when a research-store migration cannot be applied safely."""


class UnsupportedResearchSchemaVersion(ResearchMigrationError):
    """Raised when a database was written by an unsupported schema version."""


Migration = Callable[[sqlite3.Connection], None]


@dataclass(frozen=True)
class MigrationStep:
    source_version: int
    target_version: int
    migrate: Migration

    def __post_init__(self) -> None:
        if self.source_version < 0 or self.target_version != self.source_version + 1:
            raise ValueError("research migrations must advance exactly one version")


class MigrationRegistry:
    """Registry whose only valid path is a contiguous sequence of versions."""

    def __init__(self) -> None:
        self._steps: dict[int, MigrationStep] = {}

    def register(
        self, source_version: int, target_version: int, migrate: Migration
    ) -> None:
        step = MigrationStep(source_version, target_version, migrate)
        if source_version in self._steps:
            raise ValueError(f"migration from version {source_version} is registered")
        self._steps[source_version] = step

    def path(
        self, source_version: int, target_version: int
    ) -> tuple[MigrationStep, ...]:
        if source_version < 0 or target_version < 0:
            raise UnsupportedResearchSchemaVersion(
                "research schema versions cannot be negative"
            )
        if source_version > target_version:
            raise UnsupportedResearchSchemaVersion(
                "destructive research schema downgrade is unsupported"
            )
        steps: list[MigrationStep] = []
        current = source_version
        while current < target_version:
            step = self._steps.get(current)
            if step is None:
                raise UnsupportedResearchSchemaVersion(
                    f"no deterministic migration from research schema {current}"
                )
            steps.append(step)
            current = step.target_version
        return tuple(steps)

    def migrate(
        self,
        connection: sqlite3.Connection,
        source_version: int,
        target_version: int,
    ) -> None:
        """Apply a prevalidated migration path in the caller's transaction."""

        steps = self.path(source_version, target_version)
        try:
            for step in steps:
                step.migrate(connection)
                connection.execute(
                    "UPDATE research_schema SET schema_version = ? WHERE singleton = 1",
                    (step.target_version,),
                )
                connection.execute(f"PRAGMA user_version = {step.target_version:d}")
        except Exception as exc:
            raise ResearchMigrationError("research schema migration failed") from exc


DEFAULT_MIGRATIONS = MigrationRegistry()


def validate_schema_version(version: object) -> int:
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise UnsupportedResearchSchemaVersion("research schema version is invalid")
    if version > RESEARCH_STORE_SCHEMA_VERSION:
        raise UnsupportedResearchSchemaVersion(
            f"research schema {version} is newer than supported schema "
            f"{RESEARCH_STORE_SCHEMA_VERSION}"
        )
    return version
