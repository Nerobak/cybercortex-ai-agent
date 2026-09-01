"""Local secret-safe Phase 2 run store used by explain/export CLI commands."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import Field

from agent_core.agent_models import StrictModel
from agent_core.recovery_state_enforcement import PreservedRecoveryChallenge
from agent_core.result_normalizer import public_result
from agent_core.result_provenance import (
    RESULT_HASH_PATTERN,
    RESULT_ID_PATTERN,
    RESULT_SCHEMA_VERSION,
    canonical_result_json,
    new_result_id,
    result_content_hash,
    target_identity,
    validate_result_provenance,
    validate_target_fingerprint,
)
from agent_core.verification_capabilities import validate_typed_producer_provenance

_REVISION_PATTERN = re.compile(r"^(?P<run>.+)\.revision_(?P<revision>[0-9]+)\.json$")
RUN_SNAPSHOT_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def canonical_run_snapshot_json(run: Any) -> str:
    """Return canonical JSON for one public immutable run snapshot."""

    payload = public_result(run)
    if not isinstance(payload, dict):
        raise ValueError("Run snapshot must normalize to a public object.")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def run_snapshot_hash(run: Any) -> str:
    """Fingerprint one exact sanitized run revision, never latest.json."""

    material = canonical_run_snapshot_json(run).encode("utf-8")
    return "sha256:" + sha256(material).hexdigest()


def validate_run_snapshot_hash(value: Any) -> str:
    """Validate one deterministic public run-snapshot hash."""

    if not isinstance(value, str) or not RUN_SNAPSHOT_HASH_PATTERN.fullmatch(value):
        raise ValueError("Run snapshot hash is invalid.")
    return value


def _atomic_write(path: Path, rendered: str, *, replace: bool) -> None:
    """Write a complete file before atomically publishing its directory entry."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError as exc:
                raise FileExistsError(
                    f"Immutable provenance record already exists: {path.name}."
                ) from exc
            temporary_path.unlink()
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


class _PrivateRecoveryRecord(StrictModel):
    """Minimum secret-free state needed by the controlled recovery executor."""

    version: int = Field(default=1, strict=True, ge=1, le=1)
    run_reference: str = Field(min_length=1, max_length=200)
    hypothesis_id: str = Field(min_length=1, max_length=200)
    challenge: PreservedRecoveryChallenge


class Phase2PrivateRecoveryStore:
    """Restrictive non-public persistence used only by controlled recovery resume."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    @staticmethod
    def _record_name(run_reference: str, hypothesis_id: str) -> str:
        run_value = str(run_reference)
        hypothesis_value = str(hypothesis_id)
        if not run_value or len(run_value) > 200:
            raise ValueError("Recovery run reference is invalid.")
        if not hypothesis_value or len(hypothesis_value) > 200:
            raise ValueError("Recovery hypothesis reference is invalid.")
        digest = sha256(
            json.dumps([run_value, hypothesis_value], separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        return f"recovery-{digest}.json"

    def _path(self, run_reference: str, hypothesis_id: str) -> Path:
        return self.directory / self._record_name(run_reference, hypothesis_id)

    def save_for_executor(
        self,
        *,
        run_reference: str,
        hypothesis_id: str,
        challenge: dict[str, Any],
    ) -> None:
        record = _PrivateRecoveryRecord.model_validate(
            {
                "run_reference": run_reference,
                "hypothesis_id": hypothesis_id,
                "challenge": challenge,
            }
        )
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        path = self._path(run_reference, hypothesis_id)
        _atomic_write(
            path,
            json.dumps(record.model_dump(mode="json"), indent=2) + "\n",
            replace=True,
        )
        path.chmod(0o600)

    def load_for_executor(
        self, *, run_reference: str, hypothesis_id: str
    ) -> dict[str, Any] | None:
        path = self._path(run_reference, hypothesis_id)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        record = _PrivateRecoveryRecord.model_validate(payload)
        if (
            record.run_reference != run_reference
            or record.hypothesis_id != hypothesis_id
        ):
            raise ValueError("Private recovery state binding is invalid.")
        return record.challenge.model_dump(mode="json")


class Phase2RunStore:
    def __init__(self, directory: str | Path = "reports/phase2") -> None:
        self.directory = Path(directory)
        self.private_recovery = Phase2PrivateRecoveryStore(self.directory / ".private")

    @property
    def latest_path(self) -> Path:
        return self.directory / "latest.json"

    def save(self, run: dict[str, Any]) -> str:
        """Append one immutable run revision and update the convenience view.

        Re-saving identical content is idempotent. Any changed run creates a
        new numbered revision, and every previously persisted result must be
        present with exactly the same canonical public content.
        """

        self.directory.mkdir(parents=True, exist_ok=True)
        raw_run_id = str(run.get("run_id") or "run")
        for result in run.get("verification_results") or []:
            if not isinstance(result, dict):
                continue
            challenge = result.get("preserved_challenge")
            hypothesis_id = result.get("hypothesis_id")
            if isinstance(challenge, dict) and isinstance(hypothesis_id, str):
                self.private_recovery.save_for_executor(
                    run_reference=str(result.get("recovery_run_id") or raw_run_id),
                    hypothesis_id=hypothesis_id,
                    challenge=challenge,
                )
        run_id = self._validated_run_id(raw_run_id)
        previous_path = self._latest_run_path(run_id)
        previous = self.load(previous_path) if previous_path is not None else None
        payload = self._prepare_payload(run, run_id=run_id, previous=previous)

        if previous is not None:
            previous_revision = self._path_revision(previous_path, run_id=run_id)
            payload["run_revision"] = previous.get("run_revision", previous_revision)
            if self._canonical_run(payload) == self._canonical_run(previous):
                rendered = json.dumps(previous, indent=2) + "\n"
                _atomic_write(self.latest_path, rendered, replace=True)
                run.clear()
                run.update(previous)
                return str(previous_path)
            revision = previous_revision + 1
            payload["run_revision"] = revision
            destination = self.revision_path(run_id, revision)
        else:
            payload["run_revision"] = 1
            destination = self.run_path(run_id)

        rendered = json.dumps(payload, indent=2) + "\n"
        _atomic_write(destination, rendered, replace=False)
        _atomic_write(self.latest_path, rendered, replace=True)
        run.clear()
        run.update(payload)
        return str(destination)

    def _prepare_payload(
        self,
        run: dict[str, Any],
        *,
        run_id: str,
        previous: dict[str, Any] | None,
    ) -> dict[str, Any]:
        raw_target = run.get("target")
        payload = public_result(run)
        if not isinstance(payload, dict):
            raise ValueError("Phase 2 run must normalize to an object.")
        payload["run_id"] = run_id
        payload["provenance_model"] = "append_only_revisions/v1"

        if previous is None:
            payload.setdefault("created_at", datetime.now(timezone.utc).isoformat())
            if isinstance(raw_target, str) and raw_target.strip():
                public_target, fingerprint = target_identity(raw_target)
                payload["target"] = public_target
                payload["target_fingerprint"] = fingerprint
        else:
            previous_created = previous.get("created_at")
            supplied_created = payload.get("created_at")
            if (
                supplied_created is not None
                and previous_created is not None
                and supplied_created != previous_created
            ):
                raise ValueError("Immutable run creation metadata cannot change.")
            if previous_created is not None:
                payload["created_at"] = previous_created

            previous_fingerprint = previous.get("target_fingerprint")
            if previous_fingerprint is not None:
                previous_fingerprint = validate_target_fingerprint(previous_fingerprint)
                supplied_fingerprint = payload.get("target_fingerprint")
                if supplied_fingerprint is not None and (
                    validate_target_fingerprint(supplied_fingerprint)
                    != previous_fingerprint
                ):
                    raise ValueError("Immutable run target identity cannot change.")
                payload["target_fingerprint"] = previous_fingerprint
                payload["target"] = previous.get("target")
            else:
                payload.pop("target_fingerprint", None)
                payload["target_identity_status"] = "legacy_unversioned"
                if previous.get("target") is not None:
                    payload["target"] = previous["target"]

        hypotheses = {
            str(item.get("hypothesis_id") or item.get("id") or ""): item
            for item in payload.get("hypotheses") or []
            if isinstance(item, dict)
        }
        candidate_results = payload.get("verification_results") or []
        if not isinstance(candidate_results, list) or any(
            not isinstance(item, dict) for item in candidate_results
        ):
            raise ValueError("Verification results must be a list of objects.")
        previous_results = (
            previous.get("verification_results") or [] if previous is not None else []
        )
        if len(candidate_results) < len(previous_results):
            raise ValueError("Previously persisted results cannot be removed.")

        prepared_results: list[dict[str, Any]] = []
        used_result_ids: set[str] = set()
        for index, previous_result in enumerate(previous_results):
            candidate = candidate_results[index]
            reconciled = self._reconcile_existing_result(previous_result, candidate)
            prepared_results.append(reconciled)
            result_id = reconciled.get("result_id")
            if isinstance(result_id, str):
                if result_id in used_result_ids:
                    raise ValueError("Persisted result_id values must be unique.")
                used_result_ids.add(result_id)

        for candidate in candidate_results[len(previous_results) :]:
            hypothesis = hypotheses.get(str(candidate.get("hypothesis_id") or ""), {})
            prepared = self._prepare_new_result(
                candidate,
                hypothesis_category=(
                    hypothesis.get("category") if isinstance(hypothesis, dict) else None
                ),
                target_surface=(
                    hypothesis.get("target_surface")
                    if isinstance(hypothesis, dict)
                    else None
                ),
                used_result_ids=used_result_ids,
            )
            prepared_results.append(prepared)
            used_result_ids.add(prepared["result_id"])
        payload["verification_results"] = prepared_results
        return payload

    @staticmethod
    def _prepare_new_result(
        result: dict[str, Any],
        *,
        hypothesis_category: Any,
        target_surface: Any,
        used_result_ids: set[str],
    ) -> dict[str, Any]:
        prepared = public_result(result)
        if not isinstance(prepared, dict):
            raise ValueError("Verification result must normalize to an object.")
        if "target_surface" not in prepared and isinstance(target_surface, dict):
            prepared["target_surface"] = public_result(target_surface)
        prepared.setdefault("result_schema_version", RESULT_SCHEMA_VERSION)
        if (
            type(prepared["result_schema_version"]) is not int
            or prepared["result_schema_version"] != RESULT_SCHEMA_VERSION
        ):
            raise ValueError("New result schema version is unsupported.")
        category = prepared.get("category")
        if not isinstance(category, str) or not category:
            raise ValueError("New typed result requires a category.")
        if hypothesis_category is not None and category != hypothesis_category:
            raise ValueError("New typed result category does not match its hypothesis.")
        if "executor" not in prepared:
            raise ValueError("New typed result requires explicit producer provenance.")
        prepared["executor"] = validate_typed_producer_provenance(
            category, prepared["executor"]
        )

        result_id = prepared.get("result_id")
        if result_id is None:
            result_id = new_result_id()
            while result_id in used_result_ids:
                result_id = new_result_id()
            prepared["result_id"] = result_id
        elif not isinstance(result_id, str) or not RESULT_ID_PATTERN.fullmatch(
            result_id
        ):
            raise ValueError("New result_id is invalid.")
        if result_id in used_result_ids:
            raise ValueError("Conflicting immutable result_id already exists.")

        calculated_hash = result_content_hash(prepared)
        supplied_hash = prepared.get("result_hash")
        if supplied_hash is not None and (
            not isinstance(supplied_hash, str)
            or not RESULT_HASH_PATTERN.fullmatch(supplied_hash)
            or supplied_hash != calculated_hash
        ):
            raise ValueError("New result_hash does not match its public content.")
        prepared["result_hash"] = calculated_hash
        validate_result_provenance(prepared)
        return prepared

    @staticmethod
    def _reconcile_existing_result(
        previous: dict[str, Any], candidate: dict[str, Any]
    ) -> dict[str, Any]:
        existing_id = previous.get("result_id")
        if existing_id is None:
            if public_result(candidate) != previous:
                raise ValueError("Legacy persisted result content cannot change.")
            return previous

        validate_result_provenance(previous)
        trial = public_result(candidate)
        if not isinstance(trial, dict):
            raise ValueError("Verification result must normalize to an object.")
        for field in (
            "result_id",
            "result_schema_version",
            "executor",
            "target_surface",
        ):
            if field not in trial and field in previous:
                trial[field] = previous[field]
        if trial.get("result_id") != existing_id:
            raise ValueError("Previously persisted result identity cannot change.")
        if "result_hash" in trial and trial.get("result_hash") != previous.get(
            "result_hash"
        ):
            raise ValueError("Previously persisted result hash cannot change.")
        trial_hash = result_content_hash(trial)
        if trial_hash != previous.get("result_hash") or canonical_result_json(
            trial
        ) != canonical_result_json(previous):
            raise ValueError("Immutable persisted result content cannot change.")
        return previous

    @staticmethod
    def _canonical_run(run: dict[str, Any]) -> str:
        return json.dumps(
            run,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    def _path_revision(self, path: Path | None, *, run_id: str) -> int:
        if path is None:
            return 0
        if path == self.run_path(run_id):
            return 1
        match = _REVISION_PATTERN.fullmatch(path.name)
        if match and match.group("run") == run_id:
            return int(match.group("revision"))
        raise ValueError("Stored run revision filename is invalid.")

    def _latest_run_path(self, run_id: str) -> Path | None:
        base = self.run_path(run_id)
        candidates: list[tuple[int, Path]] = []
        if base.exists():
            candidates.append((1, base))
        prefix = f"{run_id}.revision_"
        for path in self.directory.glob(f"{run_id}.revision_*.json"):
            match = _REVISION_PATTERN.fullmatch(path.name)
            if match and path.name.startswith(prefix):
                candidates.append((int(match.group("revision")), path))
        return max(candidates, default=(0, None), key=lambda item: item[0])[1]

    @staticmethod
    def _validated_run_id(run_id: str) -> str:
        identifier = str(run_id).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", identifier):
            raise ValueError("Run ID contains unsupported characters.")
        if identifier == "latest":
            raise ValueError("Run ID 'latest' is reserved.")
        return identifier

    def run_path(self, run_id: str) -> Path:
        identifier = self._validated_run_id(run_id)
        return self.directory / f"{identifier}.json"

    def revision_path(self, run_id: str, revision: int) -> Path:
        identifier = self._validated_run_id(run_id)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 2:
            raise ValueError("Run revision must be an integer greater than one.")
        return self.directory / f"{identifier}.revision_{revision}.json"

    def load_run(self, run_id: str) -> dict[str, Any]:
        _, payload = self.load_latest_revision(run_id)
        return payload

    def load_latest_revision(self, run_id: str) -> tuple[int, dict[str, Any]]:
        """Select the current immutable run revision explicitly."""

        identifier = self._validated_run_id(run_id)
        selected = self._latest_run_path(identifier)
        if selected is None:
            raise FileNotFoundError(f"No stored Phase 2 run exists for {run_id}.")
        revision = self._path_revision(selected, run_id=identifier)
        return revision, self.load_revision(identifier, revision)

    def load_revision(self, run_id: str, revision: int) -> dict[str, Any]:
        """Load exactly one immutable revision without latest fallback."""

        identifier = self._validated_run_id(run_id)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("Run revision must be a positive integer.")
        selected = (
            self.run_path(identifier)
            if revision == 1
            else self.revision_path(identifier, revision)
        )
        if not selected.exists():
            raise FileNotFoundError(
                f"Stored Phase 2 run revision does not exist: {identifier}@{revision}."
            )
        payload = self.load(selected)
        if str(payload.get("run_id") or "") != identifier:
            raise ValueError("Stored Phase 2 run ID does not match its filename.")
        stored_revision = payload.get("run_revision")
        if stored_revision is not None and stored_revision != revision:
            raise ValueError("Stored Phase 2 run revision metadata is inconsistent.")
        if stored_revision is None and revision != 1:
            raise ValueError("Legacy run content cannot represent a later revision.")
        return payload

    def load_result(
        self, run_id: str, result_id: str, *, result_hash: str | None = None
    ) -> dict[str, Any]:
        if not RESULT_ID_PATTERN.fullmatch(str(result_id)):
            raise ValueError("Result ID is invalid.")
        run = self.load_run(run_id)
        matches = [
            item
            for item in run.get("verification_results") or []
            if isinstance(item, dict) and item.get("result_id") == result_id
        ]
        if len(matches) != 1:
            raise KeyError("Immutable verification result was not found uniquely.")
        result = matches[0]
        validate_result_provenance(result)
        if result_hash is not None and result.get("result_hash") != result_hash:
            raise ValueError("Result reference hash does not match stored content.")
        return result

    def load(self, path: str | Path | None = None) -> dict[str, Any]:
        selected = Path(path) if path else self.latest_path
        payload = json.loads(selected.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Stored Phase 2 run must be a JSON object.")
        seen: set[str] = set()
        for result in payload.get("verification_results") or []:
            if not isinstance(result, dict):
                raise ValueError("Stored verification result must be an object.")
            provenance_fields = {
                "result_id",
                "result_hash",
                "result_schema_version",
                "executor",
            }
            if provenance_fields & result.keys():
                validate_result_provenance(result)
                result_id = str(result["result_id"])
                if result_id in seen:
                    raise ValueError("Stored result_id values must be unique.")
                seen.add(result_id)
        if payload.get("target_fingerprint") is not None:
            validate_target_fingerprint(payload["target_fingerprint"])
        return payload

    def hypothesis(self, hypothesis_id: str) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self.load().get("hypotheses", [])
                if item.get("hypothesis_id") == hypothesis_id
            ),
            None,
        )

    def plan(self, hypothesis_id: str) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self.load().get("verification_plans", [])
                if item.get("hypothesis_id") == hypothesis_id
            ),
            None,
        )
