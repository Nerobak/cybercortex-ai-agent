"""Redacted, append-only, hash-chained execution audit log."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from agent_core.result_normalizer import redact, sanitize_text


class TamperEvidentAuditLog:
    def __init__(self, path: str | Path = "logs/agent-audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._previous_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        try:
            last = ""
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last = line
            return str(json.loads(last).get("entry_hash") or "0" * 64)
        except (OSError, json.JSONDecodeError):
            return "0" * 64

    def append(
        self,
        event: str,
        data: dict[str, Any],
        *,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "run_id": sanitize_text(run_id) if run_id is not None else None,
                "event": sanitize_text(event),
                "data": redact(data),
                "previous_hash": self._previous_hash,
            }
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry["entry_hash"] = sha256(canonical.encode()).hexdigest()
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            descriptor = os.open(self.path, flags, 0o600)
            try:
                os.write(
                    descriptor, (json.dumps(entry, sort_keys=True) + "\n").encode()
                )
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._previous_hash = entry["entry_hash"]
            return entry

    def verify(self) -> dict[str, Any]:
        previous = "0" * 64
        entries = 0
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    entry = json.loads(line)
                    recorded = entry.pop("entry_hash", None)
                    if entry.get("previous_hash") != previous:
                        return {
                            "valid": False,
                            "line": line_number,
                            "error": "Hash-chain predecessor mismatch.",
                        }
                    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                    calculated = sha256(canonical.encode()).hexdigest()
                    if calculated != recorded:
                        return {
                            "valid": False,
                            "line": line_number,
                            "error": "Audit entry hash mismatch.",
                        }
                    previous = recorded
                    entries += 1
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "valid": False,
                "entries": entries,
                "error": sanitize_text(str(exc)),
            }
        return {"valid": True, "entries": entries, "head_hash": previous}
