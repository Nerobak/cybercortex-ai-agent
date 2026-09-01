"""Process-local credential vault used by capture ingestion and replay.

Secrets are kept out of plans, the attack-surface database, reports, and audit
events. The process-local implementation deliberately has no persistence; a
future OS keychain adapter can implement the same interface.
"""

from __future__ import annotations

import secrets
import threading
from hashlib import sha256
from typing import Mapping

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}


class CredentialVault:
    def __init__(self) -> None:
        self._values: dict[str, bytearray] = {}
        self._lock = threading.RLock()
        self._closed = False

    def put(self, value: str, *, label: str = "credential") -> str:
        if self._closed:
            raise RuntimeError("Credential vault is closed.")
        material = value.encode("utf-8")
        reference = (
            "cred_"
            + sha256(label.encode() + material + secrets.token_bytes(16)).hexdigest()[
                :20
            ]
        )
        with self._lock:
            self._values[reference] = bytearray(material)
        return reference

    def get(self, reference: str) -> str:
        if self._closed:
            raise RuntimeError("Credential vault is closed.")
        with self._lock:
            if reference not in self._values:
                raise KeyError("Unknown credential reference.")
            return bytes(self._values[reference]).decode("utf-8")

    def contains(self, reference: str) -> bool:
        """Check a process-local reference without materializing its value."""
        if self._closed:
            raise RuntimeError("Credential vault is closed.")
        with self._lock:
            return reference in self._values

    def redact_headers(
        self, headers: Mapping[str, str]
    ) -> tuple[dict[str, str], dict[str, str]]:
        sanitized: dict[str, str] = {}
        references: dict[str, str] = {}
        for name, value in headers.items():
            if name.lower() in SENSITIVE_HEADER_NAMES:
                reference = self.put(value, label=f"header:{name.lower()}")
                sanitized[name] = f"[CREDENTIAL_REF:{reference}]"
                references[name] = reference
            else:
                sanitized[name] = value
        return sanitized, references

    def materialize_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        materialized: dict[str, str] = {}
        prefix = "[CREDENTIAL_REF:"
        for name, value in headers.items():
            if (
                isinstance(value, str)
                and value.startswith(prefix)
                and value.endswith("]")
            ):
                materialized[name] = self.get(value[len(prefix) : -1])
            else:
                materialized[name] = value
        return materialized

    def discard(self, reference: str) -> bool:
        """Zero and remove one process-local credential without closing the vault."""
        if self._closed:
            raise RuntimeError("Credential vault is closed.")
        with self._lock:
            value = self._values.pop(reference, None)
            if value is None:
                return False
            for index in range(len(value)):
                value[index] = 0
            return True

    def close(self) -> None:
        with self._lock:
            for value in self._values.values():
                for index in range(len(value)):
                    value[index] = 0
            self._values.clear()
            self._closed = True

    def __enter__(self) -> "CredentialVault":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def credential_reference_count(headers: Mapping[str, str]) -> int:
    return sum(
        isinstance(value, str) and value.startswith("[CREDENTIAL_REF:")
        for value in headers.values()
    )
