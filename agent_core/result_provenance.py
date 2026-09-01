"""Immutable, secret-safe provenance primitives for persisted Phase 2 results."""

from __future__ import annotations

import json
import re
import uuid
from hashlib import sha256
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from pydantic import Field

from agent_core.agent_models import StrictModel
from agent_core.result_normalizer import public_result, sanitize_url

RESULT_SCHEMA_VERSION = 2
RESULT_ID_PATTERN = re.compile(r"res_[0-9a-f]{32}")
RESULT_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TARGET_FINGERPRINT_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class ExecutorProvenance(StrictModel):
    """Stable identity for the controlled implementation that produced evidence."""

    name: str = Field(min_length=1, max_length=100)
    version: str = Field(pattern=r"[a-z0-9_]+/v[1-9][0-9]*")
    implementation_family: str = Field(min_length=1, max_length=100)


def controlled_executor_provenance(category: str) -> dict[str, str]:
    """Backward-compatible registry-gated typed producer metadata helper."""

    from agent_core.verification_capabilities import typed_producer_provenance

    return typed_producer_provenance(category)


def new_result_id() -> str:
    return f"res_{uuid.uuid4().hex}"


def _hashable_result(result: Mapping[str, Any]) -> dict[str, Any]:
    normalized = public_result(dict(result))
    if not isinstance(normalized, dict):
        raise ValueError("Verification result must normalize to an object.")
    normalized.pop("result_id", None)
    normalized.pop("result_hash", None)
    return normalized


def canonical_result_json(result: Mapping[str, Any]) -> str:
    """Canonical public JSON used as the deterministic result hash basis."""

    return json.dumps(
        _hashable_result(result),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def result_content_hash(result: Mapping[str, Any]) -> str:
    digest = sha256(canonical_result_json(result).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def validate_result_provenance(result: Mapping[str, Any]) -> None:
    result_id = result.get("result_id")
    result_hash = result.get("result_hash")
    if not isinstance(result_id, str) or not RESULT_ID_PATTERN.fullmatch(result_id):
        raise ValueError("Persisted result_id is invalid.")
    if not isinstance(result_hash, str) or not RESULT_HASH_PATTERN.fullmatch(
        result_hash
    ):
        raise ValueError("Persisted result_hash is invalid.")
    schema_version = result.get("result_schema_version")
    if type(schema_version) is not int or schema_version != RESULT_SCHEMA_VERSION:
        raise ValueError("Persisted result schema version is unsupported.")
    ExecutorProvenance.model_validate(result.get("executor"))
    if result_content_hash(result) != result_hash:
        raise ValueError("Persisted result content hash is invalid.")


def exact_target_normalization(target: str) -> str:
    """Normalize an exact target before hashing without redacting query values.

    Scheme and host are lower-cased, default ports and a root-only slash are
    removed, query pairs are decoded then sorted and re-encoded, and fragments
    are ignored. Query values remain part of the normalized identity.
    """

    raw = str(target).strip()
    parsed = urlsplit(raw)
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("Target must be an absolute HTTP(S) URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target contains an invalid port.") from exc
    host = parsed.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    default_port = (scheme, port) in {("http", 80), ("https", 443)}
    host_port = host if port is None or default_port else f"{host}:{port}"
    userinfo = ""
    if parsed.username is not None:
        userinfo = quote(unquote(parsed.username), safe="")
        if parsed.password is not None:
            userinfo += ":" + quote(unquote(parsed.password), safe="")
        userinfo += "@"
    netloc = userinfo + host_port
    path = parsed.path or ""
    if path == "/":
        path = ""
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def target_identity(target: str) -> tuple[str, str]:
    normalized = exact_target_normalization(target)
    fingerprint = f"sha256:{sha256(normalized.encode('utf-8')).hexdigest()}"
    return sanitize_url(normalized), fingerprint


def validate_target_fingerprint(value: Any) -> str:
    if not isinstance(value, str) or not TARGET_FINGERPRINT_PATTERN.fullmatch(value):
        raise ValueError("Target fingerprint is invalid.")
    return value


def verification_result_reference(
    run_id: str, result: Mapping[str, Any]
) -> dict[str, Any]:
    hypothesis_id = str(result.get("hypothesis_id") or "unknown")
    result_id = result.get("result_id")
    result_hash = result.get("result_hash")
    if (
        isinstance(result_id, str)
        and RESULT_ID_PATTERN.fullmatch(result_id)
        and isinstance(result_hash, str)
        and RESULT_HASH_PATTERN.fullmatch(result_hash)
    ):
        reference: dict[str, Any] = {
            "run_id": str(run_id),
            "result_id": result_id,
            "result_hash": result_hash,
            "hypothesis_id": hypothesis_id,
        }
        executor = result.get("executor")
        if isinstance(executor, Mapping) and isinstance(executor.get("version"), str):
            reference["executor_version"] = executor["version"]
        return reference
    return {
        "run_id": str(run_id),
        "hypothesis_id": hypothesis_id,
        "provenance_status": "legacy_unversioned",
    }
