"""Credential-free, reusable capture context profiles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from agent_core.agent_models import StrictModel
from agent_core.policy import normalize_profile_name

DEFAULT_CONTEXT_DIRECTORY = Path("config/contexts")
_SENSITIVE_KEY = re.compile(
    r"credential|password|passwd|secret|token|authorization|cookie|api.?key|session",
    re.I,
)


class ContextIdentity(StrictModel):
    identity_id: str | None = None
    captured_label: str | None = None
    label: str
    role: str = "unknown"
    tenant: str | None = None
    controlled: bool = True
    request_ids: list[str] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def has_capture_reference(self) -> "ContextIdentity":
        if not (self.identity_id or self.captured_label or self.label):
            raise ValueError(
                "context identity requires a label or captured identity reference"
            )
        return self


class ContextObject(StrictModel):
    object_id: str
    object_type: str = "unknown"
    owner_identity_id: str | None = None
    tenant: str | None = None
    test_owned: bool = False
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


class ContextProfile(StrictModel):
    identities: list[ContextIdentity] = Field(default_factory=list, max_length=100)
    objects: list[ContextObject] = Field(default_factory=list, max_length=5000)


def compile_context(manifest: dict[str, Any]) -> ContextProfile:
    if not isinstance(manifest, dict):
        raise ValueError("Context JSON must contain an object at the top level.")
    sensitive_paths: list[str] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if _SENSITIVE_KEY.search(str(key)):
                    sensitive_paths.append(path)
                walk(child, path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{prefix}[{index}]")

    walk(manifest)
    if sensitive_paths:
        raise ValueError(
            "Context profiles cannot store credentials or secrets; remove: "
            + ", ".join(sensitive_paths)
        )
    return ContextProfile.model_validate(manifest)


def load_context(path: str | Path) -> ContextProfile:
    context_path = Path(path)
    try:
        payload = json.loads(context_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Malformed context JSON in {context_path}: {exc.msg}"
        ) from exc
    return compile_context(payload)


class ContextProfileStore:
    def __init__(self, directory: str | Path = DEFAULT_CONTEXT_DIRECTORY) -> None:
        self.directory = Path(directory)

    def path_for(self, profile: str) -> Path:
        return self.directory / f"{normalize_profile_name(profile)}.json"

    def list(self) -> list[str]:
        if not self.directory.exists():
            return []
        profiles: list[str] = []
        for path in self.directory.glob("*.json"):
            try:
                profiles.append(normalize_profile_name(path.stem))
            except ValueError:
                continue
        return sorted(profiles)

    def load(self, profile: str) -> ContextProfile:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if not path.is_file():
            raise ValueError(f"Context profile '{name}' does not exist at {path}.")
        return load_context(path)

    def create(
        self, profile: str, manifest: ContextProfile | dict[str, Any]
    ) -> ContextProfile:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if path.exists():
            raise ValueError(f"Context profile '{name}' already exists.")
        context = self._compile(manifest)
        self._write(path, context)
        return context

    def update(
        self, profile: str, manifest: ContextProfile | dict[str, Any]
    ) -> ContextProfile:
        name = normalize_profile_name(profile)
        path = self.path_for(name)
        if not path.is_file():
            raise ValueError(f"Context profile '{name}' does not exist.")
        context = self._compile(manifest)
        self._write(path, context)
        return context

    @staticmethod
    def _compile(manifest: ContextProfile | dict[str, Any]) -> ContextProfile:
        if isinstance(manifest, ContextProfile):
            return manifest
        return compile_context(dict(manifest))

    def _write(self, path: Path, context: ContextProfile) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(context.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )


ContextProfileManager = ContextProfileStore


def load_context_profile(
    profile: str, *, directory: str | Path = DEFAULT_CONTEXT_DIRECTORY
) -> ContextProfile:
    return ContextProfileStore(directory).load(profile)
