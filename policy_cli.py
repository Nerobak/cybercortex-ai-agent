#!/usr/bin/env python3
"""Create and maintain persistent, versioned CyberCortex policy profiles."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
from collections.abc import Callable
from typing import Any

from agent_core.context import ContextProfileStore
from agent_core.policy import (
    DEFAULT_PROHIBITED_TECHNIQUES,
    PolicyProfileStore,
    format_policy_summary,
)

Input = Callable[[str], str]


def _answer(prompt: str, input_fn: Input, *, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input_fn(f"{prompt}{suffix}: ").strip()
    return value if value else (default or "")


def _required(prompt: str, input_fn: Input) -> str:
    while True:
        value = _answer(prompt, input_fn)
        if value:
            return value
        print(f"{prompt} is required.")


def _boolean(prompt: str, input_fn: Input, *, default: bool = False) -> bool:
    marker = "yes" if default else "no"
    while True:
        value = _answer(prompt, input_fn, default=marker).lower()
        if value in {"yes", "y", "true", "1"}:
            return True
        if value in {"no", "n", "false", "0"}:
            return False
        print("Enter yes or no.")


def _list(prompt: str, input_fn: Input, *, default: str = "") -> list[str]:
    return [
        item.strip()
        for item in _answer(prompt, input_fn, default=default).split(",")
        if item.strip()
    ]


def _integer(prompt: str, input_fn: Input, *, default: int) -> int:
    while True:
        try:
            return int(_answer(prompt, input_fn, default=str(default)))
        except ValueError:
            print("Enter a whole number.")


def _number(prompt: str, input_fn: Input, *, default: float) -> float:
    while True:
        try:
            return float(_answer(prompt, input_fn, default=f"{default:g}"))
        except ValueError:
            print("Enter a number.")


def _asset(value: str, *, schemes: list[str], ports: list[int]) -> dict[str, Any]:
    cleaned = value.strip()
    if "://" in cleaned:
        kind = "url_prefix"
    elif cleaned.startswith("*."):
        kind = "wildcard_host"
    elif "/" in cleaned:
        kind = "cidr"
    else:
        kind = "exact_host"
    return {"kind": kind, "value": cleaned, "schemes": schemes, "ports": ports}


def _collect_policy(
    input_fn: Input, *, concise: bool = False
) -> tuple[str, dict[str, Any]]:
    profile = _required("Profile name", input_fn)
    program = _required("Program name", input_fn)
    confirmed = _boolean("Authorization confirmed?", input_fn)
    reference = _required("Authorization reference", input_fn)
    exact_hosts = _list(
        "Allowed asset" if concise else "Allowed domains/hosts (comma-separated)",
        input_fn,
    )
    wildcard_hosts: list[str] = []
    if concise:
        if exact_hosts and _boolean("Allow subdomains?", input_fn):
            wildcard_hosts = exact_hosts
    else:
        wildcard_hosts = _list(
            "Wildcard subdomain bases (comma-separated, blank for none)", input_fn
        )
    prefixes = (
        []
        if concise
        else _list(
            "URL-prefix restrictions (comma-separated, blank for none)", input_fn
        )
    )
    exclusions = (
        []
        if concise
        else _list("Excluded assets (comma-separated, blank for none)", input_fn)
    )
    schemes = [
        item.lower() for item in _list("Allowed schemes", input_fn, default="https")
    ]
    ports = [int(item) for item in _list("Allowed ports", input_fn, default="443")]
    methods = [
        item.upper()
        for item in _list(
            "Allowed methods",
            input_fn,
            default=(
                "GET,POST,PUT,PATCH,DELETE,OPTIONS" if concise else "GET,HEAD,OPTIONS"
            ),
        )
    ]
    rate = _number(
        "Rate limit" if concise else "Requests per second", input_fn, default=2
    )
    max_concurrency = (
        2 if concise else _integer("Maximum concurrency", input_fn, default=2)
    )
    request_budget = (
        100 if concise else _integer("Total request budget", input_fn, default=100)
    )
    per_host_budget = (
        50 if concise else _integer("Per-host request budget", input_fn, default=50)
    )
    max_response = (
        1_000_000
        if concise
        else _integer("Maximum response size in bytes", input_fn, default=1_000_000)
    )
    credentials = _boolean(
        "Authenticated testing permitted?" if concise else "Credential use permitted?",
        input_fn,
    )
    state_changes = _boolean("State changes permitted?", input_fn)
    oast = False if concise else _boolean("OAST permitted?", input_fn)
    callback_hosts = (
        _list("OAST callback hosts (comma-separated)", input_fn) if oast else []
    )
    testing_windows: list[dict[str, str]] = []
    if not concise and _boolean("Restrict testing to a time window?", input_fn):
        testing_windows.append(
            {
                "starts_at": _required("Testing window starts (ISO 8601)", input_fn),
                "ends_at": _required("Testing window ends (ISO 8601)", input_fn),
            }
        )
    program_blocks = (
        [] if concise else _list("Program-specific prohibited techniques", input_fn)
    )
    owned = _boolean("Require test-owned objects?", input_fn, default=True)
    cleanup = _boolean("Require cleanup?", input_fn, default=True)
    allowed_assets = [
        *(_asset(host, schemes=schemes, ports=ports) for host in exact_hosts),
        *(
            _asset(f"*.{host.removeprefix('*.')}", schemes=schemes, ports=ports)
            for host in wildcard_hosts
        ),
        *(_asset(prefix, schemes=schemes, ports=ports) for prefix in prefixes),
    ]
    excluded_assets = [
        _asset(item, schemes=schemes, ports=ports) for item in exclusions
    ]
    return profile, {
        "program_name": program,
        "authorization_reference": reference,
        "authorization_confirmed": confirmed,
        "allowed_assets": allowed_assets,
        "excluded_assets": excluded_assets,
        "allowed_methods": methods,
        "prohibited_techniques": sorted(
            set(DEFAULT_PROHIBITED_TECHNIQUES)
            | {item.lower() for item in program_blocks}
        ),
        "allowed_capabilities": ["oast"] if oast else [],
        "oast_allowed": oast,
        "callback_hosts": callback_hosts,
        "testing_windows": testing_windows,
        "requests_per_second": rate,
        "max_concurrency": max_concurrency,
        "request_budget": request_budget,
        "per_host_request_budget": per_host_budget,
        "max_response_bytes": max_response,
        "credentials_allowed": credentials,
        "allow_state_changes": state_changes,
        "require_test_owned_resources": owned,
        "require_cleanup_for_state_changes": cleanup,
    }


def _editable_manifest(policy: Any) -> dict[str, Any]:
    payload = policy.model_dump(mode="json")
    for key in (
        "profile_name",
        "policy_version",
        "created_at",
        "updated_at",
        "policy_hash",
        "change_history",
        "cloned_from",
    ):
        payload.pop(key, None)
    return payload


def _edit_json(payload: dict[str, Any]) -> dict[str, Any]:
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        raise ValueError("Set VISUAL or EDITOR before using edit.")
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".json", encoding="utf-8"
    ) as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
        handle.flush()
        command = [*shlex.split(editor), handle.name]
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            raise ValueError(f"Editor exited with status {completed.returncode}.")
        handle.seek(0)
        try:
            edited = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Edited JSON is malformed: {exc.msg}") from exc
    if not isinstance(edited, dict):
        raise ValueError("Edited policy must be a JSON object.")
    return edited


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage saved CyberCortex policy profiles."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create")
    commands.add_parser("list")
    for command in ("show", "edit", "validate", "delete"):
        child = commands.add_parser(command)
        child.add_argument("profile")
    clone = commands.add_parser("clone")
    clone.add_argument("source")
    clone.add_argument("new")
    mapping = commands.add_parser("map-host")
    mapping.add_argument("hostname")
    mapping.add_argument("profile")
    commands.add_parser("init-target")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    store: PolicyProfileStore | None = None,
    context_store: ContextProfileStore | None = None,
    input_fn: Input = input,
) -> int:
    args = build_parser().parse_args(argv)
    profiles = store or PolicyProfileStore()
    contexts = context_store or ContextProfileStore()
    try:
        if args.command == "create":
            name, manifest = _collect_policy(input_fn)
            policy = profiles.create(name, manifest)
            print(
                f"Created policy profile '{policy.profile_name}' version {policy.policy_version}."
            )
        elif args.command == "list":
            for name in profiles.list():
                print(name)
        elif args.command == "show":
            policy = profiles.load(args.profile)
            print(json.dumps(policy.model_dump(mode="json"), indent=2))
        elif args.command == "validate":
            policy = profiles.load(args.profile, validate_for_execution=True)
            print(format_policy_summary(policy, profile=args.profile))
            print("\nVALID")
        elif args.command == "edit":
            previous = profiles.load(args.profile)
            edited = _edit_json(_editable_manifest(previous))
            policy = profiles.update(args.profile, edited)
            print(
                f"Updated policy profile '{args.profile}' to version {policy.policy_version}."
            )
        elif args.command == "clone":
            policy = profiles.clone(args.source, args.new)
            print(f"Cloned '{args.source}' to '{policy.profile_name}' version 1.")
        elif args.command == "delete":
            if not _boolean(f"Delete policy profile '{args.profile}'?", input_fn):
                print("Delete cancelled.")
                return 1
            profiles.delete(args.profile)
            print(f"Deleted policy profile '{args.profile}'.")
        elif args.command == "map-host":
            profiles.map_host(args.hostname, args.profile)
            print(
                f"Mapped exact host '{args.hostname}' to policy profile '{args.profile}'."
            )
        elif args.command == "init-target":
            name, manifest = _collect_policy(input_fn, concise=True)
            policy = profiles.create(name, manifest)
            print(f"Created policy profile '{policy.profile_name}' version 1.")
            if _boolean("Create a matching context template?", input_fn, default=True):
                context = {"identities": [], "objects": []}
                if policy.credentials_allowed:
                    context = {
                        "identities": [
                            {
                                "label": "account-a",
                                "role": "unknown",
                                "controlled": True,
                            },
                            {
                                "label": "account-b",
                                "role": "unknown",
                                "controlled": True,
                            },
                        ],
                        "objects": [],
                    }
                contexts.create(name, context)
                print(f"Created context profile '{name}'.")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
