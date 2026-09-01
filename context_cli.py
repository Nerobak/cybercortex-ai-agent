#!/usr/bin/env python3
"""Create and maintain credential-free CyberCortex context profiles."""

from __future__ import annotations

import argparse
import json

from agent_core.context import ContextProfileStore
from policy_cli import _boolean, _edit_json, _list, _required


def _collect_context(input_fn=input):
    profile = _required("Profile name", input_fn)
    identities = []
    while _boolean("Add a controlled identity?", input_fn):
        identities.append(
            {
                "captured_label": _required("Captured identity label", input_fn),
                "label": _required("Context identity label", input_fn),
                "role": _required("Role", input_fn),
                "tenant": _required("Tenant", input_fn),
                "controlled": True,
                "request_ids": [],
            }
        )
    objects = []
    while _boolean("Add a researcher-owned object?", input_fn):
        objects.append(
            {
                "object_id": _required("Object identifier", input_fn),
                "object_type": _required("Object type", input_fn),
                "owner_identity_id": _required("Owner identity ID", input_fn),
                "tenant": _required("Tenant", input_fn),
                "test_owned": _boolean("Researcher-owned?", input_fn, default=True),
                "evidence_refs": _list("Evidence references", input_fn),
            }
        )
    return profile, {"identities": identities, "objects": objects}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage saved CyberCortex context profiles."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create")
    commands.add_parser("list")
    for command in ("show", "edit", "validate"):
        child = commands.add_parser(command)
        child.add_argument("profile")
    return parser


def main(argv=None, *, store=None, input_fn=input) -> int:
    args = build_parser().parse_args(argv)
    profiles = store or ContextProfileStore()
    try:
        if args.command == "create":
            name, manifest = _collect_context(input_fn)
            profiles.create(name, manifest)
            print(f"Created context profile '{name}'.")
        elif args.command == "list":
            for name in profiles.list():
                print(name)
        elif args.command == "show":
            context = profiles.load(args.profile)
            print(json.dumps(context.model_dump(mode="json"), indent=2))
        elif args.command == "edit":
            context = profiles.load(args.profile)
            edited = _edit_json(context.model_dump(mode="json"))
            profiles.update(args.profile, edited)
            print(f"Updated context profile '{args.profile}'.")
        elif args.command == "validate":
            context = profiles.load(args.profile)
            print(
                f"VALID: {len(context.identities)} identities, "
                f"{len(context.objects)} objects, no stored credentials."
            )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
