"""Offline, non-executing GraphQL document inspection."""

from __future__ import annotations

import re
from typing import Any

SENSITIVE = {
    "identity",
    "account",
    "role",
    "permission",
    "payment",
    "order",
    "billing",
    "email",
    "phone",
    "token",
    "secret",
    "password",
    "file",
    "upload",
    "admin",
}
TOKEN = re.compile(
    r'\.\.\.|\$?[A-Za-z_][A-Za-z0-9_]*|[!$():=@\[\]{|}]|\d+|"(?:\\.|[^"\\])*"'
)


def _empty(error: str | None = None) -> dict[str, Any]:
    value = {
        "success": error is None,
        "operation_type": "unknown",
        "operation_name": None,
        "fields": [],
        "arguments": [],
        "sensitive_field_observations": [],
        "nesting_depth": 0,
        "aliases": [],
        "variables": [],
        "fragments": [],
        "directives": [],
        "repeated_fields": [],
        "risk_notes": [],
        "vulnerability_status": "observation",
        "executed": False,
    }
    if error:
        value["error"] = error
    return value


def analyze_graphql_query(document: str) -> dict[str, Any]:
    """Conservatively inspect a bounded GraphQL document; never execute it."""
    if not isinstance(document, str) or not document.strip():
        return _empty("GraphQL input must be a non-empty string.")
    if len(document.encode("utf-8")) > 1_000_000:
        return _empty("GraphQL input exceeds the offline analysis limit.")
    cleaned = re.sub(r'""".*?"""', '""', document, flags=re.S)
    cleaned = re.sub(r"#[^\n]*", "", cleaned)
    tokens = TOKEN.findall(cleaned)
    if not tokens or tokens.count("{") != tokens.count("}") or "{" not in tokens:
        return _empty(
            "Malformed GraphQL document: unbalanced or missing selection set."
        )
    result = _empty()
    first = tokens[0].lower()
    result["operation_type"] = (
        first
        if first in {"query", "mutation", "subscription"}
        else "query" if first == "{" else "unknown"
    )
    if (
        first in {"query", "mutation", "subscription"}
        and len(tokens) > 1
        and re.match(r"^[A-Za-z_]", tokens[1])
    ):
        result["operation_name"] = tokens[1]
    depth = 0
    max_depth = 0
    field_counts: dict[str, int] = {}
    fields: list[str] = []
    aliases: list[str] = []
    arguments: list[str] = []
    variables: list[str] = []
    fragments: list[str] = []
    directives: list[str] = []
    skip_words = {
        "query",
        "mutation",
        "subscription",
        "fragment",
        "on",
        "true",
        "false",
        "null",
    }
    for index, token in enumerate(tokens):
        if token == "{":
            depth += 1
            max_depth = max(max_depth, depth)
            continue
        if token == "}":
            depth -= 1
            continue
        if token.startswith("$"):
            if token[1:] not in variables:
                variables.append(token[1:])
            continue
        if token == "..." and index + 1 < len(tokens):
            name = tokens[index + 1]
            if name != "on" and name not in fragments:
                fragments.append(name)
            continue
        if token == "fragment" and index + 1 < len(tokens):
            if tokens[index + 1] not in fragments:
                fragments.append(tokens[index + 1])
            continue
        if token == "@" and index + 1 < len(tokens):
            directives.append(tokens[index + 1])
            continue
        if not re.match(r"^[A-Za-z_]", token) or token.lower() in skip_words:
            continue
        previous = tokens[index - 1] if index else ""
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if following == ":" and previous != "$":
            # An alias appears in a selection; argument names also use colon.
            if depth > 0 and (
                index + 2 < len(tokens) and tokens[index + 2] not in {"$", "["}
            ):
                aliases.append(token)
            else:
                arguments.append(token)
            continue
        if depth > 0 and previous not in {"@", "...", ":", "$"}:
            fields.append(token)
            field_counts[token] = field_counts.get(token, 0) + 1
    # Remove operation/type names conservatively captured before the selection.
    fields = [f for f in fields if f != result["operation_name"]]
    result.update(
        fields=list(dict.fromkeys(fields))[:200],
        aliases=list(dict.fromkeys(aliases))[:100],
        arguments=list(dict.fromkeys(arguments))[:100],
        variables=variables[:100],
        fragments=fragments[:100],
        directives=list(dict.fromkeys(directives))[:100],
        nesting_depth=max_depth,
        repeated_fields=sorted(k for k, v in field_counts.items() if v > 1)[:100],
    )
    sensitive = []
    for field in result["fields"]:
        categories = sorted(word for word in SENSITIVE if word in field.lower())
        if categories:
            sensitive.append(
                {"field": field, "categories": categories, "status": "observation"}
            )
    result["sensitive_field_observations"] = sensitive[:100]
    if result["operation_type"] == "mutation":
        result["risk_notes"].append(
            "A state-changing operation name was observed; it was not executed."
        )
    if aliases:
        result["risk_notes"].append(
            "Aliases were observed offline; no alias-amplification request was sent."
        )
    return result


graphql_query_analyzer = analyze_graphql_query
