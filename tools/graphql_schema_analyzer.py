"""Bounded offline analysis of already-obtained GraphQL schemas."""

from __future__ import annotations

from typing import Any

SENSITIVE = (
    "account",
    "admin",
    "billing",
    "email",
    "file",
    "identity",
    "order",
    "password",
    "payment",
    "permission",
    "phone",
    "role",
    "secret",
    "token",
    "upload",
)
PRIVILEGED = (
    "admin",
    "delete",
    "disable",
    "grant",
    "impersonate",
    "permission",
    "promote",
    "refund",
    "role",
    "suspend",
)
ID_NAMES = {"id", "objectid", "userid", "accountid", "orderid", "uuid"}
BUILTIN_SCALARS = {"String", "Int", "Float", "Boolean", "ID"}


def _type_name(value: Any) -> str | None:
    while isinstance(value, dict):
        if value.get("name"):
            return str(value["name"])
        value = value.get("ofType")
    return None


def analyze_graphql_schema(schema_input: Any) -> dict[str, Any]:
    base = {
        "success": False,
        "counts": {},
        "query_operations": [],
        "mutation_operations": [],
        "subscription_operations": [],
        "representative_fields": [],
        "classifications": {},
        "deprecated_fields": [],
        "sensitive_fields": [],
        "custom_scalars": [],
        "upload_scalars": [],
        "truncated": {},
        "vulnerability_status": "observation",
        "planning_only": True,
    }
    if not isinstance(schema_input, dict):
        return {**base, "error": "Schema input must be structured JSON."}
    schema = schema_input.get("data", schema_input).get(
        "__schema", schema_input.get("__schema", schema_input)
    )
    types = schema.get("types") if isinstance(schema, dict) else None
    if not isinstance(types, list):
        return {**base, "error": "No GraphQL schema type list was found."}
    by_name = {t.get("name"): t for t in types if isinstance(t, dict) and t.get("name")}
    root_names = {
        k: _type_name(schema.get(k))
        for k in ("queryType", "mutationType", "subscriptionType")
    }
    categories: dict[str, list[dict[str, Any]]] = {
        k: []
        for k in (
            "public_read_candidate",
            "account_read_candidate",
            "object_authorization_candidate",
            "privileged_operation_candidate",
            "state_change_candidate",
            "upload_operation_candidate",
            "administrative_candidate",
        )
    }
    representatives: list[dict[str, Any]] = []
    sensitive: list[dict[str, Any]] = []
    deprecated: list[dict[str, Any]] = []
    operation_lists: dict[str, list[dict[str, Any]]] = {
        "queryType": [],
        "mutationType": [],
        "subscriptionType": [],
    }
    for root_key, root_name in root_names.items():
        root = by_name.get(root_name, {})
        for field in root.get("fields") or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            name = str(field["name"])
            args = [
                str(a.get("name"))
                for a in field.get("args") or []
                if isinstance(a, dict) and a.get("name")
            ]
            item = {
                "name": name,
                "arguments": args,
                "return_type": _type_name(field.get("type")),
            }
            operation_lists[root_key].append(item)
            lower = name.lower()
            if root_key == "mutationType":
                categories["state_change_candidate"].append(item)
            else:
                categories["public_read_candidate"].append(item)
            if any(x in lower for x in ("account", "user", "profile", "me")):
                categories["account_read_candidate"].append(item)
            if any(a.lower().replace("_", "") in ID_NAMES for a in args):
                categories["object_authorization_candidate"].append(item)
            if any(x in lower for x in PRIVILEGED):
                categories["privileged_operation_candidate"].append(item)
            if any(x in lower for x in ("admin", "permission", "role")):
                categories["administrative_candidate"].append(item)
            if "upload" in lower or "file" in lower:
                categories["upload_operation_candidate"].append(item)
    for type_item in types:
        if not isinstance(type_item, dict):
            continue
        type_name = str(type_item.get("name") or "")
        for field in type_item.get("fields") or []:
            if not isinstance(field, dict) or not field.get("name"):
                continue
            item = {
                "type": type_name,
                "field": str(field["name"]),
                "return_type": _type_name(field.get("type")),
            }
            representatives.append(item)
            lower = item["field"].lower()
            matches = sorted(x for x in SENSITIVE if x in lower)
            if matches:
                sensitive.append(
                    {**item, "categories": matches, "status": "observation"}
                )
            if field.get("isDeprecated"):
                deprecated.append({**item, "reason": field.get("deprecationReason")})
    custom = sorted(
        str(t.get("name"))
        for t in types
        if isinstance(t, dict)
        and t.get("kind") == "SCALAR"
        and t.get("name") not in BUILTIN_SCALARS
        and not str(t.get("name", "")).startswith("__")
    )
    counts = {
        kind.lower(): sum(isinstance(t, dict) and t.get("kind") == kind for t in types)
        for kind in ("OBJECT", "INPUT_OBJECT", "ENUM", "INTERFACE", "UNION", "SCALAR")
    }
    counts.update(
        {
            "types": len(types),
            "query_operations": len(operation_lists["queryType"]),
            "mutation_operations": len(operation_lists["mutationType"]),
            "subscription_operations": len(operation_lists["subscriptionType"]),
            "deprecated_fields": len(deprecated),
            "sensitive_fields": len(sensitive),
        }
    )

    def bounded(values: list[Any], maximum: int) -> list[Any]:
        return sorted(values, key=lambda x: str(x.get("name") or x.get("field") or x))[
            :maximum
        ]

    base.update(
        success=True,
        counts=counts,
        query_operations=bounded(operation_lists["queryType"], 25),
        mutation_operations=bounded(operation_lists["mutationType"], 25),
        subscription_operations=bounded(operation_lists["subscriptionType"], 25),
        representative_fields=bounded(representatives, 50),
        classifications={k: bounded(v, 25) for k, v in categories.items()},
        deprecated_fields=bounded(deprecated, 25),
        sensitive_fields=bounded(sensitive, 25),
        custom_scalars=custom[:25],
        upload_scalars=[
            x for x in custom if "upload" in x.lower() or "file" in x.lower()
        ][:25],
        truncated={
            "representative_fields": len(representatives) > 50,
            **{k: len(v) > 25 for k, v in categories.items()},
        },
    )
    return base


graphql_schema_analyzer = analyze_graphql_schema
