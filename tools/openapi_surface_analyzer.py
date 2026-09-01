"""Bounded, deterministic, offline OpenAPI attack-surface extraction."""

from __future__ import annotations

import ast
import json
import re
from typing import Any

from agent_core.auth_semantics import safe_auth_semantic_summary
from agent_core.route_identity import normalize_route_path, route_identity

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
IDENTIFIER_NAMES = {
    "id",
    "user_id",
    "account_id",
    "order_id",
    "tenant_id",
    "resource_id",
    "owner_id",
    "document_id",
    "profile_id",
}
SENSITIVE_VALUE_KEYS = {
    "authorizationurl",
    "const",
    "enum",
    "example",
    "examples",
    "default",
    "openidconnecturl",
    "tokenurl",
    "value",
    "externalvalue",
}
OMITTED_METADATA_KEYS = {
    "description",
    "externaldocs",
    "contact",
    "license",
    "servers",
}
MAX_DOCUMENT_ITEMS = 20_000


def _scalar(value: str) -> Any:
    text = value.strip()
    if not text:
        return {}
    if text in {"{}", "[]"}:
        return {} if text == "{}" else []
    lowered = text.lower()
    if lowered in {"true", "false", "null", "~"}:
        return {"true": True, "false": False, "null": None, "~": None}[lowered]
    if (text.startswith("'") and text.endswith("'")) or (
        text.startswith('"') and text.endswith('"')
    ):
        return text[1:-1]
    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return text


def _split_yaml_key(line: str) -> tuple[str, str] | None:
    quoted: str | None = None
    for index, char in enumerate(line):
        if char in {"'", '"'}:
            quoted = None if quoted == char else char if quoted is None else quoted
        elif char == ":" and quoted is None:
            return line[:index].strip().strip("'\""), line[index + 1 :].strip()
    return None


def _minimal_yaml_load(text: str) -> Any:
    """Parse the conservative indentation subset used by ordinary OpenAPI YAML."""
    meaningful: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.lstrip(" ")
        if "\t" in raw[: len(raw) - len(stripped)]:
            raise ValueError("Tabs are not accepted in fallback YAML parsing.")
        meaningful.append((len(raw) - len(stripped), stripped.rstrip()))
    if not meaningful:
        raise ValueError("Empty YAML document.")

    root: Any = [] if meaningful[0][1].startswith("- ") else {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for position, (indent, content) in enumerate(meaningful):
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError("Invalid YAML indentation.")
        parent = stack[-1][1]
        next_content = (
            meaningful[position + 1][1] if position + 1 < len(meaningful) else ""
        )
        if content.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("Unsupported YAML list placement.")
            item_text = content[2:].strip()
            key_value = _split_yaml_key(item_text)
            if key_value:
                key, raw_value = key_value
                item: dict[str, Any] = {}
                parent.append(item)
                if raw_value:
                    item[key] = _scalar(raw_value)
                else:
                    child: Any = [] if next_content.startswith("- ") else {}
                    item[key] = child
                    stack.append((indent, item))
                    stack.append((indent + 1, child))
                    continue
                stack.append((indent, item))
            else:
                parent.append(_scalar(item_text))
            continue
        key_value = _split_yaml_key(content)
        if not key_value or not isinstance(parent, dict):
            raise ValueError("Unsupported YAML structure.")
        key, raw_value = key_value
        if raw_value:
            parent[key] = _scalar(raw_value)
        else:
            child = [] if next_content.startswith("- ") else {}
            parent[key] = child
            stack.append((indent, child))
    return root


def load_structured_document(value: Any) -> dict[str, Any] | None:
    """Load an already-obtained JSON/YAML document without network access."""
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    if not isinstance(value, str) or len(value.encode("utf-8")) > 2_000_000:
        return None
    try:
        loaded = json.loads(value)
    except (ValueError, json.JSONDecodeError):
        try:
            import yaml  # type: ignore[import-not-found]

            loaded = yaml.safe_load(value)
        except (ImportError, ValueError, TypeError):
            try:
                loaded = _minimal_yaml_load(value)
            except ValueError:
                return None
    return loaded if isinstance(loaded, dict) else None


def openapi_version(document: Any) -> str | None:
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return None
    openapi = document.get("openapi")
    swagger = document.get("swagger")
    if isinstance(openapi, str) and re.fullmatch(
        r"3(?:\.\d+){1,2}(?:[-+].*)?", openapi
    ):
        return openapi
    if isinstance(swagger, str) and re.fullmatch(r"2(?:\.0+)?", swagger):
        return swagger
    return None


def is_openapi_document(value: Any) -> bool:
    document = load_structured_document(value)
    return openapi_version(document) is not None


def sanitize_openapi_document(value: dict[str, Any]) -> dict[str, Any]:
    """Remove value-bearing metadata while retaining route/schema structure."""
    budget = [MAX_DOCUMENT_ITEMS]

    def clean(item: Any, key: str = "") -> Any:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        lowered = key.lower()
        if lowered == "summary":
            return safe_auth_semantic_summary(item)
        if lowered in SENSITIVE_VALUE_KEYS or lowered in OMITTED_METADATA_KEYS:
            return None
        if isinstance(item, dict):
            result: dict[str, Any] = {}
            for raw_key, child in item.items():
                child_key = str(raw_key)
                if child_key.lower().startswith("x-"):
                    continue
                sanitized = clean(child, child_key)
                if sanitized is not None:
                    result[child_key] = sanitized
            return result
        if isinstance(item, list):
            return [clean(child) for child in item[:1000] if budget[0] >= 0]
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)

    return clean(value) or {}


def _local_ref(root: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        return None
    current: Any = root
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _resolve(
    value: Any,
    root: dict[str, Any],
    *,
    depth: int,
    max_depth: int,
    seen: frozenset[str] = frozenset(),
) -> Any:
    if depth > max_depth or not isinstance(value, dict):
        return value if isinstance(value, dict) else {}
    reference = value.get("$ref")
    if isinstance(reference, str):
        if reference in seen:
            return {}
        resolved = _local_ref(root, reference)
        if not isinstance(resolved, dict):
            return {}
        merged = dict(resolved)
        merged.update({key: item for key, item in value.items() if key != "$ref"})
        return _resolve(
            merged,
            root,
            depth=depth + 1,
            max_depth=max_depth,
            seen=seen | {reference},
        )
    return value


def _schema_type(
    value: Any,
    root: dict[str, Any],
    *,
    depth: int,
    max_depth: int,
    seen: frozenset[str] = frozenset(),
) -> str:
    """Return one deterministic semantic leaf type from an OpenAPI schema."""
    if depth > max_depth or not isinstance(value, dict):
        return "unknown"
    reference = value.get("$ref")
    if isinstance(reference, str):
        if reference in seen:
            return "unknown"
        target = _local_ref(root, reference)
        if not isinstance(target, dict):
            return "unknown"
        merged = dict(target)
        merged.update({key: item for key, item in value.items() if key != "$ref"})
        return _schema_type(
            merged,
            root,
            depth=depth + 1,
            max_depth=max_depth,
            seen=seen | {reference},
        )

    raw_type = value.get("type")
    if isinstance(raw_type, str) and raw_type != "null":
        return raw_type
    if isinstance(raw_type, list):
        declared = {
            str(item) for item in raw_type if isinstance(item, str) and item != "null"
        }
        if len(declared) == 1:
            return declared.pop()

    composed_types: set[str] = set()
    for composition in ("allOf", "oneOf", "anyOf"):
        choices = value.get(composition)
        if not isinstance(choices, list):
            continue
        for choice in choices[:20]:
            candidate = _schema_type(
                choice,
                root,
                depth=depth + 1,
                max_depth=max_depth,
                seen=seen,
            )
            if candidate not in {"null", "unknown"}:
                composed_types.add(candidate)
    if len(composed_types) == 1:
        return composed_types.pop()
    if isinstance(value.get("properties"), dict):
        return "object"
    if "items" in value:
        return "array"
    return "unknown"


def _schema_names(value: Any) -> list[str]:
    found: set[str] = set()

    def visit(item: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(item, dict):
            reference = item.get("$ref")
            if isinstance(reference, str) and reference.startswith("#/"):
                found.add(reference.rsplit("/", 1)[-1])
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item[:100]:
                visit(child, depth + 1)

    visit(value)
    return sorted(found)


def _has_unresolved_local_ref(
    value: Any,
    root: dict[str, Any],
    *,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> bool:
    """Report unresolved local references without following unbounded structures."""
    if depth > 8:
        return False
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            target = _local_ref(root, reference)
            if not isinstance(target, dict):
                return True
            if reference not in seen and _has_unresolved_local_ref(
                target,
                root,
                depth=depth + 1,
                seen=seen | {reference},
            ):
                return True
        return any(
            _has_unresolved_local_ref(
                item,
                root,
                depth=depth + 1,
                seen=seen,
            )
            for item in list(value.values())[:100]
        )
    if isinstance(value, list):
        return any(
            _has_unresolved_local_ref(
                item,
                root,
                depth=depth + 1,
                seen=seen,
            )
            for item in value[:100]
        )
    return False


def _add_route_limitation(route: dict[str, Any], message: str) -> None:
    limitations = route.setdefault("limitations", [])
    if isinstance(limitations, list) and message not in limitations:
        limitations.append(message)


def _schema_fields(
    schema: Any,
    root: dict[str, Any],
    *,
    location: str,
    source: str,
    max_depth: int,
    max_items: int,
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []

    def walk(
        item: Any, prefix: str, depth: int, required: set[str], seen: frozenset[str]
    ) -> None:
        if depth > max_depth or len(fields) >= max_items or not isinstance(item, dict):
            return
        reference = item.get("$ref")
        if isinstance(reference, str):
            if reference in seen:
                return
            target = _local_ref(root, reference)
            if not isinstance(target, dict):
                return
            merged = dict(target)
            merged.update({key: value for key, value in item.items() if key != "$ref"})
            walk(merged, prefix, depth + 1, required, seen | {reference})
            return
        for composition in ("allOf", "oneOf", "anyOf"):
            choices = item.get(composition)
            if isinstance(choices, list):
                for choice in choices[:20]:
                    walk(choice, prefix, depth + 1, required, seen)
        if item.get("type") == "array" or "items" in item:
            walk(item.get("items"), prefix, depth + 1, required, seen)
        properties = item.get("properties")
        if not isinstance(properties, dict):
            return
        local_required = {
            str(name) for name in item.get("required", []) if isinstance(name, str)
        }
        for name in sorted(properties)[:max_items]:
            if len(fields) >= max_items:
                break
            child = properties[name]
            field_path = f"{prefix}.{name}" if prefix else str(name)
            fields.append(
                {
                    "name": str(name),
                    "field_path": field_path,
                    "in": location,
                    "required": str(name) in local_required,
                    "schema_type": _schema_type(
                        child,
                        root,
                        depth=depth + 1,
                        max_depth=max_depth,
                        seen=seen,
                    ),
                    "source": source,
                }
            )
            walk(child, field_path, depth + 1, local_required, seen)

    walk(schema, "", 0, set(), frozenset())
    return fields


def _is_identifier(name: str) -> bool:
    normalized = name.strip().lower().replace("-", "_")
    return normalized in IDENTIFIER_NAMES or normalized.endswith("_id")


def _singular(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    if normalized.endswith("ies"):
        return normalized[:-3] + "y"
    if normalized.endswith("s") and len(normalized) > 1:
        return normalized[:-1]
    return normalized or "object"


def _object_type(path: str, identifier: str) -> str:
    normalized = identifier.lower().replace("-", "_")
    if normalized != "id" and normalized.endswith("_id"):
        return _singular(normalized[:-3])
    placeholder = "{" + identifier + "}"
    segments = [segment for segment in path.split("/") if segment]
    if placeholder in segments:
        index = segments.index(placeholder)
        if index:
            return _singular(segments[index - 1])
    return "object"


def _security_schemes(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = (
        (document.get("components") or {}).get("securitySchemes")
        if isinstance(document.get("components"), dict)
        else None
    )
    if not isinstance(raw, dict):
        raw = document.get("securityDefinitions")
    return raw if isinstance(raw, dict) else {}


def _extract_operation_metadata(
    route: dict[str, Any],
    operation: dict[str, Any],
    root: dict[str, Any],
    *,
    shared_parameters: list[Any],
    path: str,
    method: str,
    max_ref_depth: int,
    max_items: int,
    all_parameters: list[dict[str, Any]],
    objects: dict[tuple[str, str, str, str], dict[str, Any]],
    auth_boundaries: list[dict[str, Any]],
    global_security: list[Any],
) -> None:
    """Enrich a route after its identity has already been preserved."""
    parameter_entries: list[dict[str, Any]] = []
    request_fields: list[dict[str, Any]] = []
    raw_parameters = [*shared_parameters]
    if isinstance(operation.get("parameters"), list):
        raw_parameters.extend(operation["parameters"])
    for raw_parameter in raw_parameters[:max_items]:
        if _has_unresolved_local_ref(raw_parameter, root):
            _add_route_limitation(
                route,
                "OpenAPI parameter schema metadata contains an unresolved local "
                "reference; route identity was preserved.",
            )
        parameter = _resolve(raw_parameter, root, depth=0, max_depth=max_ref_depth)
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "").strip()
        location = str(parameter.get("in") or "unknown").lower()
        if location == "body" and isinstance(parameter.get("schema"), dict):
            request_fields.extend(
                _schema_fields(
                    parameter["schema"],
                    root,
                    location="request_body",
                    source="openapi_request_body",
                    max_depth=max_ref_depth,
                    max_items=max_items - len(request_fields),
                )
            )
            continue
        if not name:
            continue
        schema = (
            parameter.get("schema")
            if isinstance(parameter.get("schema"), dict)
            else parameter
        )
        parameter_entries.append(
            {
                "name": name,
                "in": location,
                "required": bool(parameter.get("required")) or location == "path",
                "schema_type": _schema_type(
                    schema,
                    root,
                    depth=0,
                    max_depth=max_ref_depth,
                ),
                "source": "openapi_parameter",
            }
        )

    documented_names = {item["name"] for item in parameter_entries}
    for placeholder in re.findall(r"\{([^{}]+)\}", path):
        if placeholder not in documented_names:
            parameter_entries.append(
                {
                    "name": placeholder,
                    "in": "path",
                    "required": True,
                    "schema_type": "unknown",
                    "source": "openapi_path_template",
                }
            )

    raw_request_body = operation.get("requestBody")
    if _has_unresolved_local_ref(raw_request_body, root):
        _add_route_limitation(
            route,
            "OpenAPI request schema metadata contains an unresolved local reference; "
            "route identity was preserved.",
        )
    request_body = _resolve(raw_request_body, root, depth=0, max_depth=max_ref_depth)
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media_type in sorted(content)[:20]:
                media = content[media_type]
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    request_fields.extend(
                        _schema_fields(
                            media["schema"],
                            root,
                            location="request_body",
                            source="openapi_request_body",
                            max_depth=max_ref_depth,
                            max_items=max_items - len(request_fields),
                        )
                    )

    response_fields: list[dict[str, Any]] = []
    response_names: set[str] = set()
    response_status_codes: list[str] = []
    response_headers: set[str] = set()
    responses = operation.get("responses")
    if isinstance(responses, dict):
        for status_code in sorted(responses)[:50]:
            response_status_codes.append(str(status_code))
            if _has_unresolved_local_ref(responses[status_code], root):
                _add_route_limitation(
                    route,
                    "OpenAPI response schema metadata contains an unresolved local "
                    "reference; route identity was preserved.",
                )
            response = _resolve(
                responses[status_code], root, depth=0, max_depth=max_ref_depth
            )
            if not isinstance(response, dict):
                continue
            headers = response.get("headers")
            if isinstance(headers, dict):
                response_headers.update(str(name).lower() for name in headers)
            schemas: list[Any] = []
            if isinstance(response.get("schema"), dict):
                schemas.append(response["schema"])
            content = response.get("content")
            if isinstance(content, dict):
                schemas.extend(
                    media.get("schema")
                    for media in content.values()
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict)
                )
            for schema in schemas:
                response_names.update(_schema_names(schema))
                response_fields.extend(
                    _schema_fields(
                        schema,
                        root,
                        location="response_body",
                        source="openapi_response",
                        max_depth=max_ref_depth,
                        max_items=max_items - len(response_fields),
                    )
                )

    security = operation.get("security", global_security)
    requirements = security if isinstance(security, list) else []
    scheme_names = sorted(
        {
            str(name)
            for requirement in requirements
            if isinstance(requirement, dict)
            for name in requirement
        }
    )
    security_required = bool(requirements)
    object_candidates: list[dict[str, Any]] = []
    for item in [*parameter_entries, *request_fields, *response_fields]:
        name = str(item.get("name") or "")
        if not _is_identifier(name):
            continue
        source_label = {
            "path": "OpenAPI path parameter",
            "query": "OpenAPI query parameter",
            "header": "OpenAPI header parameter",
            "request_body": "OpenAPI request body field",
            "response_body": "OpenAPI response field",
        }.get(str(item.get("in")), "OpenAPI field")
        candidate = {
            "type": _object_type(path, name),
            "identifier": name,
            "source": source_label,
            "path": path,
            "method": method.upper(),
            "location": item.get("in"),
            "classification": "attack_surface_observation",
        }
        objects[(candidate["type"], name, path, method)] = candidate
        object_candidates.append(candidate)

    route.update(
        {
            "parameters": sorted(
                parameter_entries, key=lambda item: (item["in"], item["name"])
            ),
            "request_fields": sorted(
                request_fields, key=lambda item: item["field_path"]
            ),
            "response_fields": sorted(
                response_fields, key=lambda item: item["field_path"]
            ),
            "response_schema_names": sorted(response_names),
            "security_required": security_required,
            "security_schemes": scheme_names,
            "tags": sorted(
                str(tag) for tag in operation.get("tags", []) if isinstance(tag, str)
            ),
            "response_status_codes": response_status_codes,
            "response_headers": sorted(response_headers),
            "sets_cookie": "set-cookie" in response_headers,
            "object_reference_candidates": object_candidates,
        }
    )
    for item in [*parameter_entries, *request_fields]:
        all_parameters.append(
            {
                **item,
                "path": path,
                "method": method.upper(),
                "evidence_quality": 3,
            }
        )
    if security_required:
        auth_boundaries.append(
            {
                "path": path,
                "method": method.upper(),
                "security_schemes": scheme_names,
                "source": "openapi",
                "evidence_quality": 3,
            }
        )


def openapi_surface_analyzer(
    document: Any,
    *,
    source_url: str | None = None,
    max_ref_depth: int = 8,
    max_items: int = 1000,
) -> dict[str, Any]:
    """Extract routes and fields from a validated OpenAPI 2/3 document."""
    if max_ref_depth < 1 or max_ref_depth > 20 or max_items < 1 or max_items > 5000:
        return {"success": False, "error": "Parser bounds are invalid."}
    if isinstance(document, list):
        analyses: list[dict[str, Any]] = []
        for item in document[:20]:
            raw_document = item.get("document") if isinstance(item, dict) else item
            item_source = item.get("source_url") if isinstance(item, dict) else None
            analysis = openapi_surface_analyzer(
                raw_document,
                source_url=str(item_source or source_url or "") or None,
                max_ref_depth=max_ref_depth,
                max_items=max_items,
            )
            if analysis.get("success"):
                analyses.append(analysis)
        if not analyses:
            return {
                "success": False,
                "error": "No structurally valid OpenAPI documents were supplied.",
            }
        route_map: dict[tuple[str, str], dict[str, Any]] = {}
        parameter_map: dict[tuple[Any, ...], dict[str, Any]] = {}
        object_map: dict[tuple[Any, ...], dict[str, Any]] = {}
        boundary_map: dict[tuple[str, str], dict[str, Any]] = {}
        schema_map: dict[str, dict[str, Any]] = {}
        security_scheme_map: dict[str, dict[str, Any]] = {}
        for analysis in analyses:
            for route in analysis["routes"]:
                route_map[route_identity(route)] = route
            for parameter in analysis["parameters"]:
                parameter_map[
                    (
                        parameter.get("path"),
                        parameter.get("method"),
                        parameter.get("in"),
                        parameter.get("field_path", parameter.get("name")),
                    )
                ] = parameter
            for candidate in analysis["objects"]:
                object_map[
                    (
                        candidate.get("type"),
                        candidate.get("identifier"),
                        candidate.get("path"),
                        candidate.get("method"),
                    )
                ] = candidate
            for boundary in analysis["authentication_boundaries"]:
                boundary_map[(boundary["path"], boundary["method"])] = boundary
            for schema in analysis["schemas"]:
                schema_map[schema["name"]] = schema
            for scheme in analysis["security_schemes"]:
                security_scheme_map[scheme["name"]] = scheme
        routes = [route_map[key] for key in sorted(route_map)]
        parameters = [parameter_map[key] for key in sorted(parameter_map)]
        objects = [object_map[key] for key in sorted(object_map)]
        boundaries = [boundary_map[key] for key in sorted(boundary_map)]
        return {
            "success": True,
            "openapi_versions": sorted(
                {str(item["openapi_version"]) for item in analyses}
            ),
            "documents_analyzed": len(analyses),
            "routes": routes,
            "parameters": parameters,
            "objects": objects,
            "authentication_boundaries": boundaries,
            "schemas": [schema_map[key] for key in sorted(schema_map)],
            "security_schemes": [
                security_scheme_map[key] for key in sorted(security_scheme_map)
            ],
            "route_count": len({route["path"] for route in routes}),
            "operation_count": len(routes),
            "parameter_count": len(parameters),
            "object_reference_count": len(objects),
            "authentication_protected_operation_count": len(boundaries),
            "network_tested": False,
            "limits": {"max_ref_depth": max_ref_depth, "max_items": max_items},
            "vulnerability_status": "not_assessed",
        }
    loaded = load_structured_document(document)
    version = openapi_version(loaded)
    if loaded is None or version is None:
        return {
            "success": False,
            "error": "Input is not a structurally valid OpenAPI document.",
        }
    root = sanitize_openapi_document(loaded)
    raw_paths = loaded.get("paths") if isinstance(loaded.get("paths"), dict) else {}
    paths = root.get("paths") if isinstance(root.get("paths"), dict) else {}
    global_security = (
        root.get("security") if isinstance(root.get("security"), list) else []
    )
    defined_schemes = _security_schemes(root)
    routes: list[dict[str, Any]] = []
    route_identities: set[tuple[str, str]] = set()
    all_parameters: list[dict[str, Any]] = []
    objects: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    auth_boundaries: list[dict[str, Any]] = []
    base_path = (
        str(root.get("basePath") or "").rstrip("/") if version.startswith("2") else ""
    )

    for raw_path in sorted(paths)[:max_items]:
        path_item = _resolve(paths[raw_path], root, depth=0, max_depth=max_ref_depth)
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters")
        shared_parameters = (
            shared_parameters if isinstance(shared_parameters, list) else []
        )
        for method in sorted(set(path_item) & HTTP_METHODS):
            if len(routes) >= max_items:
                break
            operation = _resolve(
                path_item[method], root, depth=0, max_depth=max_ref_depth
            )
            if not isinstance(operation, dict):
                continue
            path = normalize_route_path(f"{base_path}{raw_path}" or "/")
            raw_path_item = _resolve(
                raw_paths.get(raw_path), loaded, depth=0, max_depth=max_ref_depth
            )
            raw_operation = _resolve(
                raw_path_item.get(method) if isinstance(raw_path_item, dict) else None,
                loaded,
                depth=0,
                max_depth=max_ref_depth,
            )
            summary = safe_auth_semantic_summary(raw_operation.get("summary"))
            route = {
                "path": path,
                "method": method.upper(),
                "parameters": [],
                "request_fields": [],
                "response_fields": [],
                "response_schema_names": [],
                "security_required": False,
                "security_schemes": [],
                "tags": [],
                "operation_id": str(operation.get("operationId") or ""),
                "summary": summary,
                "response_status_codes": [],
                "response_headers": [],
                "sets_cookie": False,
                "object_reference_candidates": [],
                "source": "openapi",
                "evidence_quality": 3,
            }
            identity = route_identity(route)
            if identity in route_identities:
                continue
            route_identities.add(identity)
            routes.append(route)
            try:
                _extract_operation_metadata(
                    route,
                    operation,
                    root,
                    shared_parameters=shared_parameters,
                    path=path,
                    method=method,
                    max_ref_depth=max_ref_depth,
                    max_items=max_items,
                    all_parameters=all_parameters,
                    objects=objects,
                    auth_boundaries=auth_boundaries,
                    global_security=global_security,
                )
            except Exception as exc:
                _add_route_limitation(
                    route,
                    "OpenAPI operation metadata extraction was incomplete "
                    f"({type(exc).__name__}); route identity was preserved.",
                )

    schema_container = (
        (root.get("components") or {}).get("schemas")
        if isinstance(root.get("components"), dict)
        else None
    )
    if not isinstance(schema_container, dict):
        schema_container = root.get("definitions")
    schema_names = (
        sorted(schema_container)[:max_items]
        if isinstance(schema_container, dict)
        else []
    )
    routes.sort(key=lambda item: (item["path"], item["method"]))
    deduplicated_parameters = {
        (
            item["path"],
            item["method"],
            item.get("in"),
            item.get("field_path", item.get("name")),
        ): item
        for item in all_parameters
    }
    return {
        "success": True,
        "openapi_version": version,
        "source_url": source_url,
        "routes": routes,
        "parameters": [
            deduplicated_parameters[key] for key in sorted(deduplicated_parameters)
        ],
        "objects": [objects[key] for key in sorted(objects)],
        "authentication_boundaries": auth_boundaries,
        "schemas": [{"name": name, "source": "openapi"} for name in schema_names],
        "security_schemes": [
            {
                "name": str(name),
                "type": str(scheme.get("type") or "unknown"),
                "in": str(scheme.get("in") or ""),
                "scheme": str(scheme.get("scheme") or ""),
                "source": "openapi",
            }
            for name, scheme in sorted(defined_schemes.items())
            if isinstance(scheme, dict)
        ],
        "route_count": len({route["path"] for route in routes}),
        "operation_count": len(routes),
        "parameter_count": len(deduplicated_parameters),
        "object_reference_count": len(objects),
        "authentication_protected_operation_count": len(auth_boundaries),
        "network_tested": False,
        "limits": {"max_ref_depth": max_ref_depth, "max_items": max_items},
        "vulnerability_status": "not_assessed",
    }
