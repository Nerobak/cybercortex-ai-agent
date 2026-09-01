"""Sanitized capture-first ingestion for authenticated assessments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from pydantic import Field

from agent_core.agent_models import ParameterLocation, StrictModel, stable_identifier
from agent_core.attack_surface import AttackSurfaceGraph
from agent_core.credential_vault import CredentialVault
from tools.raw_http_request_parser import parse_raw_http_request

CaptureFormat = Literal["har", "raw_http", "openapi", "postman", "graphql", "browser"]
SENSITIVE_NAME = re.compile(
    r"authorization|cookie|token|secret|password|passwd|api.?key|session|credit|ssn",
    re.I,
)
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CapturedParameter(StrictModel):
    name: str
    location: ParameterLocation
    value_type: str = "unknown"
    required: bool = False
    redacted: bool = False
    schema_hint: dict[str, Any] = Field(default_factory=dict, alias="schema")


class CapturedIdentity(StrictModel):
    identity_id: str
    label: str
    role: str = "unknown"
    tenant: str | None = None
    controlled: bool = False
    credential_references: list[str] = Field(default_factory=list)


class CapturedObject(StrictModel):
    object_id: str
    object_type: str = "unknown"
    owner_identity_id: str | None = None
    tenant: str | None = None
    test_owned: bool = False
    evidence_refs: list[str] = Field(default_factory=list)


class CapturedResponseSummary(StrictModel):
    status_code: int | None = None
    content_type: str | None = None
    body_size: int | None = None
    schema_fields: list[str] = Field(default_factory=list, max_length=500)
    cache_headers: dict[str, str] = Field(default_factory=dict)
    sets_cookie: bool = False


class CapturedRequest(StrictModel):
    request_id: str
    source_format: CaptureFormat
    source_ref: str
    method: str
    url: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    parameters: list[CapturedParameter] = Field(default_factory=list, max_length=1000)
    body_type: str | None = None
    body_schema: dict[str, Any] = Field(default_factory=dict)
    graphql_operation: str | None = None
    graphql_operation_type: str | None = None
    identity_id: str | None = None
    object_references: list[str] = Field(default_factory=list, max_length=100)
    response: CapturedResponseSummary | None = None
    state_changing: bool = False
    executable: bool = False
    execution_url_ref: str | None = None
    execution_body_ref: str | None = None


class CaptureBundle(StrictModel):
    schema_version: int = 1
    source_format: CaptureFormat
    source_ref: str
    requests: list[CapturedRequest] = Field(default_factory=list, max_length=5000)
    identities: list[CapturedIdentity] = Field(default_factory=list, max_length=100)
    objects: list[CapturedObject] = Field(default_factory=list, max_length=5000)
    schemas: dict[str, Any] = Field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)

    def summary(self) -> dict[str, Any]:
        locations: dict[str, int] = {}
        for request in self.requests:
            for parameter in request.parameters:
                locations[parameter.location] = locations.get(parameter.location, 0) + 1
        return {
            "source_format": self.source_format,
            "request_count": len(self.requests),
            "identity_count": len(self.identities),
            "object_count": len(self.objects),
            "parameter_locations": locations,
            "state_changing_request_count": sum(
                request.state_changing for request in self.requests
            ),
            "executable_request_count": sum(
                request.executable for request in self.requests
            ),
            "diagnostic_count": len(self.diagnostics),
        }


def detect_capture_format(path: str | Path, data: Any | None = None) -> CaptureFormat:
    capture_path = Path(path)
    suffix = capture_path.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix in {".graphql", ".graphqls", ".gql"}:
        return "graphql"
    if suffix in {".txt", ".http", ".request"}:
        return "raw_http"
    if isinstance(data, dict):
        if isinstance(data.get("log"), dict) and "entries" in data["log"]:
            return "har"
        if "openapi" in data or "swagger" in data:
            return "openapi"
        if "info" in data and "item" in data:
            return "postman"
        if "requests" in data or "sessions" in data:
            return "browser"
    raise ValueError("Unable to detect capture format; provide an explicit format.")


def _schema_fields(value: Any, prefix: str = "") -> list[str]:
    if not isinstance(value, dict):
        return []
    fields: list[str] = []
    for key, item in list(value.items())[:500]:
        path = f"{prefix}.{key}" if prefix else str(key)
        fields.append(path)
        if isinstance(item, dict):
            fields.extend(_schema_fields(item, path))
    return fields[:500]


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _flatten_parameters(
    value: Any,
    location: ParameterLocation,
    *,
    prefix: str = "",
) -> list[CapturedParameter]:
    if not isinstance(value, dict):
        return []
    output: list[CapturedParameter] = []
    for raw_name, item in list(value.items())[:1000]:
        name = f"{prefix}.{raw_name}" if prefix else str(raw_name)
        output.append(
            CapturedParameter(
                name=name,
                location=location,
                value_type=_value_type(item),
                redacted=bool(SENSITIVE_NAME.search(name)),
            )
        )
        if isinstance(item, dict):
            output.extend(_flatten_parameters(item, location, prefix=name))
    return output[:1000]


def _query_parameters(url: str) -> list[CapturedParameter]:
    return [
        CapturedParameter(
            name=name,
            location="query",
            value_type="string",
            redacted=bool(SENSITIVE_NAME.search(name)),
        )
        for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
    ]


def _sanitize_url(url: str, vault: CredentialVault) -> tuple[str, str]:
    execution_ref = vault.put(url, label="request-url")
    parsed = urlparse(url)
    sanitized_segments: list[str] = []
    for segment in parsed.path.split("/"):
        if not segment or (segment.startswith("{") and segment.endswith("}")):
            sanitized_segments.append(segment)
            continue
        looks_identifier = bool(
            re.fullmatch(r"\d+", segment)
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                segment,
                re.I,
            )
            or (
                len(segment) >= 16
                and re.fullmatch(r"[A-Za-z0-9_-]+", segment)
                and any(character.isdigit() for character in segment)
            )
        )
        sanitized_segments.append("{object_id}" if looks_identifier else segment)
    sanitized_query = urlencode(
        [
            (
                name,
                "[REDACTED]" if SENSITIVE_NAME.search(name) else "[VALUE]",
            )
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    sanitized = urlunparse(
        parsed._replace(
            path="/".join(sanitized_segments),
            query=sanitized_query,
            fragment="",
        )
    )
    return sanitized, execution_ref


def _sanitize_headers(
    headers: Iterable[dict[str, Any]] | dict[str, Any], vault: CredentialVault
) -> tuple[dict[str, str], list[str]]:
    if isinstance(headers, dict):
        raw = {str(name): str(value) for name, value in headers.items()}
    else:
        raw = {
            str(item.get("name")): str(item.get("value", ""))
            for item in headers
            if isinstance(item, dict) and item.get("name")
        }
    sanitized, references = vault.redact_headers(raw)
    return sanitized, list(references.values())


def _response_summary(response: dict[str, Any]) -> CapturedResponseSummary:
    content = response.get("content") or {}
    fields: list[str] = []
    text = content.get("text")
    if isinstance(text, str) and "json" in str(content.get("mimeType", "")).lower():
        try:
            fields = _schema_fields(json.loads(text))
        except json.JSONDecodeError:
            fields = []
    response_headers = {
        str(item.get("name", "")).lower(): str(item.get("value", ""))[:500]
        for item in response.get("headers") or []
        if isinstance(item, dict) and item.get("name")
    }
    cache_headers = {
        name: response_headers[name]
        for name in ("cache-control", "vary", "age", "x-cache", "cf-cache-status")
        if name in response_headers
    }
    return CapturedResponseSummary(
        status_code=response.get("status"),
        content_type=content.get("mimeType"),
        body_size=content.get("size") or response.get("bodySize"),
        schema_fields=fields,
        cache_headers=cache_headers,
        sets_cookie="set-cookie" in response_headers,
    )


def _sanitize_schema(value: Any) -> Any:
    """Retain schema structure while dropping examples, defaults, and values."""
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        structural = {
            "type",
            "format",
            "required",
            "properties",
            "items",
            "oneOf",
            "allOf",
            "anyOf",
            "readOnly",
            "writeOnly",
            "nullable",
            "additionalProperties",
            "$ref",
        }
        for key, item in value.items():
            if key in structural:
                safe[str(key)] = _sanitize_schema(item)
        return safe
    if isinstance(value, list):
        return [_sanitize_schema(item) for item in value[:100]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _request_from_har_entry(
    entry: dict[str, Any], source_ref: str, vault: CredentialVault
) -> tuple[CapturedRequest, list[str]]:
    request = entry.get("request") or {}
    method = str(request.get("method") or "GET").upper()
    raw_url = str(request.get("url") or "")
    url, execution_url_ref = _sanitize_url(raw_url, vault)
    headers, credential_refs = _sanitize_headers(request.get("headers") or [], vault)
    parameters = _query_parameters(url)
    body_schema: dict[str, Any] = {}
    body_type: str | None = None
    graphql_operation = None
    graphql_type = None
    post_data = request.get("postData") or {}
    mime_type = str(post_data.get("mimeType") or "").lower()
    text = post_data.get("text")
    execution_body_ref = (
        vault.put(
            text,
            label=f"request-body:{method}",
        )
        if isinstance(text, str) and text
        else None
    )
    if "json" in mime_type and isinstance(text, str):
        try:
            parsed_body = json.loads(text)
            body_schema = {"fields": _schema_fields(parsed_body)}
            parameters.extend(_flatten_parameters(parsed_body, "json"))
            body_type = "json"
            if isinstance(parsed_body, dict) and isinstance(
                parsed_body.get("query"), str
            ):
                graphql_operation = parsed_body.get("operationName") or _graphql_name(
                    parsed_body["query"]
                )
                graphql_type = _graphql_type(parsed_body["query"])
                parameters.extend(
                    _flatten_parameters(
                        parsed_body.get("variables") or {}, "graphql_variable"
                    )
                )
                body_type = "graphql"
        except json.JSONDecodeError:
            body_type = "invalid_json"
    elif "x-www-form-urlencoded" in mime_type:
        form = {
            str(item.get("name")): item.get("value")
            for item in post_data.get("params") or []
            if isinstance(item, dict) and item.get("name")
        }
        parameters.extend(_flatten_parameters(form, "form"))
        body_schema = {"fields": sorted(form)}
        body_type = "form"
    elif "multipart/form-data" in mime_type:
        for item in post_data.get("params") or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            parameters.append(
                CapturedParameter(
                    name=str(item["name"]),
                    location="multipart",
                    value_type="file" if item.get("fileName") else "string",
                    redacted=bool(SENSITIVE_NAME.search(str(item["name"]))),
                )
            )
        body_type = "multipart"
    request_id = stable_identifier("req", method, url, source_ref)
    return (
        CapturedRequest(
            request_id=request_id,
            source_format="har",
            source_ref=source_ref,
            method=method,
            url=url,
            path=urlparse(url).path or "/",
            headers=headers,
            parameters=_deduplicate_parameters(parameters),
            body_type=body_type,
            body_schema=body_schema,
            graphql_operation=graphql_operation,
            graphql_operation_type=graphql_type,
            response=_response_summary(entry.get("response") or {}),
            state_changing=method in STATE_CHANGING_METHODS,
            executable=bool(raw_url),
            execution_url_ref=execution_url_ref,
            execution_body_ref=execution_body_ref,
        ),
        credential_refs,
    )


def _deduplicate_parameters(
    parameters: Iterable[CapturedParameter],
) -> list[CapturedParameter]:
    unique: dict[tuple[str, str], CapturedParameter] = {}
    for parameter in parameters:
        unique[(parameter.location, parameter.name)] = parameter
    return list(unique.values())[:1000]


def _graphql_name(document: str) -> str | None:
    match = re.search(
        r"\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", document
    )
    return match.group(1) if match else None


def _graphql_type(document: str) -> str | None:
    match = re.search(r"\b(query|mutation|subscription)\b", document)
    return match.group(1) if match else "query" if "{" in document else None


def _import_har(
    data: dict[str, Any], source: str, vault: CredentialVault
) -> CaptureBundle:
    requests: list[CapturedRequest] = []
    identity_map: dict[tuple[str, ...], CapturedIdentity] = {}
    diagnostics: list[dict[str, Any]] = []
    for index, entry in enumerate((data.get("log") or {}).get("entries") or []):
        if not isinstance(entry, dict):
            diagnostics.append({"entry": index, "error": "HAR entry is not an object."})
            continue
        try:
            request, references = _request_from_har_entry(entry, source, vault)
            if request.url:
                if references:
                    identity_key = tuple(sorted(references))
                    identity = identity_map.get(identity_key)
                    if identity is None:
                        identity = CapturedIdentity(
                            identity_id=stable_identifier(
                                "identity", source, *identity_key
                            ),
                            label=f"captured-session-{len(identity_map) + 1}",
                            controlled=False,
                            credential_references=list(identity_key),
                        )
                        identity_map[identity_key] = identity
                    request.identity_id = identity.identity_id
                requests.append(request)
        except (TypeError, ValueError) as exc:
            diagnostics.append({"entry": index, "error": str(exc)})
    return CaptureBundle(
        source_format="har",
        source_ref=source,
        requests=requests,
        identities=list(identity_map.values()),
        diagnostics=diagnostics,
    )


def _import_raw_http(
    text: str, source: str, vault: CredentialVault, default_base_url: str | None
) -> CaptureBundle:
    scheme = (
        urlparse(default_base_url or "https://placeholder.invalid").scheme or "https"
    )
    parsed = parse_raw_http_request(text, default_scheme=scheme)
    if not parsed.get("success"):
        return CaptureBundle(
            source_format="raw_http",
            source_ref=source,
            diagnostics=[{"error": parsed.get("error", "Unable to parse request.")}],
        )
    headers, references = _sanitize_headers(parsed.get("headers") or {}, vault)
    raw_url = parsed["url"]
    url, execution_url_ref = _sanitize_url(raw_url, vault)
    method = parsed["method"]
    parsed_body = (parsed.get("body") or {}).get("parsed")
    body_format = str((parsed.get("body") or {}).get("format") or "empty")
    body_parameters: list[CapturedParameter] = []
    if isinstance(parsed_body, dict):
        location: ParameterLocation = "json" if body_format == "json" else "form"
        normalized_body = {
            name: value[0] if isinstance(value, list) and len(value) == 1 else value
            for name, value in parsed_body.items()
        }
        body_parameters = _flatten_parameters(normalized_body, location)
    request = CapturedRequest(
        request_id=stable_identifier("req", method, url, source),
        source_format="raw_http",
        source_ref=source,
        method=method,
        url=url,
        path=urlparse(url).path or "/",
        headers=headers,
        parameters=_deduplicate_parameters(_query_parameters(url) + body_parameters),
        body_type=body_format,
        body_schema={"fields": _schema_fields(parsed_body)},
        state_changing=method in STATE_CHANGING_METHODS,
        executable=True,
        execution_url_ref=execution_url_ref,
        execution_body_ref=(
            vault.put(str((parsed.get("body") or {}).get("raw")), label="request-body")
            if (parsed.get("body") or {}).get("raw")
            else None
        ),
    )
    identities = (
        [
            CapturedIdentity(
                identity_id=stable_identifier("identity", source, "captured"),
                label="captured-session",
                credential_references=references,
            )
        ]
        if references
        else []
    )
    if identities:
        request.identity_id = identities[0].identity_id
    return CaptureBundle(
        source_format="raw_http",
        source_ref=source,
        requests=[request],
        identities=identities,
    )


def _openapi_parameters(items: Iterable[dict[str, Any]]) -> list[CapturedParameter]:
    location_map = {
        "query": "query",
        "path": "path",
        "header": "header",
        "cookie": "cookie",
    }
    output: list[CapturedParameter] = []
    for item in items:
        location = location_map.get(str(item.get("in")))
        if not location or not item.get("name"):
            continue
        schema = item.get("schema") if isinstance(item.get("schema"), dict) else {}
        output.append(
            CapturedParameter(
                name=str(item["name"]),
                location=location,  # type: ignore[arg-type]
                value_type=str(schema.get("type") or "unknown"),
                required=bool(item.get("required")),
                redacted=bool(SENSITIVE_NAME.search(str(item["name"]))),
                schema_hint={
                    key: schema[key]
                    for key in ("type", "format", "enum")
                    if key in schema
                },
            )
        )
    return output


def _import_openapi(
    data: dict[str, Any], source: str, default_base_url: str | None
) -> CaptureBundle:
    servers = data.get("servers") or []
    base_url = default_base_url or (
        servers[0].get("url") if servers and isinstance(servers[0], dict) else None
    )
    base_url = str(base_url or "https://placeholder.invalid")
    requests: list[CapturedRequest] = []
    schemas = (data.get("components") or {}).get("schemas") or {}
    for path, path_item in (data.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        shared = _openapi_parameters(path_item.get("parameters") or [])
        for method, operation in path_item.items():
            if method.lower() not in {
                "get",
                "head",
                "options",
                "post",
                "put",
                "patch",
                "delete",
            }:
                continue
            if not isinstance(operation, dict):
                continue
            parameters = shared + _openapi_parameters(operation.get("parameters") or [])
            body_schema: dict[str, Any] = {}
            content = (operation.get("requestBody") or {}).get("content") or {}
            body_type = None
            for mime, definition in content.items():
                schema = (
                    definition.get("schema") if isinstance(definition, dict) else {}
                )
                properties = (
                    schema.get("properties") if isinstance(schema, dict) else {}
                )
                if isinstance(properties, dict):
                    parameters.extend(
                        CapturedParameter(
                            name=name,
                            location="json" if "json" in mime else "form",
                            value_type=str((value or {}).get("type") or "unknown"),
                            required=name in schema.get("required", []),
                            redacted=bool(SENSITIVE_NAME.search(name)),
                            schema_hint={
                                key: value[key]
                                for key in ("type", "format", "enum")
                                if isinstance(value, dict) and key in value
                            },
                        )
                        for name, value in properties.items()
                    )
                    body_schema = {"fields": sorted(properties)}
                body_type = mime
                break
            url = urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
            method_upper = method.upper()
            requests.append(
                CapturedRequest(
                    request_id=stable_identifier("req", method_upper, url, source),
                    source_format="openapi",
                    source_ref=source,
                    method=method_upper,
                    url=url,
                    path=str(path),
                    parameters=_deduplicate_parameters(parameters),
                    body_type=body_type,
                    body_schema=body_schema,
                    state_changing=method_upper in STATE_CHANGING_METHODS,
                    executable=False,
                )
            )
    return CaptureBundle(
        source_format="openapi",
        source_ref=source,
        requests=requests,
        schemas=_sanitize_schema(schemas) if isinstance(schemas, dict) else {},
    )


def _postman_items(items: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):
            yield from _postman_items(item["item"])
        elif isinstance(item.get("request"), dict):
            yield item


def _import_postman(
    data: dict[str, Any],
    source: str,
    vault: CredentialVault,
    default_base_url: str | None,
) -> CaptureBundle:
    requests: list[CapturedRequest] = []
    diagnostics: list[dict[str, Any]] = []
    for index, item in enumerate(_postman_items(data.get("item") or [])):
        request = item["request"]
        method = str(request.get("method") or "GET").upper()
        url_value = request.get("url")
        raw_url = url_value.get("raw") if isinstance(url_value, dict) else url_value
        if not isinstance(raw_url, str):
            diagnostics.append({"item": index, "error": "Postman request has no URL."})
            continue
        if raw_url.startswith("/") and default_base_url:
            raw_url = urljoin(default_base_url, raw_url)
        url, execution_url_ref = _sanitize_url(raw_url, vault)
        headers, references = _sanitize_headers(request.get("header") or [], vault)
        parameters = _query_parameters(url)
        body = request.get("body") or {}
        mode = body.get("mode")
        raw_body: str | None = None
        body_schema: dict[str, Any] = {}
        graphql_operation = None
        graphql_type = None
        if mode == "raw" and isinstance(body.get("raw"), str):
            raw_body = body["raw"]
            try:
                parsed_body = json.loads(body["raw"])
                parameters.extend(_flatten_parameters(parsed_body, "json"))
                body_schema = {"fields": _schema_fields(parsed_body)}
            except json.JSONDecodeError:
                pass
        elif mode == "urlencoded":
            values = {
                str(entry.get("key")): entry.get("value")
                for entry in body.get("urlencoded") or []
                if isinstance(entry, dict) and entry.get("key")
            }
            parameters.extend(_flatten_parameters(values, "form"))
            raw_body = urlencode(
                {name: str(value or "") for name, value in values.items()}
            )
        elif mode == "formdata":
            for entry in body.get("formdata") or []:
                if isinstance(entry, dict) and entry.get("key"):
                    parameters.append(
                        CapturedParameter(
                            name=str(entry["key"]),
                            location="multipart",
                            value_type=(
                                "file" if entry.get("type") == "file" else "string"
                            ),
                            redacted=bool(SENSITIVE_NAME.search(str(entry["key"]))),
                        )
                    )
        elif mode == "graphql":
            graphql = body.get("graphql") or {}
            document = str(graphql.get("query") or "")
            graphql_operation = _graphql_name(document)
            graphql_type = _graphql_type(document)
            variables = graphql.get("variables")
            if isinstance(variables, str):
                try:
                    variables = json.loads(variables)
                except json.JSONDecodeError:
                    variables = {}
            parameters.extend(_flatten_parameters(variables or {}, "graphql_variable"))
            raw_body = json.dumps(
                {"query": document, "variables": variables or {}}, separators=(",", ":")
            )
        requests.append(
            CapturedRequest(
                request_id=stable_identifier("req", method, url, source),
                source_format="postman",
                source_ref=source,
                method=method,
                url=url,
                path=urlparse(url).path or "/",
                headers=headers,
                parameters=_deduplicate_parameters(parameters),
                body_type=str(mode) if mode else None,
                body_schema=body_schema,
                graphql_operation=graphql_operation,
                graphql_operation_type=graphql_type,
                state_changing=method in STATE_CHANGING_METHODS,
                executable=not ("{{" in url or "}}" in url),
                execution_url_ref=execution_url_ref,
                execution_body_ref=(
                    vault.put(raw_body, label=f"request-body:{method}")
                    if raw_body
                    else None
                ),
            )
        )
    return CaptureBundle(
        source_format="postman",
        source_ref=source,
        requests=requests,
        diagnostics=diagnostics,
    )


def _import_graphql(text: str, source: str, base_url: str | None) -> CaptureBundle:
    parameters = [
        CapturedParameter(
            name=name,
            location="graphql_variable",
            value_type=kind.rstrip("!"),
            required=kind.endswith("!"),
        )
        for name, kind in re.findall(
            r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\[\]!A-Za-z0-9_]+)", text
        )
    ]
    url = base_url or "https://placeholder.invalid/graphql"
    operation_type = _graphql_type(text)
    method = "POST"
    request = CapturedRequest(
        request_id=stable_identifier("req", method, url, source, _graphql_name(text)),
        source_format="graphql",
        source_ref=source,
        method=method,
        url=url,
        path=urlparse(url).path or "/graphql",
        parameters=parameters,
        body_type="graphql",
        graphql_operation=_graphql_name(text),
        graphql_operation_type=operation_type,
        state_changing=operation_type == "mutation",
        executable=False,
    )
    return CaptureBundle(source_format="graphql", source_ref=source, requests=[request])


def _import_browser(
    data: dict[str, Any], source: str, vault: CredentialVault
) -> CaptureBundle:
    har_like = {"log": {"entries": []}}
    for item in data.get("requests") or []:
        if not isinstance(item, dict):
            continue
        har_like["log"]["entries"].append(
            {
                "request": {
                    "method": item.get("method", "GET"),
                    "url": item.get("url"),
                    "headers": [
                        {"name": name, "value": value}
                        for name, value in (item.get("headers") or {}).items()
                    ],
                    "postData": item.get("postData") or {},
                },
                "response": item.get("response") or {},
            }
        )
    bundle = _import_har(har_like, source, vault)
    return bundle.model_copy(update={"source_format": "browser"})


def import_capture(
    path: str | Path,
    *,
    capture_format: CaptureFormat | Literal["auto"] = "auto",
    default_base_url: str | None = None,
    vault: CredentialVault | None = None,
) -> tuple[CaptureBundle, CredentialVault]:
    capture_path = Path(path)
    raw = capture_path.read_text(encoding="utf-8")
    data: Any = None
    if capture_path.suffix.lower() in {".json", ".har"}:
        data = json.loads(raw)
    selected = (
        detect_capture_format(capture_path, data)
        if capture_format == "auto"
        else capture_format
    )
    secret_vault = vault or CredentialVault()
    source = str(capture_path)
    if selected == "har":
        bundle = _import_har(data, source, secret_vault)
    elif selected == "raw_http":
        bundle = _import_raw_http(raw, source, secret_vault, default_base_url)
    elif selected == "openapi":
        bundle = _import_openapi(data, source, default_base_url)
    elif selected == "postman":
        bundle = _import_postman(data, source, secret_vault, default_base_url)
    elif selected == "graphql":
        bundle = _import_graphql(raw, source, default_base_url)
    elif selected == "browser":
        bundle = _import_browser(data, source, secret_vault)
    else:  # pragma: no cover - Literal validation protects this route
        raise ValueError(f"Unsupported capture format: {selected}")
    return bundle, secret_vault


def apply_capture_context(
    bundle: CaptureBundle, context: dict[str, Any]
) -> CaptureBundle:
    """Attach researcher-confirmed identity, tenant, and ownership context.

    Context annotations never create credentials. They only label captured
    identity references and explicitly supplied test-owned object identifiers.
    """
    by_id = {identity.identity_id: identity for identity in bundle.identities}
    by_label = {identity.label: identity for identity in bundle.identities}
    for item in context.get("identities") or []:
        if not isinstance(item, dict):
            continue
        identity = by_id.get(str(item.get("identity_id") or "")) or by_label.get(
            str(item.get("captured_label") or item.get("label") or "")
        )
        if identity is None:
            identity = CapturedIdentity(
                identity_id=str(
                    item.get("identity_id")
                    or stable_identifier(
                        "identity", bundle.source_ref, item.get("label")
                    )
                ),
                label=str(item.get("label") or "controlled-identity"),
            )
            bundle.identities.append(identity)
            by_id[identity.identity_id] = identity
        identity.label = str(item.get("label") or identity.label)
        identity.role = str(item.get("role") or identity.role)
        identity.tenant = item.get("tenant")
        identity.controlled = bool(item.get("controlled", False))
        for request_id in item.get("request_ids") or []:
            for request in bundle.requests:
                if request.request_id == request_id:
                    request.identity_id = identity.identity_id
    for item in context.get("objects") or []:
        if not isinstance(item, dict) or not item.get("object_id"):
            continue
        bundle.objects.append(CapturedObject.model_validate(item))
    return bundle


def ingest_bundle_into_graph(
    bundle: CaptureBundle,
    graph: AttackSurfaceGraph,
    run_id: str,
) -> dict[str, int]:
    requests = parameters = identities = objects = 0
    for schema_name, schema in bundle.schemas.items():
        graph.upsert_node(
            "schema",
            f"{bundle.source_ref}\x1f{schema_name}",
            {"name": schema_name, "schema": schema},
            run_id=run_id,
        )
    for identity in bundle.identities:
        graph.upsert_node(
            "identity",
            identity.identity_id,
            identity.model_dump(exclude={"credential_references"}),
            run_id=run_id,
        )
        identities += 1
    for obj in bundle.objects:
        graph.upsert_node("object", obj.object_id, obj.model_dump(), run_id=run_id)
        objects += 1
    for request in bundle.requests:
        endpoint_id = graph.upsert_node(
            "endpoint",
            request.url,
            {
                "url": request.url,
                "path": request.path,
                "methods": [request.method],
                "body_type": request.body_type,
                "graphql_operation": request.graphql_operation,
                "state_changing": request.state_changing,
            },
            run_id=run_id,
        )
        request_id = graph.upsert_node(
            "request",
            request.request_id,
            request.model_dump(exclude={"headers"}),
            run_id=run_id,
        )
        graph.add_edge(endpoint_id, "observed_as", request_id, run_id=run_id)
        requests += 1
        if request.state_changing:
            state_id = graph.upsert_node(
                "workflow_state",
                f"{request.request_id}\x1fobserved-state-change",
                {
                    "request_id": request.request_id,
                    "method": request.method,
                    "path": request.path,
                    "state": "observed_state_changing_request",
                },
                run_id=run_id,
            )
            graph.add_edge(request_id, "may_transition", state_id, run_id=run_id)
        for parameter in request.parameters:
            parameter_id = graph.upsert_node(
                "parameter",
                f"{request.request_id}\x1f{parameter.location}\x1f{parameter.name}",
                parameter.model_dump(),
                run_id=run_id,
            )
            graph.add_edge(request_id, "accepts", parameter_id, run_id=run_id)
            parameters += 1
        if request.identity_id:
            identity_id = graph.upsert_node(
                "identity",
                request.identity_id,
                {"identity_id": request.identity_id},
                run_id=run_id,
            )
            graph.add_edge(
                request_id, "observed_under_identity", identity_id, run_id=run_id
            )
    return {
        "requests": requests,
        "parameters": parameters,
        "identities": identities,
        "objects": objects,
    }
