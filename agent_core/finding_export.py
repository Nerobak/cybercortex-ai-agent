"""Deterministic structural semantics for normalized finding exports."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class WorkflowExportRule:
    """Category semantics for selecting workflow export operations."""

    workflow_type: str
    affected_boundary_type: str
    verification_boundary_type: str | None = None
    surface_boundary_types: tuple[str, ...] = ()


WORKFLOW_EXPORT_RULES = {
    "session_invalidation": WorkflowExportRule(
        workflow_type="session_lifecycle",
        affected_boundary_type="session_termination",
        verification_boundary_type="authenticated_resource",
        surface_boundary_types=(
            "session_creation",
            "authenticated_resource",
            "session_termination",
        ),
    ),
}


def _route_template(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "unknown"
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.netloc:
        return parsed.path or "/"
    return raw.split("?", 1)[0].split("#", 1)[0] or "/"


def _http_method(value: Any) -> str:
    method = str(value or "GET").strip().upper()
    return method if re.fullmatch(r"[A-Z]{1,16}", method) else "UNKNOWN"


def _route_parameter(route_template: str, value: Any) -> str:
    parameter = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]-]*", parameter):
        return ""
    return parameter if f"{{{parameter}}}" in route_template else ""


@dataclass(frozen=True)
class ExportOperation:
    method: str
    route_template: str
    parameter: str = ""

    @property
    def affected_functionality(self) -> str:
        return " ".join(
            item for item in (self.method, self.route_template, self.parameter) if item
        )

    def normalized_resource(self) -> dict[str, str]:
        resource = {
            "method": self.method,
            "route_template": self.route_template,
        }
        if self.parameter:
            resource["parameter"] = self.parameter
        return resource


@dataclass(frozen=True)
class FindingExportStructure:
    affected_operation: ExportOperation
    verification_resource: dict[str, str] | None = None
    workflow: dict[str, Any] | None = None

    def optional_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.verification_resource is not None:
            fields["verification_resource"] = self.verification_resource
        if self.workflow is not None:
            fields["workflow"] = self.workflow
        return fields


def _target_operation(hypothesis: dict[str, Any]) -> ExportOperation:
    surface = hypothesis.get("target_surface") or {}
    if not isinstance(surface, dict):
        surface = {}
    method = str(surface.get("method") or hypothesis.get("method") or "GET").upper()
    route = str(surface.get("path") or "").strip()
    endpoint = str(hypothesis.get("endpoint") or "").strip()
    if not route and endpoint:
        route = _route_template(endpoint)
    parameter = str(
        surface.get("parameter") or hypothesis.get("parameter") or ""
    ).strip()
    return ExportOperation(
        method=method,
        route_template=_route_template(route),
        parameter=parameter,
    )


def _workflow_surfaces(
    hypothesis: dict[str, Any], boundary_types: tuple[str, ...]
) -> list[dict[str, str]]:
    metadata = hypothesis.get("metadata") or {}
    if not isinstance(metadata, dict):
        return []
    surfaces_by_type: dict[str, dict[str, Any]] = {}
    for raw_surface in metadata.get("related_surfaces") or []:
        if not isinstance(raw_surface, dict):
            continue
        boundary_type = str(raw_surface.get("boundary_type") or "").strip()
        if boundary_type in boundary_types and boundary_type not in surfaces_by_type:
            surfaces_by_type[boundary_type] = raw_surface
    surfaces: list[dict[str, str]] = []
    for boundary_type in boundary_types:
        raw_surface = surfaces_by_type.get(boundary_type)
        if raw_surface is None:
            continue
        route = _route_template(raw_surface.get("path"))
        if route == "unknown":
            continue
        operation = ExportOperation(
            method=_http_method(raw_surface.get("method")),
            route_template=route,
            parameter=_route_parameter(route, raw_surface.get("parameter")),
        )
        surface = {
            "boundary_type": boundary_type,
            **operation.normalized_resource(),
        }
        surfaces.append(surface)
    return surfaces


def _operation_for_boundary(
    surfaces: list[dict[str, str]], boundary_type: str
) -> ExportOperation | None:
    surface = next(
        (item for item in surfaces if item["boundary_type"] == boundary_type), None
    )
    if surface is None:
        return None
    return ExportOperation(
        method=surface["method"],
        route_template=surface["route_template"],
        parameter=surface.get("parameter", ""),
    )


def _workflow_identity(workflow_type: str, surfaces: list[dict[str, str]]) -> str:
    sequence = "->".join(
        f"{item['method']}:{item['route_template']}" for item in surfaces
    )
    return f"{workflow_type}:{sequence}"


def resolve_finding_export(
    hypothesis: dict[str, Any],
    *,
    default_operation: ExportOperation | None = None,
) -> FindingExportStructure:
    """Resolve affected and verification operations without interpreting prose."""

    category = str(hypothesis.get("category") or "unknown").strip().casefold()
    rule = WORKFLOW_EXPORT_RULES.get(category)
    if rule is None:
        return FindingExportStructure(
            affected_operation=default_operation or _target_operation(hypothesis)
        )

    surfaces = _workflow_surfaces(hypothesis, rule.surface_boundary_types)
    affected_operation = _operation_for_boundary(surfaces, rule.affected_boundary_type)
    if affected_operation is None:
        raise ValueError(
            f"Workflow category {category!r} requires a structured "
            f"{rule.affected_boundary_type!r} surface for export."
        )
    verification_operation = (
        _operation_for_boundary(surfaces, rule.verification_boundary_type)
        if rule.verification_boundary_type
        else None
    )
    workflow = {
        "type": rule.workflow_type,
        "identity": _workflow_identity(rule.workflow_type, surfaces),
        "surfaces": surfaces,
    }
    return FindingExportStructure(
        affected_operation=affected_operation,
        verification_resource=(
            verification_operation.normalized_resource()
            if verification_operation is not None
            else None
        ),
        workflow=workflow,
    )
