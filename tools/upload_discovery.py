"""Discover file-upload surface from already-collected evidence."""

from __future__ import annotations

from typing import Any

from tools.upload_common import iter_evidence, observation, safe_text


def discover_upload_surface(evidence: Any) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    patterns = (
        ("multipart_observed", ("multipart/form-data",), "multipart form encoding"),
        (
            "file_input_observed",
            ('type="file"', "type='file'", "input type=file"),
            "HTML file input",
        ),
        (
            "graphql_upload_scalar_observed",
            ("scalar upload", '"name": "upload"', "'name': 'upload'"),
            "GraphQL Upload scalar",
        ),
        (
            "javascript_upload_observed",
            ("formdata(", ".append(", "filelist", "filereader"),
            "JavaScript upload handling",
        ),
        (
            "upload_endpoint_observed",
            ("/upload", "/attachments", "/files", "uploadfile", "upload_file"),
            "upload-related endpoint",
        ),
    )
    for source, value in iter_evidence(evidence):
        text = safe_text(value)
        lowered = text.lower()
        for kind, markers, detail in patterns:
            if (
                any(marker in lowered for marker in markers)
                and (source, kind) not in seen
            ):
                confidence = (
                    "high"
                    if kind in {"multipart_observed", "file_input_observed"}
                    else "medium"
                )
                observations.append(observation(source, kind, detail, confidence))
                seen.add((source, kind))
    return {
        "success": True,
        "observations": observations,
        "upload_surface_observed": bool(observations),
        "observation_count": len(observations),
        "executed": False,
        "network_tested": False,
        "classification": "observation",
        "limitations": [
            "Upload-related names and client code do not prove a functioning endpoint.",
            "No request was sent and no file was uploaded.",
        ],
    }


upload_discovery = discover_upload_surface
