"""Observe filename and upload metadata handling from supplied evidence."""

from __future__ import annotations

import re
from typing import Any

from tools.upload_common import iter_evidence, observation, safe_text

RULES = {
    "filename_handling_observed": (r"\bfilename\b", r"content-disposition"),
    "path_handling_observed": (
        r"upload[_ -]?path",
        r"storage[_ -]?path",
        r"secure_filename",
    ),
    "uuid_naming_observed": (r"\buuid\b", r"[0-9a-f]{8}-[0-9a-f-]{27,}"),
    "random_naming_observed": (
        r"random[_ -]?(?:name|key)",
        r"generated[_ -]?(?:name|key)",
    ),
    "timestamp_naming_observed": (r"timestamp[_ -]?(?:name|key)", r"strftime"),
    "metadata_stripping_observed": (
        r"strip[_ -]?metadata",
        r"remove[_ -]?exif",
        r"exiftool",
    ),
    "content_disposition_observed": (r"content-disposition",),
    "object_storage_metadata_observed": (r"\betag\b", r"object[_ -]?key", r"presigned"),
}


def analyze_upload_metadata(evidence: Any) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    found: set[tuple[str, str]] = set()
    for source, value in iter_evidence(evidence):
        text = safe_text(value)
        for kind, patterns in RULES.items():
            if (source, kind) not in found and any(
                re.search(pattern, text, re.I) for pattern in patterns
            ):
                observations.append(
                    observation(source, kind, kind.replace("_", " "), "medium")
                )
                found.add((source, kind))
    return {
        "success": True,
        "observations": observations,
        "classification": "observation",
        "network_tested": False,
        "filenames_disclosed": False,
        "limitations": [
            "Naming indicators do not prove the final storage key or path."
        ],
    }


upload_metadata_analyzer = analyze_upload_metadata
