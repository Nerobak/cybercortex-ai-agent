"""Analyze observed upload-validation controls without inferring server behavior."""

from __future__ import annotations

import re
from typing import Any

from tools.upload_common import iter_evidence, observation, safe_text

RULES = {
    "accepted_types_observed": (
        r"\baccept\s*=",
        r"accepted[_ -]?types?",
        r"allowed[_ -]?types?",
    ),
    "rejected_types_observed": (r"rejected[_ -]?types?", r"unsupported file type"),
    "extension_check_observed": (r"\bextensions?\b", r"\.(?:png|jpe?g|pdf|txt|csv)\b"),
    "mime_validation_observed": (r"\bmime\b", r"content-type"),
    "size_limit_observed": (
        r"max(?:imum)?[_ -]?(?:file[_ -]?)?size",
        r"size[_ -]?limit",
        r"\d+\s*(?:kb|mb|gb)\b",
    ),
    "client_side_restriction_observed": (
        r"\baccept\s*=",
        r"files?\[0\]\.size",
        r"files?\[0\]\.type",
    ),
    "server_side_hint_observed": (
        r"status[_ -]?code",
        r"http_status",
        r"response_headers",
    ),
    "filename_validation_observed": (
        r"sanitize[_ -]?file",
        r"filename[_ -]?valid",
        r"secure_filename",
    ),
}


def analyze_upload_validation(evidence: Any) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    matched: set[tuple[str, str]] = set()
    for source, value in iter_evidence(evidence):
        text = safe_text(value)
        for kind, patterns in RULES.items():
            if (source, kind) in matched:
                continue
            if any(re.search(pattern, text, re.I) for pattern in patterns):
                observations.append(
                    observation(source, kind, kind.replace("_", " "), "medium")
                )
                matched.add((source, kind))
    kinds = {item["type"] for item in observations}
    client_only = (
        "client_side_restriction_observed" in kinds
        and "server_side_hint_observed" not in kinds
    )
    candidates = []
    if client_only:
        candidates.append(
            {
                "type": "validation_consistency_requires_verification",
                "classification": "candidate",
                "status": "needs_manual_verification",
                "evidence": [
                    "Client-side restrictions were observed without server-response evidence."
                ],
                "automatic_execution": False,
            }
        )
    return {
        "success": True,
        "observations": observations,
        "candidates": candidates,
        "classification": "observation",
        "server_behavior_inferred": False,
        "network_tested": False,
        "limitations": [
            "Absent validation evidence does not prove validation is absent."
        ],
    }


upload_validation_analyzer = analyze_upload_validation
