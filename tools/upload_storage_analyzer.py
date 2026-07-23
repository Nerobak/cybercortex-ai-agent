"""Classify storage-provider indicators as observations only."""

from __future__ import annotations

import re
from typing import Any

from tools.upload_common import iter_evidence, observation, safe_text

PROVIDERS = {
    "s3": (r"\bs3\b", r"amazonaws\.com", r"x-amz-", r"presigned"),
    "azure_blob": (r"blob\.core\.windows\.net", r"x-ms-blob", r"azure blob"),
    "gcs": (r"storage\.googleapis\.com", r"x-goog-", r"google cloud storage"),
    "cdn": (r"\bcdn\b", r"cloudfront\.net", r"fastly", r"akamai"),
    "local_filesystem": (
        r"file://",
        r"/var/www/",
        r"uploads?[\\/]",
        r"static[\\/]uploads?",
    ),
}


def analyze_upload_storage(evidence: Any) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    providers: set[str] = set()
    for source, value in iter_evidence(evidence):
        text = safe_text(value)
        for provider, patterns in PROVIDERS.items():
            if provider not in providers and any(
                re.search(pattern, text, re.I) for pattern in patterns
            ):
                observations.append(
                    observation(source, "storage_observation", provider, "medium")
                )
                providers.add(provider)
    return {
        "success": True,
        "storage_observations": observations,
        "providers_observed": sorted(providers),
        "classification": "observation",
        "exposure_verified": False,
        "network_tested": False,
        "limitations": [
            "Provider indicators do not prove public access or storage exposure."
        ],
    }


upload_storage_analyzer = analyze_upload_storage
