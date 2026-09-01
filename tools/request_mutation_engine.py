from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from tools.raw_http_request_parser import parse_raw_http_request
from tools.safe_http import ScopedHTTPClient
from tools.scope_guard import enforce_scope

MAX_RESPONSE_BYTES = 500_000
MAX_PROBES = 8
SUPPORTED_FAMILIES = {"xss", "ssti", "command", "traversal", "ssrf"}
SQL_ERROR_PATTERN = re.compile(
    r"sql syntax|mysql_fetch|ora-\d{4}|postgresql.*error|sqlite.*error|"
    r"unclosed quotation mark|jdbc.*exception",
    re.I,
)


@dataclass(frozen=True)
class Probe:
    family: str
    payload: str
    expected_marker: str | None
    proof_type: str


def _marker(label: str, seed: str) -> str:
    digest = hashlib.sha256(f"{label}:{seed}".encode()).hexdigest()[:12]
    return f"CCX_{label.upper()}_{digest}"


def _replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    updated = []
    for name, current in pairs:
        if name == parameter and not found:
            updated.append((name, value))
            found = True
        else:
            updated.append((name, current))
    if not found:
        raise ValueError(f"Query parameter '{parameter}' was not present.")
    return urlunsplit(parsed._replace(query=urlencode(updated)))


def build_probes(
    families: list[str],
    *,
    seed: str,
    callback_url: str | None = None,
    traversal_canary_path: str | None = None,
    traversal_expected_marker: str | None = None,
) -> list[Probe]:
    unknown = sorted(set(families) - SUPPORTED_FAMILIES)
    if unknown:
        raise ValueError("Unsupported probe families: " + ", ".join(unknown))
    probes: list[Probe] = []
    for family in dict.fromkeys(families):
        marker = _marker(family, seed)
        if family == "xss":
            probes.append(
                Probe(
                    family, f'"><svg data-ccx="{marker}"></svg>', marker, "reflection"
                )
            )
        elif family == "ssti":
            probes.extend(
                (
                    Probe(family, f"{marker}{{{{7*7}}}}", f"{marker}49", "evaluation"),
                    Probe(family, f"{marker}${{7*7}}", f"{marker}49", "evaluation"),
                )
            )
        elif family == "command":
            probes.append(Probe(family, f";printf {marker}", marker, "command_output"))
        elif family == "traversal":
            if not traversal_canary_path or not traversal_expected_marker:
                raise ValueError(
                    "Traversal requires a researcher-created canary path and expected marker."
                )
            if (
                traversal_canary_path.startswith(("/", "\\"))
                or ".." in traversal_canary_path
            ):
                raise ValueError("Traversal canary path must be a safe relative path.")
            probes.append(
                Probe(
                    family,
                    "../../../../" + traversal_canary_path,
                    traversal_expected_marker,
                    "controlled_file_read",
                )
            )
        elif family == "ssrf":
            if not callback_url:
                raise ValueError("SSRF requires a researcher-controlled callback URL.")
            callback = urlsplit(callback_url)
            if callback.scheme not in {"http", "https"} or not callback.hostname:
                raise ValueError("SSRF callback must be an absolute HTTP(S) URL.")
            callback_with_marker = callback_url.rstrip("/") + "/" + marker
            probes.append(
                Probe(family, callback_with_marker, marker, "callback_pending")
            )
    if len(probes) > MAX_PROBES:
        raise ValueError(f"Probe plan exceeds the {MAX_PROBES}-probe limit.")
    return probes


def _fingerprint(response: requests.Response) -> tuple[dict[str, Any], str]:
    body = response.content[:MAX_RESPONSE_BYTES]
    text = body.decode(response.encoding or "utf-8", "replace")
    return (
        {
            "status_code": response.status_code,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "content_type": response.headers.get("Content-Type", "")[:120],
        },
        text,
    )


def verify_request_mutations(
    raw_request: str,
    parameter: str,
    families: list[str],
    *,
    default_scheme: str = "https",
    authorization_confirmed: bool = False,
    callback_url: str | None = None,
    traversal_canary_path: str | None = None,
    traversal_expected_marker: str | None = None,
    timeout_seconds: int = 15,
    verify_tls: bool = True,
) -> dict[str, Any]:
    if not authorization_confirmed:
        return {
            "success": False,
            "error": "Explicit authorization confirmation is required.",
        }
    parsed = parse_raw_http_request(raw_request, default_scheme=default_scheme)
    if not parsed.get("success"):
        return parsed
    if parsed.get("method") != "GET":
        return {
            "success": False,
            "error": "Mutation verification currently supports GET only.",
        }
    url = parsed["url"]
    scope = enforce_scope(url)
    if not scope.get("allowed"):
        return {"success": False, "error": scope.get("error"), "scope": scope}
    seed = f"{urlsplit(url).path}:{parameter}"
    try:
        probes = build_probes(
            families,
            seed=seed,
            callback_url=callback_url,
            traversal_canary_path=traversal_canary_path,
            traversal_expected_marker=traversal_expected_marker,
        )
        _replace_query_parameter(url, parameter, "validation")
    except ValueError as exc:
        return {"success": False, "error": str(exc)}
    headers = {
        name: value
        for name, value in parsed.get("headers", {}).items()
        if name.lower() not in {"host", "content-length"}
    }
    client = ScopedHTTPClient(
        requester=requests.get,
        requester_takes_method=False,
        scope_prevalidated=True,
    )
    try:
        baseline_response, _ = client.request(
            "GET",
            url,
            headers=headers,
            timeout=timeout_seconds,
            follow_redirects=False,
            verify=verify_tls,
        )
        baseline_fp, baseline_text = _fingerprint(baseline_response)
        results = []
        for probe in probes:
            response, _ = client.request(
                "GET",
                _replace_query_parameter(url, parameter, probe.payload),
                headers=headers,
                timeout=timeout_seconds,
                follow_redirects=False,
                verify=verify_tls,
            )
            fingerprint, text = _fingerprint(response)
            marker_new = bool(
                probe.expected_marker
                and probe.expected_marker in text
                and probe.expected_marker not in baseline_text
            )
            sql_error = bool(SQL_ERROR_PATTERN.search(text)) and not bool(
                SQL_ERROR_PATTERN.search(baseline_text)
            )
            confirmed = marker_new and probe.proof_type in {
                "evaluation",
                "command_output",
                "controlled_file_read",
            }
            status = (
                "verified"
                if confirmed
                else "needs_manual_verification" if marker_new else "observation"
            )
            results.append(
                {
                    "family": probe.family,
                    "proof_type": probe.proof_type,
                    "status": status,
                    "confidence": (
                        "high" if confirmed else "medium" if marker_new else "low"
                    ),
                    "marker_observed": marker_new,
                    "new_sql_error_observed": sql_error,
                    "correlation_id": (
                        probe.expected_marker if probe.family == "ssrf" else None
                    ),
                    "response": fingerprint,
                }
            )
    except requests.RequestException as exc:
        return {"success": False, "error": f"Controlled mutation request failed: {exc}"}
    findings = [item for item in results if item["status"] != "observation"]
    return {
        "success": True,
        "target": urlsplit(url)._replace(query="").geturl(),
        "parameter": parameter,
        "request_count": 1 + len(probes),
        "baseline": baseline_fp,
        "probe_results": results,
        "finding_count": len(findings),
        "findings": findings,
        "safety": {
            "bounded": True,
            "data_extraction": False,
            "state_changes": False,
            "credentials_returned": False,
        },
    }
