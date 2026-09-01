import hashlib
import math
import re

from tools.safe_http import ScopedHTTPClient, scoped_get

ASSIGNMENT = re.compile(
    r"""(?i)\b(api[_-]?key|token|secret|password|client[_-]?secret|authorization)\b\s*[:=]\s*["']([^"']*)["']"""
)
EMAIL = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b")
KNOWN_CREDENTIAL = re.compile(
    r"^(?:AKIA[0-9A-Z]{16}|sk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|Bearer\s+[A-Za-z0-9._~+/-]{20,}=*)$"
)
PLACEHOLDERS = {
    "",
    "example",
    "sample",
    "placeholder",
    "changeme",
    "password",
    "secret",
    "token",
    "test",
    "undefined",
    "null",
}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (value.count(c) / len(value)) * math.log2(value.count(c) / len(value))
        for c in set(value)
    )


def _candidate(value: str) -> bool:
    return value.lower().strip() not in PLACEHOLDERS and (
        bool(KNOWN_CREDENTIAL.fullmatch(value))
        or (len(value) >= 20 and _entropy(value) >= 3.5)
    )


def _redact(value: str) -> str:
    if "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    return f"{value[:4]}…[REDACTED]…{value[-4:]}" if len(value) >= 10 else "[REDACTED]"


def _finding(
    url: str,
    content: str,
    match: re.Match,
    kind: str,
    confidence: str,
    finding_type: str,
) -> dict:
    value = match.group(0) if kind == "public_contact" else match.group(2)
    line = content.count("\n", 0, match.start()) + 1
    context = content[max(0, match.start() - 40) : match.end() + 40]
    return {
        "url": url,
        "type": finding_type,
        "match_kind": kind,
        "confidence": confidence,
        "redacted_sample": _redact(value),
        "context_hash": hashlib.sha256(context.encode()).hexdigest(),
        "line": line,
        "offset": match.start(),
        "severity": (
            "informational" if kind == "public_contact" else "needs_manual_verification"
        ),
        "vulnerability_status": (
            "needs_manual_verification" if kind == "candidate_value" else "observation"
        ),
    }


def js_secret_scanner(
    urls: list[str],
    allowed_domain: str,
    *,
    http_client: ScopedHTTPClient | None = None,
):
    findings, errors, seen = [], [], set()
    checked = 0
    for url in sorted(set(urls)):
        if allowed_domain not in url:
            continue
        if not (
            url.endswith((".js", ".mjs", ".css", "/"))
            or "/_astro/" in url
            or "." not in url.split("/")[-1]
        ):
            continue
        try:
            response, _ = scoped_get(url, timeout=10, http_client=http_client)
            checked += 1
            content = response.text
            matches = [
                _finding(
                    url,
                    content,
                    match,
                    "candidate_value",
                    "medium",
                    f"possible_{match.group(1).lower()}",
                )
                for match in ASSIGNMENT.finditer(content)
                if _candidate(match.group(2))
            ]
            matches.extend(
                _finding(url, content, match, "public_contact", "high", "contact_email")
                for match in EMAIL.finditer(content)
            )
            for item in matches:
                identity = (item["match_kind"], item["context_hash"])
                if identity not in seen:
                    seen.add(identity)
                    findings.append(item)
        except Exception as exc:
            errors.append({"url": url, "error": str(exc)})
    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "urls_checked": checked,
        "findings_count": len(findings),
        "findings": findings,
        "errors": errors,
    }
