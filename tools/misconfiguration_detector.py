import ipaddress
from urllib.parse import urlparse

BAD_PATTERNS = [
    "example.com",
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "test.com",
    "staging",
    "dev.",
    "debug",
    "TODO",
    "FIXME",
]


def misconfiguration_detector(urls: list[str], allowed_domain: str):
    findings = []
    normalized_allowed = str(allowed_domain or "").lower().strip().rstrip(".")

    def is_loopback(hostname: str) -> bool:
        if hostname in {"localhost", "::1"}:
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    for url in urls:
        lower_url = url.lower()
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        target_is_authorized_loopback = (
            bool(normalized_allowed)
            and host == normalized_allowed
            and is_loopback(host)
        )

        for pattern in BAD_PATTERNS:
            if target_is_authorized_loopback and pattern.lower() in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                continue
            if pattern.lower() in lower_url:
                findings.append(
                    {
                        "type": "suspicious_reference",
                        "severity": "low",
                        "url": url,
                        "issue": f"URL contains suspicious/test pattern: {pattern}",
                        "recommendation": "Remove test/example references from production content.",
                    }
                )

        if host and not (
            host == normalized_allowed or host.endswith(f".{normalized_allowed}")
        ):
            findings.append(
                {
                    "type": "external_link",
                    "severity": "info",
                    "url": url,
                    "issue": f"External domain found: {host}",
                    "recommendation": "Verify this external link is intentional and safe.",
                }
            )

    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "total_urls_checked": len(urls),
        "findings_count": len(findings),
        "findings": findings,
    }
