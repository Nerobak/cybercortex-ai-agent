from urllib.parse import urlparse

BAD_PATTERNS = [
    "example.com",
    "localhost",
    "127.0.0.1",
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

    for url in urls:
        lower_url = url.lower()
        parsed = urlparse(url)
        host = parsed.netloc.lower()

        for pattern in BAD_PATTERNS:
            if pattern.lower() in lower_url:
                findings.append({
                    "type": "suspicious_reference",
                    "severity": "low",
                    "url": url,
                    "issue": f"URL contains suspicious/test pattern: {pattern}",
                    "recommendation": "Remove test/example references from production content."
                })

        if host and allowed_domain not in host:
            findings.append({
                "type": "external_link",
                "severity": "info",
                "url": url,
                "issue": f"External domain found: {host}",
                "recommendation": "Verify this external link is intentional and safe."
            })

    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "total_urls_checked": len(urls),
        "findings_count": len(findings),
        "findings": findings
    }
