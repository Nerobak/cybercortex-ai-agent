import re
import requests

SECRET_PATTERNS = {
    "possible_aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "possible_api_key": r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]",
    "possible_bearer_token": r"\bBearer\s+[A-Za-z0-9\-\._~\+\/]{20,}=*\b",
    "possible_private_key": r"-----BEGIN (RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----",
    "email_address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "example_domain_reference": r"https?://example\.com[^\s\"'>)]*",
    "localhost_reference": r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s\"'>)]*",
}

def js_secret_scanner(urls: list[str], allowed_domain: str):
    findings = []
    checked = 0

    for url in sorted(set(urls)):
        if allowed_domain not in url:
            continue

        should_check = (
            url.endswith(".js")
            or url.endswith(".css")
            or "/_astro/" in url
            or url.endswith("/")
            or "." not in url.split("/")[-1]
        )

        if not should_check:
            continue

        try:
            response = requests.get(url, timeout=10)
            checked += 1
            content = response.text

            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)

                if matches:
                    sample_matches = matches[:5]

                    findings.append({
                        "url": url,
                        "type": name,
                        "matches_count": len(matches),
                        "sample_matches": sample_matches,
                        "risk": "review_required",
                        "recommendation": "Manually review the matched value and remove it if it is sensitive or a test reference."
                    })

        except Exception as e:
            findings.append({
                "url": url,
                "type": "fetch_error",
                "error": str(e)
            })

    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "urls_checked": checked,
        "findings_count": len(findings),
        "findings": findings
    }
