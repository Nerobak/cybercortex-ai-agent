from urllib.parse import urlparse, parse_qs

INTERESTING_KEYWORDS = {
    "admin": "Access control / admin exposure",
    "login": "Authentication testing",
    "logout": "Session handling",
    "register": "Account creation testing",
    "signup": "Account creation testing",
    "reset": "Password reset testing",
    "forgot": "Password reset testing",
    "password": "Password/account recovery testing",
    "api": "API testing",
    "user": "IDOR / user data testing",
    "profile": "IDOR / account data testing",
    "account": "Account authorization testing",
    "upload": "File upload testing",
    "download": "File download/path traversal testing",
    "file": "File handling testing",
    "redirect": "Open redirect testing",
    "oauth": "OAuth flow testing",
    "callback": "OAuth/callback testing",
    "token": "Token handling testing",
    "search": "Input validation testing",
    "query": "Input validation testing",
}

def endpoint_analyzer(urls: list[str], allowed_domain: str):
    findings = []
    seen = set()

    for url in urls:
        if url in seen:
            continue
        seen.add(url)

        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parse_qs(parsed.query)

        if allowed_domain not in host:
            continue

        reasons = []

        for keyword, reason in INTERESTING_KEYWORDS.items():
            if keyword in path or keyword in parsed.query.lower():
                reasons.append(reason)

        if query:
            reasons.append(f"Has parameters: {list(query.keys())}")

        if reasons:
            findings.append({
                "url": url,
                "path": parsed.path,
                "parameters": list(query.keys()),
                "reasons": sorted(set(reasons)),
                "suggested_tests": [
                    "Check authorization boundaries",
                    "Check input validation",
                    "Check for sensitive data exposure",
                    "Verify behavior manually before reporting"
                ]
            })

    return {
        "success": True,
        "allowed_domain": allowed_domain,
        "total_urls_checked": len(urls),
        "interesting_count": len(findings),
        "interesting_endpoints": findings
    }
