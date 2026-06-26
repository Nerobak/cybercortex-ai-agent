from urllib.parse import urlparse, parse_qs

PARAMETER_PATTERNS = {
    "id": "Possible IDOR / Access Control",
    "user": "User Enumeration / IDOR",
    "userid": "User Enumeration / IDOR",
    "account": "Account Access Control",
    "profile": "Profile Access Control",
    "email": "User Enumeration",
    "token": "Token Handling",
    "redirect": "Open Redirect",
    "url": "Open Redirect",
    "next": "Open Redirect",
    "return": "Open Redirect",
    "file": "File Handling",
    "path": "Path Traversal",
    "download": "File Download",
    "search": "Input Validation",
    "query": "Input Validation"
}

def parameter_analyzer(urls):
    findings = []

    for url in urls:

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:

            key = param.lower()

            for pattern, reason in PARAMETER_PATTERNS.items():

                if pattern in key:

                    findings.append({
                        "url": url,
                        "parameter": param,
                        "reason": reason
                    })

    return {
        "success": True,
        "findings_count": len(findings),
        "findings": findings
    }
