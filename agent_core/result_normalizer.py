def normalize_results(results: dict):
    normalized = {}

    # HTTP Probe
    http = results.get("http_probe", {})
    normalized["http_probe"] = {
        "status_code": http.get("status_code"),
        "server": http.get("server"),
        "content_type": http.get("content_type"),
    }

    # Security Headers
    headers = results.get("security_headers_checker", {})

    normalized["headers"] = {
        "present": headers.get("present_headers", []),
        "missing": headers.get("missing_headers", []),
    }

    # Katana
    crawl = results.get("katana_crawl", {})

    normalized["crawl"] = {
        "urls_found": crawl.get("count", 0),
    }

    # Misconfiguration
    misconfig = results.get("misconfiguration_detector", {})

    normalized["misconfigurations"] = {
        "count": misconfig.get("findings_count", 0),
        "findings": misconfig.get("findings", []),
    }

    # JS Scanner
    js = results.get("js_secret_scanner", {})

    normalized["javascript"] = {
        "findings": js.get("findings_count", 0),
    }

    # Nuclei
    nuclei = results.get("nuclei_scan", {})

    normalized["nuclei"] = {
        "severity": nuclei.get("severity"),
        "findings_count": nuclei.get("findings_count", 0),
    }

    return normalized
