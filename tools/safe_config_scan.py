from tools.http_probe import http_probe
from tools.security_headers_checker import security_headers_checker
from tools.katana_crawl import katana_crawl
from tools.misconfiguration_detector import misconfiguration_detector
from tools.js_secret_scanner import js_secret_scanner
from tools.scope_guard import enforce_scope

def safe_config_scan(url: str, allowed_domain: str):
    scope = enforce_scope(url)

    if not scope["allowed"]:
        return scope

    http_result = http_probe(url)
    headers_result = security_headers_checker(url)
    crawl_result = katana_crawl(url, depth=2)

    urls = crawl_result.get("urls", [])

    misconfig_result = misconfiguration_detector(urls, allowed_domain)
    js_result = js_secret_scanner(urls, allowed_domain)

    return {
        "success": True,
        "target": url,
        "http_probe": http_result,
        "security_headers": headers_result,
        "crawl_summary": {
            "count": crawl_result.get("count"),
            "sample_urls": urls[:20],
        },
        "misconfigurations": misconfig_result,
        "js_secret_scan": js_result,
    }
