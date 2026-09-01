import socket

from tools.safe_http import ScopedHTTPClient


def dns_lookup(
    domain: str,
    *,
    http_client: ScopedHTTPClient | None = None,
    target_url: str | None = None,
):
    try:
        if http_client is not None:
            addresses = http_client.resolve_dns(
                target_url or f"https://{domain}", expected_host=domain
            )
            return {
                "success": True,
                "domain": domain,
                "ip": addresses[0] if addresses else None,
                "addresses": addresses,
                "classification": "transport_preparation",
                "http_request_count": 0,
            }
        ip = socket.gethostbyname(domain)
        return {"success": True, "domain": domain, "ip": ip}

    except Exception as e:
        return {"success": False, "error": str(e)}
