import socket


def dns_lookup(domain: str):
    try:
        ip = socket.gethostbyname(domain)

        return {"success": True, "domain": domain, "ip": ip}

    except Exception as e:
        return {"success": False, "error": str(e)}
