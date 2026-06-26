import requests

def security_headers_checker(url: str):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        required_headers = {
            "Strict-Transport-Security": "Helps force HTTPS",
            "Content-Security-Policy": "Helps reduce XSS risk",
            "X-Frame-Options": "Helps prevent clickjacking",
            "X-Content-Type-Options": "Helps prevent MIME sniffing",
            "Referrer-Policy": "Controls referrer leakage",
            "Permissions-Policy": "Limits browser features"
        }

        results = {}

        for header, description in required_headers.items():
            results[header] = {
                "present": header in headers,
                "value": headers.get(header),
                "description": description
            }

        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "headers_checked": results
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
