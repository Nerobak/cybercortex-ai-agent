from tools.safe_http import UnsafeRedirectError, scoped_get


def security_headers_checker(url: str):
    try:
        response, redirect_chain = scoped_get(url, timeout=10)
        headers = response.headers

        required_headers = {
            "Strict-Transport-Security": "Helps force HTTPS",
            "Content-Security-Policy": "Helps reduce XSS risk",
            "X-Frame-Options": "Helps prevent clickjacking",
            "X-Content-Type-Options": "Helps prevent MIME sniffing",
            "Referrer-Policy": "Controls referrer leakage",
            "Permissions-Policy": "Limits browser features",
        }

        results = {}

        for header, description in required_headers.items():
            results[header] = {
                "present": header in headers,
                "value": headers.get(header),
                "description": description,
            }

        return {
            "success": True,
            "url": response.url,
            "status_code": response.status_code,
            "requested_url": url,
            "effective_url": response.url,
            "redirect_chain": redirect_chain,
            "headers_checked": results,
        }

    except UnsafeRedirectError as e:
        return {"success": False, "error": str(e), "redirect_chain": e.redirect_chain}
    except Exception as e:
        return {"success": False, "error": str(e)}
