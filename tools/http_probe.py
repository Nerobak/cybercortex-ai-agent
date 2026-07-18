from tools.safe_http import UnsafeRedirectError, scoped_get


def http_probe(url: str):

    try:

        response, redirect_chain = scoped_get(url, timeout=10)

        return {
            "success": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "content_type": response.headers.get("Content-Type"),
            "requested_url": url,
            "effective_url": response.url,
            "redirect_chain": redirect_chain,
        }

    except UnsafeRedirectError as e:
        return {"success": False, "error": str(e), "redirect_chain": e.redirect_chain}
    except Exception as e:

        return {"success": False, "error": str(e)}
