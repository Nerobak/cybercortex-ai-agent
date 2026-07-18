from tools.safe_http import UnsafeRedirectError, scoped_get


def tech_fingerprint(url: str):
    try:
        response, redirect_chain = scoped_get(url, timeout=10)

        headers = dict(response.headers)

        technologies = []

        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")

        if server:
            technologies.append(f"Server: {server}")

        if powered_by:
            technologies.append(f"X-Powered-By: {powered_by}")

        body = response.text[:5000].lower()

        if "cloudfront" in str(headers).lower():
            technologies.append("AWS CloudFront")

        if "amazons3" in str(headers).lower() or "amazon s3" in body:
            technologies.append("Amazon S3")

        if "astro" in body:
            technologies.append("Astro possible")

        return {
            "success": True,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": headers,
            "technologies": technologies,
            "requested_url": url,
            "redirect_chain": redirect_chain,
        }

    except UnsafeRedirectError as e:
        return {"success": False, "error": str(e), "redirect_chain": e.redirect_chain}
    except Exception as e:
        return {"success": False, "error": str(e)}
