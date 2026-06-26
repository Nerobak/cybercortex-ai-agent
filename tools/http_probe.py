import requests

def http_probe(url: str):

    try:

        response = requests.get(
            url,
            timeout=10
        )

        return {
            "success": True,
            "status_code": response.status_code,
            "server": response.headers.get("Server"),
            "content_type": response.headers.get("Content-Type")
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }
