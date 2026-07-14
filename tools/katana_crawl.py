import subprocess


def katana_crawl(url: str, depth: int = 2):
    try:
        result = subprocess.run(
            ["katana", "-u", url, "-d", str(depth), "-silent"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        return {
            "success": result.returncode == 0,
            "url": url,
            "depth": depth,
            "count": len(urls),
            "urls": urls[:100],
            "error": result.stderr.strip(),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
