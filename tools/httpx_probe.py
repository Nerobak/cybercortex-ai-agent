import subprocess
import tempfile


def httpx_probe(hosts: list[str]):
    try:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as f:
            for host in hosts:
                f.write(host + "\n")
            f.flush()

            result = subprocess.run(
                [
                    "httpx",
                    "-l",
                    f.name,
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-silent",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        return {
            "success": result.returncode == 0,
            "count": len(lines),
            "results": lines,
            "error": result.stderr.strip(),
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
