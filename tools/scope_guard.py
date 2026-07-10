from urllib.parse import urlparse

from config import (
    PENTEST_ALLOWLIST,
    PENTEST_ALLOWED_URL_PREFIXES,
)


def get_allowed_domains() -> list[str]:
    return [
        item.strip().lower().rstrip(".")
        for item in PENTEST_ALLOWLIST.split(",")
        if item.strip()
    ]


def get_allowed_url_prefixes() -> list[str]:
    return [
        item.strip().rstrip("/")
        for item in PENTEST_ALLOWED_URL_PREFIXES.split(",")
        if item.strip()
    ]


def normalize_url(target: str) -> str:
    target = target.strip()

    if "://" not in target:
        target = f"https://{target}"

    return target


def normalize_path(path: str) -> str:
    if not path:
        return "/"

    if not path.startswith("/"):
        path = f"/{path}"

    # Remove trailing slash except for the root path.
    if path != "/":
        path = path.rstrip("/")

    return path


def get_effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port

    if parsed.scheme == "https":
        return 443

    if parsed.scheme == "http":
        return 80

    return None


def is_domain_allowed(target: str) -> bool:
    parsed = urlparse(normalize_url(target))

    host = (parsed.hostname or "").lower().rstrip(".")

    if not host:
        return False

    for allowed in get_allowed_domains():
        # Domain allowlist entries should not contain URLs or paths.
        if "://" in allowed or "/" in allowed:
            continue

        allowed_host = allowed.removeprefix("www.")

        if host == allowed_host:
            return True

    return False


def is_url_prefix_allowed(target: str) -> bool:
    parsed_target = urlparse(normalize_url(target))

    target_scheme = parsed_target.scheme.lower()
    target_host = (parsed_target.hostname or "").lower().rstrip(".")
    target_port = get_effective_port(parsed_target)
    target_path = normalize_path(parsed_target.path)

    if target_scheme not in {"http", "https"}:
        return False

    if not target_host:
        return False

    for allowed_url in get_allowed_url_prefixes():
        parsed_allowed = urlparse(normalize_url(allowed_url))

        allowed_scheme = parsed_allowed.scheme.lower()
        allowed_host = (parsed_allowed.hostname or "").lower().rstrip(".")
        allowed_port = get_effective_port(parsed_allowed)
        allowed_path = normalize_path(parsed_allowed.path)

        same_origin = (
            target_scheme == allowed_scheme
            and target_host == allowed_host
            and target_port == allowed_port
        )

        path_allowed = (
            target_path == allowed_path
            or target_path.startswith(f"{allowed_path}/")
        )

        if same_origin and path_allowed:
            return True

    return False


def is_target_allowed(target: str) -> bool:
    return is_domain_allowed(target) or is_url_prefix_allowed(target)


def enforce_scope(target: str) -> dict:
    if not is_target_allowed(target):
        return {
            "allowed": False,
            "target": target,
            "error": (
                "Target is not covered by PENTEST_ALLOWLIST "
                "or PENTEST_ALLOWED_URL_PREFIXES"
            ),
        }

    return {
        "allowed": True,
        "target": target,
        "message": "Target is within the configured testing scope",
    }
