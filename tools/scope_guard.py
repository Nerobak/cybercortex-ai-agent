from urllib.parse import urlparse

from config import PENTEST_ALLOWLIST


def get_allowed_domains():
    return [
        domain.strip().lower()
        for domain in PENTEST_ALLOWLIST.split(",")
        if domain.strip()
    ]


def is_target_allowed(target: str) -> bool:
    allowed_domains = get_allowed_domains()

    parsed = urlparse(target)
    host = parsed.netloc.lower() if parsed.netloc else target.lower()
    host = host.replace("www.", "")

    for allowed in allowed_domains:
        allowed = allowed.replace("www.", "")

        if host == allowed or host.endswith("." + allowed):
            return True

    return False


def enforce_scope(target: str):
    if not is_target_allowed(target):
        return {
            "allowed": False,
            "target": target,
            "error": "Target is not in PENTEST_ALLOWLIST",
        }

    return {
        "allowed": True,
        "target": target,
        "message": "Target is allowed",
    }
