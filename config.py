from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

CONFIG_ERRORS: list[str] = []


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        CONFIG_ERRORS.append(f"{name} must be a positive integer.")
        return default


# ============================================================
# LLM Configuration
# ============================================================

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL")

# ============================================================
# Security Configuration
# ============================================================

# Domain-based allowlist
# Example:
# testphp.vulnweb.com,localhost,127.0.0.1
PENTEST_ALLOWLIST = os.getenv("PENTEST_ALLOWLIST", "")

# URL prefix allowlist
# Example:
# https://crypto.com/exchange
# https://example.com/api/v1
PENTEST_ALLOWED_URL_PREFIXES = os.getenv("PENTEST_ALLOWED_URL_PREFIXES", "")

# Enable or disable active testing
ENABLE_ACTIVE_SCANNING = (
    os.getenv("ENABLE_ACTIVE_SCANNING", "false").strip().lower() == "true"
)

# ============================================================
# Bug Bounty Configuration
# ============================================================

BUG_BOUNTY_MODE = os.getenv("BUG_BOUNTY_MODE", "false").strip().lower() == "true"

BUG_BOUNTY_PLATFORM = os.getenv("BUG_BOUNTY_PLATFORM", "")

BUG_BOUNTY_USERNAME = os.getenv("BUG_BOUNTY_USERNAME", "")

BUG_BOUNTY_IDENTIFIER = os.getenv("BUG_BOUNTY_IDENTIFIER", "")

BUG_BOUNTY_CONTACT = os.getenv("BUG_BOUNTY_CONTACT", "")

BUG_BOUNTY_USER_AGENT = os.getenv("BUG_BOUNTY_USER_AGENT", "CyberCortexAI")

# ============================================================
# Tool Defaults
# ============================================================

MAX_CRAWL_DEPTH = int(os.getenv("MAX_CRAWL_DEPTH", "2"))

NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "low")
AI_REPORT_TIMEOUT_SECONDS = int(os.getenv("AI_REPORT_TIMEOUT_SECONDS", "300"))
GRAPHQL_INTROSPECTION_ENABLED = (
    os.getenv("GRAPHQL_INTROSPECTION_ENABLED", "false").strip().lower() == "true"
)
GRAPHQL_TIMEOUT_SECONDS = int(os.getenv("GRAPHQL_TIMEOUT_SECONDS", "15"))
GRAPHQL_MAX_RESPONSE_BYTES = int(os.getenv("GRAPHQL_MAX_RESPONSE_BYTES", "1000000"))
JWT_REPLAY_ENABLED = os.getenv("JWT_REPLAY_ENABLED", "false").strip().lower() == "true"
JWT_TIMEOUT_SECONDS = _positive_int("JWT_TIMEOUT_SECONDS", 15)
JWT_MAX_RESPONSE_BYTES = _positive_int("JWT_MAX_RESPONSE_BYTES", 1000000)
JWT_MAX_LIFETIME_SECONDS = _positive_int("JWT_MAX_LIFETIME_SECONDS", 86400)
JWT_CLOCK_SKEW_SECONDS = _positive_int("JWT_CLOCK_SKEW_SECONDS", 300)
JWT_MAX_TOKEN_BYTES = _positive_int("JWT_MAX_TOKEN_BYTES", 16384)
BUSINESS_LOGIC_REPLAY_ENABLED = (
    os.getenv("BUSINESS_LOGIC_REPLAY_ENABLED", "false").strip().lower() == "true"
)
BUSINESS_LOGIC_TIMEOUT_SECONDS = _positive_int("BUSINESS_LOGIC_TIMEOUT_SECONDS", 15)
BUSINESS_LOGIC_MAX_RESPONSE_BYTES = _positive_int(
    "BUSINESS_LOGIC_MAX_RESPONSE_BYTES", 1000000
)
BUSINESS_LOGIC_MAX_STEPS = _positive_int("BUSINESS_LOGIC_MAX_STEPS", 10)
BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN = _positive_int(
    "BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN", 3
)

# ============================================================
# Output Directories
# ============================================================

REPORT_DIR = os.getenv("REPORT_DIR", "reports")

LOG_DIR = os.getenv("LOG_DIR", "logs")
