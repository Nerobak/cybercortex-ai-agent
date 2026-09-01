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


def _bounded_positive_int(name: str, default: int, maximum: int) -> int:
    value = _positive_int(name, default)
    if value > maximum:
        CONFIG_ERRORS.append(f"{name} must not exceed {maximum}.")
        return default
    return value


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

# Separate opt-in for payload-bearing checks. This never permits denial of
# service, destructive actions, credential attacks, or targets outside scope.
ENABLE_INTRUSIVE_SCANNING = (
    os.getenv("ENABLE_INTRUSIVE_SCANNING", "false").strip().lower() == "true"
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
NUCLEI_RATE_LIMIT = _positive_int("NUCLEI_RATE_LIMIT", 3)
NUCLEI_TIMEOUT_SECONDS = _positive_int("NUCLEI_TIMEOUT_SECONDS", 120)
NUCLEI_ENABLE_OAST = os.getenv("NUCLEI_ENABLE_OAST", "false").strip().lower() == "true"
AI_REPORT_TIMEOUT_SECONDS = int(os.getenv("AI_REPORT_TIMEOUT_SECONDS", "300"))
AGENT_REQUEST_BUDGET = _positive_int("AGENT_REQUEST_BUDGET", 100)
ADAPTIVE_MAX_HYPOTHESES = _bounded_positive_int("ADAPTIVE_MAX_HYPOTHESES", 20, 200)
ADAPTIVE_MAX_VERIFICATIONS = _bounded_positive_int(
    "ADAPTIVE_MAX_VERIFICATIONS", 10, 100
)
ADAPTIVE_MAX_REQUESTS = _bounded_positive_int("ADAPTIVE_MAX_REQUESTS", 50, 5000)
ADAPTIVE_MAX_RUNTIME_SECONDS = _bounded_positive_int(
    "ADAPTIVE_MAX_RUNTIME_SECONDS", 600, 3600
)
AGENT_ISOLATE_NETWORK_TOOLS = (
    os.getenv("AGENT_ISOLATE_NETWORK_TOOLS", "true").strip().lower() == "true"
)
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
API_METADATA_DISCOVERY_ENABLED = (
    os.getenv("API_METADATA_DISCOVERY_ENABLED", "true").strip().lower() == "true"
)
API_METADATA_MAX_REQUESTS = _bounded_positive_int("API_METADATA_MAX_REQUESTS", 8, 8)
API_METADATA_TIMEOUT_SECONDS = _bounded_positive_int(
    "API_METADATA_TIMEOUT_SECONDS", 10, 30
)
API_METADATA_MAX_RESPONSE_BYTES = _bounded_positive_int(
    "API_METADATA_MAX_RESPONSE_BYTES", 2_000_000, 2_000_000
)

# ============================================================
# Output Directories
# ============================================================

REPORT_DIR = os.getenv("REPORT_DIR", "reports")

LOG_DIR = os.getenv("LOG_DIR", "logs")
