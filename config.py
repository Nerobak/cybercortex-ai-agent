from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

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

# ============================================================
# Output Directories
# ============================================================

REPORT_DIR = os.getenv("REPORT_DIR", "reports")

LOG_DIR = os.getenv("LOG_DIR", "logs")
