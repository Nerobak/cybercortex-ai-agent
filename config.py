from dotenv import load_dotenv
import os

load_dotenv()

# -----------------------------
# LLM Configuration
# -----------------------------
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL")

# -----------------------------
# Security Configuration
# -----------------------------
PENTEST_ALLOWLIST = os.getenv("PENTEST_ALLOWLIST", "")

ENABLE_ACTIVE_SCANNING = (
    os.getenv("ENABLE_ACTIVE_SCANNING", "false").lower() == "true"
)

# -----------------------------
# Tool Defaults
# -----------------------------
MAX_CRAWL_DEPTH = 2

NUCLEI_SEVERITY = "low"

# -----------------------------
# Output Directories
# -----------------------------
REPORT_DIR = "reports"
LOG_DIR = "logs"
