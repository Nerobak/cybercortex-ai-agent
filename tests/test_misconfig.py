import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from agent import ask_agent
from tools.katana_crawl import katana_crawl
from tools.misconfiguration_detector import misconfiguration_detector

target = "https://example.com"
allowed_domain = "example.com"

crawl_result = katana_crawl(target, depth=2)

misconfig_result = misconfiguration_detector(
    crawl_result.get("urls", []), allowed_domain
)

print("[1] Misconfiguration Result")
print(misconfig_result)

prompt = f"""
I own and administer this website: {target}

Analyze these possible misconfiguration findings.

Results:
{misconfig_result}

Tell me:
1. What looks misconfigured
2. Why it matters
3. Whether it is security risk or quality issue
4. What I should fix first
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
