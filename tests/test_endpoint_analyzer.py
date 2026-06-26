import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent import ask_agent
from tools.katana_crawl import katana_crawl
from tools.endpoint_analyzer import endpoint_analyzer

target = "https://nerminzlatanovic.com"
allowed_domain = "nerminzlatanovic.com"

crawl_result = katana_crawl(target, depth=2)

endpoint_result = endpoint_analyzer(
    crawl_result.get("urls", []),
    allowed_domain
)

print("[1] Endpoint Analyzer Result")
print(endpoint_result)

prompt = f"""
I own and administer this website: {target}

Analyze these endpoint findings.

Results:
{endpoint_result}

Tell me:
1. Which endpoints are most interesting
2. Why they matter
3. What safe manual checks I should do next
4. Which findings are likely only informational
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
