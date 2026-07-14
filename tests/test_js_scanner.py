import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from agent import ask_agent
from tools.katana_crawl import katana_crawl
from tools.js_secret_scanner import js_secret_scanner

target = "https://example.com"
allowed_domain = "example.com"

crawl_result = katana_crawl(target, depth=2)

scan_result = js_secret_scanner(crawl_result.get("urls", []), allowed_domain)

print("[1] JS Secret Scanner Result")
print(scan_result)

prompt = f"""
I own and administer this website: {target}

Analyze these JavaScript/static asset scan findings.

Results:
{scan_result}

Tell me:
1. What was found
2. Whether it looks sensitive
3. Likely false positives
4. What I should manually review
5. Recommended fixes
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
