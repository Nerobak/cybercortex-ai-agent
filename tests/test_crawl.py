
import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent import ask_agent
from tools.katana_crawl import katana_crawl
from tools.httpx_probe import httpx_probe

target = "https://nerminzlatanovic.com"

print("[1] Katana crawl")
crawl_result = katana_crawl(target, depth=2)
print(crawl_result)

print("\n[2] DeepSeek analysis")
prompt = f"""
I own and administer this website: {target}

Analyze these Katana crawl results.

Crawl result:
{crawl_result}

Tell me:
1. What URLs were discovered
2. Which endpoints look interesting
3. What could be tested safely next
4. What should not be tested without explicit scope
"""

print(ask_agent(prompt))
