import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent import ask_agent
from tools.safe_config_scan import safe_config_scan

target = "https://nerminzlatanovic.com"
allowed_domain = "nerminzlatanovic.com"

result = safe_config_scan(target, allowed_domain)

print("[1] Safe Config Scan Result")
print(result)

prompt = f"""
I own and administer this website: {target}

Analyze this safe configuration scan.

Results:
{result}

Tell me:
1. What was checked
2. What issues were found
3. What is most important to fix first
4. What is informational only
5. Recommended next steps
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
