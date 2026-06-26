import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent import ask_agent
from tools.security_headers_checker import security_headers_checker

target = "https://nerminzlatanovic.com"

result = security_headers_checker(target)

print("[1] Security Headers Result")
print(result)

prompt = f"""
I own and administer this website: {target}

Analyze these security header results.

Results:
{result}

Tell me:
1. Which security headers are present
2. Which are missing
3. Why each missing header matters
4. Recommended safe fixes for an AWS S3 + CloudFront static website
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
