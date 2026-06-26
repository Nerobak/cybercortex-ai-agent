import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent import ask_agent
from tools.dns_lookup import dns_lookup
from tools.http_probe import http_probe
from tools.tech_fingerprint import tech_fingerprint

domain = "example.com"
url = "https://example.com"

print("\n[1] DNS LOOKUP")
dns_result = dns_lookup(domain)
print(dns_result)

print("\n[2] HTTP PROBE")
http_result = http_probe(url)
print(http_result)

print("\n[3] TECH FINGERPRINT")
tech_result = tech_fingerprint(url)
print(tech_result)

prompt = f"""
You are my local cybersecurity AI agent.

I own and administer this website:
{url}

Analyze the following safe reconnaissance results and explain what they mean.

DNS result:
{dns_result}

HTTP probe result:
{http_result}

Technology fingerprint result:
{tech_result}

Give me:
1. Simple explanation
2. Security observations
3. Anything that looks misconfigured
4. Recommended next safe steps
"""

print("\n[4] DEEPSEEK ANALYSIS")
answer = ask_agent(prompt)
print(answer)
