import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from agent_core.llm_client import ask_agent
from tools.nuclei_scan import nuclei_scan

target = "https://nerminzlatanovic.com"

result = nuclei_scan(target, severity="low")

print("[1] Nuclei Scan Result")
print(result)

prompt = f"""
I own and administer this website: {target}

Analyze these Nuclei scan results.

Results:
{result}

Tell me:
1. What was found
2. Whether the findings are real security risks
3. What should be manually verified
4. What should be fixed first
"""

print("\n[2] DeepSeek Analysis")
print(ask_agent(prompt))
