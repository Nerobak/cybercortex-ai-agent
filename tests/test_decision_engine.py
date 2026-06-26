import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from decision_engine import parse_plan, get_next_tool

sample_plan = """
1. dns_lookup
2. http_probe
3. security_headers_checker
4. katana_crawl
5. ai_report_writer
"""

steps = parse_plan(sample_plan)

print("[1] Parsed Steps")
print(steps)

completed = []

print("\n[2] Next Tool")
next_step = get_next_tool(steps, completed)
print(next_step)

completed.append(next_step["next_tool"])

print("\n[3] Next Tool After Completing First Step")
print(get_next_tool(steps, completed))
