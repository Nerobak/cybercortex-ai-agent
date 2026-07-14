import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.parameter_analyzer import parameter_analyzer
from tools.authz_test_planner import authz_test_planner

urls = [
    "https://example.com/api/user?id=123",
    "https://example.com/login?next=/dashboard",
    "https://example.com/download?file=report.pdf",
]

param_results = parameter_analyzer(urls)
planner_results = authz_test_planner(param_results["findings"])

print("[1] Parameter Analyzer")
print(param_results)

print("\n[2] Authz Test Planner")
print(planner_results)
