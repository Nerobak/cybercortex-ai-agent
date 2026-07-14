import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.authz_test_planner import authz_test_planner

sample_findings = [
    {
        "url": "https://example.com/api/user?id=123",
        "parameter": "id",
        "reason": "Possible IDOR / Access Control",
    },
    {
        "url": "https://example.com/login?next=/dashboard",
        "parameter": "next",
        "reason": "Open Redirect",
    },
    {
        "url": "https://example.com/download?file=report.pdf",
        "parameter": "file",
        "reason": "File Handling",
    },
]

result = authz_test_planner(sample_findings)

print(result)
