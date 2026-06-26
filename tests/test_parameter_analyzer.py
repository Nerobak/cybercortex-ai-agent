import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from tools.parameter_analyzer import parameter_analyzer

urls = [
    "https://example.com/api/user?id=123",
    "https://example.com/profile?email=test@test.com",
    "https://example.com/login?next=/dashboard",
    "https://example.com/download?file=report.pdf"
]

print(
    parameter_analyzer(urls)
)
