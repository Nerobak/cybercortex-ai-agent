import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.safe_config_scan import safe_config_scan
from tools.report_writer import report_writer

target = "https://example.com"
allowed_domain = "example.com"

scan_results = safe_config_scan(target, allowed_domain)

report = report_writer(target=target, results=scan_results)

print(report)
