# Tools

## CyberCortex AI Agent v2.0.0 Beta

Every registered tool declares its category, profiles, prerequisites, traffic behavior, input, evidence, limitations, false positives, verification guidance, relevance, example usage, and safety notes. Inspect those facts with `explain <tool>`, compare profiles with `explain profiles`, review workflow boundaries with `explain scan`, or summarize the current session with `explain latest`.

`doctor --quick` performs non-test readiness checks; `doctor` adds registry and compile checks. Neither command starts a live scan or prints secrets.

## Recon

- `dns_lookup.py` – resolves domain information
- `http_probe.py` – checks HTTP status, headers, server, and content type
- `katana_crawl.py` – crawls websites and discovers URLs
- `tech_fingerprint.py` – records observed technologies
- `endpoint_analyzer.py` – classifies discovered endpoint test ideas
- `api_object_discovery.py` – bounded discovery of exposed object references

## Analysis

- `security_headers_checker.py` – checks important HTTP security headers
- `misconfiguration_detector.py` – detects placeholder domains, test references, and development artifacts
- `js_secret_scanner.py` – scans static assets for secrets and suspicious references
- `parameter_analyzer.py` – identifies security-interesting parameters
- `authz_test_planner.py` – generates safe manual authorization test ideas

## Scanning

- `nuclei_scan.py` – runs approved Nuclei templates

## Reporting

- `ai_report_writer.py` – creates AI-generated Markdown reports
- `report_writer.py` – creates basic Markdown reports

## AI Commands

CyberCortex AI Agent supports interactive AI commands.

Examples:

ask What is CSP?

scan https://example.com
scan https://example.com --profile baseline
scan https://example.com --profile deep
jwt analyze
list tools

`list tools` reports availability, category, prerequisites, whether traffic is
sent, and profile applicability. `jwt_security_analyzer` is offline and runs
only with explicit JWT input. Request replay and authorization differential
tools likewise require authenticated researcher evidence and are not baseline
tools. An observed ID parameter is a candidate manual test, not verified IDOR.
