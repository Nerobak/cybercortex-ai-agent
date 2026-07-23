# Tools

## File upload tools

- `upload_discovery`: offline upload surface discovery
- `upload_validation_analyzer`: observed type, MIME, size, and filename controls
- `upload_metadata_analyzer`: naming, path, disposition, and metadata observations
- `upload_storage_analyzer`: observation-only S3, Azure Blob, GCS, CDN, and local indicators
- `upload_security_planner`: eight bounded, non-executing manual plans
- `upload_replay_checker`: default-disabled, authenticated bounded replay

Use `upload explain` for complete metadata. `upload analyze <file>` and
`upload plan <file>` are offline. Replay accepts only explicitly confirmed,
researcher-owned benign files and remains an observation.

## Business logic tools

- `workflow_evidence_discovery`: offline candidate discovery from sanitized evidence
- `workflow_model_builder`: deterministic canonical workflow model
- `workflow_transition_analyzer`: ordering, state, actor, ownership, and replay observations
- `business_rule_analyzer`: deterministic field/rule observations and redacted comparison
- `business_logic_test_planner`: non-executing controlled verification plans
- `workflow_replay_checker`: default-disabled bounded authenticated GET/HEAD replay

Use `workflow explain` for complete registry metadata and safety limitations.

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
# GraphQL tools

- `graphql_endpoint_discovery`: offline, scope-validated endpoint confidence from gathered evidence; baseline/deep/authenticated.
- `graphql_query_analyzer`: offline query structure and sensitive-name observations; deep/authenticated.
- `graphql_schema_analyzer`: bounded offline schema planning observations; deep/authenticated.
- `graphql_introspection_checker`: one opt-in, bounded, scope-safe standard request; deep/authenticated.
- `graphql_authz_planner`: authenticated-profile manual planning for controlled accounts; never executes tests.

Use `explain <tool>` for complete inputs, evidence, limitations, false positives, relevance, examples, and safety notes.

# JWT tools

- `jwt_discovery`: offline JWT metadata discovery from existing evidence.
- `jwt_decoder`: size-bounded Base64URL decoding with sensitive-value redaction.
- `jwt_claims_analyzer`: deterministic header, registered/custom claim-name, and time observations.
- `jwt_comparison_analyzer`: controlled token comparison without raw values.
- `jwt_verification_planner`: safe manual plans with prerequisites and stop conditions.
- `jwt_replay_checker`: authenticated-only, disabled-by-default bounded replay.

The compatibility `jwt_security_analyzer` remains available. Prefer the modular
tools and `jwt analyze`, `jwt compare`, `jwt plan`, or `jwt explain`.
