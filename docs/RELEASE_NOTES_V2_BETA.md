# CyberCortex AI Agent v2.0.0 Beta

## New capabilities

V2 adds scope-safe redirects, dependency-aware profiles, partial crawler evidence, normalized analyzers, local DeepSeek reporting with deterministic fallback, coverage, a localhost dashboard, deterministic `explain`, and release-readiness `doctor` commands.

## Architecture changes

The registry is the canonical capability catalogue. Tools emit failure-isolated envelopes; normalized evidence is bounded and redacted before reporting. Observations, candidates needing verification, and verified findings have explicit deterministic boundaries. The application version has one code source in `agent_core/version.py`.

## Fixed false positives

- Static assets such as `/assets/api-abc123.js` are not API routes.
- Public contact emails are informational, not potential secrets.
- Missing COOP, COEP, and CORP remain defense-in-depth observations.
- API route names remain observed routes without functioning endpoint evidence.
- Object discovery no longer sends unbounded classification rows to DeepSeek.

## Testing status

The release gate includes Black, Ruff, compileall, the full Pytest suite, and `git diff --check`. Final results are recorded in the release handoff.

## Known limitations

Automated results do not prove the absence of vulnerabilities. Authenticated authorization, JWT acceptance, GraphQL authorization, business logic, and uploads require explicit controlled context. Optional binaries and local Ollama/model availability affect coverage.

## Migration from v1

Review `.env` allowlists, install development dependencies, run `doctor --quick`, and use explicit profiles. Consumers should use normalized envelopes and the observation/candidate/verified statuses. Replace unbounded `path_segment_classifications` use with `classification_summary` and `sample_classifications`.

## Planned v2.1 work

- GraphQL suite
- JWT verification workflows
- Business-logic engine
- File-upload analysis
- Authenticated object-authorization workflows
