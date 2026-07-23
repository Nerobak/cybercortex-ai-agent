# CyberCortex AI Agent v2.1.0-beta

## Highlights

- GraphQL Security Suite
- JWT Workflow Engine
- Business Logic Analysis Engine
- File Upload Analysis Engine

## Added

- Dependency-aware GraphQL, JWT, business-workflow, and file-upload analysis.
- Offline explain workflows, capability summaries, and controlled manual plans.
- Summary-only dashboard capability cards and release-readiness diagnostics.

## Changed

- Reports use one conservative Observation, Candidate, and Verified model.
- Capability sections and manual tests appear only when evidence supports them.
- Terminal, dashboard, prompt, and report summaries are bounded.
- The canonical version is now `2.1.0-beta`.

## Fixed

- Static assets and route names no longer imply functioning endpoints.
- Introspection, JWT metadata, response differences, client-side upload hints,
  and defense-in-depth headers remain observations without controlled impact.
- Optional inapplicable and disabled replay tools do not reduce coverage.
- Model failure still produces a deterministic report and sanitized evidence.

## Safety Improvements

- Replay remains disabled by default and requires explicit controlled input.
- Dashboard responses omit raw requests, tokens, cookies, schemas, filenames,
  payment information, verification codes, and personal information.
- Reports state what evidence proves, what it does not prove, and safe guidance.

## Testing

The release-candidate suite passes **140 tests**. The release gate also includes
Black, Ruff, compileall, and `git diff --check`.

## Known Limitations

- No engine automatically proves a vulnerability.
- Authenticated testing needs controlled accounts and test-owned resources.
- Optional binaries and the local model can reduce depth or trigger fallback.
- Automated analysis cannot replace manual scope and impact review.

## Migration from v2.0.0-beta

No stable-core redesign is required. Update dependencies, keep replay disabled
unless explicitly authorized, review allowlists, and run `doctor --quick`
followed by the full release quality gates.

## Future Roadmap

Continue conservative evidence ingestion, reporting clarity, performance
bounding, and regression hardening without automatic exploitation.
