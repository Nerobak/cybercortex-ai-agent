# File Upload Analysis Engine

CyberCortex v2.1 adds an offline-first, evidence-driven upload workflow without
changing the stable workflow manager, runner contract, finding schema, scope
guard, CLI framework, dashboard framework, or report pipeline.

## Evidence flow

Existing HTML forms, multipart request metadata, JavaScript observations,
endpoint evidence, workflow models, OpenAPI data, and GraphQL schema data flow
through:

1. `upload_discovery`
2. `upload_validation_analyzer`
3. `upload_metadata_analyzer`
4. `upload_storage_analyzer`
5. `upload_security_planner`

Normal scans send no upload request. Discovery and analyzers return observations
only. A client-side validation inconsistency may become a candidate requiring
manual verification, but absent evidence never means a server control is absent.
Storage indicators never establish exposure.

## Finding boundary

- Observation: upload endpoint, multipart encoding, Upload scalar, metadata, or
  storage-provider evidence.
- Candidate: an evidence-supported validation or ownership boundary that still
  requires controlled manual verification.
- Verified: only controlled runtime evidence proving unauthorized access,
  ownership failure, storage exposure, or authorization bypass.

The default engine does not produce verified upload findings.

## Manual planning

`upload plan <evidence.json>` creates non-executing plans for extension and MIME
validation, filename normalization, overwrite protection, upload/download
authorization, ownership, and metadata handling. Every plan requires explicit
authorization, controlled accounts/resources, and benign researcher-owned files.

## Optional replay

Replay requires `UPLOAD_REPLAY_ENABLED=true`, an authenticated workflow, an
in-scope URL, and explicit researcher-file and test-resource ownership
confirmations. It is limited to one file of at most 1 MiB from a small benign
allowlist. Executables, scripts, active content, archives, embedded archive
signatures, unknown types, polyglot indicators, oversized files, and third-party
files are blocked. Redirects are disabled. Results remain observations.

The CLI command is:

```text
upload replay verification_inputs/controlled-upload.json
```

Keep request files and benign samples out of version control. The dashboard,
normalized evidence, and reports expose aggregate upload counts and provider
indicators, never supplied filenames or file bodies.

## Limitations

Static evidence may be stale or unused. Client-side restrictions do not prove
server enforcement. Provider names do not prove a storage location or its access
policy. Content screening is a conservative gate, not malware detection; manual
review remains mandatory before opting into replay.
