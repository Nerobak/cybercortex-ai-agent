# JWT Workflow

CyberCortex v2.1 adds JWT review as modular tools registered through the existing
tool registry. It does not change the stable workflow manager, finding schema,
scope guard, report pipeline, or dashboard framework.

## Evidence flow

Authorized captured or supplied evidence → `jwt_discovery` → `jwt_decoder` →
`jwt_claims_analyzer` → optional `jwt_comparison_analyzer` →
`jwt_verification_planner` → optional `jwt_replay_checker`.

Discovery accepts existing normalized headers, cookies, request metadata,
JavaScript strings, redacted evidence, or a controlled token. It returns only
source metadata, structural facts, and a 16-character SHA-256 fingerprint.
Malformed dotted strings are ignored. Discovery is always an observation.

Decoding is offline and size bounded. It decodes Base64URL header and payload
JSON but does not verify a signature without a trusted key. Signatures, raw
tokens, registered claim values, personal data, credentials, payment data, and
authorization values are never returned. Header names such as `kid`, `jku`,
`jwk`, and `x5u`, including `alg=none`, remain observations without runtime
impact evidence.

Claims analysis records registered-claim presence, custom authorization-related
claim names, and deterministic time states: expired, not yet valid, future
issued-at, long/short lived, missing expiration, clock-skew candidate, or valid
at analysis time. Missing expiration and long lifetime are not automatically
vulnerabilities.

Comparison accepts at least two explicitly controlled tokens. It returns only
safe differences in algorithms, claim names, issuer/audience presence or values,
lifetime windows, roles/scopes, subjects, tenants, and token-type indicators.
Differences do not prove authorization bypass.

Planning requires decoded or comparison evidence and always sets
`automatic_execution: false`. Plans require explicit authorization, controlled
accounts, test-owned resources, reversible steps, redacted evidence, expected
secure behavior, and stop conditions. Third-party access, token theft,
credential stuffing, brute force, payment/destructive actions, out-of-scope
bypass attempts, and replay of tokens not owned by the researcher are prohibited.

## Optional replay

Replay is disabled by default. When explicitly enabled, it requires an
authenticated profile, an in-scope endpoint, a user-supplied controlled token,
and GET/HEAD or a separately approved idempotent request. It does not mutate
tokens, strip signatures, generate `alg=none`, brute-force keys, inject `kid`,
manipulate `jku`/`x5u`, or follow redirects outside scope. Timeout and response
size are bounded. Authorization, cookies, and response cookies are redacted.
Acceptance alone is an observation.

## Commands

```text
jwt analyze
jwt analyze --file controlled.jwt
jwt compare account-a.jwt account-b.jwt
jwt plan controlled.jwt
jwt explain
jwt replay controlled-request.json
```

Omitting a token from `jwt analyze` uses a hidden prompt. Local input files must
be explicit and bounded. Do not place token files in source control.

## Configuration

- `JWT_REPLAY_ENABLED=false`
- `JWT_TIMEOUT_SECONDS=15`
- `JWT_MAX_RESPONSE_BYTES=1000000`
- `JWT_MAX_LIFETIME_SECONDS=86400`
- `JWT_CLOCK_SKEW_SECONDS=300`
- `JWT_MAX_TOKEN_BYTES=16384`

## Findings, reports, and limitations

Decoded metadata is classified as an observation. Candidate wording is reserved
for controlled evidence suggesting a policy may not be enforced. Verified
findings require controlled runtime proof of wrong audience/issuer acceptance,
expired or revoked token acceptance contrary to policy, token-type confusion,
role bypass, account isolation failure, or unauthorized access/state change.

Reports and the dashboard show only counts, sources, algorithms, claim presence,
time states, comparison counts, plan counts, signature-verification status, and
replay status. They never show tokens, signatures, full claims, Authorization
headers, or cookies. False positives include intentional public JWT metadata,
clock skew, optional claims, and expected access/refresh-token differences.
