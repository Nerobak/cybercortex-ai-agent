# CyberCortex Phase 2

Phase 2 is an evidence-driven research layer over the existing v2.1 discovery
pipeline. It does not treat an identifier, route name, schema field, successful
status, or response length as proof of a vulnerability.

## Loop

Observed evidence is normalized into one canonical attack surface. The
deterministic generator creates hypotheses, the priority engine weights evidence,
impact, verification safety, controlled context, request cost, risk, confidence,
and corroboration, and the planner emits category-specific minimum request plans.
Every planned request is independently checked by the deterministic policy gate.
Responses are reduced to secret-safe status, structure, selected-field,
ownership, error, state, and hash evidence before correlation produces
`verified`, `rejected`, or `inconclusive`.

## Canonical result status and reason contract

`agent_core.phase2_result_status` defines the only public status vocabulary for
new typed Phase 2 results. Terminal statuses are `verified`, `rejected`,
`inconclusive`, and `policy_blocked`. Recovery may also return the explicit
non-terminal states `awaiting_controlled_evidence` and
`verification_pending_cleanup`; neither is a vulnerability conclusion.

`verified` requires independently observed, category-specific positive
vulnerability evidence. `rejected` requires an active secure comparison and
the valid baseline required by that category. A denial without a valid owner,
privileged, authenticated, pre-termination, recovery, or rate-control baseline
is inconclusive. The shared instability predicate makes malformed responses,
unavailable or explicitly unstable service responses, and 5xx evidence
inconclusive; instability can never promote `verified` or `rejected`.

Every public typed result carries a deterministic, sanitized `reasons` list.
Policy, scope, method, controlled-account, credential, adapter/location,
state-change, cleanup-policy, rate-cap, and pre-traffic budget denials are
`policy_blocked`. A budget that cannot cover the required sequence before
traffic uses `Request budget is insufficient for the required verification
sequence.` If a sequence cannot finish after traffic has begun, the result is
`inconclusive` with `Verification could not complete within the approved
request budget.` An allowed transport attempt that fails is inconclusive with
one exception-independent safe reason. Required cleanup that cannot be
independently confirmed is inconclusive and retains its cleanup booleans; it is
never a verified or rejected conclusion.

`observe` generates hypotheses without active verification. `plan` also creates
plans. `verify` may execute only plans approved for explicit scope and controlled
context. Target classification as `local_range` or `dedicated_lab` is an explicit
operator input; ports and route names never infer lab status.

## Verification capability registry

`agent_core.verification_capabilities.CAPABILITY_REGISTRY` is the sole active
source of Phase 2 capability, executor binding, strict input schema, automatic
route availability, request bounds, cleanup/state burden, account requirements,
supported methods/parameter locations, and executor provenance version. The
quarantined `agent_core.verification_registry` remains disabled and is not this
registry.

`typed_verification` means the adaptive runtime has a real strict executor route
when all declared policy, context, input, target, and budget preconditions pass.
It does not mean a run is automatically authorized. `plan_only` means bounded
manual guidance may be generated, but there is no active typed route, no fake
network sequence, and no automatic execution. All currently emitted categories
are in one of those two states; none is called production-ready.

Request bounds use `RequestDelta` network semantics. Minimum means the complete
typed check with optional sessions/objects already available. Worst case includes
controlled login and owned-object acquisition where applicable, plus verification
and cleanup. Recovery is 1 request for challenge issuance, 3 for controlled
resume, and 1 for cleanup confirmation (5 across the full workflow). Bounded
login rate limiting is `N + 2`, with `1 <= N <= 5`, so its range is 3–7. SQL,
command, and traversal verification supports only GET query parameters in an
explicit `local_range` or `dedicated_lab`; the registry does not imply other
locations or adapters. Mass-assignment mutation is likewise limited to an
explicit local/dedicated lab and its test-owned restore workflow. “Auto” below
means an auto route exists under the stated preconditions, not that policy
approval can be skipped.

<!-- BEGIN GENERATED PHASE2 CAPABILITIES -->
| Category | State | Executor | Auto | Accounts | Credentials | Test-owned | State / cleanup | Requests | Methods | Locations |
|---|---|---|---:|---:|---:|---:|---|---:|---|---|
| `bola` | `typed_verification` | ControlledVerificationExecutor | yes | 2 | yes | yes | no / no | 2–5 | GET | path, query |
| `vertical_authorization` | `typed_verification` | ControlledVerificationExecutor | yes | 2 | yes | no | no / no | 2–4 | GET | none |
| `tenant_isolation` | `typed_verification` | ControlledVerificationExecutor | yes | 2 | yes | yes | no / no | 2–5 | GET | path, query |
| `mass_assignment` | `typed_verification` | ControlledVerificationExecutor | yes | 1 | yes | yes | yes / yes | 5–6 | GET, PATCH | json |
| `property_authorization` | `plan_only` | none | no | 2 | yes | yes | yes / yes | 0–0 | none | none |
| `authentication_enforcement` | `typed_verification` | ControlledVerificationExecutor | yes | 1 | yes | no | no / no | 2–3 | GET | none |
| `session_security` | `plan_only` | none | no | 1 | yes | no | no / no | 0–0 | none | none |
| `oauth_oidc` | `plan_only` | none | no | 1 | yes | no | no / no | 0–0 | none | none |
| `session_invalidation` | `typed_verification` | ControlledVerificationExecutor | yes | 1 | yes | no | yes / yes | 4–4 | GET, HEAD, OPTIONS, POST, DELETE | none |
| `recovery_state_enforcement` | `typed_verification` | ControlledVerificationExecutor | yes | 1 | yes | no | yes / yes | 1–5 | POST | none |
| `account_lifecycle` | `plan_only` | none | no | 1 | yes | no | no / no | 0–0 | none | none |
| `jwt_enforcement` | `plan_only` | none | no | 1 | yes | no | no / no | 0–0 | none | none |
| `graphql_mutation_authorization` | `plan_only` | none | no | 2 | yes | yes | yes / yes | 0–0 | none | none |
| `rate_limit_enforcement` | `typed_verification` | ControlledVerificationExecutor | yes | 1 | yes | no | yes / no | 3–7 | POST | none |
| `graphql_object_authorization` | `plan_only` | none | no | 2 | yes | yes | no / no | 0–0 | none | none |
| `graphql_field_authorization` | `plan_only` | none | no | 2 | yes | no | no / no | 0–0 | none | none |
| `business_logic` | `plan_only` | none | no | 1 | yes | yes | yes / yes | 0–0 | none | none |
| `business_logic_state_enforcement` | `plan_only` | none | no | 1 | yes | yes | yes / yes | 0–0 | none | none |
| `api_authorization` | `plan_only` | none | no | 2 | yes | yes | no / no | 0–0 | none | none |
| `graphql_authorization` | `plan_only` | none | no | 2 | yes | yes | no / no | 0–0 | none | none |
| `excessive_data_exposure` | `plan_only` | none | no | 0 | no | no | no / no | 0–0 | none | none |
| `ssrf` | `plan_only` | none | no | 0 | no | yes | no / no | 0–0 | none | none |
| `upload_ownership` | `plan_only` | none | no | 2 | yes | yes | yes / yes | 0–0 | none | none |
| `sql_injection` | `typed_verification` | ControlledVerificationExecutor | yes | 0 | no | no | no / no | 3–4 | GET | query |
| `command_injection` | `typed_verification` | ControlledVerificationExecutor | yes | 0 | no | no | no / no | 3–4 | GET | query |
| `path_traversal` | `typed_verification` | ControlledVerificationExecutor | yes | 0 | no | no | no / no | 3–4 | GET | query |
| `upload_security` | `plan_only` | none | no | 1 | yes | yes | yes / yes | 0–0 | none | none |
| `file_upload_validation` | `plan_only` | none | no | 1 | yes | yes | yes / yes | 0–0 | none | none |
| `injection` | `plan_only` | none | no | 0 | no | no | no / no | 0–0 | none | none |
| `cache_security` | `plan_only` | none | no | 2 | yes | no | no / no | 0–0 | none | none |
<!-- END GENERATED PHASE2 CAPABILITIES -->

## Shared verification runtime

Standalone verification and scan verification share one typed verification
runtime after hypothesis selection. Scan discovery remains scan-specific and its
traffic remains part of the whole-run ledger; it is not copied into the selected
result's request delta. From the selected hypothesis onward, both entry paths use
the same policy context, controlled context and vault, strict input staging,
`ScopedHTTPClient`, response adapter, controlled executor, recovery private-state
store, public serializer, request-delta helper, and immutable provenance contract.

The response adapter preserves the classifier-safe status/body shape,
content type, allowlisted Retry-After and rate-limit headers, coarse elapsed time,
and cookie security metadata. It never passes raw Authorization, Cookie, or
Set-Cookie credential material into public results. Every typed request clears
ambient session cookies; credentials are supplied only from controlled context
and the process-local vault. Redirect, timeout, header-stripping, scope, ledger,
per-host, rate, concurrency, and exception behavior therefore do not vary by CLI.

Both commands accept `--lab` for a local-range fixture and `--dedicated-lab` for
an explicitly dedicated target; the aliases become one internal target-class
value and are mutually exclusive. Top-level scan/discovery fields may differ,
but nested verification results are behaviorally comparable after ignoring
generated run/result identifiers and timestamps.

## Safety invariants

- The LLM may advise as researcher or critic but cannot authorize, execute, or
  classify evidence.
- Credential files must be explicitly selected. Their secrets move into the
  process-local vault and raw values never enter reports or stored runs.
- One canonical public serializer is applied at tool ingestion and again at
  run/latest persistence, CLI, campaign, benchmark/finding, Markdown, AI input,
  and diagnostic boundaries. It removes credentials embedded in structured
  fields, headers, cookies, URLs, exception text, and arbitrary strings while
  retaining typed counts, hashes, status/schema evidence, cookie security
  attributes, and allowlisted JWT structural metadata.
- Object comparisons require explicitly controlled accounts and test-owned
  objects. A missing object may be acquired only from an explicitly configured,
  authenticated own-resource collection for its controlled owner. Third-party
  ownership and arbitrary crawled identifiers are blocked.
- Delete, payment, transfer, withdrawal, privilege-change, denial-of-service,
  brute force, race flooding, uncontrolled command execution, executable upload,
  malware, polyglot, and bomb behavior is blocked.
- Injection and upload execution is limited to explicitly classified local or
  dedicated labs and inert fixed fixtures.
- The selected policy and one authoritative ledger exist before discovery.
  Every HTTP attempt passes exact target, scheme, port, method, exclusion,
  technique, global/per-host budget, rate, and concurrency checks before
  transport. Attempts consume the ledger even when transport fails; policy- or
  concurrency-blocked requests do not. Discovery, authentication, owned-object
  acquisition, verification, and cleanup share this ledger.
- DNS resolution is transport preparation rather than an HTTP ledger event. The
  authorized URL and unchanged hostname are validated before resolution;
  redirects, Host headers, and per-request proxy overrides cannot change the
  authorized target. DNS and HTTP transport share the concurrency bound.
- Registered subprocess/legacy network tools without a shared transport adapter
  fail closed in Phase 2. Capture campaigns are plan/offline-only, and external
  AI report calls use the deterministic offline fallback during policy-bound
  scans.
- Cross-account verification requires matching controlled object identity and
  concrete protected-data evidence. Equal 200 responses alone are inconclusive.
- Mass assignment requires a documented writable field, test-owned state,
  independent before/after evidence, unauthorized persistence, and successful
  cleanup.
- Recovery-state execution requires exactly one controlled account, a vaulted
  email-or-username identity and original password, and
  `cleanup_required=true`. Controlled recovery evidence is supplied only after
  CyberCortex issues and preserves the runtime challenge. It performs no
  guessing, candidate generation, retries, or account enumeration.

## Controlled account and login identity semantics

All 11 executable categories use the same account-eligibility contract. An
empty policy `controlled_account_ids` list means no additional account-ID
restriction beyond accounts explicitly declared with `controlled: true` in the
supplied `ControlledContext`. It never permits arbitrary or uncontrolled
accounts. A non-empty policy list is restrictive: an account is eligible only
when it is controlled in that context and its `account_id` is present in the
policy list. This eligibility decision does not replace exact per-category
runtime binding, ownership, role, tenant, credential, scope, cleanup, or request
budget requirements.

Controlled session acquisition supports only the explicit identity-field
semantics `email` and `username`. For an `email` login field, the resolver
prefers a live vaulted `email` reference and falls back to a live vaulted
`username` reference. For a `username` login field, it prefers a live vaulted
`username` reference and falls back to a live vaulted `email` reference. No
identity is derived, transformed, guessed, or enumerated. An unsupported field,
an absent identity, or a missing/discarded identity or password vault reference
is policy-blocked before transport and consumes zero requests. Public results
may report only the safe semantic source label (`email` or `username`), never the
identity value, password, vault handle, or session token.

## Bounded login rate-limit enforcement

The first rate-limit executor supports only
`authentication_login_rate_limit` on one semantically classified
`session_creation` login surface (or an explicitly login-classified credential
submission). Recovery rate-limit execution remains plan-only.

Execution is disabled unless the policy independently declares both:

```json
{
  "allow_bounded_rate_limit_verification": true,
  "max_rate_limit_attempts": 3
}
```

Generic POST permission and `allow_state_changes` do not authorize this check.
The implementation hard cap is five invalid attempts, and a request above that
cap is rejected rather than clamped. The effective ceiling is the smallest of
the supplied attempt count, policy maximum, hard cap, and remaining shared
request budget.

The exact verification input is:

```json
{
  "rate_limit": {
    "account_id": "alice",
    "mode": "authentication_login_rate_limit",
    "attempts": 3,
    "invalid_password": "<controlled synthetic wrong password>"
  },
  "expected_control": {
    "type": "throttle_or_block_within_attempts",
    "within_attempts": 3
  }
}
```

The wrong password moves immediately into the process-local credential vault.
It is used as supplied: the adapter derives, mutates, or generates no password
candidates. The executor reserves the whole sequence before sending traffic,
then performs one valid baseline login, exactly N sequential invalid-password
submissions for the same controlled synthetic account, and one final valid
login with the original vaulted password. Total requests are N + 2. There is no
spraying, concurrency, deliberate acceleration, hidden retry, username
comparison, or account enumeration.

Classification is made only against the declared bounded expectation. Explicit
429, Retry-After, rate-limit depletion, throttle error semantics, or lockout
semantics can establish secure enforcement. Repeatable, structured ordinary
credential failures plus a successful final valid login can establish that the
configured within-N control was absent. Bare or ambiguous 401 responses,
unstable service errors, timing alone, or unclear final-login behavior remain
inconclusive. Output contains status classes, whitelisted rate-limit metadata,
error categories, structure hashes, optional coarse latency buckets, booleans,
and request counts—never passwords, tokens, authorization headers, cookies, or
credential references.

## Request accounting

One authoritative `RequestBudget` enforces the whole scan and retains cumulative
run totals for discovery, authentication, verification, cleanup, and all network
requests. Each controlled result takes ledger snapshots immediately before and
after its execution and persists a strict `request_delta` containing only that
interval's `discovery`, `auth`, `verification`, `cleanup`, `attempted`, and
`total` counts. Global scan discovery and traffic from earlier results are not
copied into a finding.

The invariant is `total = discovery + auth + verification + cleanup`. The
transport consumes the ledger immediately before dispatch, so authorized
transport exceptions are attempts and `attempted = total`; requests blocked
before transport are zero. The compatibility field `requests_used` always
equals `request_delta.total` for new executable results. Local vault, parsing,
hashing, persistence, and report operations are not requests.

Mass-assignment restore and confirmation traffic is classified as cleanup.
Recovery issue, resume, and cleanup results each have their own delta; the final
original-password restoration confirmation is cleanup. A campaign may expose
the sum of linked recovery stages as `workflow_request_total`, which is distinct
from the selected result's `requests_used`. Historical results are not rewritten;
exports mark conservative legacy totals and never treat a cumulative budget
snapshot as a precise result delta.

## Controlled recovery-state enforcement

The first typed comparison mode is intentionally limited to
`reused_same_challenge_and_code`:

```json
{
  "recovery": {
    "account_id": "alice",
    "comparison_type": "reused_same_challenge_and_code"
  },
  "cleanup_required": true
}
```

Challenge issuance sends exactly one recovery-start request, preserves its
runtime `challenge_id` with run, hypothesis, account, and workflow bindings, and
returns `awaiting_controlled_evidence`. It does not accept or send a recovery
code or replacement password. Its public `challenge_reference` is a hash; the
identifier needed for deterministic resume stays in a separate private recovery
record and is absent from ordinary run JSON, `latest.json`, reports, campaigns,
exports, AI input, and CLI output. The private directory and record use local
`0700` and `0600` permissions where supported and contain no recovery code or
password value.

After the operator receives the legitimate code through the controlled
recovery channel, resume the same stored workflow:

```json
{
  "recovery": {
    "account_id": "alice",
    "comparison_type": "reused_same_challenge_and_code",
    "phase": "resume_with_controlled_evidence",
    "code": "<researcher-controlled secret>",
    "temporary_password": "<approved secret>",
    "comparison_password": "<separately approved secret>"
  },
  "cleanup_required": true
}
```

The three raw secret values move into the process-local credential vault as soon
as the resume input is loaded. CyberCortex does not issue another challenge. It
uses the preserved runtime challenge for one legitimate completion and exactly
one reuse comparison, then authenticates once with the comparison password. The
request plan accounts separately for one issuance verification request, two
resume verification requests, one resume authentication request, and one later
cleanup request.

The current controlled context has no typed in-band password-restoration
surface. Resume therefore returns `verification_pending_cleanup` and
`external_cleanup_required=true` after any possibly successful completion.
After a separate scoped restore, confirm cleanup with the same stored
hypothesis:

```json
{
  "recovery": {
    "account_id": "alice",
    "comparison_type": "reused_same_challenge_and_code",
    "phase": "confirm_external_cleanup"
  },
  "cleanup_required": true
}
```

Phase B sends one normal login with the original vaulted credential. Only a
successful restoration check promotes the stored evidence to final `verified`
or `rejected`; failure is `inconclusive` and sets `cleanup_failed=true`.
Neither phase invokes an
external reset script or accepts a user-supplied challenge ID.

Each public lifecycle transition is a new immutable result event. The challenge
issuance, pending-cleanup, and final events keep distinct `result_id` and
`result_hash` values; a later transition never edits an earlier public result.
Only the minimal private resume record is mutable/consumable, and it remains
outside public run revisions.

Each envelope is supplied through the existing
`verification run <hypothesis-id> --policy ... --context ... --input ...`
command. The command selects the latest public state for that hypothesis and the
controlled executor alone loads its bound private record; operators do not edit
challenge state or provide challenge IDs. Consumed records cannot be resumed a
second time.

## Controlled owned-object acquisition

The controlled context may include a secret-free `object_acquisition` list. Each
entry declares one controlled owner's authenticated own-resource collection and
the response fields needed to construct an in-memory `ControlledObject`:

```json
{
  "object_acquisition": [
    {
      "owner_account_id": "alice",
      "collection_url": "https://authorized.example/api/resources",
      "method": "GET",
      "object_type": "resource",
      "identifier_field": "resource_id",
      "tenant_field": "tenant_id",
      "max_items": 20
    }
  ]
}
```

Automatic acquisition permits only `GET` or `HEAD`, remains subject to normal
scope and method policy, examines at most 20 response items, and sends no BOLA
or tenant-isolation comparison when authentication, policy, transport, response
shape, or identifier extraction fails. Wrapped collections can declare the
optional `items_field`. Acquired identifiers remain process-local and are not
included in output; the result reports only whether controlled test-owned
evidence was established.

## Benchmark integrity

The exporter consumes only a completed CyberCortex run. It neither locates nor
reads benchmark ground truth, vulnerable application source, tests, or claimed
ground-truth identifiers. Exports contain normalized statuses and run metrics.

## Runs and campaigns

A **run** is one assessment execution. Its first immutable snapshot is stored as
`<run_id>.json`; later result/resume activity appends a complete immutable
`<run_id>.revision_<n>.json` snapshot. Existing results must remain an unchanged
prefix of every later revision. Identical saves are idempotent, conflicting
content under an existing result identity fails closed, and immutable files are
published atomically after the complete content has been flushed. `latest.json`
is only a replaceable convenience view of the newest saved revision and is not
authoritative provenance.

Every new persisted result has a random stable `res_<32 lowercase hex>`
`result_id`, `result_schema_version: 2`, explicit executor name/category version,
and a deterministic `sha256:` `result_hash`. The hash is computed from canonical
sorted-key, compact JSON after public sanitization and excludes only
`result_id`/`result_hash` to avoid recursion. It therefore covers the result's
hypothesis/category, classification, evidence, runtime/target binding,
`request_delta`, workflow stage, and executor contract without hashing private
recovery state or raw secrets. Finding references identify the exact support as
`run_id + result_id + result_hash + hypothesis_id`; result lookup verifies the
hash rather than searching for the latest matching hypothesis.

The public target is a sanitized URL. Separately, the run and campaign retain a
non-reversible `target_fingerprint` computed before redaction from the exact
normalized target. Normalization lower-cases scheme/host, removes default ports
and a root-only slash, sorts decoded query pairs before deterministic encoding,
and ignores fragments; query values and URL user-info remain part of the hash.
Thus equivalent target spellings compare equally while targets that differ only
by redacted secret values remain distinct. Campaign target equality uses this
fingerprint.

Legacy run/campaign files remain readable in place and are never automatically
rewritten. Results lacking immutable provenance are marked
`legacy_unversioned` by exports; no result ID, hash, executor identity, or target
fingerprint is fabricated for already persisted historical records.

A **campaign** is a cumulative authorized testing effort against one exact target.
New campaign manifests use schema version 2 and append-only campaign revisions.
Each ordered membership entry pins the exact immutable run revision, its
canonical public `run_snapshot_hash`, and the exact target fingerprint adopted
by the campaign. Campaign resolution loads that revision directly; it never
substitutes the run's latest revision. The campaign itself carries a stable
`campaign_id`, an incrementing `campaign_revision`, and a canonical public
`campaign_snapshot_hash`. Campaign, benchmark, finding, and technical export
provenance therefore continues to name the same immutable evidence until an
explicit campaign mutation is requested.

`campaign add-run` resolves the run's current immutable revision once and writes
a new campaign revision. Adding the same run twice is rejected rather than
silently refreshing its pin. `campaign refresh-run` is the explicit operation
that adopts the latest immutable revision for an existing member; it preserves
membership order and leaves every prior campaign revision addressable. Missing
or corrupt pinned revisions, run/campaign snapshot hash mismatches, target
fingerprint mismatches, and invalid stored result hashes fail closed before
export. Campaign manifests and hashes contain only canonical public data and
never include private recovery state.

Historical run-ID-only manifests remain readable without being rewritten or
given fabricated historical hashes. They are surfaced and exported as
`legacy_unpinned`; only this compatibility mode resolves current latest runs.
The first explicit `add-run` or `refresh-run` mutation creates a pinned v2
campaign revision while retaining the legacy base manifest as revision 0.

```text
python phase2_cli.py campaign create api-lab-phase2 --target http://127.0.0.1:8101
python phase2_cli.py scan http://127.0.0.1:8101 --mode plan --campaign api-lab-phase2
python phase2_cli.py campaign add-run api-lab-phase2 <run-id>
python phase2_cli.py campaign refresh-run api-lab-phase2 <run-id>
python phase2_cli.py campaign show api-lab-phase2
python phase2_cli.py campaign export api-lab-phase2 reports/api-lab-phase2.json
```

Normalized findings use three distinct structural concepts:

- `affected_functionality` is the operation whose security behavior is at issue.
- `verification_resource` is an optional resource used to establish or compare
  runtime evidence.
- `workflow` is an optional, secret-free structural sequence containing its
  semantic type, deterministic identity, and boundary surfaces.

For example, session-invalidation findings select their affected operation from
the `session_termination` boundary and retain the `authenticated_resource`
boundary as the verification resource. Methods and route templates come from
the observed workflow; exporters do not infer routes from narrative evidence.
Workflow export fields are optional, so non-workflow finding shapes remain
compatible with existing consumers. Only boundary type, method, route template,
and optional structural parameter are exported—headers, cookies, credentials,
tokens, passwords, and request bodies are excluded.

Campaign export deduplicates by category, affected-operation HTTP method,
normalized route template, and parameter/affected functionality. This keeps a
session-invalidation workflow distinct from authentication enforcement on its
protected verification resource. Status precedence is `verified > rejected >
inconclusive > discovered`. The highest-confidence evidence for the winning
status is retained, correlated sources are combined, finding counts are unique,
and request totals remain the sum of actual per-run activity. Mixed planning and
verification activity is reported as `plan+verify`. The existing `benchmark
export <path>` command remains a latest-single-run export and uses the same
affected-operation resolver as campaign export.
