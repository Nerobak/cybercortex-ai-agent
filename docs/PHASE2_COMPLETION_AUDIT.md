# FINAL FREEZE-READINESS AUDIT

Audit date: 2026-09-01

Repository: `cybercortex-ai-agent`

Verdict: **READY TO FREEZE**

Completion score: **97%**

Current backlog: **0 P0, 0 P1, 4 P2, 2 P3**

This is the current freeze decision. It supersedes, but does not remove, the
historical 88% re-audit and 68% original audit below. The audit was performed
against the working tree as found. No fixes, features, cleanup, deletions,
commits, pushes, benchmark scoring, or benchmark-ground-truth inspection were
performed. `cybercortex-range`, hidden answers, vulnerability IDs, and
vulnerable application source were not inspected or modified.

## Final verdict

Phase 2 can be frozen and tagged safely on the audited tree. All nine original
freeze blockers and all four re-audit blockers pass implementation and focused
regression review. Every mandatory zero-count safety criterion is zero, and all
requested quality gates pass on the final tree. The remaining four P2 and two
P3 items are hardening or maintainability debt with no active weaker public
Phase 2 route; they are explicitly safe to defer to Phase 3.

## 1. Original freeze blockers

| Blocker | Result | Implementation evidence | Regression-test evidence |
|---|---|---|---|
| P0-1 whole-scan policy/live ledger | **PASS** | `agent_core/workflow_manager.py` selects and authorizes one policy, then creates the authoritative `RequestBudget` and `ScopedHTTPClient` before `ToolRunner` discovery. The same client and ledger are bound to `VerificationRuntime` and used by acquisition, verification, and cleanup. `agent.py` creates a deferred-transport runtime and lets the workflow attach that exact transport. | `tests/test_phase2_network_policy.py` (17), `tests/test_phase2_scan_integration.py` (12), and the full 849-test suite pass. |
| P0-2 strict proof inputs/evidence predicates | **PASS** | `controlled_executor.py` uses strict, extra-forbidden proof schemas and exact probe bindings. `differential_analyzer.py` requires a valid owner/protected baseline and secure candidate evidence; `evidence_correlator.py` cannot promote without explicit verified analysis. Reflection, caller truthiness, unsupported locations, status-only proof, instability, and cleanup failure cannot verify. | `tests/test_p0_2_strict_proof_inputs.py` (36) and `tests/test_phase2_terminal_classification.py` (19) pass. |
| P0-3 sanitizer/private recovery state | **PASS** | `result_normalizer.public_result` is the recursive public boundary; private recovery fields and raw bodies are excluded and all strings are sanitized. Preserved recovery challenge state is stored separately from public immutable results. Hashing, storage, reports, exports, CLI, and agent output call the canonical boundary. | `tests/test_phase2_public_sanitizer.py` (37) passes, including persistence, reporting, CLI/agent, AI grounding, and private-state sentinels. |
| P1-1 canonical `RequestDelta` | **PASS** | Frozen strict `RequestDelta` validates nonnegative categorical totals. `ControlledVerificationExecutor` derives it from before/after snapshots of the authoritative ledger and always sets `requests_used == request_delta.total`; transport exceptions remain charged and pre-transport blocks do not. | `tests/test_request_delta_accounting.py` (15), the network-policy tests, and per-category execution tests pass. |
| P1-2 immutable run/result provenance | **PASS** | `result_provenance.py` supplies schema v2, target fingerprint, executor/version, UUID result ID, and canonical result hash. `phase2_store.py` appends revisions, locks prior-result prefixes, validates exact provenance, and supports exact revision/result lookup without historical overwrite. | `tests/test_result_provenance.py` (13), `tests/test_p1_ra1_plan_only_provenance.py` (41), and campaign pinning tests pass. |
| P1-3 CLI runtime parity | **PASS** | Both `phase2_cli.py` and `agent.py` construct `VerificationRuntime`; both use the shared policy-aware transport, context/vault semantics, ledger-derived accounting, provenance, sanitizer, and status normalization. | `tests/test_verification_runtime_parity.py` (29), malformed-envelope tests (28), plan-only tests (41), sanitizer tests, and scan integration tests pass. |
| P1-4 account/identity semantics | **PASS** | `auth_semantics.py` requires unique controlled-account membership, treats an empty policy allowlist as no additional restriction, supports only username/email identities, requires vault-backed credentials, and returns only public identity summaries. Runtime gates and transport revalidate the same semantics. | `tests/test_p1_4_account_identity_normalization.py` (76) and runtime-binding tests pass. |
| P1-5 capability/cost registry | **PASS** | `verification_capabilities.py` is the canonical registry and request-cost source. It exactly covers all emitted categories; typed entries require route/schema/version while plan-only entries prohibit execution metadata and nonzero request cost. Planner, priority engine, and orchestrator consume it. | `tests/test_p1_5_verification_capabilities.py` (23), hypothesis/planner tests, and plan-only provenance tests pass. |
| P1-6 terminal status/reason semantics | **PASS** | `phase2_result_status.py` owns typed terminal normalization and reason handling. Invalid input is `policy_blocked` before traffic; instability and cleanup failure demote verified/rejected outcomes. | `tests/test_phase2_terminal_classification.py` (19), strict-proof tests, and recovery/runtime parity tests pass. |

Original blockers passed: **9/9**.

## 2. Re-audit blockers

| Blocker | Result | Source evidence | Test evidence |
|---|---|---|---|
| P0-RA1 quoted/escaped structured secrets | **PASS** | `result_normalizer.py` recognizes bounded double-quoted, single-quoted, and escaped structured key/value pairs and routes their keys through the canonical secret-key predicate. Recursive sanitation applies at every public boundary. | `test_quoted_structured_secret_matrix`, multiple/nested quoted-secret tests, and public-boundary sentinel tests in `tests/test_phase2_public_sanitizer.py` pass. |
| P1-RA1 plan-only immutable provenance | **PASS** | `VerificationRuntime.execute_selected` capability-gates first and returns non-result plan metadata with `verification_result_created: false`; `phase2_cli.py` returns before persistence. `phase2_store.py` rejects unknown, fake, or plan-only typed producers. | `tests/test_p1_ra1_plan_only_provenance.py` passes all 41 tests. |
| P1-RA2 nested malformed verification input | **PASS** | `VerificationInputEnvelope` is strict, bounded, and extra-forbidden. Runtime staging and typed selection share `VerificationInputValidationError` handling and emit the canonical zero-request `policy_blocked` result. | `tests/test_p1_ra2_verification_input_envelope.py` passes all 28 tests, including nested and malformed-envelope parity. |
| P1-RA3 campaign run revision pinning | **PASS** | Schema-v2 `CampaignRunReference` pins run ID, exact revision, run snapshot hash, and target fingerprint. Resolution calls `load_revision`, validates snapshot/result hashes, and never consults latest. Only explicit refresh adopts a newer revision. | `tests/test_p1_ra3_campaign_pinning.py` passes all 15 tests. |

Re-audit blockers passed: **4/4**.

## 3. Public secret boundary

Focused quoted, escaped, nested, header, URL, model, exception, recovery-state,
and persistence sentinels were rerun. The canonical public serializer is used
at all requested surfaces:

| Surface | Boundary evidence |
|---|---|
| `public_result` | Recursive key filtering and string sanitation in `agent_core/result_normalizer.py`. |
| Immutable base/revision run files and `latest.json` | Payload and new-result preparation in `agent_core/phase2_store.py` use `public_result`. |
| Result hash basis | `_hashable_result` in `agent_core/result_provenance.py` hashes canonical public data. |
| Campaign manifests and campaign export | `agent_core/phase2_campaign.py` sanitizes before hashing and export. |
| Benchmark export | `agent_core/benchmark_exporter.py` sanitizes inputs and final output; no scoring was run. |
| Finding export | `agent_core/finding_export.py` uses the public result boundary. |
| Markdown reports | `agent_core/phase2_reporter.py` starts from public results. |
| AI grounding/evidence | `tools/ai_report_writer.py` normalizes result data before prompt grounding and evidence output. |
| `phase2_cli` public results | CLI output is passed through `public_result`. |
| `agent.py` public results | Scan return and rendered output boundaries use `public_result`. |

Quoted and escaped JSON-form secrets are covered by the focused sanitizer
regression matrix. Private recovery state remains separate from public result
history.

- Public secret leaks: **0**
- Sanitizer bypasses: **0**

## 4. Network safety

- Policy authorization occurs before construction of the first active network
  runner, and the authoritative ledger exists before discovery.
- Every registered active Phase 2 network tool is accounted for: 18 network
  capabilities use 6 shared-HTTP adapters, 1 shared-DNS adapter, 10 fail-closed
  adapters, and 1 offline fallback. No registered active bypass exists.
- `ScopedHTTPClient` authorizes before transport, enforces global and per-host
  budgets before the requester, rate-limits, and applies a concurrency
  semaphore. A transport exception occurs after budget consumption and is
  charged; policy/budget blocks occur before consumption and are not charged.
- OAST requires explicit policy authorization and cannot select an alternate
  transport path.
- Capture campaign execution remains `plan_only`, emits no findings/results,
  and uses zero requests even when legacy execute flags are supplied.

Network bypasses: **0**.

## 5. Proof and classification safety

The source and focused tests confirm no caller-truthiness proof route, no
reflection-only or status-code-only verified route, and no unsupported
parameter-location mutation. BOLA and tenant rejection require a valid owner
baseline. Metadata correlation cannot promote an inconclusive analyzer result.
Rejected results require secure evidence. Instability and cleanup failure
cannot produce verified/rejected, and malformed verification input becomes
zero-request `policy_blocked` before traffic.

Weak proof routes: **0**.

## 6. Request accounting

All 11 typed executors return the canonical `RequestDelta`, derived from the
shared ledger rather than executor estimates:

| Typed category | Canonical worst-case request cost |
|---|---:|
| Broken object level authorization | 2-5 |
| Broken function level authorization | 2-4 |
| Cross-tenant isolation failure | 2-5 |
| Mass assignment | 5-6 |
| Authentication enforcement | 2-3 |
| Session invalidation weakness | 4 |
| Account recovery state enforcement | 1-5 |
| Rate limit enforcement | 3-7 |
| SQL injection | 3-4 |
| Command injection | 3-4 |
| Path traversal | 3-4 |

Authentication, controlled acquisition, verification, cleanup, and transport
exceptions are categorized by the same transport ledger. Every typed result
satisfies `requests_used == request_delta.total`.

Request accounting inconsistencies: **0**.

## 7. Immutable result provenance

Typed results carry `result_id`, `result_hash`, executor name/version, result
schema version, and target fingerprint. Run revisions are append-only;
reconciliation rejects changed, removed, reordered, or rehashed historical
results. Recovery stages append rather than overwrite. Exact run revision and
exact result ID/hash lookup are supported. Registry validation rejects fake,
guessed, unknown, and plan-only provenance.

Immutable result provenance bypasses: **0**.

## 8. Campaign provenance

New schema-v2 campaigns pin exact run revision, run snapshot hash, target
fingerprint, and contained result hashes. Resolution never uses latest and
remains stable after later run revisions. Explicit refresh is the sole route to
adopt newer evidence and creates a new campaign revision, leaving prior
revisions addressable.

Legacy campaigns remain readable and are labeled `legacy_unpinned`; reads do
not silently rewrite them. A later explicit mutation can migrate the campaign
while retaining the legacy revision.

- New campaign latest-resolution paths: **0**
- Campaign integrity bypasses: **0**

## 9. Capability truth

The inventory was recalculated by importing the emitted-category set and the
canonical registry from the audited tree:

- Emitted categories: **30**
- Registry entries: **30**
- Typed categories: **11**
- Plan-only categories: **19**
- Missing, duplicate, or extra entries: **0**

Every typed category has a controlled route, strict input schema, schema
version, executor version, and canonical request cost. Plan-only categories
have no typed route and cannot create a typed immutable result. The hypothesis
engine enforces set equality, and planner, priority, and orchestrator decisions
consume the registry.

Capability registry drift: **0**.

## 10. CLI parity

The scan and standalone typed entry points share `VerificationRuntime`,
`VerificationHTTPTransport`, response metadata adaptation, the selected policy,
controlled context/vault, ledger-derived accounting, result provenance,
canonical sanitizer, and terminal status/reason normalization. Focused tests
also establish parity for plan-only categories, malformed envelopes, and
recovery intermediate state.

CLI verification bypasses/differences: **0**.

## 11. Terminal status vocabulary

Active typed results use only:

- Terminal: `verified`, `rejected`, `inconclusive`, `policy_blocked`
- Recovery intermediate: `awaiting_controlled_evidence`,
  `verification_pending_cleanup`

Other status strings found by source search belong to discovery/tool command
envelopes or quarantined legacy types, not active typed result persistence.

Undocumented terminal statuses: **0**.

## 12. Legacy and quarantined paths

- `verification_registry.py` declares legacy offline-only execution, disables
  active execution, and has no active adapter registrations.
- Capture campaign execution is plan/offline-only and cannot persist a typed
  verification result.
- `hardened_executor.py` refuses registered network tools in a subprocess when
  the shared policy client/ledger cannot cross the process boundary; only the
  declared offline fallback is permitted.
- Legacy verification helpers and the old verification CLI are not imported by
  either active Phase 2 typed entry path.
- Legacy campaigns are explicitly `legacy_unpinned`; legacy runs remain
  readable but cannot weaken schema-v2 creation, provenance, or pinning rules.

No inspected compatibility surface silently becomes an active weaker Phase 2
verification path.

## 13. Full test and quality gates

All commands were run on the exact final code tree with caches redirected to a
temporary directory so the repository was not changed:

| Gate | Result |
|---|---|
| `black --check .` | **PASS** — 198 files would be left unchanged |
| `ruff check .` | **PASS** |
| `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py campaign_cli.py` | **PASS** |
| `python -m pytest -q` | **PASS** — 849 passed |
| `git diff --check` | **PASS** |
| `git status --short --untracked-files=all` | **RUN** — pre-existing dirty tree recorded; no cleanup performed |

The first sandboxed pytest attempt passed 845 tests and encountered four local
loopback bind `PermissionError`s. The exact unchanged suite was rerun with
loopback binding permitted and passed all 849 tests. This was an environment
permission issue, not a product failure.

Quality gates: **PASS**.

## 14. Test inventory

Total passed tests: **849**.

The combined focused freeze suite passed **361** tests:

| Focus | Focused tests |
|---|---:|
| Network policy/live ledger | 17 |
| Strict proof | 36 |
| Sanitizer/private recovery, including quoted regression | 37 |
| Request delta | 15 |
| Immutable result provenance | 13 |
| CLI/runtime parity | 29 |
| Account/identity | 76 |
| Capability registry | 23 |
| Terminal statuses | 19 |
| Scan/public integration | 12 |
| Plan-only provenance | 41 |
| Malformed envelope | 28 |
| Campaign pinning | 15 |

## 15. P2/P3 review

No remaining P2/P3 item is reclassified as P0/P1.

| Item | Safe to defer to Phase 3? | Reason |
|---|---|---|
| P2-RA1 compare explicit recovery `parent_run` target before accepting it | **YES** | Public callers construct a self-consistent parent and target, and immutable save validation still enforces target provenance. This is defense-in-depth for direct internal API misuse, not an observed public bypass. |
| P2-RA2 parameterize a real execution-flow ledger invariant across all 11 categories | **YES** | Every category has direct execution coverage, and the shared `RequestDelta` plus transport-ledger tests enforce the invariant. The missing single matrix test is coverage consolidation. |
| P2-RA3 rename/isolate legacy verification, capture, and subprocess surfaces | **YES** | Imports and capability registrations keep them out of active typed execution; the issue is discoverability and maintenance risk, not a live weaker route. |
| P2-RA4 make private preserved-recovery-state write and public run validation transactional | **YES** | A later public validation error may leave a private resumability record, but it cannot create, overwrite, leak, or validate a public immutable result. This is private-state transaction hardening. |
| P3-1 remove redundant service-instability stop-condition wording across planning layers | **YES** | It is harmless planner-output duplication and has no execution or classification effect. |
| P3-2 split legacy `HypothesisStatus` values such as `needs_manual_verification` and `cleanup_failed` from terminal result types | **YES** | Those values are not accepted as active typed terminal results; the separation is type clarity and maintenance work. |

P2/P3 safe to defer: **YES**.

## 16. Final completion score

The original weighted rubric is retained. The score is not automatically 100%;
the intentional plan-only breadth and remaining Phase 3 hardening are reflected
below.

| Area | Weight | Earned | Basis |
|---|---:|---:|---|
| A. Discovery/hypothesis architecture | 15% | 15% | Complete emitted-category and hypothesis architecture with exact registry coverage. |
| B. Verification planning | 10% | 10% | Policy-aware plans, explicit stop conditions, and truthful plan-only handling. |
| C. Typed controlled execution | 20% | 19% | Eleven controlled typed routes pass; one point retained for legacy-surface isolation hardening. |
| D. Policy/safety enforcement | 15% | 15% | One pre-traffic policy boundary, shared live ledger, budgets, rate/concurrency, and fail-closed adapters. |
| E. Evidence/classification quality | 15% | 15% | Strict proof, secure rejection, instability/cleanup demotion, and canonical malformed-input handling. |
| F. Secret handling/controlled context | 10% | 9% | Zero public leaks/bypasses; one point retained for private-state transaction ordering hardening. |
| G. Run/campaign/provenance | 5% | 5% | Immutable result history, exact lookup, and schema-v2 campaign pinning/integrity. |
| H. Request accounting/metrics | 5% | 5% | Shared-ledger deltas and exact totals across all typed categories. |
| I. Tests/CLI/documentation | 5% | 4% | 849 passing tests and full CLI parity; one point retained for the consolidated executor matrix and legacy type cleanup. |
| **Total** | **100%** | **97%** | **Freeze-ready with explicitly deferred P2/P3 debt.** |

## 17. Freeze criteria

| Criterion | Result |
|---|---:|
| P0 | 0 |
| P1 | 0 |
| Network bypasses | 0 |
| Weak proof routes | 0 |
| Public secret leaks | 0 |
| Sanitizer bypasses | 0 |
| Request accounting inconsistencies | 0 |
| Immutable result provenance bypasses | 0 |
| Campaign integrity bypasses | 0 |
| New campaign latest-resolution paths | 0 |
| CLI verification differences | 0 |
| Account/identity semantic bypasses | 0 |
| Capability registry drift | 0 |
| Undocumented terminal statuses | 0 |
| All quality gates | PASS |

**Ready to freeze: YES.**

## 18. Audit change boundary

Only `docs/PHASE2_COMPLETION_AUDIT.md` was changed by this audit. The repository
was already substantially dirty, including this document as an untracked file;
all pre-existing tracked and untracked work was preserved. Files deleted: **0**.

---

# Phase 2 Completion Audit — Post-P0/P1 Re-Audit

Audit date: 2026-08-31

Repository: `cybercortex-ai-agent`

Branch/commit inspected: `release/v2.1.0-beta-rc` / `973ed9f6ec45997b7cdf952f4be1361ec7cfc102`

Verdict: **NOT READY TO FREEZE**

Completion score: **88%**

Fresh backlog: **1 P0, 3 P1, 4 P2, 2 P3**

## 1. Architecture verdict

This is a fresh implementation-level reassessment after P0-1 through P1-6. It does not accept earlier closure claims merely because they appear in documentation. The audit traced the current scan and standalone verification paths, inspected typed executors and their analyzers, exercised persistence and public-output boundaries with new synthetic sentinels, recalculated the capability inventory from code, collected the tests, and ran every requested quality gate.

This audit did not inspect or modify `cybercortex-range`, benchmark ground truth, vulnerability IDs, vulnerable application source, hidden tests, expected answers, or benchmark solutions. No benchmark result was used to score the architecture.

The main Phase 2 execution architecture is materially stronger than at the original audit:

- The active scan constructs the selected `AssessmentPolicy`, one `RequestBudget`, and one `ScopedHTTPClient` before discovery traffic. Discovery, controlled login/acquisition, verification, and cleanup share that ledger and client.
- All 11 typed categories route through `VerificationRuntime` and `ControlledVerificationExecutor`. Their proof-controlling input models are strict, their request deltas come from ledger snapshots, and their public statuses pass through `normalize_typed_result`.
- The capability registry covers all emitted categories exactly: 30 emitted, 11 `typed_verification`, 19 `plan_only`, and 0 `discovery_only`.
- Account eligibility and controlled login identity semantics are centralized. The empty policy account allowlist means no additional restriction beyond controlled accounts in `ControlledContext`.
- Public result history is append-only by run revision and individual typed results have IDs, hashes, executor versions, and exact lookup support.

The repository is nevertheless not ready to freeze. A fresh quoted-JSON sentinel bypasses the canonical text sanitizer and persists through multiple public boundaries. Three additional release-boundary inconsistencies remain: the standalone command persists plan-only categories as typed-looking immutable verification results, nested structured verification-input validation can escape the shared result contract, and campaigns resolve mutable latest run revisions rather than pinning the revision/results present when a run was added.

These are not requests for new categories, payloads, or broader execution. They are completion defects in already-declared safety, capability, parity, and provenance contracts.

## 2. Discovery and hypothesis inventory

### 2.1 Fresh count from code

`agent_core/hypothesis_engine.py` currently defines 30 emitted categories in `CATEGORY_PRIORITY`. Import-time code requires its set to equal the keys of the immutable `CAPABILITY_REGISTRY`; the registry also rejects duplicate entries.

| Capability state | Count |
|---|---:|
| `typed_verification` | 11 |
| `plan_only` | 19 |
| `discovery_only` | 0 |
| **Total emitted** | **30** |

The current emitted set is:

```text
account_lifecycle
api_authorization
authentication_enforcement
bola
business_logic
business_logic_state_enforcement
cache_security
command_injection
excessive_data_exposure
file_upload_validation
graphql_authorization
graphql_field_authorization
graphql_mutation_authorization
graphql_object_authorization
injection
jwt_enforcement
mass_assignment
oauth_oidc
path_traversal
property_authorization
rate_limit_enforcement
recovery_state_enforcement
session_invalidation
session_security
sql_injection
ssrf
tenant_isolation
upload_ownership
upload_security
vertical_authorization
```

### 2.2 Plan-only inventory

The 19 plan-only categories are `account_lifecycle`, `api_authorization`, `business_logic`, `business_logic_state_enforcement`, `cache_security`, `excessive_data_exposure`, `file_upload_validation`, `graphql_authorization`, `graphql_field_authorization`, `graphql_mutation_authorization`, `graphql_object_authorization`, `injection`, `jwt_enforcement`, `oauth_oidc`, `property_authorization`, `session_security`, `ssrf`, `upload_ownership`, and `upload_security`.

For each, the registry declares no executor reference, no verification input schema, zero executable request cost, and `automatic_execution=false`. Planner fallback steps are local/manual guidance with no fake request sequence. The adaptive scan checks the registry before executor routing and skips these categories.

Fresh exception: `VerificationRuntime.execute_selected` returns a zero-traffic `inconclusive` object for a plan-only category, and `phase2_cli.py verification run` appends it to `verification_results`. `Phase2RunStore` then supplies `ControlledVerificationExecutor` and `<category>/v1` provenance by default. This creates typed-looking evidence for a category whose authoritative registry says no typed route exists. See P1-RA1.

## 3. Current typed executor inventory

All rows use public executor name `ControlledVerificationExecutor`; all are automatically routable only after the registry, method/location, policy, context, credential, account, object, target-class, and budget preconditions pass.

| Category | Strict input / executor version | Policy and context requirements | Requests min–worst | State / cleanup | Evidence and maturity |
|---|---|---|---:|---|---|
| `bola` | `BOLAVerificationInput`; `bola/v1` | Two distinct eligible controlled accounts, controlled credentials/sessions, exact owner-bound test object, `GET`, path/query binding | 2–5 | Read-only / none | Valid owner protected baseline; matching protected evidence under comparator verifies, comparator denial after the valid baseline rejects. Mature bounded typed differential. |
| `tenant_isolation` | `TenantIsolationVerificationInput`; `tenant_isolation/v1` | BOLA requirements plus two distinct tenant IDs and exact object/tenant consistency | 2–5 | Read-only / none | Exact owner/tenant protected baseline and cross-tenant comparison. Mature bounded typed differential. |
| `vertical_authorization` | `VerticalAuthorizationVerificationInput`; `vertical_authorization/v1` | Two distinct eligible controlled accounts with recognized, distinct role ranks; `GET` | 2–4 | Read-only / none | Privileged protected baseline plus lower-role comparison. Mature bounded role differential. |
| `mass_assignment` | `MassAssignmentVerificationInput`; `mass_assignment/v1` | One eligible account, exact owned object, credentials, state-change permission, mandatory cleanup, local/dedicated lab, exact JSON field | 5–6 | State-changing / mandatory independent restore | GET/PATCH/GET/PATCH/GET workflow; positive persistence and independently verified restoration required. Mature narrow typed workflow. |
| `authentication_enforcement` | `AuthenticationEnforcementVerificationInput`; `authentication_enforcement/v1` | One eligible account and controlled session/credentials; `GET` | 2–3 | Read-only / none | Authenticated protected baseline plus credential-free anonymous comparison. Mature bounded differential. |
| `session_invalidation` | `SessionInvalidationVerificationInput`; `session_invalidation/v1` | Exactly one eligible controlled account, configured acquisition and termination semantics, credentials, state-change permission | 4–4 | State-changing / session termination is the controlled cleanup contract | Acquire, valid baseline, terminate, replay the same issued session. Denied replay rejects; matching protected evidence verifies. Mature narrow workflow. |
| `recovery_state_enforcement` | `RecoveryVerificationInput`; `recovery_state_enforcement/v1` | Exactly one eligible account, original password, live controlled identity, bound challenge/code, private resume state, state-change and cleanup policy | 1–5 | State-changing / mandatory confirmed cleanup | Explicit challenge, resume, independent auth, and external cleanup-confirmation stages. Mature multi-stage workflow with 1/3/1 per-stage deltas. |
| `rate_limit_enforcement` | `RateLimitVerificationInput`; `rate_limit_enforcement/v1` | Exactly one eligible account, original valid password, one supplied invalid password, explicit bounded-rate opt-in, sequential N capped at 5 | 3–7 | Account-state affecting / final valid-login control, no separate cleanup request | One valid baseline, N invalid attempts, one final valid login; total N+2. Concrete throttle/lockout rejects; controlled absence can verify. Mature bounded workflow. |
| `sql_injection` | `SQLInjectionVerificationInput`; `sql_injection/v1` | Dedicated/local lab, exact `GET` query parameter, optional controlled login, three stable probes | 3–4 | Read-only intended / none | Current harmless differential cannot independently prove SQL evaluation, so it remains inconclusive. Typed and safely conservative, not positive-proof capable. |
| `command_injection` | `CommandInjectionVerificationInput`; `command_injection/v1` | Dedicated/local lab, exact `GET` query parameter, optional controlled login, three stable probes | 3–4 | Read-only intended / none | Stable control/probe/repeated control plus a non-reflected server-derived marker. Narrow typed proof. |
| `path_traversal` | `PathTraversalVerificationInput`; `path_traversal/v1` | Dedicated/local lab, exact `GET` query parameter, optional controlled login, controlled fixture marker | 3–4 | Read-only / none | Stable controls plus a non-reflected fixture-resolution marker. Narrow typed proof. |

The schemas resolve to strict `StrictModel` subclasses with extra fields forbidden. Registry executor versions equal the P1-2 provenance versions. Unsupported methods, target classes, and parameter locations are blocked before traffic. SQL, command, and traversal advertise query-only support and are not expanded by this audit.

## 4. Policy and whole-scan safety

### 4.1 P0-1 reassessment: complete

- `agent.py` loads the explicit or runtime-derived policy and controlled context before calling `run_workflow` and before constructing a verification runtime.
- `run_workflow` authorizes the target, creates the authoritative `RequestBudget`, and constructs `ScopedHTTPClient` before `ToolRunner.run` begins discovery.
- The same policy object, budget object, and client object are injected into discovery and typed verification. `ToolRunner` checks identity consistency rather than creating a later client.
- Ledger consumption happens immediately before an allowed transport attempt. Scope, authorization, method, purpose, OAST, typed session/rate metadata, budget, per-host budget, rate, and concurrency checks happen before the requester.
- A transport exception consumes exactly one categorized request. A policy or budget denial before transport consumes zero.
- `max_concurrency` is enforced by the shared client; the regression fixture with a limit of one blocks an overlapping request without consuming the ledger.
- Registered network tools are either adapted to the shared HTTP/DNS runtime, declared offline, or fail closed. The registered-tool invariant has no active unadapted network entry.
- Capture campaign execution remains explicitly `plan_only` and returns zero requests. It does not reactivate capture execution.

Fresh active Phase 2 network bypasses found: **0**.

The old raw verification/capture utilities still exist outside the current Phase 2 route and retain older vocabularies and direct-request helpers. They are not imported by the active typed runtime. Their continued product-level presence is P2 quarantine debt, not an active Phase 2 network bypass in this audit.

## 5. Controlled context and credential vault

### 5.1 P1-4 reassessment: complete

`AssessmentPolicy.account_is_eligible` is the canonical account-decision helper. Eligibility requires the account to be explicitly controlled in the supplied context and, only when the policy list is non-empty, present in the policy list. An empty policy list therefore adds no restriction beyond `ControlledContext`; it never admits an uncontrolled or arbitrary account.

Runtime binding and typed policy actions consult this helper. The 11-category matrix checks empty/explicit lists and controlled/uncontrolled accounts, while BOLA, tenant, and vertical tests preserve their exact two-account semantics.

`resolve_controlled_login_identity` is the canonical vault-aware identity resolver. Supported semantic fields are `email` and `username`:

- `email`: prefer live vaulted email, then live vaulted username.
- `username`: prefer live vaulted username, then live vaulted email.
- any other declared field: deterministic preflight block.

Configured references must still exist in `CredentialVault`; missing or discarded identity/password references fail closed before traffic. The result exposes only `identity_bound` and the safe source label. Recovery, rate, ordinary session acquisition, session invalidation, authorization paths, and optional injection login all use this resolver. Email-only and username-only session-invalidation acquisition both pass.

Account/identity semantic bypasses found: **0**.

## 6. Request accounting

### 6.1 P1-1 reassessment: complete

Every typed execution enters `ControlledVerificationExecutor.execute`, snapshots the authoritative ledger before and after `_execute_once`, constructs strict immutable `RequestDelta`, and sets `requests_used=delta.total`. The model enforces non-negative strict integers, categorized sum equals total, and attempted equals total.

| Category | Declared bound | Observed/code-derived components | Audit result |
|---|---:|---|---|
| BOLA | 2–5 | 2 comparisons; optional 2 logins + 1 object acquisition | Consistent |
| Tenant | 2–5 | 2 comparisons; optional 2 logins + 1 object acquisition | Consistent |
| Vertical | 2–4 | 2 comparisons; optional 2 logins | Consistent |
| Mass assignment | 5–6 | 5 workflow requests; optional 1 login | Consistent |
| Authentication | 2–3 | authenticated/anonymous pair; optional 1 login | Consistent |
| Session invalidation | 4–4 | acquire + baseline + terminate + same-session replay | Consistent |
| Recovery | 1–5 | challenge 1; resume 3; cleanup confirmation 1 | Consistent and stage/workflow totals are distinct |
| Rate limiting | 3–7 | baseline 1 + N (1..5) + final 1 | Consistent; formula N+2 |
| SQL | 3–4 | control/probe/control; optional 1 login | Consistent |
| Command | 3–4 | control/probe/control; optional 1 login | Consistent |
| Traversal | 3–4 | control/probe/control; optional 1 login | Consistent |

Authentication and object acquisition are categorized as auth/discovery, cleanup attempts remain counted, and failed transports remain attempts. Campaign and benchmark consumers call `canonical_result_request_total` and prefer the stored delta. Recovery campaign export can show both selected-stage requests and cumulative workflow requests.

Fresh request-accounting inconsistencies found: **0**.

Coverage caveat: the registry-wide “never exceeds worst case” test consumes the declared number synthetically, so it proves enforcement of the upper-bound guard rather than independently deriving each executor's real worst case. Real-flow category fixtures cover the individual sequences, but a single registry-to-real-fixture invariant is still missing (P2-RA2).

## 7. Evidence and classification

### 7.1 P0-2 reassessment: complete

- All 11 typed categories resolve strict proof-controlling schemas. Malformed category input is blocked with zero traffic once it reaches the executor.
- Runtime-controlled account, object, tenant, role, and ownership facts replace legacy caller assertions.
- Proof booleans are strict; analyzer calls use explicit `is True` checks.
- BOLA and tenant rejection require a valid protected owner baseline. Vertical, authentication, and session rejection likewise require their category-specific valid baselines.
- Command and traversal reflection-only probes are inconclusive. SQL's current harmless differential never independently verifies SQL injection.
- Exact parameter name and location are checked against both the hypothesis and planned requests. Unsupported locations block before traffic.
- `verification_registry.py` declares active execution disabled and contains no adapters. `verification_gate.grade_verification` is not called by the active Phase 2 typed path.

Fresh active weak-proof routes found: **0**.

### 7.2 P1-6 reassessment: active typed contract complete

The public typed status vocabulary is:

```text
verified
rejected
inconclusive
policy_blocked
```

Non-terminal recovery states are:

```text
awaiting_controlled_evidence
verification_pending_cleanup
```

`normalize_typed_result` provides one boundary for all 11 executors. Before-traffic budget denial becomes `policy_blocked`; partial budget exhaustion becomes `inconclusive`. Transport failures use one safe deterministic reason. Shared service instability prevents verified/rejected. Required cleanup uncertainty becomes inconclusive. Undocumented executor sentinels such as `budget_exhausted` and `cleanup_failed` remain internal and are translated before persistence.

No active typed executor emits `error`, `failed`, `unknown`, `manual_required`, `budget_blocked`, or `budget_exhausted` as a terminal public result. Remaining source occurrences are internal executor sentinels, non-terminal tool/subprocess envelopes, discovery/manual classifications, CLI error fields, or quarantined legacy code.

One runtime failure-contract gap remains outside category schema validation: malformed nested `defaults`/`hypotheses` selection can throw before `ControlledVerificationExecutor.execute` and therefore produces no canonical status/reasons. See P1-RA2.

## 8. Secret handling and public boundaries

### 8.1 P0-3 reassessment: incomplete

The repository consistently calls `public_result` at the run store, result hash, campaign, benchmark, report, workflow, and CLI boundaries. Structured secret keys, header-style authorization/cookie strings, URL query secrets, JWT values, and private recovery keys are removed; numeric/JWT/cookie telemetry survives. Private recovery state is stored under restrictive permissions outside public run payloads and supports staged resume.

However, the canonical text regex expects a secret key immediately adjacent to `:` or `=`. A quoted JSON key has a closing quote between the key and colon, so strings such as `body={"access_token":"<sentinel>"}` and `body={"password":"<sentinel>"}` survive `sanitize_text`.

A fresh synthetic sentinel produced this boundary matrix:

| Boundary | Sentinel present? |
|---|---|
| `public_result` diagnostic string | Yes |
| immutable run revision | Yes |
| `latest.json` | Yes |
| result content hashed under `result_hash` | Yes |
| campaign/finding export | Yes |
| CLI-shaped public verification output | Yes |
| AI sanitized input and evidence file | Yes |
| benchmark export fixture | No |
| rendered Phase 2 report fixture | No |
| rendered deterministic AI report fixture | No |

Because the value reaches durable/public records and AI evidence input, this is P0-RA1. Existing sanitizer tests cover header syntax, URLs, structured keys, and unquoted assignment syntax, but not quoted JSON fragments embedded inside arbitrary strings.

Fresh public secret-leak classes found: **1**.

## 9. Run, campaign, and provenance

### 9.1 What passes

- The first run snapshot is immutable; changed content creates `.revision_<n>.json`. Identical saves are idempotent.
- Previously persisted results must remain an identical ordered prefix. A conflicting result ID or changed hash/content fails without replacing prior immutable records.
- New results have stable random `result_id`, deterministic content-sensitive `result_hash`, schema version, target surface, and executor provenance.
- Same-hypothesis retries/stages receive distinct result IDs. Exact result lookup requires a unique ID and can require the expected hash.
- Recovery's public stages append; private state does not enter the public result.
- Campaign and benchmark findings contain exact result references once a result has been selected.
- Target fingerprints use the exact normalized target, including secret-bearing identity components that are redacted from the public target. Campaign target comparison is fingerprint-based for versioned runs.
- Legacy runs remain readable without fabricated historical IDs/hashes.

### 9.2 Fresh provenance failures

1. **Campaigns are not snapshot-stable.** `Phase2CampaignStore` persists only `run_ids`, and `resolve` always calls `load_run`, which returns the latest revision. In a fresh reproduction, the unchanged campaign manifest first exported an `inconclusive` result, then exported a later `verified` result with a different `result_id` after the run received a new revision. Old exported references remain resolvable, but the campaign's current meaning changes without a campaign revision or pinned result/run reference. This is P1-RA3.
2. **The new-result store fabricates provenance when the producer omits it.** `_prepare_new_result` defaults every new result to `ControlledVerificationExecutor` and `<category>/v1` without checking the capability state or proving that the typed executor produced it. The standalone plan-only route demonstrates this concretely. This is part of P1-RA1.
3. **Explicit parent recovery selection bypasses target comparison.** `_prior_recovery_result` treats any supplied `parent_run` as same-target before checking fingerprints. Both public CLIs currently pass either no parent or the same run whose target is used for execution, so no public cross-target resume was found. The reusable runtime API nevertheless lacks its claimed invariant. This is P2-RA1.

Fresh immutable-provenance bypasses found: **2 active boundary defects** (fabricated executor provenance and mutable campaign resolution), plus one lower-severity internal API target-binding weakness.

## 10. CLI parity and failure modes

### 10.1 What passes

`phase2_cli.py verification run`, the conversational `agent.py` verification command, and `agent.py scan --mode verify` instantiate the same `VerificationRuntime`. The scan injects the already-created shared client/ledger; the standalone command lets the runtime create the same client type and adapter. Response metadata, rate-limit headers/latency, isolated credentials/cookies, request deltas, sanitizer, provenance fields, classifications, reasons, and recovery private store are shared. Current parity fixtures cover all 11 typed categories and representative live outcomes.

### 10.2 Fresh CLI/runtime failures

- `stage_verification_inputs` catches only a malformed top-level non-object during runtime construction. `select_verification_inputs` later validates `defaults`, `hypotheses`, and per-hypothesis objects outside the runtime's error-to-result handling. A fresh `{"defaults": []}` input raised `ValueError` with zero traffic rather than returning deterministic `policy_blocked` status/reasons. Standalone wraps this as a generic CLI error; scan wraps it as a workflow error. This violates malformed-input classification and status/reason parity (P1-RA2).
- The adaptive scan correctly skips plan-only categories, while standalone `verification run` invokes the runtime, appends its plan-only `inconclusive` object, and allows the store to attach typed provenance (P1-RA1).

Fresh CLI verification bypasses found: **2**.

Other early returns were inspected. Typed policy, scope, method, account, credential, owned-object, state-change, cleanup, rate-limit, unsupported adapter/location, OAST, and before-traffic budget denials carry safe reasons. Transport exceptions are normalized without Python exception repr. Cleanup attempts and failures keep their reasons and accounting.

## 11. Tests

`python -m pytest --collect-only -q` collected **734** tests. The full suite passed.

| Area | Focused collected tests | Assessment |
|---|---:|---|
| Whole-scan integration | 12 | Scan modes, persistence, planning/rendering, shared runtime integration |
| Whole-scan network policy | 17 | Policy before traffic, shared ledger, budget/per-host/rate/concurrency/OAST, registered adapter invariant |
| Strict proof inputs/predicates | 36 | Strict inputs, zero traffic, baseline rules, injection reflection and correlation |
| Public sanitizer/private state | 6 | Broad boundary coverage, but missing quoted-JSON-in-string cases |
| Request delta/accounting | 15 | Strict model, snapshot attribution, transport failure, optional login, campaign/export |
| Provenance | 13 | Revisions, IDs/hashes, same-hypothesis results, exact lookup, target fingerprint, legacy; current campaign test explicitly accepts later resolution drift |
| Verification runtime parity | 29 | Shared factory/transport, all 11 categories, response metadata, secrets, budget, recovery; missing malformed nested envelope and standalone plan-only cases |
| Account and identity normalization | 76 | 11-category policy matrix, multi-account binding, identity preference, discarded references, shared resolver integration |
| Capability registry | 23 | 30-category invariant, 11 typed routes/schemas/versions, 19 plan-only entries, planner/priority/report/orchestrator metadata, cost formulas |
| Terminal classifications | 19 | Status enum, budget, transport, cleanup, instability, secure baselines, hashes |
| BOLA/tenant/session acquisition and binding | 60 | Shared account/session/object acquisition and differentials |
| Vertical authorization | 24 | Roles, baselines, nested protected evidence, persistence |
| Authentication enforcement | 11 | Authenticated/anonymous evidence and isolation |
| Mass assignment | 18 | Five-step flow, optional login, independent cleanup, failure behavior |
| Session invalidation | 18 | Email/username acquisition, exact four requests, replay, policy, cleanup |
| Recovery state | 20 | Three stages, private resume, cleanup, per-stage delta, CLIs |
| Rate limiting | 33 | N+2 flow, cap/opt-in, identity, throttle/lockout, accounting |

SQL, command, and traversal share strict-proof, request-delta, capability, and runtime-parity parameterized suites rather than separate executor files.

Architectural behavior still missing direct regression coverage:

- quoted JSON secret fragments through each durable/public boundary;
- standalone plan-only invocation refusing to create a typed result;
- malformed nested verification input producing identical zero-traffic status/reasons in both public paths;
- campaign membership pinning a run revision or exact result selection;
- explicit parent recovery target-fingerprint mismatch;
- one real-flow registry cost invariant covering min/worst fixtures for every typed category.

## 12. Quality gates and worktree

All requested gates were run against the audited code and current documentation state before this re-audit document update:

```text
black --check .
All done! 195 files would be left unchanged.

ruff check .
All checks passed!

python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py campaign_cli.py
PASS

python -m pytest -q
734 passed in 14.78s

git diff --check
PASS
```

Quality gates: **PASS**. Passing gates do not negate the new architecture findings because their reproduction conditions are not covered by the current tests.

The worktree was already extensively dirty before this audit. The audit did not clean, format, delete, commit, or push anything. `git status --short --untracked-files=all` reported:

```text
 M .env.example
 M .gitignore
 M README.md
 M agent.py
 M agent_core/decision_engine.py
 M agent_core/doctor.py
 M agent_core/planner.py
 M agent_core/result_normalizer.py
 M agent_core/tool_explainer.py
 M agent_core/tool_runner.py
 M agent_core/workflow_manager.py
 M config.py
 M docs/ARCHITECTURE.md
 M docs/ROADMAP.md
 M docs/TOOLS.md
 M requirements.txt
 M tests/test_api_object_discovery.py
 M tests/test_authz_differential_tester.py
 M tests/test_release_stabilization.py
 M tests/test_scan_v2.py
 M tests/test_scope_guard.py
 M tool_registry.py
 M tools/ai_report_writer.py
 M tools/api_object_discovery.py
 M tools/authz_differential_tester.py
 M tools/dns_lookup.py
 M tools/endpoint_analyzer.py
 M tools/graphql_introspection_checker.py
 M tools/http_probe.py
 M tools/js_secret_scanner.py
 M tools/jwt_replay_checker.py
 M tools/misconfiguration_detector.py
 M tools/nuclei_scan.py
 M tools/parameter_analyzer.py
 M tools/request_replay_engine.py
 M tools/safe_http.py
 M tools/scope_guard.py
 M tools/security_headers_checker.py
 M tools/tech_fingerprint.py
 M tools/workflow_replay_checker.py
 M web_app.py
?? agent_cli.py
?? agent_core/adaptive_orchestrator.py
?? agent_core/agent_models.py
?? agent_core/attack_surface.py
?? agent_core/audit_log.py
?? agent_core/auth_semantics.py
?? agent_core/benchmark_exporter.py
?? agent_core/capture_executor.py
?? agent_core/capture_ingest.py
?? agent_core/capture_verification_orchestrator.py
?? agent_core/context.py
?? agent_core/controlled_context.py
?? agent_core/controlled_executor.py
?? agent_core/credential_vault.py
?? agent_core/differential_analyzer.py
?? agent_core/evidence_correlator.py
?? agent_core/finding_export.py
?? agent_core/hardened_executor.py
?? agent_core/hypothesis_engine.py
?? agent_core/model_roles.py
?? agent_core/phase2_campaign.py
?? agent_core/phase2_policy.py
?? agent_core/phase2_reporter.py
?? agent_core/phase2_result_status.py
?? agent_core/phase2_store.py
?? agent_core/policy.py
?? agent_core/priority_engine.py
?? agent_core/rate_limit_enforcement.py
?? agent_core/recovery_state_enforcement.py
?? agent_core/request_budget.py
?? agent_core/result_provenance.py
?? agent_core/route_identity.py
?? agent_core/runtime_binding.py
?? agent_core/session_invalidation.py
?? agent_core/verification_capabilities.py
?? agent_core/verification_gate.py
?? agent_core/verification_planner.py
?? agent_core/verification_registry.py
?? agent_core/verification_runtime.py
?? campaign_cli.py
?? config/contexts/bola-lab.json
?? config/contexts/public-site.json
?? config/policies/auth-lab-phase2.json
?? config/policies/auth-lab-policy.json
?? config/policies/bola-lab-policy.json
?? config/policies/mass-assignment-lab-policy.json
?? config/policies/nerminzlatanovic.json
?? config/policy-host-mappings.json
?? context_cli.py
?? docs/ADAPTIVE_AGENT.md
?? docs/CAPTURE_CAMPAIGNS.md
?? docs/PHASE2.md
?? docs/PHASE2_COMPLETION_AUDIT.md
?? eval_cli.py
?? evaluation/__init__.py
?? evaluation/fixtures/authorization.jsonl
?? evaluation/lab.py
?? evaluation/replay_app.py
?? examples/capture-context.example.json
?? examples/capture.example.http
?? examples/policy.example.json
?? injection_cli.py
?? mutation_cli.py
?? phase2_cli.py
?? policy_cli.py
?? tests/test_agent_architecture.py
?? tests/test_api_surface_discovery.py
?? tests/test_auth_semantic_discovery.py
?? tests/test_authenticated_injection_verifier.py
?? tests/test_authentication_enforcement_runtime_binding.py
?? tests/test_capture_verification_orchestrator.py
?? tests/test_controlled_session_acquisition.py
?? tests/test_mass_assignment_execution.py
?? tests/test_nuclei_policy.py
?? tests/test_openapi_route_preservation.py
?? tests/test_p0_2_strict_proof_inputs.py
?? tests/test_p1_4_account_identity_normalization.py
?? tests/test_p1_5_verification_capabilities.py
?? tests/test_phase2_adaptive_engine.py
?? tests/test_phase2_campaigns.py
?? tests/test_phase2_network_policy.py
?? tests/test_phase2_public_sanitizer.py
?? tests/test_phase2_scan_integration.py
?? tests/test_phase2_terminal_classification.py
?? tests/test_policy_profiles.py
?? tests/test_rate_limit_enforcement_execution.py
?? tests/test_recovery_state_enforcement_execution.py
?? tests/test_report_grounding_regressions.py
?? tests/test_request_delta_accounting.py
?? tests/test_request_mutation_engine.py
?? tests/test_result_provenance.py
?? tests/test_session_invalidation_execution.py
?? tests/test_verification_runtime_parity.py
?? tests/test_vertical_authorization_runtime_binding.py
?? tests/test_workflow_finding_export.py
?? tools/api_metadata_discovery.py
?? tools/api_target_analyzer.py
?? tools/authenticated_injection_verifier.py
?? tools/openapi_surface_analyzer.py
?? tools/request_mutation_engine.py
?? verification_inputs/captures/.gitkeep
?? verification_inputs/contexts/.gitkeep
?? verification_inputs/temporary/.gitkeep
```

`docs/PHASE2_COMPLETION_AUDIT.md` was already untracked. The only file content changed by this audit is this document.

## 13. Completion score

The original rubric and weights were applied from zero rather than carrying forward the previous percentage.

| Area | Weight | Score | Implementation evidence | Remaining gap |
|---|---:|---:|---|---|
| A. Discovery/hypothesis architecture | 15 | 15 | Canonical surface, deterministic emission, exact 30-category registry invariant, evidence-linked hypotheses | No freeze-blocking gap found |
| B. Verification planning | 10 | 10 | Category-aware plans, bounded manual fallback, registry-derived capability/cost metadata, no fake plan-only traffic | No planner-local capability/cost drift found |
| C. Typed controlled execution | 20 | 17 | 11 strict routes, exact binding, centralized transport, cleanup workflows | Standalone plan-only typed-looking result and nested input escape |
| D. Policy/safety enforcement | 15 | 15 | Policy and authoritative ledger before discovery; scope/method/OAST/rate/concurrency/budget fail closed | No active Phase 2 network bypass found |
| E. Evidence/classification quality | 15 | 14 | Strict schemas, category proof, secure baselines, reflection exclusion, shared status normalization | One malformed envelope bypasses canonical classification; store trusts producer provenance too broadly |
| F. Secret handling/controlled context | 10 | 6 | Process-local vault, live-reference checks, centralized identity, private recovery state, structured sanitizer | Quoted JSON secret fragments persist publicly and enter AI evidence input |
| G. Run/campaign/provenance | 5 | 3 | Append-only run revisions, immutable result IDs/hashes, exact lookup, target fingerprints, legacy reads | Campaigns resolve latest mutable revision; store can fabricate typed provenance |
| H. Request accounting/metrics | 5 | 5 | Strict per-result deltas, exact snapshots, auth/acquisition/cleanup/failures, stored-delta consumers | Only a non-blocking cross-fixture coverage gap remains |
| I. Tests/CLI/documentation | 5 | 3 | 734 passing tests, both CLIs share runtime, generated capability docs, all gates pass | Missing regressions correspond directly to the fresh P0/P1 findings |
| **Total** | **100** | **88** |  |  |

New completion percentage: **88%**.

## 14. Fresh remaining issues

### P0 (0 open; 1 completed re-audit blocker)

#### P0-RA1 — Canonical sanitizer leaks quoted JSON secrets embedded in diagnostic strings — COMPLETE

- Exact problem: `sanitize_text` recognizes unquoted `password=value` / `access_token:value` syntax but not quoted JSON keys. The raw value survives canonical serialization, immutable/latest persistence, result hash content, campaign/finding export, CLI output, and AI evidence input/file.
- Affected files: `agent_core/result_normalizer.py`; consumers include `agent_core/phase2_store.py`, `agent_core/result_provenance.py`, `agent_core/phase2_campaign.py`, `tools/ai_report_writer.py`, `phase2_cli.py`, and `agent.py`.
- Why it blocks freeze: Phase 2's public and persistence boundary can durably disclose credentials/tokens and send them to an AI evidence boundary despite P0-3's contract.
- Minimal fix: make arbitrary-string sanitation recognize bounded quoted key/value syntax or safely parse embedded structured fragments, while preserving safe telemetry and avoiding broad substring redaction. Continue to sanitize before hashing and every output/persistence boundary.
- Required tests: quoted JSON `password`, username/email when treated private, access/refresh/session tokens, Authorization/Cookie fields, and JWT values across public result, immutable/latest run, hash basis, campaign/finding, benchmark, report, AI input/evidence, and both CLIs. Include benign quoted telemetry to prevent over-redaction.

Completion evidence (2026-08-31):

- `agent_core.result_normalizer.sanitize_text` now applies compiled, bounded double-quoted, single-quoted, and backslash-escaped structured-pair patterns before the existing URL/header/assignment/JWT passes. Processing remains capped by `MAX_TEXT`; keys and values are explicitly bounded; no decoding, recursion, `eval`, or `literal_eval` was added.
- Quoted-pair decisions reuse the canonical `_secret_key` classifier and preserve the original key/spacing/quote form while replacing only private string values with `[REDACTED]`. Password/token/session/recovery/API/client-secret/vault-reference, Authorization/Proxy-Authorization, Cookie/Set-Cookie, compact JWT, and raw structured identity values are covered. Numeric/boolean telemetry and safe JWT/cookie metadata remain unchanged.
- The P0-RA1 matrix adds 31 collected regressions. `tests/test_phase2_public_sanitizer.py` passes 37 tests covering structured-versus-string parity, multiple and nested diagnostics, exception bodies, canonical hash input, immutable base plus revision and `latest.json`, exact campaign/benchmark/finding provenance, Markdown/technical evidence, AI grounding/evidence/rendering, and both CLI public helpers.
- Source inspection reconfirmed canonical `public_result` use before every named public/persistence edge. Public/persistence sanitizer bypasses found: **0**. No consumer-specific sanitizer patch was required.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest` (**765 passed**), and `git diff --check` pass. The completion score remains **88%** pending the explicitly deferred P1-RA work; no P1-RA finding was modified.

### P1 (0 open; 3 completed re-audit blockers)

#### P1-RA1 — Standalone plan-only invocation creates a typed-looking immutable result — COMPLETE

- Exact problem: the registry and adaptive orchestrator say plan-only/no route, but `VerificationRuntime.execute_selected` returns `inconclusive`; `phase2_cli.py` persists it; `Phase2RunStore._prepare_new_result` supplies `ControlledVerificationExecutor` and `<category>/v1` provenance by default. The store also does not validate that a new result's capability is typed or that the declared executor actually produced it.
- Affected files: `agent_core/verification_runtime.py`, `phase2_cli.py`, `agent_core/phase2_store.py`, `agent_core/result_provenance.py`.
- Why it blocks freeze: it contradicts the authoritative capability registry and makes an unavailable executor look real in immutable provenance.
- Minimal fix: reject/return plan-only command metadata before typed execution and do not append a verification result; require complete validated producer provenance for new typed results and reject typed provenance for non-typed categories. Keep legacy records readable without retrofitting provenance.
- Required tests: standalone invocation for all plan-only categories creates zero verification results and zero traffic; store rejects fabricated typed provenance for plan-only/unknown categories; all 11 typed results retain exact registry versions.

Completion evidence (2026-08-31):

- `VerificationRuntime.execute_selected` now uses the authoritative capability registry before resolving any typed executor. Every `plan_only` category returns one deterministic command envelope with `success: false`, unavailable typed capability metadata, `verification_result_created: false`, zero convenience request count, and the canonical plan-only reason. It has no terminal status, `RequestDelta`, result ID/hash, or executor provenance.
- `phase2_cli.py verification run` returns that envelope before changing hypothesis status, metrics, verification results, or persistent state. The scan path uses the same registry helper/reason on its retained plan and keeps the hypothesis proposed; it invokes no typed executor and appends no verification result.
- Real typed execution resolves the executor and strict input schema through the registry. The actual controlled executor and shared runtime attach exact registry-derived producer metadata. The compatibility provenance helper is now registry-gated and refuses plan-only/unknown categories.
- `Phase2RunStore` no longer defaults or guesses producer identity. Before assigning a result ID/hash, it requires explicit producer metadata and validates the result category, optional linked hypothesis category, typed capability state, resolvable strict input schema/executor, exact executor name/version/implementation family, and result schema version. Rejected new writes leave immutable history and `latest.json` unchanged; legacy unversioned records remain readable.
- The P1-RA1 matrix adds 41 collected regressions: all 19 dynamic plan-only categories through standalone and scan preflight, all 11 dynamic typed categories through exact provenance persistence, seven forged provenance/schema/category cases, immutable/latest preservation, campaign/benchmark/finding reference absence, terminal-vocabulary separation, and active source-route inspection. Fabricated active producer-provenance routes found: **0**.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest` (**806 passed**), and `git diff --check` pass. The completion score remains **88%**; P1-RA2 and P1-RA3 were not modified.

#### P1-RA2 — Nested structured verification input escapes canonical status/reason handling — COMPLETE

- Exact problem: `select_verification_inputs` validates `defaults`, `hypotheses`, and the selected hypothesis after the constructor's invalid-input catch. A list or scalar in those fields raises `ValueError` before the executor boundary.
- Affected files: `agent_core/verification_runtime.py`, `phase2_cli.py`, `agent.py` through their error envelopes.
- Why it blocks freeze: malformed input should be a zero-traffic deterministic `policy_blocked` result with identical status/reasons on both public paths; it currently becomes unrelated generic CLI/workflow failure.
- Minimal fix: include selection validation in the shared invalid-input result path before `_gate`/transport and return the canonical invalid-input reason/delta/provenance contract.
- Required tests: invalid `defaults`, invalid `hypotheses`, invalid per-hypothesis object, unknown structured members, zero transport, and exact standalone/scan status/reason/delta parity.

Completion evidence (2026-08-31):

- `VerificationInputEnvelope` now defines the only structured selection syntax: optional strict `defaults` and `hypotheses` objects, strict bounded string keys, bounded map sizes, object-valued hypothesis entries, and forbidden extra envelope members. Lists, scalars, strings, nulls, coercion, malformed selected or unselected entries, and mixed arbitrary envelope members are rejected. The existing direct category-input object remains a separate compatibility mode and continues through its authoritative category schema.
- `VerificationRuntime.execute_selected` preserves the P1-RA1 order: it resolves capability first and returns plan-only command metadata without interpreting typed payloads. For typed capabilities, root validation state plus all defaults/per-hypothesis selection now execute inside one `VerificationInputValidationError` boundary before gate/executor construction, recovery lookup, or traffic. Only expected input validation is normalized; unrelated runtime/programmer failures are not relabeled as user input errors.
- Every malformed typed envelope produces the existing P1-6 `policy_blocked` result with the canonical safe invalid-input reason, exact registry-derived typed producer contract, `requests_used: 0`, and a P1-1 `RequestDelta` whose discovery/auth/verification/cleanup/attempted/total fields are all zero. Raw malformed payloads and sentinel values are never reflected.
- Both `phase2_cli.py verification run` and `agent.py scan --mode verify` pass parsed data to this same runtime boundary. Public-path regressions assert identical status, reasons, and delta, zero transport, sanitizer-safe output, and no generic workflow/command failure. Malformed plan-only input still returns the P1-RA1 non-result capability envelope with no status, delta, provenance, result ID, or result hash.
- The P1-RA2 matrix adds 28 collected regressions covering malformed roots, defaults, hypotheses containers, selected/unselected entries, unknown members, bounded keys/maps, valid defaults/selection/override/direct compatibility, public-path parity, secrecy, zero traffic/accounting, truthful blocked provenance, and plan-only precedence. Source inspection of `verification_runtime.py`, `phase2_cli.py`, and `agent.py` found **0** structured validation escape routes.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest` (**834 passed**), and `git diff --check` pass. The completion score remains **88%**; P1-RA3 was not modified.

#### P1-RA3 — Campaign membership does not pin an immutable run revision/result view — COMPLETE

- Exact problem: campaign files store only run IDs. `resolve` loads the latest revision every time, so later results silently change status, metrics, and exact result reference for an unchanged campaign manifest.
- Affected files: `agent_core/phase2_campaign.py`, `agent_core/phase2_store.py`, campaign CLI/report/export consumers.
- Why it blocks freeze: P1-2 requires stable campaign meaning after later results. Exact references inside one export do not help if a later export selects different evidence without an explicit campaign update.
- Minimal fix: when adding a run, persist an immutable run revision/path/hash or exact selected result references, resolve those pins thereafter, and use an explicit campaign revision/update operation to adopt later results. Preserve legacy run-ID-only campaigns with clearly marked compatibility semantics.
- Required tests: unchanged campaign export is byte/content stable after new run revisions; pinned exact references remain resolvable; explicit update creates a new campaign revision; legacy campaigns remain readable; target fingerprints still fail closed.

Completion evidence (2026-08-31):

- New campaign manifests use `campaign_schema_version: 2`. Ordered `run_references` pin an exact positive run revision, canonical sanitized `run_snapshot_hash`, and exact target fingerprint. `run_ids` remains a validated display/compatibility projection and is not authoritative. `Phase2RunStore.load_revision` performs exact base/revision lookup with no latest fallback, while `load_latest_revision` makes the add/refresh selection boundary explicit.
- Campaign creation writes immutable revision 1. Each `add-run` writes the next immutable campaign revision and refuses duplicate run IDs. `refresh-run` is the only operation that adopts newer evidence for an existing member; it retains order, increments `campaign_revision`, changes the canonical public `campaign_snapshot_hash`, and leaves all earlier campaign revisions addressable through exact revision APIs.
- Versioned resolution loads only exact pinned run revisions and validates campaign hash, run snapshot hash, campaign/run/reference target fingerprints, stored run revision metadata, and every schema-versioned result hash before aggregation/export. Findings carry exact result provenance from the pinned snapshot plus the campaign ID/revision/hash; per-run metrics carry run revision/hash provenance. Missing/corrupt state fails before any partial export is written.
- Unchanged campaign, generic benchmark, finding, request-delta, metrics, and recovery-stage views remain content-identical after later ordinary or multi-stage recovery run revisions. Explicit refresh alone adopts the final/latest state. Campaign manifest/export hashes use canonical `public_result` content and exclude raw quoted/escaped sentinels and private recovery state.
- Legacy run-ID-only manifests remain readable and unchanged on disk, and show/export explicitly report `legacy_unpinned` without fabricated revision/run/campaign hashes. Their latest lookup is isolated to the legacy compatibility branch. The first explicit add/refresh writes a pinned v2 revision while preserving the legacy base as addressable revision 0. The existing auth-lab campaign is not automatically rewritten.
- The P1-RA3 matrix adds 15 collected regressions covering pin fields/order, exact run lookup, export/benchmark/finding/metric/delta stability, explicit refresh/history, recovery stages, five integrity failures, mutation atomicity, duplicate refusal, legacy migration, confidential target fingerprints, secret-safe hash bases, and CLI show/refresh behavior. New versioned campaign latest-resolution paths found: **0**; the remaining latest lookups are limited to explicit add/refresh/migration and marked legacy compatibility.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest` (**849 passed**), and `git diff --check` pass. The audit score and freeze decision remain the prior **88% / NO** snapshot pending a separately requested final re-audit; no P2/P3 item was implemented.

### P2 (4)

1. **P2-RA1 — Explicit parent recovery target check is bypassed.** In `VerificationRuntime._prior_recovery_result`, any supplied `parent_run` is accepted as same-target before fingerprint comparison. Public callers currently pass a self-consistent target, so this is not an observed public bypass. Minimal hardening is to compare fingerprints for every parent and add a mismatched-parent regression.
2. **P2-RA2 — Registry-to-real-executor request-cost invariant is incomplete.** The generic upper-bound test injects synthetic ledger consumption. Category tests support the declared numbers, but one parameterized real-flow min/worst fixture should bind all 11 categories directly to registry costs.
3. **P2-RA3 — Legacy verification surfaces remain easy to confuse with Phase 2.** `verification_gate.py`, `verification_orchestrator.py`, the older verification CLI, and capture utilities retain older manual/failed vocabularies and some direct requester defaults. They are not active Phase 2 routes. Phase 3 should rename, isolate, or retire them and enforce an import/routing quarantine.
4. **P2-RA4 — Private recovery state write precedes public run validation.** `Phase2RunStore.save` writes any supplied preserved challenge before validating the run revision/results. A later validation failure can therefore mutate the private resume record without a corresponding public revision. Make the private write transactional after public validation/publication and add a failed-save state-preservation test.

### P3 (2)

1. `VerificationPlanner` currently duplicates `service instability` in one stop-condition list. This is harmless output noise.
2. `HypothesisStatus` retains legacy/manual names such as `needs_manual_verification` and `cleanup_failed`. They are not accepted as active typed result terminals, but clearer type separation would reduce future vocabulary confusion.

P0 remaining: **1**. P1 remaining: **3**.

## 15. Freeze decision

1. Is Phase 2 ready to freeze now? **NO**
2. P0 remaining: **1**
3. P1 remaining: **3**
4. P2 remaining: **4**
5. P3 remaining: **2**
6. New completion percentage: **88%**
7. Work explicitly deferred to Phase 3: new typed adapters for the 19 truthful plan-only categories; broader parameter locations; GraphQL/upload/OAST/protocol-specific workflows; broader safe recovery/rate/role/object adapters; external vault integrations; UI/model sophistication; and the P2 legacy-surface cleanup. None should be pulled into the minimal Phase 2 freeze fixes.
8. Are any P2/P3 items severe enough to block freeze despite their label? **No**, provided the P0 and all three P1 findings are fixed and the P2 constraints remain documented. P2-RA1 and P2-RA4 are the highest-priority post-freeze hardening items.
9. Exact final steps before tagging:

   1. Implement only P0-RA1 and P1-RA1 through P1-RA3 with the listed regressions; do not add categories/payloads.
   2. Run `black --check .`, `ruff check .`, `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py campaign_cli.py`, `python -m pytest -q`, and `git diff --check` on the final candidate.
   3. Run the approved external benchmark harness as a black-box regression only. Do not inspect ground truth, expected vulnerability IDs, app source, hidden tests, or solutions, and do not tune architecture from recall/precision.
   4. Exercise both public verification commands against the same synthetic controlled fixtures and compare status, reasons, request delta, provenance, identity handling, and sanitized output.
   5. Run `git status --short --untracked-files=all`; ensure every intended Phase 2 source/test/doc is tracked and no reports, private recovery records, contexts with raw secrets, caches, or temporary verification inputs are staged.
   6. Review `git diff --cached --check` and the staged diff manually. Commit only after human approval, rerun the gates from the committed tree, then create the Phase 2 tag according to the project's release process.

## Terminal summary

```text
PHASE 2 RE-AUDIT COMPLETE

completion: 88%
P0: 1
P1: 3
P2: 4
P3: 2
ready to freeze: NO

emitted categories: 30
typed categories: 11
plan-only categories: 19

tests: 734 passed
quality gates: PASS
network bypasses: 0
weak proof routes: 0
public secret leaks: 1
immutable provenance bypasses: 2
request accounting inconsistencies: 0
CLI verification bypasses: 2
account/identity semantic bypasses: 0
capability registry drift: 1
undocumented terminal statuses: 0

files changed by audit: docs/PHASE2_COMPLETION_AUDIT.md only
files deleted: 0
```

---

<details>
<summary>Historical pre-remediation audit (2026-08-28)</summary>

# Historical Phase 2 Completion Audit

Audit date: 2026-08-28

Repository: `cybercortex-ai-agent`

Branch/commit inspected: `release/v2.1.0-beta-rc` / `973ed9f6ec45997b7cdf952f4be1361ec7cfc102`

Verdict: **NOT READY TO FREEZE**

Completion score: **68%**

Freeze backlog: **3 P0, 6 P1, 5 P2, 4 P3**

## 1. Scope, method, and architecture verdict

This audit inspected the implementation, tests, command-line entry points, and documentation in this repository. It did not inspect or modify `cybercortex-range`, ground truth, benchmark IDs, vulnerable application source, hidden tests, expected answers, or benchmark solutions. No benchmark result was used to infer completeness.

The implemented Phase 2 architecture is substantial: deterministic hypothesis generation, category-specific planning, a process-local credential vault, controlled runtime context, request ledgers, policy gates, 11 executable category names, evidence correlation, immutable-style identifiers, run/campaign reporting, and 494 passing tests. The strongest typed workflows—mass assignment, session invalidation, recovery state, and bounded login rate limiting—use meaningful state or sequence evidence rather than status-code-only conclusions.

It is not yet safe to freeze. P0-1 is now complete: the active scan path selects the Phase 2 policy and creates one authoritative request ledger before discovery. The remaining P0 findings are unchanged: several executable categories still accept untyped proof-controlling values and can reach `verified` from reflection or truthy strings, and the general persistence sanitizer does not remove raw authorization/cookie material embedded in strings. These are release-boundary problems, not requests for broader vulnerability coverage.

The primary policy-bound execution family and the capture planning family are now separated:

1. `agent.py scan --mode verify` / `phase2_cli.py verification run` use `ControlledVerificationExecutor`, `DeterministicPolicyGate`, `ControlledContext`, `CredentialVault`, `RequestBudget`, `Phase2RunStore`, and the adaptive orchestrator.
2. `campaign_cli.py` / `CaptureVerificationOrchestrator` are plan/offline-only for Phase 2. `--execute --authorized` returns `plan_only` with zero requests; it is no longer a weaker active execution family.

Active target traffic therefore has one policy/ledger execution family.

## 2. Discovery and hypothesis category inventory

The inventory below is the union of categories actually emitted by `agent_core/hypothesis_engine.py` from canonical attack surfaces and captured requests. No proposed category is included. Every emitted category receives either a category-specific plan or the planner fallback; “plan only” therefore means it is not routed to the active typed executor.

Priority is initialized from the shown category seed and then re-ranked by `PriorityEngine` using confidence, evidence/basis, workflow completeness, impact, safety, controlled-account readiness, request cost, risk, and corroboration. Confidence is normally `medium`; the specific low-confidence heuristics are noted. “Auto” means the implementation can execute automatically only after its policy, context, input, and budget preconditions pass.

| Category | Discovery source(s) | Generator | Evidence basis / confidence | Priority behavior | Plan? | Typed executor | Auto | Credentials | Test-owned resource | State-changing / cleanup | Maturity | Major limitations |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `bola` | Canonical path parameters; capture object-hint parameters | Both | Observed ID-like parameter; medium, lowered to low by capture generator without two identities | Seed 100, dynamically ranked | Yes | `ControlledVerificationExecutor` cross-account branch | Conditional | Two accounts | Yes; owner-bound object | No / no network cleanup | `typed_verification` | Generic input is untyped; candidate denial can be `rejected` without proving a valid owner baseline |
| `vertical_authorization` | Privileged path segments | Canonical | Privileged-route heuristic; low | Seed 96, dynamically ranked | Yes | Role differential branch | Conditional | Two ranked roles | No | No / none | `typed_verification` | Proof inputs untyped; only a fixed role vocabulary is recognized |
| `tenant_isolation` | Tenant/org parameters and object metadata | Both | Observed tenant boundary; medium | Seed 94, dynamically ranked | Yes | Tenant differential branch | Conditional | Two accounts in distinct tenants | Yes; tenant-bound | No / none | `typed_verification` | Generic input is untyped |
| `mass_assignment` | Writable JSON/form/multipart/body/GraphQL fields with privilege, owner, state, or limit names | Canonical | Concrete writable field; medium | Seed 90, dynamically ranked | Yes | Strict mass-assignment workflow | Conditional | Owner account | Yes; reversible exact object | Yes / mandatory exact restore | `typed_verification` | PATCH-only; scalar one-field mutations; caller must supply an approved safe value |
| `property_authorization` | Captured owner/tenant/org writable fields | Capture | Writable authorization property; medium | Seed 88, dynamically ranked | Yes | None | No | Planned | Planned | Potentially / plan describes cleanup | `plan_only` | Overlaps mass assignment but has no typed route |
| `authentication_enforcement` | Semantic `authenticated_resource` boundaries | Canonical | Observed protected authenticated surface; inherited boundary confidence | Seed 86, dynamically ranked | Yes | Authenticated/anonymous differential branch | Conditional | One account | No | No / none | `typed_verification` | Generic proof input untyped; action-only proof is not implemented |
| `session_security` | Authenticated lifecycle/account capture or `Set-Cookie` | Capture | Captured session evidence; medium | Seed 84, dynamically ranked | Yes | None | No | Planned | No | Potentially / plan-dependent | `plan_only` | Broad discovery category; no typed verifier |
| `oauth_oidc` | OAuth/OIDC/account path semantics | Capture | Captured path/request evidence; medium | Seed 82, dynamically ranked | Yes | None | No | Planned | No | Potentially / plan-dependent | `plan_only` | No protocol-specific typed checks |
| `session_invalidation` | Ordered session creation → authenticated resource → termination workflow | Canonical | Exact three-boundary workflow; inherited confidence | Seed 82, dynamically ranked | Yes | Strict session invalidation workflow | Conditional | One account | No | Yes, controlled termination / discard issued session | `typed_verification` | One exact acquisition/baseline/termination/replay workflow |
| `recovery_state_enforcement` | Recovery start → completion workflow | Canonical | Exact ordered recovery boundaries; inherited confidence | Seed 81, dynamically ranked | Yes | Strict multi-stage recovery workflow | Conditional | One account plus runtime challenge/code and approved passwords | No object | Yes / mandatory external restore confirmation | `typed_verification` | Multi-command mutable run state; only one approved comparison mode |
| `account_lifecycle` | Login/logout/register/reset/verify/invite path capture | Capture | Captured account operation; medium | Seed 80, dynamically ranked | Yes | None | No | Planned | No | Potentially / plan-dependent | `plan_only` | No typed lifecycle state machine |
| `jwt_enforcement` | Observed token metadata | Canonical | Token presence/metadata, not a weakness; inherited confidence | Seed 80, dynamically ranked | Yes | None | No | Planned token/session | No | No / none | `plan_only` | No Phase 2 typed enforcement verifier |
| `graphql_mutation_authorization` | Observed GraphQL mutation | Canonical | Operation/type evidence; inherited confidence | Seed 79, dynamically ranked | Yes | None | No | Planned | Likely | Yes / plan-dependent | `plan_only` | No typed GraphQL mutation differential |
| `rate_limit_enforcement` | Rate-sensitive credential/session/recovery semantic boundary | Canonical | Exact boundary/workflow evidence; inherited confidence | Seed 78, dynamically ranked | Yes | Login workflow only | Explicit opt-in | One controlled login | No | Login attempts affect account state / final valid-login check | `typed_verification` | Recovery-rate plans are not executable; scan path loses rate-limit headers |
| `graphql_object_authorization` | Observed GraphQL object operation | Canonical | Operation/object evidence; inherited confidence | Seed 78, dynamically ranked | Yes | None | No | Planned | Planned | Usually no / none | `plan_only` | No typed object differential |
| `graphql_field_authorization` | Observed GraphQL field selection | Canonical | Field selection evidence; inherited confidence | Seed 77, dynamically ranked | Yes | None | No | Planned | Planned | Usually no / none | `plan_only` | No typed field differential |
| `business_logic` | Captured state-changing request | Capture | Concrete non-read operation; medium | Seed 76, dynamically ranked | Yes | None | No | Planned | Planned | Yes / plan-dependent | `plan_only` | Generic hypothesis; no state-machine executor |
| `business_logic_state_enforcement` | Ordered/stateful non-auth workflow evidence | Canonical | Ordered steps, transition evidence, or direct mutation; inherited confidence | Seed 76, dynamically ranked | Yes | None | No | Planned | Planned | Yes / plan-dependent | `plan_only` | No typed state-transition verifier |
| `api_authorization` | Authenticated captured `/api` request | Capture | Captured authenticated API surface; medium | Seed 75, dynamically ranked | Yes | None | No | Planned | Planned | Method-dependent / plan-dependent | `plan_only` | Broad category; not routed to typed authz checks |
| `graphql_authorization` | Captured GraphQL operation | Capture | Captured operation; medium | Seed 74, dynamically ranked | Yes | None | No | Planned | Planned | Method-dependent / plan-dependent | `plan_only` | Legacy broad category overlaps three canonical categories |
| `excessive_data_exposure` | Protected-looking names in response summaries | Capture | Safe response field names; medium | Seed 72, dynamically ranked | Yes | None | No | Planned | No | No / none | `plan_only` | Field-name heuristic cannot establish sensitivity by itself |
| `ssrf` | URL/URI/webhook/callback/host-like capture parameters | Capture | Parameter-name evidence; medium | Seed 70, dynamically ranked | Yes | None | No | Planned | Planned fixture | Potential outbound effect / plan-dependent | `plan_only` | No central typed/OAST-controlled executor |
| `upload_ownership` | Upload surface plus ownership semantics | Canonical | Upload/object evidence; inherited confidence | Seed 70, dynamically ranked | Yes | None | No | Planned | Yes | Yes / required by plan | `plan_only` | No typed cross-owner upload verifier |
| `sql_injection` | Query/search/filter/ID-like parameter semantics | Canonical | Parameter-name heuristic; low | Seed 68, dynamically ranked | Yes | Generic three-request injection branch | Lab only | Optional account | No explicit object | No intended change / none | `typed_verification` | Untyped opt-in proof, fixed query-string mutation, weak repeatability predicate |
| `command_injection` | Command/template/path-like parameter semantics | Canonical | Parameter-name heuristic; low | Seed 68, dynamically ranked | Yes | Generic three-request injection branch | Lab only | Optional account | Synthetic fixture expected | No intended change / none | `typed_verification` | Reflected canary is accepted as execution proof |
| `path_traversal` | Path/file/template-like parameter semantics | Canonical | Parameter-name heuristic; low | Seed 68, dynamically ranked | Yes | Generic three-request injection branch | Lab only | Optional account | Synthetic fixture expected | No / none | `typed_verification` | Fixed query-string location and marker-only proof |
| `upload_security` | File/upload parameter or multipart capture | Capture | Concrete upload surface; medium | Seed 66, dynamically ranked | Yes | None | No | Planned | Yes | Yes / required by plan | `plan_only` | No typed safe-file corpus or cleanup route |
| `file_upload_validation` | Canonical file-upload surface | Canonical | Upload parameter/content evidence; inherited confidence | Seed 66, dynamically ranked | Yes | None | No | Planned | Yes | Yes / required by plan | `plan_only` | No typed validation executor |
| `injection` | Generic query/input capture semantics | Capture | Input-name heuristic; medium | Seed 62, dynamically ranked | Yes | None | No | Planned | No | No intended change / none | `plan_only` | Legacy broad category is distinct from the three executable categories |
| `cache_security` | Authenticated GET plus cache indicators | Capture | Captured headers/semantics; medium | Seed 58, dynamically ranked | Yes | None | No | Planned | No | No / none | `plan_only` | No typed shared-cache isolation proof |

No current category meets `production_ready_for_phase2` under this audit because all active execution paths inherit at least one P0 cross-cutting defect. Nineteen categories are plan-only and eleven are typed-verification candidates.

## 3. Typed executor inventory

All HTTP calls below pass through an injected request function and the deterministic gate once the typed executor has been reached. Maximums include on-demand login/object acquisition, not DNS resolution. The common persisted provenance contains hypothesis ID/category, plan, runtime binding, evidence/result summaries, and budget snapshots, but not a stable executor name/version or per-result immutable ID.

### BOLA

- Executor/module: `ControlledVerificationExecutor._execute_authorization_comparison` and `analyze_cross_account_access`.
- Accepted input: no strict Pydantic envelope; free-form fields include protected-field configuration and protected-data confirmation. Runtime object/account flags are overwritten from controlled context.
- Requirements: two distinct controlled accounts; owner-bound test object, supplied or safely acquired; account and object must match exact plan/runtime binding.
- Policy gates: authorization, exact scope/endpoint, `GET`, credential permission, account eligibility, object ownership, test-owned object, request/per-host/rate limits, and strict runtime-plan equality.
- Sequence/max: login owner if needed; login comparator if needed; optional owner collection `GET` to acquire an object; owner-object `GET`; same object `GET` as comparator. Maximum 5 HTTP requests.
- Accounting: up to 2 `auth`, up to 1 `discovery`, exactly 2 `verification`; result `requests_used` reports only the two comparison requests.
- Stops: missing/ambiguous account, object, credentials, policy, plan, or budget fails closed. Transport/service evidence generally becomes inconclusive.
- Cleanup: none; read-only.
- Classification: `verified` requires separate accounts, candidate identity/protected-field evidence, and successful candidate access; equal 200 alone is insufficient. `rejected` currently can be based on candidate 403/404 without requiring a valid owner baseline. Otherwise `inconclusive`; preflight failures are `policy_blocked` (budget can first appear as `budget_exhausted`).
- Secrets/provenance/tests: credentials are resolved from the vault and not intentionally copied to summaries. BOLA shares 60 controlled-session/acquisition parameter cases plus object/authz integration tests. No test covers embedded credential strings in arbitrary evidence.

### Tenant isolation

- Executor/module: same authorization branch plus tenant-specific runtime binding and differential predicate.
- Accepted input: free-form proof fields; controlled account/object/tenant facts come from context.
- Requirements: two controlled accounts with distinct explicit tenant IDs and an owner-bound, tenant-bound test object.
- Gates: all BOLA gates plus distinct-tenant and tenant/object consistency checks. The shared P1-4 rule treats an empty policy account allowlist as no additional restriction beyond controlled context.
- Sequence/max/accounting: the same optional two logins, optional object acquisition, and two `GET` comparisons; maximum 5; output again reports only 2 `requests_used`.
- Stops/cleanup: missing tenant metadata, same tenant, object mismatch, policy/budget/transport failure stop safely; read-only cleanup is unnecessary.
- Classification: `verified` requires matched object/protected tenant evidence, not equal 200 alone; `rejected` has the same weak owner-baseline issue as BOLA; other results are inconclusive or policy-blocked.
- Secrets/provenance/tests: vault-backed credentials; common result provenance. The P1-4 matrix covers empty and explicit two-account allowlists.

### Vertical authorization

- Executor/module: role differential branch and `analyze_role_authorization`.
- Accepted input: free-form protected-field and `protected_data_confirmed` values; no strict schema.
- Requirements: exactly two eligible controlled accounts with recognized, distinct role ranks; privileged account baseline and lower-role comparison; configured protected evidence.
- Gates: exact target/method/account binding, credential permission, policy allowlist, budget/rate/per-host limits, read-only request.
- Sequence/max: up to two logins; privileged `GET`; lower-role `GET`. Maximum 4 HTTP requests.
- Accounting: up to 2 `auth`, 2 `verification`; result `requests_used=2` excludes login.
- Stops/cleanup: unknown/equal roles, missing credentials/evidence, policy mismatch, budget, and transport failure stop; no cleanup.
- Classification: `verified` requires a successful protected privileged baseline and matched protected evidence in the lower-role response. Status equality alone is insufficient. `protected_functionality_confirmed` is recorded but not a verification predicate. Denial is rejected; ambiguity is inconclusive.
- Secrets/provenance/tests: vault-backed credentials, common provenance; 24 dedicated vertical tests. A string value such as `"false"` is currently truthy and can incorrectly satisfy the proof flag.

### Mass assignment

- Executor/module: `ControlledVerificationExecutor._execute_mass_assignment`.
- Accepted input: strict `MassAssignmentVerificationInput`: a single-field scalar `mutation`, optional exact one-field `expected_before`, and `cleanup_required: true`; extra or coercible fields are rejected.
- Requirements: one owner account, exact owner-bound test object, reversible approved field/value, initial state readable.
- Gates: authorization, exact scope/endpoint, `GET` and `PATCH`, credential/account permission, state-change permission, test-owned resource, mutation allowlist, mandatory cleanup, budget/rate/per-host limits.
- Sequence/max: optional login; `GET` before; `PATCH` test value; independent `GET`; `PATCH` original value; independent cleanup `GET`. Maximum 6 HTTP requests.
- Accounting: 1 optional `auth`; 5 `verification` requests; result `requests_used=5` excludes login and includes cleanup.
- Stops: strict validation occurs before mutation; after mutation, cleanup is attempted on all exits. Budget must reserve cleanup. Cleanup failure cannot verify.
- Cleanup: mandatory exact restoration and independent confirmation.
- Classification: `verified` only when before-state is established, the approved value independently persists, and cleanup is independently confirmed. `rejected` requires no persisted change and successful cleanup confirmation. Cleanup uncertainty is inconclusive; preflight policy failures are policy-blocked.
- Secrets/provenance/tests: vault-backed login; mutation summaries are sanitized, but arbitrary string redaction has a gap. Seventeen dedicated tests cover before/after, independent reads, cleanup, and failures.

### Authentication enforcement

- Executor/module: authentication differential branch and `analyze_authentication_enforcement`.
- Accepted input: free-form protected-field/protected-data evidence; no strict schema.
- Requirements: one controlled account and an authenticated protected baseline.
- Gates: exact target/method, credential/account permission for baseline, credential stripping for anonymous comparison, request budget/rate limits.
- Sequence/max: optional login; authenticated `GET`; the same request with authorization, cookie, session, token, and API-key-like headers removed. Maximum 3 HTTP requests.
- Accounting: up to 1 `auth`, 2 `verification`; result `requests_used=2` excludes login.
- Stops/cleanup: missing account/baseline/evidence, endpoint mismatch, budget, instability, or transport failure; no cleanup.
- Classification: `verified` requires a valid authenticated baseline and protected evidence in the unauthenticated response; status 200 alone is insufficient. Denial is rejected, ambiguity inconclusive. The supplied protected-functionality flag is not sufficient by itself.
- Secrets/provenance/tests: vault-backed credential use and credential-stripped comparison; 11 dedicated runtime-binding tests plus shared auth tests. Input coercion and malformed evidence remain uncovered.

### Session invalidation

- Executor/module: `ControlledVerificationExecutor._execute_session_invalidation`, `SessionInvalidationWorkflow`, and `analyze_session_invalidation`.
- Accepted input: strict `SessionInvalidationVerificationInput` with 1–50 protected fields and strict `protected_data_confirmed: true`; exact observed workflow is derived from hypothesis metadata.
- Requirements: one controlled account, exact session creation/termination/resource workflow, runtime-issued session S1, protected baseline.
- Gates: exact URLs/methods, authorized controlled account, credentials, state-change permission, typed `SessionTerminationAction`, allowed termination method (`POST` or `DELETE`), budget/rate/per-host limits. Generic DELETE remains blocked.
- Sequence/max: session acquisition `POST`; protected resource request using S1; exact termination request using S1; replay the same S1 to the same protected resource. Exactly 4 HTTP requests when no preexisting issued session can be reused.
- Accounting: 1 `auth`, 3 `verification`; output `requests_used=3` excludes session acquisition.
- Stops: a substituted session, missing protected baseline, unattempted termination, mismatched endpoint/method, missing vault reference, or budget failure cannot verify.
- Cleanup: S1 is discarded and the prior vault reference restored locally; termination itself is the permitted state change.
- Classification: `verified` only if the same issued session remains protected-capable after an attempted termination; a real denial is rejected; uncertain termination/service behavior is inconclusive; preflight is policy-blocked.
- Secrets/provenance/tests: raw session material remains vault-only during normal operation. Fourteen dedicated tests cover replay binding and failure modes. Email-only controlled identities fail in one binding path because `username` is required there despite shared email fallback elsewhere.

### Recovery state enforcement

- Executor/module: recovery branches in `ControlledVerificationExecutor`, `RecoveryVerificationInput`, and `RecoveryWorkflow`.
- Accepted input: strict, extra-forbidden stage envelopes. Only `reused_same_challenge_and_code` is an approved comparison. Runtime code, temporary password, comparison password, and current/original password are ingested into the vault and removed from public inputs.
- Requirements: one controlled account; runtime-issued challenge from the exact start response; legitimate completion evidence; exactly the approved comparison; external restoration before final confirmation.
- Gates: exact start/completion methods and URLs, controlled identity, credential permission, state-change permission, recovery technique, mandatory cleanup, scope/budget/rate limits, challenge/workflow/account binding.
- Sequence/max: stage A1 sends one start request; stage A2 sends legitimate completion, the one approved reuse comparison, then authenticates with the temporary password; phase B authenticates with the externally restored original password. Five HTTP requests over the complete workflow.
- Accounting: A1 reports `requests_used=1`; A2 `requests_used=2` plus 1 `auth`; B `requests_used=0` plus 1 `auth`. Budget snapshots show 1, 3, and 1 phase requests respectively.
- Stops: missing/stale/consumed challenge, duplicate resume, substituted challenge/session/account/workflow, malformed input, credential failure, budget, or missing cleanup evidence fails closed.
- Cleanup: external restoration is mandatory; final state cannot verify until original-password authentication confirms it. Stored challenge state is consumed during resume.
- Classification: interim states are awaiting/pending; final `verified` or `rejected` requires controlled legitimate evidence, the approved comparison, independent authentication confirmation, and external cleanup confirmation. Uncertainty is inconclusive; preflight is policy-blocked.
- Secrets/provenance/tests: raw code/password values are vaulted and removed, but the preserved challenge is stored in run JSON by design and is printed by the scan CLI even though standalone verification strips it from public output. Nineteen dedicated tests cover binding, resume, substitution, and cleanup.

### Bounded login rate-limit enforcement

- Executor/module: rate-limit branch, `AuthenticationLoginRateLimitWorkflow`, `RateLimitVerificationInput`, and `classify_rate_limit_sequence`.
- Accepted input: strict exact `rate_limit` and `expected_control` envelopes; invalid credential is vaulted and removed; requested attempts are strict and bounded.
- Requirements: one controlled login identity; known valid credential; explicit expected control; 1–5 invalid attempts; classified login workflow.
- Gates: explicit `allow_bounded_rate_limit_verification`, policy attempt maximum, hard cap `MAX_RATE_LIMIT_ATTEMPTS=5`, one account only, exact login endpoint/method, credential permission, scope/budget/rate limits.
- Sequence/max: one valid baseline login; N sequential invalid attempts against the same account; one final valid login. Maximum 7 requests at N=5; no retries, concurrency, candidate generation, spraying, or cross-account attempts.
- Accounting: all requests are `auth`; typed `request_counts` reports baseline, invalid, final-valid, and total. The result does not use the generic `requests_used` field.
- Stops: attempts over either maximum, absent opt-in/control, wrong endpoint/account, missing vault entry, budget, service instability, or transport exception stop without increasing attempts.
- Cleanup: no credential mutation; the final valid login checks for an unintended lockout.
- Classification: a configured control demonstrably absent across structured repeated invalid-credential responses with successful final login can be verified; concrete throttling/lockout is rejected. Timing or ambiguous 401 evidence remains inconclusive; there is no universal threshold assumption.
- Secrets/provenance/tests: invalid and valid credentials are vault-backed. Thirty-three dedicated tests cover caps, ambiguity, headers, and account binding. The `agent.py` transport drops response headers/elapsed time, unlike standalone verification, weakening parity and potentially hiding configured rate-limit evidence.

### SQL injection

- Executor/module: generic `ControlledVerificationExecutor._execute_read_only_probe` plus `_analyze`.
- Accepted input: no strict schema; free-form `safe_probe_semantics_confirmed` controls a proof predicate.
- Requirements: dedicated/lab target, a discovered parameter, optional first controlled account for authentication.
- Gates: explicit authorization/scope, lab-only technique, exact method restrictions, credential policy if used, budget/rate/per-host limits; no state mutation.
- Sequence/max: optional login; control request; fixed safe probe request; repeated control request. Maximum 4 HTTP requests.
- Accounting: up to 1 `auth`, 3 `verification`; result `requests_used=3` excludes login.
- Stops/cleanup: policy/budget/transport and instability checks; no cleanup.
- Classification: can be `verified` from repeatable response-hash differential plus a truthy untyped semantics flag; otherwise inconclusive. It does not produce a meaningful `rejected` result.
- Secrets/provenance/tests: vault-backed optional auth and common provenance. Five tests target the separate `tools/authenticated_injection_verifier.py`, not all proof branches here. The executor always mutates the query string even when discovery identified another parameter location.

### Command injection

- Executor/module: the same generic three-request probe branch.
- Accepted input: untyped generic input; fixed `;printf CCX_CANARY` probe.
- Requirements/gates: dedicated/lab target, safe discovered parameter, optional controlled auth, scope/method/budget/rate gates.
- Sequence/max/accounting: optional login plus control/probe/control; maximum 4; result reports 3 verification requests only.
- Stops/cleanup: policy, budget, transport, and instability stop; read-only intent, no cleanup.
- Classification: `verified` when `CCX_CANARY` appears in the probe body and differential evidence is repeatable; otherwise inconclusive. A server that merely reflects the supplied string therefore produces a false `verified` route.
- Secrets/provenance/tests: common vault/provenance behavior; no regression test proves the canary originated from execution rather than reflection.

### Path traversal

- Executor/module: the same generic three-request probe branch.
- Accepted input: untyped generic input; fixed synthetic-fixture marker expectation.
- Requirements/gates: dedicated/lab target, discovered path-like parameter, optional controlled auth, exact policy and budget gates.
- Sequence/max/accounting: optional login plus control/probe/control; maximum 4; `requests_used=3` excludes login.
- Stops/cleanup: policy, budget, transport, and instability stop; no cleanup.
- Classification: `verified` only when `CCX_SYNTHETIC_FIXTURE` appears with repeatable differential evidence; otherwise inconclusive. No status-only route exists, but reflected/cached markers and wrong-location mutation are not excluded rigorously.
- Secrets/provenance/tests: common behavior; no direct end-to-end executor coverage for location binding and origin of the marker.

## 4. Policy and safety audit

| Control | Result | Evidence and inconsistency |
|---|---|---|
| Explicit authorization | Pass for P0-1 | The selected policy is resolved and the target is preflighted before `ToolRunner`; the capture campaign is plan/offline-only |
| Exact target scope | Pass for P0-1 | Shared transport applies policy host, URL-prefix, scheme, port, and exclusion rules before discovery and verification transport |
| Allowed methods | Pass for P0-1 | Shared transport checks the policy method and retains stricter purpose-specific read-only/typed gates |
| Credential-use permission | Pass in typed executor | Vault references and policy/context checks precede use |
| Controlled accounts | Pass for P1-4 | Eligibility always requires a `controlled: true` account in the supplied context; category-specific exact binding remains separate |
| Policy account allowlists | Pass for P1-4 | Empty means no additional restriction beyond controlled context; non-empty means intersection with controlled context |
| Test-owned objects | Pass where typed mutation/cross-object execution requires them | BOLA/tenant and mass assignment bind an owned resource; plan-only stateful categories have no executor |
| State-change permission | Pass in typed stateful flows | Mass, session, and recovery require explicit permission |
| Mandatory cleanup | Pass in mass/recovery | Mass reserves and verifies restore; recovery requires external restore confirmation; session discards issued session locally |
| Global/per-host request budgets | Pass for P0-1 | One thread-safe ledger exists before discovery; authorization and both limits are checked atomically before each HTTP transport attempt |
| Request rate | Pass for P0-1 | The same policy-aware limiter schedules discovery, authentication, and verification HTTP starts |
| Maximum concurrency | Pass for P0-1 | `ScopedHTTPClient` centrally enforces `max_concurrency` with a bounded semaphore; a full slot denies before ledger consumption or transport |
| Bounded rate-limit opt-in/hard caps | Pass | Explicit opt-in, policy cap, hard cap 5, sequential same-account attempts |
| Destructive testing / DoS prohibition | Pass in central policy | Non-overridable prohibitions remain; the alternate capture path cannot execute traffic |
| OAST restrictions | Pass for P0-1 | OAST requires explicit policy permission, capability, and callback host; campaign, Nuclei, and mutation paths without the shared contract fail closed |
| No generic DELETE bypass | Pass | Generic gate rejects DELETE; only typed, exact session termination can use policy-approved DELETE |
| No guessing/spraying/brute force | Pass in typed paths | No candidate generator/retry loop; rate verifier uses one supplied invalid credential, one account, and at most five attempts |
| No arbitrary recovery challenge substitution | Pass | Runtime challenge, account, workflow, and consumed-state binding fail closed |
| No arbitrary mass-assignment values | Pass | Strict scalar one-field envelope and policy mutation allowlist; original state is restored |
| No hidden retries | Pass | Request functions are called once per ledger event; no retry adapter was introduced and adapted discovery uses the same transport |

P0-1 completion moved policy resolution, target authorization, ledger creation, and shared transport construction ahead of `ToolRunner`. `_discovery_request_count` and retrospective clamping were removed. The transport authorizes scope/method/technique/OAST, acquires a concurrency slot, performs optional DNS preparation, applies the shared rate limiter, and atomically consumes the global/per-host ledger immediately before its one transport call. A failing transport remains charged; a pre-transport denial does not.

## 5. Controlled context and credential vault audit

- Raw context passwords/tokens and runtime-acquired sessions are ingested into the process-local `CredentialVault`. Missing, discarded, or unknown references fail closed at use. `close()` overwrites its mutable byte buffers before removing entries.
- Recovery codes/passwords and rate-limit invalid credentials are popped from verification input and vaulted. Multi-stage recovery stores vault references and controlled challenge metadata, not raw code/password values.
- P1-4 centralizes login identity resolution for session acquisition, session invalidation, recovery, rate limiting, and authorization executors. Exact `email` and `username` semantics use deterministic live-vault preference/fallback; unsupported fields and missing/discarded references fail before traffic.
- There is no vault TTL/expiry timestamp. A discarded reference fails locally; a server-expired but locally live session is detected only by the response and normally becomes rejected/inconclusive.
- Structured key-based redaction handles obvious secret keys and credible JWT strings. It is insufficient for arbitrary string values. For example, an evidence string containing `Authorization: Bearer RAW` or `Cookie: sid=RAW` survives `agent_core.result_normalizer.redact` and can reach run JSON, reports, benchmark export, or CLI output.
- `phase2_campaign._safe_text` applies stronger text substitutions, but only at campaign rendering time. It does not repair already persisted run JSON or all other exporters.
- Redaction is also over-broad: the key matcher treats the entire `attack_surface.jwt` object as secret and removes safe telemetry such as token counts/source metadata. This corrupts useful non-secret evidence.
- Standalone `verification run` removes `preserved_challenge` from its returned public object. `agent.py scan --mode verify` returns the adaptive run object with that internal recovery state exposed. The stored state may be needed to resume, but it needs a separate private-state boundary and must not leak to public reports/CLI/export.

Therefore the statement “reports, run JSON, campaign JSON, benchmark export, and CLI output never persist raw secrets” is not presently enforceable for embedded header/session strings. This is P0 even though the intended vault flows are sound.

## 6. Request accounting audit

The intended authoritative ledger uses `discovery_requests`, `auth_requests`, `verification_requests`, and `total_requests`. Actual outputs additionally use `requests_used`, typed `request_counts`, campaign `requests_used`, and report metrics with different meanings.

Identified inconsistencies:

1. **Resolved by P0-1:** discovery attempts are consumed live by the authoritative pre-discovery ledger instead of reconstructed from optional tool output.
2. **Resolved by P0-1:** the next global- or per-host-over-budget request is denied before transport; no retrospective fill or clamp remains.
3. BOLA, tenant, vertical, authentication, SQL, command, and traversal `requests_used` omit authentication and optional object acquisition. Session reports 3 even though its complete workflow uses 4. Mass reports 5 and omits optional login.
4. Rate limiting omits `requests_used` and reports all requests through `request_counts`; recovery reports per-phase comparison requests separately from authentication. There is no single typed delta schema.
5. In scan mode, each result's `request_budget` is a cumulative shared snapshot containing discovery and earlier verifications. In standalone verification it is normally phase-local. Consumers cannot infer a result's delta reliably from the same field.
6. Campaign normalization usually prefers explicit `requests_used`; it therefore drops auth/object/session-acquisition requests. A session result with `requests_used=3` and budget total 4 contributes 3.
7. Recovery campaign normalization uses the maximum of phase `requests_used` and budget total. With a cumulative scan snapshot, unrelated discovery/earlier requests can be attributed to recovery; for example, discovery 8 plus one recovery request contributes 9.
8. Benchmark export also prefers `requests_used`, reproducing omitted auth/acquisition counts.
9. Standalone CLI metric updates use budget snapshots or typed counts and are more complete than campaign per-result metrics; scan-level metrics now use complete live discovery accounting, while the per-result delta ambiguity remains P1-1.
10. Transport-attempt accounting differs: the `RequestBudget` is consumed before a request and therefore includes exceptions. Several local `requests_used` counters increment only after a response, while mass assignment increments before its call. The same failed attempt is represented differently by category.
11. **Resolved by P0-1:** `ScopedHTTPClient` and the authoritative ledger count an authorized attempt immediately before the requester, including transport exceptions.
12. Cleanup requests are included for mass assignment, omitted from recovery's generic `requests_used` (final cleanup confirmation is `auth`), and correctly zero for session's local vault discard. Reports do not communicate those semantics.
13. DNS resolution remains transport preparation rather than an HTTP request and does not consume the HTTP ledger. It is performed only after URL policy authorization, under the same concurrency bound, for the unchanged authorized hostname. Redirects are reauthorized; Host-header target changes and per-request proxy overrides are blocked. No hidden HTTP retry path was found.

There is no double count in the live central ledger: production controlled transports advertise that they own pre-transport consumption, while local injected test transports retain compatibility accounting. The remaining request-accounting failures are the P1-1 cumulative-vs-delta ambiguity, legacy result-field omissions, and campaign/export attribution—not enforcement bypasses.

## 7. Evidence and classification audit

No active typed executor was found that reaches `verified` from an HTTP status code alone. Nevertheless, weak non-status evidence can still produce `verified` in the generic branches.

| Area | Required evidence is implemented? | Audit result |
|---|---|---|
| BOLA | Separate accounts, owner binding, candidate object identity and protected field | Equal 200 is insufficient. Candidate denial can be called `rejected` without a valid owner baseline, so secure classification is too eager |
| Tenant isolation | Distinct tenant metadata, owner object baseline, matching protected tenant/object evidence | Equal 200 is insufficient. Same rejected-baseline limitation as BOLA |
| Vertical authorization | Successful protected privileged baseline, ranked roles, configured protected evidence in lower-role response | Implemented, but untyped truthy proof flags allow malformed `"false"` to act as true |
| Mass assignment | Before state, approved mutation, independent persistence read, independent exact cleanup read | Implemented conservatively; cleanup failure is inconclusive |
| Authentication enforcement | Authenticated protected baseline and protected evidence in credential-free response | Implemented; status 200 alone and the functionality flag alone do not verify |
| Session invalidation | Same runtime-issued session, termination attempted, protected baseline, exact replay | Implemented; substituted session/workflow fails closed |
| Recovery | Runtime challenge binding, legitimate completion, one approved comparison, independent auth confirmation, external cleanup confirmation | Implemented across stages; final result requires restoration |
| Rate limiting | Explicit expected control, 1–5 attempts, structured evidence, final valid control | Implemented; ambiguous 401/timing evidence remains inconclusive and no universal threshold is assumed |
| SQL injection | Repeatable control/probe differential plus supplied semantic confirmation | Insufficient: an untyped caller-controlled flag and hash differential do not prove SQL evaluation; parameter location can be wrong |
| Command injection | Repeatable differential plus canary in response | Unsafe: reflection of the exact supplied canary can produce `verified` without command execution |
| Path traversal | Repeatable differential plus synthetic fixture marker | Better than status-only, but marker origin/location binding is not independently proven |

The dormant `agent_core/verification_registry.py` is not used by either requested CLI path. If activated, its offline BOLA handler can return `verified` from supplied repeatable differences without protected-object proof and with zero requests. It should be aligned with the controlled executor or quarantined before it becomes callable.

## 8. Run, campaign, provenance, and deduplication audit

- Run IDs are stable strings once generated, and `latest.json` is convenience state. Older distinct IDs remain individually addressable.
- Storage is not actually immutable: `Phase2RunStore.save` overwrites an existing `<run_id>.json`. Standalone verification appends to and rewrites the same run. Recovery resume marks preserved challenge state consumed by mutating prior result state before the run is saved again. A campaign that already references that run ID can therefore observe changed content.
- Campaigns store ordered, de-duplicated run IDs and reject a different canonical target. Canonicalization redacts secret query values, so two targets differing only in such a value compare equal; this is privacy-preserving but not literal exact-target equality.
- `verification_result_reference` preserves only `run_id` and `hypothesis_id`. It is ambiguous when the same hypothesis has multiple staged or retried results; no immutable result ID/index/hash is stored.
- Typed result records retain plan/runtime/evidence data, but do not persist an executor module/version identity. Export cannot prove which implementation produced a result.
- Campaign selection prefers completed typed results over discovery. For non-recovery categories it orders `verified > rejected > inconclusive`, then confidence. Multi-stage recovery chooses the latest completed final state. Raw rejected results remain in run JSON and are auditable.
- Campaign export does not fabricate verification when no completed typed result exists. Benchmark export's last-result dictionary behavior is simpler than campaign selection and should share one resolver.
- Finding deduplication uses category, operation method, normalized route, and parameter/fallback. It prevents repeated identical findings while keeping authentication enforcement distinct from session termination and retaining final recovery state. This is structurally reasonable, but result-reference ambiguity remains.
- Request normalization is incorrect for the reasons in section 6; final typed state wins, but its request provenance does not reliably reach campaign/export metrics.

## 9. CLI parity audit

Both `phase2_cli.py verification run` and `agent.py scan --mode verify` ultimately use the same controlled executor, policy gate, controlled context model, process-local vault, and typed classifiers. They are not behaviorally equivalent:

| Behavior | Standalone verification | Agent scan verify | Consequence |
|---|---|---|---|
| Discovery | Executes selected stored hypothesis only | Runs discovery after policy selection and authoritative ledger creation, then may execute several plans | Same safety envelope; different workflow scope |
| Response metadata | Preserves a whitelist of rate-limit headers and elapsed time | Adapts status/body only | Scan can miss `Retry-After`/rate-limit evidence and weaken rate classification |
| Ambient credential isolation | Explicitly excludes ambient session credentials for session acquisition and rate-limit workflows | Explicit exclusion is applied to session acquisition; rate uses a fresh isolated cookie context but different adapter behavior | Semantics are close, not proven equivalent |
| Target class flags | Supports dedicated-lab option | Exposes `--lab` but not the same option shape | Policy configuration parity gap |
| Secret staging | Explicitly stages recovery and rate inputs before execution | Explicit pre-stage for recovery; rate ingestion vaults/pops inside executor | Different public-input lifecycle |
| Recovery output | Removes preserved challenge from public result | Returns adaptive result containing preserved challenge state | CLI confidentiality mismatch |
| Persistence | Appends verification to a selected run | Persists the complete scan/adaptive run | Same store, different mutation lifecycle and metric shape |
| Request metrics | Usually phase-local | Shared cumulative live ledger beginning before discovery | Per-result fields remain non-comparable pending P1-1, but enforcement is authoritative |

There is no regression test that runs the same controlled fixture through both CLIs and compares policy decision, requests, classification, sanitation, persisted provenance, and metrics.

## 10. Failure-mode audit

| Failure mode | Current behavior | Gap |
|---|---|---|
| Malformed strict mass/session/recovery/rate input | Deterministic preflight block/inconclusive reason | Good |
| Malformed generic BOLA/tenant/vertical/auth/injection input | May be coerced; malformed protected-fields shape can raise after traffic | P0: validate before any request |
| Missing credentials/vault reference/discarded reference | Fails closed with a bounded reason | Good |
| Wrong/insufficient accounts or roles | Fails closed | Empty policy allowlist interpretation differs by executor |
| Missing owned object/object acquisition ambiguity | BOLA/tenant/mass fail closed | Good; reason propagation is generally useful |
| Scope/endpoint/method/plan mismatch | Typed executor blocks before action | Discovery uses the same target policy; capture execution is plan/offline-only |
| Policy mismatch | `policy_blocked` with reasons in main path | Legacy `execute_allowed_plans` can emit `budget_blocked` without an explanatory reason |
| Request budget exhaustion | Ledger raises before request | Status can be `budget_exhausted`, then adaptive orchestrator coerces it to `inconclusive`; taxonomy is inconsistent though reasons are usually retained |
| Cleanup failure | Mass/recovery cannot verify; reason retained | Correct classification, inconsistent request metrics |
| Service instability | Generic/rate paths identify several unstable patterns | Mass/session/recovery do not use one uniform instability predicate across every response |
| Transport exception | Sanitized exception type/reason, no raw secret | Attempt counts differ between ledger, local counters, and scoped client |
| Invalid/stale/duplicate recovery workflow | Fails closed; consumed challenge prevents reuse | Historical run mutation weakens audit immutability |
| Challenge/session substitution | Fails closed by exact runtime binding | Good |
| Rate attempts over policy maximum/hard cap | Deterministically blocked before requests | Good |
| Credential guessing/spraying/brute force | No route in typed executor | Good |

The opaque paths still needing normalization are legacy `budget_blocked`, category-dependent `budget_exhausted` versus `inconclusive`, some bare policy blocks assembled from lower-level reasons, and malformed generic inputs that can escape as exceptions instead of a deterministic result.

## 11. Test audit

Collection contains **494 tests**. The authoritative full run passed all 494. Counts below are collected pytest cases, so parametrized cases are counted separately.

| Test subsystem/file | Tests | Primary coverage |
|---|---:|---|
| `test_controlled_session_acquisition.py` | 60 | Shared controlled account/session/object acquisition, heavily exercising BOLA/tenant prerequisites |
| `test_rate_limit_enforcement_execution.py` | 33 | Attempt caps, expected controls, ambiguity, policy, request counts |
| `test_vertical_authorization_runtime_binding.py` | 24 | Role/account binding and protected evidence |
| `test_phase2_campaigns.py` | 21 | Campaign run ordering, target checks, selection/export |
| `test_recovery_state_enforcement_execution.py` | 19 | Multi-stage challenge binding, substitution, cleanup |
| `test_phase2_adaptive_engine.py` | 18 | Planning, priority, policy-gated orchestration |
| `test_mass_assignment_execution.py` | 17 | Strict mutation schema, persistence, cleanup |
| `test_api_surface_discovery.py` | 16 | Canonical attack-surface discovery |
| `test_auth_semantic_discovery.py` | 16 | Auth/session/recovery/rate semantic boundaries |
| `test_phase2_scan_integration.py` | 12 | Scan-mode Phase 2 integration |
| `test_authentication_enforcement_runtime_binding.py` | 11 | Authenticated versus anonymous evidence |
| `test_policy_profiles.py` | 11 | Phase 2 profiles and constraints |
| `test_session_invalidation_execution.py` | 14 | Same-session replay, termination, protected evidence |
| `test_capture_verification_orchestrator.py` | 4 | Alternate capture campaign path |
| `test_verification_cli.py` | 3 | Standalone verification CLI basics |
| `test_verification_orchestrator.py` | 3 | Legacy verification orchestration |
| Vault/sanitization coverage across suites | 35 name-matched cases | Vault reference use, context input removal, report grounding; no dedicated end-to-end boundary suite |
| Request-accounting coverage across suites | 5 explicitly named cases | Typed counts and some campaign rollups; no canonical all-executor accounting matrix |
| Failure-mode coverage across suites | 159 broadly name-matched cases | Strong for the four strict workflows; count overlaps subsystems and does not imply matrix completeness |
| CLI parity coverage | 0 | The CLI tests cover standalone or scan behavior separately, not equivalent execution of one fixture |
| All remaining repository tests | 212 | Agent architecture, APIs, tools, policies, reports, scan v2, scope, web, and legacy features |
| **Total** | **494** | **All collected tests** |

Additional per-file counts from collection: agent architecture 13, AI report 7, API object discovery 15, authz differential 6, business logic 8, conservative discovery 6, endpoint 11, file upload 10, GraphQL 6, IDOR 4, JWT security 5, JWT workflow 9, nuclei policy 8, OpenAPI preservation 8, raw HTTP parser 7, release stabilization 9, report grounding 15, request differential 3, mutation 4, replay 3, scan v2 18, scope guard 10, v2.1 readiness 8, web 4, workflow export 10, and authenticated injection tool 5.

Across all files, category-name matching finds 24 BOLA/IDOR cases, 15 tenant cases, 27 vertical cases, 21 mass-assignment cases, 11 authentication-enforcement cases, 14 session-invalidation cases, 25 recovery cases, and 34 rate-limit cases. These sets overlap and therefore must not be summed. There are zero collected test IDs explicitly naming `sql_injection`, `command_injection`, or `path_traversal` in the controlled executor; the five authenticated-injection tests exercise the separate tool. There are 52 policy-named cases across suites (including the 11 dedicated profile tests) and 25 campaign-named cases (including the 21 dedicated campaign tests).

Important untested architecture behavior:

- P0-1 now adds 17 collected regression cases for pre-discovery policy/ledger construction, discovery denials, live global/per-host accounting, failed attempts, shared categories, rate/concurrency, OAST, ToolRunner registry disposition, and capture plan-only behavior. The post-change full run is 511 passing tests.
- Per-result request-delta propagation into campaigns/benchmark export remains intentionally deferred to P1-1.
- A same-fixture parity test across both requested CLI paths.
- Embedded `Authorization`/`Cookie`/session strings through run, report, campaign, benchmark, and CLI output; safe JWT telemetry preservation.
- Run immutability, immutable result references, and recovery resume without historical mutation.
- Generic executor schema rejection before traffic; string `"false"` proof flags; command-canary reflection; SQL/path parameter-location binding.
- P1-4 regression coverage now proves uniform empty/explicit account allowlist semantics and email-only session-invalidation identity.
- BOLA/tenant secure rejection requiring a valid owner baseline.
- Enforced `max_concurrency` under the selected Phase 2 policy.

Passing tests therefore demonstrate substantial behavior, but do not cover the current P0 boundary failures.

## 12. Quality gates and worktree state

The exact requested commands were run without automatic formatting or cleanup.

| Gate | Result |
|---|---|
| `black --check .` | PASS — 182 files would be left unchanged |
| `ruff check .` | PASS |
| `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py` | PASS |
| `python -m pytest -q` | PASS — 494 passed in 5.51s in the authoritative run |
| `git diff --check` | PASS |

The first sandboxed pytest invocation produced 490 passes and 4 failures solely because the sandbox denied local `HTTPServer` socket binding (`PermissionError: [Errno 1]`). The unchanged suite was rerun with approved network/socket execution and all 494 passed. This was an environment restriction, not a product test failure.

Pre-audit worktree status:

- Modified tracked files: 37.
- Deleted files: 0.
- Untracked files: 89 with `--untracked-files=all`; this includes nearly all new Phase 2 core modules, CLIs, documentation, tests, examples, policies, and verification-input placeholders.
- Untracked Phase 2 implementation groups include `phase2_cli.py`, `policy_cli.py`, `campaign_cli.py`, `context_cli.py`, the Phase 2 files under `agent_core/`, the Phase 2 test modules under `tests/`, `docs/PHASE2.md`, `docs/CAPTURE_CAMPAIGNS.md`, policy/context examples, and verification input placeholders.

Files changed by this audit: `docs/PHASE2_COMPLETION_AUDIT.md` only. No file was deleted, formatted, cleaned, committed, or pushed. Compile/test caches may have been updated as ignored test artifacts.

Audit-end `git status --short --untracked-files=all` (the audit file itself is the additional untracked file relative to the baseline):

```text
 M .env.example
 M .gitignore
 M README.md
 M agent.py
 M agent_core/decision_engine.py
 M agent_core/doctor.py
 M agent_core/planner.py
 M agent_core/result_normalizer.py
 M agent_core/tool_explainer.py
 M agent_core/tool_runner.py
 M agent_core/workflow_manager.py
 M config.py
 M docs/ARCHITECTURE.md
 M docs/ROADMAP.md
 M docs/TOOLS.md
 M requirements.txt
 M tests/test_api_object_discovery.py
 M tests/test_authz_differential_tester.py
 M tests/test_release_stabilization.py
 M tests/test_scan_v2.py
 M tests/test_scope_guard.py
 M tool_registry.py
 M tools/ai_report_writer.py
 M tools/api_object_discovery.py
 M tools/authz_differential_tester.py
 M tools/endpoint_analyzer.py
 M tools/graphql_introspection_checker.py
 M tools/http_probe.py
 M tools/jwt_replay_checker.py
 M tools/misconfiguration_detector.py
 M tools/nuclei_scan.py
 M tools/parameter_analyzer.py
 M tools/request_replay_engine.py
 M tools/safe_http.py
 M tools/scope_guard.py
 M tools/workflow_replay_checker.py
 M web_app.py
?? agent_cli.py
?? agent_core/adaptive_orchestrator.py
?? agent_core/agent_models.py
?? agent_core/attack_surface.py
?? agent_core/audit_log.py
?? agent_core/auth_semantics.py
?? agent_core/benchmark_exporter.py
?? agent_core/capture_executor.py
?? agent_core/capture_ingest.py
?? agent_core/capture_verification_orchestrator.py
?? agent_core/context.py
?? agent_core/controlled_context.py
?? agent_core/controlled_executor.py
?? agent_core/credential_vault.py
?? agent_core/differential_analyzer.py
?? agent_core/evidence_correlator.py
?? agent_core/finding_export.py
?? agent_core/hardened_executor.py
?? agent_core/hypothesis_engine.py
?? agent_core/model_roles.py
?? agent_core/phase2_campaign.py
?? agent_core/phase2_policy.py
?? agent_core/phase2_reporter.py
?? agent_core/phase2_store.py
?? agent_core/policy.py
?? agent_core/priority_engine.py
?? agent_core/rate_limit_enforcement.py
?? agent_core/recovery_state_enforcement.py
?? agent_core/request_budget.py
?? agent_core/route_identity.py
?? agent_core/runtime_binding.py
?? agent_core/session_invalidation.py
?? agent_core/verification_gate.py
?? agent_core/verification_planner.py
?? agent_core/verification_registry.py
?? campaign_cli.py
?? config/contexts/bola-lab.json
?? config/contexts/public-site.json
?? config/policies/auth-lab-phase2.json
?? config/policies/auth-lab-policy.json
?? config/policies/bola-lab-policy.json
?? config/policies/mass-assignment-lab-policy.json
?? config/policies/nerminzlatanovic.json
?? config/policy-host-mappings.json
?? context_cli.py
?? docs/ADAPTIVE_AGENT.md
?? docs/CAPTURE_CAMPAIGNS.md
?? docs/PHASE2.md
?? docs/PHASE2_COMPLETION_AUDIT.md
?? eval_cli.py
?? evaluation/__init__.py
?? evaluation/fixtures/authorization.jsonl
?? evaluation/lab.py
?? evaluation/replay_app.py
?? examples/capture-context.example.json
?? examples/capture.example.http
?? examples/policy.example.json
?? injection_cli.py
?? mutation_cli.py
?? phase2_cli.py
?? policy_cli.py
?? tests/test_agent_architecture.py
?? tests/test_api_surface_discovery.py
?? tests/test_auth_semantic_discovery.py
?? tests/test_authenticated_injection_verifier.py
?? tests/test_authentication_enforcement_runtime_binding.py
?? tests/test_capture_verification_orchestrator.py
?? tests/test_controlled_session_acquisition.py
?? tests/test_mass_assignment_execution.py
?? tests/test_nuclei_policy.py
?? tests/test_openapi_route_preservation.py
?? tests/test_phase2_adaptive_engine.py
?? tests/test_phase2_campaigns.py
?? tests/test_phase2_scan_integration.py
?? tests/test_policy_profiles.py
?? tests/test_rate_limit_enforcement_execution.py
?? tests/test_recovery_state_enforcement_execution.py
?? tests/test_report_grounding_regressions.py
?? tests/test_request_mutation_engine.py
?? tests/test_session_invalidation_execution.py
?? tests/test_vertical_authorization_runtime_binding.py
?? tests/test_workflow_finding_export.py
?? tools/api_metadata_discovery.py
?? tools/api_target_analyzer.py
?? tools/authenticated_injection_verifier.py
?? tools/openapi_surface_analyzer.py
?? tools/request_mutation_engine.py
?? verification_inputs/captures/.gitkeep
?? verification_inputs/contexts/.gitkeep
?? verification_inputs/temporary/.gitkeep
```

## 13. Phase 2 completion score

The 68% score below is the original independent-audit score and is intentionally not recalculated by the P0-1 implementation pass.

| Dimension | Weight | Score | Evidence | Remaining gap |
|---|---:|---:|---|---|
| A. Discovery/hypothesis architecture | 15 | 12 | 30 implemented categories, deterministic IDs, canonical/capture sources, semantic workflow evidence, dynamic priority | Duplicate generator families; selected policy/ledger begins after discovery |
| B. Verification planning | 10 | 8 | Category-aware bounded plans, expected secure/vulnerable outcomes, cleanup and context preconditions | Fallback plans overstate executability; some request-cost/auto flags do not match runtime workflows |
| C. Typed controlled execution | 20 | 13 | Eleven routed categories; four strong strict workflows; exact runtime binding for authz/session/recovery | Generic four-category inputs/proofs are weak; 19 categories remain plan-only; alternate executor family is not unified |
| D. Policy/safety enforcement | 15 | 10 | Strong deterministic typed gates; no generic DELETE, spray, brute force, DoS, or arbitrary recovery/mutation route | Discovery/capture bypass selected policy; allowlist/concurrency/OAST behavior is inconsistent |
| E. Evidence/classification quality | 15 | 10 | Stateful workflows require independent evidence; no active status-only verified route | Command reflection and SQL truthy flag can verify; BOLA/tenant rejection baseline and service-failure normalization need work |
| F. Secret handling/controlled context | 10 | 6 | Process-local vault, missing/discarded refs fail closed, recovery/rate raw values staged | Embedded header strings can persist; over-redaction loses safe telemetry; recovery public-state and email identity mismatch |
| G. Run/campaign/provenance | 5 | 3 | Ordered run IDs, target validation, final typed precedence, rejected results retained | Run overwrite/history mutation; ambiguous result refs; no executor version/hash; target equality is redaction-canonicalized |
| H. Request accounting/metrics | 5 | 2 | Central typed ledger has categories and hard pre-request consumption | Discovery missing/late, cumulative-vs-delta confusion, auth/acquisition omissions, recovery campaign over-attribution |
| I. Tests/CLI/documentation | 5 | 4 | 494 passing tests, all requested quality gates pass, extensive Phase 2 docs and executor tests | No parity or boundary regression suite; docs overstate shared budgets and secret guarantees |
| **Total** | **100** | **68** | Substantial controlled verification foundation | Three safety P0s and six freeze-quality P1s remain |

## 14. Remaining issues and blockers

All identified gaps are grouped below so every issue has an owner and severity. There are exactly **3 P0 tasks and 6 P1 tasks** that should be completed before freeze.

### P0 — Phase 2 cannot safely freeze (3)

#### P0-1: Put all network discovery and capture execution under one selected policy and live ledger — COMPLETE

- Implementation: `WorkflowManager` now resolves the selected `AssessmentPolicy`, authorizes the scan target, creates one `RequestBudget`, and constructs one `ScopedHTTPClient` before `ToolRunner`. The same ledger instance is passed into `AdaptiveAssessmentOrchestrator.run_phase2` and the controlled verification transport. No later Phase 2 ledger or retrospective discovery clamp is created.
- Attempt semantics: the shared client performs policy, purpose/technique/OAST, exact URL, method, exclusion, Host/proxy binding, concurrency, DNS preparation, and rate checks before atomically consuming global and per-host budget immediately before one requester call. Authorized transport exceptions are charged. Policy, budget, DNS, OAST, and concurrency denials before requester dispatch are not charged. There are no retries.
- DNS: lookups are classified as transport preparation, not HTTP ledger events. Explicit DNS discovery validates the selected policy and unchanged target hostname; request-time resolution runs under the concurrency slot. Redirect destinations receive a new authorization check before the next attempt.
- Capture disposition: `campaign_cli.py --execute --authorized` and `CaptureVerificationOrchestrator.run_campaign` are Phase 2 plan/offline-only and return zero requests. This path cannot execute weaker active traffic.
- Registered ToolRunner disposition: seven target-network entries are adapted (`dns_lookup`, `http_probe`, `security_headers_checker`, `tech_fingerprint`, `api_metadata_discovery`, `js_secret_scanner`, `api_object_discovery`); ten legacy/subprocess target-network entries fail closed (`katana_crawl`, `nuclei_scan`, `jwt_replay_checker`, `graphql_introspection_checker`, `request_replay_engine`, `authenticated_injection_verifier`, `request_mutation_engine`, `capture_verification_orchestrator`, `workflow_replay_checker`, `upload_replay_checker`); `ai_report_writer` is forced to its deterministic offline fallback in a policy-bound scan. `HardenedExecutor` also refuses target-network subprocess execution because it cannot preserve the live in-process ledger.
- Direct primitive audit: the reachable `requests` calls in adapted discovery go through the injected shared client; controlled verification uses the same client. Direct request/subprocess implementations remain only behind the fail-closed registry disposition, the disabled capture executor, or non-scan utilities (`doctor`, unregistered `httpx_probe`). Known reachable Phase 2 network bypasses: **0**.
- Regression evidence: 17 new collected cases cover pre-discovery policy/ledger construction, unauthorized/out-of-scope/wrong-scheme/wrong-port/disallowed-method/excluded-asset zero-transport denials, global and per-host N+1 prevention, failed-attempt charging, blocked-request non-charging, shared discovery/auth/verification ledger identity, discovery depletion of verification budget, active `max_concurrency=1`, discovery rate limiting, OAST denial, capture plan-only behavior, registry disposition, and no-retry behavior. Existing session, recovery, rate-limit, mass-assignment, BOLA, and related suites remain green.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **511 passed**.
- Compatibility change: ordinary scan syntax remains available and selects a narrow runtime policy when no policy file is supplied. Registered network tools without a shared adapter no longer execute through `ToolRunner`; subprocess discovery (`katana`, `nuclei`) fails closed, the bounded Python crawler remains the policy-aware discovery fallback, external AI reporting uses deterministic fallback, and capture `--execute` is plan-only.

#### P0-2: Strictly type every proof-controlling executor input and remove weak verification predicates — COMPLETE

- Strict input boundary: BOLA, tenant isolation, vertical authorization, authentication enforcement, SQL injection, command injection, and path traversal now use category-specific, extra-forbidden strict models. Protected-field paths are bounded and canonicalized; lists, nested parameter bindings, booleans, strings, and compatibility URL overrides are strict. Numeric/string boolean coercion, unknown fields, malformed selectors, wrong containers, and ambiguous bindings stop with zero requests. The existing mass-assignment, session-invalidation, recovery-state, and bounded-rate-limit models were tightened where numeric literal equality had still accepted `1` as `true`.
- Observable authorization evidence: caller confirmation fields remain compatibility-only and cannot establish proof. BOLA/tenant require a successful owner response containing the exact controlled object (and exact controlled tenant for tenant isolation) plus every configured protected path. Candidate denial is `rejected` only after that baseline; otherwise it is `inconclusive`. Vertical authorization requires the protected privileged baseline and exact lower-role value/hash correlation. Authentication requires the protected authenticated baseline and matching evidence in the credential-free response; an unauthenticated `200` without protected evidence is inconclusive.
- Injection and traversal binding: one typed parameter-location vocabulary is used by hypotheses, plan actions, and runtime probe input. The current automatic adapter supports query parameters only, validates hypothesis/plan/caller binding, constructs all three exact mutations before traffic, and returns `manual_adapter_required` with zero requests for unsupported or mismatched locations. The planner no longer marks unsupported locations automatically executable.
- Weak predicates removed: SQL caller semantic confirmation is strict but compatibility-only and cannot verify; the present bounded SQL differential therefore remains inconclusive without independent SQL-evaluation evidence. Command injection uses a stable control/probe/control sequence and an execution-derived marker absent from the literal probe; the former `CCX_CANARY` reflection route cannot verify. Traversal requires stable controls, exact mutation, a server-side fixture marker absent from the probe, and no reflected probe literal. All automatic probe proof also requires three successful observations.
- Correlation and registry: evidence correlation requires `analysis.verified is True` and cannot promote inconclusive or truthy metadata. `agent_core/verification_registry.py` is explicitly legacy/offline-only, has no registered adapters, always returns `manual_adapter_required`, and is not imported by either active Phase 2 CLI.
- Regression evidence: 36 dedicated P0-2 cases cover strict boolean/container/extra/path rejection, zero-transport malformed input, BOLA/tenant owner-baseline rules, exact tenant/object correlation, vertical/authentication protected baselines, SQL caller assertion/reflection/instability, command reflection/derived marker/control contamination, traversal reflection/server fixture evidence, parameter-location binding, registry quarantine, and correlation non-promotion. Existing mass-assignment, session-invalidation, recovery-state, and bounded-rate-limit workflows remain green.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **547 passed**.
- Compatibility change: invalid or coercible generic inputs now fail before traffic; unsupported probe locations require a manual adapter; SQL verification is more conservative; and BOLA/tenant denial without a valid protected owner baseline is now inconclusive.

#### P0-3: Enforce one context-aware sanitizer and private recovery-state boundary at every persistence/output edge — COMPLETE

- Canonical boundary: `agent_core.result_normalizer.public_result` now provides the one recursive public serializer; the existing `redact` entry point delegates to it. It handles mappings, bounded containers, nested models, scalar telemetry, URLs, exceptions, and arbitrary diagnostic strings. Semantic secret keys and bounded embedded-value rules remove Authorization/Proxy-Authorization credentials, Cookie/Set-Cookie values, password/recovery/session/token/API-key material, JWT compact values, vault handles, and credential-bearing query values. Tool normalization, audit logging, workflow diagnostics, run/latest persistence, controlled public recovery output, both CLIs, campaign storage/export, capture-campaign reports, benchmark/finding aggregation, Phase 2 Markdown, and AI grounding/evidence/rendering use this boundary.
- Safe evidence retained: strict nonnegative request/count/field telemetry remains numeric even when its key contains `password`, `token`, or `credential`; booleans remain safe telemetry. Explicit cookie metadata retains names/count/presence and security attributes without values. The explicit JWT safe-field allowlist retains counts, source, algorithm/type, claim names, expiry observations, verification status, and structural booleans while dropping raw token, signature, and claim values.
- Private recovery state: the controlled executor now strips `preserved_challenge` structurally from every returned result and reads it only through a recovery-state store. Active scan and standalone verification use a `.private` record keyed by a deterministic hash of the bounded run/hypothesis references; its directory/file modes are `0700`/`0600`. The strict record contains only the challenge identifier, consumed bit, and account/workflow/hypothesis/run bindings—never codes, passwords, sessions, or vault contents. A process-private store covers non-persisted library execution. Missing, invalid, wrong-run, or consumed private state fails closed; the issue, resume, mandatory cleanup, and final classification lifecycle remains operational.
- Public separation: ordinary run JSON and `latest.json` cannot contain the private record. Agent/Phase 2 CLI output, campaigns, benchmark/finding exports, standalone/integrated Markdown, AI prompt/evidence input, and public diagnostics all receive structurally public data; exporters never traverse the private directory. Existing report content is re-sanitized before Phase 2 integration.
- Regression evidence: 7 new cases plus extended recovery/CLI assertions seed six unique sentinels through nested models, headers, cookies, URLs, exceptions, run/latest, agent/Phase 2 CLI objects, campaigns/findings, benchmark output, Markdown, AI grounding/rendering, vault handles, and every recovery stage. Recursive serialization finds zero sentinels in public artifacts. Tests also prove safe JWT/cookie/numeric telemetry, restrictive private permissions, resume/cleanup preservation, missing-state failure, binding-tamper rejection, and one-time challenge consumption.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **554 passed**.
- Compatibility change: public and stored JSON are now more strictly sanitized. Recovery resume is unchanged at the command level, but its resumable challenge record is no longer present in ordinary public run data.

### P1 — should fix before Phase 2 freeze (6)

#### P1-1: Define a canonical per-result request delta and use it everywhere — COMPLETE

- Canonical contract: `agent_core.request_budget.RequestDelta` is a frozen, extra-forbidden, strict-integer model with nonnegative `discovery`, `auth`, `verification`, `cleanup`, `attempted`, and `total` fields. `total` must equal the four categorized counts. Because the P0-1 ledger consumes immediately before transport, `attempted == total`; authorization, scope, concurrency, DNS, and budget denials before transport are zero.
- Attribution boundary: `ControlledVerificationExecutor.execute` takes authoritative ledger snapshots immediately before and after every result and derives the delta from their monotonic difference. All 11 executable categories use this one wrapper, so on-demand logins, owned-object acquisition, verification probes, authorized transport exceptions, and network cleanup are included without copying global discovery or earlier result traffic.
- Cleanup rule: mass-assignment restoration `PATCH` and independent confirmation `GET` are `cleanup`. Recovery challenge/comparison operations remain `verification`, comparison-password confirmation is `auth`, and the final original-password restoration confirmation is `cleanup` while retaining typed session-acquisition authorization. Session vault discard is local and remains zero network cleanup.
- Compatibility and typed detail: every new executable result sets `requests_used = request_delta.total`. Bounded rate limiting derives its baseline/invalid/final typed counts from the authoritative auth delta (`N=3` produces auth/total 5). Cumulative `request_budget` snapshots remain whole-ledger diagnostics and are not used as per-result cost.
- Consumers: standalone verification metrics consume the delta; scan run metrics remain authoritative whole-run ledger totals. Campaign and benchmark findings use the selected result's delta. Recovery additionally exposes `workflow_request_total` as the sum of linked stage deltas instead of overloading `requests_used`. Reports label whole-run totals separately from result cost. Old files are not rewritten; exporters accept explicit legacy `requests_used` or typed `total_network_requests` with a marked legacy source and do not infer precision from cumulative budget snapshots.
- Regression evidence: strict model/invariant/frozen tests, all-executor wrapper coverage, global-discovery and earlier-result isolation, policy/budget zero-delta behavior, charged transport exceptions, typed cleanup authorization, BOLA/tenant/vertical/auth/session/mass/recovery/rate/injection attribution, standalone/scan-equivalent result shapes, campaign/benchmark canonical totals, recovery stage totals, and sanitizer retention of secret-named numeric metrics are covered.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; the final suite count is recorded in the implementation handoff.
- Compatibility change: new results add `request_delta`; prior category-local `requests_used` values change to the complete per-result network cost. Recovery selected-stage cost and cumulative workflow cost are now separate fields.

#### P1-2: Make run/result provenance append-only and unambiguous — COMPLETE

- Persistence model: the first snapshot remains `<run_id>.json`; later activity creates atomically published `<run_id>.revision_<n>.json` files. Previously persisted results must remain an identical ordered prefix, conflicting result content/identity fails closed without corrupting history, and identical saves are idempotent. `latest.json` remains a replaceable convenience view only.
- Result provenance: every newly persisted result receives a stable random `res_<32 lowercase hex>` ID, `result_schema_version: 2`, explicit `ControlledVerificationExecutor` name plus `<category>/v1` contract version, and a deterministic `sha256:` hash of canonical public-sanitized result JSON. The hash includes classification/evidence, runtime and target surfaces, P1-1 `request_delta`, workflow stage, and executor contract while excluding recursive ID/hash metadata and all private recovery/secret material.
- Recovery/history: issue, resume/pending-cleanup, and final recovery classifications append distinct public result events. Earlier stages remain byte-for-byte addressable; only the separate P0-3 private resume record is consumed or updated.
- References/consumers: campaign, benchmark/finding, standalone verification output, and technical report evidence now carry or display exact `run_id + result_id + result_hash` provenance (with hypothesis ID and executor version where appropriate). The resolver may select a later stronger/terminal result under existing status semantics, but an older exact reference continues to resolve and hash-check unchanged content.
- Target binding: run/campaign creation computes a `sha256:` fingerprint from the exact normalized target before redaction; scheme/host case, default ports, root slash, query ordering, and fragments are normalized while query values/user-info remain identity-bearing. Public targets stay sanitized, and campaign equality uses the fingerprint so different hidden secret values cannot collapse.
- Legacy/compatibility: historical files are not rewritten. Legacy runs/campaigns remain readable/exportable and are marked `legacy_unversioned`; missing historical IDs, hashes, executor versions, and target fingerprints are not fabricated. New references add result ID/hash and new same-run activity creates immutable revision files.
- Regression evidence: focused cases cover deterministic/content-sensitive hashing, executor/schema provenance, idempotence, conflict refusal and atomic history preservation, multiple results for one hypothesis, immutable recovery stages, exact lookup/hash checking, campaign stability, benchmark/finding/report propagation, stored request-delta preservation, exact confidential target matching/normalization, legacy behavior, and sentinel-secret exclusion from public records/hash inputs.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **583 passed**.

#### P1-3: Make standalone verification and scan verification behaviorally equivalent — COMPLETE

- Shared boundary: `agent_core.verification_runtime.VerificationRuntime` and `create_verification_runtime` are visibly reused by `phase2_cli.py verification run` and `agent.py scan --mode verify`. The boundary begins after scan discovery and hypothesis selection; scan-only discovery stays in whole-run metrics and is not attributed to a result.
- Policy/transport: one policy-context builder supplies current target-class, controlled-account/object, acquisition, session, and replay semantics. Standalone builds a policy-bound `ScopedHTTPClient`; scan injects its existing P0-1 authoritative-ledger client into the same runtime. The runtime rejects a different policy object, ledger, context, or client type, leaving no CLI-specific typed-verification client.
- Response/credential parity: the one adapter preserves status/status class, body, content type, allowlisted Retry-After and rate-limit headers, elapsed milliseconds/coarse latency input, safe cookie attributes, and transport errors. It strips anonymous/session-acquisition/rate-limit credential headers, clears ambient cookie jars before and after every typed request, disables redirects, and uses the same timeout and policy-aware transport rules in both paths. Raw Authorization, Cookie, and Set-Cookie material remains governed by the P0-3 public serializer.
- Input/recovery/result parity: both paths stage rate-limit and recovery secrets through the same vault helper, select defaults/per-hypothesis input identically, use the same `ControlledVerificationExecutor`, private recovery store loader, RequestDelta snapshot wrapper, status allowlist, public serializer, executor/schema provenance, target identity contract, and append-only `Phase2RunStore` format.
- CLI compatibility: existing `--lab` behavior remains; both scan and standalone commands also accept the mutually exclusive `--dedicated-lab` alias and normalize these to the canonical internal target class.
- Regression evidence: a dedicated shared-runtime suite covers the same runtime/policy/context/transport/private-store contract for all 11 executable categories, response and rate-limit header/latency parity, cookie and Authorization isolation, malformed zero-traffic input, policy/budget denial, charged transport exceptions, recovery prior-state selection, RequestDelta/public result equivalence, and equivalent persisted hashes/provenance. Existing controlled-session, recovery, rate-limit, scan-integration, request-accounting, P0, and provenance suites remain green.
- Source inspection: active CLI typed verification constructs only `VerificationRuntime`; the sole active typed adapter is `VerificationHTTPTransport` over `ScopedHTTPClient`. Other scoped clients remain discovery/capture/tool-runner infrastructure outside the post-selection typed-verification boundary.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **608 passed**.

#### P1-4: Normalize policy account allowlists and login identity semantics — COMPLETE

- Canonical account contract: `AssessmentPolicy.account_is_eligible` returns one typed, secret-free decision. Empty `controlled_account_ids` means no additional account-ID restriction beyond `controlled: true` accounts in the supplied `ControlledContext`; a non-empty list intersects with that controlled set. Neither form can permit an unknown or uncontrolled account.
- Exact binding retained: BOLA owner/comparator, tenant metadata/object consistency, vertical role ordering, single-account recovery/session/rate binding, ownership, credentials, cleanup, scope, and budget gates remain separate and fail closed.
- Canonical identity contract: `resolve_controlled_login_identity` accepts a controlled account, an explicit session/workflow identity semantic, and the process-local `CredentialVault`. Only `email` and `username` are supported. It prefers the declared field's live vault reference, then the other controlled identity reference; it never derives, transforms, guesses, or enumerates an identity.
- Vault and public-state behavior: missing/discarded identity and password references and unsupported identity fields stop before transport. The typed binding exposes only `identity_bound` and the safe `email`/`username` source label; raw identities, passwords, vault handles, and session tokens do not enter public results or provenance.
- Executor migration: all 11 executable categories receive account decisions through the canonical helper. Ordinary authorization acquisition, session invalidation, recovery, and rate-limit login construction use the shared resolver; email-only session invalidation now follows the same path as username-only acquisition.
- CLI/accounting compatibility: standalone verification and scan verification use the same `VerificationRuntime` policy context and therefore return identical eligibility decisions. Pre-transport identity/account blocks consume zero requests; successful session acquisition remains one `auth` request.
- Policy/context compatibility: existing empty-list policy profiles are not rewritten and now uniformly accept only supplied controlled-context accounts. Existing username+password and email+password contexts continue to work according to the configured login field, with deterministic declared-field preference when both identities exist.
- Regression evidence: a dedicated P1-4 matrix covers all 11 category gates; empty, explicit, excluded, and uncontrolled account combinations; BOLA/tenant/vertical two-account policy intersections; email/username preference and fallback; missing/discarded vault references; unsupported fields; zero-traffic blocks; session-invalidation identity variants; public secrecy; and shared-runtime CLI parity.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full `pytest`, and `git diff --check` pass; full suite: **691 passed**.

#### P1-5: Make planner/executor capability and cost metadata truthful — COMPLETE

- Authoritative registry: `agent_core.verification_capabilities` contains one
  strict, immutable entry for each of the 30 categories emitted by the hypothesis
  engine. Eleven entries are `typed_verification`; nineteen are `plan_only`.
  No category is described as production-ready. The older
  `agent_core.verification_registry` remains quarantined and disabled.
- Typed route truth: each typed entry binds the active
  `ControlledVerificationExecutor`, its category-specific `category/v1` P1-2
  provenance version, and its extra-forbidden strict input model. Plan-only
  entries declare no executor, input schema, executable requests, or automatic
  route. The executor category compatibility constant is derived from this
  registry rather than maintained independently.
- Planner/fallback truth: both planning paths source capability and request cost
  from the registry. Plan-only guidance carries `capability_state=plan_only`,
  `typed_adapter_required=true`, zero executable request cost, and no fabricated
  network request sequence. Automatic execution means a real typed route exists
  and still depends on supported method/location, target class, explicit policy
  opt-in, controlled context, strict input, and runtime policy authorization.
- Request-cost truth: BOLA and tenant are 2–5; vertical authorization 2–4; mass
  assignment 5–6; authentication enforcement 2–3; session invalidation 4; full
  recovery 1–5 across issuance/resume/cleanup; bounded rate limiting 3–7 using
  `N + 2` for `1 <= N <= 5`; and SQL, command, and traversal are each 3–4.
  Bounds include optional controlled login and owned-object acquisition plus
  cleanup. Runtime input may narrow rate cost, never exceed the registry bound,
  and the controlled executor detects observed `RequestDelta` drift.
- Conservative coverage retained: SQL, command, and traversal advertise only
  GET query-parameter probes on explicit local/dedicated lab targets. Mass
  assignment advertises only its JSON scalar GET/PATCH restore workflow on an
  explicit local/dedicated lab. No adapter, payload family, category, or target
  scope was expanded.
- Consumer migration: hypothesis metadata, priority scoring, both planners,
  adaptive preflight, standalone runtime routing, CLI explain/plan views,
  Markdown reports, executor routing, and the generated `docs/PHASE2.md`
  capability table all read the same registry. Reports visibly distinguish
  `DISCOVERED`, `PLAN-ONLY`, and `TYPED VERIFICATION AVAILABLE`.
- Drift/compatibility evidence: tests enforce exact 30/30 category coverage,
  11/11 executor/schema/version mappings, no plan-only route, strict model
  bounds, canonical costs and dynamic formulas, fallback quarantine, priority
  cost use, orchestrator refusal, CLI/report truth, generated documentation,
  request-bound enforcement, P1-2 version alignment, and readability of legacy
  plans lacking capability metadata. Existing hypothesis IDs and commands are
  unchanged; historical stored runs are not rewritten.

#### P1-6: Normalize safe terminal classifications and deterministic failure reasons — COMPLETE

- Canonical contract: `agent_core.phase2_result_status` defines the sole new
  typed-result vocabulary. Terminal statuses are `verified`, `rejected`,
  `inconclusive`, and `policy_blocked`; recovery alone retains the explicit
  non-terminal states `awaiting_controlled_evidence` and
  `verification_pending_cleanup`. The strict decision model forbids extra
  fields and requires at least one sanitized deterministic reason.
- Shared boundary: all eleven categories pass through
  `ControlledVerificationExecutor.execute`, which derives the authoritative
  `RequestDelta` and normalizes internal workflow sentinels before executor
  provenance or immutable result hashing is attached. The standalone runtime,
  adaptive orchestrator, CLI persistence, and reports consume the same public
  status set rather than maintaining category-local terminal vocabularies.
- Policy and budget semantics: preflight authorization, scope, method, account,
  credential, object, state-change, cleanup-policy, rate-cap, unsupported typed
  surface, malformed-input, and pre-traffic budget denials are
  `policy_blocked`. Pre-traffic budget denial uses `Request budget is
  insufficient for the required verification sequence.` Partial workflows
  that cannot finish within budget are `inconclusive` with `Verification could
  not complete within the approved request budget.` Both preserve the exact
  request delta; no normalization step sends traffic.
- Evidence semantics: `verified` still requires the P0-2 category-specific
  positive proof predicate. `rejected` requires a demonstrated secure control
  and its valid category baseline. BOLA and tenant require an exact protected
  owner baseline; vertical, authentication, session, recovery, and rate checks
  retain their corresponding privileged/authenticated/pre-termination/workflow
  baselines. Missing or unstable baselines are inconclusive.
- Instability, transport, and cleanup: one base predicate handles malformed or
  unavailable response classes, explicit instability, and 5xx evidence.
  Instability cannot produce a positive or negative terminal conclusion.
  Allowed transport failures use an exception-independent safe reason and are
  inconclusive; shared-transport policy blocks remain policy-blocked. Required
  cleanup that cannot be independently confirmed is inconclusive, never
  verified/rejected, while existing cleanup-attempt/verified/failed booleans
  and recovery workflow phase remain available.
- Legacy quarantine and compatibility: the old offline verification registry
  remains disabled, and hardened subprocess statuses are local tool-runner
  envelopes rather than Phase 2 results. Legacy persisted results remain
  readable; new results cannot expose `budget_blocked`, `budget_exhausted`,
  `manual_required`, `error`, `failed`, `unknown`, or `cleanup_failed` as a
  terminal status. Recovery intermediate results remain immutable events and
  the campaign resolver continues to choose only completed
  verified/rejected/inconclusive results.
- Regression evidence: the dedicated terminal-classification suite covers the
  strict status sets, both budget phases, unsupported legacy vocabulary,
  deterministic/sanitized transport reasons, shared instability, cleanup
  demotion, authorization secure baselines, all eleven categories sharing the
  boundary, and status/reason participation in immutable result hashes.
- Quality evidence: `black .`, `ruff check .`, the requested `compileall`, full
  `pytest`, and `git diff --check` pass; full suite: **734 passed**.

### P2 — useful improvements that may move to a later phase (5)

1. Implement typed verifiers for selected plan-only categories only after the current safety boundary freezes; prioritize by real product requirements, not benchmark answers.
2. Consolidate duplicate capture/canonical category generation and legacy campaign code once the alternate path has first been made safe or disabled.
3. Add explicit DNS/transport-preparation telemetry and, if needed, a stricter non-HTTP network activity budget.
4. Add optional vault/session TTL metadata and external secret-store adapters; current missing/discarded references already fail closed.
5. Generate a machine-readable capability matrix and improve report/docs disclosure of plan-only versus executable maturity.

### P3 — future work (4)

1. Additional explicitly approved recovery comparisons and optional fully in-band cleanup workflows.
2. Recovery-endpoint rate-limit verification and broader safe bounded-control modes.
3. Broader role taxonomies and application-specific owned-object acquisition adapters.
4. UI/model-assistance/evaluation sophistication that does not change deterministic policy or evidence rules.

## 15. Phase boundary

1. **Is Phase 2 ready to freeze today? NO.**
2. **Exactly 9 P0/P1 tasks remain: 3 P0 and 6 P1.**
3. **Phase 2 is 68% complete.**
4. Defer new plan-only typed executors, broader recovery/rate modes, application-specific role/object adapters, external vault integrations, and UI/model sophistication to Phase 3 unless a listed P0/P1 minimally requires shared infrastructure.
5. Do not add hypothesis categories, exploit payload families, higher attempt caps, generic destructive/state-changing execution, benchmark-specific tuning, or unrelated UI/report features before the Phase 2 freeze.
6. Recommended sequence:

```text
Phase 2 Audit
     ↓
remaining P0/P1 fixes (3 P0, then 6 P1)
     ↓
full regression and repeated quality gates
     ↓
clean benchmark campaigns as external measurement only
     ↓
Phase 2 freeze/tag
     ↓
Phase 3
```

The freeze decision should be revisited only after all nine P0/P1 tasks have regression evidence and the clean campaigns are run without using benchmark ground truth to alter architecture or expected findings.

</details>
