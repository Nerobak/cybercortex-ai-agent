# Phase 3 Completion / Freeze Audit

Date: 2026-09-01

Branch reviewed: `develop-v3`

Frozen Phase 2 reference: `v2.1.0-beta-rc` / `c9b3fcc5df2695aeec8d832a271b7d543c23cae7`

Expected pre-audit suite: 1168 tests

## Executive summary

Phase 3 is substantially implemented and its model-facing security boundaries are
sound in the reviewed source. Provider responses are normalized, evidence crosses
the canonical Phase 2 public-result boundary, model output is parsed and
semantically validated, consensus remains advisory, and the only active Phase 3
submission call is the P3-4 call named `phase2_runtime.execute_selected`.

No model-output execution bypass, direct target HTTP transport, credential leak,
remote evidence sanitizer bypass, cleanup-barrier bypass, benchmark feedback loop,
or chain-of-thought persistence route was found. Phase 2 tracked implementation
files are unchanged from the frozen reference. Phase 3 does not import or construct
`ControlledVerificationExecutor`.

Phase 3 is not ready to freeze. Four P1 findings remain:

1. P3-6 case budgets can be exceeded by the first otherwise-permitted evaluation
   callback, with no failure recorded.
2. P3-4 loses target-request delta attribution if the Phase 2 runtime raises or
   returns a malformed result after consuming requests.
3. P3-6 collapses multi-iteration autonomy provenance and several decision metrics
   to the latest decision.
4. P3-4 recognizes the authoritative Phase 2 runtime only by a forgeable marker
   and method shape, rather than a production identity or trusted construction
   boundary.

These findings do not give model text execution authority. They do prevent a freeze
recommendation and prevent controlled autonomy or external benchmark readiness.
One-provider-at-a-time, tightly bounded provider smoke tests are architecturally
reasonable after operator configuration; no such test was performed in this audit.

Audit completion assessment: **94%**. This is a readiness assessment over the
Phase 3 requirement matrix, not a security score or a model-quality score.

## Scope and method

The review covered all Python modules under:

- `agent_core/models/` (P3-1 and P3-2)
- `agent_core/reasoning/` (P3-3)
- `agent_core/autonomy/` (P3-4)
- `agent_core/consensus/` (P3-5)
- `agent_core/model_evaluation/` and `model_eval_cli.py` (P3-6)
- the six Phase 3 test modules and `docs/PHASE3.md`

The audit used source tracing, exact dependency scans, existing sentinel tests,
small in-memory diagnostic constructions, the complete test suite, and all required
quality gates. It did not access `~/cybercortex-range`, hidden benchmark fixtures,
or benchmark ground truth. It made no provider or target network call.

No fixes or features were implemented. This document is the only file created by
the audit.

## Architecture reviewed

The reviewed provider/reasoning path is:

```text
Provider SDK/HTTP response
  -> provider adapter
  -> strict ModelResponse
  -> deterministic ModelRouter and ModelCallLedger
  -> strict JSON ReasoningCandidate parser
  -> Phase 2 catalog/policy semantic validator
  -> advisory ReasoningDecision
```

The reviewed consensus/orchestration path is:

```text
canonical sanitized ReasoningRequest
  -> independent P3-3 decisions
  -> structured agreement/arbitration
  -> ConsensusDecision
  -> revalidated P3-4-compatible ReasoningDecision
  -> ExecutionDecisionGate
  -> phase2_runtime.execute_selected
  -> Phase 2 VerificationRuntime policy/gate/executor/transport
  -> canonical public Phase 2 result and RequestDelta
```

`ReasoningDecision` and `ConsensusDecision` have no `execute` method. P3-5 has no
call to `execute_selected`. P3-6 observes normalized artifacts and has no Phase 2
executor or target-transport import.

## Security invariant results

| Invariant | Result | Evidence |
|---|---:|---|
| Model decision is not execution authorization | Pass | Strict parser and semantic validator precede the P3-4 gate; decisions have no execution method. |
| Phase 2 remains final execution authority | Pass, with P1 assurance gap | The sole active P3 submission is `agent_core/autonomy/orchestrator.py:334`; runtime identity is only structurally checked (P1-04). |
| Provider-specific objects do not escape adapters | Pass | Adapters immediately build `ModelResponse`; router rejects non-normalized/mismatched objects. |
| Remote evidence uses canonical public boundary | Pass | `ModelRequest` requires equality with `public_result`; `from_phase2` and reasoning evidence builders apply it before prompt construction. |
| Cloud consent and local routing are deterministic | Pass | Strict provider allowlist, route ordering, bounded fallbacks, and zero retries. |
| Model calls and target requests are distinct | Pass at type level; attribution gap | `ModelUsageDelta` and `RequestDelta` are distinct strict types. P1-02 can under-report target requests in an autonomy artifact. |
| Secrets and chain-of-thought are absent from public artifacts | Pass | Secret fields are excluded/redacted; histories omit prompts/raw responses; sentinel tests cover each Phase 3 layer. |
| Cleanup remains Phase 2-controlled | Pass | P3-4 observes canonical cleanup-pending state/reason and stops; it implements no cleanup transport. |
| Evaluation is measurement-only | Pass, with budget/provenance defects | No feedback/tuning API or execution import exists; see P1-01, P1-03, P2-01, and P2-02. |

## Findings

### P0 findings

None.

### P1-01 — P3-6 evaluation case budget is not an authoritative preflight

Severity: **P1 — must fix before Phase 3 freeze and real-provider evaluation**

Affected files:

- `agent_core/model_evaluation/runner.py:128-168`
- `agent_core/model_evaluation/runner.py:213-238`
- `tests/test_phase3_model_evaluation.py:697-736`

Evidence:

- The runner checks only usage already accumulated before the next repetition.
- It invokes the supplied evaluator without reserving the upcoming call, tokens, or
  cost and without binding the case budget into P3-2 routing.
- It accepts and aggregates the returned usage without verifying that the new total
  stayed within the case ceiling.
- An in-memory audit construction configured `max_model_calls=1`, returned one
  normalized fallback outcome containing two model attempts, and completed
  successfully with `model_call_count=2` and no failure.
- Existing tests prove only that an exact exhausted value blocks a subsequent
  repetition; they do not test overshoot by the permitted repetition.

Impact:

The declared P3-6 model-call, token, or cost limit can be exceeded by one evaluator
invocation. Because one invocation can represent a fallback or consensus sequence,
the overrun can exceed one physical call. Underlying P3-2 policies may impose a
separate limit, but P3-6 does not require those limits to equal the case limit.

Required remediation:

Make the case budget authoritative before provider work. Bind remaining case limits
into the P3-2/consensus policy used by the evaluator, reserve a conservative bounded
invocation, and reconcile ledger usage afterward. A post-call error alone is not
sufficient for monetary safety because spend has already occurred.

Remediation evidence (2026-09-02): **COMPLETE**

- Root cause: `EvaluationRunner` compared only previously returned usage with each
  ceiling. It neither reserved the pending invocation nor placed the remaining P3-6
  limits into the P3-2 and P3-5 policies supplied to that invocation, so one
  permitted callback could report a fallback/consensus usage delta beyond the case
  budget before the next-repetition check ran.
- `agent_core/model_evaluation/budget.py` now provides the single authoritative
  evaluation preflight. It groups cases by canonical reasoning `run_id`, intersects
  configured run limits, tracks cumulative usage, and performs deterministic input,
  output, total-token, call-count, and known/unknown-cost checks before invoking the
  evaluator.
- Every permitted callback receives an immutable remaining-budget grant: P3-2 route
  policies, fallback-attempt bounds, P3-5 consensus budgets, and P3-4 autonomy limits
  are reduced to the strict intersection of their configured ceilings and the
  authoritative evaluation allowance. Fallbacks and consensus participants therefore
  cannot acquire independent full budgets, and repeated cases sharing a reasoning
  run consume the same authority.
- Unknown pricing under a strict monetary ceiling rejects the callback before any
  provider call. Known pricing uses the configured maximum-output reservation; an
  exact fit is permitted and a one-over reservation is rejected.
- `EvaluationRunner` reconciles returned `ModelUsageDelta` values with the authority,
  normalizes any contract-breaking overshoot to the sanitized `budget_exhausted`
  failure, and emits zero usage/cost for a preflight-blocked call. Model-budget
  rejection does not mutate or consume Phase 2 `RequestDelta`, including dry-run
  evaluation.
- Seventeen focused regressions in `tests/test_phase3_model_evaluation.py` cover the
  exact and one-over boundaries for calls, deterministic input tokens, output
  reservation, total tokens, known cost, unknown strict cost, shared fallback,
  consensus and repeated-case budgets, dry-run enforcement, zero provider calls,
  unchanged `RequestDelta`, truthful failed/blocked usage, and the reported
  fallback off-by-one construction.

### P1-02 — P3-4 runtime failure can drop authoritative target request usage

Severity: **P1 — must fix before Phase 3 freeze or controlled benchmarking**

Affected files:

- `agent_core/autonomy/orchestrator.py:329-362`
- `agent_core/autonomy/orchestrator.py:647-687`

Evidence:

- `execute_selected` is called before P3-4 obtains `request_delta` from the returned
  result.
- If the runtime raises, or if `_canonical_phase2_result` rejects a malformed result,
  P3-4 records a failed iteration with the default zero `RequestDelta`.
- A Phase 2 transport can have consumed its authoritative budget before an
  unexpected runtime/result-normalization failure. That consumption remains in the
  Phase 2 ledger but disappears from `AutonomyRun.phase2_request_usage` and the
  orchestration history supplied to P3-6.

Impact:

Phase 2 still enforces its request budget, so this is not a request-budget bypass.
It is an accounting/provenance inconsistency: autonomy and evaluation reports can
understate target traffic on a failure path.

Required remediation:

Take before/after snapshots of the existing Phase 2 `RequestBudget` around every
runtime submission. Derive a strict `RequestDelta` on success and failure, reconcile
it with any returned canonical delta, and retain the failure-path delta without
creating a second request counter.

Remediation evidence (2026-09-02): **COMPLETE**

- Root cause: `AutonomousOrchestrator` previously obtained `RequestDelta` only from
  the value returned by `phase2_runtime.execute_selected`. A runtime exception or a
  later `_canonical_phase2_result` failure branched to the failed iteration before
  updating `AutonomyRun.phase2_request_usage` or
  `AutonomyIterationRecord.phase2_request_delta`, replacing traffic already consumed
  by Phase 2 with the default zero delta.
- Affected paths inspected: the sole P3-4 Phase 2 runtime submission; failures after
  controlled session/authentication, verification, and cleanup transport; returned
  result public normalization and identity/status validation; result-reference and
  execution-provenance construction; orchestration history recording; and P3-6
  autonomy observation/aggregation.
- Canonical accounting mechanism: P3-4 now snapshots the runtime's existing Phase 2
  `RequestBudget` immediately before `execute_selected`, snapshots that same ledger
  immediately after return or exception, and derives the authoritative categorized
  value with the existing `RequestDelta.from_snapshots`. It introduces no second
  request ledger and never derives traffic from status, exceptions, plans, model
  output, or estimated request cost.
- Failure behavior: the ledger delta is added to the in-memory autonomy run before
  result normalization, validation, provenance, or history processing. Runtime,
  malformed-result, validation, provenance, and history failures retain that delta,
  use only the deterministic `phase2_runtime_failed` P3 reason, create no fabricated
  Phase 2 classification/reference, and terminate without rerunning the verification.
  A returned canonical delta must exactly equal the ledger delta. Pre-transport gate,
  model-budget, autonomy-budget, and runtime-boundary failures remain zero traffic.
- Propagation: failed iterations retain the same delta in orchestration history;
  `observe_autonomy_run` carries the cumulative authoritative delta into failed P3-6
  outcomes, and target-request aggregation includes partial failed executions while
  `ModelUsageDelta` remains independent.
- Regression evidence: 38 focused cases across
  `tests/test_phase3_autonomy.py` and
  `tests/test_phase3_model_evaluation.py` cover zero-traffic failures, auth,
  verification, cleanup, partial and runtime failures, normalization/validation,
  provenance/history failure, malformed results, unchanged canonical
  classifications, no duplicate rerun, delta invariants, evaluation aggregation,
  accounting separation, private-data sentinels, deterministic failure reasons, and
  unchanged execution/runtime boundaries.
- Source inspection result: target-request attribution loss routes remaining: 0;
  alternate `RequestDelta` implementations: 0; direct executor bypasses: 0;
  alternate target HTTP transports: 0. The shared Phase 2 runtime remains the sole
  P3-4 execution route.

### P1-03 — Multi-iteration autonomy evaluation collapses provenance to latest

Severity: **P1 — remediated**

Status: **COMPLETE**

Affected files:

- `agent_core/reasoning/types.py`
- `agent_core/reasoning/engine.py`
- `agent_core/consensus/arbitration.py`
- `agent_core/autonomy/types.py`
- `agent_core/autonomy/history.py`
- `agent_core/autonomy/orchestrator.py`
- `agent_core/model_evaluation/types.py`
- `agent_core/model_evaluation/runner.py`
- `agent_core/model_evaluation/report.py`

Root cause:

- P3-4 assigned each new `ReasoningDecision` to the mutable convenience field
  `AutonomyRun.reasoning_decision`. Its history entry retained a decision reference,
  transitions, result reference, and accounting, but did not retain the complete
  sanitized decision/model/consensus and exact Phase 2 result identity snapshot.
- P3-6 iterated history for pivots but resolved provider, model, fallback, evidence,
  action, and decision-signature data from `run.reasoning_decision`. That made the
  observation internally inconsistent: usage could represent several calls while
  model provenance and several reasoning metrics represented only the last call.
- Run-level `verification_result_references` likewise did not bind each exact result
  to the decision, gate, request delta, and pivot from the iteration that produced it.
  Earlier references were not deleted, but their causal attribution was lost during
  evaluation/report construction.

Canonical iteration provenance:

- Every finalized P3-4 iteration now emits one frozen `AutonomyIterationRecord`.
  It snapshots the iteration and previous-iteration link, state transitions,
  requested route, exact decision ID and hypothesis ID, reasoning schema, actual
  route, fallback and model-call reference, selected action/capability, sanitized
  consensus ID/schema/participant decision references, gate outcome/reason, exact
  Phase 2 run/result ID/result hash/reference/executor/status where supplied by the
  canonical result, per-iteration `ModelUsageDelta`, per-iteration `RequestDelta`,
  pivot, terminal/failure reason, and timestamp.
- `ReasoningModelProvenance.requested_model` preserves the requested model at the
  provider boundary. It is optional when reading legacy decisions; the P3-4 snapshot
  uses the configured preferred model only for that legacy compatibility case.
- Failed reasoning attempts retain their requested route and ledger-derived model
  usage without inventing a decision or actual provider. Runtime failures retain the
  exact P1-2 request delta accumulated before failure. Dry runs retain decision,
  gate, proposed capability, model usage, and zero target requests without a
  fabricated Phase 2 result.
- The canonical JSON spelling for iteration target accounting is `request_delta`.
  `phase2_request_delta` remains a read/access compatibility spelling. This avoids
  misclassifying the numeric `auth` category as credential material at the public
  artifact boundary.

Append-only and exact-reference semantics:

- `AutonomyHistory.record` requires strictly increasing iteration numbers.
  `AutonomyRun.iteration_history` is extended by tuple append, and each nested record
  is frozen. Later decisions and results cannot mutate the semantic snapshot of an
  earlier iteration.
- Each iteration stores the exact `ReasoningDecision.decision_id`; consensus
  iterations also store the exact `ConsensusDecision.consensus_id`, schema version,
  participant decision IDs, and sanitized participant routes. No report-time lookup
  of a latest decision is used to resolve historical records.
- Executed iterations derive their result reference and exact stable Phase 2
  identity directly from the result returned for that execution. No latest-result-
  for-hypothesis lookup exists. Pivot records link the prior iteration/result to the
  next iteration, whose own snapshot identifies the newly selected hypothesis and
  decision.

Accounting and evaluation propagation:

- P3-4 recomputes run-level model and target-request totals as the sum of frozen
  iteration deltas. `ModelUsageDelta` and `RequestDelta` remain separate types and
  aggregation paths. The pre-record P1-2 request update is retained as a failure
  safety barrier; history reconciliation replaces it with the iteration sum and
  never adds the same request twice.
- `observe_autonomy_run` consumes embedded `AutonomyRun.iteration_history` as the
  canonical source, with the separately supplied `AutonomyHistory` accepted only
  when reading a legacy run lacking the embedded field. It derives decision/action/
  evidence/fallback metrics, exact routes, result classifications, successful
  pivots, model calls, target requests, and terminal stop reason from the complete
  history. The mutable final-decision and run-level result-reference conveniences no
  longer resolve any historical iteration.
- `EvaluationCaseOutcome.iteration_provenance` carries the complete sanitized
  snapshots into `EvaluationRun` and JSON output. Contract validation rejects
  outcomes whose decision metrics, routes, classifications, pivots, terminal reason,
  model usage, request usage, or result references disagree with that history.

Compatibility and sanitization:

- New provenance fields are optional for legacy deserialization. Existing
  single-iteration runs remain unchanged, and legacy external history is still
  observable. The final `AutonomyRun.reasoning_decision` and run-level aggregates
  remain convenience metadata but are not provenance authorities.
- Iteration/report contracts contain only public-safe IDs, counts, enums, hashes,
  routes, and sanitized references. They persist no prompt, provider response,
  rationale/chain-of-thought, credential, authorization value, cookie/session token,
  password, recovery secret, or private recovery state.

Regression and source-inspection evidence:

- Focused mocked regressions cover one/two/three iterations, earlier decision and
  result retention, exact decision/consensus/result identity, executor/status/
  hypothesis retention, per-iteration and aggregate accounting, failed/policy-
  blocked/runtime-failed iterations, non-execution actions, dry runs, all result-
  driven pivots, immutability, evaluation metrics, JSON propagation, compatibility,
  sensitive sentinels, and rejection of latest-only accounting. No provider, target,
  benchmark, or Ollama access is used.
- Latest-decision-only provenance routes remaining: **0**.
- Latest-result historical resolution routes remaining: **0**.
- Iteration overwrite routes remaining: **0**.
- Duplicate request aggregation routes remaining: **0**.

### P1-04 — Shared Phase 2 runtime identity is only duck-typed

Severity: **P1 — remediated**

Status: **COMPLETE**

Affected files:

- `agent_core/autonomy/runtime_binding.py`
- `agent_core/autonomy/decision_gate.py`
- `agent_core/autonomy/orchestrator.py`
- `tests/test_phase3_autonomy.py`
- `tests/test_phase3_consensus.py`
- `tests/test_phase3_model_evaluation.py`

Root cause and old forgeable mechanism:

- `ExecutionDecisionGate.evaluate` previously granted runtime-boundary status when
  `runtime.defers_runtime_policy_authorization is True` and a member named
  `execute_selected` was callable. `AutonomousOrchestrator` accepted and retained
  `phase2_runtime: Any` without a concrete-type or constructor-issued capability
  check.
- Any object, property, wrapper, callable, imitated class, or full-interface fake
  could copy that public boolean and method name. Once the remaining deterministic
  gate checks passed, the fake object's method became reachable through P3-4's sole
  execution-submission call. No model field supplied the object, but host dependency
  injection could accidentally or deliberately substitute a non-Phase-2 executor.
- The only P3-4 injection path is the `AutonomousOrchestrator` constructor. P3-6 is
  observation-only and has no runtime path. The authoritative Phase 2 construction
  used by stored-run CLI/scan execution is
  `agent_core.verification_runtime.create_verification_runtime`, which returns the
  concrete `VerificationRuntime` that owns Phase 2 policy, controlled context,
  credential vault, request ledger, capability registry, executor resolution, and
  scoped transport.

New authoritative binding:

- P3-4 now passes every supplied runtime through the single
  `bind_authoritative_phase2_runtime` path. Binding requires exact concrete identity
  (`type(runtime) is VerificationRuntime`); subclasses, protocol-shaped objects,
  wrappers, class-name imitations, arbitrary callables, and copied marker values are
  rejected. The old marker is no longer consulted by any Phase 3 authority decision.
- Successful validation issues a sealed, process-local
  `AuthoritativePhase2RuntimeBinding` using a private identity object. Its constructor
  cannot be called without that identity, its exact type is revalidated in the gate,
  and it cannot be subclassed, shallow/deep copied, pickled, or JSON serialized. It
  exposes only the existing policy/context/vault/ledger references and a narrow
  `submit` operation captured from the genuine Phase 2 runtime. It does not create a
  runtime, executor, policy implementation, request ledger, controlled-context
  implementation, or transport.
- Invalid constructor injection is normalized to a private unbound sentinel. After
  the validated `ReasoningDecision` and deterministic capability checks, the P3-4
  gate rejects it as `runtime_boundary_invalid` before reading runtime policy state,
  taking a request snapshot, or submitting execution. The run stops deterministically
  for manual review with zero target requests, no fallback, and no retry using a
  weaker check.

Legitimate test seam and construction behavior:

- Tests use `authoritative_test_runtime`: it calls the genuine Phase 2 factory and
  injects a scripted subordinate `execute_selected` callable into that exact concrete
  instance before P3-4 issues the sealed binding. This is a deliberate
  injected-callable-beneath-genuine-wrapper seam; arbitrary mock objects never gain
  production authority. No test performs provider or target network traffic.
- Production P3-4 performs no runtime construction of its own. Its only path is a
  concrete `VerificationRuntime` supplied to `AutonomousOrchestrator`, followed by
  the one sealed binding factory. Phase 2 CLI and scan construction remain unchanged.
- Runtime authority is provider-independent. OpenAI, Anthropic, Ollama, fallback,
  and consensus decisions all reach the identical gate and sealed Phase 2 binding;
  no model or consensus field can select a runtime, executor, callable, import path,
  or transport. Dry-run validates the same binding but never calls `submit`.

P1-2, P1-3, and independent Phase 2 enforcement:

- Invalid bindings never reach the Phase 2 request ledger and retain a zero
  `RequestDelta`. A valid bound runtime that consumes traffic and later fails still
  uses the P1-2 before/after ledger snapshots, so partial failure deltas survive.
  `ModelUsageDelta` remains separate.
- P1-3 iteration history still records the sanitized decision, gate outcome,
  result/executor references, request/model deltas, pivot, and terminal reason. The
  binding, private issuer, runtime object, and callable are not fields in reasoning,
  consensus, autonomy, or evaluation contracts and never appear in JSON reports.
- The P3-4 binding proves only runtime identity; it does not authorize the operation.
  The existing Phase 3 deterministic preflight remains in place, and the genuine
  `VerificationRuntime.execute_selected` still independently resolves the capability
  and applies the Phase 2 policy gate, scope, controlled context, credentials, state
  change, cleanup, test-owned object, request ledger, executor, and scoped transport.
  No frozen Phase 2 implementation was modified.

Regression and source-inspection evidence:

- Focused offline regressions cover genuine factory runtime acceptance, the
  legitimate seam, old/copied marker attacks, method/full-interface/class-name/
  callable/wrapper/subclass attacks, constructor and copy/serialization resistance,
  deterministic zero-request failure, no retry/fallback, successful/policy-blocked/
  post-traffic behavior, P1-3 provenance, model/consensus/config isolation, evaluation
  isolation, dry-run, provider/fallback/consensus parity, and unchanged Phase 2
  policy/capability/context/budget/cleanup checks.
- The Phase 3 direct-route scan includes autonomy, reasoning, consensus, evaluation,
  and the evaluation CLI. `requests` matches only human-readable target-request
  accounting/report labels; there are no imports or calls for `safe_http`,
  `requests`, `httpx`, `urllib`, `aiohttp`, `subprocess`, `os.system`, `shell=True`,
  `eval`, or `exec`.
- Forgeable runtime identity routes remaining: **0**.
- Duck-typed production authority checks remaining: **0**.
- Alternate runtime construction paths remaining: **0**.
- Direct executor bypasses remaining: **0**.
- Alternate target HTTP transports remaining: **0**.
- Model-controlled runtime-selection routes remaining: **0**.
- Evaluation runtime bypasses remaining: **0**.

### P2-01 — Authoritative evaluation structural expectations — RESOLVED

Closure status: **PASS — targeted P2-1 closure on 2026-09-04**

Severity: **P2 — measurement correctness**

Affected files:

- `agent_core/model_evaluation/types.py:45-71`
- `agent_core/model_evaluation/runner.py:240-261`

Original evidence preserved:

`EvaluationCase.expected_structure` can declare minimum valid decisions, allowed
actions/capabilities, and required evidence references. `_validate_outcome` checks
identity, mode, local provenance, and public safety, but never evaluates those
expectations. A normalized callback can self-report counters that are unrelated to
the case expectations.

Original required remediation:

Derive applicable structural properties from normalized decisions/results, or
validate observer-produced outcome fields against the declared expectations with a
closed failure code.

Root cause:

- Structural declarations were defined by `ExpectedStructuralProperties` and stored
  only in `EvaluationCase.expected_structure`.
- Runtime classification was represented by the coupled
  `EvaluationCaseOutcome.success`/`failure_code` fields and finalized by
  `EvaluationRunner`; `_validate_outcome` checked identity, mode, local provenance,
  and sanitization only.
- No code joined the case declaration to the normalized decision, consensus,
  autonomy provenance, canonical Phase 2 status, `RequestDelta`, or
  `ModelUsageDelta`. Consequently a callback could complete successfully while its
  declared structure was absent or mismatched.
- Case success and human/JSON comparison output could therefore imply evaluation
  success without expectation satisfaction. There were no expectation pass/fail
  metrics. Reasoning, consensus, autonomy, request, and model-usage counters remained
  observations, but consumers had no authoritative indication that the case's
  required structure had been met.

Implemented closure:

- `ExpectedStructuralProperties` is now a strict closed model for deterministic
  public-safe checks: decision validity/action/capability/hypothesis/category,
  allowed actions/capabilities, valid-decision and evidence constraints, consensus
  agreement class, autonomy state/stop/iteration/verification/execution structure,
  canonical Phase 2 terminal status, target-request maximum, model-call maximum,
  and fallback use.
- `StructuralExpectationResult` records the expectation type, expected value,
  sanitized observed value, satisfaction boolean, and deterministic matched,
  mismatched, or unavailable reason. It cannot contain rationale prose, provider
  output, secrets, or chain-of-thought.
- Normalized observers expose only typed structural observations. P3-4 autonomy
  checks use complete canonical iteration history. Phase 2 expectations use only
  embedded `Phase2ResultProvenance.canonical_status`; no result is fabricated or
  reclassified. Target traffic uses only `RequestDelta.total`; model calls and
  fallback behavior use the separate `ModelUsageDelta`/model provenance contract.
- The runner applies every configured check once after runtime and budget
  normalization, including runtime-failure outcomes. `runtime_success` remains the
  runtime concept. `success` is true only when runtime succeeded and all configured
  expectations passed. An expectation mismatch has no runtime failure code and does
  not enter `EvaluationRun.failures`.
- Every outcome exposes `expectations_present`, `expectations_checked`,
  `expectations_satisfied`, complete `expectation_results`, and
  `failed_expectations`. No-expectation cases retain neutral `null` satisfaction and
  their prior success behavior.
- Aggregate metrics now report `cases_with_expectations`,
  `cases_expectations_satisfied`, `cases_expectations_failed`, and
  `expectation_pass_rate`. JSON includes the typed results; human and comparison
  reports show expectation satisfaction without inflating reasoning metrics.
- Checks are terminal measurements only. They do not alter prompts, routes,
  consensus, autonomy, Phase 2 policy/status, or trigger retry, rerun, or tuning.
- External aggregate baseline/benchmark imports remain aggregate-only and do not
  invent case expectations or read hidden benchmark truth.

Focused regression evidence: 44 P2-1 cases in
`tests/test_phase3_evaluation_expectations.py`, plus the existing P3 evaluation,
reasoning, consensus, and autonomy suites.

Source inspection after closure:

- Declared-but-unchecked structural expectation routes remaining: **0**.
- Case-success-with-failed-required-expectation routes remaining: **0**.
- Phase 2 status reinterpretation routes introduced: **0**.
- Expectation-driven tuning/rerun routes introduced: **0**.

P2-02 remains open and was not modified by this closure.

### P2-02 — Complete material configuration fingerprint — RESOLVED

Closure status: **PASS — targeted P2-2 closure on 2026-09-04**

Severity: **P2 — repeatability/provenance correctness**

Affected files:

- `agent_core/model_evaluation/runner.py:53-105`

Original evidence preserved:

The case fingerprint includes IDs, mode, hypothesis/category summaries, schema,
budgets, and repetitions, but omits `expected_structure` and the reasoning policy
constraints. An in-memory audit changed the minimum valid decisions and allowed
actions; the configuration fingerprint remained identical.

Original required remediation:

Include all public, behaviorally material evaluation configuration in the stable
fingerprint. Continue excluding credentials, private paths, raw prompts, and raw
evidence prose.

Root cause:

- `EvaluationRunner` called a hand-built `configuration_fingerprint` function that
  included Phase 3 schema numbers, the complete `EvaluationSubject`, and only a
  reduced case projection: case/task IDs, execution mode, hypothesis/category/
  capability-state references, capability schema number, case model/autonomy
  budgets, and repetitions.
- The projection omitted the complete P2-1 expectation model, detailed capability
  eligibility/schema/executor identity, reasoning policy constraints, prior-result
  and previous-decision semantics, evidence/request constraints, reasoning model
  budget context, evaluation output-token reservation, and pricing semantics.
  Changing any omitted value could therefore produce the same digest despite
  changing interpretation, validation, eligibility, or budget behavior.
- Reasoning request run IDs were not represented semantically even though equality
  between them controls cross-case evaluation-budget sharing.
- `compare_runs` did not trust or inspect the stored fingerprint at all. It used a
  smaller `_case_shape` of case/task/hypothesis/category references, so routing,
  consensus, autonomy, budget, capability, policy, and expectation differences were
  silently labeled compatible. External configuration references were opaque and
  absence of a verifiable fingerprint had no explicit compatibility state.

Implemented closure:

- `fingerprint.py` defines one strict persistable
  `MaterialConfigurationFingerprintSource` and canonical JSON serializer for
  fingerprint schema version 2 (`material-v2`). The lowercase 64-character SHA-256
  remains the digest format; `EvaluationRun.configuration_fingerprint_schema`
  distinguishes its semantics.
- Explicit completeness guards cover every field of `EvaluationSubject`,
  `EvaluationCase`, `ModelRoutingPolicy`, route/model/consensus budgets,
  `ConsensusPolicy`, `AutonomyLimits`, the P2-1 expectation model, reasoning request
  policy/history/budget inputs, evidence packets, prior results, capability catalog
  entries, and request accounting. A future strict-model field addition fails
  fingerprint construction until its material/excluded treatment is declared.
- Material inputs include subject/type/repetitions; normalized provider/model routes,
  ordered fallback chain, mode, allowlist, fallback triggers/attempts, and route
  budgets; consensus participant route set/policy/budget; autonomy and execution
  mode/limits; case IDs/task/repetitions/model/autonomy budgets; every structural
  expectation; capability schema, eligibility, request bounds, input-schema and
  executor versions; reasoning policy, previous-decision, prior-result, target,
  model-budget-context, and public evidence semantics; runner output reservation;
  and normalized pricing/alias configuration.
- Raw reasoning run IDs are replaced by deterministic budget-sharing group labels.
  Thus random ID values do not alter identity, but shared-versus-independent budget
  semantics do. Case order and consensus participant order are canonicalized because
  they are semantically unordered. Fallback order, evidence packet order, and prior
  decision order remain ordered because they can affect behavior. Set-like
  allowlists, fallback errors, allowed actions/capabilities, and policy category
  lists are sorted.
- Pydantic-resolved defaults make omitted and explicitly supplied equivalent defaults
  identical. Explicit `null` remains stable in canonical JSON.
- Public evidence/rationale/precondition text is represented only by deterministic
  public-safe SHA-256 content digests; raw prompt/evidence prose is not persisted in
  the source. Environment secrets, credentials, Authorization/cookies/sessions,
  passwords/recovery/private state, raw provider data, chain-of-thought, timestamps,
  evaluation/result IDs, temporary path values, actual usage/cost/latency, and runtime
  object identity are excluded. Provider transport timeout is not a field of the
  evaluation subject/case routing contract; the behaviorally material runner output
  reservation that is part of evaluation configuration is included.
- `compare_runs` now compares fingerprint schema and full stored identity, continues
  returning metric deltas for explicit cross-configuration analysis, and labels the
  pair `compatible`, `incompatible`, or `unknown`. The comparison table prints that
  state and reason.
- External baseline/benchmark records may preserve a paired supplied fingerprint and
  schema. Missing identity, legacy identity, or schema mismatch produces `unknown`;
  equivalence is never fabricated. Existing records without the new run schema field
  remain readable as `legacy-v1-incomplete`, and legacy identity is never treated as
  material-v2 compatible.

Focused regression evidence: 60 P2-2 cases in
`tests/test_phase3_evaluation_fingerprint.py`, plus existing P2-1 and P3 evaluation
coverage.

Source inspection after closure:

- Material configuration omissions remaining: **0**.
- Secret-bearing fingerprint inputs remaining: **0**.
- Unstable fingerprint inputs remaining: **0**.
- Comparison false-compatibility routes remaining: **0**.
- Legacy/new fingerprint ambiguity routes remaining: **0**.

P3-01 remains open and was not modified by this closure.

### P3-01 — Clarify endpoint locality in `local_only` documentation

Severity: **P3 — documentation/hardening enhancement**

Affected files:

- `agent_core/models/config.py:35-50`
- `agent_core/models/router.py:34-37`
- `docs/PHASE3.md`

Evidence:

`local_only` restricts the provider family to Ollama, while the configurable Ollama
base URL accepts any credential-free HTTP(S) origin. This meets the tested guarantee
of no OpenAI/Anthropic invocation but does not by itself prove host-loopback or
on-machine locality.

Deferred work:

Document whether `local_only` means “Ollama-family only” or “loopback/on-machine
only.” If the latter is required for private analysis, add an explicit trusted
endpoint-locality policy in a later authorized fix.

## Execution authority and direct-dependency audit

The explicit source scan searched Phase 3 for:

`ControlledVerificationExecutor`, `safe_http`, `requests`, `httpx`, `urllib`,
`aiohttp`, `subprocess`, `os.system`, `eval(`, `exec(`, and `shell=True`.

Manual interpretation:

- `agent_core/models/ollama_provider.py` imports `httpx` and posts only to the
  configured Ollama model API. This is a model-provider transport, not target
  security execution.
- `agent_core/models/config.py` imports `urllib.parse.urlsplit` for configuration
  validation; it performs no request.
- `agent_core/autonomy/orchestrator.py` has exactly one active submission call:
  `self.phase2_runtime.execute_selected(...)`.
- No Phase 3 source imports or instantiates `ControlledVerificationExecutor`,
  `ScopedHTTPClient`, target `safe_http`, `requests`, `urllib.request`, `aiohttp`,
  `subprocess`, shell execution, `eval`, or `exec`.
- No P3-3, P3-5, or P3-6 source invokes a security tool or Phase 2 executor.

Active bypass counts:

- model-output execution bypasses: 0
- direct security execution bypasses: 0
- Phase 2 policy/runtime bypasses: 0
- consensus execution bypasses: 0

P1-04 is reported separately as a trusted-composition assurance gap because the
host-supplied runtime is not model-controlled and no alternate runtime is wired in
the repository.

## Model output trust audit

The model trust chain is closed and deterministic:

1. Provider-specific responses are immediately converted to strict
   `ModelResponse` instances.
2. `ReasoningEngine` accepts only the normalized response content.
3. The parser accepts exact JSON only; no code-fence or best-effort extraction is
   performed.
4. `ReasoningCandidate` rejects unknown fields, unknown enum values, invalid ranges,
   URLs, command/tool/shell instruction patterns, and credential requests in
   authoritative narrative fields.
5. Semantic validation binds hypothesis IDs, capability IDs, categories, evidence
   references, request estimates, plan state, prior result status, and policy
   constraints to canonical Phase 2 truth.
6. Consensus groups only exact `(hypothesis_id, action, capability)` votes and maps
   its result back through the P3-3 semantic validator.
7. P3-4 independently gates typed capability, plan, policy, controlled context,
   credentials, state-change permission, cleanup, owned objects, budgets, and
   duplicate identity before the one runtime submission.

Free-form rationale is retained only as concise, sanitized advisory text. It cannot
be used as a URL, command, capability, policy override, context mutation, or
executor selection.

## Phase 2 boundary audit

No model-controlled path was found that bypasses:

- target scope or explicit authorization;
- Phase 2 request budgets;
- controlled account eligibility or credential references;
- state-change policy or capability-specific opt-in;
- cleanup and test-owned-resource requirements;
- the authoritative capability registry or typed-executor requirement; or
- canonical Phase 2 terminal/intermediate result classifications.

P3-4 does duplicate conservative eligibility checks but does not replace the Phase 2
runtime checks. The actual `VerificationRuntime.execute_selected` resolves the
frozen typed executor, creates the controlled executor with the authoritative gate,
vault, context and transport, and normalizes the public result.

## Provider secrets, prompts, and public errors

No provider credential leak was found.

- `ProviderConfiguration.api_key` is a Pydantic `SecretStr`, excluded from dumps and
  repr output.
- Cloud SDKs are loaded lazily; keys are passed only to SDK construction and are not
  placed in prompts, responses, telemetry, ledgers, histories, reports, or errors.
- Provider output and provider-call IDs explicitly remove the configured API key.
- Provider and routing errors contain a closed error code and fixed public message;
  raw SDK exception strings, bodies and headers are discarded.
- `.env.example` contains blank cloud-key placeholders only.
- Existing sentinel tests cover API keys, Authorization/Bearer text, cookies,
  sessions, passwords, recovery secrets and private recovery state across provider,
  router, reasoning, autonomy, consensus and evaluation surfaces.

Prompt construction has one active route: the stable P3-3 system instruction plus a
strict `ReasoningRequest` serialized into `ModelRequest.evidence`. `ModelRequest`
requires direct values already to equal `public_result`; builders sanitize raw
Phase 2 inputs before creating the packet. Fallback reuses the same immutable
request. No raw Phase 2 run, raw request/response body, credential vault content, or
private recovery state can enter the reviewed cloud prompt route.

Target-derived prompt injection remains possible as adversarial *data* presented to
an LLM; the project correctly does not claim perfect prompt-injection prevention.
Such data cannot deterministically change routes, allowlists, budgets, participants,
capabilities, policy, or execution because those values are typed operator inputs
and model output still crosses strict parsing, semantic validation, P3-4 gating and
Phase 2.

## Router, budget, and loop audit

P3-2 routing is deterministic and bounded:

- exact declared route order;
- maximum 20 provider attempts per routed request;
- zero retries (`max_retries` is the literal value `0`);
- fallback only for configured reliability errors;
- cloud allowlist enforced during policy validation;
- `local_only` excludes OpenAI and Anthropic routes;
- missing/malformed providers produce normalized failures;
- unknown price remains `None` and fails closed under strict monetary policy;
- budget preflight runs before every fallback attempt.

Theoretical schema maxima:

- single routed reasoning decision: 20 provider calls;
- P3-4 iterations per run: 100;
- P3-4 verifications per run: 100;
- one P3-5 consensus evaluation: 100 participants x 20 route attempts = 2,000
  provider calls, further limited by consensus and P3-2 model budgets;
- evaluation repetition: 100 subject repetitions x 100 case repetitions = 10,000
  observations per case, bounded but affected by P1-01.

No `while` loop, recursive autonomy, recursive consensus, uncontrolled retry,
unbounded fallback, or unbounded pivot loop was found. The router iterates a bounded
route tuple, consensus iterates at most 100 participants, P3-4 uses a bounded `for`,
and P3-6 repetitions are schema-bounded.

P3-2 and P3-5 model budget preflight arithmetic uses `>` for predicted consumption,
allowing a call that exactly fits the remaining ceiling, and uses `>=` when checking
whether an already-consumed ceiling is exhausted. P3-4 iteration and verification
checks are consistent with their bounded loop. No off-by-one budget bypass was found
outside P1-01.

## Accounting audit

The type-level invariants hold:

- `ModelUsageDelta.attempted_calls == successful_calls + failed_calls`;
- `ModelUsageDelta.total_tokens == input_tokens + output_tokens`;
- `RequestDelta.total == discovery + auth + verification + cleanup`;
- `RequestDelta.attempted == total`.

Every aggregate constructor reviewed rebuilds the strict type, so invalid sums fail
validation. Unknown model cost propagates as `None`; Ollama is explicitly zero API
cost. No model call is added to a `RequestDelta`, and no target request is added to a
`ModelUsageDelta`.

The two accounting/provenance inconsistencies are P1-02 (failure-path target-request
under-count) and P1-03 (multi-iteration route/fallback attribution under-count).

## Duplicate, replay, and cleanup audit

The execution identity includes hypothesis, capability, and a hash of controlled
account/object IDs plus plan ID. The gate rejects any prior matching identity,
regardless of result state. Verified, rejected, inconclusive, and policy-blocked
paths are added to the resolved set after one execution; verified/rejected cannot be
re-executed. Repeated invalid, duplicate, reasoning-failure, and policy-blocked
recommendations terminate at strict thresholds.

`verification_pending_cleanup` and the canonical cleanup-unverified reason set the
barrier and stop the run. The gate independently blocks a new state-changing
capability while the barrier is active. `awaiting_controlled_evidence` stops without
inventing context. No Phase 3 cleanup operation or alternative cleanup state was
found.

## Consensus audit

- Participants are sorted by stable participant ID and each receives a newly
  validated copy of the same canonical `ReasoningRequest`.
- Participant decisions are not inserted into another participant's request.
- Failed, invalid and budget-blocked participants are recorded but are not votes.
- Duplicate route configurations are rejected unless explicitly allowed.
- Provider fallback remains one logical participant and actual provider/model
  provenance is retained in `ParticipantOutcome`.
- Agreement uses exact structured fields, not prose similarity.
- Two-model ties and three-way splits take the configured conservative split action.
- Confidence is the arithmetic mean of the supporting structured votes, with no
  hidden provider weight.
- Consensus mapping re-enters P3-3 semantic validation; it does not call P3-4 or
  Phase 2 itself.

No consensus execution bypass was found. Unanimous and majority decisions remain
advisory.

## Persistence and provenance inventory

| Artifact | Storage class | Safety assessment |
|---|---|---|
| Cloud API key / SDK request / raw SDK response | Private ephemeral, process memory only | Key is `SecretStr`/adapter-private; raw objects are stack-local and not returned. |
| `ModelResponse` | Public-safe, returned; not automatically persisted | Strict normalized fields, sanitized content/metadata, no SDK object or key. |
| Provider telemetry | Public-safe, process-local | Counts, latency, route, safe error code only; no prompt/content/header. |
| `ModelCallLedger` | Public-safe, process-local | Route, usage, latency, fallback depth and normalized outcome only. |
| Model prompt | Ephemeral, not persisted | Stable instructions plus canonical public evidence; absent from histories. |
| Reasoning history | Public-safe, process-local | Concise rationale, references and sanitized model provenance; no raw prompt or chain-of-thought. |
| Consensus history | Public-safe, process-local | Structured agreement IDs/metrics; no participant prose or raw response. |
| Autonomy history/run | Public-safe, process-local | Typed references, gate/result references, deltas and states; see P1-02/P1-03. |
| Evaluation run/report | Public-safe, returned or emitted to stdout | `require_public_artifact` rejects non-public content; file persistence is caller-controlled. |
| Evaluation CLI input | Public-safe user-supplied report file | Parsed directly as strict `EvaluationRun`; no credential/provider access. |

Phase 3 defines no private on-disk store and writes no debug prompts or provider
responses. Consequently there is no new Phase 3 private-file permission to audit.
Existing Phase 2 reports/logs were inventoried only by name and were not modified.

Provenance is sufficient in provider, router, standalone reasoning and consensus
result objects to identify requested/actual provider/model, fallback, decision IDs,
usage and Phase 2 result references. P1-03 describes the remaining autonomy-history
resolution ambiguity.

## Evaluation isolation audit

P3-6 contains no function that mutates reasoning prompts, routing policy, consensus
policy, autonomy policy, capability registry, or Phase 2 policy. External baseline
and benchmark import accept an explicit JSON string or mapping and aggregate fields
only. They do not discover files or read source/fixtures. No benchmark result-to-
tuning-to-rerun edge exists.

Synthetic fixtures use generic categories and synthetic IDs. No CyberCortex Range
dependency or hidden ground-truth identifier was found. The audit did not inspect
CyberCortex Range.

## Optional dependency and startup audit

Cloud SDK imports occur inside provider constructors and failures mark only that
provider unavailable. Core imports and local-only provider construction do not
require cloud API keys. The current audit environment had the OpenAI SDK and `httpx`
available and did not have the optional Anthropic SDK; the complete core/test suite
still imported and ran successfully. A missing provider therefore did not break
unrelated providers.

## Test integrity and quality gates

- No `skip`, `xfail`, collection-ignore, or test-disabling marker was found in the
  test tree/configuration.
- No tracked test deletion or modification relative to the frozen Phase 2 reference
  was reported by `git diff --name-status ... -- tests`.
- Six Phase 3 test modules contain 286 explicit test functions before parametrized
  expansion.
- The complete expected suite remained enabled.

Final quality-gate results are recorded at the end of this document.

## Phase 3 completion matrix

| Milestone | Completion | Freeze assessment |
|---|---:|---|
| P3-1 provider foundation | Complete | Provider interface, three adapters, lazy cloud SDKs, safe credentials, normalization, pricing and telemetry pass review. |
| P3-2 routing/fallback/accounting | Complete | Deterministic bounded routes, allowlist/local mode and strict model ledger pass review. |
| P3-3 grounded reasoning | Complete | Canonical evidence, strict parser, semantic validation, advisory decisions and safe history pass review. |
| P3-4 autonomous orchestration | Functionally complete; not freeze-ready | Gate/runtime path is present; P1-02, P1-03 and P1-04 require remediation. |
| P3-5 consensus/arbitration | Complete | Independence, exact agreement, bounded budgets and P3-4 revalidation pass review. |
| P3-6 evaluation/telemetry | Functionally complete; not freeze-ready | P1-01, P1-03, P2-01 and P2-02 affect cost safety and measurement fidelity. |

## Real-provider readiness

No real-provider test was executed.

| Capability | Assessment | Preconditions/notes |
|---|---|---|
| OpenAI provider smoke test | Ready, conditional | Supply key/model via environment, use a one-call P3-2 ceiling, sanitized synthetic evidence, and no tools. SDK is present in this environment. |
| Anthropic provider smoke test | Not immediately runnable | Install the optional SDK, then supply environment key/model and the same one-call safety conditions. Core operation is correctly isolated while it is absent. |
| Ollama/DeepSeek smoke test | Ready, conditional | Start an operator-controlled Ollama service and confirm the configured model/base URL. No service was required by this audit. |
| Local-only reasoning/autonomy dry run | Ready, conditional | Use Ollama-only routing and P3-4 `dry_run`; clarify endpoint locality per P3-01. |
| Cloud reasoning | Ready for bounded smoke only | Provider adapter and P3-3 path are mock-tested; use synthetic public evidence first. |
| Cloud fallback | Ready for bounded smoke only | Use exact two-route chain and ledger/cost ceilings; no target execution. |
| Multi-model consensus | Ready after individual provider smoke tests | Keep minimum participants/budget explicit; output remains advisory. |
| Controlled autonomous verification | Not ready | Remediate P1-02 and P1-04, then test against the actual shared runtime under explicit Phase 2 policy. |

Overall real-provider smoke-test readiness is **YES for narrow provider/reasoning
smokes**, not for P3-6 benchmark runs or controlled autonomy.

## Benchmark readiness

External controlled benchmarking is **not ready**. P1-01 permits an evaluation case
to exceed its stated model budget, P1-02 can undercount target traffic on a runtime
failure, and P1-03 can undercount fallback/provenance across autonomy iterations.

The evaluation layer itself is isolated from ground truth and automatic tuning. Once
the P1 findings are remediated and independently re-audited, benchmark execution can
remain external and passive: supplied aggregate baseline/benchmark records cannot
change agent behavior, prompts, routes, consensus, policy, or capability state.

## Freeze recommendation

**Do not freeze Phase 3 yet.**

Required before freeze:

1. close P1-01 so evaluation budgets are enforced at the provider/ledger boundary;
2. close P1-02 so every consumed target request remains attributable on failures;
3. close P1-03 so autonomy evaluation provenance and metrics cover every iteration;
4. close P1-04 so production P3-4 construction is bound to the shared Phase 2
   runtime rather than a marker convention;
5. add focused regression tests for each remediation; and
6. rerun this freeze audit, then perform separate bounded provider smoke tests.

P2 items should be resolved for trustworthy comparative evaluation but do not expose
model execution authority. P3-01 can be handled as explicit documentation or a
future authorized endpoint-locality control.

## Final audit counts

- P0: 0
- P1: 4
- P2: 2
- P3: 1
- provider credential leaks: 0
- remote evidence sanitizer bypasses: 0
- model-output execution bypasses: 0
- direct security execution bypasses: 0
- Phase 2 policy/runtime bypasses: 0
- model/request accounting inconsistencies: 2
- budget bypasses: 1
- unbounded loops: 0
- consensus execution bypasses: 0
- cleanup-barrier bypasses: 0
- evaluation feedback/tuning routes: 0
- chain-of-thought persistence routes: 0

## Final quality-gate results

- `black --check .`: pass; 246 files would be unchanged
- `ruff check .`: pass
- `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py campaign_cli.py model_eval_cli.py`: pass
- `python -m pytest -q`: pass; 1168 passed in 15.21 seconds
- `git diff --check`: pass
- branch/frozen-reference/status check: pass; branch remained `develop-v3` and
  both the frozen tag and stated commit resolved to
  `c9b3fcc5df2695aeec8d832a271b7d543c23cae7`

The initial sandboxed pytest invocation produced four localhost-bind
`PermissionError` failures and 1164 passes. The identical suite was rerun with
loopback-bind permission and passed in full. These were environment-permission
failures, not product-test failures.

---

## PHASE 3 FINAL RE-AUDIT

Date: 2026-09-03

Branch reviewed: `develop-v3`

Tree reviewed: exact current working tree after the four independently reported P1
remediations; no remediation status was accepted without source tracing and an
offline reproduction where practical.

### Final re-audit conclusion

Completion assessment: **97%**. This remains a readiness assessment, not a security
or model-quality score.

- P0: 0
- P1: 1
- P2: 2
- P3: 1
- original P1 blockers passed: 3/4

P1-02, P1-03, and P1-04 pass the independent re-audit. P1-01 is materially
improved for call-count, known-cost, exact-boundary, repeated-case, fallback-route,
consensus, autonomy, and dry-run enforcement, but one token-authority route remains:
a failed provider attempt is recorded with zero tokens and releases its entire
conservative token reservation. A later fallback, repetition, autonomy retry, or
consensus participant can therefore receive the same token allowance again.

An offline construction set `max_total_tokens` to exactly one conservative
input-plus-output reservation. The primary route timed out after invocation, the
ledger recorded zero tokens, the fallback received a second full reservation, and
the evaluation outcome completed successfully. The diagnostic values were:

```text
budget total tokens: 15667
reservation per invocation: 15667
primary invocations: 1
fallback invocations: 1
reported aggregate tokens: 2
evaluation success: true
```

No provider or target network was used. The defect is in reservation/accounting:
`ModelCallLedger.record_failure` records a failed attempt with zero input, output,
and total tokens, while `ModelRouter._preflight` and P3-6's next preflight consult
only accumulated reported usage. Call-count ceilings remain authoritative. Known
cost ceilings use conservative pricing before submission, and a failed cloud call
with unknown cost blocks continuation under the strict `deny` policy. The remaining
P1 is specifically the reuse of a token reservation after a failed attempt.

### Original P1 recheck

| Finding | Final result | Independent evidence |
|---|---|---|
| P1-01 evaluation budget overshoot | **INCOMPLETE / P1 remains** | Exact/one-over call and successful token/cost preflight are closed. Failed calls retain call count but zero token usage, allowing the next fallback/repetition/retry/participant to reuse a full token reservation. |
| P1-02 post-traffic request attribution | **PASS** | P3-4 snapshots the genuine Phase 2 `RequestBudget` immediately before submission and derives `RequestDelta` immediately after return or exception, before result normalization, provenance, or history processing. Runtime, result-normalization/validation/provenance, partial-execution, cleanup, and history failures preserve the categorized delta. P3-6 sums it from iteration history. |
| P1-03 multi-iteration provenance | **PASS** | Frozen `AutonomyIterationRecord` values are tuple-appended; exact decision, consensus, participant, result ID/hash/reference, executor/status, pivot, terminal, `ModelUsageDelta`, and `RequestDelta` data survive all iterations. P3-6 consumes the full embedded history and validates its metrics and aggregates against that history. |
| P1-04 runtime identity | **PASS** | Constructor injection is bound only when `type(runtime) is VerificationRuntime`. The gate accepts only the exact sealed binding issued with the process-local private identity. Marker, protocol shape, method-compatible/full-interface fakes, class-name imitations, callables, wrappers, and subclasses cannot pass the public injection path. P3-6 has no runtime path. |

Remaining P1-01 overshoot routes are all manifestations of one source defect:

1. a failed preferred route followed by a fallback;
2. a failed evaluation observation followed by another case/repetition sharing the
   reasoning run;
3. a failed reasoning attempt followed by an autonomy retry/iteration; and
4. a failed consensus participant followed by another participant.

All are bounded by their model-call limits, so none is an unbounded loop. They can
nevertheless reserve cumulative provider tokens above the configured token ceiling.

### Complete execution-path re-audit

The only active path from model advice to target transport is:

```text
configured provider adapter
  -> ModelRouter / ModelCallLedger
  -> ReasoningEngine
  -> strict ReasoningDecision
  -> optional ConsensusEngine and revalidated advisory decision
  -> AutonomousOrchestrator
  -> ExecutionDecisionGate
  -> sealed AuthoritativePhase2RuntimeBinding
  -> VerificationRuntime.execute_selected
  -> Phase 2 DeterministicPolicyGate and capability registry
  -> typed ControlledVerificationExecutor
  -> Phase 2 scoped transport
```

`ReasoningDecision` and `ConsensusDecision` remain non-invocable data. Consensus
cannot select a runtime, executor, transport, import path, class, or callable. P3-6
only observes supplied normalized artifacts. The sole active P3-4 submission is
`self._phase2_runtime.submit(...)`, which is captured from the exact Phase 2 runtime
by the sealed binding.

Runtime binding occurs before any request-ledger snapshot or execution submission.
It supplements rather than replaces Phase 2's independent authorization, scope,
capability, controlled-context, credential, state-change, cleanup, test-owned-object,
and request-budget enforcement.

### Secret, privacy, and persistence re-audit

No provider credential, Authorization/Bearer value, cookie, session token, password,
recovery secret, private recovery state, raw provider object, raw private prompt, or
chain-of-thought persistence route was found in `ModelResponse`, model telemetry,
`ModelCallLedger`, reasoning history, consensus history, autonomy history, iteration
provenance, evaluation artifacts, public errors, or report/CLI output.

- Provider-specific raw responses remain adapter-local and are normalized into the
  strict `ModelResponse` contract.
- Cloud keys remain excluded `SecretStr` configuration and are passed only to SDK
  construction. Public provider errors contain closed codes/messages.
- Prompt evidence must already equal the canonical Phase 2 `public_result` form.
- Reasoning and consensus histories retain concise sanitized advisory rationale and
  structured references, not prompts, SDK objects, or hidden reasoning.
- Evaluation JSON calls `require_public_artifact` before serialization, and the CLI
  parses strict `EvaluationRun` objects before summaries/comparisons.
- The runtime binding, issuer identity, callable, runtime object, credential vault,
  and private controlled state are absent from every serializable contract.

Sentinel coverage in the current suite includes API keys, Authorization/Bearer
values, cookies/sessions, passwords, recovery secrets, private recovery state, raw
provider responses, and chain-of-thought strings across the Phase 3 layers.

### Accounting and budget re-audit

`ModelUsageDelta` and `RequestDelta` remain distinct immutable strict types and use
separate aggregation paths. No model call is counted as a target request and no
target request is counted as a model call. Phase 2 remains the single target-request
ledger; P3-4 uses only before/after snapshots of that ledger. P3-6 sums exact
per-iteration values once, and its outcome model rejects aggregate/history
disagreement. No duplicate target-request aggregation or P1-02 attribution-loss
route was found.

The one accounting inconsistency is the P1-01 failed-model token gap: a failed call
is correctly counted as one model attempt, but has zero tokens even after a request
may have reached the provider. That zero is then treated as reusable capacity. It
affects fallback, repeated evaluation, consensus, and autonomy retry paths. Target
request accounting and model/request separation are unaffected.

Budget boundary results:

- model-call exact and one-over boundaries: pass;
- successful-call input/output/total-token exact and one-over preflight: pass;
- known-cost exact and one-over preflight: pass;
- unknown cost under a strict monetary ceiling: fail closed;
- evaluation sharing across repeated cases with the same reasoning run: pass for
  reported usage and model calls;
- fallback/consensus/autonomy policy intersection: pass for call ceilings;
- failed-attempt token reservation across those paths: fail (P1-01);
- dry-run: model budgets remain active and target `RequestDelta` remains zero;
- Phase 2 target-request exact/one-over boundary: unchanged and independently
  enforced by the shared runtime.

### Loop, consensus, cleanup, and evaluation-isolation re-audit

No unbounded provider retry, fallback, reasoning, autonomy, pivot, consensus, or
evaluation loop was found. Router retries remain the literal value zero and routes
are capped at 20; autonomy iterations/verifications are capped at 100; consensus is
sequential over at most 100 participants; cases and repetitions are schema-bounded.

Consensus participants receive independent validated copies of the canonical
request. Invalid, failed, and budget-blocked outcomes are not votes. Duplicate
participant IDs are rejected, and duplicate logical routes require explicit opt-in.
A provider fallback remains one participant. Ties/splits take the configured
conservative action. Consensus remains advisory and still crosses P3-4 and the
authoritative Phase 2 runtime before execution. The P1-01 token-reservation defect
also applies between failed consensus participants, but creates no execution bypass.

State-changing autonomous work cannot proceed across an unresolved cleanup barrier.
P3-4 sets the barrier from canonical Phase 2 status/reason data, stops the run, and
independently rejects another state-changing capability while it is active. Phase 3
contains no cleanup executor or alternate cleanup mechanism.

P3-6 remains measurement-only. No benchmark result can automatically modify a
prompt, model route, consensus policy, autonomy policy, capability, Phase 2 policy,
or trigger tuning/rerun. External records are explicit aggregate-only inputs; no
benchmark discovery or ground-truth read path exists in Phase 3.

### Original P2 findings

#### P2-01 — structural expectations

Historical classification at the time of the original audit: **STILL PRESENT / SAFE
TO DEFER** from the security freeze, but not safe to ignore for comparative
evaluation.

`EvaluationCase.expected_structure` is still not consulted by
`EvaluationRunner._validate_outcome`. An offline outcome with zero valid decisions
was accepted as successful despite `minimum_valid_decisions=1`. Allowed action,
allowed capability, and required-evidence expectations are likewise declarations,
not enforced observations. This cannot grant execution authority, but it can make a
benchmark success label misleading.

Targeted closure update (2026-09-04): **RESOLVED** by the authoritative typed checks,
case-level expectation status, success separation, metrics, and reports documented
in the P2-01 closure section above. The preceding paragraph is retained as the
original audit record.

#### P2-02 — incomplete configuration identity

Historical classification at the time of the original audit: **STILL PRESENT / SAFE
TO DEFER** from the security freeze, but not safe to ignore for comparative
evaluation.

The stable fingerprint still omits `expected_structure` and material case reasoning
constraints. Changing `minimum_valid_decisions` from one to two produced the same
fingerprint. `compare_runs` checks only a reduced case shape, so runs with materially
different expectations or case policy can be reported as configuration-compatible.
This does not affect runtime safety, but can make results non-repeatable or
incorrectly comparable.

Targeted closure update (2026-09-04): **RESOLVED** by material-v2 canonical identity,
full-fingerprint comparison, honest external/legacy compatibility, and the regression
coverage documented in the P2-02 closure section above. The preceding paragraph is
retained as the original audit record.

At the time of the original audit, both P2 findings directly affected measurement
meaning and external benchmark readiness was **NO** even aside from P1-01. Following
the targeted P2-01 and P2-02 closures, this paragraph remains only as the historical
readiness record from that audit.

### Original P3 finding

#### P3-01 — `local_only` locality semantics

Classification: **STILL PRESENT / P3 documentation and hardening**.

`local_only` currently guarantees provider-family routing: every route must be
`ollama`, and no OpenAI or Anthropic fallback can be appended. It does not guarantee
host-loopback or on-machine locality. `ProviderConfiguration` accepts any
credential-free HTTP(S) origin, and an offline construction accepted
`https://ollama.example.test` while the policy remained `local_only`.

`docs/PHASE3.md` accurately states that routes are Ollama-only and that the default
origin is loopback, but also calls the mode a strict privacy mode; README language
describes fully local hardware. A deliberately configured remote Ollama endpoint can
therefore carry model prompts off-machine. There is no silent cloud fallback and the
endpoint is operator-controlled, so the evidence does not warrant escalation above
P3. Documentation should not be read as a loopback enforcement guarantee.

### Readiness assessment

| Capability | Result | Conditions and evidence |
|---|---:|---|
| OpenAI smoke test | **YES, conditional** | Adapter/router/reasoning path is mock-tested and the SDK is installed. Supply an operator key/model and use one provider call with no fallback; no key is currently configured. |
| Anthropic smoke test | **NO** | The optional Anthropic SDK and credential are absent in the audited environment. The adapter is isolated and mock-tested, but the smoke is not immediately runnable. |
| Ollama/DeepSeek smoke test | **YES, conditional** | Adapter/router/reasoning path is ready. Start an operator-controlled endpoint, confirm model and endpoint locality, and use one bounded call. No service was contacted or required. |
| local-only reasoning | **YES, conditional** | Ollama-family isolation is enforced; confirm loopback separately because `local_only` does not enforce it. |
| cloud reasoning | **YES for a one-provider bounded smoke** | Use sanitized synthetic evidence, one call, no fallback, and explicit cloud consent. |
| provider fallback | **NO for authoritative token-budget claims** | Call bounds are correct, but failed attempts can release token reservations under P1-01. |
| three-model consensus | **NO** | P1-01 applies across failed participants; the Anthropic SDK/credential is also absent. |
| controlled autonomy against an authorized local lab | **NO** | Runtime identity, target policy, cleanup, target accounting, provenance, stop limits, and duplicate prevention pass, but model token ceilings are not authoritative across reasoning failures/retries. |
| external benchmark | **NO** | P1-01 permits token-reservation reuse; P2-01 can mislabel structural success and P2-02 can falsely report configuration compatibility. Evaluation remains isolated from ground truth and tuning. |
| Phase 3 freeze | **NO** | One P1 remains. The P2/P3 items are deferrable only after the P1 is closed and with benchmark/locality limitations explicitly retained. |

### Test-integrity and source-bypass inspection

The current collection contains **1269 tests**, matching the stated baseline. No
`pytest.skip`, `@pytest.mark.skip`, `xfail`, collection-ignore, or disabled-module
configuration was found. No tracked test deletion appears in Git status. Critical
P1 regression assertions remain present; the missing failed-attempt token-reservation
case is a coverage gap, not a disabled test.

The explicit Phase 3 source scan searched for `ControlledVerificationExecutor`,
`safe_http`, `requests`, `httpx`, `urllib`, `aiohttp`, `subprocess`, `os.system`,
`shell=True`, `eval(`, and `exec(`. Manual classification:

- `httpx` is used only by the Ollama model-provider adapter for its configured model
  API, not for target security traffic;
- `urllib.parse.urlsplit` validates provider origins and performs no I/O;
- `requests` appears only in target-request metric/report wording;
- Phase 3 has no direct controlled-executor import, target HTTP library, subprocess,
  shell, `eval`, or `exec` route.

Active source-inspection counts:

- direct executor bypasses: 0
- alternate target HTTP transports: 0
- arbitrary execution routes: 0
- model-output execution bypasses: 0
- Phase 2 policy/runtime bypasses: 0
- consensus execution bypasses: 0
- runtime identity forgery routes: 0
- evaluation runtime bypasses: 0
- latest-only provenance routes: 0
- target-request attribution-loss routes: 0
- cleanup-barrier bypasses: 0
- evaluation feedback/tuning routes: 0
- unbounded loops: 0
- model/request accounting inconsistencies: 1
- budget bypasses: 1

### Final re-audit counts and quality gates

- provider credential leaks: 0
- remote evidence sanitizer bypasses: 0
- model-output execution bypasses: 0
- direct security execution bypasses: 0
- Phase 2 policy/runtime bypasses: 0
- model/request accounting inconsistencies: 1
- budget bypasses: 1
- unbounded loops: 0
- consensus execution bypasses: 0
- cleanup-barrier bypasses: 0
- evaluation feedback/tuning routes: 0
- runtime identity forgery routes: 0
- latest-only provenance routes: 0
- target-request attribution-loss routes: 0
- chain-of-thought persistence routes: 0

Quality-gate results: **PASS**

- `black --check .`: pass; 248 files would be unchanged
- `ruff check .`: pass
- `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py campaign_cli.py model_eval_cli.py`: pass
- `python -m pytest -q`: pass; 1269 passed in 15.80 seconds
- `git diff --check`: pass
- `git status --short --untracked-files=all`: inspected; pre-existing Phase 3
  working-tree changes remain uncommitted and no file was deleted
- branch check: pass; branch remained `develop-v3`

## P1-01 R2 — authoritative failed-attempt token reservation

Status: **COMPLETE**. This section records the remediation performed after the
final re-audit above. The earlier audit and re-audit results remain unchanged as
point-in-time evidence.

### Why the initial P1-01 remediation was insufficient

The first remediation made evaluation preflight authoritative for successful
usage and model-call counts, but the model ledger still finalized every failed
provider attempt with zero input, output, and total tokens. `ModelRouter` then
preflighted fallback against those observed-zero fields. The same gap propagated
through consensus participant aggregation, autonomy reasoning retries, and P3-6
repetition reconciliation. A call that had reached a provider but returned no
usage metadata therefore released its full token reservation. The final re-audit
reproduced a second provider invocation under a total-token ceiling sized for one
reserved invocation.

### Authoritative provider-start and reservation semantics

`ModelRouter` now owns the single production provider-start boundary. It performs
deterministic route, pricing, provider construction, availability, and callable
checks first. These definite pre-call blocks are recorded as
`blocked_before_provider_call` and commit zero token and cost reservation.
Immediately before the normalized provider `generate` call, the router commits a
`ModelBudgetReservation` containing the conservative input estimate, bounded
maximum output, total tokens, and known estimated maximum cost.

The finalized attempt state is one of:

- `blocked_before_provider_call`: exact zero actual usage and zero reservation;
- `provider_call_succeeded`: trustworthy response usage reconciles the reservation
  to actual usage, without adding reservation and actual values together;
- `provider_call_failed_after_start`: trustworthy partial usage is retained when
  supplied, while unknown actual usage remains `None` on the call record and the
  conservative reservation remains committed.

An unexpectedly successful response above the reservation is accounted at the
greater actual value and fails the existing post-call budget reconciliation. A
ledger-finalization defect cannot refund a committed reservation: it remains an
active conservative reservation until successfully finalized.

### Actual usage and budget consumption

`ModelCallRecord` and `ModelUsageDelta` now keep actual usage separate from budget
consumption. Actual aggregate token fields continue to satisfy
`total_tokens = input_tokens + output_tokens`; `unknown_usage_calls` identifies
failed attempts whose actual usage is unavailable. Separate
`budget_input_tokens`, `budget_output_tokens`, `budget_total_tokens`, and
`budget_estimated_cost_usd` fields drive authority checks. Known successful usage
reconciles to actual values, so it is not double counted. Known partial failure
usage cannot reduce the committed reservation. Unknown pricing remains unknown
and preserves the existing strict monetary-ceiling fail-closed behavior.

These fields are numeric accounting only. They persist no prompt, provider request
body, raw response, raw exception, credential, authorization header, cookie,
session value, password, or recovery state. Model budget consumption remains
independent of Phase 2 `RequestDelta`; model-only failures produce zero target
requests.

### Propagation and regression evidence

Fallback and a later call through the same router see the committed ledger state.
Consensus aggregates reservation fields across participant outcomes before the
next participant. Autonomy includes failed reasoning deltas in append-only
iteration provenance and its next router call and budget context use reservation
consumption. Evaluation reconciles the same fields across repetitions and cases
sharing a reasoning run. Dry-run uses identical model-budget semantics while
remaining zero-target-traffic.

Focused mock-only regressions cover pre-call rejection, success reconciliation,
timeout/rate-limit/connection/unavailability failures, malformed responses,
partial usage, known and unknown cost, fallback and later-attempt boundaries,
OpenAI/Anthropic/Ollama parity, consensus participant exhaustion, autonomy retry
and parser failure, dry-run, repeated evaluation, sanitization, and target-request
separation. The exact re-audit reproduction now permits one started provider
attempt, retains its full total-token reservation, and rejects the fallback before
provider invocation.

Production source inspection found:

- failed-started-attempt zero-budget routes remaining: 0
- fallback reservation reset routes remaining: 0
- retry reservation reset routes remaining: 0
- consensus reservation multiplication routes remaining: 0
- autonomy reservation reset routes remaining: 0
- evaluation reservation reset routes remaining: 0

Provider adapters remain behind `ModelRouter`; no second provider transport or
provider-specific reservation rule was introduced. P1-02 target accounting,
P1-03 iteration provenance, P1-04 runtime binding, and Phase 2 are unchanged.

R2 quality gates: **PASS**. Twenty-three focused regression cases were added; the
complete suite passes with **1292 tests**. Black, Ruff, compileall, and Git
whitespace checks pass, and the branch remains `develop-v3` with the Phase 3 work
uncommitted.

## TARGETED P1 CLOSURE AUDIT

Date: 2026-09-03

Scope: independent re-audit of the four original Phase 3 P1 findings only. No
remediation, P2/P3 work, provider call, target call, benchmark execution, commit,
or push was performed. Prior audit and remediation history above remains intact;
the existing P2/P3 classifications are unchanged.

### P1-01 — authoritative model-budget reservation: PASS

The exact final-re-audit failure was reproduced with a deterministic total-token
ceiling equal to one conservative input-plus-output reservation. For each of
OpenAI, Anthropic, and Ollama, the first mocked provider call started and failed
with unknown usage. Its actual token values remained unknown/zero in the aggregate
actual-usage view, while all 83 reserved tokens remained in the authoritative
budget-consumption view. A configured second provider was rejected by router
preflight and received zero calls.

A separate same-provider attempt against the same run and ceiling was likewise
rejected before invocation. Focused consensus, autonomy, and evaluation
reproductions confirmed that a failed participant, failed reasoning iteration,
and failed evaluation invocation respectively carry the committed reservation
into the next preflight. Dry-run uses the same model accounting and remains zero
target traffic. Source tracing found one production commit point immediately
before the normalized provider call, with success reconciliation and conservative
failed-started finalization in the same router/ledger transaction.

Counts:

- failed-attempt reservation bypasses: 0
- fallback budget reuse routes: 0
- retry budget reuse routes: 0
- consensus budget reuse routes: 0
- autonomy budget reuse routes: 0
- evaluation budget reuse routes: 0

### P1-02 — post-traffic target-request attribution: PASS

Independent mocked runs exercised runtime exception, malformed result,
normalization/validation failure, provenance failure, history persistence failure,
cleanup failure, and partial execution. The Phase 2 request ledger is snapshotted
before the sole bound runtime submission and read immediately afterward, before
result normalization, provenance construction, or history persistence. Exact
observed deltas survived each failure: discovery 1 for a runtime exception,
verification 1 for malformed/validation/history failures, auth plus verification
2 for provenance and partial failures, and verification plus cleanup 2 for the
cleanup failure. A pre-transport policy block remained exactly zero.

- target-request attribution-loss routes: 0

### P1-03 — complete multi-iteration provenance: PASS

An independent three-iteration run retained decision IDs
`decision-hyp-1-recommend_verification`,
`decision-hyp-2-recommend_verification`, and `decision-hyp-3-stop`; hypothesis IDs
`hyp-1`, `hyp-2`, and `hyp-3`; exact Phase 2 result IDs and hashes for the first two
iterations; per-iteration request totals 2, 2, and 0; per-iteration model-token
totals 15, 15, and 15; verified/rejected pivot reasons; and the terminal
`model_recommended_stop` reason. A separate consensus regression retained the exact
consensus ID and supporting participant decision IDs.

The iteration model is frozen, history enforces strictly increasing append-only
records, and run aggregates are recomputed once from that history. Evaluation
consumes `run.iteration_history`/history records and validates that model usage,
request deltas, and result references equal the iteration sum. Poisoning the
mutable convenience fields with a fake latest decision/result did not change the
three historical records or evaluation JSON.

Counts:

- latest-only provenance routes: 0
- iteration overwrite routes: 0
- duplicate accounting routes: 0

### P1-04 — authoritative Phase 2 runtime identity: PASS

Independent attempts using the old public marker, a copied marker property, a
method-compatible fake, a full-interface fake, a class named
`VerificationRuntime`, an arbitrary callable, and a wrapper around a genuine
runtime all stopped at `runtime_boundary_invalid` with zero target requests and
zero fake-runtime calls. The concrete factory runtime and explicit test seam remain
accepted.

The binding requires the exact Phase 2 `VerificationRuntime` type and a private
process-local issuer; its wrapper is sealed against subclassing, copying, and
serialization. The decision gate validates this binding before the single runtime
submission. Phase 3 contains one binding call, one submission call, no runtime
constructor, and no alternate executor/transport.

Counts:

- runtime identity forgery routes: 0
- duck-typed production authority checks: 0
- alternate runtime construction paths: 0

### Cross-P1 and security invariants

An invalid runtime produces zero `RequestDelta`; a valid bound runtime preserves
post-traffic failure deltas. A failed model call consumes only model reservation
budget and produces no target request. Failed Phase 2 accounting remains in its
immutable iteration provenance. No binding/issuer capability is serialized in
autonomy or evaluation artifacts, and no model reservation field is treated as
Phase 2 traffic.

The targeted source scan found no Phase 3 direct controlled executor, target HTTP
transport, shell/subprocess, `eval`, or `exec` route. The Ollama `httpx` match is
the configured model-provider transport, and `urllib.parse` only validates model
provider origins. Public-result boundaries and sentinel regressions cover model
requests, reasoning, consensus, autonomy, iteration history, and evaluation
artifacts. All loops remain schema/policy bounded.

Security counts:

- provider credential leaks: 0
- remote evidence sanitizer bypasses: 0
- model-output execution bypasses: 0
- direct security execution bypasses: 0
- Phase 2 policy/runtime bypasses: 0
- `RequestDelta`/`ModelUsageDelta` coupling: 0
- unbounded loops: 0

### Test integrity and closure result

The focused P1 closure selection passed **114 tests**. The complete suite passed
**1292 tests**, matching the stated baseline. No skip, xfail, collection-ignore,
or disabled-test configuration was found, and the critical assertions remain
substantive. P1 blockers remaining: **0**.

Targeted closure verdict: P1-01 **PASS**, P1-02 **PASS**, P1-03 **PASS**, P1-04
**PASS**. The tree is ready to proceed to the separately scoped P2 measurement
findings and, after that work, a bounded controlled-autonomy readiness step.

---

## PHASE 3 FINAL FREEZE AUDIT

Audit date: **2026-09-09**

Scope: exact current working tree on branch **develop-v3**, at HEAD
**c9b3fcc5df2695aeec8d832a271b7d543c23cae7**. This was a read-only implementation
audit. No fix, feature, provider call, CyberCortex Range run, Phase 2 modification,
commit, or push was performed. The only audit write was this appended section.

### Final disposition

PHASE 3 FINAL FREEZE AUDIT

completion: 97%

P0: 0
P1: 1
P2: 1
P3: 1

ready to freeze: NO
ready for real-provider smoke tests: NO
ready for multi-model consensus smoke test: NO
ready for controlled autonomy test: YES
ready for external benchmark: NO

original P1 blockers passed: 3/4
original P2 findings passed: 2/2

provider credential leaks: 0
remote evidence sanitizer bypasses: 0
model-output execution bypasses: 0
direct security execution bypasses: 0
Phase 2 policy/runtime bypasses: 0
runtime identity forgery routes: 0
target-request attribution-loss routes: 1
latest-only provenance routes: 0
model/request accounting inconsistencies: 1
budget bypasses: 1
unbounded loops: 0
consensus execution bypasses: 0
cleanup-barrier bypasses: 0
evaluation feedback/tuning routes: 0
structural expectation bypasses: 0
configuration fingerprint omissions: 0
chain-of-thought persistence routes: 0

tests: 1396 passed
quality gates: PASS

files changed by audit: docs/PHASE3_COMPLETION_AUDIT.md only
files deleted: 0

### P0 findings

None.

### P1 findings

#### P1-FINAL-01 — Evaluation callback exceptions erase authoritative started-call reservations

Classification: **OPEN / regression of the evaluation branch of P1-01-R2**.

The P3-2 router itself still commits a conservative call/token/cost reservation
immediately before provider invocation, preserves that reservation on a started
failure, reconciles success to actual usage, and prevents fallback, consensus,
autonomy, or another call sharing that ledger from reusing it. Those core and
cross-component tests pass.

The independent P3-6 evaluation authority is not complete on an exception boundary.
EvaluationRunner catches any evaluator exception at runner.py lines 120-130 and
creates a replacement failed outcome. The replacement at lines 211-239 has zero
attempted calls and zero budget reservation. Reconciliation at line 131 therefore
commits zero usage. EvaluationBudgetPreflight does not hold a provisional reservation;
it relies on the callback-returned ModelUsageDelta.

An offline reproduction used two repetitions, a case ceiling of two calls but only
one output-token reservation, and a fresh correctly bound router for each evaluator
invocation. Each mocked Ollama provider call started and failed with a normalized
timeout. Both providers were invoked, while both evaluation outcomes reported zero
calls and zero reserved tokens; aggregate model calls were zero. The second call
therefore reused an exhausted reservation.

This route also allows post-model-traffic exceptions to discard actual usage,
provider provenance, and cost state. It affects evaluation repetition and any
evaluation-wrapped reasoning, consensus, or autonomy callback that raises before
returning its normalized outcome. It does not create target execution authority.

Counts:

- evaluation started-call reservation bypasses: **1**
- core P3-2 router reservation bypasses: **0**
- direct autonomy reservation bypasses: **0**
- model/request accounting inconsistency routes: **1**

### P2 findings

#### P2-FINAL-01 — Autonomy evaluation rejects canonical nonterminal Phase 2 statuses

Classification: **OPEN / evaluation validity and provenance loss**.

P3-4 correctly accepts and records all six public Phase 2 statuses, including
verification_pending_cleanup and awaiting_controlled_evidence. The first activates
the mandatory cleanup barrier; the second stops for controlled evidence. The P3-6
CanonicalPhase2ExpectationStatus enum at types.py lines 88-92 includes only verified,
rejected, inconclusive, and policy_blocked. observe_autonomy_run converts every
recorded Phase 2 result to that narrower enum at runner.py lines 558-562, and the
outcome validator repeats the conversion at types.py lines 669-675.

Offline controlled-autonomy reproductions for both legitimate nonterminal statuses
raised ValueError at observation. When invoked through EvaluationRunner, that error
enters P1-FINAL-01's generic failure path and replaces the run with autonomy_failed,
zero model usage, zero RequestDelta, and no exact iteration/result provenance. Thus
target requests already retained authoritatively by P3-4 can be lost from the
evaluation artifact.

This is not a Phase 2 status reinterpretation into success and does not bypass the
cleanup barrier. It is a failure to represent canonical status and therefore blocks
honest controlled-autonomy benchmarking.

Counts:

- target-request attribution-loss source routes: **1**
- Phase 2 success reinterpretation routes: **0**
- cleanup-barrier bypasses: **0**

The original P2-01 structural-expectation finding remains closed: every strict
expectation field is checked, failed required expectations cannot appear successful,
and runtime success is distinct from expectation success. The original P2-02
material-fingerprint finding also remains closed: the material-v2 schema has strict
field completeness, excludes secrets and ephemeral state, compares stored identity,
and treats missing external identity as unknown. Therefore the original P2 findings
pass **2/2**; P2-FINAL-01 is a new independent finding.

### P3 findings

#### P3-FINAL-01 — local_only remains provider-family isolation, not loopback enforcement

Classification: **STILL OPEN / P3 documentation and hardening**.

local_only accepts only Ollama-family routes and rejects OpenAI and Anthropic,
including fallback entries. It does not inspect or constrain the Ollama endpoint.
ProviderConfiguration accepts any credential-free HTTP or HTTPS origin; an offline
construction accepted https://ollama.example.test while the route remained
local_only. The default endpoint is loopback, but remote Ollama endpoints remain
explicitly configurable.

docs/PHASE3.md accurately says Ollama-only and default loopback, but also labels the
mode a strict privacy mode. README.md says fully local and fully local execution.
Those statements do not clearly disclose that explicit remote Ollama configuration
can move prompts off-machine. Documentation therefore does not fully state the
enforced behavior.

P3 remains appropriate: the endpoint is explicitly operator-configured, credentials
in URLs are rejected, and there is no silent cloud-provider fallback. The issue is
not an execution-authority bypass.

### Remediation closure verification

1. **Failed started provider attempts:** PASS in P3-2, reasoning, consensus, and
   direct autonomy; REGRESSION in P3-6 when the evaluator callback raises after
   provider start, as P1-FINAL-01 documents.
2. **Exhausted reservation reuse:** PASS for fallback, retry, consensus, and direct
   autonomy. FAIL for evaluation repetition through P1-FINAL-01.
3. **Post-traffic RequestDelta:** PASS in the autonomy/runtime path for runtime,
   result-normalization, provenance, and history failures. FAIL at the evaluation
   observation boundary described by P2-FINAL-01/P1-FINAL-01.
4. **Multi-iteration provenance:** PASS. Frozen, append-only iteration records retain
   exact reasoning/consensus decisions, model usage, RequestDelta, Phase 2 result
   identity/hash/executor, pivots, and terminal outcome. Evaluation reads the full
   iteration history, not latest-only convenience fields, when observation succeeds.
5. **Authoritative Phase 2 runtime identity:** PASS. Exact VerificationRuntime type,
   private issuer, sealed process-local binding, captured execute_selected method,
   non-copyability, and non-serializability remain enforced. Forgery routes: zero.
6. **Structural expectations:** PASS. All strict expectation fields are measured and
   enforced; a failed required expectation cannot produce expectation success.
7. **Material evaluation configuration:** PASS. material-v2 remains complete for its
   declared evaluation contracts; secret, ephemeral, and runtime authority values
   are excluded; comparison compatibility remains explicit and honest.

### Execution authority trace

The only active path is:

provider/model -> ModelRouter -> ReasoningEngine -> ConsensusEngine when configured
-> AutonomousOrchestrator -> DeterministicDecisionGate -> sealed authoritative Phase
2 runtime binding -> VerificationRuntime Phase 2 gate/policy -> resolved typed
ControlledVerificationExecutor -> VerificationHTTPTransport -> ScopedHTTPClient ->
authorized target.

The reasoning and consensus contracts contain no callable, executor, transport, or
runtime-selection field. Consensus remains advisory. The autonomy gate resolves the
typed capability and exact approved plan, enforces budgets/authorization/accounts/
credentials/state-change policy/cleanup, and is mandatory before the one production
runtime submission. VerificationRuntime re-resolves the typed executor, enforces
policy/context/budget object identity, and requires ScopedHTTPClient for target
transport.

Execution counts:

- direct model execution routes: **0**
- direct executor bypasses: **0**
- alternate target HTTP transports: **0**
- Phase 2 policy/runtime bypasses: **0**
- model-controlled runtime-selection routes: **0**

### Secret and privacy review

Public and persistent Phase 3 contracts, telemetry, reasoning history, consensus
history, autonomy iteration history, and evaluation JSON were checked for API keys,
Authorization and Bearer values, cookies, session tokens, passwords, recovery
secrets/state, provider objects/responses, private prompts, and chain-of-thought.
Provider configuration keys remain excluded SecretStr values; public errors omit raw
exceptions; model evidence must already satisfy the Phase 2 public_result boundary;
and evaluation serialization rechecks the same boundary. Sentinel tests cover all
listed classes.

- provider credential leaks: **0**
- remote evidence sanitizer bypasses: **0**
- raw provider-response persistence routes: **0**
- raw private-prompt persistence routes: **0**
- chain-of-thought persistence routes: **0**

### Accounting and budgets

ModelUsageDelta and RequestDelta remain separate strict types and ledgers. Model
actual usage fields remain distinct from budget-consumption reservation fields.
Success reconciles reservation to actual usage. Started failure retains conservative
call/input/output/total/cost reservation with unknown actual usage. Unknown cloud
pricing fails closed under a monetary ceiling unless explicitly allowed; Ollama has
configured zero API cost. Exact and one-over tests cover calls, tokens, total tokens,
cost, fallback, retry policy, consensus, direct autonomy, partial Phase 2 execution,
cleanup, and normal evaluation outcomes.

The sole bypass is P1-FINAL-01 at the evaluation callback-exception boundary.

- budget bypasses: **1**
- ModelUsageDelta/RequestDelta type coupling routes: **0**
- normal-path double accounting routes: **0**

### Autonomy and consensus

Autonomy remains an explicit bounded state machine with a max-iterations range,
closed transitions and stop reasons, duplicate execution identities, model and target
budgets, a pre-submit dry-run stop, policy-block limits, typed-only auto-execution,
and a cleanup barrier. No unbounded loop or cleanup bypass was found. One bounded
direct controlled run is technically ready after operator confirmation of the local
lab authorization, exact runtime configuration, test-owned accounts/objects,
request ceilings, cleanup capability, and loopback model endpoint. It must not be
wrapped in the defective evaluation path for benchmark claims.

Consensus preserves participant independence, rejects duplicate participant IDs,
does not count failures as votes, counts a fallback as one logical participant,
requires strict majority or unanimity according to policy, reports split and
insufficient outcomes conservatively, and cannot grant execution authority. P3-4's
gate remains mandatory after consensus.

- unbounded loops: **0**
- duplicate-execution routes: **0**
- dry-run target executions: **0**
- consensus execution bypasses: **0**
- cleanup-barrier bypasses: **0**

### Evaluation and external benchmark validity

Structural expectations and configuration identity are closed, and evaluation has
no prompt mutation, automatic tuning, ground-truth feedback, or result-to-rerun
loop. External baselines missing a verifiable material-v2 identity remain unknown.
Nevertheless, P1-FINAL-01 can lose or reuse model accounting and P2-FINAL-01 can lose
target accounting and exact provenance for legitimate controlled-autonomy outcomes.
External benchmark readiness is therefore **NO**.

### Real-provider and controlled-run readiness

- **OpenAI readiness: NOT READY.** The SDK is available, but P3_OPENAI_MODEL is not
  configured. No provider was contacted and no credential value was read or printed.
- **Anthropic readiness: NOT READY.** The required optional SDK and explicit model
  configuration are absent; no provider credential was used.
- **Ollama/DeepSeek readiness: READY, conditional.** The adapter has a default
  loopback origin and DeepSeek model name. An operator must start/confirm the service
  and model and verify the effective endpoint is loopback. It was not probed.
- **Consensus readiness: NOT READY.** Fewer than two real provider/model routes are
  currently confirmed usable, and evaluation-wrapped failure accounting has the P1
  defect.
- **Controlled autonomy readiness: READY, conditional.** The direct P3-4/Phase 2
  authority path is bounded and intact. Use only an explicitly authorized local lab,
  verified loopback model endpoint, exact budgets, controlled identities, and cleanup
  prerequisites. Do not make benchmark claims through P3-6 until the open findings
  are remediated.
- **External benchmark readiness: NOT READY.** Accounting and provenance can be lost
  on the two documented evaluation failure paths.

### Source-bypass inspection

Active Phase 3 production source matches were manually classified:

- ControlledVerificationExecutor: no Phase 3 direct use; it is reached only inside
  authoritative Phase 2 VerificationRuntime.
- safe_http / ScopedHTTPClient: no alternate Phase 3 target transport; Phase 2
  VerificationRuntime requires ScopedHTTPClient and binds its policy and ledger.
- requests: text/metric field names only in active Phase 3 source; no library import
  or network call.
- httpx: Ollama model-provider transport only, not target transport.
- urllib: urllib.parse.urlsplit for credential-free provider-origin validation only.
- aiohttp: no match.
- subprocess: no match.
- os.system: no match.
- shell=True: no match.
- eval(: no match.
- exec(: no match.

### Test integrity and quality gates

Collection remained exactly **1396 tests**. Eight Phase 3 modules contain 437 direct
test functions before parametrization. No pytest skip, skipif, xfail,
collection-ignore, disabled-module configuration, tracked test deletion, or weakened
security assertion was found. Phase 2 tracked source remained byte-for-byte unchanged
from HEAD.

Required gates:

- black --check .: **PASS** — 252 files unchanged.
- ruff check .: **PASS**.
- python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py
  campaign_cli.py model_eval_cli.py: **PASS**.
- python -m pytest -q: **PASS** — 1396 passed in 17.60 seconds. The first sandboxed
  run produced four PermissionError failures solely because test-owned loopback HTTP
  fixtures could not bind; the identical suite passed after loopback binding was
  permitted. No real provider or CyberCortex Range traffic occurred.
- git diff --check: **PASS**.
- git status --short --untracked-files=all: reviewed; it retained the pre-audit
  Phase 3 working tree plus the pre-existing .env.example, README.md, and
  docs/ROADMAP.md modifications. This audit changed only this document.

Branch after audit: **develop-v3**. Files deleted: **0**. No commit or push was
performed.

---

## P1-F1 — EVALUATION CALLBACK FAILURE ACCOUNTING REMEDIATION

Remediation date: **2026-09-09**

Status: **COMPLETE**

Scope: only P1-FINAL-01 from the latest Phase 3 final freeze audit. The known P2
intermediate-status representation issue and P3 local-only endpoint-locality issue
remain open and were not remediated. No Phase 2 source, benchmark repository,
provider, target, or CyberCortex Range execution was used.

### Root cause

P1-1-R2 correctly made ModelCallLedger authoritative at the P3-2 provider-start
boundary. ModelRouter commits a conservative reservation immediately before
invocation, replaces it with trustworthy actual usage on success, and finalizes a
started failure without refunding unknown usage.

That remediation did not cover the outer P3-6 callback abstraction. EvaluationRunner
previously caught EvaluationError or another callback exception, discarded every
object local to the callback, and constructed a new failed EvaluationCaseOutcome with
a zero/default ModelUsageDelta. EvaluationBudgetPreflight then reconciled that
replacement zero. When an evaluator created a fresh router for the next repetition,
the next router could not see the prior router's ledger, and the evaluation budget had
also forgotten the committed reservation. This allowed the exhausted reservation to
be reused even though the original ledger remained correct.

### Authoritative callback accounting boundary

ModelCallLedger remains the sole model-call and reservation authority. A process-local
ModelCallCapture now observes its immutable commit/finalization events only while an
evaluation callback is active. It has no routing, reservation, budget decision, or
provider API and cannot create model authority. Events are keyed by the concrete
ledger object and sequence, so a finalized record replaces its pending commit without
double counting, including when a callback uses multiple fresh routers.

EvaluationRunner opens that capture immediately before invoking the callback and
closes it afterward. On every success or exception path it derives ModelUsageDelta
from the P3-2 events when any authoritative ledger event occurred:

- no provider event: zero committed reservation remains valid;
- pending provider-start commit: conservative reservation and unknown actual usage;
- finalized started failure: conservative budget consumption and only trustworthy
  partial actual usage;
- successful response: reconciled actual usage and cost;
- fallback: each P3-2 attempt retained once, without reconstructing a fresh budget.

The failed outcome receives the captured usage and public-safe provider/model attempt
provenance. The existing evaluation budget reconciles that truthful delta, so later
repetitions and cases sharing the run budget cannot refund it.

### Reasoning, consensus, and autonomy preservation

Provider events are captured below reasoning parse and semantic validation, so a
successful provider response remains accounted when either later stage raises.
Timeout, rate-limit, connection, malformed response, normalized identity mismatch,
and fallback failures retain the exact P3-2 reservation semantics.

The three normalized evaluation observers record their latest public outcome inside
the active callback boundary. If user callback code raises after reasoning,
consensus, or autonomy observation, failure conversion preserves that outcome's
model usage and public provenance instead of rebuilding it from zero.

observe_autonomy_run also records a narrow accounting checkpoint after aggregating
the append-only iteration history and before constructing the final evaluation
outcome. This preserves ModelUsageDelta and the separate Phase 2 RequestDelta if a
later evaluation conversion raises. It does not change the P2 status enum: the known
verification_pending_cleanup/awaiting_controlled_evidence representation failure
still normalizes the case as autonomy_failed and still cannot serialize full
iteration provenance. The P2 issue therefore remains open, while its exception can no
longer erase P1 model accounting or P1-2 target-request accounting.

For ordinary terminal autonomy outcomes, a later outer callback exception preserves
the complete P1-3 iteration provenance, model usage, target RequestDelta, result
references, and public route provenance.

### Failed-case and run aggregation

EvaluationCaseOutcome continues to separate ModelUsageDelta from RequestDelta. A
model-only callback failure retains zero target traffic. An autonomy checkpoint with
already-observed target traffic retains its exact categorized RequestDelta.

ModelUsageMetrics now aggregates every case outcome, successful or failed, through
the same ModelUsageDelta addition rules. The run artifact includes unknown-usage
calls, actual tokens/cost, budget-consumed tokens/cost, failed calls, successful
calls, latency, and fallback counts. Backward-compatible defaults interpret older
actual-only evaluation metric artifacts without treating execution usage as
configuration.

Structural expectation application remains after callback failure normalization and
preserves usage. Runtime failure and expectation failure remain independent. The
material-v2 configuration fingerprint still consumes only configuration; actual and
reserved execution usage are not fingerprint inputs.

### Privacy and sanitization

The capture observes only strict ModelReservationCommit and ModelCallRecord objects.
Those contracts contain normalized provider/model identifiers, public correlation
identifiers, numeric usage/reservation values, normalized outcome codes, and latency.
They contain no prompt, response content, SDK response, exception object, credential,
header, cookie, session, password, recovery state, or chain-of-thought. Failure output
continues to use the closed EvaluationFailureCode enum rather than exception text.

Sentinel regressions cover API keys, Authorization/Bearer values, cookies, session
tokens, passwords, recovery secrets, raw provider response labels, and chain-of-
thought labels. None entered evaluation JSON.

### Focused regression evidence

Added **40** mock-only tests in
tests/test_phase3_evaluation_callback_accounting.py. Coverage includes:

- exception before provider start and after provider-start commit;
- successful actual-usage reconciliation followed by an outer exception;
- timeout, rate limit, connection failure, malformed response, and response
  normalization failure;
- reasoning parser and semantic-validator failures;
- consensus participant usage and autonomy reasoning usage checkpoints;
- failed-case visibility and successful-plus-failed run aggregation;
- exact/one-over repetition boundaries, remaining-budget allowance, cross-case retry,
  fallback, and priced cost reservation;
- unknown actual usage versus conservative budget usage;
- zero-default failure conversion, model-only zero RequestDelta, post-target
  RequestDelta, and terminal P1-3 iteration provenance;
- unchanged P2-1 expectation semantics and P2-2 fingerprint semantics;
- all requested secret/private sentinels; and
- the exact final-freeze-audit reproduction.

The exact reproduction now makes one mocked provider start. Repetition one reports
one failed/unknown call with its reserved output token. Repetition two is
budget_exhausted before evaluator entry and reports zero additional model usage. The
run aggregate reports one failed call and the same reserved output token.

### Post-remediation source inspection

- callback-exception zero-accounting routes remaining: **0**
- failed-case usage-loss routes remaining: **0**
- repetition budget-refund routes remaining: **0**
- consensus callback usage-loss routes remaining: **0**
- autonomy callback usage-loss routes remaining: **0**
- successful-only run aggregation routes remaining: **0**
- RequestDelta/ModelUsageDelta coupling introduced: **0**
- alternate ModelCallLedger introduced: **0**

Evaluation preflight budget failures remain the only zero-usage constructor outside
the callback boundary, and they occur before callback/provider entry. Generic callback
failure conversion now receives the active ledger capture and accounting checkpoint.
Budget-violation normalization and structural-expectation application copy the
existing outcome and therefore retain usage.

### Quality gates

- black --check .: **PASS** — 253 files unchanged.
- ruff check .: **PASS**.
- python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py
  campaign_cli.py model_eval_cli.py: **PASS**.
- python -m pytest -q: **PASS** — 1436 passed in 18.37 seconds.
- git diff --check: **PASS**.

P1-F1: COMPLETE

root cause identified: yes
authoritative callback accounting boundary: yes
started provider reservation survives callback exception: yes
successful actual usage survives callback exception: yes
failed unknown usage reservation preserved: yes
failed cases included in run aggregation: yes
repetition budget reuse prevented: yes
consensus callback accounting preserved: yes
autonomy callback accounting preserved: yes
P1-2 RequestDelta preservation: yes
P1-3 iteration provenance preservation: yes
P2-1 expectation semantics preserved: yes
P2-2 fingerprint semantics preserved: yes

callback-exception zero-accounting routes remaining: 0
failed-case usage-loss routes remaining: 0
repetition budget-refund routes remaining: 0
consensus callback usage-loss routes remaining: 0
autonomy callback usage-loss routes remaining: 0
successful-only aggregation routes remaining: 0
RequestDelta/ModelUsageDelta coupling introduced: 0

audit reproduction blocked: yes

tests added: 40
tests: 1436 passed
quality gates: PASS

Files changed by this remediation:

- agent_core/models/accounting.py
- agent_core/models/__init__.py
- agent_core/model_evaluation/runner.py
- agent_core/model_evaluation/types.py
- agent_core/model_evaluation/metrics.py
- tests/test_phase3_evaluation_callback_accounting.py
- docs/PHASE3_COMPLETION_AUDIT.md

Files deleted: **0**. Branch remains **develop-v3**. No commit or push was
performed.


---

## P2-F1 — PRESERVE VALID PHASE 2 INTERMEDIATE STATUSES IN EVALUATION

Remediation date: **2026-09-10**

Status: **COMPLETE**

Scope: only P2-FINAL-01 from the latest Phase 3 freeze audit. The P3 local-only
endpoint-locality finding remains open and was not inspected or remediated. No Phase
2 source or behavior was modified. No benchmark repository, provider, target,
Ollama service, or CyberCortex Range execution was used.

### Root cause

Phase 2 already defined the complete public result vocabulary in
`agent_core.phase2_result_status.Phase2ResultStatus` and explicitly separated its
four terminal statuses from its two intermediate statuses. P3-4 consumed that
authoritative contract and correctly recorded `verification_pending_cleanup` and
`awaiting_controlled_evidence` in append-only iteration history.

P3-6 independently declared `CanonicalPhase2ExpectationStatus` with only the four
terminal values. `observe_autonomy_run` cast every embedded P3-4 canonical status
through that stale evaluation-only enum, and `EvaluationCaseOutcome` repeated the
same cast while validating provenance. Either valid intermediate status therefore
raised `ValueError` during outcome construction. `EvaluationRunner` correctly
treated that unexpected observer exception as a runtime problem, but its generic
`autonomy_failed` representation could retain only the earlier narrow accounting
checkpoint, not the exact status or full iteration/result provenance.

The defect was a duplicated, terminal-only evaluation vocabulary—not malformed
Phase 2 data and not a P3-4 cleanup/control-flow defect.

### Canonical status consumption and fail-closed validation

Evaluation now types status expectations and observed status history directly with
the authoritative `Phase2ResultStatus`. The prior public evaluation name remains
only as a compatibility alias to that exact enum; it no longer declares or owns any
status values. Terminal/intermediate membership and aggregate classification consume
the authoritative `TERMINAL_RESULT_STATUSES` and `INTERMEDIATE_RESULT_STATUSES`
sets. A future canonical enum/set addition can therefore be accepted and counted
without first extending another closed evaluation enum.

Validation remains closed. An arbitrary status cannot populate strict expectation
or outcome fields. A fabricated status injected into iteration provenance raises at
observation, and a model-invented Phase 2 status is still rejected before canonical
P3-4 result provenance exists. No free-form acceptance path was added.

### Intermediate observation semantics

Both canonical intermediate states now produce an evaluation outcome containing the
exact `phase2_statuses` value and the complete embedded `AutonomyIterationRecord`.
They have `runtime_success=true` and no evaluation failure code unless a separate
observer/callback/runtime error actually occurs. They increment
`verifications_attempted` but not `verifications_completed`, and they do not increment
`verified`, `rejected`, `inconclusive`, or `policy_blocked` counts.

`verification_pending_cleanup` preserves `StopReason.cleanup_barrier`, the exact stop
transition reason, and the still-active P3-4 cleanup barrier. Evaluation performs no
mutation and cannot clear, override, or advance that state.

`awaiting_controlled_evidence` preserves
`StopReason.awaiting_controlled_evidence`, the exact stop transition reason, and the
deferred stopped state. Evaluation creates no account, credential, object, evidence,
or subsequent execution attempt.

### Accounting and provenance

The observer continues to sum the immutable P3-4 iteration records. Intermediate
outcomes therefore retain exact categorized target traffic, including zero traffic,
partial auth/verification traffic, and cleanup traffic, through `RequestDelta`. They
independently retain committed `ModelUsageDelta`; neither type derives from or
increments the other.

The outcome preserves the exact iteration number, reasoning decision identity and
route, consensus provenance when present, Phase 2 run/result reference, result ID,
result hash, executor version, per-iteration accounting, aggregate accounting, stop
reason, transitions, and full ordered iteration history. It consumes the embedded
history rather than a latest-only run alias. If a separate callback error occurs
after intermediate observation, P1-F1's checkpoint retains this complete outcome
while accurately changing only the evaluation runtime status/failure code.

### Expectations, metrics, reports, and comparison

P2-1 structural status expectations accept both intermediate enum values. A matching
expectation passes truthfully. A mismatch makes overall case success false while
leaving `runtime_success=true` and the runtime failure code null. P2-2 material-v2
fingerprints remain configuration-only and are unchanged by observed intermediate
status or accounting.

Case outcomes expose exact status history plus known per-status and aggregate
intermediate counts. Aggregate autonomy metrics expose:

- `verification_pending_cleanup_count`;
- `awaiting_controlled_evidence_count`; and
- `intermediate_outcome_count`.

JSON includes the exact status, runtime distinction, accounting/provenance, and
metrics. Human summaries show both intermediate classes separately. Run comparison
metrics and tables show cleanup-pending, awaiting-evidence, and actual evaluation
runtime-failure counts independently, so a deferred run cannot collapse into the
same representation as a failed observer.

### Privacy and controlled execution boundaries

The remediation adds no prompt, response, exception, credential, header, cookie,
session, password, recovery secret/state, or chain-of-thought field. API-key,
Authorization, cookie/session, password, recovery-secret, private-recovery-state,
chain-of-thought, and raw-provider-response sentinels placed in a post-observation
exception do not enter evaluation JSON. Failure output still uses only the closed
public failure enum.

All new execution tests use the existing scripted reasoning engine and mocked Phase
2 runtime. Evaluation remains observation-only. No provider or target was invoked,
no Ollama service was required, and neither cleanup nor controlled-evidence behavior
was altered.

### Focused regression evidence

Added **55** mock-only tests in
`tests/test_phase3_evaluation_intermediate_statuses.py` and updated the prior P1-F1
open-finding regression to assert the remediated outcome. Coverage includes:

- acceptance, exact identity, non-failure semantics, and non-completed semantics for
  both authoritative intermediate statuses;
- zero, partial, categorized, and cleanup target traffic; committed model usage;
- exact reasoning, iteration, result ID/hash/reference, executor, transition, and
  stop/barrier provenance;
- separate known-status, aggregate-intermediate, terminal-result, and failure
  metrics;
- JSON, human summary, comparison metrics/table, and runtime-failure distinction;
- matching/mismatching P2-1 expectations and unchanged P2-2 fingerprints;
- P1-F1 post-observation callback accounting, P1-2 target attribution, and P1-3
  append-only provenance;
- cleanup/control-evidence barrier immutability;
- arbitrary status rejection and canonical-source drift binding; and
- all requested secret/private sentinels.

### Post-remediation source inspection

- valid intermediate statuses rejected by evaluation: **0**
- intermediate-to-generic-failure routes remaining: **0**
- intermediate accounting-loss routes remaining: **0**
- intermediate provenance-loss routes remaining: **0**
- duplicated stale evaluation status vocabularies remaining: **0**
- Phase 2 status reinterpretation routes introduced: **0**
- RequestDelta/ModelUsageDelta coupling introduced: **0**

The generic evaluation failure route remains active only for actual callback,
observer, parser, validation, and runtime faults. The closed canonical enum rejects
unknown strings; recognizing its authoritative intermediate members does not weaken
that boundary.

### Quality gates

- `black --check .`: **PASS** — 254 files unchanged.
- `ruff check .`: **PASS**.
- `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py
  campaign_cli.py model_eval_cli.py`: **PASS**.
- `python -m pytest -q`: **PASS** — 1491 passed in 19.67 seconds. The managed
  sandbox initially denied four existing loopback mock-server binds; the approved
  loopback-only rerun passed without external target or provider traffic.
- `git diff --check`: **PASS**.

P2-F1: COMPLETE

root cause identified: yes
canonical status source reused: yes
verification_pending_cleanup preserved: yes
awaiting_controlled_evidence preserved: yes
terminal/intermediate distinction: yes
RequestDelta preserved: yes
ModelUsageDelta preserved: yes
iteration provenance preserved: yes
evaluation runtime failure distinction: yes
intermediate metrics: yes
JSON reporting: yes
human reporting: yes
comparison semantics: yes
unknown status still fails closed: yes

valid intermediate statuses rejected remaining: 0
intermediate-to-generic-failure routes remaining: 0
intermediate accounting-loss routes remaining: 0
intermediate provenance-loss routes remaining: 0
duplicated stale status vocabularies remaining: 0
Phase 2 status reinterpretation routes introduced: 0
RequestDelta/ModelUsageDelta coupling introduced: 0

tests added: 55
tests: 1491 passed
quality gates: PASS

Files changed by this remediation:

- `agent_core/model_evaluation/comparison.py`
- `agent_core/model_evaluation/metrics.py`
- `agent_core/model_evaluation/report.py`
- `agent_core/model_evaluation/runner.py`
- `agent_core/model_evaluation/types.py`
- `tests/test_phase3_evaluation_callback_accounting.py`
- `tests/test_phase3_evaluation_intermediate_statuses.py`
- `docs/PHASE3.md`
- `docs/PHASE3_COMPLETION_AUDIT.md`

Files deleted: **0**. Branch remains **develop-v3**. No commit or push was
performed. P3 remains open and unmodified.

---

## P3-F1 — CLARIFY `local_only` SEMANTICS

Remediation date: **2026-09-10**

Status: **COMPLETE**

Scope: only P3-FINAL-01 from the latest Phase 3 freeze audit. Runtime routing and
endpoint validation behavior were not changed. No Phase 2 source or behavior was
modified. No model provider, assessment target, benchmark repository, Ollama
service, or CyberCortex Range execution was used.

### Source-confirmed contract

`ModelRoutingPolicy.validate_routes` classifies `ollama` as the only current
local-model provider family. A `local_only` policy rejects every OpenAI or Anthropic
preferred/fallback route and permits configured Ollama-family routes. Consensus and
evaluation require their local-only participants/subjects to retain that same P3-2
routing mode and reject cloud-provider provenance.

Endpoint configuration is a separate concern. `ProviderConfiguration` accepts a
credential-free HTTP(S) origin with a hostname and does not require `localhost`,
`127.0.0.1`, `::1`, or another loopback address. `ModelConfiguration.from_env`
defaults `OLLAMA_BASE_URL` to `http://127.0.0.1:11434`, but an operator can explicitly
configure a non-loopback Ollama origin. The Ollama adapter sends its sanitized model
request to that configured origin. No source path currently asserts loopback or
same-machine locality.

The accurate public contract is therefore:

- `local_only` disables cloud-provider routes such as OpenAI and Anthropic;
- routing is restricted to configured local-model provider routes, currently the
  Ollama family;
- endpoint locality depends independently on the configured Ollama base URL; and
- the mode does not inherently guarantee loopback, same-device inference, same-LAN
  inference, offline operation, or absence of network transmission.

`http://127.0.0.1:11434` and `http://localhost:11434` are device-local loopback
examples. A non-loopback Ollama URL may transmit canonical sanitized model evidence
over a LAN or wider network. The existing Phase 2/public-result and ModelRequest
sanitation boundaries still apply, but sanitation does not make remote transport
equivalent to local processing. Operators must verify endpoint configuration before
relying on device-local privacy assumptions.

### Documentation and user-visible corrections

The README and roadmap no longer describe `local_only` as a general privacy mode or
present unconditional fully-local execution as the enforced configuration. They now
describe cloud-provider-disabled Ollama routing and qualify device-local inference
on a verified loopback/on-device endpoint.

The Phase 3 contract now explicitly distinguishes provider-family isolation from
endpoint locality, documents loopback and remote examples, lists the locality,
offline, and network properties the mode does not guarantee, and reiterates the
sanitized evidence boundary without equating it with local processing. It notes that
a distinct future mode such as `loopback_only` could enforce same-machine locality;
that mode is documentation-only and was not added to the routing enum or runtime.

`.env.example` labels both Ollama origins as loopback examples and warns that a
non-loopback URL can transmit sanitized model input over a network. Model-related CLI
help now says endpoint locality follows the configured base URL. Router, consensus,
and evaluation diagnostics say Ollama-family/cloud-provider-disabled routing rather
than implying physical endpoint locality. The Ollama adapter module description no
longer labels every configured endpoint as local.

### Severity and runtime disposition

The finding remained P3 because the provider-family security boundary was already
enforced: no OpenAI/Anthropic fallback can enter `local_only`, the endpoint is
explicitly operator-configured, URL credentials are rejected, canonical evidence is
sanitized, and there is no Phase 2 execution-authority impact. The defect was an
overstatement of privacy/locality in public descriptions.

No route validation condition, provider registry, endpoint validator, URL default,
provider call, fallback rule, budget, model request, sanitation rule, consensus
decision, evaluation rule, or Phase 2 path changed. Only documentation, configuration
comments, CLI/diagnostic descriptions, and one construction-only regression changed.
No loopback enforcement or strict-local feature was introduced.

### Focused regression evidence

The existing router suite already verifies that `local_only` rejects OpenAI, rejects
Anthropic, invokes only configured Ollama, and never contacts a cloud provider. Added
**1** focused construction-only regression proving that a credential-free
non-loopback Ollama URL remains accepted while its model route remains
`RoutingMode.local_only` and Ollama-family-only. The test constructs configuration
and policy objects only; it does not create or invoke a provider.

### Quality gates

- `black --check .`: **PASS** — 254 files unchanged.
- `ruff check .`: **PASS**.
- `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py
  campaign_cli.py model_eval_cli.py`: **PASS**.
- `python -m pytest -q`: **PASS** — 1492 passed in 19.68 seconds, using only the
  approved loopback binding required by existing mock HTTP-server tests.
- `git diff --check`: **PASS**.

P3-F1: COMPLETE

current local_only semantics confirmed: yes
OpenAI blocked in local_only: yes
Anthropic blocked in local_only: yes
Ollama-family routing allowed: yes
loopback locality guaranteed: no
remote Ollama possible: yes
documentation corrected: yes
CLI/config wording corrected where needed: yes
runtime behavior changed: no
future strict-local mode documented only: yes

tests added: 1
tests: 1492 passed
quality gates: PASS

Files changed by this remediation:

- `.env.example`
- `README.md`
- `agent_cli.py`
- `agent_core/consensus/types.py`
- `agent_core/model_evaluation/types.py`
- `agent_core/models/ollama_provider.py`
- `agent_core/models/router.py`
- `docs/PHASE3.md`
- `docs/PHASE3_COMPLETION_AUDIT.md`
- `docs/ROADMAP.md`
- `model_eval_cli.py`
- `tests/test_phase3_model_router.py`

Files deleted: **0**. Branch remains **develop-v3**. No commit or push was
performed.

---

## PHASE 3 FINAL CLOSURE AUDIT

Audit date: **2026-09-10**

Status: **COMPLETE — READY TO FREEZE**

Scope: the exact current `develop-v3` tree only. This audit made no runtime,
feature, test, or Phase 2 change. It did not invoke OpenAI, Anthropic, Ollama,
an assessment target, CyberCortex Range, or benchmark ground truth. The only
audit write is this appended evidence.

### Final disposition

Phase 3 completion is **100%**. No P0, P1, P2, or P3 finding remains open in
the audited tree. All ten prior remediation identifiers independently rechecked
as closed: P1-1, P1-1-R2, P1-F1, P1-2, P1-3, P1-4, P2-1, P2-2, P2-F1, and
P3-F1.

### Prior-finding recheck

1. **P1-1 — failed-started provider accounting: PASS.** `ModelRouter` performs
   definite pre-call checks before committing, commits the complete reservation
   immediately before the sole provider invocation boundary, retains that
   reservation for timeout, rate-limit, malformed-response, and other started
   failures, and reconciles successful reservations to reported actual usage.
2. **P1-1-R2 — shared budget exhaustion: PASS.** The authoritative P3-2 ledger
   uses committed call/input/output/total/cost usage for exact and one-over
   checks. Fallback, later same-provider attempts, consensus participants,
   autonomy retries, and evaluation repetitions cannot reuse a failed
   reservation or reset a run budget.
3. **P1-F1 — evaluation callback accounting: PASS.** The model-call capture
   observes reservation commits and final records without creating a second
   ledger. Evaluation callback frames retain the most recent public outcome,
   model usage, target RequestDelta, and provenance before later callback,
   validation, or construction failures.
4. **P1-2 — target request attribution: PASS.** P3-4 snapshots the authoritative
   Phase 2 request ledger before runtime submission and computes the delta after
   return or exception. Runtime, normalization, result-validation, provenance,
   history, cleanup, and partial-execution failures therefore retain all actual
   categorized target traffic; pre-transport failures remain exactly zero.
5. **P1-3 — multi-iteration provenance: PASS.** Every iteration appends an
   immutable record containing transitions, exact reasoning/consensus identity,
   gate outcome, Phase 2 result identity, RequestDelta, ModelUsageDelta, pivot,
   and terminal reason. Run and evaluation totals are recomputed from the full
   ordered history; earlier records are not overwritten or resolved through a
   latest-result alias.
6. **P1-4 — authoritative runtime identity: PASS.** Only the exact
   `VerificationRuntime` type can receive the sealed process-local P3-4 binding.
   The binding cannot be subclassed, copied, deep-copied, or serialized. The
   deterministic gate validates issuer identity, and model/configuration data
   contain no field capable of selecting or forging runtime authority.
7. **P2-1 — structural expectations: PASS.** Every configured expectation is
   deterministically checked against canonical outcome fields. Expectation
   failure changes case success without changing `runtime_success`, accounting,
   provenance, or measured structural data, and no feedback/rerun/tuning path is
   created.
8. **P2-2 — material configuration identity: PASS.** Material-v2 fingerprints
   cover every declared subject, route, budget, consensus, autonomy, case,
   capability, policy, expectation, repetition, pricing, and evaluator-output
   reservation field. Completeness assertions fail when model fields drift.
   Secrets, execution usage, timestamps, random run IDs, and ephemeral paths are
   excluded; absent external identity is reported as unknown.
9. **P2-F1 — intermediate Phase 2 statuses: PASS.** Evaluation imports the
   canonical `Phase2ResultStatus` and canonical terminal/intermediate sets.
   `verification_pending_cleanup` and `awaiting_controlled_evidence` remain exact
   runtime-success observations with their accounting, iteration/result
   provenance, reasons, pause/barrier state, metrics, expectations, JSON, human
   report, and comparison identity intact. Unknown strings still fail closed.
10. **P3-F1 — `local_only` contract: PASS.** Runtime and documentation agree that
    `local_only` rejects OpenAI and Anthropic and permits only configured
    Ollama-family routes. The URL validator intentionally accepts credential-free
    non-loopback HTTP(S) origins. Public text accurately states that the mode does
    not itself guarantee loopback, same-device/same-LAN inference, offline
    operation, or no network transmission.

### Execution authority and source-bypass inspection

The active chain remains:

`provider -> ModelRouter -> ReasoningEngine -> ConsensusEngine (when used) ->`
`AutonomousOrchestrator -> ExecutionDecisionGate -> sealed VerificationRuntime`
`binding -> Phase 2 policy/runtime -> ControlledVerificationExecutor ->`
`VerificationHTTPTransport -> ScopedHTTPClient -> target transport`.

P3-4 contains exactly one Phase 2 submission site. Reasoning and consensus are
advisory and expose no executor/callback/tool authority. Consensus arbitration
still feeds a validated `ReasoningDecision` through the same mandatory P3-4 gate.
The gate rechecks typed capability, plan identity, automatic-execution support,
authorization, controlled accounts and credentials, state-change and cleanup
requirements, test ownership, Phase 2 policy authorization, request budget,
duplicate identity, and cleanup barrier before submission.

Manual classification of the requested source patterns found:

- `ControlledVerificationExecutor`: authoritative Phase 2 registry/runtime only;
  absent from active Phase 3 reasoning, consensus, autonomy, and evaluation.
- `safe_http` / `ScopedHTTPClient`: the authoritative Phase 2 target transport;
  no alternate P3 target client.
- `httpx`: Ollama model-provider transport only, not target transport.
- `urllib`: parsing/normalization imports in inspected paths, not a P3 target
  transport.
- `requests`: legacy/tool and `ScopedHTTPClient` implementations outside P3
  execution authority; no active P3 bypass.
- `aiohttp`, `os.system`, `shell=True`, `eval(`, and `exec(`: no active Phase 3
  matches.
- `subprocess`: legacy diagnostic/tool CLI paths outside Phase 3 authority; no
  P3-4 execution route.

Final authority counts: direct model execution routes **0**; direct executor
bypasses **0**; alternate target HTTP transports **0**; Phase 2 policy/runtime
bypasses **0**; model-controlled runtime selection routes **0**.

### Privacy, accounting, budgets, and autonomy

Provider configuration excludes API-key values from dumps and representations.
Provider responses are normalized immediately, configured keys are removed from
content and call identifiers, public failures use fixed codes, telemetry stores
no prompt/response/exception/secret field, histories contain only structured
public data, and evaluation artifacts must round-trip unchanged through the
canonical public-result sanitizer. No persistent/public route was found for API
keys, Authorization/Bearer values, cookie/session values, passwords, recovery
secrets, private recovery state, raw provider responses, raw private prompts, or
chain-of-thought.

`ModelUsageDelta` and `RequestDelta` remain distinct typed contracts and ledgers.
Actual provider usage remains separate from conservative committed usage.
Pre-call blocks commit nothing; started failures retain reservations; success
reconciles to actual usage; callback failures preserve observed usage. Phase 2
RequestDelta remains the target-traffic authority for verified, rejected,
inconclusive, policy-blocked, cleanup-pending, awaiting-evidence, runtime,
normalization, provenance, persistence/history, cleanup, and partial results.

Hard boundaries remain enforced for calls, input/output/total tokens, estimated
cost, autonomy iterations, verification count, and target requests. Exact
boundaries are accepted where permitted and one-over attempts fail closed.
Fallback, retry, consensus, autonomy, repeated evaluation, and callback exceptions
do not reset those boundaries.

Autonomy is a bounded state machine with an explicit finite transition map and a
`range(1, max_iterations + 1)` loop. Duplicate execution identity is checked
before submission. Cleanup-pending stops with an active barrier;
awaiting-controlled-evidence stops without fabricating context. Plan-only
categories never execute, Phase 2 policy blocks remain authoritative, and dry-run
stops with zero target execution.

### Consensus, provenance, and evaluation validity

Consensus creates a fresh validated request for each deterministic participant,
orders participants canonically, rejects duplicate IDs and duplicate logical
routes by default, and records a fallback chain as one participant. Only valid
structured decisions vote; invalid, failed, timeout, rate-limited, and
budget-blocked participants do not. Unanimous, strict-majority, tie/split, and
explicit single-model-advisory semantics remain deterministic, and no consensus
outcome itself grants execution authority.

Reasoning decisions, consensus participants/decisions, autonomy iterations and
pivots, Phase 2 result IDs/hashes/references, executor versions, model usage,
request deltas, and terminal/intermediate states remain exact and public-safe.
Latest-only provenance routes, iteration overwrite routes, and runtime-authority
serialization routes are all **0**.

Structural expectations remain separate from runtime failure; canonical Phase 2
statuses are not reinterpreted; intermediate statuses are retained; material-v2
fingerprints are complete and secret-free; compatibility is honest and unknown
when an external fingerprint is absent. External imports accept aggregate metrics
only and reject ground-truth-identifying fields. No benchmark feedback, automatic
tuning, benchmark-aware routing, or prompt-mutation route exists.

### Readiness

- **OpenAI smoke test: NOT READY.** The adapter and installed SDK are code-ready,
  but this environment has neither `OPENAI_API_KEY` nor an explicit
  `P3_OPENAI_MODEL`. No provider call was attempted.
- **Anthropic smoke test: NOT READY.** The optional SDK, API key, and explicit
  model are absent. No provider call was attempted.
- **Ollama/DeepSeek smoke test: READY, conditional.** The HTTP adapter and default
  model/base URL configuration are available. The configured endpoint/service
  must be independently verified by the operator; this audit did not contact it.
- **Multi-model consensus smoke test: NOT READY.** Fewer than two independently
  configured real provider/model routes are currently ready in this environment.
- **Controlled autonomy test: READY, conditional.** The bounded authority,
  accounting, budget, provenance, cleanup, and evidence barriers are code-ready
  for one operator-authorized local-lab run after explicit policy, controlled
  context, vault, target class, and endpoint configuration. No run was performed.
- **External benchmark: READY.** The current tree has no identified ground-truth
  leakage, tuning route, budget ambiguity, accounting/provenance/status loss,
  expectation ambiguity, or configuration-compatibility ambiguity. CyberCortex
  Range and benchmark ground truth were not accessed.

### Test integrity and quality gates

No deleted test is present in repository status, and no skip, skipif, xfail, or
runtime skip marker was found in `tests/`. Critical source-structure assertions
remain present for the sole runtime submission path, absence of Phase 3 executor
imports/transports, sealed runtime identity, complete iteration provenance,
callback accounting, canonical status drift, material fingerprint completeness,
and no feedback/tuning route.

- `black --check .`: **PASS** — 254 files would be unchanged.
- `ruff check .`: **PASS**.
- `python -m compileall agent_core tools tests agent.py phase2_cli.py policy_cli.py
  campaign_cli.py model_eval_cli.py`: **PASS**.
- `python -m pytest -q`: **PASS** — 1492 passed in 19.50 seconds using only
  repository mocks and existing local loopback test servers.
- `git diff --check`: **PASS**.
- `git status --short --untracked-files=all`: inspected; no deleted files and the
  branch remains `develop-v3`.

### Closure counts

```text
PHASE 3 FINAL CLOSURE AUDIT

completion: 100%

P0: 0
P1: 0
P2: 0
P3: 0

ready to freeze: YES
ready for OpenAI smoke test: NO
ready for Anthropic smoke test: NO
ready for Ollama/DeepSeek smoke test: YES
ready for multi-model consensus smoke test: NO
ready for controlled autonomy test: YES
ready for external benchmark: YES

all prior findings passed: 10/10

provider credential leaks: 0
remote evidence sanitizer bypasses: 0
model-output execution bypasses: 0
direct security execution bypasses: 0
Phase 2 policy/runtime bypasses: 0
runtime identity forgery routes: 0
target-request attribution-loss routes: 0
latest-only provenance routes: 0
model/request accounting inconsistencies: 0
budget bypasses: 0
unbounded loops: 0
consensus execution bypasses: 0
cleanup-barrier bypasses: 0
evaluation feedback/tuning routes: 0
structural expectation bypasses: 0
configuration fingerprint omissions: 0
intermediate-status loss routes: 0
chain-of-thought persistence routes: 0
```

P0 findings: **none**.

P1 findings: **none**.

P2 findings: **none**.

P3 findings: **none**.

Files changed by this audit: `docs/PHASE3_COMPLETION_AUDIT.md` only.

Files deleted: **0**. No commit or push was performed.

## P3 REAL-MODEL STRUCTURED OUTPUT COMPATIBILITY

A real Ollama/DeepSeek-R1 32B smoke test reached the P3-3 reasoning layer. The
provider, `ModelRouter`, model inference, model-call ledger, and accounting all
succeeded. The model returned semantically reasonable advice but used
schema-invalid values: a string (`"medium"`) for integer `priority` and `null`
for array-valued `missing_evidence`.

The strict parser correctly rejected that output, and a direct parser check
confirmed that valid JSON arrays are accepted for tuple-backed fields. The root
cause was therefore underspecified model-facing output types in `_SINGLE_OUTPUT`
and `_RANKING_OUTPUT`, not a parser defect. The `reasoning-grounded-v2` prompt
contract now states every JSON field type, integer bound, enum, grounding rule,
and array/null requirement; forbids fences, comments, extra fields, and
surrounding prose; and supplies a compact schema-conformant example. Ranking
uses the identical object contract and requires exact supplied-hypothesis
coverage without duplicates.

Strict `ReasoningCandidate` types, exact JSON parsing, semantic validation,
capability and evidence-reference grounding, policy constraints, model routing,
accounting, autonomy gates, and Phase 2 execution authority remain unchanged.
No coercion, repair, malformed-output retry, additional model call, fallback
change, execution route, or model-budget behavior was introduced.

## P3 OLLAMA STRUCTURED OUTPUT COMPATIBILITY

A subsequent real DeepSeek-R1 32B Phase 3 smoke test using
`reasoning-grounded-v2` produced substantively schema-correct reasoning: field
types and the intended advisory contract were correct. The remaining failure was
Markdown wrapping around the JSON. This confirmed that the hardened prompt was
working, while DeepSeek still emitted code fences and the strict parser correctly
rejected anything other than exact raw JSON.

Source inspection confirmed that `OllamaProvider` reduced every structured
request to `payload["format"] = "json"`. Live testing identified this generic
JSON mode as insufficient for the installed DeepSeek-R1 32B behavior: the model
could still wrap otherwise schema-correct JSON in Markdown. The strict parser's
rejection was correct and is not the root cause. `parse_reasoning_candidate` and
`parse_reasoning_candidates` intentionally retain exact JSON parsing with no
Markdown-fence stripping, prose recovery, malformed-output repair, or coercion.

`ModelRequest.structured_output` still defaults to `false`, preserving every
existing caller. It now optionally carries a canonicalized, recursively frozen,
64,000-byte-bounded, public-safe JSON schema object. The schema admits data only,
requires the structured-output intent, and is mapped only to the provider's
structured-output field; it cannot inject callbacks, code, tools, transport
options, or arbitrary top-level provider payload. A structured request without a
schema retains the existing generic JSON mode.

`build_reasoning_model_request()` derives the single-object schema directly from
`ReasoningCandidate.model_json_schema()` and derives ranking's exact-length array
schema from the same object contract. It retains `reasoning-grounded-v2` and
reasoning schema version 1 because neither model-visible prompt text nor the
semantic output model changed. Public request metadata carries only a
deterministic SHA-256 identity of the schema. Ollama sends that schema object as
top-level `format` on the same single `/api/chat` call; generic structured callers
still receive `format: "json"`.

Direct `/api/chat` testing also showed that `think=false` did not disable the
thinking channel for this DeepSeek-R1 32B/Ollama combination. The fix does not
send or depend on `think=false`. `message.thinking` is ignored, and only
`message.content` remains authoritative model response content.

The current OpenAI and Anthropic adapters do not claim enforcement they have not
implemented. Structured requests to those adapters fail deterministically as
`provider_unavailable` before transport starts, with existing reliability
fallback and failed-start accounting semantics; ordinary requests are unchanged.
No output repair, Markdown stripping, malformed-output retry, extra provider
call, target execution path, semantic-validation bypass, budget change, or Phase
2 authority change was introduced. Capability and evidence-reference grounding,
request-cost and policy constraints, hypothesis identity, reservations, actual
usage reconciliation, latency/cost accounting, and strict parser behavior remain
authoritative.

## P3 ADVISORY / EXECUTION AUTHORITY SEPARATION

Real DeepSeek P3-3 validation successfully crossed real Phase 2 evidence
construction, Ollama provider execution, `ModelRouter`, JSON-schema structured
output, raw JSON generation, strict `ReasoningCandidate` parsing, and
`ModelUsageDelta` accounting. It then reached deterministic semantic validation,
where an otherwise grounded `recommend_verification` decision was rejected
because P3-3 also required the Phase 2 plan to be ready for execution. The real
packet carried `plan_policy_decision=pending` and
`plan_automatic_execution_allowed=false`.

The duplicated P3-3/P3-4 checks found by source inspection were:

| P3-3 semantic check | Authoritative P3-4 check |
|---|---|
| supplied hypothesis and known capability | eligible hypothesis and registry capability lookup |
| typed-verification capability state | `CapabilityState.typed_verification` |
| typed executor availability | typed route availability |
| capability/hypothesis category identity | live hypothesis/capability category identity |
| capability automatic-execution support | registry capability automatic-execution support |
| plan `automatic_execution_allowed` | live plan `automatic_execution_allowed` |
| plan policy decision is `allowed` | live plan policy is `allowed` and runtime `authorize_plan()` allows it |

The capability and grounding checks remain in P3-3 as advisory validity
constraints. The two plan execution-readiness facts no longer cause rejection by
themselves. A pending policy adds the deterministic public-safe precondition
`Phase 2 plan policy authorization is required.` A non-automatic plan adds
`Automatic execution eligibility is required.` Canonical capability
preconditions remain first, duplicates are removed without changing order, and
the model cannot supply or override these values. An explicitly blocked plan
policy still fails closed. An allowed automatic plan adds neither unresolved
precondition.

P3-4 remains the sole Phase 3 execution preflight. Its checks for plan automatic
eligibility, authoritative Phase 2 runtime binding, authorization, controlled
accounts, credentials, state-change policy, opt-ins, cleanup, test-owned
resources, runtime `authorize_plan()`, allowed plan policy, request/model/
iteration/verification budgets, cleanup barriers, and duplicate identities are
unchanged. Consensus can agree only on advisory data and the mapped decision is
revalidated before it reaches the same gate. No consensus execution authority,
direct executor path, target transport, or Phase 2 bypass was added.

The `reasoning-grounded-v2` prompt remains unchanged because it already states
that reasoning is advisory and that a model decision is not execution
authorization; the successful DeepSeek recommendation also demonstrated that
the deterministic rejection, not model instruction alignment, was the live
failure. Reasoning and iteration/consensus provenance, execution identities,
cleanup barriers, evaluation accounting, and `ModelUsageDelta` behavior remain
unchanged. Advisory acceptance creates no target request and no `RequestDelta`.

## PHASE 3 POST-LIVE FREEZE AUDIT

Audit date: 2026-09-11

This final audit reviewed the production code and tests after the controlled
local-model validation. It did not rerun the live target, call an external
target, exercise the Range, or use OpenAI or Anthropic. No credential or secret
value is recorded here.

All ten previously closed Phase 3 findings remain closed: P1-1, P1-1-R2,
P1-F1, P1-2, P1-3, P1-4, P2-1, P2-2, P2-F1, and P3-F1. The resulting severity
counts remain P0=0, P1=0, P2=0, and P3=0.

The production execution path remains bounded by the authoritative Phase 2
runtime binding and `ExecutionDecisionGate`. A `ReasoningDecision` and any
consensus result remain advisory. Deterministic preconditions, Phase 2 policy,
controlled-context and credential-vault checks, typed executor selection,
request-budget admission, cleanup requirements, and gate approval remain
mandatory before `submit()` can reach the Phase 2 executor. Approved dry runs
create only a `ProposedVerification`, return `dry_run_complete`, and produce no
Phase 2 result or target `RequestDelta`.

Model-call reservations are retained for started failures and reconciled once
for successful calls. Fallback, consensus, autonomy, and evaluation share the
applicable budget instead of resetting or refunding it. Target requests are
derived once from the authoritative Phase 2 `RequestBudget`, retained on failed
outcomes, stored with their originating iteration, and aggregated across the
full append-only history. The authentication-enforcement shape of one auth
request plus two verification requests is valid and is represented as
`RequestDelta(auth=1, verification=2, cleanup=0, total=3)`.

Strict structured output remains enforced without Markdown stripping, output
repair, malformed-output retry, or a hidden extra provider call. Ollama receives
the JSON schema through its native structured-output field. Raw prompts,
controlled credentials, target secrets, provider credentials, and raw model
thinking are not persisted; only public-safe provider/model provenance and
validated advisory decisions cross the model boundary.

Structural evaluation expectations remain authoritative, material-v2
fingerprints retain material configuration while excluding secrets and
ephemeral values, callback failures retain captured usage, failed cases remain
in aggregation, and valid intermediate Phase 2 statuses remain preserved.
Evaluation and consensus have no execution authority.

### Previously observed live evidence (not rerun)

- Real Ollama/DeepSeek reasoning: PASS.
- Blocked P3-4 dry run: PASS.
- Approved P3-4 dry run: PASS.
- Bounded P3-4 live execution: PASS.
- Exactly 3 target requests were observed.
- The observed `RequestDelta` was auth=1, verification=2, cleanup=0, total=3.
- The canonical result was `inconclusive`. This is a valid security
  classification and is not an architecture failure.
- No request ceiling violation occurred.
- No fallback was used.
- No runtime failure occurred.
- No autonomy failure occurred.

The provider-neutral Phase 3 core has no independently confirmed P0, P1, P2,
or P3 freeze blocker. OpenAI and Anthropic configuration and live-provider
validation remain post-freeze integrations rather than core freeze blockers.

Final local quality gates passed: Black, Ruff, compilation, all 1,539 tests,
and the Git whitespace check.

## POST-FREEZE OPENAI PROVIDER INTEGRATION

Integration date: 2026-09-11

The immutable `phase3-freeze` tag remains at commit `e64af48`. This section
records post-freeze provider work and does not revise the provider-neutral Phase
3 architecture or any frozen safety, accounting, provenance, routing, consensus,
evaluation, autonomy, or Phase 2 execution-authority boundary.

Direct provider validation established that the configured `gpt-5.5-pro` access
was incompatible with the prior Chat Completions production path, while a direct
Responses API request completed successfully. The OpenAI adapter now uses one
`client.responses.create(...)` call and normalizes `output_text`, returned model
identity, terminal status, Responses input/output token usage, response ID, and
existing catalog cost into the unchanged `ModelResponse` contract. No raw SDK
response, prompt, evidence, provider exception body, reasoning trace, or hidden
chain-of-thought is persisted.

OpenAI now advertises provider-native structured-output support. Generic JSON
uses the Responses JSON-object text format. Schema requests pass the exact
canonical provider-neutral schema through the Responses JSON Schema text format
with `strict=true`; the schema is neither weakened nor mutated. The existing
strict `ReasoningCandidate` parser and semantic validator remain authoritative.
There is no output repair, Markdown stripping, malformed-output retry, schema
field synthesis, or second provider call.

System instructions remain Responses instructions. User content and sanitized
evidence remain separate input text blocks, and evidence still crosses the
existing Phase 2 `public_result`/`ModelRequest` sanitizer boundary. The adapter
sends no tools, web search, file search, function calling, provider metadata, or
execution surface, and requests `store=false`. It remains advisory text and
structured-output transport only.

The Responses output ceiling is the smaller of the request and provider
configuration limits. `gpt-5.5-pro` and dated snapshots omit the unsupported
temperature transport field without changing provider-neutral request
validation. Authentication, access/permission, rate-limit, timeout, connection,
configuration, and invalid-response failures retain fixed public-safe errors;
403/404 access denial maps to the existing `provider_unavailable` code rather
than being mislabeled as credential rejection.

Returned dated OpenAI snapshot IDs are validated as realizations of the selected
alias. Provider-start reservation, failed-start retention, exact successful usage
reconciliation, fallback/shared budgets, telemetry, reasoning provenance,
consensus participation, autonomy, and evaluation accounting remain unchanged
and occur exactly once. `local_only` still blocks OpenAI. Ollama and Anthropic
adapter behavior is unchanged.

This integration did not make a paid provider call. Direct Responses validation
is previously observed evidence only. A real routed P3-3 OpenAI reasoning PASS is
not claimed here and remains scheduled for separate manual validation.

Post-integration local quality gates passed: Black, Ruff, compilation, all 1,554
tests, and the Git whitespace check.

## POST-FREEZE OPENAI STRICT-SCHEMA COMPATIBILITY

Compatibility fix date: 2026-09-11

Real OpenAI P3-3 structured reasoning reached Responses API schema validation,
where the API rejected the canonical Pydantic schema before generation. OpenAI
strict Structured Outputs require every key in an object's `properties` map to
also appear in that object's `required` array; the canonical schema correctly
omitted Python-defaulted fields such as `evidence_references` under normal JSON
Schema semantics.

The provider-neutral `ReasoningCandidate` contract was not weakened or changed,
and the strict parser and semantic validator remain unchanged and authoritative.
At the OpenAI transport boundary only, the adapter now creates a deterministic
deep copy of the canonical schema and recursively sets each schema object's
`required` array to its property keys in property order. This applies to the
root, definitions, nested properties, array items, and schema-composition
branches without mutating `ModelRequest.structured_output_schema`.

Defaulted arrays, including `evidence_references` and `missing_evidence`, are
therefore required in the OpenAI payload and must be emitted as `[]` when empty;
they remain non-nullable JSON arrays. Nullable fields, including
`recommended_capability` and `stop_reason`, are required to be present while
retaining their canonical null allowance. Types, enums, bounds, descriptions,
references, `additionalProperties`, and all other contract constraints remain
unchanged. A schema that cannot be adapted without losing an existing required
constraint fails closed before transport through the public-safe configuration
error path.

The request still uses `strict=true` and exactly one Responses provider call.
No output repair, retry, or additional provider call was introduced. Ollama
continues to receive the canonical provider-neutral schema, and Anthropic
behavior is unchanged. No paid provider call was made while implementing or
testing this compatibility fix.

## OPENAI PRICING ACCOUNTING

Post-freeze accounting support adds GPT-5.5 Pro standard API pricing at $30/M
input tokens and $180/M output tokens, with no cached-input discount. The dated
snapshot is mapped deterministically and exactly to its configured alias; other
unlisted OpenAI models remain unknown.

The real P3-3 model returned `gpt-5.5-pro-2026-04-23`. Previously observed real
usage was 3,887 input tokens and 2,056 output tokens, producing an expected
standard API estimate of approximately $0.48669. This task did not perform a new
paid provider call.

No provider, routing, or execution semantics changed.
