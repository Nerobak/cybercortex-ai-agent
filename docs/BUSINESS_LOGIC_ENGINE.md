# Business Logic Analysis Engine

CyberCortex v2.1 adds an offline-first, evidence-driven workflow analysis layer. It
does not infer vulnerabilities from route names, parameters, missing requests, or
response differences. Those inputs produce observations or manual-review
hypotheses only.

## Evidence and canonical model

`workflow_evidence_discovery` accepts explicit sanitized JSON and classifies
ordered steps, shared identifier categories, state-field presence, and
authentication context. Raw bodies, credentials, cookies, tokens, payment data,
personal data, verification values, and private identifiers are not retained.

`workflow_model_builder` converts supported ordered evidence into deterministic
actors, resources, steps, transitions, states, invariants, and unknowns. Missing
states remain `unknown`; captured order is not represented as proven server-side
enforcement.

## Offline analysis and comparison

Transition analysis records ordering, state-changing operations, actor boundaries,
one-time-value metadata, replay sensitivity, and idempotency metadata.
Business-rule analysis recognizes quantity, amount, price, currency, coupon,
ownership, tenant, role, state, approval, one-time-use, and idempotency categories.
`workflow compare` compares only redacted metadata and response structure hashes.

## Manual planning

Plans require medium- or high-confidence ordered evidence. Every plan requires
controlled accounts, test-owned resources, reversible actions, minimal requests,
evidence collection, stop conditions, cleanup, and explicit prohibited actions.
Financial, destructive, regulated/KYC, administrative, and account-security
workflows are blocked from automatic planning.

## Replay restrictions

Replay is disabled by default and never runs during analysis or a normal scan:

```text
BUSINESS_LOGIC_REPLAY_ENABLED=false
BUSINESS_LOGIC_TIMEOUT_SECONDS=15
BUSINESS_LOGIC_MAX_RESPONSE_BYTES=1000000
BUSINESS_LOGIC_MAX_STEPS=10
BUSINESS_LOGIC_MAX_REQUESTS_PER_RUN=3
```

The authenticated `workflow replay <file>` command additionally requires explicit
controlled-account and test-owned-resource confirmations. Only in-scope GET/HEAD
requests are accepted. Redirects are scope checked. State changes, financial
operations, destructive actions, security-setting changes, KYC, third-party
access, concurrency, mutation, floods, and resource manipulation are prohibited.
A completed replay remains an observation.

## Commands

```text
workflow analyze workflow.json
workflow model workflow.json
workflow compare account-a.json account-b.json
workflow plan workflow.json
workflow explain
workflow replay controlled-get.json
```

Local JSON input is limited to 64 KiB. Prefer sandbox traces and never include raw
production credentials. Limitations include incomplete captures, optional steps,
application-specific state semantics, and the inability of offline evidence to
prove server-side enforcement or impact.
