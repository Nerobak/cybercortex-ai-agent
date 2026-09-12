# CyberCortex Phase 3

Phase 3 begins with a provider-neutral foundation for advisory model reasoning.
P3-1 supplies contracts and adapters. P3-2 adds deterministic operator-configured
model routing, bounded reliability fallback, and an authoritative model-call
ledger. P3-3 adds evidence-grounded, structured advisory reasoning. None of
these components gives a model execution authority. P3-4 adds a bounded state
machine that may submit an eligible recommendation only through the existing
Phase 2 verification runtime. P3-5 adds independent multi-model decisions and
deterministic advisory consensus without changing that runtime boundary. P3-6
adds passive, benchmark-independent measurement and comparative telemetry; it
does not feed results back into model or execution configuration.

## Architecture and frozen Phase 2 relationship

Models may reason about already-sanitized CyberCortex evidence. They remain
outside every active verification authority boundary:

```text
Phase 2 public_result evidence -> EvidencePacket -> ReasoningRequest
                                                   |
                                                   v
                                      deterministic prompt builder
                                                   |
                                                   v
strict ModelRequest -> ModelRouter -> registry -> provider adapter
                         |                         |
                         v                         v
                 model-call ledger       strict ModelResponse
                                                   |
                                                   v
                               JSON schema + semantic validator
                                                   |
                                                   v
                                  advisory ReasoningDecision

Optional P3-5 advisory selection:
same canonical ReasoningRequest -> independent ReasoningDecision objects
  -> exact structured agreement -> deterministic arbitration
  -> validated P3-4-compatible ReasoningDecision -> P3-4 decision gate

P3-6 observation only:
normalized reasoning / consensus / autonomy / Phase 2 artifacts
  -> strict per-case outcomes -> aggregate metrics -> reports/comparisons

Active verification remains exclusively:
policy -> capability registry -> controlled context -> verification planner
       -> request budget -> controlled executor -> evidence classifier
       -> sanitizer -> immutable provenance
```

The model package has no shell, Python execution, arbitrary target HTTP, Phase 2
executor, automatic verification, or model-tool-call route. Provider traffic is
limited to the explicitly configured model API. A model response cannot approve
policy, consume a Phase 2 network request budget, invoke a capability, or
classify a finding as verified.

`MODEL DECISION != EXECUTION AUTHORIZATION`. A validated P3-3 decision remains
advisory data. It has no `execute()` method, and the reasoning package has no
route to the Phase 2 controlled executor or security tools.

Phase 2 remains frozen at `v2.1.0-beta-rc` / commit
`c9b3fcc5df2695aeec8d832a271b7d543c23cae7`. Phase 3 does not alter its policy,
capability, evidence, accounting, controlled-context, sanitization, or
provenance semantics.

## Provider abstraction

`agent_core.models.ModelProvider` defines the common contract. Every adapter has
`provider_name`, `model_name`, an availability result, and
`generate(ModelRequest) -> ModelResponse`. OpenAI, Anthropic, and Ollama SDK or
HTTP objects are converted inside their adapters and never escape into the
CyberCortex model contract.

`ProviderRegistry` performs deterministic provider lookup, construction,
supported-provider enumeration, alias resolution, and validation. It does not
score or select models. P3-2's separate `ModelRouter` consumes a strict routing
policy and asks the registry for only the explicitly declared routes.

Supported adapters are:

- `openai`: optional OpenAI SDK, environment/configuration API key, normalized
  Responses API text output, and native structured JSON/JSON Schema output.
- `anthropic`: optional Anthropic SDK, environment/configuration API key,
  normalized Messages API text output, and native structured JSON Schema output.
- `ollama`: HTTP adapter, default loopback origin, configurable model, and
  support for DeepSeek or any other Ollama chat model. When a request explicitly
  requires structured output, the adapter sends either Ollama's native top-level
  `format: "json"` generic control or the request's bounded JSON schema as
  `format`, on the same `/api/chat` call.

Missing cloud keys and missing optional SDKs mark only the affected provider as
unavailable. They do not break package import or Ollama-only operation. Ollama
connection failures occur deterministically when that provider is used; startup
does not require a running Ollama service.

The OpenAI adapter uses one `responses.create(...)` call. System instructions,
user content, and canonical sanitized evidence remain separate Responses input
fields/blocks. Schema-less structured requests use the native JSON-object format;
schema requests pass the exact canonical provider-neutral schema through
`text.format` with strict native enforcement. The adapter does not add tools,
output repair, Markdown stripping, malformed-output retries, or a second call.
It disables provider-side response storage and retains only normalized public-safe
response fields.

The Anthropic adapter uses one `messages.create(...)` call. Plain requests retain
their existing Messages payload and text-block normalization. Structured requests
use `output_config.format` with `type: "json_schema"`; a supplied canonical schema
is deep-copied before any transport-only compatibility adaptation and is never
mutated. Anthropic does not natively support the numeric, string-length, and most
array bounds present in the strict `ReasoningCandidate` schema, so those constraints
are removed only from the provider transport copy and recorded exactly in transport
descriptions. The unchanged canonical schema and strict reasoning parser remain
authoritative downstream. Schema objects must remain closed with
`additionalProperties: false`; an incompatible schema fails closed before provider
transport. Schema-less structured requests use a closed empty-object schema, the
only generic object contract exposed by this adapter.

Anthropic structured responses accept only one documented text content block, a
normal `end_turn`, and valid JSON. Empty, incomplete, refusal, multi-block, thinking,
or malformed output fails closed without Markdown stripping, repair, retry, field
synthesis, or another provider call. Structured mode deterministically omits the
unsupported `temperature` provider parameter without changing the provider-neutral
request. Thinking remains omitted, and the adapter sends no tools or tool choice.
Returned model identity, response ID, input/output usage, and correlation fields are
normalized into the existing public-safe response and accounting paths.

OpenAI responses preserve a returned dated model snapshot, while validating that
it is either the configured route or that route's `YYYY-MM-DD` realization.
Provider reservations remain keyed to the configured route and reconcile once to
the returned snapshot and actual Responses token usage. For `gpt-5.5-pro` and its
dated snapshots, the adapter omits the unsupported `temperature` transport field;
the provider-neutral request and its validation are not changed or reinterpreted.

## Request and evidence safety boundary

`ModelRequest` is strict, immutable, and rejects unknown fields. It contains
instructions, task content, structured evidence, sampling/output bounds,
correlation identifiers, public-safe metadata, and a strict boolean
`structured_output` intent that defaults to `false`. An optional
`structured_output_schema` carries only a canonicalized, size-bounded,
public-safe JSON schema object and is valid only with that intent enabled. The
schema is detached from caller-owned containers and frozen recursively after
validation. It cannot carry callbacks, executable code, transport options, or
arbitrary provider payload fields. The request has no callback, tool, executor,
transport, or arbitrary request field. Callers that omit the schema retain the
existing generic structured-output behavior.

Structured evidence must already equal the output of the canonical Phase 2
`public_result` serializer. Raw credentials, Authorization headers, cookies,
session tokens, recovery secrets, private recovery state, and raw vault contents
therefore fail request validation. `ModelRequest.from_phase2(...)` applies that
canonical serializer before constructing a request. The same boundary applies to
Ollama requests, including configured remote endpoints, so provider behavior remains
consistent.

System and user prompt text must also be public-safe. Provider output and
metadata are normalized through the existing text/public-result sanitizers.
Configured API-key values are explicitly removed from provider content and call
identifiers before a `ModelResponse` is created.

## Deterministic model routing

`ModelRouter.route(ModelRequest, ModelRoutingPolicy)` returns the existing
normalized `ModelResponse`. Routing policy is a separate strict, immutable input;
prompt text and model output cannot alter routes, allowlists, attempt limits, or
budgets. The router never interprets response text as an instruction.

The modes are deterministic:

- `preferred`: invoke only the preferred provider/model. Fallback is prohibited.
- `local_only`: invoke only explicitly listed local-model provider routes,
  currently Ollama-family.
  OpenAI and Anthropic are rejected at policy validation, even as inactive
  fallback entries.
- `cloud_only`: invoke only explicitly listed cloud routes that also appear in
  `allowed_cloud_providers`.
- `fallback_chain`: invoke the preferred route followed by configured fallback
  routes in exact declaration order, bounded by `max_provider_attempts`.

Cloud-provider evidence transfer always requires an explicit provider allowlist.
The router never silently appends a provider. `local_only` is therefore
cloud-provider-disabled/Ollama-only routing: an unavailable Ollama route fails
deterministically without OpenAI or Anthropic contact.

`local_only` does not inspect `OLLAMA_BASE_URL` and does not inherently guarantee a
loopback endpoint, same-device inference, same-LAN inference, offline operation, or
absence of network transmission. The default `http://127.0.0.1:11434` and an
explicit `http://localhost:11434` are device-local loopback examples. A configured
non-loopback Ollama URL may transmit canonical sanitized model evidence across a
network. Operators must verify the endpoint before relying on device-local privacy
assumptions. The canonical sanitation boundary still applies to remote Ollama, but
sanitation does not make remote transport equivalent to local processing. A future
distinct mode such as `loopback_only` could enforce same-machine locality; no such
mode or enforcement exists today.

P3-2 has zero retries. The same provider/model identity cannot appear twice in a
policy. A different provider/model is a fallback, and only
`provider_unavailable`, `timeout`, `rate_limited`, and `connection_failed` may
advance the chain. Authentication, configuration, malformed-response, routing,
and budget failures stop immediately. Answer content, agreement, findings, and
benchmark outcomes never cause fallback.

The router relies on the provider's configured timeout and does not add health
requests before each call. The route chain and each provider timeout are bounded;
there is no uncontrolled retry loop.

## Fallback provenance and normalized response

`ModelResponse` normalizes provider/model identity, content, finish reason,
input/output/total tokens, estimated API cost, measured latency, safe provider
call identifier, task/run/hypothesis correlation, fallback fields, and sanitized
metadata. Total tokens must equal input plus output tokens.

A routed success also records the requested provider/model, actual
provider/model, fallback flag and depth, total attempted calls, and every prior
attempt as provider/model/index plus a normalized error code. It never retains a
raw exception, request body, provider SDK object, Authorization header, cookie,
session token, recovery secret, or API key. Provider-specific response objects
still terminate inside the P3-1 adapter boundary.

## Model-call ledger and usage delta

Every attempted `generate` call records a `ModelCallTelemetry` event, including
failures. Telemetry contains no prompt, response content, API key, headers,
cookies, raw exception, or raw provider object. Model token and API-call
telemetry is deliberately separate from Phase 2 `RequestDelta`; LLM API calls
are not target network-security request counts.

`ModelCallLedger` is the P3-2 authority for routed model attempts. Each record
contains provider/model, success or normalized failure, token counts, known or
unknown cost, latency, task/run/hypothesis correlation, and fallback depth.
Before/after `ModelLedgerSnapshot` values produce a strict `ModelUsageDelta`.
The delta enforces:

```text
attempted_calls == successful_calls + failed_calls
total_tokens == input_tokens + output_tokens
```

All counts, costs, and latency values are non-negative. If any selected record
has unknown cost, aggregate cost remains `None`; it is not converted to zero.
Ollama's explicitly defined local API cost remains `0.0`.

`ModelUsageDelta != RequestDelta`. Model calls and model tokens never increment,
reserve, or otherwise modify the Phase 2 target-network request ledger.

## Model budgets and monetary ceilings

`ModelBudgetLimits` supports per-run model calls, input tokens, output tokens,
total tokens, estimated API cost, and a per-call estimated-cost ceiling. The
router checks the authoritative run ledger before each initial or fallback call.
If another attempt is not allowed, it stops before constructing/invoking that
provider.

Input preflight uses a deterministic conservative UTF-8-byte estimate. Output
allowance is reduced to the remaining output/total budget before calling the
provider. Reported provider usage is then reconciled against every hard token
limit and recorded truthfully in the ledger.

Monetary preflight uses configured `ModelPricingCatalog` data and the bounded
input/output estimate. With the default `unknown_cost_policy=deny`, an unknown
price under any strict per-call or run monetary ceiling fails closed before the
call. `unknown_cost_policy=allow` is an explicit policy choice; it preserves cost
as `None` and does not invent a number.

`ModelPricingCatalog` and `ModelConfiguration.pricing` centralize provider/model
aliases and per-million-token prices. The catalog includes standard API pricing
for `gpt-5.5-pro` ($30/M input and $180/M output) and an exact mapping for the
`gpt-5.5-pro-2026-04-23` snapshot. No cached-input discount applies. Other cloud
pricing is unknown unless supplied as data, so unknown prices produce
`estimated_cost_usd=None` while token counts remain available. Ollama defaults to
`0.0` API cost; no subscription, Batch, Flex, Fast, or Scale Tier pricing is used.

## Configuration

`ModelConfiguration.from_env()` supports:

```text
MODEL_DEFAULT_PROVIDER=ollama
MODEL_TIMEOUT_SECONDS=60
MODEL_MAX_OUTPUT_TOKENS=4096

OPENAI_API_KEY=
P3_OPENAI_MODEL=
P3_OPENAI_BASE_URL=

ANTHROPIC_API_KEY=
P3_ANTHROPIC_MODEL=
P3_ANTHROPIC_BASE_URL=

OLLAMA_BASE_URL=http://127.0.0.1:11434
P3_OLLAMA_MODEL=deepseek-r1:32b
```

The shown Ollama origin is a loopback example, not a `local_only` requirement.
Changing `OLLAMA_BASE_URL` to a non-loopback HTTP(S) origin can send sanitized model
input over a network. Verify the configured endpoint independently before making
device-local or offline privacy claims.

API keys are held as excluded secret configuration values. They are never
printed, logged, persisted in model responses/telemetry, placed in prompts, or
included in public errors. `.env.example` contains blank cloud-key placeholders
only.

OpenAI remains present in the main project requirements for its Phase 3 Responses
adapter and legacy local OpenAI-compatible use. Anthropic is intentionally
optional; install its SDK only when that provider is selected. Importing
`agent_core.models` does not require the Anthropic SDK.

## Errors

Public provider failures use a fixed safe vocabulary:

- `provider_unavailable`
- `authentication_failed`
- `timeout`
- `rate_limited`
- `connection_failed`
- `invalid_response`
- `configuration_error`
- `routing_exhausted`
- `routing_policy_blocked`
- `model_budget_exceeded`
- `unknown_cost`

Raw SDK exception strings, request bodies, provider internals, headers, and
credentials are not copied into public errors or telemetry.

## Evidence-grounded reasoning

`EvidencePacket` is the canonical provider-independent projection of one Phase
2 hypothesis. It contains its opaque identifier, category, concise rationale,
confidence and priority, public target surface and evidence basis, evidence
references, required context, limitations, capability state, typed-executor
availability, exact registry request bounds, an optional public verification
plan summary, and an optional canonical prior-result summary. Construction
passes the source through `public_result`; direct construction rejects evidence
that has not already crossed that boundary.

`ReasoningRequest` contains one or more evidence packets, the full read-only
capability catalog, policy-safe constraints, previous structured decisions, and
model-budget context. The catalog projects only metadata from the frozen Phase
2 registry: category, state, schema identifier, executor version, request
bounds, major preconditions, and typed/automatic availability. It contains no
executor object or callable. Raw credentials, headers, cookies, session tokens,
recovery secrets, private recovery state, credential-vault contents, arbitrary
filesystem paths, callbacks, and unsanitized HTTP bodies are not valid reasoning
input.

The canonical catalog is rebuilt and compared immediately before every model
call. A caller or model cannot forge category state, executor availability,
request bounds, or policy permission. Unknown categories are rejected.

## Deterministic prompt and untrusted evidence

The `reasoning-grounded-v2` prompt builder is versioned and deterministic. It tells every model to
reason only from supplied evidence, distinguish observation from hypothesis,
use only supplied capability identifiers, avoid credentials, commands, URLs,
tool calls, execution instructions, and return only the strict JSON schema.
Target-derived evidence is placed in the normalized evidence field rather than
interpolated into system instructions.

The v2 model-facing contract explicitly identifies integer fields and their
0-through-100 bounds, requires JSON arrays rather than `null` for evidence and
missing-evidence lists, limits `null` to documented nullable fields, and forbids
Markdown fences, comments, extra fields, and surrounding prose. It includes one
schema-only JSON example. Ranking applies the same field contract to exactly one
object per supplied hypothesis. This prompt-version change does not change the
reasoning schema version or relax strict parsing and semantic validation.

Every reasoning request sets `structured_output=true` and carries the schema
derived from `ReasoningCandidate.model_json_schema()`. Ranking carries the
corresponding exact-length array schema over the same candidate object. With
Ollama this schema becomes the native `format` object on the same provider call,
without changing the system/user messages, evidence serialization, model
options, response content, retry policy, or accounting. A deterministic SHA-256
schema identity is retained in public-safe request metadata; raw configuration is
not. Provider schema enforcement is only a generation constraint: the existing
exact parser and semantic validator remain the authorities for the reasoning
contract and Phase 2 grounding.

Live testing of the installed DeepSeek-R1 32B/Ollama combination established the
root cause for schema-correct output still arriving in Markdown fences: generic
`format: "json"` mode was insufficient for that provider behavior. Direct
`/api/chat` testing also showed that `think=false` did not disable the model's
thinking channel in this combination. CyberCortex therefore neither adds nor
depends on `think=false`; it ignores `message.thinking` and continues to treat
only `message.content` as authoritative model output.

Every target-derived string remains untrusted data, including text such as
"ignore previous instructions" or "execute this command." This is not a claim
of perfect prompt-injection prevention. The primary protection is the
deterministic boundary after the model: routing policy is immutable, output is
strictly parsed and validated, and no validated decision has an execution path.

CyberCortex does not ask a provider for hidden chain-of-thought and does not
store it. Only concise rationale and structured evidence references are
accepted. Raw reasoning prompts are not written to reasoning history.

## Structured decisions and semantic validation

Provider text is untrusted. The only accepted pipeline is:

```text
ModelResponse.content
  -> exact JSON parse
  -> strict ReasoningCandidate schema
  -> Phase 2 catalog/policy semantic validation
  -> ReasoningDecision
```

No code-fence recovery, prose interpretation, or best-effort execution parsing
is performed. Unknown fields, malformed JSON, unknown actions, capabilities or
hypotheses, category mismatches, invalid confidence, negative costs, commands,
URLs, and credential requests fail closed.

The closed action vocabulary is `prioritize`, `recommend_verification`,
`request_additional_evidence`, `manual_review`, `defer`, and `stop`.
`recommend_verification` is valid only when the canonical capability is typed,
has a registered executor route, supports automatic execution, matches the
hypothesis category, remains explicitly policy-allowed, and has an estimated
request count within registry truth and the remaining target-request budget.
Required controlled-context preconditions are copied from the registry into the
decision; the model cannot remove them. This still recommends rather than
executes the capability.

Plan execution readiness is not advisory authorization. An explicitly blocked
plan policy still rejects `recommend_verification`, but a pending plan policy or
`automatic_execution_allowed=false` does not invalidate otherwise grounded
advice. Instead, P3-3 appends the stable public-safe requirements `Phase 2 plan
policy authorization is required.` and/or `Automatic execution eligibility is
required.` after the canonical capability preconditions. These values come only
from canonical Phase 2 evidence, are de-duplicated in deterministic order, and
are not part of the model-authored candidate schema. A fully allowed automatic
plan receives no unresolved execution-readiness precondition.

These preconditions grant no authority. P3-4 independently evaluates the live
plan, authoritative runtime, policy, controlled context, credentials, budgets,
cleanup state, and prior execution identity before any Phase 2 submission.

Plan-only and discovery-only categories cannot produce a verification
recommendation. They may be referenced only for `manual_review` or
`request_additional_evidence`. Non-verification actions must estimate zero
target requests. A prior `policy_blocked` result cannot be converted into a
bypass recommendation, and prior `verified`, `rejected`, or `inconclusive`
classifications are preserved rather than rewritten.

`expected_information_gain` uses only `low`, `medium`, or `high`. Ranking accepts
exactly one validated candidate per supplied hypothesis, then applies stable
priority, confidence, information-gain, request-cost, and hypothesis-ID ordering.
It returns an ordered tuple of advisory decisions and performs no execution or
consensus.

## Common reasoning engine and model facades

`ReasoningEngine` provides the single prompt, routing, parsing, semantic
validation, provenance, history, and ranking implementation. Thin
`GPTReasoningAgent`, `ClaudeReasoningAgent`, and `DeepSeekReasoningAgent` facades
configure that same engine for OpenAI, Anthropic, or Ollama routing. The
DeepSeek facade selects a configured Ollama model; neither the engine nor the
Ollama provider is hard-wired to DeepSeek. All providers return the same
`ReasoningDecision` schema, so independent model decisions can be compared by a
later milestone without P3-3 implementing consensus.

Every decision records safe provenance: requested and actual provider, actual
model, fallback flag, safe provider call identifier when available, task type,
reasoning schema version, and the exact `ModelUsageDelta` between ledger
snapshots around that reasoning call. This attributes calls, tokens, cost, and
latency without touching Phase 2 accounting.

`ReasoningHistory` stores only the validated decision fields, concise rationale,
evidence and missing-evidence references, sanitized model provenance, and an
UTC timestamp. It stores neither raw prompts nor chain-of-thought.

Reasoning failures use a deterministic safe vocabulary:
`model_unavailable`, `model_budget_exhausted`, `invalid_model_output`,
`unsupported_recommendation`, `evidence_validation_failed`, and
`sanitization_failed`. A failure produces no decision and can never trigger
security execution.

`ModelUsageDelta != RequestDelta`. Reasoning model calls are attributed through
the P3-2 model ledger. They do not consume, increment, reserve, or otherwise
modify the Phase 2 target-network request ledger.

## Bounded autonomous orchestration

`AutonomousOrchestrator` connects validated P3-3 advice to the authoritative
Phase 2 boundary. The only active path is:

```text
sanitized evidence
  -> ReasoningEngine
  -> validated ReasoningDecision
  -> ExecutionDecisionGate
  -> VerificationRuntime.execute_selected
  -> Phase 2 policy/runtime preflight
  -> existing controlled executor and scoped transport
  -> canonical public Phase 2 result and RequestDelta
  -> sanitized result-review evidence
  -> ReasoningEngine
```

The autonomy package neither imports nor constructs
`ControlledVerificationExecutor`, resolves an executor, creates a network
client, nor sends an HTTP request. It submits typed `Hypothesis` and
`VerificationPlan` objects only to `VerificationRuntime.execute_selected`, the
same shared Phase 2 entry point used by existing scan and CLI paths. The runtime
then independently re-applies its policy gate, controlled-context binding,
credential vault, request budget, cleanup rules, scoped transport, result
classifier, sanitizer, and provenance contract.

`MODEL DECISION != EXECUTION AUTHORIZATION`.

`PHASE 2 REMAINS FINAL EXECUTION AUTHORITY`.

An orchestration-gate approval means only that a recommendation is eligible for
submission. It is not Phase 2 approval and cannot override a later Phase 2
policy or runtime denial.

## Explicit state machine

Every run begins in `initialized` and follows only declared transitions among
`observing`, `reasoning`, `decision_validation`,
`awaiting_execution_approval`, `executing`, `evaluating`, `pivoting`, `stopped`,
and `failed`. Invalid transitions raise a deterministic error. The loop is a
bounded `for` over `max_iterations`; there is no recursive or unbounded agent
loop.

`AutonomyRun` records only public references and strict accounting: autonomy and
Phase 2 run identifiers, target reference, current state and iteration, selected
hypothesis/capability, the latest validated decision, result and reasoning
references, aggregate `ModelUsageDelta`, aggregate authoritative Phase 2
`RequestDelta`, verification/failure/duplicate/block counts, cleanup barrier,
proposed dry-run submission, deterministic stop/failure code, and timestamps.
It never stores a vault value, private recovery state, raw provider response, or
raw target response.

## Execution decision gate

`ExecutionDecisionGate` rebuilds eligibility from deterministic truth. A
recommendation can pass only when all of the following hold:

- the action is `recommend_verification`, and the hypothesis and matching plan
  exist in the current run;
- the named capability exists in the frozen registry, is typed, has its typed
  route, matches the hypothesis category, supports automatic execution, and the
  plan has `automatic_execution_allowed=true`;
- the supplied object is the shared Phase 2 runtime boundary;
- the Phase 2 policy and plan contain explicit authorization, the policy
  authorizes the plan, `plan.policy_decision` is `allowed`, and any
  capability-specific policy opt-in is present;
- the required count of policy-eligible controlled accounts exists;
- required credential references exist in the live process-local vault without
  materializing or persisting their values;
- state-change permission, deterministic cleanup, and test-owned-object
  requirements are satisfied where required;
- the authoritative Phase 2 request ledger has enough remaining capacity for
  the conservative registered/plan request bound;
- P3-2 model budget, P3-4 iteration budget, and P3-4 verification budget remain
  available;
- no cleanup barrier or identical prior execution identity applies.

Failure at any check produces one closed, sanitized `GateReason`. The model
cannot modify the gate input, registry, policy, context, vault, budgets, or
prior execution identities. Plan-only and discovery-only categories always
fail automatic eligibility and produce no typed result or target traffic.

## Pivots, duplicate prevention, and cleanup barrier

Canonical Phase 2 results retain their exact status. `verified`, `rejected`,
`inconclusive`, and `policy_blocked` results become sanitized prior-result
evidence for a bounded result-review iteration. Verified and rejected paths are
resolved and cannot execute again. An identical hypothesis, capability, and
public controlled-context fingerprint is rejected as a duplicate regardless of
model repetition. The fingerprint contains only hashed public account/object
identifiers and the plan reference—never credential handles or values.

`policy_blocked` is never reinterpreted or bypassed. Only its sanitized status
and reasons return to reasoning; repeated blocks terminate at the configured
threshold. `awaiting_controlled_evidence` stops without fabricating an account,
credential, or object. `verification_pending_cleanup`, or the canonical Phase 2
cleanup-unverified reason, activates a cleanup barrier and stops new
state-changing submission. P3-4 does not implement cleanup itself.

Other deterministic terminal outcomes include a model stop, manual review,
additional evidence required, no eligible hypotheses, all paths resolved,
model call/token/cost exhaustion, Phase 2 request exhaustion, maximum
iterations/verifications, reasoning-failure or duplicate limits, service
instability, and fatal runtime failure. Stop and pivot reasons are closed enums,
not raw model or exception text.

## Dry run and routing modes

With `dry_run=true`, grounded reasoning and every deterministic gate check may
run, but `VerificationRuntime.execute_selected` is never called. The run records
the validated hypothesis, capability, plan reference, and conservative request
estimate that would have been submitted, then stops as `dry_run_complete` with
zero Phase 2 target requests.

The orchestrator passes the exact immutable P3-2 routing policy to every reasoning
call. `local_only` therefore remains Ollama-family-only and cannot contact OpenAI or
Anthropic. Endpoint locality still depends on the configured Ollama base URL. Cloud
routes retain their explicit provider allowlist, sanitizer boundary, fallback rules,
and model budget. Provider fallback changes model reliability provenance only; it
never changes execution eligibility or Phase 2 authority. P3-4 uses one configured
reasoning route per decision and implements no voting, arbitration, or consensus.

## Autonomy budgets, accounting, and history

`AutonomyLimits` supplies only orchestration-specific bounds:
`max_iterations`, `max_verifications`, `max_reasoning_failures`,
`max_duplicate_recommendations`, and `max_policy_blocks`. It does not recreate
P3-2 token/cost/call budgets or the Phase 2 target request budget. Instead it
reads their existing typed states and stops before an ineligible submission.

Reasoning usage is attributed from each decision's P3-2 ledger delta; failed
reasoning calls are recovered from before/after model-ledger snapshots when
available. Target traffic is aggregated only from canonical Phase 2
`RequestDelta` objects returned by the runtime.

`ModelUsageDelta != RequestDelta`. Model calls and tokens are not target network
requests, and neither counter mutates the other.

`AutonomyHistory` exposes one strict record per iteration: state transitions,
decision reference, selected hypothesis/capability, gate outcome, hashed Phase 2
result reference, model usage delta, Phase 2 request delta, pivot reason, and
stop reason. It stores no raw prompt, provider response, Phase 2 result body,
chain-of-thought, credential, header, cookie, session token, recovery secret, or
private recovery state.

## Multi-model consensus architecture

`ConsensusEngine` accepts one strict `ConsensusRequest`: the complete canonical
P3-3 `ReasoningRequest`, one to N explicit participant routing policies, a
strict consensus policy, a consensus coordination budget, task/run identifiers,
and an iteration reference. It validates the P3-3 evidence and capability
catalog before any participant call. Participant IDs and route configurations
are deterministic, duplicate logical participants are rejected unless the
operator explicitly allows them, and calls occur in canonical participant-ID
order.

Each participant receives a separately materialized but semantically identical
copy of the same immutable `ReasoningRequest`. A participant sees no prior or
concurrent participant decision. Only after all bounded calls complete does the
consensus engine inspect their validated `ReasoningDecision` objects. Target
text cannot change the participant list, routing policies, cloud allowlists,
model budgets, consensus policy, or capability catalog.

Provider fallback remains solely a P3-2 `ModelRouter` reliability behavior. One
configured participant produces at most one vote, regardless of how many
fallback attempts its route required. The participant outcome records the
configured provider/model and the actual provider/model selected by the router;
the actual route must be one of the participant's declared routes.

## Agreement and arbitration semantics

Agreement uses only the exact structured tuple
`(hypothesis_id, action, recommended_capability)`. Rationale similarity and
provider identity never determine a vote. Agreement classifications are:

- `unanimous`: every configured participant returned a valid identical vote;
- `majority`: more than half of the valid decisions returned the same vote;
- `split`: a tie, three-way disagreement, rejected plurality, unmet confidence
  threshold, or a non-unanimous result under a unanimity policy;
- `single_model_advisory`: exactly one valid decision and the policy explicitly
  permits advisory single-model output;
- `insufficient_participants`: the configured participant minimum is absent;
- `invalid_decisions`: too few participants produced valid decisions.

A failed model call is not a vote. Provider unavailability, timeout, rate limit,
model-budget exhaustion, consensus-budget blocking, and invalid structured
decisions remain separate participant outcomes. An invalid or failed participant
does not poison other valid decisions. For example, two identical valid votes
plus one invalid decision may form a majority when the configured valid-participant
minimum permits it; they are not reported as unanimous.

The default split result is `manual_review`. Strict policies may instead select
`request_additional_evidence` or `defer`; no provider wins a tie. Majority and
unanimous choices are deterministic and still advisory. If `require_unanimity`
is enabled, any dissent produces a split. If `require_majority` is enabled, a
plurality is insufficient.

For a selected unanimous, majority, or single-model advisory vote, confidence is
aggregated as the arithmetic mean of only the supporting valid decisions after
mapping P3-3 confidence to fixed bounded values: low `0.25`, medium `0.50`, and
high `0.75`. Split and no-selection results report the mean across all valid
decisions as diagnostic confidence only. A selected result must meet the
explicit aggregate confidence threshold. There are no hidden provider weights
or provider preferences. P3-5 does not implement an arbiter-model call.

## Consensus budgets and routing/endpoint semantics

Consensus coordination is sequential and bounded. Before each logical
participant, the engine conservatively reserves that route's maximum declared
provider attempts, the deterministic prompt/evidence byte estimate, maximum
output tokens, and configured pricing estimate against the consensus call,
input, output, total-token, and API-cost ceilings. Unknown cloud pricing fails
closed when a monetary ceiling is active unless policy explicitly allows
unknown cost. Ollama retains its configured zero API-cost semantics.

These coordination limits do not replace P3-2 budgets. Every participant's
immutable `ModelRoutingPolicy` still passes through the P3-2 router and its
authoritative `ModelCallLedger`, call/token/cost limits, local-only mode,
fallback bounds, and explicit cloud-provider allowlist. Local-only consensus
accepts only `local_only` Ollama-family routes and can never silently add OpenAI or
Anthropic; it does not add endpoint-locality enforcement. With one configured
Ollama model, the result is insufficient or a
single-model advisory only when the policy explicitly allows that outcome.

`ConsensusDecision.model_usage` is the strict aggregate of participant
`ModelUsageDelta` values: attempted, successful, and failed model calls; input,
output, and total tokens; API cost; and latency. One unknown participant cost
makes aggregate cost unknown rather than zero. This usage never reads or mutates
Phase 2 target traffic accounting.

`ModelUsageDelta != RequestDelta`.

## Consensus history and P3-4 integration

`ConsensusHistory` stores only consensus and participant decision identifiers,
agreement type, selected advisory action/capability, aggregate confidence,
dissent, invalid/failed participant identifiers, deterministic arbitration
reason, aggregate model usage, and a timestamp. It stores no model prompt,
provider response, rationale transcript, chain-of-thought, raw target result,
credential, header, cookie, session token, recovery state, or secret.

`consensus_to_reasoning_decision` is the sole P3-4 integration mapping. It turns
the selected advisory fields into a new P3-3 candidate, binds consensus usage as
sanitized provenance, and submits that candidate through the existing P3-3
semantic validator. The result is ordinary advisory `ReasoningDecision` data.
It has no `execute()` method. It must still pass `ExecutionDecisionGate`, then
the shared Phase 2 runtime must independently approve and execute it. Consensus
does not import a Phase 2 executor, call a target transport, alter prior Phase 2
result classifications, invent capabilities, or use benchmark ground truth.
Consensus may therefore agree on a grounded recommendation whose plan policy is
still pending; deterministic P3-3 preconditions record that unresolved state,
while the unchanged P3-4 gate continues to deny execution.

`CONSENSUS != EXECUTION AUTHORIZATION`.

`EVEN UNANIMOUS MODEL AGREEMENT MUST PASS P3-4 AND PHASE 2.`

## Model evaluation architecture

P3-6 adds a measurement-only `agent_core.model_evaluation` package. A strict
`EvaluationSubject` identifies one explicit single-model, consensus, dry-run
autonomy, or controlled-autonomy configuration. It embeds only normalized P3-2
routing policies, an explicit P3-5 consensus policy/budget when applicable, and
P3-4 autonomy limits when applicable. Subjects support one to N configured model
routes without embedding credentials or provider clients.

A strict `EvaluationCase` wraps one canonical P3-3 `ReasoningRequest`, optional
structural expectations, an execution mode, P3-2 model limits, P3-4 autonomy
limits, and a bounded repetition count. Cases contain sanitized synthetic or
externally supplied public evidence. They contain no hidden expected finding,
benchmark-specific vulnerability identifier, callback, provider response,
credential, or executable instruction.

`EvaluationRunner` invokes only a supplied outcome observer and accepts only
strict `EvaluationCaseOutcome` data. It does not construct a provider, route a
model, alter a prompt, run consensus, submit a recommendation, or call Phase 2.
Specific integration functions observe already normalized P3-3 decisions,
P3-5 consensus results, or completed P3-4 runs. Controlled evaluation therefore
has no second autonomy or execution implementation: active execution, when an
operator separately requests it, remains entirely within `AutonomousOrchestrator`
and the shared Phase 2 runtime. Dry-run outcomes are schema-forbidden from
containing a nonzero `RequestDelta`.

Structural expectations are a closed, typed, public-safe measurement contract.
Cases may require deterministic reasoning action/capability/validity/identity,
consensus agreement class, autonomy terminal state/stop/bounds/execution behavior,
one canonical Phase 2 status, target-request maximum, model-call maximum,
or fallback behavior. Rationale prose, chain-of-thought, raw provider output,
secrets, hidden vulnerability truth, and benchmark-specific identifiers are not
valid expectations.

Every configured expectation produces a `StructuralExpectationResult` containing
its type, expected value, sanitized observed value, satisfaction boolean, and a
closed matched/mismatched/unavailable reason. `EvaluationCaseOutcome` separately
reports `runtime_success` and overall `success`, along with
`expectations_present`, `expectations_checked`, `expectations_satisfied`, complete
results, and failed results. Runtime success plus a structural mismatch is not a
runtime error: the runtime failure code remains `null`, but overall case success is
false. With no configured expectations, satisfaction remains neutral (`null`) and
existing success behavior is unchanged.

The runner authoritatively applies checks after runtime and budget normalization.
Autonomy structure comes from canonical P3-4 history/provenance. Evaluation binds
directly to the authoritative Phase 2 status contract. It observes terminal
`verified`, `rejected`, `inconclusive`, and `policy_blocked` results separately from
the intermediate `verification_pending_cleanup` and
`awaiting_controlled_evidence` control states, and never rewrites any of them.
Intermediate states remain runtime-successful observations unless an independent
evaluation error occurred, do not increment completed or terminal-result counters,
and retain exact iteration/result provenance, `RequestDelta`, `ModelUsageDelta`, and
P3-4 stop/barrier semantics. Target-request checks read only `RequestDelta`, while
model-call and fallback checks use the separate `ModelUsageDelta` and sanitized
model provenance. A failed expectation never changes prompts, routing, consensus,
autonomy or Phase 2 policy, and never triggers a retry, rerun, or tuning path.

## Evaluation metrics

Reasoning metrics are deterministic ratios over strict counters:

- valid and invalid decisions use all attempted structured decisions;
- schema and unsupported-recommendation rates use attempted decisions;
- plan-only execution-recommendation rate records invalid execution advice;
- manual-review and stop rates use valid decisions;
- capability-grounding and evidence-reference rates use valid decisions;
- repeated-case consistency is the mean modal structured-decision share for
  cases having at least two repetitions. It measures observed agreement and
  does not claim model determinism or correctness.

Autonomy metrics sum canonical P3-4 observations: iterations, verification
attempts and completed results, unmodified `verified`, `rejected`,
`inconclusive`, and `policy_blocked` classifications, duplicate prevention,
result-driven pivots, blocked recommendations, cleanup barriers, manual-review
outcomes, and closed stop reasons. Evaluation never promotes or reinterprets a
Phase 2 result. Separate `verification_pending_cleanup_count`,
`awaiting_controlled_evidence_count`, and `intermediate_outcome_count` metrics expose
paused/deferred observations without classifying them as completed vulnerability
results or evaluation failures.

Consensus metrics report unanimous, majority, and split rates; invalid and
failed participant rates; quorum success; mean aggregate confidence; and
dissent rate. Consensus remains an agreement measurement, not evidence that an
answer is true and not execution permission.

P3-2 `ModelUsageDelta` aggregates model call attempts/successes/failures, input,
output and total tokens, API cost, model latency, and fallback count/rate. If any
component cost is unknown, aggregate API cost and dollar efficiency remain
unknown. Ollama continues to use its explicit zero API-cost semantics.

Phase 2 `RequestDelta` separately supplies total target, authentication,
verification, cleanup, and discovery requests. P3-6 never derives target
traffic from model calls.

`ModelUsageDelta != RequestDelta`.

Expectation metrics report cases with configured expectations, cases satisfying all
required expectations, cases with one or more failures, and expectation pass rate.
They do not change or inflate valid-decision, consensus, autonomy, Phase 2, request,
or model-usage metrics. JSON includes per-expectation results, and human summaries
show pass/fail/configured case counts.

Derived efficiency metrics include verified outcomes per model call, per 1,000
tokens, per target request, and per known estimated dollar; successful pivots
per model call; average model reasoning latency; and average verification
request count per completed verification. Zero denominators deterministically
produce zero. Unknown monetary cost produces `null`, never an invented value.

Timing includes total evaluation duration, observed time to first valid
decision, first verification, and first verified result, aggregate model
latency, and already available Phase 2 execution latency. Unavailable timing
remains `null`; no historical timing is reconstructed.

## Comparison, repeatability, and fingerprints

`compare_runs` reports side-by-side metric values and deltas without declaring a
universal winner. It always labels configuration compatibility from the versioned
full configuration fingerprint: `compatible`, `incompatible`, or `unknown`.
Explicit GPT/Claude/local, single/consensus, reasoning/autonomy, local/cloud, and
preferred/fallback comparisons remain available even when configurations differ;
their metrics are not presented as configuration-equivalent. A deterministic table
reports subject, valid decisions, verified outcomes, calls, tokens, known cost,
target requests, latency, fallbacks, successful pivots, expectations, and the
compatibility state/reason for a two-run comparison.
Expectation pass rate and failed-expectation case count are included as independent
comparison columns; they are not treated as hidden truth or folded into a quality
score. Intermediate cleanup/evidence counts and evaluation runtime-failure counts
are also separate comparison dimensions, so a deferred autonomy state is not
indistinguishable from an observer or callback failure.

The Pareto view keeps all non-dominated subjects across explicit quality,
verified-result, cost, latency, token, and target-request dimensions. Unknown
cost is omitted from that pairwise comparison. P3-6 does not collapse these
dimensions into a hidden score or provider preference.

Repeated cases retain repetition indexes and structured decision signatures.
Fingerprint schema `material-v2` hashes one strict canonical public configuration
source with lowercase SHA-256. It includes:

- evaluation/reasoning/consensus/autonomy/capability schema identity;
- subject ID/type/repetitions and normalized provider/model routing, ordered fallback
  chain, mode, allowlists, fallback triggers/attempts, and route/model budgets;
- consensus participant route set, policy and budget, plus autonomy execution mode
  and all configured limits;
- case/task identity, repetitions, case model/autonomy budgets, complete P2-1
  expectations, reasoning policy and model-budget context, prior result/decision
  semantics, target reference, capability eligibility/request bounds/input-schema/
  executor versions, and public evidence semantics;
- the evaluation runner output-token reservation and normalized pricing/alias
  configuration.

Pydantic-resolved defaults mean omitted and explicitly supplied equivalent defaults
hash identically. Cases are sorted by case ID. Consensus participant routes and
set-like allowlists/actions/categories are canonicalized because their order is not
semantic. Fallbacks, evidence packets, and prior decisions retain their order.
Reasoning run IDs are not persisted; deterministic budget-group labels retain only
whether cases share an evaluation budget.

Raw prompts/evidence prose/preconditions are represented only by public-safe content
digests. Environment values, API keys, credentials, Authorization/cookies/sessions,
passwords/recovery/private state, raw provider output, chain-of-thought, timestamps,
evaluation/result IDs, temporary paths, actual token/cost/latency observations, and
runtime object identity are excluded. LLM output itself is not claimed to be
deterministic.

Runs without a fingerprint schema marker remain readable as
`legacy-v1-incomplete`. Legacy identity is never silently treated as equivalent to
`material-v2`; compatibility is `unknown`.

## External aggregate records and privacy

Named `ExternalBaselineRecord` and `ExternalBenchmarkRecord` schemas accept only
externally supplied aggregate metrics, run/time/configuration references, optional
matched/discovered/verified counts, and an optional paired configuration fingerprint
and schema. Imports preserve supplied identity. Missing identity, legacy identity,
or a schema mismatch yields `unknown` compatibility rather than assumed equivalence.
Imports consume an explicit JSON string or mapping. They do not discover files,
import the Phase 2 benchmark exporter, open hidden fixtures, or read benchmark
source code. No current benchmark values are embedded in P3-6.

Evaluation JSON contains the subject and case configuration, per-case outcomes,
aggregate reasoning/autonomy/consensus/model/request/efficiency/timing metrics,
normalized failures, provenance, and configuration fingerprint. A concise text
summary and deterministic Markdown comparison table are also available. Every
artifact must satisfy the Phase 2 `public_result` boundary. Schemas expose no
raw provider response, raw prompt, chain-of-thought, authorization value, API
key, password, cookie, session token, recovery secret, or private recovery
state. Failures use a closed code and never preserve raw exceptions.

The credential-free `model_eval_cli.py` can list synthetic subjects, emit a
synthetic evaluation JSON document, summarize an existing evaluation document,
or compare two existing documents. It does not require provider SDKs, keys,
Ollama, target access, or benchmark fixtures.

Evaluation repetition is bounded by strict subject/case counts and case-level
model call/token/cost limits. Underlying reasoning and consensus still use the
authoritative P3-2 model ledger, pricing, fallback bounds, local-only mode, and
cloud allowlist. The evaluation runner stops before an additional repetition
when a cumulative case ceiling is exhausted. It never silently relaxes unknown
cost policy. Local-only subjects require local-only P3-2 routes; OpenAI and
Anthropic cannot be added by an evaluation case. Evaluation preserves the same
provider-family semantics and does not assert or enforce Ollama endpoint locality.

Evaluation output is passive. It has no API that modifies a prompt, route,
consensus policy, autonomy policy, capability registry, or Phase 2 policy, and
there is no result-to-tuning-to-rerun loop.

`BENCHMARKING MEASURES THE AGENT; IT DOES NOT AUTHORIZE OR TUNE THE AGENT.`

## P3-6 boundary

P3-6 ends at normalized measurement, reporting, and comparative telemetry. It
adds no vulnerability executor, provider call, alternate transport, policy
path, benchmark-aware routing, automated tuning, model tool access, or direct
execution route. Phase 2 remains the final execution authority.
