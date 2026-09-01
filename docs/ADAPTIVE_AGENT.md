# Adaptive red-team and bug-bounty agent

CyberCortex now uses an authorization-first adaptive architecture. It is built
for systems you own or are explicitly permitted to assess. The model proposes
hypotheses and priorities; deterministic code owns scope, budgets, execution,
evidence grading, cleanup requirements, and finding-state transitions.

## Agent loop

```text
authorized policy + sanitized capture
                 |
                 v
      persistent surface graph
                 |
                 v
 deterministic + optional LLM hypotheses
                 |
                 v
 typed VerificationPlan objects
                 |
                 v
       deterministic policy gate
                 |
         allowed | blocked
                 v
 typed verifier / bounded executor
                 |
                 v
 repeatability + ownership + cleanup gate
                 |
                 v
 observation / candidate / needs_manual_verification / verified
```

The LLM cannot directly dispatch arbitrary tools. LLM hypotheses are accepted
only when they validate against the strict schema, reference an observed request
and endpoint, select registered tools, and remain in the proposed state.

## Main components

- `agent_core/agent_models.py`: typed planning contracts.
- `agent_core/policy.py`: scope, exclusions, methods, testing windows, callback
  authorization, rates, budgets, account restrictions, and prohibited actions.
- `agent_core/attack_surface.py`: versioned SQLite surface graph.
- `agent_core/capture_ingest.py`: HAR, raw HTTP, OpenAPI, Postman, GraphQL, and
  browser-network import with credential and value removal.
- `agent_core/hypothesis_engine.py`: deterministic ranking plus optional local
  LLM proposals.
- `agent_core/capture_executor.py`: bounded differentials for query, path,
  non-sensitive header, JSON, form, and GraphQL-variable locations. Multipart
  uses the dedicated benign-file upload adapter.
- `agent_core/verification_gate.py`: volatile-field normalization and proof
  requirements.
- `agent_core/hardened_executor.py`: killable subprocesses for network tools.
- `agent_core/credential_vault.py`: process-local secret references.
- `agent_core/audit_log.py`: append-only, hash-chained redacted audit events.
- `evaluation/lab.py`: offline metrics and replayable fixture runner.

## Persistent policy profiles

Saved profiles live in `config/policies/` and are managed with `policy_cli.py`.
Each edit increments `policy_version`, preserves timestamps and prior snapshots,
and produces a SHA-256 hash. Assessment evidence records the selected profile
name, version, hash, and authorization reference.

Use `python policy_cli.py init-target` for guided setup, or the `create`, `list`,
`show`, `edit`, `validate`, `clone`, and `delete` commands. `map-host
<exact-host> <profile>` opts into `agent_cli.py --auto-policy`. Capture hosts
never create or broaden authorization. Defaults remain fail-closed:

- No implicit wildcard scope; URL-prefix path boundaries are exact.
- State changes, credentials, and OAST are disabled unless explicitly allowed.
- OAST also requires explicit callback hosts.
- State changes require an owned test resource and deterministic cleanup.
- Destructive actions, denial of service, credential attacks, phishing,
  malware, persistence, stealth evasion, and data exfiltration cannot be enabled.

## Capture-first planning

```bash
python agent_cli.py \
  --capture verification_inputs/captures/nerminzlatanovic.har \
  --policy-profile nerminzlatanovic \
  --context-profile public-site \
  --profile intrusive \
  --llm-analyst \
  --output reports/adaptive/nerminzlatanovic-assessment.json
```

Use `--format` for ambiguous extensions and `--base-url` when an input lacks an
origin. `--llm-analyst` lets the configured local model propose additional
typed hypotheses; it does not bypass policy. Context annotations model
controlled identities, roles, tenants, and researcher-owned objects without
containing credentials. Saved contexts live in `config/contexts/` and use
`context_cli.py create|list|show|edit|validate`. Legacy `--policy <file>` and
`--context <file>` inputs remain supported but cannot be combined with their
profile equivalents.

## Verification standards

CyberCortex ranks work in this order:

1. BOLA/IDOR, vertical authorization, and tenant isolation.
2. Mass assignment and property-level authorization.
3. Session, OAuth/OIDC, and account lifecycle.
4. Stateful workflow and business-rule enforcement.
5. API and GraphQL authorization.
6. Controlled SSRF/OAST correlation.
7. Upload, injection, and cache behavior.

BOLA, tenant, vertical, or GraphQL authorization cannot become verified without
known object ownership, two distinct controlled identities, and two normalized
repeatable observations. SSRF requires a unique controlled callback. A stateful
result requires a researcher-owned resource and successful cleanup. Reflection
alone remains manual verification.

## Persistent memory

The default database is `memory/attack_surface.sqlite3`. It contains sanitized
metadata and per-run hashes. New and changed requests receive higher planning
priority; known hypotheses retain prior state and receive lower priority. The
ordinary scan command also persists normalized assessment memory.

## Evaluation laboratory

```bash
python eval_cli.py
```

Metrics include verified precision/recall, false-positive rate, requests per
verified finding, reproduction success, time to first verified evidence, scope
violations, and unauthorized state changes. The safety gate requires the last
two metrics to be exactly zero.

## Operational boundary

The common HTTP transport rechecks scope for each request and redirect,
optionally resolves DNS immediately before requests, and enforces response,
rate, and budget limits. The subprocess executor lets the parent terminate a
timed-out registered network tool. For production kernel-level egress isolation,
run the worker inside an OS or container network namespace as well.
