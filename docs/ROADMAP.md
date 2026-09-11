# Roadmap

## Adaptive agent foundation: implemented

- Typed adaptive planning and evidence-linked verification plans.
- Persistent, versioned SQLite surface graph and scan-memory integration.
- Sanitized capture-first HAR, raw HTTP, OpenAPI, Postman, GraphQL, and browser
  ingestion with controlled identities and test-owned objects.
- Ranked bug-bounty hypotheses and deterministic verification gates.
- Killable network-tool subprocesses, common scoped transport, local credential
  vault, and hash-chained audit log.
- Program policy compiler with exclusions, wildcards, URL prefixes, testing
  windows, budgets, rate limits, account restrictions, and cleanup rules.
- Offline evaluation lab with quality, efficiency, reproduction, and zero-tolerance
  safety metrics.

Future work should grow replayable benchmark coverage and typed verifier
adapters before introducing multi-agent specialization.

## Phase 3: in progress

- P3-1 provider foundation: implemented on `develop-v3` with strict normalized
  contracts, model-only telemetry, configured pricing, deterministic registry,
  and OpenAI, Anthropic, and Ollama adapters.
- P3-2 model router: implemented with deterministic modes, exact bounded
  fallback, cloud-provider-disabled Ollama-family routing, explicit cloud
  allowlists, model-call ledger, strict usage deltas, and independent model
  budgets. Endpoint locality remains an operator-verified configuration property.
- P3-3 grounded reasoning: implemented with canonical evidence packets, strict
  advisory decisions, capability and policy semantic validation, common
  GPT/Claude/DeepSeek reasoning, deterministic ranking, and sanitized history.
- P3-4 adaptive orchestration: implemented with an explicit bounded state
  machine, deterministic execution gate, dry-run mode, result-driven pivots,
  duplicate/cleanup barriers, and submission only through the shared Phase 2
  verification runtime.
- P3-5 multi-model consensus: implemented with independent canonical-evidence
  decisions, exact structured-vote agreement, deterministic confidence
  aggregation and conservative arbitration, bounded consensus budgets, and a
  validated advisory mapping back to the mandatory P3-4 gate.
- P3-6 model evaluation: implemented with strict benchmark-independent subjects,
  cases and runs; reasoning/consensus/autonomy/usage/request metrics; repeatable
  comparisons and Pareto views; synthetic fixtures; and public-safe external
  aggregate imports and reports.
- Provider inputs are limited to canonical Phase 2 public-safe evidence. Models
  have no direct security-tool or Phase 2 executor authority.
- Benchmark feedback, automatic tuning, and benchmark-aware routing remain out
  of scope.

## v2.1 development

- Business Logic Analysis Engine: implemented on the feature branch with
  offline-first discovery, modeling, comparison, observations, planning, and
  default-disabled controlled replay.
- File Upload Analysis Engine: implemented with offline discovery, validation,
  metadata and storage observations, safe planning, conservative reporting, and
  default-disabled bounded replay.

## v2.0.0 Beta stabilization

The beta milestone delivers dependency-aware profiles, normalized evidence, conservative observation/candidate boundaries, bounded discovery output, deterministic/DeepSeek reporting, the local dashboard, `explain`, and `doctor`.

## v2.1

- GraphQL testing suite, activated only after endpoint evidence
- Controlled JWT verification workflows
- Business-logic analysis engine
- Evidence-driven file-upload analysis (implemented)
- Authenticated object-authorization workflows with controlled accounts

This project is under active development. The goal is to build a local-model-first
AI Security Agent capable of assisting security researchers and bug bounty hunters
with authorized reconnaissance, analysis, and reporting. Device-local inference
depends on a verified loopback/on-device model endpoint.

---

# Version 1.0 (Current)

## Core AI

* ✅ Ollama integration
* ✅ DeepSeek R1 Distill 32B
* ✅ Local LLM reasoning

## Agent Framework

* ✅ Planner
* ✅ Decision Engine
* ✅ Workflow Manager
* ✅ Tool Registry
* ✅ Scope Guard
* ✅ AI Report Writer

## Security Tools

* ✅ DNS Lookup
* ✅ HTTP Probe
* ✅ Security Header Analysis
* ✅ Katana Website Crawling
* ✅ Misconfiguration Detection
* ✅ JavaScript / Static Asset Scanner
* ✅ Parameter Analyzer
* ✅ Authorization Test Planner
* ✅ Nuclei Integration

## Reports

* ✅ AI-generated Markdown reports
* ✅ Professional report structure

### AI Interaction

- ✅ ask question
- ✅ scan authorized target

---

# Version 1.1

Focus: Stability and usability

Planned improvements:

* Better logging
* Improved error handling
* Configuration management
* Enhanced report formatting
* More comprehensive unit tests
* Better CLI experience
* Performance optimization

---

# Version 2.0

Focus: Autonomous AI Agent

Planned features:

* Memory of previous assessments
* Scan history comparison
* Dynamic tool selection
* Context-aware planning
* Parallel execution of independent tools
* Plugin architecture for custom tools

---

# Version 2.5

Focus: Bug Bounty Assistant

Planned capabilities:

* Endpoint prioritization
* Authentication workflow analysis
* JavaScript dependency analysis
* API discovery
* Business logic testing assistance
* Intelligent vulnerability triage
* CVSS estimation
* Finding deduplication

---

# Version 3.0

Focus: Multi-Agent Architecture

Research goals:

* Planner Agent
* Recon Agent
* Analysis Agent
* Reporting Agent
* Memory Agent

Each agent will specialize in a specific task while collaborating to complete a full security assessment.

---

# Long-Term Vision

The long-term goal is to build a modular, local-model-first AI security platform that helps security professionals:

* Perform authorized reconnaissance
* Analyze security findings
* Generate professional reports
* Prioritize manual testing
* Improve productivity during security assessments

The project is designed to remain local-model-first, allowing researchers to use
powerful AI workflows without relying on OpenAI or Anthropic. This provider choice
alone does not guarantee loopback, offline, or same-device processing; operators
must verify the configured Ollama endpoint.

---

# Planned Integrations

Future integrations may include:

* OWASP ZAP
* Nmap
* Amass
* ffuf
* httpx
* Subfinder
* GitHub Code Search
* CVE databases
* MITRE ATT&CK mapping

---

# Project Status

Current Status:

**Version 1.0 Beta**

Actively developed and continuously improving.
# v2.1 development planning

v2.1.0-beta includes the safe GraphQL Security Suite, JWT Workflow Engine,
Business Logic Analysis Engine, and File Upload Analysis Engine. Future phases
may expand controlled evidence ingestion and report presentation; automatic
authorization exploitation, mutation execution, amplification, and
denial-of-service testing remain out of scope.

The v2.1 JWT workflow is implemented as an offline-first registry extension.
Future work may add richer controlled evidence import. Automated token mutation,
key confusion, brute force, and unsanctioned replay remain explicitly out of
scope. The canonical release-candidate version is v2.1.0-beta.
