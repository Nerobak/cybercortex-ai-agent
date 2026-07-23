# Architecture

## CyberCortex AI Agent v2.0.0 Beta

The v2 pipeline is evidence-driven and dependency-aware: scope validation precedes network activity; independent checks run before crawl-dependent analyzers; normalized evidence separates observations, candidates needing manual verification, and verified findings. DeepSeek acts only as a local evidence analyst and may improve wording without changing deterministic classifications. When unavailable, the report writer emits a deterministic report. The local dashboard binds to `127.0.0.1`.

Baseline is low-impact, deep permits broader bounded discovery, and authenticated enables only workflows supplied with explicit controlled input. The registry powers `list tools` and `explain`; `doctor` validates local release prerequisites without scanning a live target.

CyberCortex AI Agent is built as a modular AI-assisted security workflow.

## Flow

User Goal  
↓  
CLI Entry Point (`agent.py`)  
↓  
Scope Guard  
↓  
Planner  
↓  
Decision Engine  
↓  
Dependency-aware Tool Runner
↓  
Tool Registry  
↓  
Security Tools  
↓  
AI Report Writer  

The runner uses canonical registry metadata to enforce prerequisites, explicit
inputs, per-tool and overall timeouts, network concurrency bounds, and status
envelopes. Crawler and redirect URLs are rechecked by the scope guard. A shared
URL collection feeds endpoint, parameter, misconfiguration, JavaScript, and API
object analyzers. Deterministic finding classification and secret redaction run
before one bounded evidence package is sent to the local analyst model.

## Core Components

- `agent.py` – CLI entry point
- `config.py` – central configuration
- `tool_registry.py` – metadata for available tools
- `agent_core/llm_client.py` – local LLM client through Ollama
- `agent_core/planner.py` – creates tool execution plans
- `agent_core/decision_engine.py` – parses and selects workflow steps
- `agent_core/workflow_manager.py` – executes the planned workflow
- `agent_core/tool_runner.py` – dependency execution and result envelopes
- `agent_core/result_normalizer.py` – shared URL and evidence normalization
- `tools/` – cybersecurity tools
- `reports/` – generated Markdown reports

## Safety Model

All target testing is controlled by `PENTEST_ALLOWLIST` and
`PENTEST_ALLOWED_URL_PREFIXES`. A prefix configured for a host is the narrower
authorization. Redirect destinations and discovered URLs are independently
validated; cross-domain and out-of-prefix redirects are blocked.
# GraphQL extension

Phase 1 GraphQL support is implemented as registry tools layered onto the stable dependency-aware v2 workflow. The core manager, runner contract, normalizer boundary, finding schema, scope guard, and CLI framework remain authoritative. See `GRAPHQL_SUITE.md` for the evidence flow and safety invariants.

# JWT extension

JWT support follows the same registry boundary: authorized evidence flows through
discovery, offline decoding, deterministic claim analysis, optional controlled
comparison, and non-executing verification planning. Replay is a separate,
authenticated-only opt-in tool. Raw tokens and claim values never cross the
normalization or report boundary. See `JWT_WORKFLOW.md`.
