# CyberCortex AI Agent

## Phase 3 model foundation

P3-1 adds strict provider-neutral model requests, responses, model-call
telemetry, pricing configuration, and isolated OpenAI, Anthropic, and Ollama
adapters. P3-2 adds strict deterministic model routing, bounded reliability
fallback, cloud-provider-disabled Ollama-only routing, explicit cloud allowlists,
and a separate model-call ledger/budget. P3-3 adds strict evidence packets,
advisory reasoning decisions, semantic capability grounding, stable hypothesis ranking, and
sanitized reasoning history. P3-4 adds a bounded state machine and deterministic
decision gate that can submit eligible typed recommendations only through the
existing Phase 2 verification runtime. P3-5 adds independent multi-model
reasoning, structured agreement classification, deterministic conservative
arbitration, and sanitized consensus history. P3-6 adds benchmark-independent
model, consensus, and orchestration metrics; repeatable comparison and Pareto
views; and sanitized external aggregate imports. Models receive only evidence
admitted through the frozen Phase 2 `public_result` boundary and never receive
direct tool or network authority. Evaluation does not tune routing or prompts,
and even unanimous consensus remains advisory; the P3-4 gate and Phase 2 runtime
remain mandatory. See [docs/PHASE3.md](docs/PHASE3.md).

`local_only` is a provider-family restriction: it blocks OpenAI and Anthropic and
uses configured Ollama-family routes only. It does not enforce loopback, same-device
inference, same-LAN inference, offline operation, or absence of network transmission.
The default `OLLAMA_BASE_URL=http://127.0.0.1:11434` is device-local; a non-loopback
URL may transmit sanitized model evidence over a network. Verify the configured
endpoint before relying on device-local privacy assumptions.

## Adaptive agent architecture

CyberCortex now includes typed hypotheses and verification plans, a deterministic
bug-bounty policy compiler, persistent SQLite surface memory, sanitized
HAR/OpenAPI/Postman/GraphQL/browser ingestion, controlled identity and object
modeling, killable network-tool processes, credential references, hash-chained
audit events, and an offline evaluation laboratory.

The configured model provider proposes and prioritizes hypotheses. It cannot
approve network activity or promote a finding to verified. See
[docs/ADAPTIVE_AGENT.md](docs/ADAPTIVE_AGENT.md).

```text
python policy_cli.py init-target
python agent_cli.py --capture <authorized.har> --policy-profile <profile>
python eval_cli.py
```

Saved, versioned authorization profiles live in `config/policies/`; reusable
credential-free identity and ownership annotations live in `config/contexts/`.
The legacy `--policy <file>` and `--context <file>` options remain available.

## File upload analysis

The v2.1 upload engine discovers upload evidence offline, records validation,
metadata, and storage observations, and produces bounded manual verification
plans. Normal scans never upload files. Optional replay is authenticated,
scope-enforced, disabled by default, and restricted to benign researcher-owned
files. Reports and the dashboard expose aggregate upload summaries without
filenames. See [docs/FILE_UPLOAD_ENGINE.md](docs/FILE_UPLOAD_ENGINE.md).

## Business logic analysis

The v2.1 development workflow includes modular, offline-first workflow discovery,
canonical modeling, transition and business-rule observations, redacted trace
comparison, and non-executing verification plans. Optional replay is disabled by
default and limited to explicitly supplied, in-scope controlled GET/HEAD requests.
See [docs/BUSINESS_LOGIC_ENGINE.md](docs/BUSINESS_LOGIC_ENGINE.md).

## CyberCortex AI Agent v2.1.0-beta

Version metadata is sourced only from `agent_core/version.py`. v2.1 adds the
GraphQL Security Suite, JWT Workflow Engine, Business Logic Analysis Engine,
and File Upload Analysis Engine to the evidence-driven, dependency-aware core.
Tool output is normalized before it reaches the configured DeepSeek/Ollama analyst;
deterministic fallback reports remain available when the model is unavailable.
The summary-only dashboard binds to localhost.

Use `explain <tool>`, `explain latest`, `explain scan`, and `explain profiles` for deterministic operational guidance. Use `doctor --quick` or `doctor` for local release-readiness checks; neither starts a target scan or prints secrets.

Authenticated tools require explicit controlled credentials or request input. Baseline scans do not automatically verify IDOR, JWT acceptance, GraphQL authorization, business logic, or upload behavior. Explicit authorization, configured scope, and program rules always apply.

> **An AI-powered cybersecurity assistant with cloud-provider-disabled Ollama routing for authorized security assessments, bug bounty research, reconnaissance, analysis, and professional reporting.**

![Status](https://img.shields.io/badge/Status-Beta-orange)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![AI](https://img.shields.io/badge/LLM-DeepSeek_R1_Distill_32B-red)
![Platform](https://img.shields.io/badge/Platform-Ollama-black)

---

## Overview

CyberCortex AI Agent is an AI-powered cybersecurity platform designed to assist security professionals and bug bounty researchers during **authorized** security assessments. It supports device-local model inference when Ollama is configured on a verified loopback endpoint.

Unlike traditional security automation scripts, CyberCortex AI Agent combines a configured reasoning model (such as DeepSeek R1 Distill 32B through Ollama) with custom-built cybersecurity tools to automate reconnaissance, analyze findings, prioritize manual testing, and generate professional security reports.

The project is designed around a modular AI architecture that separates planning, workflow management, decision-making, security tooling, and AI-assisted reporting.

No cloud AI services are required.

## Assessment commands

```text
scan <target>
scan <target> --profile baseline
scan <target> --profile deep
scan <target> --profile authenticated
scan <target> --jwt-file verification_inputs/token.txt
list tools
explain latest
doctor --quick
graphql analyze verification_inputs/query.graphql
jwt analyze --file verification_inputs/token.jwt
workflow analyze verification_inputs/workflow.json
jwt analyze
upload analyze verification_inputs/upload-evidence.json
upload plan verification_inputs/upload-evidence.json
upload explain
python campaign_cli.py --manifest verification_inputs/campaign.json
```

Capture campaigns rank parameters and produce an offline plan. Active execution
through `campaign_cli.py --execute` is disabled for Phase 2 until that path can
use the same selected policy and live request ledger as the primary runtime. See
[docs/CAPTURE_CAMPAIGNS.md](docs/CAPTURE_CAMPAIGNS.md).

The adaptive importer also models query, path, header, form, JSON, multipart,
and GraphQL-variable locations. Executable state-changing plans require a
researcher-owned test resource and cleanup.

## Persistent policy profiles

Create, inspect, validate, clone, edit, and delete saved authorization with
`policy_cli.py create|list|show|validate|clone|edit|delete`. The guided
`python policy_cli.py init-target` command can also create a matching context.

`python policy_cli.py map-host app.example.com my-program` creates an exact
host mapping for optional `agent_cli.py --auto-policy` selection. Auto-policy
never infers authorization from capture traffic and fails if a capture host has
no exact mapping. Context profiles are managed with
`context_cli.py create|list|show|edit|validate`; they contain roles, tenants,
and researcher-owned object references, never raw credentials.

```bash
python agent_cli.py \
  --capture verification_inputs/captures/nerminzlatanovic.har \
  --policy-profile nerminzlatanovic \
  --context-profile public-site \
  --profile intrusive \
  --llm-analyst \
  --output reports/adaptive/nerminzlatanovic-assessment.json
```

`baseline` is the default and runs target-only checks. `deep` adds bounded,
policy-approved discovery as those tools become available. Authenticated and
authorization-differential verification is never inferred from a normal scan;
it requires explicit researcher credentials or evidence. JWT input should be
entered through the hidden `jwt analyze` prompt or an ignored file under
`verification_inputs/`.

---
## Screenshots

### CyberCortex AI Agent

![CyberCortex AI Agent](screenshots/01-banner.png)

---

### Command-Line Interface

![CLI Help](screenshots/02-help.png)

---

### Security Assessment Workflow

![Security Assessment Workflow](screenshots/03-running.png)

---

### Local DeepSeek Report Generation

![DeepSeek Report Generation](screenshots/06-deepseek-thinking.png)

---

### AI-Generated Security Report

![AI Report](screenshots/04-report.png)

---

### Architecture

![Architecture](screenshots/05-architecture-diagram.png)

# Features

## Ollama AI

* Cloud-provider-disabled Ollama routing
* Device-local inference when `OLLAMA_BASE_URL` is verified as loopback
* Ollama integration
* DeepSeek R1 Distill 32B
* No cloud-based LLM required

---

## AI Architecture

* AI Planner
* Decision Engine
* Workflow Manager
* Tool Registry
* Scope Guard
* AI Report Writer

---

## Security Tools

* DNS Lookup
* HTTP Probe
* Security Header Analysis
* Website Crawling (Katana)
* Misconfiguration Detection
* JavaScript Secret Scanner
* Parameter Analyzer
* Authorization Test Planner
* Nuclei Integration

---

## Hardware Requirements

CyberCortex AI Agent can run its model inference entirely on local hardware using Ollama and DeepSeek R1 Distill 32B when the configured Ollama endpoint is verified as loopback/on-device.

The hardware required depends on the language model you choose.

| Model                   | Recommended Memory | Notes                                      |
| ----------------------- | -----------------: | ------------------------------------------ |
| Llama 3 8B              |             16 GB+ | Entry-level local AI                       |
| DeepSeek R1 Distill 8B  |           16–24 GB | Good performance                           |
| DeepSeek R1 Distill 14B |           24–32 GB | Balanced speed and quality                 |
| DeepSeek R1 Distill 32B |         **48 GB+** | Recommended configuration for this project |
| 70B-class models        |             96 GB+ | Advanced workstation or server             |

### Development System

CyberCortex AI Agent was primarily developed and tested on:

* **Apple MacBook Pro**
* **Apple M4 Pro**
* **48 GB Unified Memory**
* **20-Core GPU**
* **1 TB SSD**
* **Ollama**
* **DeepSeek R1 Distill 32B**

This configuration provides a good balance between reasoning quality and local performance for the current version of the project.

### Minimum Requirements

For smaller local models (7B–14B):

* Python 3.9+
* 16 GB RAM
* Ollama
* Git

### Recommended Requirements

For the best experience with DeepSeek R1 Distill 32B:

* Apple Silicon (M-series) or a modern workstation
* **48 GB or more memory**
* SSD storage
* Ollama
* Python 3.9+

## Reporting

* AI-generated Markdown reports
* Executive summaries
* Prioritized remediation guidance
* Manual verification recommendations

---

# Architecture

```text
                User
                  │
                  ▼
             agent.py
                  │
                  ▼
          Workflow Manager
                  │
                  ▼
              AI Planner
                  │
                  ▼
          Decision Engine
                  │
                  ▼
           Tool Registry
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
     Recon     Analysis   Reporting
        │
        ▼
 DeepSeek R1 Distill 32B
        │
        ▼
 Professional AI Report
```

---

# Installation

See:

For complete installation instructions, see:

- [Installation Guide](docs/INSTALL.md)


---

### Configure Environment

Copy the example configuration:

```bash
cp .env.example .env
```

Then edit:

```bash
nano .env
```

Update the allowlist with domains you are authorized to assess before running the agent.

# Usage

Interactive Mode

```bash
python agent.py
```

Example commands:

```text
ask What security headers are important?

scan https://example.com
```

CLI Mode

```bash
python agent.py --target https://example.com --mode safe
```

Local Web Dashboard

```bash
python web_app.py
```

Then open `http://127.0.0.1:8000`. The dashboard requires an explicit
authorization confirmation and rejects targets outside
`PENTEST_ALLOWLIST` / `PENTEST_ALLOWED_URL_PREFIXES`. It runs low-impact
DNS and HTTP configuration checks, shows live progress, preserves raw
evidence, and exports a Markdown report.

# Project Structure

```text
cybercortex-ai-agent/

agent.py
config.py
tool_registry.py

agent_core/
tools/
tests/
reports/
docs/
examples/
logs/
archive/
```

---

# Documentation

## Documentation

- [Installation Guide](docs/INSTALL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Tools](docs/TOOLS.md)
- [Project Roadmap](docs/ROADMAP.md)

---

# Safety

CyberCortex AI Agent is designed **only** for authorized security testing.

Examples include:

* Systems you own
* Laboratory environments
* Capture-the-Flag (CTF) platforms
* Bug bounty programs that explicitly authorize testing

Targets outside the configured allowlist are blocked by the built-in Scope Guard.

---

# Roadmap

See:

**docs/ROADMAP.md**

Upcoming work includes:

* Assessment memory
* Historical comparison
* Plugin architecture
* Parallel execution
* Multi-agent collaboration
* Web dashboard
* REST API

---

## Known limitations

Offline and automated analysis cannot establish exploitability by itself.
Authenticated authorization boundaries require explicit controlled inputs and
manual verification. Optional tools and the local reporting model may be
unavailable; deterministic fallback still produces a report and sanitized
evidence file.

## Contributing

Keep changes scoped, conservative, and covered by regression tests. Run Black,
Ruff, compileall, and pytest before proposing a change. Never commit local
credentials, captured requests, reports, or third-party personal information.

# License

This project is released under the MIT License.

See the **LICENSE** file for details.

---

# Author

**Nermin Zlatanovic**

Founder of **CyberCortex**

Cybersecurity Specialist • AI Security Researcher • NIST NICE Ambassador

Website:

https://nerminzlatanovic.com

GitHub:

https://github.com/nerobak

---

## CyberCortex Vision

CyberCortex is a growing ecosystem of AI-powered cybersecurity projects focused on empowering defenders, researchers, and bug bounty hunters through local AI, automation, and practical security engineering.

CyberCortex AI Agent is the first major component of that ecosystem.

# Phase 2 adaptive research

Phase 2 converts observed routes, parameters, object references, authentication
boundaries, GraphQL/JWT/upload/workflow metadata, captures, and response
summaries into testable hypotheses. It ranks evidence and verification safety,
builds minimal plans, and keeps execution behind deterministic scope, ownership,
method, side-effect, lab-classification, and request-budget gates.

```text
scan https://authorized.example --mode observe
scan https://authorized.example --mode plan --policy policy.json
scan http://local-range.example --mode verify --lab --policy policy.json --context controlled-context.json --verification-input evidence-context.json
hypotheses
hypothesis explain <id>
verification plan <id>
verification run <id> --policy policy.json --context controlled-context.json --input evidence-input.json --lab
benchmark export reports/benchmark.json
python phase2_cli.py campaign create api-lab-phase2 --target http://127.0.0.1:8101
python phase2_cli.py scan http://127.0.0.1:8101 --mode plan --campaign api-lab-phase2
python phase2_cli.py campaign add-run api-lab-phase2 <run-id>
python phase2_cli.py campaign show api-lab-phase2
python phase2_cli.py campaign export api-lab-phase2 reports/api-lab-phase2.json
```

Credentials and tokens in an explicitly supplied controlled context are moved
to the process-local vault and are never written to Phase 2 runs, reports, or
benchmark exports. A run is one assessment execution; a campaign is a cumulative
authorized effort that references multiple preserved runs for the same target.
See [Phase 2 Architecture](docs/PHASE2.md).
# GraphQL v2.1 Phase 1

The development branch includes a modular, default-safe GraphQL suite for endpoint observations, offline query/schema analysis, opt-in bounded introspection, and controlled-account authorization planning. GraphQL behavior and introspection availability are observations, not vulnerabilities. See [docs/GRAPHQL_SUITE.md](docs/GRAPHQL_SUITE.md).

# JWT v2.1 Workflow

The development branch also includes offline JWT discovery, secret-safe decoding,
header/claim analysis, controlled comparison, and manual verification planning.
Optional replay is disabled by default and requires an authenticated profile,
explicit opt-in, a researcher-owned token, and an in-scope controlled request.
See [docs/JWT_WORKFLOW.md](docs/JWT_WORKFLOW.md).
