# Roadmap

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

This project is under active development. The goal is to build a fully local AI Security Agent capable of assisting security researchers and bug bounty hunters with authorized reconnaissance, analysis, and reporting.

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

The long-term goal is to build a modular, fully local AI security platform that helps security professionals:

* Perform authorized reconnaissance
* Analyze security findings
* Generate professional reports
* Prioritize manual testing
* Improve productivity during security assessments

The project is designed to remain local-first, allowing researchers to use powerful AI workflows without relying on cloud-hosted reasoning models.

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
