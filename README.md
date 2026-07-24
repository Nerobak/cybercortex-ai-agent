# CyberCortex AI Agent

> **A fully local AI-powered cybersecurity assistant for authorized security assessments, bug bounty research, reconnaissance, analysis, and professional reporting.**

[![DOI](https://zenodo.org/badge/1281439329.svg)](https://doi.org/10.5281/zenodo.21519975)![Status](https://img.shields.io/badge/Status-Beta-orange)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![AI](https://img.shields.io/badge/LLM-DeepSeek_R1_Distill_32B-red)
![Platform](https://img.shields.io/badge/Platform-Ollama-black)

---

## Overview

CyberCortex AI Agent is a fully local AI-powered cybersecurity platform designed to assist security professionals and bug bounty researchers during **authorized** security assessments.

Unlike traditional security automation scripts, CyberCortex AI Agent combines a local reasoning model (DeepSeek R1 Distill 32B running through Ollama) with custom-built cybersecurity tools to automate reconnaissance, analyze findings, prioritize manual testing, and generate professional security reports.

The project is designed around a modular AI architecture that separates planning, workflow management, decision-making, security tooling, and AI-assisted reporting.

No cloud AI services are required.

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

## Local AI

* Fully local execution
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

CyberCortex AI Agent is designed to run entirely on local hardware using Ollama and DeepSeek R1 Distill 32B.

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

## Citation

CyberCortex AI Agent is permanently archived on Zenodo.

**Project DOI (latest version):**

https://doi.org/10.5281/zenodo.21519975

**Archived release (v2.1.0-beta):**

https://doi.org/10.5281/zenodo.21519976

GitHub users can also use the **"Cite this repository"** button when available. 
