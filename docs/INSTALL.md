# Installation Guide

## Optional upload replay configuration

Upload analysis and planning need no additional dependency and run offline.
Replay remains disabled unless `UPLOAD_REPLAY_ENABLED=true` is explicitly set.
Store controlled request JSON and benign researcher-owned files under an ignored
local directory. The replay gate enforces configured scope, ownership
confirmations, a 1 MiB limit, a benign extension allowlist, and executable,
active-content, archive, and polyglot blocking.

## Optional business-logic replay configuration

No additional dependency is required. Replay remains disabled unless
`BUSINESS_LOGIC_REPLAY_ENABLED=true` is set explicitly. Keep the timeout,
response-size, step, and request limits positive; `doctor` validates them without
printing configuration values. Offline workflow commands accept local JSON files.

## CyberCortex AI Agent v2.1.0-beta readiness

After installation, run `doctor --quick`. Resolve `FAIL` entries before use and review environment-specific `WARN` entries. A full `doctor` additionally runs registry and compile checks; it does not scan a target. Keep `.env`, reports, logs, verification inputs, captured requests, Burp files, and local JWT inputs untracked. The dashboard binds only to `127.0.0.1`.

This guide explains how to install and configure **CyberCortex AI Agent** on a local system using **Ollama** and **DeepSeek R1 Distill 32B**.

---

# System Requirements

## Operating Systems

* macOS
* Linux
* Windows (WSL recommended)

## Software Requirements

* Python 3.9+
* Git
* Ollama
* DeepSeek R1 Distill 32B

---

# 1. Clone the Repository

```bash
git clone https://github.com/nerobak/cybercortex-ai-agent.git

cd cybercortex-ai-agent
```

---

# 2. Create a Python Virtual Environment

## macOS / Linux

```bash
python3 -m venv venv

source venv/bin/activate
```

## Windows

```powershell
python -m venv venv

venv\Scripts\activate
```

---

# 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

For development checks:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Configure both the hostname allowlist and, where authorization is path-limited,
`PENTEST_ALLOWED_URL_PREFIXES`. Keep JWTs and captured verification material in
the Git-ignored `verification_inputs/` directory. Baseline and deep scans do not
automatically run authenticated tools.

---

# 4. Install Ollama

Download Ollama from:

https://ollama.com/download

Verify the installation:

```bash
ollama --version
```

---

# 5. Download DeepSeek

Pull the DeepSeek R1 Distill 32B model:

```bash
ollama pull deepseek-r1:32b
```

Verify the model:

```bash
ollama list
```

Expected output should include:

```text
deepseek-r1:32b
```

---

# 6. Configure the Environment

Create a `.env` file in the project root.

Example:

```env
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama
OPENAI_MODEL=deepseek-r1:32b

PENTEST_ALLOWLIST=example.com,localhost,127.0.0.1

ENABLE_ACTIVE_SCANNING=true
```

> **Note:** Update `PENTEST_ALLOWLIST` with only domains you own or are explicitly authorized to test.

---

# 7. Verify the Installation

Check Python:

```bash
python --version
```

Check Ollama:

```bash
ollama --version
```

Verify the installed model:

```bash
ollama list
```

---

# 8. Run CyberCortex AI Agent

## Interactive Mode

```bash
python agent.py
```

Example:

```text
==================================================
              CyberCortex AI Agent
          Local AI Security Platform
==================================================

Target URL >
```

---

## Command-Line Mode

```bash
python agent.py --target https://example.com --mode safe
```

View all available options:

```bash
python agent.py --help
```

---

# Generated Output

Reports are automatically saved to:

```text
reports/
```

Future log files will be stored in:

```text
logs/
```

---

# Updating the Project

Pull the latest changes:

```bash
git pull
```

Update Python packages if necessary:

```bash
pip install -r requirements.txt
```

Update DeepSeek (if a newer model version is available):

```bash
ollama pull deepseek-r1:32b
```

---

# Troubleshooting

## Ollama not found

Verify that Ollama is installed:

```bash
ollama --version
```

## Model not found

Download it again:

```bash
ollama pull deepseek-r1:32b
```

## Agent cannot analyze a target

Verify that the target is listed in:

```text
PENTEST_ALLOWLIST
```

inside your `.env` file.

---

# Safety Notice

CyberCortex AI Agent is intended **only** for authorized security testing.

Use it only against:

* Systems you own
* Laboratory environments
* Capture-the-Flag (CTF) platforms
* Bug bounty programs that explicitly authorize testing

The built-in **Scope Guard** prevents assessments of targets outside the configured allowlist.

# Markdown

After installation, start the interactive agent:

```bash
python agent.py
```

Example:

```text
ask Explain Content Security Policy

scan https://example.com
```
# Optional GraphQL configuration

GraphQL offline analysis requires no additional dependency. Introspection is disabled by default. To permit the bounded check for an explicitly authorized target, set `GRAPHQL_INTROSPECTION_ENABLED=true` and keep the endpoint inside `PENTEST_ALLOWLIST` or `PENTEST_ALLOWED_URL_PREFIXES`. Timeout and response limits are configured with `GRAPHQL_TIMEOUT_SECONDS` and `GRAPHQL_MAX_RESPONSE_BYTES`.

# Optional JWT configuration

JWT discovery, decoding, analysis, comparison, and planning require no additional
dependency and send no traffic. Defaults are:

```dotenv
JWT_REPLAY_ENABLED=false
JWT_TIMEOUT_SECONDS=15
JWT_MAX_RESPONSE_BYTES=1000000
JWT_MAX_LIFETIME_SECONDS=86400
JWT_CLOCK_SKEW_SECONDS=300
JWT_MAX_TOKEN_BYTES=16384
```

Keep replay disabled unless a program explicitly permits the exact controlled
request. Run `doctor --quick` to validate JWT limits without printing secrets.
