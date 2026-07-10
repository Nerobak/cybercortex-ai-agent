# Installation Guide

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
