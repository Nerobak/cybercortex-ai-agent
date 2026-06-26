# Architecture

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
Workflow Manager  
↓  
Tool Registry  
↓  
Security Tools  
↓  
AI Report Writer  

## Core Components

- `agent.py` – CLI entry point
- `config.py` – central configuration
- `tool_registry.py` – metadata for available tools
- `agent_core/llm_client.py` – local LLM client through Ollama
- `agent_core/planner.py` – creates tool execution plans
- `agent_core/decision_engine.py` – parses and selects workflow steps
- `agent_core/workflow_manager.py` – executes the planned workflow
- `tools/` – cybersecurity tools
- `reports/` – generated Markdown reports

## Safety Model

All target testing is controlled by `PENTEST_ALLOWLIST` in `.env`.
Targets not listed in the allowlist are blocked by `scope_guard.py`.
