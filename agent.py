import getpass
import shlex
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from openai import OpenAI

from agent_core.workflow_manager import run_workflow
from agent_core.doctor import doctor
from agent_core.tool_explainer import explain
from agent_core.version import __version__
from config import (
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)
from tools.scope_guard import enforce_scope
from tool_registry import validate_registry
from tools.jwt_security_analyzer import analyze_jwt

SYSTEM_PROMPT = """
You are CyberCortex AI, a cybersecurity learning and analysis assistant.

You can:
- Answer cybersecurity questions.
- Explain vulnerabilities and defensive controls.
- Analyze HTTP requests and responses supplied by the user.
- Review source code supplied by the user.
- Suggest authorized manual testing approaches.
- Help write vulnerability reports.
- Explain security tool output and logs.
- Help with secure software development and defensive analysis.

Rules:
- Do not claim that a vulnerability exists without evidence.
- Clearly distinguish confirmed findings from hypotheses.
- Do not invent scan results, endpoints, credentials, or evidence.
- Recommend testing only on systems the user owns or is explicitly
  authorized to test.
- Never start scanning from a normal question.
- Only start the testing workflow when the user explicitly uses the
  "scan" command.
- Keep explanations practical and technically accurate.
"""

LATEST_SCAN_RESULT: dict[str, Any] | None = None


def create_llm_client() -> OpenAI:
    """
    Create an OpenAI-compatible client for the configured local model.
    """

    if not OPENAI_BASE_URL:
        raise RuntimeError("OPENAI_BASE_URL is not configured in the .env file.")

    if not OPENAI_MODEL:
        raise RuntimeError("OPENAI_MODEL is not configured in the .env file.")

    return OpenAI(
        base_url=OPENAI_BASE_URL,
        api_key=OPENAI_API_KEY or "ollama",
    )


def ask_question(question: str) -> str:
    """
    Send a general cybersecurity question to the local LLM.

    This function does not execute scanners, crawlers, or other
    security-testing tools.
    """

    question = question.strip()

    if not question:
        return "Please enter a question."

    try:
        client = create_llm_client()

        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": question,
                },
            ],
            temperature=0.2,
        )

        content: Optional[str] = response.choices[0].message.content

        if not content:
            return "The model returned an empty response."

        return content.strip()

    except Exception as exc:
        return f"Question-answering error: {exc}"


def normalize_target(target: str) -> str:
    """
    Add an HTTPS scheme when the user provides only a hostname or path.
    """

    target = target.strip()

    if not target:
        return ""

    if "://" not in target:
        return f"https://{target}"

    return target


def run_scan_command(command: str) -> dict[str, Any]:
    """
    Run the existing CyberCortex workflow against an authorized target.

    The complete target URL is checked by the scope guard before any
    workflow tools are allowed to run.
    """

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return {"success": False, "error": f"Invalid scan command: {exc}"}
    if not parts:
        return {"success": False, "error": "Please provide an authorized target."}
    target = normalize_target(parts[0])
    profile = "baseline"
    jwt_token = None
    index = 1
    while index < len(parts):
        option = parts[index]
        if option == "--profile" and index + 1 < len(parts):
            profile = parts[index + 1].lower()
            index += 2
            continue
        if option == "--jwt-file" and index + 1 < len(parts):
            path = Path(parts[index + 1])
            try:
                jwt_token = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                return {"success": False, "error": f"Unable to read JWT file: {exc}"}
            index += 2
            continue
        return {"success": False, "error": f"Unsupported scan option: {option}"}
    if profile not in {"baseline", "deep", "authenticated"}:
        return {"success": False, "error": f"Unknown scan profile: {profile}"}
    if jwt_token and profile != "authenticated":
        profile = "authenticated"

    if not target:
        return {
            "success": False,
            "error": "Please provide an authorized target.",
        }

    scope_result = enforce_scope(target)

    if not scope_result.get("allowed"):
        return scope_result

    parsed = urlparse(target)
    allowed_domain = parsed.hostname or ""

    if not allowed_domain:
        return {
            "success": False,
            "target": target,
            "error": "The target does not contain a valid hostname.",
        }

    goal = (
        "Perform a safe security assessment of the authorized target "
        f"{target}. Stay within the configured scope, avoid leaving the "
        "authorized URL path, collect evidence, avoid unsupported claims, "
        "and generate a security report."
    )

    try:
        result = run_workflow(
            goal,
            target,
            allowed_domain,
            profile=profile,
            jwt_token=jwt_token,
        )
        global LATEST_SCAN_RESULT
        LATEST_SCAN_RESULT = result
        return result

    except Exception as exc:
        return {
            "success": False,
            "target": target,
            "error": f"Workflow error: {exc}",
        }


def print_nuclei_result(tool_result: dict[str, Any]) -> None:
    """
    Print a concise Nuclei summary instead of dumping full findings.
    """

    tool_result = tool_result.get("output") or tool_result
    print(f"Success: {tool_result.get('success')}")
    print(f"Target: {tool_result.get('target', tool_result.get('url', 'N/A'))}")
    print(
        f"Findings: {tool_result.get('finding_count', tool_result.get('findings_count', 0))}"
    )

    severity_summary = tool_result.get("severity_summary", {})

    if severity_summary:
        print("Severity summary:")

        for severity in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "unknown",
        ):
            count = severity_summary.get(severity, 0)

            if count:
                print(f"- {severity.capitalize()}: {count}")

    findings = tool_result.get("findings", [])

    if findings:
        print("Detected items:")

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            matcher = finding.get(
                "matcher_name",
                finding.get("name", "unknown"),
            )

            severity = finding.get(
                "severity",
                "unknown",
            )

            affected_url = finding.get(
                "matched_at",
                finding.get("url", ""),
            )

            item = f"- [{severity.upper()}] {matcher}"

            if affected_url:
                item += f" — {affected_url}"

            print(item)

    raw_file = tool_result.get("evidence_file") or tool_result.get("raw_output_file")

    if raw_file:
        print(f"Raw evidence: {raw_file}")

    error = tool_result.get("error")

    if error:
        print(f"Error: {error}")


def print_report_result(tool_result: dict[str, Any]) -> None:
    """
    Print generated report locations cleanly.
    """

    print(f"Success: {tool_result.get('success')}")

    report_file = tool_result.get("report_file")
    evidence_file = tool_result.get("evidence_file")
    generated_at = tool_result.get("generated_at")

    if report_file:
        print(f"Report: {report_file}")

    if evidence_file:
        print(f"Evidence: {evidence_file}")

    if generated_at:
        print(f"Generated: {generated_at}")

    error = tool_result.get("error")

    if error:
        print(f"Error: {error}")


def print_standard_tool_result(tool_result: dict[str, Any]) -> None:
    """
    Print a compact summary for normal tools.
    """

    success = tool_result.get("success")

    if success is not None:
        print(f"Success: {success}")

    error = tool_result.get("error")

    if error:
        print(f"Error: {error}")

    for key, value in tool_result.items():
        if key in {
            "success",
            "error",
            "findings",
            "headers_checked",
            "urls",
        }:
            continue

        print(f"{key}: {value}")

    headers_checked = tool_result.get("headers_checked")

    if isinstance(headers_checked, dict):
        print("Headers:")

        for header_name, header_result in headers_checked.items():
            if not isinstance(header_result, dict):
                print(f"- {header_name}: {header_result}")
                continue

            present = header_result.get("present", False)
            status = "present" if present else "missing"

            print(f"- {header_name}: {status}")

    urls = tool_result.get("urls")

    if isinstance(urls, list):
        print(f"URLs discovered: {len(urls)}")

        for url in urls[:10]:
            print(f"- {url}")

        if len(urls) > 10:
            print(f"- ... and {len(urls) - 10} more")

    findings = tool_result.get("findings")

    if isinstance(findings, list):
        print(f"Findings: {len(findings)}")

        for finding in findings[:10]:
            if isinstance(finding, dict):
                title = (
                    finding.get("issue")
                    or finding.get("name")
                    or finding.get("type")
                    or "Finding"
                )

                severity = finding.get("severity")

                if severity:
                    print(f"- [{severity.upper()}] {title}")
                else:
                    print(f"- {title}")
            else:
                print(f"- {finding}")

        if len(findings) > 10:
            print(f"- ... and {len(findings) - 10} more")


def print_result(result: Any) -> None:
    """
    Print strings and workflow dictionaries cleanly.
    """

    if isinstance(result, str):
        print(result)
        return

    if not isinstance(result, dict):
        print(result)
        return

    print("\n===== CYBERCORTEX RESULT =====")

    if result.get("success") is False:
        print(f"Success: {result.get('success')}")
        print(f"Target: {result.get('target', 'N/A')}")
        print(f"Error: {result.get('error', 'Unknown error')}")
        return

    print(f"Success: {result.get('success', True)}")

    assessment_status = result.get("assessment_status")
    if assessment_status:
        labels = {
            "completed": "Completed",
            "completed_with_limitations": "Completed with limitations",
            "failed": "Failed",
        }
        print(f"Assessment status: {labels.get(assessment_status, assessment_status)}")
    coverage = result.get("coverage") or {}
    if coverage:
        print(f"Coverage: {coverage.get('coverage_percentage', 0)}%")
        if coverage.get("failed_tools") or coverage.get("timed_out_tools"):
            print(
                f"Failed tools: {', '.join(coverage.get('failed_tools', [])) or 'None'}"
            )
            print(
                f"Timed-out tools: {', '.join(coverage.get('timed_out_tools', [])) or 'None'}"
            )

    if result.get("goal"):
        print(f"Goal: {result['goal']}")

    if result.get("target"):
        print(f"Target: {result['target']}")

    completed_steps = result.get("completed_steps", [])

    if completed_steps:
        print("\nCompleted steps:")

        for step in completed_steps:
            print(f"- {step}")

    results = result.get("results")

    if not isinstance(results, dict):
        return

    print("\nTool results:")

    for tool_name, tool_result in results.items():
        print(f"\n--- {tool_name} ---")

        if not isinstance(tool_result, dict):
            print(tool_result)
            continue

        if tool_name == "nuclei_scan":
            print_nuclei_result(tool_result)
            continue

        if tool_name == "ai_report_writer":
            print_report_result(tool_result)
            continue

        print_standard_tool_result(tool_result)


def print_help() -> None:
    print("""
CyberCortex AI commands

  ask <question>
      Ask a cybersecurity or technical question.

  scan <target>
  scan <target> --profile baseline
  scan <target> --profile deep
      Run the security workflow against an authorized in-scope target.

  list tools
      Display registered tools, prerequisites, traffic, and profiles.

  explain <tool> | explain latest | explain scan | explain profiles
      Explain deterministic capabilities, evidence, limitations, or the latest scan.

  jwt analyze [token]
      Analyze an explicitly supplied JWT offline. With no token, prompt securely.

  doctor [--quick]
      Check local release readiness without running a live target scan.

  help
      Display this help message.

  exit
      Exit CyberCortex AI.

Authenticated tools require explicit controlled input. Baseline scans do not
automatically test IDOR, JWT acceptance, GraphQL authorization, business logic,
or file uploads. Scope and program rules always apply.

Examples

  ask What is an IDOR vulnerability?

  ask Explain the difference between authentication and authorization.

  ask Give me a manual testing checklist for password reset.

  ask Analyze this HTTP request:
      GET /api/users/42 HTTP/1.1
      Host: example.com

  scan https://localhost:8000

  scan https://crypto.com/exchange
""")


def process_user_input(user_input: str) -> Any:
    """
    Route input into question mode or scan mode.

    Unknown commands default to question mode. This prevents unclear input
    from accidentally starting a security-testing workflow.
    """

    cleaned = user_input.strip()

    if not cleaned:
        return None

    lowered = cleaned.lower()

    if lowered in {"exit", "quit", "/exit", "/quit"}:
        print("Exiting CyberCortex AI.")
        sys.exit(0)

    if lowered in {"help", "/help", "?"}:
        print_help()
        return None

    if lowered.startswith("ask "):
        return ask_question(cleaned[4:].strip())

    if lowered.startswith("/ask "):
        return ask_question(cleaned[5:].strip())

    if lowered.startswith("scan "):
        return run_scan_command(cleaned[5:].strip())

    if lowered.startswith("/scan "):
        return run_scan_command(cleaned[6:].strip())

    if lowered == "list tools":
        rows = ["Tool | Status | Category | Prerequisites | Traffic | Profiles"]
        for item in validate_registry():
            rows.append(
                " | ".join(
                    (
                        item["name"],
                        item["status"],
                        item["category"],
                        ",".join(item["prerequisites"]) or "none",
                        "network" if item["network"] else "offline",
                        ",".join(item["profiles"]),
                    )
                )
            )
        return "\n".join(rows)

    if lowered.startswith("explain "):
        return explain(cleaned[len("explain ") :], LATEST_SCAN_RESULT)

    if lowered == "doctor" or lowered == "doctor --quick":
        return doctor(quick=lowered.endswith("--quick"))

    if lowered == "jwt analyze" or lowered.startswith("jwt analyze "):
        token = cleaned[len("jwt analyze") :].strip()
        if not token:
            token = getpass.getpass("JWT (hidden): ").strip()
        return analyze_jwt(token)

    return ask_question(cleaned)


def main() -> None:
    print("=" * 60)
    print(f"CyberCortex AI Agent v{__version__}")
    print("=" * 60)
    print("Use 'ask <question>' for questions.")
    print("Use 'scan <target>' for authorized security testing.")
    print("Type 'help' for examples or 'exit' to quit.")
    print()

    while True:
        try:
            user_input = input("CyberCortex> ")
            result = process_user_input(user_input)

            if result is None:
                continue

            print()
            print_result(result)
            print()

        except KeyboardInterrupt:
            print("\nExiting CyberCortex AI.")
            break

        except EOFError:
            print("\nExiting CyberCortex AI.")
            break

        except Exception as exc:
            print(f"\nUnexpected error: {exc}\n")


if __name__ == "__main__":
    main()
