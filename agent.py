import getpass
import shlex
import sys
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from openai import OpenAI

from agent_core.workflow_manager import run_workflow
from agent_core.adaptive_orchestrator import (
    AdaptiveAssessmentOrchestrator,
    write_assessment_plan,
)
from agent_core.policy import load_policy, policy_from_runtime
from agent_core.doctor import doctor
from agent_core.result_normalizer import public_result, sanitize_text
from agent_core.tool_explainer import explain
from agent_core.verification_capabilities import capability_metadata
from agent_core.version import __version__
from config import (
    AGENT_REQUEST_BUDGET,
    ENABLE_INTRUSIVE_SCANNING,
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    OPENAI_MODEL,
)
from tools.scope_guard import enforce_scope
from tool_registry import validate_registry
from tools.jwt_decoder import jwt_decoder
from tools.jwt_claims_analyzer import analyze_jwt_claims
from tools.jwt_comparison_analyzer import compare_jwts
from tools.jwt_verification_planner import plan_jwt_verification
from tools.jwt_replay_checker import check_jwt_replay
from tools.graphql_query_analyzer import analyze_graphql_query
from tools.graphql_schema_analyzer import analyze_graphql_schema
from tools.workflow_evidence_discovery import discover_workflow_evidence
from tools.workflow_model_builder import build_workflow_model
from tools.workflow_transition_analyzer import analyze_workflow_transitions
from tools.business_rule_analyzer import analyze_business_rules, compare_workflows
from tools.business_logic_test_planner import plan_business_logic_tests
from tools.workflow_replay_checker import check_workflow_replay
from tools.upload_discovery import discover_upload_surface
from tools.upload_validation_analyzer import analyze_upload_validation
from tools.upload_metadata_analyzer import analyze_upload_metadata
from tools.upload_storage_analyzer import analyze_upload_storage
from tools.upload_security_planner import plan_upload_security
from tools.upload_replay_checker import check_upload_replay

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
MAX_CONTROLLED_INPUT_BYTES = 64 * 1024
NO_PHASE2_STATE_MESSAGE = (
    "No Phase 2 assessment state is loaded. Run a plan or verify scan first."
)


def _latest_phase2_state() -> dict[str, Any] | None:
    """Return the in-session Phase 2 state, falling back to the saved latest run."""

    if isinstance(LATEST_SCAN_RESULT, dict):
        phase2 = LATEST_SCAN_RESULT.get("phase2")
        if isinstance(phase2, dict):
            return phase2

    from agent_core.phase2_store import Phase2RunStore

    try:
        return Phase2RunStore().load()
    except FileNotFoundError:
        return None


def _safe_text(value: Any, default: str = "Not provided") -> str:
    if value is None or value == "":
        return default
    rendered = sanitize_text(str(value))
    if not rendered:
        return default
    return str(rendered)


def _safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_text(item) for item in value if isinstance(item, (str, int, float))]


def _safe_route(value: Any) -> str:
    """Render a route without URL credentials, query values, or fragments."""

    if not isinstance(value, str) or not value:
        return "Not provided"
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return parsed.path or "/"
    return value.split("?", 1)[0].split("#", 1)[0] or "/"


def _target_surface_view(hypothesis: dict[str, Any]) -> dict[str, str]:
    surface = hypothesis.get("target_surface")
    surface = surface if isinstance(surface, dict) else {}
    route = surface.get("path") or surface.get("url") or hypothesis.get("endpoint")
    view = {
        "method": _safe_text(surface.get("method") or hypothesis.get("method"), "GET"),
        "route": _safe_route(route),
    }
    parameter = surface.get("parameter") or hypothesis.get("parameter")
    location = surface.get("parameter_location") or hypothesis.get("parameter_location")
    if parameter:
        view["parameter"] = _safe_text(parameter)
    if location:
        view["parameter_location"] = _safe_text(location)
    return view


def _evidence_basis_view(hypothesis: dict[str, Any]) -> list[str]:
    basis: list[str] = []
    raw_basis = hypothesis.get("evidence_basis")
    for item in raw_basis if isinstance(raw_basis, list) else []:
        if isinstance(item, dict):
            observation = item.get("observation")
            if observation:
                basis.append(_safe_text(observation))
        elif isinstance(item, str):
            basis.append(_safe_text(item))
    if not basis and hypothesis.get("rationale"):
        basis.append(_safe_text(hypothesis["rationale"]))
    return basis


def _hypothesis_list_item(hypothesis: dict[str, Any]) -> dict[str, Any]:
    metadata = hypothesis.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    surface = _target_surface_view(hypothesis)
    affected = " ".join(
        item for item in (surface.get("method"), surface.get("route")) if item
    )
    if surface.get("parameter"):
        affected += f" (parameter: {surface['parameter']})"
    evidence = _evidence_basis_view(hypothesis)
    category = _safe_text(hypothesis.get("category"), "unknown")
    try:
        capability = capability_metadata(category)
    except ValueError:
        capability = {}
    return {
        "id": _safe_text(hypothesis.get("hypothesis_id") or hypothesis.get("id")),
        "category": category,
        "capability_state": capability.get("capability_state", "unknown"),
        "priority": metadata.get("priority", "not ranked"),
        "score": metadata.get("priority_score", hypothesis.get("priority", 0)),
        "confidence": _safe_text(hypothesis.get("confidence"), "low"),
        "status": _safe_text(hypothesis.get("status"), "proposed"),
        "affected_route_or_functionality": affected or "Not provided",
        "evidence_basis": evidence[0] if evidence else "Not provided",
    }


def _hypothesis_explanation(hypothesis: dict[str, Any]) -> dict[str, Any]:
    metadata = hypothesis.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    category = _safe_text(hypothesis.get("category"), "unknown")
    try:
        capability = capability_metadata(category)
    except ValueError:
        capability = {}
    return {
        "hypothesis_id": _safe_text(
            hypothesis.get("hypothesis_id") or hypothesis.get("id")
        ),
        "category": category,
        "title": _safe_text(hypothesis.get("title")),
        "target_surface": _target_surface_view(hypothesis),
        "evidence_basis": _evidence_basis_view(hypothesis),
        "confidence": _safe_text(hypothesis.get("confidence"), "low"),
        "impact_if_confirmed": _safe_text(hypothesis.get("impact_if_confirmed")),
        "required_context": _safe_list(hypothesis.get("required_context")),
        "safe_verification_possible": bool(
            hypothesis.get("safe_verification_possible")
        ),
        "current_status": _safe_text(hypothesis.get("status"), "proposed"),
        "limitations": _safe_list(hypothesis.get("limitations")),
        "priority_rationale": _safe_list(metadata.get("priority_reasons")),
        **capability,
    }


def _plan_prerequisites(plan: dict[str, Any]) -> list[str]:
    prerequisites = _safe_list(plan.get("prerequisites"))
    raw_steps = plan.get("steps")
    for step in raw_steps if isinstance(raw_steps, list) else []:
        if not isinstance(step, dict):
            continue
        for item in _safe_list(step.get("prerequisites")):
            if item not in prerequisites:
                prerequisites.append(item)
    return prerequisites


def _minimal_request_view(plan: dict[str, Any]) -> list[str]:
    requests: list[str] = []
    target = _safe_route(plan.get("target"))
    raw_steps = plan.get("steps")
    for step in raw_steps if isinstance(raw_steps, list) else []:
        if not isinstance(step, dict):
            continue
        metadata = step.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        raw_requests = metadata.get("requests")
        if isinstance(raw_requests, list) and raw_requests:
            for request in raw_requests:
                if not isinstance(request, dict):
                    continue
                method = _safe_text(request.get("method") or step.get("method"), "GET")
                route = _safe_route(request.get("url") or target)
                qualifiers: list[str] = []
                if request.get("account_id"):
                    qualifiers.append("controlled account")
                if request.get("object_owner_account_id") or request.get(
                    "test_owned_resource"
                ):
                    qualifiers.append("test-owned resource")
                if request.get("replay"):
                    qualifiers.append("controlled replay")
                suffix = f" ({'; '.join(qualifiers)})" if qualifiers else ""
                requests.append(f"{method} {route}{suffix}")
            continue
        method = _safe_text(step.get("method"), "GET")
        request_cost = int(step.get("request_cost") or 0)
        requests.append(f"{method} {target} ({request_cost} request(s))")
    return requests


def _verification_plan_view(plan: dict[str, Any]) -> dict[str, Any]:
    prerequisites = _plan_prerequisites(plan)
    requirement_text = " ".join(prerequisites).lower()
    steps = [step for step in (plan.get("steps") or []) if isinstance(step, dict)]
    supplied_accounts = plan.get("controlled_accounts")
    supplied_accounts = supplied_accounts if isinstance(supplied_accounts, list) else []
    supplied_resources = plan.get("test_owned_resources")
    supplied_resources = (
        supplied_resources if isinstance(supplied_resources, list) else []
    )
    accounts_required = bool(
        supplied_accounts
        or "account" in requirement_text
        or any(step.get("requires_credentials") for step in steps)
    )
    resources_required = bool(
        plan.get("test_owned_resources_required")
        or supplied_resources
        or "test-owned" in requirement_text
        or "researcher-controlled" in requirement_text
        or "confirmed ownership" in requirement_text
        or any(step.get("test_owned_resource_required") for step in steps)
    )
    stop_conditions: list[str] = []
    cleanup = _safe_list(plan.get("cleanup"))
    for step in steps:
        for item in _safe_list(step.get("stop_conditions")):
            if item not in stop_conditions:
                stop_conditions.append(item)
        for item in _safe_list(step.get("cleanup_steps")):
            if item not in cleanup:
                cleanup.append(item)
    category = _safe_text(
        ((steps[0].get("metadata") or {}).get("category") if steps else None),
        "unknown",
    )
    try:
        capability = capability_metadata(category)
    except ValueError:
        capability = {}
    return {
        "hypothesis_id": _safe_text(plan.get("hypothesis_id")),
        "objective": _safe_text(plan.get("objective")),
        "prerequisites": prerequisites,
        "controlled_accounts_required": accounts_required,
        "test_owned_resources_required": resources_required,
        "minimal_requests": _minimal_request_view(plan),
        "expected_secure_behavior": _safe_list(plan.get("expected_secure_behavior")),
        "expected_vulnerable_behavior": _safe_list(
            plan.get("expected_vulnerable_behavior")
        ),
        "evidence_to_compare": _safe_list(plan.get("evidence_to_compare")),
        "stop_conditions": stop_conditions,
        "cleanup": cleanup,
        "max_requests": int(plan.get("request_budget") or 0),
        "side_effect_risk": _safe_text(plan.get("side_effect_risk"), "unknown"),
        **capability,
        "automatic_execution_allowed": bool(plan.get("automatic_execution_allowed")),
        "minimum_requests": capability.get(
            "min_requests", plan.get("minimum_requests", 0)
        ),
        "worst_case_requests": plan.get(
            "worst_case_requests", capability.get("worst_case_requests", 0)
        ),
    }


def _read_controlled_file(path_value: str, label: str) -> str:
    path = Path(path_value)
    try:
        if path.stat().st_size > MAX_CONTROLLED_INPUT_BYTES:
            raise ValueError(
                f"{label} file exceeds the {MAX_CONTROLLED_INPUT_BYTES}-byte limit."
            )
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"Unable to read {label} file: {exc}") from exc


def _read_json_file(path_value: str, label: str) -> Any:
    import json

    try:
        return json.loads(_read_controlled_file(path_value, label))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid {label} JSON at line {exc.lineno}, column {exc.colno}."
        ) from exc


def _jwt_analysis(token: str) -> dict[str, Any]:
    decoded = jwt_decoder(token)
    if not decoded.get("success"):
        return decoded
    claims = analyze_jwt_claims(token)
    return {**decoded, "claims_analysis": claims}


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
        return public_result(
            {"success": False, "error": f"Invalid scan command: {exc}"}
        )
    if not parts:
        return public_result(
            {"success": False, "error": "Please provide an authorized target."}
        )
    target = normalize_target(parts[0])
    profile = "baseline"
    mode = "observe"
    target_class = "external"
    lab_requested = False
    dedicated_lab_requested = False
    phase2_policy_path = None
    controlled_context_path = None
    verification_input_path = None
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
                return public_result(
                    {"success": False, "error": f"Unable to read JWT file: {exc}"}
                )
            index += 2
            continue
        if option == "--mode" and index + 1 < len(parts):
            mode = parts[index + 1].lower()
            index += 2
            continue
        if option == "--policy" and index + 1 < len(parts):
            phase2_policy_path = parts[index + 1]
            index += 2
            continue
        if option == "--context" and index + 1 < len(parts):
            controlled_context_path = parts[index + 1]
            index += 2
            continue
        if option == "--verification-input" and index + 1 < len(parts):
            verification_input_path = parts[index + 1]
            index += 2
            continue
        if option == "--lab":
            lab_requested = True
            index += 1
            continue
        if option == "--dedicated-lab":
            dedicated_lab_requested = True
            index += 1
            continue
        return public_result(
            {"success": False, "error": f"Unsupported scan option: {option}"}
        )
    if profile not in {"baseline", "deep", "authenticated", "intrusive"}:
        return public_result(
            {"success": False, "error": f"Unknown scan profile: {profile}"}
        )
    if mode not in {"observe", "plan", "verify"}:
        return public_result(
            {"success": False, "error": f"Unknown Phase 2 mode: {mode}"}
        )
    from agent_core.verification_runtime import canonical_target_class

    try:
        target_class = canonical_target_class(
            lab=lab_requested, dedicated_lab=dedicated_lab_requested
        )
    except ValueError as exc:
        return public_result({"success": False, "error": str(exc)})
    if profile == "intrusive" and not ENABLE_INTRUSIVE_SCANNING:
        return public_result(
            {
                "success": False,
                "error": (
                    "Intrusive scanning is disabled. Set "
                    "ENABLE_INTRUSIVE_SCANNING=true only for an explicitly "
                    "authorized target, then select --profile intrusive again."
                ),
            }
        )
    if jwt_token and profile != "authenticated":
        profile = "authenticated"

    if not target:
        return public_result(
            {
                "success": False,
                "error": "Please provide an authorized target.",
            }
        )

    scope_result = enforce_scope(target)

    if not scope_result.get("allowed"):
        return public_result(scope_result)

    parsed = urlparse(target)
    allowed_domain = parsed.hostname or ""

    if not allowed_domain:
        return public_result(
            {
                "success": False,
                "target": target,
                "error": "The target does not contain a valid hostname.",
            }
        )

    assessment_label = f"{mode}-mode"
    goal = (
        f"Perform an authorized {assessment_label} {profile} security assessment of the target "
        f"{target}. Stay within the configured scope, avoid leaving the "
        "authorized URL path, collect evidence, prohibit denial of service "
        "and destructive actions, avoid unsupported claims, "
        "and generate a security report."
    )

    try:
        from agent_core.controlled_context import (
            ControlledContext,
            load_controlled_context,
        )
        from agent_core.credential_vault import CredentialVault
        from agent_core.phase2_store import Phase2RunStore
        from agent_core.verification_runtime import (
            create_verification_runtime,
        )

        vault = CredentialVault()
        phase2_store = Phase2RunStore()
        try:
            controlled = (
                load_controlled_context(controlled_context_path, vault)
                if controlled_context_path
                else ControlledContext()
            )
            phase2_policy = (
                load_policy(phase2_policy_path)
                if phase2_policy_path
                else policy_from_runtime(
                    target,
                    profile=profile,
                    authorization_confirmed=True,
                    request_budget=AGENT_REQUEST_BUDGET,
                )
            )
            verification_inputs = (
                _read_json_file(verification_input_path, "verification input")
                if verification_input_path
                else {}
            )
            executor = None
            if mode == "verify":
                executor = create_verification_runtime(
                    policy=phase2_policy,
                    controlled_context=controlled,
                    vault=vault,
                    verification_inputs=verification_inputs,
                    target=target,
                    target_class=target_class,
                    store=phase2_store,
                    defer_transport=True,
                )
            result = run_workflow(
                goal,
                target,
                allowed_domain,
                profile=profile,
                assessment_mode=mode,
                jwt_token=jwt_token,
                phase2_policy=phase2_policy,
                target_class=target_class,
                controlled_context=controlled,
                phase2_executor=executor,
                phase2_store=phase2_store,
            )
        finally:
            vault.close()
        global LATEST_SCAN_RESULT
        result = public_result(result)
        LATEST_SCAN_RESULT = result
        return result

    except Exception as exc:
        return public_result(
            {
                "success": False,
                "target": target,
                "error": f"Workflow error: {exc}",
            }
        )


def print_nuclei_result(tool_result: dict[str, Any]) -> None:
    """
    Print a concise Nuclei summary instead of dumping full findings.
    """

    tool_result = public_result(tool_result)
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

    tool_result = public_result(tool_result)
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

    tool_result = public_result(tool_result)
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


def _print_phase2_list(label: str, values: Any) -> None:
    items = values if isinstance(values, list) else []
    print(f"{label}:")
    if not items:
        print("- None")
        return
    for item in items:
        print(f"- {item}")


def print_result(result: Any) -> None:
    """
    Print strings and workflow dictionaries cleanly.
    """

    if isinstance(result, str):
        print(sanitize_text(result))
        return

    if not isinstance(result, dict):
        print(sanitize_text(str(result)))
        return

    result = public_result(result)

    print("\n===== CYBERCORTEX RESULT =====")

    if result.get("success") is False:
        print(f"Success: {result.get('success')}")
        print(f"Target: {result.get('target', 'N/A')}")
        print(f"Error: {result.get('error', 'Unknown error')}")
        return

    print(f"Success: {result.get('success', True)}")

    if result.get("category") == "recovery_state_enforcement":
        print(f"Status: {result.get('status', 'inconclusive')}")
        print(f"Recovery phase: {result.get('recovery_phase') or 'not started'}")
        print(f"Comparison type: {result.get('comparison_type') or 'not selected'}")
        print(
            "Challenge reference: "
            f"{result.get('challenge_reference') or 'not established'}"
        )
        print(
            "Valid completion succeeded: "
            f"{bool(result.get('valid_completion_succeeded'))}"
        )
        print(f"Comparison attempted: {bool(result.get('comparison_attempted'))}")
        print(f"Comparison accepted: {bool(result.get('comparison_accepted'))}")
        print(
            "Independent state confirmed: "
            f"{bool(result.get('independent_state_confirmed'))}"
        )
        print(f"Cleanup verified: {bool(result.get('cleanup_verified'))}")
        print(f"Cleanup failed: {bool(result.get('cleanup_failed'))}")
        print(
            "External cleanup required: "
            f"{bool(result.get('external_cleanup_required'))}"
        )
        print(
            "Controlled recovery evidence required: "
            f"{bool(result.get('recovery_evidence_required'))}"
        )
        return

    if result.get("category") == "session_invalidation":
        runtime_binding = result.get("runtime_binding") or {}
        baseline = result.get("baseline") or {}
        replay = result.get("replay") or {}
        print(f"Status: {result.get('status', 'inconclusive')}")
        print(
            "Runtime binding: "
            f"{int(runtime_binding.get('bound_accounts') or 0)}/"
            f"{int(runtime_binding.get('required_accounts') or 0)} account(s); "
            f"policy authorized={bool(runtime_binding.get('policy_authorized'))}"
        )
        print(f"Baseline status: {baseline.get('status_code', 'not established')}")
        print(f"Replay status: {replay.get('status_code', 'not performed')}")
        print(
            "Protected field paths: "
            + ", ".join(result.get("protected_field_paths") or [])
        )
        print(
            "Protected evidence matched: "
            f"{bool(result.get('protected_evidence_matched'))}"
        )
        print(f"Same session replayed: {bool(result.get('same_session_replayed'))}")
        print(
            "Termination: "
            f"attempted={bool(result.get('termination_attempted'))}; "
            f"succeeded={bool(result.get('termination_succeeded'))}"
        )
        print(f"Cleanup verified: {bool(result.get('cleanup_verified'))}")
        return

    if isinstance(result.get("owned_object_acquisition"), dict):
        acquisition = result["owned_object_acquisition"]
        runtime_binding = result.get("runtime_binding") or {}
        print(f"Status: {result.get('status', 'inconclusive')}")
        if runtime_binding:
            print("Runtime binding:")
            print(
                "- Required accounts: "
                f"{int(runtime_binding.get('required_accounts') or 0)}"
            )
            print(
                "- Bound accounts: "
                f"{int(runtime_binding.get('bound_accounts') or 0)}"
            )
            print(f"- Owner bound: {bool(runtime_binding.get('owner_bound'))}")
            print(
                "- Comparator bound: "
                f"{bool(runtime_binding.get('comparator_bound'))}"
            )
            print(
                "- Policy authorized: "
                f"{bool(runtime_binding.get('policy_authorized'))}"
            )
        print("Owned object acquisition:")
        print(f"- Attempted: {bool(acquisition.get('attempted'))}")
        print(f"- Succeeded: {bool(acquisition.get('succeeded'))}")
        print(f"- Owner: {_safe_text(acquisition.get('owner'), 'Not applicable')}")
        print(
            "- Object type: "
            f"{_safe_text(acquisition.get('object_type'), 'Not applicable')}"
        )
        print(f"- Identifier present: {bool(acquisition.get('identifier_present'))}")
        if acquisition.get("controlled_test_owned_evidence"):
            print("- Evidence: Controlled test-owned evidence")
        return

    if isinstance(result.get("hypotheses"), list):
        hypotheses = result["hypotheses"]
        print(f"Hypotheses: {len(hypotheses)}")
        for index, hypothesis in enumerate(hypotheses, 1):
            if not isinstance(hypothesis, dict):
                continue
            print(f"\nHypothesis {index}")
            print(f"ID: {hypothesis.get('id', 'Not provided')}")
            print(f"Category: {hypothesis.get('category', 'unknown')}")
            print(
                "Capability state: " f"{hypothesis.get('capability_state', 'unknown')}"
            )
            print(f"Priority: {hypothesis.get('priority', 'not ranked')}")
            print(f"Score: {hypothesis.get('score', 0)}")
            print(f"Confidence: {hypothesis.get('confidence', 'low')}")
            print(f"Status: {hypothesis.get('status', 'proposed')}")
            print(
                "Affected route/functionality: "
                f"{hypothesis.get('affected_route_or_functionality', 'Not provided')}"
            )
            print(f"Evidence basis: {hypothesis.get('evidence_basis', 'Not provided')}")
        return

    if isinstance(result.get("hypothesis"), dict):
        hypothesis = result["hypothesis"]
        surface = hypothesis.get("target_surface") or {}
        rendered_surface = " ".join(
            item for item in (surface.get("method"), surface.get("route")) if item
        )
        if surface.get("parameter"):
            rendered_surface += f" (parameter: {surface['parameter']})"
        print(f"Hypothesis ID: {hypothesis.get('hypothesis_id', 'Not provided')}")
        print(f"Category: {hypothesis.get('category', 'unknown')}")
        print(f"Capability state: {hypothesis.get('capability_state', 'unknown')}")
        print(
            "Typed executor available: "
            f"{hypothesis.get('typed_executor_available', False)}"
        )
        print(
            "Automatic execution possible: "
            f"{hypothesis.get('automatic_execution', False)}"
        )
        print("Executor version: " f"{hypothesis.get('executor_version') or 'none'}")
        print(
            "Request cost: "
            f"{hypothesis.get('min_requests', 0)}–{hypothesis.get('worst_case_requests', 0)}"
        )
        _print_phase2_list("Major preconditions", hypothesis.get("major_preconditions"))
        print(f"Title: {hypothesis.get('title', 'Not provided')}")
        print(f"Target surface: {rendered_surface or 'Not provided'}")
        _print_phase2_list("Evidence basis", hypothesis.get("evidence_basis"))
        print(f"Confidence: {hypothesis.get('confidence', 'low')}")
        print(
            "Impact if confirmed: "
            f"{hypothesis.get('impact_if_confirmed', 'Not provided')}"
        )
        _print_phase2_list("Required context", hypothesis.get("required_context"))
        print(
            "Safe verification possible: "
            f"{hypothesis.get('safe_verification_possible', False)}"
        )
        print(f"Current status: {hypothesis.get('current_status', 'proposed')}")
        _print_phase2_list("Limitations", hypothesis.get("limitations"))
        _print_phase2_list("Priority rationale", hypothesis.get("priority_rationale"))
        return

    if isinstance(result.get("verification_plan"), dict):
        plan = result["verification_plan"]
        print(f"Hypothesis ID: {plan.get('hypothesis_id', 'Not provided')}")
        print(f"Capability state: {plan.get('capability_state', 'unknown')}")
        print(
            "Typed executor available: "
            f"{plan.get('typed_executor_available', False)}"
        )
        print(f"Executor version: {plan.get('executor_version') or 'none'}")
        print(
            "Request cost: "
            f"{plan.get('minimum_requests', 0)}–{plan.get('worst_case_requests', 0)}"
        )
        _print_phase2_list("Major preconditions", plan.get("major_preconditions"))
        print(f"Objective: {plan.get('objective', 'Not provided')}")
        _print_phase2_list("Prerequisites", plan.get("prerequisites"))
        print(
            "Controlled accounts required: "
            f"{plan.get('controlled_accounts_required', False)}"
        )
        print(
            "Test-owned resources required: "
            f"{plan.get('test_owned_resources_required', False)}"
        )
        _print_phase2_list("Minimal requests", plan.get("minimal_requests"))
        _print_phase2_list(
            "Expected secure behavior", plan.get("expected_secure_behavior")
        )
        _print_phase2_list(
            "Expected vulnerable behavior", plan.get("expected_vulnerable_behavior")
        )
        _print_phase2_list("Evidence to compare", plan.get("evidence_to_compare"))
        _print_phase2_list("Stop conditions", plan.get("stop_conditions"))
        _print_phase2_list("Cleanup", plan.get("cleanup"))
        print(f"Max requests: {plan.get('max_requests', 0)}")
        print(f"Side-effect risk: {plan.get('side_effect_risk', 'unknown')}")
        print(
            "Automatic execution allowed: "
            f"{plan.get('automatic_execution_allowed', False)}"
        )
        return

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
  scan <target> --profile authenticated
  scan <target> --profile intrusive
  scan <target> --mode observe
  scan <target> --mode plan
  scan <target> --mode verify (--lab | --dedicated-lab) --context <controlled-context.json>
      [--verification-input <secret-free-evidence-context.json>]
      Run the security workflow against an authorized in-scope target.
      Observe is the default. Verify still requires approved policy and
      explicit controlled context.

  hypotheses | hypothesis explain <id>
  verification plan <id>
  verification run <id> --policy <file> --context <file> --input <file>
      [--lab | --dedicated-lab]
      Inspect and run policy-gated Phase 2 verification plans.

  benchmark export <path>
      Export the latest normalized run without benchmark ground truth.

  list tools
      Display registered tools, prerequisites, traffic, and profiles.

  explain <tool> | explain latest | explain scan | explain profiles
      Explain deterministic capabilities, evidence, limitations, or the latest scan.

  jwt analyze [token] | jwt analyze --file <path>
  jwt compare <file-a> <file-b> | jwt plan <file>
  jwt replay <request-file> | jwt explain
      Use the offline-first JWT workflow. Replay remains disabled unless explicitly enabled.

  graphql analyze <file> | graphql schema <file> | graphql explain
      Analyze GraphQL evidence offline or explain the safe GraphQL suite.

  workflow analyze <file> | workflow model <file>
  workflow compare <file-a> <file-b> | workflow plan <file>
  workflow replay <file> | workflow explain
      Analyze sanitized business workflows offline. Replay is disabled by default.

  upload analyze <file> | upload plan <file>
  upload replay <file> | upload explain
      Analyze upload evidence offline. Replay is disabled by default.

  agent plan --capture <file> --policy <file> [--context <file>]
      Import sanitized capture metadata and create policy-gated typed hypotheses.

  agent surface
      Show the persistent sanitized attack-surface graph summary.

  eval run [dataset]
      Run the offline evaluation laboratory and safety metrics.

  doctor [--quick]
      Check local release readiness without running a live target scan.

  help
      Display this help message.

  exit
      Exit CyberCortex AI.

Offline analysis is the default. Replay features are disabled by default.
Authenticated testing requires explicit controlled input. Scope and program
rules always apply. No engine automatically proves a vulnerability.

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

    if lowered == "hypotheses":
        try:
            run = _latest_phase2_state()
            if run is None:
                return {"success": False, "error": NO_PHASE2_STATE_MESSAGE}
            return {
                "success": True,
                "run_id": run.get("run_id"),
                "hypotheses": [
                    _hypothesis_list_item(item)
                    for item in run.get("hypotheses", [])
                    if isinstance(item, dict)
                ],
            }
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("hypothesis explain "):
        identifier = cleaned[len("hypothesis explain ") :].strip()
        try:
            run = _latest_phase2_state()
            if run is None:
                return {"success": False, "error": NO_PHASE2_STATE_MESSAGE}
            item = next(
                (
                    item
                    for item in run.get("hypotheses", [])
                    if isinstance(item, dict)
                    and item.get("hypothesis_id") == identifier
                ),
                None,
            )
            if item is None:
                return {
                    "success": False,
                    "error": f"Hypothesis not found: {identifier}.",
                }
            return {"success": True, "hypothesis": _hypothesis_explanation(item)}
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("verification plan "):
        identifier = cleaned[len("verification plan ") :].strip()
        try:
            run = _latest_phase2_state()
            if run is None:
                return {"success": False, "error": NO_PHASE2_STATE_MESSAGE}
            hypothesis_exists = any(
                isinstance(item, dict) and item.get("hypothesis_id") == identifier
                for item in run.get("hypotheses", [])
            )
            if not hypothesis_exists:
                return {
                    "success": False,
                    "error": f"Hypothesis not found: {identifier}.",
                }
            item = next(
                (
                    item
                    for item in run.get("verification_plans", [])
                    if isinstance(item, dict)
                    and item.get("hypothesis_id") == identifier
                ),
                None,
            )
            if item is None:
                return {
                    "success": False,
                    "error": f"No verification plan exists for hypothesis: {identifier}.",
                }
            return {
                "success": True,
                "verification_plan": _verification_plan_view(item),
            }
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("verification run "):
        from phase2_cli import run_verification_command

        try:
            return run_verification_command(
                shlex.split(cleaned[len("verification run ") :])
            )
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("benchmark export "):
        from agent_core.benchmark_exporter import export_benchmark
        from agent_core.phase2_store import Phase2RunStore

        output = cleaned[len("benchmark export ") :].strip()
        try:
            run = Phase2RunStore().load()
            return {"success": True, "output": export_benchmark(run, output)}
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("explain "):
        return explain(cleaned[len("explain ") :], LATEST_SCAN_RESULT)

    if lowered == "agent surface":
        from agent_core.attack_surface import AttackSurfaceGraph

        return AttackSurfaceGraph().snapshot()

    if lowered.startswith("agent plan "):
        try:
            arguments = shlex.split(cleaned[len("agent plan ") :])
            options: dict[str, str] = {}
            index = 0
            while index < len(arguments):
                option = arguments[index]
                if option not in {
                    "--capture",
                    "--policy",
                    "--context",
                    "--format",
                    "--base-url",
                    "--output",
                }:
                    raise ValueError(f"Unsupported agent plan option: {option}")
                if index + 1 >= len(arguments):
                    raise ValueError(f"Missing value for {option}")
                options[option] = arguments[index + 1]
                index += 2
            if "--capture" not in options or "--policy" not in options:
                raise ValueError("agent plan requires --capture and --policy.")
            context = (
                _read_json_file(options["--context"], "capture context")
                if options.get("--context")
                else None
            )
            policy = load_policy(options["--policy"])
            plan = AdaptiveAssessmentOrchestrator().plan_capture_file(
                options["--capture"],
                policy,
                goal="Find evidence-supported vulnerabilities in the authorized capture surface.",
                capture_format=options.get("--format", "auto"),
                default_base_url=options.get("--base-url"),
                capture_context=context,
            )
            output = options.get("--output", "reports/adaptive/assessment-plan.json")
            write_assessment_plan(plan, output)
            return {
                "success": True,
                "run_id": plan.run_id,
                "hypothesis_count": len(plan.hypotheses),
                "allowed_plan_count": sum(
                    item.policy_decision == "allowed"
                    for item in plan.verification_plans
                ),
                "selected_tools": plan.selected_tools,
                "output": output,
            }
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered == "eval run" or lowered.startswith("eval run "):
        from evaluation.lab import EvaluationLab
        from evaluation.replay_app import evaluate_replay_case

        dataset = (
            cleaned[len("eval run") :].strip()
            or "evaluation/fixtures/authorization.jsonl"
        )
        try:
            lab = EvaluationLab.from_jsonl(dataset)
            return lab.run(evaluate_replay_case)
        except (OSError, ValueError, TypeError) as exc:
            return {"success": False, "error": str(exc)}

    if lowered == "doctor" or lowered == "doctor --quick":
        return doctor(quick=lowered.endswith("--quick"))

    if lowered == "jwt analyze" or lowered.startswith("jwt analyze "):
        argument = cleaned[len("jwt analyze") :].strip()
        if argument.startswith("--file "):
            try:
                token = _read_controlled_file(argument[7:].strip(), "JWT")
            except ValueError as exc:
                return {"success": False, "error": str(exc)}
        else:
            token = argument
        if not token:
            token = getpass.getpass("JWT (hidden): ").strip()
        return _jwt_analysis(token)

    if lowered.startswith("jwt compare "):
        try:
            arguments = shlex.split(cleaned[len("jwt compare ") :])
            if len(arguments) < 2:
                raise ValueError("jwt compare requires at least two local files.")
            return compare_jwts(
                [_read_controlled_file(path, "JWT") for path in arguments]
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("jwt plan "):
        try:
            token = _read_controlled_file(cleaned[len("jwt plan ") :].strip(), "JWT")
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        decoded = jwt_decoder(token)
        return plan_jwt_verification(decoded) if decoded.get("success") else decoded

    if lowered.startswith("jwt replay "):
        import json

        try:
            request_data = json.loads(
                _read_controlled_file(
                    cleaned[len("jwt replay ") :].strip(), "JWT request"
                )
            )
        except (ValueError, json.JSONDecodeError) as exc:
            return {"success": False, "error": f"Invalid JWT request file: {exc}"}
        return check_jwt_replay(request_data, authenticated_profile=True)

    if lowered in {"jwt explain", "explain jwt"}:
        names = (
            "jwt_discovery",
            "jwt_decoder",
            "jwt_claims_analyzer",
            "jwt_comparison_analyzer",
            "jwt_verification_planner",
            "jwt_replay_checker",
        )
        return "\n\n".join(explain(name) for name in names)

    if lowered.startswith("graphql analyze "):
        path = Path(cleaned[len("graphql analyze ") :].strip())
        try:
            return analyze_graphql_query(path.read_text(encoding="utf-8"))
        except OSError as exc:
            return {
                "success": False,
                "error": f"Unable to read GraphQL query file: {exc}",
            }

    if lowered.startswith("graphql schema "):
        import json

        path = Path(cleaned[len("graphql schema ") :].strip())
        try:
            return analyze_graphql_schema(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            return {
                "success": False,
                "error": f"Unable to read GraphQL schema file: {exc}",
            }

    if lowered == "graphql explain":
        names = (
            "graphql_endpoint_discovery",
            "graphql_query_analyzer",
            "graphql_schema_analyzer",
            "graphql_introspection_checker",
            "graphql_authz_planner",
        )
        return "\n\n".join(explain(name) for name in names)

    if lowered.startswith("workflow analyze "):
        try:
            data = _read_json_file(
                cleaned[len("workflow analyze ") :].strip(), "workflow"
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        discovery = discover_workflow_evidence(data)
        model = build_workflow_model(data)
        if not model.get("success"):
            return {"success": True, "discovery": discovery, "model": model}
        return {
            "success": True,
            "discovery": discovery,
            "model": model,
            "transition_analysis": analyze_workflow_transitions(model),
            "business_rule_analysis": analyze_business_rules(model),
        }

    if lowered.startswith("workflow model "):
        try:
            return build_workflow_model(
                _read_json_file(cleaned[len("workflow model ") :].strip(), "workflow")
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("workflow compare "):
        try:
            paths = shlex.split(cleaned[len("workflow compare ") :])
            if len(paths) != 2:
                raise ValueError("workflow compare requires exactly two local files.")
            return compare_workflows(
                _read_json_file(paths[0], "left workflow"),
                _read_json_file(paths[1], "right workflow"),
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

    if lowered.startswith("workflow plan "):
        try:
            data = _read_json_file(cleaned[len("workflow plan ") :].strip(), "workflow")
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        return plan_business_logic_tests(build_workflow_model(data))

    if lowered.startswith("workflow replay "):
        try:
            data = _read_json_file(
                cleaned[len("workflow replay ") :].strip(), "workflow replay"
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        return check_workflow_replay(data, authenticated_profile=True)

    if lowered in {"workflow explain", "explain workflow"}:
        names = (
            "workflow_evidence_discovery",
            "workflow_model_builder",
            "workflow_transition_analyzer",
            "business_rule_analyzer",
            "business_logic_test_planner",
            "workflow_replay_checker",
        )
        return "\n\n".join(explain(name) for name in names)

    if lowered.startswith("upload analyze "):
        try:
            data = _read_json_file(
                cleaned[len("upload analyze ") :].strip(), "upload evidence"
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        return {
            "success": True,
            "discovery": discover_upload_surface(data),
            "validation": analyze_upload_validation(data),
            "metadata": analyze_upload_metadata(data),
            "storage": analyze_upload_storage(data),
            "automatic_execution": False,
        }

    if lowered.startswith("upload plan "):
        try:
            data = _read_json_file(
                cleaned[len("upload plan ") :].strip(), "upload evidence"
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        return plan_upload_security(discover_upload_surface(data))

    if lowered.startswith("upload replay "):
        try:
            data = _read_json_file(
                cleaned[len("upload replay ") :].strip(), "upload replay"
            )
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        return check_upload_replay(data, authenticated_profile=True)

    if lowered in {"upload explain", "explain upload"}:
        names = (
            "upload_discovery",
            "upload_validation_analyzer",
            "upload_metadata_analyzer",
            "upload_storage_analyzer",
            "upload_security_planner",
            "upload_replay_checker",
        )
        return "\n\n".join(explain(name) for name in names)

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
            print(f"\nUnexpected error: {sanitize_text(str(exc))}\n")


if __name__ == "__main__":
    main()
