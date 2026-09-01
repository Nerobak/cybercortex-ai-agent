"""Deterministic Phase 2 report sections; hypotheses never become findings."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_core.result_normalizer import public_result
from agent_core.verification_capabilities import (
    CapabilityState,
    get_verification_capability,
)


def _plan_actions(category: str) -> list[str]:
    try:
        capability = get_verification_capability(category)
    except ValueError:
        capability = None
    if (
        capability is None
        or capability.capability_state is not CapabilityState.typed_verification
    ):
        return [
            "use the bounded manual guidance only; a typed execution adapter is required before network verification"
        ]
    if category in {"bola", "tenant_isolation"}:
        return [
            "authenticate controlled Account A",
            "identify an Account-A-owned test object",
            "authenticate distinct controlled Account B",
            "request the same test object as Account B",
            "compare protected object identity and selected safe data",
        ]
    if category == "vertical_authorization":
        return [
            "authenticate a controlled administrative account",
            "record the protected administrative response shape",
            "authenticate a controlled lower-privileged account",
            "request the same route and compare protected behavior",
        ]
    if category == "mass_assignment":
        return [
            "authenticate a controlled account",
            "record the exact before-state of the test-owned resource",
            "submit one documented privilege-sensitive field",
            "read the resource independently and compare state",
            "restore and confirm the original state",
        ]
    if category == "session_invalidation":
        return [
            "acquire one controlled session through the configured session-creation surface",
            "confirm the authenticated baseline on the correlated protected resource",
            "perform the configured controlled session-termination operation",
            "replay the same previously issued session against the same protected resource",
            "classify whether the old session remains usable",
        ]
    if category == "recovery_state_enforcement":
        return [
            "initiate recovery only for the controlled recovery account",
            "preserve the runtime-issued challenge and pause before any completion",
            "resume with the legitimate controlled-channel code and approved temporary password",
            "reuse that same runtime-issued challenge and code exactly once with the separately approved comparison password",
            "confirm an accepted comparison through normal controlled authentication",
            "require external cleanup when no safe in-band restoration surface exists, then resume to verify the original credential",
            "do not guess codes or tokens and do not enumerate accounts",
        ]
    if category == "rate_limit_enforcement":
        return [
            "require the dedicated bounded rate-limit policy opt-in and configured maximum",
            "establish one valid login for exactly one controlled synthetic account",
            "send only N sequential invalid-password attempts for that same account",
            "send one final valid login with the original vaulted credential",
            "use no brute force, spraying, concurrency, recovery execution, or hidden retries",
        ]
    return ["collect the minimum bounded evidence described by the typed plan"]


def render_phase2_report(run: dict[str, Any]) -> str:
    run = public_result(run)
    surface = run.get("attack_surface") or {}
    auth_boundaries = [
        item for item in surface.get("auth_boundaries") or [] if isinstance(item, dict)
    ]
    auth_workflows = [
        item
        for item in surface.get("workflows") or []
        if isinstance(item, dict) and item.get("semantic_domain") == "authentication"
    ]
    boundary_types = Counter(
        str(item.get("boundary_type") or "authenticated_resource")
        for item in auth_boundaries
    )
    workflow_types = Counter(
        str(item.get("workflow_type") or "authentication") for item in auth_workflows
    )
    hypotheses = run.get("hypotheses") or []
    plans = run.get("verification_plans") or []
    results = run.get("verification_results") or []
    metrics = run.get("metrics") or {}
    lines = [
        "## Attack Surface",
        "",
        f"- Assessment mode: {run.get('assessment_mode') or run.get('mode') or 'observe'}",
        f"- Routes: {len(surface.get('routes') or [])}",
        f"- Parameters: {len(surface.get('parameters') or [])}",
        f"- Object references: {len(surface.get('objects') or [])}",
        f"- Authentication boundaries: {len(auth_boundaries)}",
        "- Authentication boundary types: "
        + (
            ", ".join(
                f"{name}={count}" for name, count in sorted(boundary_types.items())
            )
            if boundary_types
            else "none"
        ),
        f"- Authentication workflow candidates: {len(auth_workflows)}",
        "- Authentication workflow types: "
        + (
            ", ".join(
                f"{name}={count}" for name, count in sorted(workflow_types.items())
            )
            if workflow_types
            else "none"
        ),
        f"- Captured requests: {len(surface.get('captured_requests') or [])}",
        f"- Whole-run network requests: {int(metrics.get('total_requests', metrics.get('request_count', 0)) or 0)}",
        "",
    ]
    if auth_boundaries or auth_workflows:
        lines.extend(["Authentication semantic observations:", ""])
        for boundary in auth_boundaries[:50]:
            sources = boundary.get("evidence_sources") or [
                boundary.get("source") or "normalized route evidence"
            ]
            lines.append(
                "- "
                + f"{boundary.get('method', 'GET')} {boundary.get('path', '/')}"
                + f" — {boundary.get('boundary_type', 'authenticated_resource')}"
                + f"; confidence={boundary.get('confidence', 'medium')}"
                + f"; evidence source={', '.join(str(item) for item in sources)}"
            )
        if len(auth_boundaries) > 50:
            lines.append(
                f"- {len(auth_boundaries) - 50} additional authentication boundaries omitted from this concise view."
            )
        for workflow in auth_workflows[:20]:
            steps = [
                f"{item.get('method', 'GET')} {item.get('path', '/')}"
                for item in workflow.get("steps", [])
                if isinstance(item, dict)
            ]
            lines.append(
                "- Workflow candidate "
                + f"{workflow.get('workflow_type', workflow.get('name', 'authentication'))}"
                + f"; confidence={workflow.get('confidence', 'medium')}"
                + f"; steps={' -> '.join(steps) if steps else 'not modeled'}"
            )
        auth_limitations = list(
            dict.fromkeys(
                str(item)
                for observation in [*auth_boundaries, *auth_workflows]
                for item in observation.get("limitations", []) or []
                if item
            )
        )
        for limitation in auth_limitations[:10]:
            lines.append(f"- Limitation: {limitation}")
        lines.append("")
    limitations = surface.get("limitations") or []
    if limitations:
        lines.extend(["Limitations:", *[f"- {item}" for item in limitations], ""])
    lines.extend(["## Security Hypotheses", ""])
    if not hypotheses:
        lines.extend(["No evidence-supported hypotheses were generated.", ""])
    for hypothesis in hypotheses:
        evidence = hypothesis.get("evidence_basis") or []
        metadata = hypothesis.get("metadata") or {}
        related_surfaces = [
            item
            for item in metadata.get("related_surfaces") or []
            if isinstance(item, dict)
        ]
        related_labels = [
            " ".join(
                str(value)
                for value in (
                    item.get("boundary_type"),
                    item.get("method"),
                    item.get("path"),
                )
                if value
            )
            for item in related_surfaces
        ]
        evidence_labels = [
            (
                str(
                    item.get("observation") or item.get("source") or "observed evidence"
                )
                if isinstance(item, dict)
                else str(item)
            )
            for item in evidence
            if item
        ]
        required_context = [
            str(item) for item in hypothesis.get("required_context") or [] if item
        ]
        hypothesis_limitations = [
            str(item) for item in hypothesis.get("limitations") or [] if item
        ]
        try:
            capability = get_verification_capability(
                str(hypothesis.get("category") or "")
            )
        except ValueError:
            capability = None
        capability_label = (
            "TYPED VERIFICATION AVAILABLE"
            if capability is not None
            and capability.capability_state is CapabilityState.typed_verification
            else (
                "PLAN-ONLY"
                if capability is not None
                and capability.capability_state is CapabilityState.plan_only
                else "DISCOVERED"
            )
        )
        automatic_label = str(
            bool(capability is not None and capability.automatic_execution)
        ).lower()
        lines.extend(
            [
                f"### {hypothesis.get('title', 'Untitled hypothesis')}",
                "",
                f"- Category: {hypothesis.get('category', 'unknown')}",
                "- Discovery status: DISCOVERED",
                f"- Capability: {capability_label}",
                "- Typed executor available: "
                + str(bool(capability and capability.executor_available)).lower(),
                "- Executor version: "
                + str(
                    capability.executor_version
                    if capability and capability.executor_version
                    else "none"
                ),
                "- Executable request cost: "
                + (
                    f"{capability.min_requests}–{capability.worst_case_requests}"
                    if capability
                    else "unknown"
                ),
                f"- Confidence: {hypothesis.get('confidence', 'low')}",
                f"- Status: {hypothesis.get('status', 'proposed')}",
                f"- Evidence: {len(evidence)} observation(s)",
                "- Related authentication surfaces: "
                + (" -> ".join(related_labels) if related_labels else "none"),
                "- Evidence basis:",
                *[f"  - {item}" for item in evidence_labels[:20]],
                "- Required context:",
                *[
                    f"  - {item}"
                    for item in required_context
                    or ["no additional controlled context recorded"]
                ],
                "- Safe verification possible: "
                + str(bool(hypothesis.get("safe_verification_possible"))).lower(),
                f"- Automatic execution: {automatic_label}",
                "- Adapter status: "
                + str(metadata.get("execution_status") or capability_label.casefold()),
                "- Limitations:",
                *[
                    f"  - {item}"
                    for item in hypothesis_limitations
                    or ["runtime behavior has not been verified"]
                ],
                "- Classification: hypothesis only; runtime vulnerability behavior is not inferred.",
                "",
            ]
        )
    lines.extend(["## Planned Verification", ""])
    if not plans:
        lines.extend(["No verification plans were generated in this mode.", ""])
    hypotheses_by_id = {
        item.get("hypothesis_id"): item for item in hypotheses if isinstance(item, dict)
    }
    for plan in plans:
        hypothesis_id = plan.get("hypothesis_id", "unknown")
        hypothesis = hypotheses_by_id.get(hypothesis_id, {})
        recovery_accounting = (
            ((plan.get("steps") or [{}])[0].get("metadata") or {}).get(
                "request_accounting"
            )
            if hypothesis.get("category") == "recovery_state_enforcement"
            else None
        )
        plan_metadata = (plan.get("steps") or [{}])[0].get("metadata") or {}
        try:
            capability = get_verification_capability(
                str(hypothesis.get("category") or "")
            )
        except ValueError:
            capability = None
        capability_label = (
            "TYPED VERIFICATION AVAILABLE"
            if capability is not None
            and capability.capability_state is CapabilityState.typed_verification
            else (
                "PLAN-ONLY"
                if capability is not None
                and capability.capability_state is CapabilityState.plan_only
                else "DISCOVERED"
            )
        )
        lines.extend(
            [
                f"### {hypothesis_id}",
                "",
                f"- Category: {hypothesis.get('category', 'unknown')}",
                f"- Capability: {capability_label}",
                "- Typed executor available: "
                + str(bool(capability and capability.executor_available)).lower(),
                "- Executor version: "
                + str(
                    capability.executor_version
                    if capability and capability.executor_version
                    else "none"
                ),
                "- Executable request cost: "
                + (
                    f"{capability.min_requests}–{plan.get('worst_case_requests', capability.worst_case_requests)}"
                    if capability
                    else "unknown"
                ),
                f"- Priority: {(hypothesis.get('metadata') or {}).get('priority', 'not ranked')}",
                f"- Status: {hypothesis.get('status', 'proposed')}",
                f"- Objective: {plan.get('objective', 'Collect bounded controlled evidence.')}",
                "- Requires:",
                *[
                    f"  - {item}"
                    for item in plan.get("prerequisites")
                    or ["explicit controlled verification context"]
                ],
                "- Plan:",
                *[
                    f"  - {item}"
                    for item in _plan_actions(hypothesis.get("category", ""))
                ],
                "- Expected secure behavior: "
                + "; ".join(plan.get("expected_secure_behavior") or ["not specified"]),
                "- Automatic execution: "
                + str(bool(plan.get("automatic_execution_allowed"))).lower(),
                "- Adapter status: "
                + str(
                    plan_metadata.get("execution_status") or capability_label.casefold()
                ),
                f"- Policy preflight: {plan.get('policy_decision', 'pending')}",
                *(
                    [
                        "- Bounded rate-limit policy required: true",
                        "- Dedicated policy opt-in: "
                        + str(bool(plan_metadata.get("policy_opt_in"))).lower(),
                        "- Configured maximum attempts: "
                        + str(
                            plan_metadata.get("configured_max_attempts")
                            if plan_metadata.get("configured_max_attempts") is not None
                            else "not supplied"
                        ),
                        "- Hard implementation attempt cap: "
                        + str(plan_metadata.get("hard_attempt_cap", 5)),
                        "- Brute force: false",
                        "- Spraying: false",
                        "- Concurrency: 1 (sequential only)",
                        "- Automatic execution requires typed policy opt-in: true",
                    ]
                    if hypothesis.get("category") == "rate_limit_enforcement"
                    else []
                ),
                *(
                    [
                        "- Recovery request accounting:",
                        "  - Challenge issuance recovery requests: "
                        + str(
                            recovery_accounting.get(
                                "challenge_issuance_recovery_requests", 0
                            )
                        ),
                        "  - Resume recovery completion requests: "
                        + str(
                            recovery_accounting.get(
                                "resume_recovery_completion_requests", 0
                            )
                        ),
                        "  - Resume authentication/state-confirmation requests: "
                        + str(
                            recovery_accounting.get(
                                "resume_authentication_state_confirmation_requests",
                                0,
                            )
                        ),
                        "  - External cleanup verification requests: "
                        + str(
                            recovery_accounting.get(
                                "external_cleanup_verification_requests", 0
                            )
                        ),
                        "  - External cleanup may be required: "
                        + str(
                            bool(
                                recovery_accounting.get(
                                    "external_cleanup_may_be_required"
                                )
                            )
                        ).lower(),
                    ]
                    if isinstance(recovery_accounting, dict)
                    else []
                ),
                "",
            ]
        )
    lines.extend(["## Verification Results", ""])
    if not results:
        lines.extend(["No verification plan was executed.", ""])
    for result in results:
        acquisition = result.get("owned_object_acquisition") or {}
        runtime_binding = result.get("runtime_binding") or {}
        baseline = result.get("baseline") or {}
        replay = result.get("replay") or {}
        rate_baseline = result.get("baseline_summary") or {}
        rate_final = result.get("final_valid_login_summary") or {}
        rate_counts = result.get("request_counts") or {}
        request_delta = result.get("request_delta") or {}
        executor = result.get("executor") or {}
        result_hash = str(result.get("result_hash") or "")
        provenance_lines = (
            [
                "- Immutable provenance:",
                f"  - Run ID: {run.get('run_id', 'unknown')}",
                f"  - Result ID: {result.get('result_id', 'legacy/unversioned')}",
                "  - Result hash: "
                + (result_hash[:23] if result_hash else "legacy/unversioned"),
                "  - Executor: "
                + str(executor.get("name") or "legacy/unversioned")
                + " "
                + str(executor.get("version") or ""),
            ]
            if result.get("result_id") and result_hash
            else ["- Immutable provenance: legacy/unversioned"]
        )
        lines.extend(
            [
                f"### {result.get('hypothesis_id', 'unknown')}",
                "",
                f"- Objective: classify {result.get('category', 'unknown')} with controlled evidence",
                "- Controlled context: explicit references only; no credentials are reported",
                f"- Evidence collected: {'; '.join(result.get('evidence_summary') or ['insufficient evidence'])}",
                "- Secure expectation: authorization boundary is enforced without protected-data disclosure",
                f"- Observed behavior: {result.get('status', 'inconclusive')}",
                f"- Result: {result.get('status', 'inconclusive')}",
                *provenance_lines,
                "- Result request cost:",
                "  - Discovery: " + str(int(request_delta.get("discovery") or 0)),
                "  - Authentication: " + str(int(request_delta.get("auth") or 0)),
                "  - Verification: " + str(int(request_delta.get("verification") or 0)),
                "  - Cleanup: " + str(int(request_delta.get("cleanup") or 0)),
                "  - Attempted/total: "
                + str(int(request_delta.get("attempted") or 0))
                + "/"
                + str(int(request_delta.get("total") or 0)),
                "- Runtime binding:",
                "  - Required accounts: "
                + str(int(runtime_binding.get("required_accounts") or 0)),
                "  - Bound accounts: "
                + str(int(runtime_binding.get("bound_accounts") or 0)),
                "  - Owner bound: "
                + str(bool(runtime_binding.get("owner_bound"))).lower(),
                "  - Comparator bound: "
                + str(bool(runtime_binding.get("comparator_bound"))).lower(),
                "  - Policy authorized: "
                + str(bool(runtime_binding.get("policy_authorized"))).lower(),
                *(
                    [
                        "- Session invalidation evidence:",
                        "  - Baseline status: "
                        + str(baseline.get("status_code", "not established")),
                        "  - Replay status: "
                        + str(replay.get("status_code", "not performed")),
                        "  - Protected field paths: "
                        + ", ".join(result.get("protected_field_paths") or []),
                        "  - Protected evidence matched: "
                        + str(bool(result.get("protected_evidence_matched"))).lower(),
                        "  - Same session replayed: "
                        + str(bool(result.get("same_session_replayed"))).lower(),
                        "  - Termination attempted: "
                        + str(bool(result.get("termination_attempted"))).lower(),
                        "  - Termination succeeded: "
                        + str(bool(result.get("termination_succeeded"))).lower(),
                        "  - Cleanup verified: "
                        + str(bool(result.get("cleanup_verified"))).lower(),
                    ]
                    if result.get("category") == "session_invalidation"
                    else []
                ),
                *(
                    [
                        "- Bounded login rate-limit evidence:",
                        "  - Mode: "
                        + str(result.get("mode") or "authentication_login_rate_limit"),
                        "  - Attempts requested: "
                        + str(int(result.get("attempts_requested") or 0)),
                        "  - Attempts sent: "
                        + str(int(result.get("attempts_sent") or 0)),
                        "  - Baseline status class: "
                        + str(rate_baseline.get("status_class") or "not established"),
                        "  - Final valid-login status class: "
                        + str(rate_final.get("status_class") or "not performed"),
                        "  - Throttle signal observed: "
                        + str(bool(result.get("throttle_signal_observed"))).lower(),
                        "  - Retry-After observed: "
                        + str(bool(result.get("retry_after_observed"))).lower(),
                        "  - Lockout signal observed: "
                        + str(bool(result.get("lockout_signal_observed"))).lower(),
                        "  - Expected control satisfied: "
                        + (
                            "inconclusive"
                            if result.get("expected_control_satisfied") is None
                            else str(
                                bool(result.get("expected_control_satisfied"))
                            ).lower()
                        ),
                        "  - Total network requests: "
                        + str(int(rate_counts.get("total_network_requests") or 0)),
                    ]
                    if result.get("category") == "rate_limit_enforcement"
                    else []
                ),
                *(
                    [
                        "- Recovery state-enforcement evidence:",
                        "  - Recovery phase: "
                        + str(result.get("recovery_phase") or "not started"),
                        "  - Comparison type: "
                        + str(result.get("comparison_type") or "not selected"),
                        "  - Challenge reference: "
                        + str(result.get("challenge_reference") or "not established"),
                        "  - Valid completion succeeded: "
                        + str(bool(result.get("valid_completion_succeeded"))).lower(),
                        "  - Comparison attempted: "
                        + str(bool(result.get("comparison_attempted"))).lower(),
                        "  - Comparison accepted: "
                        + str(bool(result.get("comparison_accepted"))).lower(),
                        "  - Independent state confirmed: "
                        + str(bool(result.get("independent_state_confirmed"))).lower(),
                        "  - Cleanup attempted internally: "
                        + str(bool(result.get("cleanup_attempted"))).lower(),
                        "  - Cleanup verified: "
                        + str(bool(result.get("cleanup_verified"))).lower(),
                        "  - Cleanup failed: "
                        + str(bool(result.get("cleanup_failed"))).lower(),
                        "  - External cleanup required: "
                        + str(bool(result.get("external_cleanup_required"))).lower(),
                        "  - Controlled evidence required: "
                        + str(bool(result.get("recovery_evidence_required"))).lower(),
                    ]
                    if result.get("category") == "recovery_state_enforcement"
                    else []
                ),
                "- Owned object acquisition:",
                f"  - Attempted: {str(bool(acquisition.get('attempted'))).lower()}",
                f"  - Succeeded: {str(bool(acquisition.get('succeeded'))).lower()}",
                f"  - Owner: {acquisition.get('owner') or 'not applicable'}",
                f"  - Object type: {acquisition.get('object_type') or 'not applicable'}",
                "  - Identifier present: "
                + str(bool(acquisition.get("identifier_present"))).lower(),
                "  - Evidence: "
                + (
                    "controlled test-owned evidence"
                    if acquisition.get("controlled_test_owned_evidence")
                    else "not established by acquisition"
                ),
                "",
            ]
        )
    lines.extend(["## Verified Findings", ""])
    verified = [item for item in results if item.get("status") == "verified"]
    if not verified:
        lines.append("No evidence-backed verified findings were recorded.")
    else:
        for item in verified:
            lines.append(
                f"- {item.get('category', 'unknown')}: {item.get('hypothesis_id', 'unknown')}"
            )
    return "\n".join(lines).rstrip() + "\n"
