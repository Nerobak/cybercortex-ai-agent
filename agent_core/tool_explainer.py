"""Deterministic, secret-safe operational explanations."""

from __future__ import annotations

import difflib
from typing import Any

from tool_registry import TOOLS, resolve_tool


def _lines(title: str, values: Any) -> list[str]:
    items = values if isinstance(values, list) else [values]
    return [f"{title}:", *(f"- {item}" for item in items), ""]


def explain_tool(name: str) -> str:
    key = name.strip().lower()
    info = TOOLS.get(key)
    if not info:
        suggestions = difflib.get_close_matches(key, TOOLS, n=3, cutoff=0.35)
        suffix = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
        return f"Unknown tool: {key or '(empty)'}.{suffix} Use `list tools` to see registered names."
    text = [
        f"Tool: {key}",
        f"Status: {'registered' if resolve_tool(key) else 'unavailable'}",
        f"Category: {info['category']}",
        f"Traffic: {'network' if info['sends_network_traffic'] else 'offline'}",
        f"Profiles: {', '.join(info['profiles'])}",
        f"Prerequisites: {', '.join(info['prerequisites']) or 'none'}",
        "",
    ]
    sections = (
        ("Purpose", info["purpose"]),
        ("Expected input", info["expected_input"]),
        ("Evidence collected", info["evidence_collected"]),
        ("Does not prove", info["limitations"]),
        ("Common false positives", info["common_false_positives"]),
        ("Manual verification", info["manual_verification"]),
        ("Bug bounty relevance", info["bug_bounty_relevance"]),
        ("Example command or workflow", info["example_usage"]),
        ("Safety notes", info["safety_notes"]),
    )
    for title, value in sections:
        text.extend(_lines(title, value))
    return "\n".join(text).rstrip()


def explain_profiles() -> str:
    return "\n".join(
        [
            "Profile | Traffic and depth | Controlled input | Intended use",
            "baseline | low-impact automatic checks | not required | quick authorized surface assessment",
            "deep | broader bounded discovery | not required | deeper evidence collection and planning",
            "authenticated | deep plus supplied context | explicit credentials/requests required | controlled auth and authorization workflows",
            "",
            "Authenticated tools remain skipped unless explicit controlled input is supplied.",
        ]
    )


def explain_scan() -> str:
    return """Scan profiles

Baseline runs low-impact scope validation, DNS/HTTP checks, header and technology observations, bounded discovery, offline analyzers, approved scanning, and reporting where available.

Deep allows broader bounded discovery and produces evidence-driven manual test plans. Authenticated adds only tools for which the researcher explicitly supplies controlled credentials, tokens, or requests.

Tools are skipped when prerequisites produced no usable evidence, an optional binary is unavailable, the selected profile excludes them, or required controlled input was not supplied. A baseline scan does not automatically test IDOR, JWT acceptance, GraphQL authorization, business logic, or file uploads. Scope and program rules always apply."""


def explain_latest(result: dict[str, Any] | None) -> str:
    if not result:
        return "No previous scan is available in this session. Run `scan <authorized-target>` first."
    evidence = result.get("evidence_package") or {}
    assessment = evidence.get("assessment") or {}
    execution = evidence.get("execution_summary") or {}
    coverage = result.get("coverage") or evidence.get("coverage") or {}
    report = ((result.get("results") or {}).get("ai_report_writer") or {}).get(
        "output"
    ) or {}
    surface = evidence.get("observed_surface") or {}
    graphql = surface.get("graphql") or {}
    jwt = surface.get("jwt") or {}
    business = surface.get("business_logic") or {}
    upload = surface.get("upload") or {}
    partial = list(execution.get("timed_out_partial", [])) + list(
        execution.get("timed_out", [])
    )
    limitations = []
    if partial or execution.get("failed"):
        limitations.append("Failed or timed-out tools reduced coverage.")
    if assessment.get("profile") != "authenticated":
        limitations.append("Authenticated and business-logic behavior was not tested.")
    if execution.get("skipped"):
        limitations.append(
            "Some tools were skipped because inputs, prerequisites, or optional capabilities were unavailable."
        )

    def names(key: str) -> str:
        return ", ".join(execution.get(key, [])) or "none"

    completed = list(execution.get("completed", [])) + list(
        execution.get("completed_with_fallback", [])
    )

    def summary(label: str, relevant: bool, facts: list[str]) -> str:
        return (
            f"{label} summary: " + "; ".join(facts)
            if relevant
            else f"{label} summary: Not Applicable"
        )

    return "\n".join(
        [
            "Most recent scan",
            f"Target: {assessment.get('requested_target') or result.get('target', 'unknown')}",
            f"Profile: {assessment.get('profile', 'unknown')}",
            f"Assessment status: {result.get('assessment_status') or evidence.get('assessment_status', 'unknown')}",
            f"Coverage: {coverage.get('coverage_percentage', 0)}%",
            f"Completed tools: {', '.join(completed) or 'none'}",
            f"Partial/timed-out tools: {', '.join(partial) or 'none'}",
            f"Failed tools: {names('failed')}",
            (
                "Skipped tools: "
                + ", ".join(
                    list(execution.get("skipped", []))
                    + list(execution.get("not_applicable", []))
                )
                if execution.get("skipped") or execution.get("not_applicable")
                else "Skipped tools: none"
            ),
            f"Observations: {len(evidence.get('observations', []))}",
            f"Candidates: {len(evidence.get('candidate_findings', []))}",
            f"Verified findings: {len(evidence.get('verified_findings', []))}",
            summary(
                "GraphQL",
                bool(
                    graphql.get("endpoints_observed")
                    or graphql.get("operations_observed")
                ),
                [
                    f"endpoints observed {graphql.get('endpoints_observed', 0)}",
                    f"confirmed {graphql.get('confirmed_endpoints', 0)}",
                    f"introspection {graphql.get('introspection_status', 'not tested')}",
                    f"authorization plans {graphql.get('manual_authorization_plans', 0)}",
                ],
            ),
            summary(
                "JWT",
                bool(jwt.get("tokens_observed")),
                [
                    f"tokens observed {jwt.get('tokens_observed', 0)}",
                    f"controlled comparisons {jwt.get('comparison_count', 0)}",
                    f"verification plans {jwt.get('manual_plans', 0)}",
                    f"replay {jwt.get('replay_status', 'not applicable')}",
                ],
            ),
            summary(
                "Business logic",
                bool(business.get("workflow_candidates")),
                [
                    f"workflow candidates {business.get('workflow_candidates', 0)}",
                    f"modeled {business.get('modeled_workflows', 0)}",
                    f"manual plans {business.get('manual_plans', 0)}",
                    f"replay {business.get('replay_status', 'not applicable')}",
                ],
            ),
            summary(
                "File upload",
                bool(upload.get("surface_observed")),
                [
                    f"upload candidates {upload.get('observations', 0)}",
                    f"manual plans {upload.get('manual_plans', 0)}",
                    f"replay {upload.get('replay_status', 'not applicable')}",
                ],
            ),
            f"Report mode: {report.get('report_mode', 'not available')}",
            f"Report path: {report.get('report_file') or report.get('report', 'not available')}",
            f"Evidence path: {report.get('evidence_file') or report.get('evidence', 'not available')}",
            "Most important limitations: "
            + (
                " ".join(limitations)
                or "No material execution limitation was recorded."
            ),
        ]
    )


def explain(topic: str, latest: dict[str, Any] | None = None) -> str:
    key = topic.strip().lower()
    if key == "latest":
        return explain_latest(latest)
    if key == "scan":
        return explain_scan()
    if key == "profiles":
        return explain_profiles()
    return explain_tool(key)
