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

    return "\n".join(
        [
            "Most recent scan",
            f"Target: {assessment.get('requested_target') or result.get('target', 'unknown')}",
            f"Profile: {assessment.get('profile', 'unknown')}",
            f"Assessment status: {result.get('assessment_status') or evidence.get('assessment_status', 'unknown')}",
            f"Coverage: {coverage.get('coverage_percentage', 0)}%",
            f"Completed tools: {names('completed')}",
            f"Partial/timed-out tools: {', '.join(partial) or 'none'}",
            f"Failed tools: {names('failed')}",
            f"Skipped tools: {names('skipped')}",
            f"Observations: {len(evidence.get('observations', []))}",
            f"Candidates: {len(evidence.get('candidate_findings', []))}",
            f"Verified findings: {len(evidence.get('verified_findings', []))}",
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
