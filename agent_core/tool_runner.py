"""Dependency-aware, failure-isolated scan execution."""

from __future__ import annotations

import concurrent.futures
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from agent_core.result_normalizer import (
    build_evidence_package,
    normalize_url_evidence,
    redact,
)
from tool_registry import TOOLS, resolve_tool, tools_for_profile
from config import AI_REPORT_TIMEOUT_SECONDS

DEFAULT_TOOL_TIMEOUT = 90
DEFAULT_ASSESSMENT_TIMEOUT = 600


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ToolRunner:
    def __init__(
        self,
        *,
        tool_timeout: int = DEFAULT_TOOL_TIMEOUT,
        assessment_timeout: int = DEFAULT_ASSESSMENT_TIMEOUT,
        max_network_tools: int = 3,
        status_callback: Callable[[str, dict[str, Any]], None] | None = None,
        phase_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.tool_timeout = tool_timeout
        self.assessment_timeout = assessment_timeout
        self.network_slots = threading.BoundedSemaphore(max_network_tools)
        self.status_callback = status_callback
        self.phase_callback = phase_callback

    def _phase(self, name: str) -> None:
        if self.phase_callback:
            self.phase_callback(name)

    def _notify(self, name: str, envelope: dict[str, Any]) -> None:
        if self.status_callback:
            self.status_callback(name, envelope)

    def _envelope(
        self,
        name: str,
        status: str,
        *,
        started: str | None = None,
        started_clock: float | None = None,
        output: Any = None,
        error: str | None = None,
        input_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        success = status in {"completed", "completed_with_fallback"} or (
            status == "timed_out_partial" and bool(output)
        )
        return {
            "tool": name,
            "status": status,
            "success": success,
            "started_at": started,
            "completed_at": _now(),
            "duration_ms": (
                round((time.monotonic() - started_clock) * 1000)
                if started_clock is not None
                else 0
            ),
            "input_summary": redact(input_summary or {}),
            "output": redact(output),
            "error": error,
            "prerequisites": TOOLS.get(name, {}).get("prerequisites", []),
            "evidence_files": [],
        }

    def _execute(
        self,
        name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        input_summary: dict[str, Any],
        timeout: int | None = None,
    ) -> dict[str, Any]:
        started, clock = _now(), time.monotonic()
        self._notify(name, {"tool": name, "status": "running", "started_at": started})
        try:
            function = resolve_tool(name)
        except Exception:
            function = None
        if function is None:
            envelope = self._envelope(
                name,
                "not_applicable",
                started=started,
                started_clock=clock,
                error="Tool module or callable is unavailable.",
                input_summary=input_summary,
            )
            self._notify(name, envelope)
            return envelope

        def invoke() -> Any:
            if TOOLS[name]["sends_network_traffic"]:
                with self.network_slots:
                    return function(*args, **kwargs)
            return function(*args, **kwargs)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(invoke)
        try:
            effective_timeout = timeout or self.tool_timeout
            output = future.result(timeout=effective_timeout)
            output_status = output.get("status") if isinstance(output, dict) else None
            if output_status == "timed_out_partial":
                status = "timed_out_partial"
            elif output_status == "timed_out":
                status = "timed_out"
            elif output_status == "completed_with_fallback":
                status = "completed_with_fallback"
            elif output_status in {"skipped", "not_applicable"}:
                status = output_status
            elif isinstance(output, dict) and not output.get("success", True):
                status = "failed"
            else:
                status = "completed"
            error = output.get("error") if isinstance(output, dict) else None
            envelope = self._envelope(
                name,
                status,
                started=started,
                started_clock=clock,
                output=output,
                error=error,
                input_summary=input_summary,
            )
        except concurrent.futures.TimeoutError:
            future.cancel()
            envelope = self._envelope(
                name,
                "timed_out",
                started=started,
                started_clock=clock,
                error=f"Tool exceeded {timeout or self.tool_timeout} second timeout.",
                input_summary=input_summary,
            )
        except Exception as exc:
            envelope = self._envelope(
                name,
                "failed",
                started=started,
                started_clock=clock,
                error=str(exc),
                input_summary=input_summary,
            )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        self._notify(name, envelope)
        return envelope

    def run(
        self, target: str, *, profile: str = "baseline", jwt_token: str | None = None
    ) -> dict[str, Any]:
        selected = set(tools_for_profile(profile))
        started_at, overall_clock = _now(), time.monotonic()
        results: dict[str, Any] = {}

        def expired() -> bool:
            return time.monotonic() - overall_clock >= self.assessment_timeout

        hostname = urlparse(target).hostname or ""
        independent = (
            "dns_lookup",
            "http_probe",
            "security_headers_checker",
            "tech_fingerprint",
        )
        for name in independent:
            if name in selected and not expired():
                args = (hostname,) if name == "dns_lookup" else (target,)
                results[name] = self._execute(
                    name,
                    args,
                    {},
                    {"target": hostname if name == "dns_lookup" else target},
                )

        if "katana_crawl" in selected and not expired():
            results["katana_crawl"] = self._execute(
                "katana_crawl", (target,), {}, {"target": target}
            )

        # When Katana produced no usable output, the bounded Python crawler is
        # an explicit fallback and its visited pages become shared URL evidence.
        crawl_output = results.get("katana_crawl", {}).get("output") or {}
        api_ran_as_fallback = False
        if (
            not crawl_output.get("urls")
            and "api_object_discovery" in selected
            and not expired()
        ):
            results["api_object_discovery"] = self._execute(
                "api_object_discovery",
                (target,),
                {"max_pages": 25, "allow_network_crawl": True},
                {"target": target, "fallback_for": "katana_crawl"},
            )
            api_ran_as_fallback = True
            api_output = results["api_object_discovery"].get("output") or {}
            fallback_urls = [
                page.get("url")
                for page in api_output.get("pages", [])
                if isinstance(page, dict) and page.get("url")
            ]
            if fallback_urls:
                crawl_output = {
                    **crawl_output,
                    "urls": fallback_urls,
                    "count": len(fallback_urls),
                    "fallback_used": "api_object_discovery",
                }
                results["katana_crawl"]["output"] = crawl_output

        self._phase("normalize_surface")
        surface = normalize_url_evidence(target, results)
        self._phase("dependent_analyzers")
        list_inputs = {
            "endpoint_analyzer": surface["all_urls"],
            "parameter_analyzer": surface["all_urls"],
            "misconfiguration_detector": surface["all_urls"],
            "js_secret_scanner": surface["javascript_urls"],
        }
        for name, urls in list_inputs.items():
            if name not in selected:
                continue
            if expired():
                results[name] = self._envelope(
                    name, "skipped", error="Overall assessment timeout reached."
                )
                continue
            if not urls:
                reason = (
                    "No authorized JavaScript URLs were discovered."
                    if name == "js_secret_scanner"
                    else "No authorized URLs were available from discovery."
                )
                results[name] = self._envelope(
                    name, "skipped", error=reason, input_summary={"url_count": 0}
                )
                self._notify(name, results[name])
                continue
            args = (urls,) if name == "parameter_analyzer" else (urls, hostname)
            results[name] = self._execute(name, args, {}, {"url_count": len(urls)})

        # GraphQL modules consume only scope-normalized or explicitly supplied
        # evidence. Optional stages are deterministically skipped when their
        # prerequisite evidence is absent.
        if "graphql_endpoint_discovery" in selected and not expired():
            graphql_evidence = {
                **surface,
                "requests": crawl_output.get("requests", []),
                "form_actions": crawl_output.get("form_actions", []),
                "fetch_urls": crawl_output.get("fetch_urls", []),
            }
            results["graphql_endpoint_discovery"] = self._execute(
                "graphql_endpoint_discovery",
                (graphql_evidence, target),
                {},
                {
                    "url_count": len(surface["all_urls"]),
                    "network_checks_enabled": False,
                },
            )
        discovery = results.get("graphql_endpoint_discovery", {}).get("output") or {}
        graphql_queries = crawl_output.get("graphql_queries", [])
        if "graphql_query_analyzer" in selected:
            if graphql_queries:
                # Analyze one bounded representative document in the automatic
                # workflow; direct CLI analysis can inspect individual files.
                results["graphql_query_analyzer"] = self._execute(
                    "graphql_query_analyzer",
                    (str(graphql_queries[0]),),
                    {},
                    {"query_evidence_count": len(graphql_queries)},
                )
            else:
                results["graphql_query_analyzer"] = self._envelope(
                    "graphql_query_analyzer",
                    "not_applicable",
                    error="No GraphQL query evidence was available.",
                )
                self._notify(
                    "graphql_query_analyzer", results["graphql_query_analyzer"]
                )
        schema_evidence = crawl_output.get("graphql_schema") or crawl_output.get(
            "introspection_json"
        )
        if "graphql_schema_analyzer" in selected:
            if isinstance(schema_evidence, dict):
                results["graphql_schema_analyzer"] = self._execute(
                    "graphql_schema_analyzer",
                    (schema_evidence,),
                    {},
                    {"schema_evidence": True},
                )
            else:
                results["graphql_schema_analyzer"] = self._envelope(
                    "graphql_schema_analyzer",
                    "not_applicable",
                    error="No already-obtained GraphQL schema evidence was available.",
                )
                self._notify(
                    "graphql_schema_analyzer", results["graphql_schema_analyzer"]
                )
        if "graphql_introspection_checker" in selected:
            endpoints = (
                discovery.get("confirmed_endpoints", [])
                or discovery.get("likely_endpoints", [])
                if isinstance(discovery, dict)
                else []
            )
            if endpoints:
                results["graphql_introspection_checker"] = self._execute(
                    "graphql_introspection_checker",
                    (endpoints[0],),
                    {},
                    {"endpoint": endpoints[0].get("url")},
                )
            else:
                results["graphql_introspection_checker"] = self._envelope(
                    "graphql_introspection_checker",
                    "not_applicable",
                    error="No confirmed or high-confidence GraphQL endpoint was available.",
                )
                self._notify(
                    "graphql_introspection_checker",
                    results["graphql_introspection_checker"],
                )
        if "graphql_authz_planner" in selected:
            results["graphql_authz_planner"] = self._envelope(
                "graphql_authz_planner",
                "not_applicable",
                error="Controlled accounts and sufficient GraphQL authorization evidence were not supplied.",
            )
            self._notify("graphql_authz_planner", results["graphql_authz_planner"])

        # Upload analysis consumes only existing normalized evidence. It never
        # sends a file during a normal workflow; replay is a separate opt-in.
        upload_evidence = {
            **surface,
            "requests": crawl_output.get("requests", []),
            "forms": crawl_output.get("forms", []),
            "form_actions": crawl_output.get("form_actions", []),
            "fetch_urls": crawl_output.get("fetch_urls", []),
            "javascript_strings": crawl_output.get("javascript_strings", []),
            "openapi": crawl_output.get("openapi", {}),
            "graphql_schema": (
                schema_evidence if isinstance(schema_evidence, dict) else {}
            ),
            "workflow_models": crawl_output.get("workflow_models", []),
        }
        upload_discovery: dict[str, Any] = {}
        if "upload_discovery" in selected and not expired():
            results["upload_discovery"] = self._execute(
                "upload_discovery",
                (upload_evidence,),
                {},
                {"offline_evidence_sources": sorted(upload_evidence)},
            )
            upload_discovery = results["upload_discovery"].get("output") or {}
        upload_observed = bool(upload_discovery.get("upload_surface_observed"))
        for name in (
            "upload_validation_analyzer",
            "upload_metadata_analyzer",
            "upload_storage_analyzer",
        ):
            if name not in selected:
                continue
            if upload_observed:
                results[name] = self._execute(
                    name,
                    (upload_evidence,),
                    {},
                    {"upload_surface_observed": True},
                )
            else:
                results[name] = self._envelope(
                    name,
                    "not_applicable",
                    error="No upload surface was observed in existing evidence.",
                )
                self._notify(name, results[name])
        if "upload_security_planner" in selected:
            if upload_observed:
                combined_upload_evidence = {
                    "upload_surface_observed": True,
                    "observations": upload_discovery.get("observations", []),
                    "validation": (
                        results.get("upload_validation_analyzer", {}).get("output")
                        or {}
                    ),
                    "metadata": (
                        results.get("upload_metadata_analyzer", {}).get("output") or {}
                    ),
                    "storage": (
                        results.get("upload_storage_analyzer", {}).get("output") or {}
                    ),
                }
                results["upload_security_planner"] = self._execute(
                    "upload_security_planner",
                    (combined_upload_evidence,),
                    {},
                    {"upload_surface_observed": True},
                )
            else:
                results["upload_security_planner"] = self._envelope(
                    "upload_security_planner",
                    "not_applicable",
                    error="Manual planning requires observed upload evidence.",
                )
                self._notify(
                    "upload_security_planner", results["upload_security_planner"]
                )
        if "upload_replay_checker" in selected:
            results["upload_replay_checker"] = self._envelope(
                "upload_replay_checker",
                "not_applicable",
                error="Replay requires a separate explicit opt-in controlled request and never runs automatically.",
            )
            self._notify("upload_replay_checker", results["upload_replay_checker"])

        if "authz_test_planner" in selected:
            parameter_output = results.get("parameter_analyzer", {}).get("output") or {}
            parameter_findings = (
                parameter_output.get("findings", [])
                if isinstance(parameter_output, dict)
                else []
            )
            if parameter_findings:
                results["authz_test_planner"] = self._execute(
                    "authz_test_planner",
                    (parameter_findings,),
                    {},
                    {"candidate_count": len(parameter_findings)},
                )
            else:
                results["authz_test_planner"] = self._envelope(
                    "authz_test_planner",
                    "skipped",
                    error="No parameter candidates were available for planning.",
                )
                self._notify("authz_test_planner", results["authz_test_planner"])

        if (
            "api_object_discovery" in selected
            and not api_ran_as_fallback
            and not expired()
        ):
            results["api_object_discovery"] = self._execute(
                "api_object_discovery",
                (surface["effective_target"],),
                {
                    "max_pages": 25,
                    "normalized_url_evidence": surface,
                    "allow_network_crawl": profile in {"deep", "authenticated"},
                },
                {"target": surface["effective_target"]},
            )
        self._phase("optional_tools")
        if "nuclei_scan" in selected and not expired():
            results["nuclei_scan"] = self._execute(
                "nuclei_scan", (target,), {}, {"target": target}
            )

        if "jwt_security_analyzer" in selected:
            if jwt_token:
                results["jwt_security_analyzer"] = self._execute(
                    "jwt_security_analyzer", (jwt_token,), {}, {"jwt_supplied": True}
                )
            else:
                results["jwt_security_analyzer"] = self._envelope(
                    "jwt_security_analyzer",
                    "skipped",
                    error="No researcher-supplied JWT was provided.",
                    input_summary={"jwt_supplied": False},
                )
                self._notify("jwt_security_analyzer", results["jwt_security_analyzer"])

        # JWT workflow stages are offline unless a separately supplied replay
        # request passes every opt-in safety check. A normal scan never replays.
        if "jwt_discovery" in selected:
            jwt_evidence = (
                {"controlled_token": jwt_token}
                if jwt_token
                else {
                    "requests": crawl_output.get("requests", []),
                    "headers": crawl_output.get("headers", {}),
                    "cookies": crawl_output.get("cookies", {}),
                    "javascript_strings": crawl_output.get("javascript_strings", []),
                }
            )
            results["jwt_discovery"] = self._execute(
                "jwt_discovery",
                (jwt_evidence,),
                {},
                {"controlled_token_supplied": bool(jwt_token)},
            )
        jwt_decoded: dict[str, Any] = {}
        if "jwt_decoder" in selected:
            if jwt_token:
                results["jwt_decoder"] = self._execute(
                    "jwt_decoder", (jwt_token,), {}, {"controlled_token_supplied": True}
                )
                jwt_decoded = results["jwt_decoder"].get("output") or {}
            else:
                results["jwt_decoder"] = self._envelope(
                    "jwt_decoder",
                    "not_applicable",
                    error="No researcher-supplied controlled JWT was provided.",
                )
                self._notify("jwt_decoder", results["jwt_decoder"])
        if "jwt_claims_analyzer" in selected:
            if jwt_token and jwt_decoded.get("success"):
                results["jwt_claims_analyzer"] = self._execute(
                    "jwt_claims_analyzer",
                    (jwt_token,),
                    {},
                    {"successful_decode": True},
                )
            else:
                results["jwt_claims_analyzer"] = self._envelope(
                    "jwt_claims_analyzer",
                    "not_applicable",
                    error="Successful controlled JWT decoding was unavailable.",
                )
                self._notify("jwt_claims_analyzer", results["jwt_claims_analyzer"])
        for name, reason in (
            (
                "jwt_comparison_analyzer",
                "At least two researcher-controlled JWTs were not supplied.",
            ),
            (
                "jwt_verification_planner",
                "Controlled-account context and sufficient JWT evidence were not supplied.",
            ),
            (
                "jwt_replay_checker",
                "Replay requires an explicit opt-in controlled request and never runs from a scan token.",
            ),
        ):
            if name in selected:
                results[name] = self._envelope(name, "not_applicable", error=reason)
                self._notify(name, results[name])

        # Business-logic stages consume only already-obtained sanitized metadata.
        # Normal scans never invoke the replay checker with live requests.
        workflow_discovery: dict[str, Any] = {}
        workflow_model: dict[str, Any] = {}
        workflow_input = {
            "requests": crawl_output.get("requests", []),
            "workflow_name": crawl_output.get("workflow_name"),
        }
        if "workflow_evidence_discovery" in selected:
            if workflow_input["requests"]:
                results["workflow_evidence_discovery"] = self._execute(
                    "workflow_evidence_discovery",
                    (workflow_input,),
                    {},
                    {"sanitized_request_count": len(workflow_input["requests"])},
                )
                workflow_discovery = (
                    results["workflow_evidence_discovery"].get("output") or {}
                )
            else:
                results["workflow_evidence_discovery"] = self._envelope(
                    "workflow_evidence_discovery",
                    "not_applicable",
                    error="No ordered sanitized workflow evidence was available.",
                )
                self._notify(
                    "workflow_evidence_discovery",
                    results["workflow_evidence_discovery"],
                )
        if "workflow_model_builder" in selected:
            candidates = workflow_discovery.get("workflow_candidates") or []
            supported = candidates and candidates[0].get("confidence") != "low"
            if supported:
                results["workflow_model_builder"] = self._execute(
                    "workflow_model_builder",
                    (workflow_input,),
                    {},
                    {"workflow_candidate_count": len(candidates)},
                )
                workflow_model = results["workflow_model_builder"].get("output") or {}
            else:
                results["workflow_model_builder"] = self._envelope(
                    "workflow_model_builder",
                    "not_applicable",
                    error="Sufficient ordered workflow evidence was unavailable.",
                )
                self._notify(
                    "workflow_model_builder", results["workflow_model_builder"]
                )
        for name in ("workflow_transition_analyzer", "business_rule_analyzer"):
            if name not in selected:
                continue
            if workflow_model.get("model"):
                results[name] = self._execute(
                    name,
                    (workflow_model,),
                    {},
                    {"canonical_model_available": True},
                )
            else:
                results[name] = self._envelope(
                    name,
                    "not_applicable",
                    error="A canonical workflow model was unavailable.",
                )
                self._notify(name, results[name])
        for name, reason in (
            (
                "business_logic_test_planner",
                "Planner requires explicit controlled-account evidence and never runs from route names alone.",
            ),
            (
                "workflow_replay_checker",
                "Replay requires a separate explicit opt-in local request file and never runs automatically.",
            ),
        ):
            if name in selected:
                results[name] = self._envelope(name, "not_applicable", error=reason)
                self._notify(name, results[name])

        for name in ("request_replay_engine", "authorization_differential_tester"):
            if name in selected:
                results[name] = self._envelope(
                    name,
                    "skipped",
                    error=(
                        "Explicit controlled request and credential contexts "
                        "were not supplied."
                    ),
                )
                self._notify(name, results[name])

        completed_at = _now()
        self._phase("evidence_package")
        evidence = build_evidence_package(
            target, profile, results, started_at, completed_at, surface
        )
        pre_completed = [
            name for name, env in results.items() if env.get("status") == "completed"
        ]
        pre_failed = [
            name for name, env in results.items() if env.get("status") == "failed"
        ]
        pre_timed_out = [
            name
            for name, env in results.items()
            if env.get("status") in {"timed_out", "timed_out_partial"}
        ]
        pre_skipped = [
            name
            for name, env in results.items()
            if env.get("status") in {"skipped", "not_applicable"}
        ]
        pre_applicable = len(selected) - len(pre_skipped)
        pre_coverage = {
            "planned_tools": sorted(selected),
            "completed_tools": pre_completed,
            "failed_tools": pre_failed,
            "timed_out_tools": pre_timed_out,
            "skipped_tools": pre_skipped,
            "coverage_percentage": (
                round(100 * len(pre_completed) / pre_applicable, 1)
                if pre_applicable
                else 100.0
            ),
        }
        evidence["assessment_status"] = (
            "completed_with_limitations" if pre_failed or pre_timed_out else "completed"
        )
        evidence["coverage"] = pre_coverage
        if "ai_report_writer" in selected and not expired():
            results["ai_report_writer"] = self._execute(
                "ai_report_writer",
                (target, evidence),
                {"phase_callback": self.phase_callback},
                {"evidence_package": True},
                timeout=AI_REPORT_TIMEOUT_SECONDS + 5,
            )
            report_output = results["ai_report_writer"].get("output") or {}
            if not isinstance(report_output, dict):
                report_output = {}
            evidence["evidence_files"] = (
                [report_output["evidence_file"]]
                if report_output.get("evidence_file")
                else []
            )
        planned = sorted(selected)
        completed = [
            name for name, env in results.items() if env.get("status") == "completed"
        ]
        completed_with_fallback = [
            name
            for name, env in results.items()
            if env.get("status") == "completed_with_fallback"
        ]
        failed = [
            name for name, env in results.items() if env.get("status") == "failed"
        ]
        timed_out = [
            name for name, env in results.items() if env.get("status") == "timed_out"
        ]
        partial = [
            name
            for name, env in results.items()
            if env.get("status") == "timed_out_partial"
        ]
        skipped = [
            name
            for name, env in results.items()
            if env.get("status") in {"skipped", "not_applicable"}
        ]
        required_failures = [
            name for name in failed + timed_out + partial if name in selected
        ]
        report_output = results.get("ai_report_writer", {}).get("output") or {}
        if not isinstance(report_output, dict):
            report_output = {}
        ai_limited = report_output.get("ai_status") in {"timed_out", "failed"}
        assessment_status = (
            "completed_with_limitations"
            if required_failures or ai_limited
            else "completed"
        )
        applicable_count = len(planned) - len(skipped)
        coverage = {
            "planned_tools": planned,
            "completed_tools": completed + completed_with_fallback,
            "failed_tools": failed,
            "timed_out_tools": timed_out,
            "skipped_tools": skipped,
            "partial_tools": partial,
            "completed_with_fallback_tools": completed_with_fallback,
            "coverage_percentage": (
                round(
                    100
                    * (
                        len(completed)
                        + len(completed_with_fallback)
                        + 0.5 * len(partial)
                    )
                    / applicable_count,
                    1,
                )
                if applicable_count
                else 100.0
            ),
        }
        reporting = {"ai_report_writer"}
        optional = {
            "nuclei_scan",
            "jwt_security_analyzer",
            "jwt_discovery",
            "jwt_decoder",
            "jwt_claims_analyzer",
            "jwt_comparison_analyzer",
            "jwt_verification_planner",
            "jwt_replay_checker",
            "authz_test_planner",
            "request_replay_engine",
            "authorization_differential_tester",
            "graphql_endpoint_discovery",
            "graphql_query_analyzer",
            "graphql_schema_analyzer",
            "graphql_introspection_checker",
            "graphql_authz_planner",
            "workflow_evidence_discovery",
            "workflow_model_builder",
            "workflow_transition_analyzer",
            "business_rule_analyzer",
            "business_logic_test_planner",
            "workflow_replay_checker",
            "upload_discovery",
            "upload_validation_analyzer",
            "upload_metadata_analyzer",
            "upload_storage_analyzer",
            "upload_security_planner",
            "upload_replay_checker",
        }
        required = set(planned) - optional - reporting
        coverage_detail = {
            "required_planned": len(required),
            "required_completed": len(
                required & set(completed + completed_with_fallback)
            ),
            "required_partial": len(required & set(partial)),
            "required_failed": len(required & set(failed + timed_out)),
            "optional_skipped": len(optional & set(skipped)),
            "report_generated": bool(report_output.get("report_generated")),
        }
        coverage["coverage_detail"] = coverage_detail
        evidence["assessment_status"] = assessment_status
        evidence["coverage"] = coverage
        evidence["coverage_detail"] = coverage_detail
        evidence["execution_summary"] = {
            status: [
                name for name, env in results.items() if env.get("status") == status
            ]
            for status in (
                "completed",
                "completed_with_fallback",
                "timed_out_partial",
                "timed_out",
                "failed",
                "skipped",
                "not_applicable",
            )
        }
        return {
            "success": True,
            "assessment_status": assessment_status,
            "coverage": coverage,
            "target": target,
            "profile": profile,
            "started_at": started_at,
            "completed_at": _now(),
            "completed_steps": [
                name
                for name, env in results.items()
                if env.get("status") == "completed"
            ],
            "results": results,
            "normalized_urls": surface,
            "evidence_package": evidence,
        }
