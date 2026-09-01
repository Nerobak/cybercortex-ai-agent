"""Typed observe → hypothesize → gate adaptive agent loop."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent_core.agent_models import (
    AssessmentPlan,
    PolicyRunMetadata,
    stable_identifier,
)
from agent_core.attack_surface import AttackSurfaceGraph
from agent_core.attack_surface import CanonicalAttackSurface
from agent_core.audit_log import TamperEvidentAuditLog
from agent_core.capture_ingest import (
    CaptureBundle,
    apply_capture_context,
    ingest_bundle_into_graph,
    import_capture,
)
from agent_core.hypothesis_engine import (
    build_verification_plan,
    generate_hypotheses,
    propose_llm_hypotheses,
    generate_surface_hypotheses,
)
from agent_core.policy import AssessmentPolicy, policy_hash
from agent_core.controlled_context import ControlledContext, role_privilege_rank
from agent_core.phase2_policy import DeterministicPolicyGate
from agent_core.phase2_result_status import (
    BUDGET_PREFLIGHT_REASON,
    PUBLIC_RESULT_STATUSES,
    normalize_typed_result,
)
from agent_core.priority_engine import rank_hypotheses
from agent_core.request_budget import (
    RequestBudget,
    RequestDelta,
    canonical_result_request_total,
)
from agent_core.verification_runtime import build_verification_policy_context
from agent_core.verification_capabilities import (
    CapabilityState,
    get_verification_capability,
    plan_only_command_metadata,
)
from agent_core.verification_planner import (
    VerificationPlanner,
    VerificationPlanningContext,
)
from config import (
    ADAPTIVE_MAX_HYPOTHESES,
    ADAPTIVE_MAX_REQUESTS,
    ADAPTIVE_MAX_RUNTIME_SECONDS,
    ADAPTIVE_MAX_VERIFICATIONS,
)
from tool_registry import tools_for_profile


def _now_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


class AdaptiveAssessmentOrchestrator:
    """Coordinate bounded planning while leaving execution policy deterministic."""

    def __init__(
        self,
        *,
        graph: AttackSurfaceGraph | None = None,
        audit_log: TamperEvidentAuditLog | None = None,
    ) -> None:
        self.graph = graph or AttackSurfaceGraph()
        self.audit = audit_log or TamperEvidentAuditLog()

    def plan_from_bundle(
        self,
        bundle: CaptureBundle,
        policy: AssessmentPolicy,
        *,
        goal: str,
        profile: str = "authenticated",
        controlled_accounts: list[str] | None = None,
        test_owned_resources: list[str] | None = None,
        run_id: str | None = None,
        llm_analyst: Callable[[str], str] | None = None,
    ) -> AssessmentPlan:
        assessment_id = run_id or stable_identifier("run", _now_id(), bundle.source_ref)
        target = bundle.requests[0].url if bundle.requests else "capture-only"
        prior_surface = self.graph.snapshot(target)
        self.graph.start_run(assessment_id, target, profile)
        counts = ingest_bundle_into_graph(bundle, self.graph, assessment_id)
        changed_nodes = self.graph.changed_nodes(assessment_id)
        request_changes = {
            item["canonical_key"]: (
                "new"
                if item["is_new"]
                else "changed" if item["is_changed"] else "known"
            )
            for item in changed_nodes
            if item["kind"] == "request"
        }
        deterministic_hypotheses = generate_hypotheses(bundle)
        llm_hypotheses = (
            propose_llm_hypotheses(bundle, llm_analyst) if llm_analyst else []
        )
        merged = {
            hypothesis.hypothesis_id: hypothesis
            for hypothesis in deterministic_hypotheses
        }
        for hypothesis in llm_hypotheses:
            existing = merged.get(hypothesis.hypothesis_id)
            if existing is None or hypothesis.priority > existing.priority:
                merged[hypothesis.hypothesis_id] = hypothesis
        hypotheses = sorted(
            merged.values(), key=lambda item: (-item.priority, item.hypothesis_id)
        )
        for hypothesis in hypotheses:
            request_id = str(hypothesis.metadata.get("request_id") or "")
            change = request_changes.get(request_id, "known")
            hypothesis.metadata["surface_change"] = change
            previous = self.graph.get_hypothesis(hypothesis.hypothesis_id)
            if change in {"new", "changed"}:
                hypothesis.priority = min(100, hypothesis.priority + 5)
            elif previous:
                hypothesis.priority = max(0, hypothesis.priority - 10)
                hypothesis.metadata["previous_status"] = previous["status"]
        hypotheses.sort(key=lambda item: (-item.priority, item.hypothesis_id))
        verification_plans = []
        selected_tools: set[str] = set()
        effective_accounts = controlled_accounts or [
            identity.identity_id
            for identity in bundle.identities
            if identity.controlled
        ]
        effective_test_resources = test_owned_resources or [
            item.object_id for item in bundle.objects if item.test_owned
        ]
        credentials_supplied = any(
            identity.credential_references for identity in bundle.identities
        )
        for hypothesis in hypotheses:
            plan = build_verification_plan(
                hypothesis,
                profile=profile,
                authorization_confirmed=policy.authorization_confirmed,
                credentials_supplied=credentials_supplied,
                controlled_accounts=effective_accounts,
                test_owned_resources=effective_test_resources,
                request_budget=min(20, policy.request_budget),
            )
            decision = policy.authorize_plan(plan)
            plan.policy_decision = "allowed" if decision.allowed else "blocked"
            plan.policy_reasons = decision.reasons
            hypothesis.status = "ready" if decision.allowed else "policy_blocked"
            self.graph.record_hypothesis(
                hypothesis.model_dump(mode="json"), assessment_id
            )
            verification_plans.append(plan)
            selected_tools.update(step.tool for step in plan.steps if decision.allowed)
        assessment_plan = AssessmentPlan(
            run_id=assessment_id,
            goal=goal,
            target=target,
            profile=profile,  # type: ignore[arg-type]
            selected_tools=sorted(selected_tools),
            hypotheses=hypotheses,
            verification_plans=verification_plans,
            request_budget=policy.request_budget,
            prior_surface_version=prior_surface.get("surface_version"),
            stop_conditions=[
                "scope violation",
                "request budget exhausted",
                "unexpected state change",
                "service instability",
                "policy testing window closed",
            ],
            policy_metadata=PolicyRunMetadata(
                profile_name=policy.profile_name or "policy-file",
                policy_version=policy.policy_version,
                policy_hash=policy.policy_hash or policy_hash(policy),
                authorization_reference=policy.authorization_reference or "missing",
                source="saved_profile" if policy.profile_name else "policy_file",
            ),
        )
        summary = {
            "capture": bundle.summary(),
            "graph_ingest": counts,
            "hypotheses": len(hypotheses),
            "llm_hypotheses_accepted": len(llm_hypotheses),
            "new_surface_nodes": sum(item["is_new"] for item in changed_nodes),
            "changed_surface_nodes": sum(item["is_changed"] for item in changed_nodes),
            "allowed_plans": sum(
                plan.policy_decision == "allowed" for plan in verification_plans
            ),
        }
        self.audit.append("assessment_planned", summary, run_id=assessment_id)
        self.graph.finish_run(assessment_id, "planned", summary)
        return assessment_plan

    def initial_surface_plan(
        self,
        *,
        goal: str,
        target: str,
        profile: str,
        request_budget: int,
    ) -> AssessmentPlan:
        """Create a narrow typed discovery plan for the ordinary scan command."""
        eligible = set(tools_for_profile(profile))
        baseline = {
            "dns_lookup",
            "http_probe",
            "security_headers_checker",
            "tech_fingerprint",
            "katana_crawl",
            "api_target_analyzer",
            "api_metadata_discovery",
            "openapi_surface_analyzer",
            "endpoint_analyzer",
            "parameter_analyzer",
            "misconfiguration_detector",
            "js_secret_scanner",
            "api_object_discovery",
            "graphql_endpoint_discovery",
            "jwt_discovery",
            "workflow_evidence_discovery",
            "upload_discovery",
            "nuclei_scan",
            "ai_report_writer",
        }
        if profile in {"deep", "authenticated", "intrusive"}:
            baseline |= {
                "graphql_query_analyzer",
                "graphql_schema_analyzer",
                "graphql_introspection_checker",
                "workflow_model_builder",
                "workflow_transition_analyzer",
                "business_rule_analyzer",
                "upload_validation_analyzer",
                "upload_metadata_analyzer",
                "upload_storage_analyzer",
            }
        selected = sorted(baseline & eligible)
        return AssessmentPlan(
            run_id=stable_identifier("run", _now_id(), target, profile),
            goal=goal,
            target=target,
            profile=profile,  # type: ignore[arg-type]
            selected_tools=selected,
            request_budget=request_budget,
            max_iterations=3,
            stop_conditions=[
                "scope violation",
                "request budget exhausted",
                "unexpected state change",
                "service instability",
            ],
        )

    def ingest_scan_result(
        self,
        plan: AssessmentPlan,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        self.graph.start_run(plan.run_id, plan.target, plan.profile)
        counts = self.graph.ingest_assessment(plan.run_id, result)
        summary = self.graph.snapshot(plan.target)
        self.graph.finish_run(
            plan.run_id,
            str(result.get("assessment_status") or "completed"),
            {"ingested": counts, "surface": summary},
        )
        self.audit.append(
            "surface_assessment_completed",
            {
                "status": result.get("assessment_status"),
                "coverage": result.get("coverage"),
                "ingested": counts,
                "surface_version": summary.get("surface_version"),
            },
            run_id=plan.run_id,
        )
        return {"ingested": counts, "surface": summary}

    def plan_capture_file(
        self,
        path: str | Path,
        policy: AssessmentPolicy,
        *,
        goal: str,
        profile: str = "authenticated",
        capture_format: str = "auto",
        default_base_url: str | None = None,
        controlled_accounts: list[str] | None = None,
        test_owned_resources: list[str] | None = None,
        capture_context: dict[str, Any] | None = None,
        llm_analyst: Callable[[str], str] | None = None,
    ) -> AssessmentPlan:
        bundle, vault = import_capture(
            path,
            capture_format=capture_format,  # type: ignore[arg-type]
            default_base_url=default_base_url,
        )
        try:
            if capture_context:
                apply_capture_context(bundle, capture_context)
            return self.plan_from_bundle(
                bundle,
                policy,
                goal=goal,
                profile=profile,
                controlled_accounts=controlled_accounts,
                test_owned_resources=test_owned_resources,
                llm_analyst=llm_analyst,
            )
        finally:
            vault.close()

    def execute_allowed_plans(
        self,
        plan: AssessmentPlan,
        policy: AssessmentPolicy,
        *,
        executor: Callable[[Any, Any], dict[str, Any]],
        authorization_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Execute only through an injected deterministic verifier/executor.

        This method intentionally has no generic arbitrary-tool dispatcher. Each
        verifier must provide its own typed input adapter and cleanup semantics.
        """
        if not authorization_confirmed or not policy.authorization_confirmed:
            return {
                "success": False,
                "error": "Explicit execution authorization is required.",
            }
        results: list[dict[str, Any]] = []
        requests_used = 0
        hypotheses_by_id = {
            hypothesis.hypothesis_id: hypothesis for hypothesis in plan.hypotheses
        }
        for verification_plan in plan.verification_plans:
            hypothesis = hypotheses_by_id.get(verification_plan.hypothesis_id)
            capability = (
                get_verification_capability(hypothesis.category)
                if hypothesis is not None
                else None
            )
            if (
                capability is None
                or capability.capability_state is not CapabilityState.typed_verification
            ):
                results.append(
                    {
                        "plan_id": verification_plan.plan_id,
                        "status": "plan_only",
                        "requests_used": 0,
                        "reasons": [
                            "The capability registry declares no active typed execution route."
                        ],
                    }
                )
                continue
            decision = policy.authorize_plan(verification_plan)
            if not decision.allowed:
                results.append(
                    {
                        "plan_id": verification_plan.plan_id,
                        "status": "policy_blocked",
                        "reasons": decision.reasons,
                    }
                )
                continue
            if (
                requests_used + verification_plan.estimated_requests
                > policy.request_budget
            ):
                results.append(
                    {
                        "plan_id": verification_plan.plan_id,
                        "status": "policy_blocked",
                        "reasons": [BUDGET_PREFLIGHT_REASON],
                    }
                )
                break
            output = executor(verification_plan, policy)
            result_requests, accounting_source = canonical_result_request_total(output)
            output = normalize_typed_result(
                output,
                RequestDelta(
                    verification=result_requests,
                    attempted=result_requests,
                    total=result_requests,
                ),
            )
            requests_used += result_requests
            results.append(
                {
                    "plan_id": verification_plan.plan_id,
                    "status": output.get("status", "completed"),
                    "output": output,
                }
            )
            self.audit.append(
                "verification_plan_executed",
                {
                    "plan_id": verification_plan.plan_id,
                    "requests_used": result_requests,
                    "request_accounting_source": accounting_source,
                    "status": output.get("status"),
                },
                run_id=plan.run_id,
            )
            if output.get("scope_violations") or output.get(
                "unauthorized_state_changes"
            ):
                break
        return {
            "success": True,
            "run_id": plan.run_id,
            "requests_used": requests_used,
            "request_budget": policy.request_budget,
            "results": results,
        }

    def run_phase2(
        self,
        surface: CanonicalAttackSurface,
        policy: AssessmentPolicy,
        *,
        mode: str = "observe",
        target_class: str = "external",
        controlled_context: ControlledContext | None = None,
        request_budget: RequestBudget | None = None,
        executor: (
            Callable[[Any, Any, DeterministicPolicyGate], dict[str, Any]] | None
        ) = None,
        model_name: str = "deterministic",
        profile: str = "baseline",
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the bounded attack-surface → hypothesis → evidence loop.

        ``executor`` is an injected typed verifier. Model output cannot supply it
        and cannot change the policy decision or final classification.
        """
        if mode not in {"observe", "plan", "verify"}:
            raise ValueError("Phase 2 mode must be observe, plan, or verify.")
        if target_class not in {"external", "local_range", "dedicated_lab"}:
            raise ValueError("Target class must be explicitly configured.")
        created_at = datetime.now(timezone.utc).isoformat()
        started = time.monotonic()
        assessment_id = run_id or stable_identifier(
            "run", _now_id(), surface.target, mode
        )
        if executor is not None:
            setattr(executor, "phase2_run_id", assessment_id)
        request_limit = min(policy.request_budget, ADAPTIVE_MAX_REQUESTS)
        budget = request_budget or RequestBudget(
            request_limit,
            per_host_limit=policy.per_host_request_budget,
        )
        if budget.limit > request_limit:
            raise ValueError("The authoritative request ledger exceeds the run limit.")
        if budget.per_host_limit is None:
            budget.per_host_limit = policy.per_host_request_budget
        elif budget.per_host_limit > policy.per_host_request_budget:
            raise ValueError(
                "The authoritative request ledger exceeds the per-host policy limit."
            )
        context = controlled_context or ControlledContext()
        account_ids = [item.account_id for item in context.accounts if item.controlled]
        credential_accounts = [
            item.account_id
            for item in context.accounts
            if item.controlled
            and (item.session_reference or item.credential_references)
        ]
        object_ids = [item.object_id for item in context.objects if item.test_owned]
        acquisition_owner_ids = list(
            dict.fromkeys(item.owner_account_id for item in context.object_acquisition)
        )
        ranked = rank_hypotheses(
            generate_surface_hypotheses(surface)[:ADAPTIVE_MAX_HYPOTHESES],
            controlled_context={"controlled_accounts": account_ids},
        )
        planner = VerificationPlanner()
        gate = DeterministicPolicyGate(
            policy,
            build_verification_policy_context(
                context,
                mode=mode,  # type: ignore[arg-type]
                target_class=target_class,  # type: ignore[arg-type]
            ),
            budget,
        )
        plans = []
        results: list[dict[str, Any]] = []
        missing_context: dict[str, list[str]] = {}
        verifications = 0
        pivots = 0
        stop_reason = "hypotheses exhausted"
        for hypothesis in ranked:
            if time.monotonic() - started >= ADAPTIVE_MAX_RUNTIME_SECONDS:
                stop_reason = "runtime limit exhausted"
                break
            missing = self._missing_controlled_context(hypothesis, context)
            if missing:
                missing_context[hypothesis.hypothesis_id] = missing
            if mode == "observe":
                hypothesis.status = "proposed"
                continue
            planning_accounts = [] if mode == "plan" else account_ids
            planning_credential_accounts = [] if mode == "plan" else credential_accounts
            planning_object_ids = [] if mode == "plan" else object_ids
            plan = planner.create_plan(
                hypothesis,
                VerificationPlanningContext(
                    controlled_accounts=planning_accounts,
                    credential_accounts=planning_credential_accounts,
                    test_owned_resources=planning_object_ids,
                    request_budget=min(20, budget.remaining or 1),
                    target_class=target_class,
                    resource_owner_account_id=(
                        None
                        if mode == "plan"
                        else (
                            context.objects[0].owner_account_id
                            if context.objects
                            else (
                                acquisition_owner_ids[0]
                                if acquisition_owner_ids
                                else None
                            )
                        )
                    ),
                    object_acquisition_owner_ids=(
                        [] if mode == "plan" else acquisition_owner_ids
                    ),
                    account_roles=(
                        {item.account_id: item.role for item in context.accounts}
                        if mode != "plan"
                        else {}
                    ),
                    policy_opt_ins=(
                        ["bounded_rate_limit_verification"]
                        if policy.allow_bounded_rate_limit_verification
                        else []
                    ),
                    rate_limit_attempts=(
                        policy.max_rate_limit_attempts
                        if policy.max_rate_limit_attempts > 0
                        else None
                    ),
                    state_changes_allowed=policy.allow_state_changes,
                ),
            )
            if mode == "plan":
                # Runtime credentials, identities, and owned objects are
                # deliberately deferred. The reusable template is authorized
                # only after a verify-mode runtime copy has concrete bindings.
                plan.policy_decision = "pending"
                plan.policy_reasons = []
                plan.automatic_execution_allowed = False
                hypothesis.status = "proposed"
                plans.append(plan)
                continue
            deferred_runtime_policy = bool(
                executor is not None
                and getattr(executor, "defers_runtime_policy_authorization", False)
            )
            if deferred_runtime_policy:
                plan.policy_decision = "pending"
                plan.policy_reasons = []
                plan.automatic_execution_allowed = bool(
                    plan.automatic_execution_allowed
                    and mode == "verify"
                    and not missing
                )
                preflight_ready = True
            else:
                decision = gate.authorize_plan(plan)
                plan.policy_decision = "allowed" if decision.allowed else "blocked"
                plan.policy_reasons = decision.reasons
                plan.automatic_execution_allowed = bool(
                    plan.automatic_execution_allowed
                    and decision.allowed
                    and mode == "verify"
                    and not missing
                )
                preflight_ready = decision.allowed
            hypothesis.status = "ready" if preflight_ready else "policy_blocked"
            plans.append(plan)
            capability = get_verification_capability(hypothesis.category)
            if capability.capability_state is not CapabilityState.typed_verification:
                command_metadata = plan_only_command_metadata(
                    hypothesis.category, hypothesis.hypothesis_id
                )
                plan.automatic_execution_allowed = False
                plan.policy_decision = "pending"
                plan.policy_reasons = list(command_metadata["reasons"])
                hypothesis.status = "proposed"
                continue
            if mode != "verify" or not plan.automatic_execution_allowed:
                continue
            if verifications >= ADAPTIVE_MAX_VERIFICATIONS:
                stop_reason = "verification limit exhausted"
                break
            if executor is None:
                hypothesis.status = "policy_blocked"
                zero_delta = RequestDelta().model_dump(mode="json")
                results.append(
                    {
                        "hypothesis_id": hypothesis.hypothesis_id,
                        "category": hypothesis.category,
                        "status": "policy_blocked",
                        "requests_used": 0,
                        "request_delta": zero_delta,
                        "reasons": ["The typed verification runtime is unavailable."],
                        "evidence_summary": [
                            "The typed verification runtime is unavailable."
                        ],
                    }
                )
                continue
            output = executor(hypothesis, plan, gate)
            verifications += 1
            if deferred_runtime_policy:
                binding = output.get("runtime_binding") or {}
                runtime_policy_allowed = bool(binding.get("policy_authorized"))
                plan.policy_decision = (
                    "allowed" if runtime_policy_allowed else "blocked"
                )
                plan.policy_reasons = list(output.get("reasons") or [])
            status = str(output.get("status") or "inconclusive")
            if status not in PUBLIC_RESULT_STATUSES:
                status = "inconclusive"
            hypothesis.status = status  # type: ignore[assignment]
            results.append(
                {
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "category": hypothesis.category,
                    **output,
                    "status": status,
                }
            )
            if status == "inconclusive":
                pivots += 1
            if budget.remaining == 0:
                stop_reason = "approved request budget reached"
                break
        duration = round(time.monotonic() - started, 3)
        metrics = {
            **budget.snapshot(),
            "duration_seconds": duration,
            "request_count": budget.total,
            "model_calls": 0,
            "discovery_requests_observed": budget.snapshot()["discovery_requests"],
            "hypotheses_generated": len(ranked),
            "hypotheses_verified": sum(
                item.get("status") == "verified" for item in results
            ),
            "hypotheses_rejected": sum(
                item.get("status") == "rejected" for item in results
            ),
            "pivots": pivots,
            "verifications_attempted": verifications,
            "object_acquisition_requests": sum(
                bool((item.get("owned_object_acquisition") or {}).get("attempted"))
                for item in results
            ),
        }
        payload = {
            "run_id": assessment_id,
            "target": surface.target,
            "created_at": created_at,
            "mode": mode,
            "assessment_mode": mode,
            "profile": profile,
            "target_class": target_class,
            "model": model_name,
            "attack_surface": surface.model_dump(mode="json"),
            "hypotheses": [item.model_dump(mode="json") for item in ranked],
            "verification_plans": [item.model_dump(mode="json") for item in plans],
            "verification_results": results,
            "missing_controlled_context": missing_context,
            "metrics": metrics,
            "stop_reason": stop_reason,
        }
        self.audit.append(
            "phase2_loop_completed",
            {
                "mode": mode,
                "hypotheses": len(ranked),
                "verifications": verifications,
                "requests": budget.total,
                "stop_reason": stop_reason,
            },
            run_id=assessment_id,
        )
        return payload

    @staticmethod
    def _missing_controlled_context(
        hypothesis: Any, context: ControlledContext
    ) -> list[str]:
        missing: list[str] = []
        accounts = [item for item in context.accounts if item.controlled]
        capability = get_verification_capability(hypothesis.category)
        if capability.required_account_count == 2 and len(accounts) < 2:
            missing.append("two distinct explicitly controlled accounts")
        elif capability.required_account_count == 1 and not accounts:
            missing.append("an explicitly controlled account")
        if hypothesis.category == "vertical_authorization":
            ranks = [role_privilege_rank(item.role) for item in accounts]
            known_ranks = [rank for rank in ranks if rank is not None]
            if len(known_ranks) < 2 or len(set(known_ranks)) < 2:
                missing.append(
                    "controlled accounts with explicit lower and higher privilege roles"
                )
        controlled_ids = {item.account_id for item in accounts}
        configured_acquisition = any(
            item.owner_account_id in controlled_ids
            for item in context.object_acquisition
        )
        if (
            capability.requires_test_owned_resource
            and not any(item.test_owned for item in context.objects)
            and not configured_acquisition
        ):
            missing.append("a researcher-controlled object/resource")
        if (
            hypothesis.category == "tenant_isolation"
            and len({item.tenant_id for item in accounts if item.tenant_id}) < 2
        ):
            missing.append("controlled accounts in two controlled tenants")
        return missing


def write_assessment_plan(plan: AssessmentPlan, output_path: str | Path) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(plan.model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    return str(path)
