"""Deterministic advisory-to-Phase-2 execution eligibility gate."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from agent_core.agent_models import Hypothesis, VerificationPlan
from agent_core.autonomy.runtime_binding import is_authoritative_phase2_runtime
from agent_core.autonomy.types import (
    AutonomyLimits,
    ExecutionIdentity,
    GateDecision,
    GateReason,
    ModelBudgetState,
)
from agent_core.reasoning import ReasoningAction, ReasoningDecision
from agent_core.verification_capabilities import (
    CapabilityState,
    get_verification_capability,
)


def controlled_context_reference(runtime: Any, plan: VerificationPlan) -> str:
    """Hash only public controlled identifiers; never credential values or handles."""

    controlled = getattr(runtime, "controlled_context", None)
    accounts = sorted(
        str(item.account_id)
        for item in getattr(controlled, "accounts", ())
        if getattr(item, "controlled", False)
        and str(item.account_id) in set(plan.controlled_accounts)
    )
    objects = sorted(
        str(item.object_id)
        for item in getattr(controlled, "objects", ())
        if getattr(item, "test_owned", False)
        and str(item.object_id) in set(plan.test_owned_resources)
    )
    material = json.dumps(
        {"accounts": accounts, "objects": objects, "plan_id": plan.plan_id},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "ctx-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


class ExecutionDecisionGate:
    """Preflight a recommendation without granting Phase 2 authorization."""

    def evaluate(
        self,
        decision: ReasoningDecision,
        *,
        hypotheses: Mapping[str, Hypothesis],
        plans: Mapping[str, VerificationPlan],
        eligible_hypothesis_ids: frozenset[str],
        runtime: Any,
        limits: AutonomyLimits,
        iteration: int,
        verifications_attempted: int,
        model_budget_state: ModelBudgetState,
        execution_identities: tuple[ExecutionIdentity, ...],
        cleanup_barrier_active: bool,
    ) -> GateDecision:
        capability_id = decision.recommended_capability
        base = {
            "hypothesis_id": decision.hypothesis_id,
            "capability": capability_id,
        }

        def blocked(reason: GateReason, **values: Any) -> GateDecision:
            return GateDecision(approved=False, reason=reason, **base, **values)

        if decision.action is not ReasoningAction.recommend_verification:
            return blocked(GateReason.action_not_verification)
        hypothesis = hypotheses.get(decision.hypothesis_id)
        if hypothesis is None or decision.hypothesis_id not in eligible_hypothesis_ids:
            return blocked(GateReason.hypothesis_not_found)
        plan = plans.get(decision.hypothesis_id)
        if plan is None or plan.hypothesis_id != hypothesis.hypothesis_id:
            return blocked(GateReason.plan_not_found)
        if capability_id is None:
            return blocked(GateReason.unknown_capability, plan_id=plan.plan_id)
        try:
            capability = get_verification_capability(capability_id)
        except (KeyError, ValueError):
            return blocked(GateReason.unknown_capability, plan_id=plan.plan_id)
        if capability.capability_state is not CapabilityState.typed_verification:
            return blocked(GateReason.plan_only_capability, plan_id=plan.plan_id)
        if not capability.executor_available:
            return blocked(GateReason.typed_route_unavailable, plan_id=plan.plan_id)
        if hypothesis.category != capability.category:
            return blocked(GateReason.category_mismatch, plan_id=plan.plan_id)
        if not capability.automatic_execution or not plan.automatic_execution_allowed:
            return blocked(
                GateReason.automatic_execution_unsupported, plan_id=plan.plan_id
            )
        if not is_authoritative_phase2_runtime(runtime):
            return blocked(GateReason.runtime_boundary_invalid, plan_id=plan.plan_id)
        if verifications_attempted >= limits.max_verifications:
            return blocked(
                GateReason.verification_budget_exhausted, plan_id=plan.plan_id
            )
        if iteration > limits.max_iterations:
            return blocked(GateReason.iteration_budget_exhausted, plan_id=plan.plan_id)
        if model_budget_state is not ModelBudgetState.available:
            return blocked(GateReason.model_budget_exhausted, plan_id=plan.plan_id)
        if cleanup_barrier_active and capability.state_changing:
            return blocked(GateReason.cleanup_barrier, plan_id=plan.plan_id)

        policy = runtime.policy
        controlled = runtime.controlled_context
        vault = runtime.vault
        if not policy.authorization_confirmed or not plan.authorization_confirmed:
            return blocked(GateReason.authorization_missing, plan_id=plan.plan_id)

        planned_accounts = set(plan.controlled_accounts)
        eligible_accounts = [
            account
            for account in controlled.accounts
            if account.controlled
            and account.account_id in planned_accounts
            and policy.account_is_eligible(account.account_id, controlled).eligible
        ]
        if len({item.account_id for item in eligible_accounts}) < (
            capability.required_account_count
        ):
            return blocked(GateReason.controlled_account_missing, plan_id=plan.plan_id)

        if capability.requires_credentials:
            credential_ready = 0
            for account in eligible_accounts:
                references = tuple(account.credential_references.values()) + (
                    (account.session_reference,) if account.session_reference else ()
                )
                if any(
                    isinstance(reference, str)
                    and reference
                    and _vault_contains(vault, reference)
                    for reference in references
                ):
                    credential_ready += 1
            required = max(1, capability.required_account_count)
            if (
                not policy.credentials_allowed
                or not plan.credentials_supplied
                or credential_ready < required
            ):
                return blocked(GateReason.credentials_missing, plan_id=plan.plan_id)

        if capability.requires_state_change_policy and not policy.allow_state_changes:
            return blocked(
                GateReason.state_change_permission_missing, plan_id=plan.plan_id
            )
        if capability.required_policy_opt_in and not bool(
            getattr(policy, f"allow_{capability.required_policy_opt_in}", False)
        ):
            return blocked(GateReason.phase2_policy_denied, plan_id=plan.plan_id)
        if capability.cleanup_required:
            cleanup_steps_present = bool(plan.cleanup) and all(
                not step.state_changing
                or step.cleanup_required
                and bool(step.cleanup_steps)
                for step in plan.steps
            )
            if (
                not policy.require_cleanup_for_state_changes
                or not cleanup_steps_present
            ):
                return blocked(
                    GateReason.cleanup_requirement_missing, plan_id=plan.plan_id
                )
        if capability.requires_test_owned_resource:
            planned_objects = set(plan.test_owned_resources)
            owned = {
                item.object_id
                for item in controlled.objects
                if item.test_owned and item.object_id in planned_objects
            }
            if not owned:
                return blocked(
                    GateReason.test_owned_object_missing, plan_id=plan.plan_id
                )

        try:
            phase2_policy_decision = policy.authorize_plan(plan)
        except (AttributeError, TypeError, ValueError):
            return blocked(GateReason.phase2_policy_denied, plan_id=plan.plan_id)
        if plan.policy_decision != "allowed" or not phase2_policy_decision.allowed:
            return blocked(GateReason.phase2_policy_denied, plan_id=plan.plan_id)

        required_requests = max(
            capability.worst_case_requests,
            plan.estimated_requests,
            decision.estimated_request_cost,
        )
        budget = runtime.budget
        remaining = budget.remaining if budget is not None else None
        if not isinstance(remaining, int) or isinstance(remaining, bool):
            return blocked(GateReason.runtime_boundary_invalid, plan_id=plan.plan_id)
        if remaining < required_requests:
            return blocked(
                GateReason.request_budget_exhausted,
                plan_id=plan.plan_id,
                required_requests=required_requests,
            )

        context_reference = controlled_context_reference(runtime, plan)
        if any(
            item.hypothesis_id == hypothesis.hypothesis_id
            and item.capability == capability.category
            and item.controlled_context_reference == context_reference
            for item in execution_identities
        ):
            return blocked(
                GateReason.duplicate_recommendation,
                plan_id=plan.plan_id,
                required_requests=required_requests,
            )
        return GateDecision(
            approved=True,
            reason=GateReason.approved,
            hypothesis_id=hypothesis.hypothesis_id,
            capability=capability.category,
            plan_id=plan.plan_id,
            required_requests=required_requests,
        )


def _vault_contains(vault: Any, reference: str) -> bool:
    try:
        return bool(vault.contains(reference))
    except (KeyError, RuntimeError, TypeError, ValueError):
        return False
