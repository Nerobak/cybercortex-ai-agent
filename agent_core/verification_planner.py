"""Category-specific minimal, bounded Phase 2 verification plans."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from pydantic import Field

from agent_core.agent_models import (
    Hypothesis,
    StrictModel,
    VerificationPlan,
    VerificationStep,
    stable_identifier,
)
from agent_core.controlled_context import role_privilege_rank
from agent_core.rate_limit_enforcement import MAX_RATE_LIMIT_ATTEMPTS
from agent_core.session_invalidation import SessionInvalidationWorkflow
from agent_core.verification_capabilities import (
    CAPABILITY_SCHEMA_VERSION,
    CapabilityState,
    capability_metadata,
    capability_support_reasons,
    get_verification_capability,
    request_cost_for,
)


class VerificationPlanningContext(StrictModel):
    profile: str = "authenticated"
    controlled_accounts: list[str] = Field(default_factory=list, max_length=20)
    credential_accounts: list[str] = Field(default_factory=list, max_length=20)
    test_owned_resources: list[str] = Field(default_factory=list, max_length=100)
    request_budget: int = Field(default=20, ge=1, le=500)
    target_class: str = "external"
    resource_owner_account_id: str | None = None
    object_acquisition_owner_ids: list[str] = Field(default_factory=list, max_length=20)
    account_roles: dict[str, str] = Field(default_factory=dict)
    policy_opt_ins: list[str] = Field(default_factory=list, max_length=20)
    rate_limit_attempts: int | None = Field(default=None, ge=1, le=5)
    state_changes_allowed: bool | None = None


def _action(
    hypothesis: Hypothesis,
    *,
    method: str,
    account: str | None = None,
    owner: str | None = None,
    context: VerificationPlanningContext,
    mutation_type: str | None = None,
    technique: str | None = None,
    replay: bool = False,
    url: str | None = None,
    purpose: str | None = None,
    workflow_surface: str | None = None,
) -> dict[str, Any]:
    action = {
        "url": url or hypothesis.endpoint or hypothesis.target,
        "method": method,
        "category": hypothesis.category,
        "purpose": purpose
        or (
            "state_mutation"
            if hypothesis.state_changing or mutation_type is not None
            else "verification"
        ),
        "account_id": account,
        "object_owner_account_id": owner,
        "test_owned_resource": bool(context.test_owned_resources),
        "credential_reference_present": account in context.credential_accounts,
        "mutation_type": mutation_type,
        "side_effect_risk": hypothesis.risk.value,
        "technique": technique,
        "replay": replay,
    }
    if hypothesis.category in {
        "sql_injection",
        "command_injection",
        "path_traversal",
    }:
        action["parameter"] = hypothesis.parameter
        action["parameter_location"] = hypothesis.parameter_location
    if workflow_surface is not None:
        action["workflow_surface"] = workflow_surface
    return action


class VerificationPlanner:
    def create_plan(
        self, hypothesis: Hypothesis, context: VerificationPlanningContext
    ) -> VerificationPlan:
        accounts = list(dict.fromkeys(context.controlled_accounts))
        configured_acquisition_owner = next(
            (item for item in context.object_acquisition_owner_ids if item in accounts),
            None,
        )
        account_a = (
            context.resource_owner_account_id
            or configured_acquisition_owner
            or (accounts[0] if accounts else None)
        )
        account_b = next(
            (item for item in accounts if item != account_a),
            None,
        )
        requests: list[dict[str, Any]] = []
        expected_secure: list[str] = []
        expected_vulnerable: list[str] = []
        compare = [
            "status class",
            "response schema",
            "selected safe fields",
            "ownership metadata",
            "error semantics",
            "body structure hash",
        ]
        cleanup: list[str] = []
        mutations: list[dict[str, Any]] = []
        category = hypothesis.category
        capability = get_verification_capability(category)
        method = hypothesis.method
        related_surfaces = [
            item
            for item in hypothesis.metadata.get("related_surfaces", [])
            if isinstance(item, dict)
        ]
        related_by_type = {
            str(item.get("boundary_type") or ""): item for item in related_surfaces
        }

        def related_url(boundary_type: str) -> str:
            related = related_by_type.get(boundary_type) or {}
            path = str(related.get("path") or "")
            return (
                urljoin(hypothesis.target.rstrip("/") + "/", path.lstrip("/"))
                if path
                else hypothesis.endpoint or hypothesis.target
            )

        def related_method(boundary_type: str, fallback: str) -> str:
            related = related_by_type.get(boundary_type) or {}
            return str(related.get("method") or fallback).upper()

        if category in {"bola", "tenant_isolation"}:
            requests = [
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    owner=account_a,
                    context=context,
                ),
                _action(
                    hypothesis,
                    method="GET",
                    account=account_b,
                    owner=account_a,
                    context=context,
                ),
            ]
            expected_secure = [
                "The non-owner receives 403/404 or no protected object data."
            ]
            expected_vulnerable = [
                "The non-owner receives the owner's protected object with matching identity evidence."
            ]
        elif category == "vertical_authorization":
            ranked_accounts = [
                (role_privilege_rank(context.account_roles.get(item, "")), item)
                for item in accounts
            ]
            known_accounts = [
                (rank, item) for rank, item in ranked_accounts if rank is not None
            ]
            known_accounts.sort(key=lambda item: int(item[0] or 0), reverse=True)
            distinct_ranks = {rank for rank, _ in known_accounts}
            if len(known_accounts) >= 2 and len(distinct_ranks) >= 2:
                admin_account = known_accounts[0][1]
                normal_account = known_accounts[-1][1]
            else:
                admin_account = account_b
                normal_account = account_a
            requests = [
                _action(
                    hypothesis, method="GET", account=admin_account, context=context
                ),
                _action(
                    hypothesis, method="GET", account=normal_account, context=context
                ),
            ]
            expected_secure = [
                "The lower role receives a denial or sanitized public response."
            ]
            expected_vulnerable = [
                "The lower role receives protected administrative data or functionality."
            ]
        elif category == "authentication_enforcement":
            requests = [
                _action(hypothesis, method="GET", account=account_a, context=context),
                _action(hypothesis, method="GET", context=context),
            ]
            requests[0]["request_role"] = "authenticated_baseline"
            requests[1]["request_role"] = "unauthenticated_comparison"
            expected_secure = [
                "The unauthenticated response contains no protected data or action."
            ]
            expected_vulnerable = [
                "The unauthenticated response exposes protected data or functionality."
            ]
        elif category == "session_invalidation":
            workflow = SessionInvalidationWorkflow.from_hypothesis(hypothesis)
            requests = [
                _action(
                    hypothesis,
                    method=workflow.session_creation.method,
                    account=account_a,
                    context=context,
                    url=workflow.session_creation.url,
                    purpose="session_acquisition",
                    workflow_surface="session_creation",
                ),
                _action(
                    hypothesis,
                    method=workflow.authenticated_resource.method,
                    account=account_a,
                    context=context,
                    url=workflow.authenticated_resource.url,
                    purpose="verification",
                    workflow_surface="authenticated_resource",
                ),
                _action(
                    hypothesis,
                    method=workflow.session_termination.method,
                    account=account_a,
                    context=context,
                    mutation_type="controlled_session_termination",
                    url=workflow.session_termination.url,
                    purpose="session_termination",
                    workflow_surface="session_termination",
                ),
                _action(
                    hypothesis,
                    method=workflow.authenticated_resource.method,
                    account=account_a,
                    context=context,
                    replay=True,
                    url=workflow.authenticated_resource.url,
                    purpose="verification",
                    workflow_surface="authenticated_resource",
                ),
            ]
            requests[1]["request_role"] = "authenticated_baseline"
            expected_secure = [
                "The previously issued controlled session is rejected after termination and exposes no protected resource data."
            ]
            expected_vulnerable = [
                "The same previously issued controlled session retains access to the same protected resource after termination."
            ]
            cleanup = [
                "Discard the terminated controlled session and reacquire a fresh session only if further approved testing requires it."
            ]
        elif category == "jwt_enforcement":
            requests = [
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    context=context,
                    replay=True,
                ),
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    context=context,
                    replay=True,
                ),
            ]
            expected_secure = [
                "The expired, wrong-audience, or otherwise invalid controlled token is rejected."
            ]
            expected_vulnerable = [
                "The controlled invalid token retains protected access."
            ]
        elif category == "recovery_state_enforcement":
            requests = [
                _action(
                    hypothesis,
                    method=related_method("recovery_start", "POST"),
                    account=account_a,
                    context=context,
                    mutation_type="controlled_recovery_start",
                    url=related_url("recovery_start"),
                ),
                _action(
                    hypothesis,
                    method=related_method("recovery_completion", "POST"),
                    account=account_a,
                    context=context,
                    mutation_type="valid_controlled_recovery_completion",
                    url=related_url("recovery_completion"),
                ),
                _action(
                    hypothesis,
                    method=related_method("recovery_completion", "POST"),
                    account=account_a,
                    context=context,
                    mutation_type="reused_same_challenge_and_code",
                    url=related_url("recovery_completion"),
                ),
            ]
            expected_secure = [
                "Recovery completion accepts only the matching researcher-controlled issued state in the valid order and enforces one-time use."
            ]
            expected_vulnerable = [
                "The same runtime-issued challenge and legitimate code are accepted a second time and the separately approved comparison credential authenticates."
            ]
            cleanup = [
                "If no safe in-band restoration surface exists, stop after verification and require an external scoped account restore.",
                "Resume only to authenticate with the original vaulted credential and confirm restoration before promoting the classification.",
            ]
        elif category == "rate_limit_enforcement":
            requests = []
            compare = [
                "status class",
                "Retry-After presence and value class",
                "rate-limit header value classes",
                "error semantics",
                "body structure hash",
                "coarse deterministic latency bucket",
                "final valid-login behavior",
            ]
            expected_secure = [
                "The configured throttle-or-block control is observed within its explicitly approved bounded threshold."
            ]
            expected_vulnerable = [
                "Concrete deterministic bounded evidence shows the configured throttle-or-block control was not enforced within its declared threshold."
            ]
        elif category == "mass_assignment":
            requests = [
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    owner=account_a,
                    context=context,
                ),
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type="documented_field_probe",
                ),
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    owner=account_a,
                    context=context,
                ),
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type="restore_before_state",
                ),
                _action(
                    hypothesis,
                    method="GET",
                    account=account_a,
                    owner=account_a,
                    context=context,
                ),
            ]
            mutations = [
                {
                    "field": hypothesis.parameter,
                    "value_source": "approved_verification_input",
                }
            ]
            cleanup = [
                "Restore the exact recorded before-state and verify restoration."
            ]
            compare.append("state before/after")
            expected_secure = [
                "The server rejects or ignores the unauthorized documented field."
            ]
            expected_vulnerable = [
                "The server persists or honors the field and an independent read confirms it."
            ]
        elif category.startswith("graphql_"):
            gql_method = "POST"
            requests = [
                _action(
                    hypothesis,
                    method=gql_method,
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type=(
                        "captured_bounded_operation" if "mutation" in category else None
                    ),
                ),
                _action(
                    hypothesis,
                    method=gql_method,
                    account=account_b,
                    owner=account_a,
                    context=context,
                    mutation_type=(
                        "captured_bounded_operation" if "mutation" in category else None
                    ),
                ),
            ]
            expected_secure = [
                "GraphQL returns an authorization error or omits protected object/field data."
            ]
            expected_vulnerable = [
                "The lower/non-owner controlled identity receives protected object, field, or mutation behavior."
            ]
            if "mutation" in category:
                cleanup = ["Restore the test-owned GraphQL resource state."]
        elif category in {"sql_injection", "command_injection", "path_traversal"}:
            technique = category
            requests = [
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    context=context,
                    technique=technique,
                ),
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    context=context,
                    technique=technique,
                ),
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    context=context,
                    technique=technique,
                ),
            ]
            mutations = [
                {
                    "parameter": hypothesis.parameter,
                    "parameter_location": hypothesis.parameter_location,
                    "fixture": f"safe_{category}_canary",
                }
            ]
            expected_secure = [
                "Control and harmless probe preserve normal parser and boundary behavior."
            ]
            expected_vulnerable = [
                "Stable controls and non-reflected server-origin evidence prove the exact bound interpreter or resource-resolution behavior."
            ]
        elif category in {"file_upload_validation", "upload_ownership"}:
            requests = [
                _action(
                    hypothesis,
                    method="POST",
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type="benign_fixture_upload",
                ),
                _action(
                    hypothesis,
                    method="GET",
                    account=account_b,
                    owner=account_a,
                    context=context,
                ),
            ]
            mutations = [{"fixture": "inert text or image", "executable": False}]
            cleanup = [
                "Delete the test fixture through an approved non-automatic cleanup path."
            ]
            expected_secure = [
                "Validation follows policy and a non-owner cannot retrieve the fixture."
            ]
            expected_vulnerable = [
                "A documented validation rule is bypassed or a non-owner receives the fixture."
            ]
        elif category == "business_logic_state_enforcement":
            requests = [
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type="normal_transition",
                ),
                _action(
                    hypothesis,
                    method=method,
                    account=account_a,
                    owner=account_a,
                    context=context,
                    mutation_type="single_modified_transition",
                ),
            ]
            cleanup = ["Restore the controlled workflow to its recorded initial state."]
            expected_secure = [
                "The server rejects the skipped, duplicated, or invalid transition."
            ]
            expected_vulnerable = [
                "The server persists the invalid transition on a test-owned workflow."
            ]
        else:
            requests = [
                _action(hypothesis, method="GET", account=account_a, context=context)
            ]
            expected_secure = ["The response follows the documented security boundary."]
            expected_vulnerable = [
                "Protected behavior crosses the documented boundary with concrete evidence."
            ]

        if capability.capability_state is not CapabilityState.typed_verification:
            # Manual guidance can remain, but an unimplemented category never
            # receives a fake executable request sequence or mutation payload.
            requests = []
            mutations = []

        tool = (
            hypothesis.proposed_tools[0]
            if hypothesis.proposed_tools
            else "request_diff_engine"
        )
        request_cost = request_cost_for(
            category,
            rate_limit_attempts=(
                context.rate_limit_attempts
                if category == "rate_limit_enforcement"
                else None
            ),
        )
        support_reasons = capability_support_reasons(
            category,
            method=hypothesis.method,
            parameter=hypothesis.parameter,
            parameter_location=hypothesis.parameter_location,
            request_body_field=bool(hypothesis.metadata.get("request_body_field")),
            target_class=context.target_class,
        )
        required_opt_in_present = bool(
            capability.required_policy_opt_in is None
            or capability.required_policy_opt_in in context.policy_opt_ins
        )
        precondition_reasons: list[str] = []
        if len(accounts) < capability.required_account_count:
            precondition_reasons.append(
                "The required controlled-account count is not available."
            )
        if (
            capability.requires_credentials
            and len(set(context.credential_accounts) & set(accounts))
            < capability.required_account_count
        ):
            precondition_reasons.append(
                "The required controlled credential bindings are not available."
            )
        if capability.requires_test_owned_resource and not (
            context.test_owned_resources or context.object_acquisition_owner_ids
        ):
            precondition_reasons.append(
                "The required test-owned resource or acquisition binding is not available."
            )
        if (
            capability.requires_state_change_policy
            and context.state_changes_allowed is False
        ):
            precondition_reasons.append(
                "State-changing verification is disabled by the selected policy."
            )
        automatic_execution_allowed = bool(
            capability.automatic_execution
            and not support_reasons
            and not precondition_reasons
            and required_opt_in_present
            and not bool(hypothesis.metadata.get("typed_adapter_required"))
        )
        step = VerificationStep(
            step_id=stable_identifier("step", hypothesis.hypothesis_id, tool),
            name=f"Collect bounded {category} differential evidence",
            tool=tool,
            input_ref=str(hypothesis.metadata.get("request_id") or "") or None,
            prerequisites=list(hypothesis.required_context),
            risk=hypothesis.risk,
            network=bool(
                capability.capability_state is CapabilityState.typed_verification
                and capability.worst_case_requests
            ),
            method=(
                requests[0]["method"]
                if requests
                else (
                    method
                    if capability.capability_state is CapabilityState.typed_verification
                    else None
                )
            ),
            request_cost=request_cost,
            requires_credentials=capability.requires_credentials,
            state_changing=hypothesis.state_changing,
            test_owned_resource_required=capability.requires_test_owned_resource,
            cleanup_required=capability.cleanup_required,
            cleanup_steps=cleanup,
            expected_evidence=hypothesis.evidence_requirements,
            stop_conditions=[
                "policy denial",
                "request budget exhausted",
                "unexpected state change",
                "service instability",
                "sufficient classification evidence collected",
                *(
                    [
                        "unapproved credential, code, token, or recovery-state generation",
                        "account enumeration signal",
                    ]
                    if category == "recovery_state_enforcement"
                    else []
                ),
                *(
                    [
                        "bounded attempt policy absent",
                        "any request would exceed the explicit attempt ceiling",
                    ]
                    if category == "rate_limit_enforcement"
                    else []
                ),
            ],
            metadata={
                "category": category,
                "requests": requests,
                "capability_schema_version": CAPABILITY_SCHEMA_VERSION,
                "capability_state": capability.capability_state.value,
                "execution_status": (
                    "typed_verification_available"
                    if capability.capability_state is CapabilityState.typed_verification
                    else capability.capability_state.value
                ),
                "typed_adapter_required": (
                    capability.capability_state
                    is not CapabilityState.typed_verification
                ),
                "typed_executor_available": capability.executor_available,
                "executor_version": capability.executor_version,
                "min_requests": capability.min_requests,
                "worst_case_requests": capability.worst_case_requests,
                "runtime_narrowed_request_cost": request_cost,
                "capability_support_reasons": support_reasons,
                "capability_precondition_reasons": precondition_reasons,
                "policy_opt_in": (
                    required_opt_in_present
                    if capability.required_policy_opt_in is not None
                    else None
                ),
                "workflow_sequence": (
                    [
                        "controlled_session_acquisition",
                        "authenticated_baseline",
                        "configured_controlled_logout",
                        "same_previously_issued_session_replay",
                    ]
                    if category == "session_invalidation"
                    else (
                        [
                            "issue_controlled_recovery_challenge",
                            "pause_for_controlled_channel_evidence",
                            "resume_with_ordered_controlled_completion",
                            "reuse_same_challenge_and_code_once",
                            "authenticate_comparison_credential",
                            "external_cleanup_confirmation_if_required",
                        ]
                        if category == "recovery_state_enforcement"
                        else (
                            [
                                "one_valid_controlled_baseline_login",
                                "N_sequential_invalid_password_attempts_for_same_account",
                                "one_final_valid_login_with_original_credential",
                            ]
                            if category == "rate_limit_enforcement"
                            else []
                        )
                    )
                ),
                "session_binding": (
                    "same_controlled_session"
                    if category == "session_invalidation"
                    else None
                ),
                "request_accounting": (
                    {
                        "challenge_issuance_recovery_requests": 1,
                        "resume_recovery_completion_requests": 2,
                        "resume_authentication_state_confirmation_requests": 1,
                        "external_cleanup_verification_requests": 1,
                        "phase_a1_challenge_issuance_requests": 1,
                        "phase_a2_resume_requests": 3,
                        "phase_b_cleanup_confirmation_requests": 1,
                        "external_cleanup_may_be_required": True,
                    }
                    if category == "recovery_state_enforcement"
                    else (
                        {
                            "valid_baseline_auth_requests": 1,
                            "invalid_auth_requests": "N",
                            "final_valid_auth_requests": 1,
                            "total_network_requests": "N + 2",
                        }
                        if category == "rate_limit_enforcement"
                        else None
                    )
                ),
                "supported_mode": (
                    "authentication_login_rate_limit"
                    if category == "rate_limit_enforcement"
                    else None
                ),
                "bounded_rate_limit_policy_required": (
                    category == "rate_limit_enforcement"
                ),
                "configured_max_attempts": context.rate_limit_attempts,
                "hard_attempt_cap": (
                    MAX_RATE_LIMIT_ATTEMPTS
                    if category == "rate_limit_enforcement"
                    else None
                ),
                "brute_force": False if category == "rate_limit_enforcement" else None,
                "spraying": False if category == "rate_limit_enforcement" else None,
                "concurrency": 1 if category == "rate_limit_enforcement" else None,
                "automatic_execution_requires_typed_policy_opt_in": (
                    category == "rate_limit_enforcement"
                ),
            },
        )
        return VerificationPlan(
            plan_id=stable_identifier(
                "plan", hypothesis.hypothesis_id, context.profile
            ),
            hypothesis_id=hypothesis.hypothesis_id,
            target=hypothesis.endpoint or hypothesis.target,
            profile=context.profile,  # type: ignore[arg-type]
            steps=[step],
            request_budget=min(context.request_budget, request_cost),
            authorization_confirmed=True,
            credentials_supplied=bool(context.credential_accounts),
            controlled_accounts=accounts,
            test_owned_resources=context.test_owned_resources,
            test_owned_resources_required=capability.requires_test_owned_resource,
            objective=str(
                hypothesis.metadata.get("bounded_verification_objective")
                or f"Determine whether {hypothesis.title.lower()} using the minimum controlled evidence."
            ),
            prerequisites=list(hypothesis.required_context),
            mutations=mutations,
            expected_secure_behavior=expected_secure,
            expected_vulnerable_behavior=expected_vulnerable,
            evidence_to_compare=compare,
            cleanup=cleanup if capability.cleanup_required else [],
            side_effect_risk=hypothesis.risk,
            automatic_execution_allowed=automatic_execution_allowed,
            capability_schema_version=CAPABILITY_SCHEMA_VERSION,
            capability_state=capability.capability_state.value,
            typed_executor_available=capability.executor_available,
            executor_name=capability.executor_name,
            executor_version=capability.executor_version,
            input_schema=capability_metadata(category)["input_schema"],
            minimum_requests=capability.min_requests,
            worst_case_requests=request_cost,
            major_preconditions=[
                *capability_metadata(category)["major_preconditions"],
                *support_reasons,
                *precondition_reasons,
            ],
        )
