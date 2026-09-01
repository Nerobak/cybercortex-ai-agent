"""Fail-closed runtime identity binding for reusable verification templates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

from agent_core.agent_models import Hypothesis, VerificationPlan
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    SessionAcquisition,
    SUPPORTED_LOGIN_IDENTITY_FIELDS,
    resolve_controlled_login_identity,
    role_privilege_rank,
)
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy
from agent_core.rate_limit_enforcement import AuthenticationLoginRateLimitWorkflow
from agent_core.session_invalidation import SessionInvalidationWorkflow

RUNTIME_BOUND_AUTHORIZATION_CATEGORIES = frozenset(
    {
        "authentication_enforcement",
        "bola",
        "tenant_isolation",
        "vertical_authorization",
        "mass_assignment",
        "rate_limit_enforcement",
        "recovery_state_enforcement",
        "session_invalidation",
    }
)

RUNTIME_REQUIRED_ACCOUNTS = {
    "authentication_enforcement": 1,
    "bola": 2,
    "tenant_isolation": 2,
    "vertical_authorization": 2,
    "mass_assignment": 1,
    "rate_limit_enforcement": 1,
    "recovery_state_enforcement": 1,
    "session_invalidation": 1,
}


@dataclass(frozen=True)
class RuntimeBindingResult:
    """A process-local plan copy plus secret-free binding diagnostics."""

    plan: VerificationPlan | None
    diagnostics: dict[str, int | bool]
    reasons: list[str]

    @property
    def succeeded(self) -> bool:
        return self.plan is not None and not self.reasons


def empty_runtime_binding(hypothesis: Hypothesis) -> dict[str, int | bool]:
    required = RUNTIME_REQUIRED_ACCOUNTS.get(hypothesis.category, 0)
    return {
        "required_accounts": required,
        "bound_accounts": 0,
        "owner_bound": False,
        "comparator_bound": False,
        "policy_authorized": False,
    }


def bind_runtime_accounts(
    hypothesis: Hypothesis,
    plan: VerificationPlan,
    context: ControlledContext,
    policy: AssessmentPolicy,
    vault: CredentialVault | None = None,
) -> RuntimeBindingResult:
    """Bind controlled authorization identities into a runtime copy of ``plan``."""
    diagnostics = empty_runtime_binding(hypothesis)
    runtime_plan = plan.model_copy(deep=True)
    if hypothesis.category not in RUNTIME_BOUND_AUTHORIZATION_CATEGORIES:
        return RuntimeBindingResult(runtime_plan, diagnostics, [])

    account_ids = [account.account_id for account in context.accounts]
    if len(account_ids) != len(set(account_ids)):
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Duplicate controlled account identifiers are not permitted."],
        )

    controlled = [account for account in context.accounts if account.controlled]
    eligible = [
        account
        for account in context.accounts
        if policy.account_is_eligible(account.account_id, context).eligible
    ]

    if hypothesis.category == "authentication_enforcement":
        return _bind_authentication_enforcement(
            hypothesis,
            runtime_plan,
            context,
            eligible,
            vault,
            diagnostics,
        )

    if hypothesis.category == "session_invalidation":
        return _bind_session_invalidation(
            hypothesis,
            runtime_plan,
            context,
            controlled,
            eligible,
            vault,
            diagnostics,
        )

    if hypothesis.category == "recovery_state_enforcement":
        return _bind_recovery_state_enforcement(
            hypothesis,
            runtime_plan,
            context,
            controlled,
            eligible,
            vault,
            diagnostics,
        )

    if hypothesis.category == "rate_limit_enforcement":
        return _bind_rate_limit_enforcement(
            hypothesis,
            runtime_plan,
            context,
            controlled,
            eligible,
            vault,
            diagnostics,
        )

    if hypothesis.category == "vertical_authorization":
        return _bind_vertical_authorization(
            hypothesis,
            runtime_plan,
            context,
            eligible,
            diagnostics,
        )

    if hypothesis.category == "tenant_isolation":
        return _bind_tenant_isolation(
            runtime_plan,
            context,
            eligible,
            diagnostics,
        )

    if hypothesis.category == "mass_assignment":
        return _bind_mass_assignment(
            hypothesis,
            runtime_plan,
            context,
            eligible,
            vault,
            diagnostics,
        )

    configured_owners = list(
        dict.fromkeys(item.owner_account_id for item in context.object_acquisition)
    )
    if len(configured_owners) > 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["BOLA runtime binding found multiple configured acquisition owners."],
        )

    owner: ControlledAccount | None = None
    if configured_owners:
        configured_owner = configured_owners[0]
        owner = next(
            (
                account
                for account in controlled
                if account.account_id == configured_owner
            ),
            None,
        )
        if owner is None:
            return RuntimeBindingResult(
                None,
                diagnostics,
                ["The configured acquisition owner is not a controlled account."],
            )
        if not policy.account_is_eligible(owner.account_id, context).eligible:
            return RuntimeBindingResult(
                None,
                diagnostics,
                ["The configured acquisition owner is not allowed by policy."],
            )
    else:
        existing_owner_ids = {
            item.owner_account_id for item in context.objects if item.test_owned
        }
        owner = next(
            (
                account
                for account in eligible
                if account.account_id in existing_owner_ids
            ),
            None,
        )
        if owner is None:
            planned_owner_ids = _planned_owner_ids(runtime_plan)
            owner = next(
                (
                    account
                    for account in eligible
                    if account.account_id in planned_owner_ids
                ),
                None,
            )
        if owner is None and eligible:
            owner = eligible[0]

    if owner is not None:
        diagnostics["bound_accounts"] = 1
        diagnostics["owner_bound"] = True
    comparator = next(
        (
            account
            for account in eligible
            if owner is not None and account.account_id != owner.account_id
        ),
        None,
    )
    if owner is None or comparator is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Two distinct controlled accounts explicitly permitted by policy are required."
            ],
        )

    diagnostics.update(
        {
            "bound_accounts": 2,
            "owner_bound": True,
            "comparator_bound": True,
        }
    )
    requests = _authorization_requests(runtime_plan, hypothesis.category)
    if len(requests) != 2:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["A BOLA runtime plan must contain exactly two comparison actions."],
        )

    owner_objects = [
        item.object_id
        for item in context.objects
        if item.test_owned and item.owner_account_id == owner.account_id
    ]
    runtime_plan.controlled_accounts = [owner.account_id, comparator.account_id]
    runtime_plan.test_owned_resources = owner_objects
    runtime_plan.credentials_supplied = all(
        _has_credential_material(account, context, vault)
        for account in (owner, comparator)
    )
    for index, request in enumerate(requests):
        account = owner if index == 0 else comparator
        request["account_id"] = account.account_id
        request["object_owner_account_id"] = owner.account_id
        request["test_owned_resource"] = bool(owner_objects)
        request["credential_reference_present"] = bool(
            account.session_reference or account.credential_references.get("token")
        )
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _planned_owner_ids(plan: VerificationPlan) -> set[str]:
    return {
        str(request["object_owner_account_id"])
        for step in plan.steps
        for request in (step.metadata.get("requests") or [])
        if isinstance(request, dict) and request.get("object_owner_account_id")
    }


def _authorization_requests(
    plan: VerificationPlan, category: str
) -> list[dict[str, Any]]:
    return [
        request
        for step in plan.steps
        if step.metadata.get("category") == category
        for request in (step.metadata.get("requests") or [])
        if isinstance(request, dict)
    ]


def _strip_request_credentials(request: dict[str, Any]) -> None:
    """Remove reusable-template credential material before assigning a role."""
    request.pop("headers", None)
    for key in list(request):
        normalized = str(key).strip().lower()
        if key == "headers":
            continue
        if normalized in {
            "credential_reference",
            "credential_references",
            "session_reference",
            "token_reference",
        }:
            request.pop(key, None)


def _bind_rate_limit_enforcement(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    controlled: list[ControlledAccount],
    eligible: list[ControlledAccount],
    vault: CredentialVault | None,
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind one credentialed controlled account to one classified login POST."""
    try:
        workflow = AuthenticationLoginRateLimitWorkflow.from_hypothesis(hypothesis)
    except ValueError:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The rate-limit hypothesis is not a supported classified login surface."],
        )
    plan_reasons = workflow.validate_plan(hypothesis, runtime_plan)
    if plan_reasons:
        return RuntimeBindingResult(None, diagnostics, plan_reasons)
    if len(controlled) != 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Login rate-limit verification requires exactly one controlled account."],
        )
    account = controlled[0]
    if account not in eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled account is not eligible under the selected policy."],
        )
    config = context.session_acquisition
    if config is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Configured session acquisition is required for login rate-limit verification."
            ],
        )
    if config.url != workflow.surface.url or config.method != workflow.surface.method:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Configured session acquisition does not exactly match the classified login surface."
            ],
        )
    credential_reasons = _controlled_login_credential_reasons(account, config, vault)
    if credential_reasons:
        return RuntimeBindingResult(
            None,
            diagnostics,
            credential_reasons,
        )
    runtime_plan.controlled_accounts = [account.account_id]
    runtime_plan.test_owned_resources = []
    runtime_plan.credentials_supplied = True
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _bind_recovery_state_enforcement(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    controlled: list[ControlledAccount],
    eligible: list[ControlledAccount],
    vault: CredentialVault | None,
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind exactly one policy-approved recovery account with original state."""
    from agent_core.recovery_state_enforcement import RecoveryWorkflow

    try:
        workflow = RecoveryWorkflow.from_hypothesis(hypothesis)
    except ValueError:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Recovery workflow metadata is incomplete or ambiguous."],
        )
    requests, plan_reasons = workflow.validate_plan(hypothesis, runtime_plan)
    if requests is None:
        return RuntimeBindingResult(None, diagnostics, plan_reasons)
    if len(controlled) != 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Recovery verification requires exactly one controlled account."],
        )
    account = controlled[0]
    if account not in eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled account is not eligible under the selected policy."],
        )
    if context.session_acquisition is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled login is required to confirm credential state."],
        )
    credential_reasons = _controlled_login_credential_reasons(
        account, context.session_acquisition, vault
    )
    if credential_reasons:
        return RuntimeBindingResult(
            None,
            diagnostics,
            credential_reasons,
        )
    for request in requests:
        _strip_request_credentials(request)
        request["account_id"] = account.account_id
        request["object_owner_account_id"] = None
        request["test_owned_resource"] = False
        request["credential_reference_present"] = False
    runtime_plan.controlled_accounts = [account.account_id]
    runtime_plan.test_owned_resources = []
    runtime_plan.credentials_supplied = True
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _bind_session_invalidation(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    controlled: list[ControlledAccount],
    eligible: list[ControlledAccount],
    vault: CredentialVault | None,
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind exactly one acquisition-capable account to an exact typed workflow."""
    try:
        workflow = SessionInvalidationWorkflow.from_hypothesis(hypothesis)
    except ValueError:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Session-invalidation workflow metadata is incomplete or ambiguous."],
        )
    requests, plan_reasons = workflow.validate_plan(hypothesis, runtime_plan)
    if requests is None:
        return RuntimeBindingResult(None, diagnostics, plan_reasons)
    if len(controlled) != 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Session invalidation requires exactly one controlled account."],
        )
    account = controlled[0]
    if account not in eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled account is not eligible under the selected policy."],
        )
    config = context.session_acquisition
    if config is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled session acquisition is not configured."],
        )
    if (
        config.url != workflow.session_creation.url
        or config.method != workflow.session_creation.method
    ):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Configured session acquisition does not exactly match the typed session-creation surface."
            ],
        )
    credential_reasons = _controlled_login_credential_reasons(account, config, vault)
    if credential_reasons:
        return RuntimeBindingResult(
            None,
            diagnostics,
            credential_reasons,
        )
    for request in requests:
        _strip_request_credentials(request)
        request["account_id"] = account.account_id
        request["object_owner_account_id"] = None
        request["test_owned_resource"] = False
        request["credential_reference_present"] = False
    runtime_plan.controlled_accounts = [account.account_id]
    runtime_plan.test_owned_resources = []
    runtime_plan.credentials_supplied = True
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _bind_authentication_enforcement(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    eligible: list[ControlledAccount],
    vault: CredentialVault | None,
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind one controlled subject to an authenticated/anonymous comparison."""
    expected_url = hypothesis.endpoint or hypothesis.target
    requests = _authorization_requests(runtime_plan, "authentication_enforcement")
    all_requests = [
        request
        for step in runtime_plan.steps
        for request in (step.metadata.get("requests") or [])
        if isinstance(request, dict)
    ]
    if (
        len(requests) != 2
        or len(all_requests) != 2
        or hypothesis.method != "GET"
        or any(
            str(request.get("method") or "").upper() != "GET"
            or request.get("url") != expected_url
            for request in requests
        )
    ):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Authentication enforcement requires exactly two GET requests against the unchanged planned endpoint."
            ],
        )

    if not eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Authentication enforcement requires a controlled account authorized by policy."
            ],
        )
    credentialed = [
        account
        for account in eligible
        if _has_credential_material(account, context, vault)
    ]
    if not credentialed:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "The policy-authorized controlled account has no usable session or configured login credentials."
            ],
        )

    planned_ids = [
        str(request["account_id"])
        for request in requests
        if request.get("account_id") is not None
    ]
    subject = next(
        (account for account in credentialed if account.account_id in planned_ids),
        credentialed[0],
    )
    authenticated, anonymous = requests
    for request in requests:
        _strip_request_credentials(request)
        request["object_owner_account_id"] = None
        request["test_owned_resource"] = False

    authenticated.update(
        {
            "account_id": subject.account_id,
            "credential_reference_present": bool(
                subject.session_reference or subject.credential_references.get("token")
            ),
            "request_role": "authenticated_baseline",
        }
    )
    anonymous.update(
        {
            "account_id": None,
            "credential_reference_present": False,
            "request_role": "unauthenticated_comparison",
        }
    )
    runtime_plan.controlled_accounts = [subject.account_id]
    runtime_plan.test_owned_resources = []
    runtime_plan.credentials_supplied = True
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _normalized_resource_path(value: str) -> tuple[str, ...] | None:
    """Normalize an absolute URL or context resource ID into safe path segments."""
    raw = str(value).strip()
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"/{raw.lstrip('/')}")
    if parsed.query or parsed.fragment or parsed.params:
        return None
    decoded_path = unquote(parsed.path)
    stripped_path = decoded_path.strip("/")
    if (
        decoded_path != parsed.path
        or "\\" in decoded_path
        or not stripped_path
        or "//" in stripped_path
    ):
        return None
    segments = tuple(stripped_path.split("/"))
    if not segments or any(
        segment != segment.strip()
        or segment in {".", ".."}
        or "{" in segment
        or "}" in segment
        for segment in segments
    ):
        return None
    return segments


def own_resource_url_matches(url: str, object_id: str) -> bool:
    """Match a planned own-resource URL to an explicit context resource path."""
    route = _normalized_resource_path(url)
    resource = _normalized_resource_path(object_id)
    if route is None or resource is None:
        return False
    if len(resource) == 1:
        return route == resource
    return len(route) >= len(resource) and route[-len(resource) :] == resource


def _bind_mass_assignment(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    eligible: list[ControlledAccount],
    vault: CredentialVault | None,
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind one controlled identity to one explicit own-resource state machine."""
    expected_url = hypothesis.endpoint or hypothesis.target
    requests = _authorization_requests(runtime_plan, "mass_assignment")
    all_requests = [
        request
        for step in runtime_plan.steps
        for request in (step.metadata.get("requests") or [])
        if isinstance(request, dict)
    ]
    expected_methods = ["GET", "PATCH", "GET", "PATCH", "GET"]
    expected_mutations = [
        None,
        "documented_field_probe",
        None,
        "restore_before_state",
        None,
    ]
    if (
        len(requests) != 5
        or len(all_requests) != 5
        or runtime_plan.target != expected_url
        or hypothesis.method != "PATCH"
        or any(
            str(request.get("method") or "").upper() != method
            or request.get("mutation_type") != mutation_type
            or request.get("url") != expected_url
            for request, method, mutation_type in zip(
                requests, expected_methods, expected_mutations, strict=True
            )
        )
    ):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "A mass-assignment runtime plan must contain exactly GET, PATCH, GET, PATCH, GET against one unchanged planned resource."
            ],
        )

    matching_resources = [
        item
        for item in context.objects
        if own_resource_url_matches(expected_url, item.object_id)
    ]
    if not matching_resources:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Mass-assignment runtime binding requires an explicit context resource matching the planned own-resource path."
            ],
        )
    test_owned_resources = [item for item in matching_resources if item.test_owned]
    if not test_owned_resources:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The matching own-resource state must be explicitly test-owned."],
        )

    owner_ids = {item.owner_account_id for item in test_owned_resources}
    if len(owner_ids) != 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Mass-assignment own-resource ownership must resolve to exactly one controlled account."
            ],
        )
    owner_id = next(iter(owner_ids))
    owner = next(
        (account for account in context.accounts if account.account_id == owner_id),
        None,
    )
    if owner is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The matching own-resource owner is not a controlled account."],
        )
    if owner not in eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Controlled account is not eligible under the selected policy; the matching own-resource account is not authorized by policy."
            ],
        )
    if not _has_credential_material(owner, context, vault):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "The matching own-resource account has no available controlled session or login credential references."
            ],
        )

    selected_resource = sorted(
        test_owned_resources,
        key=lambda item: (item.object_id, item.object_type, item.owner_account_id),
    )[0]
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})
    runtime_plan.controlled_accounts = [owner.account_id]
    runtime_plan.test_owned_resources = [selected_resource.object_id]
    runtime_plan.credentials_supplied = True
    credential_reference_present = bool(
        owner.session_reference or owner.credential_references.get("token")
    )
    for request in requests:
        request["account_id"] = owner.account_id
        request["object_owner_account_id"] = owner.account_id
        request["test_owned_resource"] = True
        request["credential_reference_present"] = credential_reference_present
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _bind_vertical_authorization(
    hypothesis: Hypothesis,
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    eligible: list[ControlledAccount],
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind one explicit higher role and one explicit lower role."""
    if len(eligible) != 2:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Exactly two distinct controlled accounts explicitly permitted by policy are required."
            ],
        )

    ranked = [(role_privilege_rank(account.role), account) for account in eligible]
    if any(rank is None for rank, _ in ranked):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Vertical authorization requires explicit, recognized role metadata for both controlled accounts."
            ],
        )
    if ranked[0][0] == ranked[1][0]:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Vertical authorization requires two controlled accounts at distinct privilege levels."
            ],
        )

    ordered = sorted(ranked, key=lambda item: int(item[0] or 0), reverse=True)
    privileged = ordered[0][1]
    lower_privileged = ordered[1][1]
    requests = _authorization_requests(runtime_plan, "vertical_authorization")
    all_requests = [
        request
        for step in runtime_plan.steps
        for request in (step.metadata.get("requests") or [])
        if isinstance(request, dict)
    ]
    expected_url = hypothesis.endpoint or hypothesis.target
    if len(requests) != 2 or len(all_requests) != 2:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "A vertical-authorization runtime plan must contain exactly two comparison actions."
            ],
        )
    if hypothesis.method != "GET" or any(
        str(request.get("method") or "").upper() != "GET"
        or request.get("url") != expected_url
        for request in requests
    ):
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Vertical authorization permits only two GET comparisons against the exact planned endpoint."
            ],
        )

    diagnostics.update(
        {
            "bound_accounts": 2,
            # Retain the generic owner/comparator diagnostics for stored-result
            # and report compatibility. Here, owner means privileged baseline.
            "owner_bound": True,
            "comparator_bound": True,
        }
    )
    runtime_plan.controlled_accounts = [
        privileged.account_id,
        lower_privileged.account_id,
    ]
    runtime_plan.test_owned_resources = []
    runtime_plan.credentials_supplied = all(
        _has_credential_material(account, context, None)
        for account in (privileged, lower_privileged)
    )
    for request, account in zip(requests, (privileged, lower_privileged), strict=True):
        request["account_id"] = account.account_id
        request["object_owner_account_id"] = None
        request["test_owned_resource"] = False
        request["credential_reference_present"] = bool(
            account.session_reference or account.credential_references.get("token")
        )
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def _bind_tenant_isolation(
    runtime_plan: VerificationPlan,
    context: ControlledContext,
    eligible: list[ControlledAccount],
    diagnostics: dict[str, int | bool],
) -> RuntimeBindingResult:
    """Bind one controlled tenant owner and one cross-tenant comparator."""
    tenant_objects = [
        item for item in context.objects if item.object_type.strip().lower() == "tenant"
    ]
    if len(tenant_objects) > 1:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Tenant runtime binding requires exactly one supplied tenant object."],
        )

    controlled_object: ControlledObject | None = (
        tenant_objects[0] if tenant_objects else None
    )
    if controlled_object is not None and not controlled_object.test_owned:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The supplied tenant object must be explicitly test-owned."],
        )

    if controlled_object is not None:
        owner_account_id = controlled_object.owner_account_id
    else:
        acquisition_owners = list(
            dict.fromkeys(item.owner_account_id for item in context.object_acquisition)
        )
        if len(acquisition_owners) != 1:
            return RuntimeBindingResult(
                None,
                diagnostics,
                [
                    "A supplied test-owned tenant object or one unambiguous controlled acquisition owner is required."
                ],
            )
        owner_account_id = acquisition_owners[0]

    owner = next(
        (
            account
            for account in context.accounts
            if account.account_id == owner_account_id
        ),
        None,
    )
    if owner is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The tenant object's owner is not a controlled account."],
        )
    if not owner.tenant_id:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The controlled tenant owner is missing tenant metadata."],
        )
    if controlled_object is not None:
        object_reasons = tenant_object_binding_reasons(controlled_object, owner)
        if object_reasons:
            return RuntimeBindingResult(None, diagnostics, object_reasons)

    if owner not in eligible:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Controlled account is not eligible under the selected policy."],
        )
    diagnostics.update({"bound_accounts": 1, "owner_bound": True})

    if len(eligible) != 2:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "Exactly two distinct controlled accounts explicitly permitted by policy are required."
            ],
        )
    comparator = next(
        (account for account in eligible if account.account_id != owner.account_id),
        None,
    )
    if comparator is None:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["A distinct controlled tenant comparator is required."],
        )
    if not comparator.tenant_id:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["The controlled tenant comparator is missing tenant metadata."],
        )
    if comparator.tenant_id == owner.tenant_id:
        return RuntimeBindingResult(
            None,
            diagnostics,
            ["Tenant isolation requires controlled accounts in distinct tenants."],
        )

    diagnostics.update(
        {
            "bound_accounts": 2,
            "owner_bound": True,
            "comparator_bound": True,
        }
    )
    requests = _authorization_requests(runtime_plan, "tenant_isolation")
    if len(requests) != 2:
        return RuntimeBindingResult(
            None,
            diagnostics,
            [
                "A tenant-isolation runtime plan must contain exactly two comparison actions."
            ],
        )

    owner_objects = (
        [controlled_object.object_id] if controlled_object is not None else []
    )
    runtime_plan.controlled_accounts = [owner.account_id, comparator.account_id]
    runtime_plan.test_owned_resources = owner_objects
    runtime_plan.credentials_supplied = all(
        _has_credential_material(account, context, None)
        for account in (owner, comparator)
    )
    for index, request in enumerate(requests):
        account = owner if index == 0 else comparator
        request["account_id"] = account.account_id
        request["object_owner_account_id"] = owner.account_id
        request["test_owned_resource"] = bool(owner_objects)
        request["credential_reference_present"] = bool(
            account.session_reference or account.credential_references.get("token")
        )
    return RuntimeBindingResult(runtime_plan, diagnostics, [])


def tenant_object_binding_reasons(
    controlled_object: ControlledObject, owner: ControlledAccount
) -> list[str]:
    """Validate fail-closed tenant ownership metadata without using secrets."""
    reasons: list[str] = []
    if not controlled_object.test_owned:
        reasons.append("The supplied tenant object must be explicitly test-owned.")
    if not controlled_object.tenant_id:
        reasons.append("The supplied tenant object is missing tenant metadata.")
    if not owner.tenant_id:
        reasons.append("The controlled tenant owner is missing tenant metadata.")
    if (
        controlled_object.tenant_id
        and owner.tenant_id
        and controlled_object.tenant_id != owner.tenant_id
    ):
        reasons.append("The supplied object's tenant does not match its owner tenant.")
    if (
        controlled_object.object_type.strip().lower() == "tenant"
        and controlled_object.tenant_id
        and controlled_object.object_id != controlled_object.tenant_id
    ):
        reasons.append(
            "The supplied tenant object's identity does not match its tenant."
        )
    return reasons


def _has_credential_material(
    account: ControlledAccount,
    context: ControlledContext,
    vault: CredentialVault | None,
) -> bool:
    reference = account.session_reference or account.credential_references.get("token")
    if reference:
        if vault is None:
            return True
        try:
            return vault.contains(reference)
        except RuntimeError:
            return False
    config = context.session_acquisition
    if config is None:
        return False
    if vault is None:
        return bool(account.credential_references.get("password"))
    return not _controlled_login_credential_reasons(account, config, vault)


def _controlled_login_credential_reasons(
    account: ControlledAccount,
    config: SessionAcquisition,
    vault: CredentialVault | None,
) -> list[str]:
    """Use the canonical resolver for every executable login-capability check."""

    if config.username_field.strip().casefold() not in SUPPORTED_LOGIN_IDENTITY_FIELDS:
        return ["Unsupported session-acquisition identity field."]
    password_reference = account.credential_references.get("password")
    if vault is None:
        return (
            []
            if password_reference
            else [
                "Controlled login password is unavailable; a vaulted password is required."
            ]
        )
    identity = resolve_controlled_login_identity(account, config, vault)
    reasons = [identity.reason] if identity.reason else []
    if not password_reference:
        reasons.append(
            "Controlled login password is unavailable; a vaulted password is required."
        )
    else:
        try:
            if not vault.contains(password_reference):
                reasons.append(
                    "Controlled login password reference is unavailable in the credential vault."
                )
        except RuntimeError:
            reasons.append(
                "Controlled login password reference is unavailable in the credential vault."
            )
    return list(dict.fromkeys(reason for reason in reasons if reason))
