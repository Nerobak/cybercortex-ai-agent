"""Canonical Phase 2 public evidence and read-only capability packaging."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_core.reasoning.types import (
    CapabilityCatalog,
    CapabilityCatalogEntry,
    EvidencePacket,
    ModelBudgetContext,
    PolicyReasoningConstraints,
    PreviousReasoningDecision,
    PriorVerificationOutcome,
    ReasoningRequest,
    ReasoningTaskType,
    RequestAccountingSummary,
)
from agent_core.result_normalizer import public_result, sanitize_text
from agent_core.verification_capabilities import (
    CAPABILITY_REGISTRY,
    CAPABILITY_SCHEMA_VERSION,
    CapabilityState,
    capability_metadata,
)


def _mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        value = value.model_dump(mode="python")
    if not isinstance(value, Mapping):
        raise ValueError("Phase 2 reasoning evidence must be a mapping")
    safe = public_result(dict(value))
    if not isinstance(safe, dict):
        raise ValueError("Phase 2 reasoning evidence did not normalize to an object")
    return safe


def build_capability_catalog() -> CapabilityCatalog:
    """Project immutable, non-invocable metadata from the Phase 2 registry."""

    entries: list[CapabilityCatalogEntry] = []
    for category in sorted(CAPABILITY_REGISTRY):
        capability = CAPABILITY_REGISTRY[category]
        metadata = capability_metadata(category)
        entries.append(
            CapabilityCatalogEntry(
                category=category,
                capability_state=capability.capability_state.value,
                typed_executor_available=bool(metadata["typed_executor_available"]),
                input_schema_identifier=metadata["input_schema"],
                executor_version=capability.executor_version,
                min_requests=capability.min_requests,
                worst_case_requests=capability.worst_case_requests,
                major_preconditions=tuple(metadata["major_preconditions"]),
                automatic_execution_supported=bool(
                    capability.capability_state is CapabilityState.typed_verification
                    and metadata["automatic_execution_allowed"]
                ),
            )
        )
    return CapabilityCatalog(
        schema_version=CAPABILITY_SCHEMA_VERSION,
        entries=tuple(entries),
    )


def _request_accounting(result: Mapping[str, Any]) -> RequestAccountingSummary:
    raw_delta = result.get("request_delta")
    if isinstance(raw_delta, Mapping):
        fields = {
            f"{name}_requests": raw_delta.get(name, 0)
            for name in ("discovery", "auth", "verification", "cleanup")
        }
        fields["attempted_requests"] = raw_delta.get("attempted", 0)
        fields["total_requests"] = raw_delta.get("total", 0)
        if all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in fields.values()
        ):
            try:
                return RequestAccountingSummary(
                    **fields,
                    source="request_delta_v1",
                )
            except ValueError:
                pass
    legacy = result.get("requests_used")
    if isinstance(legacy, int) and not isinstance(legacy, bool) and legacy >= 0:
        return RequestAccountingSummary(
            attempted_requests=legacy,
            total_requests=legacy,
            source="legacy_total",
        )
    return RequestAccountingSummary()


def build_prior_verification_outcome(value: Any) -> PriorVerificationOutcome:
    result = _mapping(value)
    status = result.get("status")
    reasons = result.get("reasons") or result.get("evidence_summary") or ()
    if not isinstance(status, str):
        raise ValueError("Prior verification result requires a public status")
    if not isinstance(reasons, (list, tuple)) or not all(
        isinstance(item, str) for item in reasons
    ):
        raise ValueError("Prior verification reasons must be public strings")
    return PriorVerificationOutcome(
        status=status,
        reasons=tuple(reasons),
        request_accounting=_request_accounting(result),
    )


def build_evidence_packet(
    hypothesis: Any,
    *,
    verification_plan: Any = None,
    prior_verification: Any = None,
    catalog: CapabilityCatalog | None = None,
) -> EvidencePacket:
    """Reduce one hypothesis and optional result to canonical public evidence."""

    safe = _mapping(hypothesis)
    category = str(safe.get("category") or "")
    capabilities = catalog or build_capability_catalog()
    capability = capabilities.entry(category)
    if capability is None:
        raise ValueError("Hypothesis category is absent from Phase 2 capabilities")

    plan: dict[str, Any] = {}
    if verification_plan is not None:
        plan = _mapping(verification_plan)
        if plan.get("hypothesis_id") != safe.get("hypothesis_id"):
            raise ValueError("Verification plan does not match the hypothesis")
        if not isinstance(plan.get("automatic_execution_allowed", False), bool):
            raise ValueError("Verification plan execution flag must be a boolean")

    prior = (
        build_prior_verification_outcome(prior_verification)
        if prior_verification is not None
        else None
    )
    target_surface = safe.get("target_surface") or {}
    evidence_basis = safe.get("evidence_basis") or ()
    if not isinstance(target_surface, dict) or not isinstance(
        evidence_basis, (list, tuple)
    ):
        raise ValueError("Hypothesis evidence structure is malformed")

    def text(value: Any, default: str) -> str:
        normalized = sanitize_text(str(value or default))
        return normalized[:1000]

    def text_tuple(value: Any) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(
            sanitize_text(item)[:1000] for item in value if isinstance(item, str)
        )

    return EvidencePacket(
        hypothesis_id=str(safe.get("hypothesis_id") or ""),
        category=category,
        title=text(safe.get("title"), "Untitled hypothesis"),
        rationale=text(
            safe.get("rationale"), "No additional hypothesis rationale was supplied."
        ),
        confidence=str(safe.get("confidence") or "low"),
        priority=safe.get("priority", 0),
        target_surface=target_surface,
        evidence_basis=tuple(evidence_basis),
        evidence_references=text_tuple(safe.get("evidence_refs")),
        required_context=text_tuple(safe.get("required_context")),
        limitations=text_tuple(safe.get("limitations")),
        capability_state=capability.capability_state,
        typed_executor_available=capability.typed_executor_available,
        min_requests=capability.min_requests,
        worst_case_requests=capability.worst_case_requests,
        plan_policy_decision=plan.get("policy_decision"),
        plan_automatic_execution_allowed=plan.get("automatic_execution_allowed", False),
        prior_verification=prior,
    )


def build_reasoning_request(
    *,
    task_type: ReasoningTaskType | str,
    run_id: str,
    target_reference: str,
    hypotheses: Iterable[Any],
    policy_constraints: PolicyReasoningConstraints,
    verification_plans: Mapping[str, Any] | None = None,
    prior_results: Mapping[str, Any] | None = None,
    previous_decisions: tuple[PreviousReasoningDecision, ...] = (),
    model_budget_context: ModelBudgetContext | None = None,
) -> ReasoningRequest:
    """Build a strict reasoning request without retaining raw Phase 2 objects."""

    catalog = build_capability_catalog()
    plans = verification_plans or {}
    results = prior_results or {}
    packets: list[EvidencePacket] = []
    for hypothesis in hypotheses:
        safe = _mapping(hypothesis)
        hypothesis_id = str(safe.get("hypothesis_id") or "")
        packets.append(
            build_evidence_packet(
                safe,
                verification_plan=plans.get(hypothesis_id),
                prior_verification=results.get(hypothesis_id),
                catalog=catalog,
            )
        )
    return ReasoningRequest(
        task_type=task_type,
        run_id=run_id,
        target_reference=target_reference,
        evidence_packets=tuple(packets),
        capability_catalog=catalog,
        policy_constraints=policy_constraints,
        previous_decisions=previous_decisions,
        model_budget_context=model_budget_context or ModelBudgetContext(),
    )
