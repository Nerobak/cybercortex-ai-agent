"""Versioned canonical material configuration identity for evaluation runs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from pydantic import Field, JsonValue, StrictInt, model_validator

from agent_core.consensus import CONSENSUS_SCHEMA_VERSION
from agent_core.model_evaluation.types import (
    ConfigurationFingerprintSchema,
    EvaluationCase,
    EvaluationSubject,
    EvaluationSubjectType,
    EVALUATION_SCHEMA_VERSION,
    FINGERPRINT_SCHEMA_VERSION,
)
from agent_core.models import ModelPricingCatalog, ModelRoutingPolicy
from agent_core.models.types import ModelContract
from agent_core.reasoning import REASONING_SCHEMA_VERSION
from agent_core.result_normalizer import public_result

_TEMPORARY_PATH = re.compile(
    r"(?:(?:/private)?/tmp/|/private/var/folders/|/var/folders/)\S+|"
    r"[A-Za-z]:\\(?:Temp|TMP)\\\S+",
    re.IGNORECASE,
)


class MaterialConfigurationFingerprintSource(ModelContract):
    """Persistable secret-free input to the material-v2 SHA-256 identity."""

    fingerprint_schema_version: Literal[2] = FINGERPRINT_SCHEMA_VERSION
    evaluation_schema_version: StrictInt = Field(ge=1)
    reasoning_schema_version: StrictInt = Field(ge=1)
    consensus_schema_version: StrictInt | None = Field(default=None, ge=1)
    autonomy_schema_version: StrictInt | None = Field(default=None, ge=1)
    evaluation_max_output_tokens: StrictInt = Field(ge=1)
    pricing_configuration: dict[str, JsonValue]
    subject: dict[str, JsonValue]
    cases: tuple[dict[str, JsonValue], ...] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_public_source(self) -> "MaterialConfigurationFingerprintSource":
        payload = self.model_dump(mode="json")
        if public_result(payload) != payload:
            raise ValueError("fingerprint source must satisfy the public-safe boundary")
        return self


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _normalize_digest_value(value: Any) -> Any:
    if isinstance(value, str):
        return _TEMPORARY_PATH.sub("[EPHEMERAL_PATH]", value)
    if isinstance(value, dict):
        return {
            str(key): _normalize_digest_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_digest_value(item) for item in value]
    return value


def _public_content_digest(value: Any) -> str:
    normalized = _normalize_digest_value(value)
    safe = public_result(normalized)
    if safe != normalized:
        raise ValueError("fingerprint content must already be public-safe")
    return hashlib.sha256(_canonical_json(normalized).encode("utf-8")).hexdigest()


def _semantic_reference(value: str | None) -> str | None:
    if value is None or _TEMPORARY_PATH.search(value):
        return None
    return value


def _assert_complete(value: Any, *covered_fields: str) -> None:
    actual = set(type(value).model_fields)
    covered = set(covered_fields)
    if actual != covered:
        raise RuntimeError(
            f"material fingerprint field list is incomplete for {type(value).__name__}"
        )


def _canonical_model_budget(value: Any) -> dict[str, JsonValue]:
    _assert_complete(
        value,
        "max_model_calls",
        "max_input_tokens",
        "max_output_tokens",
        "max_total_tokens",
        "max_estimated_cost_usd",
        "max_per_call_cost_usd",
        "unknown_cost_policy",
    )
    return {
        "max_model_calls": value.max_model_calls,
        "max_input_tokens": value.max_input_tokens,
        "max_output_tokens": value.max_output_tokens,
        "max_total_tokens": value.max_total_tokens,
        "max_estimated_cost_usd": value.max_estimated_cost_usd,
        "max_per_call_cost_usd": value.max_per_call_cost_usd,
        "unknown_cost_policy": value.unknown_cost_policy,
    }


def _canonical_route(value: Any) -> dict[str, JsonValue]:
    _assert_complete(value, "provider", "model")
    return {"provider": value.provider, "model": value.model}


def _canonical_routing_policy(
    policy: ModelRoutingPolicy,
) -> dict[str, JsonValue]:
    _assert_complete(
        policy,
        "mode",
        "preferred",
        "fallbacks",
        "fallback_allowed",
        "max_provider_attempts",
        "allowed_cloud_providers",
        "fallback_on",
        "max_retries",
        "budget",
    )
    return {
        "mode": policy.mode.value,
        "preferred": _canonical_route(policy.preferred),
        "fallbacks": [_canonical_route(item) for item in policy.fallbacks],
        "fallback_allowed": policy.fallback_allowed,
        "max_provider_attempts": policy.max_provider_attempts,
        "allowed_cloud_providers": sorted(policy.allowed_cloud_providers),
        "fallback_on": sorted(item.value for item in policy.fallback_on),
        "max_retries": policy.max_retries,
        "budget": _canonical_model_budget(policy.budget),
    }


def _canonical_consensus_policy(value: Any) -> dict[str, JsonValue]:
    _assert_complete(
        value,
        "minimum_participants",
        "minimum_valid_participants",
        "require_majority",
        "require_unanimity",
        "minimum_aggregate_confidence",
        "split_behavior",
        "allow_single_model_advisory",
        "allow_duplicate_participants",
        "local_only",
    )
    return {
        "minimum_participants": value.minimum_participants,
        "minimum_valid_participants": value.minimum_valid_participants,
        "require_majority": value.require_majority,
        "require_unanimity": value.require_unanimity,
        "minimum_aggregate_confidence": value.minimum_aggregate_confidence,
        "split_behavior": value.split_behavior.value,
        "allow_single_model_advisory": value.allow_single_model_advisory,
        "allow_duplicate_participants": value.allow_duplicate_participants,
        "local_only": value.local_only,
    }


def _canonical_consensus_budget(value: Any) -> dict[str, JsonValue]:
    _assert_complete(
        value,
        "max_model_calls",
        "max_input_tokens",
        "max_output_tokens",
        "max_total_tokens",
        "max_estimated_cost_usd",
        "unknown_cost_policy",
    )
    return {
        "max_model_calls": value.max_model_calls,
        "max_input_tokens": value.max_input_tokens,
        "max_output_tokens": value.max_output_tokens,
        "max_total_tokens": value.max_total_tokens,
        "max_estimated_cost_usd": value.max_estimated_cost_usd,
        "unknown_cost_policy": value.unknown_cost_policy,
    }


def _canonical_autonomy_limits(value: Any) -> dict[str, JsonValue]:
    _assert_complete(
        value,
        "max_iterations",
        "max_verifications",
        "max_reasoning_failures",
        "max_duplicate_recommendations",
        "max_policy_blocks",
    )
    return {
        "max_iterations": value.max_iterations,
        "max_verifications": value.max_verifications,
        "max_reasoning_failures": value.max_reasoning_failures,
        "max_duplicate_recommendations": value.max_duplicate_recommendations,
        "max_policy_blocks": value.max_policy_blocks,
    }


def _canonical_subject(subject: EvaluationSubject) -> dict[str, JsonValue]:
    _assert_complete(
        subject,
        "subject_id",
        "subject_type",
        "routing_policies",
        "consensus_policy",
        "consensus_budget",
        "autonomy_limits",
        "repetitions",
        "local_only",
    )
    routes = [_canonical_routing_policy(item) for item in subject.routing_policies]
    if subject.subject_type is EvaluationSubjectType.consensus_reasoning:
        routes.sort(key=_canonical_json)
    return {
        "subject_id": subject.subject_id,
        "subject_type": subject.subject_type.value,
        "routing_policies": routes,
        "consensus_policy": (
            _canonical_consensus_policy(subject.consensus_policy)
            if subject.consensus_policy is not None
            else None
        ),
        "consensus_budget": (
            _canonical_consensus_budget(subject.consensus_budget)
            if subject.consensus_budget is not None
            else None
        ),
        "autonomy_limits": (
            _canonical_autonomy_limits(subject.autonomy_limits)
            if subject.autonomy_limits is not None
            else None
        ),
        "repetitions": subject.repetitions,
        "local_only": subject.local_only,
    }


def _canonical_expectations(case: EvaluationCase) -> dict[str, JsonValue]:
    value = case.expected_structure
    _assert_complete(
        value,
        "minimum_valid_decisions",
        "maximum_valid_decisions",
        "allowed_actions",
        "allowed_capabilities",
        "evidence_references_required",
        "decision_action",
        "recommended_capability",
        "decision_valid",
        "hypothesis_id",
        "category",
        "consensus_agreement",
        "autonomy_terminal_state",
        "stop_reason",
        "minimum_iterations",
        "maximum_iterations",
        "minimum_verifications",
        "maximum_verifications",
        "execution_occurred",
        "phase2_status",
        "maximum_target_requests",
        "maximum_model_calls",
        "fallback_used",
    )
    return {
        "minimum_valid_decisions": value.minimum_valid_decisions,
        "maximum_valid_decisions": value.maximum_valid_decisions,
        "allowed_actions": sorted(item.value for item in value.allowed_actions),
        "allowed_capabilities": sorted(value.allowed_capabilities),
        "evidence_references_required": value.evidence_references_required,
        "decision_action": (
            value.decision_action.value if value.decision_action is not None else None
        ),
        "recommended_capability": value.recommended_capability,
        "decision_valid": value.decision_valid,
        "hypothesis_id": value.hypothesis_id,
        "category": value.category,
        "consensus_agreement": (
            value.consensus_agreement.value
            if value.consensus_agreement is not None
            else None
        ),
        "autonomy_terminal_state": (
            value.autonomy_terminal_state.value
            if value.autonomy_terminal_state is not None
            else None
        ),
        "stop_reason": (
            value.stop_reason.value if value.stop_reason is not None else None
        ),
        "minimum_iterations": value.minimum_iterations,
        "maximum_iterations": value.maximum_iterations,
        "minimum_verifications": value.minimum_verifications,
        "maximum_verifications": value.maximum_verifications,
        "execution_occurred": value.execution_occurred,
        "phase2_status": (
            value.phase2_status.value if value.phase2_status is not None else None
        ),
        "maximum_target_requests": value.maximum_target_requests,
        "maximum_model_calls": value.maximum_model_calls,
        "fallback_used": value.fallback_used,
    }


def _canonical_prior_verification(value: Any) -> dict[str, JsonValue] | None:
    if value is None:
        return None
    _assert_complete(value, "status", "reasons", "request_accounting")
    accounting = value.request_accounting
    _assert_complete(
        accounting,
        "discovery_requests",
        "auth_requests",
        "verification_requests",
        "cleanup_requests",
        "attempted_requests",
        "total_requests",
        "source",
    )
    return {
        "status": value.status,
        "request_accounting": {
            "discovery_requests": accounting.discovery_requests,
            "auth_requests": accounting.auth_requests,
            "verification_requests": accounting.verification_requests,
            "cleanup_requests": accounting.cleanup_requests,
            "attempted_requests": accounting.attempted_requests,
            "total_requests": accounting.total_requests,
            "source": accounting.source,
        },
        "reasons_sha256": _public_content_digest(value.reasons),
    }


def _canonical_evidence_packet(packet: Any) -> dict[str, JsonValue]:
    _assert_complete(
        packet,
        "hypothesis_id",
        "category",
        "title",
        "rationale",
        "confidence",
        "priority",
        "target_surface",
        "evidence_basis",
        "evidence_references",
        "required_context",
        "limitations",
        "capability_state",
        "typed_executor_available",
        "min_requests",
        "worst_case_requests",
        "plan_policy_decision",
        "plan_automatic_execution_allowed",
        "prior_verification",
    )
    return {
        "hypothesis_id": packet.hypothesis_id,
        "category": packet.category,
        "confidence": packet.confidence.value,
        "priority": packet.priority,
        "evidence_references": list(packet.evidence_references),
        "capability_state": packet.capability_state,
        "typed_executor_available": packet.typed_executor_available,
        "min_requests": packet.min_requests,
        "worst_case_requests": packet.worst_case_requests,
        "plan_policy_decision": packet.plan_policy_decision,
        "plan_automatic_execution_allowed": packet.plan_automatic_execution_allowed,
        "prior_verification": _canonical_prior_verification(packet.prior_verification),
        "public_evidence_sha256": _public_content_digest(
            {
                "title": packet.title,
                "rationale": packet.rationale,
                "target_surface": packet.target_surface,
                "evidence_basis": packet.evidence_basis,
                "required_context": packet.required_context,
                "limitations": packet.limitations,
            }
        ),
    }


def _canonical_capability_catalog(value: Any) -> dict[str, JsonValue]:
    _assert_complete(value, "schema_version", "entries")
    for entry in value.entries:
        _assert_complete(
            entry,
            "category",
            "capability_state",
            "typed_executor_available",
            "input_schema_identifier",
            "executor_version",
            "min_requests",
            "worst_case_requests",
            "major_preconditions",
            "automatic_execution_supported",
        )
    return {
        "schema_version": value.schema_version,
        "entries": [
            {
                "category": entry.category,
                "capability_state": entry.capability_state,
                "typed_executor_available": entry.typed_executor_available,
                "input_schema_identifier": _semantic_reference(
                    entry.input_schema_identifier
                ),
                "executor_version": _semantic_reference(entry.executor_version),
                "min_requests": entry.min_requests,
                "worst_case_requests": entry.worst_case_requests,
                "major_preconditions_sha256": _public_content_digest(
                    entry.major_preconditions
                ),
                "automatic_execution_supported": entry.automatic_execution_supported,
            }
            for entry in value.entries
        ],
    }


def _canonical_reasoning_request(value: Any) -> dict[str, JsonValue]:
    _assert_complete(
        value,
        "task_type",
        "run_id",
        "target_reference",
        "evidence_packets",
        "capability_catalog",
        "policy_constraints",
        "previous_decisions",
        "model_budget_context",
    )
    policy = value.policy_constraints
    _assert_complete(
        policy,
        "policy_reference",
        "allowed_recommendation_categories",
        "blocked_categories",
        "remaining_target_request_budget",
        "controlled_context_available",
        "notes",
    )
    for decision in value.previous_decisions:
        _assert_complete(
            decision,
            "decision_id",
            "hypothesis_id",
            "action",
            "recommended_capability",
            "concise_rationale",
        )
    budget_context = value.model_budget_context
    _assert_complete(
        budget_context,
        "remaining_model_calls",
        "remaining_input_tokens",
        "remaining_output_tokens",
        "remaining_total_tokens",
        "remaining_estimated_cost_usd",
        "cost_known",
    )
    return {
        "task_type": value.task_type.value,
        "target_reference": value.target_reference,
        "evidence_packets": [
            _canonical_evidence_packet(packet) for packet in value.evidence_packets
        ],
        "capability_catalog": _canonical_capability_catalog(value.capability_catalog),
        "policy_constraints": {
            "policy_reference": policy.policy_reference,
            "allowed_recommendation_categories": sorted(
                policy.allowed_recommendation_categories
            ),
            "blocked_categories": sorted(policy.blocked_categories),
            "remaining_target_request_budget": policy.remaining_target_request_budget,
            "controlled_context_available": policy.controlled_context_available,
            "notes_sha256": _public_content_digest(policy.notes),
        },
        "previous_decisions": [
            {
                "hypothesis_id": decision.hypothesis_id,
                "action": decision.action.value,
                "recommended_capability": decision.recommended_capability,
                "concise_rationale_sha256": _public_content_digest(
                    decision.concise_rationale
                ),
            }
            for decision in value.previous_decisions
        ],
        "model_budget_context": {
            "remaining_model_calls": budget_context.remaining_model_calls,
            "remaining_input_tokens": budget_context.remaining_input_tokens,
            "remaining_output_tokens": budget_context.remaining_output_tokens,
            "remaining_total_tokens": budget_context.remaining_total_tokens,
            "remaining_estimated_cost_usd": (
                budget_context.remaining_estimated_cost_usd
            ),
            "cost_known": budget_context.cost_known,
        },
    }


def _canonical_case(case: EvaluationCase, *, budget_group: str) -> dict[str, JsonValue]:
    _assert_complete(
        case,
        "case_id",
        "task_type",
        "reasoning_request",
        "expected_structure",
        "execution_mode",
        "model_budget",
        "autonomy_budget",
        "repetitions",
    )
    return {
        "case_id": case.case_id,
        "task_type": case.task_type.value,
        "reasoning_request": _canonical_reasoning_request(case.reasoning_request),
        "reasoning_budget_group": budget_group,
        "execution_mode": case.execution_mode.value,
        "expected_structure": _canonical_expectations(case),
        "model_budget": _canonical_model_budget(case.model_budget),
        "autonomy_budget": (
            _canonical_autonomy_limits(case.autonomy_budget)
            if case.autonomy_budget is not None
            else None
        ),
        "repetitions": case.repetitions,
    }


def configuration_fingerprint_source(
    subject: EvaluationSubject,
    cases: tuple[EvaluationCase, ...],
    *,
    evaluation_max_output_tokens: int = 4096,
    pricing: ModelPricingCatalog | None = None,
) -> MaterialConfigurationFingerprintSource:
    """Return the complete canonical public material-v2 fingerprint source."""

    if not cases:
        raise ValueError("configuration fingerprint requires at least one case")
    consensus = subject.subject_type is EvaluationSubjectType.consensus_reasoning
    autonomy = subject.subject_type in {
        EvaluationSubjectType.dry_run_autonomy,
        EvaluationSubjectType.controlled_autonomy,
    }
    ordered_cases = tuple(sorted(cases, key=lambda item: item.case_id))
    budget_groups: dict[str, str] = {}
    for case in ordered_cases:
        run_id = case.reasoning_request.run_id
        if run_id not in budget_groups:
            budget_groups[run_id] = f"group-{len(budget_groups)}"
    return MaterialConfigurationFingerprintSource(
        evaluation_schema_version=EVALUATION_SCHEMA_VERSION,
        reasoning_schema_version=REASONING_SCHEMA_VERSION,
        consensus_schema_version=CONSENSUS_SCHEMA_VERSION if consensus else None,
        autonomy_schema_version=1 if autonomy else None,
        evaluation_max_output_tokens=evaluation_max_output_tokens,
        pricing_configuration=(
            pricing or ModelPricingCatalog()
        ).fingerprint_configuration(),
        subject=_canonical_subject(subject),
        cases=tuple(
            _canonical_case(
                case,
                budget_group=budget_groups[case.reasoning_request.run_id],
            )
            for case in ordered_cases
        ),
    )


def configuration_fingerprint_source_json(
    subject: EvaluationSubject,
    cases: tuple[EvaluationCase, ...],
    *,
    evaluation_max_output_tokens: int = 4096,
    pricing: ModelPricingCatalog | None = None,
) -> str:
    """Serialize the safe source with stable keys and no Python representations."""

    source = configuration_fingerprint_source(
        subject,
        cases,
        evaluation_max_output_tokens=evaluation_max_output_tokens,
        pricing=pricing,
    )
    return _canonical_json(source.model_dump(mode="json"))


def configuration_fingerprint(
    subject: EvaluationSubject,
    cases: tuple[EvaluationCase, ...],
    *,
    evaluation_max_output_tokens: int = 4096,
    pricing: ModelPricingCatalog | None = None,
) -> str:
    """Return the material-v2 lowercase SHA-256 configuration identity."""

    encoded = configuration_fingerprint_source_json(
        subject,
        cases,
        evaluation_max_output_tokens=evaluation_max_output_tokens,
        pricing=pricing,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def material_fingerprint_schema() -> ConfigurationFingerprintSchema:
    return ConfigurationFingerprintSchema.material_v2
