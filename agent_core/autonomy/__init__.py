"""Bounded P3-4 autonomy through the authoritative Phase 2 runtime."""

from agent_core.autonomy.decision_gate import (
    ExecutionDecisionGate,
    controlled_context_reference,
)
from agent_core.autonomy.history import AutonomyHistory
from agent_core.autonomy.orchestrator import AutonomousOrchestrator
from agent_core.autonomy.state import (
    ALLOWED_TRANSITIONS,
    AutonomyStateMachine,
    InvalidStateTransition,
)
from agent_core.autonomy.types import (
    AutonomyIterationRecord,
    AutonomyLimits,
    AutonomyRun,
    AutonomyRunConfig,
    AutonomyState,
    ExecutionIdentity,
    FailureReason,
    GateDecision,
    GateReason,
    IterationReasoningProvenance,
    ModelBudgetState,
    PivotReason,
    Phase2ResultProvenance,
    ProposedVerification,
    StateTransition,
    StopReason,
    add_model_usage,
    add_request_delta,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "AutonomousOrchestrator",
    "AutonomyHistory",
    "AutonomyIterationRecord",
    "AutonomyLimits",
    "AutonomyRun",
    "AutonomyRunConfig",
    "AutonomyState",
    "AutonomyStateMachine",
    "ExecutionDecisionGate",
    "ExecutionIdentity",
    "FailureReason",
    "GateDecision",
    "GateReason",
    "IterationReasoningProvenance",
    "InvalidStateTransition",
    "ModelBudgetState",
    "PivotReason",
    "Phase2ResultProvenance",
    "ProposedVerification",
    "StateTransition",
    "StopReason",
    "add_model_usage",
    "add_request_delta",
    "controlled_context_reference",
]
