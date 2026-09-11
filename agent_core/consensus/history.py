"""Sanitized consensus history without prompts or model prose."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_core.consensus.types import ConsensusDecision, ConsensusHistoryEntry


class ConsensusHistory:
    def __init__(self) -> None:
        self._entries: list[ConsensusHistoryEntry] = []

    def record(self, decision: ConsensusDecision) -> ConsensusHistoryEntry:
        entry = ConsensusHistoryEntry(
            consensus_id=decision.consensus_id,
            participant_decision_ids=tuple(
                sorted(
                    {
                        *decision.supporting_decision_ids,
                        *decision.dissenting_decision_ids,
                    }
                )
            ),
            agreement_type=decision.agreement_type,
            selected_action=decision.selected_action,
            selected_capability=decision.selected_capability,
            aggregate_confidence=decision.aggregate_confidence,
            dissenting_decision_ids=decision.dissenting_decision_ids,
            invalid_participants=decision.invalid_participants,
            failed_participants=decision.failed_participants,
            arbitration_reason=decision.arbitration_reason,
            model_usage=decision.model_usage,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> tuple[ConsensusHistoryEntry, ...]:
        return tuple(self._entries)
