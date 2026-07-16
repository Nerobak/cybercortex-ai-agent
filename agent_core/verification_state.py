from __future__ import annotations

from enum import Enum


class VerificationState(str, Enum):
    """
    States used by the CyberCortex verification workflow.

    The orchestrator moves through these states deterministically instead
    of allowing the language model to control security-sensitive execution.
    """

    WAITING_FOR_REQUEST = "waiting_for_request"
    REQUEST_PARSED = "request_parsed"
    WAITING_FOR_SECOND_ACCOUNT = "waiting_for_second_account"
    READY_TO_REPLAY = "ready_to_replay"
    RESPONSES_CAPTURED = "responses_captured"
    FINDING_GENERATED = "finding_generated"
    COMPLETE = "complete"
    FAILED = "failed"


TERMINAL_STATES = {
    VerificationState.COMPLETE,
    VerificationState.FAILED,
}
