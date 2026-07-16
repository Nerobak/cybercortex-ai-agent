from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agent_core.verification_state import VerificationState


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class VerificationSession:
    """
    Stores the state and evidence for one controlled verification workflow.

    Secrets may exist temporarily in account authorization contexts.
    Do not write the result of to_dict(include_secrets=True) to logs,
    reports, or Git-tracked files.
    """

    target: str | None = None
    raw_request: str | None = None
    parsed_request: dict[str, Any] | None = None

    account_a_headers: dict[str, str] = field(default_factory=dict)
    account_b_headers: dict[str, str] = field(default_factory=dict)

    object_identifier: str | None = None
    ownership_confirmed: bool = False
    separate_accounts_confirmed: bool = False

    replay_result: dict[str, Any] | None = None
    finding: dict[str, Any] | None = None

    state: VerificationState = VerificationState.WAITING_FOR_REQUEST
    completed_steps: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    session_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=_utc_timestamp)
    updated_at: str = field(default_factory=_utc_timestamp)

    def touch(self) -> None:
        """Update the session modification timestamp."""
        self.updated_at = _utc_timestamp()

    def transition(
        self,
        new_state: VerificationState,
        completed_step: str | None = None,
    ) -> None:
        """Move the session to a new state."""
        self.state = new_state

        if completed_step and completed_step not in self.completed_steps:
            self.completed_steps.append(completed_step)

        self.touch()

    def add_error(self, message: str) -> None:
        """Record an error and mark the session as failed."""
        self.errors.append(message)
        self.transition(VerificationState.FAILED)

    def has_account_a_context(self) -> bool:
        return bool(self.account_a_headers)

    def has_account_b_context(self) -> bool:
        return bool(self.account_b_headers)

    def has_two_accounts(self) -> bool:
        return self.has_account_a_context() and self.has_account_b_context()

    def to_dict(
        self,
        include_secrets: bool = False,
    ) -> dict[str, Any]:
        """
        Convert the session into a serializable dictionary.

        Authorization values are redacted unless include_secrets=True.
        """
        data = asdict(self)
        data["state"] = self.state.value

        if not include_secrets:
            data["raw_request"] = "[PRESENT]" if self.raw_request else None

            data["account_a_headers"] = {
                name: "[REDACTED]" for name in self.account_a_headers
            }

            data["account_b_headers"] = {
                name: "[REDACTED]" for name in self.account_b_headers
            }

            parsed_request = data.get("parsed_request")

            if isinstance(parsed_request, dict):
                parsed_request = dict(parsed_request)

                if "headers" in parsed_request:
                    parsed_request["headers"] = parsed_request.get(
                        "sanitized_headers",
                        {},
                    )

                if "authorization_context" in parsed_request:
                    parsed_request["authorization_context"] = {
                        name: "[REDACTED]"
                        for name in parsed_request["authorization_context"]
                    }

                data["parsed_request"] = parsed_request

        return data
