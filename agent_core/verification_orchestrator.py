from __future__ import annotations

from typing import Any

from agent_core.verification_session import (
    VerificationSession,
)
from agent_core.verification_state import (
    TERMINAL_STATES,
    VerificationState,
)
from tools.raw_http_request_parser import (
    parse_raw_http_request,
)
from tools.request_replay_engine import (
    replay_authorization_contexts,
)


class VerificationOrchestrator:
    """
    Deterministic controller for controlled authorization verification.

    The orchestrator decides which safe internal step is required next.
    DeepSeek may later explain findings, but it does not control request
    execution or verification-state transitions.
    """

    def create_session(
        self,
        raw_request: str | None = None,
        default_scheme: str = "https",
    ) -> VerificationSession:
        session = VerificationSession(
            raw_request=raw_request,
        )

        if raw_request:
            self.parse_request(
                session=session,
                default_scheme=default_scheme,
            )

        return session

    def parse_request(
        self,
        session: VerificationSession,
        default_scheme: str = "https",
    ) -> dict[str, Any]:
        if not session.raw_request:
            return {
                "success": False,
                "error": "A raw HTTP request is required.",
                "next_action": "provide_request",
            }

        parsed = parse_raw_http_request(
            raw_request=session.raw_request,
            default_scheme=default_scheme,
        )

        if not parsed.get("success"):
            session.add_error(
                parsed.get(
                    "error",
                    "The HTTP request could not be parsed.",
                )
            )

            return {
                "success": False,
                "error": session.errors[-1],
                "session": session.to_dict(),
            }

        session.parsed_request = parsed
        session.target = parsed.get("url")

        account_a_context = parsed.get(
            "authorization_context",
            {},
        )

        if account_a_context:
            session.account_a_headers = account_a_context

        session.transition(
            VerificationState.REQUEST_PARSED,
            completed_step="parse_request",
        )

        self._refresh_state(session)

        return {
            "success": True,
            "parsed_request": parsed,
            "next_action": self.next_action(session),
            "session": session.to_dict(),
        }

    def set_account_a_headers(
        self,
        session: VerificationSession,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        if not headers:
            return {
                "success": False,
                "error": ("Account A authorization headers " "cannot be empty."),
            }

        session.account_a_headers = dict(headers)
        session.touch()
        self._refresh_state(session)

        return {
            "success": True,
            "next_action": self.next_action(session),
            "session": session.to_dict(),
        }

    def set_account_b_headers(
        self,
        session: VerificationSession,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        if not headers:
            return {
                "success": False,
                "error": ("Account B authorization headers " "cannot be empty."),
            }

        session.account_b_headers = dict(headers)
        session.touch()
        self._refresh_state(session)

        return {
            "success": True,
            "next_action": self.next_action(session),
            "session": session.to_dict(),
        }

    def set_verification_context(
        self,
        session: VerificationSession,
        object_identifier: str | None = None,
        ownership_confirmed: bool = False,
        separate_accounts_confirmed: bool = False,
    ) -> dict[str, Any]:
        session.object_identifier = object_identifier
        session.ownership_confirmed = ownership_confirmed
        session.separate_accounts_confirmed = separate_accounts_confirmed
        session.touch()
        self._refresh_state(session)

        return {
            "success": True,
            "next_action": self.next_action(session),
            "session": session.to_dict(),
        }

    def execute_replay(
        self,
        session: VerificationSession,
        timeout_seconds: int = 15,
        verify_tls: bool = True,
    ) -> dict[str, Any]:
        if session.state != VerificationState.READY_TO_REPLAY:
            return {
                "success": False,
                "error": ("The session is not ready for replay."),
                "state": session.state.value,
                "next_action": self.next_action(session),
            }

        parsed_request = session.parsed_request or {}

        method = parsed_request.get("method")
        url = parsed_request.get("url")

        if not method or not url:
            session.add_error("The parsed request is missing a method or URL.")

            return {
                "success": False,
                "error": session.errors[-1],
                "session": session.to_dict(),
            }

        common_headers = self._common_headers(parsed_request.get("headers", {}))

        query_params = parsed_request.get("query_parameters")

        replay_result = replay_authorization_contexts(
            url=url,
            method=method,
            account_a_headers=session.account_a_headers,
            account_b_headers=session.account_b_headers,
            common_headers=common_headers,
            query_params=query_params,
            object_identifier=session.object_identifier,
            ownership_confirmed=(session.ownership_confirmed),
            separate_accounts_confirmed=(session.separate_accounts_confirmed),
            timeout_seconds=timeout_seconds,
            verify_tls=verify_tls,
        )

        if not replay_result.get("success"):
            session.add_error(
                replay_result.get(
                    "error",
                    "Controlled replay failed.",
                )
            )

            return {
                "success": False,
                "error": session.errors[-1],
                "replay_result": replay_result,
                "session": session.to_dict(),
            }

        session.replay_result = replay_result
        session.transition(
            VerificationState.RESPONSES_CAPTURED,
            completed_step="controlled_replay",
        )

        analysis = replay_result.get(
            "analysis",
            {},
        )

        finding = analysis.get("finding")

        if finding:
            session.finding = finding
            session.transition(
                VerificationState.FINDING_GENERATED,
                completed_step="generate_finding",
            )

        self._refresh_state(session)

        return {
            "success": True,
            "finding": session.finding,
            "replay_result": replay_result,
            "next_action": self.next_action(session),
            "session": session.to_dict(),
        }

    def next_action(
        self,
        session: VerificationSession,
    ) -> str:
        state_actions = {
            VerificationState.WAITING_FOR_REQUEST: ("provide_request"),
            VerificationState.REQUEST_PARSED: ("provide_authorization_contexts"),
            VerificationState.WAITING_FOR_SECOND_ACCOUNT: ("provide_account_b"),
            VerificationState.READY_TO_REPLAY: ("execute_replay"),
            VerificationState.RESPONSES_CAPTURED: ("analyze_responses"),
            VerificationState.FINDING_GENERATED: ("review_finding"),
            VerificationState.COMPLETE: "complete",
            VerificationState.FAILED: "review_error",
        }

        return state_actions[session.state]

    def complete_session(
        self,
        session: VerificationSession,
    ) -> dict[str, Any]:
        if not session.finding:
            return {
                "success": False,
                "error": ("A session cannot be completed " "without a finding."),
            }

        session.transition(
            VerificationState.COMPLETE,
            completed_step="complete_session",
        )

        return {
            "success": True,
            "session": session.to_dict(),
        }

    def _refresh_state(
        self,
        session: VerificationSession,
    ) -> None:
        if session.state in TERMINAL_STATES:
            return

        if not session.parsed_request:
            session.state = VerificationState.WAITING_FOR_REQUEST
            session.touch()
            return

        if session.replay_result and session.finding:
            session.state = VerificationState.FINDING_GENERATED
            session.touch()
            return

        if session.replay_result:
            session.state = VerificationState.RESPONSES_CAPTURED
            session.touch()
            return

        if not session.has_account_a_context():
            session.state = VerificationState.REQUEST_PARSED
            session.touch()
            return

        if not session.has_account_b_context():
            session.state = VerificationState.WAITING_FOR_SECOND_ACCOUNT
            session.touch()
            return

        session.state = VerificationState.READY_TO_REPLAY
        session.touch()

    @staticmethod
    def _common_headers(
        headers: dict[str, str],
    ) -> dict[str, str]:
        credential_headers = {
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-api-key",
        }

        excluded_headers = credential_headers | {
            "host",
            "content-length",
        }

        return {
            name: value
            for name, value in headers.items()
            if name.lower() not in excluded_headers
        }
