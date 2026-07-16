import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from agent_core.verification_orchestrator import (
    VerificationOrchestrator,
)
from agent_core.verification_state import (
    VerificationState,
)


class ControlledVerificationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        authorization = self.headers.get(
            "Authorization",
            "",
        )

        if authorization == "Bearer ACCOUNT_A":
            self._send_json(
                403,
                {
                    "error": "Access denied",
                },
            )
            return

        if authorization == "Bearer ACCOUNT_B":
            self._send_json(
                200,
                {
                    "accountId": "account-a",
                    "email": "controlled@example.com",
                    "balance": 125.50,
                },
            )
            return

        self._send_json(
            401,
            {
                "error": "Unauthorized",
            },
        )

    def _send_json(
        self,
        status_code: int,
        body: dict,
    ):
        content = json.dumps(body).encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(len(content)),
        )
        self.end_headers()
        self.wfile.write(content)

    def log_message(
        self,
        format,
        *args,
    ):
        return


def start_server():
    server = HTTPServer(
        ("127.0.0.1", 0),
        ControlledVerificationHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server


def test_complete_verification_workflow():
    server = start_server()
    port = server.server_address[1]

    orchestrator = VerificationOrchestrator()

    raw_request = f"""GET /api/accounts/account-a HTTP/1.1
Host: 127.0.0.1:{port}
Authorization: Bearer ACCOUNT_A
Accept: application/json

"""

    try:
        session = orchestrator.create_session(
            raw_request=raw_request,
            default_scheme="http",
        )

        print("\n[1] Request parsed")
        print(session.to_dict())

        assert session.state == (VerificationState.WAITING_FOR_SECOND_ACCOUNT)

        account_b_result = orchestrator.set_account_b_headers(
            session=session,
            headers={
                "Authorization": ("Bearer ACCOUNT_B"),
            },
        )

        print("\n[2] Account B supplied")
        print(account_b_result)

        assert session.state == (VerificationState.READY_TO_REPLAY)

        orchestrator.set_verification_context(
            session=session,
            object_identifier="account-a",
            ownership_confirmed=True,
            separate_accounts_confirmed=True,
        )

        replay_result = orchestrator.execute_replay(
            session=session,
        )

        print("\n[3] Replay completed")
        print(replay_result)

        assert replay_result["success"] is True

        assert session.state == (VerificationState.FINDING_GENERATED)

        assert session.finding is not None
        assert session.finding["severity"] == "high"
        assert session.finding["confidence"] == "high"
        assert session.finding["status"] == "verified"

        completion = orchestrator.complete_session(session)

        print("\n[4] Session complete")
        print(completion)

        assert completion["success"] is True
        assert session.state == (VerificationState.COMPLETE)

    finally:
        server.shutdown()
        server.server_close()


def test_missing_request_state():
    orchestrator = VerificationOrchestrator()
    session = orchestrator.create_session()

    print("\n[5] Empty session")
    print(session.to_dict())

    assert session.state == (VerificationState.WAITING_FOR_REQUEST)

    assert orchestrator.next_action(session) == ("provide_request")


def test_secrets_are_redacted():
    orchestrator = VerificationOrchestrator()

    session = orchestrator.create_session()

    session.account_a_headers = {
        "Authorization": "Bearer SECRET_A",
        "Cookie": "session=secret-a",
    }

    session.account_b_headers = {
        "Authorization": "Bearer SECRET_B",
    }

    safe_session = session.to_dict()

    print("\n[6] Redacted session")
    print(safe_session)

    assert safe_session["account_a_headers"] == {
        "Authorization": "[REDACTED]",
        "Cookie": "[REDACTED]",
    }

    assert safe_session["account_b_headers"] == {
        "Authorization": "[REDACTED]",
    }


def main():
    test_complete_verification_workflow()
    test_missing_request_state()
    test_secrets_are_redacted()

    print("\nVerification orchestrator tests passed.")


if __name__ == "__main__":
    main()
