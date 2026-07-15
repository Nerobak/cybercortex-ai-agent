import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.request_replay_engine import (
    replay_authorization_contexts,
)


class ControlledAuthorizationHandler(BaseHTTPRequestHandler):
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
        ControlledAuthorizationHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server


def test_controlled_authorization_replay():
    server = start_server()
    port = server.server_address[1]

    try:
        result = replay_authorization_contexts(
            url=f"http://127.0.0.1:{port}/api/accounts/account-a",
            method="GET",
            account_a_headers={
                "Authorization": "Bearer ACCOUNT_A",
            },
            account_b_headers={
                "Authorization": "Bearer ACCOUNT_B",
            },
            object_identifier="account-a",
            ownership_confirmed=True,
            separate_accounts_confirmed=True,
        )

        print("\n[1] Controlled authorization replay")
        print(result)

        assert result["success"] is True

        assert result["account_a"]["response"]["status_code"] == 403

        assert result["account_b"]["response"]["status_code"] == 200

        finding = result["analysis"]["finding"]

        assert finding["severity"] == "high"
        assert finding["confidence"] == "high"
        assert finding["status"] == "verified"

        request_headers_a = result["account_a"]["request"]["headers"]

        request_headers_b = result["account_b"]["request"]["headers"]

        assert request_headers_a["Authorization"] == "[REDACTED]"

        assert request_headers_b["Authorization"] == "[REDACTED]"

    finally:
        server.shutdown()
        server.server_close()


def test_unsafe_method_is_blocked():
    result = replay_authorization_contexts(
        url="http://127.0.0.1:8000/api/accounts/account-a",
        method="DELETE",
        account_a_headers={
            "Authorization": "Bearer ACCOUNT_A",
        },
        account_b_headers={
            "Authorization": "Bearer ACCOUNT_B",
        },
    )

    print("\n[2] Unsafe method rejection")
    print(result)

    assert result["success"] is False
    assert "not supported" in result["error"]


def test_out_of_scope_target_is_blocked():
    result = replay_authorization_contexts(
        url="https://google.com/api/users/1",
        method="GET",
        account_a_headers={
            "Authorization": "Bearer ACCOUNT_A",
        },
        account_b_headers={
            "Authorization": "Bearer ACCOUNT_B",
        },
    )

    print("\n[3] Out-of-scope target rejection")
    print(result)

    assert result["success"] is False


def main():
    test_controlled_authorization_replay()
    test_unsafe_method_is_blocked()
    test_out_of_scope_target_is_blocked()

    print("\nRequest replay engine tests passed.")


if __name__ == "__main__":
    main()
