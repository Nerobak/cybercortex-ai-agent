import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from verification_cli import (
    _parse_header_input,
    _read_request_file,
    _write_safe_result,
    run_verification,
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


def test_verification_cli_workflow():
    server = start_server()
    port = server.server_address[1]

    raw_request = f"""GET /api/accounts/account-a HTTP/1.1
Host: 127.0.0.1:{port}
Authorization: Bearer ACCOUNT_A
Accept: application/json

"""

    try:
        result = run_verification(
            raw_request=raw_request,
            account_b_headers={
                "Authorization": "Bearer ACCOUNT_B",
            },
            default_scheme="http",
            object_identifier="account-a",
            ownership_confirmed=True,
            separate_accounts_confirmed=True,
        )

        print("\n[1] Verification CLI workflow")
        print(result)

        assert result["success"] is True

        finding = result["finding"]

        assert finding is not None
        assert finding["severity"] == "high"
        assert finding["confidence"] == "high"
        assert finding["status"] == "verified"

        session = result["session"]

        assert session["state"] == "complete"

        assert session["account_a_headers"] == {
            "Authorization": "[REDACTED]",
        }

        assert session["account_b_headers"] == {
            "Authorization": "[REDACTED]",
        }

    finally:
        server.shutdown()
        server.server_close()


def test_file_and_header_helpers():
    with TemporaryDirectory() as temporary_directory:
        request_file = Path(temporary_directory) / "controlled.request.txt"

        request_file.write_text(
            "GET / HTTP/1.1\nHost: example.com\n\n",
            encoding="utf-8",
        )

        content = _read_request_file(str(request_file))

        assert "Host: example.com" in content

        name, value = _parse_header_input("Authorization: Bearer CONTROLLED")

        assert name == "Authorization"
        assert value == "Bearer CONTROLLED"


def test_safe_output_does_not_contain_tokens():
    with TemporaryDirectory() as temporary_directory:
        output_file = Path(temporary_directory) / "safe-result.json"

        result = {
            "success": True,
            "finding": {
                "title": "Controlled finding",
            },
            "session": {
                "account_a_headers": {
                    "Authorization": "[REDACTED]",
                },
                "account_b_headers": {
                    "Authorization": "[REDACTED]",
                },
            },
        }

        _write_safe_result(
            output_file=str(output_file),
            result=result,
        )

        saved_content = output_file.read_text(encoding="utf-8")

        print("\n[2] Sanitized CLI output")
        print(saved_content)

        assert "ACCOUNT_A" not in saved_content
        assert "ACCOUNT_B" not in saved_content
        assert "[REDACTED]" in saved_content


def main():
    test_verification_cli_workflow()
    test_file_and_header_helpers()
    test_safe_output_does_not_contain_tokens()

    print("\nVerification CLI tests passed.")


if __name__ == "__main__":
    main()
