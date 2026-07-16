import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.api_object_discovery import (
    crawl_and_discover_ids,
)


class ControlledDiscoveryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._send_json(
                200,
                {
                    "links": [
                        "/api/users/1001",
                        "/api/projects/project-123",
                    ],
                    "ownerId": "user-456",
                },
            )
            return

        if self.path == "/api/users/1001":
            self._send_json(
                200,
                {
                    "userId": 1001,
                    "email": "controlled@example.com",
                    "orders": [
                        {
                            "orderId": 5002,
                            "href": ("/api/users/1001/" "orders/5002"),
                        }
                    ],
                },
            )
            return

        if self.path == "/api/users/1001/orders/5002":
            self._send_json(
                200,
                {
                    "orderId": 5002,
                    "ownerId": 1001,
                },
            )
            return

        if self.path == ("/api/projects/project-123"):
            self._send_json(
                200,
                {
                    "projectId": "project-123",
                    "folderId": ("550e8400-e29b-" "41d4-a716-446655440000"),
                },
            )
            return

        self._send_json(
            404,
            {
                "error": "Not found",
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
        ControlledDiscoveryHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    thread.start()

    return server


def test_authorized_id_discovery():
    server = start_server()
    port = server.server_address[1]

    try:
        result = crawl_and_discover_ids(
            start_url=f"http://127.0.0.1:{port}/",
            max_depth=3,
            max_pages=20,
            delay_seconds=0,
            same_origin_only=True,
        )

        print("\n[1] API object discovery")
        print(result)

        assert result["success"] is True

        assert result["summary"]["pages_visited"] >= 4

        values = {str(item["value"]) for item in result["identifiers"]}

        assert "1001" in values
        assert "5002" in values
        assert "project-123" in values
        assert "user-456" in values

        object_names = {item["name"] for item in result["objects"]}

        assert "user" in object_names
        assert "order" in object_names
        assert "project" in object_names

        assert result["candidate_authorization_tests"]

    finally:
        server.shutdown()
        server.server_close()


def test_out_of_scope_discovery_is_blocked():
    result = crawl_and_discover_ids(
        start_url="https://google.com/",
        max_depth=1,
        max_pages=5,
    )

    print("\n[2] Out-of-scope crawl rejection")
    print(result)

    assert result["success"] is False


def test_invalid_limits():
    result = crawl_and_discover_ids(
        start_url="https://example.com/",
        max_depth=-1,
        max_pages=0,
    )

    print("\n[3] Invalid crawl limits")
    print(result)

    assert result["success"] is False


def main():
    test_authorized_id_discovery()
    test_out_of_scope_discovery_is_blocked()
    test_invalid_limits()

    print("\nAPI object discovery tests passed.")


if __name__ == "__main__":
    main()
