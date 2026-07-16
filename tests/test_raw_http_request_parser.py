import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.raw_http_request_parser import (
    extract_authorization_context,
    parse_raw_http_request,
)


def test_get_request():
    raw_request = """GET /api/users/2002?include=profile&include=roles HTTP/1.1
Host: example.com
Authorization: Bearer ACCOUNT_A
Accept: application/json
Cookie: session=controlled-session

"""

    result = parse_raw_http_request(raw_request)

    print("\n[1] Parsed GET request")
    print(result)

    assert result["success"] is True
    assert result["method"] == "GET"
    assert result["url"] == (
        "https://example.com/api/users/2002" "?include=profile&include=roles"
    )
    assert result["path"] == "/api/users/2002"

    assert result["query_parameters"] == {
        "include": [
            "profile",
            "roles",
        ]
    }

    assert result["sanitized_headers"]["Authorization"] == "[REDACTED]"
    assert result["sanitized_headers"]["Cookie"] == "[REDACTED]"

    assert result["authorization_context"]["Authorization"] == ("Bearer ACCOUNT_A")


def test_json_post_request():
    raw_request = """POST /api/profile HTTP/1.1
Host: example.com
Authorization: Bearer CONTROLLED_TOKEN
Content-Type: application/json
Content-Length: 43

{"displayName":"Controlled User","role":"user"}"""

    result = parse_raw_http_request(raw_request)

    print("\n[2] Parsed JSON request")
    print(result)

    assert result["success"] is True
    assert result["method"] == "POST"
    assert result["body"]["format"] == "json"

    assert result["body"]["parsed"] == {
        "displayName": "Controlled User",
        "role": "user",
    }


def test_form_request():
    raw_request = """POST /api/preferences HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

theme=dark&language=en"""

    result = parse_raw_http_request(raw_request)

    print("\n[3] Parsed form request")
    print(result)

    assert result["success"] is True
    assert result["body"]["format"] == "form"

    assert result["body"]["parsed"] == {
        "theme": ["dark"],
        "language": ["en"],
    }


def test_absolute_url():
    raw_request = """GET https://example.com/api/status HTTP/1.1
Accept: application/json

"""

    result = parse_raw_http_request(raw_request)

    print("\n[4] Parsed absolute URL")
    print(result)

    assert result["success"] is True
    assert result["url"] == "https://example.com/api/status"


def test_missing_host():
    raw_request = """GET /api/status HTTP/1.1
Accept: application/json

"""

    result = parse_raw_http_request(raw_request)

    print("\n[5] Missing Host rejection")
    print(result)

    assert result["success"] is False
    assert "Host header" in result["error"]


def test_invalid_request_line():
    raw_request = """GET /api/status
Host: example.com

"""

    result = parse_raw_http_request(raw_request)

    print("\n[6] Invalid request-line rejection")
    print(result)

    assert result["success"] is False


def test_extract_authorization_context():
    parsed_request = {
        "headers": {
            "Authorization": "Bearer ACCOUNT_A",
            "Cookie": "session=controlled-session",
            "Accept": "application/json",
        }
    }

    context = extract_authorization_context(parsed_request)

    print("\n[7] Authorization context")
    print({name: "[REDACTED]" for name in context})

    assert context == {
        "Authorization": "Bearer ACCOUNT_A",
        "Cookie": "session=controlled-session",
    }


def main():
    test_get_request()
    test_json_post_request()
    test_form_request()
    test_absolute_url()
    test_missing_host()
    test_invalid_request_line()
    test_extract_authorization_context()

    print("\nRaw HTTP request parser tests passed.")


if __name__ == "__main__":
    main()
