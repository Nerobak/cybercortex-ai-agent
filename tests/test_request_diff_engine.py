import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.request_diff_engine import compare_responses


def test_authorization_change():
    baseline = {
        "status_code": 403,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "error": "Access denied",
        },
        "elapsed_ms": 85,
    }

    candidate = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "userId": 2002,
            "email": "controlled-test@example.com",
            "role": "user",
        },
        "elapsed_ms": 92,
    }

    result = compare_responses(
        baseline=baseline,
        candidate=candidate,
    )

    print("\n[1] Authorization response comparison")
    print(result)

    assert result["success"] is True
    assert result["status"]["changed"] is True
    assert result["status"]["baseline"] == 403
    assert result["status"]["candidate"] == 200

    assert (
        "Candidate response changed from an authorization denial "
        "to a successful response." in result["signals"]
    )

    assert "email" in result["json"]["sensitive_fields_present"]
    assert "role" in result["json"]["sensitive_fields_present"]
    assert "userId" in result["json"]["sensitive_fields_present"]


def test_similar_successful_responses():
    baseline = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "orderId": 1001,
            "status": "complete",
            "total": 49.99,
        },
    }

    candidate = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "orderId": 1002,
            "status": "complete",
            "total": 49.99,
        },
    }

    result = compare_responses(
        baseline=baseline,
        candidate=candidate,
    )

    print("\n[2] Similar object comparison")
    print(result)

    assert result["success"] is True
    assert result["status"]["changed"] is False
    assert "orderId" in result["json"]["changed_fields"]


def test_identical_response():
    response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "text/plain",
        },
        "body": "Operation completed",
    }

    result = compare_responses(
        baseline=response,
        candidate=response,
    )

    print("\n[3] Identical response comparison")
    print(result)

    assert result["body"]["identical"] is True
    assert result["body"]["similarity_ratio"] == 1.0


def main():
    test_authorization_change()
    test_similar_successful_responses()
    test_identical_response()

    print("\nRequest diff engine tests passed.")


if __name__ == "__main__":
    main()
