import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.authz_differential_tester import (
    analyze_authorization_difference,
)


def test_unverified_authorization_bypass():
    baseline_response = {
        "status_code": 403,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "error": "Access denied",
        },
    }

    candidate_response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "userId": 2002,
            "email": "controlled-test@example.com",
            "role": "user",
        },
    }

    result = analyze_authorization_difference(
        baseline_response=baseline_response,
        candidate_response=candidate_response,
        endpoint="/api/users/2002",
        method="GET",
        object_identifier="2002",
        ownership_confirmed=False,
        separate_accounts_confirmed=False,
    )

    print("\n[1] Unverified authorization candidate")
    print(result)

    finding = result["finding"]

    assert result["success"] is True
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["status"] == "needs_manual_verification"
    assert finding["category"] == "broken_access_control"
    assert finding["endpoint"] == "/api/users/2002"


def test_verified_authorization_bypass():
    baseline_response = {
        "status_code": 403,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "error": "Forbidden",
        },
    }

    candidate_response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "accountId": "account-a",
            "email": "account-a@example.com",
            "balance": 125.50,
        },
    }

    result = analyze_authorization_difference(
        baseline_response=baseline_response,
        candidate_response=candidate_response,
        endpoint="/api/accounts/account-a",
        method="GET",
        object_identifier="account-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )

    print("\n[2] Verified authorization finding")
    print(result)

    finding = result["finding"]

    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["status"] == "verified"
    assert "accountId" in finding["metadata"]["sensitive_fields"]
    assert "email" in finding["metadata"]["sensitive_fields"]
    assert "balance" in finding["metadata"]["sensitive_fields"]


def test_no_authorization_evidence():
    baseline_response = {
        "status_code": 403,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "error": "Forbidden",
        },
    }

    candidate_response = {
        "status_code": 403,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": {
            "error": "Forbidden",
        },
    }

    result = analyze_authorization_difference(
        baseline_response=baseline_response,
        candidate_response=candidate_response,
        endpoint="/api/accounts/account-a",
        method="GET",
    )

    print("\n[3] No authorization weakness established")
    print(result)

    finding = result["finding"]

    assert finding["severity"] == "informational"
    assert finding["confidence"] == "low"
    assert finding["status"] == "candidate"


def test_verified_owner_to_non_owner_identical_success_is_idor():
    owner_response = {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": {
            "accountId": "account-a",
            "email": "account-a@example.test",
            "balance": 125.50,
        },
    }
    non_owner_response = {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": {
            "accountId": "account-a",
            "email": "account-a@example.test",
            "balance": 125.50,
        },
    }

    result = analyze_authorization_difference(
        baseline_response=owner_response,
        candidate_response=non_owner_response,
        endpoint="/api/accounts/account-a",
        object_identifier="account-a",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )

    finding = result["finding"]
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["status"] == "verified"
    assert finding["metadata"]["baseline_context"] == "account_a_confirmed_owner"
    assert any("non-owner" in item for item in finding["evidence"])


def test_identical_success_requires_full_control_context_for_verification():
    response = {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": {"resource": "controlled-object"},
    }

    result = analyze_authorization_difference(
        baseline_response=response,
        candidate_response=response,
        endpoint="/api/resources/controlled-object",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )

    finding = result["finding"]
    assert finding["severity"] == "medium"
    assert finding["status"] == "needs_manual_verification"


def test_empty_success_responses_do_not_establish_idor():
    response = {"status_code": 204, "headers": {}, "body": ""}
    result = analyze_authorization_difference(
        baseline_response=response,
        candidate_response=response,
        endpoint="/api/resources/controlled-object",
        object_identifier="controlled-object",
        ownership_confirmed=True,
        separate_accounts_confirmed=True,
    )

    assert result["finding"]["severity"] == "informational"
    assert result["finding"]["status"] == "candidate"


def main():
    test_unverified_authorization_bypass()
    test_verified_authorization_bypass()
    test_no_authorization_evidence()

    print("\nAuthorization differential tester tests passed.")


if __name__ == "__main__":
    main()
