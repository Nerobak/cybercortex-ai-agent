import base64
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.jwt_security_analyzer import (
    analyze_jwt,
    parse_jwt,
)


def _encode_segment(value: dict) -> str:
    raw = json.dumps(
        value,
        separators=(",", ":"),
    ).encode("utf-8")

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _build_token(
    header: dict,
    payload: dict,
    signature: str = "controlled-signature",
) -> str:
    return ".".join(
        [
            _encode_segment(header),
            _encode_segment(payload),
            signature,
        ]
    )


def test_secure_looking_token():
    now = 1_700_000_000

    token = _build_token(
        {
            "alg": "RS256",
            "typ": "JWT",
            "kid": "key-2026-01",
        },
        {
            "sub": "controlled-user",
            "iss": "https://issuer.example.test",
            "aud": "cybercortex-lab",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "role": "user",
        },
    )

    result = analyze_jwt(
        token,
        current_time=now,
    )

    print("\n[1] Secure-looking token")
    print(result)

    assert result["success"] is True
    assert result["signature_verified"] is False
    assert result["summary"]["algorithm"] == "RS256"
    assert result["summary"]["expiration_present"] is True

    titles = {finding["title"] for finding in result["findings"]}

    assert "JWT has no expiration claim" not in titles
    assert "JWT uses the none algorithm" not in titles
    assert "JWT contains authorization-related claims" in titles


def test_none_algorithm_and_missing_expiration():
    token = _build_token(
        {
            "alg": "none",
            "typ": "JWT",
        },
        {
            "sub": "controlled-user",
            "role": "admin",
            "api_key": "must-not-be-stored-here",
        },
        signature="",
    )

    result = analyze_jwt(
        token,
        current_time=1_700_000_000,
    )

    print("\n[2] Unsafe token")
    print(result)

    titles = {finding["title"] for finding in result["findings"]}

    assert "JWT uses the none algorithm" in titles
    assert "JWT has no expiration claim" in titles
    assert "JWT issuer claim is missing" in titles
    assert "JWT audience claim is missing" in titles
    assert "JWT contains potentially sensitive claims" in titles

    assert result["summary"]["highest_severity"] == "high"


def test_expired_and_long_lived_tokens():
    now = 1_700_000_000

    expired_token = _build_token(
        {
            "alg": "RS256",
            "typ": "JWT",
        },
        {
            "iss": "issuer",
            "aud": "audience",
            "iat": now - 7200,
            "exp": now - 3600,
        },
    )

    expired_result = analyze_jwt(
        expired_token,
        current_time=now,
    )

    expired_titles = {finding["title"] for finding in expired_result["findings"]}

    assert "JWT is expired" in expired_titles

    long_lived_token = _build_token(
        {
            "alg": "RS256",
            "typ": "JWT",
        },
        {
            "iss": "issuer",
            "aud": "audience",
            "iat": now,
            "exp": now + 7 * 24 * 60 * 60,
        },
    )

    long_lived_result = analyze_jwt(
        long_lived_token,
        current_time=now,
        max_lifetime_seconds=24 * 60 * 60,
    )

    long_lived_titles = {finding["title"] for finding in long_lived_result["findings"]}

    assert "JWT lifetime is unusually long" in long_lived_titles


def test_future_iat_and_invalid_claim_types():
    now = 1_700_000_000

    token = _build_token(
        {
            "alg": "RS256",
            "typ": "JWT",
        },
        {
            "iss": "issuer",
            "aud": "audience",
            "iat": now + 3600,
            "nbf": "tomorrow",
            "exp": "later",
        },
    )

    result = analyze_jwt(
        token,
        current_time=now,
    )

    titles = {finding["title"] for finding in result["findings"]}

    assert "JWT issue time is in the future" in titles
    assert "JWT nbf claim has an invalid type" in titles
    assert "JWT exp claim has an invalid type" in titles


def test_bearer_prefix_and_malformed_token():
    token = _build_token(
        {
            "alg": "HS256",
            "typ": "JWT",
        },
        {
            "iss": "issuer",
            "aud": "audience",
            "exp": 1_800_000_000,
        },
    )

    result = parse_jwt(f"Bearer {token}")

    assert result["success"] is True
    assert result["header"]["alg"] == "HS256"

    malformed = parse_jwt("not-a-jwt")

    assert malformed["success"] is False


def main():
    test_secure_looking_token()
    test_none_algorithm_and_missing_expiration()
    test_expired_and_long_lived_tokens()
    test_future_iat_and_invalid_claim_types()
    test_bearer_prefix_and_malformed_token()

    print("\nJWT security analyzer tests passed.")


if __name__ == "__main__":
    main()
