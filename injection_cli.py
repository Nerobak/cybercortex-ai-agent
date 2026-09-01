from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.authenticated_injection_verifier import verify_boolean_sql_injection


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded authenticated SQL injection verification for authorized targets."
    )
    parser.add_argument("--request", required=True, help="Raw HTTP request file.")
    parser.add_argument(
        "--parameter", required=True, help="One query parameter to test."
    )
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    parser.add_argument(
        "--authorized", action="store_true", help="Confirm explicit authorization."
    )
    parser.add_argument("--no-tls-verify", action="store_true")
    parser.add_argument("--output", help="Optional sanitized JSON result path.")
    args = parser.parse_args()

    raw_request = Path(args.request).read_text(encoding="utf-8")
    result = verify_boolean_sql_injection(
        raw_request,
        args.parameter,
        default_scheme=args.scheme,
        authorization_confirmed=args.authorized,
        verify_tls=not args.no_tls_verify,
    )
    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
