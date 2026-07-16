from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from agent_core.verification_orchestrator import VerificationOrchestrator


def _read_request_file(file_path: str) -> str:
    path = Path(file_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(f"Request file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Request path is not a file: {path}")

    return path.read_text(encoding="utf-8")


def _parse_header_input(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise ValueError("Header must use the format 'Header-Name: Header value'.")

    name, header_value = value.split(":", 1)

    name = name.strip()
    header_value = header_value.strip()

    if not name:
        raise ValueError("Header name cannot be empty.")

    if not header_value:
        raise ValueError("Header value cannot be empty.")

    return name, header_value


def _prompt_account_b_headers() -> dict[str, str]:
    print("\nAccount B authorization context")
    print("--------------------------------")
    print("Choose the credential type used by Account B:")
    print("1. Authorization header")
    print("2. Cookie header")
    print("3. Custom sensitive header")

    choice = input("Selection [1]: ").strip() or "1"

    if choice == "1":
        value = getpass.getpass(
            "Account B Authorization value " "(example: Bearer TOKEN): "
        ).strip()

        if not value:
            raise ValueError("Account B Authorization value is required.")

        return {
            "Authorization": value,
        }

    if choice == "2":
        value = getpass.getpass(
            "Account B Cookie value " "(example: session=VALUE): "
        ).strip()

        if not value:
            raise ValueError("Account B Cookie value is required.")

        return {
            "Cookie": value,
        }

    if choice == "3":
        header_name = input("Sensitive header name " "(example: X-API-Key): ").strip()

        header_value = getpass.getpass(f"{header_name or 'Header'} value: ").strip()

        if not header_name or not header_value:
            raise ValueError("Both the custom header name and value are required.")

        return {
            header_name: header_value,
        }

    raise ValueError("Invalid credential selection.")


def _confirm(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    response = input(prompt + suffix).strip().lower()

    if not response:
        return default

    return response in {"y", "yes"}


def _print_finding(finding: dict[str, Any]) -> None:
    print("\n" + "=" * 64)
    print("CyberCortex Verification Result")
    print("=" * 64)

    print(f"Title:      {finding.get('title', 'Unknown')}")
    print(f"Category:   {finding.get('category', 'Unknown')}")
    print(f"Severity:   {finding.get('severity', 'Unknown')}")
    print(f"Confidence: {finding.get('confidence', 'Unknown')}")
    print(f"Status:     {finding.get('status', 'Unknown')}")
    print(f"Method:     {finding.get('method', 'Unknown')}")
    print(f"Endpoint:   {finding.get('endpoint', 'Unknown')}")

    evidence = finding.get("evidence", [])

    if evidence:
        print("\nEvidence:")

        for item in evidence:
            print(f"- {item}")

    impact = finding.get("impact")

    if impact:
        print("\nImpact:")
        print(impact)

    recommendation = finding.get("recommendation")

    if recommendation:
        print("\nRecommendation:")
        print(recommendation)

    manual_steps = finding.get("manual_verification", [])

    if manual_steps:
        print("\nManual verification:")

        for item in manual_steps:
            print(f"- {item}")


def _write_safe_result(
    output_file: str,
    result: dict[str, Any],
) -> None:
    path = Path(output_file).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    safe_output = {
        "success": result.get("success"),
        "finding": result.get("finding"),
        "session": result.get("session"),
    }

    path.write_text(
        json.dumps(
            safe_output,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def run_verification(
    raw_request: str,
    account_b_headers: dict[str, str],
    default_scheme: str = "https",
    object_identifier: str | None = None,
    ownership_confirmed: bool = False,
    separate_accounts_confirmed: bool = False,
    verify_tls: bool = True,
) -> dict[str, Any]:
    orchestrator = VerificationOrchestrator()

    session = orchestrator.create_session(
        raw_request=raw_request,
        default_scheme=default_scheme,
    )

    if session.errors:
        return {
            "success": False,
            "error": session.errors[-1],
            "session": session.to_dict(),
        }

    if not session.has_account_a_context():
        return {
            "success": False,
            "error": (
                "The captured request does not contain an "
                "Authorization, Cookie, X-API-Key, or supported "
                "credential header for Account A."
            ),
            "session": session.to_dict(),
        }

    account_b_result = orchestrator.set_account_b_headers(
        session=session,
        headers=account_b_headers,
    )

    if not account_b_result.get("success"):
        return account_b_result

    orchestrator.set_verification_context(
        session=session,
        object_identifier=object_identifier,
        ownership_confirmed=ownership_confirmed,
        separate_accounts_confirmed=separate_accounts_confirmed,
    )

    replay_result = orchestrator.execute_replay(
        session=session,
        verify_tls=verify_tls,
    )

    if not replay_result.get("success"):
        return replay_result

    finding = replay_result.get("finding")

    if finding:
        orchestrator.complete_session(session)

    return {
        "success": True,
        "finding": finding,
        "session": session.to_dict(),
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "CyberCortex controlled authorization verification CLI. "
            "Use only with systems and accounts you are explicitly "
            "authorized to test."
        )
    )

    parser.add_argument(
        "--request",
        required=True,
        help=("Path to a raw HTTP request copied from Burp Repeater."),
    )

    parser.add_argument(
        "--scheme",
        choices=["http", "https"],
        default="https",
        help=(
            "Default URL scheme when the captured request contains " "a relative path."
        ),
    )

    parser.add_argument(
        "--object-id",
        help="Known object identifier used in the verification.",
    )

    parser.add_argument(
        "--account-b-header",
        help=(
            "Account B credential header in the form "
            "'Authorization: Bearer TOKEN'. Avoid this option when "
            "shell history exposure is a concern."
        ),
    )

    parser.add_argument(
        "--ownership-confirmed",
        action="store_true",
        help=("Confirm that ownership of the tested object is known."),
    )

    parser.add_argument(
        "--separate-accounts-confirmed",
        action="store_true",
        help=(
            "Confirm that Account A and Account B are separate " "controlled accounts."
        ),
    )

    parser.add_argument(
        "--no-tls-verify",
        action="store_true",
        help=(
            "Disable TLS certificate validation. Intended only for "
            "authorized local labs."
        ),
    )

    parser.add_argument(
        "--output",
        help=(
            "Optional path for a sanitized JSON result. Raw tokens "
            "and cookies are not written."
        ),
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    print("=" * 64)
    print("CyberCortex Authorization Verification")
    print("=" * 64)
    print(
        "Use only with targets and accounts you are explicitly " "authorized to test."
    )

    try:
        raw_request = _read_request_file(args.request)

        if args.account_b_header:
            header_name, header_value = _parse_header_input(args.account_b_header)

            account_b_headers = {
                header_name: header_value,
            }
        else:
            account_b_headers = _prompt_account_b_headers()

        ownership_confirmed = args.ownership_confirmed

        if not args.ownership_confirmed:
            ownership_confirmed = _confirm(
                "Have you confirmed ownership of the tested object?"
            )

        separate_accounts_confirmed = args.separate_accounts_confirmed

        if not args.separate_accounts_confirmed:
            separate_accounts_confirmed = _confirm(
                "Are Account A and Account B separate " "controlled accounts?"
            )

        result = run_verification(
            raw_request=raw_request,
            account_b_headers=account_b_headers,
            default_scheme=args.scheme,
            object_identifier=args.object_id,
            ownership_confirmed=ownership_confirmed,
            separate_accounts_confirmed=(separate_accounts_confirmed),
            verify_tls=not args.no_tls_verify,
        )

    except (
        FileNotFoundError,
        OSError,
        ValueError,
    ) as error:
        print(f"\nError: {error}")
        return 1

    if not result.get("success"):
        print("\nVerification failed: " + result.get("error", "Unknown error"))
        return 1

    finding = result.get("finding")

    if finding:
        _print_finding(finding)
    else:
        print("\nNo structured finding was generated.")

    if args.output:
        _write_safe_result(
            output_file=args.output,
            result=result,
        )

        print(f"\nSanitized result written to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
