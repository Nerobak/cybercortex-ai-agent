from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.request_mutation_engine import SUPPORTED_FAMILIES, verify_request_mutations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized bounded request mutation verification."
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--parameter", required=True)
    parser.add_argument(
        "--families",
        required=True,
        help="Comma-separated: " + ",".join(sorted(SUPPORTED_FAMILIES)),
    )
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    parser.add_argument("--callback-url")
    parser.add_argument("--traversal-canary-path")
    parser.add_argument("--traversal-expected-marker")
    parser.add_argument("--no-tls-verify", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = verify_request_mutations(
        Path(args.request).read_text(encoding="utf-8"),
        args.parameter,
        [item.strip().lower() for item in args.families.split(",") if item.strip()],
        default_scheme=args.scheme,
        authorization_confirmed=args.authorized,
        callback_url=args.callback_url,
        traversal_canary_path=args.traversal_canary_path,
        traversal_expected_marker=args.traversal_expected_marker,
        verify_tls=not args.no_tls_verify,
    )
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
