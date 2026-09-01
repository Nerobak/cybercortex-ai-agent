from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_core.capture_verification_orchestrator import (
    build_campaign_plan,
    run_campaign,
    write_campaign_report,
)
from agent_core.result_normalizer import public_result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberCortex authorized capture verification campaign."
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--output-directory", default="reports/campaign")
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if not args.execute:
        result = public_result(build_campaign_plan(manifest))
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1
    result = public_result(
        run_campaign(manifest, authorization_confirmed=args.authorized)
    )
    if result.get("success"):
        result["report_files"] = write_campaign_report(result, args.output_directory)
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
