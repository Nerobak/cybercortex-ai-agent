import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from pathlib import Path
from tempfile import TemporaryDirectory

from agent_core.memory_manager import (
    clear_target_history,
    get_latest_assessment,
    get_target_history,
    list_targets,
    load_memory,
    record_assessment,
)


def main():
    with TemporaryDirectory() as temporary_directory:
        memory_file = Path(temporary_directory) / "scan_history.json"

        first_results = {
            "headers": {
                "present": [
                    "Strict-Transport-Security",
                    "X-Frame-Options",
                ],
                "missing": [
                    "Content-Security-Policy",
                ],
            },
            "nuclei": {
                "findings_count": 1,
                "findings": [
                    "content-security-policy",
                ],
            },
        }

        second_results = {
            "headers": {
                "present": [
                    "Strict-Transport-Security",
                    "X-Frame-Options",
                    "Content-Security-Policy",
                ],
                "missing": [],
            },
            "nuclei": {
                "findings_count": 0,
                "findings": [],
            },
        }

        print("[1] Initial memory")
        print(load_memory(memory_file))

        print("\n[2] Record first assessment")
        print(
            record_assessment(
                target="https://example.com",
                results=first_results,
                report_file="reports/example-first.md",
                memory_file=memory_file,
            )
        )

        print("\n[3] Record second assessment")
        print(
            record_assessment(
                target="https://www.example.com/path",
                results=second_results,
                report_file="reports/example-second.md",
                memory_file=memory_file,
            )
        )

        print("\n[4] Target history")
        history = get_target_history(
            "example.com",
            memory_file=memory_file,
        )
        print(history)
        assert len(history) == 2

        print("\n[5] Latest assessment")
        latest = get_latest_assessment(
            "https://example.com",
            memory_file=memory_file,
        )
        print(latest)
        assert latest is not None
        assert latest["results"]["nuclei"]["findings_count"] == 0

        print("\n[6] Stored targets")
        targets = list_targets(memory_file)
        print(targets)
        assert targets[0]["assessment_count"] == 2

        print("\n[7] Clear history")
        cleared = clear_target_history(
            "example.com",
            memory_file=memory_file,
        )
        print(cleared)
        assert cleared["removed_count"] == 2

        print("\nMemory manager tests passed.")


if __name__ == "__main__":
    main()
