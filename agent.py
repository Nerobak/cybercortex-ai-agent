import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
import argparse
from urllib.parse import urlparse

from agent_core.workflow_manager import run_workflow
from tools.scope_guard import enforce_scope


def normalize_target(target: str) -> str:
    if not target.startswith("http"):
        target = "https://" + target
    return target


def extract_allowed_domain(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc.replace("www.", "")


def run_assessment(target: str, mode: str = "safe"):
    target = normalize_target(target)

    scope = enforce_scope(target)

    if not scope["allowed"]:
        print("\n[BLOCKED]")
        print(scope["error"])
        print("Add this domain to PENTEST_ALLOWLIST only if you are authorized to test it.\n")
        return

    allowed_domain = extract_allowed_domain(target)

    goal = f"Perform a {mode} authorized security assessment of {target} and generate a report."

    result = run_workflow(
        goal=goal,
        target=target,
        allowed_domain=allowed_domain,
    )

    print("\nAssessment complete.")
    print("Completed steps:")
    print(result["completed_steps"])

    report_result = result["results"].get("ai_report_writer")

    if report_result:
        print("\nReport generated:")
        print(report_result.get("report_file"))

    print("\n")


def interactive_mode():

    print("\n==================================================")
    print("              CyberCortex AI Agent")
    print("          Local AI Security Platform")
    print("==================================================")
    print("Version: 1.0 Beta")
    print("Mode: Safe Authorized Assessment")
    print("Powered by Ollama + DeepSeek R1 Distill 32B")
    print("--------------------------------------------------\n")
    print("Type a target URL to analyze, or type 'exit' to quit.\n")

    while True:
        target = input("Target URL > ").strip()

        if target.lower() in ["exit", "quit"]:
            print("Goodbye.")
            break

        run_assessment(target, mode="safe")


def main():
    parser = argparse.ArgumentParser(
        description="CyberCortex AI Agent for authorized security testing."
    )

    parser.add_argument(
        "--target",
        help="Target URL or domain to assess.",
    )

    parser.add_argument(
        "--mode",
        default="safe",
        choices=["safe"],
        help="Assessment mode. Currently only 'safe' is supported.",
    )

    args = parser.parse_args()

    if args.target:
        run_assessment(args.target, args.mode)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
