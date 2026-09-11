from __future__ import annotations

import argparse
import json
from urllib.parse import urlparse

from agent_core.adaptive_orchestrator import (
    AdaptiveAssessmentOrchestrator,
    write_assessment_plan,
)
from agent_core.agent_models import ContextRunMetadata
from agent_core.capture_ingest import apply_capture_context, import_capture
from agent_core.context import ContextProfileStore, load_context
from agent_core.policy import (
    PolicyProfileStore,
    format_policy_summary,
    load_policy,
    validate_policy,
)
from agent_core.llm_client import ask_agent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan an authorization-first adaptive CyberCortex assessment."
    )
    parser.add_argument("--capture", required=True)
    policy_source = parser.add_mutually_exclusive_group(required=True)
    policy_source.add_argument("--policy", help="Legacy policy JSON file.")
    policy_source.add_argument(
        "--policy-profile", help="Saved profile in config/policies."
    )
    policy_source.add_argument(
        "--auto-policy",
        action="store_true",
        help="Select only an existing exact hostname-to-profile mapping.",
    )
    parser.add_argument(
        "--format",
        default="auto",
        choices=("auto", "har", "raw_http", "openapi", "postman", "graphql", "browser"),
    )
    parser.add_argument("--base-url")
    parser.add_argument(
        "--goal",
        default="Find evidence-supported vulnerabilities in the authorized capture surface.",
    )
    context_source = parser.add_mutually_exclusive_group()
    context_source.add_argument(
        "--context", help="Legacy JSON identity/object ownership annotations."
    )
    context_source.add_argument(
        "--context-profile", help="Saved profile in config/contexts."
    )
    parser.add_argument(
        "--llm-analyst",
        action="store_true",
        help=(
            "Let the configured Ollama model provider propose additional typed "
            "hypotheses; endpoint locality follows its configured base URL."
        ),
    )
    parser.add_argument(
        "--profile",
        default="authenticated",
        choices=("baseline", "deep", "authenticated", "intrusive"),
    )
    parser.add_argument("--output", default="reports/adaptive/assessment-plan.json")
    return parser


def _profile_for_bundle(bundle, store: PolicyProfileStore) -> str:
    hosts = sorted(
        {
            (urlparse(request.url).hostname or "").lower().rstrip(".")
            for request in bundle.requests
            if urlparse(request.url).hostname
        }
    )
    if not hosts:
        raise ValueError("Auto-policy could not find a hostname in the capture.")
    selections: dict[str, str] = {}
    for host in hosts:
        profile = store.profile_for_host(host)
        if profile is None:
            raise ValueError(
                f"No exact policy mapping exists for capture host '{host}'. "
                "Select --policy-profile or create a profile and run policy_cli.py map-host."
            )
        selections[host] = profile
    profiles = set(selections.values())
    if len(profiles) != 1:
        raise ValueError(
            "Capture hosts map to different policy profiles; select one explicit profile "
            "and narrow the capture."
        )
    return next(iter(profiles))


def _validate_bundle_scope(bundle, policy) -> str:
    if not bundle.requests:
        raise ValueError("Capture contains no requests to assess.")
    for request in bundle.requests:
        decision = policy.authorize_url(request.url, method=request.method)
        if not decision.allowed:
            raise ValueError(
                f"Capture request is not authorized ({request.method} {request.url}): "
                + "; ".join(decision.reasons)
            )
    return bundle.requests[0].url


def main(
    argv: list[str] | None = None,
    *,
    policy_store: PolicyProfileStore | None = None,
    context_store: ContextProfileStore | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    profiles = policy_store or PolicyProfileStore()
    contexts = context_store or ContextProfileStore()
    bundle = None
    vault = None
    try:
        bundle, vault = import_capture(
            args.capture,
            capture_format=args.format,
            default_base_url=args.base_url,
        )
        selected_profile = args.policy_profile
        if args.auto_policy:
            selected_profile = _profile_for_bundle(bundle, profiles)
        if selected_profile:
            policy = profiles.load(selected_profile, validate_for_execution=True)
        else:
            policy = validate_policy(load_policy(args.policy))
        if args.context_profile:
            context_model = contexts.load(args.context_profile)
            context = context_model.model_dump(mode="json")
            context_metadata = ContextRunMetadata(
                profile_name=args.context_profile, source="saved_profile"
            )
        elif args.context:
            context_model = load_context(args.context)
            context = context_model.model_dump(mode="json")
            context_metadata = ContextRunMetadata(source="context_file")
        else:
            context = None
            context_metadata = ContextRunMetadata()
        if context:
            apply_capture_context(bundle, context)
        target = _validate_bundle_scope(bundle, policy)
        print(format_policy_summary(policy, profile=selected_profile, target=target))
        print()
        orchestrator = AdaptiveAssessmentOrchestrator()
        plan = orchestrator.plan_from_bundle(
            bundle,
            policy,
            goal=args.goal,
            profile=args.profile,
            llm_analyst=ask_agent if args.llm_analyst else None,
        )
        plan.context_metadata = context_metadata
        write_assessment_plan(plan, args.output)
        print(
            json.dumps(
                {
                    "run_id": plan.run_id,
                    "hypotheses": len(plan.hypotheses),
                    "allowed_plans": sum(
                        item.policy_decision == "allowed"
                        for item in plan.verification_plans
                    ),
                    "selected_tools": plan.selected_tools,
                    "policy": (
                        plan.policy_metadata.model_dump(mode="json")
                        if plan.policy_metadata
                        else None
                    ),
                    "output": args.output,
                },
                indent=2,
            )
        )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"Error: {exc}")
        return 2
    finally:
        if vault is not None:
            vault.close()


if __name__ == "__main__":
    raise SystemExit(main())
