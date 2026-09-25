"""Live, bounded entrypoint for Phase 4 blind security research.

``--dry-run`` is a zero-traffic wiring check: it does not perform discovery,
model, or experiment calls. ``--bootstrap-only`` is intentionally different;
it may perform authorized discovery and at most one local model call, but it
does not execute research experiments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit, urlunsplit

from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.agent_models import stable_identifier
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
)
from agent_core.credential_vault import CredentialVault
from agent_core.models import (
    ModelBudgetLimits,
    ModelCallLedger,
    ModelConfiguration,
    ModelRoute,
    ModelRouter,
    ModelRoutingPolicy,
    ProviderRegistry,
    RoutingMode,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentCandidateBuilder,
    ExperimentEvaluator,
    ExperimentSelector,
    PivotPlanner,
    PublicSafeCandidatePacketBuilder,
    PublicSafeResearchPacketBuilder,
    ResearchBootstrapLimits,
    ResearchBootstrapper,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchExecutionGate,
    ResearchLoopResult,
    ResearchReasoningEngine,
    ResearchRunStatus,
    ResearchState,
    ResearchStore,
    SecurityResearchOrchestrator,
    TargetClass,
)
from agent_core.tool_runner import DEFAULT_TOOL_TIMEOUT, ToolRunner
from tools.safe_http import ScopedHTTPClient

DEFAULT_DATABASE = Path("memory/research.sqlite3")
MAXIMUM_CLI_REQUEST_BUDGET = 30
DEFAULT_DISCOVERED_ENDPOINT_LIMIT = 200
DEFAULT_PARAMETER_LIMIT = 500
DEFAULT_TEMPLATE_LIMIT = 200
DEFAULT_HYPOTHESIS_LIMIT = 100

_ACCOUNT_ENVIRONMENT = (
    ("A", "alice"),
    ("B", "bob"),
)


class ResearchCLIError(RuntimeError):
    """A fixed, secret-free operator error."""


@dataclass(frozen=True)
class ResearchWiring:
    store: ResearchStore
    state: ResearchState
    policy: AssessmentPolicy
    controlled_context: ControlledContext
    vault: CredentialVault
    request_budget: RequestBudget
    model_ledger: ModelCallLedger
    budget_manager: ResearchBudgetManager
    reasoning_engine: ResearchReasoningEngine
    routing_policy: ModelRoutingPolicy
    packet_builder: PublicSafeResearchPacketBuilder
    candidate_builder: ExperimentCandidateBuilder
    candidate_packet_builder: PublicSafeCandidatePacketBuilder
    bootstrapper: ResearchBootstrapper
    compiler: ExperimentCompiler
    transport: ScopedHTTPClient


class SafeTracer:
    """Emit only allowlisted event names and caller-supplied safe scalars."""

    _EVENTS = frozenset(
        {
            "DISCOVERY",
            "SURFACE",
            "HYPOTHESIS",
            "PROPOSAL",
            "COMPILE",
            "AUTHORIZE",
            "EXECUTE",
            "EVALUATE",
            "PIVOT",
            "NEW_HYPOTHESIS",
            "CANDIDATE",
            "REPRODUCTION_PLAN",
            "REPRODUCTION_AUTHORIZE",
            "REPRODUCTION_EXECUTE",
            "REPRODUCTION_EVALUATE",
            "CONFIRM",
            "REJECT",
            "MANUAL_REVIEW",
            "STOP",
        }
    )

    def __init__(self, enabled: bool, stream: TextIO) -> None:
        self.enabled = enabled
        self.stream = stream

    def emit(self, event: str, **fields: str | int | bool | None) -> None:
        if not self.enabled:
            return
        if event not in self._EVENTS:
            raise ValueError("unsupported safe trace event")
        payload = {"event": event, **fields}
        print("TRACE " + json.dumps(payload, sort_keys=True), file=self.stream)

    def tool_status(self, name: str, envelope: dict[str, Any]) -> None:
        self.emit(
            "DISCOVERY",
            tool=str(name),
            status=str(envelope.get("status") or "unknown"),
        )

    def discovery_phase(self, name: str) -> None:
        self.emit("DISCOVERY", phase=str(name))


def _bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("expected an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"expected an integer from {minimum} through {maximum}"
            )
        return parsed

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CyberCortex Phase 4 authorized blind research"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run or resume bounded blind research")
    run.add_argument("--target", help="Explicitly authorized HTTP(S) target")
    run.add_argument(
        "--target-class",
        choices=tuple(item.value for item in TargetClass),
        help="Strict target classification (required for a new run)",
    )
    run.add_argument("--research-id", help="Identifier for a new research run")
    run.add_argument("--resume", metavar="RESEARCH_ID", help="Resume persisted state")
    run.add_argument("--provider", choices=("ollama",), default="ollama")
    run.add_argument(
        "--model",
        default=None,
        help="Explicit model override (otherwise use configured provider model)",
    )
    run.add_argument(
        "--model-timeout-seconds",
        type=float,
        default=None,
        help="Explicit provider timeout override in seconds",
    )
    run.add_argument(
        "--model-max-output-tokens",
        type=_bounded_int(1, 1_000_000),
        default=None,
        help="Explicit model output-token ceiling override",
    )
    run.add_argument(
        "--request-budget",
        type=_bounded_int(1, MAXIMUM_CLI_REQUEST_BUDGET),
        default=30,
    )
    run.add_argument("--model-call-budget", type=_bounded_int(1, 10_000), default=8)
    run.add_argument("--experiment-budget", type=_bounded_int(1, 10_000), default=6)
    run.add_argument("--pivot-budget", type=_bounded_int(0, 20), default=2)
    run.add_argument(
        "--per-hypothesis-experiment-budget",
        type=_bounded_int(1, 30),
        default=3,
    )
    run.add_argument("--equivalent-retries", type=_bounded_int(0, 3), default=0)
    run.add_argument("--wall-time", type=_bounded_int(1, 31_536_000), default=900)
    run.add_argument(
        "--database",
        default=str(DEFAULT_DATABASE),
        help="Local research SQLite database (default is ignored by Git)",
    )
    run.add_argument(
        "--read-only",
        action="store_true",
        help="Require GET/HEAD/OPTIONS-only policy and zero state-change budget",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate wiring and summarize persisted state with zero discovery, "
            "model, or experiment traffic"
        ),
    )
    run.add_argument(
        "--bootstrap-only",
        action="store_true",
        help=(
            "Run authorized networked bootstrap only; no experiment execution "
            "requests are made"
        ),
    )
    run.add_argument("--trace", action="store_true", help="Print safe event traces")
    return parser


def normalize_target(target: str) -> str:
    parsed = urlsplit(str(target).strip())
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ResearchCLIError("target_must_be_an_explicit_http_origin_or_prefix")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def controlled_context_from_environment(
    vault: CredentialVault,
    environ: Mapping[str, str] | None = None,
) -> ControlledContext:
    env = os.environ if environ is None else environ
    accounts: list[ControlledAccount] = []
    for slot, default_account_id in _ACCOUNT_ENVIRONMENT:
        prefix = f"CYBERCORTEX_ACCOUNT_{slot}_"
        configured_id = env.get(prefix + "ID")
        raw_token = env.get(prefix + "TOKEN")
        role = env.get(prefix + "ROLE") or "user"
        tenant = env.get(prefix + "TENANT") or None
        any_metadata = any((configured_id, role != "user", tenant))
        if raw_token is None:
            if any_metadata:
                raise ResearchCLIError(
                    f"controlled_account_{slot.lower()}_token_is_missing"
                )
            continue
        account_id = configured_id or default_account_id
        if not raw_token:
            raise ResearchCLIError(f"controlled_account_{slot.lower()}_token_is_empty")
        authorization_value = (
            raw_token if len(raw_token.split(None, 1)) == 2 else f"Bearer {raw_token}"
        )
        reference = vault.put(
            authorization_value,
            label=f"research-cli:{slot.lower()}:{account_id}:token",
        )
        authorization_value = None
        raw_token = None
        accounts.append(
            ControlledAccount(
                account_id=account_id,
                role=role,
                tenant_id=tenant,
                credential_references={"token": reference},
            )
        )
    identifiers = tuple(item.account_id for item in accounts)
    if len(identifiers) != len(set(identifiers)):
        raise ResearchCLIError("controlled_account_ids_must_be_unique")
    return ControlledContext(accounts=accounts)


def _bind_live_session_references(context: ControlledContext) -> None:
    """Bind fresh process-local token handles after persistent import completes."""

    for account in context.accounts:
        account.session_reference = account.credential_references.get("token")


def build_assessment_policy(
    *,
    target: str,
    research_id: str,
    request_budget: int,
    controlled_context: ControlledContext,
) -> AssessmentPolicy:
    parsed = urlsplit(target)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    account_ids = [item.account_id for item in controlled_context.accounts]
    authorization_reference = stable_identifier(
        "policy",
        "phase4-blind-research",
        research_id,
        target,
        request_budget,
        ",".join(sorted(account_ids)),
    )
    return AssessmentPolicy(
        profile_name="phase4-blind-research",
        authorization_reference=authorization_reference,
        authorization_confirmed=True,
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=target,
                schemes=[parsed.scheme],
                ports=[port],
            )
        ],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        oast_allowed=False,
        requests_per_second=2.0,
        max_concurrency=1,
        request_budget=request_budget,
        per_host_request_budget=request_budget,
        credentials_allowed=bool(account_ids),
        controlled_account_ids=account_ids,
        allow_bounded_rate_limit_verification=False,
        max_rate_limit_attempts=0,
        allow_state_changes=False,
        require_test_owned_resources=True,
        require_cleanup_for_state_changes=True,
    )


def _research_budget_policy(args: argparse.Namespace) -> ResearchBudgetPolicy:
    return ResearchBudgetPolicy(
        initial_experiments_per_hypothesis=1,
        pivots_per_hypothesis=args.pivot_budget,
        total_experiments_per_hypothesis=(args.per_hypothesis_experiment_budget),
        experiments_per_surface=args.experiment_budget,
        equivalent_retries=args.equivalent_retries,
        global_experiment_ceiling=args.experiment_budget,
        wall_time_ceiling_seconds=float(args.wall_time),
        state_change_ceiling=0,
        cleanup_request_reserve=0,
    )


def _configured_budget_state(state: ResearchState, research_id: str):
    reference = f"research-cli-budget:{research_id}"
    return next(
        (item for item in state.budgets if item.budget_reference == reference), None
    )


def _restore_request_usage(
    budget: RequestBudget, state: ResearchState, research_id: str, host: str
) -> None:
    persisted = _configured_budget_state(state, research_id)
    if persisted is None:
        raise ResearchCLIError("resume_budget_state_is_unavailable")
    if persisted.request_budget.limit != budget.limit:
        raise ResearchCLIError("resume_request_budget_must_match_persisted_state")
    consumed = persisted.request_budget.consumed
    for kind, count in (
        ("discovery", consumed.discovery),
        ("auth", consumed.auth),
        ("verification", consumed.verification),
        ("cleanup", consumed.cleanup),
    ):
        if count:
            budget.consume(kind, count, host=host)  # type: ignore[arg-type]


def _restore_model_usage(
    ledger: ModelCallLedger,
    state: ResearchState,
    research_id: str,
    model_call_budget: int,
) -> None:
    persisted = _configured_budget_state(state, research_id)
    if persisted is None:
        raise ResearchCLIError("resume_budget_state_is_unavailable")
    if persisted.model_budget.max_calls != model_call_budget:
        raise ResearchCLIError("resume_model_budget_must_match_persisted_state")
    ledger.restore_run_usage(research_id, persisted.model_budget.usage)


def _validate_resume_research_policy(
    state: ResearchState, args: argparse.Namespace
) -> None:
    persisted = _configured_budget_state(state, state.research_id)
    if persisted is None:
        raise ResearchCLIError("resume_budget_state_is_unavailable")
    expected = _research_budget_policy(args)
    if (
        persisted.experiment_ceiling != expected.global_experiment_ceiling
        or persisted.wall_time_ceiling_seconds != expected.wall_time_ceiling_seconds
        or persisted.state_change_ceiling != 0
        or persisted.cleanup_request_reserve != 0
    ):
        raise ResearchCLIError("resume_research_budget_must_match_persisted_state")


def _model_configuration(
    provider: str,
    model: str | None,
    *,
    environ: Mapping[str, str] | None = None,
    timeout_seconds: float | None = None,
    max_output_tokens: int | None = None,
) -> ModelConfiguration:
    """Apply explicit CLI choices without discarding repository configuration."""

    configuration = ModelConfiguration.from_env(environ)
    selected = configuration.provider_configuration(provider)
    updates: dict[str, object] = {}
    if model is not None:
        updates["model_name"] = model
    if timeout_seconds is not None:
        if not 0 < timeout_seconds <= 3_600:
            raise ResearchCLIError("model_timeout_seconds_is_out_of_range")
        updates["timeout_seconds"] = timeout_seconds
    if max_output_tokens is not None:
        updates["max_output_tokens"] = max_output_tokens
    return configuration.model_copy(
        update={
            "default_provider": provider,
            provider: selected.model_copy(update=updates),
        }
    )


def _bootstrap_limits(args: argparse.Namespace) -> ResearchBootstrapLimits:
    return ResearchBootstrapLimits(
        maximum_discovery_target_requests=min(
            MAXIMUM_CLI_REQUEST_BUDGET, args.request_budget
        ),
        maximum_discovered_endpoints=DEFAULT_DISCOVERED_ENDPOINT_LIMIT,
        maximum_parameters_imported=DEFAULT_PARAMETER_LIMIT,
        maximum_request_templates=DEFAULT_TEMPLATE_LIMIT,
        maximum_initial_hypotheses=DEFAULT_HYPOTHESIS_LIMIT,
        maximum_bootstrap_model_calls=min(1, args.model_call_budget),
        wall_time_seconds=float(min(args.wall_time, 300)),
    )


def _resolve_run_identity(
    args: argparse.Namespace, store: ResearchStore
) -> tuple[str, str, TargetClass, ResearchState | None]:
    if bool(args.research_id) == bool(args.resume):
        raise ResearchCLIError("specify_exactly_one_of_research_id_or_resume")
    if args.resume:
        state = store.load_research(args.resume)
        if len(state.targets) != 1:
            raise ResearchCLIError("resume_requires_exactly_one_registered_target")
        persisted_target = state.targets[0]
        target = normalize_target(persisted_target.canonical_reference)
        if args.target is not None and normalize_target(args.target) != target:
            raise ResearchCLIError("resume_target_must_match_persisted_state")
        if (
            args.target_class is not None
            and TargetClass(args.target_class) is not persisted_target.target_class
        ):
            raise ResearchCLIError("resume_target_class_must_match_persisted_state")
        return state.research_id, target, persisted_target.target_class, state
    if args.target is None or args.target_class is None:
        raise ResearchCLIError("new_run_requires_target_and_target_class")
    return (
        args.research_id,
        normalize_target(args.target),
        TargetClass(args.target_class),
        None,
    )


def build_wiring(
    args: argparse.Namespace,
    *,
    vault: CredentialVault,
    controlled_context: ControlledContext,
    tracer: SafeTracer,
    environ: Mapping[str, str] | None = None,
) -> ResearchWiring:
    store = ResearchStore(args.database)
    research_id, target, target_class, resumed_state = _resolve_run_identity(
        args, store
    )
    policy = build_assessment_policy(
        target=target,
        research_id=research_id,
        request_budget=args.request_budget,
        controlled_context=controlled_context,
    )
    request_budget = RequestBudget(
        args.request_budget, per_host_limit=args.request_budget
    )
    model_ledger = ModelCallLedger()
    if resumed_state is not None:
        _validate_resume_research_policy(resumed_state, args)
        _restore_request_usage(
            request_budget,
            resumed_state,
            research_id,
            urlsplit(target).hostname or "",
        )
        _restore_model_usage(
            model_ledger, resumed_state, research_id, args.model_call_budget
        )
    budget_manager = ResearchBudgetManager(
        _research_budget_policy(args),
        request_budget=request_budget,
        model_ledger=model_ledger,
        model_call_ceiling=args.model_call_budget,
        budget_reference=f"research-cli-budget:{research_id}",
        request_ledger_reference=f"research-cli-requests:{research_id}",
        model_ledger_reference=f"research-cli-model-calls:{research_id}",
    )
    if resumed_state is None:
        state = ResearchBootstrapper.register_target(
            store,
            research_id=research_id,
            target_url=target,
            target_class=target_class,
            scope_reference=f"scope:{research_id}",
            policy=policy,
            budget_manager=budget_manager,
        )
    else:
        state = resumed_state

    model_configuration = _model_configuration(
        args.provider,
        args.model,
        environ=environ,
        timeout_seconds=args.model_timeout_seconds,
        max_output_tokens=args.model_max_output_tokens,
    )
    provider_configuration = model_configuration.provider_configuration(args.provider)
    if provider_configuration.model_name is None:
        raise ResearchCLIError("model_name_is_unavailable")
    registry = ProviderRegistry(model_configuration)
    router = ModelRouter(registry, ledger=model_ledger)
    reasoning_engine = ResearchReasoningEngine(
        router, max_output_tokens=provider_configuration.max_output_tokens
    )
    routing_policy = ModelRoutingPolicy(
        mode=RoutingMode.local_only,
        preferred=ModelRoute(
            provider=args.provider, model=provider_configuration.model_name
        ),
        fallbacks=(),
        fallback_allowed=False,
        max_provider_attempts=1,
        allowed_cloud_providers=(),
        budget=ModelBudgetLimits(max_model_calls=args.model_call_budget),
    )
    compiler = ExperimentCompiler()
    packet_builder = PublicSafeResearchPacketBuilder(compiler.registry, budget_manager)
    candidate_builder = ExperimentCandidateBuilder(
        compiler.registry, budget_manager, compiler
    )
    candidate_packet_builder = PublicSafeCandidatePacketBuilder(budget_manager)
    candidate_compiler_context = ExperimentCompilerContext(
        current_time=datetime.now(timezone.utc).isoformat(),
        execution_ready=True,
        max_response_bytes=policy.max_response_bytes,
        max_request_reservation=request_budget.limit,
        policy_reference=policy.authorization_reference,
        context_reference=f"controlled-context:{research_id}",
    )
    transport = ScopedHTTPClient(policy=policy, budget=request_budget)
    tool_runner = ToolRunner(
        tool_timeout=min(DEFAULT_TOOL_TIMEOUT, args.wall_time),
        assessment_timeout=min(args.wall_time, 300),
        max_network_tools=1,
        status_callback=tracer.tool_status if tracer.enabled else None,
        phase_callback=tracer.discovery_phase if tracer.enabled else None,
        policy=policy,
        request_budget=request_budget,
        http_client=transport,
    )
    discovery = AdaptiveAssessmentOrchestrator()
    bootstrapper = ResearchBootstrapper(
        store=store,
        policy=policy,
        controlled_context=controlled_context,
        request_budget=request_budget,
        budget_manager=budget_manager,
        target_id=state.targets[0].target_id,
        profile="authenticated" if controlled_context.accounts else "baseline",
        limits=_bootstrap_limits(args),
        discovery_orchestrator=discovery,
        tool_runner=tool_runner,
        vault=vault,
        reasoning_engine=reasoning_engine,
        routing_policy=routing_policy,
        packet_builder=packet_builder,
        candidate_builder=candidate_builder,
        candidate_compiler_context=candidate_compiler_context,
    )
    return ResearchWiring(
        store=store,
        state=state,
        policy=policy,
        controlled_context=controlled_context,
        vault=vault,
        request_budget=request_budget,
        model_ledger=model_ledger,
        budget_manager=budget_manager,
        reasoning_engine=reasoning_engine,
        routing_policy=routing_policy,
        packet_builder=packet_builder,
        candidate_builder=candidate_builder,
        candidate_packet_builder=candidate_packet_builder,
        bootstrapper=bootstrapper,
        compiler=compiler,
        transport=transport,
    )


def _compiler_context(wiring: ResearchWiring, state: ResearchState):
    base = ExperimentCompilerContext(
        current_time=datetime.now(timezone.utc).isoformat(),
        execution_ready=True,
        max_response_bytes=wiring.policy.max_response_bytes,
        max_request_reservation=wiring.request_budget.limit,
        policy_reference=wiring.policy.authorization_reference,
        context_reference=f"controlled-context:{state.research_id}",
    )
    return wiring.bootstrapper.compiler_context(state, base)


def _build_orchestrator(
    wiring: ResearchWiring, state: ResearchState
) -> SecurityResearchOrchestrator:
    context = _compiler_context(wiring, state)
    wiring.compiler.context = context
    request_templates = wiring.bootstrapper.runtime_request_templates(state)
    gate = ResearchExecutionGate(
        state=state,
        policy=wiring.policy,
        controlled_context=wiring.controlled_context,
        vault=wiring.vault,
        budget=wiring.request_budget,
        transport=wiring.transport,
        compiler_context=context,
        request_templates=request_templates,
        store=wiring.store,
        scope_reference=state.targets[0].scope_reference,
    )
    selector = ExperimentSelector(wiring.compiler, wiring.budget_manager)
    policy_limitations = (
        (
            "No controlled object was acquired; experiments requiring one remain ineligible.",
        )
        if not state.objects
        else ()
    )
    return SecurityResearchOrchestrator(
        store=wiring.store,
        compiler=wiring.compiler,
        gate=gate,
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=wiring.budget_manager,
        reasoning_engine=wiring.reasoning_engine,
        routing_policy=wiring.routing_policy,
        packet_builder=wiring.packet_builder,
        candidate_builder=wiring.candidate_builder,
        candidate_packet_builder=wiring.candidate_packet_builder,
        compiler_context=context,
        runtime=gate.runtime,
        policy_limitations=policy_limitations,
        bootstrapper=wiring.bootstrapper,
        enable_finding_confirmation=True,
    )


def _primitive_names(state: ResearchState, experiment_id: str) -> list[str]:
    outcome = next(
        (
            item
            for item in state.experiment_outcomes
            if item.experiment_id == experiment_id
        ),
        None,
    )
    if outcome is None:
        return []
    evidence_ids = set(outcome.evidence_references)
    names = {
        str(entry.value)
        for evidence in state.evidence
        if evidence.evidence_id in evidence_ids
        for entry in evidence.metadata.entries
        if entry.key == "primitive_name"
    }
    return sorted(names)


def safe_run_summary(
    *,
    state: ResearchState,
    budget_manager: ResearchBudgetManager,
    request_budget: RequestBudget,
    iterations: int,
    stop_reason: str | None,
) -> dict[str, Any]:
    budget_state = budget_manager.state(state)
    hypotheses = [
        {
            "id": item.hypothesis_id,
            "category": item.category,
            "status": item.status.value,
            "attempt_count": item.attempt_count,
            "pivot_count": item.pivot_count,
        }
        for item in state.hypotheses
    ]
    experiments = [
        {
            "id": item.experiment_id,
            "primitive_or_capability": _primitive_names(state, item.experiment_id)
            or ["not_executed"],
            "result_classification": item.result_classification,
            "request_count": item.request_cost,
        }
        for item in state.experiment_history
    ]
    findings = [
        {
            "id": item.finding_id,
            "category": item.category,
            "source_hypothesis": item.source_hypothesis_id,
            "source_experiment": item.candidate_experiment_id,
            "status": item.status.value,
            "reproduction_ids": list(item.reproduction_ids),
            "evidence_references": list(item.evidence_references),
            "confirmation_policy_reference": (item.confirmation_policy_reference),
            "total_finding_request_count": item.total_request_count,
        }
        for item in state.findings
    ]
    return {
        "research_id": state.research_id,
        "final_status": state.status.value,
        "stop_reason": stop_reason,
        "iterations": iterations,
        "request_usage": request_budget.snapshot(),
        "model_usage": budget_state.model_budget.usage.model_dump(mode="json"),
        "surfaces_discovered": len(state.surfaces),
        "endpoints_discovered": len(state.endpoints),
        "parameters_discovered": len(state.parameters),
        "templates_created": len(state.request_templates),
        "identities_imported": len(state.identities),
        "objects_acquired": len(state.objects),
        "hypotheses_generated": len(state.hypotheses),
        "experiments_attempted": len(state.experiment_history),
        "pivots": sum(item.pivot_count for item in state.hypotheses),
        "candidate_findings": len(findings),
        "hypotheses": hypotheses,
        "experiments": experiments,
        "findings": findings,
    }


def _trace_state(tracer: SafeTracer, state: ResearchState, stop_reason: str) -> None:
    tracer.emit(
        "SURFACE",
        surfaces=len(state.surfaces),
        endpoints=len(state.endpoints),
        parameters=len(state.parameters),
    )
    for hypothesis in state.hypotheses:
        tracer.emit(
            "HYPOTHESIS",
            hypothesis_id=hypothesis.hypothesis_id,
            category=hypothesis.category,
            status=hypothesis.status.value,
        )
    for experiment in state.experiment_history:
        tracer.emit("PROPOSAL", proposal_id=experiment.proposal_id)
        tracer.emit("COMPILE", experiment_id=experiment.experiment_id)
        tracer.emit(
            "AUTHORIZE",
            experiment_id=experiment.experiment_id,
            status=experiment.status.value,
        )
        if experiment.status.value not in {"policy_blocked", "duplicate_blocked"}:
            tracer.emit(
                "EXECUTE",
                experiment_id=experiment.experiment_id,
                request_count=experiment.request_cost,
            )
        tracer.emit(
            "EVALUATE",
            experiment_id=experiment.experiment_id,
            classification=experiment.result_classification,
        )
    for hypothesis in state.hypotheses:
        if hypothesis.pivot_count:
            tracer.emit(
                "PIVOT",
                hypothesis_id=hypothesis.hypothesis_id,
                count=hypothesis.pivot_count,
            )
    for finding in state.findings:
        tracer.emit(
            "CANDIDATE",
            finding_id=finding.finding_id,
            status=finding.status.value,
        )
    for plan in state.reproduction_plans:
        tracer.emit(
            "REPRODUCTION_PLAN",
            reproduction_id=plan.reproduction_id,
            finding_id=plan.finding_id,
            dimension=plan.independent_dimension.value,
        )
        if plan.compiled_experiment_id is not None:
            tracer.emit(
                "REPRODUCTION_AUTHORIZE",
                reproduction_id=plan.reproduction_id,
                experiment_id=plan.compiled_experiment_id,
                status=plan.status.value,
            )
    for outcome in state.reproduction_outcomes:
        tracer.emit(
            "REPRODUCTION_EXECUTE",
            reproduction_id=outcome.reproduction_id,
            request_count=outcome.request_delta.total,
        )
        tracer.emit(
            "REPRODUCTION_EVALUATE",
            reproduction_id=outcome.reproduction_id,
            classification=outcome.classification.value,
        )
    for decision in state.confirmation_decisions:
        event = {
            "confirm": "CONFIRM",
            "reject": "REJECT",
            "manual_review": "MANUAL_REVIEW",
        }.get(decision.action.value)
        if event is not None:
            tracer.emit(
                event,
                finding_id=decision.finding_id,
                decision_id=decision.decision_id,
            )
    tracer.emit("STOP", status=state.status.value, reason=stop_reason)


def execute_run(
    args: argparse.Namespace,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
) -> dict[str, Any]:
    if not args.read_only:
        raise ResearchCLIError("read_only_authorization_is_required")
    if args.dry_run and args.bootstrap_only:
        raise ResearchCLIError("dry_run_and_bootstrap_only_are_mutually_exclusive")
    output = stdout or sys.stdout
    tracer = SafeTracer(args.trace, output)
    with CredentialVault() as vault:
        controlled_context = controlled_context_from_environment(vault, environ)
        wiring = build_wiring(
            args,
            vault=vault,
            controlled_context=controlled_context,
            tracer=tracer,
            environ=environ,
        )
        state = wiring.state
        iterations = 0
        stop_reason: str | None = "dry_run"
        if not args.dry_run:
            tracer.emit("DISCOVERY", status="starting")
            state = wiring.bootstrapper.prepare(state)
            tracer.emit(
                "DISCOVERY",
                status="completed",
                requests=wiring.request_budget.total,
            )
            _bind_live_session_references(controlled_context)
            if args.bootstrap_only:
                stop_reason = "bootstrap_only"
            elif state.status not in {
                ResearchRunStatus.stopped,
                ResearchRunStatus.failed,
            }:
                orchestrator = _build_orchestrator(wiring, state)
                result: ResearchLoopResult = orchestrator.run(state.research_id)
                state = result.state
                iterations = result.iterations
                stop_reason = (
                    result.stop_reason.value if result.stop_reason is not None else None
                )
            else:
                stop_reason = "bootstrap_terminal_state"
        stop_reason = stop_reason or "run_incomplete"
        _trace_state(tracer, state, stop_reason)
        return safe_run_summary(
            state=state,
            budget_manager=wiring.budget_manager,
            request_budget=wiring.request_budget,
            iterations=iterations,
            stop_reason=stop_reason,
        )


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    try:
        args = build_parser().parse_args(argv)
        summary = execute_run(args, environ=environ, stdout=output)
    except ResearchCLIError as exc:
        print(f"research CLI error: {exc}", file=errors)
        return 2
    except Exception as exc:
        print(
            f"research CLI failed safely ({type(exc).__name__})",
            file=errors,
        )
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True), file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
