"""Bounded adaptation layer from authorized target discovery to Phase 4 research."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urljoin

from pydantic import Field, StrictFloat, StrictInt

from agent_core.adaptive_orchestrator import AdaptiveAssessmentOrchestrator
from agent_core.attack_surface import (
    CanonicalAttackSurface,
    build_canonical_attack_surface,
)
from agent_core.capture_ingest import CaptureBundle
from agent_core.controlled_context import (
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquirer,
    OwnedObjectAcquisitionError,
    OwnedObjectAcquisitionTransportError,
    owned_object_acquisition_reference,
)
from agent_core.credential_vault import CredentialVault
from agent_core.hypothesis_engine import (
    CATEGORY_PRIORITY,
    generate_surface_hypotheses,
)
from agent_core.models import (
    ModelRoutingPolicy,
    ModelUsageDelta,
    add_model_usage_deltas,
)
from agent_core.policy import AssessmentPolicy
from agent_core.request_budget import (
    RequestBudget,
    RequestBudgetExceeded,
    RequestDelta,
)
from agent_core.research.adapters import (
    AttackSurfaceResearchAdapter,
    ControlledContextResearchAdapter,
    adapt_model_hypotheses,
    adapt_surface_hypotheses,
    digest_for,
    opaque_reference,
    stable_research_identifier,
)
from agent_core.research.authenticated_discovery import (
    ControlledAccountDiscoveryAdapter,
)
from agent_core.research.budgets import ResearchBudgetManager
from agent_core.research.candidates import ExperimentCandidateBuilder
from agent_core.research.compiler import ExperimentCompilerContext
from agent_core.research.graphql import (
    GraphQLAuthenticationRequirement,
    build_graphql_graph_assertions,
)
from agent_core.research.graphql_discovery import (
    GraphQLAuthenticatedDiscovery,
    GraphQLDiscoveryConfig,
    GraphQLDiscoverySession,
    RegisteredGraphQLOperationSource,
    GraphQLSemanticAcquirer,
)
from agent_core.research.graphql_ingest import (
    GraphQLDocumentError,
    parse_graphql_document,
)
from agent_core.research.graphql_hypotheses import (
    GraphQLHypothesisGenerator,
    GraphQLHypothesisLimits,
)
from agent_core.research.graphql_readiness import (
    ControlledObjectDescriptor,
    GraphQLObjectBindingBasis,
    RegisteredGraphQLObjectBindingEvidence,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)
from agent_core.research.graph import GraphAssertion, ResearchGraphRepository
from agent_core.research.reasoning import (
    PublicSafeResearchPacketBuilder,
    ResearchReasoningEngine,
    ResearchReasoningError,
)
from agent_core.research.state import (
    ProvenanceRecord,
    ResearchBootstrapProgress,
    ResearchState,
    TargetAsset,
)
from agent_core.research.store import ResearchStore
from agent_core.research.templates import RequestTemplateFactory
from agent_core.research.transitions import ResearchStateMachine
from agent_core.research.types import (
    ProvenanceProducerType,
    ResearchContract,
    ResearchRunStatus,
    SurfaceType,
    TargetClass,
)
from agent_core.tool_runner import DEFAULT_TOOL_TIMEOUT, ToolRunner
from tool_registry import TOOLS
from tools.safe_http import ScopedHTTPClient

BOOTSTRAP_VERSION = "phase4-blind-bootstrap-v1"


class BootstrapStopReason(str, Enum):
    discovery_request_budget_exhausted = "bootstrap_discovery_request_budget_exhausted"
    wall_time_exhausted = "bootstrap_wall_time_exhausted"
    model_budget_exhausted = "bootstrap_model_budget_exhausted"
    target_out_of_scope = "bootstrap_target_out_of_scope"


class ResearchBootstrapLimits(ResearchContract):
    maximum_discovery_target_requests: StrictInt = Field(default=30, ge=1, le=5_000)
    maximum_graphql_discovery_requests: StrictInt = Field(default=3, ge=0, le=20)
    minimum_post_bootstrap_request_reserve: StrictInt = Field(default=4, ge=1, le=1_000)
    maximum_discovered_endpoints: StrictInt = Field(default=500, ge=1, le=5_000)
    maximum_parameters_imported: StrictInt = Field(default=1_000, ge=1, le=10_000)
    maximum_request_templates: StrictInt = Field(default=500, ge=1, le=5_000)
    maximum_initial_hypotheses: StrictInt = Field(default=200, ge=1, le=5_000)
    maximum_graphql_hypotheses_per_surface: StrictInt = Field(default=12, ge=1, le=200)
    maximum_graphql_hypotheses_per_operation: StrictInt = Field(default=6, ge=1, le=100)
    maximum_graphql_hypotheses_per_object_relationship: StrictInt = Field(
        default=4, ge=1, le=50
    )
    maximum_cross_surface_graphql_hypotheses: StrictInt = Field(default=6, ge=0, le=100)
    maximum_graphql_hypotheses_per_bootstrap: StrictInt = Field(
        default=40, ge=1, le=500
    )
    maximum_bootstrap_model_calls: StrictInt = Field(default=1, ge=0, le=20)
    wall_time_seconds: StrictFloat = Field(default=120.0, ge=1.0, le=3_600.0)


class _BootstrapStopped(RuntimeError):
    def __init__(self, reason: BootstrapStopReason):
        self.reason = reason
        super().__init__(reason.value)


class _DiscoveryBudgetView:
    """A hard phase cap that consumes only the existing authoritative ledger."""

    def __init__(self, budget: RequestBudget, maximum_discovery_requests: int) -> None:
        self._budget = budget
        self._baseline = budget.snapshot()["total_requests"]
        self._maximum = maximum_discovery_requests
        self.limit = budget.limit
        self.per_host_limit = budget.per_host_limit

    @property
    def total(self) -> int:
        return self._budget.total

    @property
    def remaining(self) -> int:
        consumed = self.snapshot()["total_requests"] - self._baseline
        return min(self._budget.remaining, max(0, self._maximum - consumed))

    def consume(self, kind: str, count: int = 1, *, host: str | None = None) -> None:
        consumed = self.snapshot()["total_requests"] - self._baseline
        if consumed + count > self._maximum:
            raise RequestBudgetExceeded("Bootstrap discovery request budget exhausted.")
        self._budget.consume(kind, count, host=host)  # type: ignore[arg-type]

    def host_total(self, host: str) -> int:
        return self._budget.host_total(host)

    def snapshot(self) -> dict[str, int]:
        return self._budget.snapshot()

    def reset_phase_limit(self, remaining_requests: int) -> None:
        self._baseline = self._budget.snapshot()["total_requests"]
        self._maximum = max(0, remaining_requests)


class ResearchBootstrapper:
    """Coordinate existing discovery and small, restart-safe Phase 4 adapters."""

    def __init__(
        self,
        *,
        store: ResearchStore,
        policy: AssessmentPolicy,
        controlled_context: ControlledContext,
        request_budget: RequestBudget,
        budget_manager: ResearchBudgetManager,
        target_id: str,
        profile: str = "authenticated",
        limits: ResearchBootstrapLimits | None = None,
        discovery_orchestrator: AdaptiveAssessmentOrchestrator | None = None,
        tool_runner: object | None = None,
        vault: CredentialVault | None = None,
        capture_bundle: CaptureBundle | None = None,
        object_acquisition_sender: (
            Callable[[dict[str, Any]], dict[str, Any]] | None
        ) = None,
        authenticated_discovery_adapter: (
            ControlledAccountDiscoveryAdapter | None
        ) = None,
        graphql_discovery_config: GraphQLDiscoveryConfig | None = None,
        graphql_hypothesis_generator: GraphQLHypothesisGenerator | None = None,
        reasoning_engine: ResearchReasoningEngine | None = None,
        routing_policy: ModelRoutingPolicy | None = None,
        packet_builder: PublicSafeResearchPacketBuilder | None = None,
        candidate_builder: ExperimentCandidateBuilder | None = None,
        candidate_compiler_context: ExperimentCompilerContext | None = None,
        allowed_hypothesis_categories: Sequence[str] = tuple(CATEGORY_PRIORITY),
        confirmation_policy_reference: str | None = None,
        now: Callable[[], str] | None = None,
    ) -> None:
        if profile not in {"baseline", "deep", "authenticated", "intrusive"}:
            raise ValueError("bootstrap discovery profile is unsupported")
        if budget_manager.request_budget is not request_budget:
            raise ValueError("bootstrap must share the authoritative request budget")
        if reasoning_engine is not None and routing_policy is None:
            raise ValueError("bootstrap model hypotheses require a routing policy")
        if reasoning_engine is not None and packet_builder is None:
            raise ValueError("bootstrap model hypotheses require a packet builder")
        if (candidate_builder is None) != (candidate_compiler_context is None):
            raise ValueError(
                "bootstrap candidate sufficiency requires builder and compiler context"
            )
        if (
            reasoning_engine is not None
            and budget_manager.model_ledger is not reasoning_engine.router.ledger
        ):
            raise ValueError("bootstrap must share the authoritative model ledger")
        self.store = store
        self.policy = policy
        self.controlled_context = controlled_context
        self.request_budget = request_budget
        self.budget_manager = budget_manager
        self.target_id = target_id
        self.profile = profile
        self.limits = limits or ResearchBootstrapLimits()
        self.graphql_discovery_config = (
            graphql_discovery_config
            or GraphQLDiscoveryConfig(
                maximum_graphql_discovery_requests=(
                    self.limits.maximum_graphql_discovery_requests
                )
            )
        )
        if (
            self.graphql_discovery_config.maximum_graphql_discovery_requests
            > self.limits.maximum_graphql_discovery_requests
        ):
            raise ValueError(
                "GraphQL discovery request ceiling exceeds the bootstrap ceiling"
            )
        self.discovery_orchestrator = (
            discovery_orchestrator or AdaptiveAssessmentOrchestrator()
        )
        self.vault = vault
        self.capture_bundle = capture_bundle
        self.object_acquisition_sender = object_acquisition_sender
        self.reasoning_engine = reasoning_engine
        self.routing_policy = routing_policy
        self.packet_builder = packet_builder
        self.candidate_builder = candidate_builder
        self.candidate_compiler_context = candidate_compiler_context
        self.allowed_hypothesis_categories = tuple(allowed_hypothesis_categories)
        self.confirmation_policy_reference = opaque_reference(
            confirmation_policy_reference
            or policy.authorization_reference
            or "bootstrap-confirmation-policy",
            "confirmation-policy",
        )
        self._now_provider = now or (lambda: datetime.now(timezone.utc).isoformat())
        self._started = time.monotonic()
        self._surface_adapter = AttackSurfaceResearchAdapter()
        self._context_adapter = ControlledContextResearchAdapter()
        self._template_factory = RequestTemplateFactory()
        self._capture_cache: dict[str, CaptureBundle] = {}
        self._bootstrap_request_ceiling = min(
            self.limits.maximum_discovery_target_requests,
            max(
                0,
                request_budget.remaining
                - self.limits.minimum_post_bootstrap_request_reserve,
            ),
        )
        self._discovery_budget_view = _DiscoveryBudgetView(
            request_budget, self._bootstrap_request_ceiling
        )
        self._budget_bindings: list[tuple[object, str, object]] = []
        if tool_runner is None:
            budget_view = self._discovery_budget_view
            client = ScopedHTTPClient(policy=policy, budget=budget_view)  # type: ignore[arg-type]
            self.tool_runner = ToolRunner(
                tool_timeout=min(
                    DEFAULT_TOOL_TIMEOUT, int(self.limits.wall_time_seconds)
                ),
                assessment_timeout=int(self.limits.wall_time_seconds),
                policy=policy,
                request_budget=budget_view,  # type: ignore[arg-type]
                http_client=client,
            )
        else:
            self.tool_runner = tool_runner
        candidate_transport = getattr(self.tool_runner, "http_client", None)
        graphql_session = None
        if isinstance(candidate_transport, ScopedHTTPClient):
            graphql_session = GraphQLDiscoverySession(
                client=candidate_transport,
                policy=policy,
                request_budget=candidate_transport.budget,  # type: ignore[arg-type]
                config=self.graphql_discovery_config,
            )
        self.graphql_acquirer = GraphQLSemanticAcquirer(
            config=self.graphql_discovery_config,
            session=graphql_session,
        )
        self._graphql_session = graphql_session
        self.graphql_authenticated_discovery = (
            GraphQLAuthenticatedDiscovery(
                session=graphql_session,
                policy=policy,
                controlled_context=controlled_context,
                vault=vault,
            )
            if graphql_session is not None
            and vault is not None
            and profile == "authenticated"
            else None
        )
        self.graphql_hypothesis_generator = graphql_hypothesis_generator or (
            GraphQLHypothesisGenerator(
                GraphQLHypothesisLimits(
                    max_hypotheses_per_surface=(
                        self.limits.maximum_graphql_hypotheses_per_surface
                    ),
                    max_hypotheses_per_operation=(
                        self.limits.maximum_graphql_hypotheses_per_operation
                    ),
                    max_hypotheses_per_object_relationship=(
                        self.limits.maximum_graphql_hypotheses_per_object_relationship
                    ),
                    max_cross_surface_hypotheses=(
                        self.limits.maximum_cross_surface_graphql_hypotheses
                    ),
                    max_total_new_hypotheses=(
                        self.limits.maximum_graphql_hypotheses_per_bootstrap
                    ),
                ),
                confirmation_policy_reference=self.confirmation_policy_reference,
                allowed_categories=self.allowed_hypothesis_categories,
            )
        )
        self.authenticated_discovery_adapter = authenticated_discovery_adapter
        if (
            self.authenticated_discovery_adapter is None
            and self.profile == "authenticated"
            and self.vault is not None
            and isinstance(candidate_transport, ScopedHTTPClient)
        ):
            self.authenticated_discovery_adapter = ControlledAccountDiscoveryAdapter(
                candidate_transport
            )

    @classmethod
    def register_target(
        cls,
        store: ResearchStore,
        *,
        research_id: str,
        target_url: str,
        target_class: TargetClass,
        scope_reference: str,
        policy: AssessmentPolicy,
        budget_manager: ResearchBudgetManager,
        occurred_at: str | None = None,
    ) -> ResearchState:
        """Create the minimal authorized state accepted by blind bootstrap."""

        decision = policy.authorize_url(target_url, method="GET")
        if not decision.allowed:
            raise ValueError("target is not authorized for bounded discovery")
        timestamp = occurred_at or datetime.now(timezone.utc).isoformat()
        provenance_id = stable_research_identifier(
            "provenance", research_id, "target-registration"
        )
        provenance = ProvenanceRecord(
            provenance_id=provenance_id,
            producer_type=ProvenanceProducerType.researcher,
            producer_name="research-bootstrapper",
            producer_version=BOOTSTRAP_VERSION,
            source_references=(
                opaque_reference(
                    policy.authorization_reference or "authorization-confirmed",
                    "policy",
                ),
            ),
            summary="Registered an explicitly authorized research target.",
            occurred_at=timestamp,
        )
        target = TargetAsset(
            target_id=stable_research_identifier("target", research_id, target_url),
            canonical_reference=target_url,
            target_class=target_class,
            scope_reference=opaque_reference(scope_reference, "scope"),
            provenance_id=provenance_id,
        )
        state = ResearchState(
            research_id=research_id,
            revision=0,
            status=ResearchRunStatus.initializing,
            created_at=timestamp,
            updated_at=timestamp,
            targets=(target,),
            provenance=(provenance,),
        )
        budget = budget_manager.state(state)
        state = state.model_copy(update={"budgets": (budget,)})
        return store.create_research(state)

    def prepare(self, state: ResearchState) -> ResearchState:
        """Run or resume bounded bootstrap until experiment selection is possible."""

        self._activate_phase_budget()
        try:
            while state.status in {
                ResearchRunStatus.initializing,
                ResearchRunStatus.discovering,
                ResearchRunStatus.modeling,
                ResearchRunStatus.hypothesizing,
            }:
                self._check_wall_time()
                if state.status is ResearchRunStatus.initializing:
                    state = self._transition(
                        state,
                        ResearchRunStatus.discovering,
                        "begin-bounded-bootstrap-discovery",
                    )
                elif state.status is ResearchRunStatus.discovering:
                    state = self._discover(state)
                elif state.status is ResearchRunStatus.modeling:
                    state = self._model(state)
                else:
                    state = self._hypothesize(state)
        except _BootstrapStopped as exc:
            current = self.store.load_research(state.research_id)
            if current.status not in {
                ResearchRunStatus.stopped,
                ResearchRunStatus.failed,
            }:
                state = self._transition(
                    current, ResearchRunStatus.stopped, exc.reason.value
                )
            else:
                state = current
        finally:
            self._restore_authoritative_budget()
        return state

    def compiler_context(
        self, state: ResearchState, base: ExperimentCompilerContext
    ) -> ExperimentCompilerContext:
        """Register persistent templates in the existing compiler context."""

        for template in state.request_templates:
            self._template_factory.validate(template, state, policy=self.policy)
        generated = {
            item.template_id: item
            for item in self._template_factory.compiler_templates(state)
        }
        generated.update({item.template_id: item for item in base.request_templates})
        graphql_templates = {
            item.template_id: item
            for item in candidate_ready_graphql_operation_templates(state)
        }
        graphql_templates.update(
            {item.template_id: item for item in base.graphql_operation_templates}
        )
        return base.model_copy(
            update={
                "request_templates": tuple(generated[key] for key in sorted(generated)),
                "graphql_operation_templates": tuple(
                    graphql_templates[key] for key in sorted(graphql_templates)
                ),
            }
        )

    def runtime_request_templates(self, state: ResearchState):
        for template in state.request_templates:
            self._template_factory.validate(template, state, policy=self.policy)
        return self._template_factory.runtime_templates(state)

    def expand_hypotheses_exceptionally(self, state: ResearchState) -> ResearchState:
        """Persist one bounded hypothesis-only model expansion after bootstrap."""

        if (
            self.reasoning_engine is None
            or self.routing_policy is None
            or self.packet_builder is None
            or self.candidate_builder is None
            or not state.evidence
        ):
            return state
        remaining_calls = self.budget_manager.state(state).model_budget.remaining_calls
        if remaining_calls <= 0:
            return state
        packet = self.packet_builder.build(state)
        routing_policy = self.routing_policy.model_copy(
            update={
                "max_provider_attempts": min(
                    self.routing_policy.max_provider_attempts, remaining_calls
                )
            }
        )
        decision = self.reasoning_engine.expand_hypotheses(packet, routing_policy)
        remaining = max(
            0, self.limits.maximum_initial_hypotheses - len(state.hypotheses)
        )
        records, provenance = adapt_model_hypotheses(
            decision.new_hypotheses,
            state,
            allowed_categories=self.allowed_hypothesis_categories,
            confirmation_policy_reference=self.confirmation_policy_reference,
            max_hypotheses=remaining,
            occurred_at=self._now(state),
        )
        merged = self._merge_hypotheses(state, records, provenance)
        synchronized = self.budget_manager.state(merged)
        budgets = {item.budget_reference: item for item in merged.budgets}
        budgets[synchronized.budget_reference] = synchronized
        timestamp = self._now(merged)
        next_state = ResearchState.model_validate(
            {
                **merged.model_dump(mode="python"),
                "revision": state.revision + 1,
                "updated_at": timestamp,
                "budgets": tuple(budgets[key] for key in sorted(budgets)),
            }
        )
        return self.store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=next_state,
        )

    def _discover(self, state: ResearchState) -> ResearchState:
        progress = self._progress(state)
        if progress is not None and progress.discovery_completed:
            return self._transition(
                state, ResearchRunStatus.modeling, "resume-bootstrap-modeling"
            )
        target = self._target(state)
        decision = self.policy.authorize_url(target.canonical_reference, method="GET")
        if not decision.allowed:
            raise _BootstrapStopped(BootstrapStopReason.target_out_of_scope)
        if self.request_budget.remaining <= 0:
            raise _BootstrapStopped(
                BootstrapStopReason.discovery_request_budget_exhausted
            )
        previously_consumed = progress.request_delta.total if progress else 0
        remaining_bootstrap_requests = max(
            0,
            self._bootstrap_request_ceiling - previously_consumed,
        )
        if remaining_bootstrap_requests <= 0:
            raise _BootstrapStopped(
                BootstrapStopReason.discovery_request_budget_exhausted
            )
        readiness_reserve = self._candidate_readiness_reserve()
        ordinary_discovery_limit = max(
            1, remaining_bootstrap_requests - readiness_reserve
        )
        self._discovery_budget_view.reset_phase_limit(ordinary_discovery_limit)
        plan = self.discovery_orchestrator.initial_surface_plan(
            goal="Build bounded Phase 4 research surface",
            target=target.canonical_reference,
            profile=self.profile,
            request_budget=min(
                self.request_budget.remaining,
                remaining_bootstrap_requests,
            ),
        )
        selected_tools = self._permitted_tools(plan.selected_tools)
        before = self.request_budget.snapshot()
        try:
            result = self.tool_runner.run(
                target.canonical_reference,
                profile=self.profile,
                assessment_mode="observe",
                selected_tools=selected_tools,
            )
        except RequestBudgetExceeded as exc:
            delta = RequestDelta.from_snapshots(before, self.request_budget.snapshot())
            failure_progress = self._updated_progress(
                state,
                progress,
                request_delta=delta,
                limitations=(str(exc),),
            )
            accounted = self._with_progress_and_budget(state, failure_progress)
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.discovery_request_budget_exhausted.value,
                replacement=accounted,
            )
        if not isinstance(result, dict):
            raise ValueError("discovery runner returned an invalid result")
        consumed_by_ordinary_discovery = RequestDelta.from_snapshots(
            before, self.request_budget.snapshot()
        ).total
        reservation_limitations = (
            (
                "Optional ordinary discovery was bounded to preserve controlled "
                "candidate-readiness request capacity.",
            )
            if readiness_reserve
            and consumed_by_ordinary_discovery >= ordinary_discovery_limit
            else ()
        )
        self._discovery_budget_view.reset_phase_limit(
            max(0, remaining_bootstrap_requests - consumed_by_ordinary_discovery)
        )
        bundle = self._capture_from_result(result)
        surface = self._canonical_surface(
            target.canonical_reference, result=result, capture_bundle=bundle
        )
        existing_endpoint_ids = {
            item.endpoint_id
            for item in state.endpoints
            if item.target_id == target.target_id
        }
        existing_parameter_count = sum(
            1 for item in state.parameters if item.endpoint_id in existing_endpoint_ids
        )
        records = self._surface_adapter.adapt(
            surface,
            state,
            target_id=target.target_id,
            max_endpoints=max(
                0,
                self.limits.maximum_discovered_endpoints - len(existing_endpoint_ids),
            ),
            max_parameters=max(
                0,
                self.limits.maximum_parameters_imported - existing_parameter_count,
            ),
            occurred_at=self._now(state),
        )
        adapted = self._surface_adapter.apply(state, records)
        graphql_limitations: set[str] = set()
        graphql_sources: tuple[Any, ...] = (
            (bundle, result) if bundle is not None else (result,)
        )
        for graphql_source in graphql_sources:
            graphql_result = self.graphql_acquirer.acquire(
                adapted,
                graphql_source,
                target_id=target.target_id,
                target_url=target.canonical_reference,
                vault=self.vault,
                occurred_at=self._now(adapted),
            )
            adapted = graphql_result.delta.apply(adapted)
            graphql_limitations.update(graphql_result.limitations)
        after = self.request_budget.snapshot()
        delta = RequestDelta.from_snapshots(before, after)
        if previously_consumed + delta.total > self._bootstrap_request_ceiling:
            failure_progress = self._updated_progress(
                state,
                progress,
                request_delta=delta,
                limitations=(
                    "Discovery exceeded the configured bootstrap request limit.",
                ),
            )
            accounted = self._with_progress_and_budget(state, failure_progress)
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.discovery_request_budget_exhausted.value,
                replacement=accounted,
            )
        if bundle is not None:
            self._capture_cache[target.target_id] = bundle
        next_progress = self._updated_progress(
            adapted,
            progress,
            plan_reference=opaque_reference(plan.run_id, "discovery-plan"),
            discovery_completed=True,
            request_delta=delta,
            limitations=tuple(
                (
                    *surface.limitations,
                    *reservation_limitations,
                    *sorted(graphql_limitations),
                )
            ),
        )
        adapted = self._with_progress_and_budget(adapted, next_progress)
        if self._wall_time_exhausted():
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.wall_time_exhausted.value,
                replacement=adapted,
            )
        return self._transition(
            state,
            ResearchRunStatus.modeling,
            "bounded-discovery-imported",
            replacement=adapted,
        )

    def _model(self, state: ResearchState) -> ResearchState:
        progress = self._progress(state)
        if progress is not None and progress.modeling_completed:
            return self._transition(
                state, ResearchRunStatus.hypothesizing, "resume-bootstrap-hypotheses"
            )
        target = self._target(state)
        bundle = self._capture_cache.get(target.target_id) or self.capture_bundle
        captures = tuple(bundle.requests) if bundle is not None else ()
        before = self.request_budget.snapshot()
        acquired, acquisition_limitations, acquisition_diagnostics = (
            self._acquire_objects(progress)
        )
        already_consumed = progress.request_delta.total if progress else 0
        acquisition_consumed = RequestDelta.from_snapshots(
            before, self.request_budget.snapshot()
        ).total
        remaining_after_acquisition = max(
            0,
            self._bootstrap_request_ceiling - already_consumed - acquisition_consumed,
        )
        graphql_authenticated_reserve = self._graphql_authenticated_reserve(
            state, remaining_after_acquisition
        )
        authenticated, authenticated_limitations = self._discover_controlled_objects(
            state,
            target,
            maximum_requests=max(
                0,
                remaining_after_acquisition - graphql_authenticated_reserve,
            ),
        )
        acquired = (*acquired, *authenticated)
        self._register_acquired_objects(acquired)
        context_records = self._context_adapter.adapt(
            self.controlled_context,
            state,
            policy=self.policy,
            target_id=target.target_id,
            vault=self.vault,
            acquired_objects=acquired,
            occurred_at=self._now(state),
        )
        adapted = self._context_adapter.apply(state, context_records)
        adapted, operation_bindings, operation_limitations = (
            self._register_controlled_acquisition_operations(adapted, target, acquired)
        )
        graphql_limitations: tuple[str, ...] = ()
        if bundle is not None:
            graphql_result = self.graphql_acquirer.acquire(
                adapted,
                bundle,
                target_id=target.target_id,
                target_url=target.canonical_reference,
                vault=self.vault,
                occurred_at=self._now(adapted),
            )
            adapted = graphql_result.delta.apply(adapted)
            graphql_limitations = graphql_result.limitations
        adapted, authenticated_graphql_limitations = (
            self._discover_authenticated_graphql(adapted, target)
        )
        adapted, readiness_limitations = derive_candidate_ready_graphql_operations(
            adapted,
            self._controlled_object_descriptors(adapted),
            occurred_at=self._now(adapted),
            binding_evidence=operation_bindings,
        )
        diagnostic_codes = set(adapted.diagnostic_codes)
        diagnostic_codes.update(acquisition_diagnostics)
        if adapted.graphql_surfaces and not adapted.graphql_operations:
            diagnostic_codes.add("no_graphql_operation")
        if adapted.graphql_surfaces and not adapted.objects:
            diagnostic_codes.add("no_controlled_object")
        after = self.request_budget.snapshot()
        delta = RequestDelta.from_snapshots(before, after)
        if (
            self.controlled_context.object_acquisition
            and not adapted.objects
            and already_consumed + delta.total >= self._bootstrap_request_ceiling
        ):
            diagnostic_codes.add("bootstrap_reserve_exhausted")
        if diagnostic_codes != set(adapted.diagnostic_codes):
            adapted = adapted.model_copy(
                update={"diagnostic_codes": tuple(sorted(diagnostic_codes))}
            )
        if (
            progress.request_delta.total if progress else 0
        ) + delta.total > self._bootstrap_request_ceiling:
            failure_progress = self._updated_progress(
                state,
                progress,
                request_delta=delta,
                limitations=(
                    "Controlled and GraphQL acquisition exceeded the configured "
                    "bootstrap request limit.",
                ),
            )
            accounted = self._with_progress_and_budget(state, failure_progress)
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.discovery_request_budget_exhausted.value,
                replacement=accounted,
            )
        templates = self._template_factory.build_all(
            adapted,
            target_id=target.target_id,
            policy=self.policy,
            captures=captures,
            max_templates=self.limits.maximum_request_templates,
        )
        adapted = self._template_factory.apply(adapted, templates)
        next_progress = self._updated_progress(
            adapted,
            progress,
            modeling_completed=True,
            request_delta=delta,
            limitations=(
                *context_records.limitations,
                *acquisition_limitations,
                *operation_limitations,
                *authenticated_limitations,
                *graphql_limitations,
                *authenticated_graphql_limitations,
                *readiness_limitations,
            ),
        )
        adapted = self._with_progress_and_budget(adapted, next_progress)
        if self._wall_time_exhausted():
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.wall_time_exhausted.value,
                replacement=adapted,
            )
        return self._transition(
            state,
            ResearchRunStatus.hypothesizing,
            "bootstrap-research-model-complete",
            replacement=adapted,
        )

    def _hypothesize(self, state: ResearchState) -> ResearchState:
        progress = self._progress(state)
        if progress is not None and progress.hypothesizing_completed:
            return self._transition(
                state,
                ResearchRunStatus.selecting_experiment,
                "resume-experiment-selection",
            )
        target = self._target(state)
        graphql_remaining = max(
            0, self.limits.maximum_initial_hypotheses - len(state.hypotheses)
        )
        graphql_generation = self.graphql_hypothesis_generator.generate_result(
            state,
            ResearchGraphRepository(self.store, state.research_id),
            occurred_at=self._now(state),
            max_new_hypotheses=graphql_remaining,
        )
        adapted = self._merge_hypotheses(
            state,
            graphql_generation.hypotheses,
            graphql_generation.provenance,
        )
        if graphql_generation.truncated:
            adapted = ResearchState.model_validate(
                {
                    **adapted.model_dump(mode="python"),
                    "diagnostic_codes": tuple(
                        sorted(
                            {
                                *adapted.diagnostic_codes,
                                "graphql-hypothesis-generation-truncated",
                            }
                        )
                    ),
                }
            )
        canonical = self._surface_adapter.to_canonical_surface(
            adapted, target_id=target.target_id
        )
        graphql_surface_ids = {
            item.surface_id
            for item in adapted.surfaces
            if item.target_id == target.target_id
            and item.surface_type is SurfaceType.graphql
        } | {
            item.surface_id
            for item in adapted.graphql_surfaces
            if item.target_id == target.target_id
        }
        graphql_endpoint_keys = {
            (item.method.value, item.route_template)
            for item in adapted.endpoints
            if item.surface_id in graphql_surface_ids
        }

        def is_graphql_route(item: Mapping[str, Any]) -> bool:
            return (
                str(item.get("method") or "GET").upper(),
                str(item.get("path") or "/"),
            ) in graphql_endpoint_keys

        canonical = canonical.model_copy(
            update={
                "routes": [
                    item for item in canonical.routes if not is_graphql_route(item)
                ],
                "parameters": [
                    item for item in canonical.parameters if not is_graphql_route(item)
                ],
                "auth_boundaries": [
                    item
                    for item in canonical.auth_boundaries
                    if not is_graphql_route(item)
                ],
                "graphql": {},
            }
        )
        generated = generate_surface_hypotheses(canonical)
        remaining = max(
            0, self.limits.maximum_initial_hypotheses - len(adapted.hypotheses)
        )
        hypotheses, provenance = adapt_surface_hypotheses(
            generated,
            adapted,
            target_id=target.target_id,
            confirmation_policy_reference=self.confirmation_policy_reference,
            max_hypotheses=remaining,
            occurred_at=self._now(state),
        )
        adapted = self._merge_hypotheses(adapted, hypotheses, provenance)
        model_delta = ModelUsageDelta()
        model_limitations: tuple[str, ...] = ()
        attempted = progress.model_usage_delta.attempted_calls if progress else 0
        # P4-1D, not model expansion, will convert deterministic GraphQL
        # hypotheses into experiment candidates. Their presence is sufficient
        # for this hypothesis-only milestone and requires no model call.
        deterministic_candidate_sufficient = bool(graphql_generation.hypotheses)
        if (
            not deterministic_candidate_sufficient
            and self.candidate_builder is not None
            and self.candidate_compiler_context is not None
            and any(
                item.derivation_type.value == "deterministic"
                and item.status.value not in {"closed", "refuted", "supported"}
                for item in adapted.hypotheses
            )
        ):
            context = self.compiler_context(adapted, self.candidate_compiler_context)
            deterministic_candidate_sufficient = bool(
                self.candidate_builder.build(
                    adapted,
                    compiler_context=context,
                    expected_state_revision=adapted.revision,
                    policy_reference=context.policy_reference,
                )
            )
        if (
            self.reasoning_engine is not None
            and self.limits.maximum_bootstrap_model_calls > attempted
            and self.packet_builder is not None
            and adapted.evidence
            and not deterministic_candidate_sufficient
        ):
            ledger = self.reasoning_engine.router.ledger
            before = ledger.snapshot(run_id=state.research_id)
            try:
                packet = self.packet_builder.build(adapted)
                remaining_model_calls = (
                    self.limits.maximum_bootstrap_model_calls - attempted
                )
                routing_policy = self.routing_policy.model_copy(
                    update={
                        "max_provider_attempts": min(
                            self.routing_policy.max_provider_attempts,
                            remaining_model_calls,
                        )
                    }
                )
                decision = (
                    self.reasoning_engine.expand_hypotheses(packet, routing_policy)
                    if self.candidate_builder is not None
                    else self.reasoning_engine.decide(packet, routing_policy)
                )
                remaining = max(
                    0,
                    self.limits.maximum_initial_hypotheses - len(adapted.hypotheses),
                )
                model_records, model_provenance = adapt_model_hypotheses(
                    decision.new_hypotheses,
                    adapted,
                    allowed_categories=self.allowed_hypothesis_categories,
                    confirmation_policy_reference=(self.confirmation_policy_reference),
                    max_hypotheses=remaining,
                    occurred_at=self._now(adapted),
                )
                adapted = self._merge_hypotheses(
                    adapted, model_records, model_provenance
                )
            except ResearchReasoningError as exc:
                model_limitations = (
                    f"Optional local hypothesis generation was unavailable: {exc.reason.value}.",
                )
            after = ledger.snapshot(run_id=state.research_id)
            model_delta = ledger.delta(before, after)
        next_progress = self._updated_progress(
            adapted,
            progress,
            hypothesizing_completed=True,
            model_usage_delta=model_delta,
            limitations=model_limitations,
        )
        adapted = self._with_progress_and_budget(adapted, next_progress)
        if self._wall_time_exhausted():
            return self._transition(
                state,
                ResearchRunStatus.stopped,
                BootstrapStopReason.wall_time_exhausted.value,
                replacement=adapted,
                graph_assertions=graphql_generation.graph_assertions,
            )
        return self._transition(
            state,
            ResearchRunStatus.selecting_experiment,
            "evidence-backed-initial-hypotheses-complete",
            replacement=adapted,
            graph_assertions=graphql_generation.graph_assertions,
        )

    def _acquire_objects(
        self, progress: ResearchBootstrapProgress | None
    ) -> tuple[tuple[ControlledObject, ...], tuple[str, ...], tuple[str, ...]]:
        if not self.controlled_context.object_acquisition:
            return (), (), ()
        if self.object_acquisition_sender is None or self.vault is None:
            return (
                (),
                (
                    "Controlled object acquisition context is incomplete; no object identifier was invented.",
                ),
                (),
            )
        output: list[ControlledObject] = []
        limitations: list[str] = []
        diagnostics: set[str] = set()
        existing = {
            (item.owner_account_id, item.object_type)
            for item in self.controlled_context.objects
            if item.test_owned
        }
        remaining = max(
            0,
            self._bootstrap_request_ceiling
            - (progress.request_delta.total if progress else 0),
        )
        for config in self.controlled_context.object_acquisition:
            if (config.owner_account_id, config.object_type) in existing:
                continue
            if remaining <= 0:
                limitations.append(
                    "Controlled object acquisition was deferred because the bootstrap request limit was exhausted."
                )
                break
            registered_graphql_post = (
                config.method == "POST"
                and config.registered_graphql_document_reference is not None
            )
            registered_document = None
            if registered_graphql_post:
                try:
                    registered_document = parse_graphql_document(
                        self.vault.get(config.registered_graphql_document_reference)
                    )
                except (KeyError, RuntimeError, GraphQLDocumentError, ValueError):
                    limitations.append(
                        "A registered controlled GraphQL acquisition document could "
                        "not be normalized."
                    )
                    continue
                if any(
                    operation.operation_type.value != "query"
                    for operation in registered_document.operations
                ):
                    limitations.append(
                        "A controlled GraphQL acquisition document was not read-only."
                    )
                    continue
            decision = (
                self.policy.authorize_semantically_read_only_url(
                    config.collection_url, method=config.method
                )
                if registered_document is not None
                else self.policy.authorize_url(
                    config.collection_url, method=config.method
                )
            )
            if not decision.allowed or (
                config.method not in {"GET", "HEAD"} and not registered_graphql_post
            ):
                limitations.append(
                    "A controlled object acquisition rule was outside current policy."
                )
                continue
            try:
                before_attempt = self.request_budget.total
                account = self.controlled_context.account(config.owner_account_id)
                output.append(
                    OwnedObjectAcquirer(self.vault, self.request_budget).acquire(
                        account, config, self.object_acquisition_sender
                    )
                )
            except OwnedObjectAcquisitionTransportError as exc:
                diagnostics.add(exc.diagnostic_code)
                limitations.append(str(exc))
            except (KeyError, OwnedObjectAcquisitionError, RequestBudgetExceeded):
                limitations.append(
                    "A bounded controlled object could not be acquired; missing context was retained."
                )
            finally:
                consumed = self.request_budget.total - before_attempt
                remaining = max(0, remaining - consumed)
        return (
            tuple(output),
            tuple(sorted(set(limitations))),
            tuple(sorted(diagnostics)),
        )

    def _register_controlled_acquisition_operations(
        self,
        state: ResearchState,
        target: TargetAsset,
        acquired: Sequence[ControlledObject],
    ) -> tuple[
        ResearchState,
        tuple[RegisteredGraphQLObjectBindingEvidence, ...],
        tuple[str, ...],
    ]:
        """Bridge successful registered GraphQL acquisitions into semantics."""

        if self.vault is None:
            return state, (), ()
        acquired_by_source = {
            item.source_reference: item
            for item in acquired
            if item.source_reference is not None
        }
        current = state
        parsed_by_reference = {}
        limitations: set[str] = set()
        for config in self.controlled_context.object_acquisition:
            document_reference = config.registered_graphql_document_reference
            acquisition_reference = owned_object_acquisition_reference(config)
            if (
                document_reference is None
                or acquisition_reference not in acquired_by_source
            ):
                continue
            try:
                parsed = parse_graphql_document(self.vault.get(document_reference))
            except (KeyError, RuntimeError, GraphQLDocumentError, ValueError):
                limitations.add(
                    "A registered controlled GraphQL acquisition document could not "
                    "be normalized."
                )
                continue
            identity = next(
                (
                    item
                    for item in current.identities
                    if item.account_reference
                    == opaque_reference(config.owner_account_id, "account")
                ),
                None,
            )
            result = self.graphql_acquirer.register_operations(
                current,
                (
                    RegisteredGraphQLOperationSource(
                        endpoint_url=config.collection_url,
                        method="POST",
                        source_kind="registered_graphql_acquisition",
                        source_reference=acquisition_reference,
                        document=parsed,
                        identity_id=(identity.identity_id if identity else None),
                    ),
                ),
                target_id=target.target_id,
                occurred_at=self._now(current),
            )
            current = result.delta.apply(current)
            limitations.update(result.limitations)
            parsed_by_reference[acquisition_reference] = (config, parsed)

        bindings: list[RegisteredGraphQLObjectBindingEvidence] = []
        for acquisition_reference, (config, parsed) in sorted(
            parsed_by_reference.items()
        ):
            if config.graphql_object_variable is None:
                continue
            controlled = acquired_by_source[acquisition_reference]
            research_object = next(
                (
                    item
                    for item in current.objects
                    if item.object_reference
                    == opaque_reference(controlled.object_id, "object-reference")
                    and item.owner_identity_id
                    == next(
                        (
                            identity.identity_id
                            for identity in current.identities
                            if identity.account_reference
                            == opaque_reference(controlled.owner_account_id, "account")
                        ),
                        None,
                    )
                ),
                None,
            )
            operations = tuple(
                item
                for item in current.graphql_operations
                if getattr(item, "document_fingerprint", None)
                in {
                    digest_for(operation.model_dump(mode="json"))
                    for operation in parsed.operations
                }
            )
            variables = tuple(
                variable
                for operation in operations
                for variable in current.graphql_variables
                if variable.operation_id == operation.operation_id
                and variable.name == config.graphql_object_variable
                and variable.linked_argument_id is not None
            )
            if research_object is None or len(variables) != 1:
                continue
            variable = variables[0]
            operation = next(
                item
                for item in operations
                if item.operation_id == variable.operation_id
            )
            semantic_surface = next(
                item
                for item in current.graphql_surfaces
                if item.graphql_surface_id == operation.graphql_surface_id
            )
            bindings.append(
                RegisteredGraphQLObjectBindingEvidence(
                    operation_id=operation.operation_id,
                    variable_id=variable.variable_id,
                    argument_id=str(variable.linked_argument_id),
                    controlled_object_id=research_object.object_id,
                    binding_basis=(
                        GraphQLObjectBindingBasis.explicit_cross_surface_relationship
                        if research_object.surface_id != semantic_surface.surface_id
                        else GraphQLObjectBindingBasis.registered_graphql_acquisition
                    ),
                    evidence_references=tuple(
                        sorted(
                            {
                                *operation.evidence_references,
                                *research_object.evidence_references,
                            }
                        )
                    ),
                )
            )
        return current, tuple(bindings), tuple(sorted(limitations))

    def _discover_controlled_objects(
        self,
        state: ResearchState,
        target: TargetAsset,
        *,
        maximum_requests: int,
    ) -> tuple[tuple[ControlledObject, ...], tuple[str, ...]]:
        adapter = self.authenticated_discovery_adapter
        if (
            adapter is None
            or self.vault is None
            or not self.controlled_context.accounts
        ):
            return (), ()
        result = adapter.discover(
            state,
            target=target,
            context=self.controlled_context,
            policy=self.policy,
            vault=self.vault,
            maximum_requests=maximum_requests,
        )
        return result.objects, result.limitations

    def _discover_authenticated_graphql(
        self, state: ResearchState, target: TargetAsset
    ) -> tuple[ResearchState, tuple[str, ...]]:
        discovery = self.graphql_authenticated_discovery
        if discovery is None or not self.controlled_context.accounts:
            return state, ()
        endpoint_by_id = {item.endpoint_id: item for item in state.endpoints}
        eligible_requirements = {
            GraphQLAuthenticationRequirement.unknown,
            GraphQLAuthenticationRequirement.anonymous_observed,
            GraphQLAuthenticationRequirement.authenticated_observed,
            GraphQLAuthenticationRequirement.authentication_required,
            GraphQLAuthenticationRequirement.role_bound,
            GraphQLAuthenticationRequirement.tenant_bound,
        }
        current = state
        limitations: set[str] = set()
        for surface in state.graphql_surfaces:
            if (
                surface.target_id != target.target_id
                or surface.authentication_requirement not in eligible_requirements
            ):
                continue
            endpoint = endpoint_by_id.get(surface.endpoint_id)
            if endpoint is None:
                continue
            result = discovery.observe(
                current,
                target_id=target.target_id,
                endpoint_url=urljoin(
                    target.canonical_reference,
                    endpoint.route_template,
                ),
                occurred_at=self._now(current),
            )
            current = result.delta.apply(current)
            limitations.update(result.limitations)
        return current, tuple(sorted(limitations))

    def _candidate_readiness_reserve(self) -> int:
        """Reserve bootstrap capacity for evidence that makes candidates usable."""

        if self.profile != "authenticated" or not self.controlled_context.accounts:
            return 0
        pending_objects = sum(
            1
            for config in self.controlled_context.object_acquisition
            if not any(
                item.test_owned
                and item.owner_account_id == config.owner_account_id
                and item.object_type == config.object_type
                for item in self.controlled_context.objects
            )
        )
        # Before discovery establishes a protocol, reserve only generic API
        # semantic and controlled-context capacity.  GraphQL-specific
        # reservation is activated later by _graphql_authenticated_reserve.
        semantic_enrichment = 2
        authenticated_context = min(2, len(self.controlled_context.accounts))
        phase_safety_reserve = 1
        return min(
            max(0, self._bootstrap_request_ceiling - 1),
            pending_objects
            + authenticated_context
            + semantic_enrichment
            + phase_safety_reserve,
        )

    def _graphql_authenticated_reserve(
        self, state: ResearchState, remaining: int
    ) -> int:
        if not state.graphql_surfaces or self.graphql_authenticated_discovery is None:
            return 0
        # The discovery session itself preserves one request, so include that
        # safety margin in this phase's reservation.
        return min(remaining, len(self.controlled_context.accounts) + 2)

    def _controlled_object_descriptors(
        self, state: ResearchState
    ) -> dict[str, ControlledObjectDescriptor]:
        """Join safe imported references back to configured acquisition semantics."""

        configurations = {
            (item.owner_account_id, item.object_type): item
            for item in self.controlled_context.object_acquisition
        }
        identity_by_account = {
            item.account_reference: item.identity_id for item in state.identities
        }
        descriptors: dict[str, ControlledObjectDescriptor] = {}
        for controlled_object in self.controlled_context.objects:
            configuration = configurations.get(
                (controlled_object.owner_account_id, controlled_object.object_type)
            )
            owner_identity_id = identity_by_account.get(
                opaque_reference(controlled_object.owner_account_id, "account")
            )
            if configuration is None or owner_identity_id is None:
                continue
            research_object = next(
                (
                    item
                    for item in state.objects
                    if item.owner_identity_id == owner_identity_id
                    and item.test_owned
                    and item.object_reference
                    == opaque_reference(controlled_object.object_id, "object-reference")
                ),
                None,
            )
            if research_object is not None:
                descriptors[research_object.object_id] = ControlledObjectDescriptor(
                    object_type=controlled_object.object_type,
                    identifier_field=configuration.identifier_field,
                )
        return descriptors

    def _bind_phase_budget(self, runner: object) -> None:
        """Temporarily constrain all bootstrap transports through one ledger view."""

        for owner, attribute in (
            (runner, "request_budget"),
            (runner, "budget"),
            (getattr(runner, "http_client", None), "budget"),
        ):
            if (
                owner is None
                or getattr(owner, attribute, None) is not self.request_budget
            ):
                continue
            self._budget_bindings.append((owner, attribute, self.request_budget))
            setattr(owner, attribute, self._discovery_budget_view)

    def _activate_phase_budget(self) -> None:
        if self._budget_bindings:
            return
        self._bind_phase_budget(self.tool_runner)
        session = self._graphql_session
        if session is not None and session.request_budget is self.request_budget:
            self._budget_bindings.append(
                (session, "request_budget", self.request_budget)
            )
            session.request_budget = self._discovery_budget_view  # type: ignore[assignment]

    def _restore_authoritative_budget(self) -> None:
        for owner, attribute, original in reversed(self._budget_bindings):
            setattr(owner, attribute, original)
        self._budget_bindings.clear()

    def _register_acquired_objects(self, objects: Sequence[ControlledObject]) -> None:
        """Retain raw values only in the process-local controlled context."""

        existing = {
            (item.owner_account_id, item.object_type, item.object_id)
            for item in self.controlled_context.objects
        }
        for item in objects:
            key = (item.owner_account_id, item.object_type, item.object_id)
            if key in existing or len(self.controlled_context.objects) >= 100:
                continue
            self.controlled_context.objects.append(item)
            existing.add(key)

    def _transition(
        self,
        state: ResearchState,
        next_status: ResearchRunStatus,
        reason: str,
        *,
        replacement: ResearchState | None = None,
        graph_assertions: Sequence[GraphAssertion] = (),
    ) -> ResearchState:
        timestamp = self._now(state)
        machine = ResearchStateMachine(state)
        event = machine.transition(
            next_status,
            reason_code=reason,
            event_id=stable_research_identifier(
                "event", state.research_id, state.revision, next_status.value, reason
            ),
            provenance_id=self._transition_provenance(state),
            occurred_at=timestamp,
        )
        lifecycle = machine.snapshot()
        if replacement is not None:
            payload = replacement.model_dump(mode="python")
            payload.update(
                revision=lifecycle.revision,
                status=lifecycle.status,
                updated_at=lifecycle.updated_at,
            )
            lifecycle = ResearchState.model_validate(payload)
        pending_assertions = {item.assertion_id: item for item in graph_assertions}
        for assertion in build_graphql_graph_assertions(
            lifecycle, asserted_at=timestamp
        ):
            try:
                self.store.load_graph_assertion(
                    lifecycle.research_id, assertion.assertion_id
                )
            except KeyError:
                pending_assertions.setdefault(assertion.assertion_id, assertion)
        new_assertions = []
        for assertion_id in sorted(pending_assertions):
            try:
                self.store.load_graph_assertion(lifecycle.research_id, assertion_id)
            except KeyError:
                new_assertions.append(pending_assertions[assertion_id])
        return self.store.commit_revision(
            state.research_id,
            expected_revision=state.revision,
            state=lifecycle,
            events=(event,),
            graph_assertions=tuple(new_assertions),
        )

    def _updated_progress(
        self,
        state: ResearchState,
        progress: ResearchBootstrapProgress | None,
        *,
        plan_reference: str | None = None,
        discovery_completed: bool | None = None,
        modeling_completed: bool | None = None,
        hypothesizing_completed: bool | None = None,
        request_delta: RequestDelta | None = None,
        model_usage_delta: ModelUsageDelta | None = None,
        limitations: Sequence[str] = (),
    ) -> ResearchBootstrapProgress:
        timestamp = self._now(state)
        current_request = progress.request_delta if progress else RequestDelta()
        current_model = progress.model_usage_delta if progress else ModelUsageDelta()
        return ResearchBootstrapProgress(
            bootstrap_id=(
                progress.bootstrap_id
                if progress
                else stable_research_identifier(
                    "bootstrap", state.research_id, self.target_id
                )
            ),
            target_id=self.target_id,
            discovery_plan_reference=(
                plan_reference
                or (progress.discovery_plan_reference if progress else None)
            ),
            discovery_completed=(
                discovery_completed
                if discovery_completed is not None
                else bool(progress and progress.discovery_completed)
            ),
            modeling_completed=(
                modeling_completed
                if modeling_completed is not None
                else bool(progress and progress.modeling_completed)
            ),
            hypothesizing_completed=(
                hypothesizing_completed
                if hypothesizing_completed is not None
                else bool(progress and progress.hypothesizing_completed)
            ),
            request_delta=_add_request_deltas(
                current_request, request_delta or RequestDelta()
            ),
            model_usage_delta=add_model_usage_deltas(
                current_model, model_usage_delta or ModelUsageDelta()
            ),
            started_at=progress.started_at if progress else timestamp,
            updated_at=timestamp,
            limitations=tuple(
                sorted(
                    {
                        *(progress.limitations if progress else ()),
                        *(str(item)[:1_000] for item in limitations if str(item)),
                    }
                )
            ),
            provenance_id=self._transition_provenance(state),
        )

    def _with_progress_and_budget(
        self, state: ResearchState, progress: ResearchBootstrapProgress
    ) -> ResearchState:
        progresses = {item.bootstrap_id: item for item in state.bootstrap_progress}
        progresses[progress.bootstrap_id] = progress
        budget = self.budget_manager.state(state)
        budgets = {item.budget_reference: item for item in state.budgets}
        budgets[budget.budget_reference] = budget
        return ResearchState.model_validate(
            {
                **state.model_dump(mode="python"),
                "bootstrap_progress": tuple(
                    progresses[key] for key in sorted(progresses)
                ),
                "budgets": tuple(budgets[key] for key in sorted(budgets)),
            }
        )

    @staticmethod
    def _merge_hypotheses(
        state: ResearchState,
        hypotheses: Sequence[Any],
        provenance: Sequence[ProvenanceRecord],
    ) -> ResearchState:
        records = {item.hypothesis_id: item for item in state.hypotheses}
        for item in hypotheses:
            records.setdefault(item.hypothesis_id, item)
        provenance_records = {item.provenance_id: item for item in state.provenance}
        for item in provenance:
            provenance_records.setdefault(item.provenance_id, item)
        return ResearchState.model_validate(
            {
                **state.model_dump(mode="python"),
                "hypotheses": tuple(records[key] for key in sorted(records)),
                "provenance": tuple(
                    provenance_records[key] for key in sorted(provenance_records)
                ),
            }
        )

    def _progress(self, state: ResearchState) -> ResearchBootstrapProgress | None:
        return next(
            (
                item
                for item in state.bootstrap_progress
                if item.target_id == self.target_id
            ),
            None,
        )

    def _target(self, state: ResearchState) -> TargetAsset:
        target = next(
            (item for item in state.targets if item.target_id == self.target_id), None
        )
        if target is None:
            raise ValueError("bootstrap target is not registered")
        return target

    def _permitted_tools(self, selected: Sequence[str]) -> list[str]:
        permitted = []
        for name in selected:
            if name in {"ai_report_writer", "graphql_introspection_checker"}:
                continue
            metadata = TOOLS.get(name)
            if metadata is None:
                continue
            if name == "nuclei_scan" and not (
                self.profile == "intrusive"
                and "nuclei_scan" in self.policy.allowed_capabilities
            ):
                continue
            permitted.append(name)
        return sorted(set(permitted))

    def _capture_from_result(self, result: dict[str, Any]) -> CaptureBundle | None:
        raw = result.get("capture_bundle")
        if raw is None:
            return self.capture_bundle
        if isinstance(raw, CaptureBundle):
            return raw
        return CaptureBundle.model_validate(raw)

    @staticmethod
    def _canonical_surface(
        target: str,
        *,
        result: dict[str, Any],
        capture_bundle: CaptureBundle | None,
    ) -> CanonicalAttackSurface:
        supplied = result.get("canonical_attack_surface")
        if supplied is not None:
            return CanonicalAttackSurface.model_validate(supplied)
        return build_canonical_attack_surface(
            target, assessment=result, capture_bundle=capture_bundle
        )

    def _check_wall_time(self) -> None:
        if self._wall_time_exhausted():
            raise _BootstrapStopped(BootstrapStopReason.wall_time_exhausted)

    def _wall_time_exhausted(self) -> bool:
        return time.monotonic() - self._started >= self.limits.wall_time_seconds

    def _now(self, state: ResearchState) -> str:
        candidate = self._now_provider()
        current = _as_datetime(state.updated_at)
        parsed = _as_datetime(candidate)
        return candidate if parsed >= current else state.updated_at

    @staticmethod
    def _transition_provenance(state: ResearchState) -> str:
        if not state.provenance:
            raise ValueError("bootstrap requires registered target provenance")
        return state.provenance[0].provenance_id


def _add_request_deltas(left: RequestDelta, right: RequestDelta) -> RequestDelta:
    discovery = left.discovery + right.discovery
    auth = left.auth + right.auth
    verification = left.verification + right.verification
    cleanup = left.cleanup + right.cleanup
    total = discovery + auth + verification + cleanup
    return RequestDelta(
        discovery=discovery,
        auth=auth,
        verification=verification,
        cleanup=cleanup,
        attempted=total,
        total=total,
    )


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value
    )


def bootstrap_fingerprint(limits: ResearchBootstrapLimits) -> str:
    encoded = limits.model_dump_json().encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


__all__ = [
    "BOOTSTRAP_VERSION",
    "BootstrapStopReason",
    "ResearchBootstrapLimits",
    "ResearchBootstrapper",
    "bootstrap_fingerprint",
]
