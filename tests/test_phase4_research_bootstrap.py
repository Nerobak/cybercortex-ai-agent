from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from agent_core.attack_surface import CanonicalAttackSurface, SurfaceEvidence
from agent_core.capture_ingest import (
    CaptureBundle,
    CapturedParameter,
    CapturedRequest,
)
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
)
from agent_core.credential_vault import CredentialVault
from agent_core.models import (
    ModelCallLedger,
    ModelResponse,
    ModelRoute,
    ModelRoutingPolicy,
    ModelUsageDelta,
    RoutingMode,
)
from agent_core.phase2_result_status import Phase2ResultStatus
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget, RequestDelta
from agent_core.research import (
    BaselineIntent,
    BaselineKind,
    CleanupExecutionResult,
    CleanupStatus,
    DifferentialSelector,
    EvidenceIntent,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentEvaluator,
    ExperimentProposal,
    ExperimentResultClassification,
    ExperimentSelector,
    IdentityRelationship,
    IdentitySwitchInput,
    InformationGainEstimate,
    MutationIntent,
    NewHypothesisProposal,
    OrchestratorStopReason,
    PivotPlanner,
    PrimitiveExecutionEvidence,
    PrimitiveStepProposal,
    PublicSafeResearchPacketBuilder,
    RequestReplayInput,
    ResearchBootstrapLimits,
    ResearchBootstrapper,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchCleanupBarrier,
    ResearchConfidence,
    ResearchReasoningEngine,
    ResearchRunStatus,
    ResearchRuntime,
    ResearchStore,
    ResearchStrategyAction,
    ResearchStrategyCandidate,
    RuntimeProvenance,
    SecurityResearchOrchestrator,
    TargetClass,
)
from agent_core.research.outcomes import ExperimentOutcome
from agent_core.research.evaluation import HypothesisProposalSource
from agent_core.research.templates import RequestTemplateFactory
from agent_core.research.types import ExperimentRuntimeStatus, HttpMethod
from agent_core.research import Parameter, ParameterLocation, ResearchState

NOW = "2026-09-22T12:00:00+00:00"
TARGET = "https://blind.example"
SECRET_SENTINEL = "synthetic-secret-bootstrap-sentinel"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="blind-bootstrap",
        authorization_reference="authorization-blind-bootstrap",
        authorization_confirmed=True,
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=TARGET,
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        controlled_account_ids=["account-a", "account-b"],
        credentials_allowed=True,
        request_budget=30,
        per_host_request_budget=30,
        resolve_dns_before_request=False,
    )


def discovery_surface(*, empty: bool = False) -> CanonicalAttackSurface:
    if empty:
        return CanonicalAttackSurface(
            target=TARGET,
            evidence_sources=[
                SurfaceEvidence(source="fake-local-discovery", reference="run-empty")
            ],
        )
    return CanonicalAttackSurface(
        target=TARGET,
        routes=[
            {
                "method": "GET",
                "path": "/admin/users/{user_id}",
                "source": "fake-local-discovery",
                "confidence": "high",
                "evidence_refs": ["capture-admin-user"],
                "content_types": ["application/json"],
            }
        ],
        parameters=[
            {
                "method": "GET",
                "path": "/admin/users/{user_id}",
                "name": "user_id",
                "in": "path",
                "schema_type": "string",
                "required": True,
                "source": "fake-local-discovery",
                "confidence": "high",
                "evidence_refs": ["capture-admin-user"],
            }
        ],
        auth_boundaries=[
            {
                "method": "GET",
                "path": "/admin/users/{user_id}",
                "boundary_type": "authenticated_resource",
                "confidence": "high",
                "evidence_refs": ["capture-admin-user"],
            }
        ],
        evidence_sources=[
            SurfaceEvidence(
                source="fake-local-discovery", reference="run-blind-bootstrap"
            )
        ],
        limitations=["Fake local discovery does not establish a vulnerability."],
    )


def capture_bundle() -> CaptureBundle:
    return CaptureBundle(
        source_format="browser",
        source_ref="fake-local-browser",
        requests=[
            CapturedRequest(
                request_id="capture-admin-user",
                source_format="browser",
                source_ref="fake-local-browser",
                method="GET",
                url=f"{TARGET}/admin/users/{{user_id}}",
                path="/admin/users/{user_id}",
                headers={"Authorization": f"Bearer {SECRET_SENTINEL}"},
                parameters=[
                    CapturedParameter(
                        name="user_id",
                        location="path",
                        value_type="string",
                        required=True,
                    )
                ],
                identity_id="account-a",
            )
        ],
    )


class FakeDiscoveryRunner:
    def __init__(
        self,
        budget: RequestBudget,
        *,
        surface: CanonicalAttackSurface | None = None,
        capture: CaptureBundle | None = None,
    ) -> None:
        self.budget = budget
        self.surface = surface or discovery_surface()
        self.capture = capture
        self.calls = 0

    def run(self, target, **kwargs):
        del target, kwargs
        self.calls += 1
        self.budget.consume("discovery", host="blind.example")
        result = {"canonical_attack_surface": self.surface.model_dump(mode="json")}
        if self.capture is not None:
            result["capture_bundle"] = self.capture.model_dump(mode="json")
        return result


def controlled(vault: CredentialVault) -> ControlledContext:
    session_a = vault.put(SECRET_SENTINEL, label="session-a")
    session_b = vault.put(f"{SECRET_SENTINEL}-b", label="session-b")
    password_a = vault.put(f"{SECRET_SENTINEL}-password", label="password-a")
    return ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="account-a",
                role="user",
                tenant_id="tenant-one",
                credential_references={"password": password_a},
                session_reference=session_a,
            ),
            ControlledAccount(
                account_id="account-b",
                role="admin",
                tenant_id="tenant-one",
                session_reference=session_b,
            ),
        ]
    )


def bootstrap_fixture(tmp_path, *, empty: bool = False, model_ledger=None):
    store = ResearchStore(tmp_path / "blind-bootstrap.sqlite3")
    request_budget = RequestBudget(30, per_host_limit=30)
    budgets = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=3600.0),
        request_budget=request_budget,
        model_ledger=model_ledger,
        model_call_ceiling=10,
    )
    initial = ResearchBootstrapper.register_target(
        store,
        research_id="research-blind",
        target_url=TARGET,
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-blind",
        policy=policy(),
        budget_manager=budgets,
        occurred_at=NOW,
    )
    vault = CredentialVault()
    context = controlled(vault)
    runner = FakeDiscoveryRunner(
        request_budget,
        surface=discovery_surface(empty=empty),
        capture=None if empty else capture_bundle(),
    )
    bootstrapper = ResearchBootstrapper(
        store=store,
        policy=policy(),
        controlled_context=context,
        request_budget=request_budget,
        budget_manager=budgets,
        target_id=initial.targets[0].target_id,
        tool_runner=runner,
        vault=vault,
        limits=ResearchBootstrapLimits(
            maximum_discovery_target_requests=5,
            maximum_discovered_endpoints=20,
            maximum_parameters_imported=50,
            maximum_request_templates=20,
            maximum_initial_hypotheses=20,
            maximum_bootstrap_model_calls=0,
            wall_time_seconds=30.0,
        ),
        now=lambda: NOW,
    )
    return store, budgets, vault, runner, bootstrapper


def proposal_from_state(state, *, proposal_id="proposal-blind", selector=None):
    hypothesis = next(
        item for item in state.hypotheses if item.category == "vertical_authorization"
    )
    endpoint = next(
        item for item in state.endpoints if item.surface_id == hypothesis.surface_id
    )
    template = next(
        item
        for item in state.request_templates
        if item.endpoint_id == endpoint.endpoint_id
    )
    user = next(item for item in state.identities if item.role_reference == "user")
    admin = next(item for item in state.identities if item.role_reference == "admin")
    return ExperimentProposal(
        proposal_id=proposal_id,
        research_id=state.research_id,
        state_revision=state.revision,
        hypothesis_id=hypothesis.hypothesis_id,
        capability="request_replay",
        target_id=hypothesis.target_id,
        surface_id=hypothesis.surface_id,
        endpoint_id=endpoint.endpoint_id,
        objective="Compare the discovered privileged route across controlled roles.",
        primary_identity_id=user.identity_id,
        comparison_identity_id=admin.identity_id,
        identity_relationship=IdentityRelationship.user_admin,
        baseline_strategy=BaselineIntent(
            kind=BaselineKind.registered_request,
            reference_id=template.template_id,
        ),
        mutation_intent=MutationIntent(kind="context_switch"),
        expected_secure_behavior="The lower role is denied protected functionality.",
        expected_vulnerable_behavior="The lower role receives protected functionality.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=selector or DifferentialSelector.status_class,
                predicate_reference=f"predicate-{proposal_id}",
            ),
        ),
        rationale="A controlled role comparison can falsify the authorization claim.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id=f"replay-user-{proposal_id}",
                input=RequestReplayInput(
                    request_template_id=template.template_id,
                    endpoint_id=endpoint.endpoint_id,
                    identity_id=user.identity_id,
                ),
            ),
            PrimitiveStepProposal(
                step_id=f"switch-{proposal_id}",
                input=IdentitySwitchInput(
                    primary_identity_id=user.identity_id,
                    comparison_identity_id=admin.identity_id,
                    relationship=IdentityRelationship.user_admin,
                ),
            ),
            PrimitiveStepProposal(
                step_id=f"replay-admin-{proposal_id}",
                input=RequestReplayInput(
                    request_template_id=template.template_id,
                    endpoint_id=endpoint.endpoint_id,
                ),
            ),
        ),
        provenance_id=hypothesis.provenance_id,
    )


def test_blind_bootstrap_discovers_models_hypothesizes_and_compiles(tmp_path):
    store, budgets, vault, runner, bootstrapper = bootstrap_fixture(tmp_path)
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        assert state.status is ResearchRunStatus.selecting_experiment
        assert len(state.endpoints) == 1
        assert len(state.parameters) == 1
        assert len(state.request_templates) == 1
        assert len(state.identities) == 2
        assert any(
            item.category == "vertical_authorization" for item in state.hypotheses
        )
        context = bootstrapper.compiler_context(
            state,
            ExperimentCompilerContext(
                current_time=NOW,
                execution_ready=True,
                policy_reference="policy-blind",
                context_reference="context-blind",
            ),
        )
        proposal = proposal_from_state(state)
        compiler = ExperimentCompiler(context=context)
        selection = ExperimentSelector(compiler, budgets).select(
            (proposal,), state, compiler_context=context
        )
        assert selection.selected is not None
        experiment = compiler.compile(proposal, state, context)
        assert experiment.expires_at == "2026-09-22T12:15:00+00:00"
        assert experiment.target.endpoint_id == state.endpoints[0].endpoint_id
        assert runner.calls == 1
    finally:
        vault.close()


def test_capture_template_secret_boundary_and_identity_survives_adapters(tmp_path):
    store, budgets, vault, _runner, bootstrapper = bootstrap_fixture(tmp_path)
    del budgets
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        template = state.request_templates[0]
        compiler_template = RequestTemplateFactory.to_compiler_template(template)
        compiler_context = bootstrapper.compiler_context(
            state,
            ExperimentCompilerContext(
                current_time=NOW,
                execution_ready=True,
                policy_reference="policy-blind",
                context_reference="context-blind",
            ),
        )
        runtime_template = RequestTemplateFactory.to_runtime_template(template, state)
        packet = PublicSafeResearchPacketBuilder(
            ExperimentCompiler().registry,
            bootstrapper.budget_manager,
        ).build(state)
        serialized = "\n".join(
            (
                state.model_dump_json(),
                packet.model_dump_json(),
                compiler_template.model_dump_json(),
                compiler_context.model_dump_json(),
                runtime_template.model_dump_json(),
            )
        )
        assert SECRET_SENTINEL not in serialized
        assert "Bearer" not in serialized
        assert template.template_id == compiler_template.template_id
        assert template.template_id == runtime_template.template_id
        assert runtime_template.credential_header_name == "Authorization"
        assert not runtime_template.safe_headers
        assert template.identity_requirement.role_reference == "user"
        assert template.identity_requirement.tenant_bound is True
    finally:
        vault.close()


def test_endpoint_template_infers_only_evidenced_authentication_headers(tmp_path):
    store, _budgets, vault, _runner, bootstrapper = bootstrap_fixture(tmp_path)
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        endpoint = state.endpoints[0]

        def with_headers(*names: str) -> ResearchState:
            parameters = tuple(
                Parameter(
                    parameter_id=f"header-parameter-{index}",
                    endpoint_id=endpoint.endpoint_id,
                    name=name,
                    location=ParameterLocation.header,
                    required=True,
                    evidence_references=endpoint.evidence_references,
                    provenance_id=endpoint.provenance_id,
                )
                for index, name in enumerate(names)
            )
            return ResearchState.model_validate(
                {
                    **state.model_dump(mode="python"),
                    "request_templates": (),
                    "parameters": (*state.parameters, *parameters),
                }
            )

        anonymous = RequestTemplateFactory().from_endpoint(
            endpoint, state, policy=policy()
        )
        unrelated_state = with_headers("X-Trace-Id")
        unrelated = RequestTemplateFactory().from_endpoint(
            endpoint, unrelated_state, policy=policy()
        )
        authorization_state = with_headers("Authorization")
        authorization = RequestTemplateFactory().from_endpoint(
            endpoint, authorization_state, policy=policy()
        )
        multiple_state = with_headers("Authorization", "Cookie")
        multiple = RequestTemplateFactory().from_endpoint(
            endpoint, multiple_state, policy=policy()
        )

        assert anonymous.identity_requirement.required is False
        assert anonymous.identity_requirement.mechanisms == ()
        assert unrelated.identity_requirement.required is False
        assert unrelated.identity_requirement.mechanisms == ()
        assert authorization.identity_requirement.required is True
        assert authorization.identity_requirement.mechanisms == (
            "authorization_header",
        )
        assert multiple.identity_requirement.mechanisms == (
            "authorization_header",
            "cookie",
        )
        runtime = RequestTemplateFactory.to_runtime_template(
            authorization, authorization_state
        )
        assert runtime.credential_header_name == "Authorization"
        assert all(item.name != "Authorization" for item in runtime.parameters)
    finally:
        vault.close()


def test_bootstrap_is_idempotent_and_does_not_reset_accounting(tmp_path):
    store, _budgets, vault, runner, bootstrapper = bootstrap_fixture(tmp_path)
    try:
        first = bootstrapper.prepare(store.load_research("research-blind"))
        first_budget = first.budgets[0].request_budget.consumed.total
        second_bootstrapper = ResearchBootstrapper(
            store=store,
            policy=policy(),
            controlled_context=bootstrapper.controlled_context,
            request_budget=bootstrapper.request_budget,
            budget_manager=bootstrapper.budget_manager,
            target_id=first.targets[0].target_id,
            tool_runner=runner,
            vault=vault,
            limits=bootstrapper.limits,
            now=lambda: NOW,
        )
        second = second_bootstrapper.prepare(first)
        assert second == first
        assert runner.calls == 1
        assert len(second.endpoints) == 1
        assert len(second.parameters) == 1
        assert len(second.request_templates) == 1
        assert second.budgets[0].request_budget.consumed.total == first_budget
        assert second.bootstrap_progress[0].request_delta.discovery == 1
    finally:
        vault.close()


def test_controlled_object_results_are_adapted_without_hints_or_third_parties(tmp_path):
    store, _budgets, vault, _runner, bootstrapper = bootstrap_fixture(tmp_path)
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        records = bootstrapper._context_adapter.adapt_acquired_objects(
            (
                ControlledObject(
                    object_id="object-acquired-1",
                    owner_account_id="account-a",
                    object_type="user",
                    test_owned=True,
                ),
                ControlledObject(
                    object_id="third-party-object",
                    owner_account_id="unknown-account",
                    object_type="user",
                    test_owned=False,
                ),
            ),
            bootstrapper.controlled_context,
            state,
            policy=policy(),
            target_id=state.targets[0].target_id,
            vault=vault,
            occurred_at=NOW,
        )
        assert len(records.objects) == 1
        assert records.objects[0].test_owned is True
        assert records.objects[0].owner_identity_id is not None
        assert "third-party-object" not in records.model_dump_json()
    finally:
        vault.close()


class InitialHypothesisRouter:
    def __init__(self):
        self.ledger = ModelCallLedger()

    def route(self, request, policy):
        del policy
        evidence = request.evidence
        target = evidence["targets"][0]
        surface = evidence["surfaces"][0]
        evidence_id = evidence["safe_evidence_summaries"][0]["evidence_id"]
        proposal = NewHypothesisProposal(
            proposal_id="initial-model-hypothesis",
            category="api_authorization",
            title="Additional API authorization boundary may need comparison.",
            claim="The discovered API route may enforce controlled roles inconsistently.",
            falsification_criterion="Equivalent secure denials across controlled roles falsify the claim.",
            target_id=target["target_id"],
            surface_id=surface["surface_id"],
            confirmation_policy_reference="model-cannot-select-policy",
            evidence_references=(evidence_id,),
            source=HypothesisProposalSource.model,
        )
        candidate = ResearchStrategyCandidate(
            decision_id="initial-model-decision",
            research_id=evidence["research_id"],
            state_revision=evidence["state_revision"],
            action=ResearchStrategyAction.defer,
            new_hypotheses=(proposal,),
            priority=50,
            confidence=ResearchConfidence.low,
            expected_information_gain=InformationGainEstimate.medium,
            reasoning_summary="The proposal cites only discovered evidence.",
            evidence_references=(evidence_id,),
        )
        response = ModelResponse(
            provider="ollama",
            model="fake-local-hypothesis",
            content=json.dumps(candidate.model_dump(mode="json"), indent=2),
            finish_reason="stop",
            input_tokens=10,
            output_tokens=10,
            total_tokens=20,
            estimated_cost_usd=0.0,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            requested_provider="ollama",
            requested_model="fake-local-hypothesis",
        )
        self.ledger.record_success(response, fallback_depth=0)
        return response


def test_optional_local_initial_hypothesis_is_grounded_and_accounted(tmp_path):
    router = InitialHypothesisRouter()
    store, budgets, vault, runner, original = bootstrap_fixture(
        tmp_path, model_ledger=router.ledger
    )
    reasoning = ResearchReasoningEngine(router)
    bootstrapper = ResearchBootstrapper(
        store=store,
        policy=policy(),
        controlled_context=original.controlled_context,
        request_budget=original.request_budget,
        budget_manager=budgets,
        target_id=original.target_id,
        tool_runner=runner,
        vault=vault,
        reasoning_engine=reasoning,
        routing_policy=ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="fake-local-hypothesis"),
        ),
        packet_builder=PublicSafeResearchPacketBuilder(
            ExperimentCompiler().registry, budgets
        ),
        limits=original.limits.model_copy(update={"maximum_bootstrap_model_calls": 1}),
        now=lambda: NOW,
    )
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        model_hypothesis = next(
            item for item in state.hypotheses if item.category == "api_authorization"
        )
        assert model_hypothesis.status.value == "proposed"
        assert model_hypothesis.derivation_type.value == "model_proposed"
        assert (
            model_hypothesis.confirmation_policy_reference
            == "authorization-blind-bootstrap"
        )
        assert model_hypothesis.supporting_evidence
        assert state.bootstrap_progress[0].model_usage_delta.attempted_calls == 1
        assert state.budgets[0].model_budget.usage.attempted_calls == 1
    finally:
        vault.close()


def test_initial_model_hypotheses_wait_for_discovery_evidence(tmp_path):
    router = InitialHypothesisRouter()
    store, budgets, vault, runner, original = bootstrap_fixture(
        tmp_path, empty=True, model_ledger=router.ledger
    )
    bootstrapper = ResearchBootstrapper(
        store=store,
        policy=policy(),
        controlled_context=original.controlled_context,
        request_budget=original.request_budget,
        budget_manager=budgets,
        target_id=original.target_id,
        tool_runner=runner,
        vault=vault,
        reasoning_engine=ResearchReasoningEngine(router),
        routing_policy=ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="fake-local-hypothesis"),
        ),
        packet_builder=PublicSafeResearchPacketBuilder(
            ExperimentCompiler().registry, budgets
        ),
        limits=original.limits.model_copy(update={"maximum_bootstrap_model_calls": 1}),
        now=lambda: NOW,
    )
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        assert state.status is ResearchRunStatus.selecting_experiment
        assert not state.evidence
        assert not state.hypotheses
        assert router.ledger.usage_for_run("research-blind").attempted_calls == 0
    finally:
        vault.close()


def test_empty_discovery_stops_only_after_bootstrap_had_a_chance(tmp_path):
    store, budgets, vault, _runner, bootstrapper = bootstrap_fixture(
        tmp_path, empty=True
    )
    runtime = FakeResearchRuntime(())
    compiler = ExperimentCompiler(
        context=ExperimentCompilerContext(current_time=NOW, execution_ready=True)
    )
    selector = ExperimentSelector(compiler, budgets)
    orchestrator = SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        gate=FakeGate(),
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        compiler_context=compiler.context,
        runtime=runtime,
        bootstrapper=bootstrapper,
    )
    try:
        result = orchestrator.run("research-blind")
        assert result.stop_reason is OrchestratorStopReason.no_research_hypotheses
        assert result.state.status is ResearchRunStatus.stopped
        assert result.state.bootstrap_progress[0].hypothesizing_completed is True
    finally:
        vault.close()


class DynamicLocalRouter:
    def __init__(self):
        self.ledger = ModelCallLedger()
        self.requests = []

    def route(self, request, policy):
        del policy
        self.requests.append(request)
        evidence = request.evidence
        hypothesis = next(
            (
                item
                for item in evidence["hypotheses"]
                if item["category"] == "vertical_authorization"
            ),
            None,
        )
        if hypothesis is None:
            candidate = ResearchStrategyCandidate(
                decision_id="decision-stop-after-signal",
                research_id=evidence["research_id"],
                state_revision=evidence["state_revision"],
                action=ResearchStrategyAction.stop,
                priority=0,
                confidence=ResearchConfidence.high,
                expected_information_gain=InformationGainEstimate.low,
                reasoning_summary="The selected authorization hypothesis is resolved.",
                stop_reason="The selected evidence-backed hypothesis is resolved.",
            )
            return self._response(request, candidate)
        endpoint = next(
            item
            for item in evidence["endpoints"]
            if item["surface_id"] == hypothesis["surface_id"]
        )
        template = next(
            item
            for item in evidence["request_templates"]
            if item["endpoint_id"] == endpoint["endpoint_id"]
        )
        user = next(
            item
            for item in evidence["controlled_identities"]
            if item["role_reference"] == "user"
        )
        admin = next(
            item
            for item in evidence["controlled_identities"]
            if item["role_reference"] == "admin"
        )
        pivot = bool(evidence["previous_experiments"])
        proposal_id = "proposal-e2" if pivot else "proposal-e1"
        selector = (
            DifferentialSelector.semantic_result_class
            if pivot
            else DifferentialSelector.status_class
        )
        proposal = ExperimentProposal(
            proposal_id=proposal_id,
            research_id=evidence["research_id"],
            state_revision=evidence["state_revision"],
            hypothesis_id=hypothesis["hypothesis_id"],
            capability="request_replay",
            target_id=hypothesis["target_id"],
            surface_id=hypothesis["surface_id"],
            endpoint_id=endpoint["endpoint_id"],
            objective="Compare the discovered privileged route across controlled roles.",
            primary_identity_id=user["identity_id"],
            comparison_identity_id=admin["identity_id"],
            identity_relationship=IdentityRelationship.user_admin,
            baseline_strategy=BaselineIntent(
                kind=BaselineKind.registered_request,
                reference_id=template["template_id"],
            ),
            mutation_intent=MutationIntent(kind="context_switch"),
            expected_secure_behavior="The lower role is denied protected functionality.",
            expected_vulnerable_behavior="The lower role receives protected functionality.",
            required_evidence_intent=(
                EvidenceIntent(
                    selector=selector,
                    predicate_reference=f"predicate-{proposal_id}",
                ),
            ),
            rationale="A controlled role comparison can falsify the authorization claim.",
            primitive_steps=(
                PrimitiveStepProposal(
                    step_id=f"replay-user-{proposal_id}",
                    input=RequestReplayInput(
                        request_template_id=template["template_id"],
                        endpoint_id=endpoint["endpoint_id"],
                        identity_id=user["identity_id"],
                    ),
                ),
                PrimitiveStepProposal(
                    step_id=f"switch-{proposal_id}",
                    input=IdentitySwitchInput(
                        primary_identity_id=user["identity_id"],
                        comparison_identity_id=admin["identity_id"],
                        relationship=IdentityRelationship.user_admin,
                    ),
                ),
                PrimitiveStepProposal(
                    step_id=f"replay-admin-{proposal_id}",
                    input=RequestReplayInput(
                        request_template_id=template["template_id"],
                        endpoint_id=endpoint["endpoint_id"],
                    ),
                ),
            ),
            provenance_id=hypothesis["provenance_id"],
        )
        candidate = ResearchStrategyCandidate(
            decision_id=f"decision-{proposal_id}",
            research_id=evidence["research_id"],
            state_revision=evidence["state_revision"],
            action=ResearchStrategyAction.propose_experiment,
            selected_hypothesis_id=hypothesis["hypothesis_id"],
            proposals=(proposal,),
            priority=95,
            confidence=ResearchConfidence.medium,
            expected_information_gain=InformationGainEstimate.high,
            reasoning_summary="The discovered role boundary supports a bounded comparison.",
            evidence_references=tuple(hypothesis["supporting_evidence"]),
        )
        return self._response(request, candidate)

    def _response(self, request, candidate):
        response = ModelResponse(
            provider="ollama",
            model="fake-local-research",
            content=json.dumps(candidate.model_dump(mode="json"), indent=2),
            finish_reason="stop",
            input_tokens=10,
            output_tokens=10,
            total_tokens=20,
            estimated_cost_usd=0.0,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            requested_provider="ollama",
            requested_model="fake-local-research",
        )
        self.ledger.record_success(response, fallback_depth=0)
        return response


@dataclass(frozen=True)
class FakeAuthorization:
    experiment: object


class FakeGate:
    def __init__(self):
        self.current_time = NOW
        self.cleanup_barrier = ResearchCleanupBarrier()
        self.policy = None

    def authorize(self, experiment):
        return FakeAuthorization(experiment)

    def bind(self, authorization):
        return authorization


class FakeResearchRuntime:
    def __init__(self, classifications):
        self.classifications = list(classifications)
        self.calls = []

    def submit(self, authorization):
        experiment = authorization.experiment
        self.calls.append(experiment.fingerprint)
        classification = self.classifications.pop(0)
        evidence_id = f"runtime-evidence-{experiment.experiment_id}"
        evidence = PrimitiveExecutionEvidence(
            evidence_id=evidence_id,
            step_id=experiment.primitive_steps[0].step_id,
            primitive_name=experiment.primitive_steps[0].primitive_name,
            summary=f"Bounded {classification.value} evidence.",
            request_accounting_reference=f"request-accounting-{len(self.calls)}",
            runtime_provenance_reference=f"runtime-provenance-{len(self.calls)}",
        )
        return ExperimentOutcome(
            outcome_id=f"outcome-{experiment.experiment_id}",
            experiment_id=experiment.experiment_id,
            runtime_status=ExperimentRuntimeStatus.completed,
            canonical_result_classification=Phase2ResultStatus.inconclusive,
            evidence_references=(evidence_id,),
            request_delta=RequestDelta(),
            model_usage_delta=ModelUsageDelta(),
            cleanup_status=CleanupStatus.not_required,
            provenance_id=f"runtime-provenance-{experiment.experiment_id}",
            occurred_at=NOW,
            result_classification=classification,
            evidence=(evidence,),
            cleanup_result=CleanupExecutionResult(status=CleanupStatus.not_required),
            runtime_provenance=RuntimeProvenance(
                runtime_name="fake-research-runtime",
                runtime_version="v1",
                executor_registry_hash=DIGEST_A,
                primitive_registry_hash=DIGEST_B,
                policy_reference="policy-blind",
                policy_hash=DIGEST_C,
                target_fingerprint=DIGEST_A,
            ),
            authorization_reference=DIGEST_B,
            runtime_binding_reference="fake-runtime-binding",
        )


def test_full_blind_fake_autonomy_pivots_to_candidate_signal(tmp_path):
    router = DynamicLocalRouter()
    store, budgets, vault, runner, bootstrapper = bootstrap_fixture(
        tmp_path, model_ledger=router.ledger
    )
    context = ExperimentCompilerContext(
        current_time=NOW,
        execution_ready=True,
        policy_reference="policy-blind",
        context_reference="context-blind",
    )
    compiler = ExperimentCompiler(context=context)
    selector = ExperimentSelector(compiler, budgets)
    runtime = FakeResearchRuntime(
        (
            ExperimentResultClassification.inconclusive,
            ExperimentResultClassification.vulnerable_signal,
        )
    )
    reasoning = ResearchReasoningEngine(router)
    packet_builder = PublicSafeResearchPacketBuilder(compiler.registry, budgets)
    orchestrator = SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        gate=FakeGate(),
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        reasoning_engine=reasoning,
        routing_policy=ModelRoutingPolicy(
            mode=RoutingMode.local_only,
            preferred=ModelRoute(provider="ollama", model="fake-local-research"),
        ),
        packet_builder=packet_builder,
        compiler_context=context,
        runtime=runtime,
        bootstrapper=bootstrapper,
    )
    try:
        result = orchestrator.run("research-blind")
        assert runner.calls == 1
        assert len(runtime.calls) == 2
        assert [item.classification for item in result.evaluations] == [
            ExperimentResultClassification.inconclusive,
            ExperimentResultClassification.vulnerable_signal,
        ]
        assert result.state.hypotheses
        assert len(result.state.experiment_outcomes) == 2
        assert result.state.findings[0].status.value == "candidate"
        assert router.ledger.usage_for_run("research-blind").attempted_calls == 3
    finally:
        vault.close()


def test_template_validation_fails_closed_for_method_or_scope_mismatch(tmp_path):
    store, _budgets, vault, _runner, bootstrapper = bootstrap_fixture(tmp_path)
    try:
        state = bootstrapper.prepare(store.load_research("research-blind"))
        template = state.request_templates[0]
        with pytest.raises(ValueError, match="relationships mismatch"):
            RequestTemplateFactory.validate(
                template.model_copy(update={"method": HttpMethod.post}),
                state,
                policy=policy(),
            )
    finally:
        vault.close()


def test_no_real_runtime_or_provider_dependency_is_introduced():
    assert ResearchRuntime is not ResearchBootstrapper
    assert not hasattr(ResearchBootstrapper, "authorize")
    assert not hasattr(ResearchBootstrapper, "execute_request")
