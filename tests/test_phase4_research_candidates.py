from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_core.models import (
    ModelCallLedger,
    ModelConfiguration,
    ModelResponse,
    ModelRoute,
    ModelRouter,
    ModelRoutingPolicy,
    ProviderConfiguration,
    ProviderRegistry,
    RoutingMode,
)
from agent_core.controlled_context import ControlledContext
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    AuthorizationBlockedError,
    CleanupStatus,
    DerivationType,
    Endpoint,
    EntityKind,
    EntityReference,
    EvidenceArtifact,
    EvidenceKind,
    ExperimentCandidateBuilder,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentEvaluator,
    ExperimentRegistry,
    ExperimentSelector,
    Fact,
    FactStatus,
    HttpMethod,
    HypothesisRecord,
    HypothesisResearchStatus,
    Identity,
    IdentityEligibility,
    InformationGainEstimate,
    HypothesisProposalSource,
    NewHypothesisProposal,
    Parameter,
    ParameterLocation,
    PivotPlanner,
    PrimitiveCapabilityState,
    ProvenanceProducerType,
    ProvenanceRecord,
    PublicSafeCandidatePacketBuilder,
    PublicSafeResearchPacketBuilder,
    RegisteredRequestTemplate,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchAuthorizationErrorCode,
    ResearchBootstrapLimits,
    ResearchBootstrapProgress,
    ResearchBootstrapper,
    ResearchConfidence,
    ResearchExperimentRecord,
    ResearchExperimentStatus,
    ResearchHypothesisExpansionCandidate,
    ResearchObject,
    ResearchPredicate,
    ResearchRequestTemplate,
    ResearchRunStatus,
    ResearchSelectionAction,
    ResearchSelectionDecision,
    ResearchReasoningEngine,
    ResearchReasoningError,
    ResearchStore,
    ResearchState,
    RequestIdentityRequirement,
    ScalarFactObject,
    SecurityResearchOrchestrator,
    Surface,
    SurfaceType,
    TargetAsset,
    TargetClass,
    material_experiment_fingerprint,
    materialize_candidate,
)
from agent_core.research.evaluation import ExperimentResultClassification
from test_phase4_research_orchestrator import FakeGate, FakeResearchRuntime

NOW = "2026-09-24T12:00:00+00:00"


def synthetic_state(
    *,
    endpoint_count: int = 6,
    hypotheses: tuple[str, ...] = ("bola", "authentication_enforcement"),
    auth_mechanisms: tuple[str, ...] = ("authorization_header",),
) -> ResearchState:
    provenance = ProvenanceRecord(
        provenance_id="provenance-generic",
        producer_type=ProvenanceProducerType.deterministic,
        producer_name="candidate-test",
        producer_version="v1",
        summary="Synthetic generic candidate provenance.",
        occurred_at=NOW,
    )
    evidence = tuple(
        EvidenceArtifact(
            evidence_id=f"evidence-{index}",
            evidence_kind=EvidenceKind.capture,
            digest="sha256:" + f"{index:x}" * 64,
            summary="A controlled generic observation was recorded.",
            source_reference=f"capture-{index}",
            observed_at=NOW,
            provenance_id=provenance.provenance_id,
        )
        for index in range(1, 7)
    )
    target = TargetAsset(
        target_id="target-generic",
        canonical_reference="https://service.example",
        target_class=TargetClass.dedicated_lab,
        scope_reference="scope-generic",
        evidence_references=("evidence-1",),
        provenance_id=provenance.provenance_id,
    )
    surface = Surface(
        surface_id="surface-resources",
        target_id=target.target_id,
        surface_type=SurfaceType.rest,
        label="Generic resource surface.",
        evidence_references=("evidence-1",),
        provenance_id=provenance.provenance_id,
    )
    endpoints = tuple(
        Endpoint(
            endpoint_id=f"endpoint-resource-{index}",
            target_id=target.target_id,
            surface_id=surface.surface_id,
            method=HttpMethod.get,
            route_template=f"/resources-{index}/{{resource_ref_{index}}}",
            evidence_references=(f"evidence-{((index - 1) % 6) + 1}",),
            provenance_id=provenance.provenance_id,
        )
        for index in range(1, endpoint_count + 1)
    )
    parameters = tuple(
        Parameter(
            parameter_id=f"parameter-resource-{index}",
            endpoint_id=f"endpoint-resource-{index}",
            name=f"resource_ref_{index}",
            location=ParameterLocation.path,
            data_type="string",
            required=True,
            evidence_references=(f"evidence-{index}",),
            provenance_id=provenance.provenance_id,
        )
        for index in range(1, min(endpoint_count, 5) + 1)
    )
    parameter_ids = {item.endpoint_id: item.parameter_id for item in parameters}
    templates = tuple(
        ResearchRequestTemplate(
            template_id=f"template-resource-{index}",
            target_id=target.target_id,
            surface_id=surface.surface_id,
            endpoint_id=f"endpoint-resource-{index}",
            method=HttpMethod.get,
            route_reference=f"/resources-{index}/{{resource_ref_{index}}}",
            parameter_ids=(
                (parameter_ids[f"endpoint-resource-{index}"],)
                if f"endpoint-resource-{index}" in parameter_ids
                else ()
            ),
            identity_requirement=RequestIdentityRequirement(
                required=bool(auth_mechanisms), mechanisms=auth_mechanisms
            ),
            evidence_references=(f"evidence-{((index - 1) % 6) + 1}",),
            provenance_id=provenance.provenance_id,
        )
        for index in range(1, endpoint_count + 1)
    )
    identities = (
        Identity(
            identity_id="identity-alpha",
            account_reference="account-alpha",
            tenant_reference="tenant-shared",
            controlled=True,
            eligibility=IdentityEligibility.eligible,
            provenance_id=provenance.provenance_id,
        ),
        Identity(
            identity_id="identity-beta",
            account_reference="account-beta",
            tenant_reference="tenant-shared",
            controlled=True,
            eligibility=IdentityEligibility.eligible,
            provenance_id=provenance.provenance_id,
        ),
    )
    objects = tuple(
        ResearchObject(
            object_id=f"object-resource-{index}",
            target_id=target.target_id,
            surface_id=surface.surface_id,
            object_type="resource",
            object_reference=f"fixture-resource-{index}",
            owner_identity_id=("identity-alpha" if index == 1 else "identity-beta"),
            tenant_reference="tenant-shared",
            test_owned=True,
            parameter_references=(f"parameter-resource-{index}",),
            evidence_references=(f"evidence-{index}",),
            provenance_id=provenance.provenance_id,
        )
        for index in (1, 2)
        if index <= min(endpoint_count, 5)
    )
    records = tuple(
        HypothesisRecord(
            hypothesis_id=f"hypothesis-{category}",
            category=category,
            title="A generic security-boundary hypothesis.",
            claim="A controlled differential may distinguish boundary behavior.",
            target_id=target.target_id,
            surface_id=surface.surface_id,
            status=HypothesisResearchStatus.proposed,
            priority=80 if category == "bola" else 70,
            confidence=ResearchConfidence.medium,
            confirmation_policy_reference="confirmation-policy-generic",
            supporting_evidence=("evidence-1",),
            derivation_type=DerivationType.deterministic,
            provenance_id=provenance.provenance_id,
        )
        for category in hypotheses
    )
    facts = tuple(
        Fact(
            fact_id=f"fact-{index}",
            subject=EntityReference(
                entity_kind=EntityKind.endpoint,
                entity_id=f"endpoint-resource-{((index - 1) % endpoint_count) + 1}",
            ),
            predicate=ResearchPredicate.references,
            object=ScalarFactObject(value=True),
            status=FactStatus.observed,
            evidence_references=(f"evidence-{index}",),
            derivation_type=DerivationType.deterministic,
            provenance_id=provenance.provenance_id,
        )
        for index in range(1, 7)
    )
    return ResearchState(
        research_id="research-generic",
        revision=0,
        status=ResearchRunStatus.selecting_experiment,
        created_at=NOW,
        updated_at=NOW,
        targets=(target,),
        surfaces=(surface,),
        endpoints=endpoints,
        parameters=parameters,
        request_templates=templates,
        identities=identities,
        objects=objects,
        evidence=evidence,
        facts=facts,
        hypotheses=records,
        provenance=(provenance,),
    )


def candidate_system(
    state: ResearchState | None = None,
    *,
    registry: ExperimentRegistry | None = None,
    budgets: ResearchBudgetManager | None = None,
):
    state = state or synthetic_state()
    registry = registry or ExperimentRegistry()
    budgets = budgets or ResearchBudgetManager()
    context = ExperimentCompilerContext(
        current_time=NOW,
        execution_ready=True,
        request_templates=tuple(
            RegisteredRequestTemplate(
                template_id=item.template_id,
                target_id=item.target_id,
                surface_id=item.surface_id,
                endpoint_id=item.endpoint_id,
                parameter_ids=item.parameter_ids,
                authentication_mechanisms=item.identity_requirement.mechanisms,
            )
            for item in state.request_templates
        ),
        policy_reference="policy-generic",
        context_reference="context-generic",
    )
    compiler = ExperimentCompiler(registry=registry, context=context)
    builder = ExperimentCandidateBuilder(registry, budgets, compiler)
    return state, budgets, compiler, context, builder


def build_candidates(state: ResearchState | None = None, **kwargs):
    state, budgets, compiler, context, builder = candidate_system(state, **kwargs)
    candidates = builder.build(
        state,
        compiler_context=context,
        expected_state_revision=state.revision,
        policy_reference=context.policy_reference,
    )
    return state, budgets, compiler, context, builder, candidates


class FakeSelectionRouter:
    def __init__(self, content=None, *, choose_index: int = 0):
        self.content = content
        self.choose_index = choose_index
        self.ledger = ModelCallLedger()
        self.requests = []

    def route(self, request, policy):
        del policy
        self.requests.append(request)
        content = self.content
        if content is None:
            selected = request.evidence["candidates"][self.choose_index]
            content = json.dumps(
                {
                    "decision_id": "decision-selection",
                    "research_id": request.evidence["research_id"],
                    "state_revision": request.evidence["state_revision"],
                    "action": "select_candidate",
                    "selected_candidate_id": selected["candidate_id"],
                    "selected_hypothesis_id": selected["hypothesis_id"],
                    "priority": 85,
                    "confidence": "medium",
                    "expected_information_gain": "high",
                    "reasoning_summary": "This candidate offers a bounded differential.",
                    "evidence_references": selected["evidence_references"][:1],
                    "missing_evidence": [],
                    "pivot_dimension": None,
                    "stop_reason": None,
                }
            )
        response = ModelResponse(
            provider="ollama",
            model="fake-local-model",
            content=content,
            finish_reason="stop",
            input_tokens=20,
            output_tokens=20,
            total_tokens=40,
            estimated_cost_usd=0.0,
            latency_seconds=0.01,
            task_type=request.task_type,
            run_id=request.run_id,
            requested_provider="ollama",
            requested_model="fake-local-model",
        )
        self.ledger.record_success(response, fallback_depth=0)
        return response


def routing_policy():
    return ModelRoutingPolicy(
        mode=RoutingMode.local_only,
        preferred=ModelRoute(provider="ollama", model="fake-local-model"),
    )


def test_generic_authorization_and_authentication_candidates_compile():
    state, _budgets, compiler, context, _builder, candidates = build_candidates()

    authorization = [
        item for item in candidates if item.primitive_kind == "object_substitution"
    ]
    authentication = [
        item
        for item in candidates
        if item.primitive_kind == "authentication_differential"
    ]

    assert len(authorization) >= 2
    assert authentication
    assert all(item.controlled_object_id for item in authorization)
    assert all(item.ownership_evidence_references for item in authorization)
    for candidate in candidates:
        compiler.compile(materialize_candidate(candidate, state), state, context)


def test_generic_parameter_candidate_uses_required_controlled_context():
    base = synthetic_state(endpoint_count=1, hypotheses=("mass_assignment",))
    endpoint = base.endpoints[0].model_copy(
        update={"method": HttpMethod.patch, "route_template": "/resources-1"}
    )
    parameter = base.parameters[0].model_copy(
        update={"name": "display_label", "location": ParameterLocation.json}
    )
    template = base.request_templates[0].model_copy(
        update={
            "method": HttpMethod.patch,
            "route_reference": "/resources-1",
            "parameter_ids": (parameter.parameter_id,),
        }
    )
    state = ResearchState.model_validate(
        {
            **base.model_dump(mode="python"),
            "endpoints": (endpoint,),
            "parameters": (parameter,),
            "request_templates": (template,),
        }
    )
    state, _budgets, compiler, context, _builder, candidates = build_candidates(state)

    assert candidates
    assert all(item.primitive_kind == "parameter_mutation" for item in candidates)
    assert candidates[0].primary_identity_id is not None
    assert candidates[0].controlled_object_id is not None
    assert candidates[0].ownership_evidence_references
    compiler.compile(materialize_candidate(candidates[0], state), state, context)


def test_model_selects_second_candidate_without_binding_authority():
    state, budgets, compiler, context, _builder, candidates = build_candidates()
    assert len(candidates) >= 3
    packet = PublicSafeCandidatePacketBuilder(budgets).build(state, candidates)
    router = FakeSelectionRouter(choose_index=1)

    decision = ResearchReasoningEngine(router, max_output_tokens=4096).select(
        packet, routing_policy()
    )
    selected = next(
        item
        for item in candidates
        if item.candidate_id == decision.selected_candidate_id
    )
    proposal = materialize_candidate(
        selected, state, model_decision_id=decision.decision_id
    )
    selection = ExperimentSelector(compiler, budgets).select(
        (proposal,), state, compiler_context=context
    )

    assert selected.candidate_id == candidates[1].candidate_id
    assert selected.candidate_id != candidates[0].candidate_id
    assert selection.selected is not None
    assert selection.selected.proposal_id == proposal.proposal_id
    assert proposal.model_decision_id == decision.decision_id
    assert not hasattr(decision, "authorize")
    assert not hasattr(decision, "execute")


def test_orchestrator_authorizes_only_the_model_selected_candidate(tmp_path):
    state, budgets, compiler, context, builder, candidates = build_candidates()
    selected_candidate = candidates[1]
    unselected_candidate = candidates[0]
    selected_proposal = materialize_candidate(selected_candidate, state)
    unselected_proposal = materialize_candidate(unselected_candidate, state)
    store = ResearchStore(tmp_path / "candidate-selection.sqlite3")
    store.create_research(state)
    router = FakeSelectionRouter(choose_index=1)

    class RecordingGate(FakeGate):
        def __init__(self):
            super().__init__()
            self.authorized = []

        def authorize(self, experiment):
            self.authorized.append(experiment)
            return super().authorize(experiment)

    gate = RecordingGate()
    runtime = FakeResearchRuntime((ExperimentResultClassification.inconclusive,))
    selector = ExperimentSelector(compiler, budgets)
    runner = SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        compiler_context=context,
        gate=gate,
        runtime=runtime,
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        reasoning_engine=ResearchReasoningEngine(router, max_output_tokens=4096),
        routing_policy=routing_policy(),
        packet_builder=PublicSafeResearchPacketBuilder(compiler.registry, budgets),
        candidate_builder=builder,
        candidate_packet_builder=PublicSafeCandidatePacketBuilder(budgets),
    )

    result = runner.run(state.research_id, max_iterations=1)

    assert len(router.requests) == 1
    assert len(gate.authorized) == 1
    assert gate.authorized[0].provenance.source_proposal_id == (
        selected_proposal.proposal_id
    )
    assert gate.authorized[0].provenance.source_proposal_id != (
        unselected_proposal.proposal_id
    )
    assert (
        result.state.experiment_history[0].proposal_id == selected_proposal.proposal_id
    )


def test_model_failure_never_falls_back_to_first_candidate(tmp_path):
    state, budgets, compiler, context, builder, _candidates = build_candidates()
    store = ResearchStore(tmp_path / "candidate-failure.sqlite3")
    store.create_research(state)
    router = FakeSelectionRouter('{"invalid":"selection"}')

    class RecordingGate(FakeGate):
        def __init__(self):
            super().__init__()
            self.authorized = []

        def authorize(self, experiment):
            self.authorized.append(experiment)
            return super().authorize(experiment)

    gate = RecordingGate()
    selector = ExperimentSelector(compiler, budgets)
    runner = SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        compiler_context=context,
        gate=gate,
        runtime=FakeResearchRuntime(()),
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        reasoning_engine=ResearchReasoningEngine(router, max_output_tokens=4096),
        routing_policy=routing_policy(),
        packet_builder=PublicSafeResearchPacketBuilder(compiler.registry, budgets),
        candidate_builder=builder,
        candidate_packet_builder=PublicSafeCandidatePacketBuilder(budgets),
    )

    result = runner.run(state.research_id)

    assert not gate.authorized
    assert result.stop_reason.value == "no_eligible_experiments"
    assert "model_invalid_structured_response" in result.state.diagnostic_codes


def test_authorization_failure_persists_successful_strategy_call_across_restart(
    tmp_path,
):
    state = synthetic_state(endpoint_count=1, hypotheses=("bola",))
    database = tmp_path / "authorization-ledger.sqlite3"
    store = ResearchStore(database)
    store.create_research(state)
    router = FakeSelectionRouter()
    budgets = ResearchBudgetManager(
        model_ledger=router.ledger,
        model_call_ceiling=4,
    )
    _state, _budgets, compiler, context, builder = candidate_system(
        state, budgets=budgets
    )

    class RejectingGate(FakeGate):
        def authorize(self, _experiment):
            raise AuthorizationBlockedError(
                ResearchAuthorizationErrorCode.authorization_blocked
            )

    runtime = FakeResearchRuntime(())
    selector = ExperimentSelector(compiler, budgets)
    runner = SecurityResearchOrchestrator(
        store=store,
        compiler=compiler,
        compiler_context=context,
        gate=RejectingGate(),
        runtime=runtime,
        selector=selector,
        evaluator=ExperimentEvaluator(),
        pivot_planner=PivotPlanner(selector),
        budget_manager=budgets,
        reasoning_engine=ResearchReasoningEngine(router, max_output_tokens=4096),
        routing_policy=routing_policy(),
        packet_builder=PublicSafeResearchPacketBuilder(compiler.registry, budgets),
        candidate_builder=builder,
        candidate_packet_builder=PublicSafeCandidatePacketBuilder(budgets),
    )

    result = runner.run(state.research_id)

    assert len(router.requests) == 1
    assert runtime.calls == []
    assert result.state.status is not ResearchRunStatus.executing_experiment
    assert result.state.experiment_history[0].result_classification == (
        ResearchAuthorizationErrorCode.authorization_blocked.value
    )
    assert result.state.budgets[0].model_budget.usage.attempted_calls == 1
    assert result.state.budgets[0].model_budget.usage.successful_calls == 1

    store.close()
    restarted = ResearchStore(database).load_research(state.research_id)
    assert restarted.status is not ResearchRunStatus.executing_experiment
    assert restarted.budgets[0].model_budget.usage.attempted_calls == 1
    assert restarted.budgets[0].model_budget.usage.successful_calls == 1


def test_bootstrap_sufficiency_skips_expansion_then_strategy_calls_once(tmp_path):
    base = synthetic_state()
    progress = ResearchBootstrapProgress(
        bootstrap_id="bootstrap-generic",
        target_id=base.targets[0].target_id,
        discovery_plan_reference="discovery-plan-generic",
        discovery_completed=True,
        modeling_completed=True,
        hypothesizing_completed=False,
        started_at=NOW,
        updated_at=NOW,
        provenance_id=base.provenance[0].provenance_id,
    )
    initial = base.model_copy(
        update={
            "status": ResearchRunStatus.hypothesizing,
            "bootstrap_progress": (progress,),
        }
    )
    store = ResearchStore(tmp_path / "bootstrap-sufficiency.sqlite3")
    store.create_research(initial)
    router = FakeSelectionRouter()
    request_budget = RequestBudget(limit=30, per_host_limit=30)
    budgets = ResearchBudgetManager(
        request_budget=request_budget,
        model_ledger=router.ledger,
        model_call_ceiling=4,
    )
    _state, _budgets, compiler, context, builder = candidate_system(
        initial, budgets=budgets
    )
    policy = AssessmentPolicy(
        profile_name="candidate-bootstrap-test",
        authorization_reference="policy-generic",
        authorization_confirmed=True,
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value="https://service.example",
                schemes=["https"],
            )
        ],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        credentials_allowed=True,
        request_budget=30,
        per_host_request_budget=30,
        resolve_dns_before_request=False,
    )
    engine = ResearchReasoningEngine(router, max_output_tokens=4096)
    bootstrapper = ResearchBootstrapper(
        store=store,
        policy=policy,
        controlled_context=ControlledContext(),
        request_budget=request_budget,
        budget_manager=budgets,
        target_id=initial.targets[0].target_id,
        tool_runner=object(),
        reasoning_engine=engine,
        routing_policy=routing_policy(),
        packet_builder=PublicSafeResearchPacketBuilder(compiler.registry, budgets),
        candidate_builder=builder,
        candidate_compiler_context=context,
        limits=ResearchBootstrapLimits(maximum_bootstrap_model_calls=1),
        now=lambda: NOW,
    )

    prepared = bootstrapper.prepare(initial)
    assert prepared.status is ResearchRunStatus.selecting_experiment
    assert len(router.requests) == 0
    assert prepared.bootstrap_progress[0].model_usage_delta.attempted_calls == 0

    current_context = bootstrapper.compiler_context(prepared, context)
    candidates = builder.build(prepared, compiler_context=current_context)
    packet = PublicSafeCandidatePacketBuilder(budgets).build(prepared, candidates)
    engine.select(packet, routing_policy())

    assert len(router.requests) == 1
    assert router.ledger.usage_for_run(prepared.research_id).attempted_calls == 1


def test_compact_selection_schema_and_packet_regressions():
    state, budgets, _compiler, _context, _builder, candidates = build_candidates()
    packet = PublicSafeCandidatePacketBuilder(budgets).build(state, candidates)
    schema = ResearchSelectionDecision.model_json_schema()
    schema_bytes = len(
        json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
    )
    packet_bytes = len(
        json.dumps(
            packet.public_payload(), sort_keys=True, separators=(",", ":")
        ).encode()
    )

    assert len(state.hypotheses) == 2
    assert len(state.endpoints) == 6
    assert len(state.parameters) == 5
    assert len(state.request_templates) == 6
    assert len(state.identities) == 2
    assert len(state.objects) == 2
    assert len(state.facts) == 6
    assert schema_bytes < 8_000
    assert packet_bytes < 8_000
    serialized_packet = json.dumps(packet.public_payload())
    assert "identity-alpha" not in serialized_packet
    assert "object-resource" not in serialized_packet
    assert "https://" not in serialized_packet
    assert "route_template" not in serialized_packet
    assert "primitive definitions" not in serialized_packet
    assert "ExperimentProposal" not in json.dumps(schema)
    assert "primitive_steps" not in schema["properties"]
    assert "new_hypotheses" not in schema["properties"]


def test_exceptional_hypothesis_expansion_remains_separate_and_strict():
    state, budgets, compiler, _context, _builder, _candidates = build_candidates()
    packet = PublicSafeResearchPacketBuilder(compiler.registry, budgets).build(state)
    proposal = NewHypothesisProposal(
        proposal_id="hypothesis-expansion-proposal",
        category="tenant_isolation",
        title="A separate controlled boundary may warrant investigation.",
        claim="A controlled cross-context comparison may distinguish behavior.",
        falsification_criterion="Equivalent denial behavior refutes the hypothesis.",
        target_id=state.targets[0].target_id,
        surface_id=state.surfaces[0].surface_id,
        confirmation_policy_reference="confirmation-policy-generic",
        evidence_references=(state.evidence[0].evidence_id,),
        source=HypothesisProposalSource.model,
    )
    output = ResearchHypothesisExpansionCandidate(
        decision_id="decision-exceptional-expansion",
        research_id=state.research_id,
        state_revision=state.revision,
        new_hypotheses=(proposal,),
        reasoning_summary="The exceptional operation adds one grounded hypothesis.",
        evidence_references=(state.evidence[0].evidence_id,),
        missing_evidence=(),
    )
    router = FakeSelectionRouter(output.model_dump_json())

    decision = ResearchReasoningEngine(router).expand_hypotheses(
        packet, routing_policy()
    )

    assert decision.new_hypotheses == (proposal,)
    assert router.requests[0].task_type == "research_hypothesis_expansion"
    assert "proposals" not in router.requests[0].structured_output_schema["properties"]


@pytest.mark.parametrize(
    "field,value",
    (
        ("controlled_object_id", "injected-object"),
        ("target_id", "injected-target"),
        ("url", "https://outside.example"),
        ("credential", "credential-value"),
        ("minimum_requests", 100),
        ("risk_class", "high"),
        ("authorize", True),
        ("execute", True),
        ("budget", 1_000),
    ),
)
def test_selection_contract_rejects_binding_and_authority_fields(field, value):
    payload = {
        "decision_id": "decision-invalid",
        "research_id": "research-generic",
        "state_revision": 0,
        "action": "defer",
        "selected_candidate_id": None,
        "selected_hypothesis_id": None,
        "priority": 50,
        "confidence": "medium",
        "expected_information_gain": "medium",
        "reasoning_summary": "No candidate is selected.",
        "evidence_references": [],
        "missing_evidence": [],
        "pivot_dimension": None,
        "stop_reason": None,
        field: value,
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ResearchSelectionDecision.model_validate(payload)


@pytest.mark.parametrize(
    "candidate_id,revision",
    (("not valid", 0), ("candidate-unknown", 0), (None, 1)),
)
def test_selection_rejects_invalid_unknown_or_stale_candidate(candidate_id, revision):
    state, budgets, _compiler, _context, _builder, candidates = build_candidates()
    packet = PublicSafeCandidatePacketBuilder(budgets).build(state, candidates)
    selected = candidates[0]
    content = json.dumps(
        {
            "decision_id": "decision-invalid-selection",
            "research_id": state.research_id,
            "state_revision": revision,
            "action": "select_candidate",
            "selected_candidate_id": candidate_id or selected.candidate_id,
            "selected_hypothesis_id": selected.hypothesis_id,
            "priority": 50,
            "confidence": "medium",
            "expected_information_gain": "medium",
            "reasoning_summary": "Attempt an invalid selection.",
            "evidence_references": [],
            "missing_evidence": [],
            "pivot_dimension": None,
            "stop_reason": None,
        }
    )
    with pytest.raises(ResearchReasoningError, match="invalid_output"):
        ResearchReasoningEngine(FakeSelectionRouter(content)).select(
            packet, routing_policy()
        )


def test_selection_schema_reaches_ollama_native_format():
    state, budgets, _compiler, _context, _builder, candidates = build_candidates()
    packet = PublicSafeCandidatePacketBuilder(budgets).build(state, candidates)
    selected = candidates[0]
    decision = ResearchSelectionDecision(
        decision_id="decision-native-schema",
        research_id=state.research_id,
        state_revision=state.revision,
        action=ResearchSelectionAction.select_candidate,
        selected_candidate_id=selected.candidate_id,
        selected_hypothesis_id=selected.hypothesis_id,
        priority=80,
        confidence=ResearchConfidence.medium,
        expected_information_gain=InformationGainEstimate.high,
        reasoning_summary="The selected candidate is bounded and informative.",
        evidence_references=selected.evidence_references[:1],
        missing_evidence=(),
        pivot_dimension=None,
        stop_reason=None,
    )

    class Response:
        status_code = 200

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "message": {"content": decision.model_dump_json()},
                "done": True,
                "prompt_eval_count": 7,
                "eval_count": 5,
            }

    class Client:
        def __init__(self):
            self.calls = []

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return Response()

    client = Client()
    configuration = ModelConfiguration(
        ollama=ProviderConfiguration(
            model_name="fake-local-model",
            base_url="http://127.0.0.1:11434",
            timeout_seconds=120,
            max_output_tokens=4096,
        )
    )

    class ClientRegistry(ProviderRegistry):
        def create(self, provider=None, *, model_name=None, client_override=None):
            del client_override
            return super().create(provider, model_name=model_name, client=client)

    router = ModelRouter(ClientRegistry(configuration))
    result = ResearchReasoningEngine(router, max_output_tokens=4096).select(
        packet, routing_policy()
    )
    transmitted = client.calls[0][1]["json"]

    assert transmitted["format"]["title"] == "ResearchSelectionDecision"
    assert transmitted["format"] == ResearchSelectionDecision.model_json_schema()
    assert transmitted["options"]["num_predict"] == 4096
    assert client.calls[0][1]["timeout"] == 120
    assert result.selected_candidate_id == selected.candidate_id


def test_no_candidate_for_uncontrolled_identities():
    state = synthetic_state(hypotheses=("bola",))
    identities = tuple(
        Identity(
            identity_id=item.identity_id,
            account_reference=item.account_reference,
            tenant_reference=item.tenant_reference,
            controlled=False,
            eligibility=IdentityEligibility.ineligible,
            provenance_id=item.provenance_id,
        )
        for item in state.identities
    )
    state = state.model_copy(update={"identities": identities})
    assert not build_candidates(state)[-1]


def test_no_candidate_for_unowned_objects():
    state = synthetic_state(hypotheses=("bola",))
    objects = tuple(
        item.model_copy(update={"test_owned": False}) for item in state.objects
    )
    state = state.model_copy(update={"objects": objects})
    assert not build_candidates(state)[-1]


def test_no_candidate_when_ownership_evidence_is_missing():
    state = synthetic_state(hypotheses=("bola",))
    state = state.model_copy(update={"evidence": ()})
    assert not build_candidates(state)[-1]


def test_no_authentication_candidate_without_auth_mechanism():
    state = synthetic_state(
        hypotheses=("authentication_enforcement",), auth_mechanisms=()
    )
    assert not build_candidates(state)[-1]


def test_no_candidate_for_compile_only_primitive():
    state = synthetic_state(hypotheses=("authentication_enforcement",))
    definitions = tuple(
        (
            item.model_copy(
                update={
                    "capability_state": PrimitiveCapabilityState.compile_only,
                    "executor_adapter_reference": None,
                }
            )
            if item.name == "authentication_differential"
            else item
        )
        for item in ExperimentRegistry().definitions
    )
    registry = ExperimentRegistry(definitions, include_defaults=False)
    assert not build_candidates(state, registry=registry)[-1]


@pytest.mark.parametrize(
    "status", (HypothesisResearchStatus.closed, HypothesisResearchStatus.refuted)
)
def test_no_candidate_for_resolved_hypothesis(status):
    state = synthetic_state(hypotheses=("authentication_enforcement",))
    record = state.hypotheses[0].model_copy(update={"status": status})
    state = state.model_copy(update={"hypotheses": (record,)})
    assert not build_candidates(state)[-1]


def test_no_candidate_for_stale_revision_or_policy_context():
    state, _budgets, _compiler, context, builder = candidate_system()
    assert not builder.build(
        state, compiler_context=context, expected_state_revision=state.revision + 1
    )
    assert not builder.build(
        state,
        compiler_context=context,
        policy_reference="different-policy-context",
    )


def test_no_candidate_when_budget_exhausted_or_cleanup_barrier_active():
    state = synthetic_state(hypotheses=("authentication_enforcement",))
    budgets = ResearchBudgetManager(ResearchBudgetPolicy(global_experiment_ceiling=1))
    budget = budgets.state(state).model_copy(update={"experiments_consumed": 1})
    exhausted = state.model_copy(update={"budgets": (budget,)})
    assert not build_candidates(exhausted, budgets=budgets)[-1]

    cleanup_budget = budget.model_copy(
        update={"experiments_consumed": 0, "cleanup_status": CleanupStatus.pending}
    )
    blocked = state.model_copy(update={"budgets": (cleanup_budget,)})
    assert not build_candidates(blocked, budgets=budgets)[-1]


def test_no_candidate_for_duplicate_completed_fingerprint():
    state = synthetic_state(
        endpoint_count=1, hypotheses=("authentication_enforcement",)
    )
    state, budgets, compiler, context, builder = candidate_system(state)
    candidate = builder.build(state, compiler_context=context)[0]
    proposal = materialize_candidate(candidate, state)
    experiment = compiler.compile(proposal, state, context)
    completed = ResearchExperimentRecord(
        experiment_id=experiment.experiment_id,
        proposal_id=proposal.proposal_id,
        hypothesis_id=proposal.hypothesis_id,
        surface_id=proposal.surface_id,
        fingerprint=experiment.fingerprint,
        material_fingerprint=material_experiment_fingerprint(experiment),
        status=ResearchExperimentStatus.completed,
        relevant_state_revision=state.revision,
        policy_reference=context.policy_reference,
        request_cost=experiment.request_estimate.total_reservation,
        state_changing=experiment.state_changing,
        occurred_at=NOW,
    )
    state = state.model_copy(update={"experiment_history": (completed,)})

    assert not builder.build(state, compiler_context=context)


def test_candidate_and_decision_are_strictly_immutable():
    _state, _budgets, _compiler, _context, _builder, candidates = build_candidates()
    with pytest.raises(ValidationError, match="frozen"):
        candidates[0].risk_class = "high"
