from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
)
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    CleanupDefinition,
    CleanupStatus,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentRegistry,
    ContextMismatchError,
    DuplicateExperimentError,
    GraphQLCandidateKind,
    GraphQLCandidatePolicy,
    GraphQLExperimentCandidateBuilder,
    GraphQLExperimentStateChangeClass,
    GraphQLHypothesisGenerator,
    GraphQLErrorClass,
    GraphQLResponseEnvelope,
    GraphQLSafeMutationClass,
    GraphQLSemanticRole,
    GraphQLVariableBinding,
    GraphQLVariableValueSource,
    HttpMethod,
    InvalidRuntimeBindingError,
    RegisteredControlledValue,
    RegisteredCleanupExecution,
    RegisteredGraphQLSafeMutation,
    ResearchBudgetManager,
    ResearchBudgetExhaustedError,
    ResearchExecutionGate,
    ResearchState,
    ResearchStore,
    RuntimeRequestTemplate,
    SessionLifecycle,
    SessionRef,
    ScopeMismatchError,
    StaleResearchStateError,
    build_registered_graphql_operation_template,
    materialize_candidate,
)
from tools.safe_http import ScopedHTTPClient

from test_phase4_graphql_candidates import _candidate_fixture
from test_phase4_graphql_candidates import _state as graphql_state
from test_phase4_graphql_hypotheses import _mutation_state

SECRET = "graphql-runtime-sentinel-credential-4f92"
NOW = "2026-09-28T12:00:00+00:00"


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        body: bytes = b'{"data":{"resource":{"resourceRef":"controlled-resource-ref","status":"ok"}}}',
        *,
        content_length: int | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = body
        self.headers = {"Content-Type": "application/json"}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.is_redirect = False
        self.is_permanent_redirect = False

    def iter_content(self, chunk_size: int):
        del chunk_size
        yield self.content

    def close(self) -> None:
        return None


@dataclass
class GraphQLRuntimeFixture:
    gate: ResearchExecutionGate
    experiment: object
    calls: list[tuple[str, str, dict[str, object]]]
    budget: RequestBudget
    vault: CredentialVault


def _runtime_fixture(
    *,
    candidate_kind: GraphQLCandidateKind = GraphQLCandidateKind.object_authorization,
    responses: tuple[FakeResponse | BaseException, ...] | None = None,
    request_limit: int = 10,
    store_factory: Callable[[ResearchState], object] | None = None,
) -> GraphQLRuntimeFixture:
    authenticated = candidate_kind is GraphQLCandidateKind.authentication
    tenant = candidate_kind is GraphQLCandidateKind.tenant_bound
    state, context, builder = _candidate_fixture(
        authenticated=authenticated, tenant=tenant
    )
    controlled_values: tuple[RegisteredControlledValue, ...] = ()
    if candidate_kind is GraphQLCandidateKind.input_validation:
        argument = state.graphql_arguments[0].model_copy(
            update={
                "semantic_role": GraphQLSemanticRole.search,
                "semantic_role_evidence_references": ("evidence-graphql",),
            }
        )
        state = graphql_state(state, hypotheses=(), graphql_arguments=(argument,))
        generated = GraphQLHypothesisGenerator().generate_result(state)
        state = graphql_state(
            state,
            hypotheses=generated.hypotheses,
            provenance=(*state.provenance, *generated.provenance),
        )
        baseline_binding = GraphQLVariableBinding(
            variable_id="variable-resource-ref",
            argument_id="argument-resource-ref",
            value_source=GraphQLVariableValueSource.registered_safe_constant,
            value_reference="registered-baseline-search",
        )
        alternative_binding = baseline_binding.model_copy(
            update={"value_reference": "registered-alternative-search"}
        )
        template = build_registered_graphql_operation_template(
            state, "operation-resource", variable_bindings=(baseline_binding,)
        )
        safe_mutation = RegisteredGraphQLSafeMutation(
            mutation_id="safe-mutation-search-boundary-runtime",
            operation_template_id=template.template_id,
            variable_id=alternative_binding.variable_id,
            argument_id=alternative_binding.argument_id,
            mutation_class=GraphQLSafeMutationClass.registered_alternative,
            binding=alternative_binding,
            evidence_references=("evidence-graphql",),
            provenance_id="prov-graphql",
        )
        context = context.model_copy(
            update={
                "controlled_value_references": (
                    baseline_binding.value_reference,
                    alternative_binding.value_reference,
                ),
                "graphql_operation_templates": (template,),
                "graphql_safe_mutations": (safe_mutation,),
            }
        )
        controlled_values = (
            RegisteredControlledValue(
                reference=baseline_binding.value_reference,
                value="baseline-search-value",
            ),
            RegisteredControlledValue(
                reference=alternative_binding.value_reference,
                value="alternative-search-value",
            ),
        )
    elif authenticated:
        binding = GraphQLVariableBinding(
            variable_id="variable-resource-ref",
            argument_id="argument-resource-ref",
            value_source=GraphQLVariableValueSource.registered_safe_constant,
            value_reference="registered-auth-resource",
        )
        template = build_registered_graphql_operation_template(
            state, "operation-resource", variable_bindings=(binding,)
        )
        context = context.model_copy(
            update={
                "controlled_value_references": (binding.value_reference,),
                "graphql_operation_templates": (template,),
            }
        )
        controlled_values = (
            RegisteredControlledValue(
                reference=binding.value_reference, value="controlled-resource-ref"
            ),
        )
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is candidate_kind
    )
    proposal = materialize_candidate(candidate, state)
    execution_context = context.model_copy(
        update={"execution_ready": True, "graphql_execution_enabled": True}
    )

    vault = CredentialVault()
    primary_reference = vault.put(SECRET, label="graphql-primary")
    comparison_reference = vault.put(
        "graphql-comparison-session-21b7", label="graphql-comparison"
    )
    payload = state.model_dump(mode="python")
    payload["targets"][0]["canonical_reference"] = "https://research.example.test"
    payload["session_refs"] = (
        SessionRef(
            session_ref_id="graphql-session-a",
            identity_id="identity-a",
            vault_reference=primary_reference,
            lifecycle=SessionLifecycle.active,
            provenance_id="prov-graphql",
        ),
        SessionRef(
            session_ref_id="graphql-session-b",
            identity_id="identity-b",
            vault_reference=comparison_reference,
            lifecycle=SessionLifecycle.active,
            provenance_id="prov-graphql",
        ),
    )
    state = ResearchState.model_validate(payload)
    experiment = builder.compiler.compile(proposal, state, execution_context)
    policy = AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="graphql-policy-authorization",
        allowed_assets=(ScopeAsset(kind="exact_host", value="research.example.test"),),
        allowed_methods=("POST",),
        request_budget=request_limit,
        per_host_request_budget=request_limit,
        credentials_allowed=True,
        controlled_account_ids=("controlled-account-a", "account-identity-b"),
        resolve_dns_before_request=False,
        requests_per_second=100,
    )
    budget = RequestBudget(request_limit)
    calls: list[tuple[str, str, dict[str, object]]] = []
    queued = list(
        responses
        or (
            FakeResponse(),
            FakeResponse(
                403,
                b'{"errors":[{"extensions":{"code":"FORBIDDEN"}}]}',
            ),
        )
    )

    def requester(method: str, url: str, **kwargs: object) -> FakeResponse:
        calls.append((method, url, kwargs))
        selected = queued.pop(0) if queued else FakeResponse()
        if isinstance(selected, BaseException):
            raise selected
        return selected

    transport = ScopedHTTPClient(
        policy=policy,
        budget=budget,
        requester=requester,
        max_response_bytes=262_144,
    )
    controlled = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="controlled-account-a",
                tenant_id="tenant-a",
                session_reference=primary_reference,
            ),
            ControlledAccount(
                account_id="account-identity-b",
                tenant_id="tenant-b" if tenant else "tenant-a",
                session_reference=comparison_reference,
            ),
        ],
        objects=[
            ControlledObject(
                object_id="object-resource-1",
                owner_account_id="controlled-account-a",
                tenant_id="tenant-a",
            )
        ],
    )
    request_template = RuntimeRequestTemplate(
        template_id="graphql-http-template",
        target_id="target-1",
        surface_id="surface-graphql",
        endpoint_id="endpoint-graphql",
        method=HttpMethod.post,
        url="https://research.example.test/graphql",
        credential_header_name="Authorization",
    )
    gate = ResearchExecutionGate(
        state=state,
        policy=policy,
        controlled_context=controlled,
        vault=vault,
        budget=budget,
        transport=transport,
        compiler_context=execution_context,
        request_templates=(request_template,),
        controlled_values=controlled_values,
        store=store_factory(state) if store_factory is not None else None,
        current_time=NOW,
    )
    return GraphQLRuntimeFixture(gate, experiment, calls, budget, vault)


def _mutation_runtime_fixture(
    *, allow_state_changes: bool, cleanup_status: int = 200
) -> GraphQLRuntimeFixture:
    state = _mutation_state()
    generated = GraphQLHypothesisGenerator().generate_result(state)
    state = graphql_state(
        state,
        hypotheses=generated.hypotheses,
        provenance=(*state.provenance, *generated.provenance),
    )
    operation_template = build_registered_graphql_operation_template(
        state,
        "operation-resource",
        state_change_class=(GraphQLExperimentStateChangeClass.reversible_state_change),
    )
    cleanup = CleanupDefinition(
        cleanup_reference="cleanup-graphql-resource",
        verification_predicate_reference="cleanup-graphql-verified",
        capability_names=("graphql_mutation_authorization",),
        minimum_requests=1,
        worst_case_requests=1,
    )
    context = ExperimentCompilerContext(
        current_time=NOW,
        graphql_operation_templates=(operation_template,),
        cleanup_definitions=(cleanup,),
        policy_reference="graphql-mutation-policy",
    )
    registry = ExperimentRegistry()
    builder = GraphQLExperimentCandidateBuilder(
        registry,
        ResearchBudgetManager(),
        ExperimentCompiler(registry, context),
        policy=GraphQLCandidatePolicy(allow_state_change_candidates=True),
    )
    candidate = next(
        item
        for item in builder.build(state, compiler_context=context)
        if item.graphql_candidate_kind is GraphQLCandidateKind.mutation_authorization
    )
    proposal = materialize_candidate(candidate, state)
    execution_context = context.model_copy(
        update={"execution_ready": True, "graphql_execution_enabled": True}
    )
    vault = CredentialVault()
    primary_reference = vault.put(SECRET, label="graphql-mutation-primary")
    comparison_reference = vault.put(
        "graphql-mutation-comparison-390a", label="graphql-mutation-comparison"
    )
    payload = state.model_dump(mode="python")
    payload["targets"][0]["canonical_reference"] = "https://research.example.test"
    payload["session_refs"] = (
        SessionRef(
            session_ref_id="graphql-mutation-session-a",
            identity_id="identity-a",
            vault_reference=primary_reference,
            lifecycle=SessionLifecycle.active,
            provenance_id="prov-graphql",
        ),
        SessionRef(
            session_ref_id="graphql-mutation-session-b",
            identity_id="identity-b",
            vault_reference=comparison_reference,
            lifecycle=SessionLifecycle.active,
            provenance_id="prov-graphql",
        ),
    )
    state = ResearchState.model_validate(payload)
    experiment = builder.compiler.compile(proposal, state, execution_context)
    policy = AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="graphql-mutation-policy",
        allowed_assets=(ScopeAsset(kind="exact_host", value="research.example.test"),),
        allowed_methods=("POST",),
        request_budget=10,
        per_host_request_budget=10,
        credentials_allowed=True,
        controlled_account_ids=("controlled-account-a", "account-identity-b"),
        resolve_dns_before_request=False,
        requests_per_second=100,
        allow_state_changes=allow_state_changes,
    )
    budget = RequestBudget(10)
    calls: list[tuple[str, str, dict[str, object]]] = []
    statuses = [200, 200, cleanup_status]

    def requester(method: str, url: str, **kwargs: object) -> FakeResponse:
        calls.append((method, url, kwargs))
        return FakeResponse(statuses.pop(0))

    transport = ScopedHTTPClient(policy=policy, budget=budget, requester=requester)
    controlled = ControlledContext(
        accounts=[
            ControlledAccount(
                account_id="controlled-account-a",
                tenant_id="tenant-a",
                session_reference=primary_reference,
            ),
            ControlledAccount(
                account_id="account-identity-b",
                tenant_id="tenant-a",
                session_reference=comparison_reference,
            ),
        ],
        objects=[
            ControlledObject(
                object_id="object-resource-1",
                owner_account_id="controlled-account-a",
                tenant_id="tenant-a",
            )
        ],
    )
    request_template = RuntimeRequestTemplate(
        template_id="graphql-mutation-http-template",
        target_id="target-1",
        surface_id="surface-graphql",
        endpoint_id="endpoint-graphql",
        method=HttpMethod.post,
        url="https://research.example.test/graphql",
        credential_header_name="Authorization",
    )
    gate = ResearchExecutionGate(
        state=state,
        policy=policy,
        controlled_context=controlled,
        vault=vault,
        budget=budget,
        transport=transport,
        compiler_context=execution_context,
        request_templates=(request_template,),
        cleanup_handlers={
            cleanup.cleanup_reference: RegisteredCleanupExecution(
                cleanup_reference=cleanup.cleanup_reference,
                request_template_id=request_template.template_id,
                identity_id="identity-a",
            )
        },
        current_time=NOW,
    )
    return GraphQLRuntimeFixture(gate, experiment, calls, budget, vault)


def test_authenticated_and_anonymous_graphql_execution_is_bounded_and_secret_safe():
    fixture = _runtime_fixture(candidate_kind=GraphQLCandidateKind.authentication)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 2
    assert fixture.calls[0][2]["headers"]["Authorization"] == SECRET
    assert "Authorization" not in fixture.calls[1][2]["headers"]
    assert outcome.request_delta.verification == 2
    assert outcome.candidate_finding_ids == ()
    assert all(item.graphql_responses for item in outcome.evidence)
    assert SECRET not in json.dumps(outcome.model_dump(mode="json"), sort_keys=True)
    assert SECRET not in repr(fixture.gate.runtime)
    trace_types = {
        event.event_type
        for item in outcome.evidence
        for event in item.graphql_trace_events
    }
    assert trace_types == {
        "GRAPHQL_AUTHORIZE",
        "GRAPHQL_EXECUTE",
        "GRAPHQL_RESPONSE",
    }


def test_object_authorization_uses_one_registered_object_and_exact_accounting():
    fixture = _runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 2
    assert fixture.budget.total == 2
    assert {
        call[2]["json"]["variables"]["resourceRef"]  # type: ignore[index]
        for call in fixture.calls
    } == {"controlled-resource-ref"}
    identities = {
        item.graphql_responses[0].identity_reference for item in outcome.evidence
    }
    assert identities == {"identity-a", "identity-b"}
    assert outcome.result_classification.value == "inconclusive"
    assert outcome.candidate_finding_ids == ()


def test_graphql_variable_mutation_uses_only_registered_bounded_values():
    fixture = _runtime_fixture(candidate_kind=GraphQLCandidateKind.input_validation)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 2
    assert fixture.budget.total == 2
    assert [
        call[2]["json"]["variables"]["resourceRef"]  # type: ignore[index]
        for call in fixture.calls
    ] == ["baseline-search-value", "alternative-search-value"]
    assert {item.primitive_name for item in outcome.evidence} == {
        "graphql_operation",
        "graphql_variable_mutation",
    }
    assert outcome.result_classification.value == "inconclusive"
    assert outcome.candidate_finding_ids == ()


def test_graphql_timeout_and_oversized_response_are_accounted_without_body_storage():
    for response in (
        TimeoutError("sentinel-free timeout"),
        FakeResponse(content_length=300_000),
    ):
        fixture = _runtime_fixture(responses=(response, response))
        authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
        outcome = binding.submit(authorization)

        assert outcome.request_delta.total == 2
        graphql = [evidence.graphql_responses[0] for evidence in outcome.evidence]
        assert all(
            item.error_classes == (GraphQLErrorClass.transport_error,)
            for item in graphql
        )
        assert all(
            item.envelope
            in {
                GraphQLResponseEnvelope.transport_failure,
                GraphQLResponseEnvelope.oversized,
            }
            for item in graphql
        )
        serialized = json.dumps(outcome.model_dump(mode="json"), sort_keys=True)
        assert "controlled-resource-ref" not in serialized
        assert '"data"' not in serialized


def test_graphql_error_processing_is_bounded():
    body = json.dumps(
        {"errors": [{"extensions": {"code": "FORBIDDEN"}} for _ in range(40)]}
    ).encode()
    response = FakeResponse(403, body)
    fixture = _runtime_fixture(responses=(response, response))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    graphql = [evidence.graphql_responses[0] for evidence in outcome.evidence]
    assert len(fixture.calls) == 2
    assert fixture.budget.total == 2
    assert all(item.error_count == 32 for item in graphql)
    assert all(item.truncated for item in graphql)
    assert all(
        item.error_classes == (GraphQLErrorClass.authorization_error,)
        for item in graphql
    )


def test_graphql_budget_stale_revision_and_duplicate_block_before_new_request():
    insufficient = _runtime_fixture(request_limit=1)
    with pytest.raises(ResearchBudgetExhaustedError, match="budget_exhausted"):
        insufficient.gate.authorize(insufficient.experiment)
    assert insufficient.calls == []

    stale = _runtime_fixture()
    authorization, binding = stale.gate.authorize_and_bind(stale.experiment)
    object.__setattr__(
        stale.gate.runtime,
        "_ResearchRuntime__state",
        stale.gate.state.model_copy(update={"revision": 1}),
    )
    with pytest.raises(InvalidRuntimeBindingError, match="invalid_binding"):
        binding.submit(authorization)
    assert stale.calls == []

    duplicate = _runtime_fixture()
    authorization, binding = duplicate.gate.authorize_and_bind(duplicate.experiment)
    binding.submit(authorization)
    with pytest.raises(DuplicateExperimentError, match="duplicate_experiment"):
        duplicate.gate.authorize(duplicate.experiment)
    assert len(duplicate.calls) == 2


def test_graphql_outcome_survives_restart_without_reexecution(tmp_path):
    database = tmp_path / "graphql-runtime.sqlite3"

    def create_store(state: ResearchState) -> ResearchStore:
        store = ResearchStore(database)
        store.create_research(state)
        return store

    fixture = _runtime_fixture(store_factory=create_store)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    calls_before_restart = len(fixture.calls)
    budget_before_restart = fixture.budget.total

    reopened = ResearchStore(database)
    restarted_state = reopened.load_research(fixture.gate.state.research_id)
    assert len(restarted_state.experiment_outcomes) == 1
    assert restarted_state.experiment_outcomes[0].outcome_id == outcome.outcome_id
    assert restarted_state.experiment_outcomes[0].request_delta.total == 2

    restarted_gate = ResearchExecutionGate(
        state=restarted_state,
        policy=fixture.gate.policy,
        controlled_context=fixture.gate.controlled_context,
        vault=fixture.vault,
        budget=fixture.budget,
        transport=fixture.gate.transport,
        compiler_context=fixture.gate.compiler_context,
        request_templates=tuple(fixture.gate.request_templates.values()),
        controlled_values=tuple(fixture.gate.controlled_values.values()),
        store=reopened,
        current_time=NOW,
    )
    with pytest.raises(StaleResearchStateError, match="stale_state"):
        restarted_gate.authorize(fixture.experiment)
    assert len(fixture.calls) == calls_before_restart
    assert fixture.budget.total == budget_before_restart


def test_uncontrolled_tenant_or_identity_context_is_rejected_before_request():
    fixture = _runtime_fixture()
    fixture.gate.controlled_context.accounts[1].controlled = False
    with pytest.raises(ContextMismatchError, match="context_mismatch"):
        fixture.gate.authorize(fixture.experiment)
    assert fixture.calls == []


def test_graphql_tenant_differential_uses_only_two_controlled_tenant_contexts():
    fixture = _runtime_fixture(candidate_kind=GraphQLCandidateKind.tenant_bound)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 2
    assert fixture.budget.total == 2
    assert {
        item.graphql_responses[0].identity_reference for item in outcome.evidence
    } == {"identity-a", "identity-b"}
    assert outcome.result_classification.value == "inconclusive"
    assert outcome.candidate_finding_ids == ()


def test_graphql_mutation_is_blocked_by_read_only_policy_before_request():
    fixture = _mutation_runtime_fixture(allow_state_changes=False)
    with pytest.raises(ScopeMismatchError, match="scope_mismatch"):
        fixture.gate.authorize(fixture.experiment)
    assert fixture.calls == []
    assert fixture.budget.total == 0


def test_graphql_mutation_cleanup_is_reserved_accounted_and_not_classified():
    fixture = _mutation_runtime_fixture(allow_state_changes=True)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 3
    assert outcome.request_delta.verification == 2
    assert outcome.request_delta.cleanup == 1
    assert outcome.cleanup_status is CleanupStatus.completed
    assert outcome.candidate_finding_ids == ()
    assert outcome.result_classification.value == "inconclusive"
    assert outcome.cleanup_result.graphql_trace_event.event_type == "GRAPHQL_CLEANUP"


def test_graphql_cleanup_failure_activates_barrier_without_retry_or_confirmation():
    fixture = _mutation_runtime_fixture(allow_state_changes=True, cleanup_status=500)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)

    assert len(fixture.calls) == 3
    assert outcome.cleanup_status is CleanupStatus.failed
    assert outcome.result_classification.value == "cleanup_failed"
    assert outcome.candidate_finding_ids == ()
    assert fixture.gate.cleanup_barrier.active
