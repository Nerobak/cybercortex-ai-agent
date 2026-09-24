from __future__ import annotations

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
    AuthenticationDifferentialInput,
    BaselineIntent,
    BaselineKind,
    CleanupDefinition,
    DifferentialSelector,
    EvidenceIntent,
    ExperimentCompiler,
    ExperimentProposal,
    HttpMethod,
    MutationIntent,
    ParameterLocation,
    PrimitiveStepProposal,
    RegisteredControlledValue,
    RegisteredCleanupExecution,
    RegisteredRequestParameter,
    RequestReplayInput,
    ResearchExecutionGate,
    ResearchPersistenceError,
    ResearchRuntimeError,
    ResearchStore,
    RuntimeRequestTemplate,
    SafeValueBinding,
    SessionLifecycle,
    SessionRef,
)
from tests.test_phase4_research_compiler import (
    FUTURE,
    NOW,
    compiler_context,
    mutation_proposal,
    object_proposal,
    research_state,
)
from tools.safe_http import ScopedHTTPClient

SECRET_SENTINEL = "runtime-only-session-material-4f7e2c"


class FakeResponse:
    def __init__(self, status_code: int, body: bytes = b'{"result":"bounded"}'):
        self.status_code = status_code
        self.content = body
        self.headers = {"Content-Type": "application/json"}
        self.is_redirect = False
        self.is_permanent_redirect = False

    def iter_content(self, chunk_size: int):
        del chunk_size
        yield self.content

    def close(self) -> None:
        return None


@dataclass
class RuntimeFixture:
    gate: ResearchExecutionGate
    experiment: object
    calls: list[tuple[str, str, dict[str, object]]]
    vault: CredentialVault
    budget: RequestBudget


def replay_proposal() -> ExperimentProposal:
    return ExperimentProposal(
        proposal_id="replay-proposal",
        research_id="research-1",
        state_revision=4,
        hypothesis_id="hypothesis-1",
        capability="request_replay",
        target_id="target-1",
        surface_id="surface-1",
        endpoint_id="endpoint-1",
        objective="Replay one registered controlled request.",
        primary_identity_id="identity-1",
        primary_session_ref_id="session-1",
        baseline=BaselineIntent(
            kind=BaselineKind.registered_request, reference_id="template-1"
        ),
        mutation_intent=MutationIntent(kind="none"),
        expected_secure_behavior="The registered request is handled safely.",
        expected_vulnerable_behavior="The registered request exposes a signal.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="predicate-1",
            ),
        ),
        rationale="A single registered replay is deterministic.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id="replay-step",
                input=RequestReplayInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    identity_id="identity-1",
                    session_ref_id="session-1",
                    bindings=(
                        SafeValueBinding(
                            parameter_id="parameter-1",
                            value_source_reference="safe-value-1",
                        ),
                    ),
                ),
            ),
        ),
        provenance_id="provenance-1",
        expires_at=FUTURE,
    )


def authentication_differential_proposal() -> ExperimentProposal:
    return ExperimentProposal(
        proposal_id="authentication-differential-proposal",
        research_id="research-1",
        state_revision=4,
        hypothesis_id="hypothesis-1",
        capability="authentication_enforcement",
        target_id="target-1",
        surface_id="surface-1",
        endpoint_id="endpoint-1",
        objective="Compare one protected request with its anonymous form.",
        primary_identity_id="identity-1",
        primary_session_ref_id="session-1",
        baseline=BaselineIntent(
            kind=BaselineKind.registered_request, reference_id="template-1"
        ),
        mutation_intent=MutationIntent(kind="differential"),
        expected_secure_behavior="Anonymous access is denied or challenged.",
        expected_vulnerable_behavior="Anonymous access exposes the protected response.",
        required_evidence_intent=(
            EvidenceIntent(
                selector=DifferentialSelector.status_class,
                predicate_reference="authentication-boundary-predicate",
            ),
        ),
        rationale="A same-template differential isolates authentication enforcement.",
        primitive_steps=(
            PrimitiveStepProposal(
                step_id="authentication-differential-step",
                input=AuthenticationDifferentialInput(
                    request_template_id="template-1",
                    endpoint_id="endpoint-1",
                    identity_id="identity-1",
                ),
            ),
        ),
        provenance_id="provenance-1",
        expires_at=FUTURE,
    )


def build_runtime_fixture(
    *,
    proposal: ExperimentProposal | None = None,
    statuses: tuple[int, ...] = (200, 403),
    request_limit: int = 20,
    store: object | None = None,
    store_factory: object | None = None,
    evidence_summaries: tuple[object, ...] = (),
    state_snapshots: tuple[object, ...] = (),
    state_changing: bool = False,
    target_fingerprints: dict[str, str] | None = None,
) -> RuntimeFixture:
    state = research_state.__wrapped__()
    vault = CredentialVault()
    primary_ref = vault.put(SECRET_SENTINEL, label="primary-session")
    comparison_ref = vault.put(
        "comparison-session-material-9b83", label="comparison-session"
    )
    payload = state.model_dump(mode="python")
    payload["targets"][0]["canonical_reference"] = "https://research.example.test"
    if state_changing:
        payload["endpoints"][0]["method"] = HttpMethod.patch
    payload["session_refs"] = (
        SessionRef(
            session_ref_id="session-1",
            identity_id="identity-1",
            vault_reference=primary_ref,
            lifecycle=SessionLifecycle.active,
            provenance_id="provenance-1",
        ),
        SessionRef(
            session_ref_id="session-2",
            identity_id="identity-2",
            vault_reference=comparison_ref,
            lifecycle=SessionLifecycle.active,
            provenance_id="provenance-1",
        ),
    )
    state = type(state).model_validate(payload)
    if store_factory is not None:
        store = store_factory(state)  # type: ignore[operator]
    context = compiler_context.__wrapped__().model_copy(
        update={
            "execution_ready": True,
            "cleanup_definitions": (
                (
                    CleanupDefinition(
                        cleanup_reference="cleanup-parameter-1",
                        verification_predicate_reference="cleanup-verified-1",
                        primitive_names=("parameter_mutation",),
                        minimum_requests=1,
                        worst_case_requests=1,
                    ),
                )
                if state_changing
                else ()
            ),
        }
    )
    experiment = ExperimentCompiler().compile(
        proposal or object_proposal(), state, context
    )
    policy = AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="policy-authorization-1",
        allowed_assets=(ScopeAsset(kind="exact_host", value="research.example.test"),),
        allowed_methods=(("GET", "PATCH") if state_changing else ("GET",)),
        request_budget=request_limit,
        per_host_request_budget=request_limit,
        credentials_allowed=True,
        controlled_account_ids=("account-1", "account-2"),
        resolve_dns_before_request=False,
        requests_per_second=100,
        allow_state_changes=state_changing,
    )
    budget = RequestBudget(request_limit)
    calls: list[tuple[str, str, dict[str, object]]] = []
    queued = list(statuses)

    def requester(method: str, url: str, **kwargs: object) -> FakeResponse:
        calls.append((method, url, kwargs))
        return FakeResponse(queued.pop(0) if queued else statuses[-1])

    transport = ScopedHTTPClient(
        policy=policy,
        budget=budget,
        requester=requester,
        max_response_bytes=100_000,
    )
    controlled = ControlledContext(
        accounts=(
            ControlledAccount(
                account_id="account-1",
                tenant_id="tenant-1",
                session_reference=primary_ref,
            ),
            ControlledAccount(
                account_id="account-2",
                tenant_id="tenant-1",
                session_reference=comparison_ref,
            ),
        ),
        objects=(
            ControlledObject(
                object_id="controlled-object-1",
                owner_account_id="account-1",
                tenant_id="tenant-1",
            ),
        ),
    )
    template = RuntimeRequestTemplate(
        template_id="template-1",
        target_id="target-1",
        surface_id="surface-1",
        endpoint_id="endpoint-1",
        method=HttpMethod.patch if state_changing else HttpMethod.get,
        url="https://research.example.test/objects-1/{id1}",
        parameters=(
            RegisteredRequestParameter(
                parameter_id="parameter-1",
                name="id1",
                location=ParameterLocation.path,
                value="controlled-object-1",
            ),
        ),
        credential_header_name="Authorization",
    )
    gate = ResearchExecutionGate(
        state=state,
        policy=policy,
        controlled_context=controlled,
        vault=vault,
        budget=budget,
        transport=transport,
        compiler_context=context,
        request_templates=(template,),
        controlled_values=(
            RegisteredControlledValue(reference="safe-value-1", value="bounded"),
            RegisteredControlledValue(reference="safe-value-2", value="boundary"),
        ),
        evidence_summaries=evidence_summaries,  # type: ignore[arg-type]
        state_snapshots=state_snapshots,  # type: ignore[arg-type]
        cleanup_handlers=(
            {
                "cleanup-parameter-1": RegisteredCleanupExecution(
                    cleanup_reference="cleanup-parameter-1",
                    request_template_id="template-1",
                    identity_id="identity-1",
                )
            }
            if state_changing
            else None
        ),
        store=store,
        scope_reference="scope-1",
        current_time=NOW,
        target_fingerprints=target_fingerprints,
    )
    return RuntimeFixture(gate, experiment, calls, vault, budget)


def test_security_experiment_alone_cannot_execute():
    fixture = build_runtime_fixture()
    with pytest.raises(Exception, match="invalid_binding"):
        fixture.gate.runtime.submit(fixture.experiment)  # type: ignore[arg-type]
    assert fixture.calls == []


def test_request_replay_is_exactly_one_accounted_registered_request():
    fixture = build_runtime_fixture(proposal=replay_proposal(), statuses=(200,))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert len(fixture.calls) == 1
    assert fixture.calls[0][0:2] == (
        "GET",
        "https://research.example.test/objects-1/bounded",
    )
    assert fixture.calls[0][2]["headers"]["Authorization"] == SECRET_SENTINEL
    assert outcome.request_delta.verification == outcome.request_delta.total == 1
    assert SECRET_SENTINEL not in outcome.model_dump_json()


@pytest.mark.parametrize(
    ("statuses", "classification"),
    (((200, 403), "secure_signal"), ((200, 200), "vulnerable_signal")),
)
def test_authentication_differential_is_exactly_two_accounted_requests(
    statuses, classification
):
    fixture = build_runtime_fixture(
        proposal=authentication_differential_proposal(), statuses=statuses
    )
    fixture.gate.transport.session.cookies.set("sid", SECRET_SENTINEL)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert len(fixture.calls) == 2
    assert fixture.calls[0][2]["headers"]["Authorization"] == SECRET_SENTINEL
    assert "Authorization" not in fixture.calls[1][2]["headers"]
    assert not fixture.gate.transport.session.cookies
    assert outcome.result_classification.value == classification
    assert outcome.request_delta.verification == 2
    assert outcome.request_delta.total == 2
    assert SECRET_SENTINEL not in outcome.model_dump_json()


def test_object_substitution_uses_only_sealed_controlled_object():
    fixture = build_runtime_fixture(statuses=(200, 403))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert [call[1] for call in fixture.calls] == [
        "https://research.example.test/objects-1/controlled-object-1",
        "https://research.example.test/objects-1/controlled-object-1",
    ]
    assert outcome.result_classification.value == "secure_signal"
    assert outcome.request_delta.total == 2


def test_duplicate_completed_experiment_is_blocked():
    fixture = build_runtime_fixture()
    first, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    binding.submit(first)
    with pytest.raises(Exception, match="duplicate_experiment"):
        fixture.gate.authorize(fixture.experiment)


def test_dry_run_resolves_authority_with_zero_traffic_and_zero_secret_reads(
    monkeypatch,
):
    fixture = build_runtime_fixture(proposal=replay_proposal(), statuses=(200,))

    def forbidden_get(_reference: str) -> str:
        raise AssertionError("dry run must not materialize credentials")

    monkeypatch.setattr(fixture.vault, "get", forbidden_get)
    authorization, binding = fixture.gate.authorize_and_bind(
        fixture.experiment, dry_run=True
    )
    outcome = binding.submit(authorization)
    assert fixture.calls == []
    assert outcome.request_delta.total == 0
    assert outcome.proposed_execution is not None
    assert outcome.proposed_execution.total_reservation == 1


def test_started_transport_failure_remains_exactly_accounted():
    fixture = build_runtime_fixture(proposal=replay_proposal())

    def failed_requester(_method: str, _url: str, **_kwargs: object):
        raise OSError("private transport detail")

    fixture.gate.transport.requester = failed_requester
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert outcome.result_classification.value == "runtime_failed"
    assert outcome.request_delta.total == outcome.request_delta.attempted == 1
    assert "private transport detail" not in outcome.model_dump_json()


def test_unbound_runtime_rejects_authorization():
    fixture = build_runtime_fixture()
    authorization = fixture.gate.authorize(fixture.experiment)
    with pytest.raises(Exception, match="invalid_binding"):
        fixture.gate.runtime.submit(authorization)
    assert fixture.calls == []


def test_reusing_same_binding_is_blocked_after_completion():
    fixture = build_runtime_fixture()
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    binding.submit(authorization)
    with pytest.raises(ResearchRuntimeError, match="duplicate_experiment"):
        binding.submit(authorization)


def test_explicit_reproduction_is_structurally_permitted_and_bounded():
    fixture = build_runtime_fixture(statuses=(200, 403, 200, 403, 403))
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    binding.submit(authorization)
    reproduction = fixture.experiment.model_copy(
        update={
            "experiment_id": "reproduction-experiment-1",
            "reproduction_of": fixture.experiment.experiment_id,
        }
    )
    reproduction_authorization, reproduction_binding = fixture.gate.authorize_and_bind(
        reproduction
    )
    outcome = reproduction_binding.submit(reproduction_authorization)
    assert outcome.request_delta.total == 3
    assert len(fixture.calls) == 5


def _state_change_proposal() -> ExperimentProposal:
    payload = mutation_proposal().model_dump(mode="python")
    payload["primary_identity_id"] = "identity-1"
    payload["primary_session_ref_id"] = "session-1"
    return ExperimentProposal.model_validate(payload)


def test_cleanup_uses_reserved_budget_and_failure_activates_barrier():
    fixture = build_runtime_fixture(
        proposal=_state_change_proposal(),
        statuses=(200, 500),
        state_changing=True,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert outcome.result_classification.value == "cleanup_failed"
    assert outcome.request_delta.verification == 1
    assert outcome.request_delta.cleanup == 1
    assert fixture.gate.cleanup_barrier.active is True
    with pytest.raises(Exception, match="cleanup_reserve_unavailable"):
        fixture.gate.authorize(fixture.experiment)


def test_successful_cleanup_is_recorded_with_exact_delta():
    fixture = build_runtime_fixture(
        proposal=_state_change_proposal(),
        statuses=(200, 204),
        state_changing=True,
    )
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    assert outcome.cleanup_status.value == "completed"
    assert outcome.cleanup_result.requests_used == 1
    assert outcome.request_delta.total == 2
    assert fixture.gate.cleanup_barrier.active is False


def test_persistence_failure_stops_runtime_progression():
    class FailingStore:
        state = None

        def load_research(self, _research_id: str):
            return self.state

        def commit_revision(self, *_args: object, **_kwargs: object):
            raise OSError("private database detail")

    store = FailingStore()
    fixture = build_runtime_fixture(store=store)
    store.state = fixture.gate.state
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    with pytest.raises(ResearchPersistenceError, match="persistence_failure"):
        binding.submit(authorization)
    assert len(fixture.calls) == 2
    with pytest.raises(ResearchPersistenceError, match="persistence_failure"):
        binding.submit(authorization)


def test_successful_execution_is_atomically_recorded(tmp_path):
    stores: list[ResearchStore] = []

    def create_store(state):
        store = ResearchStore(tmp_path / "research.sqlite3")
        initial = state.model_copy(update={"revision": 0})
        store.create_research(initial)
        current = initial
        for revision in range(1, state.revision + 1):
            current = current.model_copy(update={"revision": revision})
            store.commit_revision(
                state.research_id,
                expected_revision=revision - 1,
                state=current,
            )
        stores.append(store)
        return store

    fixture = build_runtime_fixture(store_factory=create_store)
    authorization, binding = fixture.gate.authorize_and_bind(fixture.experiment)
    outcome = binding.submit(authorization)
    persisted = stores[0].load_research("research-1")
    assert persisted.revision == 5
    assert persisted.experiment_outcomes[0].outcome_id == outcome.outcome_id
    assert persisted.experiment_outcomes[0].request_delta == outcome.request_delta
    assert {item.evidence_id for item in persisted.evidence}.issuperset(
        outcome.evidence_references
    )
    assert outcome.authorization_reference in persisted.provenance[-1].source_references
