from __future__ import annotations

import json

from agent_core.attack_surface import CanonicalAttackSurface, SurfaceEvidence
from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
)
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    BaselineIntent,
    BaselineKind,
    DifferentialSelector,
    EvidenceIntent,
    ExperimentCandidateBuilder,
    ExperimentCompiler,
    ExperimentCompilerContext,
    ExperimentProposal,
    ExperimentSelector,
    IdentityRelationship,
    MutationIntent,
    MutationKind,
    ObjectSubstitutionInput,
    PrimitiveStepProposal,
    PublicSafeCandidatePacketBuilder,
    PublicSafeResearchPacketBuilder,
    ResearchBootstrapLimits,
    ResearchBootstrapper,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchExecutionGate,
    ResearchStore,
    RequestTemplateFactory,
    TargetClass,
    materialize_candidate,
)
from tools.safe_http import ScopedHTTPClient
from agent_core.research.authenticated_discovery import (
    _identity_bound_owned_objects,
)

TARGET = "https://controlled-discovery.example"
NOW = "2026-09-24T12:00:00+00:00"
TOKEN_A = "controlled-discovery-token-a"
TOKEN_B = "controlled-discovery-token-b"


class FakeResponse:
    def __init__(self, body: object):
        self.status_code = 200
        self.content = json.dumps(body).encode()
        self.headers = {"Content-Type": "application/json"}
        self.is_redirect = False
        self.is_permanent_redirect = False

    def iter_content(self, chunk_size: int):
        del chunk_size
        yield self.content

    def close(self):
        return None


def surface() -> CanonicalAttackSurface:
    routes = []
    parameters = []
    boundaries = []
    for path in ("/resources", "/resources/{resource_id}"):
        routes.append(
            {
                "method": "GET",
                "path": path,
                "source": "fake-observation",
                "confidence": "high",
                "evidence_refs": [f"evidence:{path}"],
                "content_types": ["application/json"],
            }
        )
        parameters.append(
            {
                "method": "GET",
                "path": path,
                "name": "Authorization",
                "in": "header",
                "schema_type": "string",
                "required": True,
                "source": "fake-observation",
                "confidence": "high",
                "evidence_refs": [f"evidence:{path}"],
            }
        )
        boundaries.append(
            {
                "method": "GET",
                "path": path,
                "boundary_type": "authenticated_resource",
                "confidence": "high",
                "evidence_refs": [f"evidence:{path}"],
            }
        )
    parameters.append(
        {
            "method": "GET",
            "path": "/resources/{resource_id}",
            "name": "resource_id",
            "in": "path",
            "schema_type": "string",
            "required": True,
            "source": "fake-observation",
            "confidence": "high",
            "evidence_refs": ["evidence:/resources/{resource_id}"],
        }
    )
    return CanonicalAttackSurface(
        target=TARGET,
        routes=routes,
        parameters=parameters,
        auth_boundaries=boundaries,
        evidence_sources=(
            SurfaceEvidence(source="fake-observation", reference="surface-run"),
        ),
    )


class DiscoveryRunner:
    def __init__(self, budget: RequestBudget, client: ScopedHTTPClient):
        self.request_budget = budget
        self.http_client = client

    def run(self, target: str, **_kwargs):
        self.request_budget.consume("discovery", host="controlled-discovery.example")
        assert target == TARGET
        return {"canonical_attack_surface": surface().model_dump(mode="json")}


def policy() -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="controlled-discovery-test",
        authorization_reference="authorization-controlled-discovery",
        authorization_confirmed=True,
        allowed_assets=(ScopeAsset(kind="url_prefix", value=TARGET),),
        allowed_methods=("GET", "HEAD", "OPTIONS"),
        controlled_account_ids=("owner-a", "owner-b"),
        credentials_allowed=True,
        request_budget=10,
        per_host_request_budget=10,
        resolve_dns_before_request=False,
        requests_per_second=100,
    )


def test_authenticated_discovery_acquires_only_owner_scoped_objects_and_enables_bola(
    tmp_path,
):
    budget = RequestBudget(10, per_host_limit=10)
    assessment_policy = policy()
    calls = []

    def requester(method: str, url: str, **kwargs):
        calls.append((method, url, kwargs))
        credential = kwargs["headers"]["Authorization"]
        identifier = "owned-a" if credential == f"Bearer {TOKEN_A}" else "owned-b"
        return FakeResponse([{"id": identifier, "label": "controlled"}])

    client = ScopedHTTPClient(
        policy=assessment_policy,
        budget=budget,
        requester=requester,
        max_response_bytes=100_000,
    )
    budgets = ResearchBudgetManager(
        ResearchBudgetPolicy(wall_time_ceiling_seconds=300.0),
        request_budget=budget,
        model_call_ceiling=4,
    )
    store = ResearchStore(tmp_path / "authenticated-discovery.sqlite3")
    initial = ResearchBootstrapper.register_target(
        store,
        research_id="controlled-discovery-run",
        target_url=TARGET,
        target_class=TargetClass.dedicated_lab,
        scope_reference="controlled-discovery-scope",
        policy=assessment_policy,
        budget_manager=budgets,
        occurred_at=NOW,
    )
    with CredentialVault() as vault:
        context = ControlledContext(
            accounts=(
                ControlledAccount(
                    account_id="owner-a",
                    session_reference=vault.put(TOKEN_A, label="owner-a-token"),
                ),
                ControlledAccount(
                    account_id="owner-b",
                    session_reference=vault.put(TOKEN_B, label="owner-b-token"),
                ),
            )
        )
        assert context.objects == []
        bootstrapper = ResearchBootstrapper(
            store=store,
            policy=assessment_policy,
            controlled_context=context,
            request_budget=budget,
            budget_manager=budgets,
            target_id=initial.targets[0].target_id,
            profile="authenticated",
            tool_runner=DiscoveryRunner(budget, client),
            vault=vault,
            limits=ResearchBootstrapLimits(
                maximum_discovery_target_requests=5,
                maximum_bootstrap_model_calls=0,
                wall_time_seconds=30.0,
            ),
            now=lambda: NOW,
        )
        state = bootstrapper.prepare(initial)

        assert len(calls) == 2
        assert all(call[0] == "GET" for call in calls)
        assert all(call[1] == f"{TARGET}/resources" for call in calls)
        assert budget.snapshot()["discovery_requests"] == 3
        assert len(state.objects) == 2
        assert len(context.objects) == 2
        assert {item.object_reference for item in state.objects} == {
            "owned-a",
            "owned-b",
        }
        assert all(item.test_owned for item in state.objects)
        assert all(item.owner_identity_id for item in state.objects)
        assert all(len(item.parameter_references) == 1 for item in state.objects)
        assert all(
            "owner-scoped authenticated collection"
            in next(
                evidence.summary
                for evidence in state.evidence
                if evidence.evidence_id == item.evidence_references[0]
            ).lower()
            for item in state.objects
        )

        detail = next(item for item in state.endpoints if "{" in item.route_template)
        parameter = next(
            item
            for item in state.parameters
            if item.endpoint_id == detail.endpoint_id and item.location.value == "path"
        )
        template = next(
            item
            for item in state.request_templates
            if item.endpoint_id == detail.endpoint_id
        )
        assert template.identity_requirement.required is True
        assert template.identity_requirement.mechanisms == ("authorization_header",)
        runtime_template = RequestTemplateFactory.to_runtime_template(template, state)
        assert runtime_template.credential_header_name == "Authorization"
        assert [item.parameter_id for item in runtime_template.parameters] == [
            parameter.parameter_id
        ]

        owned = next(
            item for item in state.objects if item.object_reference == "owned-a"
        )
        comparison = next(
            item
            for item in state.identities
            if item.identity_id != owned.owner_identity_id
        )
        hypothesis = next(item for item in state.hypotheses if item.category == "bola")
        proposal = ExperimentProposal(
            proposal_id="generic-object-substitution-proposal",
            research_id=state.research_id,
            state_revision=state.revision,
            hypothesis_id=hypothesis.hypothesis_id,
            capability="bola",
            target_id=hypothesis.target_id,
            surface_id=hypothesis.surface_id,
            endpoint_id=detail.endpoint_id,
            objective="Compare one controlled owner resource across two accounts.",
            primary_identity_id=owned.owner_identity_id,
            comparison_identity_id=comparison.identity_id,
            identity_relationship=IdentityRelationship.owner_non_owner,
            baseline=BaselineIntent(
                kind=BaselineKind.registered_request,
                reference_id=template.template_id,
            ),
            mutation_intent=MutationIntent(
                kind=MutationKind.replace_with_controlled_object_reference,
                parameter_id=parameter.parameter_id,
                controlled_object_id=owned.object_id,
            ),
            expected_secure_behavior="The non-owner is denied the owner resource.",
            expected_vulnerable_behavior="The non-owner receives the owner resource.",
            required_evidence_intent=(
                EvidenceIntent(
                    selector=DifferentialSelector.status_class,
                    predicate_reference="owner-boundary-predicate",
                ),
            ),
            rationale="The observed ownership and parameter relationship is bounded.",
            primitive_steps=(
                PrimitiveStepProposal(
                    step_id="generic-object-substitution-step",
                    input=ObjectSubstitutionInput(
                        request_template_id=template.template_id,
                        endpoint_id=detail.endpoint_id,
                        parameter_id=parameter.parameter_id,
                        primary_identity_id=owned.owner_identity_id,
                        comparison_identity_id=comparison.identity_id,
                        controlled_object_id=owned.object_id,
                        relationship=IdentityRelationship.owner_non_owner,
                        ownership_evidence_ids=owned.evidence_references,
                    ),
                ),
            ),
            provenance_id=hypothesis.provenance_id,
            model_decision_id="fake-research-decision",
        )
        compiler_context = bootstrapper.compiler_context(
            state,
            ExperimentCompilerContext(
                current_time=NOW,
                execution_ready=True,
                policy_reference=assessment_policy.authorization_reference,
                context_reference="controlled-discovery-context",
            ),
        )
        compiler = ExperimentCompiler(context=compiler_context)
        selection = ExperimentSelector(compiler, budgets).select((proposal,), state)
        packet = PublicSafeResearchPacketBuilder(compiler.registry, budgets).build(
            state
        )
        registry = compiler.registry
        candidate_builder = ExperimentCandidateBuilder(registry, budgets, compiler)
        candidates = candidate_builder.build(
            state,
            compiler_context=compiler_context,
            expected_state_revision=state.revision,
            policy_reference=compiler_context.policy_reference,
        )
        candidate_packet = PublicSafeCandidatePacketBuilder(budgets).build(
            state, candidates
        )
        candidate = next(
            item for item in candidates if item.primitive_kind == "object_substitution"
        )
        candidate_proposal = materialize_candidate(candidate, state)
        experiment = compiler.compile(candidate_proposal, state, compiler_context)
        gate = ResearchExecutionGate(
            state=state,
            policy=assessment_policy,
            controlled_context=context,
            vault=vault,
            budget=budget,
            transport=client,
            compiler_context=compiler_context,
            request_templates=bootstrapper.runtime_request_templates(state),
            store=store,
            scope_reference=state.targets[0].scope_reference,
            current_time=NOW,
        )
        authorization = gate.authorize(experiment)
        serialized = "".join(
            (
                state.model_dump_json(),
                packet.model_dump_json(),
                json.dumps(
                    [item.model_dump(mode="json") for item in candidates],
                    sort_keys=True,
                ),
                candidate_packet.model_dump_json(),
                candidate_proposal.model_dump_json(),
                experiment.model_dump_json(),
            )
        )

    assert selection.selected is not None
    assert candidates
    assert authorization.experiment is experiment
    assert any(
        item["name"] == "object_substitution"
        for item in packet.available_execution_primitives
    )
    assert len(packet.controlled_objects) == 2
    assert all(item["parameter_references"] for item in packet.controlled_objects)
    assert TOKEN_A not in serialized
    assert TOKEN_B not in serialized
    for path in tmp_path.iterdir():
        assert TOKEN_A.encode() not in path.read_bytes()
        assert TOKEN_B.encode() not in path.read_bytes()


def test_shared_collection_identifier_is_not_asserted_as_owned():
    candidates = [
        ControlledObject(
            object_id="shared-resource",
            owner_account_id=account,
            object_type="resource",
            parameter_ids=("resource-parameter",),
            ownership_basis="owner_scoped_authenticated_collection",
        )
        for account in ("owner-a", "owner-b")
    ]
    assert _identity_bound_owned_objects(candidates) == ()
