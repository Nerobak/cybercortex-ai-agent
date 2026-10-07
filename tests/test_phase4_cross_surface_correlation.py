from __future__ import annotations

import json

from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquirer,
    OwnedObjectAcquisition,
    owned_object_acquisition_reference,
)
from agent_core.credential_vault import CredentialVault
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.research import (
    ControlledContextResearchAdapter,
    CrossSurfaceControlledObjectCorrelator,
    CrossSurfaceCorrelationRejectionReason,
    ExperimentRegistry,
    ExperimentCompiler,
    ExperimentCompilerContext,
    GraphQLExperimentCandidateBuilder,
    GraphQLHypothesisGenerator,
    PublicSafeResearchPacketBuilder,
    ResearchBudgetManager,
    ResearchPredicate,
    ResearchState,
    ResearchStore,
    build_graphql_graph_assertions,
    candidate_ready_graphql_operation_templates,
    derive_candidate_ready_graphql_operations,
)

from test_phase4_graphql_readiness import (
    TARGET,
    _controlled_policy,
    _schema_without_controlled_objects,
    _with_registered_operation,
)
from test_phase4_graphql_semantics import TS


def _policy(*account_ids: str) -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="cross-surface-correlation-fixture",
        authorization_reference="authorization-cross-surface-correlation",
        authorization_confirmed=True,
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        controlled_account_ids=list(account_ids),
        credentials_allowed=True,
        request_budget=20,
        per_host_request_budget=20,
        resolve_dns_before_request=False,
    )


def _state(
    *,
    accounts: tuple[str, ...] = ("account-a", "account-b"),
    evidenced_accounts: tuple[str, ...] = ("account-a",),
) -> ResearchState:
    schema = _schema_without_controlled_objects()
    acquisitions = tuple(
        OwnedObjectAcquisition(
            owner_account_id=account_id,
            collection_url=f"{TARGET}/resources/{{resourceRef}}",
            object_type="Resource",
            identifier_field="resourceRef",
            identifier_parameter_reference=(
                "parameter-resource-ref" if account_id in evidenced_accounts else None
            ),
        )
        for account_id in accounts
    )
    context = ControlledContext(
        accounts=[ControlledAccount(account_id=item) for item in accounts],
        object_acquisition=list(acquisitions),
    )
    acquired = tuple(
        ControlledObject(
            object_id=f"controlled-reference-{index}",
            owner_account_id=config.owner_account_id,
            object_type=config.object_type,
            parameter_ids=(
                (config.identifier_parameter_reference,)
                if config.identifier_parameter_reference is not None
                else ()
            ),
            ownership_basis="owner_scoped_authenticated_collection",
            source_reference=owned_object_acquisition_reference(config),
        )
        for index, config in enumerate(acquisitions, start=1)
    )
    adapter = ControlledContextResearchAdapter()
    records = adapter.adapt_acquired_objects(
        acquired,
        context,
        schema,
        policy=_controlled_policy(),
        target_id="target-1",
        occurred_at=TS,
    )
    return _with_registered_operation(adapter.apply(schema, records))


def _correlate(state: ResearchState, *, include_cross_surface: bool = True):
    graph = build_graphql_graph_assertions(state, asserted_at=TS)
    if not include_cross_surface:
        graph = tuple(
            item
            for item in graph
            if item.relation is not ResearchPredicate.crosses_surface
        )
    return CrossSurfaceControlledObjectCorrelator().correlate(
        state,
        graph_assertions=graph,
        templates=candidate_ready_graphql_operation_templates(state),
    )


def test_closed_cross_surface_evidence_creates_stable_binding_without_calls():
    state = _state()

    first = _correlate(state)
    second = _correlate(state)

    assert len(first.correlations) == 1
    assert first == second
    assert first.bindings[0].value_reference in {
        item.object_id for item in state.objects if item.reference_evidence
    }
    assert first.correlations[0].binding_fingerprint.startswith("sha256:")
    assert first.target_requests == first.model_calls == 0


def test_benchmark7_shape_blocks_without_object_reference_then_closes_with_it():
    blocked = _correlate(_state(evidenced_accounts=()))
    closed = _correlate(_state(evidenced_accounts=("account-a",)))

    assert blocked.bindings == ()
    assert {item.reason for item in blocked.rejections} == {
        CrossSurfaceCorrelationRejectionReason.missing_object_reference_evidence
    }
    assert len(closed.bindings) == 1


def test_name_only_match_cannot_replace_typed_cross_surface_relation():
    state = _state()
    result = _correlate(state, include_cross_surface=False)

    assert result.bindings == ()
    assert {item.reason for item in result.rejections} == {
        CrossSurfaceCorrelationRejectionReason.missing_cross_surface_relation
    }
    assert GraphQLHypothesisGenerator().generate_result(state, ()).hypotheses == ()


def test_two_fully_evidenced_objects_fail_closed_as_ambiguous():
    result = _correlate(_state(evidenced_accounts=("account-a", "account-b")))

    assert result.bindings == ()
    assert {item.reason for item in result.rejections} == {
        CrossSurfaceCorrelationRejectionReason.ambiguous_object_reference
    }


def test_same_wire_reference_remains_distinct_across_controlled_owners():
    shared_reference = "shared-owner-local-reference"
    schema = _schema_without_controlled_objects()
    acquisitions = tuple(
        OwnedObjectAcquisition(
            owner_account_id=account_id,
            collection_url=f"{TARGET}/resources/{{resourceRef}}",
            object_type="Resource",
            identifier_field="resourceRef",
            identifier_parameter_reference="parameter-resource-ref",
        )
        for account_id in ("account-a", "account-b")
    )
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id=item) for item in ("account-a", "account-b")
        ],
        object_acquisition=list(acquisitions),
    )
    acquired = tuple(
        ControlledObject(
            object_id=shared_reference,
            owner_account_id=config.owner_account_id,
            object_type=config.object_type,
            parameter_ids=("parameter-resource-ref",),
            ownership_basis="owner_scoped_authenticated_collection",
            source_reference=owned_object_acquisition_reference(config),
        )
        for config in acquisitions
    )
    records = ControlledContextResearchAdapter().adapt_acquired_objects(
        acquired,
        context,
        schema,
        policy=_controlled_policy(),
        target_id="target-1",
        occurred_at=TS,
    )

    assert len(records.objects) == 2
    assert len({item.object_id for item in records.objects}) == 2
    assert len({item.owner_identity_id for item in records.objects}) == 2


def test_third_party_object_cannot_be_promoted_to_binding_or_hypothesis():
    state = _state(accounts=("account-a",), evidenced_accounts=("account-a",))
    third_party = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "objects": tuple(
                item.model_copy(update={"test_owned": False}) for item in state.objects
            ),
        }
    )
    result = _correlate(third_party)

    assert result.bindings == ()
    assert {item.reason for item in result.rejections} == {
        CrossSurfaceCorrelationRejectionReason.missing_ownership_evidence
    }
    assert (
        GraphQLHypothesisGenerator()
        .generate_result(
            third_party,
            build_graphql_graph_assertions(third_party, asserted_at=TS),
        )
        .hypotheses
        == ()
    )


def test_conflicting_reference_fingerprints_fail_closed():
    state = _state(accounts=("account-a",), evidenced_accounts=("account-a",))
    controlled_object = state.objects[0]
    reference = controlled_object.reference_evidence[0]
    conflict = reference.model_copy(
        update={
            "reference_evidence_id": "object-reference-evidence-conflict",
            "value_fingerprint": "sha256:" + "9" * 64,
        }
    )
    conflicting = ResearchState.model_validate(
        {
            **state.model_dump(mode="python"),
            "objects": (
                controlled_object.model_copy(
                    update={"reference_evidence": (reference, conflict)}
                ),
            ),
        }
    )

    result = _correlate(conflicting)

    assert result.bindings == ()
    assert {item.reason for item in result.rejections} == {
        CrossSurfaceCorrelationRejectionReason.conflicting_object_reference
    }


def test_binding_applies_through_existing_readiness_without_execution():
    state = _state()
    correlation = _correlate(state)

    ready, limitations = derive_candidate_ready_graphql_operations(
        state,
        {},
        occurred_at=TS,
        binding_evidence=correlation.readiness_evidence,
    )

    assert limitations == ()
    assert ready.graphql_variables[0].controlled_value_reference == (
        correlation.bindings[0].value_reference
    )
    assert candidate_ready_graphql_operation_templates(ready)[0].variable_bindings
    assert correlation.target_requests == correlation.model_calls == 0


def test_readiness_rejects_forged_relationship_references():
    state = _state()
    correlation = _correlate(state)
    unrelated = tuple(
        item.assertion_id
        for item in build_graphql_graph_assertions(state, asserted_at=TS)
        if item.relation
        not in {
            ResearchPredicate.graphql_variable_binds_argument,
            ResearchPredicate.crosses_surface,
        }
    )[:2]
    forged = correlation.readiness_evidence[0].model_copy(
        update={"relationship_assertion_ids": unrelated}
    )

    rejected, _ = derive_candidate_ready_graphql_operations(
        state,
        {},
        occurred_at=TS,
        binding_evidence=(forged,),
    )

    assert len(unrelated) == 2
    assert rejected.graphql_variables[0].controlled_value_reference is None
    assert (
        candidate_ready_graphql_operation_templates(rejected)[0].variable_bindings == ()
    )


def test_repeated_full_readiness_generation_and_candidates_are_idempotent():
    state = _state()
    first = _correlate(state)
    ready, _ = derive_candidate_ready_graphql_operations(
        state,
        {},
        occurred_at=TS,
        binding_evidence=first.readiness_evidence,
    )
    second = _correlate(ready)
    ready_again, _ = derive_candidate_ready_graphql_operations(
        ready,
        {},
        occurred_at=TS,
        binding_evidence=second.readiness_evidence,
    )
    first_graph = build_graphql_graph_assertions(ready, asserted_at=TS)
    second_graph = build_graphql_graph_assertions(ready_again, asserted_at=TS)
    first_generation = GraphQLHypothesisGenerator().generate_result(ready, first_graph)
    second_generation = GraphQLHypothesisGenerator().generate_result(
        ready_again, second_graph
    )
    prepared = ResearchState.model_validate(
        {
            **ready.model_dump(mode="python"),
            "hypotheses": first_generation.hypotheses,
            "provenance": (*ready.provenance, *first_generation.provenance),
        }
    )
    registry = ExperimentRegistry()
    budgets = ResearchBudgetManager()
    compiler_context = ExperimentCompilerContext(
        current_time=TS,
        graphql_operation_templates=candidate_ready_graphql_operation_templates(
            prepared
        ),
        policy_reference="policy-cross-surface-idempotency",
    )
    compiler = ExperimentCompiler(registry, compiler_context)
    builder = GraphQLExperimentCandidateBuilder(registry, budgets, compiler)
    candidates_first = builder.build(
        prepared,
        compiler_context=compiler_context,
        graph=first_graph,
    )
    candidates_second = builder.build(
        prepared,
        compiler_context=compiler_context,
        graph=first_graph,
    )

    assert first.correlations[0].binding_fingerprint == (
        second.correlations[0].binding_fingerprint
    )
    assert ready_again == ready
    assert second_graph == first_graph
    assert second_generation == first_generation
    assert candidates_second == candidates_first
    assert len({item.candidate_id for item in candidates_first}) == len(
        candidates_first
    )


def test_correlation_survives_research_store_restart(tmp_path):
    state = _state()
    store = ResearchStore(tmp_path / "cross-surface-restart.sqlite3")
    store.create_research(state)

    before = _correlate(state)
    after = _correlate(store.load_research(state.research_id))

    assert before == after
    assert store.verify_integrity(state.research_id).valid is True


def test_owned_rest_acquisition_preserves_explicit_parameter_provenance():
    vault = CredentialVault()
    budget = RequestBudget(2, per_host_limit=2)
    token_reference = vault.put("synthetic-wire-token", label="controlled-token")
    account = ControlledAccount(
        account_id="account-a", session_reference=token_reference
    )
    config = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=f"{TARGET}/resources",
        object_type="Resource",
        identifier_field="resourceRef",
        identifier_parameter_reference="parameter-resource-ref",
    )

    try:
        acquired = OwnedObjectAcquirer(vault, budget).acquire(
            account,
            config,
            lambda _request: {
                "status_code": 200,
                "body": [{"resourceRef": "synthetic-controlled-reference"}],
            },
        )
    finally:
        vault.close()

    assert acquired.parameter_ids == ("parameter-resource-ref",)
    assert acquired.source_reference == owned_object_acquisition_reference(config)


def test_secret_and_personal_values_never_enter_state_packets_or_graph():
    sentinels = (
        "sensitive-object-secret-sentinel",
        "credential-value-sentinel",
        "jwt-value-sentinel",
        "cookie-value-sentinel",
        "private-person@example.test",
    )
    schema = _schema_without_controlled_objects()
    accounts = tuple(f"account-{index}" for index in range(len(sentinels)))
    acquisitions = tuple(
        OwnedObjectAcquisition(
            owner_account_id=account,
            collection_url=f"{TARGET}/resources/{{resourceRef}}",
            object_type="Resource",
            identifier_field="resourceRef",
            identifier_parameter_reference="parameter-resource-ref",
        )
        for account in accounts
    )
    context = ControlledContext(
        accounts=[ControlledAccount(account_id=item) for item in accounts],
        object_acquisition=list(acquisitions),
    )
    acquired = tuple(
        ControlledObject(
            object_id=sentinel,
            owner_account_id=config.owner_account_id,
            object_type=config.object_type,
            parameter_ids=("parameter-resource-ref",),
            ownership_basis="owner_scoped_authenticated_collection",
            source_reference=owned_object_acquisition_reference(config),
        )
        for sentinel, config in zip(sentinels, acquisitions, strict=True)
    )
    adapter = ControlledContextResearchAdapter()
    records = adapter.adapt_acquired_objects(
        acquired,
        context,
        schema,
        policy=_policy(*accounts),
        target_id="target-1",
        occurred_at=TS,
    )
    state = _with_registered_operation(adapter.apply(schema, records))
    packet = PublicSafeResearchPacketBuilder(
        ExperimentRegistry(), ResearchBudgetManager()
    ).build(state)
    graph = build_graphql_graph_assertions(state, asserted_at=TS)
    serialized = json.dumps(
        {
            "packet": packet.model_dump(mode="json"),
            "graph": [item.model_dump(mode="json") for item in graph],
            "correlation": _correlate(state).model_dump(mode="json"),
        },
        sort_keys=True,
    )

    assert all(item not in serialized for item in sentinels)
