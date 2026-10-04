from __future__ import annotations

import pytest

from agent_core.controlled_context import (
    ControlledAccount,
    ControlledContext,
    ControlledObject,
    OwnedObjectAcquisition,
    owned_object_acquisition_reference,
)
from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.research import ControlledContextResearchAdapter, ResearchState

from test_phase4_graphql_semantics import TS, semantic_state

TARGET = "https://controlled.invalid"


def _policy(*account_ids: str) -> AssessmentPolicy:
    return AssessmentPolicy(
        profile_name="controlled-adapter-fixture",
        authorization_reference="authorization-controlled-adapter",
        authorization_confirmed=True,
        allowed_assets=[ScopeAsset(kind="url_prefix", value=TARGET, schemes=["https"])],
        allowed_methods=["GET", "POST"],
        controlled_account_ids=list(account_ids),
        credentials_allowed=True,
        request_budget=10,
        per_host_request_budget=10,
        resolve_dns_before_request=False,
    )


def _state(*surface_ids: str) -> ResearchState:
    base = semantic_state()
    selected_surfaces = tuple(
        item for item in base.surfaces if item.surface_id in surface_ids
    )
    selected_surface_ids = {item.surface_id for item in selected_surfaces}
    selected_endpoints = tuple(
        item for item in base.endpoints if item.surface_id in selected_surface_ids
    )
    selected_endpoint_ids = {item.endpoint_id for item in selected_endpoints}
    return ResearchState.model_validate(
        {
            **base.model_dump(mode="python"),
            "targets": (
                base.targets[0].model_copy(update={"canonical_reference": TARGET}),
            ),
            "surfaces": selected_surfaces,
            "endpoints": selected_endpoints,
            "parameters": tuple(
                item
                for item in base.parameters
                if item.endpoint_id in selected_endpoint_ids
            ),
            "identities": (),
            "objects": (),
            "graphql_surfaces": (),
            "graphql_types": (),
            "graphql_fields": (),
            "graphql_arguments": (),
            "graphql_operations": (),
            "graphql_variables": (),
        }
    )


@pytest.mark.parametrize(
    ("surface_ids", "source_reference", "expected_surface"),
    (
        (("surface-rest",), None, "surface-rest"),
        (("surface-graphql",), None, "surface-graphql"),
        (("surface-rest", "surface-graphql"), "surface-rest", "surface-rest"),
        (
            ("surface-rest", "surface-graphql"),
            "surface-graphql",
            "surface-graphql",
        ),
    ),
)
def test_controlled_object_import_is_deterministic_for_each_surface_shape(
    surface_ids,
    source_reference,
    expected_surface,
):
    state = _state(*surface_ids)
    context = ControlledContext(
        accounts=[ControlledAccount(account_id="account-a")],
        objects=[
            ControlledObject(
                object_id="owned-object-a",
                owner_account_id="account-a",
                object_type="Resource",
                source_reference=source_reference,
            )
        ],
    )

    records = ControlledContextResearchAdapter().adapt(
        context,
        state,
        policy=_policy("account-a"),
        target_id="target-1",
        occurred_at=TS,
    )

    assert len(records.objects) == 1
    assert records.objects[0].surface_id == expected_surface
    assert records.objects[0].test_owned is True
    assert records.objects[0].owner_identity_id is not None
    assert records.limitations == ()
    assert "controlled_object_surface_bound" in records.diagnostic_codes


@pytest.mark.parametrize(
    ("method", "collection_path", "expected_surface"),
    (
        ("GET", "/resources/{resourceRef}", "surface-rest"),
        ("POST", "/graphql", "surface-graphql"),
    ),
)
def test_acquisition_endpoint_provenance_binds_multi_surface_object(
    method,
    collection_path,
    expected_surface,
):
    state = _state("surface-rest", "surface-graphql")
    acquisition = OwnedObjectAcquisition(
        owner_account_id="account-a",
        collection_url=f"{TARGET}{collection_path}",
        method=method,
        object_type="Resource",
        identifier_field="resourceRef",
    )
    controlled_object = ControlledObject(
        object_id="owned-object-a",
        owner_account_id="account-a",
        object_type="Resource",
        ownership_basis="owner_scoped_authenticated_collection",
        source_reference=owned_object_acquisition_reference(acquisition),
    )
    context = ControlledContext(
        accounts=[ControlledAccount(account_id="account-a")],
        object_acquisition=[acquisition],
    )

    records = ControlledContextResearchAdapter().adapt_acquired_objects(
        (controlled_object,),
        context,
        state,
        policy=_policy("account-a"),
        target_id="target-1",
        occurred_at=TS,
    )

    assert len(records.objects) == 1
    assert records.objects[0].surface_id == expected_surface
    assert records.evidence[0].source_reference == controlled_object.source_reference


def test_ambiguous_object_fails_closed_without_discarding_resolvable_sibling():
    state = _state("surface-rest", "surface-graphql")
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="account-a"),
            ControlledAccount(account_id="account-b"),
        ],
        objects=[
            ControlledObject(
                object_id="ambiguous-object",
                owner_account_id="account-a",
                object_type="Resource",
            ),
            ControlledObject(
                object_id="resolved-object",
                owner_account_id="account-b",
                object_type="Resource",
                source_reference="endpoint-graphql",
            ),
        ],
    )

    records = ControlledContextResearchAdapter().adapt(
        context,
        state,
        policy=_policy("account-a", "account-b"),
        target_id="target-1",
        occurred_at=TS,
    )

    assert len(records.objects) == 1
    assert records.objects[0].surface_id == "surface-graphql"
    assert records.objects[0].object_reference == "resolved-object"
    assert records.limitations == ("controlled_object_surface_ambiguous",)
    assert set(records.diagnostic_codes) == {
        "controlled_object_surface_ambiguous",
        "controlled_object_surface_bound",
    }


def test_surface_binding_cannot_promote_uncontrolled_or_third_party_objects():
    state = _state("surface-rest", "surface-graphql")
    context = ControlledContext(
        accounts=[
            ControlledAccount(account_id="controlled"),
            ControlledAccount(account_id="uncontrolled", controlled=False),
        ],
        objects=[
            ControlledObject(
                object_id="third-party",
                owner_account_id="controlled",
                test_owned=False,
                source_reference="surface-rest",
            ),
            ControlledObject(
                object_id="uncontrolled-owner",
                owner_account_id="uncontrolled",
                source_reference="surface-rest",
            ),
            ControlledObject(
                object_id="unknown-owner",
                owner_account_id="unknown",
                source_reference="surface-rest",
            ),
        ],
    )

    records = ControlledContextResearchAdapter().adapt(
        context,
        state,
        policy=_policy("controlled"),
        target_id="target-1",
        occurred_at=TS,
    )

    assert records.objects == ()
    assert records.evidence == ()
    assert "controlled_object_owner_unavailable" in records.diagnostic_codes
    serialized = records.model_dump_json()
    assert "third-party" not in serialized
    assert "uncontrolled-owner" not in serialized
    assert "unknown-owner" not in serialized
