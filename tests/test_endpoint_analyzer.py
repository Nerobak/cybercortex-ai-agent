from __future__ import annotations

import pytest

from tools.endpoint_analyzer import endpoint_analyzer


@pytest.mark.parametrize("value", [None, [], (), set(), (item for item in [])])
def test_empty_iterables(value):
    result = endpoint_analyzer(value, "example.test")
    assert result == {
        "success": True,
        "allowed_domain": "example.test",
        "total_urls_checked": 0,
        "interesting_count": 0,
        "interesting_endpoints": [],
        "static_assets": [],
        "skipped_urls": [],
        "errors": [],
    }


def test_one_and_multiple_urls_with_and_without_parameters():
    result = endpoint_analyzer(
        [
            "https://example.test/api/users",
            "https://example.test/search?q=one&sort=asc",
            "https://example.test/plain",
        ],
        "example.test",
    )
    assert result["total_urls_checked"] == 3
    assert result["interesting_count"] == 2
    assert result["interesting_endpoints"][1]["parameters"] == ["q", "sort"]


def test_duplicates_and_malformed_values_are_skipped_without_crashing():
    url = "https://example.test/api/users"
    result = endpoint_analyzer([url, url, None, 12, "not a url"], "example.test")
    assert result["interesting_count"] == 1
    assert len(result["skipped_urls"]) == 4


def test_user_route_is_observation_without_idor_claim():
    result = endpoint_analyzer(["https://example.test/account/profile"], "example.test")
    item = result["interesting_endpoints"][0]
    assert item["observed_identifiers"] == []
    assert item["vulnerability_status"] == "observation"
    assert "User-related route observed" in item["route_category"]
    assert "authorization" not in " ".join(item["review_reasons"]).lower()


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("https://example.test/api/users/1001", "numeric_identifier"),
        (
            "https://example.test/api/users/550e8400-e29b-41d4-a716-446655440000",
            "uuid_identifier",
        ),
        ("https://example.test/api/users?userId=1001", "id_named_parameter"),
    ],
)
def test_actual_object_references_enable_authorization_review(url, kind):
    item = endpoint_analyzer([url], "example.test")["interesting_endpoints"][0]
    assert item["observed_identifiers"][0]["identifier_kind"] == kind
    assert any(
        "authorization" in check.lower() for check in item["suggested_manual_checks"]
    )
