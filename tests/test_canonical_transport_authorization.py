from __future__ import annotations

import math
import os
from collections.abc import Callable
from typing import Any

import pytest
import requests

from agent_core.policy import AssessmentPolicy, ScopeAsset
from agent_core.request_budget import RequestBudget
from agent_core.url_authorization import (
    URLCanonicalizationError,
    canonicalize_transport_url,
)
from tools import scope_guard
from tools.api_metadata_discovery import api_metadata_discovery
from tools.api_object_discovery import crawl_and_discover_ids
from tools.safe_http import (
    PolicyViolationError,
    ScopedHTTPClient,
    UnsafeRedirectError,
)

ORIGIN = "https://scope.example.test"
ROOT = f"{ORIGIN}/app"


def _policy(root: str = ROOT, *, max_redirects: int = 5) -> AssessmentPolicy:
    return AssessmentPolicy(
        authorization_confirmed=True,
        authorization_reference="synthetic-canonical-transport-test",
        program_name="synthetic-canonical-transport-test",
        allowed_assets=[
            ScopeAsset(
                kind="url_prefix",
                value=root,
                schemes=["https"],
                ports=[443],
            )
        ],
        request_budget=20,
        per_host_request_budget=20,
        requests_per_second=100,
        max_concurrency=2,
        max_redirects=max_redirects,
        resolve_dns_before_request=False,
    )


def _response(
    url: str,
    *,
    status: int = 200,
    location: str | None = None,
    body: bytes = b"",
    content_type: str = "text/plain",
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers = requests.structures.CaseInsensitiveDict(
        {"Content-Type": content_type}
    )
    if location is not None:
        response.headers["Location"] = location
    response._content = body
    response._content_consumed = True
    return response


class RecordingRequester:
    def __init__(
        self,
        responses: list[requests.Response]
        | Callable[[str, str, dict[str, Any], int], requests.Response],
    ) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.calls.append((method, url, dict(kwargs)))
        if callable(self.responses):
            return self.responses(method, url, kwargs, len(self.calls))
        if not self.responses:
            raise AssertionError("unexpected fake-client dispatch")
        response = self.responses.pop(0)
        response.url = url
        return response


def _client(
    policy: AssessmentPolicy,
    requester: RecordingRequester,
    *,
    budget: RequestBudget | None = None,
) -> ScopedHTTPClient:
    return ScopedHTTPClient(
        policy=policy,
        budget=budget or RequestBudget(20, per_host_limit=20),
        requester=requester,
    )


@pytest.mark.parametrize(
    "suffix",
    [
        "/%2e%2e/outside",
        "/%2E%2e/outside",
        "/../outside",
        "/./outside",
        "/%252e%252e/outside",
        "/%2f..%2foutside",
        "/%2F..%2Foutside",
        "/%5c..%5coutside",
        "/%5C..%5Coutside",
        "/\\../outside",
        "/%2",
        "/%zz",
    ],
)
def test_ambiguous_path_rejected_before_explicit_transport(suffix: str) -> None:
    policy = _policy()
    requester = RecordingRequester([])
    client = _client(policy, requester)

    assert not policy.authorize_url(ROOT + suffix).allowed
    with pytest.raises(PolicyViolationError):
        client.request("GET", ROOT + suffix, purpose="discovery", timeout=1)

    assert requester.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://scope.example.test@evil.example/app",
        "https://user:password@scope.example.test/app",
        "https://scope.example.test.evil.example/app",
        "https://scope.example.test:444/app",
        "http://scope.example.test/app",
    ],
)
def test_authority_origin_changes_rejected_before_transport(url: str) -> None:
    policy = _policy()
    requester = RecordingRequester([])
    client = _client(policy, requester)

    with pytest.raises(PolicyViolationError):
        client.request("GET", url, purpose="discovery", timeout=1)

    assert requester.calls == []


def test_query_is_preserved_but_never_changes_path_authorization() -> None:
    policy = _policy()
    requester = RecordingRequester([_response(ROOT)])
    client = _client(policy, requester)
    query_url = ROOT + "?next=/outside/../still-query&value=%2F"

    client.request("GET", query_url, purpose="discovery", timeout=(1, 2))

    assert requester.calls[0][1] == query_url
    assert requester.calls[0][2]["timeout"] == (1.0, 2.0)
    assert policy.authorize_url(query_url).allowed
    assert not policy.authorize_url(ROOT + "?bad=%zz").allowed


def test_explicit_and_legacy_use_the_same_canonical_contract(monkeypatch) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", ROOT)
    policy = _policy()
    valid = "HTTPS://SCOPE.EXAMPLE.TEST/app/items?order=1"
    invalid = ROOT + "/%252e%252e/outside"

    explicit = scope_guard.enforce_scope(valid, assessment_policy=policy)
    legacy = scope_guard.enforce_scope(valid)

    assert explicit["allowed"] and legacy["allowed"]
    assert explicit["target"] == legacy["target"]
    assert explicit["target"] == ROOT + "/items?order=1"
    assert not scope_guard.enforce_scope(invalid, assessment_policy=policy)["allowed"]
    assert not scope_guard.enforce_scope(invalid)["allowed"]


def test_permit_yields_the_exact_prepared_target_and_finite_timeout() -> None:
    policy = _policy()
    with scope_guard.assessment_policy_scope(policy):
        with scope_guard.request_dispatch_permit(
            "HTTPS://SCOPE.EXAMPLE.TEST/app?x=1",
            assessment_policy=policy,
            timeout=(1, 2),
        ) as admission:
            assert admission["target"] == ROOT + "?x=1"
            assert admission["dispatch_timeout"] == (1.0, 2.0)


@pytest.mark.parametrize("timeout", [None, 0, -1, math.inf, math.nan, (1,), (1, 0)])
def test_non_finite_or_incomplete_timeout_rejected_before_transport(
    timeout: Any,
) -> None:
    requester = RecordingRequester([])
    client = _client(_policy(), requester)

    with pytest.raises(PolicyViolationError):
        client.request("GET", ROOT, purpose="discovery", timeout=timeout)

    assert requester.calls == []


def test_relative_and_absolute_redirects_are_prepared_and_authorized_per_hop() -> None:
    policy = _policy()
    requester = RecordingRequester(
        [
            _response(ROOT + "/start", status=302, location="next"),
            _response(ROOT + "/next", status=302, location=ROOT + "/final"),
            _response(ROOT + "/final"),
        ]
    )
    client = _client(policy, requester)

    _, chain = client.request(
        "GET",
        ROOT + "/start",
        purpose="discovery",
        timeout=1,
        follow_redirects=True,
        max_redirects=2,
    )

    assert [call[1] for call in requester.calls] == [
        ROOT + "/start",
        ROOT + "/next",
        ROOT + "/final",
    ]
    assert len(chain) == 2
    assert all(hop["allowed"] for hop in chain)


@pytest.mark.parametrize(
    "location",
    [
        "https://sibling.example.test/app",
        "https://scope.example.test:444/app",
        "http://scope.example.test/app",
        "/app/%2e%2e/outside",
        "/app/%252e%252e/outside",
        "/app/%2Foutside",
    ],
)
def test_unauthorized_absolute_or_ambiguous_redirect_never_dispatches(
    location: str,
) -> None:
    requester = RecordingRequester([_response(ROOT, status=302, location=location)])
    client = _client(_policy(), requester)

    with pytest.raises(UnsafeRedirectError):
        client.request(
            "GET",
            ROOT,
            purpose="discovery",
            timeout=1,
            follow_redirects=True,
            max_redirects=2,
        )

    assert len(requester.calls) == 1


def test_redirect_loop_and_depth_are_bounded() -> None:
    loop_requester = RecordingRequester([_response(ROOT, status=302, location=ROOT)])
    loop_client = _client(_policy(), loop_requester)
    with pytest.raises(UnsafeRedirectError, match="loop"):
        loop_client.request(
            "GET",
            ROOT,
            purpose="discovery",
            timeout=1,
            follow_redirects=True,
            max_redirects=2,
        )
    assert len(loop_requester.calls) == 1

    def redirect_forever(
        method: str, url: str, kwargs: dict[str, Any], position: int
    ) -> requests.Response:
        return _response(url, status=302, location=f"{ROOT}/hop-{position}")

    depth_requester = RecordingRequester(redirect_forever)
    depth_client = _client(_policy(max_redirects=1), depth_requester)
    with pytest.raises(UnsafeRedirectError, match="limit"):
        depth_client.request(
            "GET",
            ROOT,
            purpose="discovery",
            timeout=1,
            follow_redirects=True,
            max_redirects=1,
        )
    assert len(depth_requester.calls) == 2


def test_redirect_request_budget_exhaustion_prevents_next_hop_dispatch() -> None:
    policy = _policy()
    budget = RequestBudget(1, per_host_limit=1)
    requester = RecordingRequester(
        [_response(ROOT, status=302, location=ROOT + "/next")]
    )
    client = _client(policy, requester, budget=budget)

    with pytest.raises(PolicyViolationError, match="budget exhausted"):
        client.request(
            "GET",
            ROOT,
            purpose="discovery",
            timeout=1,
            follow_redirects=True,
            max_redirects=1,
        )

    assert len(requester.calls) == 1
    assert budget.total == 1


def test_p4_1i45_metadata_redirect_regression_has_zero_unauthorized_dispatches() -> (
    None
):
    root = f"{ORIGIN}/openapi.json"
    policy = _policy(root)
    requester = RecordingRequester(
        [
            _response(
                root,
                status=302,
                location="/openapi.json/%2e%2e/outside",
            )
        ]
    )
    client = _client(policy, requester)

    with scope_guard.assessment_policy_scope(policy):
        result = api_metadata_discovery(
            root,
            max_requests=2,
            timeout_seconds=1,
            http_client=client,
            assessment_policy=policy,
        )

    assert len(requester.calls) == 1
    assert result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert all("outside" not in call[1] for call in requester.calls)


def test_metadata_rejects_broader_supplied_client_policy_before_dispatch() -> None:
    narrow = _policy(ORIGIN)
    broader = _policy(ORIGIN).model_copy(
        update={
            "allowed_assets": [
                ScopeAsset(
                    kind="url_prefix",
                    value=ORIGIN,
                    schemes=["https"],
                    ports=[443],
                ),
                ScopeAsset(
                    kind="url_prefix",
                    value="https://outside.example.test",
                    schemes=["https"],
                    ports=[443],
                ),
            ]
        }
    )
    requester = RecordingRequester(
        [
            _response(
                f"{ORIGIN}/openapi.json",
                status=302,
                location="https://outside.example.test/spec",
            )
        ]
    )

    with scope_guard.assessment_policy_scope(narrow):
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=2,
            timeout_seconds=1,
            http_client=_client(broader, requester),
            assessment_policy=narrow,
        )

    assert result["success"] is False
    assert "different assessment policy" in result["error"]
    assert requester.calls == []


def test_metadata_rejects_distinct_same_scope_client_policy_before_dispatch() -> None:
    authority = _policy(ORIGIN)
    distinct_policy = _policy(ORIGIN)
    requester = RecordingRequester([])

    with scope_guard.assessment_policy_scope(authority):
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=1,
            timeout_seconds=1,
            http_client=_client(distinct_policy, requester),
            assessment_policy=authority,
        )

    assert result["success"] is False
    assert "different assessment policy" in result["error"]
    assert requester.calls == []


def test_metadata_rejects_scope_prevalidated_client_before_dispatch() -> None:
    authority = _policy(ORIGIN)
    requester = RecordingRequester([])
    prevalidated_client = ScopedHTTPClient(
        policy=authority,
        budget=RequestBudget(20, per_host_limit=20),
        requester=requester,
        scope_prevalidated=True,
    )

    with scope_guard.assessment_policy_scope(authority):
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=1,
            timeout_seconds=1,
            http_client=prevalidated_client,
            assessment_policy=authority,
        )

    assert result["success"] is False
    assert "prevalidated HTTP client" in result["error"]
    assert requester.calls == []


@pytest.mark.parametrize(
    "location",
    [
        "https://outside.example.test/spec",
        "https://sibling.scope.example.test/openapi.json",
        f"{ORIGIN}/openapi.json-outside",
        "https://scope.example.test:444/openapi.json",
        f"{ORIGIN}/openapi.json/%2e%2e/outside",
    ],
)
def test_metadata_redirect_hop_uses_original_policy_before_dispatch(
    location: str,
) -> None:
    root = f"{ORIGIN}/openapi.json"
    authority = _policy(root)
    requester = RecordingRequester([_response(root, status=302, location=location)])

    with scope_guard.assessment_policy_scope(authority):
        result = api_metadata_discovery(
            root,
            max_requests=2,
            timeout_seconds=1,
            http_client=_client(authority, requester),
            assessment_policy=authority,
        )

    assert result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert len(requester.calls) == 1


def test_metadata_multi_hop_redirects_reuse_original_policy_and_budget() -> None:
    authority = _policy(ORIGIN)
    requester = RecordingRequester(
        [
            _response(f"{ORIGIN}/openapi.json", status=302, location="/spec/one"),
            _response(f"{ORIGIN}/spec/one", status=302, location="../spec/two"),
            _response(f"{ORIGIN}/spec/two"),
        ]
    )

    with scope_guard.assessment_policy_scope(authority):
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=3,
            timeout_seconds=1,
            http_client=_client(authority, requester),
            assessment_policy=authority,
        )

    assert result["metadata_requests"][0]["status"] == "completed"
    assert result["network_request_count"] == 3
    assert [call[1] for call in requester.calls] == [
        f"{ORIGIN}/openapi.json",
        f"{ORIGIN}/spec/one",
        f"{ORIGIN}/spec/two",
    ]


def test_metadata_redirect_after_lease_revocation_never_dispatches() -> None:
    authority = _policy(ORIGIN)
    transfer = None

    def revoke_after_first_dispatch(
        method: str,
        url: str,
        kwargs: dict[str, Any],
        position: int,
    ) -> requests.Response:
        del method, kwargs
        if position == 1:
            assert transfer is not None
            assert transfer._lease.revoke() is True
            return _response(url, status=302, location="/after-revocation")
        pytest.fail("redirect dispatched after its lease was revoked")

    requester = RecordingRequester(revoke_after_first_dispatch)
    with scope_guard.assessment_policy_scope(authority):
        transfer = scope_guard.capture_assessment_policy_scope(authority)
        assert transfer is not None
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=2,
            timeout_seconds=1,
            http_client=_client(authority, requester),
            assessment_policy=authority,
        )

    assert result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert len(requester.calls) == 1


def test_metadata_redirect_depth_and_loop_are_bounded() -> None:
    authority = _policy(ORIGIN)
    loop_requester = RecordingRequester(
        [
            _response(
                f"{ORIGIN}/openapi.json",
                status=302,
                location=f"{ORIGIN}/openapi.json",
            )
        ]
    )
    with scope_guard.assessment_policy_scope(authority):
        loop_result = api_metadata_discovery(
            ORIGIN,
            max_requests=1,
            timeout_seconds=1,
            http_client=_client(authority, loop_requester),
            assessment_policy=authority,
        )
    assert loop_result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert len(loop_requester.calls) == 1

    depth_requester = RecordingRequester(
        lambda method, url, kwargs, position: _response(
            url, status=302, location=f"{ORIGIN}/hop-{position}"
        )
    )
    with scope_guard.assessment_policy_scope(authority):
        depth_result = api_metadata_discovery(
            ORIGIN,
            max_requests=2,
            timeout_seconds=1,
            http_client=_client(authority, depth_requester),
            assessment_policy=authority,
        )
    assert depth_result["metadata_requests"][0]["status"] == "blocked_redirect"
    assert len(depth_requester.calls) == 2


def test_original_authorized_metadata_request_still_succeeds() -> None:
    authority = _policy(ORIGIN)
    requester = RecordingRequester([_response(f"{ORIGIN}/openapi.json")])

    with scope_guard.assessment_policy_scope(authority):
        result = api_metadata_discovery(
            ORIGIN,
            max_requests=1,
            timeout_seconds=1,
            http_client=_client(authority, requester),
            assessment_policy=authority,
        )

    assert result["success"] is True
    assert result["metadata_requests"][0]["status"] == "completed"
    assert len(requester.calls) == 1


def test_scope_prevalidated_flag_never_authorizes_redirect_destination(
    monkeypatch,
) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", ROOT)
    requester = RecordingRequester(
        [_response(ROOT, status=302, location="https://outside.example.test/spec")]
    )
    prevalidated_client = ScopedHTTPClient(
        requester=requester,
        scope_prevalidated=True,
    )

    with pytest.raises(UnsafeRedirectError):
        prevalidated_client.request(
            "GET",
            ROOT,
            purpose="discovery",
            timeout=1,
            max_redirects=1,
            follow_redirects=True,
        )

    assert len(requester.calls) == 1


def test_object_discovery_resolves_safe_relative_links_against_current_page() -> None:
    requester = RecordingRequester(
        [
            _response(
                ROOT + "/index",
                body=b'<a href="items/1">item</a>',
                content_type="text/html",
            ),
            _response(ROOT + "/items/1"),
        ]
    )
    policy = _policy()
    client = _client(policy, requester)

    with scope_guard.assessment_policy_scope(policy):
        result = crawl_and_discover_ids(
            ROOT + "/index",
            max_depth=1,
            max_pages=2,
            delay_seconds=0,
            timeout_seconds=1,
            http_client=client,
            assessment_policy=policy,
        )

    assert result["success"]
    assert [call[1] for call in requester.calls] == [
        ROOT + "/index",
        ROOT + "/items/1",
    ]


@pytest.mark.parametrize(
    "link",
    [
        "/app/%2e%2e/outside",
        "/app/%252e%252e/outside",
        "/app/%2F..%2Foutside",
        "/app/%5c..%5coutside",
    ],
)
def test_p4_1i45_object_link_regression_has_zero_unauthorized_dispatches(
    link: str,
) -> None:
    requester = RecordingRequester(
        [
            _response(
                ROOT,
                body=f'<a href="{link}">outside</a>'.encode(),
                content_type="text/html",
            )
        ]
    )
    policy = _policy()
    client = _client(policy, requester)

    with scope_guard.assessment_policy_scope(policy):
        result = crawl_and_discover_ids(
            ROOT,
            max_depth=1,
            max_pages=2,
            delay_seconds=0,
            timeout_seconds=1,
            http_client=client,
            assessment_policy=policy,
        )

    assert result["success"]
    assert len(requester.calls) == 1
    assert all("outside" not in call[1] for call in requester.calls)


def test_canonicalization_and_scopes_do_not_mutate_process_environment(
    monkeypatch,
) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", ROOT)
    before = dict(os.environ)

    assert canonicalize_transport_url(ROOT).url == ROOT
    assert scope_guard.enforce_scope(ROOT)["allowed"]
    with pytest.raises(URLCanonicalizationError):
        canonicalize_transport_url(ROOT + "/%2e%2e/outside")

    assert dict(os.environ) == before


def test_legacy_www_host_does_not_authorize_apex_or_siblings(monkeypatch) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "www.scope.example.test")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")

    assert scope_guard.enforce_scope("https://www.scope.example.test/app")["allowed"]
    assert not scope_guard.enforce_scope("https://scope.example.test/app")["allowed"]
    assert not scope_guard.enforce_scope("https://sibling.scope.example.test/app")[
        "allowed"
    ]


def test_legacy_apex_host_does_not_authorize_www_or_siblings(monkeypatch) -> None:
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "scope.example.test")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")

    assert scope_guard.enforce_scope("https://scope.example.test/app")["allowed"]
    assert not scope_guard.enforce_scope("https://www.scope.example.test/app")[
        "allowed"
    ]
    assert not scope_guard.enforce_scope("https://sibling.scope.example.test/app")[
        "allowed"
    ]


def test_legacy_explicit_apex_and_www_hosts_are_independently_allowed(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        scope_guard,
        "PENTEST_ALLOWLIST",
        "scope.example.test,www.scope.example.test",
    )
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")

    assert scope_guard.enforce_scope("https://scope.example.test/app")["allowed"]
    assert scope_guard.enforce_scope("https://www.scope.example.test/app")["allowed"]
