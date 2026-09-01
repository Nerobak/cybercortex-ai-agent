from __future__ import annotations

import pytest

import tools.scope_guard as scope_guard


@pytest.fixture
def authorized_domain(monkeypatch):
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "nerminzlatanovic.com")
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWED_URL_PREFIXES", "")


@pytest.mark.parametrize(
    "url",
    [
        "https://nerminzlatanovic.com",
        "https://nerminzlatanovic.com/",
        "https://nerminzlatanovic.com/about",
        "https://nerminzlatanovic.com/blog/test",
    ],
)
def test_domain_allowlist_authorizes_all_exact_host_paths(authorized_domain, url):
    assert scope_guard.enforce_scope(url)["allowed"] is True


@pytest.mark.parametrize(
    "url",
    [
        "https://docs.aws.amazon.com/some/path",
        "https://github.com/nerminzlatanovic",
        "https://nerminzlatanovic.com.attacker.example/about",
    ],
)
def test_domain_allowlist_blocks_external_and_deceptive_hosts(authorized_domain, url):
    assert scope_guard.enforce_scope(url)["allowed"] is False


def test_root_url_prefix_authorizes_all_paths_on_exact_origin(monkeypatch):
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(
        scope_guard,
        "PENTEST_ALLOWED_URL_PREFIXES",
        "https://nerminzlatanovic.com",
    )
    assert scope_guard.is_target_allowed("https://nerminzlatanovic.com/about")
    assert scope_guard.is_target_allowed(
        "https://nerminzlatanovic.com/sitemap-index.xml"
    )
    assert not scope_guard.is_target_allowed(
        "https://nerminzlatanovic.com.attacker.example/about"
    )


def test_explicit_non_root_prefix_remains_restrictive(monkeypatch):
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "nerminzlatanovic.com")
    monkeypatch.setattr(
        scope_guard,
        "PENTEST_ALLOWED_URL_PREFIXES",
        "https://nerminzlatanovic.com/blog",
    )
    assert scope_guard.is_target_allowed("https://nerminzlatanovic.com/blog")
    assert scope_guard.is_target_allowed("https://nerminzlatanovic.com/blog/test")
    assert not scope_guard.is_target_allowed("https://nerminzlatanovic.com/about")
    assert not scope_guard.is_target_allowed("https://nerminzlatanovic.com/blogger")


def test_root_prefix_does_not_broaden_scheme_or_port(monkeypatch):
    monkeypatch.setattr(scope_guard, "PENTEST_ALLOWLIST", "")
    monkeypatch.setattr(
        scope_guard,
        "PENTEST_ALLOWED_URL_PREFIXES",
        "https://nerminzlatanovic.com",
    )
    assert not scope_guard.is_target_allowed("http://nerminzlatanovic.com/about")
    assert not scope_guard.is_target_allowed("https://nerminzlatanovic.com:8443/about")
