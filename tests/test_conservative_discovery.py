import json

from agent_core.result_normalizer import build_evidence_package
from tools.api_object_discovery import _extract_path_identifiers, crawl_and_discover_ids
from tools.endpoint_analyzer import endpoint_analyzer
from tools.js_secret_scanner import js_secret_scanner


def test_route_words_are_not_object_identifiers():
    assert _extract_path_identifiers("https://example.test/exchange") == []
    assert (
        _extract_path_identifiers("https://example.test/exchange/announcements") == []
    )


def test_contextual_and_uuid_path_identifiers():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert (
        _extract_path_identifiers("https://example.test/api/users/1001")[0]["field"]
        == "user"
    )
    assert (
        _extract_path_identifiers("https://example.test/api/projects/project-123")[0][
            "value"
        ]
        == "project-123"
    )
    assert (
        _extract_path_identifiers(f"https://example.test/api/items/{uuid}")[0][
            "identifier_type"
        ]
        == "uuid"
    )
    assert (
        _extract_path_identifiers("https://example.test/assets/app.a8f92c1d.js") == []
    )


def test_katana_urls_are_analyzed_offline(monkeypatch):
    monkeypatch.setattr(
        "tools.api_object_discovery.enforce_scope", lambda url: {"allowed": True}
    )
    result = crawl_and_discover_ids(
        "https://example.test",
        normalized_url_evidence={"all_urls": ["https://example.test/api/users/1001"]},
        allow_network_crawl=False,
    )
    assert result["urls_received_from_katana"] == 1
    assert result["urls_analyzed_offline"] == 1
    assert result["extra_pages_requested"] == 0
    assert result["identifiers_discovered"] == 1


def test_route_interest_is_only_an_observation():
    result = endpoint_analyzer(["https://example.test/api/admin/users"], "example.test")
    finding = result["interesting_endpoints"][0]
    assert "API-related route observed" in finding["route_category"]
    assert finding["observed_identifiers"] == []
    assert finding["vulnerability_status"] == "observation"
    assert not any(
        "authorization" in reason.lower() for reason in finding["review_reasons"]
    )


class _Response:
    text = """const apiKey; const x={apiKey:""}; apiKey:"example";
apiKey:"sk_test_a8F4kL9pQ2wX7mN6zR3t"; contact@company.com"""


def test_secret_values_are_credible_redacted_and_contacts_informational(monkeypatch):
    monkeypatch.setattr(
        "tools.js_secret_scanner.scoped_get", lambda *a, **k: (_Response(), [])
    )
    result = js_secret_scanner(["https://example.test/app.js"], "example.test")
    assert result["findings_count"] == 2
    kinds = {item["match_kind"] for item in result["findings"]}
    assert kinds == {"candidate_value", "public_contact"}
    serialized = json.dumps(result)
    assert "sk_test_a8F4kL9pQ2wX7mN6zR3t" not in serialized
    assert "contact@company.com" not in serialized


def test_three_nuclei_info_observations_survive_evidence_normalization():
    findings = [
        {
            "name": f"info-{i}",
            "severity": "info",
            "matched_at": f"https://example.test/{i}",
        }
        for i in range(3)
    ]
    results = {
        "nuclei_scan": {
            "status": "completed",
            "success": True,
            "output": {
                "target": "https://example.test",
                "status": "completed",
                "finding_count": 3,
                "severity_summary": {"info": 3},
                "findings": findings,
                "evidence_file": "nuclei.jsonl",
            },
        }
    }
    package = build_evidence_package(
        "https://example.test", "baseline", results, "start", "end"
    )
    assert (
        len(
            [
                item
                for item in package["observations"]
                if item["source_tool"] == "nuclei_scan"
            ]
        )
        == 3
    )
    assert package["tool_results"]["nuclei_scan"]["output"]["finding_count"] == 3
