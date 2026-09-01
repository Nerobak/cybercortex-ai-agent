from pathlib import Path

import pytest

from agent_core.result_normalizer import redact
from tools.ai_report_writer import ai_report_writer, build_canonical_report_facts
from tools.api_object_discovery import classify_path_segment, crawl_and_discover_ids
from tools.endpoint_analyzer import endpoint_analyzer


def _package(**overrides):
    package = {
        "observed_surface": {
            "objects": [],
            "graphql": {
                "endpoints_observed": 0,
                "confirmed_endpoints": 0,
                "introspection_status": "not_tested",
                "operations_observed": 0,
                "manual_authorization_plans": 0,
            },
            "jwt": {"tokens_observed": 0},
            "business_logic": {"workflow_candidates": 0},
            "upload": {"surface_observed": False, "observations": 0},
        },
        "observations": [],
        "candidate_findings": [],
        "verified_findings": [],
        "manual_verification_queue": [],
        "tool_results": {},
        "execution_summary": {},
        "coverage": {"coverage_percentage": 100},
        "evidence_files": [],
    }
    package.update(overrides)
    return package


def _write_report(tmp_path: Path, monkeypatch, package: dict, model_text: str):
    monkeypatch.setattr(
        "tools.ai_report_writer.ask_agent", lambda *args, **kwargs: model_text
    )
    result = ai_report_writer("https://example.test", package, output_dir=str(tmp_path))
    report = Path(result["report_file"]).read_text(encoding="utf-8")
    return result, report


@pytest.fixture
def zero_jwt_package():
    return _package(
        tool_results={
            "jwt_discovery": {
                "status": "completed",
                "success": True,
                "output": {"token_count": 0, "tokens_observed": []},
            }
        }
    )


def test_model_cannot_change_zero_jwt_count(tmp_path, monkeypatch, zero_jwt_package):
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        zero_jwt_package,
        "# Report\n\n5 tokens observed.",
    )
    assert result["report_mode"] == "deterministic_fallback"
    assert "5 tokens observed" not in report
    assert (
        "JWT discovery completed. No JWTs were observed in the collected evidence."
        in report
    )


def test_public_contact_is_demoted_to_observation(tmp_path, monkeypatch):
    contact = {
        "title": "Sensitive contact disclosure",
        "category": "public_contact",
        "severity": "medium",
        "confidence": "high",
        "status": "needs_manual_verification",
        "source_tool": "js_secret_scanner",
    }
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        _package(
            candidate_findings=[contact],
            manual_verification_queue=[contact],
            tool_results={
                "js_secret_scanner": {
                    "status": "completed",
                    "output": {"findings": [{"match_kind": "public_contact"}]},
                }
            },
        ),
        "## Candidate Findings Requiring Manual Verification\n\n"
        "### Public contact information\n\nPII exposure requires verification.",
    )
    assert result["report_mode"] == "deterministic_fallback"
    candidate_section = report.split(
        "## Candidate Findings Requiring Manual Verification", 1
    )[1].split("## Informational and Defense-in-Depth Observations", 1)[0]
    assert "Public contact" not in candidate_section
    assert (
        "Public contact information was observed in JavaScript. No credential-like secret was identified."
        in report
    )
    assert "PII exposure" not in report


def test_timed_out_nuclei_with_zero_findings_cannot_add_headers(tmp_path, monkeypatch):
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        _package(
            tool_results={
                "nuclei_scan": {
                    "status": "timed_out",
                    "success": False,
                    "error": "Nuclei scan timed out.",
                    "output": {
                        "status": "timed_out",
                        "finding_count": 0,
                        "findings": [],
                    },
                }
            }
        ),
        "# Report\n\nMissing COOP, Cross-Origin-Embedder-Policy, "
        "and Expect-CT were found by Nuclei.",
    )
    assert result["report_mode"] == "deterministic_fallback"
    assert "COOP" not in report
    assert "Cross-Origin-Opener-Policy" not in report
    assert "Cross-Origin-Embedder-Policy" not in report
    assert "Expect-CT" not in report
    assert "nuclei_scan: timed_out" in report


@pytest.mark.parametrize(
    "slug",
    [
        "iphone-17-eift-mvt",
        "cybercortex-ai-agent",
        "dfir-linux-memory",
        "trace-labs-osint-search-party-ctf",
    ],
)
def test_human_readable_project_slugs_are_not_identifiers(slug):
    assert classify_path_segment(slug, parent="projects") == "resource_slug"


def test_project_slug_does_not_create_authorization_recommendation(monkeypatch):
    monkeypatch.setattr(
        "tools.api_object_discovery.enforce_scope", lambda url: {"allowed": True}
    )
    result = crawl_and_discover_ids(
        "https://example.test/projects/iphone-17-eift-mvt",
        normalized_url_evidence={
            "all_urls": ["https://example.test/projects/iphone-17-eift-mvt"]
        },
        allow_network_crawl=False,
    )
    assert result["classification_summary"]["resource_slug"] == 1
    assert result["classification_summary"]["opaque_identifier"] == 0
    assert result["candidate_authorization_tests"] == []
    endpoint = endpoint_analyzer(
        ["https://example.test/projects/iphone-17-eift-mvt"], "example.test"
    )["interesting_endpoints"][0]
    assert endpoint["observed_identifiers"] == []
    assert not any(
        "authorization" in check.lower()
        for check in endpoint["suggested_manual_checks"]
    )


def test_static_asset_filename_is_not_redacted_as_jwt():
    filename = "_slug_.CJX3L6sa.css"
    assert redact(filename) == filename
    assert (
        redact("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature")
        == "[REDACTED JWT]"
    )


def test_skipped_javascript_scan_is_not_reported_as_negative(tmp_path, monkeypatch):
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        _package(
            tool_results={
                "js_secret_scanner": {
                    "status": "skipped",
                    "success": False,
                    "error": "No authorized JavaScript URLs were available.",
                    "output": {},
                }
            }
        ),
        "# Report\n\nNo exposed JavaScript secrets were detected.",
    )
    assert result["report_mode"] == "deterministic_fallback"
    assert "No exposed JavaScript secrets were detected" not in report
    assert (
        "JavaScript secret scanning was not performed because no authorized JavaScript URLs were available."
        in report
    )


def test_manual_business_logic_recommendation_is_removed_without_workflow_evidence(
    tmp_path, monkeypatch
):
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        _package(),
        "# Report\n\n## Prioritized Next Manual Tests\n\n"
        "- Perform business-logic testing.\n\n## Limitations\n\nNone.",
    )
    assert result["report_mode"] == "deepseek"
    assert "business-logic testing" not in report
    assert "No evidence-supported manual test was queued." in report


@pytest.mark.parametrize(
    "present,model_claim,expected",
    [(True, "missing", "present"), (False, "present", "not present")],
)
def test_security_header_checker_is_authoritative(
    tmp_path, monkeypatch, present, model_claim, expected
):
    result, report = _write_report(
        tmp_path,
        monkeypatch,
        _package(
            tool_results={
                "security_headers_checker": {
                    "status": "completed",
                    "output": {
                        "headers_checked": {
                            "Content-Security-Policy": {"present": present}
                        }
                    },
                }
            }
        ),
        f"# Report\n\nContent-Security-Policy is {model_claim}.",
    )
    assert result["report_mode"] == "deterministic_fallback"
    assert f"Content-Security-Policy: {expected}" in report


def test_authoritative_header_fact_filters_conflicting_scanner_item():
    facts = build_canonical_report_facts(
        _package(
            observations=[
                {
                    "title": "Missing Content-Security-Policy",
                    "source_tool": "nuclei_scan",
                    "category": "scanner_observation",
                    "severity": "informational",
                    "status": "observation",
                }
            ],
            tool_results={
                "security_headers_checker": {
                    "status": "completed",
                    "output": {
                        "headers_checked": {
                            "Content-Security-Policy": {"present": True}
                        }
                    },
                },
                "nuclei_scan": {
                    "status": "completed",
                    "output": {
                        "finding_count": 1,
                        "findings": [{"name": "Missing Content-Security-Policy"}],
                    },
                },
            },
        )
    )
    assert facts["security_headers"]["Content-Security-Policy"]["present"] is True
    assert facts["observations"] == ()


def test_canonical_report_facts_are_immutable(zero_jwt_package):
    facts = build_canonical_report_facts(zero_jwt_package)
    assert facts["counts"]["jwt_tokens"] == 0
    with pytest.raises(TypeError):
        facts["counts"]["jwt_tokens"] = 5
