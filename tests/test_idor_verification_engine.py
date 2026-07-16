from tools import idor_verification_engine as engine


RAW_REQUEST = """GET /api/users/1001 HTTP/1.1
Host: lab.local
Accept: application/json
Authorization: captured-secret
"""


def _allowed(target: str) -> dict:
    return {"allowed": True, "target": target}


def _response(status: int, body: dict) -> dict:
    return {
        "success": True,
        "response": {
            "status_code": status,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsed_ms": 1,
        },
    }


def test_batch_scan_deduplicates_and_orients_owner_baseline(monkeypatch):
    calls = []

    def replay(**kwargs):
        calls.append(kwargs)
        return {
            "success": True,
            "account_a": _response(
                200, {"email": "owner@example.test", "accountId": "b"}
            ),
            "account_b": _response(
                200, {"email": "owner@example.test", "accountId": "b"}
            ),
        }

    monkeypatch.setattr(engine, "enforce_scope", _allowed)
    monkeypatch.setattr(engine, "replay_authorization_contexts", replay)

    result = engine.scan_controlled_idor(
        raw_request=RAW_REQUEST,
        account_a_headers={"Authorization": "Bearer A"},
        account_b_headers={"Authorization": "Bearer B"},
        original_identifier="1001",
        comparison_identifiers=["2001", 2001, "2002", "1001", ""],
        account_b_owned_ids={"2001", "2002"},
        separate_accounts_confirmed=True,
        delay_seconds=0,
    )

    assert result["success"] is True
    assert result["summary"]["identifiers_tested"] == 2
    assert result["summary"]["verified_findings"] == 2
    assert [item["identifier"] for item in result["results"]] == ["2001", "2002"]
    assert all(item["owner_account"] == "B" for item in result["results"])
    assert all(item["candidate_account"] == "A" for item in result["results"])
    assert len(calls) == 2
    assert calls[0]["url"] == "https://lab.local/api/users/2001"
    assert "Authorization" not in calls[0]["common_headers"]


def test_batch_scan_rejects_more_than_25_identifiers():
    result = engine.scan_controlled_idor(
        raw_request=RAW_REQUEST,
        account_a_headers={"Authorization": "Bearer A"},
        account_b_headers={"Authorization": "Bearer B"},
        original_identifier="1001",
        comparison_identifiers=[str(value) for value in range(25, 51)],
    )

    assert result["success"] is False
    assert "maximum of 25" in result["error"]


def test_query_variants_preserve_other_parameters(monkeypatch):
    monkeypatch.setattr(engine, "enforce_scope", _allowed)
    result = engine.build_controlled_idor_variant(
        url="https://lab.local/api/users?active=true&userId=1001",
        original_identifier="1001",
        comparison_identifier="user/2001",
        location="query",
        query_field="userId",
    )

    assert result["success"] is True
    assert result["modified_url"] == (
        "https://lab.local/api/users?active=true&userId=user%2F2001"
    )


def test_unsafe_method_is_rejected_before_replay(monkeypatch):
    monkeypatch.setattr(engine, "enforce_scope", _allowed)
    raw_request = RAW_REQUEST.replace("GET ", "DELETE ", 1)
    result = engine.scan_controlled_idor(
        raw_request=raw_request,
        account_a_headers={"Authorization": "Bearer A"},
        account_b_headers={"Authorization": "Bearer B"},
        original_identifier="1001",
        comparison_identifiers=["2001"],
    )

    assert result["success"] is False
    assert "not supported" in result["error"]
