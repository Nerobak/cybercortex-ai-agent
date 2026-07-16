import os
import sys

from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import web_app

client = TestClient(web_app.app)


def test_dashboard_and_health_are_available():
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json()["status"] == "ok"


def test_scan_requires_authorization():
    response = client.post(
        "/api/scans",
        json={"target": "https://example.com", "authorization_confirmed": False},
    )
    assert response.status_code == 400


def test_scan_rejects_out_of_scope_target(monkeypatch):
    monkeypatch.setattr(
        web_app, "enforce_scope", lambda target: {"allowed": False, "error": "outside"}
    )
    response = client.post(
        "/api/scans",
        json={"target": "https://outside.example", "authorization_confirmed": True},
    )
    assert response.status_code == 403


def test_completed_scan_and_report(monkeypatch):
    monkeypatch.setattr(web_app, "enforce_scope", lambda target: {"allowed": True})
    monkeypatch.setattr(
        web_app, "dns_lookup", lambda host: {"success": True, "host": host}
    )
    monkeypatch.setattr(
        web_app, "http_probe", lambda target: {"success": True, "status_code": 200}
    )
    monkeypatch.setattr(
        web_app,
        "security_headers_checker",
        lambda target: {
            "success": True,
            "headers_checked": {
                "Content-Security-Policy": {
                    "present": False,
                    "description": "Reduces XSS risk",
                }
            },
        },
    )
    monkeypatch.setattr(
        web_app,
        "tech_fingerprint",
        lambda target: {"success": True, "technologies": []},
    )

    created = client.post(
        "/api/scans",
        json={"target": "https://example.com", "authorization_confirmed": True},
    )
    assert created.status_code == 202
    job_id = created.json()["id"]
    completed = client.get(f"/api/scans/{job_id}").json()
    assert completed["status"] == "completed"
    assert completed["findings"][0]["title"] == "Missing Content-Security-Policy"
    report = client.get(f"/api/scans/{job_id}/report")
    assert report.status_code == 200
    assert "Missing Content-Security-Policy" in report.text
