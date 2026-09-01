"""In-memory vulnerable/secure application for deterministic agent evals."""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from agent_core.verification_gate import VerificationEvidence, grade_verification
from tools.authz_differential_tester import analyze_authorization_difference


@dataclass
class ReplayResponse:
    status_code: int
    payload: dict[str, Any]
    url: str

    def __post_init__(self) -> None:
        self.content = json.dumps(self.payload, sort_keys=True).encode()
        self.headers = {"Content-Type": "application/json"}
        self.encoding = "utf-8"
        self.is_redirect = False
        self.is_permanent_redirect = False
        self.elapsed = SimpleNamespace(total_seconds=lambda: 0.001)
        self.request = SimpleNamespace(
            url=self.url,
            headers={},
        )

    def json(self) -> dict[str, Any]:
        return self.payload


class ReplayApplication:
    """Tiny controlled app with switchable authorization and assignment flaws."""

    def __init__(
        self,
        *,
        bola_vulnerable: bool = False,
        mass_assignment_vulnerable: bool = False,
    ) -> None:
        self.bola_vulnerable = bola_vulnerable
        self.mass_assignment_vulnerable = mass_assignment_vulnerable
        self.objects = {
            "1": {"id": "1", "owner": "account-a", "email": "a@example.test"},
            "2": {"id": "2", "owner": "account-b", "email": "b@example.test"},
        }
        self.profiles = {
            "account-a": {"role": "member", "display_name": "Account A"},
            "account-b": {"role": "member", "display_name": "Account B"},
        }

    @staticmethod
    def _identity(headers: dict[str, str] | None) -> str | None:
        value = (headers or {}).get("Authorization", "")
        return value.removeprefix("Bearer ") or None

    def request(self, method: str, url: str, **kwargs: Any) -> ReplayResponse:
        method = method.upper()
        path = urlparse(url).path
        identity = self._identity(kwargs.get("headers"))
        if path.startswith("/api/objects/") and method == "GET":
            object_id = path.rsplit("/", 1)[-1]
            obj = self.objects.get(object_id)
            if obj is None:
                return ReplayResponse(404, {"error": "not_found"}, url)
            if not self.bola_vulnerable and identity != obj["owner"]:
                return ReplayResponse(403, {"error": "forbidden"}, url)
            return ReplayResponse(200, obj, url)
        if path == "/api/profile" and method == "PATCH":
            if identity not in self.profiles:
                return ReplayResponse(401, {"error": "unauthorized"}, url)
            raw = kwargs.get("data") or b"{}"
            body = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            allowed = {"display_name"}
            updates = (
                body
                if self.mass_assignment_vulnerable
                else {key: value for key, value in body.items() if key in allowed}
            )
            self.profiles[identity].update(updates)
            return ReplayResponse(200, self.profiles[identity], url)
        return ReplayResponse(404, {"error": "not_found"}, url)


def _stored_response(response: ReplayResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "headers": response.headers,
        "body": response.payload,
    }


def evaluate_replay_case(case) -> dict[str, Any]:
    scenario = str(case.input.get("scenario") or "")
    if scenario not in {"bola_vulnerable", "bola_secure"}:
        return {
            "status": "not_applicable",
            "category": case.expected_category,
            "requests_used": 0,
            "scope_violations": 0,
            "unauthorized_state_changes": 0,
        }
    app = ReplayApplication(bola_vulnerable=scenario == "bola_vulnerable")
    owner_identity = "account-a"
    non_owner_identity = "account-b"
    url = "https://authorized.example/api/objects/1"
    diffs = []
    analysis = None
    for _ in range(2):
        owner = app.request(
            "GET", url, headers={"Authorization": f"Bearer {owner_identity}"}
        )
        non_owner = app.request(
            "GET", url, headers={"Authorization": f"Bearer {non_owner_identity}"}
        )
        analysis = analyze_authorization_difference(
            _stored_response(owner),
            _stored_response(non_owner),
            url,
            object_identifier="1",
            ownership_confirmed=True,
            separate_accounts_confirmed=True,
        )
        diffs.append(analysis["response_diff"])
    unauthorized_success = (analysis or {}).get("finding", {}).get("severity") in {
        "medium",
        "high",
    }
    grade = grade_verification(
        "bola",
        VerificationEvidence(
            repetitions=diffs if unauthorized_success else [],
            owner_identity=owner_identity,
            non_owner_identity=non_owner_identity,
            object_identifier="1",
            ownership_confirmed=True,
            separate_accounts_confirmed=True,
        ),
    )
    return {
        "status": grade["status"] if unauthorized_success else "observation",
        "verified": bool(grade["verified"] and unauthorized_success),
        "category": "broken_access_control",
        "reproduced": bool(grade["verified"] and unauthorized_success),
        "requests_used": 4,
        "scope_violations": 0,
        "unauthorized_state_changes": 0,
        "evidence_grade": grade,
    }
