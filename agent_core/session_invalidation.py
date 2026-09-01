"""Typed contracts for one bounded session-invalidation workflow."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urljoin

from pydantic import field_validator

from agent_core.agent_models import Hypothesis, StrictModel, VerificationPlan


class SessionInvalidationSurface(StrictModel):
    boundary_type: Literal[
        "session_creation",
        "authenticated_resource",
        "session_termination",
    ]
    method: str
    url: str

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("method must be a conventional HTTP method token")
        return method


class SessionInvalidationWorkflow(StrictModel):
    session_creation: SessionInvalidationSurface
    authenticated_resource: SessionInvalidationSurface
    session_termination: SessionInvalidationSurface

    @classmethod
    def from_hypothesis(cls, hypothesis: Hypothesis) -> SessionInvalidationWorkflow:
        """Resolve exact workflow surfaces from semantic hypothesis metadata."""
        if hypothesis.category != "session_invalidation":
            raise ValueError("A session-invalidation hypothesis is required.")
        related = hypothesis.metadata.get("related_surfaces")
        if not isinstance(related, list) or len(related) != 3:
            raise ValueError(
                "Session invalidation requires exactly three semantic workflow surfaces."
            )
        by_type: dict[str, SessionInvalidationSurface] = {}
        for raw_surface in related:
            if not isinstance(raw_surface, dict):
                raise ValueError("Session-invalidation workflow metadata is invalid.")
            boundary_type = str(raw_surface.get("boundary_type") or "")
            if boundary_type in by_type:
                raise ValueError(
                    "Session-invalidation workflow surfaces are ambiguous."
                )
            path = raw_surface.get("path")
            method = raw_surface.get("method")
            if not isinstance(path, str) or not path.strip() or not method:
                raise ValueError(
                    "Session-invalidation workflow surfaces require a path and method."
                )
            by_type[boundary_type] = SessionInvalidationSurface(
                boundary_type=boundary_type,
                method=str(method),
                url=urljoin(
                    hypothesis.target.rstrip("/") + "/",
                    path.strip().lstrip("/"),
                ),
            )
        required = {
            "session_creation",
            "authenticated_resource",
            "session_termination",
        }
        if set(by_type) != required:
            raise ValueError(
                "Session-invalidation workflow metadata is incomplete or ambiguous."
            )
        workflow = cls(
            session_creation=by_type["session_creation"],
            authenticated_resource=by_type["authenticated_resource"],
            session_termination=by_type["session_termination"],
        )
        if workflow.session_creation.method != "POST":
            raise ValueError("Session creation requires its typed POST surface.")
        if workflow.authenticated_resource.method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(
                "The authenticated-resource surface must use an allowed read-only method."
            )
        if workflow.session_termination.method not in {"POST", "DELETE"}:
            raise ValueError("The session-termination surface must use POST or DELETE.")
        return workflow

    def validate_plan(
        self, hypothesis: Hypothesis, plan: VerificationPlan
    ) -> tuple[list[dict[str, Any]] | None, list[str]]:
        """Validate one immutable creation/baseline/logout/replay action sequence."""
        actions = [
            request
            for step in plan.steps
            for request in (step.metadata.get("requests") or [])
            if isinstance(request, dict)
        ]
        expected = [
            (
                self.session_creation,
                "session_acquisition",
                "session_creation",
                False,
                None,
            ),
            (
                self.authenticated_resource,
                "verification",
                "authenticated_resource",
                False,
                None,
            ),
            (
                self.session_termination,
                "session_termination",
                "session_termination",
                False,
                "controlled_session_termination",
            ),
            (
                self.authenticated_resource,
                "verification",
                "authenticated_resource",
                True,
                None,
            ),
        ]
        if len(actions) != 4 or plan.hypothesis_id != hypothesis.hypothesis_id:
            return None, [
                "Session invalidation requires exactly four typed workflow actions."
            ]
        for action, (surface, purpose, role, replay, mutation_type) in zip(
            actions, expected, strict=True
        ):
            if (
                action.get("category") != "session_invalidation"
                or str(action.get("url") or "") != surface.url
                or str(action.get("method") or "").upper() != surface.method
                or action.get("purpose") != purpose
                or action.get("workflow_surface") != role
                or bool(action.get("replay")) is not replay
                or action.get("mutation_type") != mutation_type
            ):
                return None, [
                    "The planned request sequence does not exactly match the typed session-invalidation workflow."
                ]
        if (
            actions[1]["url"] != actions[3]["url"]
            or actions[1]["method"] != actions[3]["method"]
        ):
            return None, [
                "Session invalidation must replay the same authenticated resource."
            ]
        return actions, []
