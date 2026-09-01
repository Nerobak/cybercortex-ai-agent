"""One typed Phase 2 verification runtime shared by every public entry path."""

from __future__ import annotations

from copy import deepcopy
from http.cookies import CookieError, SimpleCookie
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, StrictStr, ValidationError

from agent_core.agent_models import Hypothesis, StrictModel, VerificationPlan
from agent_core.controlled_context import ControlledContext
from agent_core.credential_vault import CredentialVault
from agent_core.phase2_policy import DeterministicPolicyGate, Phase2PolicyContext
from agent_core.phase2_result_status import (
    INVALID_INPUT_REASON,
    PUBLIC_RESULT_STATUSES,
    normalize_typed_result,
)
from agent_core.phase2_store import Phase2RunStore
from agent_core.policy import AssessmentPolicy
from agent_core.rate_limit_enforcement import stage_rate_limit_input_secret
from agent_core.recovery_state_enforcement import (
    pending_recovery_result,
    stage_recovery_input_secrets,
)
from agent_core.request_budget import RequestBudget, RequestDelta
from agent_core.result_normalizer import public_result
from agent_core.result_provenance import (
    RESULT_SCHEMA_VERSION,
    target_identity,
)
from agent_core.verification_capabilities import (
    CapabilityState,
    get_verification_capability,
    plan_only_command_metadata,
    resolve_verification_executor,
    typed_producer_provenance,
    validate_typed_producer_provenance,
)
from config import ADAPTIVE_MAX_REQUESTS
from tools.safe_http import ScopedHTTPClient

TargetClass = Literal["external", "local_range", "dedicated_lab"]

MAX_VERIFICATION_INPUT_KEYS = 200
MAX_VERIFICATION_INPUT_KEY_LENGTH = 200
VerificationInputKey = Annotated[
    StrictStr,
    Field(min_length=1, max_length=MAX_VERIFICATION_INPUT_KEY_LENGTH),
]
VerificationCategoryInput = Annotated[
    dict[VerificationInputKey, Any],
    Field(max_length=MAX_VERIFICATION_INPUT_KEYS),
]


class VerificationInputValidationError(ValueError):
    """Expected, secret-safe verification input envelope failure."""


class VerificationInputEnvelope(StrictModel):
    """Strict defaults/per-hypothesis envelope; direct category syntax is separate."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        strict=True,
    )

    defaults: VerificationCategoryInput = Field(default_factory=dict)
    hypotheses: dict[VerificationInputKey, VerificationCategoryInput] = Field(
        default_factory=dict,
        max_length=MAX_VERIFICATION_INPUT_KEYS,
    )


SAFE_RESPONSE_HEADERS = (
    "Content-Type",
    "Retry-After",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "RateLimit-Policy",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
)

_VOLATILE_RESULT_FIELDS = {
    "created_at",
    "request_budget",
    "result_hash",
    "result_id",
    "run_id",
    "timestamp",
    "updated_at",
}


def canonical_target_class(
    *, lab: bool = False, dedicated_lab: bool = False
) -> TargetClass:
    """Normalize public CLI aliases to the one policy target-class contract."""

    if type(lab) is not bool or type(dedicated_lab) is not bool:
        raise ValueError("Lab target flags must be strict booleans.")
    if lab and dedicated_lab:
        raise ValueError("Select either local lab or dedicated lab, not both.")
    if lab:
        return "local_range"
    if dedicated_lab:
        return "dedicated_lab"
    return "external"


def build_verification_policy_context(
    controlled: ControlledContext,
    *,
    target_class: TargetClass,
    mode: Literal["observe", "plan", "verify"] = "verify",
) -> Phase2PolicyContext:
    """Build the identical deterministic gate context for both entry paths."""

    accounts = [item.account_id for item in controlled.accounts if item.controlled]
    objects = [item.object_id for item in controlled.objects if item.test_owned]
    acquisition_owners = list(
        dict.fromkeys(item.owner_account_id for item in controlled.object_acquisition)
    )
    acquisition = controlled.session_acquisition
    return Phase2PolicyContext(
        mode=mode,
        target_class=target_class,
        controlled_account_ids=accounts,
        controlled_object_ids=objects,
        object_acquisition_owner_ids=acquisition_owners,
        session_acquisition_url=acquisition.url if acquisition is not None else None,
        session_acquisition_method=(
            acquisition.method if acquisition is not None else None
        ),
        replay_enabled=mode == "verify" and target_class != "external",
    )


def stage_verification_inputs(value: Any, vault: CredentialVault) -> dict[str, Any]:
    """Copy and vault every recognized secret before typed execution."""

    if type(value) is not dict:
        raise VerificationInputValidationError(
            "Verification input must be a JSON object."
        )
    _validate_verification_input_keys(value)
    staged = deepcopy(value)
    stage_rate_limit_input_secret(staged, vault)
    stage_recovery_input_secrets(staged, vault)
    return staged


def _validate_verification_input_keys(value: dict[Any, Any]) -> None:
    """Reject unbounded/non-string root keys without reflecting their values."""

    if len(value) > MAX_VERIFICATION_INPUT_KEYS:
        raise VerificationInputValidationError(
            "Verification input contains too many fields."
        )
    if any(
        type(key) is not str or not key or len(key) > MAX_VERIFICATION_INPUT_KEY_LENGTH
        for key in value
    ):
        raise VerificationInputValidationError(
            "Verification input field names must be bounded strings."
        )


def select_verification_inputs(
    staged: dict[str, Any], hypothesis_id: str
) -> dict[str, Any]:
    """Resolve direct or strict defaults/per-hypothesis input without coercion."""

    _validate_verification_input_keys(staged)
    structured = "defaults" in staged or "hypotheses" in staged
    if not structured:
        return deepcopy(staged)
    try:
        envelope = VerificationInputEnvelope.model_validate(staged)
    except ValidationError:
        raise VerificationInputValidationError(
            "Verification input envelope is invalid."
        ) from None
    specific = envelope.hypotheses.get(hypothesis_id, {})
    selected = deepcopy(envelope.defaults)
    selected.update(deepcopy(specific))
    return selected


def _safe_cookie_metadata(response: Any, headers: dict[str, Any]) -> dict[str, Any]:
    names: set[str] = set()
    secure = False
    http_only = False
    same_site: set[str] = set()
    response_cookies = getattr(response, "cookies", None)
    try:
        for cookie in response_cookies or ():
            name = str(getattr(cookie, "name", "")).strip()
            if name:
                names.add(name[:100])
            secure = secure or bool(getattr(cookie, "secure", False))
            rest = getattr(cookie, "_rest", {})
            if isinstance(rest, dict):
                lowered = {str(key).casefold(): value for key, value in rest.items()}
                http_only = http_only or "httponly" in lowered
                value = lowered.get("samesite")
                if value is not None:
                    same_site.add(str(value).strip().casefold()[:20])
    except TypeError:
        pass

    raw_set_cookie = next(
        (
            str(value)
            for name, value in headers.items()
            if str(name).strip().casefold() == "set-cookie"
        ),
        "",
    )[:8192]
    if raw_set_cookie:
        parsed = SimpleCookie()
        try:
            parsed.load(raw_set_cookie)
        except CookieError:
            parsed = SimpleCookie()
        for name, morsel in parsed.items():
            names.add(str(name)[:100])
            secure = secure or bool(morsel["secure"])
            http_only = http_only or bool(morsel["httponly"])
            if morsel["samesite"]:
                same_site.add(str(morsel["samesite"]).strip().casefold()[:20])
        lowered_cookie = raw_set_cookie.casefold()
        secure = secure or "; secure" in lowered_cookie
        http_only = http_only or "; httponly" in lowered_cookie

    return {
        "cookie_present": bool(names or raw_set_cookie),
        "cookie_count": len(names),
        "cookie_names": sorted(names)[:50],
        "secure": secure,
        "http_only": http_only,
        "same_site": sorted(item for item in same_site if item),
    }


def adapt_verification_response(response: Any) -> dict[str, Any]:
    """Convert one HTTP response to the sole classifier-facing safe shape."""

    try:
        body: Any = response.json()
    except (TypeError, ValueError):
        body = getattr(response, "text", "")
    raw_headers = getattr(response, "headers", {})
    if not isinstance(raw_headers, dict) and not hasattr(raw_headers, "items"):
        raw_headers = {}
    header_items = {
        str(name).strip().casefold(): value for name, value in raw_headers.items()
    }
    safe_headers = {
        name: header_items[name.casefold()]
        for name in SAFE_RESPONSE_HEADERS
        if name.casefold() in header_items
    }
    status_code = getattr(response, "status_code", None)
    normalized = {
        "status_code": status_code,
        "status_class": (
            f"{status_code // 100}xx"
            if isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and 100 <= status_code < 600
            else "unknown"
        ),
        "headers": safe_headers,
        "body": body,
        "cookie_metadata": _safe_cookie_metadata(response, dict(raw_headers)),
    }
    content_type = safe_headers.get("Content-Type")
    if content_type is not None:
        normalized["content_type"] = str(content_type).split(";", 1)[0].strip()
    elapsed = getattr(response, "elapsed", None)
    total_seconds = getattr(elapsed, "total_seconds", None)
    if callable(total_seconds):
        try:
            elapsed_ms = float(total_seconds()) * 1000
        except (TypeError, ValueError, OverflowError):
            elapsed_ms = -1
        if 0 <= elapsed_ms < float("inf"):
            normalized["elapsed_ms"] = elapsed_ms
    return normalized


class VerificationHTTPTransport:
    """Sole policy-aware network adapter for typed Phase 2 execution."""

    manages_request_budget = True

    def __init__(self, client: ScopedHTTPClient) -> None:
        if not isinstance(client, ScopedHTTPClient):
            raise TypeError("Typed verification requires ScopedHTTPClient.")
        self.client = client
        self.manages_request_budget = bool(client.manages_request_budget)

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        purpose = request.get("purpose")
        credential_mode = request.get("credential_mode")
        allow_session_credentials = bool(
            purpose not in {"session_acquisition", "rate_limit_verification"}
            and credential_mode != "anonymous"
        )
        response, _ = self.client.request(
            request["method"],
            request["url"],
            headers=request.get("headers"),
            json=request.get("json"),
            purpose=purpose,
            request_context=request.get("request_context"),
            techniques=request.get("techniques"),
            oast_callback_url=request.get("oast_callback_url"),
            isolate_session_cookies=True,
            allow_session_credentials=allow_session_credentials,
            timeout=10,
            follow_redirects=False,
        )
        return adapt_verification_response(response)


def comparable_verification_result(value: Any) -> dict[str, Any]:
    """Return public behavioral content with documented volatile fields removed."""

    normalized = public_result(value)
    if not isinstance(normalized, dict):
        raise ValueError("Verification result must be a public object.")
    return {
        key: item
        for key, item in normalized.items()
        if key not in _VOLATILE_RESULT_FIELDS and key != "success"
    }


class VerificationRuntime:
    """Shared policy, transport, executor, recovery, and serialization boundary."""

    defers_runtime_policy_authorization = True

    def __init__(
        self,
        *,
        policy: AssessmentPolicy,
        controlled_context: ControlledContext,
        vault: CredentialVault,
        verification_inputs: Any,
        target: str,
        target_class: TargetClass,
        store: Phase2RunStore,
        budget: RequestBudget | None = None,
        network_client: ScopedHTTPClient | None = None,
        parent_run: dict[str, Any] | None = None,
        defer_transport: bool = False,
    ) -> None:
        if target_class not in {"external", "local_range", "dedicated_lab"}:
            raise ValueError("Target class must be explicitly configured.")
        self.policy = policy
        self.controlled_context = controlled_context
        self.vault = vault
        self._verification_input_invalid = False
        try:
            self.verification_inputs = stage_verification_inputs(
                verification_inputs, vault
            )
        except VerificationInputValidationError:
            self.verification_inputs = {}
            self._verification_input_invalid = True
        self.target = str(target)
        self.target_class = target_class
        self.store = store
        self.parent_run = parent_run
        self.phase2_run_id: str | None = None
        self.policy_context = build_verification_policy_context(
            controlled_context, target_class=target_class
        )
        self.budget = budget
        self._network_client: ScopedHTTPClient | None = None
        self.transport: VerificationHTTPTransport | None = None

        if network_client is not None:
            self.network_client = network_client
        elif not defer_transport:
            self.budget = budget or RequestBudget(
                min(policy.request_budget, ADAPTIVE_MAX_REQUESTS),
                per_host_limit=policy.per_host_request_budget,
            )
            self.network_client = ScopedHTTPClient(policy=policy, budget=self.budget)

    @property
    def network_client(self) -> ScopedHTTPClient | None:
        return self._network_client

    @network_client.setter
    def network_client(self, client: ScopedHTTPClient) -> None:
        if not isinstance(client, ScopedHTTPClient):
            raise TypeError("Typed verification requires ScopedHTTPClient.")
        if client.policy is not self.policy:
            raise ValueError(
                "Verification transport must use the selected policy object."
            )
        if client.budget is None:
            raise ValueError("Verification transport requires an authoritative ledger.")
        if self.budget is not None and client.budget is not self.budget:
            raise ValueError("Verification transport ledger identity is inconsistent.")
        self.budget = client.budget
        self._network_client = client
        self.transport = VerificationHTTPTransport(client)

    def _gate(
        self, supplied: DeterministicPolicyGate | None
    ) -> DeterministicPolicyGate:
        if self.budget is None or self.transport is None:
            raise RuntimeError(
                "Shared authorized verification transport is unavailable."
            )
        gate = supplied or DeterministicPolicyGate(
            self.policy, self.policy_context.model_copy(deep=True), self.budget
        )
        if gate.policy is not self.policy:
            raise ValueError("Verification gate policy identity is inconsistent.")
        if gate.budget is not self.budget:
            raise ValueError("Verification gate ledger identity is inconsistent.")
        if gate.context != self.policy_context:
            raise ValueError("Verification gate context is inconsistent.")
        return gate

    def _prior_recovery_result(self, hypothesis: Hypothesis) -> dict[str, Any] | None:
        if hypothesis.category != "recovery_state_enforcement":
            return None
        candidate = self.parent_run
        parent_selected = candidate is not None
        if candidate is None:
            try:
                candidate = self.store.load()
            except (OSError, ValueError):
                candidate = None
        if not isinstance(candidate, dict):
            return None
        candidate_fingerprint = candidate.get("target_fingerprint")
        current_public, current_fingerprint = target_identity(self.target)
        same_target = (
            parent_selected
            or candidate_fingerprint == current_fingerprint
            or (
                candidate_fingerprint is None
                and candidate.get("target") == current_public
            )
        )
        if not same_target:
            return None
        return pending_recovery_result(
            candidate, hypothesis_id=hypothesis.hypothesis_id
        )

    @staticmethod
    def _invalid_input_result(
        hypothesis: Hypothesis, producer: dict[str, str]
    ) -> dict[str, Any]:
        """Build the one zero-traffic typed invalid-input result contract."""

        delta = RequestDelta()
        output = normalize_typed_result(
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "category": hypothesis.category,
                "status": "invalid_verification_input",
                "reasons": [INVALID_INPUT_REASON],
            },
            delta,
        )
        output.update(
            {
                "request_delta": delta.model_dump(mode="json"),
                "requests_used": 0,
                "result_schema_version": RESULT_SCHEMA_VERSION,
                "executor": producer,
            }
        )
        return public_result(output)

    def execute_selected(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        *,
        gate: DeterministicPolicyGate | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        capability = get_verification_capability(hypothesis.category)
        if capability.capability_state is not CapabilityState.typed_verification:
            return public_result(
                plan_only_command_metadata(
                    hypothesis.category, hypothesis.hypothesis_id
                )
            )
        producer = typed_producer_provenance(hypothesis.category)
        executor_type = resolve_verification_executor(hypothesis.category)
        if executor_type is None:
            raise ValueError("The typed verification executor route is unavailable.")
        try:
            if self._verification_input_invalid:
                raise VerificationInputValidationError(
                    "Verification input root is invalid."
                )
            selected_inputs = select_verification_inputs(
                self.verification_inputs, hypothesis.hypothesis_id
            )
        except VerificationInputValidationError:
            return self._invalid_input_result(hypothesis, producer)
        effective_gate = self._gate(gate)
        executor = executor_type(
            effective_gate,
            self.vault,
            self.controlled_context,
            self.transport,
            private_recovery_store=self.store.private_recovery,
        )
        prior = self._prior_recovery_result(hypothesis)
        recovery_run_id = str(
            (prior or {}).get("recovery_run_id")
            or run_id
            or self.phase2_run_id
            or plan.plan_id
        )
        output = executor.execute(
            hypothesis,
            plan,
            inputs=selected_inputs,
            prior_result=prior,
            run_id=recovery_run_id,
        )
        supplied_producer = output.get("executor")
        if supplied_producer is not None:
            validate_typed_producer_provenance(hypothesis.category, supplied_producer)
        supplied_schema_version = output.get(
            "result_schema_version", RESULT_SCHEMA_VERSION
        )
        if (
            type(supplied_schema_version) is not int
            or supplied_schema_version != RESULT_SCHEMA_VERSION
        ):
            raise ValueError("Typed result schema version is invalid.")
        output["result_schema_version"] = RESULT_SCHEMA_VERSION
        output["executor"] = producer
        self.policy_context = effective_gate.context.model_copy(deep=True)
        status = str(output.get("status") or "inconclusive")
        if status not in PUBLIC_RESULT_STATUSES:
            status = "inconclusive"
        return public_result(
            {
                **output,
                "hypothesis_id": hypothesis.hypothesis_id,
                "category": hypothesis.category,
                "status": status,
            }
        )

    def __call__(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        gate: DeterministicPolicyGate,
    ) -> dict[str, Any]:
        return self.execute_selected(
            hypothesis,
            plan,
            gate=gate,
            run_id=self.phase2_run_id,
        )


def create_verification_runtime(**kwargs: Any) -> VerificationRuntime:
    """Factory named explicitly so both public entry paths reuse one contract."""

    return VerificationRuntime(**kwargs)
