"""Explicit controlled-account, object-ownership, and session context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import Field, field_validator

from agent_core.agent_models import (
    AuthorizationAction,
    PolicyDecision,
    StrictModel,
    TransportRequestContext,
)
from agent_core.credential_vault import CredentialVault
from agent_core.request_budget import RequestBudget
from tools.safe_http import PolicyViolationError

ROLE_PRIVILEGE_RANKS = {
    "user": 10,
    "member": 10,
    "normal": 10,
    "normal_user": 10,
    "standard_user": 10,
    "moderator": 20,
    "operator": 20,
    "admin": 30,
    "administrator": 30,
    "owner": 40,
    "superadmin": 40,
    "super_admin": 40,
}

SUPPORTED_LOGIN_IDENTITY_FIELDS = ("email", "username")
CONTROLLED_IDENTITY_UNAVAILABLE_REASON = (
    "Controlled login identity is unavailable; a vaulted identity is required."
)
CONTROLLED_IDENTITY_VAULT_REASON = (
    "Controlled login identity reference is unavailable in the credential vault."
)
UNSUPPORTED_IDENTITY_FIELD_REASON = "Unsupported session-acquisition identity field."
CONTROLLED_PASSWORD_UNAVAILABLE_REASON = (
    "Controlled login password is unavailable; a vaulted password is required."
)
CONTROLLED_PASSWORD_VAULT_REASON = (
    "Controlled login password reference is unavailable in the credential vault."
)


def role_privilege_rank(role: str) -> int | None:
    """Resolve only explicit, recognized role metadata to a privilege rank."""
    normalized = "_".join(str(role).strip().lower().replace("-", " ").split())
    return ROLE_PRIVILEGE_RANKS.get(normalized)


class ControlledAccount(StrictModel):
    account_id: str
    role: str = "user"
    tenant_id: str | None = None
    credential_references: dict[str, str] = Field(default_factory=dict)
    session_reference: str | None = None
    controlled: bool = True


class ControlledObject(StrictModel):
    object_id: str
    owner_account_id: str
    tenant_id: str | None = None
    object_type: str = "unknown"
    test_owned: bool = True


class OwnedObjectAcquisition(StrictModel):
    """Explicit authenticated own-resource collection used for ownership proof."""

    owner_account_id: str = Field(min_length=1, max_length=100)
    collection_url: str = Field(min_length=1, max_length=2048)
    method: str = "GET"
    object_type: str = Field(default="unknown", min_length=1, max_length=100)
    identifier_field: str = Field(min_length=1, max_length=200)
    tenant_field: str | None = Field(default=None, min_length=1, max_length=200)
    items_field: str | None = Field(default=None, min_length=1, max_length=200)
    max_items: int = Field(default=20, ge=1, le=20)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("method must be a conventional HTTP method token")
        return method


class SessionAcquisition(StrictModel):
    url: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    token_field: str = "token"

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or len(method) > 16 or not method.isalpha():
            raise ValueError("method must be a conventional HTTP method token")
        return method


class SessionAcquisitionAction(AuthorizationAction):
    """Typed authorization input emitted only by ``SessionAcquirer``."""

    purpose: Literal["session_acquisition"] = "session_acquisition"
    generated_by: Literal["SessionAcquirer"] = "SessionAcquirer"
    account_id: str
    account_controlled: bool
    identity_field: str
    identity_bound: bool
    identity_source: Literal["email", "username"] | None = None
    credential_reference_present: bool
    request_count: int = Field(default=1, ge=1, le=1)
    follow_redirects: Literal[False] = False


class SessionAcquisitionDecision(PolicyDecision):
    """Typed gate result carrying only safe HTTP authorization metadata."""

    request_context: TransportRequestContext


class SessionAcquisitionPolicyError(ValueError):
    """Secret-free deterministic policy denial for controlled authentication."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("Controlled session acquisition was blocked by policy.")
        self.reasons = list(reasons)


class SessionAcquisitionTransportPolicyError(ValueError):
    """The shared transport rejected an otherwise typed session request."""


class SessionAuthenticationRejectedError(ValueError):
    """The configured authentication endpoint returned a non-success status."""


class SessionTokenFieldAbsentError(ValueError):
    """Authentication succeeded but its configured token field was absent."""


class ControlledContext(StrictModel):
    accounts: list[ControlledAccount] = Field(default_factory=list, max_length=20)
    objects: list[ControlledObject] = Field(default_factory=list, max_length=100)
    session_acquisition: SessionAcquisition | None = None
    object_acquisition: list[OwnedObjectAcquisition] = Field(
        default_factory=list, max_length=20
    )

    def account(self, account_id: str) -> ControlledAccount:
        match = next(
            (item for item in self.accounts if item.account_id == account_id), None
        )
        if match is None:
            raise KeyError("Unknown controlled account reference.")
        return match


class ControlledLoginIdentityResolution:
    """Typed identity binding whose vault handle is never publicly serialized."""

    __slots__ = (
        "identity_bound",
        "identity_field",
        "identity_source",
        "reason",
        "_credential_reference",
    )

    def __init__(
        self,
        *,
        identity_bound: bool,
        identity_field: str | None,
        identity_source: Literal["email", "username"] | None,
        reason: str | None,
        credential_reference: str | None = None,
    ) -> None:
        self.identity_bound = identity_bound
        self.identity_field = identity_field
        self.identity_source = identity_source
        self.reason = reason
        self._credential_reference = credential_reference

    def __repr__(self) -> str:
        return (
            "ControlledLoginIdentityResolution("
            f"identity_bound={self.identity_bound!r}, "
            f"identity_field={self.identity_field!r}, "
            f"identity_source={self.identity_source!r}, reason={self.reason!r})"
        )

    def public_summary(self) -> dict[str, bool | str | None]:
        """Return safe semantic metadata without an identity value or handle."""

        return {
            "identity_bound": self.identity_bound,
            "identity_source": self.identity_source,
        }

    def materialize(self, vault: CredentialVault) -> str:
        """Read the bound value only at the private request-construction boundary."""

        if not self.identity_bound or self._credential_reference is None:
            raise KeyError(CONTROLLED_IDENTITY_UNAVAILABLE_REASON)
        return vault.get(self._credential_reference)


def resolve_controlled_login_identity(
    account: ControlledAccount,
    acquisition: SessionAcquisition | str,
    vault: CredentialVault,
) -> ControlledLoginIdentityResolution:
    """Resolve one live controlled identity for an explicit login field semantic."""

    declared_field = (
        acquisition.username_field
        if isinstance(acquisition, SessionAcquisition)
        else str(acquisition)
    )
    identity_field = declared_field.strip().casefold()
    if identity_field not in SUPPORTED_LOGIN_IDENTITY_FIELDS:
        return ControlledLoginIdentityResolution(
            identity_bound=False,
            identity_field=None,
            identity_source=None,
            reason=UNSUPPORTED_IDENTITY_FIELD_REASON,
        )
    primary = identity_field
    alternate = "username" if primary == "email" else "email"
    reference_configured = False
    for name in (primary, alternate):
        reference = account.credential_references.get(name)
        if not reference:
            continue
        reference_configured = True
        try:
            if vault.contains(reference):
                return ControlledLoginIdentityResolution(
                    identity_bound=True,
                    identity_field=identity_field,
                    identity_source=name,
                    reason=None,
                    credential_reference=reference,
                )
        except RuntimeError:
            break
    return ControlledLoginIdentityResolution(
        identity_bound=False,
        identity_field=identity_field,
        identity_source=None,
        reason=(
            CONTROLLED_IDENTITY_VAULT_REASON
            if reference_configured
            else CONTROLLED_IDENTITY_UNAVAILABLE_REASON
        ),
    )


def load_controlled_context(
    path: str | Path, vault: CredentialVault
) -> ControlledContext:
    """Load an explicitly configured file while moving secrets into the vault."""
    context_path = Path(path)
    payload = json.loads(context_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Controlled context must be a JSON object.")
    sanitized_accounts: list[dict[str, Any]] = []
    for item in payload.get("accounts", []):
        if not isinstance(item, dict) or not item.get("account_id"):
            raise ValueError("Every controlled account requires account_id.")
        sanitized = {
            key: value
            for key, value in item.items()
            if key not in {"email", "username", "password", "token", "credentials"}
        }
        references = dict(sanitized.get("credential_references") or {})
        credentials = item.get("credentials") or {}
        for name in ("email", "username", "password", "token"):
            value = item.get(name, credentials.get(name))
            if value is not None:
                references[name] = vault.put(
                    str(value), label=f"controlled:{item['account_id']}:{name}"
                )
        sanitized["credential_references"] = references
        sanitized["controlled"] = item.get("controlled", True)
        sanitized_accounts.append(sanitized)
    return ControlledContext.model_validate({**payload, "accounts": sanitized_accounts})


class SessionAcquirer:
    """Acquire only configured controlled sessions through an injected sender."""

    def __init__(self, vault: CredentialVault, budget: RequestBudget) -> None:
        self.vault = vault
        self.budget = budget

    @staticmethod
    def authorization_action(
        account: ControlledAccount,
        config: SessionAcquisition,
        vault: CredentialVault | None = None,
    ) -> SessionAcquisitionAction:
        """Build the only action type accepted by the session policy gate."""
        password_reference = account.credential_references.get("password")
        if vault is None:
            identity_bound = any(
                account.credential_references.get(field)
                for field in SUPPORTED_LOGIN_IDENTITY_FIELDS
            )
            identity_source = None
            password_available = bool(password_reference)
        else:
            identity = resolve_controlled_login_identity(account, config, vault)
            identity_bound = identity.identity_bound
            identity_source = identity.identity_source
            try:
                password_available = bool(
                    password_reference and vault.contains(password_reference)
                )
            except RuntimeError:
                password_available = False
        return SessionAcquisitionAction(
            url=config.url,
            method=config.method,
            account_id=account.account_id,
            account_controlled=account.controlled,
            identity_field=config.username_field,
            identity_bound=identity_bound,
            identity_source=identity_source,
            credential_reference_present=bool(identity_bound and password_available),
        )

    def credential_reasons(
        self, account: ControlledAccount, config: SessionAcquisition
    ) -> list[str]:
        """Validate live identity/password references without reading their values."""

        identity = resolve_controlled_login_identity(account, config, self.vault)
        reasons = [identity.reason] if identity.reason else []
        password_reference = account.credential_references.get("password")
        if not password_reference:
            reasons.append(CONTROLLED_PASSWORD_UNAVAILABLE_REASON)
        elif not self._reference_available(password_reference):
            reasons.append(CONTROLLED_PASSWORD_VAULT_REASON)
        return reasons

    def _reference_available(self, reference: str | None) -> bool:
        try:
            return bool(reference and self.vault.contains(reference))
        except RuntimeError:
            return False

    def authorize(
        self,
        account: ControlledAccount,
        config: SessionAcquisition,
        authorization_check: Callable[[SessionAcquisitionAction], PolicyDecision],
    ) -> PolicyDecision:
        """Submit typed session intent before any credential values are read."""
        decision = authorization_check(
            self.authorization_action(account, config, self.vault)
        )
        credential_reasons = self.credential_reasons(account, config)
        if not credential_reasons:
            return decision
        reasons = list(dict.fromkeys([*decision.reasons, *credential_reasons]))
        updates: dict[str, Any] = {"allowed": False, "reasons": reasons}
        request_context = getattr(decision, "request_context", None)
        if isinstance(request_context, TransportRequestContext):
            updates["request_context"] = request_context.model_copy(
                update={"policy_authorized": False}
            )
        return decision.model_copy(update=updates)

    def acquire(
        self,
        account: ControlledAccount,
        config: SessionAcquisition,
        sender: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        authorization_check: Callable[[SessionAcquisitionAction], PolicyDecision],
    ) -> ControlledAccount:
        decision = self.authorize(account, config, authorization_check)
        if not decision.allowed:
            raise SessionAcquisitionPolicyError(decision.reasons)
        identity = resolve_controlled_login_identity(account, config, self.vault)
        password_ref = account.credential_references.get("password")
        credential_reasons = self.credential_reasons(account, config)
        if credential_reasons or password_ref is None:
            raise SessionAcquisitionPolicyError(credential_reasons)
        request_context = getattr(decision, "request_context", None)
        if not isinstance(request_context, TransportRequestContext):
            raise SessionAcquisitionPolicyError(
                ["Typed session transport authorization metadata is missing."]
            )
        try:
            identity_value = identity.materialize(self.vault)
            password_value = self.vault.get(password_ref)
        except (KeyError, RuntimeError) as exc:
            raise SessionAcquisitionPolicyError(
                ["Controlled login credentials became unavailable before transport."]
            ) from exc
        if not getattr(sender, "manages_request_budget", False):
            self.budget.consume("auth")
        try:
            response = sender(
                {
                    "method": config.method,
                    "url": config.url,
                    "purpose": "session_acquisition",
                    "request_context": request_context.model_dump(mode="json"),
                    "json": {
                        config.username_field: identity_value,
                        config.password_field: password_value,
                    },
                }
            )
        except PolicyViolationError as exc:
            raise SessionAcquisitionTransportPolicyError(
                "Controlled session acquisition was denied by transport policy."
            ) from exc
        status_code = response.get("status_code")
        if status_code is not None and (
            not isinstance(status_code, int) or not 200 <= status_code < 300
        ):
            raise SessionAuthenticationRejectedError(
                "Controlled session authentication was rejected."
            )
        body = response.get("body") or {}
        token = body.get(config.token_field) if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise SessionTokenFieldAbsentError(
                "Configured session response did not contain the configured token field."
            )
        account.session_reference = self.vault.put(
            token, label=f"session:{account.account_id}"
        )
        return account


class OwnedObjectAcquisitionError(ValueError):
    """Safe, secret-free failure raised while parsing an owned collection."""


class OwnedObjectAcquirer:
    """Acquire one bounded object from an authenticated controlled-owner source."""

    def __init__(self, vault: CredentialVault, budget: RequestBudget) -> None:
        self.vault = vault
        self.budget = budget

    def acquire(
        self,
        account: ControlledAccount,
        config: OwnedObjectAcquisition,
        sender: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> ControlledObject:
        if account.account_id != config.owner_account_id or not account.controlled:
            raise OwnedObjectAcquisitionError(
                "Owned-object acquisition requires the configured controlled owner."
            )
        credential_reference = (
            account.session_reference or account.credential_references.get("token")
        )
        if not credential_reference:
            raise OwnedObjectAcquisitionError(
                "The configured owner has no acquired session or token."
            )
        try:
            token = self.vault.get(credential_reference)
        except (KeyError, RuntimeError) as exc:
            raise OwnedObjectAcquisitionError(
                "The configured owner's session is not available."
            ) from exc

        if not getattr(sender, "manages_request_budget", False):
            self.budget.consume("discovery")
        response = sender(
            {
                "method": config.method,
                "url": config.collection_url,
                "purpose": "owned_object_acquisition",
                "headers": {"Authorization": f"Bearer {token}"},
            }
        )
        status_code = response.get("status_code")
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise OwnedObjectAcquisitionError(
                "The configured owned-object collection request failed."
            )
        item = self._select_item(response.get("body"), config)
        identifier = self._scalar(item.get(config.identifier_field))
        if identifier is None:
            raise OwnedObjectAcquisitionError(
                "The configured identifier field was absent from the collection response."
            )
        tenant_id = None
        if config.tenant_field:
            tenant_id = self._scalar(item.get(config.tenant_field))
        return ControlledObject(
            object_id=identifier,
            owner_account_id=account.account_id,
            tenant_id=tenant_id,
            object_type=config.object_type,
            test_owned=True,
        )

    @classmethod
    def _select_item(cls, body: Any, config: OwnedObjectAcquisition) -> dict[str, Any]:
        if isinstance(body, list):
            collection: Any = body
        elif isinstance(body, dict):
            if config.items_field:
                if config.items_field not in body:
                    raise OwnedObjectAcquisitionError(
                        "The configured collection field was absent from the response."
                    )
                collection = body[config.items_field]
            else:
                list_fields = [
                    value for value in body.values() if isinstance(value, list)
                ]
                has_direct_identifier = (
                    cls._scalar(body.get(config.identifier_field)) is not None
                )
                if has_direct_identifier and not list_fields:
                    collection = [body]
                elif not has_direct_identifier and len(list_fields) == 1:
                    collection = list_fields[0]
                else:
                    raise OwnedObjectAcquisitionError(
                        "The owned-object collection response structure was ambiguous."
                    )
        else:
            raise OwnedObjectAcquisitionError(
                "The owned-object collection response structure was ambiguous."
            )

        if isinstance(collection, dict):
            collection = [collection]
        if not isinstance(collection, list):
            raise OwnedObjectAcquisitionError(
                "The owned-object collection response structure was ambiguous."
            )
        if not collection:
            raise OwnedObjectAcquisitionError(
                "The configured owned-object collection was empty."
            )
        bounded = collection[: config.max_items]
        for item in bounded:
            if (
                isinstance(item, dict)
                and cls._scalar(item.get(config.identifier_field)) is not None
            ):
                return item
        raise OwnedObjectAcquisitionError(
            "The configured identifier field was absent from the collection response."
        )

    @staticmethod
    def _scalar(value: Any) -> str | None:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return None
        rendered = str(value).strip()
        return rendered or None
