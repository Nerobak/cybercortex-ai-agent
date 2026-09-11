"""Non-serializable binding to the one authoritative Phase 2 runtime."""

from __future__ import annotations

from typing import Any, TypeGuard

from agent_core.agent_models import Hypothesis, VerificationPlan
from agent_core.verification_runtime import VerificationRuntime

_BINDING_ISSUER = object()


class Phase2RuntimeBindingError(ValueError):
    """A supplied object is not the concrete authoritative Phase 2 runtime."""


class AuthoritativePhase2RuntimeBinding:
    """Sealed, process-local authority issued only for ``VerificationRuntime``."""

    __slots__ = ("__execute_selected", "__issuer", "__runtime")

    def __init__(self, runtime: VerificationRuntime, issuer: object) -> None:
        if issuer is not _BINDING_ISSUER or type(runtime) is not VerificationRuntime:
            raise Phase2RuntimeBindingError("Phase 2 runtime binding is invalid")
        self.__runtime = runtime
        self.__execute_selected = runtime.execute_selected
        self.__issuer = issuer

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("Authoritative Phase 2 runtime binding cannot be subclassed")

    @property
    def policy(self) -> Any:
        return self.__runtime.policy

    @property
    def controlled_context(self) -> Any:
        return self.__runtime.controlled_context

    @property
    def vault(self) -> Any:
        return self.__runtime.vault

    @property
    def budget(self) -> Any:
        return self.__runtime.budget

    def submit(
        self,
        hypothesis: Hypothesis,
        plan: VerificationPlan,
        *,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        return self.__execute_selected(hypothesis, plan, run_id=run_id)

    def __copy__(self) -> None:
        raise TypeError("Phase 2 runtime authority cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> None:
        raise TypeError("Phase 2 runtime authority cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("Phase 2 runtime authority cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("Phase 2 runtime authority cannot be serialized")

    def _issued_by(self, issuer: object) -> bool:
        return self.__issuer is issuer


class _UnboundPhase2Runtime:
    __slots__ = ()


UNBOUND_PHASE2_RUNTIME = _UnboundPhase2Runtime()


def bind_authoritative_phase2_runtime(
    runtime: object,
) -> AuthoritativePhase2RuntimeBinding:
    """Bind only the exact shared Phase 2 runtime; subclasses are not authority."""

    if type(runtime) is not VerificationRuntime:
        raise Phase2RuntimeBindingError("Phase 2 runtime binding is invalid")
    return AuthoritativePhase2RuntimeBinding(runtime, _BINDING_ISSUER)


def is_authoritative_phase2_runtime(
    runtime: object,
) -> TypeGuard[AuthoritativePhase2RuntimeBinding]:
    """Validate sealed binding identity without consulting runtime attributes."""

    if type(runtime) is not AuthoritativePhase2RuntimeBinding:
        return False
    try:
        return runtime._issued_by(_BINDING_ISSUER)
    except AttributeError:
        return False
