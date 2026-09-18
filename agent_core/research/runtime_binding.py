"""Sealed process-local binding for one authorized research experiment."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeGuard

from agent_core.research.authorization import (
    ResearchAuthorizationErrorCode,
    policy_fingerprint,
    target_fingerprint,
)
from agent_core.research.experiments import AuthorizedExperiment, _is_gate_authorized

_BINDING_ISSUER = object()

if TYPE_CHECKING:
    from agent_core.research.runtime import ResearchRuntime


class InvalidRuntimeBindingError(ValueError):
    """A public-safe rejection of an invalid or mismatched runtime binding."""

    code = ResearchAuthorizationErrorCode.invalid_binding

    def __init__(self) -> None:
        super().__init__(self.code.value)


class ResearchRuntimeBinding:
    """Bind one authorization to the exact runtime dependencies it approved."""

    __slots__ = (
        "__authorization",
        "__budget",
        "__controlled_context",
        "__executor_registry",
        "__issuer",
        "__policy",
        "__primitive_registry",
        "__runtime",
        "__scope_reference",
        "__transport",
        "__vault",
    )

    def __init__(
        self,
        authorization: AuthorizedExperiment,
        runtime: "ResearchRuntime",
        issuer: object,
    ) -> None:
        from agent_core.research.runtime import ResearchRuntime

        if (
            issuer is not _BINDING_ISSUER
            or type(runtime) is not ResearchRuntime
            or not _is_gate_authorized(authorization)
            or authorization.runtime_binding_reference != runtime.binding_reference
        ):
            raise InvalidRuntimeBindingError()
        target = runtime.target(authorization.experiment.target.target_id)
        if (
            authorization.policy_hash != policy_fingerprint(runtime.policy)
            or authorization.target_fingerprint != target_fingerprint(target)
            or authorization.scope_reference != target.scope_reference
        ):
            raise InvalidRuntimeBindingError()
        object.__setattr__(self, "_ResearchRuntimeBinding__issuer", issuer)
        object.__setattr__(
            self, "_ResearchRuntimeBinding__authorization", authorization
        )
        object.__setattr__(self, "_ResearchRuntimeBinding__runtime", runtime)
        object.__setattr__(self, "_ResearchRuntimeBinding__budget", runtime.budget)
        object.__setattr__(
            self,
            "_ResearchRuntimeBinding__controlled_context",
            runtime.controlled_context,
        )
        object.__setattr__(self, "_ResearchRuntimeBinding__vault", runtime.vault)
        object.__setattr__(
            self, "_ResearchRuntimeBinding__transport", runtime.transport
        )
        object.__setattr__(self, "_ResearchRuntimeBinding__policy", runtime.policy)
        object.__setattr__(
            self,
            "_ResearchRuntimeBinding__primitive_registry",
            runtime.primitive_registry,
        )
        object.__setattr__(
            self,
            "_ResearchRuntimeBinding__executor_registry",
            runtime.executor_registry,
        )
        object.__setattr__(
            self, "_ResearchRuntimeBinding__scope_reference", target.scope_reference
        )
        runtime._register_binding(self, _BINDING_ISSUER)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        raise TypeError("ResearchRuntimeBinding cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("ResearchRuntimeBinding is immutable")

    @property
    def binding_reference(self) -> str:
        return self.__authorization.runtime_binding_reference

    @property
    def authorization_reference(self) -> str:
        return self.__authorization.authorization_reference

    @property
    def budget(self):
        return self.__budget

    @property
    def controlled_context(self):
        return self.__controlled_context

    @property
    def vault(self):
        return self.__vault

    @property
    def transport(self):
        return self.__transport

    @property
    def policy(self):
        return self.__policy

    @property
    def primitive_registry(self):
        return self.__primitive_registry

    @property
    def executor_registry(self):
        return self.__executor_registry

    @property
    def scope_reference(self) -> str:
        return self.__scope_reference

    def submit(self, authorization: AuthorizedExperiment):
        if authorization is not self.__authorization:
            raise InvalidRuntimeBindingError()
        return self.__runtime._submit_bound(
            authorization, self, binding_issuer=_BINDING_ISSUER
        )

    def _matches(
        self, authorization: AuthorizedExperiment, runtime: "ResearchRuntime"
    ) -> bool:
        return bool(
            self.__issuer is _BINDING_ISSUER
            and authorization is self.__authorization
            and runtime is self.__runtime
            and runtime.budget is self.__budget
            and runtime.controlled_context is self.__controlled_context
            and runtime.vault is self.__vault
            and runtime.transport is self.__transport
            and runtime.policy is self.__policy
            and runtime.primitive_registry is self.__primitive_registry
            and runtime.executor_registry is self.__executor_registry
        )

    def __copy__(self) -> None:
        raise TypeError("ResearchRuntimeBinding cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> None:
        raise TypeError("ResearchRuntimeBinding cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("ResearchRuntimeBinding cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> None:
        raise TypeError("ResearchRuntimeBinding cannot be serialized")


def bind_research_runtime(
    authorization: AuthorizedExperiment, runtime: "ResearchRuntime"
) -> ResearchRuntimeBinding:
    return ResearchRuntimeBinding(authorization, runtime, _BINDING_ISSUER)


def is_research_runtime_binding(
    value: object,
) -> TypeGuard[ResearchRuntimeBinding]:
    return type(value) is ResearchRuntimeBinding


__all__ = [
    "InvalidRuntimeBindingError",
    "ResearchRuntimeBinding",
    "bind_research_runtime",
    "is_research_runtime_binding",
]
