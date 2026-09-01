"""Provider-neutral advisory researcher and critic roles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class AdvisoryModelRoles:
    researcher: Callable[[str], str]
    critic: Callable[[str], str]

    @classmethod
    def from_local_model(cls, model: Callable[[str], str]) -> "AdvisoryModelRoles":
        return cls(researcher=model, critic=model)

    def research(self, prompt: str) -> str:
        return self.researcher(
            "Advisory researcher role. Suggest hypotheses only; never authorize or execute.\n"
            + prompt
        )

    def critique(self, prompt: str) -> str:
        return self.critic(
            "Advisory critic role. Identify benign explanations, missing evidence, and false-positive risk.\n"
            + prompt
        )
