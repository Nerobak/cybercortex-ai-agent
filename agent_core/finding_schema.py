from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

Confidence = Literal[
    "low",
    "medium",
    "high",
]

FindingStatus = Literal[
    "observation",
    "candidate",
    "needs_manual_verification",
    "verified",
    "false_positive",
]


@dataclass
class SecurityFinding:
    """
    Standard finding format used by CyberCortex AI Agent v2.

    Tools should return structured evidence through this object instead of
    asking the language model to invent findings or severity.
    """

    title: str
    category: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus

    endpoint: str | None = None
    method: str | None = None

    evidence: list[str] = field(default_factory=list)
    impact: str = ""
    recommendation: str = ""
    manual_verification: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding into a serializable dictionary."""
        return asdict(self)
