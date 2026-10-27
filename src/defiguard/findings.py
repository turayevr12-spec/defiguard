"""Finding and severity data model shared by every rule and report."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity reflects *how much review a flag deserves*, not a confirmed
    exploitability rating. ``REVIEW`` means "a human must look here"."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    REVIEW = "review"

    def __str__(self) -> str:  # nicer CLI/markdown output
        return self.value


# Rough ordering so reports can sort most-serious first.
_SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.REVIEW: 3,
}


@dataclass(frozen=True)
class Finding:
    """One flagged location. ``rationale`` explains WHY it is suspicious and
    ``recommendation`` says what to check -- deliberately not "this is a bug"."""

    rule_id: str
    severity: Severity
    title: str
    file: str
    line: int
    snippet: str
    rationale: str
    recommendation: str
    cwe: str | None = None
    # free-form, e.g. the captured identifier a rule keyed on
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return (_SEVERITY_ORDER[self.severity], self.file, self.line)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def location(self) -> str:
        return f"{self.file}:{self.line}"


def relpath(path: Path, root: Path) -> str:
    """Report paths relative to the scanned root when possible (stable output)."""
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
