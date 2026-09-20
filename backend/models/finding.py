"""Common finding schema (blueprint §7) shared by every scanner adapter."""

import hashlib
import re
from enum import StrEnum, auto

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FindingStatus(StrEnum):
    UNVALIDATED = auto()
    TRUE_POSITIVE = auto()
    FALSE_POSITIVE = auto()
    NEEDS_REVIEW = auto()
    FIX_FAILED = auto()
    FIXED = auto()


class PRScope(StrEnum):
    """Whether a finding sits on lines the PR changed (decision D2)."""

    NEW = auto()
    EXISTING = auto()
    UNKNOWN = auto()


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./").lstrip("/")


def compute_fingerprint(
    *, cwe: str | None, rule_id: str, file: str, symbol: str | None, snippet: str
) -> str:
    """Stable identity for a finding across scanners and across line shifts.

    Line numbers are deliberately excluded so a patch that moves code does not
    change the fingerprint. The snippet is whitespace-normalized and only its
    hash is kept, so secrets never enter the fingerprint in clear text.
    """
    normalized = re.sub(r"\s+", " ", snippet).strip()
    parts = (cwe or rule_id, normalize_path(file), symbol or "", normalized)
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


class Verdict(StrEnum):
    TRUE_POSITIVE = auto()
    FALSE_POSITIVE = auto()
    NEEDS_REVIEW = auto()

    @classmethod
    def _missing_(cls, value: object) -> "Verdict | None":
        """LLMs answer 'TRUE_POSITIVE', 'True Positive' or 'true_positive'; accept all of them."""
        if isinstance(value, str):
            key = value.strip().lower().replace(" ", "_").replace("-", "_")
            for member in cls:
                if member.value == key:
                    return member
        return None


class Analysis(BaseModel):
    """Security Analyst output for one finding."""

    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    priority: int = Field(ge=0, le=3, description="0 = fix now ... 3 = low")
    exploitability: str = ""
    reasoning: str = ""
    cited_lines: list[int] = Field(default_factory=list)
    model: str = ""


class Finding(BaseModel):
    id: str
    scanner: str
    rule_id: str
    file: str
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    severity: Severity
    cwe: str | None = None
    owasp: str | None = None
    title: str
    evidence: str = ""
    status: FindingStatus = FindingStatus.UNVALIDATED
    model_confidence: float | None = Field(default=None, ge=0, le=1)
    recommended_fix: str | None = None
    symbol: str | None = None
    fingerprint: str
    pr_scope: PRScope = PRScope.UNKNOWN
    cve: str | None = None
    package: str | None = None
    also_detected_by: list[str] = Field(default_factory=list)  # other scanners, after correlation
    merged_rule_ids: list[str] = Field(default_factory=list)
    reachable: bool | None = None  # dependency findings: is the package imported?
    analysis: Analysis | None = None
