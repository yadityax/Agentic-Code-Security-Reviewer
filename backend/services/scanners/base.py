from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from backend.models.finding import Finding


@dataclass
class ScanContext:
    root: Path
    changed_files: list[str] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    timeout_s: int = 300


@dataclass
class ScanOutput:
    scanner: str
    findings: list[Finding]
    duration_s: float = 0.0
    error: str | None = None  # a failing scanner degrades the scan; it must not abort it
    raw_bytes: int = 0
    artifacts: dict[str, Any] = field(default_factory=dict)  # e.g. the SBOM


class ScannerAdapter(Protocol):
    name: str

    async def run(self, ctx: ScanContext) -> ScanOutput: ...
