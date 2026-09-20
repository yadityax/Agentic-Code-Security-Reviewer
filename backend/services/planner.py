"""Planner agent: decides which scanners apply. Deterministic on purpose: cheap, testable, explainable."""

from dataclasses import dataclass, field
from pathlib import Path

from backend.services.workspace import SCANNABLE_SKIP_DIRS

MANIFESTS = {
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pom.xml",
    "go.mod",
    "Gemfile.lock",
    "uv.lock",
}
CODEQL_LANGS = {"python", "javascript", "typescript"}
FRAMEWORK_HINTS = {
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "express": "express",
    "sqlalchemy": "sqlalchemy",
}


@dataclass
class Plan:
    scanners: list[str]
    languages: list[str]
    frameworks: list[str] = field(default_factory=list)
    has_manifests: bool = False
    has_dockerfile: bool = False
    reasons: dict[str, str] = field(default_factory=dict)


def detect_frameworks(root: Path) -> list[str]:
    found: set[str] = set()
    for name in ("requirements.txt", "pyproject.toml", "package.json"):
        p = root / name
        if p.is_file():
            text = p.read_text(errors="replace").lower()
            found |= {label for hint, label in FRAMEWORK_HINTS.items() if hint in text}
    return sorted(found)


def make_plan(
    root: Path, languages: set[str], *, enable_codeql: bool = True, enabled: set[str] | None = None
) -> Plan:
    files = [p for p in root.rglob("*") if p.is_file() and not SCANNABLE_SKIP_DIRS & set(p.parts)]
    names = {p.name for p in files}
    manifests = bool(MANIFESTS & names)
    dockerfile = any(
        n == "Dockerfile" or n.startswith("Dockerfile.") or n.endswith(".dockerfile") for n in names
    )
    plan = Plan(scanners=[], languages=sorted(languages), frameworks=detect_frameworks(root),
                has_manifests=manifests, has_dockerfile=dockerfile)  # fmt: skip

    def add(name: str, why: str) -> None:
        if enabled is None or name in enabled:
            plan.scanners.append(name)
            plan.reasons[name] = why

    if languages & {"python", "javascript", "typescript", "go", "java", "ruby"}:
        add(
            "semgrep",
            f"source code present ({', '.join(sorted(languages & {'python', 'javascript', 'typescript', 'go', 'java', 'ruby'}))})",
        )
    add("gitleaks", "secrets can live in any file type")
    if enable_codeql and languages & CODEQL_LANGS:
        add(
            "codeql",
            "deep data-flow analysis supported for " + ", ".join(sorted(languages & CODEQL_LANGS)),
        )
    if manifests or dockerfile:
        add("trivy", "dependency manifests / Dockerfile present")
    if manifests:
        add("syft", "SBOM for dependency reachability")
    return plan
