import ast
import hashlib
import re
from functools import lru_cache
from pathlib import Path

from backend.models.finding import Severity, normalize_path


def read_snippet(
    root: Path, file: str, line: int, end_line: int | None = None, pad: int = 0
) -> str:
    try:
        lines = (root / normalize_path(file)).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(line - 1 - pad, 0), (end_line or line) + pad
    return "\n".join(lines[lo:hi])


@lru_cache(maxsize=512)
def _symbol_spans(path: str, mtime: float) -> tuple[tuple[int, int, str], ...]:  # noqa: ARG001
    try:
        tree = ast.parse(Path(path).read_text(errors="replace"))
    except (SyntaxError, OSError, ValueError):
        return ()
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            spans.append((node.lineno, node.end_lineno or node.lineno, node.name))
    return tuple(spans)


def enclosing_symbol(root: Path, file: str, line: int) -> str | None:
    """Innermost function/class containing `line` (Python only), used for stable fingerprints."""
    p = root / normalize_path(file)
    if p.suffix != ".py" or not p.is_file():
        return None
    inside = [s for s in _symbol_spans(str(p), p.stat().st_mtime) if s[0] <= line <= s[1]]
    return min(inside, key=lambda s: s[1] - s[0])[2] if inside else None


def short_id(scanner: str, rule_id: str, file: str, line: int) -> str:
    h = hashlib.sha1(f"{scanner}|{rule_id}|{file}|{line}".encode(), usedforsecurity=False)
    return f"{scanner}-{h.hexdigest()[:10]}"


def first_cwe(values: object) -> str | None:
    items = values if isinstance(values, list) else [values]
    for v in items:
        if m := re.search(r"CWE-(\d+)", str(v), re.I):
            return f"CWE-{int(m[1])}"  # CodeQL writes CWE-089
    return None


def first_owasp(values: object) -> str | None:
    """Prefer the OWASP Top 10 2021 category; fall back to whatever is listed first."""
    items = [str(v) for v in (values if isinstance(values, list) else [values])]
    for v in sorted(items, key=lambda v: ":2021" not in v):
        if m := re.search(r"\bA(\d{2})\b", v):
            return f"A{m[1]}"
    return None


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "WARNING": Severity.MEDIUM, "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFO": Severity.LOW, "UNKNOWN": Severity.LOW,
}  # fmt: skip


def map_severity(value: str | None, default: Severity = Severity.MEDIUM) -> Severity:
    return SEVERITY_MAP.get((value or "").upper(), default)


def enclosing_span(root: Path, file: str, line: int) -> tuple[int, int, str] | None:
    p = root / normalize_path(file)
    if p.suffix != ".py" or not p.is_file():
        return None
    inside = [s for s in _symbol_spans(str(p), p.stat().st_mtime) if s[0] <= line <= s[1]]
    return min(inside, key=lambda s: s[1] - s[0]) if inside else None


def secret_shape(line: str) -> str:
    """A source line with its string literals removed (`AWS_KEY = ""` -> `AWS_KEY =`).

    Identifies *which* secret a finding is about without hashing or storing the secret itself, and is
    scanner-independent, so Gitleaks/Trivy/Semgrep reports of the same line share one fingerprint.
    """
    return re.sub(r"""(["'`]).*?\1""", "", line)
