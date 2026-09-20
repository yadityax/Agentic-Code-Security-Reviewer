"""Code-context retrieval for the analyst: the function around a finding, imports, and callers."""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from backend.models.finding import Finding, normalize_path
from backend.services.redact import redact_secrets
from backend.services.scanners.common import enclosing_span

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


@dataclass
class CodeContext:
    text: str  # numbered, redacted source
    first_line: int
    last_line: int
    imports: str = ""
    callers: list[str] = field(default_factory=list)

    def has_line(self, n: int) -> bool:
        return self.first_line <= n <= self.last_line


def _numbered(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + i:>4} | {redact_secrets(ln)}" for i, ln in enumerate(lines))


def _imports(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, OSError, ValueError):
        return ""
    out = []
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            out.append(ast.unparse(node))
    return "; ".join(out[:14])


def _callers(root: Path, symbol: str, own_file: str, limit: int = 2) -> list[str]:
    pat = re.compile(rf"\b{re.escape(symbol)}\s*\(")
    found: list[str] = []
    for p in sorted(root.rglob("*.py")):
        if SKIP_DIRS & set(p.parts) or len(found) >= limit:
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        rel = str(p.relative_to(root))
        for i, ln in enumerate(lines):
            if pat.search(ln) and not ln.lstrip().startswith(("def ", "async def ", "class ")):
                lo = max(i - 1, 0)
                found.append(f"{rel}:{i + 1}\n" + _numbered(lines[lo : i + 2], lo + 1))
                break
    return found


def build_context(root: Path, f: Finding, max_lines: int = 50) -> CodeContext:
    path = root / normalize_path(f.file)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return CodeContext("(file unavailable)", f.line, f.line)
    span = enclosing_span(root, f.file, f.line)
    lo, hi = (span[0], span[1]) if span else (max(f.line - 15, 1), min(f.line + 15, len(lines)))
    if hi - lo + 1 > max_lines:  # long function: window around the finding
        lo = max(lo, f.line - max_lines // 2)
        hi = min(hi, lo + max_lines - 1)
    ctx = CodeContext(_numbered(lines[lo - 1 : hi], lo), lo, hi, _imports(path))
    if span:
        ctx.callers = _callers(root, span[2], f.file)
    return ctx
