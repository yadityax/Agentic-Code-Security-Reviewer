"""Repository ingestion: materialize a PR (or any two refs) and work out which lines changed."""

import asyncio
import re
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from backend.models.finding import Finding, PRScope, normalize_path

LineRanges = dict[str, list[tuple[int, int]]]

SCANNABLE_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


@dataclass
class Workspace:
    root: Path
    base_sha: str | None = None
    head_sha: str | None = None
    changed_files: list[str] = field(default_factory=list)
    changed_lines: LineRanges = field(default_factory=dict)
    languages: set[str] = field(default_factory=set)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


async def _git(cwd: Path, *args: str, token: str | None = None) -> str:
    cmd = ["git"]
    if token:  # passed as a header, never written into the remote URL or into a sandbox
        cmd += ["-c", f"http.extraHeader=Authorization: Bearer {token}"]
    proc = await asyncio.create_subprocess_exec(
        *cmd, *args, cwd=cwd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(cwd)},
    )  # fmt: skip
    out, err = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {err.decode(errors='replace')[:300]}")
    return out.decode(errors="replace")


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_changed_lines(diff: str) -> LineRanges:
    """Parse `git diff -U0` output into {path: [(start, end), ...]} on the new side."""
    result: LineRanges = {}
    current: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = (
                None if line == "+++ /dev/null" else normalize_path(line[4:].removeprefix("b/"))
            )
        elif current and (m := HUNK_RE.match(line)):
            start, count = int(m[1]), int(m[2]) if m[2] is not None else 1
            if count > 0:
                result.setdefault(current, []).append((start, start + count - 1))
    return result


def detect_languages(root: Path, files: Sequence[str] | None = None) -> set[str]:
    ext = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
           ".jsx": "javascript", ".go": "go", ".java": "java", ".rb": "ruby"}  # fmt: skip
    paths = [root / f for f in files] if files else [
        p for p in root.rglob("*") if p.is_file() and not SCANNABLE_SKIP_DIRS & set(p.parts)
    ]  # fmt: skip
    langs = {ext[p.suffix] for p in paths if p.suffix in ext}
    names = {p.name for p in paths}
    if "Dockerfile" in names or any(n.startswith("Dockerfile") for n in names):
        langs.add("docker")
    if "requirements.txt" in names or "pyproject.toml" in names:
        langs.add("python")
    return langs


async def prepare_from_git(
    clone_url: str, base_sha: str, head_sha: str, *, token: str | None = None,
    head_clone_url: str | None = None,
) -> Workspace:  # fmt: skip
    """Clone a repo, fetch the PR head (possibly from a fork) and check it out."""
    root = Path(tempfile.mkdtemp(prefix="acsr-ws-"))
    try:
        await _git(root, "clone", "--quiet", "--no-checkout", clone_url, ".", token=token)
        if head_clone_url and head_clone_url != clone_url:
            await _git(root, "fetch", "--quiet", head_clone_url, head_sha, token=token)
        await _git(root, "checkout", "--quiet", "--detach", head_sha)
        return await describe_changes(root, base_sha, head_sha)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


async def describe_changes(root: Path, base_sha: str, head_sha: str) -> Workspace:
    diff = await _git(
        root, "diff", "-U0", "--no-color", "--diff-filter=AM", f"{base_sha}...{head_sha}"
    )
    lines = parse_changed_lines(diff)
    files = sorted(lines)
    return Workspace(
        root=root, base_sha=base_sha, head_sha=head_sha, changed_files=files,
        changed_lines=lines, languages=detect_languages(root),
    )  # fmt: skip


def tag_pr_scope(findings: list[Finding], changed_lines: LineRanges) -> list[Finding]:
    """Mark findings that touch changed lines as NEW, everything else EXISTING (decision D2)."""
    out = []
    for f in findings:
        ranges = changed_lines.get(normalize_path(f.file), [])
        end = f.end_line or f.line
        hit = any(f.line <= hi and end >= lo for lo, hi in ranges)
        out.append(f.model_copy(update={"pr_scope": PRScope.NEW if hit else PRScope.EXISTING}))
    return out
