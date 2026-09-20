"""Execution tools (privilege: exec). They run the repository's own code, so: throwaway copy of the
workspace, container with no network, non-root user, memory/CPU/pid limits and a hard timeout."""

import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from backend.services.sandbox import (
    TEST_RUNNER_IMAGE,
    Mount,
    SandboxResult,
    SandboxSpec,
    run_sandboxed,
)
from mcp_server.context import ToolContext
from mcp_server.policy import EXEC, governed


async def run_in_sandbox_copy(
    root: Path, command: list[str], *, timeout_s: int, extra_files: dict[str, str] | None = None
) -> SandboxResult:
    """Copy the workspace (minus .git), run `python -m <command>` offline, then discard the copy."""
    tmp = Path(tempfile.mkdtemp(prefix="acsr-run-"))
    try:
        work = tmp / "w"
        shutil.copytree(
            root,
            work,
            ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "node_modules"),
            symlinks=True,
        )
        for rel, content in (extra_files or {}).items():
            (work / rel).write_text(content)
        return await run_sandboxed(SandboxSpec(
            image=TEST_RUNNER_IMAGE, entrypoint="python", command=command, workdir="/work", timeout_s=timeout_s,
            mounts=[Mount(work, "/work", read_only=False)], memory="1g", cpus=1.0, pids=256, network=False,
            env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/work", "PYTHONHASHSEED": "0"},
        ))  # fmt: skip
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


PYTEST_SUMMARY = re.compile(r"(\d+) (passed|failed|error|errors|skipped|xfailed|deselected)")


def summarize_pytest(out: str) -> dict[str, int]:
    tail = "\n".join(out.strip().splitlines()[-4:])
    counts: dict[str, int] = {}
    for n, kind in PYTEST_SUMMARY.findall(tail):
        counts["errors" if kind == "error" else kind] = counts.get(kind, 0) + int(n)
    return counts


def register(mcp: MCPServer, ctx: ToolContext) -> None:
    if not ctx.policy.allows(EXEC):
        return

    def tool(name: str) -> Any:
        return lambda fn: mcp.tool(name=name)(
            governed(ctx.policy, ctx.audit, group=EXEC, name=name)(fn)
        )

    @tool("run_tests")
    async def run_tests(
        workspace_id: str, path: str = "tests", timeout_s: int = 120
    ) -> dict[str, Any]:
        """Run pytest on a throwaway copy of the workspace with no network. Returns pass/fail counts and output tail."""
        ws = ctx.registry.get(workspace_id)
        ctx.registry.safe_path(workspace_id, path)  # validates the path stays inside the workspace
        res = await run_in_sandbox_copy(
            ws.root,
            ["-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", path],
            timeout_s=min(timeout_s, 600),
        )
        counts = summarize_pytest(res.stdout + res.stderr)
        return {"exit_code": res.exit_code, "passed": res.exit_code == 0, "timed_out": res.timed_out, "counts": counts,
                "duration_s": round(res.duration_s, 2), "output_tail": (res.stdout + res.stderr)[-1500:]}  # fmt: skip

    @tool("run_linter")
    async def run_linter(workspace_id: str, timeout_s: int = 60) -> dict[str, Any]:
        """ruff, restricted to errors that mean broken code (syntax errors, undefined names). Not a style check."""
        ws = ctx.registry.get(workspace_id)
        res = await run_in_sandbox_copy(
            ws.root,
            [
                "-m",
                "ruff",
                "check",
                "--select",
                "E9,F63,F7,F82",
                "--no-cache",
                "--output-format",
                "concise",
                ".",
            ],
            timeout_s=timeout_s,
        )
        return {
            "exit_code": res.exit_code,
            "clean": res.exit_code == 0,
            "timed_out": res.timed_out,
            "output_tail": (res.stdout + res.stderr)[-1500:],
        }

    @tool("build_project")
    async def build_project(workspace_id: str, timeout_s: int = 60) -> dict[str, Any]:
        """Byte-compile every Python file (catches syntax errors). Container image builds are out of scope."""
        ws = ctx.registry.get(workspace_id)
        res = await run_in_sandbox_copy(
            ws.root,
            ["-m", "compileall", "-q", "-x", r"(\.venv|node_modules)", "."],
            timeout_s=timeout_s,
        )
        return {
            "exit_code": res.exit_code,
            "ok": res.exit_code == 0,
            "timed_out": res.timed_out,
            "output_tail": (res.stdout + res.stderr)[-1000:],
        }
