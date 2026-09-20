"""Scanner tools (privilege: scan) and read-only workspace inspection tools (privilege: read)."""

import json
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from backend.models.finding import Finding
from backend.services.knowledge import guidance_text
from backend.services.scanners.base import ScanContext
from mcp_server.context import ToolContext
from mcp_server.policy import MAX_OUTPUT_CHARS, READ, SCAN, governed

SCANNER_TOOLS = {
    "run_semgrep": "semgrep", "run_gitleaks": "gitleaks", "run_codeql": "codeql",
    "run_trivy": "trivy", "generate_sbom": "syft",
}  # fmt: skip


def compact(findings: list[Finding], limit: int = MAX_OUTPUT_CHARS - 2000) -> list[dict[str, Any]]:
    """Findings as dicts, shrunk until the JSON fits the output cap (never truncated mid-JSON)."""
    for evidence_len in (1500, 500, 150, 0):
        rows = [
            f.model_dump(mode="json") | {"evidence": f.evidence[:evidence_len]} for f in findings
        ]
        if len(json.dumps(rows)) <= limit:
            return rows
    return rows[: max(1, limit // 600)]


def register(mcp: MCPServer, ctx: ToolContext) -> None:
    def tool(group: str, name: str) -> Any:
        if not ctx.policy.allows(group):
            return lambda fn: fn
        return lambda fn: mcp.tool(name=name)(
            governed(ctx.policy, ctx.audit, group=group, name=name)(fn)
        )

    async def run_scanner(tool_name: str, workspace_id: str) -> dict[str, Any]:
        ws = ctx.registry.get(workspace_id)
        adapter = ctx.adapters.get(SCANNER_TOOLS[tool_name])
        if adapter is None:
            raise ToolError(f"scanner for {tool_name} is not installed")
        out = await adapter.run(
            ScanContext(
                root=ws.root,
                changed_files=ws.changed_files,
                languages=ws.languages,
                timeout_s=ctx.scanner_timeout_s,
            )
        )
        return {"scanner": out.scanner, "duration_s": round(out.duration_s, 2), "error": out.error, "count": len(out.findings),
                "findings": compact(out.findings), "artifacts": out.artifacts}  # fmt: skip

    @tool(SCAN, "run_semgrep")
    async def run_semgrep(workspace_id: str) -> dict[str, Any]:
        """Semgrep pattern/taint analysis (offline rules). Returns normalized findings."""
        return await run_scanner("run_semgrep", workspace_id)

    @tool(SCAN, "run_gitleaks")
    async def run_gitleaks(workspace_id: str) -> dict[str, Any]:
        """Secret detection over the working tree. Secret values are redacted."""
        return await run_scanner("run_gitleaks", workspace_id)

    @tool(SCAN, "run_codeql")
    async def run_codeql(workspace_id: str) -> dict[str, Any]:
        """CodeQL data-flow analysis (Python/JavaScript). Slowest scanner (~10-60 s)."""
        return await run_scanner("run_codeql", workspace_id)

    @tool(SCAN, "run_trivy")
    async def run_trivy(workspace_id: str) -> dict[str, Any]:
        """Dependency CVEs, Dockerfile/IaC misconfiguration and secrets (offline vulnerability DB)."""
        return await run_scanner("run_trivy", workspace_id)

    @tool(SCAN, "generate_sbom")
    async def generate_sbom(workspace_id: str) -> dict[str, Any]:
        """CycloneDX SBOM (component list) for the workspace."""
        return await run_scanner("generate_sbom", workspace_id)

    # ---- read-only workspace inspection ------------------------------------------------------
    @tool(READ, "workspace_info")
    async def workspace_info(workspace_id: str) -> dict[str, Any]:
        """Languages and changed files of a prepared workspace."""
        ws = ctx.registry.get(workspace_id)
        return {
            "languages": sorted(ws.languages),
            "changed_files": ws.changed_files[:200],
            "repo": ws.repo,
            "head": ws.head_sha,
            "base": ws.base_sha,
        }

    @tool(READ, "workspace_get_file")
    async def workspace_get_file(
        workspace_id: str, path: str, start_line: int = 1, end_line: int = 400
    ) -> str:
        """Numbered lines of a file in the workspace (untrusted text). Paths cannot leave the workspace."""
        from backend.services.redact import redact_secrets

        text = ctx.registry.read_text(workspace_id, path)
        lines = text.splitlines()[max(start_line, 1) - 1 : min(end_line, start_line + 799)]
        return "\n".join(
            f"{start_line + i:>4} | {redact_secrets(ln)}" for i, ln in enumerate(lines)
        )

    @tool(READ, "workspace_list_files")
    async def workspace_list_files(workspace_id: str, subdir: str = ".") -> list[str]:
        """Relative file paths under a directory of the workspace (max 500)."""
        root = ctx.registry.get(workspace_id).root
        base = root if subdir in (".", "") else ctx.registry.safe_path(workspace_id, subdir)
        skip = {".git", "node_modules", ".venv", "__pycache__"}
        return [
            str(p.relative_to(root))
            for p in sorted(base.rglob("*"))
            if p.is_file() and not skip & set(p.parts)
        ][:500]

    @tool(READ, "security_guidance")
    async def security_guidance(cwe: str) -> str:
        """Curated guidance for a CWE: when it is exploitable, when it is not, and the typical fix."""
        return guidance_text(cwe) or f"no curated guidance for {cwe}"
