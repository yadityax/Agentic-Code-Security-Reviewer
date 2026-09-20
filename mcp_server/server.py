"""Internal MCP server. Narrow, typed, audited tools instead of an unrestricted shell for the LLM."""

import argparse
import asyncio
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from backend.services.workspace import detect_languages
from mcp_server import dev_tools, github_tools, security_tools
from mcp_server.context import ToolContext
from mcp_server.policy import COMMENT, DEFAULT_GROUPS, EXEC, READ, REPO_WRITE, SCAN, ToolPolicy
from mcp_server.workspaces import WorkspaceInfo

ALL_GROUPS = {READ, SCAN, EXEC, COMMENT, REPO_WRITE}


def build_server(ctx: ToolContext) -> MCPServer:
    mcp = MCPServer("acsr-security-tools")
    github_tools.register(mcp, ctx)
    security_tools.register(mcp, ctx)
    dev_tools.register(mcp, ctx)
    return mcp


def policy_from_settings(*, comments: bool, repo_write: bool) -> ToolPolicy:
    groups = set(DEFAULT_GROUPS)
    if comments:
        groups.add(COMMENT)
    if repo_write:
        groups.add(REPO_WRITE)
    return ToolPolicy(frozenset(groups))


def main() -> None:
    """stdio entrypoint: `python -m mcp_server --workspace PATH [--allow comment,repo_write]`."""
    ap = argparse.ArgumentParser(prog="mcp_server")
    ap.add_argument("--workspace", type=Path, help="register this directory as workspace 'default'")
    ap.add_argument("--allow", default="", help="extra privilege groups: comment,repo_write")
    args = ap.parse_args()
    extra = {g for g in args.allow.split(",") if g in ALL_GROUPS}
    ctx = ToolContext(policy=ToolPolicy(frozenset(DEFAULT_GROUPS | extra)))
    if args.workspace:
        root = args.workspace.resolve()
        ctx.registry.register(WorkspaceInfo(root, [], {}, detect_languages(root)), "default")
    asyncio.run(build_server(ctx).run_stdio_async())


if __name__ == "__main__":
    main()
