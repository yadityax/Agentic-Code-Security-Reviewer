"""Client-side access to the MCP server. Agents use these adapters, never the scanner classes directly."""

import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server.mcpserver import MCPServer

from backend.models.finding import Finding
from backend.services.scanners.base import ScanContext, ScanOutput
from mcp_server.security_tools import SCANNER_TOOLS
from mcp_server.workspaces import WorkspaceRegistry

TOOL_FOR_SCANNER = {v: k for k, v in SCANNER_TOOLS.items()}


class ToolCallError(RuntimeError):
    pass


class MCPTools:
    def __init__(self, client: Client) -> None:
        self._c = client

    async def names(self) -> set[str]:
        return {t.name for t in (await self._c.list_tools()).tools}

    async def call(self, name: str, /, **args: Any) -> Any:
        res = await self._c.call_tool(name, args)
        text = "".join(getattr(c, "text", "") for c in res.content)
        if res.is_error:
            raise ToolCallError(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


@asynccontextmanager
async def connect(server: MCPServer) -> AsyncIterator[MCPTools]:
    async with Client(server) as client:
        yield MCPTools(client)


class MCPScannerAdapter:
    """Implements the ScannerAdapter protocol by calling the corresponding MCP tool."""

    def __init__(
        self, scanner: str, tools: MCPTools, registry: WorkspaceRegistry, workspace_id: str
    ) -> None:
        self.name = scanner
        self._tools, self._registry, self._wid = tools, registry, workspace_id

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        try:
            data = await self._tools.call(TOOL_FOR_SCANNER[self.name], workspace_id=self._wid)
        except Exception as exc:
            return ScanOutput(
                self.name, [], time.monotonic() - start, error=f"mcp: {str(exc)[:200]}"
            )
        return ScanOutput(
            self.name,
            [Finding.model_validate(f) for f in data["findings"]],
            data["duration_s"],
            error=data.get("error"),
            artifacts=data.get("artifacts") or {},
        )


def mcp_adapters(
    tools: MCPTools, registry: WorkspaceRegistry, workspace_id: str, names: set[str]
) -> dict[str, MCPScannerAdapter]:
    return {
        n: MCPScannerAdapter(n, tools, registry, workspace_id)
        for n in names
        if n in TOOL_FOR_SCANNER
    }


def root_of(registry: WorkspaceRegistry, workspace_id: str) -> Path:
    return registry.get(workspace_id).root
