from dataclasses import dataclass, field
from typing import Any

from backend.config import Settings, get_settings
from backend.services.github import GitHubClient
from backend.services.registry import build_adapters
from backend.services.scanners.base import ScannerAdapter
from mcp_server.policy import AuditLog, ToolPolicy
from mcp_server.workspaces import WorkspaceRegistry


@dataclass
class ToolContext:
    policy: ToolPolicy
    registry: WorkspaceRegistry = field(default_factory=WorkspaceRegistry)
    audit: AuditLog = field(default_factory=AuditLog)
    settings: Settings = field(default_factory=get_settings)
    github: GitHubClient | Any | None = None
    adapters: dict[str, ScannerAdapter] = field(default_factory=build_adapters)
    scanner_timeout_s: int = 300
