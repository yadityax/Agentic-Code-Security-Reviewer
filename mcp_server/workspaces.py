"""Workspace registry. The model refers to workspaces by opaque id; it never supplies host paths."""

import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

MAX_FILE_BYTES = 200_000


@dataclass
class WorkspaceInfo:
    root: Path
    changed_files: list[str]
    changed_lines: dict[str, list[tuple[int, int]]]
    languages: set[str]
    base_sha: str | None = None
    head_sha: str | None = None
    repo: str | None = None


class WorkspaceRegistry:
    def __init__(self) -> None:
        self._ws: dict[str, WorkspaceInfo] = {}

    def register(self, info: WorkspaceInfo, workspace_id: str | None = None) -> str:
        wid = workspace_id or uuid.uuid4().hex[:12]
        info.root = info.root.resolve()
        self._ws[wid] = info
        return wid

    def get(self, wid: str) -> WorkspaceInfo:
        if wid not in self._ws:
            raise ToolError(f"unknown workspace '{wid}'")
        return self._ws[wid]

    def safe_path(self, wid: str, rel: str) -> Path:
        """Resolve `rel` inside the workspace, rejecting traversal and symlinks that escape the root."""
        root = self.get(wid).root
        if not rel or rel.startswith(("/", "~")) or "\x00" in rel:
            raise ToolError("invalid path")
        target = Path(os.path.realpath(root / rel))
        if not target.is_relative_to(root):
            raise ToolError("path escapes the workspace")
        return target

    def read_text(self, wid: str, rel: str) -> str:
        p = self.safe_path(wid, rel)
        if not p.is_file():
            raise ToolError(f"not a file: {rel}")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ToolError(f"file too large (> {MAX_FILE_BYTES} bytes)")
        return p.read_text(errors="replace")

    def drop(self, wid: str) -> None:
        self._ws.pop(wid, None)
