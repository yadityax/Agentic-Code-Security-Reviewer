import base64
import json
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from backend.services.mcp_client import ToolCallError, connect
from mcp_server.context import ToolContext
from mcp_server.policy import COMMENT, DEFAULT_GROUPS, REPO_WRITE, ToolPolicy, truncate
from mcp_server.server import build_server, policy_from_settings
from mcp_server.workspaces import WorkspaceInfo


class FakeGitHub:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get_repository(self, repo: str) -> dict[str, Any]:
        self.calls.append("get_repository")
        return {
            "full_name": repo,
            "private": False,
            "default_branch": "main",
            "token": "SHOULD-NOT-LEAK",
        }

    async def upsert_report_comment(self, repo: str, n: int, body: str) -> str:
        self.calls.append("comment")
        return "https://x/c"

    async def create_branch(self, repo: str, name: str, sha: str) -> None:
        self.calls.append(f"branch:{name}")

    async def create_pull_request(self, repo: str, **kw: Any) -> str:
        self.calls.append("pr")
        return "https://x/pr"


def make(
    groups: frozenset[str] = DEFAULT_GROUPS, tmp_path: Path | None = None
) -> tuple[ToolContext, str]:
    ctx = ToolContext(policy=ToolPolicy(groups), github=FakeGitHub(), adapters={})
    root = tmp_path or Path("/tmp")
    wid = ctx.registry.register(WorkspaceInfo(root, ["app.py"], {}, {"python"}))
    return ctx, wid


async def names(ctx: ToolContext) -> set[str]:
    async with connect(build_server(ctx)) as t:
        return await t.names()


async def test_default_policy_hides_write_tools() -> None:
    ctx, _ = make()
    n = await names(ctx)
    assert {"get_repository", "run_semgrep", "run_tests", "workspace_get_file"} <= n
    assert not n & {"post_review_comment", "create_branch", "apply_patch", "create_pull_request"}


async def test_write_tools_appear_only_when_enabled() -> None:
    ctx, _ = make(policy_from_settings(comments=True, repo_write=False).groups)
    n = await names(ctx)
    assert "post_review_comment" in n and "create_pull_request" not in n
    ctx2, _ = make(policy_from_settings(comments=True, repo_write=True).groups)
    assert {"create_branch", "apply_patch", "create_pull_request"} <= await names(ctx2)


async def test_write_tool_refuses_when_policy_disabled_even_if_called_directly(
    tmp_path: Path,
) -> None:
    from mcp_server.policy import AuditLog, governed

    audit = AuditLog()

    @governed(ToolPolicy(DEFAULT_GROUPS), audit, group=REPO_WRITE, name="create_branch")
    async def create_branch() -> str:
        raise AssertionError("must never run")

    with pytest.raises(Exception, match="permission_denied"):
        await create_branch()
    assert audit.records[-1].status == "denied"


async def test_branch_and_commit_restricted_to_acsr_namespace() -> None:
    ctx, _ = make(policy_from_settings(comments=False, repo_write=True).groups)
    async with connect(build_server(ctx)) as t:
        with pytest.raises(ToolCallError, match="acsr/"):
            await t.call("create_branch", repo="o/r", name="main", from_sha="abc")
        with pytest.raises(ToolCallError, match="acsr/"):
            await t.call(
                "apply_patch",
                repo="o/r",
                branch="main",
                path="a.py",
                content_b64=base64.b64encode(b"x").decode(),
                message="m",
            )
        with pytest.raises(ToolCallError, match="acsr/"):
            await t.call(
                "create_pull_request", repo="o/r", head="feature", base="main", title="t", body="b"
            )
        assert (await t.call("create_branch", repo="o/r", name="acsr/fix-1", from_sha="abc")) == {
            "branch": "acsr/fix-1"
        }
    assert ctx.github.calls == ["branch:acsr/fix-1"]  # type: ignore[union-attr]


async def test_get_repository_returns_only_whitelisted_fields() -> None:
    ctx, _ = make()
    async with connect(build_server(ctx)) as t:
        out = await t.call("get_repository", repo="o/r")
    assert "token" not in out and out["default_branch"] == "main"


async def test_workspace_path_escape_is_blocked(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n")
    (tmp_path / "secret.txt").write_text("outside")
    (root / "link").symlink_to(tmp_path / "secret.txt")
    ctx, wid = make(tmp_path=root)
    async with connect(build_server(ctx)) as t:
        assert "x = 1" in await t.call("workspace_get_file", workspace_id=wid, path="ok.py")
        for bad in ("../secret.txt", "/etc/passwd", "link", "~/.ssh/id_rsa", "a/../../secret.txt"):
            with pytest.raises(ToolCallError):
                await t.call("workspace_get_file", workspace_id=wid, path=bad)
        with pytest.raises(ToolCallError, match="unknown workspace"):
            await t.call("workspace_get_file", workspace_id="nope", path="ok.py")


async def test_audit_log_records_calls_and_redacts_secrets(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x=1\n")
    ctx, wid = make(tmp_path=tmp_path)
    async with connect(build_server(ctx)) as t:
        await t.call("workspace_get_file", workspace_id=wid, path="a.py")
        await t.call("get_repository", repo="o/AKIAZ5QW7NRTKLM4PXV2")
    tools = [(r.tool, r.status) for r in ctx.audit.records]
    assert tools == [("workspace_get_file", "ok"), ("get_repository", "ok")]
    assert "AKIAZ5QW7NRTKLM4PXV2" not in json.dumps([r.args for r in ctx.audit.records])


async def test_file_contents_are_redacted_when_read_through_the_tool(tmp_path: Path) -> None:
    (tmp_path / "c.py").write_text('KEY = "AKIAZ5QW7NRTKLM4PXV2"\n')
    ctx, wid = make(tmp_path=tmp_path)
    async with connect(build_server(ctx)) as t:
        out = await t.call("workspace_get_file", workspace_id=wid, path="c.py")
    assert "AKIAZ5QW7NRTKLM4PXV2" not in out


def test_truncate_marks_cut_output() -> None:
    assert truncate("x" * 100, 10).endswith("[truncated 90 chars]")


async def test_security_guidance_tool() -> None:
    ctx, _ = make()
    async with connect(build_server(ctx)) as t:
        assert "SQL injection" in await t.call("security_guidance", cwe="CWE-89")


async def test_raw_mcp_client_sees_the_same_tool_list() -> None:
    ctx, _ = make(frozenset({COMMENT} | DEFAULT_GROUPS))
    async with Client(build_server(ctx)) as c:
        listed = {t.name for t in (await c.list_tools()).tools}
    assert "post_review_comment" in listed
