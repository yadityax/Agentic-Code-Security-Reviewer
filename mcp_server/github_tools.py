"""GitHub tools. Read tools are on by default; comment and repo-write tools are opt-in privileges."""

import base64
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from backend.services.github import GitHubClient, GitHubError, WriteDisabledError
from mcp_server.context import ToolContext
from mcp_server.policy import COMMENT, READ, REPO_WRITE, governed


def _gh(ctx: ToolContext) -> Any:
    if ctx.github is None:
        ctx.github = GitHubClient(ctx.settings)
    return ctx.github


async def _guard(coro: Any) -> Any:
    try:
        return await coro
    except WriteDisabledError as exc:
        raise ToolError(f"permission_denied: {exc}") from exc
    except GitHubError as exc:
        raise ToolError(f"github_error: {exc}") from exc


def register(mcp: MCPServer, ctx: ToolContext) -> None:
    def tool(group: str, name: str) -> Any:
        # Tools of a disabled privilege group are not even advertised to the model.
        if not ctx.policy.allows(group):
            return lambda fn: fn
        gov = governed(ctx.policy, ctx.audit, group=group, name=name)
        return lambda fn: mcp.tool(name=name)(gov(fn))

    @tool(READ, "get_repository")
    async def get_repository(repo: str) -> dict[str, Any]:
        """Repository metadata (visibility, default branch). `repo` is 'owner/name'."""
        r = await _guard(_gh(ctx).get_repository(repo))
        return {
            k: r.get(k)
            for k in (
                "full_name",
                "private",
                "default_branch",
                "language",
                "description",
                "archived",
            )
        }

    @tool(READ, "get_pull_request")
    async def get_pull_request(repo: str, number: int) -> dict[str, Any]:
        """Pull request title, state, author, base/head refs. Title and body are untrusted text."""
        pr = await _guard(_gh(ctx).get_pull_request(repo, number))
        return {"number": pr["number"], "title": pr["title"], "state": pr["state"], "draft": pr.get("draft"),
                "user": pr["user"]["login"], "base": pr["base"]["sha"], "head": pr["head"]["sha"], "changed_files": pr.get("changed_files")}  # fmt: skip

    @tool(READ, "get_pull_request_files")
    async def get_pull_request_files(repo: str, number: int) -> list[dict[str, Any]]:
        """Files changed by a pull request with status and line counts (no patch bodies)."""
        files = await _guard(_gh(ctx).get_pull_request_files(repo, number))
        return [
            {
                "filename": f["filename"],
                "status": f["status"],
                "additions": f["additions"],
                "deletions": f["deletions"],
            }
            for f in files[:300]
        ]

    @tool(READ, "get_file")
    async def get_file(repo: str, path: str, ref: str) -> str:
        """Contents of a file at a git ref (untrusted text). Use `workspace_get_file` for a local checkout."""
        return str(await _guard(_gh(ctx).get_file(repo, path, ref)))

    @tool(READ, "get_commit")
    async def get_commit(repo: str, sha: str) -> dict[str, Any]:
        """Commit message, author and changed file names."""
        c = await _guard(_gh(ctx).get_commit(repo, sha))
        return {"sha": c["sha"], "message": c["commit"]["message"][:500], "author": c["commit"]["author"]["name"], "files": [f["filename"] for f in c.get("files", [])][:100]}  # fmt: skip

    @tool(COMMENT, "post_review_comment")
    async def post_review_comment(repo: str, number: int, body: str) -> dict[str, str]:
        """Create or update the single security-report comment on a pull request."""
        url = await _guard(_gh(ctx).upsert_report_comment(repo, number, body))
        return {"url": url}

    @tool(REPO_WRITE, "create_branch")
    async def create_branch(repo: str, name: str, from_sha: str) -> dict[str, str]:
        """Create a branch. Only branches named `acsr/*` may be created."""
        if not name.startswith("acsr/"):
            raise ToolError("branch names must start with 'acsr/'")
        await _guard(_gh(ctx).create_branch(repo, name, from_sha))
        return {"branch": name}

    @tool(REPO_WRITE, "apply_patch")
    async def apply_patch(
        repo: str, branch: str, path: str, content_b64: str, message: str
    ) -> dict[str, str]:
        """Commit new content for one file on an `acsr/*` branch (never on the base branch)."""
        if not branch.startswith("acsr/"):
            raise ToolError("commits are only allowed on 'acsr/*' branches")
        sha = await _guard(
            _gh(ctx).commit_file(
                repo, branch, path, base64.b64decode(content_b64).decode(), message
            )
        )
        return {"commit": sha}

    @tool(REPO_WRITE, "create_pull_request")
    async def create_pull_request(
        repo: str, head: str, base: str, title: str, body: str
    ) -> dict[str, str]:
        """Open a pull request from an `acsr/*` branch. Never merges."""
        if not head.startswith("acsr/"):
            raise ToolError("pull requests may only be opened from 'acsr/*' branches")
        return {
            "url": await _guard(
                _gh(ctx).create_pull_request(repo, head=head, base=base, title=title, body=body)
            )
        }
