"""Minimal GitHub REST client. Write methods are gated by explicit settings flags."""

import base64
from typing import Any

import httpx

from backend.config import Settings, get_settings

REPORT_MARKER = "<!-- acsr-security-report -->"


class GitHubError(RuntimeError):
    pass


class WriteDisabledError(GitHubError):
    pass


class GitHubClient:
    def __init__(self, settings: Settings | None = None, http: httpx.AsyncClient | None = None):
        self.s = settings or get_settings()
        token = self.s.github_token.get_secret_value()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "agentic-security-reviewer"}  # fmt: skip
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = http or httpx.AsyncClient(
            base_url=self.s.github_api_url, headers=headers, timeout=30
        )

    async def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = await self._http.request(method, path, **kw)
        if r.status_code >= 400:
            raise GitHubError(f"{method} {path} -> {r.status_code}: {r.text[:200]}")
        return r.json() if r.content else None

    # --- read -------------------------------------------------------------------------------
    async def get_repository(self, repo: str) -> dict[str, Any]:
        return dict(await self._req("GET", f"/repos/{repo}"))

    async def get_pull_request(self, repo: str, number: int) -> dict[str, Any]:
        return dict(await self._req("GET", f"/repos/{repo}/pulls/{number}"))

    async def get_pull_request_files(self, repo: str, number: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for page in range(1, 11):
            batch = await self._req("GET", f"/repos/{repo}/pulls/{number}/files",
                                    params={"per_page": 100, "page": page})  # fmt: skip
            out += batch
            if len(batch) < 100:
                break
        return out

    async def get_file(self, repo: str, path: str, ref: str) -> str:
        data = await self._req("GET", f"/repos/{repo}/contents/{path}", params={"ref": ref})
        return base64.b64decode(data["content"]).decode(errors="replace")

    async def get_commit(self, repo: str, sha: str) -> dict[str, Any]:
        return dict(await self._req("GET", f"/repos/{repo}/commits/{sha}"))

    # --- comments (gated by post_pr_comments) -------------------------------------------------
    async def upsert_report_comment(self, repo: str, number: int, body: str) -> str:
        """Create or update our single report comment so re-scans don't spam the PR."""
        if not self.s.post_pr_comments:
            raise WriteDisabledError("post_pr_comments is disabled")
        comments = await self._req(
            "GET", f"/repos/{repo}/issues/{number}/comments", params={"per_page": 100}
        )
        for c in comments:
            if REPORT_MARKER in (c.get("body") or ""):
                res = await self._req(
                    "PATCH", f"/repos/{repo}/issues/comments/{c['id']}", json={"body": body}
                )
                return str(res["html_url"])
        res = await self._req(
            "POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body}
        )
        return str(res["html_url"])

    # --- remediation writes (gated by allow_github_write) --------------------------------------
    def _require_write(self) -> None:
        if not self.s.allow_github_write:
            raise WriteDisabledError(
                "allow_github_write is disabled; remediation writes are blocked"
            )

    async def create_branch(self, repo: str, name: str, from_sha: str) -> None:
        self._require_write()
        await self._req(
            "POST", f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{name}", "sha": from_sha}
        )

    async def commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> str:
        self._require_write()
        sha = None
        try:
            existing = await self._req(
                "GET", f"/repos/{repo}/contents/{path}", params={"ref": branch}
            )
            sha = existing["sha"]
        except GitHubError:
            pass
        body: dict[str, Any] = {"message": message, "branch": branch,
                                "content": base64.b64encode(content.encode()).decode()}  # fmt: skip
        if sha:
            body["sha"] = sha
        res = await self._req("PUT", f"/repos/{repo}/contents/{path}", json=body)
        return str(res["commit"]["sha"])

    async def create_pull_request(
        self, repo: str, *, head: str, base: str, title: str, body: str
    ) -> str:
        self._require_write()
        res = await self._req("POST", f"/repos/{repo}/pulls",
                              json={"title": title, "head": head, "base": base, "body": body})  # fmt: skip
        return str(res["html_url"])

    async def aclose(self) -> None:
        await self._http.aclose()


class OfflineGitHub:
    """Drop-in for GitHubClient when GITHUB_OFFLINE=true: no network, comments are only recorded."""

    def __init__(self) -> None:
        self.comments: list[tuple[str, int, str]] = []

    async def get_repository(self, repo: str) -> dict[str, Any]:
        return {"full_name": repo, "private": False}

    async def upsert_report_comment(self, repo: str, number: int, body: str) -> str:
        self.comments.append((repo, number, body))
        return f"offline://{repo}/pull/{number}#report"

    async def aclose(self) -> None: ...
