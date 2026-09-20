import uuid
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from backend.api.dashboard import get_github
from backend.config import Settings, get_settings
from backend.main import app
from backend.models.db import AuditEvent, Remediation, Repository, Scan
from backend.services.db import session_scope

pytestmark = pytest.mark.integration
TOKEN = "test-admin-token"
FIXED = 'db.execute("SELECT * FROM t WHERE n = ?", (name,))'


class FakeGH:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def create_branch(self, repo: str, name: str, from_sha: str) -> None:
        self.calls.append(("branch", {"repo": repo, "name": name, "sha": from_sha}))

    async def commit_file(
        self, repo: str, branch: str, path: str, content: str, message: str
    ) -> str:
        self.calls.append(
            ("commit", {"branch": branch, "path": path, "content": content, "message": message})
        )
        return "c" * 40

    async def create_pull_request(
        self, repo: str, *, head: str, base: str, title: str, body: str
    ) -> str:
        self.calls.append(("pr", {"head": head, "base": base, "title": title, "body": body}))
        return f"https://github.test/{repo}/pull/99"


async def seed(*, head_repo: str = "acme/shop", verified: bool = True) -> str:
    async with session_scope() as s:
        repo = Repository(full_name=f"acme/shop-{uuid.uuid4().hex[:6]}")
        s.add(repo)
        await s.flush()
        repo_name = repo.full_name
        scan = Scan(repo_id=repo.id, pr_number=7, head_sha="h" * 40, base_sha="b" * 40, status="completed",
                    summary={"pr": {"head_ref": "feature/x", "base_ref": "main", "head_repo": repo_name if head_repo == "acme/shop" else head_repo}})  # fmt: skip
        s.add(scan)
        await s.flush()
        s.add(Remediation(scan_id=scan.id, fingerprint="fp1", attempt=1, status="verified" if verified else "failed", finding_id="f1",
                          title="SQL injection", cwe="CWE-89", file_path="app.py", line=12, patch="-old\n+new", rationale="bind the parameter",
                          files={"app.py": f"x = 1\n{FIXED}\n"},
                          verification={"build": {"ok": True}, "lint": {"clean": True}, "tests": {"passed": True, "counts": {"passed": 3}},
                                        "rescan": {"original_finding_gone": True, "new_findings": 0}}))  # fmt: skip
        return scan.id


@pytest.fixture
def client_factory(migrated_db: None):  # type: ignore[no-untyped-def]
    gh = FakeGH()

    def make(**settings: Any) -> httpx.AsyncClient:
        token = settings.pop("token", TOKEN)  # evaluated once, not per request
        cfg = Settings(admin_api_token=SecretStr(token), **settings)
        app.dependency_overrides[get_settings] = lambda: cfg
        app.dependency_overrides[get_github] = lambda: gh
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    yield make, gh
    app.dependency_overrides.clear()


def auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_api_is_disabled_without_a_configured_token(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, _ = client_factory
    async with make(token="") as c:
        assert (await c.get("/api/scans")).status_code == 503
        assert (
            await c.post("/api/scans/x/remediations/approve", json={"approved_by": "a"})
        ).status_code == 503


async def test_bad_or_missing_token_is_rejected(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, _ = client_factory
    async with make() as c:
        for headers in ({}, auth("wrong"), {"Authorization": "Basic abc"}):
            assert (await c.get("/api/scans", headers=headers)).status_code == 401
        assert (await c.get("/api/scans", headers=auth())).status_code == 200


async def test_approval_is_blocked_while_github_writes_are_disabled(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, gh = client_factory
    scan_id = await seed()
    async with make(allow_github_write=False) as c:
        r = await c.post(
            f"/api/scans/{scan_id}/remediations/approve",
            json={"approved_by": "alice"},
            headers=auth(),
        )
    assert r.status_code == 409 and gh.calls == []


async def test_approval_opens_a_pr_on_an_acsr_branch_and_records_who_approved(
    client_factory,
) -> None:  # type: ignore[no-untyped-def]
    make, gh = client_factory
    scan_id = await seed()
    async with make(allow_github_write=True) as c:
        r = await c.post(
            f"/api/scans/{scan_id}/remediations/approve",
            json={"approved_by": "alice"},
            headers=auth(),
        )
        assert r.status_code == 200 and r.json()["pr_url"].endswith("/pull/99")
        kinds = [k for k, _ in gh.calls]
        assert kinds == ["branch", "commit", "pr"]
        branch = gh.calls[0][1]["name"]
        assert branch.startswith("acsr/fix-") and gh.calls[1][1]["branch"] == branch
        pr = gh.calls[2][1]
        assert (
            pr["head"] == branch and pr["base"] == "feature/x"
        )  # merges into the PR's own branch, never main directly
        assert (
            "tests pass (3 passed)" in pr["body"]
            and "never merged automatically" in pr["body"]
            and "Rotate" not in pr["body"]
        )
        assert gh.calls[1][1]["content"].endswith(FIXED + "\n")

        again = await c.post(
            f"/api/scans/{scan_id}/remediations/approve",
            json={"approved_by": "alice"},
            headers=auth(),
        )
        assert again.status_code == 409  # nothing left awaiting approval; no duplicate PR
        assert [k for k, _ in gh.calls].count("pr") == 1

    async with session_scope() as s:
        rem = (
            await s.execute(select(Remediation).where(Remediation.scan_id == scan_id))
        ).scalar_one()
        assert rem.status == "pr_opened" and rem.approved_by == "alice" and rem.pr_url
        actions = [
            (a.actor, a.action)
            for a in (
                await s.execute(select(AuditEvent).where(AuditEvent.scan_id == scan_id))
            ).scalars()
        ]
        assert ("human:alice", "remediation_approved") in actions
        assert ("mcp", "tool:create_pull_request") in actions and (
            "github_agent",
            "remediation_pr_opened",
        ) in actions


async def test_unverified_fixes_can_never_be_approved(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, gh = client_factory
    scan_id = await seed(verified=False)
    async with make(allow_github_write=True) as c:
        r = await c.post(
            f"/api/scans/{scan_id}/remediations/approve",
            json={"approved_by": "alice"},
            headers=auth(),
        )
    assert r.status_code == 409 and gh.calls == []


async def test_prs_from_forks_are_refused(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, gh = client_factory
    scan_id = await seed(head_repo="attacker/fork")
    async with make(allow_github_write=True) as c:
        r = await c.post(
            f"/api/scans/{scan_id}/remediations/approve",
            json={"approved_by": "alice"},
            headers=auth(),
        )
    assert r.status_code == 409 and "fork" in r.json()["detail"] and gh.calls == []


async def test_approver_name_is_required(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, gh = client_factory
    scan_id = await seed()
    async with make(allow_github_write=True) as c:
        r = await c.post(
            f"/api/scans/{scan_id}/remediations/approve", json={"approved_by": "  "}, headers=auth()
        )
    assert r.status_code == 422 and gh.calls == []


async def test_read_endpoints_expose_scan_detail_and_audit(client_factory) -> None:  # type: ignore[no-untyped-def]
    make, _ = client_factory
    scan_id = await seed()
    async with make() as c:
        detail = (await c.get(f"/api/scans/{scan_id}", headers=auth())).json()
        assert detail["id"] == scan_id and detail["pr_number"] == 7
        rems = (await c.get(f"/api/scans/{scan_id}/remediations", headers=auth())).json()
        assert rems[0]["status"] == "verified" and rems[0]["verification"]["tests"]["passed"]
        assert (await c.get("/api/scans/nope", headers=auth())).status_code == 404
        stats = (await c.get("/api/stats", headers=auth())).json()
        assert "findings_by_verdict" in stats and stats["scans_completed"] >= 1
