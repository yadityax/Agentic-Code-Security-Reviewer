import subprocess
import uuid
from pathlib import Path

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import select

from backend.config import get_settings
from backend.models.db import AuditEvent, FindingRow, Scan, ToolRun
from backend.services.db import session_scope
from backend.services.github import REPORT_MARKER
from backend.worker import _pg_dsn, scan_pull_request
from tests.fakes import FakeGitHub, FakeLLM

pytestmark = pytest.mark.integration

BASE_APP = """import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def old_lookup():
    uid = request.args.get("id")
    conn = sqlite3.connect("db")
    return str(conn.execute("SELECT * FROM t WHERE id = '%s'" % uid).fetchall())
"""
HEAD_ADD = """

@app.route("/ping")
def new_ping():
    import subprocess

    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
"""


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin", "HOME": str(cwd)}).stdout.strip()  # fmt: skip


@pytest.fixture
def origin(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "acme" / "shop.git"
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text(BASE_APP)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")  # noqa: E702
    base = git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text(BASE_APP + HEAD_ADD)
    git(repo, "commit", "-qam", "add ping endpoint")
    head = git(repo, "rev-parse", "HEAD")
    for p in tmp_path.rglob("*"):
        p.chmod(p.stat().st_mode | 0o055)
    return tmp_path, base, head


async def test_pull_request_scan_end_to_end(
    migrated_db: None,
    docker_ok: None,
    origin: tuple[Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, base, head = origin
    monkeypatch.setenv("GIT_BASE_URL", f"file://{root}")
    monkeypatch.setenv("ENABLE_CODEQL", "false")  # covered separately; keeps this test fast
    get_settings.cache_clear()
    gh, llm = FakeGitHub(), FakeLLM()
    raw = {
        "delivery_id": f"d-{head[:8]}",
        "repo": "acme/shop",
        "pr_number": 5,
        "head_sha": head,
        "base_sha": base,
        "head_repo": "acme/shop",
    }

    async with AsyncPostgresSaver.from_conn_string(_pg_dsn(get_settings().database_url)) as cp:
        await cp.setup()
        out = await scan_pull_request({"github": gh, "llm": llm, "checkpointer": cp}, raw)
        # LangGraph persisted a checkpoint for this scan's thread
        ckpt = await cp.aget_tuple({"configurable": {"thread_id": out["scan_id"]}})
        assert ckpt is not None and "report_md" in ckpt.checkpoint["channel_values"]

    assert out["comment"] and gh.comments
    repo, pr, body = gh.comments[0]
    assert (repo, pr) == ("acme/shop", 5) and REPORT_MARKER in body
    assert "CWE-78" in body  # the finding on the PR's added lines is reported
    assert "1 pre-existing finding" in body  # old_lookup SQLi was not introduced by the PR

    # a redelivered webhook for a completed scan is skipped: no second scan, no second comment
    again = await scan_pull_request({"github": gh, "llm": llm}, raw)
    assert again == {"scan_id": out["scan_id"], "skipped": True} and len(gh.comments) == 1

    async with session_scope() as s:
        scan = (await s.execute(select(Scan).where(Scan.id == out["scan_id"]))).scalar_one()
        assert scan.status == "completed" and scan.llm_requests >= 1 and scan.pr_number == 5
        rows = (
            (await s.execute(select(FindingRow).where(FindingRow.scan_id == scan.id)))
            .scalars()
            .all()
        )
        scopes = {(r.cwe, r.pr_scope) for r in rows}
        assert ("CWE-78", "new") in scopes and ("CWE-89", "existing") in scopes
        assert all(r.status in ("true_positive", "needs_review", "false_positive") for r in rows)
        tools = {
            t.tool
            for t in (await s.execute(select(ToolRun).where(ToolRun.scan_id == scan.id))).scalars()
        }
        assert {"semgrep", "gitleaks"} <= tools
        actions = [
            a.action
            for a in (
                await s.execute(select(AuditEvent).where(AuditEvent.scan_id == scan.id))
            ).scalars()
        ]
        assert {
            "scan_started",
            "plan",
            "scan_complete",
            "correlate",
            "analyze",
            "report_posted",
        } <= set(actions)


async def test_failed_scan_is_recorded_and_retried_on_redelivery(migrated_db: None) -> None:
    """Failed scans are recorded, not lost, and a redelivery retries the same row instead of crashing."""
    gh, llm = FakeGitHub(), FakeLLM()
    raw = {
        "delivery_id": f"d-fail-{uuid.uuid4().hex[:8]}",
        "repo": "nope/none",
        "pr_number": 1,
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "head_repo": "nope/none",
    }
    with pytest.raises(RuntimeError):
        await scan_pull_request({"github": gh, "llm": llm}, raw)
    async with session_scope() as s:
        scan = (
            await s.execute(select(Scan).where(Scan.delivery_id == raw["delivery_id"]))
        ).scalar_one()
        assert scan.status == "failed"
        actions = [
            a.action
            for a in (
                await s.execute(select(AuditEvent).where(AuditEvent.scan_id == scan.id))
            ).scalars()
        ]
        assert "scan_failed" in actions
        first_id = scan.id
    with pytest.raises(RuntimeError):  # GitHub redelivers the same delivery id
        await scan_pull_request({"github": gh, "llm": llm}, raw)
    async with session_scope() as s:
        rows = (
            (await s.execute(select(Scan).where(Scan.delivery_id == raw["delivery_id"])))
            .scalars()
            .all()
        )
        assert [r.id for r in rows] == [first_id]  # retried on the same row
