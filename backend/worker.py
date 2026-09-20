"""arq worker: consumes scan jobs queued by the webhook. Run with `arq backend.worker.WorkerSettings`."""

import time
import traceback
from typing import Any

from arq.connections import RedisSettings
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from backend.config import get_settings
from backend.graph.remediation import RemediationConfig
from backend.graph.workflow import Deps, run_scan
from backend.services import store, telemetry
from backend.services.github import GitHubClient, GitHubError, OfflineGitHub, WriteDisabledError
from backend.services.llm import LLMClient, RedisCache
from backend.services.mcp_client import connect, mcp_adapters
from backend.services.queue import ScanRequest
from backend.services.registry import build_adapters
from backend.services.report import render_remediation_section
from backend.services.verification import Verifier
from backend.services.workspace import prepare_from_git
from mcp_server.context import ToolContext
from mcp_server.policy import AuditLog, AuditRecord
from mcp_server.server import build_server, policy_from_settings
from mcp_server.workspaces import WorkspaceInfo


def _pg_dsn(url: str) -> str:
    return url.replace("+asyncpg", "").replace("+psycopg", "")


async def startup(ctx: dict[str, Any]) -> None:
    telemetry.setup_telemetry("acsr-worker")
    s = get_settings()
    if s.metrics_port:
        from prometheus_client import start_http_server

        start_http_server(s.metrics_port)
    cm = AsyncPostgresSaver.from_conn_string(_pg_dsn(s.database_url))
    ctx["_cp_cm"] = cm
    ctx["checkpointer"] = await cm.__aenter__()
    await ctx["checkpointer"].setup()


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["_cp_cm"].__aexit__(None, None, None)


async def scan_pull_request(ctx: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    req = ScanRequest.model_validate(raw)
    s = get_settings()
    gh = ctx.get("github") or (
        OfflineGitHub() if s.github_offline else GitHubClient(s)
    )  # injectable for tests
    llm = ctx.get("llm") or LLMClient(cache=RedisCache(s.redis_url))
    scan_id, should_run = await store.start_scan(
        req.repo,
        delivery_id=req.delivery_id,
        pr_number=req.pr_number,
        head_sha=req.head_sha,
        base_sha=req.base_sha,
        meta={"head_ref": req.head_ref, "base_ref": req.base_ref, "head_repo": req.head_repo},
    )
    if not should_run:  # redelivered webhook for a scan that already completed
        await store.audit(
            scan_id, "worker", "duplicate_delivery_skipped", {"delivery": req.delivery_id}
        )
        return {"scan_id": scan_id, "skipped": True}
    started = time.monotonic()
    ws = None
    try:
        await store.audit(
            scan_id,
            "worker",
            "scan_started",
            {"repo": req.repo, "pr": req.pr_number, "head": req.head_sha},
        )
        repo_info = await gh.get_repository(req.repo)
        token = s.github_token.get_secret_value() if repo_info.get("private") else None
        base = s.git_base_url.rstrip("/")
        ws = await prepare_from_git(
            f"{base}/{req.repo}.git", req.base_sha, req.head_sha, token=token,
            head_clone_url=f"{base}/{req.head_repo}.git" if req.head_repo != req.repo else None,
        )  # fmt: skip
        names = {"semgrep", "gitleaks", "trivy", "syft"} | (
            {"codeql"} if s.enable_codeql else set()
        )
        if s.use_mcp:
            result, comment_url = await _scan_via_mcp(
                s, gh, llm, ws, req, scan_id, names, ctx.get("checkpointer")
            )
        else:
            deps = Deps(
                llm=llm,
                adapters=build_adapters(names),
                persist=True,
                enable_codeql=s.enable_codeql,
                discover=s.enable_discovery,
                scanner_timeout_s=s.scanner_timeout_s,
            )
            result = await run_scan(
                deps,
                ws.root,
                changed_lines=ws.changed_lines,
                changed_files=ws.changed_files,
                scan_id=scan_id,
                checkpointer=ctx.get("checkpointer"),
            )
            comment_url = await _post_report(gh, req, result, scan_id)
        return {"scan_id": scan_id, "findings": len(result.findings), "comment": comment_url}
    except Exception as exc:
        telemetry.SCANS.labels("failed").inc()
        await store.audit(
            scan_id,
            "worker",
            "scan_failed",
            {
                "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                "trace": traceback.format_exc()[-800:],
            },
        )
        await store.finish_scan(
            scan_id,
            status="failed",
            latency_s=time.monotonic() - started,
            usage={},
            summary={"error": str(exc)[:300]},
        )
        raise
    finally:
        if ws:
            ws.cleanup()
        await gh.aclose()
        await llm.aclose()


async def _post_report(gh: Any, req: ScanRequest, result: Any, scan_id: str) -> str | None:
    try:
        url = str(
            await gh.upsert_report_comment(req.repo, req.pr_number, _report_body(result, scan_id))
        )
        await store.audit(scan_id, "github_agent", "report_posted", {"url": url})
        return url
    except (GitHubError, WriteDisabledError) as exc:
        await store.audit(scan_id, "github_agent", "report_not_posted", {"reason": str(exc)[:200]})
        return None


def _report_body(result: Any, scan_id: str) -> str:
    return (
        str(result.report_md)
        + render_remediation_section(result.remediations)
        + f"\n<sub>scan `{scan_id}` · {result.latency_s:.0f}s</sub>"
    )


async def _scan_via_mcp(
    s: Any,
    gh: Any,
    llm: Any,
    ws: Any,
    req: ScanRequest,
    scan_id: str,
    names: set[str],
    checkpointer: Any,
) -> tuple[Any, str | None]:
    """Agents reach every scanner (and the PR comment) only through the MCP server."""

    async def sink(rec: AuditRecord) -> None:
        await store.audit(
            scan_id,
            "mcp",
            f"tool:{rec.tool}",
            {
                "group": rec.group,
                "status": rec.status,
                "duration_s": round(rec.duration_s, 2),
                "args": rec.args,
            },
        )

    tctx = ToolContext(
        policy=policy_from_settings(comments=s.post_pr_comments, repo_write=s.allow_github_write),
        settings=s,
        github=gh,
        scanner_timeout_s=s.scanner_timeout_s,
    )
    tctx.audit = AuditLog(sink=sink)
    wid = tctx.registry.register(
        WorkspaceInfo(
            ws.root,
            ws.changed_files,
            ws.changed_lines,
            ws.languages,
            ws.base_sha,
            ws.head_sha,
            req.repo,
        )
    )
    async with connect(build_server(tctx)) as tools:
        deps = Deps(
            llm=llm,
            adapters=mcp_adapters(tools, tctx.registry, wid, names),
            persist=True,
            enable_codeql=s.enable_codeql,
            discover=s.enable_discovery,
            scanner_timeout_s=s.scanner_timeout_s,
        )
        verifier: Verifier | None = None
        if s.enable_remediation:
            # Fix only what the PR introduced; verification runs through the same MCP tools.
            verifier = Verifier(tools, tctx.registry, names, [], require_tests=True)
            deps.remediation = RemediationConfig(
                verifier, max_targets=s.remediation_max_targets, only_new=True
            )
        try:
            result = await run_scan(
                deps,
                ws.root,
                changed_lines=ws.changed_lines,
                changed_files=ws.changed_files,
                scan_id=scan_id,
                checkpointer=checkpointer,
            )
        finally:
            if verifier:
                verifier.cleanup()
        comment_url = None
        if "post_review_comment" in await tools.names():
            try:
                out = await tools.call(
                    "post_review_comment",
                    repo=req.repo,
                    number=req.pr_number,
                    body=_report_body(result, scan_id),
                )
                comment_url = out["url"]
                await store.audit(scan_id, "github_agent", "report_posted", {"url": comment_url})
            except Exception as exc:
                await store.audit(
                    scan_id, "github_agent", "report_not_posted", {"reason": str(exc)[:200]}
                )
        else:
            await store.audit(
                scan_id,
                "github_agent",
                "report_not_posted",
                {"reason": "post_review_comment not enabled"},
            )
    return result, comment_url


class WorkerSettings:
    functions = [scan_pull_request]  # noqa: RUF012
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    job_timeout = get_settings().scan_job_timeout_s
    max_jobs = 2
    keep_result = 3600
