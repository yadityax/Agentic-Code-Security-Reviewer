"""Read API for the dashboard plus the human-approval endpoint. Everything here requires the admin token."""

import hmac
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select

from backend.config import Settings, get_settings
from backend.models.db import AuditEvent, FindingRow, Remediation, Repository, Scan, ToolRun
from backend.services import store
from backend.services.db import session_scope
from backend.services.github import GitHubClient
from backend.services.mcp_client import connect
from backend.services.pr_agent import FixSummary, open_remediation_pr
from mcp_server.context import ToolContext
from mcp_server.policy import AuditLog, AuditRecord
from mcp_server.server import build_server, policy_from_settings

router = APIRouter(prefix="/api")


def require_token(request: Request, settings: Annotated[Settings, Depends(get_settings)]) -> None:
    expected = settings.admin_api_token.get_secret_value()
    if not expected:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "API disabled: ADMIN_API_TOKEN is not configured"
        )
    auth = request.headers.get("authorization", "")
    if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], expected)):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


Auth = Depends(require_token)


def _scan_dict(s: Scan, repo: str, counts: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "id": s.id, "repo": repo, "pr_number": s.pr_number, "head_sha": s.head_sha, "status": s.status,
        "started_at": s.started_at, "finished_at": s.finished_at, "latency_s": s.latency_s,
        "llm_requests": s.llm_requests, "llm_tokens": s.llm_prompt_tokens + s.llm_completion_tokens, "llm_cost_usd": s.llm_cost_usd,
        "summary": s.summary, "counts": counts or {},
    }  # fmt: skip


@router.get("/scans", dependencies=[Auth])
async def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(Scan, Repository.full_name)
                .join(Repository, Repository.id == Scan.repo_id)
                .order_by(Scan.started_at.desc())
                .limit(min(limit, 200))
            )
        ).all()
        counts: dict[str, dict[str, int]] = {}
        ids = [r[0].id for r in rows]
        if ids:
            for scan_id, sev, n in (
                await s.execute(
                    select(FindingRow.scan_id, FindingRow.severity, func.count())
                    .where(FindingRow.scan_id.in_(ids), FindingRow.status != "false_positive")
                    .group_by(FindingRow.scan_id, FindingRow.severity)
                )
            ).all():
                counts.setdefault(scan_id, {})[sev] = n
        return [_scan_dict(sc, repo, counts.get(sc.id)) for sc, repo in rows]


@router.get("/scans/{scan_id}", dependencies=[Auth])
async def get_scan(scan_id: str) -> dict[str, Any]:
    async with session_scope() as s:
        row = (
            await s.execute(
                select(Scan, Repository.full_name)
                .join(Repository, Repository.id == Scan.repo_id)
                .where(Scan.id == scan_id)
            )
        ).first()
        if not row:
            raise HTTPException(404, "scan not found")
        findings = (
            (
                await s.execute(
                    select(FindingRow)
                    .where(FindingRow.scan_id == scan_id)
                    .order_by(FindingRow.id if hasattr(FindingRow, "id") else FindingRow.pk)
                )
            )
            .scalars()
            .all()
        )
        tools = (await s.execute(select(ToolRun).where(ToolRun.scan_id == scan_id))).scalars().all()
        return {
            **_scan_dict(row[0], row[1]),
            "findings": [{"id": f.finding_id, "fingerprint": f.fingerprint, "file": f.file, "line": f.line, "severity": f.severity, "cwe": f.cwe, "owasp": f.owasp,
                          "title": f.title, "evidence": f.evidence, "status": f.status, "pr_scope": f.pr_scope, "confidence": f.model_confidence,
                          "scanners": f.scanners, "rule_ids": f.rule_ids, "analysis": f.analysis} for f in findings],
            "tool_runs": [{"tool": t.tool, "status": t.status, "duration_s": t.duration_s, "findings": t.findings_count, "error": t.error} for t in tools],
        }  # fmt: skip


@router.get("/scans/{scan_id}/audit", dependencies=[Auth])
async def scan_audit(scan_id: str) -> list[dict[str, Any]]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(AuditEvent).where(AuditEvent.scan_id == scan_id).order_by(AuditEvent.id)
                )
            )
            .scalars()
            .all()
        )
        return [
            {"id": e.id, "ts": e.ts, "actor": e.actor, "action": e.action, "detail": e.detail}
            for e in rows
        ]


@router.get("/scans/{scan_id}/remediations", dependencies=[Auth])
async def scan_remediations(scan_id: str) -> list[dict[str, Any]]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(Remediation)
                    .where(Remediation.scan_id == scan_id)
                    .order_by(Remediation.id)
                )
            )
            .scalars()
            .all()
        )
        return [{"id": r.id, "fingerprint": r.fingerprint, "attempt": r.attempt, "status": r.status, "title": r.title, "cwe": r.cwe, "file": r.file_path,
                 "line": r.line, "patch": r.patch, "rationale": r.rationale, "verification": r.verification, "approved_by": r.approved_by, "pr_url": r.pr_url,
                 "created_at": r.created_at} for r in rows]  # fmt: skip


async def _group_counts(session: Any, column: Any, *where: Any) -> dict[str, int]:
    rows = (
        await session.execute(select(column, func.count()).where(*where).group_by(column))
    ).all()
    return {str(k): int(n) for k, n in rows}


@router.get("/stats", dependencies=[Auth])
async def stats() -> dict[str, Any]:
    async with session_scope() as s:
        done = (
            await s.execute(
                select(
                    func.count(),
                    func.avg(Scan.latency_s),
                    func.sum(Scan.llm_prompt_tokens + Scan.llm_completion_tokens),
                    func.sum(Scan.llm_cost_usd),
                ).where(Scan.status == "completed")
            )
        ).one()
        return {
            "scans_completed": done[0],
            "avg_latency_s": done[1],
            "llm_tokens": int(done[2] or 0),
            "llm_cost_usd": float(done[3] or 0.0),
            "findings_by_verdict": await _group_counts(s, FindingRow.status),
            "findings_by_severity": await _group_counts(
                s, FindingRow.severity, FindingRow.status != "false_positive"
            ),
            "remediations_by_status": await _group_counts(s, Remediation.status),
        }


class ApproveBody(BaseModel):
    approved_by: str


def get_github(settings: Annotated[Settings, Depends(get_settings)]) -> Any:
    return GitHubClient(settings)


@router.post("/scans/{scan_id}/remediations/approve", dependencies=[Auth])
async def approve_remediations(
    scan_id: str,
    body: ApproveBody,
    settings: Annotated[Settings, Depends(get_settings)],
    gh: Annotated[Any, Depends(get_github)],
) -> dict[str, Any]:
    """Human approval gate: only now does a verified fix become a branch, commits and a pull request."""
    if not settings.allow_github_write:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "GitHub writes are disabled (ALLOW_GITHUB_WRITE=false)"
        )
    if not body.approved_by.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "approved_by is required")
    async with session_scope() as s:
        row = (
            await s.execute(
                select(Scan, Repository.full_name)
                .join(Repository, Repository.id == Scan.repo_id)
                .where(Scan.id == scan_id)
            )
        ).first()
    if not row:
        raise HTTPException(404, "scan not found")
    scan, repo = row
    pr_meta = (scan.summary or {}).get("pr", {})
    if pr_meta.get("head_repo") not in (None, repo):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the pull request comes from a fork; a remediation branch cannot be created",
        )
    rems = [r for r in await store.verified_remediations(scan_id)]
    if not rems:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "no verified remediations awaiting approval for this scan"
        )
    fixes = [
        FixSummary(
            r.finding_id or "",
            r.title,
            r.cwe,
            r.file_path or "",
            r.line,
            r.patch,
            r.rationale,
            r.files,
            r.verification,
        )
        for r in rems
    ]

    async def sink(rec: AuditRecord) -> None:
        await store.audit(
            scan_id,
            "mcp",
            f"tool:{rec.tool}",
            {"group": rec.group, "status": rec.status, "args": rec.args},
        )

    ctx = ToolContext(
        policy=policy_from_settings(comments=False, repo_write=True), settings=settings, github=gh
    )
    ctx.audit = AuditLog(sink=sink)
    await store.audit(
        scan_id,
        f"human:{body.approved_by.strip()[:60]}",
        "remediation_approved",
        {"fixes": len(fixes)},
    )
    async with connect(build_server(ctx)) as tools:
        try:
            url = await open_remediation_pr(
                tools,
                repo=repo,
                base_ref=pr_meta.get("head_ref") or "main",
                from_sha=scan.head_sha or "",
                scan_id=scan_id,
                source_pr=scan.pr_number,
                fixes=fixes,
            )
        except Exception as exc:
            await store.audit(
                scan_id, "github_agent", "remediation_pr_failed", {"error": str(exc)[:300]}
            )
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, f"could not open the pull request: {str(exc)[:200]}"
            ) from exc
    await store.mark_remediations(
        [r.id for r in rems], status="pr_opened", approved_by=body.approved_by.strip(), pr_url=url
    )
    await store.audit(scan_id, "github_agent", "remediation_pr_opened", {"url": url})
    return {"pr_url": url, "fixes": len(fixes)}
