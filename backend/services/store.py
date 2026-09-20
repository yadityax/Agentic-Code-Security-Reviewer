"""Persistence helpers for scans, findings, tool runs and the audit trail."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.db import AuditEvent, FindingRow, Remediation, Repository, Scan, ToolRun
from backend.models.finding import Finding
from backend.services.db import session_scope


async def start_scan(
    repo: str,
    *,
    delivery_id: str | None,
    pr_number: int | None,
    head_sha: str | None,
    base_sha: str | None,
    meta: dict[str, Any] | None = None,
) -> tuple[str, bool]:
    """Create a scan row. Returns (scan_id, should_run).

    A redelivered webhook (same delivery id) must be idempotent: a completed scan is not repeated,
    a failed or interrupted one is retried on the same row.
    """
    async with session_scope() as s:
        if delivery_id:
            prev = (
                await s.execute(select(Scan).where(Scan.delivery_id == delivery_id))
            ).scalar_one_or_none()
            if prev:
                if prev.status == "completed":
                    return prev.id, False
                await s.execute(delete(FindingRow).where(FindingRow.scan_id == prev.id))
                prev.status, prev.started_at, prev.finished_at = "running", datetime.now(UTC), None
                return prev.id, True
        r = (
            await s.execute(select(Repository).where(Repository.full_name == repo))
        ).scalar_one_or_none()
        if not r:
            r = Repository(full_name=repo)
            s.add(r)
            await s.flush()
        scan = Scan(
            repo_id=r.id,
            delivery_id=delivery_id,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            summary={"pr": meta or {}},
        )
        s.add(scan)
        await s.flush()
        return scan.id, True


async def audit(
    scan_id: str | None, actor: str, action: str, detail: dict[str, Any] | None = None
) -> None:
    async with session_scope() as s:
        s.add(AuditEvent(scan_id=scan_id, actor=actor, action=action, detail=detail or {}))


async def record_tool_run(
    scan_id: str, tool: str, *, error: str | None, duration_s: float, findings: int
) -> None:
    async with session_scope() as s:
        s.add(
            ToolRun(
                scan_id=scan_id,
                tool=tool,
                status="error" if error else "ok",
                duration_s=duration_s,
                findings_count=findings,
                error=error,
            )
        )


async def save_findings(scan_id: str, findings: list[Finding]) -> None:
    async with session_scope() as s:
        for f in findings:
            s.add(FindingRow(
                scan_id=scan_id, finding_id=f.id, fingerprint=f.fingerprint, scanners=[f.scanner, *f.also_detected_by],
                rule_ids=[f.rule_id, *f.merged_rule_ids], file=f.file, line=f.line, severity=f.severity.value,
                cwe=f.cwe, owasp=f.owasp, title=f.title, evidence=f.evidence,
                status=(f.analysis.verdict.value if f.analysis else f.status.value), pr_scope=f.pr_scope.value,
                model_confidence=f.analysis.confidence if f.analysis else None,
                analysis=f.analysis.model_dump(mode="json") if f.analysis else {},
            ))  # fmt: skip


async def finish_scan(
    scan_id: str, *, status: str, latency_s: float, usage: dict[str, float], summary: dict[str, Any]
) -> None:
    async with session_scope() as s:
        scan = await s.get(Scan, scan_id)
        assert scan is not None
        scan.status, scan.latency_s = status, latency_s
        scan.finished_at = datetime.now(UTC)
        scan.llm_requests = int(usage.get("requests", 0))
        scan.llm_prompt_tokens = int(usage.get("prompt_tokens", 0))
        scan.llm_completion_tokens = int(usage.get("completion_tokens", 0))
        scan.llm_cost_usd = float(usage.get("cost_usd", 0))
        scan.summary = {**(scan.summary or {}), **summary}


async def save_remediation(
    scan_id: str, fingerprint: str, *, attempt: int, status: str, patch: str, rationale: str,
    verification: dict[str, Any], files: dict[str, str] | None = None, finding: Finding | None = None, pr_url: str | None = None,
) -> None:  # fmt: skip
    async with session_scope() as s:
        s.add(Remediation(
            scan_id=scan_id, fingerprint=fingerprint, attempt=attempt, status=status, patch=patch, rationale=rationale,
            verification=verification, files=files or {}, pr_url=pr_url,
            finding_id=finding.id if finding else None, title=finding.title[:500] if finding else "",
            cwe=finding.cwe if finding else None, file_path=finding.file if finding else None, line=finding.line if finding else None,
        ))  # fmt: skip


async def verified_remediations(scan_id: str) -> list[Remediation]:
    """The latest verified remediation per finding, in the order they were created (i.e. applied)."""
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(Remediation)
                    .where(Remediation.scan_id == scan_id, Remediation.status == "verified")
                    .order_by(Remediation.id)
                )
            )
            .scalars()
            .all()
        )
        latest = {r.fingerprint: r for r in rows}
        return list(latest.values())


async def mark_remediations(
    ids: list[int], *, status: str, approved_by: str | None = None, pr_url: str | None = None
) -> None:
    async with session_scope() as s:
        for r in (await s.execute(select(Remediation).where(Remediation.id.in_(ids)))).scalars():
            r.status = status
            if approved_by:
                r.approved_by, r.approved_at = approved_by, datetime.now(UTC)
            if pr_url:
                r.pr_url = pr_url


async def list_scans(session: AsyncSession, limit: int = 50) -> list[Scan]:
    return list(
        (
            await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(limit))
        ).scalars()
    )
