"""Scan job queue. The webhook depends on the ScanQueue protocol, not on Redis."""

from typing import Protocol

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from pydantic import BaseModel

from backend.config import get_settings


class ScanRequest(BaseModel):
    delivery_id: str
    repo: str
    pr_number: int
    head_sha: str
    base_sha: str
    head_repo: str  # differs from `repo` for PRs opened from forks
    head_ref: str = ""  # branch name of the PR head (target for remediation PRs)
    base_ref: str = ""


class ScanQueue(Protocol):
    async def enqueue(self, req: ScanRequest) -> bool:
        """Queue a scan. Returns False if this delivery was already queued."""
        ...


class ArqScanQueue:
    def __init__(self) -> None:
        self._pool: ArqRedis | None = None

    async def enqueue(self, req: ScanRequest) -> bool:
        if self._pool is None:
            self._pool = await create_pool(RedisSettings.from_dsn(get_settings().redis_url))
        # Using the delivery id as the job id makes GitHub redeliveries idempotent.
        job = await self._pool.enqueue_job(
            "scan_pull_request", req.model_dump(), _job_id=req.delivery_id
        )
        return job is not None


_queue = ArqScanQueue()


def get_queue() -> ScanQueue:
    return _queue
