"""Tool permissions and the audit trail. Least privilege: only read/scan tools are on by default."""

import functools
import inspect
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

from backend.services.redact import redact_secrets

MAX_OUTPUT_CHARS = 30_000

# Privilege groups, from safest to most dangerous.
READ = "read"  # inspect GitHub and workspace files
SCAN = "scan"  # run scanners on a workspace (sandboxed, offline)
EXEC = "exec"  # execute the repository's own code (tests/lint/build) in a network-less sandbox
COMMENT = "comment"  # post PR review comments
REPO_WRITE = "repo_write"  # create branches, commits and pull requests

DEFAULT_GROUPS = frozenset({READ, SCAN, EXEC})


@dataclass(frozen=True)
class ToolPolicy:
    groups: frozenset[str] = DEFAULT_GROUPS

    def allows(self, group: str) -> bool:
        return group in self.groups

    def require(self, group: str, tool: str) -> None:
        if not self.allows(group):
            raise ToolError(
                f"permission_denied: tool '{tool}' needs the '{group}' privilege, which is not enabled"
            )


@dataclass
class AuditRecord:
    ts: float
    tool: str
    group: str
    args: dict[str, Any]
    status: str
    duration_s: float
    detail: str = ""


@dataclass
class AuditLog:
    records: list[AuditRecord] = field(default_factory=list)
    sink: Callable[[AuditRecord], Awaitable[None]] | None = None  # e.g. persist to Postgres

    async def record(self, rec: AuditRecord) -> None:
        self.records.append(rec)
        if self.sink:
            await self.sink(rec)


def _safe_args(kwargs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in kwargs.items():
        s = v if isinstance(v, int | float | bool | type(None)) else redact_secrets(str(v))
        out[k] = s if not isinstance(s, str) or len(s) <= 200 else s[:200] + "…"
    return out


def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    return (
        text if len(text) <= limit else text[:limit] + f"\n…[truncated {len(text) - limit} chars]"
    )


def tool_json(obj: Any) -> str:
    return truncate(json.dumps(obj, default=str))


def governed(
    policy: ToolPolicy, audit: AuditLog, *, group: str, name: str
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[str]]]:
    """Decorator: enforce the privilege group, audit every call (with secrets redacted), cap output size."""

    def deco(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[str]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> str:
            start = time.monotonic()
            status, detail = "ok", ""
            try:
                policy.require(group, name)
                result = await fn(*args, **kwargs)
                return (
                    result
                    if isinstance(result, str) and len(result) <= MAX_OUTPUT_CHARS
                    else tool_json(result)
                    if not isinstance(result, str)
                    else truncate(result)
                )
            except ToolError as exc:
                status, detail = (
                    "denied" if "permission_denied" in str(exc) else "error",
                    str(exc)[:200],
                )
                raise
            except Exception as exc:
                status, detail = "error", f"{type(exc).__name__}: {str(exc)[:200]}"
                raise
            finally:
                await audit.record(
                    AuditRecord(
                        time.time(),
                        name,
                        group,
                        _safe_args(kwargs),
                        status,
                        time.monotonic() - start,
                        detail,
                    )
                )

        # advertise the real return type: the wrapper always returns capped JSON text
        wrapper.__signature__ = inspect.signature(fn).replace(return_annotation=str)  # type: ignore[attr-defined]
        return wrapper

    return deco
