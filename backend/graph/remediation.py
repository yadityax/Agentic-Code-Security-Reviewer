"""Remediation subgraph: propose -> verify -> retry (bounded) -> record, one finding at a time.

Patches accumulate: each verified fix becomes the base for the next target, so later fixes are verified
against the code as it will actually be merged.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langgraph.graph import END

from backend.models.finding import Finding, FindingStatus, PRScope
from backend.services import store, telemetry
from backend.services.llm import BudgetExceededError, LLMClient, LLMError
from backend.services.remediation import AppliedPatch, eligible, propose_patch
from backend.services.verification import Verifier

AuditFn = Callable[[Any, str, str, dict[str, Any] | None], Awaitable[None]]


@dataclass
class RemediationConfig:
    verifier: Verifier
    max_attempts: int = 3  # bounded retry loop
    max_targets: int = 5
    only_new: bool = False  # True: only fix findings introduced by the PR


def _by_id(state: Any) -> dict[str, Finding]:
    return {f["id"]: Finding.model_validate(f) for f in state.get("findings", [])}


def select_targets(findings: list[Finding], cfg: RemediationConfig) -> list[Finding]:
    cands = [
        f for f in findings if eligible(f) and not (cfg.only_new and f.pr_scope == PRScope.EXISTING)
    ]
    cands.sort(
        key=lambda f: (
            f.analysis.priority if f.analysis else 3,
            -(f.analysis.confidence if f.analysis else 0),
        )
    )
    # One target per vulnerable package: bumping it fixes every CVE of that package at once.
    seen: set[tuple[str, str]] = set()
    targets: list[Finding] = []
    for f in cands:
        if f.package:
            if (f.file, f.package) in seen:
                continue
            seen.add((f.file, f.package))
        targets.append(f)
    return targets[: cfg.max_targets]


def add_remediation(
    g: Any, llm: LLMClient, cfg: RemediationConfig, audit: AuditFn, persist: bool
) -> str:
    """Add the remediation nodes to `g` and return the name of the entry node."""

    async def init(state: Any) -> dict[str, Any]:
        with telemetry.span("remediate_init"):
            findings = [Finding.model_validate(f) for f in state.get("findings", [])]
            cfg.verifier.baseline = findings
            targets = select_targets(findings, cfg)
            note = ""
            if targets:
                base = await cfg.verifier.baseline_tests(Path(state["root"]))
                if not base.get("skipped") and not base.get("passed"):
                    note = "baseline tests already fail; skipping remediation because fixes cannot be verified"
                    targets = []
            await audit(
                state,
                "remediation_agent",
                "remediation_start",
                {"targets": [t.id for t in targets], "note": note},
            )
            return {
                "rem_targets": [t.id for t in targets],
                "rem_idx": -1,
                "rem_root": state["root"],
                "rem_results": [],
                "warnings": [*state.get("warnings", []), *([note] if note else [])],
            }

    async def next_target(state: Any) -> dict[str, Any]:
        return {
            "rem_idx": state["rem_idx"] + 1,
            "rem_attempt": 1,
            "rem_feedback": "",
            "rem_current": None,
            "rem_history": [],
            "rem_declined": False,
        }

    def route_next(state: Any) -> str:
        return "rem_propose" if state["rem_idx"] < len(state["rem_targets"]) else "rem_finish"

    async def propose(state: Any) -> dict[str, Any]:
        f = _by_id(state)[state["rem_targets"][state["rem_idx"]]]
        attempt = state["rem_attempt"]
        with telemetry.span("remediate_propose", finding=f.id, attempt=attempt):
            try:
                check = await propose_patch(
                    f,
                    Path(state["rem_root"]),
                    llm,
                    state.get("rem_feedback", ""),
                    list(_by_id(state).values()),
                )
            except (BudgetExceededError, LLMError) as exc:
                hist = [
                    *state["rem_history"],
                    {"attempt": attempt, "stage": "llm", "error": str(exc)[:200]},
                ]
                return {
                    "rem_current": None,
                    "rem_declined": True,
                    "rem_feedback": f"LLM unavailable: {str(exc)[:120]}",
                    "rem_history": hist,
                }
        if check.ok and check.patch:
            hist = [
                *state["rem_history"],
                {
                    "attempt": attempt,
                    "stage": "proposed",
                    "changed_lines": check.patch.changed_lines,
                },
            ]
            p = check.patch
            return {
                "rem_current": {
                    "files": p.files,
                    "diff": p.diff,
                    "changed_lines": p.changed_lines,
                    "explanation": p.explanation,
                },
                "rem_history": hist,
            }
        declined = any(
            e.startswith(("model declined", "no fixed version", "automatic upgrades", "no edits"))
            or "is not pinned" in e
            for e in check.errors
        )
        hist = [
            *state["rem_history"],
            {"attempt": attempt, "stage": "rejected_by_guardrails", "errors": check.errors},
        ]
        return {
            "rem_current": None,
            "rem_declined": declined,
            "rem_feedback": "\n".join(check.errors),
            "rem_attempt": attempt + 1,
            "rem_history": hist,
        }

    def route_propose(state: Any) -> str:
        if state.get("rem_current"):
            return "rem_verify"
        if state.get("rem_declined"):
            return "rem_record_declined"
        return "rem_propose" if state["rem_attempt"] <= cfg.max_attempts else "rem_record_failed"

    async def verify(state: Any) -> dict[str, Any]:
        f = _by_id(state)[state["rem_targets"][state["rem_idx"]]]
        attempt = state["rem_attempt"]
        cur = state["rem_current"]
        with telemetry.span("remediate_verify", finding=f.id, attempt=attempt):
            patch = AppliedPatch(
                cur["files"], cur["diff"], cur["changed_lines"], cur["explanation"]
            )
            result, new_root = await cfg.verifier.verify(f, patch, Path(state["rem_root"]))
        entry = {
            "attempt": attempt,
            "stage": "verified" if result.passed else "failed_verification",
            "checks": result.checks,
            "failure": result.failure[:600],
        }
        if persist and state.get("scan_id"):
            await store.save_remediation(
                state["scan_id"],
                f.fingerprint,
                attempt=attempt,
                status=entry["stage"],
                patch=cur["diff"],
                rationale=cur["explanation"],
                verification=result.checks | {"failure": result.failure[:600]},
                files=cur["files"] if result.passed else None,
                finding=f,
            )
        hist = [*state["rem_history"], entry]
        if result.passed:
            return {"rem_root": str(new_root), "rem_history": hist, "rem_verified": True}
        return {
            "rem_history": hist,
            "rem_verified": False,
            "rem_feedback": result.failure,
            "rem_attempt": attempt + 1,
            "rem_retriable": result.retriable,
        }

    def route_verify(state: Any) -> str:
        if state.get("rem_verified"):
            return "rem_record_ok"
        if not state.get("rem_retriable", True) or state["rem_attempt"] > cfg.max_attempts:
            return "rem_record_failed"
        return "rem_propose"

    def recorder(outcome: str) -> Callable[[Any], Awaitable[dict[str, Any]]]:
        async def record(state: Any) -> dict[str, Any]:
            f = _by_id(state)[state["rem_targets"][state["rem_idx"]]]
            cur = state.get("rem_current") or {}
            last = state["rem_history"][-1] if state["rem_history"] else {}
            entry = {"finding_id": f.id, "fingerprint": f.fingerprint, "file": f.file, "line": f.line, "cwe": f.cwe, "title": f.title, "outcome": outcome,
                     "attempts": len([h for h in state["rem_history"] if h["stage"] in ("verified", "failed_verification", "rejected_by_guardrails")]),
                     "diff": cur.get("diff", ""), "explanation": cur.get("explanation", ""), "files": cur.get("files", {}) if outcome == "verified" else {},
                     "verification": last.get("checks", {}), "failure": last.get("failure") or state.get("rem_feedback", "")[:600], "history": state["rem_history"]}  # fmt: skip
            telemetry.REMEDIATIONS.labels(outcome).inc()
            await audit(
                state,
                "remediation_agent",
                f"remediation_{outcome}",
                {"finding": f.id, "attempts": entry["attempts"], "failure": entry["failure"][:200]},
            )
            if persist and state.get("scan_id") and outcome != "verified":
                await store.save_remediation(
                    state["scan_id"],
                    f.fingerprint,
                    attempt=entry["attempts"],
                    status=outcome,
                    patch=entry["diff"],
                    rationale=entry["explanation"],
                    verification={"failure": entry["failure"]},
                )
            return {
                "rem_results": [*state["rem_results"], entry],
                "rem_verified": False,
                "rem_retriable": True,
            }

        return record

    async def finish(state: Any) -> dict[str, Any]:
        results = {r["finding_id"]: r for r in state["rem_results"]}
        updated = []
        for raw in state.get("findings", []):
            f = Finding.model_validate(raw)
            r = results.get(f.id)
            if r:
                f = f.model_copy(
                    update={
                        "status": FindingStatus.FIXED
                        if r["outcome"] == "verified"
                        else FindingStatus.FIX_FAILED
                        if r["outcome"] == "failed"
                        else f.status
                    }
                )
            updated.append(f.model_dump(mode="json"))
        await audit(
            state,
            "remediation_agent",
            "remediation_done",
            {
                "verified": sum(r["outcome"] == "verified" for r in state["rem_results"]),
                "total": len(state["rem_results"]),
            },
        )
        final_files: dict[str, str] = {}
        for r in state["rem_results"]:  # verified fixes were applied cumulatively, in order
            final_files |= r["files"]
        return {"findings": updated, "rem_final_files": final_files}

    g.add_node("rem_init", init)
    g.add_node("rem_next", next_target)
    g.add_node("rem_propose", propose)
    g.add_node("rem_verify", verify)
    g.add_node("rem_record_ok", recorder("verified"))
    g.add_node("rem_record_failed", recorder("failed"))
    g.add_node("rem_record_declined", recorder("declined"))
    g.add_node("rem_finish", finish)
    g.add_edge("rem_init", "rem_next")
    g.add_conditional_edges(
        "rem_next", route_next, {"rem_propose": "rem_propose", "rem_finish": "rem_finish"}
    )
    g.add_conditional_edges(
        "rem_propose",
        route_propose,
        {
            "rem_verify": "rem_verify",
            "rem_record_declined": "rem_record_declined",
            "rem_propose": "rem_propose",
            "rem_record_failed": "rem_record_failed",
        },
    )
    g.add_conditional_edges(
        "rem_verify",
        route_verify,
        {
            "rem_record_ok": "rem_record_ok",
            "rem_record_failed": "rem_record_failed",
            "rem_propose": "rem_propose",
        },
    )
    for rec in ("rem_record_ok", "rem_record_failed", "rem_record_declined"):
        g.add_edge(rec, "rem_next")
    g.add_edge("rem_finish", END)
    return "rem_init"
