"""LangGraph workflow: plan -> scan -> correlate -> analyze -> report (remediation nodes join in Week 4)."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from backend.graph.remediation import RemediationConfig, add_remediation
from backend.models.finding import Finding, Verdict
from backend.services import store, telemetry
from backend.services.analyst import analyze_findings
from backend.services.correlator import correlate
from backend.services.discovery import discover_findings, select_files
from backend.services.llm import LLMClient
from backend.services.planner import make_plan
from backend.services.report import render_report
from backend.services.scanners.base import ScanContext, ScannerAdapter, ScanOutput
from backend.services.workspace import detect_languages, tag_pr_scope

Emit = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass
class Deps:
    llm: LLMClient
    adapters: Mapping[str, ScannerAdapter]
    persist: bool = False
    enable_codeql: bool = True
    scanner_timeout_s: int = 300
    analyze: bool = True  # False = scanner-only baseline
    discover: bool = False  # LLM pass for logic-level issues scanners cannot see
    remediation: RemediationConfig | None = None  # set to enable patch generation + verification
    extra: dict[str, Any] = field(default_factory=dict)


class ScanState(TypedDict, total=False):
    scan_id: str | None
    root: str
    changed_files: list[str]
    changed_lines: dict[str, list[list[int]]]
    languages: list[str]
    plan: dict[str, Any]
    raw_findings: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    scan_errors: dict[str, str]
    tool_seconds: dict[str, float]
    artifacts: dict[str, Any]
    warnings: list[str]
    report_md: str
    stats: dict[str, Any]
    rem_targets: list[str]
    rem_idx: int
    rem_attempt: int
    rem_feedback: str
    rem_current: dict[str, Any] | None
    rem_history: list[dict[str, Any]]
    rem_declined: bool
    rem_verified: bool
    rem_retriable: bool
    rem_root: str
    rem_results: list[dict[str, Any]]
    rem_final_files: dict[str, str]


def _findings(state: ScanState, key: str = "findings") -> list[Finding]:
    items: list[dict[str, Any]] = dict(state).get(key, [])  # type: ignore[assignment]
    return [Finding.model_validate(f) for f in items]


def build_graph(deps: Deps, checkpointer: Any = None) -> Any:
    async def audit(
        state: ScanState, actor: str, action: str, detail: dict[str, Any] | None = None
    ) -> None:
        if deps.persist and state.get("scan_id"):
            await store.audit(state["scan_id"], actor, action, detail)

    async def plan_node(state: ScanState) -> dict[str, Any]:
        with telemetry.span("plan"):
            root = Path(state["root"])
            langs = set(state.get("languages") or detect_languages(root))
            plan = make_plan(
                root, langs, enable_codeql=deps.enable_codeql, enabled=set(deps.adapters)
            )
            await audit(
                state,
                "planner",
                "plan",
                {"scanners": plan.scanners, "languages": plan.languages, "reasons": plan.reasons},
            )
            return {"languages": sorted(langs), "plan": plan.__dict__}

    async def scan_node(state: ScanState) -> dict[str, Any]:
        root = Path(state["root"])
        ctx = ScanContext(
            root=root,
            changed_files=state.get("changed_files", []),
            languages=set(state.get("languages", [])),
            timeout_s=deps.scanner_timeout_s,
        )
        names = state["plan"]["scanners"]

        async def run_one(name: str) -> ScanOutput:
            with telemetry.span("scanner", tool=name):
                try:
                    out = await asyncio.wait_for(
                        deps.adapters[name].run(ctx), timeout=deps.scanner_timeout_s + 30
                    )
                except Exception as exc:  # a broken scanner degrades the scan, never aborts it
                    out = ScanOutput(name, [], 0.0, error=f"{type(exc).__name__}: {str(exc)[:200]}")
                telemetry.TOOL_DURATION.labels(name).observe(out.duration_s)
                if out.error:
                    telemetry.TOOL_ERRORS.labels(name).inc()
                if deps.persist and (sid := state.get("scan_id")):
                    await store.record_tool_run(
                        sid,
                        name,
                        error=out.error,
                        duration_s=out.duration_s,
                        findings=len(out.findings),
                    )
                return out

        outs = await asyncio.gather(*(run_one(n) for n in names))
        raw = [f for o in outs for f in o.findings]
        await audit(
            state, "scanner_agent", "scan_complete", {o.scanner: len(o.findings) for o in outs}
        )
        return {
            "raw_findings": [f.model_dump(mode="json") for f in raw],
            "scan_errors": {o.scanner: o.error for o in outs if o.error},
            "tool_seconds": {o.scanner: round(o.duration_s, 2) for o in outs},
            "artifacts": {k: v for o in outs for k, v in o.artifacts.items()},
        }  # fmt: skip

    async def correlate_node(state: ScanState) -> dict[str, Any]:
        with telemetry.span("correlate"):
            raw = _findings(state, "raw_findings")
            lines = {k: [(a, b) for a, b in v] for k, v in state.get("changed_lines", {}).items()}
            merged = correlate(tag_pr_scope(raw, lines) if lines else raw)
            await audit(state, "correlator", "correlate", {"raw": len(raw), "merged": len(merged)})
            return {"findings": [f.model_dump(mode="json") for f in merged]}

    async def analyze_node(state: ScanState) -> dict[str, Any]:
        with telemetry.span("analyze"):
            findings = _findings(state)
            if not deps.analyze:
                return {"warnings": ["analysis skipped (scanner-only mode)"]}
            done, warnings = await analyze_findings(findings, Path(state["root"]), deps.llm)
            await audit(
                state,
                "security_analyst",
                "analyze",
                {
                    "findings": len(done),
                    "warnings": warnings,
                    "tokens": deps.llm.usage.total_tokens,
                },
            )
            return {"findings": [f.model_dump(mode="json") for f in done], "warnings": warnings}

    async def discover_node(state: ScanState) -> dict[str, Any]:
        if not (deps.discover and deps.analyze):
            return {}
        with telemetry.span("discover"):
            root = Path(state["root"])
            existing = _findings(state)
            files = select_files(root, state.get("changed_files"))
            new, warns = await discover_findings(root, files, existing, deps.llm)
            await audit(
                state,
                "security_analyst",
                "discover",
                {"files": len(files), "new_findings": len(new), "warnings": warns},
            )
            merged = correlate([*existing, *new])
            return {
                "findings": [f.model_dump(mode="json") for f in merged],
                "warnings": [*state.get("warnings", []), *warns],
            }

    async def report_node(state: ScanState) -> dict[str, Any]:
        with telemetry.span("report"):
            findings = _findings(state)
            u = deps.llm.usage
            md = render_report(findings, scanners=state["plan"]["scanners"], warnings=state.get("warnings"),
                               usage={"tokens": u.total_tokens, "cost_usd": u.cost_usd}, scan_errors=state.get("scan_errors"))  # fmt: skip
            for f in findings:
                telemetry.FINDINGS.labels(
                    f.severity.value, f.analysis.verdict.value if f.analysis else "unvalidated"
                ).inc()
            return {"report_md": md}

    g = StateGraph(ScanState)
    g.add_node("plan", plan_node)
    g.add_node("scan", scan_node)
    g.add_node("correlate", correlate_node)
    g.add_node("analyze", analyze_node)
    g.add_node("discover", discover_node)
    g.add_node("report", report_node)
    g.add_edge(START, "plan")
    g.add_edge("plan", "scan")
    g.add_edge("scan", "correlate")
    g.add_edge("correlate", "analyze")
    g.add_edge("analyze", "discover")
    g.add_edge("discover", "report")
    if deps.remediation:
        entry = add_remediation(g, deps.llm, deps.remediation, audit, deps.persist)
        g.add_edge("report", entry)
    else:
        g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)


@dataclass
class ScanResult:
    findings: list[Finding]
    report_md: str
    plan: dict[str, Any]
    scan_errors: dict[str, str]
    warnings: list[str]
    latency_s: float
    usage: dict[str, float]
    tool_seconds: dict[str, float]
    artifacts: dict[str, Any] = field(default_factory=dict)
    remediations: list[dict[str, Any]] = field(default_factory=list)
    patched_files: dict[str, str] = field(
        default_factory=dict
    )  # path -> final content of every verified fix

    @property
    def actionable(self) -> list[Finding]:
        return [
            f
            for f in self.findings
            if not f.analysis or f.analysis.verdict != Verdict.FALSE_POSITIVE
        ]


async def run_scan(
    deps: Deps, root: Path, *, changed_lines: dict[str, list[tuple[int, int]]] | None = None,
    changed_files: list[str] | None = None, scan_id: str | None = None, checkpointer: Any = None,
    thread_id: str | None = None,
) -> ScanResult:  # fmt: skip
    graph = build_graph(deps, checkpointer)
    start = time.monotonic()
    telemetry.IN_FLIGHT.inc()
    state: ScanState = {"scan_id": scan_id, "root": str(root), "changed_files": changed_files or [],
                        "changed_lines": {k: [list(r) for r in v] for k, v in (changed_lines or {}).items()}}  # fmt: skip
    cfg = {"configurable": {"thread_id": thread_id or scan_id or "adhoc"}}
    try:
        with telemetry.span("scan_pipeline", root=str(root)):
            final: ScanState = await graph.ainvoke(state, cfg)
    finally:
        telemetry.IN_FLIGHT.dec()
    latency = time.monotonic() - start
    u = deps.llm.usage
    usage = {"requests": u.requests, "prompt_tokens": u.prompt_tokens, "completion_tokens": u.completion_tokens,
             "tokens": u.total_tokens, "cost_usd": u.cost_usd, "cache_hits": u.cache_hits}  # fmt: skip
    result = ScanResult(_findings(final), final["report_md"], final["plan"], final.get("scan_errors", {}),
                        final.get("warnings", []), latency, usage, final.get("tool_seconds", {}), final.get("artifacts", {}), final.get("rem_results", []), final.get("rem_final_files", {}))  # fmt: skip
    telemetry.SCAN_LATENCY.observe(latency)
    telemetry.LLM_TOKENS.labels("prompt").inc(u.prompt_tokens)
    telemetry.LLM_TOKENS.labels("completion").inc(u.completion_tokens)
    telemetry.LLM_COST.inc(u.cost_usd)
    telemetry.SCANS.labels("ok").inc()
    if deps.persist and scan_id:
        await store.save_findings(scan_id, result.findings)
        await store.finish_scan(scan_id, status="completed", latency_s=latency, usage=usage,
                                summary={"plan": result.plan, "scan_errors": result.scan_errors, "warnings": result.warnings,
                                         "tool_seconds": result.tool_seconds, "counts": len(result.findings), "report_md": result.report_md, "sbom_components": len(result.artifacts.get("sbom", {}).get("components", []))})  # fmt: skip
    return result
