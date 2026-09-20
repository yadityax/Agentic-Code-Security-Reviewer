"""Remediation benchmark: `python -m backend.bench.remediation_bench --split dev`.

For every vulnerable case the full pipeline runs with remediation enabled. The hidden exploit test is an
independent oracle: it is never shown to the system and decides whether a "verified" fix is real.
"""

import argparse
import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from backend.bench.matching import Truth, match_case
from backend.bench.run import CASES, RESULTS, ROOT, load_cases
from backend.bench.systems import make_llm, to_preds
from backend.graph.remediation import RemediationConfig
from backend.graph.workflow import Deps, run_scan
from backend.models.finding import Finding
from backend.services.cwe import class_of
from backend.services.llm import TokenLimiter
from backend.services.mcp_client import connect, mcp_adapters
from backend.services.sandbox import TEST_RUNNER_IMAGE, Mount, SandboxSpec, run_sandboxed
from backend.services.verification import Verifier
from backend.services.workspace import detect_languages
from mcp_server.context import ToolContext
from mcp_server.policy import DEFAULT_GROUPS, ToolPolicy
from mcp_server.server import build_server
from mcp_server.workspaces import WorkspaceInfo

NAMES = {"semgrep", "gitleaks", "trivy", "syft", "codeql"}


async def oracle(original: Path, patched: dict[str, str], case: str) -> bool | None:
    exploit = CASES / case / "src" / "tests" / "test_security.py"
    if not exploit.exists():
        return None
    tmp = Path(tempfile.mkdtemp(prefix="acsr-oracle-"))
    try:
        work = tmp / "w"
        shutil.copytree(original, work)
        for rel, content in patched.items():
            (work / rel).write_text(content)
        shutil.copy(exploit, work / "tests" / "test_security.py")
        res = await run_sandboxed(
            SandboxSpec(
                image=TEST_RUNNER_IMAGE,
                entrypoint="python",
                command=["-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_security.py"],
                workdir="/work",
                mounts=[Mount(work, "/work", read_only=False)],
                timeout_s=90,
            )
        )
        return res.exit_code == 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def run_case(meta: dict[str, Any], limiter: TokenLimiter, cache: Path) -> dict[str, Any]:
    tmp = Path(tempfile.mkdtemp(prefix="acsr-rbench-"))
    root = tmp / "w"
    shutil.copytree(meta["src"], root)
    (root / "tests" / "test_security.py").unlink(
        missing_ok=True
    )  # oracle stays hidden from the system
    llm = make_llm(cache, limiter, "agentic")
    ctx = ToolContext(policy=ToolPolicy(DEFAULT_GROUPS))
    start = time.monotonic()
    try:
        async with connect(build_server(ctx)) as tools:
            wid = ctx.registry.register(WorkspaceInfo(root, [], {}, detect_languages(root)))
            verifier = Verifier(tools, ctx.registry, NAMES, [], require_tests=True)
            deps = Deps(
                llm=llm,
                adapters=mcp_adapters(tools, ctx.registry, wid, NAMES),
                analyze=True,
                discover=True,
                remediation=RemediationConfig(verifier, max_attempts=3, max_targets=6),
            )
            try:
                res = await run_scan(deps, root)
            finally:
                verifier.cleanup()
        truths = [Truth(t["file"], t["line"], t["cwe"]) for t in meta["vulns"]]
        # which remediation targets were real vulnerabilities (matched ground truth) vs false alarms?
        by_id: dict[str, Finding] = {f.id: f for f in res.findings}
        preds = to_preds(
            [by_id[r["finding_id"]] for r in res.remediations if r["finding_id"] in by_id],
            drop_false_positives=False,
        )
        pairs, fps, _ = match_case(preds, truths)
        real = {(p.file, p.line) for p, _ in pairs}
        out_rems = []
        for r in res.remediations:
            f = by_id.get(r["finding_id"])
            hist = r["history"]
            out_rems.append({
                "case_class": "Vulnerable dependency" if f and f.package else class_of(r["cwe"]), "outcome": r["outcome"], "attempts": r["attempts"], "real": bool(f and (any(f.file == a and abs(f.line - b) <= 6 or (f.package and f.file == a) for a, b in real))),
                "tests_attempts": sum(1 for h in hist if "checks" in h and "tests" in h["checks"]),
                "tests_passed": sum(1 for h in hist if h.get("checks", {}).get("tests", {}).get("passed")),
                "rescan_attempts": sum(1 for h in hist if "rescan" in h.get("checks", {})),
                "rescan_passed": sum(1 for h in hist if h.get("checks", {}).get("rescan", {}).get("original_finding_gone") and h.get("checks", {}).get("rescan", {}).get("new_findings") == 0),
                "failure": r["failure"][:160],
            })  # fmt: skip
        oracle_ok = (
            await oracle(meta["src"], res.patched_files, meta["id"])
            if res.patched_files
            else (False if meta["has_exploit_test"] else None)
        )
        return {"id": meta["id"], "kind": meta["kind"], "remediations": out_rems, "oracle_passes": oracle_ok, "has_exploit_test": meta["has_exploit_test"],
                "tokens": llm.usage.total_tokens, "latency_s": time.monotonic() - start, "needs_review": sum(1 for f in res.findings if f.analysis and f.analysis.verdict.value == "needs_review")}  # fmt: skip
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    rems = [r for c in results for r in c["remediations"]]
    real = [r for r in rems if r["real"]]
    verified = [r for r in real if r["outcome"] == "verified"]
    oracle_cases = [
        c for c in results if c["has_exploit_test"] and any(r["real"] for r in c["remediations"])
    ]
    oracle_true = [c for c in oracle_cases if c["oracle_passes"]]
    ta, tp = sum(r["tests_attempts"] for r in rems), sum(r["tests_passed"] for r in rems)
    ra, rp = sum(r["rescan_attempts"] for r in rems), sum(r["rescan_passed"] for r in rems)
    n_needs = sum(c["needs_review"] for c in results)
    return {
        "targets_real": len(real), "targets_false_alarm": len(rems) - len(real),
        "fix_success_rate": len(verified) / len(real) if real else 0.0,
        "exploit_oracle_pass_rate": len(oracle_true) / len(oracle_cases) if oracle_cases else 0.0, "oracle_cases": len(oracle_cases),
        "post_fix_test_pass_rate": tp / ta if ta else 0.0, "security_rescan_pass_rate": rp / ra if ra else 0.0,
        "avg_attempts_per_target": sum(r["attempts"] for r in real) / len(real) if real else 0.0,
        "human_intervention_rate": (len(real) - len(verified) + n_needs) / (len(real) + n_needs) if real or n_needs else 0.0,
        "by_class": {k: {"targets": sum(1 for r in real if r["case_class"] == k), "verified": sum(1 for r in verified if r["case_class"] == k)} for k in sorted({r["case_class"] for r in real})},
        "tokens_per_case": sum(c["tokens"] for c in results) / max(len(results), 1), "latency_per_case_s": sum(c["latency_s"] for c in results) / max(len(results), 1),
    }  # fmt: skip


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "heldout", "all"])
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--tpm", type=int, default=7000)
    ap.add_argument("--cases", default="")
    ap.add_argument(
        "--cache-dir", default="", help="LLM cache directory (fresh one = independent repeat)"
    )
    args = ap.parse_args()
    cases = [
        c
        for c in load_cases(args.split, set(filter(None, args.cases.split(","))) or None)
        if c["kind"] == "vulnerable"
    ]
    limiter, sem, cache = (
        TokenLimiter(args.tpm),
        asyncio.Semaphore(args.concurrency),
        ROOT / ".llm_cache",
    )
    t0 = time.monotonic()

    async def go(m: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            r = await run_case(m, limiter, cache)
            print(
                f"  done {m['id']:24s} {[x['outcome'] for x in r['remediations']]} oracle={r['oracle_passes']} ({time.monotonic() - t0:.0f}s)",
                flush=True,
            )
            return r

    results = await asyncio.gather(*(go(m) for m in cases))
    s = summarize(results)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{time.strftime('%Y%m%d-%H%M%S')}-remediation-{args.split}.json").write_text(
        json.dumps({"summary": s, "cases": results}, indent=1, default=str)
    )
    print(json.dumps(s, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
