"""Benchmark runner: `python -m backend.bench.run [--split dev|heldout|all] [--systems A,B,C]`."""

import argparse
import asyncio
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from backend.bench import systems
from backend.bench.matching import Counts, Truth
from backend.services.llm import TokenLimiter

ROOT = Path(__file__).resolve().parents[2] / "benchmarks"
CASES = ROOT / "cases"
RESULTS = ROOT / "results"


def load_cases(split: str, only: set[str] | None = None) -> list[dict[str, Any]]:
    cases = []
    for d in sorted(CASES.iterdir()):
        if not (d / "expected.json").exists():
            continue
        meta = json.loads((d / "expected.json").read_text())
        if (split == "all" or meta["split"] == split) and (not only or meta["id"] in only):
            meta["src"] = d / "src"
            cases.append(meta)
    return cases


async def run_case(
    meta: dict[str, Any], limiter: TokenLimiter, want: set[str], cache: Path, codeql: bool
) -> dict[str, Any]:
    out: dict[str, Any] = {"id": meta["id"], "split": meta["split"], "kind": meta["kind"]}
    if "A" in want:
        llm = systems.make_llm(cache, limiter, "llm_only")
        out["A"] = await systems.llm_only(meta["src"], llm)
    if want & {"B", "C", "C+", "C-strict"}:
        llm = systems.make_llm(cache, limiter, "agentic")
        res, wall = await systems.run_pipeline(meta["src"], llm, enable_codeql=codeql)
        out["B"] = systems.scanner_only(res)
        out["C"] = systems.agentic(res)
        out["C+"] = systems.agentic(res, discovery=True)
        out["C-strict"] = systems.agentic(res, strict=True)
        out["raw_findings"] = [f.model_dump(mode="json") for f in res.findings]
        out["scan_errors"] = res.scan_errors
    return out


def score(results: list[dict[str, Any]], system: str) -> tuple[Counts, dict[str, float]]:
    c = Counts()
    lat = tokens = cost = calls = tools = nr = n_pred = 0.0
    n = 0
    for r in results:
        if system not in r:
            continue
        sr: systems.SystemResult = r[system]
        c.add_case(
            sr.preds, [Truth(**{k: t[k] for k in ("file", "line", "cwe")}) for t in r["truth"]]
        )
        lat += sr.latency_s
        tokens += sr.tokens
        cost += sr.cost_usd
        calls += sr.llm_calls  # noqa: E702
        tools += sr.tool_calls
        nr += sr.needs_review
        n_pred += len(sr.preds)
        n += 1  # noqa: E702
    n = max(n, 1)
    return c, {"latency_s": lat / n, "tokens": tokens / n, "cost_usd": cost / n, "iterations": (calls + tools) / n,
               "needs_review_rate": nr / n_pred if n_pred else 0.0}  # fmt: skip


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="all", choices=["dev", "heldout", "all"])
    ap.add_argument("--systems", default="A,B,C")
    ap.add_argument("--cases", default="", help="comma-separated case ids")
    ap.add_argument("--no-codeql", action="store_true")
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--tpm", type=int, default=7000)
    ap.add_argument(
        "--cache-dir",
        default="",
        help="LLM response cache (use a fresh directory for an independent repeat)",
    )
    args = ap.parse_args()
    want = set(args.systems.split(","))
    cases = load_cases(args.split, set(filter(None, args.cases.split(","))) or None)
    limiter = TokenLimiter(args.tpm)
    cache = Path(args.cache_dir) if args.cache_dir else ROOT / ".llm_cache"
    sem = asyncio.Semaphore(args.concurrency)
    t0 = time.monotonic()

    async def guarded(m: dict[str, Any]) -> dict[str, Any]:
        async with sem:
            r = await run_case(m, limiter, want, cache, not args.no_codeql)
            r["truth"] = m["vulns"]
            print(f"  done {m['id']:24s} ({time.monotonic() - t0:.0f}s)", flush=True)
            return r

    results = await asyncio.gather(*(guarded(m) for m in cases))
    stamp = time.strftime("%Y%m%d-%H%M%S")
    RESULTS.mkdir(exist_ok=True)
    dump = [
        {
            k: (
                {
                    "preds": [asdict(p) for p in v.preds],
                    **{a: b for a, b in asdict(v).items() if a != "preds"},
                }
                if isinstance(v, systems.SystemResult)
                else v
            )
            for k, v in r.items()
        }
        for r in results
    ]
    (RESULTS / f"{stamp}-{args.split}.json").write_text(json.dumps(dump, indent=1, default=str))
    print(f"\nSplit={args.split}  cases={len(cases)}  wall={time.monotonic() - t0:.0f}s\n")
    print(
        f"{'system':10s} {'P':>6} {'R':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'safe-case FPR':>14} {'lat(s)':>7} {'tokens':>7} {'$/review':>9}"
    )
    for s in ("A", "B", "C", "C+", "C-strict"):
        if s not in want and not (s in ("C-strict", "C+") and "C" in want):
            continue
        c, m = score(results, s)
        print(
            f"{s:10s} {c.precision:6.2f} {c.recall:6.2f} {c.f1:6.2f} {c.tp:4d} {c.fp:4d} {c.fn:4d} {c.fp_rate_safe_cases:14.2f} {m['latency_s']:7.1f} {m['tokens']:7.0f} {m['cost_usd']:9.5f}"
        )


if __name__ == "__main__":
    asyncio.run(main())
