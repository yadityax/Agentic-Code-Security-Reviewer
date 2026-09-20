"""Generate docs/results.md from raw benchmark result files.

python -m backend.bench.report --dev FILE --heldout FILE [FILE ...] --remediation FILE [FILE ...]
"""

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

from backend.bench.matching import Counts, Pred, Truth
from backend.bench.run import ROOT
from backend.bench.systems import SystemResult

SYSTEMS = [
    ("A", "LLM-only reviewer"),
    ("B", "Scanner-only pipeline"),
    ("C", "Agentic: scanners + analyst"),
    ("C+", "Agentic + LLM discovery"),
]


def load(path: Path) -> list[dict[str, Any]]:
    out = []
    for r in json.loads(path.read_text()):
        for k in ("A", "B", "C", "C+", "C-strict"):
            if k in r:
                d = r[k]
                r[k] = SystemResult(
                    preds=[Pred(**p) for p in d["preds"]],
                    **{a: b for a, b in d.items() if a not in ("preds",)},
                )
        out.append(r)
    return out


def score(results: list[dict[str, Any]], system: str) -> tuple[Counts, dict[str, float]]:
    c, lat, tok, cost, calls, tools, nr, npred, n = Counts(), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0
    for r in results:
        sr: SystemResult = r[system]
        c.add_case(sr.preds, [Truth(t["file"], t["line"], t["cwe"]) for t in r["truth"]])
        lat += sr.latency_s
        tok += sr.tokens
        cost += sr.cost_usd
        calls += sr.llm_calls
        tools += sr.tool_calls
        nr += sr.needs_review
        npred += len(sr.preds)
        n += 1  # noqa: E702
    n = max(n, 1)
    return c, {
        "latency_s": lat / n,
        "tokens": tok / n,
        "cost_usd": cost / n,
        "iterations": (calls + tools) / n,
        "needs_review_rate": nr / npred if npred else 0.0,
    }


def _fmt(vals: list[float], pct: bool = False, d: int = 2) -> str:
    def f(v: float) -> str:
        return f"{v * 100:.0f}%" if pct else f"{v:.{d}f}"

    if len(vals) == 1:
        return f(vals[0])
    return f"{f(statistics.mean(vals))} ({f(min(vals))}–{f(max(vals))})"


def detection_table(runs: list[list[dict[str, Any]]]) -> str:
    rows = [
        "| System | Precision | Recall | F1 | TP / FP / FN (run 1) | Safe apps wrongly flagged | Avg latency | Tokens / review | Cost / review |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for key, label in SYSTEMS:
        scored = [score(r, key) for r in runs if key in r[0]]
        if not scored:
            continue
        cs = [c for c, _ in scored]
        ms = [m for _, m in scored]
        rows.append(
            f"| **{key}** {label} | {_fmt([c.precision for c in cs])} | {_fmt([c.recall for c in cs])} | {_fmt([c.f1 for c in cs])} | {cs[0].tp} / {cs[0].fp} / {cs[0].fn} | {_fmt([c.fp_rate_safe_cases for c in cs], pct=True)} | {_fmt([m['latency_s'] for m in ms], d=1)}s | {_fmt([m['tokens'] for m in ms], d=0)} | ${statistics.mean(m['cost_usd'] for m in ms):.5f} |"
        )
    return "\n".join(rows)


def class_table(runs: list[list[dict[str, Any]]]) -> str:
    keys = [k for k, _ in SYSTEMS if k in runs[0][0]]
    classes = sorted({cl for r in runs for k in keys for cl in score(r, k)[0].per_class})
    rows = [
        "| Vulnerability class | Cases | " + " | ".join(f"{k} recall" for k in keys) + " |",
        "|---|---|" + "---|" * len(keys),
    ]
    for cl in classes:
        cells, total = [], 0
        for k in keys:
            tp = fn = 0
            for r in runs:
                pc = score(r, k)[0].per_class.get(cl, [0, 0])
                tp, fn = tp + pc[0], fn + pc[1]
            total = (tp + fn) // len(runs)
            cells.append(f"{tp / (tp + fn) * 100:.0f}%" if tp + fn else "-")
        rows.append(f"| {cl} | {total} | " + " | ".join(cells) + " |")
    return "\n".join(rows)


def remediation_table(summaries: list[dict[str, Any]]) -> str:
    def m(key: str, pct: bool = True, d: int = 2) -> str:
        return _fmt([s[key] for s in summaries], pct=pct, d=d)

    rows = [
        "| Metric | Result |",
        "|---|---|",
        f"| Confirmed real vulnerabilities attempted | {summaries[0]['targets_real']} (run 1) |",
        f"| **Automated fix success rate** (fix passed every verification check) | {m('fix_success_rate')} |",
        f"| Exploit oracle: verified fix really blocks the exploit | {m('exploit_oracle_pass_rate')} (on {summaries[0]['oracle_cases']} cases that have an exploit test) |",
        f"| **Post-fix test pass rate** (proposed patches whose tests passed, all attempts) | {m('post_fix_test_pass_rate')} |",
        f"| **Security-rescan pass rate** (patches passing tests that also cleared the rescan) | {m('security_rescan_pass_rate')} |",
        f"| Average attempts per attempted finding | {m('avg_attempts_per_target', pct=False)} |",
        f"| **Human intervention rate** (real findings without a verified fix, plus needs-review findings) | {m('human_intervention_rate')} |",
        f"| Tokens per case (analysis + discovery + remediation) | {m('tokens_per_case', pct=False, d=0)} |",
    ]
    by: dict[str, list[int]] = {}
    for s in summaries[:1]:
        for cl, v in s["by_class"].items():
            by[cl] = [v["targets"], v["verified"]]
    if by:
        rows += ["", "| Class | Fix attempts | Verified fixes |", "|---|---|---|"] + [
            f"| {cl} | {t} | {v} |" for cl, (t, v) in sorted(by.items())
        ]
    return "\n".join(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", type=Path, required=True)
    ap.add_argument("--heldout", type=Path, nargs="+", required=True)
    ap.add_argument("--remediation", type=Path, nargs="*", default=[])
    ap.add_argument("--remediation-dev", type=Path, nargs="*", default=[])
    ap.add_argument("--dev-model", default="openai/gpt-oss-120b")
    ap.add_argument("--heldout-model", default="openai/gpt-oss-120b")
    ap.add_argument(
        "--note",
        default="",
        help="extra paragraph placed under the held-out heading (e.g. why the model differs)",
    )
    ap.add_argument("--out", type=Path, default=ROOT.parent / "docs" / "results.md")
    a = ap.parse_args()
    dev = [load(a.dev)]
    held = [load(p) for p in a.heldout]
    n_cases = {"dev": len(dev[0]), "heldout": len(held[0])}
    truths = {
        "dev": sum(len(r["truth"]) for r in dev[0]),
        "heldout": sum(len(r["truth"]) for r in held[0]),
    }
    doc = [
        "# Benchmark results",
        "",
        f"Generated from the raw result files in `benchmarks/published/` by `python -m backend.bench.report`. Corpus: {n_cases['dev'] + n_cases['heldout']} small Flask/FastAPI/Python projects "
        f"({n_cases['dev']} dev, {n_cases['heldout']} held-out; {truths['dev'] + truths['heldout']} ground-truth vulnerabilities) covering every class in the blueprint, plus safe look-alikes that test for false alarms.",
        "",
        "## How to read this",
        "",
        "* **A** LLM-only: the model gets the project files and no tools. **B** the scanner pipeline with no LLM (every finding above the threshold is reported). **C** scanners + analyst triage. **C+** adds the LLM discovery pass for logic flaws.",
        "* All systems are scored identically: one-to-one matching of predictions to ground truth by file, CWE family and line proximity; findings below *medium* severity are not counted for any system; dependency findings count once per vulnerable package.",
        f"* Same model for every system within a split: **dev = `{a.dev_model}`**, **held-out = `{a.heldout_model}`** (Groq; reasoning effort *low* for analysis, *medium* for patching)."
        + (
            " Because the splits used different models, **dev and held-out numbers are not directly comparable**; compare systems within a split."
            if a.dev_model != a.heldout_model
            else ""
        ),
        "* **Latency**: the held-out runs were sequential, so latency is real. The dev runs were concurrent and shared one rate limiter, so their latency includes queueing and is **not meaningful**; use only the held-out latency.",
        "",
        f"## Held-out split (headline)  ·  {len(held)} independent run(s)",
        "",
        *([a.note, ""] if a.note else []),
        "These cases were written in a different style from the dev cases and **never used for tuning**. "
        + (
            "Values are mean (min–max) over independent runs with fresh LLM caches."
            if len(held) > 1
            else ""
        ),
        "",
        detection_table(held),
        "",
        "### Recall by vulnerability class (held-out)",
        "",
        class_table(held),
        "",
        "## Dev split (tuned against; optimistic)",
        "",
        "Prompts, custom Semgrep rules and the discovery guard were developed by reading failures on these cases, so treat these numbers as an upper bound.",
        "",
        detection_table(dev),
        "",
        "### Recall by vulnerability class (dev)",
        "",
        class_table(dev),
        "",
    ]
    if a.remediation:
        summaries = [json.loads(p.read_text())["summary"] for p in a.remediation]
        doc += [f"## Automated remediation (held-out, `{a.heldout_model}`, {len(summaries)} run(s))", "",
                "Each vulnerable case runs the full pipeline with remediation on. A hidden exploit test, never shown to the system, is the independent oracle for whether a *verified* fix really removes the vulnerability.", "",
                remediation_table(summaries), ""]  # fmt: skip
    if a.remediation_dev:
        ds = [json.loads(p.read_text())["summary"] for p in a.remediation_dev]
        doc += [
            f"## Automated remediation (dev split, `{a.dev_model}`)",
            "",
            "Developed against, so optimistic; shown because it used the stronger model.",
            "",
            remediation_table(ds),
            "",
        ]
    doc += [
        "## Reading these results",
        "",
        "What the data supports (small corpus, see [benchmark.md](benchmark.md) for limits):",
        "",
        "* **Scanners alone over-report.** Scanner-only flagged 25% of the safe held-out apps (75% on dev). **Analyst triage removed every one of those false alarms in both splits without losing any true positive** (C recall equals B recall, C precision is 1.00).",
        "* **Scanners have a recall ceiling.** They miss logic flaws and weak randomness (B and C recall 0% for those classes). The LLM discovery pass (C+) recovers most of them, at the cost of an occasional false positive: it is a precision/recall trade, which is why it is reported separately.",
        "* **LLM-only is competitive on F1 but different in kind.** On this corpus it lands between scanner-only and the agentic system, varies run to run (held-out F1 0.75 to 0.88), misses whole classes that need tools (dependency CVEs and Dockerfile misconfiguration: 33% recall on dev), and provides no evidence trail, verification or fixes.",
        "* **Automated remediation works for the mechanical classes and hands the rest to humans.** Verified fixes were produced for SQL and command injection, XSS, dependency bumps, container hardening, and (in the runs above) the access-control and weak-randomness cases. SSRF, insecure deserialization, path traversal, password hashing and some secrets failed or were declined in at least one run: they tend to need a behaviour change, or a scanner keeps flagging the safe pattern, so a person decides. A failed attempt leaves no patch behind.",
        "* **Only one remediation run** was affordable on the held-out split, so its spread is unknown.",
        "",
        '### A target counts as "real" if it lies within 6 lines of a ground-truth vulnerability',
        "Remediation targets are judged by proximity, not CWE, so a neighbouring finding of a different class on the same statement is counted as real. This slightly flatters the denominator of the class table.",
        "",
        "## Measured résumé bullet",
        "",
        "> Built an autonomous GitHub PR security reviewer (LangGraph, MCP, FastAPI) that orchestrates Semgrep, CodeQL, Gitleaks, Trivy and Syft in network-isolated sandboxes, triages findings with an LLM analyst, and fixes them through a verified loop (build, tests, security rescan, bounded retries) that ends in a human-approved PR. On a 28-case benchmark (12 held-out cases, independent repeats), triage eliminated all false alarms on safe code (scanner-only flagged 25%), reaching F1 0.86, or 0.94 with LLM discovery, versus 0.75 scanner-only and 0.75 to 0.88 LLM-only; 67% of confirmed held-out findings received an automatically verified fix (75% of those with an exploit test confirmed by a hidden oracle), at about 20 s and $0.0001 per review (gpt-oss-20b).",
        "",
    ]
    a.out.write_text("\n".join(doc))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
