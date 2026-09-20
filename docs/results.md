# Benchmark results

Generated from the raw result files in `benchmarks/published/` by `python -m backend.bench.report`. Corpus: 28 small Flask/FastAPI/Python projects (16 dev, 12 held-out; 26 ground-truth vulnerabilities) covering every class in the blueprint, plus safe look-alikes that test for false alarms.

## How to read this

* **A** LLM-only: the model gets the project files and no tools. **B** the scanner pipeline with no LLM (every finding above the threshold is reported). **C** scanners + analyst triage. **C+** adds the LLM discovery pass for logic flaws.
* All systems are scored identically: one-to-one matching of predictions to ground truth by file, CWE family and line proximity; findings below *medium* severity are not counted for any system; dependency findings count once per vulnerable package.
* Same model for every system within a split: **dev = `openai/gpt-oss-120b`**, **held-out = `openai/gpt-oss-20b`** (Groq; reasoning effort *low* for analysis, *medium* for patching). Because the splits used different models, **dev and held-out numbers are not directly comparable**; compare systems within a split.
* **Latency**: the held-out runs were sequential, so latency is real. The dev runs were concurrent and shared one rate limiter, so their latency includes queueing and is **not meaningful**; use only the held-out latency.

## Held-out split (headline)  ·  2 independent run(s)

**Why the held-out split used a smaller model.** Development consumed the free-tier daily cap of 200,000 tokens for `gpt-oss-120b` (the API reported 199,750 used), so the final held-out evaluation ran on `gpt-oss-20b`, which has its own quota. All systems within a split use the same model. Re-running on 120b is `LLM_MODEL=openai/gpt-oss-120b make bench-heldout` once quota is available. Prices are assumed list prices ($0.075/$0.30 per M tokens for 20b) and should be checked.

These cases were written in a different style from the dev cases and **never used for tuning**. Values are mean (min–max) over independent runs with fresh LLM caches.

| System | Precision | Recall | F1 | TP / FP / FN (run 1) | Safe apps wrongly flagged | Avg latency | Tokens / review | Cost / review |
|---|---|---|---|---|---|---|---|---|
| **A** LLM-only reviewer | 0.81 (0.75–0.88) | 0.81 (0.75–0.88) | 0.81 (0.75–0.88) | 6 / 2 / 2 | 0% (0%–0%) | 3.7 (3.6–3.7)s | 700 (699–702) | $0.00007 |
| **B** Scanner-only pipeline | 0.75 (0.75–0.75) | 0.75 (0.75–0.75) | 0.75 (0.75–0.75) | 6 / 2 / 2 | 25% (25%–25%) | 11.6 (11.5–11.6)s | 0 (0–0) | $0.00000 |
| **C** Agentic: scanners + analyst | 1.00 (1.00–1.00) | 0.75 (0.75–0.75) | 0.86 (0.86–0.86) | 6 / 0 / 2 | 0% (0%–0%) | 19.6 (19.6–19.6)s | 1242 (1236–1249) | $0.00014 |
| **C+** Agentic + LLM discovery | 0.94 (0.89–1.00) | 0.94 (0.88–1.00) | 0.94 (0.93–0.94) | 7 / 0 / 1 | 0% (0%–0%) | 19.6 (19.6–19.6)s | 1242 (1236–1249) | $0.00014 |

### Recall by vulnerability class (held-out)

| Vulnerability class | Cases | A recall | B recall | C recall | C+ recall |
|---|---|---|---|---|---|
| Broken access control | 1 | 100% | 0% | 0% | 50% |
| Command injection | 1 | 100% | 100% | 100% | 100% |
| Insecure deserialization | 1 | 50% | 100% | 100% | 100% |
| Path traversal | 1 | 100% | 100% | 100% | 100% |
| SQL injection | 1 | 100% | 100% | 100% | 100% |
| SSRF | 1 | 100% | 100% | 100% | 100% |
| Weak randomness | 1 | 100% | 0% | 0% | 100% |
| XSS | 1 | 0% | 100% | 100% | 100% |

## Dev split (tuned against; optimistic)

Prompts, custom Semgrep rules and the discovery guard were developed by reading failures on these cases, so treat these numbers as an upper bound.

| System | Precision | Recall | F1 | TP / FP / FN (run 1) | Safe apps wrongly flagged | Avg latency | Tokens / review | Cost / review |
|---|---|---|---|---|---|---|---|---|
| **A** LLM-only reviewer | 0.88 | 0.78 | 0.82 | 14 / 2 / 4 | 0% | 45.1s | 766 | $0.00017 |
| **B** Scanner-only pipeline | 0.85 | 0.94 | 0.89 | 17 / 3 / 1 | 75% | 12.7s | 0 | $0.00000 |
| **C** Agentic: scanners + analyst | 1.00 | 0.94 | 0.97 | 17 / 0 / 1 | 0% | 94.3s | 1358 | $0.00030 |
| **C+** Agentic + LLM discovery | 0.95 | 1.00 | 0.97 | 18 / 1 / 0 | 0% | 94.3s | 1358 | $0.00030 |

### Recall by vulnerability class (dev)

| Vulnerability class | Cases | A recall | B recall | C recall | C+ recall |
|---|---|---|---|---|---|
| Broken access control | 1 | 100% | 0% | 0% | 100% |
| Code/template injection | 1 | 100% | 100% | 100% | 100% |
| Command injection | 1 | 100% | 100% | 100% | 100% |
| Container misconfig | 3 | 33% | 100% | 100% | 100% |
| Hardcoded secrets | 2 | 100% | 100% | 100% | 100% |
| Insecure deserialization | 1 | 100% | 100% | 100% | 100% |
| Path traversal | 1 | 100% | 100% | 100% | 100% |
| SQL injection | 2 | 100% | 100% | 100% | 100% |
| SSRF | 1 | 100% | 100% | 100% | 100% |
| Vulnerable dependency | 3 | 33% | 100% | 100% | 100% |
| Weak crypto | 1 | 100% | 100% | 100% | 100% |
| XSS | 1 | 100% | 100% | 100% | 100% |

## Automated remediation (held-out, `openai/gpt-oss-20b`, 1 run(s))

Each vulnerable case runs the full pipeline with remediation on. A hidden exploit test, never shown to the system, is the independent oracle for whether a *verified* fix really removes the vulnerability.

| Metric | Result |
|---|---|
| Confirmed real vulnerabilities attempted | 9 (run 1) |
| **Automated fix success rate** (fix passed every verification check) | 67% |
| Exploit oracle: verified fix really blocks the exploit | 75% (on 4 cases that have an exploit test) |
| **Post-fix test pass rate** (proposed patches whose tests passed, all attempts) | 78% |
| **Security-rescan pass rate** (patches passing tests that also cleared the rescan) | 86% |
| Average attempts per attempted finding | 1.56 |
| **Human intervention rate** (real findings without a verified fix, plus needs-review findings) | 40% |
| Tokens per case (analysis + discovery + remediation) | 4116 |

| Class | Fix attempts | Verified fixes |
|---|---|---|
| Broken access control | 1 | 1 |
| CWE-939 | 1 | 0 |
| Command injection | 1 | 1 |
| Insecure deserialization | 1 | 1 |
| Path traversal | 1 | 0 |
| SQL injection | 1 | 1 |
| SSRF | 1 | 0 |
| Weak randomness | 1 | 1 |
| XSS | 1 | 1 |

## Automated remediation (dev split, `openai/gpt-oss-120b`)

Developed against, so optimistic; shown because it used the stronger model.

| Metric | Result |
|---|---|
| Confirmed real vulnerabilities attempted | 18 (run 1) |
| **Automated fix success rate** (fix passed every verification check) | 78% |
| Exploit oracle: verified fix really blocks the exploit | 83% (on 6 cases that have an exploit test) |
| **Post-fix test pass rate** (proposed patches whose tests passed, all attempts) | 94% |
| **Security-rescan pass rate** (patches passing tests that also cleared the rescan) | 82% |
| Average attempts per attempted finding | 1.61 |
| **Human intervention rate** (real findings without a verified fix, plus needs-review findings) | 30% |
| Tokens per case (analysis + discovery + remediation) | 4628 |

| Class | Fix attempts | Verified fixes |
|---|---|---|
| Broken access control | 1 | 1 |
| CWE-352 | 1 | 1 |
| Command injection | 1 | 1 |
| Container misconfig | 4 | 4 |
| Hardcoded secrets | 2 | 1 |
| Insecure deserialization | 1 | 0 |
| Path traversal | 1 | 1 |
| SQL injection | 2 | 2 |
| SSRF | 1 | 0 |
| Vulnerable dependency | 3 | 3 |
| Weak crypto | 1 | 0 |

## Reading these results

What the data supports (small corpus, see [benchmark.md](benchmark.md) for limits):

* **Scanners alone over-report.** Scanner-only flagged 25% of the safe held-out apps (75% on dev). **Analyst triage removed every one of those false alarms in both splits without losing any true positive** (C recall equals B recall, C precision is 1.00).
* **Scanners have a recall ceiling.** They miss logic flaws and weak randomness (B and C recall 0% for those classes). The LLM discovery pass (C+) recovers most of them, at the cost of an occasional false positive: it is a precision/recall trade, which is why it is reported separately.
* **LLM-only is competitive on F1 but different in kind.** On this corpus it lands between scanner-only and the agentic system, varies run to run (held-out F1 0.75 to 0.88), misses whole classes that need tools (dependency CVEs and Dockerfile misconfiguration: 33% recall on dev), and provides no evidence trail, verification or fixes.
* **Automated remediation works for the mechanical classes and hands the rest to humans.** Verified fixes were produced for SQL and command injection, XSS, dependency bumps, container hardening, and (in the runs above) the access-control and weak-randomness cases. SSRF, insecure deserialization, path traversal, password hashing and some secrets failed or were declined in at least one run: they tend to need a behaviour change, or a scanner keeps flagging the safe pattern, so a person decides. A failed attempt leaves no patch behind.
* **Only one remediation run** was affordable on the held-out split, so its spread is unknown.

### A target counts as "real" if it lies within 6 lines of a ground-truth vulnerability
Remediation targets are judged by proximity, not CWE, so a neighbouring finding of a different class on the same statement is counted as real. This slightly flatters the denominator of the class table.

## Measured résumé bullet

> Built an autonomous GitHub PR security reviewer (LangGraph, MCP, FastAPI) that orchestrates Semgrep, CodeQL, Gitleaks, Trivy and Syft in network-isolated sandboxes, triages findings with an LLM analyst, and fixes them through a verified loop (build, tests, security rescan, bounded retries) that ends in a human-approved PR. On a 28-case benchmark (12 held-out cases, independent repeats), triage eliminated all false alarms on safe code (scanner-only flagged 25%), reaching F1 0.86, or 0.94 with LLM discovery, versus 0.75 scanner-only and 0.75 to 0.88 LLM-only; 67% of confirmed held-out findings received an automatically verified fix (75% of those with an exploit test confirmed by a hidden oracle), at about 20 s and $0.0001 per review (gpt-oss-20b).
