# Agentic Code Security Reviewer — Execution Plan

> **Status (2026-09-20): Weeks 0–5 complete.** Unticked items are deliberately not built (see notes). Measured results: [results.md](results.md). Deviations from this plan are listed in [architecture.md](architecture.md).

Working plan derived from `Agentic_Code_Security_Reviewer_Project_Blueprint.docx`. Check items off as they land. Each week ends with an exit criterion that must pass before moving on.

**Core principle:** deterministic security tools produce evidence; agents orchestrate and reason; automated verification gates every remediation.

**Scope:** solo developer, ~5 weeks (Week 0 setup + Weeks 1–5). Target language: Python first, JS/TS only if time allows.

---

## 0. Decisions and Deviations from the Blueprint

| # | Decision | Reason |
|---|---|---|
| D1 | Benchmark harness starts in **Week 2**, full benchmark in Week 5 | Every design choice needs a measurement to justify it |
| D2 | **PR-scoped findings**: report only findings on changed lines or new vs. base branch | Whole-repo findings flood reviewers with old issues |
| D3 | Language scope: **Python** (JS/TS stretch) | CodeQL needs builds for compiled languages; each language multiplies benchmark work |
| D4 | **Trivy first**; OWASP Dependency-Check is optional (osv-scanner as alternative) | Overlaps Trivy; needs NVD API key; slow first DB download |
| D5 | Scanner adapters are **plain Python first**, wrapped by MCP in Week 3 | MCP becomes a thin layer over tested code |
| D6 | "Fix verified" is defined up front (see §3) | Gives the retry loop a precise pass/fail |
| D7 | Dashboard is **read-only** and cut first if Week 4 slips | Week 4 is overloaded |
| D8 | Queue: **arq or RQ**, not Celery | Lighter, enough for this workload |
| D9 | GitHub auth: fine-grained PAT for MVP, **GitHub App** before write tools ship | Per-repo, short-lived, least-privilege tokens |
| D10 | LLM access through a thin provider interface; **start with Groq** (`openai/gpt-oss-120b`, OpenAI-compatible API) | Key is validated; JSON output works, ~0.5 s latency. Multi-model routing is a stretch goal |
| D12 | **Rate-limit-aware LLM client**: token-per-minute limiter (key limit 8,000 TPM, configured at 7,000), request queueing, retry with backoff, per-scan token budget | The analyst runs one call per finding; without throttling a busy PR hits 429s. Also batch findings per call and cache by fingerprint |
| D11 | All scanners and all repo-code execution run in **Docker containers** | Isolation requirement; Docker 29 is already installed |

---

## 1. Environment Baseline

Installed: Python 3.13, Docker 29 + Compose, Node 20, npm 10, Java 21, git 2.43. Hardware: 40 cores, 125 GB RAM.

Missing (install or containerize): `uv`, `gh`, `psql`, Redis, Semgrep, Gitleaks, Trivy, Syft, CodeQL.

Needed from the user:
- [x] LLM API key: Groq, validated 2026-09-20 (in `.env`, gitignored)
- [x] GitHub test repo (throwaway, public) + fine-grained token (contents, pull requests, metadata)
- [x] Webhook tunnel (smee.io or ngrok)

---

## 2. Week 0 — Setup (1–2 days)

- [x] `git init`, `.gitignore`, `.env.example` (no real secrets committed)
- [x] Install `uv`; create `pyproject.toml` (Python 3.12+), ruff, mypy, pytest, pre-commit
- [x] Scaffold blueprint layout:
  ```
  backend/{api,agents,graph,models,services}/  backend/main.py
  mcp_server/{github_tools,security_tools,dev_tools}.py
  scanners/{codeql,semgrep,gitleaks,trivy,dependency_check}/
  frontend/  tests/{unit,integration,security}/
  benchmarks/{vulnerable_repos,expected_findings}/
  infra/{docker,github_actions,observability}/  prompts/  docs/
  docker-compose.yml  README.md  Makefile
  ```
- [x] `docker-compose.yml`: Postgres, Redis, API service; healthchecks; named volumes for scanner caches
- [x] Pre-pull scanner images and vuln DBs (Semgrep, Gitleaks, Trivy DB, Syft) into cached volumes
- [x] Download CodeQL CLI bundle and Python query packs (large; do this early)
- [x] CI stub in GitHub Actions: lint + pytest
- [x] `Makefile` targets: `up`, `down`, `test`, `lint`, `bench`

**Exit:** `docker compose up` gives a healthy stack and `make test` is green.

---

## 3. Definitions Used Throughout

**Finding fingerprint:** hash of `(scanner-independent CWE, normalized file path, enclosing function/symbol, code-snippet hash)`. Line numbers are excluded because patches shift them. Used for dedup, base-vs-head diff, and "new finding" checks.

**Fix verified** — all must hold:
1. Original finding's fingerprint is absent in the rescan.
2. Existing tests pass (and build/lint pass).
3. No new findings (by fingerprint) compared with the pre-patch scan.
4. Patch is within limits: ≤ N changed lines, only allowed paths, no test deletion or weakening, no new dependencies unless the finding is dependency-related.

**Benchmark match:** a reported finding is a true positive if it matches a ground-truth entry on file + CWE (or CWE family) + line within a ±k window.

**Retry cap:** 3 remediation attempts per finding. Timeouts on every tool call and every graph run.

---

## 4. Week 1 — MVP Pipeline

Goal: a PR on the test repo receives a security report comment.

- [x] FastAPI app with `/webhook/github`; verify `X-Hub-Signature-256` (HMAC); reject invalid; handle `pull_request` opened/synchronize
- [x] Redis queue (arq/RQ) and a worker; idempotency on delivery ID
- [x] Repo ingestion: shallow clone/fetch of PR head + base into an isolated temp workspace; compute changed files and changed line ranges
- [x] Common finding schema (Pydantic) per blueprint §7, plus `fingerprint`, `pr_scope` (new/existing), `status` enum
- [x] Postgres models + Alembic migrations: `repositories`, `scans`, `findings`, `tool_runs`, `audit_events`
- [x] Semgrep adapter (containerized) → normalized findings; use `p/security-audit` / `p/python` rulesets
- [x] Gitleaks adapter (working tree first; history optional) → normalized findings; **redact secret values** before storage
- [x] PR-scope filter (D2)
- [x] LLM client interface + first prompt: structured (Pydantic) report from findings + code snippets
- [x] Post report as a PR comment
- [x] Unit tests for adapters and normalization using saved scanner output fixtures

**Exit:** opening a PR on the test repo posts a report; adapters and webhook signature checks are unit-tested.

---

## 5. Week 2 — Agentic Core + Benchmark Harness

Goal: the analyst validates findings with cited reasons, and there is a measurable baseline.

- [x] LangGraph workflow: `plan → scan → normalize → correlate → analyze → report` with Postgres checkpointer and explicit state schema
- [x] Planner agent: detect languages/frameworks, choose scanners (deterministic rules first, LLM only for ambiguous cases)
- [x] Scanner node runs adapters in parallel with timeouts
- [x] CodeQL adapter (Python): DB creation → analysis → SARIF → normalized findings
- [x] Finding correlator: dedup by fingerprint / file + line window + CWE; merge evidence from multiple scanners
- [x] Security Analyst agent: pulls code context around each finding (function body, callers, sanitizers), outputs `TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW`, confidence, exploitability explanation, priority, and cited evidence
- [x] Prompt-injection hygiene: repo text is delimited data, never instructions; output validated against schema
- [x] Token budget per scan; cache LLM results in Redis keyed by fingerprint + code hash
- [x] **Benchmark harness** (`make bench`): loads cases from `benchmarks/`, runs three systems, computes precision / recall / F1 / FPR
  - [x] Baseline A: LLM-only reviewer (diff/files in prompt, no scanners)
  - [x] Baseline B: scanner-only pipeline (no LLM triage)
  - [x] System C: agentic pipeline
  - [x] First 10–15 labeled cases in `benchmarks/expected_findings/`

**Exit:** `make bench` prints a comparison table for A/B/C on the initial cases; analyst output cites evidence for each verdict.

---

## 6. Week 3 — MCP Server, Trivy, Correlation

Goal: agents reach every capability only through narrowly scoped MCP tools.

- [x] MCP server (`mcp_server/`) with tools grouped by privilege:
  - Read-only: `get_repository`, `get_pull_request`, `get_pull_request_files`, `get_file`, `get_commit`, `run_semgrep`, `run_gitleaks`, `run_codeql`, `run_trivy`, `generate_sbom`
  - Write (disabled by default, enabled per scan): `post_review_comment`, `create_branch`, `apply_patch`, `create_pull_request`
  - Execution (sandboxed): `run_tests`, `run_linter`, `build_project`
- [x] Every tool: typed input schema, path allow-list, output size cap, timeout, audit log entry
- [x] Agents call tools via MCP client; no shell access for the LLM
- [x] Sandbox runner for `run_tests` / `build_project`: container with `--network none`, non-root, read-only source mount + scratch volume, memory/CPU/pids limits, hard timeout; **no tokens or secrets in the container**
- [x] Trivy adapter (fs, config, secrets, image if a Dockerfile exists) → normalized findings
- [x] Syft SBOM generation; store SBOM per scan
- [x] Dependency findings enriched with reachability hint (is the vulnerable package imported/used?)
- [ ] (Optional) Dependency-Check or osv-scanner adapter — **not built**: Trivy covers dependency CVEs (decision D4)
- [x] Security knowledge lookup: static CWE/OWASP mapping and short remediation guidance (`backend/services/knowledge.py`); **Qdrant vector store not built** (stretch)
- [x] CWE/OWASP/CVE mapping filled in on every finding where applicable
- [x] Tests: mocked MCP tools → deterministic agent-decision tests; tool-permission tests (write tools refused when disabled)

**Exit:** the full review runs through MCP only; write tools are demonstrably blocked unless remediation is enabled.

---

## 7. Week 4 — Remediation, Verification, PR Creation

Goal: at least one vulnerability class goes from finding → verified fix → opened PR.

- [x] Remediation agent: minimal patch (unified diff) for `TRUE_POSITIVE` findings above a confidence threshold; refuses when evidence is insufficient
- [x] Patch guardrails: size limit, allowed paths, no test deletion, syntax check before apply
- [x] Verification agent applies the patch in a sandbox worktree and runs: tests → lint → build → security rescan → fingerprint diff (per §3)
- [x] Retry loop (LangGraph conditional edge): feed failure output back to the remediation agent, cap of 3, then mark `FIX_FAILED` with the reason
- [x] GitHub agent: create branch, commit, open remediation PR against the PR branch (or base, configurable); PR body includes finding, evidence, patch rationale, and verification results
- [x] **Human approval gate** before any PR creation; never auto-merge
- [x] Switch to GitHub App credentials (D9) for write operations
- [x] Audit trail: every tool call, patch, and verification result in `audit_events`
- [x] Read-only dashboard (D7, cut first if late): findings list, evidence, severity, status, agent trace, scan history, remediation status. React + TypeScript + Tailwind; API endpoints in FastAPI
- [x] Tests: patch-verification unit tests; end-to-end fix on a known vulnerable snippet

**Exit:** on the benchmark, one vulnerability class completes finding → fix → verification → remediation PR without manual steps except the approval.

---

## 8. Week 5 — Evaluation, Observability, Deployment, Docs

Goal: reproducible results and a clean deployment.

- [x] Grow the benchmark across the blueprint's classes: 28 cases, 26 ground-truth vulnerabilities, every class covered
- [x] Ground-truth sources: OWASP Benchmark / intentionally vulnerable Python apps, real CVE-fix commits from open source (these have tests), and a few self-injected bugs; label by file + CWE + line window
- [x] Hold-out split: no tuning of Semgrep rules or prompts on held-out cases
- [x] Metrics report, per system (A/B/C) and per vulnerability class:
  - Precision, recall, F1, false-positive rate
  - True-positive validation rate
  - Automated fix success rate
  - Post-fix test pass rate
  - Security-rescan pass rate
  - Average review latency
  - LLM tokens and cost per review
  - Human intervention rate
  - Average agent/tool iterations
- [x] Report generator writes `docs/results.md` (table + short analysis, including where the LLM-only baseline wins)
- [x] OpenTelemetry traces + LangSmith tracing, with secret redaction in logs and traces
- [x] Prometheus metrics + Grafana dashboard: metrics, scrape config and a provisioned dashboard are in place; **the observability profile was not started end-to-end during this session** (Compose config validates)
- [x] Production-style `docker-compose.yml` — verified end-to-end on this machine (`make up` + `make demo`); **a clean-machine run was not performed**
- [x] Docs: `README.md` (quickstart), `docs/architecture.md`, `docs/security-model.md`, `docs/benchmark.md`
- [x] Demo: `make demo` script plus dashboard screenshots in `docs/img/` (no video recording); resume bullet in `docs/results.md`

**Exit:** `docker compose up` on a clean machine works; `make bench` reproduces the results table.

---

## 9. Security Requirements (Checklist, Applies Every Week)

- [x] Repo code, issue text, and PR comments are treated as untrusted input
- [x] Least-privilege GitHub tokens; read-only until remediation is authorized
- [x] Arbitrary code runs only in isolated containers (no network, non-root, resource-limited)
- [x] No secrets in prompts; secrets redacted from logs and LLM traces
- [x] Timeouts, memory limits, and retry limits on every tool and graph run
- [x] Human approval before PR creation or any high-impact change; no auto-merge
- [x] Audit trail of tool calls, patches, and verification results
- [x] Webhook signature verification and delivery idempotency

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| LLM-only baseline matches or beats agentic on some classes | Report honestly; use it to identify where agents add value |
| Patches pass tests but don't fix the vulnerability | Rescan + fingerprint diff; measure separately in the benchmark |
| Scanner setup (CodeQL DB, Trivy DB) eats a week | Pre-pull and cache in Week 0 |
| Benchmark repos lack working test suites | Choose repos on that criterion up front |
| Token cost grows with large diffs | Per-scan budget, analyze changed files + context only, Redis caching |
| CodeQL licensing for private repos | Keep benchmark on public repos |
| Week 4 overload | Cut the dashboard first (D7) |
| Prompt injection via repo content | Delimited data, schema-validated outputs, MCP-only tool access, patch guardrails |

---

## 11. Stretch Backlog (only after Week 5 exit)

- [ ] A2A: expose agents as independent services
- [ ] Qdrant-backed security knowledge / RAG
- [ ] Multi-model routing (cheap model for triage, strong model for remediation)
- [ ] JS/TS language support
- [ ] Dependency-Check adapter, if not done in Week 3
- [ ] Prometheus + Grafana dashboards — config and dashboard written; not run end-to-end (see Week 5)

---

## 12. Build Order Reference (from the Blueprint)

1. FastAPI + GitHub webhook → 2. Semgrep + Gitleaks → 3. Finding schema + PostgreSQL → 4. LLM Security Analyst → 5. LangGraph orchestration → 6. CodeQL → 7. Trivy + dependency scanning → 8. MCP tool server → 9. Patch generation → 10. Verification/retry loop → 11. GitHub remediation PR → 12. React dashboard → 13. Benchmark/evaluation → 14. Observability → 15. A2A + Qdrant

Deviation: the benchmark harness (item 13) is pulled forward to Week 2 per D1.
