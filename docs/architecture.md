# Architecture

## Principle

Deterministic tools produce **evidence**. Agents **orchestrate and reason** over it. Automated
**verification** gates every remediation. No component both proposes and approves its own output:
the analyst does not run scanners, the remediation agent cannot mark a fix verified, and only a human
can turn a verified fix into a pull request.

## Components

```
GitHub ──webhook──► FastAPI (HMAC check, idempotent) ──► Redis (arq) ──► worker
                                                                           │
                        ┌──────────────────────────────────────────────────┘
                        ▼
              LangGraph workflow (checkpointed in Postgres)
   ┌──────┐  ┌──────┐  ┌───────────┐  ┌─────────┐  ┌──────────┐  ┌────────┐
   │ plan │─►│ scan │─►│ correlate │─►│ analyze │─►│ discover │─►│ report │─► (remediation subgraph)
   └──────┘  └──┬───┘  └───────────┘  └────┬────┘  └────┬─────┘  └────────┘
                │ MCP tools                  │ LLM       │ LLM
                ▼                            ▼           ▼
   ┌────────────────────────────┐     LLM client (rate limit, budget, cache, retries)
   │ MCP server                 │
   │  read · scan · exec        │◄── remediation: propose ─► verify ─► retry ≤3 ─► record
   │  comment · repo_write      │                                                      │
   └───────────┬────────────────┘                                          human approval (API/dashboard)
               ▼                                                                       │
   sandbox containers (no network, non-root, capped)                       MCP repo_write ─► acsr/* branch ─► PR
   Semgrep · CodeQL · Gitleaks · Trivy · Syft · pytest · ruff
                        │
                        ▼
   PostgreSQL: repositories, scans, findings, tool_runs, audit_events, remediations, LangGraph checkpoints
```

## The workflow

| Node | Kind | What it does |
|---|---|---|
| `plan` | deterministic | Detects languages, frameworks, manifests, Dockerfiles; chooses scanners and records why. |
| `scan` | tools via MCP | Runs the chosen scanners in parallel with timeouts. A failing scanner degrades the scan, never aborts it. |
| `correlate` | deterministic | Merges findings by fingerprint, then by (file, CWE family, adjacent lines) for code analyzers. |
| `analyze` | LLM | Verdict per finding from code context plus curated CWE guidance. Must cite real line numbers or the verdict is downgraded to *needs review*. |
| `discover` | LLM | Finds logic flaws scanners cannot see. Same grounding rules; cannot repeat scanner findings. |
| `report` | deterministic | One sanitized markdown comment, updated in place on every push. |
| `remediate` subgraph | LLM + tools | For each confirmed finding: propose → guardrails → verify → retry (≤3) → record. |

PR-scoped: findings are tagged `new` (on lines the PR changed) or `existing`. The report leads with `new`.

### Deterministic shortcuts (no LLM tokens)
Dependency CVEs (verdict from reachability), Dockerfile misconfigurations, placeholder/test secrets, and
dependency upgrades in `requirements.txt` are decided or patched by code.

## Finding identity

`fingerprint = sha256(CWE-or-rule | path | enclosing function | whitespace-normalised snippet)`.
Line numbers are excluded so a patch that shifts code keeps its identity. Secret values are never hashed;
secrets are identified by the source line with its string literals removed (`AWS_KEY =`).
Across a patch, "is the same issue still there?" is decided by `same_issue` (file + CWE family + same
function or nearby line), because the snippet, and therefore the fingerprint, has changed.

## What "fix verified" means

All must hold on a throwaway copy of the workspace with the patch applied:

1. The patch passed the guardrails: only the finding's file, never tests, exactly-once match, no new
   third-party imports, ≤ 40 changed lines, still parses.
2. The project builds (`compileall`) and `ruff` reports no broken code (syntax errors, undefined names).
3. The project's own tests pass, in a sandbox with no network. No tests means no verified fix.
4. A rescan with the same scanners no longer reports the original issue.
5. The rescan reports no new medium-or-higher finding.

Fixes accumulate: each verified fix is the base for the next, so later fixes are verified against the
code as it would actually be merged.

## MCP tool surface

| Group | Tools | Enabled |
|---|---|---|
| `read` | `get_repository`, `get_pull_request`, `get_pull_request_files`, `get_file`, `get_commit`, `workspace_info`, `workspace_get_file`, `workspace_list_files`, `security_guidance` | default |
| `scan` | `run_semgrep`, `run_gitleaks`, `run_codeql`, `run_trivy`, `generate_sbom` | default |
| `exec` | `run_tests`, `run_linter`, `build_project` | default (sandboxed) |
| `comment` | `post_review_comment` | `POST_PR_COMMENTS` |
| `repo_write` | `create_branch`, `apply_patch`, `create_pull_request` | `ALLOW_GITHUB_WRITE` + human approval |

Tools of a disabled group are not advertised at all, and are also refused if called. The model refers to
workspaces by opaque id and never supplies host paths. Every call is audited (arguments redacted) and its
output size-capped. Write tools only accept `acsr/*` branches and never merge.

## Data model

`repositories` ← `scans` ← `findings`, `tool_runs`, `audit_events`, `remediations`. `audit_events` holds the
agent trace (planner/scanner/analyst/remediation decisions), every MCP tool call, and the human approval
with the approver's name. LangGraph checkpoints live in the same database, keyed by scan id.

## Deployment

`docker compose`: postgres, redis, migrate (alembic), api, worker, docker-proxy, frontend; observability
profile adds Prometheus, Grafana and Jaeger. The worker launches scanner and test containers as siblings
through a restricted Docker socket proxy, with the project mounted at the same absolute path as on the
host so volume paths resolve. See [security-model.md](security-model.md) for the trust boundaries this implies.

## Decisions that differ from the original blueprint

| Change | Why |
|---|---|
| Benchmark harness built in Week 2, not Week 5 | Every design choice needed a measurement. It found real bugs in the scoring, the correlator and the discovery prompt. |
| PR-scoped reporting | Whole-repo findings flood reviewers with old issues. |
| Python-first | CodeQL needs builds for compiled languages; each language multiplies benchmark work. |
| No OWASP Dependency-Check | Duplicates Trivy, needs an NVD key, slow first run. |
| Adapters as plain Python first, MCP wrapper second | MCP is a thin layer over already-tested code. |
| LLM discovery pass added | Access-control flaws are invisible to scanners; only reasoning finds them. Measured separately (C+) because it costs precision. |
| Rate-limit-aware LLM client | The provider key allows 8,000 tokens/minute. |
| Custom Semgrep rules | Stock rules missed low-entropy credentials and SQL built from function parameters. |
