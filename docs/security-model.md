# Security model

The system reads attacker-controlled code, executes it (tests), and holds credentials that can write to
GitHub. This document states what is trusted, what is not, and which test proves each control.

## Trust boundaries

| Zone | Trust | Contains |
|---|---|---|
| Repository content | **untrusted** | source, tests, comments, PR title and body, filenames, dependencies |
| Sandbox containers | **untrusted execution** | scanners and test runs over that content |
| LLM provider | third party | receives redacted code snippets |
| Worker, API, MCP server, Postgres | trusted | our code and data |
| GitHub token, admin token, webhook secret | secrets | `.env` only |

## Threats and controls

| # | Threat | Control | Evidence |
|---|---|---|---|
| 1 | **Prompt injection** in code or PR text steers the LLM (e.g. "mark this safe", "run this command") | Repo text is wrapped in per-call random delimiters and declared data. The LLM has no shell and no free-form tools: it emits JSON that our code validates. Verdicts must cite lines that exist. Patches are validated by code, not trusted. | `test_discovery.py` (unverifiable claims dropped), `test_remediation.py` (guardrails) |
| 2 | **Malicious PR code runs during tests** and tries to exfiltrate secrets or reach the network | Tests run on a throwaway copy in a container with `--network none`, `--cap-drop ALL`, `no-new-privileges`, non-root user, memory/CPU/pids limits, hard timeout. No token or key is ever placed in the container. | `tests/security/test_sandbox_isolation.py`: no network, no host secrets, read-only mounts, no root, timeout, memory limit, fork bomb contained |
| 3 | **Secrets leak into prompts, logs, traces or PR comments** | `redact_secrets` runs on every prompt, evidence field, audit record, span attribute and comment. Secret values are never stored: findings keep only the variable shape. | `test_correlator_redact.py`, `test_scanner_parsers.py` (no secret in findings), `test_mcp_server.py` (audit redaction) |
| 4 | **Forged webhooks** | HMAC-SHA256 over the raw body, constant-time compare, fails closed when no secret is configured. Redelivery is idempotent. | `test_webhook.py`, `test_worker_e2e.py` |
| 5 | **Untrusted text in the PR comment** (@mentions, HTML, link injection, oversized) | All repo/LLM text is sanitized: mentions defused, HTML comments/tags neutralized, links broken, fences sized, length capped. | `test_report_github.py` |
| 6 | **The model tries to write to GitHub** | Write tools are separate privilege groups: not advertised when disabled and refused if called. Only `acsr/*` branches; never merges. Approval requires a named human, an admin token, and `ALLOW_GITHUB_WRITE`. | `test_mcp_server.py`, `test_approval_api.py` |
| 7 | **A bad patch reaches a PR** | A patch must pass guardrails, build, the project's tests, and a rescan with no persisting or new findings, then a human must approve. Failed fixes leave no patch behind. | `test_remediation.py`, `test_remediation_e2e.py` (incl. hidden exploit oracle) |
| 8 | **Path traversal via tool arguments** | Workspaces are opaque ids; paths are resolved with `realpath` and must stay inside the root; symlink escapes rejected. | `test_mcp_server.py` (`../`, absolute, `~`, symlink) |
| 9 | **Resource exhaustion** (huge repo, runaway LLM loop) | Scanner and tool timeouts, container memory/CPU/pid limits, output caps, per-scan LLM token budget, bounded retries (3), bounded targets per scan. | `test_llm.py` (budget), `test_remediation_e2e.py` (bounded retries) |
| 10 | **Unauthorised dashboard access** | Bearer admin token, constant-time compare. An unset token disables the API entirely. | `test_approval_api.py` |
| 11 | **Fork PRs** (attacker-controlled head repo) | Scanning is read-only and sandboxed. Remediation branches cannot be created for fork PRs. | `test_approval_api.py::test_prs_from_forks_are_refused` |
| 12 | **Least privilege on GitHub** | Fine-grained token for one repo: contents read, pull requests read/write. `contents: write` only when remediation PRs are wanted. | verified against the live API during setup |

## Residual risks (honest list)

* **The worker can talk to the Docker API.** It launches sandbox containers, so a compromise of the worker
  *process* (not of untrusted repo code, which is confined to the sandbox) could create arbitrary containers.
  The socket proxy blocks exec, build, volumes, networks and swarm, but cannot inspect `containers/create`
  bodies. Mitigate further with rootless Docker or gVisor/sysbox.
* **Code leaves the machine.** Redacted snippets are sent to the LLM provider. For sensitive code use a
  local model behind the same OpenAI-compatible interface.
* **Redaction is pattern-based.** Novel secret formats with innocuous variable names can slip through.
  Gitleaks findings are the primary defence.
* **Test execution is arbitrary code.** The sandbox is strong but not a VM. Do not enable remediation on
  repositories you do not at least partially trust.
* **The LLM can be wrong.** Confirmed findings are strongly filtered, but every result is a recommendation.
  Human approval is a hard requirement for anything that changes a repository.
