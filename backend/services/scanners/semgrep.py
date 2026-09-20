import json
import time
from pathlib import Path
from typing import Any

from backend.models.finding import Finding, compute_fingerprint
from backend.services.redact import redact_secrets
from backend.services.sandbox import Mount, SandboxSpec, run_sandboxed
from backend.services.scanners.base import ScanContext, ScanOutput
from backend.services.scanners.common import (
    enclosing_symbol,
    first_cwe,
    first_owasp,
    map_severity,
    read_snippet,
    secret_shape,
    short_id,
)  # fmt: skip

RULES_DIR = Path(__file__).resolve().parents[3] / "scanners" / "semgrep" / "rules"
IMAGE = "returntocorp/semgrep:latest"
# Registry metadata sometimes labels a rule with a tangential CWE; normalize the ones we have seen.
CWE_OVERRIDES = {
    "tainted-sql-string": "CWE-89",
    "avoid-pickle": "CWE-502",
    "avoid-mark-safe": "CWE-79",
}
DEFAULT_RULESETS = ("python.yml", "security-audit.yml", "flask.yml", "django.yml", "custom.yml")


def parse_semgrep(raw: str | dict[str, Any], root: Path) -> list[Finding]:
    data = json.loads(raw) if isinstance(raw, str) else raw
    findings: list[Finding] = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        path = r["path"].removeprefix("/src/")
        line, end = r["start"]["line"], r["end"]["line"]
        rule_id = r["check_id"].rsplit(".", 1)[-1]
        cwe = CWE_OVERRIDES.get(rule_id) or first_cwe(meta.get("cwe"))
        snippet = read_snippet(root, path, line, end)
        findings.append(
            Finding(
                id=short_id("semgrep", r["check_id"], path, line),
                scanner="semgrep",
                rule_id=rule_id,
                file=path,
                line=line,
                end_line=end,
                severity=map_severity(meta.get("impact") or r["extra"].get("severity")),
                cwe=cwe,
                owasp=first_owasp(meta.get("owasp")),
                title=(r["extra"].get("message") or rule_id).strip().splitlines()[0][:200],
                evidence=redact_secrets(snippet)[:1500],  # never persist a secret literal
                recommended_fix=None,
                symbol=enclosing_symbol(root, path, line),
                fingerprint=compute_fingerprint(
                    cwe=cwe, rule_id=rule_id, file=path,
                    symbol=enclosing_symbol(root, path, line), snippet=secret_shape(snippet) if cwe == "CWE-798" else snippet,
                ),
            )
        )  # fmt: skip
    return findings


class SemgrepAdapter:
    name = "semgrep"

    def __init__(self, rulesets: tuple[str, ...] = DEFAULT_RULESETS, rules_dir: Path = RULES_DIR):
        self.rulesets = [rules_dir / r for r in rulesets if (rules_dir / r).exists()]
        self.rules_dir = rules_dir

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        cmd = ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
        cmd += ["--exclude", ".git", "--exclude", "node_modules", "--exclude", ".venv"]
        for rs in self.rulesets:
            cmd += ["--config", f"/rules/{rs.name}"]
        res = await run_sandboxed(
            SandboxSpec(
                image=IMAGE, command=[*cmd, "/src"], timeout_s=ctx.timeout_s,
                mounts=[Mount(ctx.root, "/src"), Mount(self.rules_dir, "/rules")],
            )
        )  # fmt: skip
        if res.timed_out or not res.stdout.strip().startswith("{"):
            err = "timeout" if res.timed_out else res.stderr[-300:] or f"exit {res.exit_code}"
            return ScanOutput("semgrep", [], time.monotonic() - start, error=err)
        return ScanOutput(
            "semgrep", parse_semgrep(res.stdout, ctx.root), time.monotonic() - start,
            raw_bytes=len(res.stdout),
        )  # fmt: skip
