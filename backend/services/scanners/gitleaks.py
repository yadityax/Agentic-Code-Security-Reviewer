import json
import time
from pathlib import Path
from typing import Any

from backend.models.finding import Finding, Severity, compute_fingerprint
from backend.services.sandbox import Mount, SandboxSpec, run_sandboxed
from backend.services.scanners.base import ScanContext, ScanOutput
from backend.services.scanners.common import enclosing_symbol, read_snippet, secret_shape, short_id

IMAGE = "zricethezav/gitleaks:latest"


def parse_gitleaks(raw: str | list[dict[str, Any]], root: Path) -> list[Finding]:
    """Normalize gitleaks JSON. Secret values are never copied into a finding."""
    data = json.loads(raw) if isinstance(raw, str) else raw
    findings = []
    for r in data or []:
        path = r["File"].removeprefix("/src/")
        line = r["StartLine"]
        rule = r["RuleID"]
        symbol = enclosing_symbol(root, path, line)
        # Identify *which* secret without hashing its value: keep the line with string literals stripped
        # (leaves e.g. `AWS_KEY =`), so two secrets in one file get distinct fingerprints.
        shape = secret_shape(read_snippet(root, path, line))
        findings.append(
            Finding(
                id=short_id("gitleaks", rule, path, line),
                scanner="gitleaks",
                rule_id=rule,
                file=path,
                line=line,
                end_line=r.get("EndLine") or line,
                severity=Severity.HIGH,
                cwe="CWE-798",
                owasp="A07",
                title=f"Hardcoded secret: {r.get('Description') or rule}",
                evidence=f"{r.get('Description') or rule} detected at {path}:{line} (value redacted)",
                recommended_fix="Remove the credential, rotate it, and load it from the environment or a secret manager.",
                symbol=symbol,
                fingerprint=compute_fingerprint(
                    cwe="CWE-798", rule_id=rule, file=path, symbol=symbol, snippet=shape
                ),
            )
        )  # fmt: skip
    return findings


class GitleaksAdapter:
    name = "gitleaks"

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        res = await run_sandboxed(
            SandboxSpec(
                image=IMAGE, timeout_s=ctx.timeout_s, mounts=[Mount(ctx.root, "/src")],
                command=["dir", "/src", "--report-format", "json", "--report-path", "-",
                         "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"],
            )
        )  # fmt: skip
        out = res.stdout.strip()
        if res.timed_out or not (out.startswith("[") or out == ""):
            err = "timeout" if res.timed_out else res.stderr[-300:] or f"exit {res.exit_code}"
            return ScanOutput("gitleaks", [], time.monotonic() - start, error=err)
        findings = parse_gitleaks(out, ctx.root) if out else []
        return ScanOutput("gitleaks", findings, time.monotonic() - start, raw_bytes=len(out))
