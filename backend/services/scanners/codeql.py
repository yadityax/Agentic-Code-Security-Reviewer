"""CodeQL adapter. Runs the CLI inside a locked-down container: extraction may execute build tooling."""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from backend.models.finding import Finding, Severity, compute_fingerprint
from backend.services.redact import redact_secrets
from backend.services.sandbox import Mount, SandboxSpec, run_sandboxed
from backend.services.scanners.base import ScanContext, ScanOutput
from backend.services.scanners.common import enclosing_symbol, first_cwe, read_snippet, short_id

CODEQL_HOME = Path(__file__).resolve().parents[3] / ".tools" / "codeql"
IMAGE = "python:3.12-slim"  # provides python3 for the Python extractor; CodeQL bundle brings its own JDK
LANG_SUITES = {
    "python": "python-security-extended.qls",
    "javascript": "javascript-security-extended.qls",
}


def _severity(score: str | float | None, level: str | None) -> Severity:
    try:
        n = float(score) if score is not None else None
    except ValueError:
        n = None
    if n is not None:
        return (
            Severity.CRITICAL
            if n >= 9
            else Severity.HIGH
            if n >= 7
            else Severity.MEDIUM
            if n >= 4
            else Severity.LOW
        )
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM}.get(level or "", Severity.LOW)


def parse_sarif(raw: str | dict[str, Any], root: Path) -> list[Finding]:
    data = json.loads(raw) if isinstance(raw, str) else raw
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res["ruleId"]
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            cwe = next(
                (
                    c
                    for t in props.get("tags", [])
                    if (c := first_cwe(t.replace("external/cwe/cwe-", "CWE-")))
                ),
                None,
            )
            loc = res["locations"][0]["physicalLocation"]
            path = loc["artifactLocation"]["uri"].removeprefix("file:///src/").removeprefix("/src/")
            line = loc["region"]["startLine"]
            end = loc["region"].get("endLine", line)
            snippet = read_snippet(root, path, line, end)
            symbol = enclosing_symbol(root, path, line)
            findings.append(
                Finding(
                    id=short_id("codeql", rule_id, path, line),
                    scanner="codeql",
                    rule_id=rule_id,
                    file=path,
                    line=line,
                    end_line=end,
                    severity=_severity(props.get("security-severity"), res.get("level")),
                    cwe=cwe,
                    title=(rule.get("shortDescription", {}).get("text") or rule_id)[:200],
                    evidence=redact_secrets(
                        f"{res.get('message', {}).get('text', '')[:400]}\n{snippet}"
                    )[:1500],
                    symbol=symbol,
                    fingerprint=compute_fingerprint(
                        cwe=cwe, rule_id=rule_id, file=path, symbol=symbol, snippet=snippet
                    ),
                )
            )
    return findings


class CodeQLAdapter:
    name = "codeql"

    def __init__(self, home: Path = CODEQL_HOME) -> None:
        self.home = home

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        if not (self.home / "codeql").exists():
            return ScanOutput("codeql", [], 0.0, error=f"CodeQL bundle not found at {self.home}")
        langs = [lang for lang in LANG_SUITES if lang in ctx.languages]
        if not langs:
            return ScanOutput("codeql", [], 0.0)
        out_dir = Path(tempfile.mkdtemp(prefix="acsr-codeql-"))
        out_dir.chmod(0o777)
        findings: list[Finding] = []
        try:
            user = f"{os.getuid()}:{os.getgid()}"
            for lang in langs:
                sarif = f"/out/{lang}.sarif"
                script = (
                    f"/codeql/codeql database create /out/db-{lang} --language={lang} --source-root=/src --overwrite --threads=8 -q"
                    f" && /codeql/codeql database analyze /out/db-{lang} codeql/{lang}-queries:codeql-suites/{LANG_SUITES[lang]}"
                    f" --format=sarif-latest --output={sarif} --threads=8 -q"
                )
                res = await run_sandboxed(
                    SandboxSpec(
                        image=IMAGE, entrypoint="/bin/sh", command=["-c", script], timeout_s=ctx.timeout_s, user=user,
                        memory="8g", cpus=8, env={"HOME": "/tmp", "CODEQL_ALLOW_INSTALLATION_ANYWHERE": "true", "CODEQL_EXTRACTOR_PYTHON_DISABLE_LIBRARY_EXTRACTION": "true"},
                        mounts=[Mount(ctx.root, "/src"), Mount(self.home, "/codeql"), Mount(out_dir, "/out", read_only=False)],
                    )
                )  # fmt: skip
                f = out_dir / f"{lang}.sarif"
                if res.timed_out or not f.exists():
                    err = "timeout" if res.timed_out else (res.stderr or res.stdout)[-300:]
                    return ScanOutput(
                        "codeql", findings, time.monotonic() - start, error=f"{lang}: {err}"
                    )
                findings += parse_sarif(f.read_text(), ctx.root)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)
        return ScanOutput("codeql", findings, time.monotonic() - start)
