"""Trivy (vulnerabilities, misconfiguration, secrets) and Syft (SBOM) adapters. Both run offline."""

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from backend.models.finding import Finding, Severity, compute_fingerprint
from backend.services.sandbox import Mount, SandboxSpec, run_sandboxed
from backend.services.scanners.base import ScanContext, ScanOutput
from backend.services.scanners.common import (
    enclosing_symbol,
    first_cwe,
    map_severity,
    read_snippet,
    secret_shape,
    short_id,
)

TRIVY_IMAGE = "aquasec/trivy:latest"
SYFT_IMAGE = "anchore/syft:latest"
CACHE_VOLUME = "acsr_scanner-cache"  # pre-populated in Week 0 (vulnerability DB + checks)

# distribution name -> import name, where they differ
IMPORT_ALIASES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "python-dateutil": "dateutil",
    "pycryptodome": "Crypto",
    "msgpack-python": "msgpack",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def is_imported(root: Path, package: str) -> bool | None:
    """Best-effort reachability for Python packages: is the package imported anywhere in source?"""
    py = [
        p
        for p in root.rglob("*.py")
        if not {".git", ".venv", "node_modules", "venv"} & set(p.parts)
    ]
    if not py:
        return None
    mod = IMPORT_ALIASES.get(_norm(package), _norm(package).replace("-", "_"))
    pat = re.compile(
        rf"^\s*(?:from\s+{re.escape(mod)}(?:\.\w+)*\s+import|import\s+{re.escape(mod)}(?:\.\w+)*\b|import\s+[\w\s,.]*\b{re.escape(mod)}\b)",
        re.M | re.I,
    )
    return any(pat.search(p.read_text(errors="replace")) for p in py)


def _manifest_line(root: Path, target: str, package: str) -> int:
    try:
        for i, ln in enumerate((root / target).read_text(errors="replace").splitlines(), 1):
            if re.match(rf"\s*{re.escape(package)}\b", ln, re.I):
                return i
    except OSError:
        pass
    return 1


def parse_trivy(raw: str | dict[str, Any], root: Path) -> list[Finding]:
    data = json.loads(raw) if isinstance(raw, str) else raw
    out: list[Finding] = []
    for res in data.get("Results") or []:
        target = res["Target"].removeprefix("/src/")
        for v in res.get("Vulnerabilities") or []:
            pkg, ver, cve = v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"]
            line = _manifest_line(root, target, pkg)
            fixed = v.get("FixedVersion")
            out.append(
                Finding(
                    id=short_id("trivy", cve, f"{target}:{pkg}", line),
                    scanner="trivy", rule_id=cve, file=target, line=line, severity=map_severity(v.get("Severity")),
                    cwe=first_cwe(v.get("CweIDs")) or "CWE-1104", cve=cve, package=pkg,
                    title=f"{pkg} {ver}: {v.get('Title') or cve}"[:200],
                    evidence=f"{pkg}=={ver} is affected by {cve}. Fixed in: {fixed or 'no fix available'}.",
                    recommended_fix=f"Upgrade {pkg} to {fixed}." if fixed else f"No fixed release of {pkg} yet; consider a replacement or mitigation.",
                    reachable=is_imported(root, pkg),
                    fingerprint=compute_fingerprint(cwe=None, rule_id=cve, file=target, symbol=pkg, snippet=f"{pkg}=={ver}"),
                )
            )  # fmt: skip
        for m in res.get("Misconfigurations") or []:
            cm = m.get("CauseMetadata") or {}
            line = cm.get("StartLine") or 1
            rid = m.get("AVDID") or m["ID"]
            snippet = read_snippet(root, target, line, cm.get("EndLine"))
            out.append(
                Finding(
                    id=short_id("trivy", rid, target, line),
                    scanner="trivy", rule_id=m["ID"], file=target, line=line, end_line=cm.get("EndLine") or line,
                    severity=map_severity(m.get("Severity")), cwe="CWE-16", title=m.get("Title") or m["ID"],
                    evidence=(m.get("Message") or m.get("Description") or "")[:600],
                    recommended_fix=(m.get("Resolution") or "")[:300] or None,
                    fingerprint=compute_fingerprint(cwe=None, rule_id=m["ID"], file=target, symbol=None, snippet=snippet),
                )
            )  # fmt: skip
        for sec in res.get("Secrets") or []:
            line = sec["StartLine"]
            shape = secret_shape(read_snippet(root, target, line))
            out.append(
                Finding(
                    id=short_id("trivy", sec["RuleID"], target, line),
                    scanner="trivy", rule_id=sec["RuleID"], file=target, line=line, severity=Severity.HIGH,
                    cwe="CWE-798", owasp="A07", title=f"Hardcoded secret: {sec.get('Title') or sec['RuleID']}",
                    evidence=f"{sec.get('Title')} detected (value redacted)",
                    symbol=enclosing_symbol(root, target, line),
                    fingerprint=compute_fingerprint(cwe="CWE-798", rule_id=sec["RuleID"], file=target, symbol=enclosing_symbol(root, target, line), snippet=shape),
                )
            )  # fmt: skip
    return out


class TrivyAdapter:
    name = "trivy"
    # bbolt takes an exclusive lock on the shared vulnerability DB, so scans in one process queue up.
    _db_lock = asyncio.Lock()

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        async with self._db_lock:
            return await self._run_locked(ctx, start)

    async def _run_locked(self, ctx: ScanContext, start: float) -> ScanOutput:
        res = await run_sandboxed(
            SandboxSpec(
                image=TRIVY_IMAGE, timeout_s=ctx.timeout_s, memory="4g",
                mounts=[Mount(ctx.root, "/src"), Mount(CACHE_VOLUME, "/cache", read_only=False)],
                command=["fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", "--skip-db-update",
                         "--skip-java-db-update", "--skip-check-update", "--offline-scan", "--no-progress",
                         "--cache-dir", "/cache/trivy", "--cache-backend", "memory", "/src"],
            )
        )  # fmt: skip
        out = res.stdout.strip()
        if res.timed_out or not out.startswith("{"):
            err = "timeout" if res.timed_out else (res.stderr[-300:] or f"exit {res.exit_code}")
            return ScanOutput("trivy", [], time.monotonic() - start, error=err)
        return ScanOutput(
            "trivy", parse_trivy(out, ctx.root), time.monotonic() - start, raw_bytes=len(out)
        )


class SyftAdapter:
    """Generates the SBOM. Produces no findings; the SBOM is stored as a scan artifact."""

    name = "syft"

    async def run(self, ctx: ScanContext) -> ScanOutput:
        start = time.monotonic()
        res = await run_sandboxed(
            SandboxSpec(image=SYFT_IMAGE, timeout_s=ctx.timeout_s, mounts=[Mount(ctx.root, "/src")],
                        command=["dir:/src", "-o", "cyclonedx-json", "-q"], env={"SYFT_CHECK_FOR_APP_UPDATE": "false"})
        )  # fmt: skip
        if res.timed_out or not res.stdout.strip().startswith("{"):
            err = "timeout" if res.timed_out else (res.stderr[-300:] or f"exit {res.exit_code}")
            return ScanOutput("syft", [], time.monotonic() - start, error=err)
        sbom = json.loads(res.stdout)
        comps = [
            {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl")}
            for c in sbom.get("components", [])
        ]
        return ScanOutput(
            "syft",
            [],
            time.monotonic() - start,
            artifacts={"sbom": {"format": "cyclonedx", "components": comps}},
        )
