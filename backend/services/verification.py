"""Verification agent: a fix is accepted only if tools, not the model, confirm it."""

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.models.finding import Finding, Severity
from backend.services.correlator import correlate
from backend.services.cwe import family
from backend.services.mcp_client import MCPTools, mcp_adapters
from backend.services.remediation import AppliedPatch
from backend.services.scanners.base import ScanContext
from backend.services.workspace import detect_languages
from mcp_server.workspaces import WorkspaceInfo, WorkspaceRegistry

SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
LINE_WINDOW = 8


def same_issue(a: Finding, b: Finding) -> bool:
    """Do two findings (before/after a patch) describe the same weakness at the same place?

    Fingerprints are useless across a patch (the snippet changed), so match on file, CWE family, and
    either the enclosing function or a nearby line.
    """
    if a.file != b.file or family(a.cwe) != family(b.cwe):
        return False
    if a.package or b.package:
        return a.package == b.package and a.cve == b.cve
    if family(a.cwe) == "CWE-798":
        return a.symbol == b.symbol and abs(a.line - b.line) <= LINE_WINDOW
    return (a.symbol is not None and a.symbol == b.symbol) or abs(a.line - b.line) <= LINE_WINDOW


def persisting(original: Finding, rescan: list[Finding]) -> list[Finding]:
    return [f for f in rescan if same_issue(original, f)]


def introduced(
    baseline: list[Finding], rescan: list[Finding], min_severity: Severity = Severity.MEDIUM
) -> list[Finding]:
    return [
        f
        for f in rescan
        if SEV_RANK[f.severity] >= SEV_RANK[min_severity]
        and not any(same_issue(b, f) for b in baseline)
    ]


@dataclass
class VerificationResult:
    passed: bool
    retriable: bool = True
    checks: dict[str, Any] = field(default_factory=dict)
    failure: str = ""  # fed back to the remediation agent on retry
    persisting: list[str] = field(default_factory=list)
    introduced: list[str] = field(default_factory=list)


def _describe(fs: list[Finding]) -> list[str]:
    return [f"{f.file}:{f.line} {f.cwe or f.rule_id} {f.title[:70]}" for f in fs[:6]]


def has_tests(root: Path) -> bool:
    return any(root.rglob("test_*.py")) or any(root.rglob("*_test.py"))


class Verifier:
    def __init__(
        self,
        tools: MCPTools,
        registry: WorkspaceRegistry,
        scanners: set[str],
        baseline: list[Finding],
        *,
        require_tests: bool = True,
    ) -> None:
        self.tools, self.registry, self.scanners = tools, registry, scanners
        self.baseline, self.require_tests = baseline, require_tests
        self._tmp: list[Path] = []

    def make_copy(self, root: Path, patch: AppliedPatch | None = None) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="acsr-verify-"))
        self._tmp.append(tmp)
        dest = tmp / "w"
        shutil.copytree(
            root,
            dest,
            ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "node_modules"),
            symlinks=True,
        )
        for rel, content in (patch.files if patch else {}).items():
            (dest / rel).write_text(content)
        return dest

    def cleanup(self) -> None:
        for t in self._tmp:
            shutil.rmtree(t, ignore_errors=True)
        self._tmp.clear()

    async def baseline_tests(self, root: Path) -> dict[str, Any]:
        if not has_tests(root):
            return {"skipped": True, "reason": "no tests found"}
        return await self._run_tests(root)

    async def _run_tests(self, root: Path) -> dict[str, Any]:
        wid = self.registry.register(WorkspaceInfo(root, [], {}, detect_languages(root)))
        try:
            res: dict[str, Any] = await self.tools.call("run_tests", workspace_id=wid, path=".")
            return res
        finally:
            self.registry.drop(wid)

    async def verify(
        self, finding: Finding, patch: AppliedPatch, current_root: Path
    ) -> tuple[VerificationResult, Path]:
        root = self.make_copy(current_root, patch)
        wid = self.registry.register(
            WorkspaceInfo(root, list(patch.files), {}, detect_languages(root))
        )
        checks: dict[str, Any] = {}
        try:
            build = await self.tools.call("build_project", workspace_id=wid)
            checks["build"] = {"ok": build["ok"]}
            if not build["ok"]:
                return VerificationResult(
                    False, checks=checks, failure=f"build failed:\n{build['output_tail']}"
                ), root

            lint = await self.tools.call("run_linter", workspace_id=wid)
            checks["lint"] = {"clean": lint["clean"]}
            if not lint["clean"]:
                return VerificationResult(
                    False,
                    checks=checks,
                    failure=f"linter found broken code:\n{lint['output_tail']}",
                ), root

            if has_tests(root):
                tests = await self.tools.call("run_tests", workspace_id=wid, path=".")
                checks["tests"] = {
                    "passed": tests["passed"],
                    "counts": tests["counts"],
                    "timed_out": tests["timed_out"],
                }
                if not tests["passed"]:
                    return VerificationResult(
                        False,
                        checks=checks,
                        failure=f"the project's tests fail after your patch:\n{tests['output_tail']}",
                    ), root
            else:
                checks["tests"] = {"skipped": True, "reason": "no tests found"}
                if self.require_tests:
                    return VerificationResult(
                        False,
                        retriable=False,
                        checks=checks,
                        failure="the project has no tests, so the fix cannot be verified",
                    ), root

            adapters = mcp_adapters(self.tools, self.registry, wid, self.scanners)
            ctx = ScanContext(
                root=root, changed_files=list(patch.files), languages=detect_languages(root)
            )
            outs = [await a.run(ctx) for a in adapters.values()]
            errors = {o.scanner: o.error for o in outs if o.error}
            rescan = correlate([f for o in outs for f in o.findings])
            checks["rescan"] = {"findings": len(rescan), "scanner_errors": errors}
            if errors:
                return VerificationResult(
                    False, checks=checks, failure=f"security rescan failed to run: {errors}"
                ), root

            still = persisting(finding, rescan)
            new = introduced(self.baseline, rescan)
            checks["rescan"] |= {"original_finding_gone": not still, "new_findings": len(new)}
            if still:
                return VerificationResult(
                    False,
                    checks=checks,
                    persisting=_describe(still),
                    failure="the security rescan still reports the original issue:\n"
                    + "\n".join(_describe(still)),
                ), root
            if new:
                return VerificationResult(
                    False,
                    checks=checks,
                    introduced=_describe(new),
                    failure="your patch introduced new findings:\n" + "\n".join(_describe(new)),
                ), root
            return VerificationResult(True, checks=checks), root
        finally:
            self.registry.drop(wid)
