import shutil
from pathlib import Path

import pytest

from backend.graph.remediation import RemediationConfig
from backend.graph.workflow import Deps, run_scan
from backend.models.finding import FindingStatus
from backend.services.mcp_client import connect, mcp_adapters
from backend.services.sandbox import TEST_RUNNER_IMAGE, Mount, SandboxSpec, run_sandboxed
from backend.services.verification import Verifier
from mcp_server.context import ToolContext
from mcp_server.policy import DEFAULT_GROUPS, ToolPolicy
from mcp_server.server import build_server
from tests.fakes import ScriptedLLM

pytestmark = pytest.mark.integration
CASES = Path(__file__).resolve().parents[2] / "benchmarks" / "cases"
OLD = "rows = db.execute(f\"SELECT id, name, email FROM users WHERE name = '{name}'\").fetchall()"
GOOD = {
    "can_fix": True,
    "explanation": "bind the parameter",
    "edits": [
        {
            "file": "app.py",
            "old": OLD,
            "new": 'rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()',
        }
    ],
}
STILL_VULNERABLE = {
    "can_fix": True,
    "explanation": "format instead",
    "edits": [
        {
            "file": "app.py",
            "old": OLD,
            "new": "rows = db.execute(\"SELECT id, name, email FROM users WHERE name = '%s'\" % name).fetchall()",
        }
    ],
}
BREAKS_TESTS = {
    "can_fix": True,
    "explanation": "wrong shape",
    "edits": [
        {
            "file": "app.py",
            "old": OLD,
            "new": 'rows = db.execute("SELECT id, name, email FROM users WHERE name = ?", (name,)).fetchall()\n    rows = []',
        }
    ],
}


async def oracle_exploit_test_passes(
    original_root: Path, patched_files: dict[str, str], case: str, tmp: Path
) -> bool:
    """The hidden oracle: does the real exploit test pass on the patched code? (The system never sees it.)"""
    tmp.mkdir(parents=True, exist_ok=True)
    work = tmp / "oracle"
    shutil.copytree(original_root, work)
    for rel, content in patched_files.items():
        (work / rel).write_text(content)
    shutil.copy(
        CASES / case / "src" / "tests" / "test_security.py", work / "tests" / "test_security.py"
    )
    res = await run_sandboxed(
        SandboxSpec(
            image=TEST_RUNNER_IMAGE,
            entrypoint="python",
            command=["-m", "pytest", "-q", "tests/test_security.py"],
            workdir="/work",
            mounts=[Mount(work, "/work", read_only=False)],
            timeout_s=60,
        )
    )
    return res.exit_code == 0


async def remediate(tmp_path: Path, proposals: list[dict]) -> tuple[object, ScriptedLLM, Path]:  # type: ignore[type-arg]
    root = tmp_path / "ws"
    shutil.copytree(CASES / "sqli_flask" / "src", root)
    (
        root / "tests" / "test_security.py"
    ).unlink()  # the oracle is hidden from the system under test
    llm = ScriptedLLM(proposals)
    ctx = ToolContext(policy=ToolPolicy(DEFAULT_GROUPS))
    async with connect(build_server(ctx)) as tools:
        from backend.services.workspace import detect_languages
        from mcp_server.workspaces import WorkspaceInfo

        wid = ctx.registry.register(WorkspaceInfo(root, [], {}, detect_languages(root)))
        names = {"semgrep", "gitleaks", "trivy"}
        verifier = Verifier(tools, ctx.registry, names, [])
        deps = Deps(
            llm=llm,
            adapters=mcp_adapters(tools, ctx.registry, wid, names),
            enable_codeql=False,
            remediation=RemediationConfig(verifier, max_attempts=3),
        )  # type: ignore[arg-type]
        try:
            result = await run_scan(deps, root)
        finally:
            verifier.cleanup()
    return result, llm, root


async def test_good_fix_is_verified_and_really_fixes_the_exploit(
    docker_ok: None, tmp_path: Path
) -> None:
    result, llm, root = await remediate(tmp_path, [GOOD])
    [r] = result.remediations
    assert r["outcome"] == "verified" and r["attempts"] == 1
    assert (
        r["verification"]["tests"]["passed"]
        and r["verification"]["rescan"]["original_finding_gone"]
    )
    assert r["verification"]["rescan"]["new_findings"] == 0
    assert "?" in r["files"]["app.py"] and "'{name}'" not in r["files"]["app.py"]
    assert any(f.status == FindingStatus.FIXED for f in result.findings)
    assert (
        "VULN" not in (root / "app.py").read_text() and "{name}" in (root / "app.py").read_text()
    )  # original untouched
    assert result.patched_files == r["files"]
    # oracle: the exploit test (never shown to the system) fails before the patch and passes after it
    assert not await oracle_exploit_test_passes(root, {}, "sqli_flask", tmp_path)
    assert await oracle_exploit_test_passes(
        root, result.patched_files, "sqli_flask", tmp_path / "after"
    )


async def test_retry_loop_feeds_back_and_second_attempt_succeeds(
    docker_ok: None, tmp_path: Path
) -> None:
    result, llm, _ = await remediate(tmp_path, [STILL_VULNERABLE, GOOD])
    [r] = result.remediations
    assert r["outcome"] == "verified" and r["attempts"] == 2
    assert [h["stage"] for h in r["history"] if h["stage"] != "proposed"] == [
        "failed_verification",
        "verified",
    ]
    assert (
        "still reports the original issue" in llm.remediation_prompts[1]
    )  # the failure was fed back to the model


async def test_patch_that_breaks_tests_is_rejected_with_test_output(
    docker_ok: None, tmp_path: Path
) -> None:
    result, llm, _ = await remediate(tmp_path, [BREAKS_TESTS, GOOD])
    [r] = result.remediations
    assert r["outcome"] == "verified" and r["attempts"] == 2
    assert "tests fail after your patch" in llm.remediation_prompts[1]


async def test_retries_are_bounded_and_nothing_is_applied_on_failure(
    docker_ok: None, tmp_path: Path
) -> None:
    result, llm, root = await remediate(
        tmp_path, [STILL_VULNERABLE, STILL_VULNERABLE, STILL_VULNERABLE, GOOD]
    )
    [r] = result.remediations
    assert r["outcome"] == "failed" and r["attempts"] == 3
    assert (
        len(llm.remediation_prompts) == 3 and len(llm.proposals) == 1
    )  # the 4th (good) proposal was never requested
    assert any(f.status == FindingStatus.FIX_FAILED for f in result.findings)
    assert r["files"] == {}  # a failed fix carries no patch
    assert result.patched_files == {}  # nothing to commit


async def test_guardrail_rejections_count_as_attempts(docker_ok: None, tmp_path: Path) -> None:
    bad_file = {
        "can_fix": True,
        "edits": [{"file": "tests/test_app.py", "old": "def", "new": "def"}],
    }
    result, llm, _ = await remediate(tmp_path, [bad_file, GOOD])
    [r] = result.remediations
    assert r["outcome"] == "verified" and r["attempts"] == 2
    assert "only" in llm.remediation_prompts[1]  # guardrail error reached the model


async def test_model_can_decline(docker_ok: None, tmp_path: Path) -> None:
    result, _, _ = await remediate(tmp_path, [{"can_fix": False, "reason": "needs a redesign"}])
    [r] = result.remediations
    assert r["outcome"] == "declined"
