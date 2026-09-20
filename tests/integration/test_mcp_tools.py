import shutil
from pathlib import Path

import pytest

from backend.services.mcp_client import connect
from mcp_server.context import ToolContext
from mcp_server.policy import DEFAULT_GROUPS, ToolPolicy
from mcp_server.server import build_server
from mcp_server.workspaces import WorkspaceInfo

pytestmark = pytest.mark.integration
CASES = Path(__file__).resolve().parents[2] / "benchmarks" / "cases"


@pytest.fixture
def workspace(tmp_path: Path):  # type: ignore[no-untyped-def]
    def make(case: str) -> tuple[ToolContext, str, Path]:
        root = tmp_path / case
        shutil.copytree(CASES / case / "src", root)
        ctx = ToolContext(policy=ToolPolicy(DEFAULT_GROUPS))
        wid = ctx.registry.register(WorkspaceInfo(root, [], {}, {"python"}))
        return ctx, wid, root

    return make


async def test_scanners_over_mcp_return_normalized_findings(docker_ok: None, workspace) -> None:  # type: ignore[no-untyped-def]
    ctx, wid, _ = workspace("sqli_flask")
    async with connect(build_server(ctx)) as t:
        semgrep = await t.call("run_semgrep", workspace_id=wid)
        assert semgrep["error"] is None and any(f["cwe"] == "CWE-89" for f in semgrep["findings"])
        assert all(f["scanner"] == "semgrep" for f in semgrep["findings"])
        leaks = await t.call("run_gitleaks", workspace_id=wid)
        assert leaks["error"] is None and leaks["count"] == 0
    assert [r.tool for r in ctx.audit.records] == ["run_semgrep", "run_gitleaks"]


async def test_run_tests_passes_on_functional_and_fails_on_exploit_test(
    docker_ok: None, workspace
) -> None:  # type: ignore[no-untyped-def]
    ctx, wid, root = workspace("sqli_flask")
    before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    async with connect(build_server(ctx)) as t:
        ok = await t.call("run_tests", workspace_id=wid, path="tests/test_app.py")
        assert ok["passed"] and ok["counts"].get("passed") == 2
        exploit = await t.call("run_tests", workspace_id=wid, path="tests/test_security.py")
        assert (
            not exploit["passed"] and exploit["counts"].get("failed") == 1
        )  # the vulnerability is real
    assert (
        sorted(str(p.relative_to(root)) for p in root.rglob("*")) == before
    )  # tests ran on a copy


async def test_run_tests_cannot_touch_the_network_or_host(
    docker_ok: None, workspace, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    ctx, wid, root = workspace("safe_env_secrets_yaml")
    (root / "tests" / "test_evil.py").write_text(
        "import socket, os\n\ndef test_evil():\n    try:\n        socket.create_connection(('1.1.1.1', 53), timeout=2)\n    except OSError:\n        assert 'GITHUB_TOKEN' not in os.environ\n        return\n    raise AssertionError('network reachable from the sandbox')\n"
    )
    async with connect(build_server(ctx)) as t:
        res = await t.call("run_tests", workspace_id=wid, path="tests/test_evil.py")
    assert res["passed"], res["output_tail"]


async def test_test_timeout_is_enforced(docker_ok: None, workspace) -> None:  # type: ignore[no-untyped-def]
    ctx, wid, root = workspace("safe_env_secrets_yaml")
    (root / "tests" / "test_hang.py").write_text(
        "import time\n\ndef test_hang():\n    time.sleep(120)\n"
    )
    async with connect(build_server(ctx)) as t:
        res = await t.call("run_tests", workspace_id=wid, path="tests/test_hang.py", timeout_s=4)
    assert res["timed_out"] and not res["passed"]


async def test_linter_and_build_detect_broken_code(docker_ok: None, workspace) -> None:  # type: ignore[no-untyped-def]
    ctx, wid, root = workspace("weak_crypto_md5")
    async with connect(build_server(ctx)) as t:
        assert (await t.call("run_linter", workspace_id=wid))["clean"]
        assert (await t.call("build_project", workspace_id=wid))["ok"]
        (root / "auth.py").write_text("def broken(:\n    pass\n")
        assert not (await t.call("run_linter", workspace_id=wid))["clean"]
        assert not (await t.call("build_project", workspace_id=wid))["ok"]
