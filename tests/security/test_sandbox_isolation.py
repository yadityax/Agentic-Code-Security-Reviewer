"""The sandbox is a security boundary: prove the properties instead of assuming them."""

import os
from pathlib import Path

import pytest

from backend.services.sandbox import (
    TEST_RUNNER_IMAGE,
    Mount,
    SandboxSpec,
    build_docker_args,
    run_sandboxed,
)

pytestmark = pytest.mark.integration


def spec(code: str, tmp: Path, **kw: object) -> SandboxSpec:
    (tmp / "probe.py").write_text(code)
    return SandboxSpec(
        image=TEST_RUNNER_IMAGE,
        entrypoint="python",
        command=["/work/probe.py"],
        mounts=[Mount(tmp, "/work")],
        timeout_s=30,
        **kw,
    )  # type: ignore[arg-type]


def test_docker_args_are_hardened() -> None:
    args = " ".join(build_docker_args(SandboxSpec(image="x", command=["y"]), "n"))
    assert "--network none" in args and "--cap-drop ALL" in args and "no-new-privileges" in args
    assert "--pids-limit" in args and "--memory " in args
    assert f"--user {os.getuid()}:{os.getgid()}" in args  # never container root


def test_network_is_opt_in() -> None:
    assert "--network none" not in " ".join(
        build_docker_args(SandboxSpec(image="x", command=["y"], network=True), "n")
    )


async def test_no_network_access(docker_ok: None, tmp_path: Path) -> None:
    code = "import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=3); print('CONNECTED')\nexcept OSError as e:\n    print('BLOCKED')\n"
    res = await run_sandboxed(spec(code, tmp_path))
    assert "BLOCKED" in res.stdout and "CONNECTED" not in res.stdout


async def test_no_host_secrets_visible(
    docker_ok: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "github_pat_SHOULD_NOT_APPEAR_IN_SANDBOX")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_SHOULD_NOT_APPEAR_IN_SANDBOX")
    code = "import os\nprint([k for k in os.environ if any(s in k for s in ('TOKEN','KEY','SECRET','PASSWORD'))])\nprint(os.path.exists('/home') and os.listdir('/home'))\n"
    res = await run_sandboxed(spec(code, tmp_path))
    assert "SHOULD_NOT_APPEAR" not in res.stdout + res.stderr
    assert (
        "TOKEN" not in res.stdout.splitlines()[0]
    )  # no credential-like variable exists in the sandbox at all


async def test_read_only_mount_cannot_be_modified(docker_ok: None, tmp_path: Path) -> None:
    code = "try:\n    open('/work/pwned.txt', 'w').write('x'); print('WROTE')\nexcept OSError:\n    print('READONLY')\n"
    res = await run_sandboxed(spec(code, tmp_path))
    assert "READONLY" in res.stdout and not (tmp_path / "pwned.txt").exists()


async def test_cannot_gain_root_or_escape_via_capabilities(docker_ok: None, tmp_path: Path) -> None:
    code = "import os\nprint(os.getuid())\ntry:\n    os.setuid(0); print('ROOT')\nexcept OSError:\n    print('NOROOT')\n"
    res = await run_sandboxed(spec(code, tmp_path))
    assert "NOROOT" in res.stdout and str(os.getuid()) in res.stdout.splitlines()[0]


async def test_timeout_kills_runaway_code(docker_ok: None, tmp_path: Path) -> None:
    res = await run_sandboxed(
        spec("import time\ntime.sleep(60)\n", tmp_path).__class__(
            image=TEST_RUNNER_IMAGE,
            entrypoint="python",
            command=["/work/probe.py"],
            mounts=[Mount(tmp_path, "/work")],
            timeout_s=3,
        )
    )
    assert res.timed_out and res.duration_s < 20


async def test_memory_limit_is_enforced(docker_ok: None, tmp_path: Path) -> None:
    res = await run_sandboxed(
        spec("x = bytearray(2 * 1024**3)\nprint('ALLOCATED')\n", tmp_path, memory="256m")
    )
    assert "ALLOCATED" not in res.stdout and res.exit_code != 0


async def test_fork_bomb_is_contained(docker_ok: None, tmp_path: Path) -> None:
    code = "import os\nn = 0\ntry:\n    while n < 2000:\n        if os.fork() == 0:\n            import time; time.sleep(5); os._exit(0)\n        n += 1\nexcept OSError:\n    pass\nprint('FORKS', n)\n"
    res = await run_sandboxed(spec(code, tmp_path, pids=64))
    forks = int(res.stdout.split("FORKS")[-1].strip() or 0) if "FORKS" in res.stdout else 0
    assert forks < 200  # the pids limit stopped it long before 2000
