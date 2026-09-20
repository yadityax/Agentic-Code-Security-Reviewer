"""Hardened one-shot container runner. Everything that touches untrusted code goes through here."""

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


@dataclass
class Mount:
    host: Path | str  # a str is a named Docker volume
    container: str
    read_only: bool = True


@dataclass
class SandboxSpec:
    image: str
    command: list[str]
    mounts: list[Mount] = field(default_factory=list)
    network: bool = False  # off by default; scanners use pre-fetched rules and DBs
    memory: str = "2g"
    cpus: float = 2.0
    pids: int = 512
    timeout_s: int = 300
    workdir: str | None = None
    user: str | None = None  # default: the invoking uid:gid
    env: dict[str, str] = field(default_factory=dict)  # never pass secrets here
    entrypoint: str | None = None
    tmpfs: list[str] = field(default_factory=lambda: ["/tmp"])  # noqa: S108
    read_only_root: bool = False


def build_docker_args(spec: SandboxSpec, name: str) -> list[str]:
    args = [
        "docker", "run", "--rm", "--name", name,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", spec.memory, "--memory-swap", spec.memory,
        "--cpus", str(spec.cpus), "--pids-limit", str(spec.pids),
    ]  # fmt: skip
    if not spec.network:
        args += ["--network", "none"]
    if spec.read_only_root:
        args += ["--read-only"]
    for t in spec.tmpfs:
        args += ["--tmpfs", t]
    for m in spec.mounts:
        src = m.host.resolve() if isinstance(m.host, Path) else m.host
        args += ["-v", f"{src}:{m.container}:{'ro' if m.read_only else 'rw'}"]
    if spec.workdir:
        args += ["-w", spec.workdir]
    # Run as the invoking user, never as container root: least privilege, and it can read our
    # 0700 workspaces without loosening their permissions for other users on the machine.
    args += ["--user", spec.user or f"{os.getuid()}:{os.getgid()}"]
    args += ["-e", "HOME=/tmp"]
    if spec.entrypoint is not None:
        args += ["--entrypoint", spec.entrypoint]
    for k, v in spec.env.items():
        args += ["-e", f"{k}={v}"]
    return [*args, spec.image, *spec.command]


async def run_sandboxed(spec: SandboxSpec) -> SandboxResult:
    name = f"acsr-{uuid.uuid4().hex[:12]}"
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *build_docker_args(spec, name),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=spec.timeout_s)
        timed_out = False
    except TimeoutError:
        kill = await asyncio.create_subprocess_exec(
            "docker", "kill", name,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        await kill.wait()
        out, err = await proc.communicate()
        timed_out = True
    return SandboxResult(
        exit_code=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
        duration_s=time.monotonic() - start,
        timed_out=timed_out,
    )


TEST_RUNNER_IMAGE = "acsr-testrunner:latest"
