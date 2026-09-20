import os
import subprocess

import pytest

# Tests never touch the dev database. Must be set before backend.config is imported.
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://acsr:acsr@localhost:5433/acsr_test"
)


def _have(cmd: list[str]) -> bool:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session")
def migrated_db() -> None:
    if not _have(["docker", "exec", "acsr-postgres-1", "pg_isready"]):
        pytest.skip("Postgres container not running (make up)")
    r = subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"], capture_output=True, text=True, env=os.environ
    )
    assert r.returncode == 0, r.stderr[-500:]


@pytest.fixture(scope="session")
def docker_ok() -> None:
    if not _have(["docker", "image", "inspect", "returntocorp/semgrep:latest"]):
        pytest.skip("scanner images not pulled (make pull-scanners)")
