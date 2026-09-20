"""End-to-end demo through the real deployed path: signed webhook -> API -> Redis -> worker -> Postgres.

Prerequisite (offline, no GitHub involved):
    GIT_BASE_URL=file://$PWD/.demo GITHUB_OFFLINE=true ENABLE_REMEDIATION=true make up
    make demo
"""

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = {
    m[1]: m[2].strip()
    for ln in (ROOT / ".env").read_text().splitlines()
    if (m := re.match(r"^([A-Z_]+)=(.*)$", ln))
}
API = os.environ.get("ACSR_API", "http://127.0.0.1:8000")
REPO = "acme/shop"

APP = """import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
db.execute("INSERT INTO users (name, email) VALUES ('alice', 'a@shop.io')")


@app.route("/health")
def health():
    return {"ok": True}
"""
HEAD_ADD = """

@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    rows = db.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'").fetchall()
    return jsonify(rows)
"""
TESTS = """import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    assert client.get("/health").get_json() == {"ok": True}


def test_lookup(client):
    assert client.get("/users?name=alice").get_json() == [[1, "alice", "a@shop.io"]]
"""


def git(cwd: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "demo",
        "GIT_AUTHOR_EMAIL": "d@d",
        "GIT_COMMITTER_NAME": "demo",
        "GIT_COMMITTER_EMAIL": "d@d",
        "PATH": os.environ["PATH"],
        "HOME": str(cwd),
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def build_origin() -> tuple[str, str]:
    origin = ROOT / ".demo" / REPO
    origin = origin.parent / f"{origin.name}.git"
    if origin.exists():
        subprocess.run(["rm", "-rf", str(origin)], check=True)
    (origin / "tests").mkdir(parents=True)
    git(origin, "init", "-q", "-b", "main")
    (origin / "app.py").write_text(APP)
    (origin / "tests" / "test_app.py").write_text(TESTS.split("def test_lookup")[0].rstrip() + "\n")
    (origin / "requirements.txt").write_text("flask\n")
    git(origin, "add", ".")
    git(origin, "commit", "-qm", "base")
    base = git(origin, "rev-parse", "HEAD")
    (origin / "app.py").write_text(APP + HEAD_ADD)
    (origin / "tests" / "test_app.py").write_text(TESTS)
    git(origin, "commit", "-qam", "add user lookup endpoint")
    head = git(origin, "rev-parse", "HEAD")
    subprocess.run(["chmod", "-R", "a+rX", str(ROOT / ".demo")], check=True)
    return base, head


def call(
    method: str, path: str, *, body: bytes | None = None, headers: dict[str, str] | None = None
) -> dict:
    req = urllib.request.Request(API + path, data=body, method=method, headers=headers or {})  # noqa: S310  (API is a fixed http URL)
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
        return json.loads(r.read() or b"{}")


def main() -> int:
    secret, token = ENV.get("GITHUB_WEBHOOK_SECRET", ""), ENV.get("ADMIN_API_TOKEN", "")
    if not secret or not token:
        print("GITHUB_WEBHOOK_SECRET and ADMIN_API_TOKEN must be set in .env")
        return 1
    base, head = build_origin()
    delivery = f"demo-{int(time.time())}"
    payload = {
        "action": "opened",
        "repository": {"full_name": REPO},
        "pull_request": {
            "number": 1,
            "draft": False,
            "head": {"sha": head, "ref": "feature/user-lookup", "repo": {"full_name": REPO}},
            "base": {"sha": base, "ref": "main"},
        },
    }
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    res = call(
        "POST",
        "/webhook/github",
        body=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        },
    )
    print(f"webhook accepted: {res}")
    auth = {"Authorization": f"Bearer {token}"}
    print("waiting for the worker", end="", flush=True)
    scan = None
    for _ in range(240):
        time.sleep(3)
        print(".", end="", flush=True)
        scans = call("GET", "/api/scans?limit=20", headers=auth)
        scan = next((s for s in scans if s["head_sha"] == head), None)
        if scan and scan["status"] in ("completed", "failed"):
            break
    print()
    if not scan or scan["status"] != "completed":
        print(f"scan did not complete: {scan and scan['status']}. Check `make logs`.")
        return 1
    detail = call("GET", f"/api/scans/{scan['id']}", headers=auth)
    print("\n" + detail["summary"].get("report_md", "(no report)"))
    rems = call("GET", f"/api/scans/{scan['id']}/remediations", headers=auth)
    print(
        f"\nscan {scan['id']}: {len(detail['findings'])} findings, {scan['llm_tokens']} tokens, {scan['latency_s']:.0f}s"
    )
    print(f"remediations: {[(r['status'], r['attempt']) for r in rems]}")
    print("\nDashboard: http://127.0.0.1:8088  (token: ADMIN_API_TOKEN from .env)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
