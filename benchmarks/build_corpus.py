"""Generates the benchmark corpus under benchmarks/cases/.

Each vulnerable line in a case source carries a trailing `#@V` marker. The generator strips the marker
(so scanners and LLMs never see it) and records the line number in expected.json.

Splits: `dev` cases may be used while building/tuning rules and prompts; `heldout` cases are written in a
different style and must not be used for tuning, so reported numbers are not tuned to the test set.
"""

import json
import re
import shutil
import textwrap
from pathlib import Path

OUT = Path(__file__).parent / "cases"
CASES: list[dict] = []


def case(id: str, split: str, files: dict[str, str], vulns: list[tuple[str, str]], desc: str, exploit_test: bool = False) -> None:
    """vulns: [(cwe, file)] in the order the #@V markers appear in that file."""
    CASES.append(dict(id=id, split=split, files=files, vulns=vulns, desc=desc, exploit_test=exploit_test))


def d(s: str) -> str:
    return textwrap.dedent(s).lstrip("\n")


FLASK_TEST_HEAD = "import pytest\nfrom app import app\n\n\n@pytest.fixture\ndef client():\n    app.config['TESTING'] = True\n    return app.test_client()\n\n\n"

# ------------------------------------------------------------------------------------------ DEV: vulnerable
case("sqli_flask", "dev", {
    "app.py": d('''
        import sqlite3

        from flask import Flask, jsonify, request

        app = Flask(__name__)
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
        db.execute("INSERT INTO users (name, email) VALUES ('alice', 'a@x.io'), ('bob', 'b@x.io')")


        @app.route("/users")
        def find_user():
            name = request.args.get("name", "")
            rows = db.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'").fetchall()  #@V
            return jsonify(rows)
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        def test_lookup(client):
            assert client.get("/users?name=alice").get_json() == [[1, "alice", "a@x.io"]]


        def test_unknown(client):
            assert client.get("/users?name=zed").get_json() == []
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_injection_does_not_dump_table(client):
            assert client.get("/users?name=x' OR '1'='1").get_json() == []
    '''),
}, [("CWE-89", "app.py")], "SQL injection via f-string in a Flask route", exploit_test=True)

case("sqli_cli_input", "dev", {
    "app.py": d('''
        import sqlite3

        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE items (id INTEGER, label TEXT)")
        conn.execute("INSERT INTO items VALUES (1, 'pen'), (2, 'ink')")


        def find_item(item_id):
            query = "SELECT id, label FROM items WHERE id = " + item_id  #@V
            return conn.execute(query).fetchall()


        if __name__ == "__main__":
            print(find_item(input("id: ")))
    '''),
    "tests/test_app.py": d('''
        from app import find_item


        def test_find():
            assert find_item("1") == [(1, "pen")]
    '''),
    "tests/test_security.py": d('''
        from app import find_item


        def test_no_injection():
            assert find_item("1 OR 1=1") == [] or len(find_item("1 OR 1=1")) <= 1
    '''),
}, [("CWE-89", "app.py")], "SQL injection with taint from input() (no web framework)", exploit_test=True)

case("xss_flask", "dev", {
    "app.py": d('''
        from flask import Flask, render_template_string, request

        app = Flask(__name__)


        @app.route("/hello")
        def hello():
            name = request.args.get("name", "world")
            return render_template_string("<h1>Hello " + name + "</h1>")  #@V #@V
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        def test_hello(client):
            assert b"Hello bob" in client.get("/hello?name=bob").data
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_script_is_escaped(client):
            assert b"<script>" not in client.get("/hello?name=<script>alert(1)</script>").data
    '''),
}, [("CWE-79", "app.py"), ("CWE-1336", "app.py")], "Reflected XSS and server-side template injection via a string-built template (both on one line)", exploit_test=True)

case("cmdi_flask", "dev", {
    "app.py": d('''
        import subprocess

        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/ping")
        def ping():
            host = request.args.get("host", "localhost")
            out = subprocess.run("echo pinging " + host, shell=True, capture_output=True, text=True)  #@V
            return out.stdout
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        def test_ping(client):
            assert "pinging localhost" in client.get("/ping?host=localhost").get_data(as_text=True)
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_no_command_chaining(client):
            body = client.get("/ping?host=x;echo INJECTED").get_data(as_text=True)
            assert "INJECTED\\n" not in body.replace("pinging x;echo INJECTED", "")
    '''),
}, [("CWE-78", "app.py")], "OS command injection via shell=True", exploit_test=True)

case("path_traversal_flask", "dev", {
    "app.py": d('''
        import os

        from flask import Flask, request

        app = Flask(__name__)
        BASE = os.path.join(os.path.dirname(__file__), "files")


        @app.route("/download")
        def download():
            name = request.args.get("name", "")
            with open(os.path.join(BASE, name)) as fh:  #@V
                return fh.read()
    '''),
    "files/hello.txt": "hello file\n",
    "secret.txt": "top-secret\n",
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        def test_download(client):
            assert client.get("/download?name=hello.txt").get_data(as_text=True) == "hello file\\n"
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_traversal_blocked(client):
            resp = client.get("/download?name=../secret.txt")
            assert "top-secret" not in resp.get_data(as_text=True)
    '''),
}, [("CWE-22", "app.py")], "Path traversal in file download", exploit_test=True)

case("ssrf_requests", "dev", {
    "app.py": d('''
        import requests
        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/fetch")
        def fetch():
            url = request.args.get("url", "")
            return {"length": len(requests.get(url, timeout=5).text)}  #@V
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        class FakeResp:
            text = "remote body"


        def test_fetch_public_url(client, monkeypatch):
            import requests

            monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResp())
            assert client.get("/fetch?url=https://example.com/").get_json() == {"length": 11}
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_cloud_metadata_url_is_not_fetched(client, monkeypatch):
            import requests

            calls = []
            monkeypatch.setattr(requests, "get", lambda url, **kw: calls.append(url) or type("R", (), {"text": "x"})())
            client.get("/fetch?url=http://169.254.169.254/latest/meta-data/")
            assert calls == []
    '''),
}, [("CWE-918", "app.py")], "SSRF: server fetches an arbitrary user-supplied URL", exploit_test=True)

case("secrets_hardcoded", "dev", {
    "config.py": d('''
        AWS_ACCESS_KEY_ID = "AKIAZ5QW7NRTKLM4PXV2"  #@V
        DB_PASSWORD = "Sup3rS3cretPassw0rd!"  #@V
        DEBUG = False


        def db_url():
            return f"postgresql://app:{DB_PASSWORD}@db.internal/app"
    '''),
    "tests/test_config.py": d('''
        import config


        def test_url():
            assert config.db_url().startswith("postgresql://app:")
    '''),
}, [("CWE-798", "config.py"), ("CWE-798", "config.py")], "Hardcoded cloud key and DB password")

case("weak_crypto_md5", "dev", {
    "auth.py": d('''
        import hashlib


        def hash_password(password: str) -> str:
            return hashlib.md5(password.encode()).hexdigest()  #@V


        def check_password(password: str, stored: str) -> bool:
            return hash_password(password) == stored
    '''),
    "tests/test_auth.py": d('''
        from auth import check_password, hash_password


        def test_roundtrip():
            assert check_password("pw", hash_password("pw"))
            assert not check_password("other", hash_password("pw"))
    '''),
}, [("CWE-327", "auth.py")], "MD5 used to hash passwords")

case("pickle_deser", "dev", {
    "app.py": d('''
        import base64
        import pickle

        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/load", methods=["POST"])
        def load():
            blob = base64.b64decode(request.form["data"])
            obj = pickle.loads(blob)  #@V
            return {"type": type(obj).__name__}
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        import base64
        import pickle


        def test_load(client):
            data = base64.b64encode(pickle.dumps({"a": 1})).decode()
            assert client.post("/load", data={"data": data}).get_json() == {"type": "dict"}
    '''),
}, [("CWE-502", "app.py")], "Unsafe deserialization of client data with pickle")

case("idor_invoice", "dev", {
    "app.py": d('''
        from flask import Flask, abort, jsonify, request

        app = Flask(__name__)
        INVOICES = {1: {"owner": "alice", "total": 120}, 2: {"owner": "bob", "total": 999}}


        def current_user():
            return request.headers.get("X-User", "")


        @app.route("/invoice/<int:invoice_id>")
        def get_invoice(invoice_id):
            if not current_user():
                abort(401)
            invoice = INVOICES.get(invoice_id)  #@V
            if invoice is None:
                abort(404)
            return jsonify(invoice)
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        def test_own_invoice(client):
            assert client.get("/invoice/1", headers={"X-User": "alice"}).get_json()["total"] == 120


        def test_requires_login(client):
            assert client.get("/invoice/1").status_code == 401
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_cannot_read_other_users_invoice(client):
            assert client.get("/invoice/2", headers={"X-User": "alice"}).status_code in (403, 404)
    '''),
}, [("CWE-639", "app.py")], "IDOR: invoice returned without checking ownership", exploit_test=True)

case("vuln_deps", "dev", {
    "requirements.txt": "flask==0.12.2  #@V\npyyaml==5.3  #@V\nrequests==2.19.0  #@V\n",
    "app.py": d('''
        import requests
        import yaml
        from flask import Flask

        app = Flask(__name__)


        @app.route("/")
        def index():
            return "ok"
    '''),
    "tests/test_app.py": d('''
        def test_import():
            import app  # noqa: F401
    '''),
}, [("CWE-1104", "requirements.txt")] * 3, "Known-vulnerable pinned dependencies (flask, pyyaml, requests), all imported or used by the app")

case("docker_misconfig", "dev", {
    "Dockerfile": d('''
        FROM python:latest  #@V
        WORKDIR /app
        ENV API_TOKEN=abc123abc123abc123  #@V
        COPY . /app
        RUN pip install flask
        CMD ["python", "app.py"]  #@V
    '''),
    "app.py": "print('hi')\n",
    "tests/test_app.py": "def test_ok():\n    assert True\n",
}, [("CWE-16", "Dockerfile")] * 3, "Container: unpinned image tag, secret in ENV, no non-root USER (one ground-truth entry each)")

# ------------------------------------------------------------------------------------------ DEV: safe decoys
case("safe_sql_param", "dev", {
    "app.py": d('''
        import sqlite3

        from flask import Flask, jsonify, request

        app = Flask(__name__)
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        db.execute("INSERT INTO users (name) VALUES ('alice')")
        ALLOWED_SORT = {"id": "id", "name": "name"}


        @app.route("/users")
        def find_user():
            name = request.args.get("name", "")
            order = ALLOWED_SORT.get(request.args.get("sort", "id"), "id")
            rows = db.execute("SELECT id, name FROM users WHERE name = ? ORDER BY " + order, (name,)).fetchall()
            return jsonify(rows)
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_ok(client):\n    assert client.get('/users?name=alice').get_json() == [[1, 'alice']]\n",
}, [], "SAFE: bound parameter; ORDER BY comes from an allow-list")

case("safe_subprocess_list", "dev", {
    "app.py": d('''
        import subprocess

        from flask import Flask, abort, request

        app = Flask(__name__)
        ALLOWED = {"date", "uptime"}


        @app.route("/run")
        def run():
            cmd = request.args.get("cmd", "")
            if cmd not in ALLOWED:
                abort(400)
            return subprocess.run([cmd], capture_output=True, text=True, check=False).stdout
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_reject(client):\n    assert client.get('/run?cmd=rm').status_code == 400\n",
}, [], "SAFE: allow-listed command, argument list, no shell")

case("safe_path_resolved", "dev", {
    "app.py": d('''
        from pathlib import Path

        from flask import Flask, abort, request

        app = Flask(__name__)
        BASE = (Path(__file__).parent / "files").resolve()


        @app.route("/download")
        def download():
            target = (BASE / request.args.get("name", "")).resolve()
            if not target.is_relative_to(BASE) or not target.is_file():
                abort(404)
            return target.read_text()
    '''),
    "files/a.txt": "a\n",
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_ok(client):\n    assert client.get('/download?name=a.txt').get_data(as_text=True) == 'a\\n'\n",
}, [], "SAFE: resolved path verified to stay inside the base directory")

case("safe_env_secrets_yaml", "dev", {
    "app.py": d('''
        import os

        import yaml

        API_KEY = os.environ.get("API_KEY", "")
        PLACEHOLDER = "changeme"


        def load_config(text: str) -> dict:
            return yaml.safe_load(text)
    '''),
    "tests/test_app.py": d('''
        from app import load_config


        def test_load():
            assert load_config("a: 1") == {"a": 1}
    '''),
}, [], "SAFE: secrets from the environment, yaml.safe_load, placeholder value")

# ------------------------------------------------------------------------------------------ HELD-OUT: vulnerable
case("h_sqli_format", "heldout", {
    "app.py": d('''
        import sqlite3

        from flask import Flask, request

        app = Flask(__name__)
        con = sqlite3.connect(":memory:", check_same_thread=False)
        con.execute("CREATE TABLE products (sku TEXT, price REAL)")
        con.execute("INSERT INTO products VALUES ('A1', 9.5), ('B2', 20)")


        @app.get("/price")
        def price():
            sku = request.args["sku"]
            cur = con.cursor()
            cur.execute("SELECT price FROM products WHERE sku = '{}'".format(sku))  #@V
            row = cur.fetchone()
            return {"price": row[0] if row else None}
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_price(client):\n    assert client.get('/price?sku=A1').get_json() == {'price': 9.5}\n",
    "tests/test_security.py": FLASK_TEST_HEAD + "def test_no_injection(client):\n    assert client.get(\"/price?sku=x' OR '1'='1\").get_json() == {'price': None}\n",
}, [("CWE-89", "app.py")], "SQL injection via str.format", exploit_test=True)

case("h_cmdi_fastapi", "heldout", {
    "main.py": d('''
        import os

        from fastapi import FastAPI

        app = FastAPI()


        @app.get("/echo")
        def echo(msg: str):
            os.system("echo " + msg + " > /tmp/last_echo.txt")  #@V
            return {"ok": True}
    '''),
    "tests/test_app.py": d('''
        from fastapi.testclient import TestClient

        from main import app


        def test_echo():
            assert TestClient(app).get("/echo", params={"msg": "hi"}).json() == {"ok": True}
    '''),
}, [("CWE-78", "main.py")], "Command injection via os.system in FastAPI")

case("h_xss_markup", "heldout", {
    "app.py": d('''
        from flask import Flask, request
        from markupsafe import Markup

        app = Flask(__name__)


        @app.route("/greet")
        def greet():
            who = request.args.get("who", "guest")
            return Markup("<p>Welcome, %s</p>") % Markup(who)  #@V
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_greet(client):\n    assert b'Welcome, ann' in client.get('/greet?who=ann').data\n",
    "tests/test_security.py": FLASK_TEST_HEAD + "def test_escaped(client):\n    assert b'<img' not in client.get('/greet?who=<img src=x onerror=1>').data\n",
}, [("CWE-79", "app.py")], "XSS by marking user input as safe Markup", exploit_test=True)

case("h_ssrf_urllib", "heldout", {
    "app.py": d('''
        import urllib.request

        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/preview")
        def preview():
            target = request.args.get("link")
            with urllib.request.urlopen(target, timeout=3) as resp:  #@V
                return {"bytes": len(resp.read(2000))}
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + d('''
        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"page"


        def test_preview_public(client, monkeypatch):
            import urllib.request

            monkeypatch.setattr(urllib.request, "urlopen", lambda url, **kw: FakeResp())
            assert client.get("/preview?link=https://example.com/").get_json() == {"bytes": 4}
    '''),
    "tests/test_security.py": FLASK_TEST_HEAD + d('''
        def test_internal_link_not_fetched(client, monkeypatch):
            import urllib.request

            calls = []
            monkeypatch.setattr(urllib.request, "urlopen", lambda url, **kw: calls.append(url) or (_ for _ in ()).throw(RuntimeError("blocked")))
            client.get("/preview?link=http://127.0.0.1:8080/admin")
            assert calls == []
    '''),
}, [("CWE-918", "app.py")], "SSRF via urllib with user-supplied link", exploit_test=True)

case("h_yaml_load", "heldout", {
    "app.py": d('''
        import yaml
        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/import", methods=["POST"])
        def import_config():
            cfg = yaml.load(request.data, Loader=yaml.Loader)  #@V
            return {"keys": sorted(cfg)}
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_import(client):\n    assert client.post('/import', data='a: 1\\nb: 2').get_json() == {'keys': ['a', 'b']}\n",
}, [("CWE-502", "app.py")], "yaml.load with the unsafe Loader on request data")

case("h_path_send_file", "heldout", {
    "app.py": d('''
        from flask import Flask, request, send_file

        app = Flask(__name__)


        @app.route("/report")
        def report():
            return send_file("reports/" + request.args.get("id", "") + ".txt")  #@V
    '''),
    "reports/1.txt": "report one\n",
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_report(client):\n    assert client.get('/report?id=1').status_code in (200, 404)\n",
}, [("CWE-22", "app.py")], "Path traversal through send_file with concatenated path")

case("h_missing_auth_admin", "heldout", {
    "app.py": d('''
        from flask import Flask, jsonify, request

        app = Flask(__name__)
        USERS = {"alice": {"role": "user"}, "root": {"role": "admin"}}


        @app.route("/admin/users")
        def list_users():  #@V
            return jsonify(sorted(USERS))


        @app.route("/profile")
        def profile():
            user = request.headers.get("X-User")
            return jsonify(USERS.get(user, {}))
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_profile(client):\n    assert client.get('/profile', headers={'X-User': 'alice'}).get_json() == {'role': 'user'}\n",
    "tests/test_security.py": FLASK_TEST_HEAD + "def test_admin_requires_admin(client):\n    assert client.get('/admin/users').status_code in (401, 403)\n",
}, [("CWE-306", "app.py")], "Admin endpoint reachable without authentication", exploit_test=True)

case("h_weak_random_token", "heldout", {
    "tokens.py": d('''
        import random
        import string


        def make_reset_token(length: int = 16) -> str:
            alphabet = string.ascii_letters + string.digits
            return "".join(random.choice(alphabet) for _ in range(length))  #@V
    '''),
    "tests/test_tokens.py": "from tokens import make_reset_token\n\n\ndef test_len():\n    assert len(make_reset_token(20)) == 20\n",
}, [("CWE-330", "tokens.py")], "Password-reset token from the non-cryptographic random module")

# ------------------------------------------------------------------------------------------ HELD-OUT: safe decoys
case("h_safe_orm", "heldout", {
    "app.py": d('''
        from flask import Flask, jsonify, request
        from sqlalchemy import Column, Integer, String, create_engine, select
        from sqlalchemy.orm import Session, declarative_base

        Base = declarative_base()


        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            name = Column(String)


        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        with Session(engine) as s:
            s.add(User(name="alice"))
            s.commit()
        app = Flask(__name__)


        @app.route("/u")
        def u():
            with Session(engine) as s:
                rows = s.execute(select(User).where(User.name == request.args.get("name", ""))).scalars().all()
                return jsonify([r.name for r in rows])
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_u(client):\n    assert client.get('/u?name=alice').get_json() == ['alice']\n",
}, [], "SAFE: SQLAlchemy ORM expression")

case("h_safe_html_escape", "heldout", {
    "app.py": d('''
        import html

        from flask import Flask, request

        app = Flask(__name__)


        @app.route("/hi")
        def hi():
            return "<p>Hi " + html.escape(request.args.get("n", "")) + "</p>"
    '''),
    "tests/test_app.py": FLASK_TEST_HEAD + "def test_hi(client):\n    assert client.get('/hi?n=x').get_data(as_text=True) == '<p>Hi x</p>'\n",
}, [], "SAFE: output escaped with html.escape")

case("h_safe_test_secret", "heldout", {
    "app.py": "def add(a, b):\n    return a + b\n",
    "tests/test_app.py": d('''
        from app import add

        FAKE_TOKEN = "test-token-not-a-real-secret"  # fixture value


        def test_add():
            assert add(1, 2) == 3 and FAKE_TOKEN
    '''),
}, [], "SAFE: obviously fake token confined to a test file")

case("h_safe_sha256", "heldout", {
    "app.py": d('''
        import hashlib


        def etag(content: bytes) -> str:
            # cache validator only, not a security control
            return hashlib.sha256(content).hexdigest()[:16]
    '''),
    "tests/test_app.py": "from app import etag\n\n\ndef test_etag():\n    assert len(etag(b'x')) == 16\n",
}, [], "SAFE: SHA-256 used for an ETag")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    index = []
    for c in CASES:
        root = OUT / c["id"] / "src"
        expected = []
        counters: dict[str, int] = {}
        for rel, content in c["files"].items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            lines = content.splitlines()
            out_lines = []
            for i, line in enumerate(lines, 1):
                if "#@V" in line:
                    for _ in range(line.count("#@V")):
                        expected.append({"file": rel, "line": i, "lines": [i, i]})
                    line = re.sub(r"(\s*#@V)+\s*$", "", line)
                out_lines.append(line)
            path.write_text("\n".join(out_lines) + ("\n" if content.endswith("\n") or True else ""))
        # attach CWEs in order of appearance per file
        per_file: dict[str, list[str]] = {}
        for cwe, f in c["vulns"]:
            per_file.setdefault(f, []).append(cwe)
        seen: dict[str, int] = {}
        for e in expected:
            i = seen.get(e["file"], 0)
            e["cwe"] = per_file[e["file"]][i]
            seen[e["file"]] = i + 1
        assert len(expected) == len(c["vulns"]), f"{c['id']}: marker/CWE count mismatch"
        meta = {"id": c["id"], "split": c["split"], "description": c["desc"], "kind": "vulnerable" if expected else "safe", "vulns": expected, "has_exploit_test": c["exploit_test"]}
        (OUT / c["id"] / "expected.json").write_text(json.dumps(meta, indent=2) + "\n")
        index.append({k: meta[k] for k in ("id", "split", "kind", "description")} | {"n_vulns": len(expected)})
    (OUT / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    v = sum(1 for i in index if i["kind"] == "vulnerable")
    print(f"generated {len(index)} cases ({v} vulnerable, {len(index) - v} safe): "
          f"{sum(1 for i in index if i['split'] == 'dev')} dev / {sum(1 for i in index if i['split'] == 'heldout')} held-out; "
          f"{sum(i['n_vulns'] for i in index)} ground-truth vulnerabilities")


if __name__ == "__main__":
    main()
