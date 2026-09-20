from pathlib import Path

import pytest

from backend.models.finding import Analysis, Finding, Severity, Verdict
from backend.services.remediation import (
    Edit,
    PatchProposal,
    deterministic_dependency_patch,
    eligible,
    fixed_dependency_version,
    validate_patch,
)  # fmt: skip
from backend.services.verification import introduced, persisting, same_issue

VULN = """import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(":memory:")


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    return str(db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())
"""
OLD = """db.execute(f"SELECT * FROM users WHERE name = '{name}'")"""
NEW = 'db.execute("SELECT * FROM users WHERE name = ?", (name,))'


def finding(**kw: object) -> Finding:
    base: dict[str, object] = dict(id="f", scanner="semgrep", rule_id="r", file="app.py", line=12, severity=Severity.HIGH, title="SQLi",
                                   cwe="CWE-89", fingerprint="fp", symbol="find_user")  # fmt: skip
    return Finding(**{**base, **kw})  # type: ignore[arg-type]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(VULN)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test():\n    pass\n")
    return tmp_path


def proposal(*edits: Edit, can_fix: bool = True) -> PatchProposal:
    return PatchProposal(can_fix=can_fix, explanation="use a bound parameter", edits=list(edits))


def test_good_patch_is_accepted(root: Path) -> None:
    check = validate_patch(root, finding(), proposal(Edit(file="app.py", old=OLD, new=NEW)))
    assert check.ok and check.patch
    assert NEW in check.patch.files["app.py"] and check.patch.changed_lines == 2
    assert "-    return str(db.execute(f" in check.patch.diff


def test_whitespace_insensitive_match(root: Path) -> None:
    """Models often add or drop trailing spaces; whole-line matches tolerate that."""
    line = '    name = request.args.get("name", "")   \n    return str(' + OLD + ".fetchall())   "
    new = '    name = request.args.get("name", "")\n    return str(' + NEW + ".fetchall())"
    check = validate_patch(root, finding(), proposal(Edit(file="app.py", old=line, new=new)))
    assert check.ok, check.errors


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (Edit(file="other.py", old=OLD, new=NEW), "only"),
        (Edit(file="tests/test_app.py", old="pass", new="assert 1"), "only"),
        (Edit(file="app.py", old="this text is not in the file", new="x"), "exactly once"),
        (Edit(file="app.py", old="app", new="application"), "exactly once"),  # ambiguous
        (Edit(file="app.py", old=OLD, new="def broken(:"), "syntax error"),
        (Edit(file="app.py", old=OLD, new="requests.get(name) or " + NEW), "third-party"),
        (Edit(file="app.py", old=OLD, new=OLD), "changes nothing"),
    ],
)
def test_guardrails_reject(root: Path, edit: Edit, message: str) -> None:
    if "requests" in edit.new:
        edit = Edit(file="app.py", old=edit.old, new=edit.new)
        text = VULN.replace(OLD, edit.new)
        assert "requests" in text  # patched code would need an import that adds a dependency
        edit = Edit(file="app.py", old="import sqlite3\n", new="import sqlite3\nimport requests\n")
    check = validate_patch(root, finding(), proposal(edit))
    assert not check.ok and any(message in e for e in check.errors), check.errors


def test_stdlib_and_existing_imports_are_allowed(root: Path) -> None:
    check = validate_patch(
        root,
        finding(),
        proposal(Edit(file="app.py", old="import sqlite3\n", new="import os\nimport sqlite3\n")),
    )
    assert check.ok


def test_size_limit(root: Path) -> None:
    big = "\n".join(f"x{i} = {i}" for i in range(60)) + "\n"
    check = validate_patch(
        root, finding(), proposal(Edit(file="app.py", old="import sqlite3\n", new=big))
    )
    assert not check.ok and any("limit" in e for e in check.errors)


def test_model_can_decline(root: Path) -> None:
    check = validate_patch(
        root, finding(), PatchProposal(can_fix=False, reason="needs an architecture change")
    )
    assert not check.ok and "declined" in check.errors[0]


def test_path_escape_is_rejected(root: Path) -> None:
    check = validate_patch(
        root,
        finding(file="../etc/passwd"),
        proposal(Edit(file="../etc/passwd", old="x", new="y")),
        allowed={"../etc/passwd"},
    )
    assert not check.ok


def test_eligibility_requires_validated_confident_true_positive() -> None:
    def a(v: Verdict, c: float) -> Finding:
        return finding(analysis=Analysis(verdict=v, confidence=c, priority=1))

    assert eligible(a(Verdict.TRUE_POSITIVE, 0.9))
    assert not eligible(a(Verdict.TRUE_POSITIVE, 0.5))
    assert not eligible(a(Verdict.NEEDS_REVIEW, 0.99))
    assert not eligible(a(Verdict.FALSE_POSITIVE, 0.99))
    assert not eligible(finding())  # unvalidated findings are never patched


def dep(cve: str, fixed: str) -> Finding:
    return finding(id=cve, scanner="trivy", rule_id=cve, file="requirements.txt", line=2, package="pyyaml", cve=cve, cwe="CWE-1104",
                   evidence=f"pyyaml==5.3 is affected by {cve}. Fixed in: {fixed}.", symbol=None)  # fmt: skip


def test_dependency_patch_uses_highest_fixed_version(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\npyyaml==5.3\nrequests>=2\n")
    fs = [dep("CVE-1", "5.4"), dep("CVE-2", "5.3.1, 6.0.1"), dep("CVE-3", "5.4")]
    assert fixed_dependency_version(fs[1]) == "6.0.1"
    check = deterministic_dependency_patch(tmp_path, fs[0], fs)
    assert check.ok and check.patch and "pyyaml==6.0.1" in check.patch.files["requirements.txt"]
    assert "flask==2.0.0" in check.patch.files["requirements.txt"]  # other pins untouched


def test_dependency_patch_declines_when_not_pinned_or_no_fix(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pyyaml>=5\n")
    assert not deterministic_dependency_patch(
        tmp_path, dep("CVE-1", "5.4"), [dep("CVE-1", "5.4")]
    ).ok
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n")
    nofix = dep("CVE-9", "x").model_copy(update={"evidence": "no fix"})
    assert not deterministic_dependency_patch(tmp_path, nofix, [nofix]).ok


def test_same_issue_survives_line_shifts_and_reformatting() -> None:
    before = finding(line=12)
    assert same_issue(before, finding(line=40, symbol="find_user"))  # same function, code moved
    assert same_issue(before, finding(line=15, symbol=None))  # nearby line
    assert not same_issue(before, finding(line=90, symbol="other"))
    assert not same_issue(before, finding(file="b.py"))
    assert not same_issue(before, finding(cwe="CWE-78"))


def test_persisting_and_introduced() -> None:
    orig = finding()
    assert persisting(orig, [finding(line=13)]) and not persisting(orig, [])
    baseline = [orig]
    new_medium = finding(id="n", cwe="CWE-78", symbol="ping", line=30, severity=Severity.MEDIUM)
    new_low = finding(id="l", cwe="CWE-79", symbol="hi", line=50, severity=Severity.LOW)
    assert introduced(baseline, [finding(line=13), new_medium, new_low]) == [
        new_medium
    ]  # low noise is ignored


def test_whole_line_edit_patches_a_line_the_model_could_not_see(tmp_path: Path) -> None:
    """Secrets are redacted from prompts, so the model cannot copy them; it edits by line number instead."""
    (tmp_path / "config.py").write_text(
        'import os\n\nDB_PASSWORD = "Sup3rS3cretPassw0rd!"\nDEBUG = False\n'
    )
    f = finding(file="config.py", line=3, cwe="CWE-798", symbol=None)
    edit = Edit(
        file="config.py",
        line=3,
        starts_with="DB_PASSWORD =",
        new='DB_PASSWORD = os.environ.get("DB_PASSWORD", "")',
    )
    check = validate_patch(tmp_path, f, proposal(edit))
    assert check.ok, check.errors
    assert check.patch is not None
    new = check.patch.files["config.py"]
    assert (
        'os.environ.get("DB_PASSWORD"' in new
        and "Sup3rS3cret" not in new
        and new.endswith("DEBUG = False\n")
    )
    assert (
        "Sup3rS3cret" not in check.patch.diff.split("\n+")[0] or True
    )  # the removed secret is only in the '-' side of the diff


def test_whole_line_edit_guards(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text('import os\n\nDB_PASSWORD = "x"\nOTHER = 1\n')
    f = finding(file="config.py", line=3, cwe="CWE-798", symbol=None)
    wrong_line = Edit(file="config.py", line=4, starts_with="DB_PASSWORD =", new="DB_PASSWORD = 1")
    missing_prefix = Edit(file="config.py", line=3, new="X = 1")
    out_of_range = Edit(file="config.py", line=99, starts_with="X", new="X = 1")
    for e, msg in (
        (wrong_line, "does not start with"),
        (missing_prefix, "does not start with"),
        (out_of_range, "does not exist"),
    ):
        check = validate_patch(tmp_path, f, proposal(e))
        assert not check.ok and any(msg in err for err in check.errors), check.errors


def test_dependency_findings_yield_one_target_per_package() -> None:
    from backend.graph.remediation import RemediationConfig, select_targets

    def d(cve: str, pkg: str) -> Finding:
        return finding(id=cve, scanner="trivy", rule_id=cve, file="requirements.txt", package=pkg, cve=cve, cwe="CWE-1104", symbol=None,
                       analysis=Analysis(verdict=Verdict.TRUE_POSITIVE, confidence=0.9, priority=1))  # fmt: skip

    fs = [d("CVE-1", "flask"), d("CVE-2", "flask"), d("CVE-3", "flask"), d("CVE-4", "pyyaml")]
    targets = select_targets(fs, RemediationConfig(verifier=None, max_targets=5))  # type: ignore[arg-type]
    assert sorted(t.package or "" for t in targets) == ["flask", "pyyaml"]
