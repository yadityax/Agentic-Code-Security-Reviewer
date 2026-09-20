from pathlib import Path
from typing import Any

from backend.models.finding import Finding, Severity, Verdict
from backend.services.discovery import discover_findings, select_files
from backend.services.llm import Usage

APP = """from flask import Flask, jsonify

app = Flask(__name__)
INVOICES = {1: {"owner": "alice"}}


@app.route("/invoice/<int:i>")
def get(i):
    return jsonify(INVOICES.get(i))
"""


class ScriptedLLM:
    model = "scripted"

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items, self.usage = items, Usage()

    async def complete_json(self, system: str, user: str, schema: Any, **kw: Any) -> Any:
        assert "<untrusted_code_" in user  # repo text is always delimited as data
        return schema.model_validate({"findings": self.items})


def item(**kw: Any) -> dict[str, Any]:
    base = {
        "file": "app.py",
        "line": 9,
        "cwe": "CWE-639",
        "severity": "high",
        "title": "IDOR",
        "confidence": 0.9,
        "cited_lines": [9, 10],
    }
    return {**base, **kw}


def setup(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(APP)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test():\n    pass\n")
    return tmp_path


def existing(line: int = 9, cwe: str = "CWE-89") -> Finding:
    return Finding(
        id="e",
        scanner="semgrep",
        rule_id="r",
        file="app.py",
        line=line,
        severity=Severity.HIGH,
        title="t",
        cwe=cwe,
        fingerprint="fp",
    )


async def test_valid_discovery_is_kept(tmp_path: Path) -> None:
    root = setup(tmp_path)
    found, _ = await discover_findings(root, select_files(root, None), [], ScriptedLLM([item()]))  # type: ignore[arg-type]
    assert len(found) == 1
    f = found[0]
    assert (
        f.scanner == "llm-review"
        and f.cwe == "CWE-639"
        and f.analysis
        and f.analysis.verdict == Verdict.TRUE_POSITIVE
    )


async def test_low_confidence_becomes_needs_review(tmp_path: Path) -> None:
    root = setup(tmp_path)
    found, _ = await discover_findings(root, ["app.py"], [], ScriptedLLM([item(confidence=0.6)]))  # type: ignore[arg-type]
    assert found[0].analysis and found[0].analysis.verdict == Verdict.NEEDS_REVIEW


async def test_unverifiable_claims_are_dropped(tmp_path: Path) -> None:
    root = setup(tmp_path)
    bad = [
        item(file="ghost.py"),
        item(line=999),
        item(cited_lines=[]),
        item(cited_lines=[500]),
        item(confidence=0.3),
    ]
    found, _ = await discover_findings(root, ["app.py"], [], ScriptedLLM(bad))  # type: ignore[arg-type]
    assert found == []


async def test_scanner_duplicates_are_dropped(tmp_path: Path) -> None:
    root = setup(tmp_path)
    same_family = item(
        cwe="CWE-862"
    )  # access-control family, next to an existing access-control finding
    found, _ = await discover_findings(
        root, ["app.py"], [existing(cwe="CWE-639")], ScriptedLLM([same_family])
    )  # type: ignore[arg-type]
    assert found == []
    other, _ = await discover_findings(
        root, ["app.py"], [existing(cwe="CWE-89")], ScriptedLLM([item()])
    )  # type: ignore[arg-type]
    assert len(other) == 1  # a different class at the same line is a new finding


def test_select_files_skips_tests(tmp_path: Path) -> None:
    root = setup(tmp_path)
    assert select_files(root, None) == ["app.py"]
    assert select_files(root, ["tests/test_app.py", "app.py", "README.md"]) == ["app.py"]


async def test_missing_auth_dropped_when_code_has_no_auth_concept(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n@app.route('/x')\ndef x():\n    return 'hi'\n"
    )
    claim = item(cwe="CWE-306", line=6, cited_lines=[6])
    found, _ = await discover_findings(tmp_path, ["app.py"], [], ScriptedLLM([claim]))  # type: ignore[arg-type]
    assert found == []
    # ...but the same claim survives once the code has an auth mechanism the route skips
    (tmp_path / "app.py").write_text(APP + "\n\ndef current_user():\n    return 'x'\n")
    found, _ = await discover_findings(tmp_path, ["app.py"], [], ScriptedLLM([item(cwe="CWE-306")]))  # type: ignore[arg-type]
    assert len(found) == 1
