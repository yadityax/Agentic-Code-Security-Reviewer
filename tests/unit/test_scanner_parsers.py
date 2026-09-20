import json
from pathlib import Path

from backend.models.finding import PRScope, Severity
from backend.services.scanners.gitleaks import parse_gitleaks
from backend.services.scanners.semgrep import parse_semgrep
from backend.services.workspace import parse_changed_lines, tag_pr_scope

FIX = Path(__file__).parent.parent / "fixtures"
APP = FIX / "sample_app"


def test_semgrep_parse_real_output() -> None:
    findings = parse_semgrep((FIX / "scanner_output/semgrep.json").read_text(), APP)
    by_cwe = {f.cwe for f in findings}
    assert {"CWE-89", "CWE-78"} <= by_cwe
    sqli = next(f for f in findings if f.cwe == "CWE-89")
    assert sqli.file == "app.py"  # /src prefix stripped
    assert sqli.owasp == "A03"
    assert sqli.symbol == "user"
    assert sqli.severity in (Severity.HIGH, Severity.MEDIUM)
    assert "request.args" in sqli.evidence or "SELECT" in sqli.evidence


def test_semgrep_overlapping_rules_share_fingerprint() -> None:
    findings = parse_semgrep((FIX / "scanner_output/semgrep.json").read_text(), APP)
    cmd = [f for f in findings if f.cwe == "CWE-78"]
    assert len(cmd) >= 2
    assert len({f.fingerprint for f in cmd}) == 1  # correlator can dedup these


def test_gitleaks_never_stores_secret_values() -> None:
    raw = (FIX / "scanner_output/gitleaks.json").read_text()
    findings = parse_gitleaks(raw, APP)
    assert {f.rule_id for f in findings} == {"aws-access-token", "generic-api-key"}
    blob = json.dumps([f.model_dump() for f in findings])
    assert "AKIAZ5QW7NRTKLM4PXV2" not in blob
    assert "9f8e7d6c5b4a" not in blob
    assert all(f.cwe == "CWE-798" and f.file == "app.py" for f in findings)


def test_parse_changed_lines() -> None:
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,0 +2,3 @@\n+x\n+y\n+z\n"
        "@@ -10 +14 @@\n-old\n+new\n"
        "@@ -20,2 +23,0 @@\n-gone\n-gone\n"
        "diff --git a/b.py b/b.py\n--- a/b.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert parse_changed_lines(diff) == {"a.py": [(2, 4), (14, 14)]}


def test_pr_scope_tagging() -> None:
    findings = parse_semgrep((FIX / "scanner_output/semgrep.json").read_text(), APP)
    tagged = tag_pr_scope(findings, {"app.py": [(20, 22)]})
    scopes = {f.cwe: f.pr_scope for f in tagged}
    assert scopes["CWE-78"] == PRScope.NEW
    assert scopes["CWE-89"] == PRScope.EXISTING
    assert all(f.pr_scope == PRScope.EXISTING for f in tag_pr_scope(findings, {}))
