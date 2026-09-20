from pathlib import Path

from backend.models.finding import Severity
from backend.services.correlator import correlate
from backend.services.scanners.codeql import parse_sarif
from backend.services.scanners.semgrep import parse_semgrep
from backend.services.scanners.trivy import is_imported, parse_trivy

FIX = Path(__file__).parent.parent / "fixtures"
APP = FIX / "sample_app"
OUT = FIX / "scanner_output"


def test_codeql_sarif_normalizes_cwe_and_severity() -> None:
    fs = parse_sarif((OUT / "codeql.sarif.json").read_text(), APP)
    assert {f.cwe for f in fs} == {"CWE-89", "CWE-78"}  # leading zeros stripped
    assert next(f for f in fs if f.cwe == "CWE-78").severity == Severity.CRITICAL
    assert next(f for f in fs if f.cwe == "CWE-89").symbol == "user"


def test_codeql_and_semgrep_correlate_into_one_finding() -> None:
    semgrep = parse_semgrep((OUT / "semgrep.json").read_text(), APP)
    codeql = parse_sarif((OUT / "codeql.sarif.json").read_text(), APP)
    merged = correlate(semgrep + codeql)
    sqli = [f for f in merged if f.cwe == "CWE-89"]
    assert len(sqli) == 1
    assert sqli[0].scanner == "codeql" and "semgrep" in sqli[0].also_detected_by


def test_trivy_dependencies_and_reachability() -> None:
    fs = parse_trivy((OUT / "trivy.json").read_text(), APP)
    deps = [f for f in fs if f.package]
    assert {f.package for f in deps} >= {"flask", "pyyaml", "requests"}
    assert all(f.cve and f.cve.startswith("CVE-") for f in deps)
    reach = {f.package: f.reachable for f in deps}
    assert reach["flask"] is True  # app.py imports flask
    assert reach["pyyaml"] is False and reach["requests"] is False
    assert next(f for f in deps if f.package == "pyyaml").line == 2  # located in requirements.txt


def test_trivy_dockerfile_misconfigurations() -> None:
    fs = parse_trivy((OUT / "trivy.json").read_text(), APP)
    docker = [f for f in fs if f.file == "Dockerfile"]
    assert {"DS-0002", "DS-0001"} <= {f.rule_id for f in docker}
    assert all(f.cwe == "CWE-16" for f in docker)


def test_is_imported_handles_aliases(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import yaml\nfrom PIL import Image\nimport os, requests as r\n")
    assert is_imported(tmp_path, "PyYAML") is True
    assert is_imported(tmp_path, "pillow") is True
    assert is_imported(tmp_path, "requests") is True
    assert is_imported(tmp_path, "django") is False
    assert is_imported(tmp_path / "nope", "x") is None
