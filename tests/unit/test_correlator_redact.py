from backend.models.finding import Finding, Severity
from backend.services.correlator import correlate
from backend.services.knowledge import guidance_for, guidance_text
from backend.services.redact import redact_secrets


def mk(scanner: str, rule: str, line: int, *, cwe: str = "CWE-89", fp: str = "fp1",
       sev: Severity = Severity.MEDIUM, file: str = "a.py", **kw: object) -> Finding:  # fmt: skip
    return Finding(id=f"{scanner}{rule}{line}", scanner=scanner, rule_id=rule, file=file, line=line,
                   severity=sev, cwe=cwe, title=rule, fingerprint=fp, **kw)  # type: ignore[arg-type]  # fmt: skip


def test_same_fingerprint_merges_and_keeps_highest_severity() -> None:
    out = correlate([mk("semgrep", "r1", 10, sev=Severity.LOW), mk("semgrep", "r2", 10, sev=Severity.HIGH),
                     mk("codeql", "py/sqli", 10, sev=Severity.MEDIUM)])  # fmt: skip
    assert len(out) == 1
    f = out[0]
    assert f.scanner == "codeql"  # richer evidence wins as primary
    assert f.severity == Severity.HIGH
    assert f.also_detected_by == ["semgrep"]
    assert set(f.merged_rule_ids) == {"r1", "r2"}


def test_nearby_lines_same_cwe_merge_across_different_fingerprints() -> None:
    out = correlate([mk("semgrep", "src", 10, fp="a"), mk("codeql", "sink", 12, fp="b")])
    assert len(out) == 1


def test_far_apart_or_different_cwe_do_not_merge() -> None:
    assert len(correlate([mk("semgrep", "x", 10, fp="a"), mk("semgrep", "y", 40, fp="b")])) == 2
    assert (
        len(
            correlate(
                [mk("semgrep", "x", 10, fp="a"), mk("semgrep", "y", 11, fp="b", cwe="CWE-78")]
            )
        )
        == 2
    )


def test_dependency_findings_never_merge_by_proximity() -> None:
    a = mk("trivy", "CVE-1", 1, fp="a", cwe="CWE-1104", package="flask")
    b = mk("trivy", "CVE-2", 1, fp="b", cwe="CWE-1104", package="pyyaml")
    assert len(correlate([a, b])) == 2


def test_sorted_by_severity() -> None:
    out = correlate([mk("s", "a", 1, fp="1", sev=Severity.LOW, cwe="CWE-1"),
                     mk("s", "b", 50, fp="2", sev=Severity.CRITICAL, cwe="CWE-2")])  # fmt: skip
    assert [f.severity for f in out] == [Severity.CRITICAL, Severity.LOW]


def test_redaction() -> None:
    src = ('AWS_KEY = "AKIAZ5QW7NRTKLM4PXV2"\napi_token = "9f8e7d6c5b4a39281706f5e4d3c2b1a0aa"\n'
           'url = "postgresql://user:hunter2pass@db/app"\nkey = "gsk_abcdefghijklmnopqrstuvwx"\n'
           "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nname = 'bob'\n")  # fmt: skip
    out = redact_secrets(src)
    for leaked in ("AKIAZ5QW7NRTKLM4PXV2", "9f8e7d6c5b4a", "hunter2pass", "gsk_abcdef", "MIIabc"):
        assert leaked not in out
    assert "name = 'bob'" in out  # ordinary code is untouched


def test_knowledge_lookup() -> None:
    assert guidance_for("CWE-89") is not None
    assert guidance_for("CWE-73") is guidance_for("CWE-22")  # alias
    assert guidance_for("CWE-9999") is None and guidance_text(None) == ""
    assert "Real when" in guidance_text("CWE-78")


def test_adjacent_secrets_stay_separate() -> None:
    a = mk("semgrep", "cred", 1, cwe="CWE-798", fp="s1")
    b = mk("semgrep", "cred", 2, cwe="CWE-798", fp="s2")
    assert len(correlate([a, b])) == 2
