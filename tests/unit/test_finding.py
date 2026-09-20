from backend.models.finding import Finding, Severity, compute_fingerprint


def fp(**kw: str | None) -> str:
    base: dict[str, str | None] = {
        "cwe": "CWE-89",
        "rule_id": "sql-injection",
        "file": "api/users.py",
        "symbol": "get_user",
        "snippet": "q = \"SELECT * FROM users WHERE name = '%s'\" % name",
    }
    return compute_fingerprint(**{**base, **kw})  # type: ignore[arg-type]


def test_fingerprint_is_stable_across_whitespace_and_path_style() -> None:
    assert fp() == fp(snippet="q  =  \"SELECT * FROM users WHERE name = '%s'\"   %\n name")
    assert fp() == fp(file="./api/users.py")


def test_fingerprint_is_scanner_independent() -> None:
    # Same CWE at the same place must collapse even if rule ids differ.
    assert fp(rule_id="semgrep.sqli") == fp(rule_id="codeql.py/sql-injection")


def test_fingerprint_changes_with_code_or_location() -> None:
    assert fp() != fp(snippet="q = safe_query(name)")
    assert fp() != fp(file="api/orders.py")
    assert fp() != fp(cwe="CWE-79")


def test_finding_validates_ranges() -> None:
    f = Finding(
        id="f1",
        scanner="semgrep",
        rule_id="r",
        file="a.py",
        line=1,
        severity=Severity.HIGH,
        title="t",
        fingerprint="x",
    )
    assert f.status == "unvalidated"
    assert f.pr_scope == "unknown"


def test_verdict_accepts_any_llm_casing() -> None:
    from backend.models.finding import Verdict

    for raw in ("TRUE_POSITIVE", "true_positive", "True Positive", " true-positive "):
        assert Verdict(raw) is Verdict.TRUE_POSITIVE
    assert Verdict("NEEDS_REVIEW") is Verdict.NEEDS_REVIEW
