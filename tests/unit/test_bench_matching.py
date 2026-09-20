from backend.bench.matching import Counts, Pred, Truth, class_of, family, match_case
from backend.bench.systems import collapse_dependencies, to_preds
from backend.models.finding import Finding, Severity


def T(cwe: str, line: int, file: str = "app.py") -> Truth:
    return Truth(file, line, cwe)


def P(cwe: str, line: int, file: str = "app.py") -> Pred:
    return Pred(file, line, cwe)


def test_exact_and_family_match() -> None:
    pairs, fps, missed = match_case([P("CWE-1236", 10), P("CWE-73", 20)], [T("CWE-22", 22)])
    assert len(pairs) == 1 and pairs[0][0].cwe == "CWE-73"  # CWE-73 is in the path-traversal family
    assert [p.cwe for p in fps] == ["CWE-1236"] and missed == []


def test_line_tolerance_and_wrong_file() -> None:
    assert match_case([P("CWE-89", 30)], [T("CWE-89", 10)])[2]  # 20 lines away: missed
    assert not match_case([P("CWE-89", 14)], [T("CWE-89", 10)])[2]  # within tolerance
    assert match_case([P("CWE-89", 10, "other.py")], [T("CWE-89", 10)])[2]


def test_one_to_one_duplicates_are_false_positives() -> None:
    pairs, fps, missed = match_case([P("CWE-89", 10), P("CWE-89", 11)], [T("CWE-89", 10)])
    assert len(pairs) == 1 and len(fps) == 1 and not missed


def test_two_truths_need_two_predictions() -> None:
    pairs, fps, missed = match_case([P("CWE-798", 1)], [T("CWE-798", 1), T("CWE-798", 2)])
    assert len(pairs) == 1 and len(missed) == 1


def test_config_files_match_any_line() -> None:
    assert not match_case([P("CWE-16", 40, "Dockerfile")], [T("CWE-16", 1, "Dockerfile")])[2]


def test_dockerfile_secret_counts_as_misconfig() -> None:
    assert not match_case([P("CWE-798", 3, "Dockerfile")], [T("CWE-16", 3, "Dockerfile")])[2]
    assert match_case([P("CWE-798", 3, "app.py")], [T("CWE-16", 3, "app.py")])[
        2
    ]  # only special-cased for Dockerfiles


def test_access_control_family() -> None:
    assert not match_case([P("CWE-862", 5)], [T("CWE-639", 5)])[2]
    assert not match_case([P("CWE-284", 5)], [T("CWE-306", 5)])[2]
    assert class_of("CWE-306") == "Broken access control" and family("CWE-73") == "CWE-22"


def test_metrics_and_safe_case_fpr() -> None:
    c = Counts()
    c.add_case(
        [P("CWE-89", 10), P("CWE-78", 50)], [T("CWE-89", 10), T("CWE-22", 30)]
    )  # 1 TP, 1 FP, 1 FN
    c.add_case([P("CWE-79", 3)], [])  # safe case wrongly flagged
    c.add_case([], [])  # safe case, clean
    assert (c.tp, c.fp, c.fn) == (1, 2, 1)
    assert c.precision == 1 / 3 and c.recall == 0.5
    assert c.fp_rate_safe_cases == 0.5
    assert c.per_class["SQL injection"] == [1, 0] and c.per_class["Path traversal"] == [0, 1]


def test_dependency_collapse_and_severity_threshold() -> None:
    def dep(cve: str, sev: Severity) -> Finding:
        return Finding(id=cve, scanner="trivy", rule_id=cve, file="requirements.txt", line=1, severity=sev, title=cve,
                       fingerprint=cve, package="flask", cwe="CWE-1104", cve=cve)  # fmt: skip

    fs = [dep("CVE-1", Severity.LOW), dep("CVE-2", Severity.HIGH), dep("CVE-3", Severity.MEDIUM)]
    assert len(collapse_dependencies(fs)) == 1
    preds = to_preds(fs, drop_false_positives=False)
    assert len(preds) == 1 and preds[0].severity == "high"
    low_only = to_preds([dep("CVE-9", Severity.LOW)], drop_false_positives=False)
    assert low_only == []  # below the MEDIUM reporting threshold
