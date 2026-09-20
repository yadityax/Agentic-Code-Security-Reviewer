"""Finding correlator: collapse overlapping results from different scanners/rules into one finding."""

from collections import defaultdict

from backend.models.finding import Finding, Severity
from backend.services.cwe import family

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
LINE_WINDOW = 3
CODE_ANALYZERS = {
    "semgrep",
    "codeql",
}  # proximity merging only makes sense for code data-flow results
SCANNER_PRIORITY = ["codeql", "semgrep", "trivy", "gitleaks"]  # prefer richer data-flow evidence


def _rank(f: Finding) -> tuple[int, int]:
    try:
        p = SCANNER_PRIORITY.index(f.scanner)
    except ValueError:
        p = len(SCANNER_PRIORITY)
    return (p, -SEVERITY_ORDER.index(f.severity))


def _merge(group: list[Finding]) -> Finding:
    group = sorted(group, key=_rank)
    primary = group[0]
    top = max((f.severity for f in group), key=SEVERITY_ORDER.index)
    scanners = sorted({f.scanner for f in group})
    rules = sorted({r for f in group for r in (f.rule_id, *f.merged_rule_ids)})
    cwe = primary.cwe or next((f.cwe for f in group if f.cwe), None)
    return primary.model_copy(update={
        "severity": top,
        "cwe": cwe,
        "owasp": primary.owasp or next((f.owasp for f in group if f.owasp), None),
        "also_detected_by": [s for s in scanners if s != primary.scanner],
        "merged_rule_ids": [r for r in rules if r != primary.rule_id],
        "evidence": max((f.evidence for f in group), key=len),
        "end_line": max((f.end_line or f.line) for f in group),
    })  # fmt: skip


def _same_issue(last: Finding, f: Finding) -> bool:
    """Proximity rule for the second pass: same file, same CWE family, adjacent lines, code analyzers only."""
    if not f.cwe or last.file != f.file or family(last.cwe) != family(f.cwe):
        return False
    if family(f.cwe) == "CWE-798":  # each hardcoded secret is its own issue
        return False
    if f.scanner not in CODE_ANALYZERS or last.scanner not in CODE_ANALYZERS:
        return False
    return f.line - (last.end_line or last.line) <= LINE_WINDOW


def correlate(findings: list[Finding]) -> list[Finding]:
    """Group by fingerprint, then by (file, CWE, nearby lines). Order is deterministic."""
    by_fp: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_fp[f.fingerprint].append(f)
    merged = [_merge(g) for g in by_fp.values()]

    # Second pass: same file + same CWE + lines within a small window are the same issue
    # even if the snippet hash differs (e.g. CodeQL flags the sink, Semgrep the source).
    merged.sort(key=lambda f: (f.file, family(f.cwe) or "", f.line))
    out: list[list[Finding]] = []
    for f in merged:
        if out and _same_issue(out[-1][-1], f):
            out[-1].append(f)
        else:
            out.append([f])
    result = [_merge(g) if len(g) > 1 else g[0] for g in out]
    return sorted(result, key=lambda f: (-SEVERITY_ORDER.index(f.severity), f.file, f.line))
