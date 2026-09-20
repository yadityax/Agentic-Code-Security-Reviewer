"""Markdown security report for a PR comment. All repo/LLM-derived text is sanitized first."""

import re
from collections import Counter

from backend.models.finding import Finding, PRScope, Severity, Verdict
from backend.services.github import REPORT_MARKER
from backend.services.knowledge import guidance_for
from backend.services.redact import redact_secrets

MAX_COMMENT_CHARS = 60_000
SEV_ICON = {
    Severity.CRITICAL: "🟣",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🟡",
    Severity.INFO: "⚪",
}
VERDICT_LABEL = {
    Verdict.TRUE_POSITIVE: "confirmed",
    Verdict.NEEDS_REVIEW: "needs review",
    Verdict.FALSE_POSITIVE: "likely false positive",
}


def sanitize(text: str, limit: int = 400) -> str:
    """Neutralize @mentions, HTML comments/tags and markdown link injection in untrusted text."""
    text = redact_secrets(text)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(
        r"<[^>\n]{1,200}>", lambda m: m[0].replace("<", "&lt;").replace(">", "&gt;"), text
    )
    text = re.sub(r"(?<![\w`])@(?=[\w-])", "@​", text)  # zero-width space stops notifications
    text = re.sub(r"\]\(", "]​(", text)
    text = " ".join(text.split())
    return text[: limit - 1] + "…" if len(text) > limit else text


def fence(code: str, lang: str = "python") -> str:
    ticks = "`" * max(3, max((len(m) for m in re.findall(r"`+", code)), default=0) + 1)
    return f"{ticks}{lang}\n{redact_secrets(code).strip()}\n{ticks}"


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _dependency_rows(deps: list[Finding]) -> list[str]:
    """One row per vulnerable package instead of one per CVE."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in deps:
        groups.setdefault((f.file, f.package or "?"), []).append(f)
    rows = [
        "| Package | Location | CVEs | Highest | Upgrade to | Imported by code? |",
        "|---|---|---|---|---|---|",
    ]
    order = list(Severity)
    for (file, pkg), fs in sorted(
        groups.items(), key=lambda kv: -max(order.index(f.severity) for f in kv[1])
    ):
        top = max((f.severity for f in fs), key=order.index)
        fixes = [m for f in fs for m in re.findall(r"Fixed in: ([\d.,\s]+?)\.(?:\s|$)", f.evidence)]
        versions = [v.strip() for chunk in fixes for v in chunk.split(",") if v.strip()]
        upgrade = max(versions, key=_ver) if versions else "no fix yet"
        reach = {True: "yes", False: "no", None: "unknown"}[fs[0].reachable]
        cves = ", ".join(sorted({f.cve or f.rule_id for f in fs})[:3]) + (
            " …" if len(fs) > 3 else ""
        )
        rows.append(
            f"| `{sanitize(pkg, 40)}` | `{sanitize(file, 60)}:{fs[0].line}` | {len(fs)} ({cves}) | {SEV_ICON[top]} {top.value} | {sanitize(upgrade, 30)} | {reach} |"
        )
    return rows


def _row(f: Finding) -> str:
    a = f.analysis
    verdict = VERDICT_LABEL[a.verdict] if a else "unvalidated"
    conf = f"{a.confidence:.0%}" if a else "-"
    by = ", ".join([f.scanner, *f.also_detected_by])
    return (f"| {SEV_ICON[f.severity]} {f.severity.value} | `{sanitize(f.file, 80)}:{f.line}` | "
            f"{sanitize(f.title, 90)} | {f.cwe or '-'} | {verdict} ({conf}) | {by} |")  # fmt: skip


def _detail(f: Finding) -> str:
    a = f.analysis
    g = guidance_for(f.cwe)
    lines = [f"#### {SEV_ICON[f.severity]} {sanitize(f.title, 120)}",
             f"`{sanitize(f.file, 120)}:{f.line}` · {f.cwe or 'no CWE'}" + (f" · OWASP {f.owasp}" if f.owasp else "")
             + (f" · {f.cve}" if f.cve else "") + f" · found by {', '.join([f.scanner, *f.also_detected_by])}"]  # fmt: skip
    if a:
        lines.append(
            f"**Verdict:** {VERDICT_LABEL[a.verdict]} ({a.confidence:.0%}, priority P{a.priority})"
        )
        if a.exploitability:
            lines.append(f"**Impact:** {sanitize(a.exploitability, 400)}")
        if a.reasoning:
            lines.append(f"**Why:** {sanitize(a.reasoning, 500)}")
    if f.evidence and f.scanner not in ("gitleaks",):
        lines.append(fence(f.evidence[:700], "" if f.scanner == "trivy" else "python"))
    if f.recommended_fix or g:
        lines.append(
            f"**Suggested fix:** {sanitize(f.recommended_fix or (g.fix if g else ''), 300)}"
        )
    return "\n\n".join(lines)


def render_report(findings: list[Finding], *, scanners: list[str], warnings: list[str] | None = None,
                  usage: dict[str, float] | None = None, scan_errors: dict[str, str] | None = None) -> str:  # fmt: skip
    live = [f for f in findings if not f.analysis or f.analysis.verdict != Verdict.FALSE_POSITIVE]
    fps = [f for f in findings if f.analysis and f.analysis.verdict == Verdict.FALSE_POSITIVE]
    live_code = [f for f in live if not f.package]
    dep_findings = [f for f in live if f.package]
    new = [f for f in live_code if f.pr_scope != PRScope.EXISTING]
    old = [f for f in live_code if f.pr_scope == PRScope.EXISTING]
    new_deps = [f for f in dep_findings if f.pr_scope != PRScope.EXISTING]
    sev = Counter(f.severity for f in new)
    out = [REPORT_MARKER, "## 🛡️ Security review"]
    if not new and not new_deps:
        out.append("✅ No actionable security findings on the lines changed in this PR.")
    elif not new:
        out.append("No code-level findings on the lines changed in this PR.")
    else:
        out.append("**" + ", ".join(f"{n} {s.value}" for s, n in sorted(sev.items(), key=lambda kv: -list(Severity).index(kv[0])) ) + f"** across {len(new)} finding(s) introduced or touched by this PR.")  # fmt: skip
        out += [
            "| Severity | Location | Issue | CWE | Verdict | Detected by |",
            "|---|---|---|---|---|---|",
        ]
        out += [_row(f) for f in new[:40]]
        out += ["", "<details open><summary><b>Details</b></summary>", ""]
        out += [_detail(f) for f in new[:15]]
        out += ["", "</details>"]
    if new_deps:
        n_pkgs = len({(f.file, f.package) for f in new_deps})
        out += [
            "",
            f"### 📦 Vulnerable dependencies ({n_pkgs} package(s), {len(new_deps)} CVE(s))",
            "",
        ] + _dependency_rows(new_deps)
    if old:
        out += ["", f"<details><summary>{len(old)} pre-existing finding(s) not introduced by this PR</summary>", "",
                "| Severity | Location | Issue | CWE | Verdict | Detected by |", "|---|---|---|---|---|---|"]  # fmt: skip
        out += [_row(f) for f in old[:30]] + ["", "</details>"]
    if fps:
        out += [
            "",
            f"<details><summary>{len(fps)} finding(s) dismissed as likely false positives</summary>",
            "",
        ]
        out += [f"- `{sanitize(f.file, 80)}:{f.line}` {sanitize(f.title, 80)} — {sanitize(f.analysis.reasoning if f.analysis else '', 160)}" for f in fps[:20]]  # fmt: skip
        out += ["", "</details>"]
    foot = f"Scanners: {', '.join(scanners) or 'none'}"
    if scan_errors:
        foot += " · ⚠️ failed: " + ", ".join(f"{k}" for k in scan_errors)
    if usage:
        foot += f" · LLM: {int(usage.get('tokens', 0)):,} tokens (${usage.get('cost_usd', 0):.4f})"
    out += ["", f"<sub>{foot}</sub>"]
    for w in (warnings or [])[:5]:
        out.append(f"> ⚠️ {sanitize(w, 200)}")
    body = "\n".join(out)
    return (
        body
        if len(body) <= MAX_COMMENT_CHARS
        else body[:MAX_COMMENT_CHARS] + "\n\n_…report truncated_"
    )


def render_remediation_section(results: list[dict[str, object]]) -> str:
    """PR-comment section summarizing automated fix attempts. Fixes are proposals until a human approves."""
    if not results:
        return ""
    icon = {
        "verified": "✅ verified",
        "failed": "❌ could not be fixed automatically",
        "declined": "⚪ needs a human",
    }
    rows = ["", "### 🔧 Automated fixes", "", "| Finding | Outcome | Attempts |", "|---|---|---|"]
    for r in results:
        rows.append(
            f"| `{sanitize(str(r['file']), 60)}:{r['line']}` {sanitize(str(r['title']), 70)} | {icon.get(str(r['outcome']), r['outcome'])} | {r['attempts']} |"
        )
    if any(r["outcome"] == "verified" for r in results):
        rows += ["", "Verified fixes passed the build, the project's tests and a security rescan with no new findings. "
                     "They are **not applied**: a maintainer must approve them before a remediation pull request is opened."]  # fmt: skip
    return "\n".join(rows)
