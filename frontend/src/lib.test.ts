import { describe, expect, it } from "vitest";
import { applyFilter, awaitingApproval, checkRows, countBy, defaultFilter, fmtCost, fmtSeconds } from "./lib";
import type { Finding, Remediation } from "./types";

const f = (o: Partial<Finding>): Finding => ({
  id: "1", fingerprint: "fp", file: "a.py", line: 1, severity: "medium", cwe: "CWE-89", owasp: null, title: "SQL injection",
  evidence: "", status: "true_positive", pr_scope: "new", confidence: 0.9, scanners: ["semgrep"], rule_ids: [], analysis: {}, ...o,
});
const r = (o: Partial<Remediation>): Remediation => ({
  id: 1, fingerprint: "fp", attempt: 1, status: "verified", title: "t", cwe: null, file: "a.py", line: 1, patch: "", rationale: "",
  verification: {}, approved_by: null, pr_url: null, created_at: "", ...o,
});

describe("applyFilter", () => {
  const data = [
    f({ id: "a", severity: "low", file: "z.py" }),
    f({ id: "b", severity: "critical", file: "b.py" }),
    f({ id: "c", severity: "high", status: "false_positive" }),
    f({ id: "d", severity: "high", pr_scope: "existing", title: "XSS", cwe: "CWE-79", scanners: ["codeql"] }),
  ];
  it("orders by severity then location and hides false positives by default", () => {
    expect(applyFilter(data, defaultFilter).map((x) => x.id)).toEqual(["b", "d", "a"]);
  });
  it("shows false positives when asked for that verdict explicitly", () => {
    expect(applyFilter(data, { ...defaultFilter, verdict: "false_positive" }).map((x) => x.id)).toEqual(["c"]);
  });
  it("filters by scope, severity and free-text search", () => {
    expect(applyFilter(data, { ...defaultFilter, scope: "existing" }).map((x) => x.id)).toEqual(["d"]);
    expect(applyFilter(data, { ...defaultFilter, severity: "low" }).map((x) => x.id)).toEqual(["a"]);
    expect(applyFilter(data, { ...defaultFilter, query: "codeql" }).map((x) => x.id)).toEqual(["d"]);
    expect(applyFilter(data, { ...defaultFilter, query: "cwe-79" }).map((x) => x.id)).toEqual(["d"]);
  });
});

describe("helpers", () => {
  it("countBy groups", () => expect(countBy(["a", "b", "a"], (x) => x)).toEqual({ a: 2, b: 1 }));
  it("formats durations and cost", () => {
    expect(fmtSeconds(null)).toBe("-");
    expect(fmtSeconds(4.25)).toBe("4.3s");
    expect(fmtSeconds(125)).toBe("2m 5s");
    expect(fmtCost(0.00031)).toBe("$0.0003");
    expect(fmtCost(1.5)).toBe("$1.50");
  });
  it("awaitingApproval keeps only the latest verified row per fingerprint", () => {
    const rows = [r({ id: 1, status: "failed_verification" }), r({ id: 2, status: "verified" }), r({ id: 3, fingerprint: "x", status: "pr_opened" })];
    expect(awaitingApproval(rows).map((x) => x.id)).toEqual([2]);
    expect(awaitingApproval([r({ id: 1, status: "verified" }), r({ id: 2, status: "failed_verification" })])).toEqual([]);
  });
  it("checkRows maps verification results and treats missing tests as not run", () => {
    const rows = checkRows(r({ verification: { build: { ok: true }, lint: { clean: true }, tests: { skipped: true }, rescan: { original_finding_gone: true, new_findings: 0 } } }));
    expect(rows.map((x) => x.ok)).toEqual([true, true, null, true, true]);
    expect(checkRows(r({ verification: { rescan: { new_findings: 2 } } })).at(-1)?.ok).toBe(false);
  });
});
