import type { Finding, Remediation, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const severityRank = (s: string): number => {
  const i = SEVERITIES.indexOf(s as Severity);
  return i === -1 ? SEVERITIES.length : i;
};

export interface FindingFilter {
  severity: string;
  verdict: string;
  scope: string;
  query: string;
  hideFalsePositives: boolean;
}

export const defaultFilter: FindingFilter = { severity: "all", verdict: "all", scope: "all", query: "", hideFalsePositives: true };

/** Filter and order findings: most severe first, then by file and line. */
export function applyFilter(findings: Finding[], f: FindingFilter): Finding[] {
  const q = f.query.trim().toLowerCase();
  return findings
    .filter((x) => (f.severity === "all" || x.severity === f.severity))
    .filter((x) => (f.verdict === "all" || x.status === f.verdict))
    .filter((x) => (f.scope === "all" || x.pr_scope === f.scope))
    .filter((x) => !(f.hideFalsePositives && x.status === "false_positive" && f.verdict === "all"))
    .filter((x) => !q || `${x.file} ${x.title} ${x.cwe ?? ""} ${x.scanners.join(" ")}`.toLowerCase().includes(q))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
}

export function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, it) => {
    const k = key(it);
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
}

export const fmtSeconds = (s: number | null | undefined): string =>
  s == null ? "-" : s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;

export const fmtCost = (usd: number): string => (usd < 0.01 ? `$${usd.toFixed(4)}` : `$${usd.toFixed(2)}`);

export const fmtNumber = (n: number): string => n.toLocaleString("en-US");

/** A remediation row is awaiting a human decision only if it verified and no PR exists yet. */
export const awaitingApproval = (rems: Remediation[]): Remediation[] => {
  const latest = new Map<string, Remediation>();
  for (const r of rems) latest.set(r.fingerprint, r);
  return [...latest.values()].filter((r) => r.status === "verified");
};

export const checkRows = (r: Remediation): { label: string; ok: boolean | null }[] => {
  const v = r.verification;
  return [
    { label: "builds", ok: v.build?.ok ?? null },
    { label: "no broken code", ok: v.lint?.clean ?? null },
    { label: "tests pass", ok: v.tests?.skipped ? null : (v.tests?.passed ?? null) },
    { label: "original finding gone", ok: v.rescan?.original_finding_gone ?? null },
    { label: "no new findings", ok: v.rescan ? v.rescan.new_findings === 0 : null },
  ];
};
