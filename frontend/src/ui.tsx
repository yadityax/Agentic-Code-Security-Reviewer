import type { ReactNode } from "react";
import type { Severity } from "./types";

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-200",
  high: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
  medium: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200",
  low: "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200",
  info: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
};

export const SeverityChip = ({ severity }: { severity: string }) => (
  <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_STYLE[severity as Severity] ?? SEV_STYLE.info}`}>{severity}</span>
);

const VERDICT_STYLE: Record<string, string> = {
  true_positive: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950 dark:text-red-300 dark:ring-red-900",
  false_positive: "bg-slate-50 text-slate-600 ring-slate-200 dark:bg-slate-900 dark:text-slate-400 dark:ring-slate-700",
  needs_review: "bg-amber-50 text-amber-700 ring-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:ring-amber-900",
  fixed: "bg-green-50 text-green-700 ring-green-200 dark:bg-green-950 dark:text-green-300 dark:ring-green-900",
  fix_failed: "bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-950 dark:text-rose-300 dark:ring-rose-900",
};
const VERDICT_LABEL: Record<string, string> = {
  true_positive: "confirmed",
  false_positive: "false positive",
  needs_review: "needs review",
  fixed: "fix verified",
  fix_failed: "fix failed",
  unvalidated: "unvalidated",
};

export const VerdictChip = ({ status }: { status: string }) => (
  <span className={`inline-block rounded px-2 py-0.5 text-xs ring-1 ${VERDICT_STYLE[status] ?? "bg-slate-50 text-slate-600 ring-slate-200 dark:bg-slate-900 dark:text-slate-400 dark:ring-slate-700"}`}>
    {VERDICT_LABEL[status] ?? status}
  </span>
);

export const Card = ({ title, value, hint }: { title: string; value: ReactNode; hint?: string }) => (
  <div className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
    <div className="text-xs uppercase tracking-wide text-slate-500">{title}</div>
    <div className="mt-1 text-2xl font-semibold">{value}</div>
    {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
  </div>
);

export const Empty = ({ children }: { children: ReactNode }) => (
  <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500 dark:border-slate-700">{children}</div>
);

export const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-xs">{children}</span>;

export const Check = ({ ok, label }: { ok: boolean | null; label: string }) => (
  <li className="flex items-center gap-2 text-sm">
    <span aria-hidden className={ok === true ? "text-green-600" : ok === false ? "text-red-600" : "text-slate-400"}>
      {ok === true ? "✓" : ok === false ? "✗" : "–"}
    </span>
    <span className={ok === false ? "text-red-700 dark:text-red-300" : ""}>{label}</span>
    <span className="sr-only">{ok === true ? "passed" : ok === false ? "failed" : "not run"}</span>
  </li>
);
