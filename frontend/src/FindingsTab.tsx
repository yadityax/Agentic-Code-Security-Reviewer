import { useMemo, useState } from "react";
import { SEVERITIES, applyFilter, defaultFilter, type FindingFilter } from "./lib";
import type { Analysis, Finding } from "./types";
import { Empty, Mono, SeverityChip, VerdictChip } from "./ui";

const hasAnalysis = (a: Finding["analysis"]): a is Analysis => "verdict" in a;

function Detail({ f }: { f: Finding }) {
  const a = hasAnalysis(f.analysis) ? f.analysis : null;
  return (
    <div className="space-y-3 bg-slate-50 p-4 text-sm dark:bg-slate-900/60">
      {a && (
        <div className="grid gap-2 md:grid-cols-2">
          <p><span className="font-semibold">Impact: </span>{a.exploitability || "-"}</p>
          <p><span className="font-semibold">Reasoning: </span>{a.reasoning || "-"}</p>
          <p className="text-xs text-slate-500">
            {a.model} · confidence {(a.confidence * 100).toFixed(0)}% · priority P{a.priority}
            {a.cited_lines.length > 0 && <> · cites lines {a.cited_lines.join(", ")}</>}
          </p>
        </div>
      )}
      {f.evidence && <pre className="overflow-x-auto rounded border border-slate-200 bg-white p-3 text-xs dark:border-slate-700 dark:bg-slate-950">{f.evidence}</pre>}
      <p className="text-xs text-slate-500">
        rules: <Mono>{f.rule_ids.join(", ")}</Mono> · fingerprint <Mono>{f.fingerprint.slice(0, 12)}</Mono>
        {f.owasp && <> · OWASP {f.owasp}</>}
      </p>
    </div>
  );
}

export function FindingsTab({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<FindingFilter>(defaultFilter);
  const [open, setOpen] = useState<string | null>(null);
  const rows = useMemo(() => applyFilter(findings, filter), [findings, filter]);
  const set = (patch: Partial<FindingFilter>) => setFilter((f) => ({ ...f, ...patch }));
  const select = "rounded border border-slate-300 bg-white px-2 py-1 text-sm dark:border-slate-700 dark:bg-slate-900";

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <input aria-label="Search findings" placeholder="Search file, title, CWE, scanner" value={filter.query} onChange={(e) => set({ query: e.target.value })} className={`${select} w-64`} />
        <select aria-label="Severity" className={select} value={filter.severity} onChange={(e) => set({ severity: e.target.value })}>
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select aria-label="Verdict" className={select} value={filter.verdict} onChange={(e) => set({ verdict: e.target.value })}>
          <option value="all">All verdicts</option>
          <option value="true_positive">Confirmed</option>
          <option value="needs_review">Needs review</option>
          <option value="false_positive">False positive</option>
          <option value="fixed">Fix verified</option>
          <option value="fix_failed">Fix failed</option>
        </select>
        <select aria-label="Scope" className={select} value={filter.scope} onChange={(e) => set({ scope: e.target.value })}>
          <option value="all">All code</option>
          <option value="new">Changed by this PR</option>
          <option value="existing">Pre-existing</option>
        </select>
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={filter.hideFalsePositives} onChange={(e) => set({ hideFalsePositives: e.target.checked })} /> hide false positives
        </label>
        <span className="ml-auto text-sm text-slate-500">{rows.length} of {findings.length}</span>
      </div>
      {rows.length === 0 ? (
        <Empty>No findings match these filters.</Empty>
      ) : (
        <div className="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-100 text-xs uppercase text-slate-500 dark:bg-slate-900">
              <tr><th className="p-2">Severity</th><th className="p-2">Location</th><th className="p-2">Issue</th><th className="p-2">CWE</th><th className="p-2">Verdict</th><th className="p-2">Detected by</th></tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <FindingRow key={f.id} f={f} open={open === f.id} onToggle={() => setOpen(open === f.id ? null : f.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingRow({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr onClick={onToggle} className="cursor-pointer border-t border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-900" aria-expanded={open}>
        <td className="p-2"><SeverityChip severity={f.severity} /></td>
        <td className="p-2"><Mono>{f.file}:{f.line}</Mono>{f.pr_scope === "new" && <span className="ml-2 rounded bg-blue-100 px-1 text-xs text-blue-800 dark:bg-blue-950 dark:text-blue-200">PR</span>}</td>
        <td className="max-w-md truncate p-2" title={f.title}>{f.title}</td>
        <td className="p-2">{f.cwe ?? "-"}</td>
        <td className="p-2"><VerdictChip status={f.status} /></td>
        <td className="p-2 text-xs text-slate-500">{f.scanners.join(", ")}</td>
      </tr>
      {open && <tr><td colSpan={6} className="p-0"><Detail f={f} /></td></tr>}
    </>
  );
}
