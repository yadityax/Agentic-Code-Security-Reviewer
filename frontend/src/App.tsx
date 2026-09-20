import { useCallback, useEffect, useState } from "react";
import { ApiError, api, getToken, setToken } from "./api";
import { FindingsTab } from "./FindingsTab";
import { FixesTab } from "./FixesTab";
import { TraceTab } from "./TraceTab";
import { SEVERITIES, countBy, fmtCost, fmtNumber, fmtSeconds } from "./lib";
import type { AuditEvent, Remediation, ScanDetail, ScanSummary, Stats } from "./types";
import { Card, Empty, Mono, SeverityChip } from "./ui";

function Login({ onDone }: { onDone: () => void }) {
  const [v, setV] = useState("");
  return (
    <form className="mx-auto mt-24 max-w-sm space-y-3 rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900" onSubmit={(e) => { e.preventDefault(); setToken(v.trim()); onDone(); }}>
      <h1 className="text-lg font-semibold">Security Reviewer</h1>
      <p className="text-sm text-slate-500">Enter the admin API token (<Mono>ADMIN_API_TOKEN</Mono>). It is kept for this browser tab only.</p>
      <input type="password" autoFocus aria-label="Admin API token" value={v} onChange={(e) => setV(e.target.value)} className="w-full rounded border border-slate-300 px-3 py-2 dark:border-slate-700 dark:bg-slate-950" />
      <button className="w-full rounded bg-slate-900 py-2 text-sm text-white dark:bg-slate-100 dark:text-slate-900">Sign in</button>
    </form>
  );
}

function useAsync<T>(load: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ data?: T; error?: ApiError | Error; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true }));
    load().then((data) => live && setState({ data, loading: false })).catch((error) => live && setState({ error, loading: false }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

function Overview({ onOpen }: { onOpen: (id: string) => void }) {
  const stats = useAsync<Stats>(api.stats, []);
  const scans = useAsync<ScanSummary[]>(api.scans, []);
  const s = stats.data;
  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card title="Scans completed" value={s ? fmtNumber(s.scans_completed) : "-"} />
        <Card title="Average latency" value={fmtSeconds(s?.avg_latency_s)} />
        <Card title="LLM tokens" value={s ? fmtNumber(s.llm_tokens) : "-"} hint={s ? `${fmtCost(s.llm_cost_usd)} total` : undefined} />
        <Card title="Fixes verified / opened" value={s ? `${s.remediations_by_status.verified ?? 0} / ${s.remediations_by_status.pr_opened ?? 0}` : "-"} hint="awaiting approval / PR opened" />
      </div>
      {s && (
        <div className="flex flex-wrap gap-2 text-sm" aria-label="Findings by severity">
          {SEVERITIES.map((sev) => <span key={sev} className="flex items-center gap-1"><SeverityChip severity={sev} /> {s.findings_by_severity[sev] ?? 0}</span>)}
        </div>
      )}
      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">Scan history</h2>
        {scans.error ? <ErrorBox e={scans.error} /> : !scans.data?.length ? <Empty>No scans yet. Open a pull request on a repository with the webhook configured.</Empty> : (
          <div className="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-100 text-xs uppercase text-slate-500 dark:bg-slate-900"><tr><th className="p-2">Repository</th><th className="p-2">PR</th><th className="p-2">Status</th><th className="p-2">Findings</th><th className="p-2">Latency</th><th className="p-2">Tokens</th><th className="p-2">Started</th></tr></thead>
              <tbody>
                {scans.data.map((sc) => (
                  <tr key={sc.id} onClick={() => onOpen(sc.id)} className="cursor-pointer border-t border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-900">
                    <td className="p-2 font-medium">{sc.repo}</td>
                    <td className="p-2">{sc.pr_number ? `#${sc.pr_number}` : "-"}</td>
                    <td className="p-2">{sc.status}</td>
                    <td className="p-2"><span className="flex gap-1">{SEVERITIES.filter((v) => sc.counts[v]).map((v) => <span key={v} className="flex items-center gap-0.5"><SeverityChip severity={v} />{sc.counts[v]}</span>)}{!Object.keys(sc.counts).length && "-"}</span></td>
                    <td className="p-2">{fmtSeconds(sc.latency_s)}</td>
                    <td className="p-2">{fmtNumber(sc.llm_tokens)}</td>
                    <td className="p-2 text-slate-500">{new Date(sc.started_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

const ErrorBox = ({ e }: { e: Error }) => <div role="alert" className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-200">{e.message}</div>;

type Tab = "findings" | "trace" | "fixes" | "tools";

function ScanView({ id, onBack }: { id: string; onBack: () => void }) {
  const [tab, setTab] = useState<Tab>("findings");
  const scan = useAsync<ScanDetail>(() => api.scan(id), [id]);
  const audit = useAsync<AuditEvent[]>(() => api.audit(id), [id]);
  const rems = useAsync<Remediation[]>(() => api.remediations(id), [id]);
  const refresh = useCallback(() => { scan.reload(); audit.reload(); rems.reload(); }, [scan, audit, rems]);
  const d = scan.data;
  if (scan.error) return <><button onClick={onBack} className="mb-3 text-sm underline">← Back</button><ErrorBox e={scan.error} /></>;
  if (!d) return <p className="text-sm text-slate-500">Loading…</p>;
  const verdicts = countBy(d.findings, (f) => f.status);
  const tabs: [Tab, string][] = [["findings", `Findings (${d.findings.length})`], ["trace", `Agent trace (${audit.data?.length ?? 0})`], ["fixes", `Fixes (${rems.data?.length ?? 0})`], ["tools", `Tools (${d.tool_runs.length})`]];
  return (
    <div className="space-y-4">
      <button onClick={onBack} className="text-sm underline">← All scans</button>
      <header>
        <h1 className="text-xl font-semibold">{d.repo}{d.pr_number ? ` #${d.pr_number}` : ""}</h1>
        <p className="text-sm text-slate-500"><Mono>{d.head_sha?.slice(0, 10)}</Mono> · {d.status} · {fmtSeconds(d.latency_s)} · {fmtNumber(d.llm_tokens)} tokens ({fmtCost(d.llm_cost_usd)}) · {d.llm_requests} LLM calls · confirmed {verdicts.true_positive ?? 0}, needs review {verdicts.needs_review ?? 0}, dismissed {verdicts.false_positive ?? 0}</p>
      </header>
      <nav className="flex gap-1 border-b border-slate-200 dark:border-slate-800" role="tablist">
        {tabs.map(([k, label]) => <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} className={`px-3 py-2 text-sm ${tab === k ? "border-b-2 border-slate-900 font-semibold dark:border-slate-100" : "text-slate-500"}`}>{label}</button>)}
      </nav>
      {tab === "findings" && <FindingsTab findings={d.findings} />}
      {tab === "trace" && <TraceTab events={audit.data ?? []} />}
      {tab === "fixes" && <FixesTab scanId={id} rems={rems.data ?? []} onChanged={refresh} />}
      {tab === "tools" && (
        <table className="w-full text-left text-sm"><thead className="text-xs uppercase text-slate-500"><tr><th className="p-2">Tool</th><th className="p-2">Status</th><th className="p-2">Findings</th><th className="p-2">Duration</th><th className="p-2">Error</th></tr></thead>
          <tbody>{d.tool_runs.map((t, i) => <tr key={i} className="border-t border-slate-200 dark:border-slate-800"><td className="p-2">{t.tool}</td><td className="p-2">{t.status}</td><td className="p-2">{t.findings}</td><td className="p-2">{fmtSeconds(t.duration_s)}</td><td className="p-2 text-red-600">{t.error ?? ""}</td></tr>)}</tbody></table>
      )}
    </div>
  );
}

const readHash = (): string | null => window.location.hash.match(/^#\/scan\/(\w+)$/)?.[1] ?? null;

export default function App() {
  const [authed, setAuthed] = useState(() => Boolean(getToken()));
  const [scanId, setScanId] = useState<string | null>(readHash);
  useEffect(() => { const h = () => setScanId(readHash()); window.addEventListener("hashchange", h); return () => window.removeEventListener("hashchange", h); }, []);
  const open = (id: string | null) => { window.location.hash = id ? `#/scan/${id}` : ""; setScanId(id); };
  if (!authed) return <Login onDone={() => setAuthed(true)} />;
  return (
    <div className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6 flex items-center justify-between">
        <a href="#/" onClick={() => open(null)} className="text-lg font-bold">🛡️ Security Reviewer</a>
        <button onClick={() => { setToken(""); setAuthed(false); }} className="text-sm text-slate-500 underline">Sign out</button>
      </div>
      {scanId ? <ScanView id={scanId} onBack={() => open(null)} /> : <Overview onOpen={open} />}
    </div>
  );
}
