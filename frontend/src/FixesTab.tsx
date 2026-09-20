import { useState } from "react";
import { ApiError, api } from "./api";
import { awaitingApproval, checkRows } from "./lib";
import type { Remediation } from "./types";
import { Check, Empty, Mono } from "./ui";

const STATUS_LABEL: Record<string, string> = {
  verified: "verified, awaiting approval",
  failed_verification: "attempt rejected by verification",
  rejected_by_guardrails: "attempt rejected by guardrails",
  failed: "could not be fixed automatically",
  declined: "needs a human",
  pr_opened: "pull request opened",
};

function Diff({ patch }: { patch: string }) {
  return (
    <pre className="max-h-72 overflow-auto rounded border border-slate-200 bg-white p-3 text-xs dark:border-slate-700 dark:bg-slate-950">
      {patch.split("\n").map((ln, i) => (
        <div key={i} className={ln.startsWith("+") && !ln.startsWith("+++") ? "bg-green-50 text-green-800 dark:bg-green-950 dark:text-green-300" : ln.startsWith("-") && !ln.startsWith("---") ? "bg-red-50 text-red-800 dark:bg-red-950 dark:text-red-300" : ""}>{ln || " "}</div>
      ))}
    </pre>
  );
}

export function FixesTab({ scanId, rems, onChanged }: { scanId: string; rems: Remediation[]; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const pending = awaitingApproval(rems);

  const approve = async () => {
    const name = window.prompt(`Approve ${pending.length} verified fix(es) and open a pull request?\nEnter your name for the audit trail:`);
    if (!name?.trim()) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await api.approve(scanId, name.trim());
      setMsg({ ok: true, text: `Pull request opened: ${res.pr_url}` });
      onChanged();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? `${e.status}: ${e.message}` : String(e) });
    } finally {
      setBusy(false);
    }
  };

  if (rems.length === 0) return <Empty>No remediation attempts for this scan. Automatic fixes run only for confirmed findings, and only when remediation is enabled.</Empty>;

  return (
    <div className="space-y-4">
      {pending.length > 0 && (
        <div className="flex items-center justify-between rounded-lg border border-green-300 bg-green-50 p-4 dark:border-green-900 dark:bg-green-950">
          <div className="text-sm">
            <div className="font-semibold">{pending.length} verified fix(es) ready</div>
            <div className="text-slate-600 dark:text-slate-400">Nothing is applied until you approve. Approval opens a pull request on an <Mono>acsr/*</Mono> branch; it is never merged automatically.</div>
          </div>
          <button onClick={approve} disabled={busy} className="rounded bg-green-700 px-4 py-2 text-sm font-medium text-white hover:bg-green-800 disabled:opacity-50">{busy ? "Opening PR…" : "Approve and open PR"}</button>
        </div>
      )}
      {msg && <div role="status" className={`rounded border p-3 text-sm ${msg.ok ? "border-green-300 bg-green-50 dark:bg-green-950" : "border-red-300 bg-red-50 dark:bg-red-950"}`}>{msg.text}</div>}
      {rems.map((r) => (
        <details key={r.id} open={r.status === "verified"} className="rounded-lg border border-slate-200 dark:border-slate-800">
          <summary className="cursor-pointer p-3 text-sm">
            <span className="font-medium">{r.title || r.fingerprint.slice(0, 8)}</span>
            <span className="ml-2 text-slate-500"><Mono>{r.file}{r.line ? `:${r.line}` : ""}</Mono> · attempt {r.attempt} · {STATUS_LABEL[r.status] ?? r.status}</span>
            {r.pr_url && <a className="ml-2 text-blue-600 underline" href={r.pr_url} target="_blank" rel="noreferrer">view PR</a>}
          </summary>
          <div className="space-y-3 border-t border-slate-200 p-3 dark:border-slate-800">
            {r.rationale && <p className="text-sm">{r.rationale}</p>}
            <ul className="grid gap-1 sm:grid-cols-2">{checkRows(r).map((c) => <Check key={c.label} ok={c.ok} label={c.label} />)}</ul>
            {r.verification.failure && <pre className="overflow-x-auto rounded bg-red-50 p-2 text-xs text-red-800 dark:bg-red-950 dark:text-red-300">{r.verification.failure}</pre>}
            {r.patch && <Diff patch={r.patch} />}
            {r.approved_by && <p className="text-xs text-slate-500">Approved by {r.approved_by}</p>}
          </div>
        </details>
      ))}
    </div>
  );
}
