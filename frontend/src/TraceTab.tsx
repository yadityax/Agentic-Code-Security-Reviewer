import type { AuditEvent } from "./types";
import { Empty, Mono } from "./ui";

const ICON: Record<string, string> = { planner: "🧭", scanner_agent: "🔎", correlator: "🔗", security_analyst: "🧠", remediation_agent: "🔧", github_agent: "🐙", worker: "⚙️", mcp: "🧰" };

const summarize = (e: AuditEvent): string => {
  const d = e.detail;
  const parts: string[] = [];
  for (const [k, v] of Object.entries(d)) {
    if (k === "trace" || v == null) continue;
    parts.push(`${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  }
  return parts.join("  ").slice(0, 220);
};

export function TraceTab({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) return <Empty>No audit events recorded for this scan.</Empty>;
  return (
    <ol className="space-y-1" aria-label="Agent and tool trace">
      {events.map((e) => {
        const isHuman = e.actor.startsWith("human:");
        const isTool = e.action.startsWith("tool:");
        return (
          <li key={e.id} className={`flex gap-3 rounded border px-3 py-2 text-sm ${isHuman ? "border-blue-300 bg-blue-50 dark:border-blue-900 dark:bg-blue-950" : "border-slate-200 dark:border-slate-800"} ${isTool ? "ml-6" : ""}`}>
            <span aria-hidden>{isHuman ? "👤" : (ICON[e.actor] ?? "•")}</span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-medium">{e.action}</span>
                <span className="text-xs text-slate-500">{e.actor}</span>
                <span className="ml-auto text-xs text-slate-400">{new Date(e.ts).toLocaleTimeString()}</span>
              </div>
              <div className="truncate text-xs text-slate-500"><Mono>{summarize(e)}</Mono></div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
