export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Analysis {
  verdict: "true_positive" | "false_positive" | "needs_review";
  confidence: number;
  priority: number;
  exploitability: string;
  reasoning: string;
  cited_lines: number[];
  model: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  file: string;
  line: number;
  severity: Severity;
  cwe: string | null;
  owasp: string | null;
  title: string;
  evidence: string;
  status: string;
  pr_scope: "new" | "existing" | "unknown";
  confidence: number | null;
  scanners: string[];
  rule_ids: string[];
  analysis: Analysis | Record<string, never>;
}

export interface ToolRun {
  tool: string;
  status: string;
  duration_s: number;
  findings: number;
  error: string | null;
}

export interface ScanSummary {
  id: string;
  repo: string;
  pr_number: number | null;
  head_sha: string | null;
  status: string;
  started_at: string;
  finished_at: string | null;
  latency_s: number | null;
  llm_requests: number;
  llm_tokens: number;
  llm_cost_usd: number;
  counts: Record<string, number>;
  summary: Record<string, unknown>;
}

export interface ScanDetail extends ScanSummary {
  findings: Finding[];
  tool_runs: ToolRun[];
}

export interface AuditEvent {
  id: number;
  ts: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
}

export interface Verification {
  build?: { ok: boolean };
  lint?: { clean: boolean };
  tests?: { passed?: boolean; skipped?: boolean; counts?: Record<string, number> };
  rescan?: { original_finding_gone?: boolean; new_findings?: number };
  failure?: string;
}

export interface Remediation {
  id: number;
  fingerprint: string;
  attempt: number;
  status: string;
  title: string;
  cwe: string | null;
  file: string | null;
  line: number | null;
  patch: string;
  rationale: string;
  verification: Verification;
  approved_by: string | null;
  pr_url: string | null;
  created_at: string;
}

export interface Stats {
  scans_completed: number;
  avg_latency_s: number | null;
  llm_tokens: number;
  llm_cost_usd: number;
  findings_by_verdict: Record<string, number>;
  findings_by_severity: Record<string, number>;
  remediations_by_status: Record<string, number>;
}
