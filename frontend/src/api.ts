import type { AuditEvent, Remediation, ScanDetail, ScanSummary, Stats } from "./types";

const KEY = "acsr_token";

export const getToken = (): string => {
  try {
    return sessionStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
};

export const setToken = (t: string): void => {
  try {
    if (t) sessionStorage.setItem(KEY, t);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: token lives only for this page view */
  }
};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${getToken()}`, ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, String(detail));
  }
  return (await res.json()) as T;
}

export const api = {
  stats: () => request<Stats>("/api/stats"),
  scans: () => request<ScanSummary[]>("/api/scans?limit=100"),
  scan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  audit: (id: string) => request<AuditEvent[]>(`/api/scans/${id}/audit`),
  remediations: (id: string) => request<Remediation[]>(`/api/scans/${id}/remediations`),
  approve: (id: string, approvedBy: string) =>
    request<{ pr_url: string; fixes: number }>(`/api/scans/${id}/remediations/approve`, {
      method: "POST",
      body: JSON.stringify({ approved_by: approvedBy }),
    }),
};
