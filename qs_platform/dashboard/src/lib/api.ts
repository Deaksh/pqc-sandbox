const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("qs_token") : null;
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...opts?.headers,
    },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export type Verdict    = "GO" | "CAUTION" | "BLOCKED";
export type Framework  = "RBI" | "SEBI" | "CERT-In" | "DPDP" | "NIST_CNSA2" | "EU_DORA" | "MAS_TRM" | "ISO27001";

export interface Asset {
  id: string;
  name: string;
  asset_type: string;
  target: string;
  team?: string;
  tags: string[];
  last_scanned_at?: string;
}

export interface AssetCreate {
  name: string;
  asset_type: string;
  target: string;
  team?: string;
  tags?: string[];
}

export interface AlgorithmFinding {
  classical_algorithm: string;
  location?: string;
  recommended_pqc: string[];
  severity: string;
}

export interface ScanResult {
  id: string;
  asset_id: string;
  org_id: string;
  status: string;
  verdict?: Verdict;
  difficulty_score?: number;
  difficulty_label?: string;
  issues_blocked: number;
  issues_caution: number;
  algorithms_found: AlgorithmFinding[];
  started_at: string;
  completed_at?: string;
  error?: string;
  full_report?: Record<string, unknown>;
}

export interface TeamReadiness {
  team: string;
  total: number;
  go: number;
  caution: number;
  blocked: number;
  avg_score: number;
}

export interface OrgSnapshot {
  org_id: string;
  snapshot_at: string;
  total_assets: number;
  scanned_assets: number;
  go_count: number;
  caution_count: number;
  blocked_count: number;
  avg_difficulty_score: number;
  readiness_pct: number;
  teams: Record<string, TeamReadiness>;
}

export interface ComplianceReport {
  id: string;
  framework: Framework;
  generated_at: string;
  snapshot: OrgSnapshot;
}

// ── API calls ─────────────────────────────────────────────────────────────────

export const api = {
  getSnapshot:    () => apiFetch<OrgSnapshot>("/api/v1/reports/dashboard/snapshot"),
  listAssets:     () => apiFetch<Asset[]>("/api/v1/assets"),
  getAsset:       (id: string) => apiFetch<Asset>(`/api/v1/assets/${id}`),
  createAsset:    (body: AssetCreate) =>
    apiFetch<Asset>("/api/v1/assets", { method: "POST", body: JSON.stringify(body) }),
  triggerScan:    (assetId: string) =>
    apiFetch<ScanResult>(`/api/v1/assets/${assetId}/scan`, { method: "POST" }),
  listScans:      (assetId: string) =>
    apiFetch<ScanResult[]>(`/api/v1/assets/${assetId}/scans`),
  listReports:    () => apiFetch<ComplianceReport[]>("/api/v1/reports"),
  generateReport: (framework: Framework, config: Record<string, unknown>) =>
    apiFetch<ComplianceReport>("/api/v1/reports", {
      method: "POST",
      body: JSON.stringify({ framework, config }),
    }),
  getReportHtml:  (reportId: string) =>
    fetch(`${BASE}/api/v1/reports/${reportId}/html`).then(r => r.text()),
  // Investigation workspace
  getAssetDetail: (assetId: string) =>
    apiFetch<AssetDetailPayload>(`/api/v1/assets/${assetId}/detail`),
  acknowledgeIssue: (assetId: string, scanId: string, algorithm: string, note: string) =>
    apiFetch<{ ok: boolean }>(`/api/v1/assets/${assetId}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, algorithm, note }),
    }),
};

// ── Detail payload (assembled by investigation endpoint) ──────────────────────

export interface BenchmarkRow {
  metric: string;
  classical: string;
  pqc: string;
  delta: string;
  ratio: string;
  flag: "ok" | "warn" | "bad";
}

export interface CompatIssueDetail {
  severity: "BLOCKED" | "CAUTION" | "INFO" | "OK";
  category: string;
  title: string;
  detail: string;
  mitigation?: string;
}

export interface FindingDetail {
  algorithm: string;
  recommended_pqc: string;
  location?: string;
  standard: string;
  why_vulnerable: string;
  benchmark_rows: BenchmarkRow[];
  compat_issues: CompatIssueDetail[];
  config_diff: string;
  verdict: Verdict;
  score: number;
  score_label: string;
  acknowledged?: boolean;
  ack_note?: string;
}

export interface AssetDetailPayload {
  asset: Asset;
  latest_scan?: ScanResult;
  findings: FindingDetail[];
}
