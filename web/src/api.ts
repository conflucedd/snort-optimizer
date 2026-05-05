import type {
  AlertList,
  AnalysisStatus,
  AnalysisStrategy,
  CaptureSummary,
  FileItem,
  Overview,
  Recommendation,
  RuleList,
  Settings,
  SettingsResponse,
  SystemStatus
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  settings: () => request<SettingsResponse>("/api/settings"),
  saveSettings: (settings: Settings) =>
    request<SettingsResponse>("/api/settings", { method: "PUT", body: JSON.stringify(settings) }),
  overview: () => request<Overview>("/api/overview"),
  startSnort: () => request<Record<string, unknown>>("/api/snort/start", { method: "POST", body: "{}" }),
  stopSnort: () => request<Record<string, unknown>>("/api/snort/stop", { method: "POST", body: "{}" }),
  restartSnort: () => request<Record<string, unknown>>("/api/snort/restart", { method: "POST", body: "{}" }),
  resetSnort: () => request<Record<string, unknown>>("/api/snort/reset", { method: "POST", body: "{}" }),
  perfTests: () => request<{ items: unknown[] }>("/api/perf-tests"),
  startPerfTest: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/perf-tests", { method: "POST", body: JSON.stringify(payload) }),
  alerts: (params: URLSearchParams) => request<AlertList>(`/api/alerts?${params.toString()}`),
  analysisStatus: () => request<AnalysisStatus>("/api/analysis/status"),
  analysisStrategies: () => request<{ items: AnalysisStrategy[] }>("/api/analysis/strategies"),
  startAnalysis: (payload: Record<string, unknown>) =>
    request<AnalysisStatus>("/api/analysis/start", { method: "POST", body: JSON.stringify(payload) }),
  cancelAnalysis: () => request<Record<string, unknown>>("/api/analysis/cancel", { method: "POST", body: "{}" }),
  applyAnalysis: (runId: number) =>
    request<Record<string, unknown>>("/api/analysis/apply", {
      method: "POST",
      body: JSON.stringify({ run_id: runId })
    }),
  rules: (params: URLSearchParams) => request<RuleList>(`/api/config/rules?${params.toString()}`),
  toggleRule: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/config/rules/toggle", { method: "POST", body: JSON.stringify(payload) }),
  recommendations: (limit = 80) =>
    request<{ items: Recommendation[] }>(`/api/config/recommendations?limit=${limit}`),
  system: () => request<SystemStatus>("/api/system/status"),
  setOffload: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/system/offload", { method: "POST", body: JSON.stringify(payload) }),
  setAffinity: (cpus: string) =>
    request<Record<string, unknown>>("/api/system/affinity", { method: "POST", body: JSON.stringify({ cpus }) }),
  pcapFiles: () => request<{ files: FileItem[] }>("/api/files/pcaps"),
  startCapture: (payload: Record<string, unknown>) =>
    request<CaptureSummary>("/api/capture/start", { method: "POST", body: JSON.stringify(payload) }),
  captureStatus: () => request<{ items: CaptureSummary[] }>("/api/capture/status")
};

export function fmtNumber(value: number | undefined, digits = 0): string {
  if (value === undefined || Number.isNaN(value)) return "0";
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits: digits }).format(value);
}

export function pct(value: number | undefined, digits = 2): string {
  if (value === undefined || Number.isNaN(value)) return "0%";
  return `${(value * 100).toFixed(digits)}%`;
}

export function compactBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}
