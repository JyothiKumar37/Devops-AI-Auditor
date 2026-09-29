// Minimal typed API client. Requests are made to `/api/...`, which the Vite dev
// server (and the production reverse proxy) forward to the backend. This keeps
// the browser on a single origin and avoids CORS during development.

import type {
  ApiErrorBody,
  AuditReport,
  DiscoveryResponse,
  FindingFilters,
  FindingsResponse,
  GitScanRequest,
  AiAnswer,
  AiExplanation,
  AiFixSuggestion,
  AiPriorities,
  AiScanSummary,
  AiTriage,
  ChatHistory,
  HealthResponse,
  LLMHealth,
  LLMSettings,
  RemediationProposal,
  RemediationResult,
  ReportModel,
  RepositoryFileContent,
  ScanDiffResponse,
  ScanFilesResponse,
  ScanListResponse,
  ScanSummary,
  StatsResponse,
  SuppressionRead,
  SuppressRequest,
} from "@/types/api";

const API_V1 = "/api/v1";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
  });

  // Readiness returns 503 with a valid body when a dependency is down; that is
  // a meaningful state for the dashboard, not a transport failure.
  const isReadiness = path.endsWith("/health/ready");
  if (!response.ok && !(isReadiness && response.status === 503)) {
    throw new ApiError(`Request to ${path} failed`, response.status);
  }

  return (await response.json()) as T;
}

async function post<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as ApiErrorBody | null;
    throw new ApiError(
      body?.error?.message ?? `Request to ${path} failed`,
      response.status,
      body?.error?.code,
    );
  }
  return (await response.json()) as T;
}

async function sendJson<T>(method: "POST" | "PUT", path: string, payload: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as ApiErrorBody | null;
    throw new ApiError(
      body?.error?.message ?? `Request to ${path} failed`,
      response.status,
      body?.error?.code,
    );
  }
  return (await response.json()) as T;
}

function postJson<T>(path: string, payload: unknown): Promise<T> {
  return sendJson<T>("POST", path, payload);
}

function putJson<T>(path: string, payload: unknown): Promise<T> {
  return sendJson<T>("PUT", path, payload);
}

async function del(path: string): Promise<void> {
  const response = await fetch(path, {
    method: "DELETE",
    headers: { Accept: "application/json" },
  });
  if (!response.ok && response.status !== 204) {
    const body = (await response.json().catch(() => null)) as ApiErrorBody | null;
    throw new ApiError(
      body?.error?.message ?? `Request to ${path} failed`,
      response.status,
      body?.error?.code,
    );
  }
}

/**
 * Upload a repository ZIP with progress reporting.
 *
 * Uses XMLHttpRequest because the fetch API cannot report upload progress.
 */
export function uploadScan(
  file: File,
  onProgress?: (fraction: number) => void,
): Promise<ScanSummary> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("file", file);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_V1}/scans/upload`);
    xhr.responseType = "json";

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && onProgress) {
        onProgress(event.loaded / event.total);
      }
    };

    xhr.onload = () => {
      const body = xhr.response as ScanSummary | ApiErrorBody | null;
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as ScanSummary);
      } else {
        const err = body as ApiErrorBody | null;
        reject(
          new ApiError(
            err?.error?.message ?? "Upload failed",
            xhr.status,
            err?.error?.code,
          ),
        );
      }
    };

    xhr.onerror = () => reject(new ApiError("Network error during upload", 0));
    xhr.send(form);
  });
}

function query(params: Record<string, string | undefined>): string {
  const entries = Object.entries(params).filter(([, v]) => v);
  if (entries.length === 0) return "";
  return "?" + entries.map(([k, v]) => `${k}=${encodeURIComponent(v as string)}`).join("&");
}

export const api = {
  /** Readiness health, including per-dependency status, version and environment. */
  getHealth: () => request<HealthResponse>(`${API_V1}/health/ready`),
  /** On-demand LLM connectivity check (provider reachable + model valid). */
  getLLMHealth: () => request<LLMHealth>(`${API_V1}/health/llm`),
  /** Current effective LLM configuration (env default + any runtime override). */
  getLLMSettings: () => request<LLMSettings>(`${API_V1}/settings/llm`),
  /** Switch the LLM model at runtime; empty string reverts to the env default. */
  updateLLMModel: (model: string) =>
    putJson<LLMSettings>(`${API_V1}/settings/llm`, { model }),

  // ---- interactive AI assistance ----
  /** AI explanation of a finding (impact + fix). */
  explainFinding: (scanId: string, findingId: string) =>
    post<AiExplanation>(`${API_V1}/scans/${scanId}/findings/${findingId}/explain`),
  /** AI-proposed fix for a finding (review-only). */
  suggestFix: (scanId: string, findingId: string) =>
    post<AiFixSuggestion>(`${API_V1}/scans/${scanId}/findings/${findingId}/fix-suggestion`),
  /** AI false-positive triage of a finding. */
  triageFinding: (scanId: string, findingId: string) =>
    post<AiTriage>(`${API_V1}/scans/${scanId}/findings/${findingId}/triage`),
  /** AI executive summary of a scan. */
  getAiSummary: (scanId: string) =>
    request<AiScanSummary>(`${API_V1}/scans/${scanId}/ai-summary`),
  /** AI context-aware risk ranking of a scan's findings. */
  getPriorities: (scanId: string) =>
    request<AiPriorities>(`${API_V1}/scans/${scanId}/priorities`),
  /** Ask a question grounded in a scan's findings. */
  askScan: (scanId: string, question: string) =>
    postJson<AiAnswer>(`${API_V1}/scans/${scanId}/ask`, { question }),
  /** Get the scan's persistent AI chat history. */
  getChat: (scanId: string) => request<ChatHistory>(`${API_V1}/scans/${scanId}/chat`),
  /** Post a question to the scan's persistent chat; returns the updated history. */
  postChat: (scanId: string, question: string) =>
    postJson<ChatHistory>(`${API_V1}/scans/${scanId}/chat`, { question }),
  /** Clear the scan's chat history. */
  clearChat: (scanId: string) => del(`${API_V1}/scans/${scanId}/chat`),
  /** Aggregate dashboard metrics. */
  getStats: () => request<StatsResponse>(`${API_V1}/stats`),
  /** List scans, most recent first. */
  listScans: () => request<ScanListResponse>(`${API_V1}/scans`),
  /** Clone and ingest a repository directly from a git URL. */
  ingestGit: (payload: GitScanRequest) =>
    postJson<ScanSummary>(`${API_V1}/scans/git`, payload),
  /** Fetch a single scan's summary. */
  getScan: (id: string) => request<ScanSummary>(`${API_V1}/scans/${id}`),
  /** Fetch the grouped discovery output for a scan. */
  getDiscovery: (id: string) => request<DiscoveryResponse>(`${API_V1}/scans/${id}/discovery`),
  /** Diff a scan's findings against a previous (or explicit) base scan. */
  getScanDiff: (id: string, base?: string) =>
    request<ScanDiffResponse>(`${API_V1}/scans/${id}/diff${query({ base })}`),
  /** URL of the server-sent-events stream of a scan's status. */
  scanStreamUrl: (id: string) => `${API_V1}/scans/${id}/stream`,
  /** List repository files for a scan. */
  getScanFiles: (id: string) =>
    request<ScanFilesResponse>(`${API_V1}/scans/${id}/files?limit=2000`),
  /** Fetch a repository file's content for the code viewer. */
  getFileContent: (scanId: string, fileId: string) =>
    request<RepositoryFileContent>(`${API_V1}/scans/${scanId}/files/${fileId}/content`),
  /** Fetch findings for a scan with optional filters. */
  getFindings: (id: string, filters: FindingFilters = {}) =>
    request<FindingsResponse>(`${API_V1}/scans/${id}/findings${query({ ...filters, limit: "2000" })}`),
  /** Fetch the AI reasoning report (production readiness, groups, recommendations). */
  getReport: (id: string) => request<AuditReport>(`${API_V1}/scans/${id}/report`),
  /** URL that exports the full audit report in the given format (json|html|pdf). */
  reportExportUrl: (
    id: string,
    format: "json" | "html" | "pdf" | "sarif",
    opts: { download?: boolean; ai?: boolean } = {},
  ) =>
    `${API_V1}/scans/${id}/report/export?format=${format}` +
    `&download=${opts.download ?? true}&ai=${opts.ai ?? false}`,
  /** Fetch the full structured report model for in-app viewing. */
  getReportModel: (id: string) =>
    request<ReportModel>(`${API_V1}/scans/${id}/report/export?format=json&download=false`),
  /** Generate a proposed fix for a finding (no changes are made). */
  generateRemediation: (scanId: string, findingId: string) =>
    post<RemediationProposal>(`${API_V1}/scans/${scanId}/findings/${findingId}/remediation`),
  /** Apply an approved fix to the stored copy and verify resolution. */
  applyRemediation: (scanId: string, findingId: string) =>
    post<RemediationResult>(
      `${API_V1}/scans/${scanId}/findings/${findingId}/remediation/apply`,
    ),
  /** Suppress (baseline) a finding for its repository. */
  suppressFinding: (scanId: string, findingId: string, payload: SuppressRequest) =>
    postJson<SuppressionRead>(
      `${API_V1}/scans/${scanId}/findings/${findingId}/suppress`,
      payload,
    ),
  /** Remove a finding's baseline (un-suppress). */
  unsuppressFinding: (scanId: string, findingId: string) =>
    del(`${API_V1}/scans/${scanId}/findings/${findingId}/suppress`),
  uploadScan,
};
