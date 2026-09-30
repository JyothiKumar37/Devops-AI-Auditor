import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

import { api } from "@/lib/api";
import type {
  AuditReport,
  DiscoveryResponse,
  FindingFilters,
  FindingsResponse,
  GitScanRequest,
  RemediationProposal,
  RemediationResult,
  ReportModel,
  ContainerSecurityResponse,
  DependenciesResponse,
  KubernetesScoreResponse,
  PostureResponse,
  RemediationHistoryResponse,
  RepositoryFileContent,
  RiskSummaryResponse,
  ScanDiffResponse,
  ScanFilesResponse,
  ScanListResponse,
  ScanSummary,
  StatsResponse,
  SuppressionRead,
  SuppressRequest,
  TrendsResponse,
} from "@/types/api";

export function useStats() {
  return useQuery<StatsResponse>({
    queryKey: ["stats"],
    queryFn: api.getStats,
    refetchInterval: 10_000,
  });
}

export function useScans() {
  return useQuery<ScanListResponse>({
    queryKey: ["scans"],
    queryFn: api.listScans,
    refetchInterval: 8_000,
  });
}

export function useScan(scanId: string | null) {
  return useQuery<ScanSummary>({
    queryKey: ["scan", scanId],
    queryFn: () => api.getScan(scanId as string),
    enabled: Boolean(scanId),
    refetchInterval: (query) =>
      query.state.data && ["pending", "running"].includes(query.state.data.status) ? 2000 : false,
  });
}

export function useDiscovery(scanId: string | null) {
  return useQuery<DiscoveryResponse>({
    queryKey: ["discovery", scanId],
    queryFn: () => api.getDiscovery(scanId as string),
    enabled: Boolean(scanId),
  });
}

/**
 * Live scan status via server-sent events. While a scan is not terminal this
 * opens an EventSource, pushes each status update straight into the scan query
 * cache, and - the moment the scan completes or fails - invalidates the derived
 * queries so results appear immediately (instead of waiting for the next poll).
 */
export function useScanStream(scanId: string | null, status?: string) {
  const queryClient = useQueryClient();
  const done = status === "completed" || status === "failed";
  useEffect(() => {
    if (!scanId || done) return;
    const source = new EventSource(api.scanStreamUrl(scanId));
    source.onmessage = (event) => {
      let summary: ScanSummary;
      try {
        summary = JSON.parse(event.data) as ScanSummary;
      } catch {
        return; // ignore malformed / non-data frames
      }
      queryClient.setQueryData(["scan", scanId], summary);
      if (summary.status === "completed" || summary.status === "failed") {
        for (const key of [
          ["findings", scanId],
          ["report", scanId],
          ["discovery", scanId],
          ["files", scanId],
          ["diff", scanId],
          ["stats"],
        ]) {
          void queryClient.invalidateQueries({ queryKey: key });
        }
        source.close();
      }
    };
    source.onerror = () => source.close(); // fall back to polling
    return () => source.close();
  }, [scanId, done, queryClient]);
}

export function useScanDiff(scanId: string | null, base?: string) {
  return useQuery<ScanDiffResponse>({
    queryKey: ["diff", scanId, base ?? null],
    queryFn: () => api.getScanDiff(scanId as string, base),
    enabled: Boolean(scanId),
  });
}

export function useReport(scanId: string | null) {
  return useQuery<AuditReport>({
    queryKey: ["report", scanId],
    queryFn: () => api.getReport(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useReportModel(scanId: string | null) {
  return useQuery<ReportModel>({
    queryKey: ["report-model", scanId],
    queryFn: () => api.getReportModel(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useScanFiles(scanId: string | null) {
  return useQuery<ScanFilesResponse>({
    queryKey: ["files", scanId],
    queryFn: () => api.getScanFiles(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useFindings(scanId: string | null, filters: FindingFilters) {
  return useQuery<FindingsResponse>({
    queryKey: ["findings", scanId, filters],
    queryFn: () => api.getFindings(scanId as string, filters),
    enabled: Boolean(scanId),
  });
}

export function useRiskSummary(scanId: string | null) {
  return useQuery<RiskSummaryResponse>({
    queryKey: ["risk-summary", scanId],
    queryFn: () => api.getRiskSummary(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function usePosture(scanId: string | null) {
  return useQuery<PostureResponse>({
    queryKey: ["posture", scanId],
    queryFn: () => api.getPosture(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useTrends(scanId: string | null) {
  return useQuery<TrendsResponse>({
    queryKey: ["trends", scanId],
    queryFn: () => api.getTrends(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useKubernetesScore(scanId: string | null) {
  return useQuery<KubernetesScoreResponse>({
    queryKey: ["kubernetes-score", scanId],
    queryFn: () => api.getKubernetesScore(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useContainerSecurity(scanId: string | null) {
  return useQuery<ContainerSecurityResponse>({
    queryKey: ["container-security", scanId],
    queryFn: () => api.getContainerSecurity(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useDependencies(scanId: string | null) {
  return useQuery<DependenciesResponse>({
    queryKey: ["dependencies", scanId],
    queryFn: () => api.getDependencies(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useFileContent(scanId: string | null, fileId: string | null) {
  return useQuery<RepositoryFileContent>({
    queryKey: ["file-content", scanId, fileId],
    queryFn: () => api.getFileContent(scanId as string, fileId as string),
    enabled: Boolean(scanId && fileId),
  });
}

/** Generate a fix proposal for a finding. This never mutates anything. */
export function useGenerateRemediation(scanId: string, findingId: string) {
  return useMutation<RemediationProposal, Error, void>({
    mutationFn: () => api.generateRemediation(scanId, findingId),
  });
}

/**
 * Apply an approved fix to the stored copy, then verify by re-scan.
 *
 * On success the affected caches are refreshed so the (patched) file content,
 * findings list, report and dashboard reflect the change.
 */
export function useApplyRemediation(scanId: string, findingId: string) {
  const queryClient = useQueryClient();
  return useMutation<RemediationResult, Error, void>({
    mutationFn: () => api.applyRemediation(scanId, findingId),
    onSuccess: (result) => {
      if (!result.applied) return;
      void queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["file-content", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["files", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["report", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["posture", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["remediation-history", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}

export function useRemediationHistory(scanId: string | null) {
  return useQuery<RemediationHistoryResponse>({
    queryKey: ["remediation-history", scanId],
    queryFn: () => api.getRemediationHistory(scanId as string),
    enabled: Boolean(scanId),
  });
}

/** Suppress (baseline) a finding, then refresh findings/report/stats. */
export function useSuppressFinding(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation<SuppressionRead, Error, { findingId: string } & SuppressRequest>({
    mutationFn: ({ findingId, ...payload }) =>
      api.suppressFinding(scanId, findingId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["suppressions", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["report", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}

/** Remove a finding's baseline, then refresh findings/report/stats. */
export function useUnsuppressFinding(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (findingId: string) => api.unsuppressFinding(scanId, findingId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["suppressions", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["report", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}

export function useUploadScan(onProgress?: (fraction: number) => void) {
  const queryClient = useQueryClient();
  return useMutation<ScanSummary, Error, File>({
    mutationFn: (file: File) => api.uploadScan(file, onProgress),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}

/** Clone and ingest a repository directly from a git URL. */
export function useIngestGitScan() {
  const queryClient = useQueryClient();
  return useMutation<ScanSummary, Error, GitScanRequest>({
    mutationFn: (payload: GitScanRequest) => api.ingestGit(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
      void queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}
