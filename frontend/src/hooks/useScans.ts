import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  AuditReport,
  DiscoveryResponse,
  FindingFilters,
  FindingsResponse,
  RemediationProposal,
  RemediationResult,
  RepositoryFileContent,
  ScanFilesResponse,
  ScanListResponse,
  ScanSummary,
  StatsResponse,
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

export function useReport(scanId: string | null) {
  return useQuery<AuditReport>({
    queryKey: ["report", scanId],
    queryFn: () => api.getReport(scanId as string),
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
