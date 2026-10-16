// React Query hooks for the Phase 4 cloud (AWS) runtime intelligence engine.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  CloudAccount,
  CloudAccountConnectRequest,
  CloudAccountListResponse,
  CloudAsset,
  CloudAssetListResponse,
  CloudAttackSurfaceResponse,
  CloudChangeListResponse,
  CloudDriftListResponse,
  CloudEksResponse,
  CloudFindingListResponse,
  CloudNetworkResponse,
  CloudPostureResponse,
  CloudSnapshot,
  ComplianceAssessment,
  ComplianceException,
  ComplianceExceptionCreateRequest,
  ComplianceExceptionListResponse,
  ComplianceFramework,
  InvestigationResult,
} from "@/types/api";

export function useCloudAccounts() {
  return useQuery<CloudAccountListResponse>({
    queryKey: ["cloud-accounts"],
    queryFn: api.listCloudAccounts,
    refetchInterval: 15_000,
  });
}

export function useCloudAccount(accountId: string | null) {
  return useQuery<CloudAccount>({
    queryKey: ["cloud-account", accountId],
    queryFn: () => api.getCloudAccount(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useConnectCloudAccount() {
  const qc = useQueryClient();
  return useMutation<CloudAccount, Error, CloudAccountConnectRequest>({
    mutationFn: (payload) => api.connectCloudAccount(payload),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["cloud-accounts"] }),
  });
}

export function useValidateCloudAccount() {
  const qc = useQueryClient();
  return useMutation<CloudAccount, Error, string>({
    mutationFn: (id) => api.validateCloudAccount(id),
    onSuccess: (account) => {
      void qc.invalidateQueries({ queryKey: ["cloud-accounts"] });
      void qc.invalidateQueries({ queryKey: ["cloud-account", account.id] });
    },
  });
}

export function useDeleteCloudAccount() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) => api.deleteCloudAccount(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["cloud-accounts"] }),
  });
}

export function useSyncCloudAccount(accountId: string) {
  const qc = useQueryClient();
  return useMutation<CloudSnapshot, Error, void>({
    mutationFn: () => api.syncCloudAccount(accountId),
    onSuccess: () => {
      for (const key of [
        ["cloud-accounts"],
        ["cloud-account", accountId],
        ["cloud-assets", accountId],
        ["cloud-findings", accountId],
        ["cloud-posture", accountId],
        ["cloud-network", accountId],
        ["cloud-attack-surface", accountId],
        ["cloud-changes", accountId],
      ]) {
        void qc.invalidateQueries({ queryKey: key });
      }
    },
  });
}

export function useCloudAssets(
  accountId: string | null,
  filters: { svc?: string; region?: string; exposure?: string } = {},
) {
  return useQuery<CloudAssetListResponse>({
    queryKey: ["cloud-assets", accountId, filters],
    queryFn: () => api.listCloudAssets(accountId as string, filters),
    enabled: Boolean(accountId),
  });
}

export function useCloudAsset(assetId: string | null) {
  return useQuery<CloudAsset>({
    queryKey: ["cloud-asset", assetId],
    queryFn: () => api.getCloudAsset(assetId as string),
    enabled: Boolean(assetId),
  });
}

export function useCloudFindings(
  accountId: string | null,
  filters: { svc?: string; severity?: string } = {},
) {
  return useQuery<CloudFindingListResponse>({
    queryKey: ["cloud-findings", accountId, filters],
    queryFn: () => api.listCloudFindings(accountId as string, filters),
    enabled: Boolean(accountId),
  });
}

export function useCloudPosture(accountId: string | null) {
  return useQuery<CloudPostureResponse>({
    queryKey: ["cloud-posture", accountId],
    queryFn: () => api.getCloudPosture(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useCloudNetwork(accountId: string | null) {
  return useQuery<CloudNetworkResponse>({
    queryKey: ["cloud-network", accountId],
    queryFn: () => api.getCloudNetwork(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useCloudAttackSurface(accountId: string | null) {
  return useQuery<CloudAttackSurfaceResponse>({
    queryKey: ["cloud-attack-surface", accountId],
    queryFn: () => api.getCloudAttackSurface(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useCloudDrift(accountId: string | null, status?: string) {
  return useQuery<CloudDriftListResponse>({
    queryKey: ["cloud-drift", accountId, status ?? null],
    queryFn: () => api.listCloudDrift(accountId as string, status),
    enabled: Boolean(accountId),
  });
}

export function useCorrelateDrift(accountId: string) {
  const qc = useQueryClient();
  return useMutation<CloudDriftListResponse, Error, string>({
    mutationFn: (scanId) => api.correlateCloudDrift(accountId, scanId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["cloud-drift", accountId] }),
  });
}

export function useComplianceFrameworks() {
  return useQuery<{ frameworks: ComplianceFramework[] }>({
    queryKey: ["compliance-frameworks"],
    queryFn: api.listComplianceFrameworks,
  });
}

export function useComplianceAssessment(accountId: string | null, framework: string | null) {
  return useQuery<ComplianceAssessment>({
    queryKey: ["compliance-assessment", accountId, framework],
    queryFn: () => api.assessCompliance(accountId as string, framework as string),
    enabled: Boolean(accountId && framework),
  });
}

export function useComplianceExceptions(accountId: string | null) {
  return useQuery<ComplianceExceptionListResponse>({
    queryKey: ["compliance-exceptions", accountId],
    queryFn: () => api.listComplianceExceptions(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useCreateComplianceException(accountId: string) {
  const qc = useQueryClient();
  return useMutation<ComplianceException, Error, ComplianceExceptionCreateRequest>({
    mutationFn: (payload) => api.createComplianceException(accountId, payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["compliance-exceptions", accountId] });
      void qc.invalidateQueries({ queryKey: ["compliance-assessment", accountId] });
    },
  });
}

export function useDeleteComplianceException(accountId: string) {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (exceptionId) => api.deleteComplianceException(exceptionId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["compliance-exceptions", accountId] });
      void qc.invalidateQueries({ queryKey: ["compliance-assessment", accountId] });
    },
  });
}

export function useCloudChanges(accountId: string | null, riskOnly = false) {
  return useQuery<CloudChangeListResponse>({
    queryKey: ["cloud-changes", accountId, riskOnly],
    queryFn: () => api.listCloudChanges(accountId as string, riskOnly),
    enabled: Boolean(accountId),
  });
}

export function useEksCorrelation(accountId: string | null) {
  return useQuery<CloudEksResponse>({
    queryKey: ["cloud-eks", accountId],
    queryFn: () => api.getEksCorrelation(accountId as string),
    enabled: Boolean(accountId),
  });
}

export function useInvestigateCloud(accountId: string) {
  return useMutation<InvestigationResult, Error, string>({
    mutationFn: (question) => api.investigateCloud(accountId, question),
  });
}
