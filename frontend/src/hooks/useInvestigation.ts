// React Query hooks for the Phase 3 AI investigation engine.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  AIReviewResponse,
  InvestigationDetail,
  InvestigationListResponse,
  InvestigationResult,
  RemediationPlan,
} from "@/types/api";

export function useInvestigateScan(scanId: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationResult, Error, string>({
    mutationFn: (question) => api.investigateScan(scanId, question),
    onSuccess: () =>
      void qc.invalidateQueries({ queryKey: ["investigations", scanId] }),
  });
}

export function useInvestigateFinding(scanId: string, findingId: string) {
  const qc = useQueryClient();
  return useMutation<InvestigationResult, Error, string>({
    mutationFn: (question) => api.investigateFinding(scanId, findingId, question),
    onSuccess: () =>
      void qc.invalidateQueries({ queryKey: ["investigations", scanId] }),
  });
}

export function useInvestigations(scanId: string) {
  return useQuery<InvestigationListResponse>({
    queryKey: ["investigations", scanId],
    queryFn: () => api.listInvestigations({ scan_id: scanId }),
  });
}

export function useInvestigation(id: string | null) {
  return useQuery<InvestigationDetail>({
    queryKey: ["investigation", id],
    queryFn: () => api.getInvestigation(id as string),
    enabled: Boolean(id),
  });
}

export function useRemediationPlan(scanId: string) {
  return useMutation<RemediationPlan, Error, { finding_ids?: string[]; max_targets?: number }>({
    mutationFn: (payload) => api.remediationPlan(scanId, payload),
  });
}

export function useSecurityReview(scanId: string) {
  return useMutation<AIReviewResponse, Error, void>({
    mutationFn: () => api.securityReview(scanId),
  });
}
