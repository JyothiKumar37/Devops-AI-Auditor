import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  AiAnswer,
  AiExplanation,
  AiFixSuggestion,
  AiPriorities,
  AiScanSummary,
  AiTriage,
  ChatHistory,
} from "@/types/api";

// All AI assistance is on-demand (a live model call), so each is a mutation
// triggered by an explicit user action rather than an auto-fetched query.

export function useExplainFinding(scanId: string, findingId: string) {
  return useMutation<AiExplanation, Error>({
    mutationFn: () => api.explainFinding(scanId, findingId),
  });
}

export function useSuggestFix(scanId: string, findingId: string) {
  return useMutation<AiFixSuggestion, Error>({
    mutationFn: () => api.suggestFix(scanId, findingId),
  });
}

export function useTriageFinding(scanId: string, findingId: string) {
  return useMutation<AiTriage, Error>({
    mutationFn: () => api.triageFinding(scanId, findingId),
  });
}

export function useAiSummary(scanId: string) {
  return useMutation<AiScanSummary, Error>({
    mutationFn: () => api.getAiSummary(scanId),
  });
}

export function usePriorities(scanId: string) {
  return useMutation<AiPriorities, Error>({
    mutationFn: () => api.getPriorities(scanId),
  });
}

export function useAskScan(scanId: string) {
  return useMutation<AiAnswer, Error, string>({
    mutationFn: (question: string) => api.askScan(scanId, question),
  });
}

// Persistent per-scan chat: history query + send/clear mutations.
export function useChat(scanId: string | null) {
  return useQuery<ChatHistory>({
    queryKey: ["chat", scanId],
    queryFn: () => api.getChat(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useSendChat(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation<ChatHistory, Error, string>({
    mutationFn: (question: string) => api.postChat(scanId, question),
    onSuccess: (data) => queryClient.setQueryData(["chat", scanId], data),
  });
}

export function useClearChat(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation<void, Error, void>({
    mutationFn: () => api.clearChat(scanId),
    onSuccess: () =>
      queryClient.setQueryData(["chat", scanId], { scan_id: scanId, messages: [] }),
  });
}
