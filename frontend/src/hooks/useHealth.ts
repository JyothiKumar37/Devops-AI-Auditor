import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { HealthResponse, LLMHealth, LLMSettings } from "@/types/api";

// Polls backend readiness so the dashboard reflects live dependency status.
export function useHealth() {
  return useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: api.getHealth,
    refetchInterval: 10_000,
  });
}

// On-demand LLM connectivity check. Disabled by default (it makes a live model
// call); `enabled` lets the Settings page trigger it explicitly.
export function useLLMHealth(enabled: boolean) {
  return useQuery<LLMHealth>({
    queryKey: ["llm-health"],
    queryFn: api.getLLMHealth,
    enabled,
    staleTime: 30_000,
    retry: false,
  });
}

// Current effective LLM config (env default + any runtime model override).
export function useLLMSettings() {
  return useQuery<LLMSettings>({ queryKey: ["llm-settings"], queryFn: api.getLLMSettings });
}

// Switch the active LLM model at runtime (empty string reverts to the env default).
export function useUpdateLLMModel() {
  const queryClient = useQueryClient();
  return useMutation<LLMSettings, Error, string>({
    mutationFn: (model: string) => api.updateLLMModel(model),
    onSuccess: (data) => {
      queryClient.setQueryData(["llm-settings"], data);
      // The connection check should be re-run against the new model.
      void queryClient.invalidateQueries({ queryKey: ["llm-health"] });
    },
  });
}
