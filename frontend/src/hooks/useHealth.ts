import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { HealthResponse, LLMHealth } from "@/types/api";

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
