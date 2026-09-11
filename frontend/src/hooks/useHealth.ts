import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { HealthResponse } from "@/types/api";

// Polls backend readiness so the dashboard reflects live dependency status.
export function useHealth() {
  return useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: api.getHealth,
    refetchInterval: 10_000,
  });
}
