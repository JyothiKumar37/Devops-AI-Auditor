// React Query hooks for the Phase 5 incident operations center.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  ContainmentExecution,
  ContainmentPlan,
  ContainmentPlanDetail,
  ContainmentPlanListResponse,
  CorrelateResponse,
  Incident,
  IncidentDetail,
  IncidentInvestigationSummary,
  IncidentListResponse,
  IncidentNote,
  IncidentRelationships,
  SecurityEventListResponse,
  SecurityIntegrationHealth,
} from "@/types/api";

export function useSecurityEvents(filters: {
  source_type?: string;
  severity?: string;
  event_status?: string;
  verified?: string;
} = {}) {
  return useQuery<SecurityEventListResponse>({
    queryKey: ["security-events", filters],
    queryFn: () => api.listSecurityEvents(filters),
    refetchInterval: 20_000,
  });
}

export function useSecurityHealth() {
  return useQuery<SecurityIntegrationHealth>({
    queryKey: ["security-health"],
    queryFn: api.getSecurityIntegrationHealth,
    refetchInterval: 30_000,
  });
}

export function useCorrelate() {
  const qc = useQueryClient();
  return useMutation<CorrelateResponse, Error, void>({
    mutationFn: () => api.correlateSecurity(),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["security-events"] });
    },
  });
}

export function useIncidents(filters: {
  incident_status?: string;
  severity?: string;
  unassigned?: string;
} = {}) {
  return useQuery<IncidentListResponse>({
    queryKey: ["incidents", filters],
    queryFn: () => api.listIncidents(filters),
    refetchInterval: 20_000,
  });
}

export function useIncident(id: string | null) {
  return useQuery<IncidentDetail>({
    queryKey: ["incident", id],
    queryFn: () => api.getIncident(id as string),
    enabled: Boolean(id),
  });
}

function useIncidentInvalidator(id: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["incident", id] });
    void qc.invalidateQueries({ queryKey: ["incidents"] });
  };
}

export function useUpdateIncident(id: string) {
  const invalidate = useIncidentInvalidator(id);
  return useMutation<
    Incident,
    Error,
    { owner?: string; root_cause_hypothesis?: string; resolution_summary?: string }
  >({
    mutationFn: (payload) => api.updateIncident(id, payload),
    onSuccess: invalidate,
  });
}

export function useTransitionIncident(id: string) {
  const invalidate = useIncidentInvalidator(id);
  return useMutation<Incident, Error, { status: string; actor?: string; note?: string }>({
    mutationFn: ({ status, actor, note }) =>
      api.transitionIncident(id, status, actor ?? "", note ?? ""),
    onSuccess: invalidate,
  });
}

export function useAddIncidentNote(id: string) {
  const invalidate = useIncidentInvalidator(id);
  return useMutation<IncidentNote, Error, { body: string; author?: string }>({
    mutationFn: ({ body, author }) => api.addIncidentNote(id, body, author ?? ""),
    onSuccess: invalidate,
  });
}

export function useIncidentRelationships(id: string | null) {
  return useQuery<IncidentRelationships>({
    queryKey: ["incident-graph", id],
    queryFn: () => api.getIncidentRelationships(id as string),
    enabled: Boolean(id),
  });
}

export function useRemediationPlans(incidentId: string | null) {
  return useQuery<ContainmentPlanListResponse>({
    queryKey: ["remediation-plans", incidentId],
    queryFn: () => api.listRemediationPlans(incidentId as string),
    enabled: Boolean(incidentId),
  });
}

export function useGeneratePlans(incidentId: string) {
  const qc = useQueryClient();
  return useMutation<ContainmentPlanListResponse, Error, void>({
    mutationFn: () => api.generateRemediationPlans(incidentId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["remediation-plans", incidentId] });
      void qc.invalidateQueries({ queryKey: ["incident", incidentId] });
    },
  });
}

function usePlanInvalidator(incidentId: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["remediation-plans", incidentId] });
    void qc.invalidateQueries({ queryKey: ["incident", incidentId] });
  };
}

export function usePlanDecision(incidentId: string) {
  const invalidate = usePlanInvalidator(incidentId);
  const approve = useMutation<ContainmentPlan, Error, { planId: string; approver: string; reason?: string }>({
    mutationFn: ({ planId, approver, reason }) =>
      api.approveRemediationPlan(planId, approver, reason ?? ""),
    onSuccess: invalidate,
  });
  const reject = useMutation<ContainmentPlan, Error, { planId: string; approver: string; reason?: string }>({
    mutationFn: ({ planId, approver, reason }) =>
      api.rejectRemediationPlan(planId, approver, reason ?? ""),
    onSuccess: invalidate,
  });
  const execute = useMutation<ContainmentExecution, Error, { planId: string; actor?: string }>({
    mutationFn: ({ planId, actor }) => api.executeRemediationPlan(planId, actor ?? ""),
    onSuccess: invalidate,
  });
  const verify = useMutation<ContainmentExecution, Error, { planId: string }>({
    mutationFn: ({ planId }) => api.verifyRemediationPlan(planId),
    onSuccess: invalidate,
  });
  return { approve, reject, execute, verify };
}

export function usePlanDetail(planId: string | null) {
  return useQuery<ContainmentPlanDetail>({
    queryKey: ["remediation-plan", planId],
    queryFn: () => api.getRemediationPlan(planId as string),
    enabled: Boolean(planId),
  });
}

export function useIncidentInvestigations(id: string | null) {
  return useQuery<IncidentInvestigationSummary[]>({
    queryKey: ["incident-investigations", id],
    queryFn: () => api.listIncidentInvestigations(id as string),
    enabled: Boolean(id),
  });
}

export function useInvestigateIncident(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (question: string) => api.investigateIncident(id, question),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident-investigations", id] }),
  });
}
