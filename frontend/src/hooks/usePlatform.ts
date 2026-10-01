// React Query hooks for the Phase 2 DevSecOps platform: SCM integrations,
// pull requests, policies, notification channels and the audit log.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type {
  AuditLogListResponse,
  Integration,
  IntegrationConnectRequest,
  IntegrationListResponse,
  NotificationChannel,
  NotificationChannelCreateRequest,
  NotificationChannelListResponse,
  NotificationChannelUpdateRequest,
  NotificationDelivery,
  Policy,
  PolicyCreateRequest,
  PolicyListResponse,
  PolicyUpdateRequest,
  PullRequestDetail,
  PullRequestListResponse,
  RemoteRepositoryListResponse,
  SCMRepository,
  SCMRepositoryListResponse,
} from "@/types/api";

// ---- Integrations ----

export function useIntegrations() {
  return useQuery<IntegrationListResponse>({
    queryKey: ["integrations"],
    queryFn: api.listIntegrations,
  });
}

export function useRepositories() {
  return useQuery<SCMRepositoryListResponse>({
    queryKey: ["repositories"],
    queryFn: api.listRepositories,
  });
}

export function useRemoteRepositories(integrationId: string | null) {
  return useQuery<RemoteRepositoryListResponse>({
    queryKey: ["remote-repositories", integrationId],
    queryFn: () => api.listRemoteRepositories(integrationId as string),
    enabled: Boolean(integrationId),
  });
}

export function useConnectIntegration() {
  const qc = useQueryClient();
  return useMutation<Integration, Error, IntegrationConnectRequest>({
    mutationFn: (payload) => api.connectIntegration(payload),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["integrations"] });
      void qc.invalidateQueries({ queryKey: ["audit-logs"] });
    },
  });
}

export function useDeleteIntegration() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) => api.deleteIntegration(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["integrations"] });
      void qc.invalidateQueries({ queryKey: ["repositories"] });
      void qc.invalidateQueries({ queryKey: ["audit-logs"] });
    },
  });
}

export function useImportRepository() {
  const qc = useQueryClient();
  return useMutation<SCMRepository, Error, { integrationId: string; owner: string; name: string }>({
    mutationFn: ({ integrationId, owner, name }) =>
      api.importRepository(integrationId, owner, name),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["repositories"] }),
  });
}

// ---- Pull requests ----

export function usePullRequests(repo?: string) {
  return useQuery<PullRequestListResponse>({
    queryKey: ["pull-requests", repo ?? null],
    queryFn: () => api.listPullRequests(repo),
    refetchInterval: 15_000,
  });
}

export function usePullRequest(id: string | null) {
  return useQuery<PullRequestDetail>({
    queryKey: ["pull-request", id],
    queryFn: () => api.getPullRequest(id as string),
    enabled: Boolean(id),
  });
}

// ---- Policies ----

export function usePolicies() {
  return useQuery<PolicyListResponse>({
    queryKey: ["policies"],
    queryFn: api.listPolicies,
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation<Policy, Error, PolicyCreateRequest>({
    mutationFn: (payload) => api.createPolicy(payload),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation<Policy, Error, { id: string; payload: PolicyUpdateRequest }>({
    mutationFn: ({ id, payload }) => api.updatePolicy(id, payload),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useDeletePolicy() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) => api.deletePolicy(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useAssignPolicy() {
  const qc = useQueryClient();
  return useMutation<
    Policy,
    Error,
    { id: string; scope_type: "repo" | "global"; scope_value?: string }
  >({
    mutationFn: ({ id, scope_type, scope_value }) =>
      api.assignPolicy(id, { scope_type, scope_value }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["policies"] });
      void qc.invalidateQueries({ queryKey: ["repositories"] });
    },
  });
}

// ---- Notifications ----

export function useNotificationChannels() {
  return useQuery<NotificationChannelListResponse>({
    queryKey: ["notification-channels"],
    queryFn: api.listNotificationChannels,
  });
}

export function useNotificationDeliveries() {
  return useQuery<NotificationDelivery[]>({
    queryKey: ["notification-deliveries"],
    queryFn: api.listNotificationDeliveries,
    refetchInterval: 20_000,
  });
}

export function useCreateNotificationChannel() {
  const qc = useQueryClient();
  return useMutation<NotificationChannel, Error, NotificationChannelCreateRequest>({
    mutationFn: (payload) => api.createNotificationChannel(payload),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-channels"] }),
  });
}

export function useUpdateNotificationChannel() {
  const qc = useQueryClient();
  return useMutation<
    NotificationChannel,
    Error,
    { id: string; payload: NotificationChannelUpdateRequest }
  >({
    mutationFn: ({ id, payload }) => api.updateNotificationChannel(id, payload),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-channels"] }),
  });
}

export function useDeleteNotificationChannel() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) => api.deleteNotificationChannel(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-channels"] }),
  });
}

export function useTestNotificationChannel() {
  const qc = useQueryClient();
  return useMutation<NotificationDelivery, Error, string>({
    mutationFn: (id) => api.testNotificationChannel(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["notification-deliveries"] }),
  });
}

// ---- Audit log ----

export function useAuditLogs(params: { action?: string; resource_type?: string } = {}) {
  return useQuery<AuditLogListResponse>({
    queryKey: ["audit-logs", params],
    queryFn: () => api.listAuditLogs(params),
    refetchInterval: 20_000,
  });
}
