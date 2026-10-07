// Types mirroring the backend API schemas (models/schemas.py). Kept in sync
// manually in the foundation; a generated client can replace this later.

export type HealthState = "healthy" | "degraded" | "unhealthy";

export interface ComponentHealth {
  name: string;
  state: HealthState;
  detail: string | null;
}

export interface HealthResponse {
  status: HealthState;
  version: string;
  environment: string;
  components: ComponentHealth[];
}

export interface ServiceInfo {
  name: string;
  version: string;
  environment: string;
  docs_url: string;
}

// ---- Scans / discovery ----

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type SourceType = "zip" | "local" | "git";

export interface ScanSummary {
  id: string;
  repository_name: string;
  source_type: SourceType;
  status: ScanStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  file_count: number;
  readiness?: number | null;
}

export interface ScanListResponse {
  items: ScanSummary[];
  total: number;
}

export interface GitScanRequest {
  repository_url: string;
  ref?: string | null;
}

export interface LLMHealth {
  provider: string;
  model: string;
  configured: boolean;
  ok: boolean;
  detail: string;
  latency_ms: number | null;
}

export interface LLMSettings {
  provider: string;
  model: string;
  env_model: string;
  overridden: boolean;
  configured: boolean;
}

export interface AiExplanation {
  explanation: string;
}

export interface AiFixSuggestion {
  file_path: string | null;
  before: string;
  after: string;
  diff: string;
  explanation: string;
  changed: boolean;
}

export interface AiTriage {
  likely_false_positive: boolean;
  confidence: string;
  reason: string;
}

export interface AiScanSummary {
  summary: string;
}

export interface AiPriorityItem {
  finding_id: string;
  rule_id: string;
  severity: string;
  title: string;
  file: string | null;
  rationale: string;
}

export interface AiPriorities {
  items: AiPriorityItem[];
}

export interface AiAnswer {
  answer: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
}

export interface ChatHistory {
  scan_id: string;
  messages: ChatMessage[];
}

export interface ScanDiffFinding {
  rule_id: string;
  scanner: string;
  category: string;
  severity: string;
  confidence: string;
  title: string;
  file: string | null;
  line: number | null;
  recommendation: string;
}

export interface ScanDiffSummary {
  new: number;
  fixed: number;
  unchanged: number;
  base_total: number;
  head_total: number;
}

export interface ScanDiffResponse {
  base_scan_id: string | null;
  head_scan_id: string;
  repository_name: string;
  base_created_at: string | null;
  head_created_at: string;
  base_readiness: number | null;
  head_readiness: number;
  readiness_delta: number | null;
  summary: ScanDiffSummary;
  new_severity_counts: Record<string, number>;
  fixed_severity_counts: Record<string, number>;
  new_findings: ScanDiffFinding[];
  fixed_findings: ScanDiffFinding[];
  unchanged_findings: ScanDiffFinding[];
}

export interface RepositoryFile {
  id: string;
  scan_id: string;
  path: string;
  file_type: string;
  size: number;
  checksum: string;
}

// The ten discovery categories, matching the backend FileCategory enum.
export type DiscoveryCategory =
  | "docker"
  | "compose"
  | "kubernetes"
  | "terraform"
  | "cicd"
  | "helm"
  | "ansible"
  | "shell"
  | "configuration"
  | "other";

export interface DiscoveryResponse {
  scan_id: string;
  total: number;
  counts: Record<DiscoveryCategory, number>;
  categories: Record<DiscoveryCategory, RepositoryFile[]>;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details: Record<string, unknown>;
  };
}

// ---- AI report / production readiness ----

export interface CategoryScore {
  category: string;
  score: number;
  weight: number;
  applicable: boolean;
  findings: number;
  counts: Record<string, number>;
  explanation: string;
}

export interface ProductionReadiness {
  ready: boolean;
  score: number;
  summary: string;
  confidence: string;
  category_scores: CategoryScore[];
  blockers: string[];
  top_risks: string[];
  next_actions: string[];
  explanation: string;
}

export interface AuditReport {
  scan_id: string;
  summary: string;
  llm_used: boolean;
  understanding: {
    summary: string;
    technologies: string[];
    components: string[];
    risk_areas: string[];
    confidence: string;
  };
  severity_counts: Record<string, number>;
  total_findings: number;
  reviewed_false_positives: number;
  production_readiness: ProductionReadiness;
  recommendations: string[];
  key_findings: AIFinding[];
  finding_groups: FindingGroup[];
}

export interface AIFinding {
  title: string;
  category: string;
  severity: string;
  confidence: string;
  file: string | null;
  line: number | null;
  evidence: string;
  source: string;
  reasoning: string;
  recommendation: string;
  source_finding_ids: string[];
}

export interface FindingGroup {
  root_cause: string;
  category: string;
  severity: string;
  confidence: string;
  affected_files: string[];
  evidence: string[];
  impact: string;
  recommendation: string;
  member_finding_ids: string[];
}


// ---- Findings ----

export type ConfidenceLevel = "low" | "medium" | "high";

export type SuppressionReason = "false_positive" | "accepted_risk" | "wont_fix";

export type RiskPriority = "immediate" | "high" | "normal" | "low";

export interface RiskFactors {
  severity_base: number;
  exploitability: number;
  exposure: number;
  production_impact: number;
  recurrence: number;
  confidence_factor: number;
  asset_criticality: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  file_id: string | null;
  category: string;
  severity: string;
  confidence: ConfidenceLevel;
  title: string;
  description: string;
  evidence: string | null;
  line_number: number | null;
  recommendation: string;
  rule_id: string;
  scanner: string;
  suppressed: boolean;
  suppression_reason: SuppressionReason | null;
  suppression_note: string | null;
  // Deterministic risk prioritisation (annotated by the backend at read time).
  risk_score: number;
  risk_priority: RiskPriority;
  risk_explanation: string;
  risk_signals: string[];
  risk_factors: RiskFactors | null;
}

export interface RiskSummaryItem {
  finding_id: string;
  rule_id: string;
  scanner: string;
  category: string;
  severity: string;
  confidence: string;
  title: string;
  file: string | null;
  line: number | null;
  risk_score: number;
  risk_priority: RiskPriority;
  risk_explanation: string;
}

export interface RiskSummaryResponse {
  scan_id: string;
  total: number;
  counts: Record<RiskPriority, number>;
  max_score: number;
  average_score: number;
  top: RiskSummaryItem[];
}

export interface TrendPoint {
  scan_id: string;
  created_at: string;
  status: string;
  readiness: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  new_findings: number;
  fixed_findings: number;
  unchanged_findings: number;
}

export interface TrendsResponse {
  repository_name: string;
  total_scans: number;
  points: TrendPoint[];
}

export interface DependencyItem {
  name: string;
  version: string;
  ecosystem: string;
  scope: string;
  license: string | null;
  purl: string;
  sources: string[];
}

export interface DependenciesResponse {
  scan_id: string;
  total: number;
  direct: number;
  transitive: number;
  ecosystem_counts: Record<string, number>;
  vulnerabilities_available: boolean;
  vulnerability_counts: Record<string, number>;
  items: DependencyItem[];
}

export interface ContainerCategoryScore {
  key: string;
  label: string;
  score: number;
  findings: number;
  counts: Record<string, number>;
  explanation: string;
}

export interface ContainerSecurityResponse {
  scan_id: string;
  applicable: boolean;
  overall: number;
  total_findings: number;
  categories: ContainerCategoryScore[];
}

export interface K8sCategoryScore {
  key: string;
  label: string;
  score: number;
  findings: number;
  counts: Record<string, number>;
  explanation: string;
}

export interface KubernetesScoreResponse {
  scan_id: string;
  applicable: boolean;
  overall: number;
  total_findings: number;
  categories: K8sCategoryScore[];
}

export interface PostureCategory {
  key: string;
  label: string;
  score: number;
  applicable: boolean;
  findings: number;
  counts: Record<string, number>;
  explanation: string;
}

export interface AffectedFile {
  file: string;
  findings: number;
  max_severity: string;
}

export interface PostureResponse {
  scan_id: string;
  overall: number;
  ready: boolean;
  categories: PostureCategory[];
  severity_counts: Record<string, number>;
  total_findings: number;
  new_findings: number;
  fixed_findings: number;
  unchanged_findings: number;
  top_risk_areas: PostureCategory[];
  most_affected_files: AffectedFile[];
  recommendations: string[];
}

export interface FindingsResponse {
  scan_id: string;
  total: number;
  severity_counts: Record<string, number>;
  suppressed_count: number;
  items: Finding[];
}

export interface SuppressRequest {
  reason: SuppressionReason;
  note?: string;
}

export interface SuppressionRead {
  id: string;
  repository_name: string;
  fingerprint: string;
  rule_id: string;
  file_path: string | null;
  reason: SuppressionReason;
  note: string;
  created_at: string;
}

export interface ScanFilesResponse {
  scan_id: string;
  total: number;
  items: RepositoryFile[];
}

export interface RepositoryFileContent {
  id: string;
  scan_id: string;
  path: string;
  file_type: string;
  size: number;
  content: string | null;
}

export interface TopRule {
  rule_id: string;
  count: number;
}

export interface StatsResponse {
  total_scans: number;
  repositories_scanned: number;
  repositories_ready: number;
  critical_issues: number;
  high_issues: number;
  average_readiness: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
  top_rules: TopRule[];
  latest_scans: ScanSummary[];
}

export interface FindingFilters {
  severity?: string;
  category?: string;
  scanner?: string;
  confidence?: string;
  file_type?: string;
  priority?: string;
  sort?: string;
}

// ---- Report model (services/report/model.py) ----

export interface ReportFinding {
  id: string;
  rule_id: string;
  scanner: string;
  category: string;
  severity: string;
  confidence: string;
  title: string;
  description: string;
  file: string | null;
  line: number | null;
  evidence: string | null;
  recommendation: string;
}

export interface SeverityBucket {
  severity: string;
  label: string;
  count: number;
  findings: ReportFinding[];
}

export interface DomainSection {
  key: string;
  label: string;
  count: number;
  findings: ReportFinding[];
}

export interface CrossFileRisk {
  root_cause: string;
  category: string;
  severity: string;
  confidence: string;
  affected_files: string[];
  evidence: string[];
  impact: string;
  recommendation: string;
}

export interface RemediationStep {
  priority: number;
  severity: string;
  action: string;
  affected_rule_ids: string[];
  affected_files: string[];
  finding_count: number;
}

export interface ReportCategoryScore {
  category: string;
  label: string;
  score: number;
  weight: number;
  applicable: boolean;
  findings: number;
  explanation: string;
}

export interface ReadinessSection {
  score: number;
  ready: boolean;
  rating: string;
  summary: string;
  confidence: string;
  category_scores: ReportCategoryScore[];
  blockers: string[];
  top_risks: string[];
  next_actions: string[];
  explanation: string;
}

export interface RepositoryInfo {
  name: string;
  scan_id: string;
  source_type: string;
  status: string;
  created_at: string | null;
  completed_at: string | null;
  total_files: number;
  file_type_counts: Record<string, number>;
  technologies: string[];
  components: string[];
}

export interface ReportModel {
  schema_version: string;
  report_id: string;
  generated_at: string;
  title: string;
  repository: RepositoryInfo;
  executive_summary: string;
  llm_used: boolean;
  production_readiness: ReadinessSection;
  total_findings: number;
  reviewed_false_positives: number;
  severity_summary: Record<string, number>;
  issues_by_severity: SeverityBucket[];
  findings_by_domain: DomainSection[];
  cross_file_risks: CrossFileRisk[];
  remediation_plan: RemediationStep[];
  recommendations: string[];
  detailed_findings: ReportFinding[];
}

// ---- Remediation ----

export type RemediationStatus = "proposed" | "manual_required";

export interface RemediationProposal {
  finding_id: string;
  rule_id: string;
  status: RemediationStatus;
  summary: string;
  rationale: string;
  confidence: ConfidenceLevel;
  file_path: string | null;
  before: string | null;
  after: string | null;
  diff: string | null;
  guidance: string | null;
  message: string;
}

export interface RemediationResult {
  finding_id: string;
  rule_id: string;
  applied: boolean;
  resolved: boolean;
  remaining_rule_ids: string[];
  diff: string | null;
  message: string;
  severity: string | null;
  before_counts: Record<string, number>;
  after_counts: Record<string, number>;
}

export interface RemediationHistoryItem {
  id: string;
  scan_id: string;
  finding_id: string;
  rule_id: string;
  scanner: string;
  file_path: string | null;
  severity: string;
  applied: boolean;
  resolved: boolean;
  remaining_rule_ids: string[];
  diff: string | null;
  message: string;
  before_counts: Record<string, number>;
  after_counts: Record<string, number>;
  created_at: string;
}

export interface RemediationHistoryResponse {
  scan_id: string;
  total: number;
  resolved_count: number;
  items: RemediationHistoryItem[];
}


// ---- Phase 2: integrations, pull requests, policies, notifications, audit ----

export type SCMProviderName = "github" | "gitlab";

export interface Integration {
  id: string;
  provider: SCMProviderName;
  account: string | null;
  name: string;
  status: string;
  api_url: string;
  created_at: string;
}

export interface IntegrationListResponse {
  total: number;
  items: Integration[];
}

export interface IntegrationConnectRequest {
  provider: SCMProviderName;
  token: string;
  name?: string | null;
}

export interface RemoteRepository {
  external_id: string;
  owner: string;
  name: string;
  full_name: string;
  default_branch: string;
  web_url: string;
  private: boolean;
}

export interface RemoteRepositoryListResponse {
  total: number;
  items: RemoteRepository[];
}

export interface SCMRepository {
  id: string;
  integration_id: string;
  provider: SCMProviderName;
  owner: string;
  name: string;
  full_name: string;
  default_branch: string;
  web_url: string;
  private: boolean;
  policy_id: string | null;
  created_at: string;
}

export interface SCMRepositoryListResponse {
  total: number;
  items: SCMRepository[];
}

export interface RepositoryImportRequest {
  owner: string;
  name: string;
}

// ---- Policies ----

export interface Policy {
  id: string;
  name: string;
  description: string;
  yaml_text: string;
  version: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyListResponse {
  total: number;
  items: Policy[];
}

export interface PolicyCreateRequest {
  name: string;
  yaml_text: string;
  description?: string;
}

export interface PolicyUpdateRequest {
  yaml_text?: string;
  description?: string;
  enabled?: boolean;
}

export interface PolicyVersion {
  version: number;
  yaml_text: string;
  created_at: string;
}

export interface PolicyAssignRequest {
  scope_type: "repo" | "global";
  scope_value?: string;
  environment?: string | null;
}

export interface PolicyEvaluationResult {
  status: "pass" | "warning" | "fail";
  rules: Array<Record<string, unknown>>;
  violations: Array<Record<string, unknown>>;
}

// ---- Pull requests ----

export type GateStatus = "pass" | "warning" | "fail";

export interface PullRequestScan {
  id: string;
  pull_request_id: string;
  head_sha: string;
  status: string;
  changed_files: number;
  new_findings: number;
  fixed_findings: number;
  pr_risk_score: number;
  readiness_before: number;
  readiness_after: number;
  gate_status: GateStatus;
  severity_delta: Record<string, number> | null;
  findings_detail: Array<Record<string, unknown>> | null;
  policy_result: Record<string, unknown> | null;
  summary: string;
  created_at: string;
}

export interface PullRequest {
  id: string;
  provider: SCMProviderName;
  repo_full_name: string;
  number: number;
  title: string;
  author: string;
  base_ref: string;
  head_ref: string;
  head_sha: string;
  web_url: string;
  state: string;
  created_at: string;
  updated_at: string;
}

export interface PullRequestListResponse {
  total: number;
  items: PullRequest[];
}

export interface PullRequestDetail {
  pull_request: PullRequest;
  latest_scan: PullRequestScan | null;
  scans: PullRequestScan[];
}

// ---- Notifications ----

export type NotificationChannelType = "slack" | "teams" | "webhook" | "email";

export interface NotificationChannel {
  id: string;
  type: NotificationChannelType;
  name: string;
  enabled: boolean;
  events: string[];
  config: Record<string, unknown>; // masked - never contains full secrets
  created_at: string;
  updated_at: string;
}

export interface NotificationChannelListResponse {
  total: number;
  items: NotificationChannel[];
}

export interface NotificationChannelCreateRequest {
  type: NotificationChannelType;
  name: string;
  config: Record<string, unknown>;
  events: string[];
}

export interface NotificationChannelUpdateRequest {
  name?: string;
  config?: Record<string, unknown>;
  events?: string[];
  enabled?: boolean;
}

export interface NotificationDelivery {
  id: string;
  channel_id: string;
  event_type: string;
  status: "sent" | "failed";
  error: string | null;
  created_at: string;
}

// ---- Audit log ----

export interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  actor: string;
  status: string;
  detail: Record<string, unknown> | null;
  created_at: string;
}

export interface AuditLogListResponse {
  total: number;
  items: AuditLog[];
}


// ---- Phase 3: AI investigation ---------------------------------------------

export interface InvestigationTraceStep {
  kind: string; // plan | tool | observation | answer | note
  label: string;
  tool?: string;
  status?: string;
  returned?: number;
  truncated?: boolean;
}

export interface InvestigationCitation {
  type: string; // finding | file
  finding_id?: string;
  path?: string;
}

export interface InvestigationEvidence {
  tool: string;
  args: Record<string, unknown>;
  returned: number;
  truncated: boolean;
  data: unknown;
}

export interface InvestigationResult {
  investigation_id: string | null;
  question: string;
  answer: string;
  root_cause: string;
  impact: string;
  recommendations: string[];
  confidence: "high" | "medium" | "low";
  cited_finding_ids: string[];
  cited_files: string[];
  citations: InvestigationCitation[];
  evidence: InvestigationEvidence[];
  trace: InvestigationTraceStep[];
  label: string;
  ai_used: boolean;
  tool_calls: number;
  hallucination_guard_triggered: boolean;
}

export interface InvestigationSummary {
  id: string;
  scope: string;
  scan_id: string | null;
  finding_id: string | null;
  repository_name: string;
  question: string;
  confidence: string;
  label: string;
  ai_used: boolean;
  tool_calls: number;
  created_at: string;
}

export interface InvestigationListResponse {
  total: number;
  items: InvestigationSummary[];
}

export interface InvestigationDetail extends InvestigationSummary {
  answer: string;
  root_cause: string;
  impact: string;
  recommendations: string[];
  citations: InvestigationCitation[];
  evidence: InvestigationEvidence[];
  trace: InvestigationTraceStep[];
  hallucination_guard_triggered: boolean;
}

export interface RemediationStep {
  order: number;
  action: string;
  finding_id: string;
  rule_id: string;
  file: string | null;
  deterministic_recommendation: string;
}

export interface RemediationPlan {
  scan_id: string;
  problem: string;
  root_cause: string;
  steps: RemediationStep[];
  affected_files: string[];
  expected_findings_resolved: string[];
  estimated_score_before: number;
  estimated_score_after: number;
  estimated_score_delta: number;
  estimate_note: string;
  risk_level: string;
  requires_approval: boolean;
  status: string;
  label: string;
  ai_used: boolean;
  confidence: string;
}

export interface AIReviewItem {
  title: string;
  concern: string;
  category: string;
  confidence: string;
  files: string[];
  source: string;
  authoritative: boolean;
}

export interface AIReviewResponse {
  label: string;
  authoritative: boolean;
  ai_used: boolean;
  note: string;
  items: AIReviewItem[];
  pr_scan_id?: string | null;
  scan_id?: string | null;
}
