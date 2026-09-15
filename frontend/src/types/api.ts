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
}

export interface ScanListResponse {
  items: ScanSummary[];
  total: number;
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
}

export interface FindingsResponse {
  scan_id: string;
  total: number;
  severity_counts: Record<string, number>;
  items: Finding[];
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

export interface StatsResponse {
  total_scans: number;
  repositories_scanned: number;
  critical_issues: number;
  high_issues: number;
  average_readiness: number;
  latest_scans: ScanSummary[];
}

export interface FindingFilters {
  severity?: string;
  category?: string;
  scanner?: string;
  confidence?: string;
  file_type?: string;
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
}
