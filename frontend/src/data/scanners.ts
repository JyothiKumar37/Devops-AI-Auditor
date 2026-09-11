// The artifact categories the auditor is designed to analyse. Mirrors the
// backend `ScannerType` enum. Every scanner is "planned" in the foundation -
// the analysis engines are implemented in later stages.

export interface ScannerCatalogEntry {
  id: string;
  label: string;
  description: string;
  status: "planned";
}

export const SCANNER_CATALOG: ScannerCatalogEntry[] = [
  { id: "dockerfile", label: "Dockerfiles", description: "Base images, layering, non-root users, pinned versions.", status: "planned" },
  { id: "docker_compose", label: "Docker Compose", description: "Service config, exposed ports, secrets, restart policies.", status: "planned" },
  { id: "kubernetes", label: "Kubernetes", description: "Manifests, security contexts, resource limits, probes.", status: "planned" },
  { id: "helm", label: "Helm Charts", description: "Templates, values hygiene, chart best practices.", status: "planned" },
  { id: "terraform", label: "Terraform", description: "Providers, state, IAM, drift and misconfigurations.", status: "planned" },
  { id: "github_actions", label: "GitHub Actions", description: "Workflow permissions, pinned actions, secret usage.", status: "planned" },
  { id: "gitlab_ci", label: "GitLab CI", description: "Pipeline stages, runners, protected variables.", status: "planned" },
  { id: "jenkins", label: "Jenkinsfiles", description: "Pipeline steps, credentials, unsafe shell usage.", status: "planned" },
  { id: "shell", label: "Shell Scripts", description: "Unsafe patterns, quoting, error handling.", status: "planned" },
  { id: "ansible", label: "Ansible", description: "Playbooks, roles, idempotency, vault usage.", status: "planned" },
  { id: "config", label: "Config Files", description: "Environment, service and application configuration.", status: "planned" },
  { id: "secrets", label: "Secrets & Credentials", description: "Hardcoded keys, tokens and credential leakage.", status: "planned" },
];
