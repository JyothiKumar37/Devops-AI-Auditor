import type { DiscoveryCategory } from "@/types/api";

// Maximum upload size (MB). Mirrors the backend `max_upload_size_mb` default.
export const MAX_UPLOAD_MB = 100;
export const ACCEPTED_EXTENSIONS = [".zip"];

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

export function formatDateTime(iso: string | null): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}

export function relativeTime(iso: string | null): string {
  if (!iso) return "-";
  const then = new Date(iso).getTime();
  const seconds = Math.round((Date.now() - then) / 1000);
  const units: [number, string][] = [
    [60, "s"],
    [60, "m"],
    [24, "h"],
    [7, "d"],
    [4.35, "w"],
    [12, "mo"],
  ];
  let value = seconds;
  let unit = "s";
  for (const [factor, label] of units) {
    if (Math.abs(value) < factor) break;
    value = Math.round(value / factor);
    unit = label;
  }
  return `${value}${unit} ago`;
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export const SEVERITY_META: Record<string, { label: string; text: string; badge: string; dot: string }> = {
  critical: { label: "Critical", text: "text-rose-300", badge: "bg-rose-500/15 text-rose-300 ring-rose-500/30", dot: "bg-rose-500" },
  high: { label: "High", text: "text-orange-300", badge: "bg-orange-500/15 text-orange-300 ring-orange-500/30", dot: "bg-orange-500" },
  medium: { label: "Medium", text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300 ring-amber-500/30", dot: "bg-amber-500" },
  low: { label: "Low", text: "text-sky-300", badge: "bg-sky-500/15 text-sky-300 ring-sky-500/30", dot: "bg-sky-500" },
  info: { label: "Info", text: "text-slate-300", badge: "bg-slate-500/15 text-slate-300 ring-slate-500/30", dot: "bg-slate-500" },
};

const _INFO_META = { label: "Info", text: "text-slate-300", badge: "bg-slate-500/15 text-slate-300 ring-slate-500/30", dot: "bg-slate-500" };

export function severityMeta(severity: string) {
  return SEVERITY_META[severity] ?? _INFO_META;
}

export function prettyLabel(value: string): string {
  return value
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// Health color for a 0-100 score (green / amber / red).
export function scoreColor(score: number): string {
  if (score >= 75) return "#22c55e";
  if (score >= 50) return "#f59e0b";
  return "#f43f5e";
}

// Map detected file types to a Monaco language id.
export function monacoLanguage(fileType: string, path: string): string {
  if (fileType === "dockerfile") return "dockerfile";
  if (path.endsWith(".tf") || path.endsWith(".tfvars")) return "hcl";
  if (path.endsWith(".json")) return "json";
  if (path.endsWith(".toml")) return "ini";
  if (path.endsWith(".xml")) return "xml";
  if (path.endsWith(".sh") || path.endsWith(".bash")) return "shell";
  if (path.endsWith(".py")) return "python";
  if (path.endsWith(".md")) return "markdown";
  if (path.endsWith(".yml") || path.endsWith(".yaml") || fileType.includes("yaml")) return "yaml";
  if (["kubernetes", "docker_compose", "github_actions", "gitlab_ci", "helm_chart", "helm_values", "helm_template", "ansible_playbook", "ansible_role"].includes(fileType))
    return "yaml";
  return "plaintext";
}

interface CategoryMeta {
  label: string;
  accent: string;
}

// Display metadata for each discovery category.
export const CATEGORY_META: Record<DiscoveryCategory, CategoryMeta> = {
  docker: { label: "Docker", accent: "text-sky-300 ring-sky-500/30 bg-sky-500/10" },
  compose: { label: "Docker Compose", accent: "text-cyan-300 ring-cyan-500/30 bg-cyan-500/10" },
  kubernetes: { label: "Kubernetes", accent: "text-blue-300 ring-blue-500/30 bg-blue-500/10" },
  terraform: { label: "Terraform", accent: "text-violet-300 ring-violet-500/30 bg-violet-500/10" },
  cicd: { label: "CI/CD", accent: "text-amber-300 ring-amber-500/30 bg-amber-500/10" },
  helm: { label: "Helm", accent: "text-teal-300 ring-teal-500/30 bg-teal-500/10" },
  ansible: { label: "Ansible", accent: "text-rose-300 ring-rose-500/30 bg-rose-500/10" },
  shell: { label: "Shell", accent: "text-emerald-300 ring-emerald-500/30 bg-emerald-500/10" },
  configuration: {
    label: "Configuration",
    accent: "text-indigo-300 ring-indigo-500/30 bg-indigo-500/10",
  },
  other: { label: "Other", accent: "text-slate-300 ring-slate-500/30 bg-slate-500/10" },
};

export const CATEGORY_ORDER: DiscoveryCategory[] = [
  "docker",
  "compose",
  "kubernetes",
  "terraform",
  "cicd",
  "helm",
  "ansible",
  "shell",
  "configuration",
  "other",
];
