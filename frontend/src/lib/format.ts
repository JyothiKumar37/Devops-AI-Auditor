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
  critical: { label: "Critical", text: "text-rose-700", badge: "bg-rose-50 text-rose-700 ring-rose-600/20", dot: "bg-rose-500" },
  high: { label: "High", text: "text-orange-700", badge: "bg-orange-50 text-orange-700 ring-orange-600/20", dot: "bg-orange-500" },
  medium: { label: "Medium", text: "text-amber-700", badge: "bg-amber-50 text-amber-700 ring-amber-600/20", dot: "bg-amber-500" },
  low: { label: "Low", text: "text-sky-700", badge: "bg-sky-50 text-sky-700 ring-sky-600/20", dot: "bg-sky-500" },
  info: { label: "Info", text: "text-slate-600", badge: "bg-slate-100 text-slate-600 ring-slate-500/20", dot: "bg-slate-400" },
};

const _INFO_META = { label: "Info", text: "text-slate-600", badge: "bg-slate-100 text-slate-600 ring-slate-500/20", dot: "bg-slate-400" };

export function severityMeta(severity: string) {
  return SEVERITY_META[severity] ?? _INFO_META;
}

export function prettyLabel(value: string): string {
  return value
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// Health color for a 0-100 score (green / amber / red), tuned for contrast on
// a white background.
export function scoreColor(score: number): string {
  if (score >= 75) return "#16a34a";
  if (score >= 50) return "#d97706";
  return "#dc2626";
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
  docker: { label: "Docker", accent: "text-sky-700 ring-sky-600/20 bg-sky-50" },
  compose: { label: "Docker Compose", accent: "text-cyan-700 ring-cyan-600/20 bg-cyan-50" },
  kubernetes: { label: "Kubernetes", accent: "text-blue-700 ring-blue-600/20 bg-blue-50" },
  terraform: { label: "Terraform", accent: "text-violet-700 ring-violet-600/20 bg-violet-50" },
  cicd: { label: "CI/CD", accent: "text-amber-700 ring-amber-600/20 bg-amber-50" },
  helm: { label: "Helm", accent: "text-teal-700 ring-teal-600/20 bg-teal-50" },
  ansible: { label: "Ansible", accent: "text-rose-700 ring-rose-600/20 bg-rose-50" },
  shell: { label: "Shell", accent: "text-emerald-700 ring-emerald-600/20 bg-emerald-50" },
  configuration: {
    label: "Configuration",
    accent: "text-indigo-700 ring-indigo-600/20 bg-indigo-50",
  },
  other: { label: "Other", accent: "text-slate-600 ring-slate-500/20 bg-slate-100" },
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
