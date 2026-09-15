import type { ReactNode } from "react";

import { scoreColor, severityMeta } from "@/lib/format";

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={`card ${className}`}>{children}</div>;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle ? <p className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SeverityPill({ severity, count }: { severity: string; count?: number }) {
  const meta = severityMeta(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${meta.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden />
      {meta.label}
      {typeof count === "number" ? <span className="opacity-70">· {count}</span> : null}
    </span>
  );
}

export function Badge({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${className}`}
    >
      {children}
    </span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/20 border-t-brand" />
      {label ?? "Loading…"}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-white/10 bg-slate-900/30 px-6 py-14 text-center">
      <p className="text-sm font-medium text-slate-200">{title}</p>
      {description ? <p className="mt-1 max-w-md text-sm text-slate-500">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="font-medium uppercase tracking-wide text-slate-500">{label}</span>
      {children}
    </label>
  );
}

// A number score (0-100) rendered as a circular gauge with a health color.
export function ScoreRing({
  score,
  size = 132,
  stroke = 11,
  caption,
}: {
  score: number;
  size?: number;
  stroke?: number;
  caption?: string;
}) {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - clamped / 100);
  const color = scoreColor(clamped);
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(148,163,184,0.15)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.16,1,0.3,1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-extrabold text-white">{clamped}</span>
        <span className="text-[10px] uppercase tracking-widest text-slate-500">
          {caption ?? "/ 100"}
        </span>
      </div>
    </div>
  );
}

export function StatCard({
  label,
  value,
  hint,
  accent = "text-white",
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: string;
  icon?: ReactNode;
}) {
  return (
    <div className="card card-hover animate-in p-5">
      <div className="flex items-start justify-between">
        <p className="section-title">{label}</p>
        {icon ? <span className="text-slate-500">{icon}</span> : null}
      </div>
      <p className={`mt-3 text-3xl font-bold tracking-tight ${accent}`}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function Meter({
  value,
  color,
  height = 8,
}: {
  value: number;
  color?: string;
  height?: number;
}) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <span
      className="block w-full overflow-hidden rounded-full bg-white/10"
      style={{ height }}
    >
      <span
        className="block h-full rounded-full"
        style={{
          width: `${clamped}%`,
          background: color ?? scoreColor(clamped),
          transition: "width 0.9s cubic-bezier(0.16,1,0.3,1)",
        }}
      />
    </span>
  );
}

export function SectionHeading({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold tracking-tight text-white">{title}</h2>
        {subtitle ? <p className="mt-0.5 text-sm text-slate-400">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}
