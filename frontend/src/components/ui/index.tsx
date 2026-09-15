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
      <div className="flex items-start gap-3">
        <span className="mt-1 h-8 w-1.5 shrink-0 rounded-full bg-brand-gradient" aria-hidden />
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h1>
          {subtitle ? <p className="mt-1 text-sm text-slate-500">{subtitle}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

// Accent tones used by StatCard (and reusable elsewhere) for a colorful,
// premium feel on a light canvas.
export const TONES = {
  indigo: { tile: "bg-indigo-50 text-indigo-600", value: "text-indigo-600", bar: "bg-indigo-500" },
  violet: { tile: "bg-violet-50 text-violet-600", value: "text-violet-600", bar: "bg-violet-500" },
  sky: { tile: "bg-sky-50 text-sky-600", value: "text-sky-600", bar: "bg-sky-500" },
  emerald: { tile: "bg-emerald-50 text-emerald-600", value: "text-emerald-600", bar: "bg-emerald-500" },
  amber: { tile: "bg-amber-50 text-amber-600", value: "text-amber-600", bar: "bg-amber-500" },
  rose: { tile: "bg-rose-50 text-rose-600", value: "text-rose-600", bar: "bg-rose-500" },
  slate: { tile: "bg-slate-100 text-slate-500", value: "text-slate-900", bar: "bg-slate-300" },
} as const;

export type Tone = keyof typeof TONES;

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
    <div className="flex items-center gap-2 text-sm text-slate-500" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-accent" />
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
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-slate-50 px-6 py-14 text-center">
      <p className="text-sm font-medium text-slate-800">{title}</p>
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
          stroke="rgba(148,163,184,0.25)"
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
        <span className="text-3xl font-extrabold text-slate-900">{clamped}</span>
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
  accent,
  tone = "slate",
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  accent?: string;
  tone?: Tone;
  icon?: ReactNode;
}) {
  const t = TONES[tone];
  const valueClass = accent ?? t.value;
  return (
    <div className="card card-hover animate-in relative overflow-hidden p-5">
      <span className={`absolute inset-x-0 top-0 h-1 ${t.bar}`} aria-hidden />
      <div className="flex items-start justify-between">
        <p className="section-title">{label}</p>
        {icon ? (
          <span className={`grid h-9 w-9 place-items-center rounded-lg ${t.tile}`}>{icon}</span>
        ) : null}
      </div>
      <p className={`mt-3 text-3xl font-bold tracking-tight ${valueClass}`}>{value}</p>
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
      className="block w-full overflow-hidden rounded-full bg-slate-100"
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
      <div className="flex items-start gap-2.5">
        <span className="mt-0.5 h-6 w-1 shrink-0 rounded-full bg-brand-gradient" aria-hidden />
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-slate-900">{title}</h2>
          {subtitle ? <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}
