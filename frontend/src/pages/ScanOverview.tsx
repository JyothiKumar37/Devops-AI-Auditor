import { Link, useParams } from "react-router-dom";

import { Card, SeverityPill, Spinner } from "@/components/ui";
import { useDiscovery, useReport, useScan } from "@/hooks/useScans";
import { CATEGORY_META, SEVERITY_ORDER, severityMeta } from "@/lib/format";
import type { DiscoveryCategory } from "@/types/api";

const SEV_HEX: Record<string, string> = {
  critical: "#f43f5e",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#0ea5e9",
  info: "#94a3b8",
};

function readinessColor(score: number): string {
  if (score >= 80) return "text-emerald-600";
  if (score >= 60) return "text-amber-600";
  return "text-rose-600";
}

function gaugeStroke(score: number): string {
  if (score >= 80) return "#16a34a";
  if (score >= 60) return "#d97706";
  return "#dc2626";
}

function ReadinessGauge({ score }: { score: number }) {
  const size = 120;
  const stroke = 11;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - clamped / 100);
  const color = gaugeStroke(clamped);
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.22)" strokeWidth={stroke} />
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
        <span className={`text-3xl font-extrabold tabular-nums ${readinessColor(clamped)}`}>{clamped}</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">/ 100</span>
      </div>
    </div>
  );
}

export default function ScanOverview() {
  const { scanId } = useParams();
  const id = scanId ?? null;
  const { data: scan } = useScan(id);
  const isDone = scan?.status === "completed";
  const { data: discovery } = useDiscovery(isDone ? id : null);
  const { data: report } = useReport(isDone ? id : null);

  if (scan && !isDone) {
    return (
      <Card className="p-6">
        <Spinner label={`Scan ${scan.status}…`} />
        <p className="mt-2 max-w-xl text-sm text-slate-500">
          Discovering files, running deterministic scanners, detecting secrets and correlating
          findings. This view updates automatically.
        </p>
      </Card>
    );
  }

  if (!report || !discovery) {
    return <Spinner />;
  }

  const pr = report.production_readiness;
  const total = report.total_findings || 0;
  const activeCats = (Object.keys(discovery.counts) as DiscoveryCategory[]).filter(
    (c) => (discovery.counts[c] ?? 0) > 0,
  );

  return (
    <div className="space-y-4">
      {/* Summary bar: readiness gauge + severity distribution (clickable). */}
      <Card className="relative overflow-hidden p-5">
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-brand-50/60 via-white to-violet-50/40" />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-center">
          <div className="flex items-center gap-4 lg:w-72 lg:border-r lg:border-slate-200 lg:pr-6">
            <ReadinessGauge score={pr.score} />
            <div>
              <p className="section-title">Production readiness</p>
              <span
                className={`chip mt-2 ring-1 ${
                  pr.ready
                    ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
                    : "bg-rose-50 text-rose-700 ring-rose-600/20"
                }`}
              >
                {pr.ready ? "Production ready" : "Not production ready"}
              </span>
              <p className="mt-2 text-xs capitalize text-slate-500">confidence: {pr.confidence}</p>
            </div>
          </div>

          <div className="flex-1">
            <div className="mb-2 flex items-center justify-between">
              <p className="section-title">Findings · {report.total_findings}</p>
              <Link to={`/scans/${id}/findings`} className="text-xs font-semibold text-brand hover:text-brand-deep hover:underline">
                All findings →
              </Link>
            </div>
            <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
              {SEVERITY_ORDER.map((sev) => {
                const c = report.severity_counts[sev] ?? 0;
                if (!c || total === 0) return null;
                return (
                  <span
                    key={sev}
                    className={severityMeta(sev).dot}
                    style={{ width: `${(c / total) * 100}%` }}
                    title={`${sev}: ${c}`}
                  />
                );
              })}
            </div>
            {/* Clickable severity chips → filtered findings. */}
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
              {SEVERITY_ORDER.map((sev) => {
                const c = report.severity_counts[sev] ?? 0;
                return (
                  <Link
                    key={sev}
                    to={`/scans/${id}/findings?severity=${sev}`}
                    className="group rounded-lg border border-slate-200/70 bg-white/70 px-2.5 py-2 transition-all hover:border-slate-300 hover:shadow-card-hover"
                    style={{ borderLeft: `3px solid ${SEV_HEX[sev] ?? "#94a3b8"}` }}
                  >
                    <span className="block text-lg font-bold tabular-nums text-slate-900">{c}</span>
                    <span className="block text-[11px] capitalize text-slate-500 group-hover:text-slate-700">
                      {sev}
                    </span>
                  </Link>
                );
              })}
            </div>
            <p className="mt-3 text-xs text-slate-500">
              {report.reviewed_false_positives} reviewed as likely false positives · click a severity to filter
            </p>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Detected stack + artifacts */}
        <Card className="p-5">
          <p className="section-title">Detected stack</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {report.understanding.technologies.length ? (
              report.understanding.technologies.map((t) => (
                <span key={t} className="chip bg-slate-50 text-slate-700 ring-slate-200">
                  {t}
                </span>
              ))
            ) : (
              <span className="text-sm text-slate-500">No known technologies detected.</span>
            )}
          </div>
          <p className="section-title mt-5">Discovered artifacts</p>
          <div className="mt-2 space-y-1.5">
            {activeCats.map((c) => {
              const meta = CATEGORY_META[c];
              const count = discovery.counts[c] ?? 0;
              const max = Math.max(1, ...activeCats.map((k) => discovery.counts[k] ?? 0));
              return (
                <div key={c} className="flex items-center gap-3">
                  <span className={`chip w-32 shrink-0 justify-center ring-1 ring-inset ${meta?.accent ?? ""}`}>
                    {meta?.label ?? c}
                  </span>
                  <span className="block h-1.5 flex-1 overflow-hidden rounded-full bg-slate-100">
                    <span
                      className="block h-full rounded-full bg-brand-gradient"
                      style={{ width: `${(count / max) * 100}%` }}
                    />
                  </span>
                  <span className="w-8 text-right font-mono text-xs tabular-nums text-slate-600">{count}</span>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Root-cause correlations */}
        <Card className="p-5">
          <div className="flex items-center justify-between">
            <p className="section-title">Root-cause correlations</p>
            {report.finding_groups.length > 5 ? (
              <span className="text-xs text-slate-400">
                showing 5 of {report.finding_groups.length}
              </span>
            ) : null}
          </div>
          {report.finding_groups.length === 0 ? (
            <p className="mt-2 text-sm text-slate-500">No cross-file root causes identified.</p>
          ) : (
            <ul className="mt-2 divide-y divide-slate-100">
              {report.finding_groups.slice(0, 5).map((g) => (
                <li key={g.root_cause} className="flex items-start gap-2.5 py-2.5 text-sm">
                  <SeverityPill severity={g.severity} />
                  <span className="text-slate-700">{g.root_cause}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
