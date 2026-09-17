import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, Spinner } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import type { StatsResponse } from "@/types/api";
import { SEVERITY_ORDER, prettyLabel, relativeTime, severityMeta } from "@/lib/format";

// Hex values matching the severity dot classes, needed for the SVG donut and
// conic gradients (Tailwind classes can't be used inside inline gradients).
const SEV_HEX: Record<string, string> = {
  critical: "#f43f5e",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#0ea5e9",
  info: "#94a3b8",
};

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-[18px] w-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

function readinessAccent(score: number): string {
  if (score >= 75) return "text-emerald-600";
  if (score >= 50) return "text-amber-600";
  return "text-rose-600";
}

function readinessRating(score: number): { label: string; tone: string } {
  if (score >= 75) return { label: "Production ready", tone: "bg-emerald-50 text-emerald-700 ring-emerald-600/20" };
  if (score >= 50) return { label: "Needs hardening", tone: "bg-amber-50 text-amber-700 ring-amber-600/20" };
  return { label: "At risk", tone: "bg-rose-50 text-rose-700 ring-rose-600/20" };
}

export default function Dashboard() {
  const { data, isLoading, isError } = useStats();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Control Center</h1>
          <span className="chip bg-brand-50 text-brand-deep ring-brand-200">overview</span>
        </div>
        <p className="text-sm text-slate-500">
          Production-readiness signal and open findings across every audited repository.
        </p>
      </div>

      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load dashboard" description="Is the backend reachable?" />
      ) : (
        <>
          <HeroBand data={data} />

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <KpiTile
              label="Total scans"
              value={data.total_scans}
              hint={`${data.repositories_scanned} repositories`}
              tone="brand"
              icon={<Icon path="M4 6h16M4 12h16M4 18h16" />}
            />
            <KpiTile
              label="Total findings"
              value={data.total_findings}
              hint="across all scans"
              tone="violet"
              icon={<Icon path="M12 9v4m0 4h.01M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />}
            />
            <KpiTile
              label="Critical"
              value={data.critical_issues}
              hint={data.critical_issues > 0 ? "needs attention" : "all clear"}
              tone={data.critical_issues > 0 ? "rose" : "emerald"}
              icon={<Icon path="M12 9v4m0 4h.01M12 3a9 9 0 100 18 9 9 0 000-18z" />}
            />
            <KpiTile
              label="High"
              value={data.high_issues}
              hint={data.high_issues > 0 ? "review soon" : "all clear"}
              tone={data.high_issues > 0 ? "amber" : "emerald"}
              icon={<Icon path="M13 2L3 14h7l-1 8 10-12h-7l1-8z" />}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <SeverityCard data={data} />
            <CategoryCard counts={data.category_counts} />
            <TopRulesCard rules={data.top_rules} />
          </div>

          <LatestScans data={data} />
        </>
      )}
    </div>
  );
}

function HeroBand({ data }: { data: StatsResponse }) {
  const readiness = Math.round(data.average_readiness);
  const rating = readinessRating(readiness);
  const total = data.repositories_scanned || 0;
  const ready = data.repositories_ready || 0;
  const readyPct = total > 0 ? Math.round((ready / total) * 100) : 0;

  return (
    <div className="relative animate-in overflow-hidden rounded-2xl border border-slate-200/70 bg-white shadow-elevated">
      {/* Decorative gradient wash + grid, kept subtle on the light surface. */}
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-brand-50 via-white to-violet-50/60" />
      <div
        className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full opacity-30 blur-3xl"
        style={{ background: "radial-gradient(circle, #7c3aed, transparent 70%)" }}
      />
      <div className="relative grid gap-6 p-6 sm:p-7 lg:grid-cols-[auto,1fr] lg:items-center">
        <div className="flex items-center gap-5">
          <ReadinessGauge score={readiness} />
          <div className="space-y-2">
            <p className="section-title">Average readiness</p>
            <div className="flex items-baseline gap-1">
              <span className={`text-4xl font-extrabold tabular-nums tracking-tight ${readinessAccent(readiness)}`}>
                {readiness}
              </span>
              <span className="text-lg font-semibold text-slate-400">/100</span>
            </div>
            <span className={`chip ring-1 ${rating.tone}`}>{rating.label}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <HeroStat
            label="Ready to ship"
            value={`${ready}/${total}`}
            sub={`${readyPct}% of repositories`}
            bar={readyPct}
            barColor="#10b981"
          />
          <HeroStat
            label="Critical + High"
            value={data.critical_issues + data.high_issues}
            sub="blocking-class issues"
            bar={data.total_findings > 0 ? ((data.critical_issues + data.high_issues) / data.total_findings) * 100 : 0}
            barColor="#f43f5e"
          />
          <HeroStat
            label="Open findings"
            value={data.total_findings}
            sub={`${Object.keys(data.category_counts).length} categories`}
            bar={100}
            barColor="#7c3aed"
          />
        </div>
      </div>
    </div>
  );
}

// Circular readiness gauge (health-colored) hand-rolled in SVG.
function ReadinessGauge({ score }: { score: number }) {
  const size = 128;
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - clamped / 100);
  const color = clamped >= 75 ? "#16a34a" : clamped >= 50 ? "#d97706" : "#dc2626";
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={color} stopOpacity={0.85} />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
        </defs>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(148,163,184,0.22)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="url(#gaugeGrad)"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.16,1,0.3,1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-extrabold tabular-nums text-slate-900">{clamped}</span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">score</span>
      </div>
    </div>
  );
}

function HeroStat({
  label,
  value,
  sub,
  bar,
  barColor,
}: {
  label: string;
  value: ReactNode;
  sub: string;
  bar: number;
  barColor: string;
}) {
  const clamped = Math.max(0, Math.min(100, bar));
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white/70 p-3.5 backdrop-blur">
      <p className="section-title">{label}</p>
      <p className="mt-1 text-2xl font-bold tabular-nums tracking-tight text-slate-900">{value}</p>
      <p className="text-[11px] text-slate-500">{sub}</p>
      <span className="mt-2 block h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
        <span
          className="block h-full rounded-full"
          style={{ width: `${clamped}%`, background: barColor, transition: "width 0.9s cubic-bezier(0.16,1,0.3,1)" }}
        />
      </span>
    </div>
  );
}

const TONE_STYLES: Record<string, { tile: string; value: string }> = {
  brand: { tile: "bg-brand-50 text-brand-deep ring-brand-200", value: "text-slate-900" },
  violet: { tile: "bg-violet-50 text-violet-700 ring-violet-200", value: "text-slate-900" },
  rose: { tile: "bg-rose-50 text-rose-600 ring-rose-200", value: "text-rose-600" },
  amber: { tile: "bg-amber-50 text-amber-600 ring-amber-200", value: "text-amber-600" },
  emerald: { tile: "bg-emerald-50 text-emerald-600 ring-emerald-200", value: "text-slate-900" },
};

function KpiTile({
  label,
  value,
  hint,
  tone,
  icon,
}: {
  label: string;
  value: ReactNode;
  hint: string;
  tone: keyof typeof TONE_STYLES;
  icon: ReactNode;
}) {
  const style = TONE_STYLES[tone] ?? TONE_STYLES.brand;
  return (
    <div className="card card-hover animate-in p-4">
      <div className="flex items-start justify-between">
        <p className="section-title">{label}</p>
        <span className={`icon-tile ${style?.tile ?? ""}`}>{icon}</span>
      </div>
      <p className={`mt-2 text-3xl font-extrabold tabular-nums tracking-tight ${style?.value ?? "text-slate-900"}`}>
        {value}
      </p>
      <p className="mt-0.5 text-xs text-slate-500">{hint}</p>
    </div>
  );
}

function SeverityCard({ data }: { data: StatsResponse }) {
  const total = data.total_findings || 0;
  const segments = SEVERITY_ORDER.map((sev) => ({
    sev,
    count: data.severity_counts[sev] ?? 0,
  })).filter((s) => s.count > 0);

  // Build a conic-gradient donut from cumulative percentages.
  let acc = 0;
  const stops: string[] = [];
  for (const { sev, count } of segments) {
    const start = (acc / (total || 1)) * 100;
    acc += count;
    const end = (acc / (total || 1)) * 100;
    const hex = SEV_HEX[sev] ?? "#94a3b8";
    stops.push(`${hex} ${start}% ${end}%`);
  }
  const gradient =
    total > 0 ? `conic-gradient(${stops.join(", ")})` : "conic-gradient(#e2e8f0 0% 100%)";

  return (
    <Card className="animate-in p-5">
      <p className="section-title">Findings by severity</p>
      <div className="mt-4 flex items-center gap-5">
        <div className="relative grid h-[104px] w-[104px] shrink-0 place-items-center">
          <div className="h-full w-full rounded-full" style={{ background: gradient }} />
          <div className="absolute grid h-[70px] w-[70px] place-items-center rounded-full bg-white shadow-inner">
            <span className="text-xl font-extrabold tabular-nums text-slate-900">{total}</span>
            <span className="text-[9px] font-semibold uppercase tracking-widest text-slate-400">total</span>
          </div>
        </div>
        <ul className="flex-1 space-y-1.5">
          {SEVERITY_ORDER.map((sev) => {
            const count = data.severity_counts[sev] ?? 0;
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            return (
              <li key={sev} className="flex items-center gap-2 text-xs">
                <span className={`h-2.5 w-2.5 rounded-sm ${severityMeta(sev).dot}`} aria-hidden />
                <span className="capitalize text-slate-600">{sev}</span>
                <span className="ml-auto font-semibold tabular-nums text-slate-800">{count}</span>
                <span className="w-9 text-right tabular-nums text-slate-400">{pct}%</span>
              </li>
            );
          })}
        </ul>
      </div>
    </Card>
  );
}

function CategoryCard({ counts }: { counts: Record<string, number> }) {
  const cats = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...cats.map(([, n]) => n));
  return (
    <Card className="animate-in p-5">
      <p className="section-title">Findings by category</p>
      {cats.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No findings.</p>
      ) : (
        <div className="mt-4 space-y-3">
          {cats.map(([cat, n]) => (
            <div key={cat}>
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="font-medium text-slate-700">{prettyLabel(cat)}</span>
                <span className="font-semibold tabular-nums text-slate-800">{n}</span>
              </div>
              <span className="block h-2 w-full overflow-hidden rounded-full bg-slate-100">
                <span
                  className="block h-full rounded-full bg-brand-gradient"
                  style={{ width: `${(n / max) * 100}%`, transition: "width 0.9s cubic-bezier(0.16,1,0.3,1)" }}
                />
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function TopRulesCard({ rules }: { rules: { rule_id: string; count: number }[] }) {
  const max = Math.max(1, ...rules.map((r) => r.count));
  return (
    <Card className="animate-in p-5">
      <p className="section-title">Top recurring issues</p>
      {rules.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">No findings.</p>
      ) : (
        <ol className="mt-4 space-y-2.5">
          {rules.map((r, i) => (
            <li key={r.rule_id} className="flex items-center gap-3 text-xs">
              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-md bg-slate-100 font-mono text-[10px] font-semibold text-slate-500">
                {i + 1}
              </span>
              <span className="w-20 shrink-0 truncate font-mono text-slate-600" title={r.rule_id}>
                {r.rule_id}
              </span>
              <span className="block h-2 flex-1 overflow-hidden rounded-full bg-slate-100">
                <span
                  className="block h-full rounded-full bg-violet-500"
                  style={{ width: `${(r.count / max) * 100}%`, transition: "width 0.9s cubic-bezier(0.16,1,0.3,1)" }}
                />
              </span>
              <span className="w-6 text-right font-semibold tabular-nums text-slate-800">{r.count}</span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

function LatestScans({ data }: { data: StatsResponse }) {
  return (
    <Card className="animate-in overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-200/80 px-5 py-3">
        <h2 className="text-sm font-semibold text-slate-900">Latest scans</h2>
        <Link to="/scans" className="text-xs font-semibold text-brand hover:text-brand-deep hover:underline">
          View all →
        </Link>
      </div>
      {data.latest_scans.length === 0 ? (
        <div className="p-6">
          <EmptyState
            title="No scans yet"
            description="Upload a repository to run your first audit."
            action={
              <Link to="/scan/new" className="btn-primary">
                New Scan
              </Link>
            }
          />
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-200/80 text-left text-[11px] uppercase tracking-wide text-slate-500">
              <th className="px-5 py-2.5 font-semibold">Repository</th>
              <th className="px-5 py-2.5 font-semibold">Status</th>
              <th className="px-5 py-2.5 font-semibold">Readiness</th>
              <th className="px-5 py-2.5 font-semibold tabular-nums">Files</th>
              <th className="px-5 py-2.5 font-semibold">Created</th>
            </tr>
          </thead>
          <tbody>
            {data.latest_scans.map((scan) => (
              <tr key={scan.id} className="border-b border-slate-100 transition-colors last:border-0 hover:bg-slate-50/70">
                <td className="px-5 py-3">
                  <Link to={`/scans/${scan.id}`} className="font-medium text-slate-900 hover:text-brand">
                    {scan.repository_name}
                  </Link>
                </td>
                <td className="px-5 py-3">
                  <ScanStatusBadge status={scan.status} />
                </td>
                <td className="px-5 py-3">
                  {typeof scan.readiness === "number" ? (
                    <div className="flex items-center gap-2">
                      <span className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-100">
                        <span
                          className="block h-full rounded-full"
                          style={{
                            width: `${scan.readiness}%`,
                            background: scan.readiness >= 75 ? "#16a34a" : scan.readiness >= 50 ? "#d97706" : "#dc2626",
                          }}
                        />
                      </span>
                      <span className={`font-semibold tabular-nums ${readinessAccent(scan.readiness)}`}>
                        {scan.readiness}
                      </span>
                    </div>
                  ) : (
                    <span className="text-slate-300">—</span>
                  )}
                </td>
                <td className="px-5 py-3 tabular-nums text-slate-500">{scan.file_count}</td>
                <td className="px-5 py-3 text-slate-500">{relativeTime(scan.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
