import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, PageHeader, Spinner, StatCard } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import { SEVERITY_ORDER, prettyLabel, relativeTime, severityMeta } from "@/lib/format";

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-[18px] w-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

function readinessAccent(score: number): string {
  if (score >= 75) return "text-emerald-600";
  if (score >= 50) return "text-amber-600";
  return "text-rose-600";
}

export default function Dashboard() {
  const { data, isLoading, isError } = useStats();

  return (
    <div className="space-y-5">
      <PageHeader title="Dashboard" subtitle="Scan activity and open findings across all repositories." />

      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load dashboard" description="Is the backend reachable?" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
            <StatCard
              label="Total scans"
              value={data.total_scans}
              icon={<Icon path="M4 6h16M4 12h16M4 18h16" />}
            />
            <StatCard
              label="Repositories"
              value={data.repositories_scanned}
              icon={<Icon path="M3 7h18M3 12h18M3 17h18" />}
            />
            <StatCard
              label="Avg readiness"
              value={`${Math.round(data.average_readiness)}`}
              hint={`/ 100 · ${data.repositories_ready} ready`}
              accent={readinessAccent(Math.round(data.average_readiness))}
            />
            <StatCard
              label="Critical"
              value={data.critical_issues}
              accent={data.critical_issues > 0 ? "text-rose-600" : "text-slate-900"}
            />
            <StatCard
              label="High"
              value={data.high_issues}
              accent={data.high_issues > 0 ? "text-amber-600" : "text-slate-900"}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <SeverityCard data={data} />
            <CategoryCard counts={data.category_counts} />
            <TopRulesCard rules={data.top_rules} />
          </div>

          <Card className="animate-in overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-200 px-4 py-2.5">
              <h2 className="text-sm font-semibold text-slate-900">Latest scans</h2>
              <Link to="/scans" className="text-xs font-medium text-brand hover:underline">
                View all
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
                  <tr className="border-b border-slate-200 text-left text-[11px] uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-2 font-medium">Repository</th>
                    <th className="px-4 py-2 font-medium">Status</th>
                    <th className="px-4 py-2 font-medium tabular-nums">Readiness</th>
                    <th className="px-4 py-2 font-medium tabular-nums">Files</th>
                    <th className="px-4 py-2 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.latest_scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="border-b border-slate-100 transition-colors last:border-0 hover:bg-slate-50"
                    >
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-slate-900 hover:text-brand"
                        >
                          {scan.repository_name}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-4 py-2.5 tabular-nums">
                        {typeof scan.readiness === "number" ? (
                          <span className={`font-medium ${readinessAccent(scan.readiness)}`}>
                            {scan.readiness}
                          </span>
                        ) : (
                          <span className="text-slate-300">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 tabular-nums text-slate-500">{scan.file_count}</td>
                      <td className="px-4 py-2.5 text-slate-500">{relativeTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}

function SeverityCard({ data }: { data: { total_findings: number; severity_counts: Record<string, number> } }) {
  const total = data.total_findings || 1;
  return (
    <Card className="animate-in p-5">
      <div className="flex items-baseline justify-between">
        <p className="section-title">Findings by severity</p>
        <span className="text-2xl font-semibold tabular-nums text-slate-900">{data.total_findings}</span>
      </div>
      <div className="mt-3 flex h-2 w-full overflow-hidden rounded-full bg-slate-100">
        {SEVERITY_ORDER.map((sev) => {
          const count = data.severity_counts[sev] ?? 0;
          if (!count) return null;
          return (
            <span
              key={sev}
              className={severityMeta(sev).dot}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${sev}: ${count}`}
            />
          );
        })}
      </div>
      <div className="mt-3 space-y-1.5">
        {SEVERITY_ORDER.map((sev) => (
          <div key={sev} className="flex items-center gap-2 text-xs">
            <span className={`h-2 w-2 rounded-full ${severityMeta(sev).dot}`} aria-hidden />
            <span className="capitalize text-slate-500">{sev}</span>
            <span className="ml-auto font-medium tabular-nums text-slate-800">
              {data.severity_counts[sev] ?? 0}
            </span>
          </div>
        ))}
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
        <p className="mt-2 text-sm text-slate-500">No findings.</p>
      ) : (
        <div className="mt-3 space-y-2.5">
          {cats.map(([cat, n]) => (
            <div key={cat}>
              <div className="mb-1 flex items-center justify-between text-xs">
                <span className="text-slate-600">{prettyLabel(cat)}</span>
                <span className="font-medium tabular-nums text-slate-800">{n}</span>
              </div>
              <span className="block h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                <span
                  className="block h-full rounded-full bg-slate-400"
                  style={{ width: `${(n / max) * 100}%` }}
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
        <p className="mt-2 text-sm text-slate-500">No findings.</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {rules.map((r) => (
            <li key={r.rule_id} className="flex items-center gap-3 text-xs">
              <span className="w-16 shrink-0 font-mono text-slate-600">{r.rule_id}</span>
              <span className="block h-1.5 flex-1 overflow-hidden rounded-full bg-slate-100">
                <span
                  className="block h-full rounded-full bg-slate-400"
                  style={{ width: `${(r.count / max) * 100}%` }}
                />
              </span>
              <span className="w-6 text-right font-medium tabular-nums text-slate-800">{r.count}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
