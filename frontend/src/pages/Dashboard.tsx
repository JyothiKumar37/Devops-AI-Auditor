import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, PageHeader, Spinner } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import { relativeTime } from "@/lib/format";

function StatCard({
  label,
  value,
  accent = "text-white",
  hint,
}: {
  label: string;
  value: string | number;
  accent?: string;
  hint?: string;
}) {
  return (
    <Card className="p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tracking-tight ${accent}`}>{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </Card>
  );
}

function readinessColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  return "text-rose-400";
}

export default function Dashboard() {
  const { data, isLoading, isError } = useStats();

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Security and production-readiness posture across your repositories."
        actions={
          <Link
            to="/scan/new"
            className="rounded-lg bg-brand px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-brand-muted"
          >
            New Scan
          </Link>
        }
      />

      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load dashboard" description="Is the backend reachable?" />
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-5">
            <StatCard label="Total scans" value={data.total_scans} />
            <StatCard label="Repositories" value={data.repositories_scanned} />
            <StatCard label="Critical issues" value={data.critical_issues} accent="text-rose-400" />
            <StatCard label="High issues" value={data.high_issues} accent="text-orange-400" />
            <StatCard
              label="Avg readiness"
              value={`${data.average_readiness}`}
              accent={readinessColor(data.average_readiness)}
              hint="/ 100 across completed scans"
            />
          </div>

          <Card>
            <div className="flex items-center justify-between border-b border-white/10 px-5 py-3">
              <h2 className="text-sm font-semibold text-white">Latest scans</h2>
              <Link to="/scans" className="text-xs text-brand hover:underline">
                View all
              </Link>
            </div>
            {data.latest_scans.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No scans yet"
                  description="Upload a repository to run your first audit."
                  action={
                    <Link
                      to="/scan/new"
                      className="rounded-lg bg-brand px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-brand-muted"
                    >
                      New Scan
                    </Link>
                  }
                />
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/5 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-5 py-2 font-medium">Repository</th>
                    <th className="px-5 py-2 font-medium">Status</th>
                    <th className="px-5 py-2 font-medium">Files</th>
                    <th className="px-5 py-2 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.latest_scans.map((scan) => (
                    <tr key={scan.id} className="border-b border-white/5 last:border-0 hover:bg-white/5">
                      <td className="px-5 py-3">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-slate-100 hover:text-brand"
                        >
                          {scan.repository_name}
                        </Link>
                      </td>
                      <td className="px-5 py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-5 py-3 text-slate-400">{scan.file_count}</td>
                      <td className="px-5 py-3 text-slate-400">{relativeTime(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
