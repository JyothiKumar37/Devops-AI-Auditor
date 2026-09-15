import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, PageHeader, Spinner, StatCard } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import { relativeTime } from "@/lib/format";

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
              hint="/ 100 across completed scans"
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
