import { Link } from "react-router-dom";

import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { Card, EmptyState, ScoreRing, Spinner, StatCard } from "@/components/ui";
import { useStats } from "@/hooks/useScans";
import { relativeTime } from "@/lib/format";

function Icon({ path }: { path: string }) {
  return (
    <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.7}>
      <path strokeLinecap="round" strokeLinejoin="round" d={path} />
    </svg>
  );
}

export default function Dashboard() {
  const { data, isLoading, isError } = useStats();

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div className="card animate-in relative overflow-hidden p-6 sm:p-8">
        <div className="pointer-events-none absolute inset-0 bg-grid-faint [background-size:32px_32px] opacity-40" />
        <div className="relative flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div className="max-w-xl">
            <span className="chip bg-brand/15 text-brand ring-brand/30">Security &amp; readiness</span>
            <h1 className="mt-3 text-2xl font-bold tracking-tight sm:text-3xl">
              <span className="text-gradient">Ship infrastructure with confidence.</span>
            </h1>
            <p className="mt-2 text-sm text-slate-500">
              Continuous auditing of Docker, Kubernetes, Terraform, CI/CD and secrets — with
              AI-grounded reasoning and a production-readiness score.
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Link to="/scan/new" className="btn-primary">
                <Icon path="M12 4v16m8-8H4" />
                New Scan
              </Link>
              <Link to="/scans" className="btn-ghost">
                View history
              </Link>
            </div>
          </div>
          {data ? (
            <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-slate-50 p-5">
              <ScoreRing score={Math.round(data.average_readiness)} size={112} />
              <div>
                <p className="section-title">Avg readiness</p>
                <p className="mt-1 text-sm text-slate-500">across completed scans</p>
              </div>
            </div>
          ) : null}
        </div>
      </div>

      {isLoading ? (
        <Spinner />
      ) : isError || !data ? (
        <EmptyState title="Could not load dashboard" description="Is the backend reachable?" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
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
              label="Critical issues"
              value={data.critical_issues}
              accent="text-rose-600"
              icon={<Icon path="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L14.7 3.9a2 2 0 00-3.4 0z" />}
            />
            <StatCard
              label="High issues"
              value={data.high_issues}
              accent="text-orange-600"
              icon={<Icon path="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L14.7 3.9a2 2 0 00-3.4 0z" />}
            />
          </div>

          <Card className="animate-in overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5">
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
                  <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-5 py-2.5 font-medium">Repository</th>
                    <th className="px-5 py-2.5 font-medium">Status</th>
                    <th className="px-5 py-2.5 font-medium">Files</th>
                    <th className="px-5 py-2.5 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.latest_scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="border-b border-slate-200 transition last:border-0 hover:bg-slate-50"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-slate-900 hover:text-brand"
                        >
                          {scan.repository_name}
                        </Link>
                      </td>
                      <td className="px-5 py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-5 py-3 text-slate-500">{scan.file_count}</td>
                      <td className="px-5 py-3 text-slate-500">{relativeTime(scan.created_at)}</td>
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
